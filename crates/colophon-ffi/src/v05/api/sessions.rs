//! 0.6 sessions (`spec/colophon-0.6-sessions.md`, wire in `docs/colophon-0.6-sessions-wire.md`):
//! the core's sans-IO `Endpoint` behind a handle, and the account view it verifies against.
//!
//! * `SessionEndpoint`: one member of one cell, from wire bytes to application events and back.
//!   Every call returns a `SessionStep`: the effects in the order the host carries them out.
//! * `SessionAccountView`: the account view, taken from the engine (`session_account`) and
//!   stamped with the engine, account, namespace and authority head.
//!
//! The endpoint reads the account's authority head and epoch keys from the engine's
//! `SessionGate` on every call that runs the session, as an opaque copy that never leaves Rust:
//! no key crosses the boundary in either direction, and no endpoint call takes the engine's
//! lock. The conformance surface (supplied views and keys, the machine and the receiver on
//! their own) is in the unpublished `colophon-conformance` crate, never in this one.
//!
//! Commands, events, claims, policies and persisted claims cross as the JSON the conformance
//! vectors use (tagged by `command`, `event`, `input`, `output`). Every JSON argument is decoded
//! strictly: it must parse, name a known variant, and read back to exactly the value given (no
//! unknown or missing fields, canonical base64); anything else is `Malformed` and changes nothing.
//! The member key never enters: the host signs the delegation body with it, as it signs a `Raw`
//! signing step. Nothing here implements `Debug`; errors never carry key material, payloads or
//! frames.
use super::engine::AccountEngine;
use super::fault::AccountError;
use super::types::*;
use super::{guard, Cell};
use colophon_core::v06::session::codec::{CellId, Dropped, SealError, SessionEpochs};
use colophon_core::v06::session::endpoint::{Clock, Effect, Endpoint, EndpointError};
use colophon_core::v06::session::keys::{KeyError, SessionAccount};
use colophon_core::v06::session::{Command, Persisted, Policy};
use serde_json::Value;

/// The largest JSON argument: a command or input carries at most one frame or snapshot.
pub(super) const MAX_SESSION_JSON: usize = 256 << 10;
/// The largest frame taken from a carrier (the core drops anything over 16,384 bytes; a larger
/// argument is refused before it is copied).
pub(super) const MAX_FRAME_ARG: usize = 1 << 20;

/// Decode `text` as `$t` strictly: it must read back to exactly the JSON given.
macro_rules! strict {
    ($t:ty, $text:expr, $what:expr) => {{
        let (text, what): (&str, &str) = ($text, $what);
        (|| -> R<$t> {
            bytes_ok(
                text.as_bytes(),
                $crate::v05::api::sessions::MAX_SESSION_JSON,
                what,
            )?;
            let bad = || AccountError::bad(format!("{what} is not valid"));
            let given: Value = serde_json::from_str(text).map_err(|_| bad())?;
            let v: $t = serde_json::from_value(given.clone()).map_err(|_| bad())?;
            let back = serde_json::to_value(&v).map_err(|_| bad())?;
            if back != given {
                return Err(bad());
            }
            Ok(v)
        })()
    }};
}
/// A value as its JSON text.
macro_rules! json_out {
    ($v:expr) => {
        serde_json::to_string($v)
            .map_err(|_| AccountError::internal("a result could not be written"))
    };
}

pub(super) fn persisted_in(p: Option<String>) -> R<Option<Persisted>> {
    let Some(p) = p else { return Ok(None) };
    let p: Persisted = strict!(Persisted, &p, "the persisted claim")?;
    if !p.claim.well_formed() {
        return Err(AccountError::bad("the persisted claim is not well formed"));
    }
    Ok(Some(p))
}
fn clock_in(c: &SessionClock) -> Clock {
    Clock {
        mono_ms: c.mono_ms,
        wall_ms: c.wall_ms,
    }
}
fn key_code(k: &KeyError) -> &'static str {
    match k {
        KeyError::Scalar => "scalar",
        KeyError::Exhausted => "exhausted",
        KeyError::Window => "window",
        KeyError::Retired => "retired",
    }
}
fn key_error(k: KeyError) -> AccountError {
    let code = format!("session:{}", key_code(&k));
    match k {
        KeyError::Scalar | KeyError::Window => AccountError::Malformed {
            code,
            detail: k.to_string(),
        },
        KeyError::Exhausted | KeyError::Retired => AccountError::Consumed {
            code,
            detail: k.to_string(),
        },
    }
}
/// A stable code for a frame that could not be sealed.
fn seal_code(e: &SealError) -> String {
    match e {
        SealError::NoDelegation => "noDelegation".into(),
        SealError::DelegationWindow => "delegationWindow".into(),
        SealError::NotMine => "notMine".into(),
        SealError::NoEpoch => "noEpoch".into(),
        SealError::Key(k) => format!("key:{}", key_code(k)),
        SealError::Oversize => "oversize".into(),
        SealError::NotEntitled => "notEntitled".into(),
        SealError::NotWriter => "notWriter".into(),
        SealError::Retired => "retired".into(),
        SealError::Encode(_) => "encode".into(),
    }
}
pub(super) fn drop_out(d: &Dropped) -> SessionDrop {
    SessionDrop {
        reason: d.reason.code().into(),
        hello_to: d.hello_to.clone(),
    }
}
fn effect_out(e: Effect) -> R<SessionEffect> {
    let mut o = SessionEffect {
        kind: SessionEffectKind::Send,
        bytes: Vec::new(),
        to: None,
        frame_kind: None,
        persisted_json: None,
        event: None,
        event_json: None,
        unsent: None,
    };
    match e {
        Effect::Send { bytes, to, kind } => {
            o.bytes = bytes;
            o.to = to;
            o.frame_kind = Some(kind.into());
        }
        Effect::Persist { claim, released } => {
            o.kind = SessionEffectKind::Persist;
            o.persisted_json = Some(json_out!(&Persisted { claim, released })?);
        }
        Effect::Event(ev) => {
            o.kind = SessionEffectKind::Event;
            let v = serde_json::to_value(&ev)
                .map_err(|_| AccountError::internal("an event could not be written"))?;
            o.event = v.get("event").and_then(Value::as_str).map(str::to_string);
            o.event_json = Some(json_out!(&v)?);
        }
        Effect::Unsent { kind, error } => {
            o.kind = SessionEffectKind::Unsent;
            o.frame_kind = Some(kind.into());
            o.unsent = Some(seal_code(&error));
        }
    }
    Ok(o)
}

// --- The account view ---------------------------------------------------------------------------

/// The members of one account that are current at the host's accepted authority head (§S1,
/// §S2), stamped with the engine and authority head it was taken at. Immutable: a new head is
/// a new view.
#[cfg_attr(feature = "native05", derive(uniffi::Object))]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub struct SessionAccountView {
    pub(crate) v: SessionAccount,
    /// The engine, account, namespace and authority head it was taken at.
    pub(crate) stamp: Head,
}
#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
impl SessionAccountView {
    /// The account (64 hex).
    pub fn account(&self) -> String {
        self.v.account().to_string()
    }
    /// The members entitled to write in `namespace` at `wall_ms`, sorted.
    pub fn writers(&self, namespace: String, wall_ms: i64) -> Vec<String> {
        self.v.writers(&namespace, wall_ms)
    }
    /// Whether `member` is current at `wall_ms` and holds a `records` entry for `namespace`.
    pub fn entitled(&self, member: String, namespace: String, wall_ms: i64) -> bool {
        self.v.access(&member, &namespace, wall_ms).is_some()
    }
    /// The member's session number, when it is current.
    pub fn session_of(&self, member: String) -> Option<u64> {
        self.v.member(&member).map(|m| m.session)
    }
}

// --- The head gate --------------------------------------------------------------------------------

/// The most frames an endpoint keeps while a `Persist` is unacknowledged, and their most bytes
/// together. A durable write takes milliseconds to a few hundred; 64 frames cover several
/// seconds of a busy cell, and 1 MiB bounds the memory and the work of the `persisted` call
/// that runs them. Ticks and link changes coalesce and take no slot.
pub(super) const MAX_QUEUED: usize = 64;
pub(super) const MAX_QUEUED_BYTES: usize = 1 << 20;

/// The engine's authority head and keys as session endpoints read them.
pub(crate) struct Published {
    seq: u64,
    digest: String,
    locked: bool,
    /// The epoch keys of every namespace a view was taken for (opaque, wiped on drop).
    epochs: std::collections::HashMap<String, std::sync::Arc<SessionEpochs>>,
}

/// What a session endpoint reads from its engine, without the engine's lock: the installed
/// authority head and epoch keys, behind a read-write lock of its own.
///
/// The engine takes the write side only to install a new head or key set, for the instant of
/// the assignment, at the end of each engine call and while it still holds its own lock (so the
/// call returns only once the new head is visible here). An endpoint call takes the read side
/// for its whole run and never takes the engine's lock. Order: engine, then gate (write); gate
/// (read), then endpoint. No path takes them in another order, so there is no cycle: a tick waits
/// at most for one installation, and an installation at most for the endpoint calls in progress,
/// whose work is bounded (one input, or one acknowledged `Persist` and its bounded queue).
pub(crate) struct SessionGate {
    inner: std::sync::RwLock<Published>,
    /// Writers waiting to install a head. `std::sync::RwLock` promises no fairness, so a new
    /// endpoint call waits while one is set: a stream of endpoint calls cannot starve an
    /// installation.
    intent: std::sync::atomic::AtomicUsize,
}
impl SessionGate {
    pub(crate) fn new(a: &colophon_core::v05::account::Account, locked: bool) -> Self {
        let (seq, digest) = a.head();
        Self {
            inner: std::sync::RwLock::new(Published {
                seq,
                digest,
                locked,
                epochs: Default::default(),
            }),
            intent: std::sync::atomic::AtomicUsize::new(0),
        }
    }
    /// The write side, announced first so new readers hold back.
    fn write(&self) -> Option<std::sync::RwLockWriteGuard<'_, Published>> {
        use std::sync::atomic::Ordering;
        self.intent.fetch_add(1, Ordering::SeqCst);
        let w = self.inner.write().ok();
        self.intent.fetch_sub(1, Ordering::SeqCst);
        w
    }
    /// Install the engine's current head and keys, if they changed. Called with the engine held.
    pub(crate) fn publish(&self, a: &colophon_core::v05::account::Account, locked: bool) {
        use colophon_core::v06::session::codec::EpochKeys;
        let (seq, digest) = a.head();
        let Ok(cur) = self.inner.read() else { return };
        let mut fresh = Vec::new();
        for (ns, old) in &cur.epochs {
            let new = a.session_epochs(ns);
            if new.len() != old.len() || new.current_epoch(ns) != old.current_epoch(ns) {
                fresh.push((ns.clone(), new));
            }
        }
        if cur.seq == seq && cur.digest == digest && cur.locked == locked && fresh.is_empty() {
            return;
        }
        drop(cur);
        if let Some(mut w) = self.write() {
            w.seq = seq;
            w.digest = digest;
            w.locked = locked;
            for (ns, e) in fresh {
                w.epochs.insert(ns, std::sync::Arc::new(e));
            }
        }
    }
    /// Start publishing the keys of `namespace` (a view was taken for it). Engine held.
    fn register(&self, a: &colophon_core::v05::account::Account, namespace: &str) {
        let known = self
            .inner
            .read()
            .map(|p| p.epochs.contains_key(namespace))
            .unwrap_or(false);
        if !known {
            if let Some(mut w) = self.write() {
                w.epochs.insert(
                    namespace.to_owned(),
                    std::sync::Arc::new(a.session_epochs(namespace)),
                );
            }
        }
    }
    fn read(&self) -> R<std::sync::RwLockReadGuard<'_, Published>> {
        while self.intent.load(std::sync::atomic::Ordering::SeqCst) > 0 {
            std::thread::yield_now();
        }
        self.inner.read().map_err(|_| {
            AccountError::internal(
                "an earlier call panicked; discard this engine and open a new one",
            )
        })
    }
}

// --- The endpoint -------------------------------------------------------------------------------

/// The engine, account, namespace and authority head (sequence and body digest) a view was
/// taken at.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Head {
    owner: u64,
    account: String,
    namespace: String,
    seq: u64,
    digest: String,
}

/// A `Persist` the host has not acknowledged yet, with the effects that followed it (decided
/// under `head`; released only while `head` is still the engine's).
struct Pending {
    ack: u64,
    rest: Vec<Effect>,
}

/// An input to run.
enum Input0 {
    Tick,
    Receive(Vec<u8>),
    Link(bool),
    Command(Command),
    /// Only run from the outage summary, never taken from the host.
    Outage {
        down_ms: u64,
        ended: bool,
    },
}

/// The link changes seen while a `Persist` waits, as a constant-size summary: the link's state
/// now, when the current outage began (if it began while waiting), and the longest outage that
/// began and ended while waiting. The machine learns it at the processing clock, through
/// `Input::Outage`, never at a past clock.
#[derive(Default)]
struct OutageSummary {
    /// The link's state after the changes seen; none when no change was seen.
    up: Option<bool>,
    /// When the current outage began, if it began while waiting.
    down_since: Option<u64>,
    /// An outage ended while waiting (one that began before is counted too, as 0 ms: the
    /// machine keeps its own start for it).
    ended: bool,
    /// The longest outage that began and ended while waiting.
    longest: u64,
}
impl OutageSummary {
    fn seen(&self) -> bool {
        self.up.is_some()
    }
    fn change(&mut self, up: bool, at: u64, machine_up: bool) {
        let was = self.up.unwrap_or(machine_up);
        if was == up {
            return;
        }
        self.up = Some(up);
        if up {
            self.ended = true;
            if let Some(d) = self.down_since.take() {
                self.longest = self.longest.max(at.saturating_sub(d));
            }
        } else {
            self.down_since = Some(at);
        }
    }
}

/// What one call hands back, accumulated across the inputs it ran.
struct Out {
    effects: Vec<SessionEffect>,
    drops: Vec<SessionDrop>,
    awaiting: Option<u64>,
    queued: bool,
    discarded: u32,
}
impl Out {
    fn new() -> Self {
        Self {
            effects: Vec::new(),
            drops: Vec::new(),
            awaiting: None,
            queued: false,
            discarded: 0,
        }
    }
    /// The step; `outstanding` says whether a `Persist` still waits for its acknowledgement.
    fn step(self, outstanding: bool) -> SessionStep {
        SessionStep {
            effects: self.effects,
            drops: self.drops,
            awaiting_persist: self.awaiting,
            persist_outstanding: outstanding,
            queued: self.queued,
            discarded: self.discarded,
        }
    }
}

struct EndpointState {
    e: Endpoint,
    /// The head of the view installed last.
    installed: Head,
    /// The body `begin_delegation` returned and `finish_delegation` has not installed yet.
    delegation: Option<Vec<u8>>,
    pending: Option<Pending>,
    /// Inputs that arrived while a `Persist` waited: the frames in arrival order, the link
    /// changes as a summary, and whether a tick fell due. All run at the clock of the call
    /// that drains them.
    frames: std::collections::VecDeque<Vec<u8>>,
    frame_bytes: usize,
    outage: OutageSummary,
    tick: bool,
    next_ack: u64,
    /// The last monotonic clock given to the machine: a call with an earlier one is refused.
    last_mono: u64,
}

fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

impl EndpointState {
    /// Release effects up to and including the first `Persist`, holding the rest behind it.
    /// True when a `Persist` now waits.
    fn absorb(&mut self, effects: Vec<Effect>, out: &mut Out) -> R<bool> {
        let mut it = effects.into_iter();
        for e in it.by_ref() {
            let persist = matches!(e, Effect::Persist { .. });
            out.effects.push(effect_out(e)?);
            if persist {
                self.next_ack = self.next_ack.wrapping_add(1).max(1);
                out.awaiting = Some(self.next_ack);
                self.pending = Some(Pending {
                    ack: self.next_ack,
                    rest: it.collect(),
                });
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn run(
        &mut self,
        input: Input0,
        clock: Clock,
        epochs: &SessionEpochs,
        out: &mut Out,
    ) -> R<bool> {
        let step = match input {
            Input0::Tick => self.e.tick(clock, epochs),
            Input0::Receive(b) => self.e.receive(&b, clock, epochs),
            Input0::Link(true) => self.e.link_up(clock, epochs),
            Input0::Link(false) => self.e.link_down(clock, epochs),
            Input0::Outage { down_ms, ended } => self.e.outage(down_ms, ended, clock, epochs),
            Input0::Command(c) => self.e.command(c, clock, epochs),
        };
        if let Some(d) = step.dropped.as_ref() {
            out.drops.push(drop_out(d));
        }
        self.absorb(step.effects, out)
    }
    /// Run what waited, all at this call's clock, until a `Persist`: first the link changes
    /// (an outage that ended, then one still under way, as `Input::Outage`, so a holder that
    /// lapsed is gated before it acts on anything), then the frames in arrival order, then one
    /// tick. Running the outage before frames that arrived earlier is a deliberate, cautious
    /// reordering.
    fn drain(&mut self, clock: Clock, epochs: &SessionEpochs, out: &mut Out) -> R<()> {
        let o = std::mem::take(&mut self.outage);
        if o.ended
            && self.run(
                Input0::Outage {
                    down_ms: o.longest,
                    ended: true,
                },
                clock,
                epochs,
                out,
            )?
        {
            return Ok(());
        }
        if let (Some(false), Some(since)) = (o.up, o.down_since) {
            let down_ms = clock.mono_ms.saturating_sub(since);
            if self.run(
                Input0::Outage {
                    down_ms,
                    ended: false,
                },
                clock,
                epochs,
                out,
            )? {
                return Ok(());
            }
        }
        while let Some(b) = self.frames.pop_front() {
            self.frame_bytes = self.frame_bytes.saturating_sub(b.len());
            if self.run(Input0::Receive(b), clock, epochs, out)? {
                return Ok(());
            }
        }
        if std::mem::take(&mut self.tick) {
            self.run(Input0::Tick, clock, epochs, out)?;
        }
        Ok(())
    }
    /// Keep an input that arrived at `clock` while a `Persist` waits; a command is refused.
    fn hold(&mut self, input: Input0, clock: Clock, out: &mut Out) -> R<()> {
        match input {
            Input0::Command(_) => Err(persist_pending()),
            Input0::Outage { .. } => Err(AccountError::internal("an outage is not an input")),
            Input0::Tick => {
                self.tick = true;
                out.queued = true;
                Ok(())
            }
            Input0::Link(up) => {
                let machine_up = self.e.machine().link_is_up();
                self.outage.change(up, clock.mono_ms, machine_up);
                out.queued = true;
                Ok(())
            }
            Input0::Receive(b) => {
                if self.frames.len() >= MAX_QUEUED
                    || self.frame_bytes.saturating_add(b.len()) > MAX_QUEUED_BYTES
                {
                    // The newest frame is lost, as on any carrier.
                    out.drops.push(SessionDrop {
                        reason: "queueFull".into(),
                        hello_to: None,
                    });
                } else {
                    self.frame_bytes += b.len();
                    self.frames.push_back(b);
                    out.queued = true;
                }
                Ok(())
            }
        }
    }
    /// Refuse a monotonic clock earlier than the last one given, changing nothing; else record it.
    fn advance(&mut self, clock: &Clock) -> R<()> {
        if clock.mono_ms < self.last_mono {
            return Err(AccountError::Malformed {
                code: "session:clockBackwards".into(),
                detail: format!(
                    "the monotonic clock went back from {} to {} ms",
                    self.last_mono, clock.mono_ms
                ),
            });
        }
        self.last_mono = clock.mono_ms;
        Ok(())
    }
    fn queued(&self) -> usize {
        self.frames.len() + usize::from(self.tick) + usize::from(self.outage.seen())
    }
}

fn stale() -> AccountError {
    AccountError::Unavailable {
        code: "session:staleAccount".into(),
        detail: "the engine has accepted a newer authority head than the endpoint's view: call \
                 set_account with a new session_account first"
            .into(),
    }
}
fn persist_pending() -> AccountError {
    AccountError::Unavailable {
        code: "session:persistPending".into(),
        detail: "a Persist effect is not acknowledged yet: store it, call persisted, then retry"
            .into(),
    }
}
fn wrong_ack() -> AccountError {
    AccountError::WrongObject {
        code: "session:wrongAck".into(),
        detail: "no Persist with this acknowledgement ID is waiting".into(),
    }
}
fn wrong_view(what: &str) -> AccountError {
    AccountError::WrongObject {
        code: "session:wrongView".into(),
        detail: what.into(),
    }
}

/// One member of one cell, with sealing. Calls are serialized (one at a time, as §6 of the wire
/// document requires): a second thread waits for the first.
///
/// Every call that runs the session takes the engine and works under its `SessionGate` (read
/// side; see there for the lock order), against the head and keys the engine has installed. A
/// view of an older head is refused with `session:staleAccount`, changing nothing. A step
/// releases its effects only up to and including the first `Persist`; what follows waits for
/// `persisted`, and is discarded, never released, if the head moves before it is acknowledged.
#[cfg_attr(feature = "native05", derive(uniffi::Object))]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub struct SessionEndpoint {
    s: Cell<EndpointState>,
}
impl SessionEndpoint {
    #[allow(clippy::too_many_arguments)]
    fn new_inner(
        account: String,
        namespace: String,
        cell: String,
        me: String,
        policy_json: String,
        persisted_json: Option<String>,
        view: &SessionAccountView,
        key_random: Vec<u8>,
        fresh_seed: Vec<u8>,
        clock: SessionClock,
    ) -> R<Self> {
        let mut key_random = key_random;
        let mut fresh_seed = fresh_seed;
        let r = guard(|| {
            if view.stamp.account != account || view.stamp.namespace != namespace {
                return Err(wrong_view("the view is for another account or namespace"));
            }
            let policy: Policy = strict!(Policy, &policy_json, "the cell policy")?;
            let persisted = persisted_in(persisted_json)?;
            let mut random = fixed::<32>(&key_random, "the key randomness")?;
            let seed = fixed::<16>(&fresh_seed, "the fresh seed")?;
            let made = Endpoint::new(
                CellId::new(&account, &namespace, &cell),
                &me,
                policy,
                persisted,
                view.v.clone(),
                &mut random,
                seed,
                clock_in(&clock),
            );
            wipe(&mut random);
            match made {
                Ok(e) => Ok(Self {
                    s: Cell::new(EndpointState {
                        e,
                        installed: view.stamp.clone(),
                        delegation: None,
                        pending: None,
                        frames: Default::default(),
                        frame_bytes: 0,
                        outage: OutageSummary::default(),
                        tick: false,
                        next_ack: 0,
                        last_mono: clock.mono_ms,
                    }),
                }),
                Err(EndpointError::Key(k)) => Err(key_error(k)),
                Err(EndpointError::WrongAccount) => {
                    Err(wrong_view("the view is for another account"))
                }
                Err(EndpointError::NotEntitled) => Err(AccountError::denied(
                    "notGranted",
                    "this member is not current or holds no records entry for the namespace",
                )),
                Err(EndpointError::Policy(why)) => Err(AccountError::Malformed {
                    code: "session:policy".into(),
                    detail: why.chars().take(512).collect(),
                }),
            }
        });
        wipe(&mut key_random);
        wipe(&mut fresh_seed);
        r
    }
    /// Run `f` under the engine's gate (read side) with the endpoint locked, given whether the
    /// installed view is the engine's current head and the namespace's keys.
    fn gated<T>(
        &self,
        engine: &AccountEngine,
        f: impl FnOnce(&mut EndpointState, &Published, &SessionEpochs) -> R<T>,
    ) -> R<T> {
        guard(|| {
            let p = engine.gate.read()?;
            if p.locked {
                return Err(AccountError::locked());
            }
            let mut s = self.s.lock()?;
            if s.installed.owner != engine.owner {
                return Err(wrong_view("this endpoint's view came from another engine"));
            }
            let epochs = p
                .epochs
                .get(&s.installed.namespace)
                .cloned()
                .ok_or_else(|| AccountError::internal("the namespace's keys are not published"))?;
            f(&mut s, &p, &epochs)
        })
    }
    /// One input: held while a `Persist` waits (a command is refused), else refused on a stale
    /// view, else run.
    fn driven(
        &self,
        engine: &AccountEngine,
        clock: &SessionClock,
        input: Input0,
    ) -> R<SessionStep> {
        let clock = clock_in(clock);
        self.gated(engine, |s, p, epochs| {
            let current = s.installed.seq == p.seq && s.installed.digest == p.digest;
            let mut out = Out::new();
            s.advance(&clock)?;
            if s.pending.is_some() {
                s.hold(input, clock, &mut out)?;
                return Ok(out.step(s.pending.is_some()));
            }
            if !current {
                return Err(stale());
            }
            s.drain(clock, epochs, &mut out)?;
            if s.pending.is_some() {
                s.hold(input, clock, &mut out)?;
            } else {
                s.run(input, clock, epochs, &mut out)?;
            }
            Ok(out.step(s.pending.is_some()))
        })
    }
}
#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
impl SessionEndpoint {
    /// The exact `colophon/session-key/6` body for the host to sign with this member's key, as
    /// it signs a `Raw` signing step (P-256, `r||s`), for the window `[not_before_ms,
    /// expires_ms]` (at most 86,400 s). Nothing can be sent before the signature is installed;
    /// call again to renew before the window ends. Only the latest body can be finished.
    pub fn begin_delegation(
        &self,
        not_before_ms: i64,
        expires_ms: i64,
    ) -> Result<Vec<u8>, AccountError> {
        guard(|| {
            let mut s = self.s.lock()?;
            let body =
                s.e.begin_delegation(not_before_ms, expires_ms)
                    .map_err(key_error)?;
            s.delegation = Some(body.clone());
            Ok(body)
        })
    }
    /// Install the host's signature over the body the last `begin_delegation` returned, after
    /// verifying it under this member's key in the account view. Any other body, including one
    /// with a field changed, is `session:delegation`; a body already installed is `consumed`.
    pub fn finish_delegation(
        &self,
        body: Vec<u8>,
        signature: Vec<u8>,
        clock: SessionClock,
    ) -> Result<(), AccountError> {
        guard(|| {
            bytes_ok(&body, 1_024, "a delegation body")?;
            bytes_ok(&signature, 128, "a signature")?;
            let mut s = self.s.lock()?;
            match &s.delegation {
                None => {
                    return Err(AccountError::consumed(
                        "no delegation body is waiting to be installed",
                    ))
                }
                Some(b) if *b != body => {
                    return Err(AccountError::Malformed {
                        code: "session:delegation".into(),
                        detail: "not the body begin_delegation returned".into(),
                    })
                }
                Some(_) => {}
            }
            s.e.finish_delegation(&body, &signature, clock_in(&clock))
                .map_err(|why| AccountError::Malformed {
                    code: "session:delegation".into(),
                    detail: why.chars().take(512).collect(),
                })?;
            s.delegation = None;
            Ok(())
        })
    }
    /// A newly accepted authority head: install `view`, which must be `engine`'s
    /// `session_account` for this endpoint's account and namespace (else `session:wrongView`)
    /// at its current head (else `session:staleAccount`). Allowed while a `Persist` waits: the
    /// effects held behind it, decided under the older head, are discarded (`discarded`), and
    /// what this call decides waits behind that `Persist` in their place. Otherwise the inputs
    /// that waited run.
    pub fn set_account(
        &self,
        view: &SessionAccountView,
        engine: &AccountEngine,
        clock: SessionClock,
    ) -> Result<SessionStep, AccountError> {
        let clock = clock_in(&clock);
        self.gated(engine, |s, p, epochs| {
            let stamp = &view.stamp;
            if stamp.owner != engine.owner
                || stamp.account != s.installed.account
                || stamp.namespace != s.installed.namespace
            {
                return Err(wrong_view(
                    "the view is for another engine, account or namespace",
                ));
            }
            if stamp.seq != p.seq || stamp.digest != p.digest {
                return Err(stale());
            }
            s.advance(&clock)?;
            let mut out = Out::new();
            let step = s.e.set_account(view.v.clone(), clock, epochs);
            s.installed = stamp.clone();
            if let Some(pending) = s.pending.as_mut() {
                out.discarded = count(pending.rest.len());
                pending.rest = step.effects;
                return Ok(out.step(s.pending.is_some()));
            }
            if !s.absorb(step.effects, &mut out)? {
                s.drain(clock, epochs, &mut out)?;
            }
            Ok(out.step(s.pending.is_some()))
        })
    }
    /// An application command (§S10), as JSON tagged by `command`. While a `Persist` waits it
    /// is refused with `session:persistPending` and changes nothing: retry after `persisted`.
    pub fn command(
        &self,
        command_json: String,
        engine: &AccountEngine,
        clock: SessionClock,
    ) -> Result<SessionStep, AccountError> {
        let c: Command = guard(|| strict!(Command, &command_json, "the session command"))?;
        self.driven(engine, &clock, Input0::Command(c))
    }
    /// A timer expiry: call at or soon after `next_deadline` (within 250 ms). While a
    /// `Persist` waits it is kept (one, however many arrive) and runs at `persisted`.
    pub fn tick(
        &self,
        engine: &AccountEngine,
        clock: SessionClock,
    ) -> Result<SessionStep, AccountError> {
        self.driven(engine, &clock, Input0::Tick)
    }
    /// Some carrier works again. While a `Persist` waits it updates the outage summary.
    pub fn link_up(
        &self,
        engine: &AccountEngine,
        clock: SessionClock,
    ) -> Result<SessionStep, AccountError> {
        self.driven(engine, &clock, Input0::Link(true))
    }
    /// No carrier works. While a `Persist` waits it updates the outage summary.
    pub fn link_down(
        &self,
        engine: &AccountEngine,
        clock: SessionClock,
    ) -> Result<SessionStep, AccountError> {
        self.driven(engine, &clock, Input0::Link(false))
    }
    /// Bytes received from a carrier, exactly as the sender sealed them. A frame that fails any
    /// §S3 check changes nothing and is reported in `drops`. While a `Persist` waits the frame is
    /// kept (`queued`), up to 64 frames and 1 MiB; past that it is lost (a `queueFull` drop).
    pub fn receive(
        &self,
        bytes: Vec<u8>,
        engine: &AccountEngine,
        clock: SessionClock,
    ) -> Result<SessionStep, AccountError> {
        bytes_ok(&bytes, MAX_FRAME_ARG, "a session frame")?;
        self.driven(engine, &clock, Input0::Receive(bytes))
    }
    /// The host stored the `Persist` whose acknowledgement ID is `ack` (the step's
    /// `awaiting_persist`); any other ID, or one already acknowledged, is `session:wrongAck`.
    /// If the engine's head is still the installed view's, the effects held behind it are
    /// released and the inputs that waited run (the outage summary, the frames in order, one
    /// tick), all with this call's clock, up to the next
    /// `Persist`. If the head has moved, the held effects are discarded (`discarded`), the
    /// inputs keep waiting, and the next call that runs the session is `session:staleAccount`
    /// until `set_account`.
    pub fn persisted(
        &self,
        ack: u64,
        engine: &AccountEngine,
        clock: SessionClock,
    ) -> Result<SessionStep, AccountError> {
        let clock = clock_in(&clock);
        self.gated(engine, |s, p, epochs| {
            let current = s.installed.seq == p.seq && s.installed.digest == p.digest;
            match &s.pending {
                Some(p) if p.ack == ack => {}
                _ => return Err(wrong_ack()),
            }
            s.advance(&clock)?;
            let mut out = Out::new();
            let rest = s.pending.take().map(|p| p.rest).unwrap_or_default();
            if !current {
                out.discarded = count(rest.len());
                return Ok(out.step(s.pending.is_some()));
            }
            if !s.absorb(rest, &mut out)? {
                s.drain(clock, epochs, &mut out)?;
            }
            Ok(out.step(s.pending.is_some()))
        })
    }
    /// The acknowledgement ID of the `Persist` waiting for `persisted`, if any.
    pub fn awaiting_persist(&self) -> Result<Option<u64>, AccountError> {
        guard(|| Ok(self.s.lock()?.pending.as_ref().map(|p| p.ack)))
    }
    /// How many inputs wait (frames, plus one for a tick and one for a link state).
    pub fn queued(&self) -> Result<u32, AccountError> {
        guard(|| Ok(count(self.s.lock()?.queued())))
    }
    /// When to call `tick` next (monotonic ms), if ever. While a `Persist` waits this is still
    /// the machine's deadline: a tick then is kept and runs at `persisted`.
    pub fn next_deadline(&self) -> Result<Option<u64>, AccountError> {
        guard(|| Ok(self.s.lock()?.e.next_deadline()))
    }
    /// This member.
    pub fn me(&self) -> Result<String, AccountError> {
        guard(|| Ok(self.s.lock()?.e.me().to_string()))
    }
    /// The session key's ID (a key ID of its point).
    pub fn key_id(&self) -> Result<String, AccountError> {
        guard(|| Ok(self.s.lock()?.e.key_id().to_string()))
    }
    /// The highest `n` sealed so far.
    pub fn last_n(&self) -> Result<u64, AccountError> {
        guard(|| Ok(self.s.lock()?.e.last_n()))
    }
    /// Whether this member holds a `records` entry for the namespace (it may send).
    pub fn entitled(&self) -> Result<bool, AccountError> {
        guard(|| Ok(self.s.lock()?.e.entitled()))
    }
    /// Whether this member may write (§S1), as last set.
    pub fn can_write(&self) -> Result<bool, AccountError> {
        guard(|| Ok(self.s.lock()?.e.machine().can_write()))
    }
    /// Whether the member has joined.
    pub fn joined(&self) -> Result<bool, AccountError> {
        guard(|| Ok(self.s.lock()?.e.machine().joined()))
    }
    /// The holder this member sees, if any.
    pub fn holder(&self) -> Result<Option<String>, AccountError> {
        guard(|| Ok(self.s.lock()?.e.machine().holder().map(str::to_string)))
    }
    /// Whether this member acts as holder.
    pub fn is_holder(&self) -> Result<bool, AccountError> {
        guard(|| Ok(self.s.lock()?.e.machine().is_holder()))
    }
    /// The greatest accepted claim as JSON (`{term, rank, holder, via?}`), if any.
    pub fn claim_json(&self) -> Result<Option<String>, AccountError> {
        guard(|| {
            self.s
                .lock()?
                .e
                .machine()
                .accepted()
                .map(|v| json_out!(v))
                .transpose()
        })
    }
    /// The protocol-visible state as JSON (`{accepted, holder, holding, gated, synced, seq,
    /// state}`, as in the vectors' `final`). It carries application state: do not log it.
    pub fn view_json(&self) -> Result<String, AccountError> {
        guard(|| json_out!(&self.s.lock()?.e.machine().view()))
    }
    /// SHA-256 hex of `view_json` as the reference writes it.
    pub fn digest(&self) -> Result<String, AccountError> {
        guard(|| Ok(self.s.lock()?.e.machine().digest()))
    }
}
#[cfg(feature = "native05")]
#[uniffi::export]
impl SessionEndpoint {
    /// Start a session for member `me` in `(account, namespace, cell)` under `policy_json` (the
    /// §S1 policy as JSON; `session_default_policy` gives the defaults), resuming from
    /// `persisted_json` (the last `Persist` effect the host stored, or none). `view` is the
    /// engine's `session_account`. `key_random` (32 bytes) makes the session key and
    /// `fresh_seed` (16 bytes) seeds the machine's challenges: both must be new random bytes on
    /// every process start, and both are wiped. A policy out of bounds is `session:policy`; a
    /// member not entitled to the namespace is `denied:notGranted`.
    #[uniffi::constructor]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account: String,
        namespace: String,
        cell: String,
        me: String,
        policy_json: String,
        persisted_json: Option<String>,
        view: std::sync::Arc<SessionAccountView>,
        key_random: Vec<u8>,
        fresh_seed: Vec<u8>,
        clock: SessionClock,
    ) -> Result<std::sync::Arc<Self>, AccountError> {
        Self::new_inner(
            account,
            namespace,
            cell,
            me,
            policy_json,
            persisted_json,
            &view,
            key_random,
            fresh_seed,
            clock,
        )
        .map(std::sync::Arc::new)
    }
}
#[cfg(feature = "web05")]
#[wasm_bindgen::prelude::wasm_bindgen]
impl SessionEndpoint {
    /// Start a session (see the native constructor).
    #[wasm_bindgen::prelude::wasm_bindgen(constructor)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account: String,
        namespace: String,
        cell: String,
        me: String,
        policy_json: String,
        persisted_json: Option<String>,
        view: &SessionAccountView,
        key_random: Vec<u8>,
        fresh_seed: Vec<u8>,
        clock: SessionClock,
    ) -> Result<SessionEndpoint, AccountError> {
        Self::new_inner(
            account,
            namespace,
            cell,
            me,
            policy_json,
            persisted_json,
            view,
            key_random,
            fresh_seed,
            clock,
        )
    }
}

// --- From the engine ----------------------------------------------------------------------------

impl AccountEngine {
    fn session_account_inner(&self, namespace: String, at_ms: i64) -> R<SessionAccountView> {
        if !colophon_core::v05::terms::valid_namespace(&namespace) {
            return Err(AccountError::bad("invalid namespace"));
        }
        self.acct(|a| {
            self.gate.register(a, &namespace);
            let (seq, digest) = a.head();
            Ok(SessionAccountView {
                v: a.session_account(at_ms),
                stamp: Head {
                    owner: self.owner,
                    account: a.id().as_str().to_string(),
                    namespace: namespace.clone(),
                    seq,
                    digest,
                },
            })
        })
    }
}
#[cfg(feature = "native05")]
#[uniffi::export]
impl AccountEngine {
    /// The session view of the verified history at `at_ms` (wall clock) for an endpoint of
    /// `namespace`: every member current then, with its session number and `records` entries,
    /// stamped with this engine, the account, the namespace and the authority head.
    pub fn session_account(
        &self,
        namespace: String,
        at_ms: i64,
    ) -> Result<std::sync::Arc<SessionAccountView>, AccountError> {
        self.session_account_inner(namespace, at_ms)
            .map(std::sync::Arc::new)
    }
}
#[cfg(feature = "web05")]
#[wasm_bindgen::prelude::wasm_bindgen]
impl AccountEngine {
    /// The session view of the verified history at `at_ms` (wall clock) for an endpoint of
    /// `namespace`, stamped with this engine, the account, the namespace and the head.
    pub fn session_account(
        &self,
        namespace: String,
        at_ms: i64,
    ) -> Result<SessionAccountView, AccountError> {
        self.session_account_inner(namespace, at_ms)
    }
}

/// The default §S1 cell policy as JSON (camelCase, as in the vectors).
#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub fn session_default_policy() -> Result<String, AccountError> {
    json_out!(&Policy::default())
}

/// Check a cell policy as `SessionEndpoint` does: its largest frame in bytes, or
/// `session:policy` with the bound it breaks.
#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub fn session_validate_policy(
    policy_json: String,
    account: String,
    namespace: String,
    cell: String,
) -> Result<u64, AccountError> {
    guard(|| {
        let p: Policy = strict!(Policy, &policy_json, "the cell policy")?;
        colophon_core::v06::session::endpoint::validate_policy(
            &p,
            &CellId::new(&account, &namespace, &cell),
        )
        .map(|n| n as u64)
        .map_err(|why| AccountError::Malformed {
            code: "session:policy".into(),
            detail: why.chars().take(512).collect(),
        })
    })
}

/// The §S7 sample of one `pong` (`rtt = max(0, (now - echo) - hold)`, `offset = t - now +
/// floor(rtt / 2)`, `error = ceil(rtt / 2)`), as the machine computes it.
#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub fn session_clock_sample(now: u64, t: u64, echo: u64, hold: u64) -> SessionClockSample {
    let s = colophon_core::v06::session::sample(now, t, echo, hold);
    SessionClockSample {
        rtt: s.rtt,
        offset: s.offset,
        error: s.error,
    }
}
