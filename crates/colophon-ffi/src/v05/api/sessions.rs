//! 0.6 sessions (`spec/colophon-0.6-sessions.md`, wire in `docs/colophon-0.6-sessions-wire.md`):
//! the core's sans-IO `Endpoint` behind a handle, and the account view it verifies against.
//!
//! * `SessionEndpoint`: one member of one cell, from wire bytes to application events and back.
//!   Every call returns a `SessionStep`: the effects in the order the host carries them out.
//! * `SessionAccountView`: the account view, taken from the engine (`session_account`) and
//!   stamped with the engine's authority head.
//!
//! The endpoint reads the account's epoch keys from the engine on every call that seals or
//! opens, as an opaque copy that never leaves Rust: no key crosses the boundary in either
//! direction. The conformance surface (`conformance.rs`) is compiled only with the
//! `conformance` feature.
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
use colophon_core::v06::session::endpoint::{Clock, Effect, Endpoint, EndpointError, Step};
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
    /// The engine and authority head it was taken at; none for a supplied view.
    pub(crate) stamp: Option<(u64, u64)>,
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

// --- The endpoint -------------------------------------------------------------------------------

/// Effects held back behind a `Persist` until the host acknowledges it.
struct HeldEffects {
    /// The acknowledgement ID of the `Persist` that ends what was released.
    ack: u64,
    /// The effects after it, in order.
    rest: Vec<Effect>,
}

struct EndpointState {
    e: Endpoint,
    /// The engine and authority head of the view installed last (`None`: a view that did not
    /// come from an engine, which no engine-driven call accepts).
    installed: Option<(u64, u64)>,
    /// The body `begin_delegation` returned and `finish_delegation` has not installed yet.
    delegation: Option<Vec<u8>>,
    held: Option<HeldEffects>,
    next_ack: u64,
}

impl EndpointState {
    /// Release effects up to and including the first `Persist`; hold the rest behind it.
    fn release(&mut self, effects: Vec<Effect>, dropped: Option<SessionDrop>) -> R<SessionStep> {
        let mut out = Vec::new();
        let mut it = effects.into_iter();
        let mut awaiting = None;
        for e in it.by_ref() {
            let persist = matches!(e, Effect::Persist { .. });
            out.push(effect_out(e)?);
            if persist {
                self.next_ack = self.next_ack.wrapping_add(1).max(1);
                awaiting = Some(self.next_ack);
                break;
            }
        }
        if let Some(ack) = awaiting {
            self.held = Some(HeldEffects {
                ack,
                rest: it.collect(),
            });
        }
        Ok(SessionStep {
            effects: out,
            dropped,
            awaiting_persist: awaiting,
        })
    }
    fn not_held(&self) -> R<()> {
        match self.held {
            Some(_) => Err(AccountError::Unavailable {
                code: "session:persistPending".into(),
                detail: "a Persist effect is not acknowledged yet: store it and call persisted"
                    .into(),
            }),
            None => Ok(()),
        }
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

/// What an engine-driven call reads from the engine: its identity and authority head, and the
/// epoch keys of the cell's namespace (an opaque copy, wiped on drop).
fn engine_now(engine: &AccountEngine, namespace: &str) -> R<((u64, u64), SessionEpochs)> {
    engine.ensure_live()?;
    engine.acct(|a| Ok(((engine.owner, a.head().0), a.session_epochs(namespace))))
}

/// One member of one cell, with sealing. Calls are serialized (one at a time, as §6 of the wire
/// document requires): a second thread waits for the first.
///
/// Two orders are enforced here rather than left to the host. Every call that consults the
/// account (`receive`, `command`, `tick`, `link_up`, `link_down`) takes the engine and is refused
/// with `session:staleAccount`, changing nothing, when the engine has accepted an authority head
/// newer than the view last installed; `set_account` installs a view of the engine's current
/// head. And a step releases its effects only up to and including the first `Persist`: the
/// effects after it are held until `persisted` acknowledges it, and every other mutating call is
/// refused with `session:persistPending` until then.
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
                        installed: view.stamp,
                        delegation: None,
                        held: None,
                        next_ack: 0,
                    }),
                }),
                Err(EndpointError::Key(k)) => Err(key_error(k)),
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
    /// Run one engine-driven call: read the engine, then refuse a pending acknowledgement or a
    /// stale view before anything changes.
    fn driven(
        &self,
        engine: &AccountEngine,
        clock: &SessionClock,
        f: impl FnOnce(&mut Endpoint, Clock, &SessionEpochs) -> Step,
    ) -> R<SessionStep> {
        guard(|| {
            let ns = self.s.lock()?.e.cell().namespace.clone();
            let (head, epochs) = engine_now(engine, &ns)?;
            let mut s = self.s.lock()?;
            s.not_held()?;
            if s.installed != Some(head) {
                return Err(stale());
            }
            let step = f(&mut s.e, clock_in(clock), &epochs);
            let dropped = step.dropped.as_ref().map(drop_out);
            s.release(step.effects, dropped)
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
    /// A newly accepted authority head: install `view`, which must be the engine's
    /// `session_account` at its current head (else `session:staleAccount`). Call it after every
    /// pass that moved the head, before any frame received after it.
    pub fn set_account(
        &self,
        view: &SessionAccountView,
        engine: &AccountEngine,
        clock: SessionClock,
    ) -> Result<SessionStep, AccountError> {
        guard(|| {
            let ns = self.s.lock()?.e.cell().namespace.clone();
            let (head, epochs) = engine_now(engine, &ns)?;
            let mut s = self.s.lock()?;
            s.not_held()?;
            if view.stamp != Some(head) {
                return Err(stale());
            }
            let step = s.e.set_account(view.v.clone(), clock_in(&clock), &epochs);
            s.installed = Some(head);
            s.release(step.effects, None)
        })
    }
    /// An application command (§S10), as JSON tagged by `command`.
    pub fn command(
        &self,
        command_json: String,
        engine: &AccountEngine,
        clock: SessionClock,
    ) -> Result<SessionStep, AccountError> {
        let c: Command = guard(|| strict!(Command, &command_json, "the session command"))?;
        self.driven(engine, &clock, |e, c2, k| e.command(c, c2, k))
    }
    /// A timer expiry: call at or soon after `next_deadline` (within 250 ms).
    pub fn tick(
        &self,
        engine: &AccountEngine,
        clock: SessionClock,
    ) -> Result<SessionStep, AccountError> {
        self.driven(engine, &clock, |e, c, k| e.tick(c, k))
    }
    /// Some carrier works again.
    pub fn link_up(
        &self,
        engine: &AccountEngine,
        clock: SessionClock,
    ) -> Result<SessionStep, AccountError> {
        self.driven(engine, &clock, |e, c, k| e.link_up(c, k))
    }
    /// No carrier works.
    pub fn link_down(
        &self,
        engine: &AccountEngine,
        clock: SessionClock,
    ) -> Result<SessionStep, AccountError> {
        self.driven(engine, &clock, |e, c, k| e.link_down(c, k))
    }
    /// Bytes received from a carrier, exactly as the sender sealed them. A frame that fails any
    /// §S3 check changes nothing and is reported in `dropped`. Refused (the frame not judged:
    /// keep it and deliver it again) while a `Persist` is unacknowledged or the view is stale.
    pub fn receive(
        &self,
        bytes: Vec<u8>,
        engine: &AccountEngine,
        clock: SessionClock,
    ) -> Result<SessionStep, AccountError> {
        bytes_ok(&bytes, MAX_FRAME_ARG, "a session frame")?;
        self.driven(engine, &clock, |e, c, k| e.receive(&bytes, c, k))
    }
    /// The host stored the `Persist` whose acknowledgement ID is `ack` (the step's
    /// `awaiting_persist`): the effects held behind it, again up to and including the next
    /// `Persist`. Any other ID, or one already acknowledged, is `session:wrongAck`.
    pub fn persisted(&self, ack: u64) -> Result<SessionStep, AccountError> {
        guard(|| {
            let mut s = self.s.lock()?;
            match &s.held {
                Some(h) if h.ack == ack => {}
                _ => {
                    return Err(AccountError::WrongObject {
                        code: "session:wrongAck".into(),
                        detail: "no Persist with this acknowledgement ID is waiting".into(),
                    })
                }
            }
            let rest = s.held.take().map(|h| h.rest).unwrap_or_default();
            s.release(rest, None)
        })
    }
    /// The acknowledgement ID of the `Persist` waiting for `persisted`, if any.
    pub fn awaiting_persist(&self) -> Result<Option<u64>, AccountError> {
        guard(|| Ok(self.s.lock()?.held.as_ref().map(|h| h.ack)))
    }
    /// When to call `tick` next (monotonic ms), if ever.
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
    fn session_account_inner(&self, at_ms: i64) -> R<SessionAccountView> {
        self.acct(|a| {
            Ok(SessionAccountView {
                v: a.session_account(at_ms),
                stamp: Some((self.owner, a.head().0)),
            })
        })
    }
}
#[cfg(feature = "native05")]
#[uniffi::export]
impl AccountEngine {
    /// The session view of the verified history at `at_ms` (wall clock): every member current
    /// then, with its session number and `records` entries, stamped with this engine's
    /// authority head.
    pub fn session_account(
        &self,
        at_ms: i64,
    ) -> Result<std::sync::Arc<SessionAccountView>, AccountError> {
        self.session_account_inner(at_ms).map(std::sync::Arc::new)
    }
}
#[cfg(feature = "web05")]
#[wasm_bindgen::prelude::wasm_bindgen]
impl AccountEngine {
    /// The session view of the verified history at `at_ms` (wall clock), stamped with this
    /// engine's authority head.
    pub fn session_account(&self, at_ms: i64) -> Result<SessionAccountView, AccountError> {
        self.session_account_inner(at_ms)
    }
}

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
