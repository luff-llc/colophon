//! 0.6 sessions (`spec/colophon-0.6-sessions.md`, wire in `docs/colophon-0.6-sessions-wire.md`):
//! the core's sans-IO `Endpoint` behind a handle, plus the objects it reads.
//!
//! * `SessionEndpoint`: one member of one cell, from wire bytes to application events and back.
//!   Every call returns a `SessionStep`: the effects in the order the host carries them out.
//! * `SessionAccountView`: the account view the endpoint verifies against. An application takes
//!   it from its engine (`AccountEngine.session_account`) after every pass that accepted a new
//!   authority head, and gives it to `set_account` before delivering any frame received after.
//! * `SessionEpochs`: the namespace epoch keys frames are sealed and opened under. An application
//!   takes a copy from its engine (`AccountEngine.session_epochs`), which holds the keys it
//!   unlocked; the bytes stay in Rust, as every epoch key does. `with_keys` builds one from
//!   supplied bytes for conformance vectors and tests only.
//! * `SessionMachine` and `SessionWireReceiver`: the state machine and the receiving codec on
//!   their own, so a host can replay `conformance/0.6-sessions/` (machine transcripts over
//!   plaintext frames) and `conformance/0.6-sessions/wire/` (sealed frames against a receiver).
//!   They are not for applications: the receiver does not bound itself (the endpoint bounds it
//!   by the machine's keys), and the machine seals nothing.
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
use colophon_core::v05::terms::Access;
use colophon_core::v06::session::codec::{CellId, Dropped, EpochTable, Receiver, SealError};
use colophon_core::v06::session::endpoint::{Clock, Effect, Endpoint, EndpointError, Step};
use colophon_core::v06::session::keys::{KeyError, SessionAccount};
use colophon_core::v06::session::wire::encode_body;
use colophon_core::v06::session::{Command, Fixes, Input, Persisted, Policy, Session};
use serde_json::Value;

/// The largest JSON argument: a command or input carries at most one frame or snapshot.
const MAX_SESSION_JSON: usize = 256 << 10;
/// The largest frame taken from a carrier (the core drops anything over 16,384 bytes; a larger
/// argument is refused before it is copied).
const MAX_FRAME_ARG: usize = 1 << 20;
/// The most members in a supplied view.
const MAX_MEMBERS: usize = 4_096;

/// Decode `text` as `$t` strictly: it must read back to exactly the JSON given.
macro_rules! strict {
    ($t:ty, $text:expr, $what:expr) => {{
        let (text, what): (&str, &str) = ($text, $what);
        (|| -> R<$t> {
            bytes_ok(text.as_bytes(), MAX_SESSION_JSON, what)?;
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

fn persisted_in(p: Option<String>) -> R<Option<Persisted>> {
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
fn drop_out(d: &Dropped) -> SessionDrop {
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
fn step_out(s: Step) -> R<SessionStep> {
    Ok(SessionStep {
        dropped: s.dropped.as_ref().map(drop_out),
        effects: s.effects.into_iter().map(effect_out).collect::<R<_>>()?,
    })
}

// --- The account view ---------------------------------------------------------------------------

/// The members of one account that are current at the host's accepted authority head (§S1,
/// §S2). Immutable: a new head is a new view.
#[cfg_attr(feature = "native05", derive(uniffi::Object))]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub struct SessionAccountView {
    pub(crate) v: SessionAccount,
}
impl SessionAccountView {
    fn supplied_inner(account: String, members: Vec<SessionMemberEntry>) -> R<Self> {
        guard(|| {
            if account.len() != 64 || !account.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(AccountError::bad("an account ID is 64 hex characters"));
            }
            if members.len() > MAX_MEMBERS {
                return Err(AccountError::bound("a view names too many members"));
            }
            let mut v = SessionAccount::new(&account);
            for m in members {
                if m.signing.len() != 65 || m.signing[0] != 4 {
                    return Err(AccountError::bad(
                        "a signing point is 65 bytes, uncompressed",
                    ));
                }
                list_len(&m.records, "a member's records")?;
                let records: Vec<(String, Access)> = m
                    .records
                    .into_iter()
                    .map(|r| {
                        let a = match r.access {
                            SessionAccess::Read => Access::Read,
                            SessionAccess::Write => Access::Write,
                        };
                        (r.namespace, a)
                    })
                    .collect();
                let refs: Vec<(&str, Access)> =
                    records.iter().map(|(n, a)| (n.as_str(), *a)).collect();
                v = v.with_member(&m.signing, m.session, m.expires_ms, &refs);
            }
            Ok(Self { v })
        })
    }
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
#[cfg(feature = "native05")]
#[uniffi::export]
impl SessionAccountView {
    /// A view from supplied members, for conformance vectors and tests. An application takes
    /// its view from its engine (`AccountEngine.session_account`).
    #[uniffi::constructor]
    pub fn supplied(
        account: String,
        members: Vec<SessionMemberEntry>,
    ) -> Result<std::sync::Arc<Self>, AccountError> {
        Self::supplied_inner(account, members).map(std::sync::Arc::new)
    }
}
#[cfg(feature = "web05")]
#[wasm_bindgen::prelude::wasm_bindgen]
impl SessionAccountView {
    /// A view from supplied members, for conformance vectors and tests.
    pub fn supplied(
        account: String,
        members: Vec<SessionMemberEntry>,
    ) -> Result<SessionAccountView, AccountError> {
        Self::supplied_inner(account, members)
    }
}

// --- Epoch keys ---------------------------------------------------------------------------------

/// Namespace epoch keys for one cell's endpoint, held in Rust and wiped when dropped. The host
/// never reads them back.
#[cfg_attr(feature = "native05", derive(uniffi::Object))]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub struct SessionEpochs {
    pub(crate) t: EpochTable,
    namespace: String,
}
impl SessionEpochs {
    fn with_keys_inner(namespace: String, keys: Vec<SessionEpochKey>) -> R<Self> {
        let mut keys = keys;
        let r = guard(|| {
            if !colophon_core::v05::terms::valid_namespace(&namespace) {
                return Err(AccountError::bad("invalid namespace"));
            }
            list_len(&keys, "the epoch keys")?;
            let mut t = EpochTable::new();
            for k in keys.iter() {
                t = t.with(&namespace, k.epoch, fixed::<32>(&k.key, "an epoch key")?);
            }
            Ok(Self {
                t,
                namespace: namespace.clone(),
            })
        });
        for k in keys.iter_mut() {
            wipe(&mut k.key);
        }
        r
    }
}
#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
impl SessionEpochs {
    /// The namespace these keys are for.
    pub fn namespace(&self) -> String {
        self.namespace.clone()
    }
    /// The newest epoch held (frames are sealed under it), if any.
    pub fn current_epoch(&self) -> Option<u64> {
        use colophon_core::v06::session::codec::EpochKeys;
        self.t.current_epoch(&self.namespace)
    }
}
#[cfg(feature = "native05")]
#[uniffi::export]
impl SessionEpochs {
    /// Keys from supplied bytes (32 each, wiped once read), for conformance vectors and tests.
    /// An application takes its keys from its engine (`AccountEngine.session_epochs`).
    #[uniffi::constructor]
    pub fn with_keys(
        namespace: String,
        keys: Vec<SessionEpochKey>,
    ) -> Result<std::sync::Arc<Self>, AccountError> {
        Self::with_keys_inner(namespace, keys).map(std::sync::Arc::new)
    }
}
#[cfg(feature = "web05")]
#[wasm_bindgen::prelude::wasm_bindgen]
impl SessionEpochs {
    /// Keys from supplied bytes (32 each, wiped once read), for conformance vectors and tests.
    pub fn with_keys(
        namespace: String,
        keys: Vec<SessionEpochKey>,
    ) -> Result<SessionEpochs, AccountError> {
        Self::with_keys_inner(namespace, keys)
    }
}

// --- The endpoint -------------------------------------------------------------------------------

/// One member of one cell, with sealing. Calls are serialized (one at a time, as §6 of the wire
/// document requires): a second thread waits for the first.
#[cfg_attr(feature = "native05", derive(uniffi::Object))]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub struct SessionEndpoint {
    e: Cell<Endpoint>,
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
                Ok(e) => Ok(Self { e: Cell::new(e) }),
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
}
#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
impl SessionEndpoint {
    /// The exact `colophon/session-key/6` body for the host to sign with this member's key, as
    /// it signs a `Raw` signing step (P-256, `r||s`), for the window `[not_before_ms,
    /// expires_ms]` (at most 86,400 s). Nothing can be sent before the signature is installed;
    /// call again to renew before the window ends.
    pub fn begin_delegation(
        &self,
        not_before_ms: i64,
        expires_ms: i64,
    ) -> Result<Vec<u8>, AccountError> {
        guard(|| {
            self.e
                .lock()?
                .begin_delegation(not_before_ms, expires_ms)
                .map_err(key_error)
        })
    }
    /// Install the host's signature over a body from `begin_delegation`, after verifying it
    /// under this member's key in the account view.
    pub fn finish_delegation(
        &self,
        body: Vec<u8>,
        signature: Vec<u8>,
        clock: SessionClock,
    ) -> Result<(), AccountError> {
        guard(|| {
            bytes_ok(&body, 1_024, "a delegation body")?;
            bytes_ok(&signature, 128, "a signature")?;
            self.e
                .lock()?
                .finish_delegation(&body, &signature, clock_in(&clock))
                .map_err(|why| AccountError::Malformed {
                    code: "session:delegation".into(),
                    detail: why.chars().take(512).collect(),
                })
        })
    }
    /// A newly accepted authority head: give its view before delivering any frame received
    /// after the host accepted it.
    pub fn set_account(
        &self,
        view: &SessionAccountView,
        epochs: &SessionEpochs,
        clock: SessionClock,
    ) -> Result<SessionStep, AccountError> {
        guard(|| {
            step_out(
                self.e
                    .lock()?
                    .set_account(view.v.clone(), clock_in(&clock), &epochs.t),
            )
        })
    }
    /// An application command (§S10), as JSON tagged by `command`.
    pub fn command(
        &self,
        command_json: String,
        epochs: &SessionEpochs,
        clock: SessionClock,
    ) -> Result<SessionStep, AccountError> {
        guard(|| {
            let c: Command = strict!(Command, &command_json, "the session command")?;
            step_out(self.e.lock()?.command(c, clock_in(&clock), &epochs.t))
        })
    }
    /// A timer expiry: call at or soon after `next_deadline` (within 250 ms).
    pub fn tick(
        &self,
        epochs: &SessionEpochs,
        clock: SessionClock,
    ) -> Result<SessionStep, AccountError> {
        guard(|| step_out(self.e.lock()?.tick(clock_in(&clock), &epochs.t)))
    }
    /// Some carrier works again.
    pub fn link_up(
        &self,
        epochs: &SessionEpochs,
        clock: SessionClock,
    ) -> Result<SessionStep, AccountError> {
        guard(|| step_out(self.e.lock()?.link_up(clock_in(&clock), &epochs.t)))
    }
    /// No carrier works.
    pub fn link_down(
        &self,
        epochs: &SessionEpochs,
        clock: SessionClock,
    ) -> Result<SessionStep, AccountError> {
        guard(|| step_out(self.e.lock()?.link_down(clock_in(&clock), &epochs.t)))
    }
    /// Bytes received from a carrier, exactly as the sender sealed them. A frame that fails any
    /// §S3 check changes nothing and is reported in `dropped`.
    pub fn receive(
        &self,
        bytes: Vec<u8>,
        epochs: &SessionEpochs,
        clock: SessionClock,
    ) -> Result<SessionStep, AccountError> {
        guard(|| {
            bytes_ok(&bytes, MAX_FRAME_ARG, "a session frame")?;
            step_out(self.e.lock()?.receive(&bytes, clock_in(&clock), &epochs.t))
        })
    }
    /// When to call `tick` next (monotonic ms), if ever.
    pub fn next_deadline(&self) -> Result<Option<u64>, AccountError> {
        guard(|| Ok(self.e.lock()?.next_deadline()))
    }
    /// This member.
    pub fn me(&self) -> Result<String, AccountError> {
        guard(|| Ok(self.e.lock()?.me().to_string()))
    }
    /// The session key's ID (a key ID of its point).
    pub fn key_id(&self) -> Result<String, AccountError> {
        guard(|| Ok(self.e.lock()?.key_id().to_string()))
    }
    /// The highest `n` sealed so far.
    pub fn last_n(&self) -> Result<u64, AccountError> {
        guard(|| Ok(self.e.lock()?.last_n()))
    }
    /// Whether this member holds a `records` entry for the namespace (it may send).
    pub fn entitled(&self) -> Result<bool, AccountError> {
        guard(|| Ok(self.e.lock()?.entitled()))
    }
    /// Whether this member may write (§S1), as last set.
    pub fn can_write(&self) -> Result<bool, AccountError> {
        guard(|| Ok(self.e.lock()?.machine().can_write()))
    }
    /// Whether the member has joined.
    pub fn joined(&self) -> Result<bool, AccountError> {
        guard(|| Ok(self.e.lock()?.machine().joined()))
    }
    /// The holder this member sees, if any.
    pub fn holder(&self) -> Result<Option<String>, AccountError> {
        guard(|| Ok(self.e.lock()?.machine().holder().map(str::to_string)))
    }
    /// Whether this member acts as holder.
    pub fn is_holder(&self) -> Result<bool, AccountError> {
        guard(|| Ok(self.e.lock()?.machine().is_holder()))
    }
    /// The greatest accepted claim as JSON (`{term, rank, holder, via?}`), if any.
    pub fn claim_json(&self) -> Result<Option<String>, AccountError> {
        guard(|| {
            self.e
                .lock()?
                .machine()
                .accepted()
                .map(|v| json_out!(v))
                .transpose()
        })
    }
    /// The protocol-visible state as JSON (`{accepted, holder, holding, gated, synced, seq,
    /// state}`, as in the vectors' `final`). It carries application state: do not log it.
    pub fn view_json(&self) -> Result<String, AccountError> {
        guard(|| json_out!(&self.e.lock()?.machine().view()))
    }
    /// SHA-256 hex of `view_json` as the reference writes it.
    pub fn digest(&self) -> Result<String, AccountError> {
        guard(|| Ok(self.e.lock()?.machine().digest()))
    }
}
#[cfg(feature = "native05")]
#[uniffi::export]
impl SessionEndpoint {
    /// Start a session for member `me` in `(account, namespace, cell)` under `policy_json` (the
    /// §S1 policy as JSON; `session_default_policy` gives the defaults), resuming from
    /// `persisted_json` (the last `Persist` effect's, or none). `key_random` (32 bytes) makes the
    /// session key and `fresh_seed` (16 bytes) seeds the machine's challenges: both must be new
    /// random bytes on every process start, and both are wiped. A policy out of bounds is
    /// `session:policy`; a member not entitled to the namespace is `denied:notGranted`.
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
            })
        })
    }
    fn session_epochs_inner(&self, namespace: String) -> R<SessionEpochs> {
        if !colophon_core::v05::terms::valid_namespace(&namespace) {
            return Err(AccountError::bad("invalid namespace"));
        }
        self.ensure_live()?;
        self.acct(|a| {
            Ok(SessionEpochs {
                t: a.session_epochs(&namespace),
                namespace: namespace.clone(),
            })
        })
    }
}
#[cfg(feature = "native05")]
#[uniffi::export]
impl AccountEngine {
    /// The session view of the verified history at `at_ms` (wall clock): every member current
    /// then, with its session number and `records` entries.
    pub fn session_account(
        &self,
        at_ms: i64,
    ) -> Result<std::sync::Arc<SessionAccountView>, AccountError> {
        self.session_account_inner(at_ms).map(std::sync::Arc::new)
    }
    /// A copy, held in Rust, of the epoch keys this engine holds for `namespace`, for a session
    /// endpoint. Take a new one after an unlock or a rekey. `Locked` once the engine is locked.
    pub fn session_epochs(
        &self,
        namespace: String,
    ) -> Result<std::sync::Arc<SessionEpochs>, AccountError> {
        self.session_epochs_inner(namespace)
            .map(std::sync::Arc::new)
    }
}
#[cfg(feature = "web05")]
#[wasm_bindgen::prelude::wasm_bindgen]
impl AccountEngine {
    /// The session view of the verified history at `at_ms` (wall clock).
    pub fn session_account(&self, at_ms: i64) -> Result<SessionAccountView, AccountError> {
        self.session_account_inner(at_ms)
    }
    /// A copy, held in Rust, of the epoch keys this engine holds for `namespace`.
    pub fn session_epochs(&self, namespace: String) -> Result<SessionEpochs, AccountError> {
        self.session_epochs_inner(namespace)
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

// --- Conformance: the machine and the receiver on their own -------------------------------------

/// The session state machine of one member over plaintext frames, for replaying
/// `conformance/0.6-sessions/`. Not for applications: it seals and verifies nothing.
#[cfg_attr(feature = "native05", derive(uniffi::Object))]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub struct SessionMachine {
    s: Cell<Session>,
}
impl SessionMachine {
    fn new_inner(
        me: String,
        can_write: bool,
        policy_json: String,
        persisted_json: Option<String>,
        fixes_json: Option<String>,
        fresh_seed: Option<Vec<u8>>,
    ) -> R<Self> {
        guard(|| {
            let policy: Policy = strict!(Policy, &policy_json, "the cell policy")?;
            let persisted = persisted_in(persisted_json)?;
            let fixes = match fixes_json {
                Some(f) => strict!(Fixes, &f, "the fixes")?,
                None => Fixes::default(),
            };
            let mut s = Session::with_fixes(&me, can_write, policy, persisted, fixes);
            if let Some(seed) = fresh_seed {
                s = s.with_fresh_seed(fixed::<16>(&seed, "the fresh seed")?);
            }
            Ok(Self { s: Cell::new(s) })
        })
    }
}
#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
impl SessionMachine {
    /// One input (JSON tagged by `input`) at `at` (this member's monotonic ms): the outputs, in
    /// order, as a JSON array tagged by `output`.
    pub fn handle(&self, input_json: String, at: u64) -> Result<String, AccountError> {
        guard(|| {
            let input: Input = strict!(Input, &input_json, "the session input")?;
            let outs = self.s.lock()?.handle(input, at);
            json_out!(&outs)
        })
    }
    /// What this member would persist (`{claim, released}`), if anything: a restart rebuilds the
    /// machine from it.
    pub fn persisted_json(&self) -> Result<Option<String>, AccountError> {
        guard(|| {
            self.s
                .lock()?
                .persisted()
                .as_ref()
                .map(|v| json_out!(v))
                .transpose()
        })
    }
    /// The protocol-visible state as JSON (the vectors' `final[].view`).
    pub fn view_json(&self) -> Result<String, AccountError> {
        guard(|| json_out!(&self.s.lock()?.view()))
    }
    /// SHA-256 hex of the view (the vectors' `final[].digest`).
    pub fn digest(&self) -> Result<String, AccountError> {
        guard(|| Ok(self.s.lock()?.digest()))
    }
    /// When to give the next `tick` (monotonic ms), if ever.
    pub fn next_deadline(&self) -> Result<Option<u64>, AccountError> {
        guard(|| Ok(self.s.lock()?.next_deadline()))
    }
}
#[cfg(feature = "native05")]
#[uniffi::export]
impl SessionMachine {
    /// A member before `join`, as a vector's `members[]` entry describes it: `fixes_json` the
    /// file's `fixes` (none: the reference reading), `fresh_seed` its 16-byte `freshSeed`.
    #[uniffi::constructor]
    pub fn new(
        me: String,
        can_write: bool,
        policy_json: String,
        persisted_json: Option<String>,
        fixes_json: Option<String>,
        fresh_seed: Option<Vec<u8>>,
    ) -> Result<std::sync::Arc<Self>, AccountError> {
        Self::new_inner(
            me,
            can_write,
            policy_json,
            persisted_json,
            fixes_json,
            fresh_seed,
        )
        .map(std::sync::Arc::new)
    }
}
#[cfg(feature = "web05")]
#[wasm_bindgen::prelude::wasm_bindgen]
impl SessionMachine {
    /// A member before `join`, as a vector's `members[]` entry describes it.
    #[wasm_bindgen::prelude::wasm_bindgen(constructor)]
    pub fn new(
        me: String,
        can_write: bool,
        policy_json: String,
        persisted_json: Option<String>,
        fixes_json: Option<String>,
        fresh_seed: Option<Vec<u8>>,
    ) -> Result<SessionMachine, AccountError> {
        Self::new_inner(
            me,
            can_write,
            policy_json,
            persisted_json,
            fixes_json,
            fresh_seed,
        )
    }
}

/// The receiving codec of one member in one cell on its own (§S3 steps 1–7), for replaying
/// `conformance/0.6-sessions/wire/`. Not for applications: it keeps every key it accepts until
/// a view drops it, where `SessionEndpoint` keeps only the keys its machine knows.
#[cfg_attr(feature = "native05", derive(uniffi::Object))]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub struct SessionWireReceiver {
    r: Cell<Receiver>,
}
impl SessionWireReceiver {
    fn new_inner(account: String, namespace: String, cell: String, me: String) -> Self {
        Self {
            r: Cell::new(Receiver::new(CellId::new(&account, &namespace, &cell), &me)),
        }
    }
}
#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
impl SessionWireReceiver {
    /// Judge one frame at `wall_ms` against `view`, `epochs` and the cell's `max_payload`.
    pub fn open(
        &self,
        bytes: Vec<u8>,
        view: &SessionAccountView,
        epochs: &SessionEpochs,
        wall_ms: i64,
        max_payload: u64,
    ) -> Result<SessionOpenResult, AccountError> {
        guard(|| {
            bytes_ok(&bytes, MAX_FRAME_ARG, "a session frame")?;
            let got = self
                .r
                .lock()?
                .open(&bytes, &view.v, wall_ms, &epochs.t, max_payload);
            Ok(match got {
                Ok(o) => SessionOpenResult {
                    opened: Some(SessionOpened {
                        plaintext: encode_body(&o.frame.body).map_err(|_| {
                            AccountError::internal("an opened body could not be encoded")
                        })?,
                        from: o.frame.from,
                        to: o.frame.to,
                        writer: o.writer,
                        key: o.key,
                        n: o.n,
                        epoch: o.epoch,
                    }),
                    dropped: None,
                },
                Err(d) => SessionOpenResult {
                    opened: None,
                    dropped: Some(drop_out(&d)),
                },
            })
        })
    }
    /// A newly accepted authority head: what it removed.
    pub fn set_account(
        &self,
        view: &SessionAccountView,
        wall_ms: i64,
    ) -> Result<SessionForgotten, AccountError> {
        guard(|| {
            let g = self.r.lock()?.set_account(&view.v, wall_ms);
            Ok(SessionForgotten {
                members: g.members,
                keys: g
                    .keys
                    .into_iter()
                    .map(|(member, key)| SessionKeyRef { member, key })
                    .collect(),
            })
        })
    }
    /// The session keys held now, sorted.
    pub fn keys(&self) -> Result<Vec<SessionKeyRef>, AccountError> {
        guard(|| {
            Ok(self
                .r
                .lock()?
                .key_set()
                .into_iter()
                .map(|(member, key)| SessionKeyRef { member, key })
                .collect())
        })
    }
    /// The highest `n` accepted for `(member, key)`, if the key is held.
    pub fn window_high(&self, member: String, key: String) -> Result<Option<u64>, AccountError> {
        guard(|| Ok(self.r.lock()?.window(&member, &key).map(|w| w.high())))
    }
}
#[cfg(feature = "native05")]
#[uniffi::export]
impl SessionWireReceiver {
    /// A receiver for member `me` in `(account, namespace, cell)`.
    #[uniffi::constructor]
    pub fn new(
        account: String,
        namespace: String,
        cell: String,
        me: String,
    ) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self::new_inner(account, namespace, cell, me))
    }
}
#[cfg(feature = "web05")]
#[wasm_bindgen::prelude::wasm_bindgen]
impl SessionWireReceiver {
    /// A receiver for member `me` in `(account, namespace, cell)`.
    #[wasm_bindgen::prelude::wasm_bindgen(constructor)]
    pub fn new(
        account: String,
        namespace: String,
        cell: String,
        me: String,
    ) -> SessionWireReceiver {
        Self::new_inner(account, namespace, cell, me)
    }
}
