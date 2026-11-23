//! The conformance surface of 0.6 sessions, compiled only with the `conformance` feature (off by
//! default; never enabled in a shipped artifact). It lets a host replay
//! `conformance/0.6-sessions/` and `conformance/0.6-sessions/wire/` against the core: the state
//! machine over plaintext frames (`SessionMachine`), the receiving codec on its own
//! (`SessionWireReceiver`), a view built from supplied members (`SessionAccountView.supplied`)
//! and epoch keys supplied as bytes (`SessionEpochs.with_keys`). Each of these bypasses a trust
//! boundary an application relies on (the verified history, the engine-held keys, the endpoint's
//! bound on cached keys), which is why a release build does not contain them.
use super::fault::AccountError;
use super::sessions::{drop_out, persisted_in, SessionAccountView, MAX_FRAME_ARG};
use super::types::*;
use super::{guard, Cell};
use colophon_core::v05::terms::Access;
use colophon_core::v06::session::codec::{CellId, EpochTable, Receiver};
use colophon_core::v06::session::keys::SessionAccount;
use colophon_core::v06::session::wire::encode_body;
use colophon_core::v06::session::{Fixes, Input, Policy, Session};
use serde_json::Value;

/// The most members in a supplied view.
const MAX_MEMBERS: usize = 4_096;

cenum! {
    /// A member's `records` access to a namespace (§S1).
    pub enum SessionAccess { Read, Write }
}

record! {
    /// One `records` entry of a member in a session account view.
    pub struct SessionRecordEntry { pub namespace: String, pub access: SessionAccess }
}

record! {
    /// A member as a session verifier sees it: its signing point (65 bytes), session number,
    /// expiry and `records` entries. For conformance vectors and tests; an application takes
    /// its view from its engine (`session_account`).
    pub struct SessionMemberEntry {
        pub signing: Vec<u8>,
        pub session: u64,
        pub expires_ms: Option<i64>,
        pub records: Vec<SessionRecordEntry>,
    }
}

secret_record! {
    /// One epoch key supplied for conformance vectors and tests (32 bytes, wiped once read).
    pub struct SessionEpochKey { pub epoch: u64, pub key: Vec<u8> }
}

record! {
    /// A frame that passed every §S3 check (conformance receiver): its canonical plaintext, the
    /// sender, `to`, whether the sender may write, its session key, `n` and epoch.
    pub struct SessionOpened {
        pub plaintext: Vec<u8>,
        pub from: String,
        pub to: Option<String>,
        pub writer: bool,
        pub key: String,
        pub n: u64,
        pub epoch: u64,
    }
}

record! {
    /// The conformance receiver's judgement of one frame: exactly one of the two is set.
    pub struct SessionOpenResult { pub opened: Option<SessionOpened>, pub dropped: Option<SessionDrop> }
}

record! {
    /// A member's session key.
    pub struct SessionKeyRef { pub member: String, pub key: String }
}

record! {
    /// What a new account view removed from a conformance receiver (§S2).
    pub struct SessionForgotten { pub members: Vec<String>, pub keys: Vec<SessionKeyRef> }
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
            Ok(Self { v, stamp: None })
        })
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

/// Namespace epoch keys supplied as bytes, for the conformance receiver: held in Rust, wiped
/// when dropped, never read back.
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
