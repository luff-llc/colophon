//! The 0.6 session conformance surface, shared by `colophon-conformance` (UniFFI, `native05`)
//! and `colophon-conformance-wasm` (wasm-bindgen, `web05`).
//!
//! It lets a host replay `conformance/0.6-sessions/` and `conformance/0.6-sessions/wire/`
//! against the core: the state machine over plaintext frames (`ConformanceMachine`), the
//! receiving codec on its own (`ConformanceReceiver`), the sending side's key and delegation
//! (`ConformanceSender`), an account view built from supplied members (`ConformanceView`) and
//! epoch keys supplied as bytes (`ConformanceEpochs`). Each bypasses a trust boundary an
//! application relies on (the verified history, the engine-held keys, the endpoint's bound on
//! cached keys and its enforced orders), so none of it is in the shipping crates. These crates
//! are unpublished and nothing shipped depends on them; a host's conformance tests link them.
//!
//! The surface uses only the core's public API; it needs nothing private from the shipping
//! crates. Errors are `ConformanceError` with the same codes the shipping surface uses.
#![allow(missing_docs, clippy::too_many_arguments)]

use colophon_core::v05::terms::Access;
use colophon_core::v06::session::codec::{
    CellId, Dropped, EpochKeys, EpochTable, Receiver, Sender,
};
use colophon_core::v06::session::keys::{SessionAccount, SessionKey};
use colophon_core::v06::session::wire::encode_body;
use colophon_core::v06::session::{Fixes, Input, Persisted, Policy, Session};
use serde_json::Value;
use std::sync::Mutex;

macro_rules! record {
    ($(#[$m:meta])* pub struct $n:ident { $( $(#[$fm:meta])* pub $f:ident : $t:ty ),* $(,)? }) => {
        $(#[$m])*
        #[cfg_attr(feature = "web05", derive(Clone))]
        #[cfg_attr(feature = "native05", derive(uniffi::Record))]
        #[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen(getter_with_clone))]
        pub struct $n { $( $(#[$fm])* pub $f: $t ),* }
        #[cfg(feature = "web05")]
        #[wasm_bindgen::prelude::wasm_bindgen]
        impl $n {
            /// Every field, in order.
            #[wasm_bindgen::prelude::wasm_bindgen(constructor)]
            pub fn new($($f: $t),*) -> $n { $n { $($f),* } }
        }
    };
}
macro_rules! secret_record {
    ($(#[$m:meta])* pub struct $n:ident { $( $(#[$fm:meta])* pub $f:ident : $t:ty ),* $(,)? }) => {
        $(#[$m])*
        #[cfg_attr(feature = "native05", derive(uniffi::Record))]
        #[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen(getter_with_clone))]
        pub struct $n { $( $(#[$fm])* pub $f: $t ),* }
        #[cfg(feature = "web05")]
        #[wasm_bindgen::prelude::wasm_bindgen]
        impl $n {
            /// Every field, in order.
            #[wasm_bindgen::prelude::wasm_bindgen(constructor)]
            pub fn new($($f: $t),*) -> $n { $n { $($f),* } }
        }
    };
}
macro_rules! cenum {
    ($(#[$m:meta])* pub enum $n:ident { $( $(#[$vm:meta])* $v:ident ),* $(,)? }) => {
        $(#[$m])*
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        #[cfg_attr(feature = "native05", derive(uniffi::Enum))]
        #[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
        pub enum $n { $( $(#[$vm])* $v ),* }
    };
}

/// A failed conformance call: `code` as the shipping surface spells it, `detail` for logs.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "native05", derive(uniffi::Error))]
pub enum ConformanceError {
    Failed { code: String, detail: String },
}
impl ConformanceError {
    fn new(code: &str, detail: impl Into<String>) -> Self {
        Self::Failed {
            code: code.into(),
            detail: detail.into().chars().take(512).collect(),
        }
    }
    /// The code (`malformed`, `bound`, `internal`, `session:policy`, ...).
    pub fn code(&self) -> String {
        match self {
            Self::Failed { code, .. } => code.clone(),
        }
    }
    /// The detail, for logs.
    pub fn detail(&self) -> String {
        match self {
            Self::Failed { detail, .. } => detail.clone(),
        }
    }
}
impl std::fmt::Display for ConformanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code(), self.detail())
    }
}
impl std::error::Error for ConformanceError {}

type R<T> = Result<T, ConformanceError>;

fn bad(what: &str) -> ConformanceError {
    ConformanceError::new("malformed", format!("{what} is not valid"))
}
fn bound(what: &str) -> ConformanceError {
    ConformanceError::new("bound", what)
}
fn fixed<const N: usize>(b: &[u8], what: &str) -> R<[u8; N]> {
    b.try_into()
        .map_err(|_| bound(&format!("{what} must be exactly {N} bytes")))
}
fn wipe(v: &mut [u8]) {
    v.fill(0);
    std::hint::black_box(&*v);
}
/// No panic crosses the boundary.
fn guard<T>(f: impl FnOnce() -> R<T>) -> R<T> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f))
        .unwrap_or_else(|_| Err(ConformanceError::new("internal", "an internal error")))
}
fn lock<T>(m: &Mutex<T>) -> R<std::sync::MutexGuard<'_, T>> {
    m.lock()
        .map_err(|_| ConformanceError::new("internal", "an earlier call panicked"))
}

/// The largest JSON argument.
const MAX_JSON: usize = 256 << 10;
/// The largest frame argument.
const MAX_FRAME: usize = 1 << 20;
/// The most members in a supplied view.
const MAX_MEMBERS: usize = 4_096;

/// Decode `text` as `$t` strictly: it must read back to exactly the JSON given.
macro_rules! strict {
    ($t:ty, $text:expr, $what:expr) => {{
        let (text, what): (&str, &str) = ($text, $what);
        (|| -> R<$t> {
            if text.len() > MAX_JSON {
                return Err(bound(&format!("{what} is too large")));
            }
            let given: Value = serde_json::from_str(text).map_err(|_| bad(what))?;
            let v: $t = serde_json::from_value(given.clone()).map_err(|_| bad(what))?;
            let back = serde_json::to_value(&v).map_err(|_| bad(what))?;
            if back != given {
                return Err(bad(what));
            }
            Ok(v)
        })()
    }};
}
macro_rules! json_out {
    ($v:expr) => {
        serde_json::to_string($v)
            .map_err(|_| ConformanceError::new("internal", "a result could not be written"))
    };
}

fn persisted_in(p: Option<String>) -> R<Option<Persisted>> {
    let Some(p) = p else { return Ok(None) };
    let p: Persisted = strict!(Persisted, &p, "the persisted claim")?;
    if !p.claim.well_formed() {
        return Err(ConformanceError::new(
            "malformed",
            "the persisted claim is not well formed",
        ));
    }
    Ok(Some(p))
}

// --- Records -------------------------------------------------------------------------------------

cenum! {
    /// A member's `records` access to a namespace (§S1).
    pub enum ConformanceAccess { Read, Write }
}
record! {
    /// One `records` entry of a supplied member.
    pub struct ConformanceRecordEntry { pub namespace: String, pub access: ConformanceAccess }
}
record! {
    /// A supplied member: its signing point (65 bytes), session number, expiry and entries.
    pub struct ConformanceMember {
        pub signing: Vec<u8>,
        pub session: u64,
        pub expires_ms: Option<i64>,
        pub records: Vec<ConformanceRecordEntry>,
    }
}
secret_record! {
    /// One supplied epoch key (32 bytes, wiped once read).
    pub struct ConformanceEpochKey { pub epoch: u64, pub key: Vec<u8> }
}
record! {
    /// A dropped frame: the §S3 code and the member a `hello` is owed to, if any.
    pub struct ConformanceDrop { pub reason: String, pub hello_to: Option<String> }
}
record! {
    /// A frame that passed every §S3 check: its canonical plaintext and the inputs the machine
    /// takes.
    pub struct ConformanceOpened {
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
    /// The receiver's judgement of one frame: exactly one of the two is set.
    pub struct ConformanceOpenResult { pub opened: Option<ConformanceOpened>, pub dropped: Option<ConformanceDrop> }
}
record! {
    /// A member's session key.
    pub struct ConformanceKeyRef { pub member: String, pub key: String }
}
record! {
    /// What a new account view removed from a receiver (§S2).
    pub struct ConformanceForgotten { pub members: Vec<String>, pub keys: Vec<ConformanceKeyRef> }
}

fn drop_out(d: &Dropped) -> ConformanceDrop {
    ConformanceDrop {
        reason: d.reason.code().into(),
        hello_to: d.hello_to.clone(),
    }
}

// --- A supplied view ------------------------------------------------------------------------------

/// An account view from supplied members.
#[cfg_attr(feature = "native05", derive(uniffi::Object))]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub struct ConformanceView {
    v: SessionAccount,
}
impl ConformanceView {
    fn new_inner(account: String, members: Vec<ConformanceMember>) -> R<Self> {
        guard(|| {
            if account.len() != 64 || !account.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(ConformanceError::new(
                    "malformed",
                    "an account ID is 64 hex characters",
                ));
            }
            if members.len() > MAX_MEMBERS {
                return Err(bound("a view names too many members"));
            }
            let mut v = SessionAccount::new(&account);
            for m in members {
                if m.signing.len() != 65 || m.signing[0] != 4 {
                    return Err(ConformanceError::new(
                        "malformed",
                        "a signing point is 65 bytes, uncompressed",
                    ));
                }
                let records: Vec<(String, Access)> = m
                    .records
                    .into_iter()
                    .map(|r| {
                        let a = match r.access {
                            ConformanceAccess::Read => Access::Read,
                            ConformanceAccess::Write => Access::Write,
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
impl ConformanceView {
    /// The members entitled to write in `namespace` at `wall_ms`, sorted.
    pub fn writers(&self, namespace: String, wall_ms: i64) -> Vec<String> {
        self.v.writers(&namespace, wall_ms)
    }
}
#[cfg(feature = "native05")]
#[uniffi::export]
impl ConformanceView {
    /// A view of `account` with `members`.
    #[uniffi::constructor]
    pub fn new(
        account: String,
        members: Vec<ConformanceMember>,
    ) -> Result<std::sync::Arc<Self>, ConformanceError> {
        Self::new_inner(account, members).map(std::sync::Arc::new)
    }
}
#[cfg(feature = "web05")]
#[wasm_bindgen::prelude::wasm_bindgen]
impl ConformanceView {
    /// A view of `account` with `members`.
    #[wasm_bindgen::prelude::wasm_bindgen(constructor)]
    pub fn new(
        account: String,
        members: Vec<ConformanceMember>,
    ) -> Result<ConformanceView, ConformanceError> {
        Self::new_inner(account, members)
    }
}

// --- Supplied epoch keys --------------------------------------------------------------------------

/// Epoch keys of one namespace supplied as bytes: held in Rust, wiped on drop, never read back.
#[cfg_attr(feature = "native05", derive(uniffi::Object))]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub struct ConformanceEpochs {
    t: EpochTable,
    namespace: String,
}
impl ConformanceEpochs {
    fn new_inner(namespace: String, keys: Vec<ConformanceEpochKey>) -> R<Self> {
        let mut keys = keys;
        let r = guard(|| {
            if !colophon_core::v05::terms::valid_namespace(&namespace) {
                return Err(ConformanceError::new("malformed", "invalid namespace"));
            }
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
impl ConformanceEpochs {
    /// The newest epoch held, if any.
    pub fn current_epoch(&self) -> Option<u64> {
        self.t.current_epoch(&self.namespace)
    }
}
#[cfg(feature = "native05")]
#[uniffi::export]
impl ConformanceEpochs {
    /// Keys for `namespace` from supplied bytes (32 each, wiped once read).
    #[uniffi::constructor]
    pub fn new(
        namespace: String,
        keys: Vec<ConformanceEpochKey>,
    ) -> Result<std::sync::Arc<Self>, ConformanceError> {
        Self::new_inner(namespace, keys).map(std::sync::Arc::new)
    }
}
#[cfg(feature = "web05")]
#[wasm_bindgen::prelude::wasm_bindgen]
impl ConformanceEpochs {
    /// Keys for `namespace` from supplied bytes (32 each, wiped once read).
    #[wasm_bindgen::prelude::wasm_bindgen(constructor)]
    pub fn new(
        namespace: String,
        keys: Vec<ConformanceEpochKey>,
    ) -> Result<ConformanceEpochs, ConformanceError> {
        Self::new_inner(namespace, keys)
    }
}

// --- The machine ----------------------------------------------------------------------------------

/// The session state machine of one member over plaintext frames.
#[cfg_attr(feature = "native05", derive(uniffi::Object))]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub struct ConformanceMachine {
    s: Mutex<Session>,
}
impl ConformanceMachine {
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
            Ok(Self { s: Mutex::new(s) })
        })
    }
}
#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
impl ConformanceMachine {
    /// One input (JSON tagged by `input`) at `at`: the outputs as a JSON array.
    pub fn handle(&self, input_json: String, at: u64) -> Result<String, ConformanceError> {
        guard(|| {
            let input: Input = strict!(Input, &input_json, "the session input")?;
            let outs = lock(&self.s)?.handle(input, at);
            json_out!(&outs)
        })
    }
    /// What this member would persist, if anything.
    pub fn persisted_json(&self) -> Result<Option<String>, ConformanceError> {
        guard(|| {
            lock(&self.s)?
                .persisted()
                .as_ref()
                .map(|v| json_out!(v))
                .transpose()
        })
    }
    /// The protocol-visible state as JSON.
    pub fn view_json(&self) -> Result<String, ConformanceError> {
        guard(|| json_out!(&lock(&self.s)?.view()))
    }
    /// SHA-256 hex of the view.
    pub fn digest(&self) -> Result<String, ConformanceError> {
        guard(|| Ok(lock(&self.s)?.digest()))
    }
    /// When to give the next `tick`, if ever.
    pub fn next_deadline(&self) -> Result<Option<u64>, ConformanceError> {
        guard(|| Ok(lock(&self.s)?.next_deadline()))
    }
}
#[cfg(feature = "native05")]
#[uniffi::export]
impl ConformanceMachine {
    /// A member before `join`, as a vector's `members[]` entry describes it.
    #[uniffi::constructor]
    pub fn new(
        me: String,
        can_write: bool,
        policy_json: String,
        persisted_json: Option<String>,
        fixes_json: Option<String>,
        fresh_seed: Option<Vec<u8>>,
    ) -> Result<std::sync::Arc<Self>, ConformanceError> {
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
impl ConformanceMachine {
    /// A member before `join`, as a vector's `members[]` entry describes it.
    #[wasm_bindgen::prelude::wasm_bindgen(constructor)]
    pub fn new(
        me: String,
        can_write: bool,
        policy_json: String,
        persisted_json: Option<String>,
        fixes_json: Option<String>,
        fresh_seed: Option<Vec<u8>>,
    ) -> Result<ConformanceMachine, ConformanceError> {
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

// --- The receiver ---------------------------------------------------------------------------------

/// The receiving codec of one member in one cell (§S3 steps 1–7), unbounded by a machine.
#[cfg_attr(feature = "native05", derive(uniffi::Object))]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub struct ConformanceReceiver {
    r: Mutex<Receiver>,
}
impl ConformanceReceiver {
    fn new_inner(account: String, namespace: String, cell: String, me: String) -> Self {
        Self {
            r: Mutex::new(Receiver::new(CellId::new(&account, &namespace, &cell), &me)),
        }
    }
}
#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
impl ConformanceReceiver {
    /// Judge one frame at `wall_ms` against `view`, `epochs` and the cell's `max_payload`.
    pub fn open(
        &self,
        bytes: Vec<u8>,
        view: &ConformanceView,
        epochs: &ConformanceEpochs,
        wall_ms: i64,
        max_payload: u64,
    ) -> Result<ConformanceOpenResult, ConformanceError> {
        guard(|| {
            if bytes.len() > MAX_FRAME {
                return Err(bound("a session frame is too large"));
            }
            let got = lock(&self.r)?.open(&bytes, &view.v, wall_ms, &epochs.t, max_payload);
            Ok(match got {
                Ok(o) => ConformanceOpenResult {
                    opened: Some(ConformanceOpened {
                        plaintext: encode_body(&o.frame.body).map_err(|_| {
                            ConformanceError::new("internal", "an opened body could not be encoded")
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
                Err(d) => ConformanceOpenResult {
                    opened: None,
                    dropped: Some(drop_out(&d)),
                },
            })
        })
    }
    /// A newly accepted authority head: what it removed.
    pub fn set_account(
        &self,
        view: &ConformanceView,
        wall_ms: i64,
    ) -> Result<ConformanceForgotten, ConformanceError> {
        guard(|| {
            let g = lock(&self.r)?.set_account(&view.v, wall_ms);
            Ok(ConformanceForgotten {
                members: g.members,
                keys: g
                    .keys
                    .into_iter()
                    .map(|(member, key)| ConformanceKeyRef { member, key })
                    .collect(),
            })
        })
    }
    /// The session keys held now, sorted.
    pub fn keys(&self) -> Result<Vec<ConformanceKeyRef>, ConformanceError> {
        guard(|| {
            Ok(lock(&self.r)?
                .key_set()
                .into_iter()
                .map(|(member, key)| ConformanceKeyRef { member, key })
                .collect())
        })
    }
    /// The highest `n` accepted for `(member, key)`, if held.
    pub fn window_high(
        &self,
        member: String,
        key: String,
    ) -> Result<Option<u64>, ConformanceError> {
        guard(|| Ok(lock(&self.r)?.window(&member, &key).map(|w| w.high())))
    }
}
#[cfg(feature = "native05")]
#[uniffi::export]
impl ConformanceReceiver {
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
impl ConformanceReceiver {
    /// A receiver for member `me` in `(account, namespace, cell)`.
    #[wasm_bindgen::prelude::wasm_bindgen(constructor)]
    pub fn new(
        account: String,
        namespace: String,
        cell: String,
        me: String,
    ) -> ConformanceReceiver {
        Self::new_inner(account, namespace, cell, me)
    }
}

// --- The sender's key and delegation --------------------------------------------------------------

/// The sending side's session key and delegation, from supplied randomness: the key ID and the
/// exact delegation body a vector names.
#[cfg_attr(feature = "native05", derive(uniffi::Object))]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub struct ConformanceSender {
    s: Mutex<Sender>,
}
impl ConformanceSender {
    fn new_inner(
        account: String,
        namespace: String,
        cell: String,
        me: String,
        key_random: Vec<u8>,
    ) -> R<Self> {
        let mut key_random = key_random;
        let r = guard(|| {
            let mut random = fixed::<32>(&key_random, "the key randomness")?;
            let key = SessionKey::generate(&mut random);
            wipe(&mut random);
            let key = key.map_err(|e| ConformanceError::new("session:key", e.to_string()))?;
            Ok(Self {
                s: Mutex::new(Sender::new(
                    CellId::new(&account, &namespace, &cell),
                    &me,
                    key,
                )),
            })
        });
        wipe(&mut key_random);
        r
    }
}
#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
impl ConformanceSender {
    /// The session key's ID.
    pub fn key_id(&self) -> Result<String, ConformanceError> {
        guard(|| Ok(lock(&self.s)?.key().id().to_string()))
    }
    /// The delegation body for session number `session` and the window `[not_before_ms,
    /// expires_ms]`.
    pub fn delegation_body(
        &self,
        session: u64,
        not_before_ms: i64,
        expires_ms: i64,
    ) -> Result<Vec<u8>, ConformanceError> {
        guard(|| {
            lock(&self.s)?
                .delegation_body(session, not_before_ms, expires_ms)
                .map_err(|e| ConformanceError::new("session:window", e.to_string()))
        })
    }
    /// Install a signed delegation after verifying it under the member's key in `view`.
    pub fn install(
        &self,
        body: Vec<u8>,
        signature: Vec<u8>,
        view: &ConformanceView,
        wall_ms: i64,
    ) -> Result<(), ConformanceError> {
        guard(|| {
            lock(&self.s)?
                .install(&body, &signature, &view.v, wall_ms)
                .map_err(|why| ConformanceError::new("session:delegation", why))
        })
    }
}
#[cfg(feature = "native05")]
#[uniffi::export]
impl ConformanceSender {
    /// A sender for member `me` in `(account, namespace, cell)` whose key comes from
    /// `key_random` (32 bytes, wiped).
    #[uniffi::constructor]
    pub fn new(
        account: String,
        namespace: String,
        cell: String,
        me: String,
        key_random: Vec<u8>,
    ) -> Result<std::sync::Arc<Self>, ConformanceError> {
        Self::new_inner(account, namespace, cell, me, key_random).map(std::sync::Arc::new)
    }
}
#[cfg(feature = "web05")]
#[wasm_bindgen::prelude::wasm_bindgen]
impl ConformanceSender {
    /// A sender for member `me` in `(account, namespace, cell)`.
    #[wasm_bindgen::prelude::wasm_bindgen(constructor)]
    pub fn new(
        account: String,
        namespace: String,
        cell: String,
        me: String,
        key_random: Vec<u8>,
    ) -> Result<ConformanceSender, ConformanceError> {
        Self::new_inner(account, namespace, cell, me, key_random)
    }
}
