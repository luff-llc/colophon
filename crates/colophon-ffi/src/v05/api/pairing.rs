//! Pairing (§7.3) and moving the seed to a new device (§7.4). Public values only cross: the
//! account ID, points, nonces, a commitment and a code. The seed leaves an account only as an
//! HPKE ciphertext sealed to the paired device's key, and is opened only inside the core.
use super::account::AccountCore;
use super::fault::AccountError;
use super::json::*;
use super::{guard, lock};
use colophon_core::v05::account::Changes;
use colophon_core::v05::ids::AccountId;
use colophon_core::v05::pairing::{
    ConfirmedPairing, ExistingAwaitingReveal, ExistingWaiting, FailureLimiter, Joiner,
    PairingAbort, PairingCode, QrJoiner, QrPayload, ScannedQr, TransferKey,
};
use colophon_core::v05::vault::SealedBox;
use serde_json::{json, Value};
use std::sync::Mutex;

type R<T> = Result<T, AccountError>;

fn abort(a: PairingAbort) -> AccountError {
    let code = match a {
        PairingAbort::CommitmentMismatch => "commitmentMismatch",
        PairingAbort::InvalidPoint => "invalidPoint",
        PairingAbort::WrongAccount => "wrongAccount",
    };
    AccountError::Malformed {
        code: format!("pairing:{code}"),
        detail: a.to_string(),
    }
}
fn account_id(s: &str) -> R<AccountId> {
    Ok(AccountId::parse(s)?)
}

/// The five-failures-per-hour ledger of an existing device (§7.3). Plain data the host keeps:
/// persist `to_json` and restore it, or the limit holds only for this process.
#[cfg_attr(feature = "native05", derive(uniffi::Object))]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub struct PairingFailureLimiter {
    l: Mutex<FailureLimiter>,
}
impl PairingFailureLimiter {
    fn from_json_inner(state: String) -> R<Self> {
        guard(|| {
            let l: FailureLimiter = if state.is_empty() {
                FailureLimiter::new()
            } else {
                bounded(state.as_bytes(), 1 << 16, "limiter state")?;
                serde_json::from_str(&state)
                    .map_err(|_| AccountError::bad("not a limiter state"))?
            };
            Ok(Self { l: Mutex::new(l) })
        })
    }
}
#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
impl PairingFailureLimiter {
    /// The state to persist.
    pub fn to_json(&self) -> Result<String, AccountError> {
        guard(|| ser!(*lock(&self.l)?))
    }
    /// Whether a session may start now.
    pub fn may_start(&self, now_ms: i64) -> Result<bool, AccountError> {
        guard(|| Ok(lock(&self.l)?.may_start(now_ms)))
    }
}

#[cfg(feature = "native05")]
#[uniffi::export]
impl PairingFailureLimiter {
    /// A limiter from saved state, or a fresh one from an empty string.
    #[uniffi::constructor]
    pub fn from_json(state: String) -> Result<std::sync::Arc<Self>, AccountError> {
        Self::from_json_inner(state).map(std::sync::Arc::new)
    }
}

#[cfg(feature = "web05")]
#[wasm_bindgen::prelude::wasm_bindgen]
impl PairingFailureLimiter {
    pub fn from_json(state: String) -> Result<PairingFailureLimiter, AccountError> {
        Self::from_json_inner(state)
    }
}

enum Stage {
    Joiner(Joiner, [u8; 32]),
    Revealed(PairingCode),
    QrJoiner(QrJoiner),
    Waiting(ExistingWaiting),
    AwaitingReveal(ExistingAwaitingReveal),
    Code(PairingCode),
    Scanned(ScannedQr),
    Confirmed(ConfirmedPairing),
    Spent,
}
impl Stage {
    fn name(&self) -> &'static str {
        match self {
            Self::Joiner(..) => "joiner",
            Self::Revealed(_) => "revealed",
            Self::QrJoiner(_) => "qrJoiner",
            Self::Waiting(_) => "waiting",
            Self::AwaitingReveal(_) => "awaitingReveal",
            Self::Code(_) => "code",
            Self::Scanned(_) => "scanned",
            Self::Confirmed(_) => "confirmed",
            Self::Spent => "spent",
        }
    }
}

/// One pairing session, on either device and either path (the code or the QR). Each step
/// consumes the state it was in: a commitment permits exactly one reveal.
#[cfg_attr(feature = "native05", derive(uniffi::Object))]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub struct AccountPairing {
    st: Mutex<Stage>,
}
impl AccountPairing {
    fn new(s: Stage) -> Self {
        Self { st: Mutex::new(s) }
    }
    fn step<T>(&self, allowed: &[&str], f: impl FnOnce(Stage) -> R<(Stage, T)>) -> R<T> {
        guard(|| {
            let mut g = lock(&self.st)?;
            if !allowed.contains(&g.name()) {
                return Err(AccountError::consumed(&format!(
                    "not valid in the `{}` stage",
                    g.name()
                )));
            }
            let old = std::mem::replace(&mut *g, Stage::Spent);
            let (next, out) = f(old)?;
            *g = next;
            Ok(out)
        })
    }
    pub(crate) fn with_confirmed<T>(&self, f: impl FnOnce(&ConfirmedPairing) -> R<T>) -> R<T> {
        match &*lock(&self.st)? {
            Stage::Confirmed(c) => f(c),
            _ => Err(AccountError::consumed("this pairing is not confirmed")),
        }
    }
    fn join_inner(account: String, e: Vec<u8>, nb: Vec<u8>) -> R<Self> {
        guard(|| {
            let nb = fixed::<32>(&nb, "nonce")?;
            let (j, c) = Joiner::begin(&account_id(&account)?, &e, nb).map_err(abort)?;
            Ok(Self::new(Stage::Joiner(j, c)))
        })
    }
    fn join_qr_inner(account: String, e: Vec<u8>, nb: Vec<u8>) -> R<Self> {
        guard(|| {
            let nb = fixed::<32>(&nb, "nonce")?;
            let j = QrJoiner::begin(&account_id(&account)?, &e, nb).map_err(abort)?;
            Ok(Self::new(Stage::QrJoiner(j)))
        })
    }
    fn receive_commitment_inner(
        account: String,
        commitment: Vec<u8>,
        limiter: &PairingFailureLimiter,
        now_ms: i64,
    ) -> R<Self> {
        guard(|| {
            let c = fixed::<32>(&commitment, "commitment")?;
            let permit = lock(&limiter.l)?
                .permit(now_ms)
                .map_err(|e| AccountError::Refused {
                    code: "pairing:limit".into(),
                    reason: "pairingLimit".into(),
                    detail: e.to_string(),
                })?;
            Ok(Self::new(Stage::Waiting(
                ExistingWaiting::receive_commitment(&account_id(&account)?, c, permit),
            )))
        })
    }
    fn scan_qr_inner(
        account: String,
        payload: Vec<u8>,
        limiter: &PairingFailureLimiter,
        now_ms: i64,
    ) -> R<Self> {
        guard(|| {
            bounded(&payload, 4096, "a QR payload")?;
            let p = QrPayload::from_bytes(&payload)?;
            let permit = lock(&limiter.l)?
                .permit(now_ms)
                .map_err(|e| AccountError::Refused {
                    code: "pairing:limit".into(),
                    reason: "pairingLimit".into(),
                    detail: e.to_string(),
                })?;
            match ScannedQr::scan(&account_id(&account)?, &p, permit) {
                Ok(s) => Ok(Self::new(Stage::Scanned(s))),
                Err(e) => {
                    lock(&limiter.l)?.record_failure(now_ms);
                    Err(abort(e))
                }
            }
        })
    }
    fn finish_inner(
        &self,
        e: Vec<u8>,
        nb: Vec<u8>,
        limiter: &PairingFailureLimiter,
        now_ms: i64,
    ) -> R<String> {
        let nb = fixed::<32>(&nb, "nonce")?;
        self.step(&["awaitingReveal"], |s| match s {
            Stage::AwaitingReveal(a) => {
                let mut l = lock(&limiter.l)?;
                let code = a.finish_limited(&e, &nb, &mut l, now_ms).map_err(abort)?;
                let digits = code.digits().to_string();
                Ok((Stage::Code(code), digits))
            }
            other => Err(wrong(other)),
        })
    }
    fn reject_inner(&self, limiter: &PairingFailureLimiter, now_ms: i64) -> R<()> {
        self.step(&["code", "revealed"], |s| match s {
            Stage::Code(c) | Stage::Revealed(c) => {
                c.reject(&mut *lock(&limiter.l)?, now_ms);
                Ok((Stage::Spent, ()))
            }
            other => Err(wrong(other)),
        })
    }
}
fn wrong(s: Stage) -> AccountError {
    AccountError::consumed(&format!("not valid in the `{}` stage", s.name()))
}

#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
impl AccountPairing {
    /// Where the session stands.
    pub fn stage(&self) -> Result<String, AccountError> {
        guard(|| Ok(lock(&self.st)?.name().into()))
    }
    /// The joiner's commitment `C` (32 bytes), to send first.
    pub fn commitment(&self) -> Result<Vec<u8>, AccountError> {
        guard(|| match &*lock(&self.st)? {
            Stage::Joiner(_, c) => Ok(c.to_vec()),
            _ => Err(AccountError::consumed(
                "only a code-path joiner has a commitment",
            )),
        })
    }
    /// The QR payload a joiner shows.
    pub fn qr_payload(&self) -> Result<Vec<u8>, AccountError> {
        guard(|| match &*lock(&self.st)? {
            Stage::QrJoiner(j) => Ok(j.payload().to_bytes()?),
            _ => Err(AccountError::consumed("only a QR joiner has a payload")),
        })
    }
    /// The existing device sends its nonce `na` (32 fresh bytes) and gets it back to send. On
    /// the QR path this confirms the pairing at once.
    pub fn send_nonce(&self, na: Vec<u8>) -> Result<Vec<u8>, AccountError> {
        let na = fixed::<32>(&na, "nonce")?;
        self.step(&["waiting", "scanned"], |s| match s {
            Stage::Waiting(w) => {
                let (next, n) = w.send_nonce(na);
                Ok((Stage::AwaitingReveal(next), n.to_vec()))
            }
            Stage::Scanned(q) => {
                let (c, n) = q.send_nonce(na);
                Ok((Stage::Confirmed(c), n.to_vec()))
            }
            other => Err(wrong(other)),
        })
    }
    /// The joiner received `na`. Code path: returns `{"e","nb"}` to send, and the code is then
    /// available from `digits`. QR path: confirms the pairing.
    pub fn receive_nonce(&self, na: Vec<u8>) -> Result<String, AccountError> {
        let na = fixed::<32>(&na, "nonce")?;
        self.step(&["joiner", "qrJoiner"], |s| match s {
            Stage::Joiner(j, _) => {
                let (r, code) = j.reveal(na).map_err(abort)?;
                Ok((
                    Stage::Revealed(code),
                    to_string(&json!({"e": enc(&r.e), "nb": enc(&r.nb)}))?,
                ))
            }
            Stage::QrJoiner(q) => Ok((Stage::Confirmed(q.receive_nonce(na)), String::new())),
            other => Err(wrong(other)),
        })
    }
    /// The six digits both devices must show the person to compare.
    pub fn digits(&self) -> Result<String, AccountError> {
        guard(|| match &*lock(&self.st)? {
            Stage::Revealed(c) | Stage::Code(c) => Ok(c.digits().to_string()),
            _ => Err(AccountError::consumed("there is no code in this stage")),
        })
    }
    /// The person saw the same code on both screens.
    pub fn confirm(&self) -> Result<(), AccountError> {
        self.step(&["code", "revealed"], |s| match s {
            Stage::Revealed(c) | Stage::Code(c) => Ok((Stage::Confirmed(c.confirm()), ())),
            other => Err(wrong(other)),
        })
    }
}

#[cfg(feature = "native05")]
#[uniffi::export]
impl AccountPairing {
    /// The joining device, code path: its account ID, its ephemeral point `e` and a fresh
    /// 32-byte nonce `nb`. Read `commitment` and send it to the existing device.
    #[uniffi::constructor]
    pub fn join(
        account: String,
        e: Vec<u8>,
        nb: Vec<u8>,
    ) -> Result<std::sync::Arc<Self>, AccountError> {
        Self::join_inner(account, e, nb).map(std::sync::Arc::new)
    }
    /// The joining device, QR path: show `qr_payload`.
    #[uniffi::constructor]
    pub fn join_qr(
        account: String,
        e: Vec<u8>,
        nb: Vec<u8>,
    ) -> Result<std::sync::Arc<Self>, AccountError> {
        Self::join_qr_inner(account, e, nb).map(std::sync::Arc::new)
    }
    /// The existing device, code path: it received the joiner's commitment.
    #[uniffi::constructor]
    pub fn existing_receive_commitment(
        account: String,
        commitment: Vec<u8>,
        limiter: std::sync::Arc<PairingFailureLimiter>,
        now_ms: i64,
    ) -> Result<std::sync::Arc<Self>, AccountError> {
        Self::receive_commitment_inner(account, commitment, &limiter, now_ms)
            .map(std::sync::Arc::new)
    }
    /// The existing device, QR path: it scanned the joiner's screen. The host attests the scan
    /// by calling this: a payload the host builds is a scan it claims to have made.
    #[uniffi::constructor]
    pub fn existing_scan_qr(
        account: String,
        payload: Vec<u8>,
        limiter: std::sync::Arc<PairingFailureLimiter>,
        now_ms: i64,
    ) -> Result<std::sync::Arc<Self>, AccountError> {
        Self::scan_qr_inner(account, payload, &limiter, now_ms).map(std::sync::Arc::new)
    }
    /// The existing device received the joiner's reveal (`e` and `nb`): the code is computed
    /// and returned (six digits). A mismatch is `pairing:commitmentMismatch` and counts as a
    /// failure.
    pub fn receive_reveal(
        &self,
        e: Vec<u8>,
        nb: Vec<u8>,
        limiter: std::sync::Arc<PairingFailureLimiter>,
        now_ms: i64,
    ) -> Result<String, AccountError> {
        self.finish_inner(e, nb, &limiter, now_ms)
    }
    /// The codes differed: record a failure.
    pub fn reject(
        &self,
        limiter: std::sync::Arc<PairingFailureLimiter>,
        now_ms: i64,
    ) -> Result<(), AccountError> {
        self.reject_inner(&limiter, now_ms)
    }
}

#[cfg(feature = "web05")]
#[wasm_bindgen::prelude::wasm_bindgen]
impl AccountPairing {
    pub fn join(account: String, e: Vec<u8>, nb: Vec<u8>) -> Result<AccountPairing, AccountError> {
        Self::join_inner(account, e, nb)
    }
    pub fn join_qr(
        account: String,
        e: Vec<u8>,
        nb: Vec<u8>,
    ) -> Result<AccountPairing, AccountError> {
        Self::join_qr_inner(account, e, nb)
    }
    pub fn existing_receive_commitment(
        account: String,
        commitment: Vec<u8>,
        limiter: &PairingFailureLimiter,
        now_ms: i64,
    ) -> Result<AccountPairing, AccountError> {
        Self::receive_commitment_inner(account, commitment, limiter, now_ms)
    }
    pub fn existing_scan_qr(
        account: String,
        payload: Vec<u8>,
        limiter: &PairingFailureLimiter,
        now_ms: i64,
    ) -> Result<AccountPairing, AccountError> {
        Self::scan_qr_inner(account, payload, limiter, now_ms)
    }
    pub fn receive_reveal(
        &self,
        e: Vec<u8>,
        nb: Vec<u8>,
        limiter: &PairingFailureLimiter,
        now_ms: i64,
    ) -> Result<String, AccountError> {
        self.finish_inner(e, nb, limiter, now_ms)
    }
    pub fn reject(&self, limiter: &PairingFailureLimiter, now_ms: i64) -> Result<(), AccountError> {
        self.reject_inner(limiter, now_ms)
    }
}

/// The new device's one-use key a seed is sealed to. Its private scalar never leaves the core.
#[cfg_attr(feature = "native05", derive(uniffi::Object))]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub struct PairingTransferKey {
    k: TransferKey,
}
impl PairingTransferKey {
    fn new_inner(mut entropy: Vec<u8>) -> R<Self> {
        guard(|| {
            let s = fixed::<32>(&entropy, "entropy")?;
            entropy.fill(0);
            Ok(Self {
                k: TransferKey::new(s)?,
            })
        })
    }
}
#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
impl PairingTransferKey {
    /// The uncompressed public point.
    pub fn public(&self) -> Vec<u8> {
        self.k.public()
    }
}

#[cfg(feature = "native05")]
#[uniffi::export]
impl PairingTransferKey {
    /// A transfer key from 32 fresh bytes. Its public point is the pairing's `e`.
    #[uniffi::constructor]
    pub fn create(entropy: Vec<u8>) -> Result<std::sync::Arc<Self>, AccountError> {
        Self::new_inner(entropy).map(std::sync::Arc::new)
    }
}

#[cfg(feature = "web05")]
#[wasm_bindgen::prelude::wasm_bindgen]
impl PairingTransferKey {
    pub fn create(entropy: Vec<u8>) -> Result<PairingTransferKey, AccountError> {
        Self::new_inner(entropy)
    }
}

/// Moving the seed (§7.4): the existing device seals it, the new device opens it.
#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
impl AccountCore {}

#[cfg(feature = "native05")]
#[uniffi::export]
impl AccountCore {
    /// Seal the opened vault seed to the confirmed pairing's device. Returns the sealed box as
    /// JSON `{"enc","ciphertext"}`; it is public and only that device can open it.
    pub fn transfer_seed(
        &self,
        pairing: std::sync::Arc<AccountPairing>,
        entropy: Vec<u8>,
    ) -> Result<String, AccountError> {
        self.transfer_inner(&pairing, entropy)
    }
    /// Open a sealed seed on the new device with its transfer key and the confirmed pairing.
    pub fn accept_seed_transfer(
        &self,
        key: std::sync::Arc<PairingTransferKey>,
        sealed: String,
        pairing: std::sync::Arc<AccountPairing>,
    ) -> Result<String, AccountError> {
        self.accept_inner(&key, sealed, &pairing)
    }
}

#[cfg(feature = "web05")]
#[wasm_bindgen::prelude::wasm_bindgen]
impl AccountCore {
    pub fn transfer_seed(
        &self,
        pairing: &AccountPairing,
        entropy: Vec<u8>,
    ) -> Result<String, AccountError> {
        self.transfer_inner(pairing, entropy)
    }
    pub fn accept_seed_transfer(
        &self,
        key: &PairingTransferKey,
        sealed: String,
        pairing: &AccountPairing,
    ) -> Result<String, AccountError> {
        self.accept_inner(key, sealed, pairing)
    }
}
impl AccountCore {
    fn transfer_inner(&self, pairing: &AccountPairing, mut entropy: Vec<u8>) -> R<String> {
        guard(|| {
            let s = fixed::<32>(&entropy, "entropy")?;
            entropy.fill(0);
            let a = lock(&self.acc)?;
            pairing.with_confirmed(|p| {
                let b = a.transfer_seed(p, s)?;
                to_string(&b.to_value())
            })
        })
    }
    fn accept_inner(
        &self,
        key: &PairingTransferKey,
        sealed: String,
        pairing: &AccountPairing,
    ) -> R<String> {
        guard(|| {
            let v = parse(&sealed, "the sealed seed")?;
            let b = SealedBox {
                enc: b64(&v, "enc")?,
                ciphertext: b64(&v, "ciphertext")?,
            };
            b.validate_secret_box()?;
            let mut a = lock(&self.acc)?;
            let c: Changes =
                pairing.with_confirmed(|p| Ok(a.accept_seed_transfer(&key.k, &b, p)?))?;
            ser!(c)
        })
    }
}
#[allow(dead_code)]
fn _v(_: Value) {}
