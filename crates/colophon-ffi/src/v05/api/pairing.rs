//! Pairing (§7.3). Public values only cross: the account ID, points, nonces, a commitment and
//! a code. Moving the seed to the paired device is `AccountEngine.transfer_seed` and
//! `accept_seed_transfer`.
//!
//! Approving a member spends a confirmed pairing (§9.1): `AccountEngine.begin_approve` and
//! `begin_grant_transition` take the pairing object, which must be in the `Confirmed` stage on
//! the approving device, and leave it `Spent`. Exactly two pairings approve: the six-digit code
//! confirmed on the approving device (`confirm`), and the canonical request envelope scanned from
//! the joining device (`scan_request`), the scan path's one payload (§9.1). The pairing QR
//! (`existing_scan_qr`) moves the seed and does not approve.
use super::fault::AccountError;
use super::types::*;
use super::{guard, Cell};
use colophon_core::v05::ids::AccountId;
use colophon_core::v05::pairing::{
    scanned_request, ConfirmedPairing, ExistingAwaitingReveal, ExistingWaiting, FailureLimiter,
    Joiner, PairingAbort, PairingCode, QrJoiner, QrPayload, ScannedQr, TransferKey,
};

type R<T> = Result<T, AccountError>;

fn abort(a: PairingAbort) -> AccountError {
    let code = match a {
        PairingAbort::CommitmentMismatch => "commitmentMismatch",
        PairingAbort::InvalidPoint => "invalidPoint",
        PairingAbort::WrongAccount => "wrongAccount",
        PairingAbort::InvalidRequest => "invalidRequest",
    };
    AccountError::Malformed {
        code: format!("pairing:{code}"),
        detail: a.to_string(),
    }
}
fn limit_error(e: impl std::fmt::Display) -> AccountError {
    AccountError::Refused {
        code: "pairing:limit".into(),
        reason: "pairingLimit".into(),
        detail: e.to_string(),
    }
}
fn account_id(s: &str) -> R<AccountId> {
    Ok(AccountId::parse(s)?)
}

/// The five-failures-per-hour ledger of an existing device (§7.3). Plain data the host keeps:
/// persist `to_state` and restore it with `from_state`, or the limit holds only for this process.
#[cfg_attr(feature = "native05", derive(uniffi::Object))]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub struct PairingFailureLimiter {
    l: Cell<FailureLimiter>,
}
impl PairingFailureLimiter {
    fn from_state_inner(state: String) -> R<Self> {
        guard(|| {
            let l: FailureLimiter = if state.is_empty() {
                FailureLimiter::new()
            } else {
                if state.len() > 1 << 16 {
                    return Err(AccountError::bound("limiter state is over 64 KiB"));
                }
                serde_json::from_str(&state)
                    .map_err(|_| AccountError::bad("not a limiter state"))?
            };
            Ok(Self { l: Cell::new(l) })
        })
    }
}
#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
impl PairingFailureLimiter {
    /// The state to persist (an opaque text the host stores and gives back).
    pub fn to_state(&self) -> Result<String, AccountError> {
        guard(|| {
            serde_json::to_string(&*self.l.lock()?)
                .map_err(|_| AccountError::internal("a result could not be written"))
        })
    }
    /// Whether a session may start now.
    pub fn may_start(&self, now_ms: i64) -> Result<bool, AccountError> {
        guard(|| Ok(self.l.lock()?.may_start(now_ms)))
    }
}
#[cfg(feature = "native05")]
#[uniffi::export]
impl PairingFailureLimiter {
    /// A limiter from saved state, or a fresh one from an empty string.
    #[uniffi::constructor]
    pub fn from_state(state: String) -> Result<std::sync::Arc<Self>, AccountError> {
        Self::from_state_inner(state).map(std::sync::Arc::new)
    }
}
#[cfg(feature = "web05")]
#[wasm_bindgen::prelude::wasm_bindgen]
impl PairingFailureLimiter {
    /// A limiter from saved state, or a fresh one from an empty string.
    pub fn from_state(state: String) -> Result<PairingFailureLimiter, AccountError> {
        Self::from_state_inner(state)
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
    fn kind(&self) -> PairingStage {
        match self {
            Self::Joiner(..) => PairingStage::Joiner,
            Self::Revealed(_) => PairingStage::Revealed,
            Self::QrJoiner(_) => PairingStage::QrJoiner,
            Self::Waiting(_) => PairingStage::Waiting,
            Self::AwaitingReveal(_) => PairingStage::AwaitingReveal,
            Self::Code(_) => PairingStage::Code,
            Self::Scanned(_) => PairingStage::Scanned,
            Self::Confirmed(_) => PairingStage::Confirmed,
            Self::Spent => PairingStage::Spent,
        }
    }
}

/// One pairing session, on either device and either path (the code or the QR). Each step
/// consumes the state it was in: a commitment permits exactly one reveal.
#[cfg_attr(feature = "native05", derive(uniffi::Object))]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub struct AccountPairing {
    st: Cell<Stage>,
}
impl AccountPairing {
    fn new(s: Stage) -> Self {
        Self { st: Cell::new(s) }
    }
    /// Run a step only in the stages `allowed`; otherwise nothing is consumed.
    fn step<T>(&self, allowed: &[PairingStage], f: impl FnOnce(Stage) -> R<(Stage, T)>) -> R<T> {
        guard(|| {
            let mut g = self.st.lock()?;
            if !allowed.contains(&g.kind()) {
                return Err(AccountError::consumed(&format!(
                    "not valid in the {:?} stage",
                    g.kind()
                )));
            }
            let old = std::mem::replace(&mut *g, Stage::Spent);
            let (next, out) = f(old)?;
            *g = next;
            Ok(out)
        })
    }
    fn join_inner(account: String, e: Vec<u8>, nb: Vec<u8>) -> R<Self> {
        guard(|| {
            bytes_ok(&e, 65, "a point")?;
            let nb = fixed::<32>(&nb, "nonce")?;
            let (j, c) = Joiner::begin(&account_id(&account)?, &e, nb).map_err(abort)?;
            Ok(Self::new(Stage::Joiner(j, c)))
        })
    }
    fn join_qr_inner(account: String, e: Vec<u8>, nb: Vec<u8>) -> R<Self> {
        guard(|| {
            bytes_ok(&e, 65, "a point")?;
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
            let permit = limiter.l.lock()?.permit(now_ms).map_err(limit_error)?;
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
            bytes_ok(&payload, 4096, "a QR payload")?;
            let p = QrPayload::from_bytes(&payload)?;
            let permit = limiter.l.lock()?.permit(now_ms).map_err(limit_error)?;
            match ScannedQr::scan(&account_id(&account)?, &p, permit) {
                Ok(s) => Ok(Self::new(Stage::Scanned(s))),
                Err(e) => {
                    limiter.l.lock()?.record_failure(now_ms);
                    Err(abort(e))
                }
            }
        })
    }
    fn scan_request_inner(
        account: String,
        request: Vec<u8>,
        limiter: &PairingFailureLimiter,
        now_ms: i64,
    ) -> R<Self> {
        guard(|| {
            // A request envelope: a body of at most 16 KiB and a signature, in JSON.
            bytes_ok(&request, 1 << 16, "a request")?;
            let acct = account_id(&account)?;
            let permit = limiter.l.lock()?.permit(now_ms).map_err(limit_error)?;
            match scanned_request(&acct, &request, permit) {
                Ok(c) => Ok(Self::new(Stage::Confirmed(c))),
                Err(e) => {
                    limiter.l.lock()?.record_failure(now_ms);
                    Err(abort(e))
                }
            }
        })
    }
    /// Run `f` on the confirmed pairing, or refuse.
    pub(crate) fn with_confirmed<T>(&self, f: impl FnOnce(&ConfirmedPairing) -> R<T>) -> R<T> {
        match &*self.st.lock()? {
            Stage::Confirmed(c) => f(c),
            _ => Err(AccountError::consumed("this pairing is not confirmed")),
        }
    }
    /// Refuse unless the pairing is confirmed, without spending it.
    pub(crate) fn require_confirmed(&self) -> R<()> {
        self.with_confirmed(|_| Ok(()))
    }
    /// Take the confirmed pairing out to spend it on an approval (§9.1): the session is then
    /// `Spent`, so one pairing approves at most one request. Any other stage is refused and
    /// left as it was.
    pub(crate) fn take_confirmed(&self) -> R<ConfirmedPairing> {
        self.step(&[PairingStage::Confirmed], |s| match s {
            Stage::Confirmed(c) => Ok((Stage::Spent, c)),
            _ => Err(AccountError::internal("stage")),
        })
    }
    fn reveal_inner(
        &self,
        e: Vec<u8>,
        nb: Vec<u8>,
        limiter: &PairingFailureLimiter,
        now_ms: i64,
    ) -> R<String> {
        guard(|| {
            bytes_ok(&e, 65, "a point")?;
            let nb = fixed::<32>(&nb, "nonce")?;
            self.step(&[PairingStage::AwaitingReveal], |s| match s {
                Stage::AwaitingReveal(a) => {
                    let mut l = limiter.l.lock()?;
                    let code = a.finish_limited(&e, &nb, &mut l, now_ms).map_err(abort)?;
                    let digits = code.digits().to_string();
                    Ok((Stage::Code(code), digits))
                }
                _ => Err(AccountError::internal("stage")),
            })
        })
    }
    fn reject_inner(&self, limiter: &PairingFailureLimiter, now_ms: i64) -> R<()> {
        self.step(&[PairingStage::Code, PairingStage::Revealed], |s| match s {
            Stage::Code(c) | Stage::Revealed(c) => {
                c.reject(&mut *limiter.l.lock()?, now_ms);
                Ok((Stage::Spent, ()))
            }
            _ => Err(AccountError::internal("stage")),
        })
    }
}

#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
impl AccountPairing {
    /// Where the session stands.
    pub fn stage(&self) -> Result<PairingStage, AccountError> {
        guard(|| Ok(self.st.lock()?.kind()))
    }
    /// The joiner's commitment `C` (32 bytes), to send first.
    pub fn commitment(&self) -> Result<Vec<u8>, AccountError> {
        guard(|| match &*self.st.lock()? {
            Stage::Joiner(_, c) => Ok(c.to_vec()),
            _ => Err(AccountError::consumed(
                "only a code-path joiner has a commitment",
            )),
        })
    }
    /// The QR payload a joiner shows.
    pub fn qr_payload(&self) -> Result<Vec<u8>, AccountError> {
        guard(|| match &*self.st.lock()? {
            Stage::QrJoiner(j) => Ok(j.payload().to_bytes()?),
            _ => Err(AccountError::consumed("only a QR joiner has a payload")),
        })
    }
    /// The existing device sends its nonce `na` (32 fresh bytes) and gets it back to send. On
    /// the QR path this confirms the pairing at once.
    pub fn send_nonce(&self, na: Vec<u8>) -> Result<Vec<u8>, AccountError> {
        let na = guard(|| fixed::<32>(&na, "nonce"))?;
        self.step(
            &[PairingStage::Waiting, PairingStage::Scanned],
            |s| match s {
                Stage::Waiting(w) => {
                    let (next, n) = w.send_nonce(na);
                    Ok((Stage::AwaitingReveal(next), n.to_vec()))
                }
                Stage::Scanned(q) => {
                    let (c, n) = q.send_nonce(na);
                    Ok((Stage::Confirmed(c), n.to_vec()))
                }
                _ => Err(AccountError::internal("stage")),
            },
        )
    }
    /// The joiner received `na`. Code path: returns the reveal (`e`, `nb`) to send, and the
    /// code is then available from `digits`. QR path: confirms the pairing and returns none.
    pub fn receive_nonce(&self, na: Vec<u8>) -> Result<Option<PairingReveal>, AccountError> {
        let na = guard(|| fixed::<32>(&na, "nonce"))?;
        self.step(
            &[PairingStage::Joiner, PairingStage::QrJoiner],
            |s| match s {
                Stage::Joiner(j, _) => {
                    let (r, code) = j.reveal(na).map_err(abort)?;
                    Ok((
                        Stage::Revealed(code),
                        Some(PairingReveal {
                            e: r.e,
                            nb: r.nb.to_vec(),
                        }),
                    ))
                }
                Stage::QrJoiner(q) => Ok((Stage::Confirmed(q.receive_nonce(na)), None)),
                _ => Err(AccountError::internal("stage")),
            },
        )
    }
    /// The six digits both devices must show the person to compare.
    pub fn digits(&self) -> Result<String, AccountError> {
        guard(|| match &*self.st.lock()? {
            Stage::Revealed(c) | Stage::Code(c) => Ok(c.digits().to_string()),
            _ => Err(AccountError::consumed("there is no code in this stage")),
        })
    }
    /// The person saw the same code on both screens.
    pub fn confirm(&self) -> Result<(), AccountError> {
        self.step(&[PairingStage::Code, PairingStage::Revealed], |s| match s {
            Stage::Revealed(c) | Stage::Code(c) => Ok((Stage::Confirmed(c.confirm()), ())),
            _ => Err(AccountError::internal("stage")),
        })
    }
}

#[cfg(feature = "native05")]
#[uniffi::export]
impl AccountPairing {
    /// The joining device, code path: its account ID, ephemeral point `e` and a fresh 32-byte
    /// nonce `nb`. Send `commitment()` to the existing device.
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
    /// The existing device, QR path: it scanned the joiner's screen. The host attests the scan.
    #[uniffi::constructor]
    pub fn existing_scan_qr(
        account: String,
        payload: Vec<u8>,
        limiter: std::sync::Arc<PairingFailureLimiter>,
        now_ms: i64,
    ) -> Result<std::sync::Arc<Self>, AccountError> {
        Self::scan_qr_inner(account, payload, &limiter, now_ms).map(std::sync::Arc::new)
    }
    /// The existing device scanned a membership request from the joining device's screen
    /// (§7.3, §7a): the request must verify and name `account`; the pairing is then confirmed
    /// for its `member.signing` and may approve that one request. The host attests the scan.
    /// A bad request is `pairing:invalidRequest` or `pairing:wrongAccount` and counts as a
    /// failure.
    #[uniffi::constructor]
    pub fn scan_request(
        account: String,
        request: Vec<u8>,
        limiter: std::sync::Arc<PairingFailureLimiter>,
        now_ms: i64,
    ) -> Result<std::sync::Arc<Self>, AccountError> {
        Self::scan_request_inner(account, request, &limiter, now_ms).map(std::sync::Arc::new)
    }
    /// The existing device received the joiner's reveal: returns the six-digit code. A mismatch
    /// is `pairing:commitmentMismatch` and counts as a failure.
    pub fn receive_reveal(
        &self,
        e: Vec<u8>,
        nb: Vec<u8>,
        limiter: std::sync::Arc<PairingFailureLimiter>,
        now_ms: i64,
    ) -> Result<String, AccountError> {
        self.reveal_inner(e, nb, &limiter, now_ms)
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
    /// The joining device, code path.
    pub fn join(account: String, e: Vec<u8>, nb: Vec<u8>) -> Result<AccountPairing, AccountError> {
        Self::join_inner(account, e, nb)
    }
    /// The joining device, QR path.
    pub fn join_qr(
        account: String,
        e: Vec<u8>,
        nb: Vec<u8>,
    ) -> Result<AccountPairing, AccountError> {
        Self::join_qr_inner(account, e, nb)
    }
    /// The existing device, code path.
    pub fn existing_receive_commitment(
        account: String,
        commitment: Vec<u8>,
        limiter: &PairingFailureLimiter,
        now_ms: i64,
    ) -> Result<AccountPairing, AccountError> {
        Self::receive_commitment_inner(account, commitment, limiter, now_ms)
    }
    /// The existing device, QR path.
    pub fn existing_scan_qr(
        account: String,
        payload: Vec<u8>,
        limiter: &PairingFailureLimiter,
        now_ms: i64,
    ) -> Result<AccountPairing, AccountError> {
        Self::scan_qr_inner(account, payload, limiter, now_ms)
    }
    /// The existing device scanned a membership request from the joining device's screen.
    pub fn scan_request(
        account: String,
        request: Vec<u8>,
        limiter: &PairingFailureLimiter,
        now_ms: i64,
    ) -> Result<AccountPairing, AccountError> {
        Self::scan_request_inner(account, request, limiter, now_ms)
    }
    /// The existing device received the joiner's reveal: returns the six-digit code.
    pub fn receive_reveal(
        &self,
        e: Vec<u8>,
        nb: Vec<u8>,
        limiter: &PairingFailureLimiter,
        now_ms: i64,
    ) -> Result<String, AccountError> {
        self.reveal_inner(e, nb, limiter, now_ms)
    }
    /// The codes differed: record a failure.
    pub fn reject(&self, limiter: &PairingFailureLimiter, now_ms: i64) -> Result<(), AccountError> {
        self.reject_inner(limiter, now_ms)
    }
}

/// The new device's one-use key a seed is sealed to. Its private scalar never leaves the core.
#[cfg_attr(feature = "native05", derive(uniffi::Object))]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub struct PairingTransferKey {
    pub(crate) k: TransferKey,
}
impl PairingTransferKey {
    fn new_inner(entropy: Vec<u8>) -> R<Self> {
        let mut entropy = entropy;
        let r = guard(|| {
            let s = fixed::<32>(&entropy, "entropy")?;
            Ok(Self {
                k: TransferKey::new(s)?,
            })
        });
        wipe(&mut entropy);
        r
    }
}
#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
impl PairingTransferKey {
    /// The uncompressed public point (the pairing's `e`).
    pub fn public(&self) -> Vec<u8> {
        self.k.public()
    }
}
#[cfg(feature = "native05")]
#[uniffi::export]
impl PairingTransferKey {
    /// A transfer key from 32 fresh bytes (wiped).
    #[uniffi::constructor]
    pub fn create(entropy: Vec<u8>) -> Result<std::sync::Arc<Self>, AccountError> {
        Self::new_inner(entropy).map(std::sync::Arc::new)
    }
}
#[cfg(feature = "web05")]
#[wasm_bindgen::prelude::wasm_bindgen]
impl PairingTransferKey {
    /// A transfer key from 32 fresh bytes (wiped).
    pub fn create(entropy: Vec<u8>) -> Result<PairingTransferKey, AccountError> {
        Self::new_inner(entropy)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn confirmed_qr() -> AccountPairing {
        let account = "ab".repeat(32);
        let e = TransferKey::new([1; 32]).unwrap().public();
        let limiter = PairingFailureLimiter::from_state_inner(String::new()).unwrap();
        let j = AccountPairing::join_qr_inner(account.clone(), e, vec![2; 32]).unwrap();
        let payload = j.qr_payload().unwrap();
        let h = AccountPairing::scan_qr_inner(account, payload, &limiter, 0).unwrap();
        h.send_nonce(vec![3; 32]).unwrap();
        h
    }

    /// One confirmed pairing approves once: taking it leaves the session spent, and a second
    /// take is refused (§9.1).
    #[test]
    fn a_confirmed_pairing_is_taken_once() {
        let h = confirmed_qr();
        assert!(h.take_confirmed().is_ok());
        assert_eq!(h.stage().unwrap(), PairingStage::Spent);
        assert!(matches!(
            h.take_confirmed(),
            Err(AccountError::Consumed { .. })
        ));
        assert!(h.require_confirmed().is_err());
    }

    /// A pairing that is not confirmed is refused and left as it was.
    #[test]
    fn an_unconfirmed_pairing_is_refused_and_kept() {
        let account = "ab".repeat(32);
        let e = TransferKey::new([1; 32]).unwrap().public();
        let j = AccountPairing::join_inner(account, e, vec![2; 32]).unwrap();
        assert!(j.require_confirmed().is_err());
        assert!(j.take_confirmed().is_err());
        assert_eq!(j.stage().unwrap(), PairingStage::Joiner);
        assert!(j.commitment().is_ok(), "the session goes on");
    }

    /// A scanned request that does not verify is refused and counts as a failure.
    #[test]
    fn a_bad_scanned_request_is_a_failure() {
        let limiter = PairingFailureLimiter::from_state_inner(String::new()).unwrap();
        for _ in 0..5 {
            let r = AccountPairing::scan_request_inner("ab".repeat(32), b"{}".to_vec(), &limiter, 0);
            assert!(matches!(r, Err(AccountError::Malformed { ref code, .. }) if code == "pairing:invalidRequest"));
        }
        assert!(!limiter.may_start(0).unwrap(), "five failures close the hour");
    }
}
