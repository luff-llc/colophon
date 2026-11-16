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
//!
//! **One ceremony at a time, every start counted.** An existing device's sessions start from its
//! `PairingFailureLimiter`, the sealed ledger of §7.3. Starting one reserves one of the five an
//! hour; only a confirmed pairing gives it back. While one is live (not ended, younger than ten
//! minutes) another start is refused (`pairing:busy`) and never yields a nonce. The session's
//! nonce (`send_nonce`) is refused (`pairing:unsealed`) until the host took the sealed ledger
//! (`seal`) after the start, so a host that cannot persist it never sends one. `abandon` ends a
//! session, counted; dropping the object does the same.
use super::fault::AccountError;
use super::types::*;
use super::{guard, Cell};
use colophon_core::v05::ids::AccountId;
use colophon_core::v05::pairing::{
    scanned_request, ConfirmedPairing, ExistingAwaitingReveal, ExistingWaiting, FailureLimiter,
    Joiner, PairingAbort, PairingCode, PermitRefused, QrJoiner, QrPayload, ScannedQr, TransferKey,
};
use std::sync::Arc;

type R<T> = Result<T, AccountError>;

fn abort(a: PairingAbort) -> AccountError {
    let code = match a {
        PairingAbort::CommitmentMismatch => "commitmentMismatch",
        PairingAbort::InvalidPoint => "invalidPoint",
        PairingAbort::WrongAccount => "wrongAccount",
        PairingAbort::InvalidRequest => "invalidRequest",
        PairingAbort::Timeout => "timeout",
    };
    AccountError::Malformed {
        code: format!("pairing:{code}"),
        detail: a.to_string(),
    }
}
fn permit_error(e: PermitRefused) -> AccountError {
    let (code, reason) = match e {
        PermitRefused::LimitReached => ("pairing:limit", "pairingLimit"),
        PermitRefused::CeremonyLive => ("pairing:busy", "pairingBusy"),
        PermitRefused::ClockImplausible => ("pairing:clock", "pairingClock"),
    };
    AccountError::Refused {
        code: code.into(),
        reason: reason.into(),
        detail: e.to_string(),
    }
}
fn account_id(s: &str) -> R<AccountId> {
    Ok(AccountId::parse(s)?)
}
fn device_key(key: &[u8]) -> R<[u8; 32]> {
    fixed::<32>(key, "device key")
}

/// The pairing ledger of an existing device (§7.3): five failed sessions an hour, one ceremony at
/// a time. The host persists it sealed: `seal` after every change, `open` on start. An edited,
/// foreign or unreadable ledger, or one older than the generation the host recorded beside it,
/// opens as a spent budget.
#[cfg_attr(feature = "native05", derive(uniffi::Object))]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
pub struct PairingFailureLimiter {
    pub(crate) l: Arc<Cell<FailureLimiter>>,
}
impl PairingFailureLimiter {
    fn wrap(l: FailureLimiter) -> Self {
        Self {
            l: Arc::new(Cell::new(l)),
        }
    }
    fn open_inner(
        sealed: Vec<u8>,
        key: Vec<u8>,
        account: String,
        floor: u64,
        now_ms: i64,
    ) -> R<Self> {
        let mut key = key;
        let r = guard(|| {
            bytes_ok(&sealed, 1 << 20, "a sealed ledger")?;
            let k = device_key(&key)?;
            Ok(Self::wrap(FailureLimiter::open(
                &sealed,
                &account_id(&account)?,
                &k,
                floor,
                now_ms,
            )))
        });
        wipe(&mut key);
        r
    }
}
#[cfg_attr(feature = "native05", uniffi::export)]
#[cfg_attr(feature = "web05", wasm_bindgen::prelude::wasm_bindgen)]
impl PairingFailureLimiter {
    /// The ledger sealed for `account` under the device-held key, to persist (with `generation`
    /// recorded beside it) before acting on the change. 32 bytes of entropy.
    pub fn seal(&self, device_key: Vec<u8>, account: String, entropy: Vec<u8>) -> Result<Vec<u8>, AccountError> {
        let (mut key, mut entropy) = (device_key, entropy);
        let r = guard(|| {
            let k = self::device_key(&key)?;
            let seed = fixed::<32>(&entropy, "entropy")?;
            Ok(self.l.lock()?.seal(&account_id(&account)?, &k, seed)?)
        });
        wipe(&mut key);
        wipe(&mut entropy);
        r
    }
    /// The ledger's generation, raised by every change: record it beside the sealed ledger.
    pub fn generation(&self) -> Result<u64, AccountError> {
        guard(|| Ok(self.l.lock()?.generation()))
    }
    /// Whether a session may start now (none live, budget left).
    pub fn may_start(&self, now_ms: i64) -> Result<bool, AccountError> {
        guard(|| Ok(self.l.lock()?.may_start(now_ms)))
    }
    /// Whether a ceremony is live now.
    pub fn is_live(&self, now_ms: i64) -> Result<bool, AccountError> {
        guard(|| Ok(self.l.lock()?.is_live(now_ms)))
    }
}
#[cfg(feature = "native05")]
#[uniffi::export]
impl PairingFailureLimiter {
    /// A new, empty ledger held in memory (a device that keeps none, or a test).
    #[uniffi::constructor]
    pub fn fresh() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self::wrap(FailureLimiter::new()))
    }
    /// The ledger the host stored for `account` (empty when none), opened under the device-held
    /// key; `floor` is the generation the host recorded beside it (0 when none).
    #[uniffi::constructor]
    pub fn open(
        sealed: Vec<u8>,
        device_key: Vec<u8>,
        account: String,
        floor: u64,
        now_ms: i64,
    ) -> Result<std::sync::Arc<Self>, AccountError> {
        Self::open_inner(sealed, device_key, account, floor, now_ms).map(std::sync::Arc::new)
    }
}
#[cfg(feature = "web05")]
#[wasm_bindgen::prelude::wasm_bindgen]
impl PairingFailureLimiter {
    /// A new, empty ledger held in memory.
    pub fn fresh() -> PairingFailureLimiter {
        Self::wrap(FailureLimiter::new())
    }
    /// The ledger the host stored for `account`, opened under the device-held key.
    pub fn open(
        sealed: Vec<u8>,
        device_key: Vec<u8>,
        account: String,
        floor: u64,
        now_ms: i64,
    ) -> Result<PairingFailureLimiter, AccountError> {
        Self::open_inner(sealed, device_key, account, floor, now_ms)
    }
}

/// The ledger and reservation of an existing-side session.
struct Gate {
    l: Arc<Cell<FailureLimiter>>,
    id: u64,
    generation: u64,
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
    /// On the existing side: the ledger and the reservation this session holds.
    gate: std::sync::Mutex<Option<Gate>>,
}
impl Drop for AccountPairing {
    /// A session dropped before it ended is abandoned: its reservation stays counted (§7.3).
    fn drop(&mut self) {
        let live = self
            .st
            .lock()
            .map(|s| {
                matches!(
                    s.kind(),
                    PairingStage::Waiting
                        | PairingStage::AwaitingReveal
                        | PairingStage::Code
                        | PairingStage::Scanned
                )
            })
            .unwrap_or(true);
        if live {
            self.end_gate(i64::MIN);
        }
    }
}
impl AccountPairing {
    fn new(s: Stage) -> Self {
        Self {
            st: Cell::new(s),
            gate: std::sync::Mutex::new(None),
        }
    }
    fn gated(s: Stage, l: &Arc<Cell<FailureLimiter>>, id: u64, generation: u64) -> Self {
        Self {
            st: Cell::new(s),
            gate: std::sync::Mutex::new(Some(Gate {
                l: l.clone(),
                id,
                generation,
            })),
        }
    }
    /// End this session's reservation, counted, and forget the gate.
    fn end_gate(&self, now_ms: i64) {
        let gate = self.gate.lock().ok().and_then(|mut g| g.take());
        if let Some(g) = gate {
            if let Ok(mut l) = g.l.lock() {
                l.end_reservation(g.id, now_ms);
            }
        }
    }
    /// Give this session's reservation back for the confirmed pairing `c`.
    fn release_gate(&self, c: &ConfirmedPairing) {
        let gate = self.gate.lock().ok().and_then(|mut g| g.take());
        if let Some(g) = gate {
            if let Ok(mut l) = g.l.lock() {
                l.release(c);
            }
        }
    }
    /// The ledger this session started from; refused when `limiter` is another one.
    fn gate_ledger(&self, limiter: &PairingFailureLimiter) -> R<Arc<Cell<FailureLimiter>>> {
        let g = self
            .gate
            .lock()
            .map_err(|_| AccountError::internal("the pairing gate"))?;
        match &*g {
            Some(g) if Arc::ptr_eq(&g.l, &limiter.l) => Ok(g.l.clone()),
            Some(_) => Err(AccountError::bad("this session started from another ledger")),
            None => Ok(limiter.l.clone()),
        }
    }
    /// The nonce goes only after the host took the sealed ledger since this session began.
    fn require_sealed(&self) -> R<()> {
        let g = self
            .gate
            .lock()
            .map_err(|_| AccountError::internal("the pairing gate"))?;
        if let Some(g) = &*g {
            if !g.l.lock()?.sealed_since(g.generation) {
                return Err(AccountError::Refused {
                    code: "pairing:unsealed".into(),
                    reason: "pairingUnsealed".into(),
                    detail: "persist the sealed ledger (seal) before sending the nonce".into(),
                });
            }
        }
        Ok(())
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
            let acct = account_id(&account)?;
            let permit = limiter.l.lock()?.permit(now_ms).map_err(permit_error)?;
            let generation = permit.generation();
            let w = ExistingWaiting::receive_commitment(&acct, c, permit);
            let id = w.reservation();
            Ok(Self::gated(Stage::Waiting(w), &limiter.l, id, generation))
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
            let acct = account_id(&account)?;
            let permit = limiter.l.lock()?.permit(now_ms).map_err(permit_error)?;
            let generation = permit.generation();
            match ScannedQr::scan(&acct, &p, permit) {
                Ok(s) => {
                    let id = s.reservation();
                    Ok(Self::gated(Stage::Scanned(s), &limiter.l, id, generation))
                }
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
            let permit = limiter.l.lock()?.permit(now_ms).map_err(permit_error)?;
            match scanned_request(&acct, &request, permit) {
                // A request read from the joining device's screen confirms at once: its
                // reservation goes back and nothing is left live.
                Ok(c) => {
                    limiter.l.lock()?.release(&c);
                    Ok(Self::new(Stage::Confirmed(c)))
                }
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
            let ledger = self.gate_ledger(limiter)?;
            self.step(&[PairingStage::AwaitingReveal], |s| match s {
                Stage::AwaitingReveal(a) => {
                    let mut l = ledger.lock()?;
                    let code = a.finish_limited(&e, &nb, &mut l, now_ms).map_err(abort)?;
                    let digits = code.digits().to_string();
                    Ok((Stage::Code(code), digits))
                }
                _ => Err(AccountError::internal("stage")),
            })
        })
    }
    fn reject_inner(&self, limiter: &PairingFailureLimiter, now_ms: i64) -> R<()> {
        let ledger = self.gate_ledger(limiter)?;
        self.step(&[PairingStage::Code, PairingStage::Revealed], |s| match s {
            Stage::Code(c) | Stage::Revealed(c) => {
                c.reject(&mut *ledger.lock()?, now_ms);
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
        guard(|| self.require_sealed())?;
        self.step(
            &[PairingStage::Waiting, PairingStage::Scanned],
            |s| match s {
                Stage::Waiting(w) => {
                    let (next, n) = w.send_nonce(na);
                    Ok((Stage::AwaitingReveal(next), n.to_vec()))
                }
                Stage::Scanned(q) => {
                    let (c, n) = q.send_nonce(na);
                    self.release_gate(&c);
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
    /// The person saw the same code on both screens. On the existing device the ceremony's
    /// reservation goes back: a confirmed pairing is not a failure.
    pub fn confirm(&self) -> Result<(), AccountError> {
        self.step(&[PairingStage::Code, PairingStage::Revealed], |s| match s {
            Stage::Revealed(c) | Stage::Code(c) => {
                let c = c.confirm();
                self.release_gate(&c);
                Ok((Stage::Confirmed(c), ()))
            }
            _ => Err(AccountError::internal("stage")),
        })
    }
    /// End the session now, in any stage before it is confirmed: abandoned, it stays counted in
    /// the existing device's ledger (§7.3). A confirmed or spent session is left as it is.
    pub fn abandon(&self, now_ms: i64) -> Result<(), AccountError> {
        guard(|| {
            let ended = {
                let mut g = self.st.lock()?;
                if matches!(g.kind(), PairingStage::Confirmed | PairingStage::Spent) {
                    false
                } else {
                    *g = Stage::Spent;
                    true
                }
            };
            if ended {
                self.end_gate(now_ms);
            }
            Ok(())
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

    const KEY: [u8; 32] = [0x44; 32];

    fn account() -> String {
        "ab".repeat(32)
    }
    fn point(n: u8) -> Vec<u8> {
        TransferKey::new([n; 32]).unwrap().public()
    }
    fn seal(limiter: &PairingFailureLimiter) -> Vec<u8> {
        limiter.seal(KEY.to_vec(), account(), vec![9; 32]).unwrap()
    }
    fn commitment_of(e: &[u8], nb: [u8; 32]) -> Vec<u8> {
        colophon_core::v05::pairing::commitment(&AccountId::parse(&account()).unwrap(), e, &nb)
            .unwrap()
            .to_vec()
    }

    fn confirmed_qr() -> AccountPairing {
        let limiter = PairingFailureLimiter::wrap(FailureLimiter::new());
        let j = AccountPairing::join_qr_inner(account(), point(1), vec![2; 32]).unwrap();
        let payload = j.qr_payload().unwrap();
        let h = AccountPairing::scan_qr_inner(account(), payload, &limiter, 0).unwrap();
        seal(&limiter);
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
        let j = AccountPairing::join_inner(account(), point(1), vec![2; 32]).unwrap();
        assert!(j.require_confirmed().is_err());
        assert!(j.take_confirmed().is_err());
        assert_eq!(j.stage().unwrap(), PairingStage::Joiner);
        assert!(j.commitment().is_ok(), "the session goes on");
    }

    /// A scanned request that does not verify is refused and counts as a failure.
    #[test]
    fn a_bad_scanned_request_is_a_failure() {
        let limiter = PairingFailureLimiter::wrap(FailureLimiter::new());
        for _ in 0..5 {
            let r = AccountPairing::scan_request_inner(account(), b"{}".to_vec(), &limiter, 0);
            assert!(matches!(r, Err(AccountError::Malformed { ref code, .. }) if code == "pairing:invalidRequest"));
        }
        assert!(!limiter.may_start(0).unwrap(), "five failures close the hour");
    }

    /// A second commitment while one ceremony is live is refused and yields no nonce.
    #[test]
    fn a_second_commitment_while_one_is_live_is_refused() {
        let limiter = PairingFailureLimiter::wrap(FailureLimiter::new());
        let first = AccountPairing::receive_commitment_inner(account(), commitment_of(&point(1), [1; 32]), &limiter, 0).unwrap();
        let second = AccountPairing::receive_commitment_inner(account(), commitment_of(&point(2), [2; 32]), &limiter, 1);
        assert!(matches!(second, Err(AccountError::Refused { ref code, .. }) if code == "pairing:busy"));
        seal(&limiter);
        assert!(first.send_nonce(vec![7; 32]).is_ok());
    }

    /// The attack of the check: a relay starts many sessions with its own keys beside the honest
    /// one, to pick the one whose code matches. Only the first start yields a nonce; every other
    /// is refused, so the relay has one code to match, not hundreds of thousands.
    #[test]
    fn many_sequential_starts_against_one_ledger_yield_one_nonce() {
        let limiter = PairingFailureLimiter::wrap(FailureLimiter::new());
        let mut nonces = 0;
        let mut held = Vec::new();
        for i in 0..1_000u32 {
            let e = point((i % 200) as u8 + 1);
            let nb = [(i % 251) as u8; 32];
            if let Ok(p) = AccountPairing::receive_commitment_inner(account(), commitment_of(&e, nb), &limiter, i64::from(i)) {
                seal(&limiter);
                if p.send_nonce(vec![5; 32]).is_ok() {
                    nonces += 1;
                }
                held.push(p);
            }
        }
        assert_eq!(nonces, 1, "one live ceremony, one nonce");
    }

    /// The nonce is refused until the host took the sealed ledger after the start: a host that
    /// cannot persist it never sends one.
    #[test]
    fn without_a_sealed_ledger_there_is_no_nonce() {
        let limiter = PairingFailureLimiter::wrap(FailureLimiter::new());
        let p = AccountPairing::receive_commitment_inner(account(), commitment_of(&point(1), [1; 32]), &limiter, 0).unwrap();
        assert!(matches!(p.send_nonce(vec![7; 32]), Err(AccountError::Refused { ref code, .. }) if code == "pairing:unsealed"));
        assert_eq!(p.stage().unwrap(), PairingStage::Waiting, "nothing consumed");
        seal(&limiter);
        assert!(p.send_nonce(vec![7; 32]).is_ok());
    }

    /// An abandoned ceremony, or a dropped one, stays counted; a confirmed one gives its
    /// reservation back.
    #[test]
    fn abandoned_and_dropped_ceremonies_count_and_a_confirmed_one_does_not() {
        let limiter = PairingFailureLimiter::wrap(FailureLimiter::new());
        for i in 0..4 {
            let p = AccountPairing::receive_commitment_inner(account(), commitment_of(&point(1), [i; 32]), &limiter, i64::from(i)).unwrap();
            if i % 2 == 0 {
                p.abandon(i64::from(i)).unwrap();
            } else {
                drop(p);
            }
            assert!(!limiter.is_live(i64::from(i)).unwrap());
        }
        // A confirmed code ceremony: J and H agree, H confirms, the budget is back to four used.
        let e = point(3);
        let j = AccountPairing::join_inner(account(), e.clone(), vec![4; 32]).unwrap();
        let h = AccountPairing::receive_commitment_inner(account(), j.commitment().unwrap(), &limiter, 10).unwrap();
        seal(&limiter);
        let na = h.send_nonce(vec![6; 32]).unwrap();
        let r = j.receive_nonce(na).unwrap().unwrap();
        let digits = h.reveal_inner(r.e, r.nb, &limiter, 11).unwrap();
        assert_eq!(digits, j.digits().unwrap());
        h.confirm().unwrap();
        assert!(limiter.may_start(12).unwrap(), "four counted, the confirmed one given back");
        let p = AccountPairing::receive_commitment_inner(account(), commitment_of(&point(1), [9; 32]), &limiter, 13).unwrap();
        p.abandon(13).unwrap();
        assert!(!limiter.may_start(14).unwrap(), "five counted");
    }

    /// A rolled-back, edited, foreign or missing ledger does not restore the budget.
    #[test]
    fn a_rolled_back_ledger_does_not_restore_the_budget() {
        let limiter = PairingFailureLimiter::wrap(FailureLimiter::new());
        let early = seal(&limiter);
        let early_generation = limiter.generation().unwrap();
        for i in 0..5 {
            let p = AccountPairing::receive_commitment_inner(account(), commitment_of(&point(1), [i; 32]), &limiter, i64::from(i)).unwrap();
            p.abandon(i64::from(i)).unwrap();
        }
        let late = seal(&limiter);
        let floor = limiter.generation().unwrap();
        assert!(floor > early_generation);
        let open = |b: &[u8], f: u64| PairingFailureLimiter::open_inner(b.to_vec(), KEY.to_vec(), account(), f, 10).unwrap();
        assert!(!open(&late, floor).may_start(10).unwrap(), "the real ledger: spent");
        assert!(!open(&early, floor).may_start(10).unwrap(), "an older ledger opens as spent");
        assert!(!open(&[], floor).may_start(10).unwrap(), "a missing ledger with a floor opens as spent");
        let mut edited = late.clone();
        let n = edited.len() - 1;
        edited[n] ^= 1;
        assert!(!open(&edited, 0).may_start(10).unwrap(), "an edited ledger opens as spent");
        let other = PairingFailureLimiter::open_inner(late.clone(), [0x45; 32].to_vec(), account(), 0, 10).unwrap();
        assert!(!other.may_start(10).unwrap(), "another device key: spent");
        assert!(open(&[], 0).may_start(10).unwrap(), "no ledger and no floor: a new device");
    }
}
