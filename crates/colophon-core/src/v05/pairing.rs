//! Pairing (§7.3) and moving the seed to a new device (§7.4).
//!
//! **What the core guarantees, exactly.** The core never returns seed bytes or a raw ECDH
//! output through its API. An opened seed can be sealed only to controllers of its own account's
//! verified keyring (it records the account it was opened under, and a state of another account
//! is refused), to a new vault the host itself creates at rotation, or to a device the person
//! confirmed by pairing. The host is trusted with the seed during rotation and transfer: it
//! supplies the new seed's entropy and so can read what is sealed to it, and it performs the
//! QR scan, so a payload it builds is a pairing it confirmed. The core does not, and cannot,
//! stop a host that performs the ECDH and PRF work from computing a seed it was never meant to
//! hold; it bounds what the *core's own functions* will seal.
//!
//! Pairing handles only public values (the account ID, the point `E` and the two nonces). The
//! seed moves only as an HPKE ciphertext: the seed holder seals it through [`VaultSeed`]'s
//! sealing method (the seed bytes are never read here), and the new device opens it with a
//! [`TransferKey`], whose private scalar lives inside an opaque [`AgreementKey`] of
//! [`super::vault`] and is never exposed; the result is a [`VaultSeed`] handle, checked against
//! the keyring's vault and recorded as opened under the pairing's account. No raw ECDH result
//! is formed here.
//!
//! **Sessions are typed.** The code path (`Joiner`, `ExistingWaiting`, `PairingCode`) and the QR
//! path (`QrJoiner`, `ScannedQr`) are different types: a commitment-bearing `Joiner` cannot show
//! `nB`, and each step consumes its state. A `ConfirmedPairing`, which a seed transfer needs, has
//! no public constructor: it comes only from a compared code or the QR path. On the QR path what
//! authenticates `E` is the scan of the joining device's screen (§7.3); the core cannot see a
//! scan, so the host attests it by calling `ScannedQr::scan`: a payload the host builds is a
//! scan it claims to have made. Starting a session on H takes a `Permit` from the
//! `FailureLimiter`, which is plain data the host keeps: a fresh one always grants a permit, so
//! the five-per-hour limit holds only while the host keeps its ledger.
//!
//! The core has no clock and no RNG: nonces, the ephemeral key's seed and the time of every
//! failure come in as arguments. The state machine consumes itself at each step, so a
//! commitment permits exactly one reveal (§7.3).
//!
//! **Approving a member spends a confirmed pairing (§9.1, §17.1).** A [`ConfirmedPairing`] is
//! also the token without which the account refuses to prepare a `grant` or a transition's
//! `grant` component ([`crate::v05::account::Account::begin_approve`],
//! [`crate::v05::account::Account::begin_grant_transition`]). It is not `Clone`: the approval
//! takes it by value, so one pairing approves at most one request. It approves only when it
//! names this account, its `E` is exactly the request's `member.signing`, no more than
//! [`CONFIRMED_PAIRING_LIFETIME_MS`] passed since the approving session began, and it came from
//! one of exactly two places, each a session H started with a [`Permit`] (so failures are
//! bounded by the limiter): the six-digit code confirmed on H ([`PairingCode::confirm`]), or the
//! canonical request envelope scanned from J's screen ([`scanned_request`]), the scan path's one
//! payload (§9.1). The joining side's pairing and the pairing QR ([`ScannedQr`], which moves the
//! seed) do not approve. Nothing approves a member from its ID or a prefix of it.
use super::descriptor::valid_point;
use super::encoding::hex;
use super::ids::{key_id, AccountId};
use super::vault::{malformed, AgreementKey, SealedBox, VResult, VaultPublic, VaultSeed};
use super::{Failure, Reason};
use crate::crypto::Entropy;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain label of the commitment (§7.3 step 1).
pub const COMMITMENT_LABEL: &[u8] = b"colophon/pair/5";
/// Domain label of the displayed code (§7.3 step 4).
pub const CODE_LABEL: &[u8] = b"colophon/pair-code/5";
/// Prefix of the seed-transfer `info` and AAD (§7.4).
pub const TRANSFER_LABEL: &str = "colophon/vault-transfer/5";
/// Failed pairing sessions an existing device allows per hour (§7.3).
pub const MAX_FAILED_PER_HOUR: usize = 5;
/// How long a confirmed pairing may approve a member, from the moment the existing side's
/// session began (its [`Permit`]): ten minutes. The spec bounds a session by "a timeout" without
/// a number; this is the core's, the same as an invite link's default (§18).
pub const CONFIRMED_PAIRING_LIFETIME_MS: i64 = 10 * 60 * 1000;

/// Why a pairing aborted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingAbort {
    /// `SHA-256("colophon/pair/5" ‖ accountID ‖ E ‖ nB)` did not equal the commitment `C`:
    /// "abort: commitment mismatch".
    CommitmentMismatch,
    /// `E` is not a valid uncompressed P-256 point.
    InvalidPoint,
    /// A QR payload (or a scanned request) names another account.
    WrongAccount,
    /// A scanned membership request does not parse or its signature does not verify (§9.1).
    InvalidRequest,
}
impl std::fmt::Display for PairingAbort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::CommitmentMismatch => "abort: commitment mismatch",
            Self::InvalidPoint => "abort: E is not a valid point",
            Self::WrongAccount => "abort: QR names another account",
            Self::InvalidRequest => "abort: the scanned request is not a valid request",
        })
    }
}
impl std::error::Error for PairingAbort {}

fn check_point(e: &[u8]) -> Result<(), PairingAbort> {
    if valid_point(e) {
        Ok(())
    } else {
        Err(PairingAbort::InvalidPoint)
    }
}

/// `C = SHA-256("colophon/pair/5" ‖ accountID ‖ E ‖ nB)` (§7.3 step 1), `accountID` its 64
/// ASCII hex characters, `E` the 65-byte point and `nB` 32 bytes.
pub fn commitment(account: &AccountId, e: &[u8], nb: &[u8; 32]) -> Result<[u8; 32], PairingAbort> {
    check_point(e)?;
    let mut h = Sha256::new();
    h.update(COMMITMENT_LABEL);
    h.update(account.as_str().as_bytes());
    h.update(e);
    h.update(nb);
    Ok(h.finalize().into())
}

/// The six-digit code (§7.3 step 4): the first four bytes of `SHA-256("colophon/pair-code/5"
/// ‖ accountID ‖ E ‖ nA ‖ nB)`, big-endian, modulo 1,000,000, zero-padded.
pub fn code(
    account: &AccountId,
    e: &[u8],
    na: &[u8; 32],
    nb: &[u8; 32],
) -> Result<String, PairingAbort> {
    check_point(e)?;
    let mut h = Sha256::new();
    h.update(CODE_LABEL);
    h.update(account.as_str().as_bytes());
    h.update(e);
    h.update(na);
    h.update(nb);
    let d = h.finalize();
    let n = u32::from_be_bytes([d[0], d[1], d[2], d[3]]) % 1_000_000;
    Ok(format!("{n:06}"))
}

/// What the joining side reveals at step 3: `E` and `nB`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reveal {
    /// The 65-byte point.
    pub e: Vec<u8>,
    /// The joiner's nonce.
    pub nb: [u8; 32],
}

/// A pairing both sides computed but the person has not yet confirmed. The code is compared
/// by eye; [`PairingCode::confirm`] is the person's "they match". Not `Clone`: one compared code
/// confirms one pairing.
#[derive(Debug)]
pub struct PairingCode {
    account: AccountId,
    e: Vec<u8>,
    na: [u8; 32],
    nb: [u8; 32],
    digits: String,
    /// When H's session began (its permit); `None` on the joining side.
    started_ms: Option<i64>,
}
impl PairingCode {
    /// The six digits to display.
    pub fn digits(&self) -> &str {
        &self.digits
    }
    /// The person confirmed that the codes match: a pairing that §7.4 may use and, on the
    /// existing side, that may approve the member whose `member.signing` is `E` (§9.1). This,
    /// [`ScannedQr::send_nonce`], [`QrJoiner::receive_nonce`] and [`scanned_request`] are the
    /// only ways to obtain a [`ConfirmedPairing`].
    pub fn confirm(self) -> ConfirmedPairing {
        ConfirmedPairing {
            account: self.account,
            e: self.e,
            nonces: Some((self.na, self.nb)),
            approving_since_ms: self.started_ms,
        }
    }
    /// The person rejected the code (or abandoned the comparison): a failed session, recorded
    /// in `limiter` at `now_ms` (§7.3). Consumes the code.
    pub fn reject(self, limiter: &mut FailureLimiter, now_ms: i64) {
        limiter.record_failure(now_ms);
    }
}

/// A pairing the person confirmed: the only thing from which a seed transfer can be sealed or
/// opened (§7.4), and the token a member approval spends (§9.1). It has no public constructor:
/// it exists only after (a) a compared six-digit code ([`PairingCode::confirm`]), (b) the QR
/// path of §7.3 ([`ScannedQr`], [`QrJoiner`]), or (c) a membership request scanned from the
/// requester's screen ([`scanned_request`], approval only: it carries no nonces and moves no
/// seed). It is not `Clone`: an approval takes it by value and so spends it.
///
/// ```compile_fail
/// use colophon_core::v05::pairing::{ConfirmedPairing, QrPayload};
/// // There is no way to build a confirmed pairing from a payload the caller made.
/// let _ = ConfirmedPairing::from_qr;
/// ```
///
/// ```compile_fail
/// fn twice(p: colophon_core::v05::pairing::ConfirmedPairing) {
///     // A confirmed pairing cannot be copied, so one cannot approve twice.
///     let _q = p.clone();
/// }
/// ```
#[derive(Debug)]
pub struct ConfirmedPairing {
    account: AccountId,
    e: Vec<u8>,
    /// `(nA, nB)`; `None` for a scanned request, which has no nonces.
    nonces: Option<([u8; 32], [u8; 32])>,
    /// When the approving session began (its permit), for a pairing that may approve a member:
    /// the existing side's code session or a scanned request envelope. `None` on the joining
    /// side and for the pairing QR, which moves the seed but does not approve (§9.1: the scan
    /// path's one payload is the canonical request envelope).
    approving_since_ms: Option<i64>,
}
/// Two confirmed pairings are equal when they are the same pairing (account, `E` and nonces),
/// whichever side holds each and whenever its session began: both devices hold equal pairings.
impl PartialEq for ConfirmedPairing {
    fn eq(&self, other: &Self) -> bool {
        self.account == other.account && self.e == other.e && self.nonces == other.nonces
    }
}
impl Eq for ConfirmedPairing {}
impl ConfirmedPairing {
    /// The joining key `E`.
    pub fn e(&self) -> &[u8] {
        &self.e
    }
    /// The account.
    pub fn account(&self) -> &AccountId {
        &self.account
    }
    /// Whether this pairing may approve a member (§9.1): confirmed on the existing side by the
    /// six-digit code, or a request envelope scanned from the requester's screen.
    pub fn may_approve(&self) -> bool {
        self.approving_since_ms.is_some()
    }
    /// Whether this pairing carries both nonces and so may move the seed (§7.4).
    pub fn can_move_seed(&self) -> bool {
        self.nonces.is_some()
    }
    /// The seed-transfer `info` and AAD (§7.4):
    /// `"colophon/vault-transfer/5\n" ‖ accountID ‖ "\n" ‖ keyID(E) ‖ "\n" ‖ hex(nA) ‖ hex(nB)`.
    /// Empty for a scanned request, which has no nonces: sealing or opening a seed with one is
    /// refused.
    pub fn transfer_info(&self) -> Vec<u8> {
        let Some((na, nb)) = &self.nonces else {
            return Vec::new();
        };
        format!(
            "{TRANSFER_LABEL}\n{}\n{}\n{}{}",
            self.account,
            key_id(&self.e),
            hex(na),
            hex(nb)
        )
        .into_bytes()
    }
    fn require_nonces(&self) -> VResult<()> {
        if self.nonces.is_some() {
            Ok(())
        } else {
            Err(malformed(
                "a scanned request approves a member; it cannot move the seed",
            ))
        }
    }
    /// Spend this pairing on approving the member whose `member.signing` is `signing`, in
    /// `account`, at `now_ms` (§9.1, §17.1). Refused `refused:outOfScope` unless it was confirmed
    /// on the existing side, names `account` and paired exactly `signing`; `refused:expired`
    /// when more than [`CONFIRMED_PAIRING_LIFETIME_MS`] passed since H's session began. The
    /// pairing is consumed whatever the answer.
    pub(crate) fn spend_for_grant(
        self,
        account: &AccountId,
        signing: &[u8],
        now_ms: i64,
    ) -> Result<(), Failure> {
        // Joining side, pairing QR, another account or another key: out of scope.
        let Some(started) = self.approving_since_ms else {
            return Err(Failure::Refused(Reason::OutOfScope));
        };
        if &self.account != account || self.e != signing {
            return Err(Failure::Refused(Reason::OutOfScope));
        }
        if now_ms > started.saturating_add(CONFIRMED_PAIRING_LIFETIME_MS) {
            return Err(Failure::Refused(Reason::Expired));
        }
        Ok(())
    }
}

/// The content of the QR code J shows (§7.3): `accountID`, `E` and `nB`, as the canonical JSON
/// bytes of [`QrPayload::to_bytes`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QrPayload {
    /// The account.
    pub account: AccountId,
    /// `E`.
    pub e: Vec<u8>,
    /// `nB`.
    pub nb: [u8; 32],
}

/// The `protocol` marker of the QR payload (§7.3, §20).
pub const QR_PROTOCOL: &str = "colophon/pair-qr/5";

impl QrPayload {
    /// The bytes the QR code carries (§7.3): canonical JSON of the closed object
    /// `{"account","e","nB","protocol"}`, `e` and `nB` standard padded base64.
    pub fn to_bytes(&self) -> VResult<Vec<u8>> {
        super::encoding::canonical(&serde_json::json!({
            "account": self.account.as_str(),
            "e": super::encoding::encode_base64(&self.e),
            "nB": super::encoding::encode_base64(&self.nb),
            "protocol": QR_PROTOCOL,
        }))
    }

    /// Read a QR payload strictly (§7.3): canonical bytes, exactly the four members, the
    /// protocol marker, a valid account ID, `e` a valid 65-byte point and `nB` 32 bytes; anything
    /// else is `malformed`.
    pub fn from_bytes(bytes: &[u8]) -> VResult<Self> {
        let v = super::encoding::canonical_body(bytes, 1_024)?;
        let m = v.as_object().ok_or_else(|| malformed("QR payload"))?;
        if m.len() != 4 {
            return Err(malformed("QR payload members"));
        }
        let text = |k: &str| {
            m.get(k)
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| malformed(format!("QR payload {k}")))
        };
        if text("protocol")? != QR_PROTOCOL {
            return Err(malformed("QR payload protocol"));
        }
        let account =
            AccountId::parse(text("account")?).map_err(|_| malformed("QR payload account"))?;
        let e = super::encoding::decode_base64(text("e")?, 65)?;
        if e.len() != 65 || !valid_point(&e) {
            return Err(malformed("QR payload e"));
        }
        let nb: [u8; 32] = super::encoding::decode_base64(text("nB")?, 32)?
            .try_into()
            .map_err(|_| malformed("QR payload nB"))?;
        Ok(Self { account, e, nb })
    }
}

// --- The joining side J ------------------------------------------------------------------

/// J after choosing `nB` and sending the commitment (§7.3 step 1).
#[derive(Debug)]
pub struct Joiner {
    account: AccountId,
    e: Vec<u8>,
    nb: [u8; 32],
}
impl Joiner {
    /// Begin: J holds `E` (a transfer key's public point, or a new member's signing key) and
    /// chose `nb` at random. Returns the commitment `C` to send first.
    pub fn begin(
        account: &AccountId,
        e: &[u8],
        nb: [u8; 32],
    ) -> Result<(Self, [u8; 32]), PairingAbort> {
        let c = commitment(account, e, &nb)?;
        Ok((
            Self {
                account: account.clone(),
                e: e.to_vec(),
                nb,
            },
            c,
        ))
    }
    /// Step 3: after receiving `nA`, reveal `E` and `nB` once (this consumes the session) and
    /// show the code.
    pub fn reveal(self, na: [u8; 32]) -> Result<(Reveal, PairingCode), PairingAbort> {
        let digits = code(&self.account, &self.e, &na, &self.nb)?;
        let reveal = Reveal {
            e: self.e.clone(),
            nb: self.nb,
        };
        Ok((
            reveal,
            PairingCode {
                account: self.account,
                e: self.e,
                na,
                nb: self.nb,
                digits,
                started_ms: None,
            },
        ))
    }
}

/// J in the QR alternative (§7.3): a different session type from [`Joiner`]. It never sends
/// a commitment, and a code-flow `Joiner` can never produce a payload, so `nB` is not
/// obtainable except by choosing this path at the start.
#[derive(Debug)]
pub struct QrJoiner {
    account: AccountId,
    e: Vec<u8>,
    nb: [u8; 32],
}
impl QrJoiner {
    /// J holds `E` and chose `nb`; it will show `accountID`, `E` and `nB` as a QR code.
    pub fn begin(account: &AccountId, e: &[u8], nb: [u8; 32]) -> Result<Self, PairingAbort> {
        check_point(e)?;
        Ok(Self {
            account: account.clone(),
            e: e.to_vec(),
            nb,
        })
    }
    /// What J shows on its screen.
    pub fn payload(&self) -> QrPayload {
        QrPayload {
            account: self.account.clone(),
            e: self.e.clone(),
            nb: self.nb,
        }
    }
    /// H sent `nA` after scanning: J now has both nonces. No code is compared. Consumes J.
    pub fn receive_nonce(self, na: [u8; 32]) -> ConfirmedPairing {
        ConfirmedPairing {
            account: self.account,
            e: self.e,
            nonces: Some((na, self.nb)),
            approving_since_ms: None,
        }
    }
}

// --- The existing side H -----------------------------------------------------------------

/// H after receiving `C` and before choosing `nA` (§7.3 step 2: "only after receiving `C`").
/// There is no way to obtain a nonce-bearing state without this one.
#[derive(Debug)]
pub struct ExistingWaiting {
    account: AccountId,
    commitment: [u8; 32],
    started_ms: i64,
}
impl ExistingWaiting {
    /// H received `C` for `account`. A session needs a [`Permit`] from the failure limiter
    /// (§7.3: no more than 5 failed sessions per hour); there is no way to start one without it.
    /// The session begins at the permit's time.
    pub fn receive_commitment(account: &AccountId, commitment: [u8; 32], permit: Permit) -> Self {
        Self {
            account: account.clone(),
            commitment,
            started_ms: permit.at_ms,
        }
    }
    /// Step 2: H chose `nA` (host-random, only now) and sends it. Returns the nonce and the
    /// state that accepts exactly one reveal.
    pub fn send_nonce(self, na: [u8; 32]) -> (ExistingAwaitingReveal, [u8; 32]) {
        (
            ExistingAwaitingReveal {
                account: self.account,
                commitment: self.commitment,
                na,
                started_ms: self.started_ms,
            },
            na,
        )
    }
}

/// H after sending `nA`: it accepts one reveal, and a mismatch aborts the session.
#[derive(Debug)]
pub struct ExistingAwaitingReveal {
    account: AccountId,
    commitment: [u8; 32],
    na: [u8; 32],
    started_ms: i64,
}
impl ExistingAwaitingReveal {
    /// Step 3 and 4: J sent `E` and `nB`. H checks `C`; a mismatch aborts
    /// ([`PairingAbort::CommitmentMismatch`]). Otherwise the code to display and compare.
    /// Consumes the session: a commitment permits exactly one reveal.
    pub fn finish(self, e: &[u8], nb: &[u8; 32]) -> Result<PairingCode, PairingAbort> {
        check_point(e)?;
        if commitment(&self.account, e, nb)? != self.commitment {
            return Err(PairingAbort::CommitmentMismatch);
        }
        let digits = code(&self.account, e, &self.na, nb)?;
        Ok(PairingCode {
            account: self.account,
            e: e.to_vec(),
            na: self.na,
            nb: *nb,
            digits,
            started_ms: Some(self.started_ms),
        })
    }
    /// [`ExistingAwaitingReveal::finish`], recording an abort in `limiter` at `now_ms`.
    pub fn finish_limited(
        self,
        e: &[u8],
        nb: &[u8; 32],
        limiter: &mut FailureLimiter,
        now_ms: i64,
    ) -> Result<PairingCode, PairingAbort> {
        let result = self.finish(e, nb);
        if result.is_err() {
            limiter.record_failure(now_ms);
        }
        result
    }
}

/// H scanned J's QR code (§7.3 QR alternative). What authenticates `E` here is the scan itself:
/// `accountID`, `E` and `nB` come from J's screen over a channel the person controls, so `E`
/// is checked directly and no code is compared. The core cannot verify that a scan happened:
/// the host calls [`ScannedQr::scan`] only with a payload it read from J's screen. H still
/// sends `nA`, so that §7.4's label has both nonces.
#[derive(Debug)]
pub struct ScannedQr {
    payload: QrPayload,
}
impl ScannedQr {
    /// H scanned `payload` while pairing for `expected`. A payload for another account or with
    /// an invalid `E` aborts. A [`Permit`] from the limiter is required, as for a code session.
    pub fn scan(
        expected: &AccountId,
        payload: &QrPayload,
        _permit: Permit,
    ) -> Result<Self, PairingAbort> {
        if payload.account != *expected {
            return Err(PairingAbort::WrongAccount);
        }
        check_point(&payload.e)?;
        Ok(Self {
            payload: payload.clone(),
        })
    }
    /// H chose `nA` and sends it to J. Consumes the scan.
    pub fn send_nonce(self, na: [u8; 32]) -> (ConfirmedPairing, [u8; 32]) {
        (
            ConfirmedPairing {
                account: self.payload.account,
                e: self.payload.e,
                nonces: Some((na, self.payload.nb)),
                // The pairing QR moves the seed; it does not approve a member (§9.1).
                approving_since_ms: None,
            },
            na,
        )
    }
}

/// H scanned a membership request from the requester's screen (§7.3 QR alternative, §7a): the
/// scan authenticates the request's `member.signing` as `E` directly, so nothing is compared.
/// The request must parse and verify under its own key (§9.1) and name `expected`; otherwise the
/// session aborts. A [`Permit`] from the limiter is required, as for any session H starts. The
/// result approves that one request and carries no nonces, so it cannot move the seed. As with
/// [`ScannedQr::scan`], the core cannot see a camera: the host calls this only with bytes it
/// read from the requester's screen.
pub fn scanned_request(
    expected: &AccountId,
    request: &[u8],
    permit: Permit,
) -> Result<ConfirmedPairing, PairingAbort> {
    let req = super::members::Request::parse(request, true)
        .map_err(|_| PairingAbort::InvalidRequest)?;
    if req.account != *expected {
        return Err(PairingAbort::WrongAccount);
    }
    check_point(&req.signing)?;
    Ok(ConfirmedPairing {
        account: req.account,
        e: req.signing,
        nonces: None,
        approving_since_ms: Some(permit.at_ms),
    })
}

/// The failed-session limit of H (§7.3): no more than 5 failed sessions per hour. A mismatch,
/// abort or timeout is a failure; the host records it with the time it observed. The ledger is
/// plain data the host persists.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureLimiter {
    failures_ms: Vec<i64>,
    /// The latest time this ledger has seen: a clock moved backwards never reopens the budget.
    #[serde(default)]
    latest_ms: i64,
}

/// Permission to start one pairing session, taken from the limiter. It cannot be made any
/// other way, and every session start ([`ExistingWaiting::receive_commitment`],
/// [`ScannedQr::scan`], [`scanned_request`]) consumes one. It carries the time the session
/// began (the latest the ledger has seen), from which a confirmed pairing's lifetime runs.
#[derive(Debug)]
pub struct Permit {
    at_ms: i64,
}
impl Permit {
    /// The session was abandoned or timed out: a failure, recorded at `now_ms` (§7.3).
    pub fn abandon(self, limiter: &mut FailureLimiter, now_ms: i64) {
        limiter.record_failure(now_ms);
    }
}

/// The limit is reached: 5 failed sessions in the last hour (§7.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LimitReached;
impl std::fmt::Display for LimitReached {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("pairing: 5 failed sessions in the last hour")
    }
}
impl std::error::Error for LimitReached {}

impl FailureLimiter {
    /// An empty ledger.
    pub fn new() -> Self {
        Self::default()
    }
    fn effective(&self, now_ms: i64) -> i64 {
        now_ms.max(self.latest_ms)
    }
    /// Record a failed session (mismatch, abort, rejected code or timeout) at `now_ms`.
    pub fn record_failure(&mut self, now_ms: i64) {
        let now = self.effective(now_ms);
        self.latest_ms = now;
        self.failures_ms.retain(|t| *t > now - 3_600_000);
        self.failures_ms.push(now);
    }
    /// True when a new session may start: fewer than 5 failures in the last hour, measured at
    /// the latest time the ledger has seen (a clock moved backwards does not help).
    pub fn may_start(&self, now_ms: i64) -> bool {
        let now = self.effective(now_ms);
        self.failures_ms
            .iter()
            .filter(|t| **t > now - 3_600_000)
            .count()
            < MAX_FAILED_PER_HOUR
    }
    /// Start a session: a [`Permit`], or [`LimitReached`]. Sessions cannot start without one.
    pub fn permit(&mut self, now_ms: i64) -> Result<Permit, LimitReached> {
        self.latest_ms = self.effective(now_ms);
        if self.may_start(now_ms) {
            Ok(Permit {
                at_ms: self.latest_ms,
            })
        } else {
            Err(LimitReached)
        }
    }
}

// --- Moving the seed (§7.4) --------------------------------------------------------------

/// The seed holder seals the seed to `E` (§7.4): HPKE (§11.1 suite) with `info` and AAD
/// [`ConfirmedPairing::transfer_info`]. Offered only to a device about to become a controller
/// with a slot; the host decides that. The seed is not read here: it is sealed by the vault
/// handle.
pub fn seal_seed_for_transfer(
    seed: &VaultSeed,
    pairing: &ConfirmedPairing,
    entropy: &mut Entropy,
) -> VResult<SealedBox> {
    pairing.require_nonces()?;
    seed.seal_to(pairing.e(), &pairing.transfer_info(), entropy)
}

/// The new device's ephemeral agreement key `E` (§7.4). The private scalar never leaves it; it
/// is erased when dropped, which the host does when the session ends.
#[derive(Debug)]
pub struct TransferKey(AgreementKey);
impl TransferKey {
    /// Generate `E` from a fresh host-random 32-byte seed (expanded by §7.5).
    pub fn new(entropy_seed: [u8; 32]) -> VResult<Self> {
        AgreementKey::ephemeral(entropy_seed).map(Self)
    }
    /// The 65-byte public point `E`.
    pub fn public(&self) -> Vec<u8> {
        self.0.public()
    }
    /// The new device opens the transfer and checks it against the keyring's vault (§7.1,
    /// §7.4): wrong nonces, a wrong `E` or a wrong account change the `info` and fail as
    /// `refused:vaultLocked`; so does a seed that does not derive `vault`.
    pub fn open_seed(
        &self,
        sealed: &SealedBox,
        pairing: &ConfirmedPairing,
        vault: &VaultPublic,
    ) -> VResult<VaultSeed> {
        vault.validate()?;
        pairing.require_nonces()?;
        if pairing.e() != self.public().as_slice() {
            return Err(malformed("the pairing is not for this transfer key"));
        }
        self.0
            .open_seed(sealed, &pairing.transfer_info(), vault)
            .map(|s| s.bound_to(pairing.account()))
    }
}
