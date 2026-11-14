//! Pairing (§7.3) and moving the seed to a new device (§7.4).
//!
//! **No secret crosses this module.** Pairing handles only public values (the account ID, the
//! point `E` and the two nonces). The seed moves only as an HPKE ciphertext: the seed holder
//! seals it through [`VaultSeed`]'s sealing method (the seed bytes are never read here), and
//! the new device opens it with a [`TransferKey`], whose private scalar lives inside an opaque
//! [`AgreementKey`] of [`super::vault`] and is never exposed; the result is a [`VaultSeed`]
//! handle, checked against the keyring's vault. No raw ECDH result is formed here.
//!
//! The core has no clock and no RNG: nonces, the ephemeral key's seed and the time of every
//! failure come in as arguments. The state machine consumes itself at each step, so a
//! commitment permits exactly one reveal (§7.3).
use super::descriptor::valid_point;
use super::encoding::hex;
use super::ids::{key_id, AccountId};
use super::vault::{malformed, AgreementKey, SealedBox, VResult, VaultPublic, VaultSeed};
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

/// Why a pairing aborted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingAbort {
    /// `SHA-256("colophon/pair/5" ‖ accountID ‖ E ‖ nB)` did not equal the commitment `C`:
    /// "abort: commitment mismatch".
    CommitmentMismatch,
    /// `E` is not a valid uncompressed P-256 point.
    InvalidPoint,
    /// A QR payload names another account.
    WrongAccount,
}
impl std::fmt::Display for PairingAbort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::CommitmentMismatch => "abort: commitment mismatch",
            Self::InvalidPoint => "abort: E is not a valid point",
            Self::WrongAccount => "abort: QR names another account",
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
/// by eye; [`PairingCode::confirm`] is the person's "they match".
#[derive(Clone, Debug)]
pub struct PairingCode {
    account: AccountId,
    e: Vec<u8>,
    na: [u8; 32],
    nb: [u8; 32],
    digits: String,
}
impl PairingCode {
    /// The six digits to display.
    pub fn digits(&self) -> &str {
        &self.digits
    }
    /// The person confirmed that the codes match: a pairing that §7.4 may use.
    pub fn confirm(self) -> ConfirmedPairing {
        ConfirmedPairing {
            account: self.account,
            e: self.e,
            na: self.na,
            nb: self.nb,
        }
    }
}

/// A pairing the person confirmed (or a QR pairing): the only thing from which a seed transfer
/// can be sealed or opened (§7.4). It carries both nonces for the transfer label.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfirmedPairing {
    account: AccountId,
    e: Vec<u8>,
    na: [u8; 32],
    nb: [u8; 32],
}
impl ConfirmedPairing {
    /// The QR alternative (§7.3): H scans `accountID`, `E` and `nB` from J's screen and checks
    /// `E` directly; H still sends `nA` to J so both sides have both nonces. No code is
    /// compared. `expected` is the account the scanning side means to pair for.
    pub fn from_qr(
        expected: &AccountId,
        payload: &QrPayload,
        na: [u8; 32],
    ) -> Result<Self, PairingAbort> {
        if payload.account != *expected {
            return Err(PairingAbort::WrongAccount);
        }
        check_point(&payload.e)?;
        Ok(Self {
            account: payload.account.clone(),
            e: payload.e.clone(),
            na,
            nb: payload.nb,
        })
    }
    /// The joining side of a QR pairing: it displayed the QR and now has H's `nA`.
    pub fn joiner_qr(
        account: &AccountId,
        e: &[u8],
        nb: [u8; 32],
        na: [u8; 32],
    ) -> Result<Self, PairingAbort> {
        check_point(e)?;
        Ok(Self {
            account: account.clone(),
            e: e.to_vec(),
            na,
            nb,
        })
    }
    /// The joining key `E`.
    pub fn e(&self) -> &[u8] {
        &self.e
    }
    /// The account.
    pub fn account(&self) -> &AccountId {
        &self.account
    }
    /// The seed-transfer `info` and AAD (§7.4):
    /// `"colophon/vault-transfer/5\n" ‖ accountID ‖ "\n" ‖ keyID(E) ‖ "\n" ‖ hex(nA) ‖ hex(nB)`.
    pub fn transfer_info(&self) -> Vec<u8> {
        format!(
            "{TRANSFER_LABEL}\n{}\n{}\n{}{}",
            self.account,
            key_id(&self.e),
            hex(&self.na),
            hex(&self.nb)
        )
        .into_bytes()
    }
}

/// The content of the QR code J shows (§7.3): `accountID`, `E` and `nB`. The byte format of the
/// QR itself is not specified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QrPayload {
    /// The account.
    pub account: AccountId,
    /// `E`.
    pub e: Vec<u8>,
    /// `nB`.
    pub nb: [u8; 32],
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
            },
        ))
    }
    /// The QR payload for the QR alternative: J shows `accountID`, `E` and `nB` instead of
    /// sending a commitment.
    pub fn qr_payload(&self) -> QrPayload {
        QrPayload {
            account: self.account.clone(),
            e: self.e.clone(),
            nb: self.nb,
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
}
impl ExistingWaiting {
    /// H received `C` for `account`.
    pub fn receive_commitment(account: &AccountId, commitment: [u8; 32]) -> Self {
        Self {
            account: account.clone(),
            commitment,
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

/// The failed-session limit of H (§7.3): no more than 5 failed sessions per hour. A mismatch,
/// abort or timeout is a failure; the host records it with the time it observed. The ledger is
/// plain data the host persists.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureLimiter {
    failures_ms: Vec<i64>,
}
impl FailureLimiter {
    /// An empty ledger.
    pub fn new() -> Self {
        Self::default()
    }
    /// Record a failed session (mismatch, abort or timeout) at `now_ms`.
    pub fn record_failure(&mut self, now_ms: i64) {
        self.prune(now_ms);
        self.failures_ms.push(now_ms);
    }
    /// True when a new session may start: fewer than 5 failures in the last hour.
    pub fn may_start(&self, now_ms: i64) -> bool {
        self.failures_ms
            .iter()
            .filter(|t| **t > now_ms - 3_600_000 && **t <= now_ms)
            .count()
            < MAX_FAILED_PER_HOUR
    }
    fn prune(&mut self, now_ms: i64) {
        self.failures_ms.retain(|t| *t > now_ms - 3_600_000);
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
        if pairing.e() != self.public().as_slice() {
            return Err(malformed("the pairing is not for this transfer key"));
        }
        self.0.open_seed(sealed, &pairing.transfer_info(), vault)
    }
}
