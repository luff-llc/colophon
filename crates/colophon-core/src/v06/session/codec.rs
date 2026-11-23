//! Sealing and opening frames (§S2, §S3).
//!
//! [`Sender`] turns a plaintext [`Frame`] from the state machine into wire bytes: it numbers
//! the frame under its session key, derives the per-session-key AES-256-GCM key from the
//! namespace epoch key, encrypts with nonce = `n`, signs the canonical body and attaches the
//! delegation. [`Receiver`] runs the §S3 receiver checks in order and hands back the opened
//! frame with the inputs the state machine expects (`writer`, `key`, `n`).
//!
//! Layers. This module owns signatures, delegations, sealing and the 128-wide replay window
//! per `(member, key)` (at most 4 keys per member). The §S3 freshness exchange (`fresh`,
//! `echo`, the window floor opened by an echoing `hello`, the 60 s / 32-value memory and the
//! once-per-`askTimeoutMs` retry) is owned by the state machine ([`super::Session`]), which
//! receives each frame's `key` and `n` for it.
//!
//! Every failure is a silent drop that changes no state: a receiver computes everything first
//! and commits the accepted key and the window update only when every check has passed.
use super::keys::{Delegation, KeyError, SessionAccount, SessionKey};
use super::types::{Body, Frame, MemberId};
use super::wire::{decode_body, encode_body, DropReason, Outer, WireFrame, MAX_FRAME_BYTES};
use crate::v05::signature::verify_raw;
use crate::v05::terms::Access;
use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use std::collections::BTreeMap;
use zeroize::{Zeroize, Zeroizing};

/// The `info` prefix of the frame key derivation (§S3).
pub const FRAME_KEY_INFO: &str = "colophon/session-frame/6";
/// Width of the replay window (§S3).
pub const WINDOW: u64 = 128;
/// Session keys kept per member (§S3).
pub const KEYS_PER_MEMBER: usize = 4;

/// A cell: `(account, namespace, cell)` (§S1).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CellId {
    /// The account (64 hex).
    pub account: String,
    /// The namespace.
    pub namespace: String,
    /// The cell name.
    pub cell: String,
}
impl CellId {
    /// A cell.
    pub fn new(account: &str, namespace: &str, cell: &str) -> Self {
        Self {
            account: account.to_owned(),
            namespace: namespace.to_owned(),
            cell: cell.to_owned(),
        }
    }
}

/// Namespace epoch keys (0.5 §11.1), supplied by the host. Returned key bytes are wiped when
/// the core drops them.
pub trait EpochKeys {
    /// The newest epoch of `namespace` this member holds; frames are sealed under it.
    fn current_epoch(&self, namespace: &str) -> Option<u64>;
    /// The 32-byte key of `epoch` of `namespace`, if this member holds it.
    fn epoch_key(&self, namespace: &str, epoch: u64) -> Option<Zeroizing<[u8; 32]>>;
}

/// A fixed table of epoch keys (tests and tools). Wiped on drop.
#[derive(Default)]
pub struct EpochTable {
    keys: BTreeMap<(String, u64), [u8; 32]>,
}
impl EpochTable {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }
    /// Add a key.
    pub fn with(mut self, namespace: &str, epoch: u64, key: [u8; 32]) -> Self {
        self.keys.insert((namespace.to_owned(), epoch), key);
        self
    }
}
impl Drop for EpochTable {
    fn drop(&mut self) {
        for k in self.keys.values_mut() {
            k.zeroize();
        }
    }
}
impl EpochKeys for EpochTable {
    fn current_epoch(&self, namespace: &str) -> Option<u64> {
        self.keys
            .keys()
            .filter(|(n, _)| n == namespace)
            .map(|(_, e)| *e)
            .max()
    }
    fn epoch_key(&self, namespace: &str, epoch: u64) -> Option<Zeroizing<[u8; 32]>> {
        self.keys
            .get(&(namespace.to_owned(), epoch))
            .map(|k| Zeroizing::new(*k))
    }
}

/// The `info` of the frame key: `colophon/session-frame/6\n<account>\n<namespace>\n<cell>\n<key>`.
pub fn frame_key_info(cell: &CellId, key_id: &str) -> Vec<u8> {
    format!(
        "{FRAME_KEY_INFO}\n{}\n{}\n{}\n{key_id}",
        cell.account, cell.namespace, cell.cell
    )
    .into_bytes()
}

/// The AES-256-GCM key used by one session key in one cell under one epoch: HKDF-SHA-256 of
/// the epoch key, no salt, [`frame_key_info`], 32 bytes.
pub fn frame_key(epoch_key: &[u8; 32], cell: &CellId, key_id: &str) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    // 32 bytes is always a valid HKDF-SHA-256 output length.
    let _ = Hkdf::<Sha256>::new(None, epoch_key).expand(&frame_key_info(cell, key_id), &mut *out);
    out
}

/// The nonce: `n` as 12 big-endian bytes.
pub fn nonce(n: u64) -> [u8; 12] {
    let mut b = [0u8; 12];
    b[4..].copy_from_slice(&n.to_be_bytes());
    b
}

/// Encrypt a plaintext under a frame key.
pub fn encrypt(key: &[u8; 32], n: u64, aad: &[u8], plaintext: &[u8]) -> Option<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    cipher
        .encrypt(Nonce::from_slice(&nonce(n)), Payload { msg: plaintext, aad })
        .ok()
}

/// Decrypt a ciphertext under a frame key.
pub fn decrypt(key: &[u8; 32], n: u64, aad: &[u8], ciphertext: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    cipher
        .decrypt(Nonce::from_slice(&nonce(n)), Payload { msg: ciphertext, aad })
        .ok()
        .map(Zeroizing::new)
}

/// The 128-wide window of one sender key (§S3): the highest accepted `n`, and which of the 128
/// values below it were accepted. A frame whose `n` was accepted, or that is more than 128
/// below the highest, is dropped; gaps and reordering inside the window are allowed. The same
/// shape as the bridge's forwarding window ([`crate::v06::bridge::Window`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ReplayWindow {
    high: u64,
    /// Bit `i` set: `high − 1 − i` was accepted.
    below: u128,
}
impl ReplayWindow {
    /// Whether `n` would be accepted now. Changes nothing.
    pub fn check(&self, n: u64) -> Result<(), DropReason> {
        if self.high == 0 || n > self.high {
            return Ok(());
        }
        if n == self.high {
            return Err(DropReason::Replay);
        }
        let back = self.high - n; // 1..
        if back > WINDOW {
            return Err(DropReason::TooOld);
        }
        if self.below & (1u128 << (back - 1)) != 0 {
            Err(DropReason::Replay)
        } else {
            Ok(())
        }
    }
    /// Record `n` as accepted (after [`ReplayWindow::check`] passed).
    pub fn admit(&mut self, n: u64) {
        if self.high == 0 {
            self.high = n;
            return;
        }
        if n > self.high {
            let shift = n - self.high;
            self.below = if shift >= 128 {
                if shift == 128 {
                    1u128 << 127
                } else {
                    0
                }
            } else {
                (self.below << shift) | (1u128 << (shift - 1))
            };
            self.high = n;
        } else if n < self.high {
            let back = self.high - n;
            if back <= WINDOW {
                self.below |= 1u128 << (back - 1);
            }
        }
    }
    /// The highest accepted `n` (0 before any).
    pub fn high(&self) -> u64 {
        self.high
    }
}

/// An accepted session key of another member.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Accepted {
    delegation: Delegation,
    window: ReplayWindow,
    /// Acceptance order, for the 4-keys-per-member cap.
    since: u64,
}

/// A frame that passed every §S3 check, with the inputs the state machine expects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opened {
    /// The opened frame.
    pub frame: Frame,
    /// Whether the sender's entry for the namespace has access `write` (§S1).
    pub writer: bool,
    /// The sender's session key ID.
    pub key: String,
    /// The frame's `n`.
    pub n: u64,
    /// The epoch it was sealed under.
    pub epoch: u64,
}

/// A dropped frame: why, and whether §S3 asks the receiver to send `hello` to the sender
/// (no accepted session key for `(from, key)`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dropped {
    /// Why.
    pub reason: DropReason,
    /// Send `hello` to this member.
    pub hello_to: Option<MemberId>,
}
impl From<DropReason> for Dropped {
    fn from(reason: DropReason) -> Self {
        Self {
            reason,
            hello_to: None,
        }
    }
}

/// The receiving side of one member in one cell: accepted session keys of other members and
/// their replay windows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receiver {
    cell: CellId,
    me: MemberId,
    keys: BTreeMap<(MemberId, String), Accepted>,
    counter: u64,
}
impl Receiver {
    /// A receiver for `me` in `cell`, knowing no keys.
    pub fn new(cell: CellId, me: &str) -> Self {
        Self {
            cell,
            me: me.to_owned(),
            keys: BTreeMap::new(),
            counter: 0,
        }
    }
    /// The number of accepted session keys of `member`.
    pub fn keys_for(&self, member: &str) -> usize {
        self.keys.keys().filter(|(m, _)| m == member).count()
    }
    /// Whether `(member, key)` is an accepted session key.
    pub fn knows(&self, member: &str, key: &str) -> bool {
        self.keys.contains_key(&(member.to_owned(), key.to_owned()))
    }
    /// The replay window of `(member, key)`.
    pub fn window(&self, member: &str, key: &str) -> Option<ReplayWindow> {
        self.keys
            .get(&(member.to_owned(), key.to_owned()))
            .map(|a| a.window)
    }

    /// A newly accepted authority head (§S2): drop every key whose member is no longer
    /// current, lost its `records` entry for the namespace, or has another session number.
    /// Returns the members left with no key, for the state machine to forget.
    pub fn set_account(&mut self, view: &SessionAccount, wall_ms: i64) -> Vec<MemberId> {
        let before: Vec<MemberId> = self.keys.keys().map(|(m, _)| m.clone()).collect();
        self.keys
            .retain(|_, a| a.delegation.holds_in(view, wall_ms));
        let mut gone: Vec<MemberId> = before
            .into_iter()
            .filter(|m| self.keys_for(m) == 0)
            .collect();
        gone.dedup();
        gone
    }

    /// Run the §S3 receiver checks, in order: parse with closed field sets; check `account`,
    /// `namespace` and `cell`; verify a carried delegation that names `(from, key)`; find an
    /// accepted session key (its window re-checked at `wall_ms`), else drop and ask for a
    /// `hello`; verify the frame signature; check `n` against the replay window; open the
    /// ciphertext; decode the plaintext strictly. Only then is anything remembered.
    pub fn open(
        &mut self,
        bytes: &[u8],
        view: &SessionAccount,
        wall_ms: i64,
        epochs: &dyn EpochKeys,
        max_payload: u64,
    ) -> Result<Opened, Dropped> {
        let w = WireFrame::parse(bytes)?;
        let o = &w.outer;
        if o.account != self.cell.account || o.account != view.account() {
            return Err(DropReason::Account.into());
        }
        if o.namespace != self.cell.namespace {
            return Err(DropReason::Namespace.into());
        }
        if o.cell != self.cell.cell {
            return Err(DropReason::Cell.into());
        }
        if o.from == self.me {
            return Err(DropReason::FromSelf.into());
        }
        let slot = (o.from.clone(), o.key.clone());
        let stored = self.keys.get(&slot);
        // A carried delegation must name (from, key) and verify; one byte-identical to the
        // accepted envelope for that pair is the same verified object.
        let fresh = match &w.delegation {
            None => None,
            Some(env) if stored.is_some_and(|a| &a.delegation.envelope == env) => None,
            Some(env) => {
                let d = Delegation::parse(env).map_err(DropReason::Delegation)?;
                if d.body.member != o.from || d.key_id() != o.key {
                    return Err(DropReason::Delegation("names another (from, key)".into()).into());
                }
                d.verify(view, &o.namespace, wall_ms)
                    .map_err(DropReason::Delegation)?;
                Some(d)
            }
        };
        let Some(delegation) = fresh.as_ref().or(stored.map(|a| &a.delegation)) else {
            return Err(Dropped {
                reason: DropReason::NoKey,
                hello_to: Some(o.from.clone()),
            });
        };
        if !delegation.holds_in(view, wall_ms) {
            return Err(Dropped {
                reason: DropReason::NoKey,
                hello_to: Some(o.from.clone()),
            });
        }
        if !delegation.body.in_window(wall_ms) {
            return Err(Dropped {
                reason: DropReason::KeyWindow,
                hello_to: Some(o.from.clone()),
            });
        }
        verify_raw(&delegation.body.key, &w.signed_body(), &w.signature)
            .map_err(|_| DropReason::Signature)?;
        let mut window = stored.map(|a| a.window).unwrap_or_default();
        window.check(o.n)?;
        let epoch_key = epochs
            .epoch_key(&o.namespace, o.epoch)
            .ok_or(DropReason::NoEpoch(o.epoch))?;
        let key = frame_key(&epoch_key, &self.cell, &o.key);
        let plaintext = decrypt(&key, o.n, &o.aad(), &w.ciphertext).ok_or(DropReason::Open)?;
        let body = decode_body(&plaintext, max_payload)?;

        // Every check passed: commit.
        window.admit(o.n);
        let writer = view.access(&o.from, &o.namespace, wall_ms) == Some(Access::Write);
        match fresh {
            Some(d) => self.accept(slot, d, window),
            None => {
                if let Some(a) = self.keys.get_mut(&slot) {
                    a.window = window;
                }
            }
        }
        Ok(Opened {
            frame: Frame {
                from: o.from.clone(),
                to: o.to.clone(),
                retain: o.retain,
                body,
            },
            writer,
            key: o.key.clone(),
            n: o.n,
            epoch: o.epoch,
        })
    }

    fn accept(&mut self, slot: (MemberId, String), d: Delegation, window: ReplayWindow) {
        if let Some(a) = self.keys.get_mut(&slot) {
            // A renewed delegation for a known key keeps its window.
            a.delegation = d;
            a.window = window;
            return;
        }
        // At most 4 keys per member: drop the oldest.
        while self.keys_for(&slot.0) >= KEYS_PER_MEMBER {
            let oldest = self
                .keys
                .iter()
                .filter(|((m, _), _)| *m == slot.0)
                .min_by_key(|(_, a)| a.since)
                .map(|(k, _)| k.clone());
            match oldest {
                Some(k) => {
                    self.keys.remove(&k);
                }
                None => break,
            }
        }
        self.counter += 1;
        self.keys.insert(
            slot,
            Accepted {
                delegation: d,
                window,
                since: self.counter,
            },
        );
    }
}

/// Why a frame could not be sealed. The frame is not sent; to the protocol that is loss.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SealError {
    /// The host has not signed a delegation for the session key yet.
    NoDelegation,
    /// The delegation's window does not include the clock (± 60 s): renew it.
    DelegationWindow,
    /// The frame's `from` is not this member.
    NotMine,
    /// The host holds no epoch of the namespace.
    NoEpoch,
    /// The session key cannot number another frame.
    Key(KeyError),
    /// The encoded frame would exceed 16,384 bytes.
    Oversize,
    /// The plaintext could not be encoded.
    Encode(String),
}
impl std::fmt::Display for SealError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for SealError {}

/// The sending side of one member in one cell: its session key, the counter `n` and the
/// host-signed delegation.
#[derive(Debug)]
pub struct Sender {
    cell: CellId,
    me: MemberId,
    key: SessionKey,
    delegation: Option<Delegation>,
}
impl Sender {
    /// A sender for `me` in `cell` with a fresh session key.
    pub fn new(cell: CellId, me: &str, key: SessionKey) -> Self {
        Self {
            cell,
            me: me.to_owned(),
            key,
            delegation: None,
        }
    }
    /// The session key.
    pub fn key(&self) -> &SessionKey {
        &self.key
    }
    /// The installed delegation.
    pub fn delegation(&self) -> Option<&Delegation> {
        self.delegation.as_ref()
    }
    /// The exact delegation body for the host to sign with the member key.
    pub fn delegation_body(
        &self,
        session: u64,
        not_before_ms: i64,
        expires_ms: i64,
    ) -> Result<Vec<u8>, KeyError> {
        self.key.delegation_body(
            &self.cell.account,
            &self.me,
            session,
            &self.cell.namespace,
            not_before_ms,
            expires_ms,
        )
    }
    /// Verify a host-signed delegation for this key under `view` and install it.
    pub fn install(
        &mut self,
        body: &[u8],
        signature: &[u8],
        view: &SessionAccount,
        wall_ms: i64,
    ) -> Result<(), String> {
        let d = Delegation::assemble(body, signature)?;
        if d.body.member != self.me || d.key_id() != self.key.id() {
            return Err("the delegation names another member or key".into());
        }
        d.verify(view, &self.cell.namespace, wall_ms)?;
        self.delegation = Some(d);
        Ok(())
    }

    /// Seal a frame from the state machine. A `hello` always carries the delegation; any other
    /// frame carries it when it still fits in 16,384 bytes.
    pub fn seal(
        &mut self,
        frame: &Frame,
        epochs: &dyn EpochKeys,
        wall_ms: i64,
    ) -> Result<Vec<u8>, SealError> {
        if frame.from != self.me {
            return Err(SealError::NotMine);
        }
        let plaintext = Zeroizing::new(encode_body(&frame.body).map_err(SealError::Encode)?);
        let hello = matches!(frame.body, Body::Hello { .. });
        self.seal_plaintext(
            frame.to.as_deref(),
            frame.retain,
            &plaintext,
            if hello { Attach::Always } else { Attach::IfFits },
            epochs,
            wall_ms,
        )
    }

    /// Seal arbitrary plaintext bytes (conformance tools and negative tests). `n` still comes
    /// from the key's counter.
    pub fn seal_plaintext(
        &mut self,
        to: Option<&str>,
        retain: bool,
        plaintext: &[u8],
        attach: Attach,
        epochs: &dyn EpochKeys,
        wall_ms: i64,
    ) -> Result<Vec<u8>, SealError> {
        let delegation = self.delegation.as_ref().ok_or(SealError::NoDelegation)?;
        if !delegation.body.in_window(wall_ms) {
            return Err(SealError::DelegationWindow);
        }
        let envelope = delegation.envelope.clone();
        let epoch = epochs
            .current_epoch(&self.cell.namespace)
            .ok_or(SealError::NoEpoch)?;
        let epoch_key = epochs
            .epoch_key(&self.cell.namespace, epoch)
            .ok_or(SealError::NoEpoch)?;
        let n = self.key.next_n().map_err(SealError::Key)?;
        let outer = Outer {
            account: self.cell.account.clone(),
            namespace: self.cell.namespace.clone(),
            cell: self.cell.cell.clone(),
            from: self.me.clone(),
            key: self.key.id().to_owned(),
            to: to.map(str::to_owned),
            n,
            epoch,
            retain,
        };
        let key = frame_key(&epoch_key, &self.cell, self.key.id());
        let ciphertext = encrypt(&key, n, &outer.aad(), plaintext)
            .ok_or_else(|| SealError::Encode("AES-GCM".into()))?;
        let signature = self.key.sign(&outer.signed_body(&ciphertext));
        let mut wire = WireFrame {
            outer,
            ciphertext,
            signature,
            delegation: (attach != Attach::Never).then_some(envelope),
        };
        let mut bytes = wire.encode();
        if bytes.len() > MAX_FRAME_BYTES && attach == Attach::IfFits {
            wire.delegation = None;
            bytes = wire.encode();
        }
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(SealError::Oversize);
        }
        Ok(bytes)
    }
}

/// Whether a sealed frame carries the delegation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Attach {
    /// Always (every `hello`).
    Always,
    /// When the frame still fits in 16,384 bytes with it.
    IfFits,
    /// Never.
    Never,
}
