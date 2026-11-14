//! The vault (§7.1), software identities and kits (§7.5), and the restricted vault HPKE open
//! (§17.1) under Colophon 0.5.
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
//! **How the secrets are kept inside the core (§3.4, §17.1).** Every secret is an opaque type
//! with private fields and no accessor of any visibility: [`VaultSeed`], [`EcdhOutput`],
//! [`PrfOutput`], [`PartSecret`], [`BoxKey`], [`AgreementKey`] and [`SoftwareIdentity`]. They
//! have no `Clone`, no `Copy`, no `Serialize` and a redacted `Debug`. Anything that must read
//! their bytes is a function or method *in this file*; the `pub(super)` ones take and return
//! only other opaque secrets, ciphertext or public points. Secrets enter only through
//! `from_host_*` constructors (the host's inputs) and leave only sealed.
//!
//! **The paths that seal a seed.** A seed is **new** (made from host entropy in this session:
//! a genesis, or the new vault of a rotation) or **opened** (obtained by unlocking a slot, a
//! transfer or `previousVault`, and recorded as opened under that account). The only paths:
//! 1. `slots::SlotBuild` to controllers of a verified `v05::history::State`. An opened seed is
//!    sealed only if the state is of the account it was opened under; a controller the
//!    verifier has not seen is refused. `pub(crate)` additions are for the account layer.
//! 2. `slots::SlotBuild` for a genesis or a rotation: only a **new** seed, to the controllers
//!    of the genesis being prepared, or of the verified state for a rotation.
//! 3. [`VaultSeed::seal_previous`]: the old seed (any) to the **new seed** the core holds
//!    (new only). The new seed is made from host-chosen bytes, so the host that creates the new
//!    vault can open `previousVault` and read the old seed. That is the host's power at
//!    rotation, by design.
//! 4. `pairing::seal_seed_for_transfer` to the ephemeral `E` of a [`ConfirmedPairing`], which
//!    exists only after a compared six-digit code or a QR scanned from the joining device's
//!    screen (§7.3). §7.4 requires it. The core cannot check the scan or the comparison beyond
//!    the commit-then-reveal order and the single reveal; the host attests them.
//!
//! **Erasure is best effort.** The crate forbids `unsafe` and has no zeroizing dependency, so
//! overwriting uses ordinary writes that `std::hint::black_box` only discourages the
//! optimizer from removing; there are no volatile writes. Seed, ECDH, PRF, part-secret and
//! box-key buffers, and opened plaintexts, are overwritten on drop. The 0.4 `Entropy` type
//! (`crypto.rs`) keeps its seed without erasing it, and so do HPKE intermediates in `hpke.rs`;
//! `slots::SlotBuild` erases its own copy of the entropy seed. p256 key types zeroize on drop.
//!
//! The 0.4 labels `colophon/vault/4`, `colophon/entropy/3` and the slot labels are kept on
//! purpose (§7.1: "unchanged in 0.5").
use super::descriptor::{valid_point, KeyDescriptor};
use super::encoding::{decode_base64, encode_base64};
use super::ids::{key_id, AccountId};
use super::{Failure, Reason};
use crate::crypto::Entropy;
use crate::hpke::SealedKey;
use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use hkdf::Hkdf;
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    elliptic_curve::sec1::ToEncodedPoint,
    PublicKey, SecretKey,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::Sha256;
use std::fmt;

/// HKDF salt of the vault identity (§7.1). `/4` is a domain-separation label, unchanged in 0.5.
pub const VAULT_SALT: &[u8] = b"colophon/vault/4";
/// HKDF salt of the software-identity expansion (§7.5).
pub const ENTROPY_SALT: &[u8] = b"colophon/entropy/3";
/// HKDF salt of the recovery-kit pre-step (§7.5, decision: the 0.4 derivation is the only one).
pub const KIT_SALT: &[u8] = b"colophon/recovery/3";
/// Prefix of every label the core reserves; the host may not open a seal under one (§17.1).
pub const RESERVED_LABEL: &[u8] = b"colophon/";
/// Largest `info` the restricted open accepts.
pub const HOST_OPEN_MAX_INFO: usize = 1_024;
/// Largest ciphertext the restricted open accepts.
pub const HOST_OPEN_MAX_CIPHERTEXT: usize = 65_536;

/// The result of a vault or slot operation: a 0.5 [`Failure`], including
/// `refused:vaultLocked` ([`Reason::VaultLocked`], §19).
pub type VResult<T> = std::result::Result<T, Failure>;

/// `refused:vaultLocked`: a wrong or missing secret, or a seed that does not derive the
/// keyring's vault (§7.1, §7.2).
pub fn locked() -> Failure {
    Failure::Refused(Reason::VaultLocked)
}
pub(crate) fn malformed(reason: impl Into<String>) -> Failure {
    Failure::Malformed(reason.into())
}
pub(crate) fn bad_signature(reason: impl Into<String>) -> Failure {
    Failure::BadSignature(reason.into())
}
pub(crate) fn require(ok: bool, reason: &str) -> VResult<()> {
    if ok {
        Ok(())
    } else {
        Err(malformed(reason))
    }
}

/// Serde adapter: standard padded base64, canonical spelling only (§2.2).
pub(crate) mod b64 {
    use super::*;
    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&encode_base64(bytes))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        decode_base64(&text, 4_096).map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

fn erase(bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        *b = 0;
    }
    std::hint::black_box(&*bytes);
}

/// An HPKE ciphertext object `{enc, ciphertext}` (RFC 9180 base mode, KEM 0x0010, KDF 0x0001,
/// AEAD 0x0002, one message at sequence zero; §11.1). It is public data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedBox {
    /// The 65-byte uncompressed ephemeral point.
    #[serde(with = "b64")]
    pub enc: Vec<u8>,
    /// Ciphertext and the 16-byte GCM tag.
    #[serde(with = "b64")]
    pub ciphertext: Vec<u8>,
}
impl SealedBox {
    /// Check the point and the exact ciphertext length (48 bytes for a 32-byte plaintext).
    pub fn validate_secret_box(&self) -> VResult<()> {
        require(
            valid_point(&self.enc),
            "sealed: enc is not a valid 65-byte point",
        )?;
        require(
            self.ciphertext.len() == 48,
            "sealed: ciphertext is not 48 bytes",
        )
    }
    /// The JSON value `{"ciphertext","enc"}`.
    pub fn to_value(&self) -> serde_json::Value {
        serde_json::json!({"enc": encode_base64(&self.enc), "ciphertext": encode_base64(&self.ciphertext)})
    }
    fn from_key(k: SealedKey) -> Self {
        Self {
            enc: k.enc,
            ciphertext: k.ciphertext,
        }
    }
    fn to_key(&self) -> SealedKey {
        SealedKey {
            enc: self.enc.clone(),
            ciphertext: self.ciphertext.clone(),
        }
    }
    /// Seal a public plaintext to a public agreement point (for example an epoch key to a
    /// recipient). `info` is both the HPKE `info` and the AAD (§11.1). The seed and part secrets
    /// are sealed only by the methods of this file.
    pub(crate) fn seal_public(
        recipient: &[u8],
        plaintext: &[u8],
        info: &[u8],
        entropy: &mut Entropy,
    ) -> VResult<Self> {
        require(
            valid_point(recipient),
            "HPKE recipient is not a valid point",
        )?;
        SealedKey::seal(recipient, plaintext, info, entropy)
            .map(Self::from_key)
            .map_err(|e| malformed(format!("HPKE seal: {e}")))
    }
}

/// A host-supplied raw ECDH x-coordinate (32 bytes). It can be passed in and consumed; its
/// bytes can be read nowhere outside this file.
///
/// ```compile_fail
/// let d = colophon_core::v05::vault::EcdhOutput::from_host(&[1; 32]).unwrap();
/// let _bytes = d.0; // the field is private
/// ```
pub struct EcdhOutput(Vec<u8>);
impl EcdhOutput {
    /// The host's ECDH result. Not 32 bytes is `refused:vaultLocked` (a missing secret).
    pub fn from_host(bytes: &[u8]) -> VResult<Self> {
        if bytes.len() != 32 {
            return Err(locked());
        }
        Ok(Self(bytes.to_vec()))
    }
}
impl Drop for EcdhOutput {
    fn drop(&mut self) {
        erase(&mut self.0);
    }
}
impl fmt::Debug for EcdhOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EcdhOutput(..)")
    }
}

/// A host-supplied WebAuthn PRF result (`results.first`, 32 bytes). Opaque like [`EcdhOutput`].
pub struct PrfOutput(Vec<u8>);
impl PrfOutput {
    /// The host's PRF result. Missing or not 32 bytes fails explicitly: there is no fallback
    /// (§7.2), and the result is `refused:vaultLocked`.
    pub fn from_host(bytes: &[u8]) -> VResult<Self> {
        if bytes.len() != 32 {
            return Err(locked());
        }
        Ok(Self(bytes.to_vec()))
    }
    /// `HKDF-SHA256(IKM = P, salt, info, 32)`: the key of a `prf` slot or the secret of a PRF
    /// part (§7.2).
    pub(super) fn derive(&self, salt: &[u8], info: &[u8]) -> VResult<PartSecret> {
        require(salt.len() == 32, "prf: salt is not 32 bytes")?;
        hkdf32(&self.0, salt, info).map(PartSecret)
    }
}
impl Drop for PrfOutput {
    fn drop(&mut self) {
        erase(&mut self.0);
    }
}
impl fmt::Debug for PrfOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrfOutput(..)")
    }
}

fn hkdf32(ikm: &[u8], salt: &[u8], info: &[u8]) -> VResult<[u8; 32]> {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, &mut out)
        .map_err(|_| malformed("HKDF output length"))?;
    Ok(out)
}

/// A 32-byte part secret (§7.2): a PRF-derived secret or the plaintext of a sealed part.
pub struct PartSecret([u8; 32]);
impl PartSecret {
    /// A fresh independent secret from host entropy, together with its HPKE seal to a raw
    /// controller's agreement point under `info` (a sealed part, §7.2).
    pub(super) fn fresh_sealed(
        recipient: &[u8],
        info: &[u8],
        entropy: &mut Entropy,
    ) -> VResult<(Self, SealedBox)> {
        require(
            valid_point(recipient),
            "sealed part: invalid agreement point",
        )?;
        let secret = entropy
            .take::<32>()
            .map_err(|e| malformed(format!("entropy: {e}")))?;
        let sealed = SealedKey::seal(recipient, &secret, info, entropy)
            .map(SealedBox::from_key)
            .map_err(|e| malformed(format!("HPKE seal: {e}")))?;
        Ok((Self(secret), sealed))
    }
    /// Open a sealed part with the host's ECDH result for the controller's agreement key. A
    /// wrong result, or a plaintext that is not 32 bytes, is `refused:vaultLocked`.
    pub(super) fn open_sealed(
        sealed: &SealedBox,
        recipient: &[u8],
        dh: &EcdhOutput,
        info: &[u8],
    ) -> VResult<Self> {
        let plain = open_dh(sealed, recipient, dh, info)?;
        <[u8; 32]>::try_from(plain.as_slice())
            .map(Self)
            .map_err(|_| locked())
    }
    /// The combined key: `HKDF-SHA256(IKM = S0 ‖ … ‖ Sn−1, salt empty, info I, 32)` (§7.2).
    pub(super) fn combine(parts: &[PartSecret], info: &[u8]) -> VResult<BoxKey> {
        require(parts.len() >= 2, "combined: fewer than two parts")?;
        let mut ikm: Vec<u8> = parts.iter().flat_map(|p| p.0).collect();
        let key = hkdf32(&ikm, &[], info);
        erase(&mut ikm);
        key.map(BoxKey)
    }
    /// A single-secret slot key (a `prf` slot): the secret itself is the box key.
    pub(super) fn into_box_key(self) -> BoxKey {
        BoxKey(self.0)
    }
}
impl Drop for PartSecret {
    fn drop(&mut self) {
        erase(&mut self.0);
    }
}
impl fmt::Debug for PartSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PartSecret(..)")
    }
}

fn open_dh(sealed: &SealedBox, recipient: &[u8], dh: &EcdhOutput, info: &[u8]) -> VResult<Vec<u8>> {
    sealed
        .to_key()
        .finish_open(recipient, &dh.0, info)
        .map_err(|_| locked())
}

/// Open an HPKE seal addressed to `recipient` under one of the core's own labels (an epoch
/// key, §11.1), with the host's raw ECDH result. Crate-internal, added for `records.rs`: the
/// plaintext goes to the caller (an epoch key it wraps at once), never the ECDH bytes. A label
/// outside `colophon/` is refused, as it is in [`VaultSeed::open_core_seal`].
pub(crate) fn open_core_seal_with_dh(
    sealed: &SealedBox,
    recipient: &[u8],
    dh: &EcdhOutput,
    info: &[u8],
) -> VResult<Vec<u8>> {
    require(
        info.starts_with(RESERVED_LABEL),
        "core open: not a core label",
    )?;
    require(
        valid_point(&sealed.enc),
        "core open: enc is not a valid point",
    )?;
    require(
        sealed.ciphertext.len() == 48,
        "core open: ciphertext length",
    )?;
    open_dh(sealed, recipient, dh, info)
}

/// The AES-256-GCM key of a `prf`, or `combined` slot box (§7.2).
pub struct BoxKey([u8; 32]);
impl BoxKey {
    /// `nonce(12) ‖ AES-256-GCM(seed, AAD = I) ‖ tag`: the 60-byte `box`.
    pub(super) fn seal_seed(
        &self,
        seed: &VaultSeed,
        info: &[u8],
        entropy: &mut Entropy,
    ) -> VResult<Vec<u8>> {
        let nonce = entropy
            .take::<12>()
            .map_err(|e| malformed(format!("entropy: {e}")))?;
        let ct = Aes256Gcm::new_from_slice(&self.0)
            .map_err(|_| malformed("AES key length"))?
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &seed.seed,
                    aad: info,
                },
            )
            .map_err(|_| malformed("encryption failed"))?;
        let mut out = nonce.to_vec();
        out.extend(ct);
        Ok(out)
    }
    /// Open a 60-byte box and check the plaintext against the keyring's vault (§7.1). A wrong
    /// key or any mismatch is `refused:vaultLocked`.
    pub(super) fn open_seed(
        &self,
        boxed: &[u8],
        info: &[u8],
        expected: &VaultPublic,
    ) -> VResult<VaultSeed> {
        require(boxed.len() == 60, "box is not 60 bytes")?;
        let plain = Aes256Gcm::new_from_slice(&self.0)
            .map_err(|_| malformed("AES key length"))?
            .decrypt(
                Nonce::from_slice(&boxed[..12]),
                Payload {
                    msg: &boxed[12..],
                    aad: info,
                },
            )
            .map_err(|_| locked())?;
        VaultSeed::check_owned(plain, expected)
    }
}
impl Drop for BoxKey {
    fn drop(&mut self) {
        erase(&mut self.0);
    }
}
impl fmt::Debug for BoxKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BoxKey(..)")
    }
}

/// An agreement (ECDH) key the core holds in memory: an ephemeral transfer key (§7.4), a
/// software identity's agreement half, or the vault's. Only the public point leaves it.
pub struct AgreementKey(SecretKey);
impl AgreementKey {
    /// A fresh ephemeral agreement key (§7.4's `E`) from a host-random 32-byte seed, expanded
    /// by §7.5: the first valid scalar. The scalar stays inside this type.
    pub fn ephemeral(entropy_seed: [u8; 32]) -> VResult<Self> {
        Entropy::new(entropy_seed)
            .scalar()
            .map(Self)
            .map_err(|e| malformed(format!("entropy: {e}")))
    }
    /// The 65-byte uncompressed public point.
    pub fn public(&self) -> Vec<u8> {
        self.0
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }
    /// The key ID of the public point (§3.1).
    pub fn id(&self) -> String {
        key_id(&self.public())
    }
    /// The ECDH result for a peer point, as an opaque value for HPKE and nothing else.
    pub fn agree(&self, peer: &[u8]) -> VResult<EcdhOutput> {
        require(valid_point(peer), "ECDH peer is not a valid point")?;
        let peer = PublicKey::from_sec1_bytes(peer).map_err(|_| malformed("ECDH peer"))?;
        let dh = p256::ecdh::diffie_hellman(self.0.to_nonzero_scalar(), peer.as_affine());
        Ok(EcdhOutput(dh.raw_secret_bytes().to_vec()))
    }
    /// Open a seed transfer (§7.4) addressed to this key and check it against `expected`
    /// (§7.1). The seed goes straight into a [`VaultSeed`] handle.
    pub(super) fn open_seed(
        &self,
        sealed: &SealedBox,
        info: &[u8],
        expected: &VaultPublic,
    ) -> VResult<VaultSeed> {
        let dh = self.agree(&sealed.enc).map_err(|_| locked())?;
        VaultSeed::open_sealed(sealed, &self.public(), &dh, info, expected)
    }
    /// Open an HPKE seal addressed to this key. The plaintext is returned; the ECDH result
    /// never is.
    pub(super) fn open_hpke(&self, sealed: &SealedBox, info: &[u8]) -> VResult<Vec<u8>> {
        let dh = self.agree(&sealed.enc)?;
        open_dh(sealed, &self.public(), &dh, info)
    }
}
impl fmt::Debug for AgreementKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AgreementKey(..)")
    }
}

/// The public half of a software identity or of the vault: a signing and an agreement point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultPublic {
    /// The 65-byte signing point.
    pub signing: Vec<u8>,
    /// The 65-byte agreement point.
    pub agreement: Vec<u8>,
}
impl VaultPublic {
    /// From the `(signing, agreement)` pair a folded keyring holds.
    pub fn from_pair(pair: &(Vec<u8>, Vec<u8>)) -> Self {
        Self {
            signing: pair.0.clone(),
            agreement: pair.1.clone(),
        }
    }
    /// The vault ID: the key ID of the signing key (§7.2).
    pub fn id(&self) -> String {
        key_id(&self.signing)
    }
    /// Both points valid and different (§3.3 rule 1).
    pub fn validate(&self) -> VResult<()> {
        require(
            valid_point(&self.signing) && valid_point(&self.agreement),
            "vault: invalid point",
        )?;
        require(
            self.signing != self.agreement,
            "vault: signing equals agreement",
        )
    }
    /// The keyring's `vault` JSON object.
    pub fn to_value(&self) -> serde_json::Value {
        serde_json::json!({"signing": encode_base64(&self.signing), "agreement": encode_base64(&self.agreement)})
    }
}

/// A software identity (§7.5): a signing key and an agreement key expanded from 32 bytes. The
/// vault and recovery kits are software identities. The private scalars never leave this type.
pub struct SoftwareIdentity {
    signing: SigningKey,
    agreement: AgreementKey,
}
impl SoftwareIdentity {
    /// Expand a 32-byte seed (§7.5): HKDF-SHA256 with salt `colophon/entropy/3` and, as info,
    /// the eight-byte big-endian counter from zero, 32 bytes each; the first valid scalar
    /// signs, the next valid scalar agrees, and an invalid scalar consumes a counter.
    pub fn from_seed(seed: &[u8; 32]) -> VResult<Self> {
        let mut found: Vec<SecretKey> = Vec::with_capacity(2);
        for counter in 0u64..4_096 {
            let mut bytes = hkdf32(seed, ENTROPY_SALT, &counter.to_be_bytes())?;
            let key = SecretKey::from_slice(&bytes);
            erase(&mut bytes);
            if let Ok(k) = key {
                found.push(k);
                if found.len() == 2 {
                    break;
                }
            }
        }
        let (Some(agreement), Some(signing)) = (found.pop(), found.pop()) else {
            return Err(malformed("software identity: no valid scalar"));
        };
        Ok(Self {
            signing: SigningKey::from(&signing),
            agreement: AgreementKey(agreement),
        })
    }
    /// The public points.
    pub fn public(&self) -> VaultPublic {
        VaultPublic {
            signing: self
                .signing
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
            agreement: self.agreement.public(),
        }
    }
    /// The signing key's ID.
    pub fn id(&self) -> String {
        self.public().id()
    }
    /// A `raw` signature over exact bytes: 64 bytes `r ‖ s` (§4.2), deterministic (RFC 6979).
    pub fn sign(&self, body: &[u8]) -> [u8; 64] {
        let sig: Signature = self.signing.sign(body);
        let mut out = [0u8; 64];
        out.copy_from_slice(&sig.to_bytes());
        out
    }
    /// The ECDH result for an HPKE `enc`, opaque.
    pub fn agree(&self, enc: &[u8]) -> VResult<EcdhOutput> {
        self.agreement.agree(enc)
    }
    /// A `raw` controller descriptor for this identity: `signing` and `agreement` (§3.1).
    pub fn descriptor(&self) -> VResult<KeyDescriptor> {
        let p = self.public();
        KeyDescriptor::new_raw(p.signing, Some(p.agreement))
    }
}
impl fmt::Debug for SoftwareIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SoftwareIdentity({})", self.id())
    }
}

/// A recovery kit (§7.5): 32 secret bytes the host prints or stores. There is exactly one
/// derivation, the 0.3 and 0.4 one: `s' = HKDF-SHA256(IKM = kit, salt = "colophon/recovery/3",
/// info = "identity", 32)`, then the software-identity expansion of `s'`. A kit made under
/// 0.4 therefore keeps its keys after an in-place upgrade (§16.1). §7.5 states this derivation.
pub fn kit_identity(secret: &[u8; 32]) -> VResult<SoftwareIdentity> {
    let mut s = hkdf32(secret, KIT_SALT, b"identity")?;
    let id = SoftwareIdentity::from_seed(&s);
    erase(&mut s);
    id
}

/// The vault seed (§7.1): an account secret the core may hold in memory for a session and MUST
/// NOT persist. It cannot be read, cloned or serialized; it can only be used through the
/// methods of this file and of `slots` and `pairing`, which take it by reference and return
/// ciphertext, public data or other opaque secrets.
///
/// ```compile_fail
/// let s = colophon_core::v05::vault::VaultSeed::from_host_random([1; 32]);
/// let _bytes = s.0; // the field is private
/// ```
///
/// ```compile_fail
/// let s = colophon_core::v05::vault::VaultSeed::from_host_random([1; 32]);
/// let _copy = s.clone(); // no Clone
/// ```
pub struct VaultSeed {
    seed: [u8; 32],
    new: bool,
    /// The account whose keyring this seed was opened under; `None` for a new seed.
    account: Option<AccountId>,
}
impl VaultSeed {
    /// A fresh vault seed: 32 random bytes from the host (§7.1).
    ///
    /// This is a **new** seed ([`VaultSeed::is_new`]): made from host entropy in this session,
    /// for a genesis or the new vault of a rotation. A seed obtained by unlocking a slot or a
    /// transfer is an **opened** seed and is not new.
    pub fn from_host_random(bytes: [u8; 32]) -> Self {
        Self {
            seed: bytes,
            new: true,
            account: None,
        }
    }
    /// The account this opened seed was opened under (the account of the keyring whose slot,
    /// transfer or `previousVault` it came from); `None` for a new seed. An opened seed can be
    /// sealed to controllers only of this account's verified keyring.
    pub fn account(&self) -> Option<&AccountId> {
        self.account.as_ref()
    }
    /// Record the account an opened seed was opened under (set once, by the open paths).
    pub(super) fn bound_to(mut self, account: &AccountId) -> Self {
        if !self.new {
            self.account = Some(account.clone());
        }
        self
    }
    /// True for a seed made from host entropy in this session, false for an opened one.
    pub fn is_new(&self) -> bool {
        self.new
    }
    /// The vault's public identity: `s' = HKDF-SHA256(IKM = seed, salt = "colophon/vault/4",
    /// info = "identity", 32)`, then §7.5 on `s'` (§7.1).
    pub fn public(&self) -> VResult<VaultPublic> {
        Ok(self.identity()?.public())
    }
    fn identity(&self) -> VResult<SoftwareIdentity> {
        let mut s = hkdf32(&self.seed, VAULT_SALT, b"identity")?;
        let id = SoftwareIdentity::from_seed(&s);
        erase(&mut s);
        id
    }
    /// After opening any slot (§7.1): the plaintext must be 32 bytes and derive both public
    /// keys of the keyring's `vault`. Anything else is `refused:vaultLocked`. The caller
    /// replaces its session seed only on `Ok`.
    ///
    /// The result is an **opened** seed ([`VaultSeed::is_new`] is false), recorded as opened
    /// under `account`.
    pub fn check(plaintext: &[u8], expected: &VaultPublic, account: &AccountId) -> VResult<Self> {
        Self::check_unbound(plaintext, expected).map(|s| s.bound_to(account))
    }
    /// [`VaultSeed::check`] without recording an account: crate-internal, for the open paths
    /// that bind the result themselves and for re-opening a slot being built.
    pub(super) fn check_unbound(plaintext: &[u8], expected: &VaultPublic) -> VResult<Self> {
        let seed = <[u8; 32]>::try_from(plaintext).map_err(|_| locked())?;
        let this = Self {
            seed,
            new: false,
            account: None,
        };
        let public = this.public().map_err(|_| locked())?;
        if public != *expected {
            return Err(locked());
        }
        Ok(this)
    }
    /// [`VaultSeed::check`] on a plaintext buffer the core owns: the buffer is overwritten
    /// before it is dropped (best effort, see the file header).
    pub(super) fn check_owned(mut plain: Vec<u8>, expected: &VaultPublic) -> VResult<Self> {
        let r = Self::check_unbound(&plain, expected);
        erase(&mut plain);
        r
    }
    /// Open a `sealed` slot (or a transfer seal) with the host's ECDH result for the
    /// recipient's agreement key, then check the plaintext against the vault (§7.1).
    pub(super) fn open_sealed(
        sealed: &SealedBox,
        recipient: &[u8],
        dh: &EcdhOutput,
        info: &[u8],
        expected: &VaultPublic,
    ) -> VResult<Self> {
        Self::check_owned(open_dh(sealed, recipient, dh, info)?, expected)
    }
    /// Seal this seed to a raw controller's agreement point (a `sealed` slot) or to a transfer
    /// key (§7.4). `info` is both the HPKE `info` and the AAD.
    pub(super) fn seal_to(
        &self,
        recipient: &[u8],
        info: &[u8],
        entropy: &mut Entropy,
    ) -> VResult<SealedBox> {
        SealedBox::seal_public(recipient, &self.seed, info, entropy)
    }
    /// Seal the seed of the *previous* vault to the new vault (§8.3 `previousVault`): HPKE to
    /// the new vault's agreement key with `info` and AAD
    /// `"colophon/vault-previous/5\n" ‖ newVaultID ‖ "\n" ‖ oldVaultID`. `self` is the old seed.
    ///
    /// The target is the **new seed itself**, which must be a new seed ([`VaultSeed::is_new`]):
    /// one the host made from entropy in this session for this rotation. A caller cannot name
    /// a bare public vault, and an opened seed is refused as a target. The new seed's bytes are
    /// the host's own choice, so the host that creates the new vault can open `previousVault`
    /// and read the old seed: the host is trusted with the seed during rotation.
    ///
    /// ```compile_fail
    /// use colophon_core::{crypto::Entropy, v05::vault::VaultSeed};
    /// let old = VaultSeed::from_host_random([1; 32]);
    /// let public = VaultSeed::from_host_random([2; 32]).public().unwrap();
    /// // A bare public vault is not an accepted target.
    /// let _ = old.seal_previous(&public, &mut Entropy::new([3; 32]));
    /// ```
    pub fn seal_previous(&self, new_seed: &VaultSeed, entropy: &mut Entropy) -> VResult<SealedBox> {
        require(
            new_seed.is_new(),
            "previousVault: the target must be the new seed made this session",
        )?;
        let new_vault = new_seed.public()?;
        new_vault.validate()?;
        let old = self.public()?;
        let info = previous_info(&new_vault.id(), &old.id());
        self.seal_to(&new_vault.agreement, &info, entropy)
    }
    /// Open a `previousVault` seal with the *new* seed (`self`), checking the result against
    /// the old vault's public identity: the way to reach the old vault and every epoch sealed
    /// to it. A mismatch is `refused:vaultLocked`.
    pub fn open_previous(
        &self,
        previous: &SealedBox,
        old_vault: &VaultPublic,
        account: &AccountId,
    ) -> VResult<VaultSeed> {
        let new = self.public()?;
        let info = previous_info(&new.id(), &old_vault.id());
        let plain = self.identity()?.agreement.open_hpke(previous, &info)?;
        Self::check_owned(plain, old_vault).map(|s| s.bound_to(account))
    }
    /// Open an HPKE seal to the vault for a format the **host** registered (§17.1). The seal's
    /// `info` (also its AAD) is the host's label. A label beginning with `colophon/` is
    /// refused: those belong to the core. The core returns the plaintext of the seal, never
    /// the seed or an ECDH result.
    ///
    /// The envelope, the `info`-and-AAD convention and the bounds are not stated in §17.1; the
    /// `{enc, ciphertext}` object of §11.1, `info = AAD`, [`HOST_OPEN_MAX_INFO`] and
    /// [`HOST_OPEN_MAX_CIPHERTEXT`] are this implementation's reading (reported as a spec
    /// question).
    pub fn open_host_format(&self, sealed: &SealedBox, info: &[u8]) -> VResult<Vec<u8>> {
        if info.starts_with(RESERVED_LABEL) {
            return Err(Failure::Refused(Reason::OutOfScope));
        }
        require(info.len() <= HOST_OPEN_MAX_INFO, "host open: info too long")?;
        require(
            sealed.ciphertext.len() >= 16 && sealed.ciphertext.len() <= HOST_OPEN_MAX_CIPHERTEXT,
            "host open: ciphertext length",
        )?;
        require(
            valid_point(&sealed.enc),
            "host open: enc is not a valid point",
        )?;
        self.identity()?.agreement.open_hpke(sealed, info)
    }
    /// Open a seal to the vault under one of the core's own labels (an epoch key, §11.1).
    /// Crate-internal: the plaintext is a key the caller needs, never the seed.
    pub(crate) fn open_core_seal(&self, sealed: &SealedBox, info: &[u8]) -> VResult<Vec<u8>> {
        require(
            info.starts_with(RESERVED_LABEL),
            "core open: not a core label",
        )?;
        self.identity()?.agreement.open_hpke(sealed, info)
    }
}
impl Drop for VaultSeed {
    fn drop(&mut self) {
        erase(&mut self.seed);
    }
}
impl fmt::Debug for VaultSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VaultSeed(..)")
    }
}

fn previous_info(new_id: &str, old_id: &str) -> Vec<u8> {
    format!("colophon/vault-previous/5\n{new_id}\n{old_id}").into_bytes()
}

/// The core's unlocked-vault state for one session (§3.4: in memory only, never persisted).
/// A failed open never changes it (§7.1).
#[derive(Debug, Default)]
pub struct VaultSession {
    seed: Option<VaultSeed>,
}
impl VaultSession {
    /// A locked session.
    pub fn new() -> Self {
        Self::default()
    }
    /// Install the result of an open. On `Err` the session is left exactly as it was, and the
    /// error is returned.
    pub fn install(&mut self, opened: VResult<VaultSeed>) -> VResult<()> {
        self.seed = Some(opened?);
        Ok(())
    }
    /// The unlocked seed, when there is one.
    pub fn seed(&self) -> Option<&VaultSeed> {
        self.seed.as_ref()
    }
    /// True when a seed is held.
    pub fn is_unlocked(&self) -> bool {
        self.seed.is_some()
    }
    /// Drop the seed (erased on drop).
    pub fn lock(&mut self) {
        self.seed = None;
    }
}
