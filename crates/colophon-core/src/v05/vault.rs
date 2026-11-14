//! The vault (§7.1), software identities and kits (§7.5), and the restricted vault HPKE open
//! (§17.1) under Colophon 0.5.
//!
//! **How "the core never exports the seed or a raw ECDH output" is enforced here (§3.4,
//! §17.1).** Every secret is an opaque type with private fields and no accessor of any
//! visibility: [`VaultSeed`], [`EcdhOutput`], [`PrfOutput`], [`PartSecret`], [`BoxKey`],
//! [`AgreementKey`] and [`SoftwareIdentity`]. They have no `Clone`, no `Copy`, no `Serialize`
//! and a redacted `Debug`. Anything that must read their bytes is a function or method *in this
//! file*; the `pub(super)` ones take and return only other opaque secrets, ciphertext or
//! public points. Nothing returns the seed, a raw ECDH result, a PRF output, a part secret or a
//! derived key. Secrets enter only through `from_host_*` constructors (the host's inputs) and
//! leave only sealed. Memory is overwritten on drop on a best-effort basis (the crate forbids
//! `unsafe` and has no zeroizing dependency, so the optimizer is only discouraged from
//! removing the write).
//!
//! The 0.4 labels `colophon/vault/4`, `colophon/entropy/3` and the slot labels are kept on
//! purpose (§7.1: "unchanged in 0.5").
use super::descriptor::{valid_point, KeyDescriptor};
use super::encoding::{decode_base64, encode_base64};
use super::ids::key_id;
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
/// HKDF salt of the 0.3 and 0.4 recovery-kit pre-step (see [`legacy_kit_identity`]).
pub const LEGACY_KIT_SALT: &[u8] = b"colophon/recovery/3";
/// Prefix of every label the core reserves; the host may not open a seal under one (§17.1).
pub const RESERVED_LABEL: &[u8] = b"colophon/";
/// Largest `info` the restricted open accepts.
pub const HOST_OPEN_MAX_INFO: usize = 1_024;
/// Largest ciphertext the restricted open accepts.
pub const HOST_OPEN_MAX_CIPHERTEXT: usize = 65_536;

/// A failure of a vault or slot operation: `refused:vaultLocked` (§7.1, §7.2, §19), or one of
/// the 0.5 results of §1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VaultError {
    /// `refused:vaultLocked`: a wrong or missing secret, or a seed that does not derive the
    /// keyring's vault.
    Locked,
    /// Any other 0.5 result.
    Failed(Failure),
}
impl VaultError {
    /// The exact protocol result code.
    pub fn code(&self) -> String {
        match self {
            Self::Locked => "refused:vaultLocked".into(),
            Self::Failed(f) => f.code(),
        }
    }
}
impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Locked => f.write_str("refused:vaultLocked"),
            Self::Failed(x) => x.fmt(f),
        }
    }
}
impl std::error::Error for VaultError {}
impl From<Failure> for VaultError {
    fn from(f: Failure) -> Self {
        Self::Failed(f)
    }
}
/// The result of a vault or slot operation.
pub type VResult<T> = std::result::Result<T, VaultError>;

pub(crate) fn malformed(reason: impl Into<String>) -> VaultError {
    VaultError::Failed(Failure::Malformed(reason.into()))
}
pub(crate) fn bad_signature(reason: impl Into<String>) -> VaultError {
    VaultError::Failed(Failure::BadSignature(reason.into()))
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
            return Err(VaultError::Locked);
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
            return Err(VaultError::Locked);
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
            .map_err(|_| VaultError::Locked)
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
        .map_err(|_| VaultError::Locked)
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
                    msg: &seed.0,
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
            .map_err(|_| VaultError::Locked)?;
        VaultSeed::check(&plain, expected)
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
        let dh = self.agree(&sealed.enc).map_err(|_| VaultError::Locked)?;
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
        KeyDescriptor::new_raw(p.signing, Some(p.agreement)).map_err(VaultError::from)
    }
}
impl fmt::Debug for SoftwareIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SoftwareIdentity({})", self.id())
    }
}

/// A recovery kit (§7.5): "a software identity from 32 secret bytes the host prints or
/// stores". This is the literal text: [`SoftwareIdentity::from_seed`] on the secret.
///
/// **Open spec question (§7.5 against 0.3 §2 and 0.4):** a 0.3 and 0.4 kit first applied
/// `HKDF-SHA256(salt = "colophon/recovery/3", info = "identity")`. The 0.5 text does not say
/// that step is dropped or kept. See [`legacy_kit_identity`].
pub fn kit_identity(secret: &[u8; 32]) -> VResult<SoftwareIdentity> {
    SoftwareIdentity::from_seed(secret)
}

/// The 0.3 §2 and 0.4 recovery-kit derivation: `s' = HKDF-SHA256(IKM = kit, salt =
/// "colophon/recovery/3", info = "identity", 32)`, then the software-identity expansion of `s'`.
/// This is how the kits that exist in 0.4 accounts derive their published keys. A host
/// re-entering a printed 0.4 kit needs it. Which of the two a 0.5 kit uses is a spec question
/// (§7.5); the core does not choose.
pub fn legacy_kit_identity(secret: &[u8; 32]) -> VResult<SoftwareIdentity> {
    let mut s = hkdf32(secret, LEGACY_KIT_SALT, b"identity")?;
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
pub struct VaultSeed([u8; 32]);
impl VaultSeed {
    /// A fresh vault seed: 32 random bytes from the host (§7.1).
    pub fn from_host_random(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    /// The vault's public identity: `s' = HKDF-SHA256(IKM = seed, salt = "colophon/vault/4",
    /// info = "identity", 32)`, then §7.5 on `s'` (§7.1).
    pub fn public(&self) -> VResult<VaultPublic> {
        Ok(self.identity()?.public())
    }
    fn identity(&self) -> VResult<SoftwareIdentity> {
        let mut s = hkdf32(&self.0, VAULT_SALT, b"identity")?;
        let id = SoftwareIdentity::from_seed(&s);
        erase(&mut s);
        id
    }
    /// After opening any slot (§7.1): the plaintext must be 32 bytes and derive both public
    /// keys of the keyring's `vault`. Anything else is `refused:vaultLocked`. The caller
    /// replaces its session seed only on `Ok`.
    pub fn check(plaintext: &[u8], expected: &VaultPublic) -> VResult<Self> {
        let seed = <[u8; 32]>::try_from(plaintext).map_err(|_| VaultError::Locked)?;
        let this = Self(seed);
        let public = this.public().map_err(|_| VaultError::Locked)?;
        if public != *expected {
            return Err(VaultError::Locked);
        }
        Ok(this)
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
        let plain = open_dh(sealed, recipient, dh, info)?;
        Self::check(&plain, expected)
    }
    /// Seal this seed to a raw controller's agreement point (a `sealed` slot) or to a transfer
    /// key (§7.4). `info` is both the HPKE `info` and the AAD.
    pub(super) fn seal_to(
        &self,
        recipient: &[u8],
        info: &[u8],
        entropy: &mut Entropy,
    ) -> VResult<SealedBox> {
        SealedBox::seal_public(recipient, &self.0, info, entropy)
    }
    /// Seal the seed of the *previous* vault to the new vault (§8.3 `previousVault`): HPKE to
    /// the new vault's agreement key with `info` and AAD
    /// `"colophon/vault-previous/5\n" ‖ newVaultID ‖ "\n" ‖ oldVaultID`. `self` is the old seed.
    pub fn seal_previous(
        &self,
        new_vault: &VaultPublic,
        entropy: &mut Entropy,
    ) -> VResult<SealedBox> {
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
    ) -> VResult<VaultSeed> {
        let new = self.public()?;
        let info = previous_info(&new.id(), &old_vault.id());
        let plain = self.identity()?.agreement.open_hpke(previous, &info)?;
        Self::check(&plain, old_vault)
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
            return Err(VaultError::Failed(Failure::Refused(Reason::OutOfScope)));
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
    #[allow(dead_code)] // used by the record and account packages (E4, E5)
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
        erase(&mut self.0);
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
