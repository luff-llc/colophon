//! Explicit seed-based entropy and optional software identities. No OS randomness is used.
use crate::{
    ensure,
    records::{bytes, id},
    Error, Result,
};
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
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// The two uncompressed SEC1 public keys of a member.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicIdentity {
    /// Signing point.
    #[serde(with = "bytes")]
    pub signing: Vec<u8>,
    /// ECDH point.
    #[serde(with = "bytes")]
    pub agreement: Vec<u8>,
}
impl PublicIdentity {
    /// ID of the signing key.
    pub fn id(&self) -> String {
        id(&self.signing)
    }
    /// Validate both P-256 points and their required uncompressed representation.
    pub fn validate(&self) -> Result<()> {
        for key in [&self.signing, &self.agreement] {
            ensure(
                key.len() == 65 && key[0] == 4,
                "Expected uncompressed P-256 point",
            )?;
            PublicKey::from_sec1_bytes(key).map_err(|_| Error("Invalid public point".into()))?;
        }
        Ok(())
    }
}
/// Deterministic entropy expansion. Hosts MUST supply a fresh secret 32-byte seed per action.
pub struct Entropy {
    seed: [u8; 32],
    counter: u64,
}
impl Entropy {
    /// Construct from explicit host entropy (fixed seeds are for tests only).
    pub fn new(seed: [u8; 32]) -> Self {
        Self { seed, counter: 0 }
    }
    /// Derive the next pseudorandom byte array with domain separation.
    pub fn take<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut out = [0; N];
        Hkdf::<Sha256>::new(Some(crate::protocol::ENTROPY), &self.seed)
            .expand(&self.counter.to_be_bytes(), &mut out)
            .map_err(|_| Error("Entropy length".into()))?;
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or_else(|| Error("Entropy exhausted".into()))?;
        Ok(out)
    }
    pub(crate) fn scalar(&mut self) -> Result<SecretKey> {
        loop {
            if let Ok(key) = SecretKey::from_slice(&self.take::<32>()?) {
                return Ok(key);
            }
        }
    }
}
/// Software-only identity for tests, CLI use and deterministic recovery derivation.
/// Platform keys should instead implement signing/ECDH in their host.
pub struct SoftwareKeys {
    signing: SigningKey,
    agreement: SecretKey,
}
impl SoftwareKeys {
    /// Derive both keys from a secret seed. Domain-separated from recovery kits.
    pub fn from_seed(seed: [u8; 32]) -> Result<Self> {
        let mut rng = Entropy::new(seed);
        Ok(Self {
            signing: SigningKey::from(rng.scalar()?),
            agreement: rng.scalar()?,
        })
    }
    /// Derive a recovery identity from the exact 32-byte secret recovery kit.
    pub fn recovery(kit: [u8; 32]) -> Result<Self> {
        let mut seed = [0; 32];
        Hkdf::<Sha256>::new(Some(crate::protocol::RECOVERY), &kit)
            .expand(b"identity", &mut seed)
            .map_err(|_| Error("Recovery derivation".into()))?;
        Self::from_seed(seed)
    }
    /// Construct from private scalars; useful for external cryptographic vectors.
    pub fn from_scalars(signing: &[u8], agreement: &[u8]) -> Result<Self> {
        Ok(Self {
            signing: SigningKey::from_slice(signing).map_err(|_| Error("Signing scalar".into()))?,
            agreement: SecretKey::from_slice(agreement)
                .map_err(|_| Error("Agreement scalar".into()))?,
        })
    }
    /// Public keys; no private key serialization is exposed.
    pub fn public(&self) -> PublicIdentity {
        PublicIdentity {
            signing: self
                .signing
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
            agreement: self
                .agreement
                .public_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
        }
    }
    /// Deterministic RFC 6979 raw ECDSA signature.
    pub fn sign(&self, body: &[u8]) -> Vec<u8> {
        let sig: Signature = self.signing.sign(body);
        sig.to_bytes().to_vec()
    }
    /// Host-equivalent ECDH operation; returns the raw x-coordinate.
    pub fn agree(&self, peer: &[u8]) -> Result<Vec<u8>> {
        agree(&self.agreement, peer)
    }
}
pub(crate) fn agree(key: &SecretKey, peer: &[u8]) -> Result<Vec<u8>> {
    let peer = PublicKey::from_sec1_bytes(peer).map_err(|_| Error("Invalid ECDH peer".into()))?;
    Ok(
        p256::ecdh::diffie_hellman(key.to_nonzero_scalar(), peer.as_affine())
            .raw_secret_bytes()
            .to_vec(),
    )
}
pub(crate) fn seal(key: &[u8], nonce: &[u8], plain: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    ensure(nonce.len() == 12, "Nonce length")?;
    Aes256Gcm::new_from_slice(key)
        .map_err(|_| Error("AES key length".into()))?
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plain, aad })
        .map_err(|_| Error("Encryption failed".into()))
}
pub(crate) fn open(key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    ensure(nonce.len() == 12, "Nonce length")?;
    Aes256Gcm::new_from_slice(key)
        .map_err(|_| Error("AES key length".into()))?
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error("Authentication failed".into()))
}
