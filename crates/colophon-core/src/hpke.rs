//! RFC 9180 base mode: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM.
//! Decapsulation deliberately separates the host ECDH operation from key derivation.
use crate::{
    crypto::{self, Entropy},
    ensure,
    records::bytes,
    Error, Result,
};
use hkdf::Hkdf;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

const KEM_SUITE: &[u8] = b"KEM\x00\x10";
fn extract(suite: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> Vec<u8> {
    let input = [b"HPKE-v1".as_slice(), suite, label, ikm].concat();
    Hkdf::<Sha256>::extract(Some(salt), &input).0.to_vec()
}
fn expand(suite: &[u8], prk: &[u8], label: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>> {
    let len16 = u16::try_from(len).map_err(|_| Error("HPKE output length".into()))?;
    let labeled = [&len16.to_be_bytes()[..], b"HPKE-v1", suite, label, info].concat();
    let mut out = vec![0; len];
    Hkdf::<Sha256>::from_prk(prk)
        .map_err(|_| Error("HPKE PRK".into()))?
        .expand(&labeled, &mut out)
        .map_err(|_| Error("HPKE expand".into()))?;
    Ok(out)
}
/// RFC 9180 ExtractAndExpand after the host has supplied raw P-256 ECDH bytes.
pub fn kem_shared_secret(dh: &[u8], enc: &[u8], recipient: &[u8]) -> Result<Vec<u8>> {
    ensure(dh.len() == 32, "Expected 32-byte ECDH secret")?;
    for point in [enc, recipient] {
        ensure(
            point.len() == 65 && point[0] == 4,
            "Expected uncompressed HPKE point",
        )?;
        p256::PublicKey::from_sec1_bytes(point).map_err(|_| Error("Invalid HPKE point".into()))?;
    }
    let prk = extract(KEM_SUITE, &[], b"eae_prk", dh);
    expand(
        KEM_SUITE,
        &prk,
        b"shared_secret",
        &[enc, recipient].concat(),
        32,
    )
}
/// Base-mode key schedule. AEAD 1 is exposed for RFC vectors; production uses AEAD 2.
pub fn key_schedule(shared: &[u8], info: &[u8], aead: u16) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    ensure(aead == 1 || aead == 2, "Unsupported HPKE AEAD")?;
    let suite = [b"HPKE\x00\x10\x00\x01".as_slice(), &aead.to_be_bytes()].concat();
    let psk_hash = extract(&suite, &[], b"psk_id_hash", &[]);
    let info_hash = extract(&suite, &[], b"info_hash", info);
    let context = [&[0][..], &psk_hash, &info_hash].concat();
    let secret = extract(&suite, shared, b"secret", &[]);
    Ok((
        expand(
            &suite,
            &secret,
            b"key",
            &context,
            if aead == 1 { 16 } else { 32 },
        )?,
        expand(&suite, &secret, b"base_nonce", &context, 12)?,
        expand(&suite, &secret, b"exp", &context, 32)?,
    ))
}
/// A single-shot HPKE ciphertext (sequence number zero).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedKey {
    /// Encapsulated uncompressed P-256 ephemeral public key.
    #[serde(with = "bytes")]
    pub enc: Vec<u8>,
    /// Ciphertext and the 16-byte GCM tag.
    #[serde(with = "bytes")]
    pub ciphertext: Vec<u8>,
}
impl SealedKey {
    /// Seal with explicit entropy; info binds the library, namespace, epoch and recipient.
    pub fn seal(
        recipient: &[u8],
        plaintext: &[u8],
        info: &[u8],
        entropy: &mut Entropy,
    ) -> Result<Self> {
        let ephemeral = entropy.scalar()?;
        let enc = ephemeral
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let dh = crypto::agree(&ephemeral, recipient)?;
        let shared = kem_shared_secret(&dh, &enc, recipient)?;
        let (key, nonce, _) = key_schedule(&shared, info, 2)?;
        Ok(Self {
            enc,
            ciphertext: crypto::seal(&key, &nonce, plaintext, info)?,
        })
    }
    /// Begin decapsulation: return the peer point to pass to the host's agreement key.
    pub fn begin_open(&self) -> &[u8] {
        &self.enc
    }
    /// Finish decapsulation with the raw host ECDH result. No private key enters this call.
    pub fn finish_open(&self, recipient: &[u8], dh: &[u8], info: &[u8]) -> Result<Vec<u8>> {
        let shared = kem_shared_secret(dh, &self.enc, recipient)?;
        let (key, nonce, _) = key_schedule(&shared, info, 2)?;
        crypto::open(&key, &nonce, &self.ciphertext, info)
    }
}
