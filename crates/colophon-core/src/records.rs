//! Canonical writing and verification of the exact stored body bytes.
use crate::{Error, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Standard padded base64 for wire byte strings.
pub mod bytes {
    use super::*;
    /// Encode bytes as standard padded base64.
    pub fn serialize<S: serde::Serializer>(v: &[u8], s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }
    /// Decode a standard padded base64 wire string.
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        d: D,
    ) -> std::result::Result<Vec<u8>, D::Error> {
        STANDARD
            .decode(String::deserialize(d)?)
            .map_err(serde::de::Error::custom)
    }
}
/// Sorted object keys at every depth, UTF-8, unescaped slashes. Verification never calls this.
pub fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut value = serde_json::to_value(value)?;
    value.sort_all_objects();
    Ok(serde_json::to_vec(&value)?)
}
/// Lowercase SHA-256 hex digest.
pub fn digest(value: &[u8]) -> String {
    hex(&Sha256::digest(value))
}
pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 15) as usize] as char);
    }
    output
}
/// First 128 bits of SHA-256, in lowercase hex.
pub fn id(value: &[u8]) -> String {
    hex(&Sha256::digest(value)[..16])
}
/// Exact signed bytes, with a raw P-256 ECDSA signature.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedRecord {
    /// Stored JSON bytes; verify before parsing their content.
    #[serde(with = "bytes")]
    pub body: Vec<u8>,
    /// Raw r || s, 64 bytes.
    #[serde(with = "bytes")]
    pub signature: Vec<u8>,
}
impl SignedRecord {
    /// Finish a host signing step, verifying the result before accepting it.
    pub fn finish_sign(body: Vec<u8>, signature: Vec<u8>, public: &[u8]) -> Result<Self> {
        let record = Self { body, signature };
        record.verify(public)?;
        Ok(record)
    }
    /// Verify the stored bytes (including their original whitespace).
    pub fn verify(&self, public: &[u8]) -> Result<()> {
        let key = VerifyingKey::from_sec1_bytes(public)
            .map_err(|_| Error("Invalid signing public key".into()))?;
        self.verify_with(&key)
    }
    pub(crate) fn verify_with(&self, key: &VerifyingKey) -> Result<()> {
        let sig = Signature::from_slice(&self.signature)
            .map_err(|_| Error("Invalid signature format".into()))?;
        key.verify(&self.body, &sig)
            .map_err(|_| Error("Invalid signature".into()))
    }
    /// Encode an envelope for persistence.
    pub fn encode(&self) -> Result<Vec<u8>> {
        canonical(self)
    }
}
/// Begin a host signing step.
pub fn begin_sign<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    canonical(value)
}
