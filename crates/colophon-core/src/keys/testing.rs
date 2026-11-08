//! Published, fixed software keys for synthetic conformance assertions only.
//! Never use this authenticator to protect a real library.
use super::{malformed, Assertion, KeyDescriptor};
use crate::Result;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use sha2::{Digest, Sha256};

/// A deterministic test authenticator whose public private scalar is `[1; 32]`.
#[doc(hidden)]
pub struct SyntheticAuthenticator {
    signing: SigningKey,
}
/// A synthetic assertion and its separate DER signature.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct SyntheticAssertion {
    /// Exact signed WebAuthn bytes.
    pub assertion: Assertion,
    /// DER signature, including the requested S representative.
    pub signature: Vec<u8>,
}
impl SyntheticAuthenticator {
    /// Create the fixed-key software authenticator (no entropy or platform API).
    pub fn new() -> Result<Self> {
        Self::from_scalar(&[1; 32])
    }
    /// Create an alternate published scalar, for foreign-key refuse vectors.
    pub fn from_scalar(scalar: &[u8; 32]) -> Result<Self> {
        Ok(Self {
            signing: SigningKey::from_slice(scalar).map_err(|_| malformed("synthetic scalar"))?,
        })
    }
    /// Build a descriptor with the fixed key and a non-authoritative credential hint.
    pub fn descriptor(&self, rp: &str, origins: Option<Vec<String>>) -> Result<KeyDescriptor> {
        let key = KeyDescriptor::WebAuthn {
            signing: self
                .signing
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
            rp: rp.into(),
            credential: vec![1],
            origins,
        };
        key.validate()?;
        Ok(key)
    }
    /// Build canonical clientData with a body-bound challenge and a zero sign counter.
    /// Flags are supplied explicitly to construct UP/UV refuse cases.
    pub fn assertion(
        &self,
        body: &[u8],
        rp: &str,
        origin: &str,
        flags: u8,
        high_s: bool,
    ) -> Result<SyntheticAssertion> {
        let client_data = crate::records::canonical(&serde_json::json!({
            "type": "webauthn.get",
            "challenge": super::challenge(body),
            "origin": origin,
        }))
        .map_err(malformed)?;
        let mut authenticator_data = Sha256::digest(rp.as_bytes()).to_vec();
        authenticator_data.push(flags);
        authenticator_data.extend_from_slice(&[0; 4]);
        self.sign_bytes(authenticator_data, client_data, high_s)
    }
    /// Sign arbitrary exact authenticator/client data, without rewriting either.
    pub fn sign_bytes(
        &self,
        authenticator_data: Vec<u8>,
        client_data: Vec<u8>,
        high_s: bool,
    ) -> Result<SyntheticAssertion> {
        let mut message = authenticator_data.clone();
        message.extend_from_slice(&Sha256::digest(&client_data));
        let signature: Signature = self.signing.sign(&message);
        let signature = signature.normalize_s().unwrap_or(signature);
        let signature = if high_s {
            // Negating a nonzero scalar computes n-s without changing r.
            Signature::from_scalars(signature.r().to_bytes(), (-signature.s()).to_bytes())
                .map_err(|_| malformed("synthetic signature scalars"))?
        } else {
            signature
        };
        Ok(SyntheticAssertion {
            assertion: Assertion::new(authenticator_data, client_data),
            signature: signature.to_der().as_bytes().to_vec(),
        })
    }
}
