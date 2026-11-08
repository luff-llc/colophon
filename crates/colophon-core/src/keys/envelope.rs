//! Authority-only envelopes and cosignature verification (§3.1).
use super::{
    bad_signature, malformed, newer_format, object, require, strict_json, take_bytes, take_string,
    KeyDescriptor,
};
use crate::Result;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

/// Exact WebAuthn assertion bytes, stored separately from its DER signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Assertion {
    /// RP hash, flags, counter and any opaque signed extension bytes.
    #[serde(with = "crate::records::bytes")]
    pub authenticator_data: Vec<u8>,
    /// Original clientDataJSON bytes; never rewritten for verification.
    #[serde(with = "crate::records::bytes")]
    pub client_data: Vec<u8>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}
impl Assertion {
    /// Construct an assertion from exact authenticator and client data bytes.
    pub fn new(authenticator_data: Vec<u8>, client_data: Vec<u8>) -> Self {
        Self {
            authenticator_data,
            client_data,
            extra: Map::new(),
        }
    }
    fn from_value(value: Value) -> Result<Self> {
        let mut map = object(value)?;
        Ok(Self {
            authenticator_data: take_bytes(&mut map, "authenticatorData")?,
            client_data: take_bytes(&mut map, "clientData")?,
            extra: map,
        })
    }
    fn check_known_fields(&self) -> Result<()> {
        if self.extra.is_empty() {
            Ok(())
        } else {
            Err(newer_format("unknown assertion field"))
        }
    }
}

/// Another controller's signature over the same exact authority body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Cosignature {
    /// Lowercase 32-hex controller key ID.
    pub signer: String,
    /// Raw ES256 or DER WebAuthn signature, according to the descriptor.
    #[serde(with = "crate::records::bytes")]
    pub signature: Vec<u8>,
    /// Present if and only if this signer uses WebAuthn.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assertion: Option<Assertion>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}
impl Cosignature {
    /// Construct a cosignature; envelope validation checks ordering and uniqueness.
    pub fn new(signer: String, signature: Vec<u8>, assertion: Option<Assertion>) -> Self {
        Self {
            signer,
            signature,
            assertion,
            extra: Map::new(),
        }
    }
    fn from_value(value: Value) -> Result<Self> {
        let mut map = object(value)?;
        Ok(Self {
            signer: take_string(&mut map, "signer")?,
            signature: take_bytes(&mut map, "signature")?,
            assertion: optional_assertion(&mut map)?,
            extra: map,
        })
    }
}

/// An authority/4 envelope. Requests and operations must use their existing raw envelope.
/// Unknown fields are retained so authorization can precede `newerFormat` (§6.3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AuthorityEnvelope {
    /// Original authority body bytes; signatures never use a re-encoded body.
    #[serde(with = "crate::records::bytes")]
    pub body: Vec<u8>,
    /// Signature by the body's `by` controller.
    #[serde(with = "crate::records::bytes")]
    pub signature: Vec<u8>,
    /// Present if and only if the primary signer uses WebAuthn.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assertion: Option<Assertion>,
    /// Absent or non-empty, in strictly ascending signer-ID order.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cosignatures: Option<Vec<Cosignature>>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

/// An attached signature successfully verified against the authorizing keyring.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedSigner {
    /// Controller key ID; the primary signer is first in the returned list.
    pub id: String,
    /// WebAuthn UV flag, or `None` for a raw signer.
    pub uv: Option<bool>,
}
impl AuthorityEnvelope {
    /// Construct and check envelope structure, preserving the exact signed body.
    /// Assertion/form presence is checked once descriptors are available.
    pub fn new(
        body: Vec<u8>,
        signature: Vec<u8>,
        assertion: Option<Assertion>,
        cosignatures: Option<Vec<Cosignature>>,
    ) -> Result<Self> {
        let envelope = Self {
            body,
            signature,
            assertion,
            cosignatures,
            extra: Map::new(),
        };
        envelope.validate_structure()?;
        Ok(envelope)
    }
    /// Parse strict envelope and body JSON. Unknown fields await authorization.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        Self::from_value(strict_json::parse(bytes)?)
    }
    fn from_value(value: Value) -> Result<Self> {
        let mut map = object(value)?;
        let body = take_bytes(&mut map, "body")?;
        let signature = take_bytes(&mut map, "signature")?;
        let assertion = optional_assertion(&mut map)?;
        let cosignatures = match map.remove("cosignatures") {
            None => None,
            Some(Value::Array(values)) => Some(
                values
                    .into_iter()
                    .map(Cosignature::from_value)
                    .collect::<Result<_>>()?,
            ),
            _ => return Err(malformed("cosignatures must be non-empty array")),
        };
        let envelope = Self {
            body,
            signature,
            assertion,
            cosignatures,
            extra: map,
        };
        envelope.validate_structure()?;
        Ok(envelope)
    }
    /// Parse the exact body with duplicate rejection, leaving typed authority checks to replay.
    pub fn body_value(&self) -> Result<Value> {
        strict_json::parse(&self.body)
    }
    /// Read and validate the primary signer's key ID from the strict body.
    pub fn primary_signer(&self) -> Result<String> {
        let mut body = object(self.body_value()?)?;
        let by = take_string(&mut body, "by")?;
        require(valid_id(&by), "invalid primary signer ID")?;
        Ok(by)
    }
    /// Check signer IDs, non-empty cosignatures, strict sorting and primary distinctness.
    pub fn validate_structure(&self) -> Result<()> {
        let by = self.primary_signer()?;
        if let Some(cosignatures) = &self.cosignatures {
            require(!cosignatures.is_empty(), "empty cosignatures")?;
            for cosignature in cosignatures {
                require(valid_id(&cosignature.signer), "invalid cosigner ID")?;
                require(cosignature.signer != by, "primary repeated as cosigner")?;
            }
            require(
                cosignatures.windows(2).all(|w| w[0].signer < w[1].signer),
                "cosigners must be strictly sorted",
            )?;
        }
        Ok(())
    }
    /// Reject unknown envelope, cosignature and assertion fields with `newerFormat`.
    /// Call only AFTER signature verification AND authority-rule authorization (§6.3).
    pub fn check_known_fields(&self) -> Result<()> {
        if !self.extra.is_empty() {
            return Err(newer_format("unknown envelope field"));
        }
        if let Some(assertion) = &self.assertion {
            assertion.check_known_fields()?;
        }
        for cosignature in self.cosignatures.iter().flatten() {
            if !cosignature.extra.is_empty() {
                return Err(newer_format("unknown cosignature field"));
            }
            if let Some(assertion) = &cosignature.assertion {
                assertion.check_known_fields()?;
            }
        }
        Ok(())
    }
    /// Serialize the envelope canonically, keeping the original body and assertion bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate_structure()?;
        crate::records::canonical(self).map_err(malformed)
    }
    /// Verify EVERY attached signature against a lookup of authorizing controllers.
    /// Unknown or mismatched controller IDs and failed signatures are `badSignature`.
    /// `uv_required` enforces a rule-wide requirement; replay must additionally enforce
    /// per-controller `verification` using each returned UV flag before authorizing.
    /// This does not authorize roles or thresholds and does not check unknown fields.
    pub fn verify_all<'a, F>(&self, mut lookup: F, uv_required: bool) -> Result<Vec<VerifiedSigner>>
    where
        F: FnMut(&str) -> Option<&'a KeyDescriptor>,
    {
        self.validate_structure()?;
        let by = self.primary_signer()?;
        let mut verified = Vec::new();
        let mut verify =
            |id: &str, signature: &[u8], assertion: Option<&Assertion>| -> Result<()> {
                let key = lookup(id).ok_or_else(|| bad_signature("foreign controller"))?;
                if key.id() != id {
                    return Err(bad_signature("controller key ID mismatch"));
                }
                key.validate()
                    .map_err(|_| bad_signature("invalid controller descriptor"))?;
                let uv = match (key, assertion) {
                    (KeyDescriptor::Raw { signing, .. }, None) => {
                        super::verify_raw(signing, &self.body, signature)?;
                        None
                    }
                    (KeyDescriptor::WebAuthn { .. }, Some(assertion)) => Some(
                        super::verify_webauthn(
                            key,
                            &self.body,
                            signature,
                            &assertion.authenticator_data,
                            &assertion.client_data,
                            uv_required,
                        )
                        .map_err(bad_signature)?,
                    ),
                    _ => {
                        return Err(bad_signature(
                            "assertion presence does not match signer form",
                        ))
                    }
                };
                verified.push(VerifiedSigner { id: id.into(), uv });
                Ok(())
            };
        verify(&by, &self.signature, self.assertion.as_ref())?;
        for cosignature in self.cosignatures.iter().flatten() {
            verify(
                &cosignature.signer,
                &cosignature.signature,
                cosignature.assertion.as_ref(),
            )?;
        }
        Ok(verified)
    }
}
fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn optional_assertion(map: &mut Map<String, Value>) -> Result<Option<Assertion>> {
    map.remove("assertion")
        .map(Assertion::from_value)
        .transpose()
}
macro_rules! strict_deserialize {
    ($type:ty) => {
        impl<'de> Deserialize<'de> for $type {
            fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
                Self::from_value(strict_json::StrictValue::deserialize(d)?.0)
                    .map_err(serde::de::Error::custom)
            }
        }
    };
}
strict_deserialize!(Assertion);
strict_deserialize!(Cosignature);
strict_deserialize!(AuthorityEnvelope);

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::keys::{testing::SyntheticAuthenticator, ErrorCode};
    use base64::{engine::general_purpose::STANDARD, Engine};
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use serde_json::json;
    use std::collections::BTreeMap;
    fn raw(scalar: u8) -> (SigningKey, KeyDescriptor) {
        let signing = SigningKey::from_slice(&[scalar; 32]).unwrap();
        let key = KeyDescriptor::Raw {
            signing: signing
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
            agreement: None,
        };
        (signing, key)
    }
    fn body(by: &str) -> Vec<u8> {
        format!(" {{\"by\":\"{by}\",\"kind\":\"genesis\"}}\n").into_bytes()
    }
    fn sign(signing: &SigningKey, body: &[u8]) -> Vec<u8> {
        let signature: Signature = signing.sign(body);
        signature.to_bytes().to_vec()
    }
    #[test]
    fn raw_and_webauthn_primary_and_cosignatures_verify_and_roundtrip() {
        let (signing, key) = raw(3);
        let authenticator = SyntheticAuthenticator::new().unwrap();
        let passkey = authenticator.descriptor("id.luff.works", None).unwrap();
        for primary_raw in [false, true] {
            let (by, co) = if primary_raw {
                (key.id(), passkey.id())
            } else {
                (passkey.id(), key.id())
            };
            let body = body(&by);
            let web = authenticator
                .assertion(&body, "id.luff.works", "https://a.b.id.luff.works", 5, true)
                .unwrap();
            let raw_signature = sign(&signing, &body);
            let (signature, assertion, cosignature) = if primary_raw {
                (
                    raw_signature,
                    None,
                    Cosignature::new(co, web.signature, Some(web.assertion)),
                )
            } else {
                (
                    web.signature,
                    Some(web.assertion),
                    Cosignature::new(co, raw_signature, None),
                )
            };
            let envelope =
                AuthorityEnvelope::new(body, signature, assertion, Some(vec![cosignature]))
                    .unwrap();
            let keys = BTreeMap::from([(key.id(), key.clone()), (passkey.id(), passkey.clone())]);
            let verified = envelope.verify_all(|id| keys.get(id), true).unwrap();
            assert_eq!(verified.len(), 2);
            assert_eq!(verified[0].id, by);
            assert_eq!(verified[0].uv, if primary_raw { None } else { Some(true) });
            let encoded = envelope.encode().unwrap();
            let decoded = AuthorityEnvelope::from_json(&encoded).unwrap();
            assert_eq!(envelope, decoded);
            assert_eq!(decoded.body, envelope.body);
            assert_eq!(
                serde_json::from_slice::<AuthorityEnvelope>(&encoded).unwrap(),
                envelope
            );
            decoded.check_known_fields().unwrap();
        }
    }
    #[test]
    fn empty_unsorted_duplicate_primary_and_invalid_ids_refuse() {
        let (_, key) = raw(3);
        let by = key.id();
        let low = "00000000000000000000000000000000";
        let high = "ffffffffffffffffffffffffffffffff";
        for cosignatures in [
            vec![],
            vec![
                Cosignature::new(high.into(), vec![], None),
                Cosignature::new(low.into(), vec![], None),
            ],
            vec![
                Cosignature::new(low.into(), vec![], None),
                Cosignature::new(low.into(), vec![], None),
            ],
            vec![Cosignature::new(by.clone(), vec![], None)],
            vec![Cosignature::new("INVALID".into(), vec![], None)],
        ] {
            let result = AuthorityEnvelope::new(body(&by), vec![], None, Some(cosignatures));
            assert_eq!(
                ErrorCode::of(&result.unwrap_err()),
                Some(ErrorCode::Malformed)
            );
        }
        for by in [
            "",
            "0123456789abcdef0123456789abcdeF",
            "0123456789abcdef0123456789abcdef0",
        ] {
            assert!(AuthorityEnvelope::new(body(by), vec![], None, None).is_err());
        }
    }
    #[test]
    fn invalid_extra_foreign_signature_and_form_presence_refuse() {
        let (signing, key) = raw(3);
        let (_, foreign) = raw(4);
        let bytes = body(&key.id());
        let mut envelope =
            AuthorityEnvelope::new(bytes.clone(), sign(&signing, &bytes), None, None).unwrap();
        assert!(envelope.verify_all(|_| Some(&key), false).is_ok());
        assert_eq!(
            ErrorCode::of(&envelope.verify_all(|_| None, false).unwrap_err()),
            Some(ErrorCode::BadSignature)
        );
        assert!(envelope.verify_all(|_| Some(&foreign), false).is_err());
        envelope.cosignatures = Some(vec![Cosignature::new(foreign.id(), vec![0; 64], None)]);
        let keys = BTreeMap::from([(key.id(), key.clone()), (foreign.id(), foreign.clone())]);
        assert_eq!(
            ErrorCode::of(&envelope.verify_all(|id| keys.get(id), false).unwrap_err()),
            Some(ErrorCode::BadSignature)
        );
        envelope.cosignatures = None;
        envelope.assertion = Some(Assertion::new(vec![], vec![]));
        assert!(envelope.verify_all(|_| Some(&key), false).is_err());
        let authenticator = SyntheticAuthenticator::new().unwrap();
        let passkey = authenticator.descriptor("id.luff.works", None).unwrap();
        let bytes = body(&passkey.id());
        let signed = authenticator
            .assertion(&bytes, "id.luff.works", "https://id.luff.works", 1, false)
            .unwrap();
        let mut envelope = AuthorityEnvelope::new(bytes, signed.signature, None, None).unwrap();
        assert!(envelope.verify_all(|_| Some(&passkey), false).is_err());
        envelope.assertion = Some(signed.assertion);
        assert_eq!(
            envelope.verify_all(|_| Some(&passkey), false).unwrap()[0].uv,
            Some(false)
        );
        assert!(envelope.verify_all(|_| Some(&passkey), true).is_err());
        envelope.assertion.as_mut().unwrap().client_data = b"{}".to_vec();
        assert_eq!(
            ErrorCode::of(&envelope.verify_all(|_| Some(&passkey), false).unwrap_err()),
            Some(ErrorCode::BadSignature)
        );
    }
    #[test]
    fn strict_body_envelope_assertion_and_cosignature_json() {
        let (_, key) = raw(3);
        let by = key.id();
        let encoded_body = STANDARD.encode(body(&by));
        for bytes in [format!("{{\"body\":\"{encoded_body}\",\"body\":\"{encoded_body}\",\"signature\":\"\"}}"),format!("{{\"body\":\"{encoded_body}\",\"signature\":\"\",\"assertion\":{{\"authenticatorData\":\"\",\"clientData\":\"\",\"clientData\":\"\"}}}}"),format!("{{\"body\":\"{encoded_body}\",\"signature\":\"\",\"cosignatures\":[{{\"signer\":\"00000000000000000000000000000000\",\"signer\":\"00000000000000000000000000000000\",\"signature\":\"\"}}]}}"),format!("{{\"body\":\"{}\",\"signature\":\"\"}}",STANDARD.encode(format!("{{\"by\":\"{by}\",\"x\":{{\"a\":1,\"a\":2}}}}")))] {
            assert!(AuthorityEnvelope::from_json(bytes.as_bytes()).is_err()); assert!(serde_json::from_str::<AuthorityEnvelope>(&bytes).is_err());
        }
        for (field, invalid) in [
            ("body", json!(null)),
            ("body", json!("%%%")),
            ("body", json!("eA==")),
            ("signature", json!(null)),
            ("assertion", json!(null)),
            ("cosignatures", json!(null)),
            ("cosignatures", json!([])),
            ("cosignatures", json!({})),
            (
                "assertion",
                json!({"authenticatorData":null,"clientData":""}),
            ),
            ("assertion", json!({"authenticatorData":""})),
        ] {
            let mut value = json!({"body":encoded_body,"signature":""});
            value[field] = invalid;
            assert!(AuthorityEnvelope::from_json(&serde_json::to_vec(&value).unwrap()).is_err());
        }
    }
    #[test]
    fn unknown_content_waits_for_authorization() {
        let (signing, key) = raw(3);
        let bytes = body(&key.id());
        let envelope =
            AuthorityEnvelope::new(bytes.clone(), sign(&signing, &bytes), None, None).unwrap();
        let mut value = serde_json::to_value(&envelope).unwrap();
        value["future"] = json!({"x":null});
        let decoded = AuthorityEnvelope::from_json(&serde_json::to_vec(&value).unwrap()).unwrap();
        decoded.verify_all(|_| Some(&key), false).unwrap();
        assert_eq!(
            ErrorCode::of(&decoded.check_known_fields().unwrap_err()),
            Some(ErrorCode::NewerFormat)
        );
        let mut invalid = decoded;
        invalid.signature[0] ^= 1;
        assert_eq!(
            ErrorCode::of(&invalid.verify_all(|_| Some(&key), false).unwrap_err()),
            Some(ErrorCode::BadSignature)
        );
    }
}
