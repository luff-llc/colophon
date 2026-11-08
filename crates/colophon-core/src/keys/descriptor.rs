//! Validated raw and WebAuthn key descriptors (§2.2).
use super::{
    malformed, newer_format, object, point, require, strict_json, take_bytes, take_string,
};
use crate::Result;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

/// A controller's public key and its form-specific metadata.
/// Validate host-constructed values before using them in a keyring.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "form")]
pub enum KeyDescriptor {
    /// A raw ES256 signing key with an optional separate ECDH key.
    #[serde(rename = "raw")]
    Raw {
        /// Uncompressed 65-byte P-256 signing point.
        #[serde(with = "crate::records::bytes")]
        signing: Vec<u8>,
        /// Separate uncompressed ECDH point, when the key opens sealed slots.
        #[serde(skip_serializing_if = "Option::is_none", with = "optional_bytes")]
        agreement: Option<Vec<u8>>,
    },
    /// A WebAuthn assertion key with its relying party and credential hint.
    #[serde(rename = "webauthn")]
    WebAuthn {
        /// Uncompressed 65-byte P-256 signing point.
        #[serde(with = "crate::records::bytes")]
        signing: Vec<u8>,
        /// Relying party ID, as constrained by §2.2.
        rp: String,
        /// Credential lookup hint; never used in signature verification.
        #[serde(with = "crate::records::bytes")]
        credential: Vec<u8>,
        /// Sorted allowlist of additional, non-web origins.
        #[serde(skip_serializing_if = "Option::is_none")]
        origins: Option<Vec<String>>,
    },
}
mod optional_bytes {
    use serde::Serializer;
    pub fn serialize<S: Serializer>(
        value: &Option<Vec<u8>>,
        s: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        match value {
            Some(bytes) => crate::records::bytes::serialize(bytes, s),
            None => s.serialize_none(),
        }
    }
}
impl<'de> Deserialize<'de> for KeyDescriptor {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let value = strict_json::StrictValue::deserialize(d)?.0;
        Self::from_value(value).map_err(serde::de::Error::custom)
    }
}
impl KeyDescriptor {
    /// Parse a descriptor with duplicate rejection and full validation.
    /// Call only at the typed-schema stage of authority replay (§6.3).
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        Self::from_value(strict_json::parse(bytes)?)
    }
    /// Validate a descriptor value already parsed with the strict JSON parser.
    /// Unknown forms or fields report `newerFormat`; authorization is the caller's job.
    pub fn from_value(value: Value) -> Result<Self> {
        let mut map = object(value)?;
        let form = take_string(&mut map, "form")?;
        let key = match form.as_str() {
            "raw" => {
                require(
                    !["rp", "credential", "origins"]
                        .iter()
                        .any(|f| map.contains_key(*f)),
                    "WebAuthn fields on raw key",
                )?;
                Self::Raw {
                    signing: take_bytes(&mut map, "signing")?,
                    agreement: if map.contains_key("agreement") {
                        Some(take_bytes(&mut map, "agreement")?)
                    } else {
                        None
                    },
                }
            }
            "webauthn" => {
                require(!map.contains_key("agreement"), "agreement on WebAuthn key")?;
                Self::WebAuthn {
                    signing: take_bytes(&mut map, "signing")?,
                    rp: take_string(&mut map, "rp")?,
                    credential: take_bytes(&mut map, "credential")?,
                    origins: match map.remove("origins") {
                        None => None,
                        Some(Value::Array(values)) => Some(
                            values
                                .into_iter()
                                .map(|v| match v {
                                    Value::String(s) => Ok(s),
                                    _ => Err(malformed("origin must be string")),
                                })
                                .collect::<Result<_>>()?,
                        ),
                        _ => return Err(malformed("origins must be array")),
                    },
                }
            }
            _ => return Err(newer_format("unknown key form")),
        };
        if !map.is_empty() {
            return Err(newer_format("unknown key descriptor field"));
        }
        key.validate()?;
        Ok(key)
    }
    /// Validate point encodings, separate usage and all form-specific constraints.
    /// Cross-principal uniqueness and required sealed-slot agreement keys are checked by replay.
    pub fn validate(&self) -> Result<()> {
        point(self.signing())?;
        match self {
            Self::Raw { signing, agreement } => {
                if let Some(agreement) = agreement {
                    point(agreement)?;
                    require(signing != agreement, "signing equals agreement")?;
                }
            }
            Self::WebAuthn {
                rp,
                credential,
                origins,
                ..
            } => {
                require(valid_rp(rp), "invalid relying party ID")?;
                require((1..=1023).contains(&credential.len()), "credential length")?;
                if let Some(origins) = origins {
                    require((1..=32).contains(&origins.len()), "origins length")?;
                    for origin in origins {
                        require(
                            (1..=512).contains(&origin.len())
                                && origin.bytes().all(|b| (0x21..=0x7e).contains(&b)),
                            "invalid origin entry",
                        )?;
                        require(
                            !origin.starts_with("http:") && !origin.starts_with("https:"),
                            "web origin in allowlist",
                        )?;
                    }
                    require(
                        origins
                            .windows(2)
                            .all(|w| w[0].as_bytes() < w[1].as_bytes()),
                        "origins must be strictly sorted",
                    )?;
                }
            }
        }
        Ok(())
    }
    /// The uncompressed signing point.
    pub fn signing(&self) -> &[u8] {
        match self {
            Self::Raw { signing, .. } | Self::WebAuthn { signing, .. } => signing,
        }
    }
    /// The raw key's optional agreement point.
    pub fn agreement(&self) -> Option<&[u8]> {
        match self {
            Self::Raw { agreement, .. } => agreement.as_deref(),
            Self::WebAuthn { .. } => None,
        }
    }
    /// First 32 lowercase hex characters of SHA-256(signing).
    pub fn id(&self) -> String {
        crate::records::id(self.signing())
    }
    /// Whether this descriptor signs using WebAuthn assertions.
    pub fn is_webauthn(&self) -> bool {
        matches!(self, Self::WebAuthn { .. })
    }
    /// Validate and serialize canonical JSON, omitting absent optional fields.
    pub fn canonical(&self) -> Result<Vec<u8>> {
        self.validate()?;
        crate::records::canonical(self).map_err(malformed)
    }
}
fn valid_rp(rp: &str) -> bool {
    (1..=253).contains(&rp.len())
        && rp.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde_json::json;
    fn value() -> Value {
        let signing = p256::ecdsa::SigningKey::from_slice(&[1; 32]).unwrap();
        json!({"form":"webauthn","signing":STANDARD.encode(signing.verifying_key().to_encoded_point(false).as_bytes()),"rp":"id.luff.works","credential":"AQ=="})
    }
    #[test]
    fn canonical_id_and_optional_fields() {
        let key = KeyDescriptor::from_value(value()).unwrap();
        let encoded = key.canonical().unwrap();
        assert_eq!(encoded, format!(
            "{{\"credential\":\"AQ==\",\"form\":\"webauthn\",\"rp\":\"id.luff.works\",\"signing\":\"{}\"}}",
            STANDARD.encode(key.signing())
        ).into_bytes());
        assert_eq!(KeyDescriptor::from_json(&encoded).unwrap(), key);
        assert_eq!(
            serde_json::from_slice::<KeyDescriptor>(&encoded).unwrap(),
            key
        );
        assert!(!String::from_utf8(encoded).unwrap().contains("origins"));
        assert_eq!(key.id(), crate::records::digest(key.signing())[..32]);
        let raw = KeyDescriptor::Raw {
            signing: key.signing().to_vec(),
            agreement: None,
        };
        assert!(!String::from_utf8(raw.canonical().unwrap())
            .unwrap()
            .contains("agreement"));
    }
    #[test]
    fn rp_syntax_and_boundaries() {
        for rp in [
            "",
            "-id.example",
            "id-.example",
            ".id",
            "id.",
            "id..example",
            "Id.example",
            "id:80",
            "é",
            &"x".repeat(64),
            &format!(
                "{}.{}.{}.{}",
                "a".repeat(63),
                "b".repeat(63),
                "c".repeat(63),
                "d".repeat(62)
            ),
        ] {
            let mut v = value();
            v["rp"] = json!(rp);
            assert!(KeyDescriptor::from_value(v).is_err(), "{rp}");
        }
        for rp in [
            "a",
            "0-1.id.luff.works",
            &format!(
                "{}.{}.{}.{}",
                "a".repeat(63),
                "b".repeat(63),
                "c".repeat(63),
                "d".repeat(61)
            ),
        ] {
            let mut v = value();
            v["rp"] = json!(rp);
            assert!(KeyDescriptor::from_value(v).is_ok());
        }
    }
    #[test]
    fn origins_syntax_and_boundaries() {
        for origins in [
            json!([]),
            json!(["https:example"]),
            json!(["http:example"]),
            json!([""]),
            json!(["a b"]),
            json!(["a\n"]),
            json!(["é"]),
            json!(["\u{7f}"]),
            json!(["b", "a"]),
            json!(["a", "a"]),
            json!(["x".repeat(513)]),
            json!(null),
            json!([1]),
            json!(vec!["x"; 33]),
        ] {
            let mut v = value();
            v["origins"] = origins;
            assert!(KeyDescriptor::from_value(v).is_err());
        }
        let mut v = value();
        v["origins"] = json!(["android:apk-key-hash:abcd", "x".repeat(512)]);
        assert!(KeyDescriptor::from_value(v).is_ok());
        let mut v = value();
        v["origins"] = json!((0..32)
            .map(|i| format!("android:{i:02}"))
            .collect::<Vec<_>>());
        assert!(KeyDescriptor::from_value(v).is_ok());
    }
    #[test]
    fn wrong_sizes_forbidden_fields_points_and_unknowns() {
        for credential in [vec![], vec![0; 1024]] {
            let mut v = value();
            v["credential"] = json!(STANDARD.encode(credential));
            assert!(KeyDescriptor::from_value(v).is_err());
        }
        let mut v = value();
        v["credential"] = json!(STANDARD.encode(vec![0; 1023]));
        assert!(KeyDescriptor::from_value(v).is_ok());
        for signing in [vec![], vec![4; 65], vec![2; 33], vec![0; 65]] {
            let mut v = value();
            v["signing"] = json!(STANDARD.encode(signing));
            assert!(KeyDescriptor::from_value(v).is_err());
        }
        for field in ["agreement", "credential", "rp"] {
            let mut v = value();
            v[field] = Value::Null;
            assert!(KeyDescriptor::from_value(v).is_err());
        }
        for field in ["rp", "credential", "origins"] {
            let mut v = value();
            v["form"] = json!("raw");
            v.as_object_mut().unwrap().remove("rp");
            v.as_object_mut().unwrap().remove("credential");
            v[field] = json!("forbidden");
            assert!(KeyDescriptor::from_value(v).is_err());
        }
        let key = KeyDescriptor::from_value(value()).unwrap();
        let agreement = p256::ecdsa::SigningKey::from_slice(&[2; 32])
            .unwrap()
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let valid = KeyDescriptor::Raw {
            signing: key.signing().to_vec(),
            agreement: Some(agreement.clone()),
        };
        assert_eq!(
            KeyDescriptor::from_json(&valid.canonical().unwrap()).unwrap(),
            valid
        );
        assert_eq!(valid.agreement(), Some(agreement.as_slice()));
        for invalid in [
            json!(null),
            json!(0),
            json!("%%%"),
            json!(STANDARD.encode([4; 65])),
        ] {
            let mut raw_value = serde_json::to_value(&valid).unwrap();
            raw_value["agreement"] = invalid;
            assert!(KeyDescriptor::from_value(raw_value).is_err());
        }
        let raw = KeyDescriptor::Raw {
            signing: key.signing().to_vec(),
            agreement: Some(key.signing().to_vec()),
        };
        assert!(raw.validate().is_err());
        let mut v = value();
        v["future"] = json!(true);
        assert_eq!(
            super::super::ErrorCode::of(&KeyDescriptor::from_value(v).unwrap_err()),
            Some(super::super::ErrorCode::NewerFormat)
        );
        let mut v = value();
        v["form"] = json!("future");
        assert!(KeyDescriptor::from_value(v).is_err());
        let bytes = br#"{"form":"raw","form":"raw"}"#;
        assert!(KeyDescriptor::from_json(bytes).is_err());
        assert!(serde_json::from_slice::<KeyDescriptor>(bytes).is_err());
    }
}
