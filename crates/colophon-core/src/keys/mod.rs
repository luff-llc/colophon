//! Colophon 0.4 key descriptors and authority signatures (§2–§3).
//!
//! Parsing retains unknown envelope fields until the authority layer has authorized
//! the record. Call [`AuthorityEnvelope::check_known_fields`] only after §6.3's
//! authorization step. Requests and operations continue to use `records`.

pub mod cose;
pub mod descriptor;
pub mod envelope;
pub mod strict_json;
/// Synthetic software authenticator for conformance vectors, never platform custody.
#[doc(hidden)]
pub mod testing;
pub mod webauthn;

pub use descriptor::KeyDescriptor;
pub use envelope::{Assertion, AuthorityEnvelope, Cosignature, VerifiedSigner};
pub use webauthn::{challenge, verify_raw, verify_webauthn};

use crate::{Error, Result};
use serde_json::{Map, Value};

/// Stable Colophon 0.4 failure categories, carried by the crate's string error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    /// Invalid protocol structure or encoding.
    Malformed,
    /// An attached authority signature failed verification or lookup.
    BadSignature,
    /// Authenticated content uses an unsupported field or variant.
    NewerFormat,
}
impl ErrorCode {
    /// Protocol spelling of this category.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::BadSignature => "badSignature",
            Self::NewerFormat => "newerFormat",
        }
    }
    /// Recover a keys error category from the crate's string error.
    pub fn of(error: &Error) -> Option<Self> {
        [Self::Malformed, Self::BadSignature, Self::NewerFormat]
            .into_iter()
            .find(|code| {
                error.0 == code.as_str() || error.0.starts_with(&format!("{}: ", code.as_str()))
            })
    }
}
fn failure(code: ErrorCode, reason: impl std::fmt::Display) -> Error {
    Error(format!("{}: {reason}", code.as_str()))
}
fn malformed(reason: impl std::fmt::Display) -> Error {
    failure(ErrorCode::Malformed, reason)
}
fn bad_signature(reason: impl std::fmt::Display) -> Error {
    failure(ErrorCode::BadSignature, reason)
}
fn newer_format(reason: impl std::fmt::Display) -> Error {
    failure(ErrorCode::NewerFormat, reason)
}
fn require(ok: bool, reason: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(malformed(reason))
    }
}
fn object(value: Value) -> Result<Map<String, Value>> {
    match value {
        Value::Object(map) => Ok(map),
        _ => Err(malformed("expected object")),
    }
}
fn take_string(map: &mut Map<String, Value>, field: &str) -> Result<String> {
    match map.remove(field) {
        Some(Value::String(value)) => Ok(value),
        _ => Err(malformed(format!("expected string: {field}"))),
    }
}
fn take_bytes(map: &mut Map<String, Value>, field: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(take_string(map, field)?)
        .map_err(|_| malformed(format!("invalid base64: {field}")))
}
fn point(bytes: &[u8]) -> Result<()> {
    require(
        bytes.len() == 65 && bytes[0] == 4,
        "expected uncompressed P-256 point",
    )?;
    p256::PublicKey::from_sec1_bytes(bytes).map_err(|_| malformed("invalid P-256 point"))?;
    Ok(())
}
