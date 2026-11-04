//! Pure Colophon 0.2 protocol evaluation. Hosts own storage, time, entropy and private keys.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod authority;
pub mod crypto;
pub mod domain;
pub mod hpke;
pub mod library;
pub mod model;
pub mod records;

/// A protocol or cryptographic validation failure. Messages contain no private key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Error {}
impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Self {
        Self(value.to_string())
    }
}
/// Fallible protocol result.
pub type Result<T> = std::result::Result<T, Error>;
pub(crate) fn ensure(ok: bool, reason: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(Error(reason.into()))
    }
}
