//! The 0.5 export surface, written once. `colophon-ffi` (UniFFI) and `colophon-wasm`
//! (wasm-bindgen) both compile this directory: the wasm crate includes it by `#[path]`, so the two
//! surfaces cannot drift. The only platform differences are the attributes switched by the
//! `native05` and `web05` features, the host callback type, and how an error is shown. The
//! contract is `docs/bindings-05.md`; the list of exported names is `surface-names.txt`.
//!
//! Everything that crosses is a scalar, a byte string, a UTF-8 string, or a JSON string whose
//! binary fields are standard base64 (as in the protocol). Complex values (views, notices,
//! members, steps) are JSON documented in the contract. Objects stay on the Rust side: handles
//! are opaque, a prepared action is held by the core and finished from its own retained state.
//!
//! What never crosses in either direction: seed bytes, epoch key bytes, a PRF output read back,
//! a raw ECDH result read back, a prepared action's state, a verified state supplied by the host.
#![allow(missing_docs, clippy::too_many_arguments)]

/// Serialize a core value to JSON text (the wasm crate has no `serde` of its own, so this is
/// a macro over `serde_json` rather than a generic function).
macro_rules! ser {
    ($x:expr) => {
        serde_json::to_string(&$x)
            .map_err(|_| AccountError::internal("a result could not be written"))
    };
}
macro_rules! ser_value {
    ($x:expr) => {
        serde_json::to_value(&$x)
            .map_err(|_| AccountError::internal("a result could not be written"))
    };
}

mod account;
mod action;
mod create;
mod engine;
mod fault;
mod json;
mod moving;
mod pairing;
mod verify;

pub use account::AccountCore;
pub use action::AccountAction;
pub use create::AccountCreation;
pub use engine::{AccountBlobWriter, AccountEngine, AccountLiveWrite};
pub use fault::{AccountError, REFUSAL_REASONS};
pub use moving::AccountMove;
pub use pairing::{AccountPairing, PairingFailureLimiter, PairingTransferKey};
pub use verify::AccountRequest;
pub use verify::*;

use std::sync::Mutex;

/// The record source the host supplies: synchronous, read-only, and it must not call back into
/// the engine that is reading it (a re-entering call fails with `Reentered`). The engine reads
/// only paths it was told about by a listing or that it wrote itself.
#[cfg(feature = "native05")]
#[uniffi::export(callback_interface)]
pub trait HostSource: Send + Sync {
    /// The exact stored bytes at `path`. An error means the path cannot be read now.
    fn read(&self, path: String) -> Result<Vec<u8>, AccountError>;
    /// The provider's content-version token for `path`, or an empty string for none.
    fn version(&self, path: String) -> Result<String, AccountError>;
    /// A blob chunk's stored bytes: an empty vector means not held here (missing); an error
    /// means inaccessible.
    fn read_blob(&self, path: String) -> Result<Vec<u8>, AccountError>;
}
#[cfg(not(feature = "native05"))]
pub trait HostSource {
    fn read(&self, path: String) -> Result<Vec<u8>, AccountError>;
    fn version(&self, path: String) -> Result<String, AccountError>;
    fn read_blob(&self, path: String) -> Result<Vec<u8>, AccountError>;
}

/// The engine's view of the host's source.
pub(crate) struct Source {
    host: Box<dyn HostSource>,
}
impl Source {
    pub(crate) fn new(host: Box<dyn HostSource>) -> Self {
        Self { host }
    }
}
fn host_err(e: AccountError) -> colophon_core::Error {
    colophon_core::Error(e.detail_text())
}
impl colophon_core::engine::RecordSource for Source {
    fn read(&self, path: &str) -> colophon_core::Result<Vec<u8>> {
        self.host.read(path.to_string()).map_err(host_err)
    }
    fn content_version(&self, path: &str) -> colophon_core::Result<Option<String>> {
        let v = self.host.version(path.to_string()).map_err(host_err)?;
        if v.len() > 256 {
            return Err(colophon_core::Error("a content version over 256 bytes".into()));
        }
        Ok((!v.is_empty()).then_some(v))
    }
    fn read_blob(&self, path: &str) -> colophon_core::Result<colophon_core::blobs::BlobRead> {
        match self.host.read_blob(path.to_string()) {
            Ok(b) if b.is_empty() => Ok(colophon_core::blobs::BlobRead::Missing),
            Ok(b) => Ok(colophon_core::blobs::BlobRead::Available(b)),
            Err(e) => Ok(colophon_core::blobs::BlobRead::Inaccessible(e.detail_text())),
        }
    }
}

/// Lock an object's state without waiting: a callback that re-enters finds it locked, and a
/// panic that poisoned it is reported, never ignored.
pub(crate) fn lock<T>(m: &Mutex<T>) -> Result<std::sync::MutexGuard<'_, T>, AccountError> {
    match m.try_lock() {
        Ok(g) => Ok(g),
        Err(std::sync::TryLockError::WouldBlock) => Err(AccountError::reentered()),
        Err(std::sync::TryLockError::Poisoned(_)) => Err(AccountError::internal(
            "an earlier call panicked; discard this object and open a new one",
        )),
    }
}

/// Run a call so that no panic crosses the boundary. On a target without unwinding (wasm32) a
/// panic aborts the instance instead; the contract says so.
pub(crate) fn guard<T>(f: impl FnOnce() -> Result<T, AccountError>) -> Result<T, AccountError> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(r) => r,
        Err(_) => Err(AccountError::internal(
            "an internal error; the object may be unusable",
        )),
    }
}
