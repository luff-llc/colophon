//! The 0.5 export surface, written once. `colophon-ffi` (UniFFI) and `colophon-wasm`
//! (wasm-bindgen) both compile this directory: the wasm crate includes it by `#[path]`, so the two
//! surfaces cannot drift. The only platform differences are the attributes switched by the
//! `native05` and `web05` features, the host callback type, and how an error is shown. The
//! contract is `docs/bindings-05.md`; the list of exported names is `surface-names.txt`.
//!
//! Everything that crosses is typed: records and C-like enums (`types.rs`), bytes as bytes. Only
//! open-ended protocol or domain content (terms, policy documents, record payloads, view and
//! query results) is UTF-8 JSON, as in 0.4. Objects stay in Rust; handles are opaque.
//!
//! What never crosses in either direction: seed bytes, epoch key bytes, a PRF output or a raw
//! ECDH result read back, a prepared action's state, a verified state supplied by the host.
#![allow(missing_docs, clippy::too_many_arguments)]

#[cfg(all(feature = "native05", feature = "web05"))]
compile_error!(
    "the `native05` (UniFFI) and `web05` (wasm-bindgen) features are two builds of one surface and \
     cannot be on together: build each crate with its own feature (`--all-features` is not \
     supported; use `--features native05` for colophon-ffi and the default for colophon-wasm)"
);

mod action;
mod convert;
mod create;
mod engine;
mod fault;
mod moving;
mod pairing;
mod session;
mod successor;
mod types;
mod verify;

pub use action::AccountAction;
pub use create::{account_default_policy, AccountCreation};
pub use engine::{AccountBlobWriter, AccountEngine, AccountLiveWrite};
pub use fault::{AccountError, REFUSAL_REASONS};
pub use moving::AccountMove;
pub use pairing::{AccountPairing, PairingFailureLimiter, PairingTransferKey};
pub use session::{
    AccountCopyWrite, SwiftCopyDestination, SwiftCopyPlan, SwiftCopyResult, SwiftSource,
    SwiftTranslator,
};
pub use successor::SwiftSuccessorCreation;
pub use types::*;
pub use verify::*;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// The record source the host supplies: synchronous and read-only. It must not call back into
/// the engine that is reading it (that fails with `Reentered`). The engine reads only paths it
/// was told about by a listing or that it wrote itself. Content versions arrive with the
/// listing, in one batch, not through a callback per path.
#[cfg(feature = "native05")]
#[uniffi::export(callback_interface)]
pub trait HostSource: Send + Sync {
    /// The exact stored bytes at `path`. An error means the path cannot be read now; its
    /// message reaches the caller as `Host`.
    fn read(&self, path: String) -> Result<Vec<u8>, AccountError>;
    /// A blob chunk's stored bytes: an empty vector means not held here (missing); an error
    /// means inaccessible.
    fn read_blob(&self, path: String) -> Result<Vec<u8>, AccountError>;
}
#[cfg(not(feature = "native05"))]
pub trait HostSource {
    fn read(&self, path: String) -> Result<Vec<u8>, AccountError>;
    fn read_blob(&self, path: String) -> Result<Vec<u8>, AccountError>;
}

/// The versions a listing carried, shared between the engine's source and its wrapper.
pub(crate) type Versions = Arc<Mutex<HashMap<String, String>>>;
/// The first failure a host callback reported during the current call.
pub(crate) type HostFault = Arc<Mutex<Option<String>>>;

/// Whether the thread that holds an object's lock is inside a host callback right now.
pub(crate) type InCallback = Arc<std::sync::atomic::AtomicBool>;

/// The engine's view of the host's source.
pub(crate) struct Source {
    host: Box<dyn HostSource>,
    versions: Versions,
    fault: HostFault,
    busy: InCallback,
}
/// Marks the engine as inside a host callback for as long as it lives.
struct InHost<'a>(&'a InCallback);
impl<'a> InHost<'a> {
    fn enter(b: &'a InCallback) -> Self {
        b.store(true, Ordering::SeqCst);
        Self(b)
    }
}
impl Drop for InHost<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}
impl Source {
    pub(crate) fn new(
        host: Box<dyn HostSource>,
        versions: Versions,
        fault: HostFault,
        busy: InCallback,
    ) -> Self {
        Self {
            host,
            versions,
            fault,
            busy,
        }
    }
    fn note(&self, e: &AccountError) {
        if let Ok(mut f) = self.fault.lock() {
            if f.is_none() {
                *f = Some(e.detail_text());
            }
        }
    }
}
impl colophon_core::engine::RecordSource for Source {
    fn read(&self, path: &str) -> colophon_core::Result<Vec<u8>> {
        let _in = InHost::enter(&self.busy);
        self.host.read(path.to_string()).map_err(|e| {
            self.note(&e);
            colophon_core::Error(e.detail_text())
        })
    }
    fn content_version(&self, path: &str) -> colophon_core::Result<Option<String>> {
        Ok(self
            .versions
            .lock()
            .ok()
            .and_then(|v| v.get(path).cloned())
            .filter(|v| !v.is_empty()))
    }
    fn read_blob(&self, path: &str) -> colophon_core::Result<colophon_core::blobs::BlobRead> {
        let _in = InHost::enter(&self.busy);
        match self.host.read_blob(path.to_string()) {
            Ok(b) if b.is_empty() => Ok(colophon_core::blobs::BlobRead::Missing),
            Ok(b) => Ok(colophon_core::blobs::BlobRead::Available(b)),
            Err(e) => {
                self.note(&e);
                Ok(colophon_core::blobs::BlobRead::Inaccessible(
                    e.detail_text(),
                ))
            }
        }
    }
}

static NEXT_THREAD: AtomicU64 = AtomicU64::new(1);
thread_local! {
    static THREAD: u64 = NEXT_THREAD.fetch_add(1, Ordering::Relaxed);
}

/// How long a call from another thread waits for an object whose holder is inside a host
/// callback before it fails (milliseconds). A callback is synchronous, so this only bites a
/// callback that waits for the thread that is waiting: a deadlock the host wrote.
static CALLBACK_WAIT_MS: AtomicU64 = AtomicU64::new(30_000);
/// Test support: how long (ms) a call waits for an object whose holder is inside a host
/// callback. The default is 30,000.
#[doc(hidden)]
pub fn set_callback_wait_ms(ms: u64) {
    CALLBACK_WAIT_MS.store(ms, Ordering::SeqCst);
}

/// A lock that waits for calls from other threads (as 0.4's does) and fails with `Reentered`
/// when the thread that holds it asks again (a host callback calling into the object that is
/// calling it), and when it has waited for longer than [`set_callback_wait_ms`] for an object
/// whose holder is inside a host callback (a callback that waits for the thread that waits).
pub(crate) struct Cell<T> {
    m: Mutex<T>,
    owner: AtomicU64,
    busy: Option<InCallback>,
}
pub(crate) struct Held<'a, T> {
    g: std::sync::MutexGuard<'a, T>,
    flag: &'a AtomicU64,
}
impl<T> std::ops::Deref for Held<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.g
    }
}
impl<T> std::ops::DerefMut for Held<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.g
    }
}
impl<T> Drop for Held<'_, T> {
    fn drop(&mut self) {
        self.flag.store(0, Ordering::Release);
    }
}
impl<T> Cell<T> {
    pub(crate) fn new(v: T) -> Self {
        Self {
            m: Mutex::new(v),
            owner: AtomicU64::new(0),
            busy: None,
        }
    }
    /// A cell whose holder is known to be inside a host callback while `busy` is set.
    pub(crate) fn watched(v: T, busy: InCallback) -> Self {
        Self {
            m: Mutex::new(v),
            owner: AtomicU64::new(0),
            busy: Some(busy),
        }
    }
    pub(crate) fn lock(&self) -> Result<Held<'_, T>, AccountError> {
        use std::sync::TryLockError;
        let me = THREAD.with(|t| *t);
        if self.owner.load(Ordering::Acquire) == me {
            return Err(AccountError::reentered());
        }
        let poisoned = || {
            AccountError::internal(
                "an earlier call panicked; discard this object and open a new one",
            )
        };
        let g = match (&self.busy, self.m.try_lock()) {
            (_, Ok(g)) => g,
            (_, Err(TryLockError::Poisoned(_))) => return Err(poisoned()),
            (None, Err(TryLockError::WouldBlock)) => self.m.lock().map_err(|_| poisoned())?,
            (Some(busy), Err(TryLockError::WouldBlock)) => {
                let start = std::time::Instant::now();
                loop {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    match self.m.try_lock() {
                        Ok(g) => break g,
                        Err(TryLockError::Poisoned(_)) => return Err(poisoned()),
                        Err(TryLockError::WouldBlock) => {}
                    }
                    let limit = CALLBACK_WAIT_MS.load(Ordering::Relaxed);
                    if busy.load(Ordering::SeqCst)
                        && start.elapsed() >= std::time::Duration::from_millis(limit)
                    {
                        return Err(AccountError::Reentered {
                            code: "reentered".into(),
                            detail: "this object's holder has been inside a host callback for \
                                     longer than the wait allows: a callback must not call the \
                                     engine and must not wait for a thread that does"
                                .into(),
                        });
                    }
                }
            }
        };
        self.owner.store(me, Ordering::Release);
        Ok(Held {
            g,
            flag: &self.owner,
        })
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
