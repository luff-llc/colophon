//! The decisions of a Colophon 0.5 home (§13–§14), as one pure function over bytes and a plain
//! C ABI around it.
//!
//! A relay is I/O: sockets, files, a clock, a signing key. Everything it must *decide* is here,
//! and is only thin composition over `colophon-core`: [`colophon_core::v05::history::home`]
//! (admission, vetoes, receipts, caps, the pending feed, the head guard), the history verifier,
//! `calls` (§12.3) and the engine's path grammar. This crate adds no rule of its own.
//!
//! **Shape.** [`handle`] takes one JSON request `{"op": …, …}` and returns one JSON response
//! `{"ok": true, …}` or `{"ok": false, "error": …}`. Bytes are standard base64. The persisted
//! state is an opaque, versioned value (`"state"`): every operation that changes it returns the
//! new one, and the host commits it atomically before it acts on anything else in the response
//! (a refusal changes state too, §13.1: first-seen facts and permanent late decisions).
//! Nothing here reads a clock, a file or a key: the host passes `now` (milliseconds) and signs
//! what an operation asks it to sign (`"sign"` lists), then gives the signature back.
//!
//! **ABI** (module `abi`): `colophon_alloc`, `colophon_free` and `colophon_home`; the result of
//! the last is a 4-byte little-endian length followed by the response. No wasm-bindgen: a host
//! instantiates the module with `WebAssembly.instantiate` and nothing else.
#![deny(missing_docs)]

pub mod abi;
mod ops;

pub use ops::handle;

// The core's engine fixture and the relay tests' account builders, for the unit tests of `ops`
// that need a real history (`ops::waiting_tests`).
#[cfg(test)]
#[path = "../../colophon-core/tests/v05_engine_support/mod.rs"]
mod support;
#[cfg(test)]
#[path = "../tests/support_relay/mod.rs"]
mod support_relay;
