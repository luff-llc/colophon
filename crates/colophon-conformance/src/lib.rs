//! The 0.6 session conformance surface for native hosts (UniFFI). It is linked only into a host's
//! conformance tests: it is not published, and no shipped crate or artifact depends on it. The
//! surface (`api.rs`) is shared with `colophon-conformance-wasm`; see it for what each object
//! bypasses and why that keeps it out of the shipping crates. This crate links `colophon-ffi`, so
//! its artifact also carries the whole shipping surface.
uniffi::setup_scaffolding!();

pub mod api;
pub use api::*;
pub use colophon_ffi;
