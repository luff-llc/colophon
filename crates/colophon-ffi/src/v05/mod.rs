//! The 0.5 UniFFI exports. The surface is written once in `api/` (shared with the wasm crate);
//! this module only registers it. The 0.4 exports in the crate root are unchanged.
pub mod api;
pub use api::*;
