//! The 0.5 UniFFI exports. The surface is written once in `api/` (shared with the wasm crate);
//! this module only registers it. The 0.4 exports in the crate root are unchanged.
pub mod api;
pub use api::*;

/// The zero-on-free allocator (see the module). The crate installs it when the `zero-on-free`
/// feature is on (it is by default).
pub mod zero_alloc;
#[cfg(feature = "zero-on-free")]
#[global_allocator]
static ALLOCATOR: zero_alloc::ZeroOnFree = zero_alloc::ZeroOnFree::new(std::alloc::System);
