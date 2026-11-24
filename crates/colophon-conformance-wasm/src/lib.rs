//! The 0.6 session conformance surface for web hosts (wasm-bindgen): the same source as
//! `colophon-conformance` (`api.rs`), for a host's conformance tests only. Not published; no
//! shipped crate or artifact depends on it. It links `colophon-wasm`, so its module also carries
//! the whole shipping surface.
#[path = "../../colophon-conformance/src/api.rs"]
pub mod api;
pub use api::*;
pub use colophon_wasm;

impl From<ConformanceError> for wasm_bindgen::JsValue {
    fn from(e: ConformanceError) -> wasm_bindgen::JsValue {
        wasm_bindgen::JsValue::from_str(&e.to_string())
    }
}
