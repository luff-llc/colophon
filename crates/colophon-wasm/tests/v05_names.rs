//! The wasm crate exports exactly the names in `colophon-ffi/src/v05/surface-names.txt`.
#[path = "../../colophon-ffi/tests/support_names.rs"]
mod support_names;

#[test]
fn the_web_surface_is_the_shared_list() {
    let glue = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/v05/mod.rs");
    support_names::check("web05", Some(&glue));
}
