//! The web conformance crate exports the same names as the native one.
#[path = "../../colophon-ffi/tests/support_names.rs"]
mod support_names;

#[test]
fn the_web_conformance_surface_is_the_same_list() {
    support_names::check_conformance("web05");
}
