//! The conformance crates export exactly `surface-names.txt` here, and none of those names is a
//! shipping name.
#[path = "../../colophon-ffi/tests/support_names.rs"]
mod support_names;

#[test]
fn the_conformance_surface_is_its_own_list() {
    support_names::check_conformance("native05");
}
