//! Every 0.6 session conformance vector the conformance surface can drive (see
//! `support/vectors.rs` for the parts it cannot), and strict decoding at the boundary, through
//! the UniFFI conformance crate. `colophon-conformance-wasm` runs the same sources.
#![allow(clippy::unwrap_used)]
pub use colophon_conformance::*;
pub use colophon_ffi::v05::api::{
    session_clock_sample, session_default_policy, session_validate_policy,
};
#[path = "support/vectors.rs"]
mod vectors;

#[test]
fn every_session_machine_vector_replays() {
    let n = vectors::replay_machine_vectors();
    assert!(n >= 25, "{n} machine vectors");
    assert!(vectors::replay_offset_cases() > 0);
}
#[test]
fn the_wire_vectors_replay() {
    let (frames, steps, negative) = vectors::replay_wire_vectors();
    assert!(frames > 0 && steps > 0 && negative > 0);
}
#[test]
fn session_inputs_are_decoded_strictly() {
    vectors::strict_inputs_fail_closed();
}
