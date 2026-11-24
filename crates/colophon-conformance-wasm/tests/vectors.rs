//! The 0.6 session conformance vectors through the wasm conformance crate's exports, run
//! natively: the same sources as `colophon-conformance/tests/vectors.rs`.
#![allow(clippy::unwrap_used)]
pub use colophon_conformance_wasm::*;
pub use colophon_wasm::v05::{
    session_clock_sample, session_default_policy, session_validate_policy,
};
#[path = "../../colophon-conformance/tests/support/vectors.rs"]
mod vectors;

#[test]
fn the_web_build_replays_the_session_vectors() {
    assert!(vectors::replay_machine_vectors() >= 25);
    assert!(vectors::replay_offset_cases() > 0);
    let (frames, steps, negative) = vectors::replay_wire_vectors();
    assert!(frames > 0 && steps > 0 && negative > 0);
    vectors::strict_inputs_fail_closed();
}
