//! The 0.6 stream client and session conformance vectors through the web build's exports, run
//! natively: the same sources as `colophon-ffi/tests/v06_bindings.rs`. Nothing here needs a JS
//! host: the stream and the session objects take no callbacks.
#![allow(clippy::unwrap_used)]
pub use colophon_wasm::v05::*;
use serde_json::Value;
#[path = "../../colophon-ffi/tests/v06_support/stream.rs"]
mod stream;
#[path = "../../colophon-ffi/tests/v06_support/vectors.rs"]
mod vectors;

/// What `SessionAccountView::supplied` returns in this build.
pub type ViewHandle = SessionAccountView;

fn unhex(t: &str) -> Vec<u8> {
    (0..t.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&t[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn the_web_build_runs_the_stream_transcripts() {
    stream::ticket_open_frames_close_backoff_resume();
    stream::backoff_is_seeded_and_capped();
    stream::refusals_fall_back_to_polling();
    stream::misuse_is_typed();
}

#[test]
fn the_web_build_replays_the_session_vectors() {
    assert!(vectors::replay_machine_vectors() >= 25);
    assert!(vectors::replay_offset_cases() > 0);
    let (frames, steps, negative) =
        vectors::replay_wire_vectors(|view: &ViewHandle, v: &Value, me: String, scalar: String| {
            SessionEndpoint::new(
                v["account"].as_str().unwrap().into(),
                v["namespace"].as_str().unwrap().into(),
                v["cell"].as_str().unwrap().into(),
                me,
                session_default_policy().unwrap(),
                None,
                view,
                unhex(&scalar),
                vec![0; 16],
                SessionClock {
                    mono_ms: 0,
                    wall_ms: v["clockMs"].as_i64().unwrap(),
                },
            )
            .unwrap()
        });
    assert!(frames > 0 && steps > 0 && negative > 0);
    vectors::strict_inputs_fail_closed();
}
