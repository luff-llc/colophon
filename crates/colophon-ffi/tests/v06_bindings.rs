//! The 0.6 stream client and session endpoint through the UniFFI build's exports only: the
//! stream transcripts (ticket, open, frames, close, backoff, polling fallback) and every session
//! conformance vector the binding surface can drive (see `v06_support/vectors.rs` for the parts
//! it cannot). The wasm crate runs the same sources (`colophon-wasm/tests/v06_bindings.rs`).
#![allow(clippy::unwrap_used)]
pub use colophon_ffi::v05::api::*;
use serde_json::Value;
use std::sync::Arc;
#[path = "v06_support/stream.rs"]
mod stream;
#[path = "v06_support/vectors.rs"]
mod vectors;

/// What `SessionAccountView::supplied` returns in this build.
pub type ViewHandle = Arc<SessionAccountView>;

fn unhex(t: &str) -> Vec<u8> {
    (0..t.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&t[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn the_stream_client_runs_ticket_open_frames_close_backoff_and_resume() {
    stream::ticket_open_frames_close_backoff_resume();
}
#[test]
fn the_stream_backoff_is_seeded_and_capped() {
    stream::backoff_is_seeded_and_capped();
}
#[test]
fn a_refused_or_ended_stream_falls_back_to_polling() {
    stream::refusals_fall_back_to_polling();
}
#[test]
fn stream_misuse_is_a_typed_error() {
    stream::misuse_is_typed();
}

#[test]
fn every_session_machine_vector_replays_through_the_binding() {
    let n = vectors::replay_machine_vectors();
    assert!(n >= 25, "{n} machine vectors");
    let c = vectors::replay_offset_cases();
    assert!(c > 0);
    println!("{n} machine vectors and {c} offset cases replayed through the binding");
}

#[test]
fn the_wire_vectors_replay_through_the_binding() {
    let (frames, steps, negative) =
        vectors::replay_wire_vectors(|view: &ViewHandle, v: &Value, me: String, scalar: String| {
            SessionEndpoint::new(
                v["account"].as_str().unwrap().into(),
                v["namespace"].as_str().unwrap().into(),
                v["cell"].as_str().unwrap().into(),
                me,
                session_default_policy().unwrap(),
                None,
                view.clone(),
                unhex(&scalar),
                vec![0; 16],
                SessionClock {
                    mono_ms: 0,
                    wall_ms: v["clockMs"].as_i64().unwrap(),
                },
            )
            .unwrap()
        });
    println!("{frames} frames, {steps} scenario steps, {negative} negative cases replayed");
    assert!(frames > 0 && steps > 0 && negative > 0);
}

#[test]
fn session_inputs_are_decoded_strictly() {
    vectors::strict_inputs_fail_closed();
}
