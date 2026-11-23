//! The 0.6 stream client through the web build's exports, run natively: the same sources as
//! `colophon-ffi/tests/v06_bindings.rs`. Nothing here needs a JS host: the stream takes no
//! callbacks.
#![allow(clippy::unwrap_used)]
pub use colophon_wasm::v05::*;
#[path = "../../colophon-ffi/tests/v06_support/stream.rs"]
mod stream;

#[test]
fn the_web_build_runs_the_stream_transcripts() {
    stream::ticket_open_frames_close_backoff_resume();
    stream::backoff_is_seeded_and_capped();
    stream::refusals_fall_back_to_polling();
    stream::misuse_is_typed();
}
