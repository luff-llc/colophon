//! The 0.6 stream client through the UniFFI build's exports only: the stream transcripts
//! (ticket, open, frames, close, backoff, polling fallback), and that the handles are `Send +
//! Sync` and serialize concurrent calls. The session vectors are `v06_conformance.rs` (a
//! conformance build). The wasm crate runs the same stream sources.
#![allow(clippy::unwrap_used)]
pub use colophon_ffi::v05::api::*;
use std::sync::Arc;
#[path = "v06_support/stream.rs"]
mod stream;

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
fn one_ticket_call_is_out_at_a_time() {
    stream::one_ticket_call_at_a_time();
}
#[test]
fn stream_misuse_is_a_typed_error() {
    stream::misuse_is_typed();
}

#[test]
fn the_handles_are_send_and_sync_and_serialize_concurrent_calls() {
    fn send_sync<T: Send + Sync>() {}
    send_sync::<HomeStream>();
    send_sync::<SessionEndpoint>();
    send_sync::<SessionAccountView>();
    // Eight threads race for the one outstanding ticket call: exactly one is answered, the
    // others are refused because the first already took it. Without serialization two could
    // both see it outstanding.
    for _ in 0..20 {
        let s = HomeStream::new(
            "h".into(),
            stream::BASE.into(),
            stream_default_config(),
            None,
        )
        .unwrap();
        assert_eq!(s.next(0).unwrap().kind, StreamStepKind::NeedTicketCall);
        let won: usize = (0..8)
            .map(|_| {
                let s = Arc::clone(&s);
                std::thread::spawn(move || s.ticket_request(b"c".to_vec(), 0).is_ok())
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| usize::from(h.join().unwrap()))
            .sum();
        assert_eq!(won, 1);
        assert_eq!(s.unstable_mints().unwrap(), 1, "one mint counted");
    }
}
