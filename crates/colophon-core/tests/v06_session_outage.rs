//! `Input::Outage`, an outage reported after the fact at the processing clock, is exactly
//! `LinkDown` at `now - down_ms` followed (when ended) by `LinkUp` at `now`: the same outputs and
//! the same whole machine state, for a holder and a non-holder, below, at and above the holder
//! timeout, for an outage that has ended and one still under way, and when the link was already
//! down.
#![allow(clippy::unwrap_used)]
use colophon_core::v06::session::*;

const NOW: u64 = 100_000;

fn member(holder: bool) -> Session {
    let mut s = Session::new("a", true, Policy::default(), None).with_fresh_seed([1; 16]);
    s.handle(
        Input::Entitled {
            writers: vec!["a".into(), "b".into()],
        },
        0,
    );
    s.handle(
        Input::App {
            command: Command::Join { state: None },
        },
        0,
    );
    if holder {
        s.handle(
            Input::App {
                command: Command::Take {
                    state: Some(Bytes(b"s".to_vec())),
                },
            },
            10,
        );
        assert!(s.is_holder());
    }
    s
}

#[test]
fn an_ended_outage_is_a_down_then_an_up() {
    let timeout = Policy::default().holder_timeout_ms;
    for holder in [true, false] {
        for d in [timeout - 1, timeout, timeout + 1] {
            let start = member(holder);
            let mut a = start.clone();
            let mut b = start.clone();
            let mut outs_a = a.handle(Input::LinkDown, NOW - d);
            outs_a.extend(a.handle(Input::LinkUp, NOW));
            let outs_b = b.handle(
                Input::Outage {
                    down_ms: d,
                    ended: true,
                },
                NOW,
            );
            assert_eq!(outs_a, outs_b, "holder {holder}, {d} ms");
            assert_eq!(a, b, "holder {holder}, {d} ms: the same state");
            assert_eq!(
                b.view().gated,
                holder && d >= timeout,
                "holder {holder}, {d} ms"
            );
            assert_eq!(b.link_down_since(), None);
            assert!(b.link_is_up());
        }
    }
}

#[test]
fn an_outage_under_way_is_a_down_at_its_start() {
    let timeout = Policy::default().holder_timeout_ms;
    for holder in [true, false] {
        for d in [timeout - 1, timeout, timeout + 1] {
            let start = member(holder);
            let mut a = start.clone();
            let mut b = start.clone();
            assert!(a.handle(Input::LinkDown, NOW - d).is_empty());
            assert!(b
                .handle(
                    Input::Outage {
                        down_ms: d,
                        ended: false
                    },
                    NOW
                )
                .is_empty());
            assert_eq!(
                b.link_down_since(),
                Some(NOW - d),
                "the outage's true start"
            );
            assert!(!b.link_is_up());
            // The same from the next input on.
            let later = NOW + 5_000;
            let outs_a = a.handle(Input::LinkUp, later);
            let outs_b = b.handle(Input::LinkUp, later);
            assert_eq!(outs_a, outs_b, "holder {holder}, {d} ms");
            assert_eq!(a, b, "holder {holder}, {d} ms");
            assert_eq!(b.view().gated, holder && d + 5_000 >= timeout);
        }
    }
}

#[test]
fn an_outage_while_already_down_keeps_the_earlier_start() {
    let start = member(true);
    let mut a = start.clone();
    let mut b = start.clone();
    a.handle(Input::LinkDown, 50_000);
    b.handle(Input::LinkDown, 50_000);
    let mut outs_a = a.handle(Input::LinkDown, NOW - 1_000);
    outs_a.extend(a.handle(Input::LinkUp, NOW));
    let outs_b = b.handle(
        Input::Outage {
            down_ms: 1_000,
            ended: true,
        },
        NOW,
    );
    assert_eq!(outs_a, outs_b);
    assert_eq!(a, b);
    assert!(b.view().gated, "down since 50 s: lapsed");
}
