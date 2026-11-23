//! Revision 15 in the machine: read-only members cannot inject claims (§S4 rule 1), the term
//! step bound, and pass acknowledgement (§S5, G11). Every frame a reader can send, with
//! every claim shape, is delivered to members in every role; nothing about the holder may
//! change.
#![allow(clippy::unwrap_used)]
mod v06_session_support;
use colophon_core::v06::session::*;
use v06_session_support::*;

const WRITERS: [&str; 3] = ["a", "b", "c"];
const READER: &str = "r";

fn b(s: &str) -> Bytes {
    Bytes(s.as_bytes().to_vec())
}
fn id(s: &str) -> Id {
    Id::from_label(s)
}
fn frame(from: &str, body: Body) -> Frame {
    Frame { from: from.into(), to: None, retain: false, body }
}
fn input(f: Frame, writer: bool) -> Input {
    Input::Frame { frame: f, writer, key: None, n: None }
}
fn member(me: &str) -> Session {
    Session::new(me, WRITERS.contains(&me), Policy::default(), None).with_entitled(WRITERS)
}
fn sends(outs: &[Output]) -> Vec<Frame> {
    outs.iter()
        .filter_map(|o| match o {
            Output::Send { frame } => Some(frame.clone()),
            _ => None,
        })
        .collect()
}

/// `b` in each role: nobody holds; `a` holds and `b` listens; `b` holds.
fn roles() -> Vec<(&'static str, Session)> {
    let mut none = member("b");
    none.handle(Input::App { command: Command::Join { state: None } }, 0);
    let mut listener = none.clone();
    for body in [
        Body::Take { claim: Claim::new(1, 0, "a") },
        Body::State { claim: Claim::new(1, 0, "a"), seq: 0, snapshot: b("s") },
    ] {
        listener.handle(input(frame("a", body), true), 10);
    }
    assert_eq!(listener.holder(), Some("a"));
    let mut holder = none.clone();
    holder.handle(Input::App { command: Command::Take { state: Some(b("h")) } }, 10);
    assert!(holder.is_holder());
    vec![("no holder", none), ("listener", listener), ("holder", holder)]
}

/// Every kind, with claims naming the reader at small and extreme terms, a pass from the
/// reader naming `b`, and claims naming writers.
fn reader_bodies() -> Vec<Body> {
    let mut out = Vec::new();
    for term in [1, 2, 1 << 20, MAX_TERM - 1, MAX_TERM] {
        let mine = Claim::new(term, 0, READER);
        let to_b = Claim::passed(term.min(MAX_TERM - 1) + 1, "b", READER);
        let from_a = Claim::passed(term.min(MAX_TERM - 1) + 1, READER, "a");
        for c in [mine.clone(), from_a.clone(), Claim::new(term, 0, "a")] {
            out.extend([
                Body::Hello { fresh: id("f"), echo: vec![], seen: Some(Seen { claim: c.clone(), seq: Some(0) }), heard: None, lapsed: false },
                Body::Hello { fresh: id("g"), echo: vec![], seen: Some(Seen { claim: c.clone(), seq: None }), heard: None, lapsed: true },
                Body::State { claim: c.clone(), seq: 3, snapshot: b("evil") },
                Body::Beat { claim: c.clone(), seq: 3 },
                Body::Msg { claim: c.clone(), seq: 1, origin: READER.into(), id: id("m"), payload: b("evil") },
                Body::Ask { claim: c.clone() },
                Body::Decline { claim: c.clone() },
                Body::Take { claim: c.clone() },
                Body::Yielded { claim: c.clone(), seq: 3, snapshot: b("evil") },
                Body::Ack { yielded: Some(c.clone()), passed: None },
                Body::Ack { yielded: None, passed: Some(c.clone()) },
                Body::Bye { claim: Some(c.clone()), leaving: false },
                Body::Bye { claim: Some(c), leaving: true },
            ]);
        }
        out.push(Body::Pass { claim: mine.clone(), next: to_b, seq: 3, snapshot: b("evil") });
        out.push(Body::Pass { claim: Claim::new(term, 0, "a"), next: from_a, seq: 3, snapshot: b("evil") });
    }
    out.extend([
        Body::Hello { fresh: id("h"), echo: vec![], seen: None, heard: None, lapsed: false },
        Body::Submit { id: id("s"), payload: b("evil") },
        Body::Refuse { id: id("s"), reason: "no".into() },
        Body::Presence { payload: b("here") },
        Body::Ping { t: 1 },
        Body::Pong { t: 1, echo: 1, hold: 0 },
        Body::Bye { claim: None, leaving: false },
    ]);
    out
}

fn holder_events(outs: &[Output]) -> Vec<String> {
    outs.iter()
        .filter_map(|o| match o {
            Output::Event { event } => match event {
                Event::BecameHolder { .. }
                | Event::Yielded { .. }
                | Event::HolderChanged { .. }
                | Event::Displaced { .. }
                | Event::LatePass { .. }
                | Event::AskReceived { .. }
                | Event::Declined { .. }
                | Event::Message { .. }
                | Event::Snapshot { .. }
                | Event::Refused { .. } => Some(format!("{event:?}")),
                _ => None,
            },
            Output::Persist { .. } => Some(format!("{o:?}")),
            _ => None,
        })
        .collect()
}

/// HIGH finding of the first codec review: a reader's `hello` naming itself at 2^53 − 1 made
/// non-holders adopt it, after which nobody could take or renew.
#[test]
fn no_frame_from_a_reader_changes_who_holds() {
    let mut checked = 0;
    for (role, start) in roles() {
        for body in reader_bodies() {
            for writer_flag in [false, true] {
                let mut s = start.clone();
                let f = frame(READER, body.clone());
                let outs = s.handle(input(f.clone(), writer_flag), 20);
                let what = format!("{role}: {} (host writer flag {writer_flag})", show_body(&body));
                assert_eq!(s.accepted(), start.accepted(), "{what}");
                assert_eq!(s.holder(), start.holder(), "{what}");
                assert_eq!(s.is_holder(), start.is_holder(), "{what}");
                assert_eq!(s.state(), start.state(), "{what}");
                assert!(holder_events(&outs).is_empty(), "{what}: {:?}", holder_events(&outs));
                // Nothing it sends speaks under a claim it did not hold before.
                for out in sends(&outs) {
                    assert!(out.body.claim().is_none_or(|c| Some(c) == start.accepted()), "{what}: {}", show_body(&out.body));
                }
                // And it can still take afterwards, one term up.
                if role == "no holder" {
                    let outs = s.handle(Input::App { command: Command::Take { state: None } }, 30);
                    assert!(s.is_holder(), "{what}: {outs:?}");
                    assert_eq!(s.accepted().map(|c| c.term), Some(1));
                }
                checked += 1;
            }
        }
    }
    assert!(checked > 600, "{checked}");
}

#[test]
fn readers_still_listen_and_are_answered() {
    let (_, mut holder) = roles().pop().unwrap();
    holder.handle(Input::App { command: Command::Publish { id: id("p"), payload: b("one") } }, 20);
    // A reader that joins is sent the state, and its presence and pings are honoured.
    let outs = holder.handle(input(frame(READER, Body::Hello { fresh: id("x"), echo: vec![], seen: None, heard: None, lapsed: false }), false), 30);
    assert!(sends(&outs).iter().any(|f| matches!(&f.body, Body::State { snapshot, .. } if *snapshot == b("one")) && f.to.as_deref() == Some(READER)));
    // A reader reporting the holder's own claim and an older seq is sent the missing tail.
    let mine = holder.accepted().cloned().unwrap();
    let outs = holder.handle(input(frame(READER, Body::Hello { fresh: id("y"), echo: vec![], seen: Some(Seen { claim: mine, seq: Some(0) }), heard: None, lapsed: false }), false), 40);
    assert!(sends(&outs).iter().any(|f| matches!(&f.body, Body::Msg { seq: 1, .. })), "{outs:?}");
    let outs = holder.handle(input(frame(READER, Body::Presence { payload: b("Kitchen") }), false), 50);
    assert!(outs.iter().any(|o| matches!(o, Output::Event { event: Event::PresenceChanged { member, .. } } if member == READER)));
    let outs = holder.handle(input(frame(READER, Body::Ping { t: 5 }), false), 60);
    assert!(sends(&outs).iter().any(|f| matches!(f.body, Body::Pong { echo: 5, .. })));
}

#[test]
fn a_claim_more_than_2_pow_20_terms_up_is_ignored() {
    let step = MAX_TERM_STEP;
    let (_, listener) = roles().into_iter().nth(1).unwrap();
    // From the writer c: a take at accepted + 2^20 is accepted, one more is not.
    let mut s = listener.clone();
    s.handle(input(frame("c", Body::Take { claim: Claim::new(1 + step + 1, 0, "c") }), true), 20);
    assert_eq!(s.holder(), Some("a"), "beyond the step: ignored");
    s.handle(input(frame("c", Body::Take { claim: Claim::new(1 + step, 0, "c") }), true), 20);
    assert_eq!(s.accepted(), Some(&Claim::new(1 + step, 0, "c")));
    // A holder does not renew over a writer's hello naming a claim beyond the step.
    let (_, mut holder) = roles().pop().unwrap();
    let before = holder.accepted().cloned();
    holder.handle(input(frame("c", Body::Hello { fresh: id("z"), echo: vec![], seen: Some(Seen { claim: Claim::new(MAX_TERM, 0, "c"), seq: None }), heard: None, lapsed: false }), true), 20);
    assert_eq!(holder.accepted(), before.as_ref());
}

// ---------------------------------------------------------------------------------------
// Pass acknowledgement (§S5, revision 15).

fn pair() -> (Session, Session) {
    let mut a = member("a");
    let mut bb = member("b");
    a.handle(Input::App { command: Command::Join { state: None } }, 0);
    bb.handle(Input::App { command: Command::Join { state: None } }, 0);
    for f in sends(&a.handle(Input::App { command: Command::Take { state: Some(b("playing")) } }, 10)) {
        bb.handle(input(f, true), 10);
    }
    for f in sends(&bb.handle(Input::App { command: Command::Ask }, 20)) {
        a.handle(input(f, true), 20);
    }
    (a, bb)
}

#[test]
fn a_lost_pass_is_resent_on_any_frame_until_acknowledged() {
    let (mut a, mut bb) = pair();
    let pass = sends(&a.handle(Input::App { command: Command::Pass { to: "b".into(), snapshot: b("stopped") } }, 30));
    assert!(pass.iter().any(|f| matches!(f.body, Body::Pass { .. })));
    // The pass is lost. b takes on the ask timeout, under a lesser claim than the pass.
    let mut now = 30;
    let mut from_b = Vec::new();
    while !bb.is_holder() {
        now += 100;
        from_b.extend(sends(&bb.handle(Input::Tick, now)));
    }
    assert_eq!(bb.accepted(), Some(&Claim::new(2, 0, "b")));
    // The first frame a hears from b, within askTimeoutMs of the pass, draws no resend.
    let outs = a.handle(input(from_b[0].clone(), true), 1_000);
    assert!(!sends(&outs).iter().any(|f| matches!(f.body, Body::Pass { .. })));
    // A later frame does: any frame, at most once per askTimeoutMs.
    let resent: Vec<Frame> = from_b.iter().flat_map(|f| sends(&a.handle(input(f.clone(), true), 2_000))).filter(|f| matches!(f.body, Body::Pass { .. })).collect();
    assert_eq!(resent.len(), 1, "once per askTimeoutMs");
    // b reports it as a late pass, renews over it, and acknowledges.
    let outs = bb.handle(input(resent[0].clone(), true), 2_010);
    assert!(outs.iter().any(|o| matches!(o, Output::Event { event: Event::LatePass { snapshot, .. } } if *snapshot == b("stopped"))));
    let acks: Vec<Frame> = sends(&outs).into_iter().filter(|f| matches!(f.body, Body::Ack { passed: Some(_), .. })).collect();
    assert_eq!(acks.len(), 1);
    // The duplicate is acknowledged again but reported only once.
    let outs = bb.handle(input(resent[0].clone(), true), 2_020);
    assert!(!outs.iter().any(|o| matches!(o, Output::Event { event: Event::LatePass { .. } })));
    assert!(sends(&outs).iter().any(|f| matches!(f.body, Body::Ack { passed: Some(_), .. })));
    // After the ack, a never resends.
    a.handle(input(acks[0].clone(), true), 2_030);
    for (k, f) in from_b.iter().enumerate() {
        let outs = a.handle(input(f.clone(), true), 10_000 + 2_000 * k as u64);
        assert!(!sends(&outs).iter().any(|f| matches!(f.body, Body::Pass { .. })));
    }
}

#[test]
fn an_ack_from_another_member_does_not_stop_the_resends() {
    let (mut a, mut bb) = pair();
    let pass = sends(&a.handle(Input::App { command: Command::Pass { to: "b".into(), snapshot: b("stopped") } }, 30));
    let next = match &pass[0].body {
        Body::Pass { next, .. } => next.clone(),
        _ => unreachable!(),
    };
    a.handle(input(frame("c", Body::Ack { yielded: None, passed: Some(next.clone()) }), true), 40);
    let hello = sends(&bb.handle(Input::LinkDown, 50)).into_iter().chain(sends(&bb.handle(Input::LinkUp, 60))).find(|f| matches!(f.body, Body::Hello { .. })).unwrap();
    let outs = a.handle(input(hello, true), 5_000);
    assert!(sends(&outs).iter().any(|f| matches!(&f.body, Body::Pass { next: n, .. } if *n == next)));
    // When it arrives, b starts from exactly the passed snapshot and acknowledges.
    let p = sends(&outs).into_iter().find(|f| matches!(f.body, Body::Pass { .. })).unwrap();
    let outs = bb.handle(input(p, true), 5_010);
    assert!(bb.is_holder());
    assert_eq!(bb.state(), &b("stopped"));
    assert!(sends(&outs).iter().any(|f| matches!(&f.body, Body::Ack { passed: Some(n), .. } if *n == next)));
}
