//! The stream client (`v05::engine::stream`, proposed 0.6 `docs/colophon-0.6-stream.md`) as
//! transcripts: ticket, hello, change, wake; resume after a drop; resync; a gap in frame
//! numbers; access ended; the backoff schedule; polling when the stream is refused or the home
//! is 0.5; and two engines with a simulated home, where one device's write reaches the other by
//! a stream wake with no poll timer. A frame is a hint only: a forged `change` makes the engine
//! accept nothing a poll would not.
#![allow(clippy::unwrap_used, clippy::too_many_arguments)]
#[path = "v05_engine_support/mod.rs"]
mod support;
use colophon_core::v05::engine::exchange::{Method, Response};
use colophon_core::v05::engine::stream::{
    Blocked, HomeStream, StreamConfig, StreamEvent, StreamStatus, StreamStep, CLOSE_IDLE,
    CLOSE_PROTOCOL,
};
use colophon_core::v05::engine::Engine;
use serde_json::{json, Value};
use support::*;

const NOW: i64 = T0 + 3 * HOUR;
const NS: &str = "notes";
const BASE: &str = "https://home.example";

fn ok_ticket(t: &str) -> Response {
    Response {
        status: 200,
        headers: vec![],
        body: json!({"ticket": t, "expires": 0, "path": "/stream"})
            .to_string()
            .into_bytes(),
    }
}
fn status(s: u16, body: Value) -> Response {
    Response {
        status: s,
        headers: vec![],
        body: body.to_string().into_bytes(),
    }
}
fn ticket(i: u8) -> String {
    format!("{:A>43}", i)
}
fn hello(n: u64, cursor: &str) -> String {
    json!({"type": "hello", "n": n, "protocol": "colophon/home-stream/6", "account": "a",
           "home": "h", "instance": "i", "cursor": cursor, "head": null, "notice": 0,
           "principal": "member:m", "expiresAt": null, "namespaces": [],
           "limits": {"pingMs": 20000, "idleMs": 60000, "resumeEntries": 1024}})
    .to_string()
}
fn change(n: u64, cursor: &str) -> String {
    json!({"type": "change", "n": n, "cursor": cursor,
           "entry": {"path": "ops/x.json", "size": 1, "sha256": "0".repeat(64)}})
    .to_string()
}

/// Drive a bare client to live with `hello` at `t`, returning the connect URL.
fn connect(s: &mut HomeStream, t: i64, i: u8, cursor: &str) -> String {
    let mut step = s.next(t);
    while step == StreamStep::Wake {
        step = s.next(t);
    }
    assert_eq!(step, StreamStep::NeedTicketCall);
    let req = s.ticket_request(b"signed call", t).unwrap();
    assert_eq!(req.method, Method::Post);
    assert_eq!(req.url, format!("{BASE}/stream/ticket"));
    assert!(req.body.is_empty());
    assert!(req
        .headers
        .iter()
        .any(|(k, v)| k == "Authorization" && v.starts_with("Colophon ")));
    assert!(s.on_ticket(Some(&ok_ticket(&ticket(i))), t).is_empty());
    let StreamStep::Connect { url } = s.next(t) else {
        panic!("connect")
    };
    s.on_open(t);
    let ev = s.on_frame(&hello(1, cursor), t);
    assert!(matches!(ev[0], StreamEvent::Connected { .. }), "{ev:?}");
    assert_eq!(s.status(), StreamStatus::Live);
    url
}

/// Run `next` until it asks for nothing more at `t`; the steps taken.
fn settle(s: &mut HomeStream, t: i64) -> Vec<StreamStep> {
    let mut out = Vec::new();
    for _ in 0..16 {
        let st = s.next(t);
        let stop = matches!(st, StreamStep::Sleep { .. } | StreamStep::Waiting);
        out.push(st);
        if stop {
            break;
        }
    }
    out
}

#[test]
fn ticket_hello_change_wakes_once_per_burst_and_persists_the_cursor() {
    let mut s = HomeStream::new("h", "https://home.example/", StreamConfig::default(), None);
    assert!(s.polling(), "polling until the stream is live");
    let url = connect(&mut s, 0, 1, "c.10");
    assert_eq!(
        url,
        format!("wss://home.example/stream?ticket={}", ticket(1))
    );
    assert!(!s.polling());
    assert_eq!(
        s.cursor(),
        Some("c.10"),
        "no replay follows: the hello's cursor"
    );
    // The first connection wakes a catch-up pass, after the coalescing window.
    assert!(matches!(
        s.next(100),
        StreamStep::Sleep { until: Some(250) }
    ));
    assert_eq!(s.next(250), StreamStep::Wake);
    assert!(matches!(s.next(251), StreamStep::Sleep { .. }));
    // A burst of changes is one wake.
    let mut cursors = Vec::new();
    for (i, n) in (2..7).enumerate() {
        for e in s.on_frame(&change(n, &format!("c.{}", 11 + i)), 1_000 + i as i64) {
            if let StreamEvent::Cursor(c) = e {
                cursors.push(c.unwrap());
            }
        }
    }
    assert_eq!(cursors, ["c.11", "c.12", "c.13", "c.14", "c.15"]);
    assert_eq!(
        settle(&mut s, 1_100),
        [StreamStep::Sleep { until: Some(1_250) }]
    );
    assert_eq!(s.next(1_250), StreamStep::Wake);
    assert!(matches!(s.next(1_251), StreamStep::Sleep { .. }));
    // A head or notice frame wakes too; route and session frames pass through and do not.
    s.on_frame(
        &json!({"type": "head", "n": 7, "home": "h", "seq": 9, "digest": "0".repeat(64)})
            .to_string(),
        2_000,
    );
    assert_eq!(s.next(2_250), StreamStep::Wake);
    let sess = r#"{"type":"session","n":8,"frame":{"account":"a","ciphertext":"AA==","signature":"AA=="}}"#;
    assert_eq!(
        s.on_frame(sess, 3_000),
        [StreamEvent::Session(sess.to_string())],
        "byte for byte"
    );
    let ev = s.on_frame(
        &json!({"type": "route", "n": 9, "id": "r", "change": "delete"}).to_string(),
        3_000,
    );
    assert!(matches!(ev[0], StreamEvent::Route(_)));
    // Unknown types and fields are ignored, but numbered.
    assert!(s
        .on_frame(
            &json!({"type": "future", "n": 10, "x": 1}).to_string(),
            3_000
        )
        .is_empty());
    assert!(matches!(s.next(3_500), StreamStep::Sleep { .. }), "no wake");
    let ev = s.on_frame(
        &json!({"type": "notice", "n": 11, "notice": 4, "object": "o", "kind": "transition", "deadline": 1})
            .to_string(),
        4_000,
    );
    assert!(matches!(ev[0], StreamEvent::Notice(_)));
    assert_eq!(s.next(4_250), StreamStep::Wake);
}

#[test]
fn a_dropped_stream_resumes_from_its_cursor_and_a_resync_wakes_a_poll() {
    let mut s = HomeStream::new("h", BASE, StreamConfig::default(), Some("c.10".into()));
    let url = connect(&mut s, 0, 1, "c.12");
    assert!(url.ends_with("&after=c.10"), "{url}");
    assert_eq!(
        s.cursor(),
        Some("c.10"),
        "a replay follows: not the hello's cursor yet"
    );
    // The replay: two changes.
    s.on_frame(&change(2, "c.11"), 0);
    s.on_frame(&change(3, "c.12"), 0);
    assert_eq!(s.cursor(), Some("c.12"));
    // The home drops us (slow consumer): back off, then resume from the last change handled.
    let ev = s.on_closed(Some(4013), 10);
    let StreamEvent::Down { retry_at } = ev[0] else {
        panic!("{ev:?}")
    };
    assert!((10 + 500..=10 + 1_000).contains(&retry_at), "{retry_at}");
    assert!(s.polling());
    let _ = settle(&mut s, 11); // the pending wake from the replay
    assert!(matches!(
        s.next(retry_at - 1),
        StreamStep::Sleep { .. } | StreamStep::Wake
    ));
    let url = connect(&mut s, retry_at, 2, "c.12");
    assert!(url.ends_with("&after=c.12"), "{url}");
    assert_eq!(s.attempts(), 1, "a hello alone does not reset the backoff");

    // `gone`: the cursor is forgotten and a pass is woken; `tooFar` keeps it and wakes.
    let t = retry_at + 10_000;
    let _ = settle(&mut s, t);
    let ev = s.on_frame(
        &json!({"type": "resync", "n": 2, "reason": "gone", "after": "c.12"}).to_string(),
        t,
    );
    assert_eq!(
        ev,
        [
            StreamEvent::Cursor(None),
            StreamEvent::Resync {
                reason: "gone".into()
            }
        ]
    );
    assert_eq!(s.next(t + 250), StreamStep::Wake);
    s.on_frame(&change(3, "d.1"), t + 300);
    assert_eq!(s.cursor(), Some("d.1"));
    let ev = s.on_frame(
        &json!({"type": "resync", "n": 4, "reason": "tooFar", "after": "d.1"}).to_string(),
        t + 300,
    );
    assert_eq!(
        ev,
        [StreamEvent::Resync {
            reason: "tooFar".into()
        }]
    );
    assert_eq!(s.cursor(), Some("d.1"));
}

#[test]
fn a_gap_in_frame_numbers_closes_and_resumes() {
    let mut s = HomeStream::new("h", BASE, StreamConfig::default(), None);
    connect(&mut s, 0, 1, "c.1");
    s.on_frame(&change(2, "c.2"), 0);
    // Frame 3 never came.
    let ev = s.on_frame(&change(4, "c.4"), 5);
    assert!(matches!(ev[0], StreamEvent::Violation(_)), "{ev:?}");
    assert_eq!(s.cursor(), Some("c.2"), "nothing past the gap is taken");
    let steps = settle(&mut s, 5);
    assert!(
        steps.contains(&StreamStep::Close {
            code: CLOSE_PROTOCOL
        }),
        "{steps:?}"
    );
    // Further frames on the closing socket are ignored.
    assert!(s.on_frame(&change(5, "c.5"), 6).is_empty());
    let ev = s.on_closed(Some(CLOSE_PROTOCOL), 7);
    let StreamEvent::Down { retry_at } = ev[0] else {
        panic!("{ev:?}")
    };
    let url = connect(&mut s, retry_at, 2, "c.5");
    assert!(url.ends_with("&after=c.2"), "{url}");
    // A frame without `n`, a second hello, a first frame that is not hello: the same.
    for bad in [
        json!({"type": "change", "cursor": "x"}).to_string(),
        hello(2, "c"),
        "not json".to_string(),
    ] {
        let mut s = HomeStream::new("h", BASE, StreamConfig::default(), None);
        connect(&mut s, 0, 1, "c.1");
        let ev = s.on_frame(&bad, 1);
        assert!(matches!(ev[0], StreamEvent::Violation(_)), "{bad}: {ev:?}");
    }
    let mut s = HomeStream::new("h", BASE, StreamConfig::default(), None);
    assert_eq!(s.next(0), StreamStep::NeedTicketCall);
    s.ticket_request(b"c", 0).unwrap();
    s.on_ticket(Some(&ok_ticket(&ticket(1))), 0);
    let _ = s.next(0);
    s.on_open(0);
    let ev = s.on_frame(&change(1, "c.1"), 0);
    assert!(matches!(ev[0], StreamEvent::Violation(_)), "{ev:?}");
}

#[test]
fn access_ended_and_released_stop_reconnecting_until_the_history_changes() {
    for (code, why) in [(1008, Blocked::AccessEnded), (1001, Blocked::Released)] {
        let mut s = HomeStream::new("h", BASE, StreamConfig::default(), None);
        s.on_history(7);
        connect(&mut s, 0, 1, "c.1");
        let _ = settle(&mut s, 1_000);
        if code == 1001 {
            // Released is the home's `bye` with `resume: false`, then 1001.
            s.on_frame(
                &json!({"type": "bye", "n": 2, "reason": "released", "resume": false}).to_string(),
                1_000,
            );
        }
        let ev = s.on_closed(Some(code), 1_000);
        assert_eq!(ev, [StreamEvent::Blocked(why.clone())]);
        assert_eq!(s.status(), StreamStatus::Blocked(why));
        assert!(s.polling());
        assert_eq!(s.next(10_000_000), StreamStep::Sleep { until: None });
        s.on_history(7);
        assert_eq!(s.next(20_000_000), StreamStep::Sleep { until: None });
        s.on_history(8);
        assert_eq!(s.next(20_000_000), StreamStep::NeedTicketCall);
    }
    // A bare 1001 (a proxy going away) is a drop: the client resumes.
    let mut s = HomeStream::new("h", BASE, StreamConfig::default(), None);
    connect(&mut s, 0, 1, "c.1");
    assert!(matches!(
        s.on_closed(Some(1001), 5)[0],
        StreamEvent::Down { .. }
    ));
    // `bye` released, then any close: blocked.
    let mut s = HomeStream::new("h", BASE, StreamConfig::default(), None);
    connect(&mut s, 0, 1, "c.1");
    s.on_frame(
        &json!({"type": "bye", "n": 2, "reason": "released", "resume": false}).to_string(),
        5,
    );
    assert_eq!(
        s.on_closed(Some(1000), 6),
        [StreamEvent::Blocked(Blocked::Released)]
    );
    // An upgrade refused as revoked: blocked as well.
    let mut s = HomeStream::new("h", BASE, StreamConfig::default(), None);
    assert_eq!(s.next(0), StreamStep::NeedTicketCall);
    s.ticket_request(b"c", 0).unwrap();
    s.on_ticket(Some(&ok_ticket(&ticket(1))), 0);
    let _ = s.next(0);
    let ev = s.on_refused(&status(403, json!({"result": "refused:revoked"})), 1);
    assert_eq!(ev, [StreamEvent::Blocked(Blocked::AccessEnded)]);
}

#[test]
fn a_restart_comes_back_after_retry_ms_and_idle_connections_are_pinged_then_closed() {
    let mut s = HomeStream::new("h", BASE, StreamConfig::default(), None);
    connect(&mut s, 0, 1, "c.1");
    let _ = settle(&mut s, 300);
    s.on_frame(
        &json!({"type": "bye", "n": 2, "reason": "restart", "resume": true, "retryMs": 5000})
            .to_string(),
        1_000,
    );
    let ev = s.on_closed(Some(1012), 1_000);
    let StreamEvent::Down { retry_at } = ev[0] else {
        panic!("{ev:?}")
    };
    assert!((6_000..7_000).contains(&retry_at), "{retry_at}");
    assert_eq!(s.attempts(), 0, "a restart is not a failure");

    let mut s = HomeStream::new("h", BASE, StreamConfig::default(), None);
    connect(&mut s, 0, 1, "c.1");
    let _ = settle(&mut s, 300);
    // Nothing heard for pingMs: a ping; its pong keeps the connection.
    let StreamStep::Send { text } = s.next(20_000) else {
        panic!()
    };
    assert_eq!(
        serde_json::from_str::<Value>(&text).unwrap()["type"],
        "ping"
    );
    assert!(matches!(s.next(20_001), StreamStep::Sleep { .. }));
    s.on_frame(
        &json!({"type": "pong", "n": 2, "t": 20_000}).to_string(),
        20_050,
    );
    assert!(matches!(
        s.next(60_000),
        StreamStep::Sleep { .. } | StreamStep::Send { .. }
    ));
    // Then silence past idleMs: the client closes and resumes.
    let mut closed = false;
    for t in (60_000..200_000).step_by(5_000) {
        match s.next(t) {
            StreamStep::Close { code } => {
                assert_eq!(code, CLOSE_IDLE);
                assert!(t > 20_050 + 60_000);
                closed = true;
                break;
            }
            StreamStep::Send { .. } | StreamStep::Sleep { .. } | StreamStep::Wake => {}
            other => panic!("{other:?}"),
        }
    }
    assert!(closed);
    assert!(matches!(
        s.on_closed(None, 200_000)[0],
        StreamEvent::Down { .. }
    ));
}

#[test]
fn the_backoff_is_jittered_exponential_capped_seeded_and_reset_by_hello() {
    let schedule = |seed: u64| {
        let cfg = StreamConfig {
            seed,
            mint_budget: 100,
            ..StreamConfig::default()
        };
        let mut s = HomeStream::new("h", BASE, cfg, None);
        let mut t = 0;
        let mut delays = Vec::new();
        for _ in 0..10 {
            assert_eq!(s.next(t), StreamStep::NeedTicketCall);
            s.ticket_request(b"c", t).unwrap();
            let ev = s.on_ticket(None, t);
            let StreamEvent::Down { retry_at } = ev[0] else {
                panic!("{ev:?}")
            };
            delays.push(retry_at - t);
            assert!(matches!(s.next(retry_at - 1), StreamStep::Sleep { .. }));
            t = retry_at;
        }
        (delays, s, t)
    };
    let (a, mut s, t) = schedule(1);
    let (b, _, _) = schedule(1);
    let (c, _, _) = schedule(2);
    assert_eq!(a, b, "the same seed, the same schedule");
    assert_ne!(a, c, "another seed, another jitter");
    println!("backoff (seed 1): {a:?}");
    for (i, d) in a.iter().enumerate() {
        let full = (1_000_i64 << i).min(60_000);
        assert!(
            (full / 2..=full).contains(d),
            "attempt {i}: {d} not in [{}, {full}]",
            full / 2
        );
    }
    // Refusals the home rate-limits: at least its Retry-After.
    assert_eq!(s.next(t), StreamStep::NeedTicketCall);
    s.ticket_request(b"c", 0).unwrap();
    let r = Response {
        status: 429,
        headers: vec![("Retry-After".into(), "120".into())],
        body: br#"{"result":"refused:window"}"#.to_vec(),
    };
    let StreamEvent::Down { retry_at } = s.on_ticket(Some(&r), t)[0] else {
        panic!()
    };
    assert!(retry_at - t >= 120_000);
    // A connection that stays live `stable_ms` resets it; a hello alone does not.
    connect(&mut s, retry_at, 1, "c");
    assert!(s.attempts() > 0);
    let mut now = retry_at;
    for (i, step) in (0..14).map(|i| (i, 5_000)) {
        now += step;
        let _ = settle(&mut s, now);
        s.on_frame(&json!({"type": "pong", "n": 2 + i}).to_string(), now);
    }
    assert_eq!(s.attempts(), 0, "stable for 70 s");
    let StreamEvent::Down { retry_at: r2 } = s.on_closed(Some(1011), now)[0] else {
        panic!()
    };
    assert!(r2 - now <= 1_000);
}

#[test]
fn a_refused_or_unsupported_stream_falls_back_to_polling() {
    for (r, why) in [
        (status(404, json!({})), Blocked::Unsupported),
        (status(405, json!({})), Blocked::Unsupported),
        (
            status(403, json!({"result": "refused:outOfScope"})),
            Blocked::Refused("refused:outOfScope".into()),
        ),
        (status(401, json!({})), Blocked::Refused("401".into())),
    ] {
        let mut s = HomeStream::new("h", BASE, StreamConfig::default(), None);
        assert_eq!(s.next(0), StreamStep::NeedTicketCall);
        s.ticket_request(b"c", 0).unwrap();
        assert_eq!(s.on_ticket(Some(&r), 0), [StreamEvent::Blocked(why)]);
        assert!(s.polling());
        assert_eq!(s.next(1_000_000), StreamStep::Sleep { until: None });
    }
    // A hello for another protocol: closed, unsupported.
    let mut s = HomeStream::new("h", BASE, StreamConfig::default(), None);
    assert_eq!(s.next(0), StreamStep::NeedTicketCall);
    s.ticket_request(b"c", 0).unwrap();
    s.on_ticket(Some(&ok_ticket(&ticket(1))), 0);
    let _ = s.next(0);
    s.on_open(0);
    let other = hello(1, "c").replace("home-stream/6", "home-stream/7");
    assert!(matches!(
        s.on_frame(&other, 0)[0],
        StreamEvent::Violation(_)
    ));
    assert_eq!(
        s.next(0),
        StreamStep::Close {
            code: CLOSE_PROTOCOL
        }
    );
    assert_eq!(
        s.on_closed(Some(CLOSE_PROTOCOL), 1),
        [StreamEvent::Blocked(Blocked::Unsupported)]
    );
    // A ticket answer that names another path, or no valid ticket: not presented.
    let mut s = HomeStream::new("h", BASE, StreamConfig::default(), None);
    assert_eq!(s.next(0), StreamStep::NeedTicketCall);
    s.ticket_request(b"c", 0).unwrap();
    let r = status(200, json!({"ticket": ticket(1), "path": "/elsewhere"}));
    assert!(matches!(
        s.on_ticket(Some(&r), 0)[0],
        StreamEvent::Violation(_)
    ));
    assert!(matches!(s.status(), StreamStatus::Backoff(_)));
    // A ticket too old to present safely is minted again.
    let mut s = HomeStream::new("h", BASE, StreamConfig::default(), None);
    assert_eq!(s.next(0), StreamStep::NeedTicketCall);
    s.ticket_request(b"c", 0).unwrap();
    s.on_ticket(Some(&ok_ticket(&ticket(1))), 0);
    assert_eq!(s.next(25_000), StreamStep::NeedTicketCall);
}

// ---------------------------------------------------------------------------------------------
// With engines and a simulated home.

struct World {
    s: Setup,
    host: Host,
    a: Engine<MemSource>,
    a_src: MemSource,
    b: Engine<MemSource>,
    b_src: MemSource,
    b_id: String,
}
fn world() -> World {
    let (mut s, ids) = setup(NS, &[("A", 31, "write"), ("B", 32, "write")]);
    let host = std::mem::replace(&mut s.f.host, Host::new());
    let (a_src, b_src) = (device_source(&s), device_source(&s));
    let a = member_engine(&s.f, &host, &a_src, &ids[0], NOW);
    let b = member_engine(&s.f, &host, &b_src, &ids[1], NOW);
    s.sim.require_calls = true;
    World {
        s,
        host,
        a,
        a_src,
        b,
        b_src,
        b_id: ids[1].clone(),
    }
}
fn records(e: &Engine<MemSource>) -> usize {
    match e.view(NS).unwrap() {
        colophon_core::model::Outcome::Success { value, .. } => value.admitted.len(),
        colophon_core::model::Outcome::Failure { reason, .. } => panic!("{reason}"),
    }
}

/// Drive `stream` (B's) until it sleeps, waits or wakes, doing what it asks against `sim`: the
/// ticket through B's engine (a real `colophon.home.stream` call, judged by the core), the
/// connection through the simulated home. Returns the open connection and whether it woke.
fn drive(
    stream: &mut HomeStream,
    e: &mut Engine<MemSource>,
    me: &str,
    host: &mut Host,
    sim: &mut SimHome,
    conn: &mut Option<SimConn>,
    now: i64,
) -> bool {
    for _ in 0..64 {
        match stream.next(now) {
            StreamStep::Wake => return true,
            StreamStep::Sleep { .. } | StreamStep::Waiting => return false,
            StreamStep::NeedTicketCall => {
                let key = host.ids[me].public().signing;
                // A call needs a fresh head of the home: a device that has not run a pass yet
                // cannot build one, and the stream backs off (the host polls meanwhile).
                let action = match e.stream_begin_call(stream.home(), &key, host.fresh()) {
                    Ok(a) => a,
                    Err(_) => {
                        stream.ticket_call_failed(now);
                        return false;
                    }
                };
                let sigs = host.sign(action.steps());
                let call = match e.finish_write(action, sigs) {
                    Ok(w) => w.artifact.unwrap(),
                    Err(_) => {
                        stream.ticket_call_failed(now);
                        return false;
                    }
                };
                let req = stream.ticket_request(&call, now).unwrap();
                let r = sim.call(host, &req, now);
                stream.on_ticket(Some(&r), now);
            }
            StreamStep::Connect { url } => match sim.stream_connect(&url, now) {
                Ok((c, frames)) => {
                    stream.on_open(now);
                    for f in frames {
                        stream.on_frame(&f, now);
                    }
                    *conn = Some(c);
                }
                Err(r) => {
                    stream.on_refused(&r, now);
                }
            },
            StreamStep::Send { .. } => {}
            StreamStep::Close { .. } => {
                *conn = None;
                stream.on_closed(None, now);
            }
        }
    }
    panic!("the stream did not settle");
}

#[test]
fn a_write_on_one_device_reaches_the_other_by_a_stream_wake_with_no_poll_timer() {
    let mut w = world();
    let home = w.s.home.clone();
    // Both devices catch up once (the app's launch pass).
    let f = sync_pass(&mut w.a, &w.a_src, &home, &mut w.s.sim, &w.host, NOW);
    assert!(f.is_empty(), "{f:?}");
    let f = sync_pass(&mut w.b, &w.b_src, &home, &mut w.s.sim, &w.host, NOW);
    assert!(f.is_empty(), "{f:?}");
    let base = records(&w.b);

    // B opens its stream.
    let mut stream =
        w.b.stream_client(&home, StreamConfig::default(), None)
            .unwrap();
    let mut conn = None;
    let mut host = std::mem::replace(&mut w.host, Host::new());
    let b_id = w.b_id.clone();
    let mut t = NOW + 1_000;
    let mint_before = w.s.sim.minted;
    drive(
        &mut stream,
        &mut w.b,
        &b_id,
        &mut host,
        &mut w.s.sim,
        &mut conn,
        t,
    );
    assert_eq!(w.s.sim.minted, mint_before + 1, "one ticket");
    assert_eq!(stream.status(), StreamStatus::Live);
    // The first connection's catch-up wake (B is current: the pass moves nothing).
    t += 300;
    assert!(drive(
        &mut stream,
        &mut w.b,
        &b_id,
        &mut host,
        &mut w.s.sim,
        &mut conn,
        t
    ));
    let f = sync_pass(&mut w.b, &w.b_src, &home, &mut w.s.sim, &host, t);
    assert!(f.is_empty(), "{f:?}");

    // A writes one record and pushes it.
    t += 5_000;
    engine_write(
        &mut w.a,
        &mut host,
        &w.a_src,
        NS,
        "createNotebook",
        json!({"id": "n1", "title": "Pushed"}),
    );
    let f = sync_pass(&mut w.a, &w.a_src, &home, &mut w.s.sim, &host, t);
    assert!(f.is_empty(), "{f:?}");

    // The home's stream tells B; B wakes after the coalescing window and runs one pass.
    let frames = w.s.sim.stream_pump(conn.as_mut().unwrap());
    assert!(!frames.is_empty());
    for fr in &frames {
        stream.on_frame(fr, t);
    }
    assert!(!drive(
        &mut stream,
        &mut w.b,
        &b_id,
        &mut host,
        &mut w.s.sim,
        &mut conn,
        t
    ));
    t += 250;
    assert!(drive(
        &mut stream,
        &mut w.b,
        &b_id,
        &mut host,
        &mut w.s.sim,
        &mut conn,
        t
    ));
    let mark = w.s.sim.requests.len();
    let f = sync_pass(&mut w.b, &w.b_src, &home, &mut w.s.sim, &host, t);
    assert!(f.is_empty(), "{f:?}");
    assert_eq!(records(&w.b), base + 1, "A's write reached B");
    let trips = &w.s.sim.requests[mark..];
    println!(
        "single-record update by stream wake: {} round trips {trips:?}",
        trips.len()
    );
    assert!(trips.iter().any(|r| r.starts_with("Get /records/ops/")));
    // After the pass nothing more is due.
    assert!(!drive(
        &mut stream,
        &mut w.b,
        &b_id,
        &mut host,
        &mut w.s.sim,
        &mut conn,
        t + 1
    ));
    w.host = host;
}

#[test]
fn a_stream_to_a_05_home_is_unsupported_and_the_device_keeps_polling() {
    let mut w = world();
    let home = w.s.home.clone();
    w.s.sim.stream = false;
    let mut stream =
        w.b.stream_client(&home, StreamConfig::default(), None)
            .unwrap();
    let mut conn = None;
    let mut host = std::mem::replace(&mut w.host, Host::new());
    let b_id = w.b_id.clone();
    // Before any pass the device holds no fresh head of the home: no call, a backoff.
    drive(
        &mut stream,
        &mut w.b,
        &b_id,
        &mut host,
        &mut w.s.sim,
        &mut conn,
        NOW,
    );
    let StreamStatus::Backoff(at) = stream.status() else {
        panic!("{:?}", stream.status())
    };
    let f = sync_pass(&mut w.b, &w.b_src, &home, &mut w.s.sim, &host, NOW);
    assert!(f.is_empty(), "{f:?}");
    drive(
        &mut stream,
        &mut w.b,
        &b_id,
        &mut host,
        &mut w.s.sim,
        &mut conn,
        at,
    );
    assert_eq!(stream.status(), StreamStatus::Blocked(Blocked::Unsupported));
    assert!(stream.polling());
    assert!(conn.is_none());
    // Polling still works, unchanged.
    let f = sync_pass(&mut w.b, &w.b_src, &home, &mut w.s.sim, &host, at + 60_000);
    assert!(f.is_empty(), "{f:?}");
    w.host = host;
}

#[test]
fn a_forged_change_frame_makes_the_engine_accept_nothing_a_poll_would_not() {
    let mut w = world();
    let home = w.s.home.clone();
    let mut host = std::mem::replace(&mut w.host, Host::new());
    // A writes two records; the home holds them.
    for i in 0..2 {
        engine_write(
            &mut w.a,
            &mut host,
            &w.a_src,
            NS,
            "createNotebook",
            json!({"id": format!("n{i}"), "title": "Real"}),
        );
    }
    let f = sync_pass(&mut w.a, &w.a_src, &home, &mut w.s.sim, &host, NOW);
    assert!(f.is_empty(), "{f:?}");
    // A control device that only polls.
    let c_src = device_source(&w.s);
    let mut c = member_engine(&w.s.f, &host, &c_src, &w.b_id, NOW);
    let f = sync_pass(&mut c, &c_src, &home, &mut w.s.sim, &host, NOW);
    assert!(f.is_empty(), "{f:?}");

    // B's stream receives forged frames: a change naming a record that does not exist, one
    // naming a real path with another digest, a head ahead of the history. Each is only a wake.
    let mut stream = HomeStream::new(&home, BASE, StreamConfig::default(), None);
    connect(&mut stream, 0, 1, "0");
    let real =
        w.s.sim
            .files
            .keys()
            .find(|p| p.starts_with("ops/"))
            .unwrap()
            .clone();
    let forged = [
        json!({"type": "change", "n": 2, "cursor": "999999",
               "entry": {"path": "ops/forged/notes/000000000001-x.json", "size": 10, "sha256": "ab".repeat(32)}}),
        json!({"type": "change", "n": 3, "cursor": "1000000",
               "entry": {"path": real, "size": 10, "sha256": "cd".repeat(32)}}),
        json!({"type": "head", "n": 4, "home": home, "seq": 999, "digest": "ef".repeat(32)}),
    ];
    let mut events = Vec::new();
    for fr in &forged {
        events.extend(stream.on_frame(&fr.to_string(), 0));
    }
    // What the stream hands the host is a cursor and a wake: never an entry, a path or bytes.
    assert!(
        events.iter().all(|e| matches!(e, StreamEvent::Cursor(_))),
        "{events:?}"
    );
    let _ = settle(&mut stream, 100);
    assert_eq!(stream.next(250), StreamStep::Wake);
    let mark = w.s.sim.requests.len();
    let f = sync_pass(&mut w.b, &w.b_src, &home, &mut w.s.sim, &host, NOW + 1_000);
    assert!(f.is_empty(), "{f:?}");
    // Exactly what the poll accepted: the same head, records and stored paths; no request for
    // a forged path.
    assert_eq!(w.b.account().head(), c.account().head());
    assert_eq!(records(&w.b), records(&c));
    assert_eq!(records(&w.b), 2);
    let ours: Vec<String> = w.b_src.listing();
    assert_eq!(ours, c_src.listing());
    assert!(!w.s.sim.requests[mark..]
        .iter()
        .any(|r| r.contains("forged")));
    w.host = host;
}

// ---------------------------------------------------------------------------------------------
// Review fixes: a home cannot make the device sign without bound, tickets never reach `Debug`,
// and a live but silent stream still syncs.

#[test]
fn a_home_that_says_hello_and_closes_at_once_cannot_make_the_device_sign_without_bound() {
    let cfg = StreamConfig::default();
    let (budget, window) = (cfg.mint_budget as usize, cfg.mint_window_ms);
    let mut s = HomeStream::new("h", BASE, cfg, None);
    s.on_history(5);
    let mut t = 0_i64;
    let mut mints: Vec<i64> = Vec::new();
    let mut throttled = false;
    let end = 3 * 3_600_000;
    let mut i = 0u8;
    while t < end {
        match s.next(t) {
            StreamStep::NeedTicketCall => {
                mints.push(t);
                s.ticket_request(b"signed", t).unwrap();
                i = i.wrapping_add(1);
                s.on_ticket(Some(&ok_ticket(&ticket(i))), t);
                let StreamStep::Connect { .. } = s.next(t) else {
                    panic!()
                };
                s.on_open(t);
                s.on_frame(&hello(1, "c"), t);
                // ...and the home closes at once.
                s.on_closed(Some(1000), t);
            }
            StreamStep::Sleep { until: Some(u) } => {
                if matches!(s.status(), StreamStatus::Throttled(_)) {
                    throttled = true;
                    assert!(s.polling(), "a throttled stream keeps the poll timer");
                }
                t = u.max(t + 1);
            }
            StreamStep::Wake => {}
            other => panic!("{other:?}"),
        }
    }
    assert!(throttled, "the budget was reached");
    // Never more than the budget in any window, whatever the home does.
    for (k, m) in mints.iter().enumerate() {
        let in_window = mints[k..].iter().take_while(|x| **x - m < window).count();
        assert!(
            in_window <= budget,
            "{in_window} mints within a window from {m}"
        );
    }
    let per_hour = mints.len() as f64 / 3.0;
    println!(
        "hello/close loop: {} mints in 3 h ({per_hour:.0}/h), attempts {}",
        mints.len(),
        s.attempts()
    );
    assert!(mints.len() <= budget * (end / window + 1) as usize);
    assert!(
        s.attempts() >= 8,
        "hello does not reset the backoff: {}",
        s.attempts()
    );
    // A changed history lifts the throttle (a new standing); the same one does not.
    let mut s2 = s.clone();
    s2.on_history(5);
    s2.on_history(6);
    let st = s2.next(t);
    assert!(
        matches!(st, StreamStep::NeedTicketCall | StreamStep::Sleep { .. }),
        "{st:?}"
    );
}

#[test]
fn a_ticket_never_appears_in_debug_output() {
    let mut s = HomeStream::new("h", BASE, StreamConfig::default(), Some("c.1".into()));
    assert_eq!(s.next(0), StreamStep::NeedTicketCall);
    s.ticket_request(b"signed", 0).unwrap();
    let secret = ticket(7);
    s.on_ticket(Some(&ok_ticket(&secret)), 0);
    assert!(!format!("{s:?}").contains(&secret), "{s:?}");
    let step = s.next(0);
    let StreamStep::Connect { url } = &step else {
        panic!()
    };
    assert!(
        url.contains(&secret),
        "the host still gets the URL it must open"
    );
    let shown = format!("{step:?} {step:#?}");
    assert!(!shown.contains(&secret), "{shown}");
    assert!(
        shown.contains("ticket=<redacted>") && shown.contains("after=c.1"),
        "{shown}"
    );
    assert!(!format!("{s:?}").contains(&secret));
    assert!(!colophon_core::v05::engine::stream::redact_url(url).contains(&secret));
}

#[test]
fn a_live_stream_that_only_sends_pongs_still_wakes_a_pass_every_safety_interval() {
    let mut s = HomeStream::new("h", BASE, StreamConfig::default(), None);
    let safety = s.config().safety_poll_ms;
    connect(&mut s, 0, 1, "c.1");
    let mut wakes = Vec::new();
    let mut n = 2;
    let mut t = 0;
    while t < 10 * 60_000 {
        t += 5_000;
        // The home answers every ping and sends frames nobody wakes for.
        loop {
            match s.next(t) {
                StreamStep::Wake => wakes.push(t),
                StreamStep::Send { .. } => {
                    s.on_frame(&json!({"type": "pong", "n": n}).to_string(), t);
                    n += 1;
                }
                StreamStep::Sleep { until } => {
                    assert!(until.is_some_and(|u| u <= wakes.last().copied().unwrap_or(0) + safety));
                    break;
                }
                other => panic!("{other:?}"),
            }
        }
        s.on_frame(&json!({"type": "future", "n": n}).to_string(), t);
        n += 1;
        assert!(!s.polling(), "live");
    }
    assert!(wakes.len() >= 9, "{wakes:?}");
    for w in wakes.windows(2) {
        assert!(w[1] - w[0] <= safety + 5_000, "{wakes:?}");
    }
}

#[test]
fn the_engine_lowers_the_safety_poll_to_the_accounts_recovery_rule() {
    let w = world();
    let home = w.s.home.clone();
    let cfg = StreamConfig {
        safety_poll_ms: 24 * 3_600_000,
        ..StreamConfig::default()
    };
    let s = w.b.stream_client(&home, cfg, None).unwrap();
    // The fixture's recoveryDelay is 3,600 s: at least every 600 s (§17.5).
    assert_eq!(s.config().safety_poll_ms, 600_000);
    let s =
        w.b.stream_client(&home, StreamConfig::default(), None)
            .unwrap();
    assert_eq!(
        s.config().safety_poll_ms,
        60_000,
        "a shorter interval is kept"
    );
}

// ---------------------------------------------------------------------------------------------
// Second review: the circuit breaker, clock rollback and extreme times, request redaction.

/// Drive `s` from `t` to `end` against a home that answers every ticket and says `hello`; a
/// connection is held (with pongs) for as long as `keep(mint index)` says, and closed at once
/// when it says `None`. Returns the mint times and whether the stream was ever suspended.
fn hostile_run(
    s: &mut HomeStream,
    mut t: i64,
    end: i64,
    keep: &dyn Fn(usize) -> Option<i64>,
) -> (Vec<i64>, bool) {
    let mut mints = Vec::new();
    let mut suspended = false;
    while t < end {
        if matches!(s.status(), StreamStatus::Suspended(_)) {
            suspended = true;
        }
        match s.next(t) {
            StreamStep::NeedTicketCall => {
                let k = mints.len();
                mints.push(t);
                s.ticket_request(b"signed", t).unwrap();
                s.on_ticket(Some(&ok_ticket(&ticket((k % 200) as u8))), t);
                let StreamStep::Connect { .. } = s.next(t) else {
                    panic!()
                };
                s.on_open(t);
                s.on_frame(&hello(1, "c"), t);
                if let Some(hold) = keep(k) {
                    let mut n = 2;
                    let until = t + hold;
                    while t < until {
                        t += 5_000;
                        while let StreamStep::Send { .. } | StreamStep::Wake = s.next(t) {}
                        s.on_frame(&json!({"type": "pong", "n": n}).to_string(), t);
                        n += 1;
                    }
                }
                s.on_closed(Some(1000), t);
            }
            StreamStep::Sleep { until: Some(u) } => t = u.max(t + 1),
            StreamStep::Wake => {}
            other => panic!("{other:?}"),
        }
    }
    (mints, suspended)
}

const DAY: i64 = 24 * 3_600_000;

#[test]
fn a_day_of_hello_then_close_mints_a_bounded_total_then_suspends() {
    let cfg = StreamConfig::default();
    let bound = cfg.suspend_after as i64 * (DAY / cfg.suspend_ms + 1);
    let mut s = HomeStream::new("h", BASE, cfg, None);
    s.on_history(5);
    let (mints, suspended) = hostile_run(&mut s, 0, DAY, &|_| None);
    println!("24 h hello/close loop: {} mints", mints.len());
    assert!(suspended);
    assert!(s.polling());
    // Each 6-hour cool-off allows one more run of 16: four runs in a day.
    assert_eq!(mints.len(), 64);
    assert!(mints.len() as i64 <= bound);
}

#[test]
fn a_suspended_stream_recovers_by_history_retry_now_or_cool_off() {
    let mut s = HomeStream::new("h", BASE, StreamConfig::default(), None);
    s.on_history(5);
    let (mints, _) = hostile_run(&mut s, 0, 3 * 3_600_000, &|_| None);
    assert_eq!(mints.len(), 16);
    let StreamStatus::Suspended(until) = s.status() else {
        panic!("{:?}", s.status())
    };
    // The run's clock ended at 3 h (time stays monotonic here).
    let t = 3 * 3_600_000;
    assert!(until >= *mints.last().unwrap() + 6 * 3_600_000 && until > t);
    assert!(matches!(s.next(t), StreamStep::Sleep { until: Some(u) } if u == until));
    // (a) The verified history changed.
    let mut a = s.clone();
    a.on_history(5);
    assert!(
        matches!(a.next(t), StreamStep::Sleep { .. }),
        "the same history does not"
    );
    a.on_history(6);
    assert_eq!(a.next(t), StreamStep::NeedTicketCall);
    // (b) The host's explicit retry.
    let mut b = s.clone();
    b.retry_now();
    assert_eq!(b.next(t), StreamStep::NeedTicketCall);
    assert_eq!(b.unstable_mints(), 0);
    // (c) The cool-off.
    let mut c = s.clone();
    assert!(matches!(c.next(until - 1), StreamStep::Sleep { .. }));
    assert_eq!(c.next(until), StreamStep::NeedTicketCall);
}

/// The largest number of mints within any `window` of `mints`.
fn densest(mints: &[i64], window: i64) -> usize {
    (0..mints.len())
        .map(|k| {
            mints[k..]
                .iter()
                .take_while(|x| **x - mints[k] < window)
                .count()
        })
        .max()
        .unwrap_or(0)
}

#[test]
fn a_home_that_holds_one_connection_in_four_cannot_sign_past_the_daily_budget() {
    for (label, hold) in [("60 s", 61_000), ("20 min", 20 * 60_000)] {
        let cfg = StreamConfig::default();
        let (budget, window, day) = (
            cfg.mint_budget as usize,
            cfg.mint_window_ms,
            cfg.max_mints_per_day as usize,
        );
        let mut s = HomeStream::new("h", BASE, cfg, None);
        s.on_history(5);
        let (mints, suspended) = hostile_run(&mut s, 0, 7 * DAY, &|k| (k % 4 == 3).then_some(hold));
        let first_day = mints.iter().filter(|m| **m < DAY).count();
        println!(
            "hold {label} every 4th: {first_day} mints on day 1, {} in 7 days",
            mints.len()
        );
        assert!(suspended);
        assert!(first_day <= day, "{first_day}");
        assert!(densest(&mints, DAY) <= day);
        assert!(densest(&mints, window) <= budget);
        assert!(mints.len() <= 7 * day, "{}", mints.len());
    }
}

#[test]
fn a_flaky_network_under_the_budget_never_suspends() {
    let cfg = StreamConfig::default();
    let day = cfg.max_mints_per_day as usize;
    let mut s = HomeStream::new("h", BASE, cfg, None);
    s.on_history(5);
    // Two connections in three hold for half an hour; the third fails at once.
    let (mints, suspended) =
        hostile_run(&mut s, 0, 3 * DAY, &|k| (k % 3 != 2).then_some(30 * 60_000));
    println!("flaky network: {} mints in 3 days", mints.len());
    assert!(!suspended);
    assert!(densest(&mints, DAY) <= day);
    assert!(mints.len() > 100, "it kept reconnecting: {}", mints.len());
}

#[test]
fn retry_now_allows_a_small_allowance_past_the_daily_budget_and_no_more() {
    // No breaker and no short window: only the daily budget binds.
    let cfg = StreamConfig {
        suspend_after: 10_000,
        mint_budget: 10_000,
        ..StreamConfig::default()
    };
    let (day, extra) = (cfg.max_mints_per_day as usize, cfg.retry_allowance as usize);
    let mut s = HomeStream::new("h", BASE, cfg, None);
    s.on_history(5);
    let (mints, _) = hostile_run(&mut s, 0, 6 * 3_600_000, &|_| None);
    assert_eq!(mints.len(), day);
    assert!(matches!(s.status(), StreamStatus::Suspended(_)));
    // A host calling `retry_now` from a timer gets the allowance once per day, not per call.
    let mut t = 6 * 3_600_000;
    let mut more = 0;
    for _ in 0..50 {
        s.retry_now();
        let (m, _) = hostile_run(&mut s, t, t + 60_000, &|_| None);
        more += m.len();
        t += 600_000;
    }
    assert_eq!(more, extra, "the allowance, once");
    let StreamStatus::Suspended(until) = s.status() else {
        panic!("{:?}", s.status())
    };
    // 104 signed: under the budget again once the 9 oldest are a day old.
    assert_eq!(until, mints[extra] + DAY);
    // A changed history starts a new day.
    s.on_history(6);
    assert_eq!(s.next(t), StreamStep::NeedTicketCall);
}

#[test]
fn a_clock_rollback_never_delays_the_safety_poll_idle_check_backoff_or_window() {
    let t0 = 10 * 3_600_000;
    let back = t0 - 3_600_000;
    // Live: the safety poll is due at once after a rollback; the idle check counts from it.
    let mut s = HomeStream::new("h", BASE, StreamConfig::default(), None);
    connect(&mut s, t0, 1, "c");
    let _ = settle(&mut s, t0 + 300);
    assert_eq!(s.next(back), StreamStep::Wake, "safety poll due at once");
    let idle = s.config().idle_ms;
    let mut closed_at = None;
    let mut t = back;
    while t < back + 3 * idle {
        match s.next(t) {
            StreamStep::Close { .. } => {
                closed_at = Some(t);
                break;
            }
            _ => t += 1_000,
        }
    }
    let closed = closed_at.expect("the idle check still fires");
    assert!(closed <= back + idle + 1_000, "{closed} vs {}", back + idle);
    // A backoff deadline is due at once.
    let mut s = HomeStream::new("h", BASE, StreamConfig::default(), None);
    assert_eq!(s.next(t0), StreamStep::NeedTicketCall);
    s.ticket_request(b"c", t0).unwrap();
    let StreamEvent::Down { retry_at } = s.on_ticket(None, t0)[0] else {
        panic!()
    };
    assert!(retry_at > t0);
    assert_eq!(s.next(back), StreamStep::NeedTicketCall);
    // A spent ticket window clears within the window from the rollback point.
    let cfg = StreamConfig::default();
    let window = cfg.mint_window_ms;
    let mut s = HomeStream::new("h", BASE, cfg, None);
    s.on_history(1);
    let (_, _) = hostile_run(&mut s, t0, t0 + 120_000, &|_| None);
    if let StreamStatus::Throttled(_) = s.status() {
        let StreamStep::Sleep { until: Some(u) } = s.next(back) else {
            panic!()
        };
        assert!(u <= back + window, "{u} vs {}", back + window);
    }
    // A spent daily budget clears within a day of the rollback point.
    let cfg = StreamConfig {
        suspend_after: 10_000,
        mint_budget: 10_000,
        ..StreamConfig::default()
    };
    let mut s = HomeStream::new("h", BASE, cfg, None);
    s.on_history(1);
    let (m, _) = hostile_run(&mut s, t0, t0 + 3 * 3_600_000, &|_| None);
    assert_eq!(m.len(), 96);
    let StreamStep::Sleep { until: Some(u) } = s.next(back) else {
        panic!()
    };
    assert!(u <= back + DAY, "{u} vs {}", back + DAY);
    // A ticket held across a rollback is not presented: its age is unknown.
    let mut s = HomeStream::new("h", BASE, StreamConfig::default(), None);
    assert_eq!(s.next(t0), StreamStep::NeedTicketCall);
    s.ticket_request(b"c", t0).unwrap();
    s.on_ticket(Some(&ok_ticket(&ticket(1))), t0);
    assert_eq!(s.next(back), StreamStep::NeedTicketCall);
}

#[test]
fn extreme_times_do_not_panic_and_give_sane_deadlines() {
    for start in [0, i64::MAX - 10, i64::MAX] {
        let mut s = HomeStream::new("h", BASE, StreamConfig::default(), None);
        assert_eq!(s.next(start), StreamStep::NeedTicketCall);
        s.ticket_request(b"c", start).unwrap();
        s.on_ticket(Some(&ok_ticket(&ticket(1))), start);
        let StreamStep::Connect { .. } = s.next(start) else {
            panic!()
        };
        s.on_open(start);
        s.on_frame(&hello(1, "c"), start);
        s.on_frame(&change(2, "c.2"), start);
        for _ in 0..8 {
            match s.next(start) {
                StreamStep::Sleep { until } => {
                    assert!(until.is_some_and(|u| u >= start));
                    break;
                }
                StreamStep::Wake | StreamStep::Send { .. } => {}
                other => panic!("{start}: {other:?}"),
            }
        }
        let ev = s.on_closed(Some(1011), start);
        let StreamEvent::Down { retry_at } = ev[0] else {
            panic!("{ev:?}")
        };
        assert!(retry_at >= start, "{start}: {retry_at}");
        let _ = s.next(i64::MAX);
        let _ = s.next(0); // and back again
        let _ = s.next(i64::MIN);
    }
}

#[test]
fn requests_never_show_their_authorization_in_debug() {
    let mut s = HomeStream::new("h", BASE, StreamConfig::default(), None);
    assert_eq!(s.next(0), StreamStep::NeedTicketCall);
    let call = br#"{"body":"c2VjcmV0LWNhbGw","signature":"AAAA"}"#;
    let req = s.ticket_request(call, 0).unwrap();
    let encoded = req
        .headers
        .iter()
        .find(|(k, _)| k == "Authorization")
        .map(|(_, v)| v.clone())
        .unwrap();
    let shown = format!("{req:?} {req:#?}");
    assert!(!shown.contains(&encoded["Colophon ".len()..]), "{shown}");
    assert!(shown.contains("<redacted>"));
}

#[test]
fn a_session_frame_is_carried_byte_for_byte() {
    let mut s = HomeStream::new("h", "https://home.example/", StreamConfig::default(), None);
    // Not live yet: nothing to send on.
    assert!(s.session_frame("{}", None).is_err());
    connect(&mut s, 0, 1, "c.1");
    // Real codec frames (the 0.6 session wire vectors), with and without a delegation.
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/0.6-sessions/wire/vectors.json");
    let vectors: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    for (i, v) in vectors["frames"].as_array().unwrap().iter().enumerate() {
        let frame = v["frame"].as_str().unwrap();
        let id = format!("f{i}");
        let msg = s.session_frame(frame, Some(&id)).unwrap();
        assert_eq!(
            msg,
            format!("{{\"type\":\"session\",\"id\":\"{id}\",\"frame\":{frame}}}")
        );
        let parsed: Value = serde_json::from_str(&msg).unwrap();
        assert_eq!(parsed["frame"], serde_json::from_str::<Value>(frame).unwrap());
        let bare = s.session_frame(frame, None).unwrap();
        assert_eq!(bare, format!("{{\"type\":\"session\",\"frame\":{frame}}}"));
    }
    // An id is escaped as a JSON string.
    let quoted = s.session_frame("{}", Some("a\"b")).unwrap();
    let parsed: Value = serde_json::from_str(&quoted).unwrap();
    assert_eq!(parsed["id"], "a\"b");
    // Not a strict JSON object: refused.
    for bad in ["[]", "\"x\"", "{", r#"{"a":1,"a":2}"#, "{} {}"] {
        assert!(s.session_frame(bad, None).is_err(), "{bad}");
    }
    let big = format!("{{\"a\":\"{}\"}}", "A".repeat(16_384));
    assert!(s.session_frame(&big, None).is_err());
}
