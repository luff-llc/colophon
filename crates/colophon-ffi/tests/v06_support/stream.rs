//! The 0.6 home stream client through the exported surface only, as a host drives it: ticket,
//! open, frames, close, backoff, resume and polling fallback, with the transcripts of the core's
//! own stream tests (`colophon-core/tests/v05_engine_stream.rs`). Shared with the wasm crate's
//! test, which includes it with that crate's exports in scope.
#![allow(dead_code, clippy::unwrap_used)]
use super::*;
use serde_json::{json, Value};

pub const BASE: &str = "https://home.example";

pub fn answer(status: u32, body: Value) -> HttpAnswer {
    HttpAnswer {
        status,
        headers: vec![],
        body: body.to_string().into_bytes(),
    }
}
pub fn ticket(i: u8) -> String {
    format!("{:A>43}", i)
}
pub fn ok_ticket(i: u8) -> HttpAnswer {
    answer(
        200,
        json!({"ticket": ticket(i), "expires": 0, "path": "/stream"}),
    )
}
pub fn hello(n: u64, cursor: &str) -> String {
    json!({"type": "hello", "n": n, "protocol": "colophon/home-stream/6", "account": "a",
           "home": "h", "instance": "i", "cursor": cursor, "head": null, "notice": 0,
           "principal": "member:m", "expiresAt": null, "namespaces": [],
           "limits": {"pingMs": 20000, "idleMs": 60000, "resumeEntries": 1024}})
    .to_string()
}
pub fn change(n: u64, cursor: &str) -> String {
    json!({"type": "change", "n": n, "cursor": cursor,
           "entry": {"path": "ops/x.json", "size": 1, "sha256": "0".repeat(64)}})
    .to_string()
}

/// Drive a client to live with `hello` at `t`; the connect step's URL and log URL.
pub fn connect(s: &HomeStream, t: i64, i: u8, cursor: &str) -> (String, String) {
    let mut step = s.next(t).unwrap();
    while step.kind == StreamStepKind::Wake {
        step = s.next(t).unwrap();
    }
    assert_eq!(step.kind, StreamStepKind::NeedTicketCall);
    let req = s.ticket_request(b"signed call".to_vec(), t).unwrap();
    assert_eq!(req.method, HttpMethod::Post);
    assert_eq!(req.url, format!("{BASE}/stream/ticket"));
    assert!(req.body.is_empty());
    assert!(req
        .headers
        .iter()
        .any(|h| h.name == "Authorization" && h.value.starts_with("Colophon ")));
    assert!(s.on_ticket(Some(ok_ticket(i)), t).unwrap().is_empty());
    let step = s.next(t).unwrap();
    assert_eq!(step.kind, StreamStepKind::Connect);
    s.on_open(t).unwrap();
    let ev = s.on_frame(hello(1, cursor), t).unwrap();
    assert_eq!(ev[0].kind, StreamEventKind::Connected);
    assert_eq!(ev[0].principal.as_deref(), Some("member:m"));
    assert_eq!(s.status().unwrap().kind, StreamStatusKind::Live);
    (step.url.unwrap(), step.log_url.unwrap())
}

/// Run `next` until it asks for nothing more at `t`; the kinds of the steps taken.
pub fn settle(s: &HomeStream, t: i64) -> Vec<StreamStep> {
    let mut out = Vec::new();
    for _ in 0..16 {
        let st = s.next(t).unwrap();
        let stop = matches!(st.kind, StreamStepKind::Sleep | StreamStepKind::Waiting);
        out.push(st);
        if stop {
            break;
        }
    }
    out
}

fn cursors(ev: &[StreamEvent]) -> Vec<Option<String>> {
    ev.iter()
        .filter(|e| e.kind == StreamEventKind::Cursor)
        .map(|e| e.cursor.clone())
        .collect()
}

/// Ticket, open, hello, a burst of changes coalesced into one wake, pass-through frames, then a
/// drop, the backoff, a resume from the cursor, and a resync.
pub fn ticket_open_frames_close_backoff_resume() {
    let s = HomeStream::new(
        "h".into(),
        format!("{BASE}/"),
        stream_default_config(),
        None,
    )
    .unwrap();
    assert!(s.polling().unwrap(), "polling until the stream is live");
    let (url, log) = connect(&s, 0, 1, "c.10");
    assert_eq!(
        url,
        format!("wss://home.example/stream?ticket={}", ticket(1))
    );
    assert_eq!(log, "wss://home.example/stream?ticket=<redacted>");
    assert_eq!(stream_redact_url(url.clone()), log);
    assert!(!s.polling().unwrap());
    assert_eq!(
        s.cursor().unwrap().as_deref(),
        Some("c.10"),
        "the hello's cursor"
    );
    // The first connection wakes a catch-up pass after the coalescing window.
    let st = s.next(100).unwrap();
    assert_eq!((st.kind, st.until), (StreamStepKind::Sleep, Some(250)));
    assert_eq!(s.next(250).unwrap().kind, StreamStepKind::Wake);
    s.on_history(1).unwrap();
    // A burst of changes is one wake; every cursor is reported to persist.
    let mut seen = Vec::new();
    for (i, n) in (2..7).enumerate() {
        seen.extend(cursors(
            &s.on_frame(change(n, &format!("c.{}", 11 + i)), 1_000 + i as i64)
                .unwrap(),
        ));
    }
    let want: Vec<Option<String>> = (11..16).map(|i| Some(format!("c.{i}"))).collect();
    assert_eq!(seen, want);
    let st = settle(&s, 1_100);
    assert_eq!(st.len(), 1);
    assert_eq!(
        (st[0].kind, st[0].until),
        (StreamStepKind::Sleep, Some(1_250))
    );
    assert_eq!(s.next(1_250).unwrap().kind, StreamStepKind::Wake);
    // Session, route and notice frames pass through; a session frame byte for byte.
    let sess = r#"{"type":"session","n":7,"frame":{"body":"e30=","signature":"AA=="}}"#;
    let ev = s.on_frame(sess.into(), 2_000).unwrap();
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].kind, StreamEventKind::Session);
    assert_eq!(ev[0].text.as_deref(), Some(sess));
    let ev = s
        .on_frame(
            json!({"type": "route", "n": 8, "id": "r", "change": "delete"}).to_string(),
            2_000,
        )
        .unwrap();
    assert_eq!(ev[0].kind, StreamEventKind::Route);
    let route: Value = serde_json::from_str(ev[0].json.as_deref().unwrap()).unwrap();
    assert_eq!(route["id"], "r");
    let ev = s
        .on_frame(
            json!({"type": "notice", "n": 9, "notice": 4, "object": "o", "kind": "transition", "deadline": 1})
                .to_string(),
            2_000,
        )
        .unwrap();
    assert_eq!(ev[0].kind, StreamEventKind::Notice);
    assert_eq!(s.next(2_250).unwrap().kind, StreamStepKind::Wake);
    // Unknown frame types are ignored but numbered.
    assert!(s
        .on_frame(json!({"type": "future", "n": 10}).to_string(), 2_300)
        .unwrap()
        .is_empty());
    // Client frames for session cells while live.
    let sub: Value = serde_json::from_str(
        &s.subscribe(
            "listening.podcasts".into(),
            "now-playing".into(),
            Some("s1".into()),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(sub["type"], "subscribe");
    let env = r#"{"body":"e30=","signature":"AA=="}"#;
    let frame: Value = serde_json::from_str(&s.session_frame(env.into(), None).unwrap()).unwrap();
    assert_eq!(frame["type"], "session");
    assert_eq!(frame["frame"]["body"], "e30=");
    assert_eq!(
        s.session_frame("not json".into(), None)
            .err()
            .unwrap()
            .code(),
        "malformed"
    );

    // The home drops us (slow consumer): back off and poll, then resume from the cursor.
    let ev = s.on_closed(Some(4013), 3_000).unwrap();
    assert_eq!(ev[0].kind, StreamEventKind::Down);
    let retry_at = ev[0].retry_at.unwrap();
    assert!(
        (3_000 + 500..=3_000 + 1_000).contains(&retry_at),
        "{retry_at}"
    );
    assert!(s.polling().unwrap());
    let status = s.status().unwrap();
    assert_eq!(
        (status.kind, status.until),
        (StreamStatusKind::Backoff, Some(retry_at))
    );
    let st = s.next(retry_at - 1).unwrap();
    assert_eq!((st.kind, st.until), (StreamStepKind::Sleep, Some(retry_at)));
    let (url, _) = connect(&s, retry_at, 2, "c.20");
    assert!(url.ends_with("&after=c.15"), "{url}");
    assert_eq!(
        s.attempts().unwrap(),
        1,
        "a hello alone does not reset the backoff"
    );
    // `gone`: the cursor is forgotten and a pass woken.
    let t = retry_at + 10_000;
    let _ = settle(&s, t);
    let ev = s
        .on_frame(
            json!({"type": "resync", "n": 2, "reason": "gone", "after": "c.15"}).to_string(),
            t,
        )
        .unwrap();
    assert_eq!(cursors(&ev), [None]);
    assert_eq!(ev[1].kind, StreamEventKind::Resync);
    assert_eq!(ev[1].reason.as_deref(), Some("gone"));
    assert_eq!(s.cursor().unwrap(), None);
    assert_eq!(s.next(t + 250).unwrap().kind, StreamStepKind::Wake);
    // A gap in frame numbers: a violation, then the client closes with 1002 and backs off.
    let ev = s.on_frame(change(9, "d.9"), t + 300).unwrap();
    assert_eq!(ev[0].kind, StreamEventKind::Violation);
    let steps = settle(&s, t + 300);
    assert!(steps
        .iter()
        .any(|x| x.kind == StreamStepKind::Close && x.code == Some(1002)));
    let ev = s.on_closed(Some(1002), t + 301).unwrap();
    assert_eq!(ev[0].kind, StreamEventKind::Down);
}

/// The jittered backoff schedule comes from the seed alone; a rate-limited ticket waits at least
/// the home's Retry-After.
pub fn backoff_is_seeded_and_capped() {
    let schedule = |seed: u64| {
        let mut cfg = stream_default_config();
        cfg.seed = seed;
        cfg.mint_budget = 100;
        let s = HomeStream::new("h".into(), BASE.into(), cfg, None).unwrap();
        let mut t = 0;
        let mut delays = Vec::new();
        for _ in 0..10 {
            assert_eq!(s.next(t).unwrap().kind, StreamStepKind::NeedTicketCall);
            s.ticket_request(b"c".to_vec(), t).unwrap();
            let ev = s.on_ticket(None, t).unwrap();
            assert_eq!(ev[0].kind, StreamEventKind::Down);
            let r = ev[0].retry_at.unwrap();
            delays.push(r - t);
            t = r;
        }
        (delays, s, t)
    };
    let (a, s, t) = schedule(1);
    let (b, _, _) = schedule(1);
    let (c, _, _) = schedule(2);
    assert_eq!(a, b, "the same seed, the same schedule");
    assert_ne!(a, c);
    for (i, d) in a.iter().enumerate() {
        let full = (1_000_i64 << i).min(60_000);
        assert!((full / 2..=full).contains(d), "attempt {i}: {d}");
    }
    assert_eq!(s.next(t).unwrap().kind, StreamStepKind::NeedTicketCall);
    s.ticket_request(b"c".to_vec(), t).unwrap();
    let r = HttpAnswer {
        status: 429,
        headers: vec![Header {
            name: "Retry-After".into(),
            value: "120".into(),
        }],
        body: br#"{"result":"refused:window"}"#.to_vec(),
    };
    let ev = s.on_ticket(Some(r), t).unwrap();
    assert!(ev[0].retry_at.unwrap() - t >= 120_000);
}

/// Refused, unsupported, access ended and released streams stay on polling until the history
/// changes; the ticket budget throttles minting.
pub fn refusals_fall_back_to_polling() {
    for (r, kind, refused) in [
        (answer(404, json!({})), StreamBlockedKind::Unsupported, None),
        (
            answer(403, json!({"result": "refused:outOfScope"})),
            StreamBlockedKind::Refused,
            Some("refused:outOfScope"),
        ),
        (
            answer(401, json!({})),
            StreamBlockedKind::Refused,
            Some("401"),
        ),
    ] {
        let s = HomeStream::new("h".into(), BASE.into(), stream_default_config(), None).unwrap();
        s.on_history(7).unwrap();
        assert_eq!(s.next(0).unwrap().kind, StreamStepKind::NeedTicketCall);
        s.ticket_request(b"c".to_vec(), 0).unwrap();
        let ev = s.on_ticket(Some(r), 0).unwrap();
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].kind, StreamEventKind::Blocked);
        assert_eq!(ev[0].blocked, Some(kind));
        assert_eq!(ev[0].refused.as_deref(), refused);
        let st = s.status().unwrap();
        assert_eq!(
            (st.kind, st.blocked),
            (StreamStatusKind::Blocked, Some(kind))
        );
        assert!(s.polling().unwrap());
        let n = s.next(1_000_000).unwrap();
        assert_eq!((n.kind, n.until), (StreamStepKind::Sleep, None));
        s.on_history(8).unwrap();
        assert_eq!(
            s.next(1_000_001).unwrap().kind,
            StreamStepKind::NeedTicketCall
        );
    }
    // Access ended (1008) blocks; a bare 1001 is a drop; `bye` released then a close blocks.
    for (code, bye, want) in [
        (1008, false, Some(StreamBlockedKind::AccessEnded)),
        (1001, false, None),
        (1000, true, Some(StreamBlockedKind::Released)),
    ] {
        let s = HomeStream::new("h".into(), BASE.into(), stream_default_config(), None).unwrap();
        connect(&s, 0, 1, "c.1");
        if bye {
            let ev = s
                .on_frame(
                    json!({"type": "bye", "n": 2, "reason": "released", "resume": false})
                        .to_string(),
                    5,
                )
                .unwrap();
            assert_eq!(ev[0].kind, StreamEventKind::Bye);
        }
        let ev = s.on_closed(Some(code), 6).unwrap();
        match want {
            Some(k) => assert_eq!(
                (ev[0].kind, ev[0].blocked),
                (StreamEventKind::Blocked, Some(k))
            ),
            None => assert_eq!(ev[0].kind, StreamEventKind::Down),
        }
    }
    // An upgrade refused as revoked.
    let s = HomeStream::new("h".into(), BASE.into(), stream_default_config(), None).unwrap();
    s.next(0).unwrap();
    s.ticket_request(b"c".to_vec(), 0).unwrap();
    s.on_ticket(Some(ok_ticket(1)), 0).unwrap();
    assert_eq!(s.next(0).unwrap().kind, StreamStepKind::Connect);
    let ev = s
        .on_refused(answer(403, json!({"result": "refused:revoked"})), 1)
        .unwrap();
    assert_eq!(ev[0].blocked, Some(StreamBlockedKind::AccessEnded));
    // The ticket budget: past `mint_budget` in the window the stream is throttled, polling.
    let mut cfg = stream_default_config();
    cfg.mint_budget = 2;
    let s = HomeStream::new("h".into(), BASE.into(), cfg, None).unwrap();
    let mut t = 0;
    for _ in 0..2 {
        assert_eq!(s.next(t).unwrap().kind, StreamStepKind::NeedTicketCall);
        s.ticket_request(b"c".to_vec(), t).unwrap();
        t = s.on_ticket(None, t).unwrap()[0].retry_at.unwrap();
    }
    let st = s.next(t).unwrap();
    assert_eq!(st.kind, StreamStepKind::Sleep);
    let status = s.status().unwrap();
    assert_eq!(status.kind, StreamStatusKind::Throttled);
    assert_eq!(status.until, Some(600_000));
    assert!(s.polling().unwrap());
    // A call the host could not build counts like a mint and backs off.
    let s = HomeStream::new("h".into(), BASE.into(), stream_default_config(), None).unwrap();
    assert_eq!(s.next(0).unwrap().kind, StreamStepKind::NeedTicketCall);
    let ev = s.ticket_call_failed(0).unwrap();
    assert_eq!(ev[0].kind, StreamEventKind::Down);
    assert_eq!(s.unstable_mints().unwrap(), 1);
    s.retry_now().unwrap();
    assert_eq!(s.unstable_mints().unwrap(), 0);
}

/// Misuse is a typed error, never a default or a panic.
pub fn misuse_is_typed() {
    let s = HomeStream::new("h".into(), BASE.into(), stream_default_config(), None).unwrap();
    // No ticket call is outstanding before `next` asked for one... it is, at first; after the
    // request it is not.
    s.next(0).unwrap();
    s.ticket_request(b"c".to_vec(), 0).unwrap();
    let e = s.ticket_request(b"c".to_vec(), 0).err().unwrap();
    assert_eq!(e.code(), "malformed");
    assert!(!e.detail().contains("signed"), "no call in an error");
    assert_eq!(s.on_closed(Some(70_000), 0).err().unwrap().code(), "bound");
    let big = HttpAnswer {
        status: 70_000,
        headers: vec![],
        body: vec![],
    };
    assert_eq!(s.on_ticket(Some(big), 0).err().unwrap().code(), "bound");
    assert_eq!(
        s.subscribe("n".into(), "c".into(), None)
            .err()
            .unwrap()
            .code(),
        "malformed",
        "not live"
    );
    assert_eq!(
        HomeStream::new(
            "h".into(),
            BASE.into(),
            stream_default_config(),
            Some("c".repeat(300))
        )
        .err()
        .map(|e| e.code()),
        Some("bound".to_string())
    );
    let cfg = s.config().unwrap();
    assert_eq!(cfg.safety_poll_ms, 60_000);
    assert_eq!(cfg.max_mints_per_day, 96);
    assert_eq!(s.home().unwrap(), "h");
}

/// A ticket call is handed out once; `next` then waits, saying when to ask again, until the host
/// answers, and a call never answered fails after the timeout and backs off.
pub fn one_ticket_call_at_a_time() {
    let s = HomeStream::new("h".into(), BASE.into(), stream_default_config(), None).unwrap();
    let first = s.next(0).unwrap();
    assert_eq!(first.kind, StreamStepKind::NeedTicketCall);
    assert_eq!(first.wake_at, Some(60_000), "the call's timeout");
    for t in [1, 10, 1_000, 59_999] {
        let st = s.next(t).unwrap();
        assert_eq!(st.kind, StreamStepKind::Waiting, "no second call at {t}");
        assert_eq!(st.wake_at, Some(60_000));
    }
    let st = s.next(60_000).unwrap();
    assert_eq!(st.kind, StreamStepKind::Sleep, "the unanswered call failed");
    assert_eq!(s.status().unwrap().kind, StreamStatusKind::Backoff);
    assert_eq!(s.unstable_mints().unwrap(), 1, "counted as a mint");
    assert!(
        st.wake_at.is_some_and(|w| w > 60_000),
        "ask again when the backoff ends"
    );
    assert_eq!(
        s.ticket_request(b"late".to_vec(), 60_001)
            .err()
            .unwrap()
            .code(),
        "malformed",
        "a late answer is refused"
    );
}
