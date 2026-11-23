//! Sync over the stream against the REAL relay (`relay/server.js` on Bun with the home module):
//! the engine's batch reads (`POST /records/batch`, proposed 0.6 W1) and the stream client
//! (`v05::engine::stream`, proposed 0.6 home stream v2) with a minimal RFC 6455 client over
//! `std::net` (no dependency). Device A writes; device B, whose stream is open, wakes on the
//! `change` frame and catches up in one pass that reads the records in one batch.
#![allow(
    clippy::unwrap_used,
    clippy::too_many_arguments,
    clippy::cloned_ref_to_slice_refs,
    dead_code
)]
#[path = "../../colophon-core/tests/v05_engine_support/mod.rs"]
mod support;
mod support_relay;
use colophon_core::v05::engine::exchange::Response;
use colophon_core::v05::engine::stream::{StreamConfig, StreamStatus, StreamStep};
use colophon_core::v05::engine::Engine;
use serde_json::json;
use std::io::{Read, Write};
use std::net::TcpStream;
use support::*;
use support_relay::*;

const NOW: i64 = T0 + 3 * HOUR;
const NS: &str = "notes";

/// A WebSocket client: the upgrade, then unmasked server text frames read one at a time.
struct Ws {
    s: TcpStream,
    buf: Vec<u8>,
}
impl Ws {
    /// Upgrade at `path`: `Ok` on 101, else the HTTP answer.
    fn open(port: u16, path: &str) -> Result<Ws, Response> {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        let head = format!(
            "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );
        s.write_all(head.as_bytes()).unwrap();
        let mut raw = Vec::new();
        let mut byte = [0u8; 1];
        while !raw.ends_with(b"\r\n\r\n") {
            if s.read(&mut byte).unwrap() == 0 {
                break;
            }
            raw.push(byte[0]);
        }
        let text = String::from_utf8_lossy(&raw).to_string();
        let status: u16 = text
            .split_whitespace()
            .nth(1)
            .and_then(|x| x.parse().ok())
            .unwrap_or(0);
        if status == 101 {
            return Ok(Ws { s, buf: Vec::new() });
        }
        let mut body = Vec::new();
        let _ = s.read_to_end(&mut body);
        Err(Response {
            status,
            headers: vec![],
            body,
        })
    }
    fn fill(&mut self, n: usize) -> bool {
        let mut chunk = [0u8; 4096];
        while self.buf.len() < n {
            match self.s.read(&mut chunk) {
                Ok(0) | Err(_) => return false,
                Ok(k) => self.buf.extend_from_slice(&chunk[..k]),
            }
        }
        true
    }
    /// The next text frame, `Err(code)` for a close, `None` on timeout.
    fn next(&mut self) -> Option<Result<String, u16>> {
        loop {
            if !self.fill(2) {
                return None;
            }
            let op = self.buf[0] & 0x0f;
            let mut len = (self.buf[1] & 0x7f) as usize;
            let mut at = 2;
            if len == 126 {
                self.fill(4);
                len = u16::from_be_bytes([self.buf[2], self.buf[3]]) as usize;
                at = 4;
            } else if len == 127 {
                self.fill(10);
                len = u64::from_be_bytes(self.buf[2..10].try_into().unwrap()) as usize;
                at = 10;
            }
            if !self.fill(at + len) {
                return None;
            }
            let payload: Vec<u8> = self.buf[at..at + len].to_vec();
            self.buf.drain(..at + len);
            match op {
                1 => return Some(Ok(String::from_utf8(payload).unwrap())),
                8 => {
                    let code = if payload.len() >= 2 {
                        u16::from_be_bytes([payload[0], payload[1]])
                    } else {
                        1005
                    };
                    return Some(Err(code));
                }
                9 => self.send(10, &payload), // ping: pong
                _ => {}
            }
        }
    }
    fn send(&mut self, op: u8, payload: &[u8]) {
        let mut f = vec![0x80 | op];
        let mask = [1u8, 2, 3, 4];
        if payload.len() < 126 {
            f.push(0x80 | payload.len() as u8);
        } else {
            f.push(0x80 | 126);
            f.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        }
        f.extend_from_slice(&mask);
        f.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        self.s.write_all(&f).unwrap();
    }
}

fn records(e: &Engine<MemSource>) -> usize {
    match e.view(NS).unwrap() {
        colophon_core::model::Outcome::Success { value, .. } => value.admitted.len(),
        colophon_core::model::Outcome::Failure { reason, .. } => panic!("{reason}"),
    }
}

#[test]
fn a_write_reaches_another_device_by_a_stream_wake_and_one_batch_against_the_real_relay() {
    let Some(_) = prerequisites() else { return };
    let keys = HomeKeys::new(0x77);
    let mut f = create_public(&[NS]);
    let home = appoint_home_keys(&mut f, &keys, BASE_A);
    let mut ids = Vec::new();
    for (label, seed) in [("A", 31u8), ("B", 32u8)] {
        let id = f.host.identity(seed);
        admit(
            &mut f,
            &id,
            label,
            "device",
            terms_for(&[(NS, "write")]),
            terms_for(&[(NS, "write")]),
        );
        ids.push(id);
    }
    let authority = MemSource::new();
    authority.store_account(&f.account);
    let scratch = Scratch::new("v06-sync");
    let relay = Relay::start(
        &keys,
        f.account.id().as_str(),
        BASE_A,
        scratch.path(),
        f.account.now_ms(),
        &[],
    );
    first_upload(&relay, &f, f.account.now_ms() + 1_000);
    let src = |_: ()| {
        let s = MemSource::new();
        for p in authority.listing() {
            s.put(&p, authority.get(&p).unwrap());
        }
        s
    };
    let (a_src, b_src) = (src(()), src(()));
    let mut a = member_engine(&f, &f.host, &a_src, &ids[0], NOW);
    let mut b = member_engine(&f, &f.host, &b_src, &ids[1], NOW);
    let mut host = std::mem::replace(&mut f.host, Host::new());
    let mut wire = RealRelay::new(&relay);
    let mut t = NOW;
    let fa = relay_pass(&mut a, &a_src, &home, &mut wire, &host, t);
    let fb = relay_pass(&mut b, &b_src, &home, &mut wire, &host, t);
    assert!(fa.is_empty() && fb.is_empty(), "{fa:?} {fb:?}");

    // B opens its stream: a real `colophon.home.stream` call mints the ticket.
    let mut stream = b
        .stream_client(&home, StreamConfig::default(), None)
        .unwrap();
    assert_eq!(stream.next(t), StreamStep::NeedTicketCall);
    let key = host.ids[&ids[1]].public().signing;
    let action = b
        .stream_begin_call(&home, &key, fresh_request_id())
        .unwrap();
    let sigs = host.sign(action.steps());
    let call = b.finish_write(action, sigs).unwrap().artifact.unwrap();
    let req = stream.ticket_request(&call).unwrap();
    let r = wire.call(&host, &req, t);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert!(stream.on_ticket(Some(&r), t).is_empty());
    let StreamStep::Connect { url } = stream.next(t) else {
        panic!()
    };
    let path = url.strip_prefix("wss://home-a.example").unwrap();
    let mut ws = Ws::open(relay.port, &relay.url(path)).unwrap_or_else(|r| {
        panic!(
            "upgrade refused: {} {}",
            r.status,
            String::from_utf8_lossy(&r.body)
        )
    });
    stream.on_open(t);
    let hello = ws.next().unwrap().unwrap();
    let ev = stream.on_frame(&hello, t);
    assert_eq!(stream.status(), StreamStatus::Live, "{hello} {ev:?}");
    // The first connection's catch-up (nothing to fetch).
    t += 300;
    assert_eq!(stream.next(t), StreamStep::Wake);
    let fb = relay_pass(&mut b, &b_src, &home, &mut wire, &host, t);
    assert!(fb.is_empty(), "{fb:?}");

    // A writes five records and pushes them.
    t += 5_000;
    for i in 0..5 {
        engine_write(
            &mut a,
            &mut host,
            &a_src,
            NS,
            "createNotebook",
            json!({"id": format!("n{i}"), "title": "Pushed"}),
        );
    }
    let fa = relay_pass(&mut a, &a_src, &home, &mut wire, &host, t);
    assert!(fa.is_empty(), "{fa:?}");

    // B's socket carries the changes; B wakes and catches up in one pass.
    let mut changes = 0;
    while changes < 5 {
        let fr = ws.next().expect("a frame").expect("not closed");
        if fr.contains("\"change\"") {
            changes += 1;
        }
        stream.on_frame(&fr, t);
    }
    t += 250;
    assert_eq!(stream.next(t), StreamStep::Wake);
    let mark = wire.requests.len();
    let fb = relay_pass(&mut b, &b_src, &home, &mut wire, &host, t);
    assert!(fb.is_empty(), "{fb:?}");
    assert_eq!(records(&b), 5);
    let trips = wire.requests[mark..].to_vec();
    println!(
        "real relay: B's woken pass, {} round trips: {trips:?}",
        trips.len()
    );
    assert_eq!(
        trips.iter().filter(|r| *r == "POST /records/batch").count(),
        1
    );
    assert_eq!(
        trips
            .iter()
            .filter(|r| r.starts_with("GET /records/ops/"))
            .count(),
        0
    );
    assert_eq!(b.exchange_batch_support(&home), Some(true));
    ws.send(8, &1000u16.to_be_bytes());
}
