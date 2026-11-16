//! Independent checker's tests for E6 (the account engine), 2026-11-14. Each test is named
//! `check_*` and asserts the behaviour it demonstrates (a flaw where the report says so).
#![allow(
    clippy::unwrap_used,
    clippy::too_many_arguments,
    clippy::cloned_ref_to_slice_refs,
    dead_code
)]
#[path = "v05_engine_support/mod.rs"]
mod support;
use base64::engine::general_purpose::STANDARD;
use colophon_core::model::Outcome;
use colophon_core::v05::account::{Account, Identity, RevokeKeep};
use colophon_core::v05::encoding::canonical;
use colophon_core::v05::engine::exchange::{Method, Request, Response, Step};
use colophon_core::v05::engine::{Engine, EngineOptions, OpenMode};
use colophon_core::v05::records::{judge_records, HeldRecord, Level};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::Instant;
use support::*;

const NOW: i64 = T0 + 3 * HOUR;
const LISTEN: &str = "listening.podcasts";
const NOTES: &str = "notes";

fn position(id: &str, seconds: f64) -> Value {
    json!({"id": id, "show": "show", "seconds": seconds})
}
fn follow() -> Value {
    json!({"id": "show", "url": "https://example.org/feed", "title": "The Show"})
}
fn sha_hex(b: &[u8]) -> String {
    hex(&Sha256::digest(b))
}
fn resp(status: u16, body: Value) -> Response {
    Response {
        status,
        headers: vec![],
        body: serde_json::to_vec(&body).unwrap(),
    }
}

// ---------------------------------------------------------------------------------------------
// A notes world (as `v05_account_engine.rs`): one member that has written `n` notes.

struct Notes {
    f: Fixture,
    src: MemSource,
    member: String,
    writer: Account,
}
fn notes(n: usize) -> Notes {
    let mut f = create(&[NOTES]);
    let member = f.host.identity(31);
    admit(
        &mut f,
        &member,
        "Phone",
        "device",
        terms("write"),
        terms("write"),
    );
    let src = MemSource::versioned();
    src.store_account(&f.account);
    let writer = member_session(&f, &member);
    let mut w = Notes {
        f,
        src,
        member,
        writer,
    };
    for i in 0..n {
        write_note(&mut w, i);
    }
    w
}
fn write_note(w: &mut Notes, i: usize) {
    let seed = w.f.host.fresh();
    let action = w
        .writer
        .begin_write(
            NOTES,
            "createNotebook",
            json!({"id": format!("nb{i:05}"), "title": format!("Notebook {i}")}),
            Level::Write,
            seed,
        )
        .unwrap()
        .unwrap();
    let done = run(&mut w.writer, &w.f.host, action);
    w.src.publish(&done);
}
fn open_notes(
    w: &Notes,
    src: &MemSource,
    saved: Option<&colophon_core::v05::engine::Saved>,
) -> colophon_core::v05::Result<Engine<MemSource>> {
    let mut e = Engine::open(
        src.clone(),
        src.listing(),
        Identity::Member(w.member.clone()),
        EngineOptions::new(w.f.account.id().as_str(), DEVICE_KEY),
        saved,
        w.f.account.now_ms(),
    )?;
    let steps = e.begin_unlock_epochs();
    let results = w.f.host.answer_epochs(&w.member, steps);
    e.finish_unlock_epochs(results)?;
    Ok(e)
}
fn admitted_ids(e: &Engine<MemSource>, ns: &str) -> Vec<String> {
    match e.view(ns).unwrap() {
        Outcome::Success { value, .. } => {
            let v = serde_json::to_value(value).unwrap();
            v["admitted"]
                .as_array()
                .unwrap()
                .iter()
                .map(|o| o["id"].as_str().unwrap().to_string())
                .collect()
        }
        Outcome::Failure { reason, .. } => panic!("{reason}"),
    }
}

/// F-1 (checkpoint): a covered immutable record whose bytes changed between sessions is
/// silently replaced on a resumed open. In a session the same change is equivocation and
/// poisons the engine; across a restart it drops the verified record without a word, the
/// open still says `Resumed`, nothing is listed as missing, and the integrity audit passes.
#[test]
fn check_resume_accepts_changed_bytes_at_a_covered_immutable_path() {
    let w = notes(10);
    let mut e = open_notes(&w, &w.src, None).unwrap();
    assert_eq!(admitted_ids(&e, NOTES).len(), 10);
    let saved = e.save([3; 32]).unwrap();
    let victim = w
        .src
        .listing()
        .into_iter()
        .find(|p| p.starts_with("ops/"))
        .unwrap();
    // The folder's bytes at that path change (a sync conflict, a hostile folder) to bytes that
    // are no record at all.
    let twin = b"{}".to_vec();
    // In a running session: fail closed.
    w.src.put(&victim, twin.clone());
    let in_session = e.refresh(w.src.listing());
    assert!(
        in_session.is_err(),
        "in a session it is equivocation: {in_session:?}"
    );
    // After a restart with the checkpoint: accepted, the record is gone, no fault.
    let mut r = open_notes(&w, &w.src, Some(&saved)).unwrap();
    assert!(
        matches!(r.open_mode(), OpenMode::Invalidated(m) if m.contains("covered")),
        "the open says what it judged again: {:?}",
        r.open_mode()
    );
    assert_eq!(r.rejudged(), [victim.clone()]);
    assert_eq!(
        admitted_ids(&r, NOTES).len(),
        9,
        "the changed record is judged again and is no record"
    );
    let audit = r.verify_batch(1_000);
    assert!(
        audit.is_err(),
        "and the integrity audit fails on bytes that do not parse: {audit:?}"
    );
}

/// The checkpoint's seal binds account, identity and scope; a truncated, bit-flipped or
/// swapped checkpoint opens cold (ran to confirm the builder's claims).
#[test]
fn check_checkpoint_forgeries_open_cold() {
    let w = notes(4);
    let mut e = open_notes(&w, &w.src, None).unwrap();
    let saved = e.save([4; 32]).unwrap();
    for cut in [0usize, 8, 12, 40, saved.checkpoint.len() - 1] {
        let mut s = saved.clone();
        s.checkpoint.truncate(cut);
        let r = open_notes(&w, &w.src, Some(&s)).unwrap();
        assert!(
            matches!(r.open_mode(), OpenMode::Invalidated(_)),
            "cut {cut}"
        );
        assert_eq!(admitted_ids(&r, NOTES).len(), 4);
    }
    let mut s = saved.clone();
    let n = s.checkpoint.len();
    s.checkpoint[n - 20] ^= 1;
    let r = open_notes(&w, &w.src, Some(&s)).unwrap();
    assert!(matches!(r.open_mode(), OpenMode::Invalidated(_)));
    // An absurd header length does not panic.
    let mut s = saved.clone();
    s.checkpoint[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    let r = open_notes(&w, &w.src, Some(&s)).unwrap();
    assert!(matches!(r.open_mode(), OpenMode::Invalidated(_)));
}

// ---------------------------------------------------------------------------------------------
// A home world (as `v05_engine_home.rs`).

struct HomeWorld {
    s: Setup,
    host: Host,
    phone: Engine<MemSource>,
    phone_src: MemSource,
    phone_id: String,
}
fn home_world() -> HomeWorld {
    let (mut s, ids) = setup(LISTEN, &[("Phone", 31, "write")]);
    let phone_src = device_source(&s);
    let phone = member_engine(&s.f, &s.f.host, &phone_src, &ids[0], NOW);
    let host = std::mem::replace(&mut s.f.host, Host::new());
    let mut w = HomeWorld {
        s,
        host,
        phone,
        phone_src,
        phone_id: ids[0].clone(),
    };
    engine_write(
        &mut w.phone,
        &mut w.host,
        &w.phone_src,
        LISTEN,
        "follow",
        follow(),
    );
    let home = w.s.home.clone();
    let f = sync_pass(
        &mut w.phone,
        &w.phone_src,
        &home,
        &mut w.s.sim,
        &w.host,
        NOW,
    );
    assert!(f.is_empty(), "{f:?}");
    w
}

/// Drive at most `max` steps of one pass. Returns (requests sent, finished).
fn bounded_pass(
    e: &mut Engine<MemSource>,
    src: &MemSource,
    home: &str,
    wire: &mut dyn Wire,
    host: &Host,
    now: i64,
    max: usize,
) -> (Vec<String>, bool) {
    e.advance(now).unwrap();
    e.refresh(src.listing()).unwrap();
    let mut sent = Vec::new();
    for _ in 0..max {
        match e.exchange_next(home).unwrap() {
            Step::Done => return (sent, true),
            Step::Waiting => panic!("waiting"),
            Step::NeedCall(n) => e
                .exchange_provide_call(home, n.ticket, format!("call-{}", n.ticket).as_bytes())
                .unwrap(),
            Step::Request(r) => {
                sent.push(format!(
                    "{:?} {}",
                    r.method,
                    r.url.strip_prefix("https://home.example").unwrap_or(&r.url)
                ));
                let a = wire.call(host, &r, now);
                let report = e.exchange_answer(home, r.ticket, a).unwrap();
                for (p, b) in report.store {
                    src.put(&p, b);
                }
            }
        }
    }
    (sent, false)
}

/// A home that lists its genesis under a different envelope (same body, other signature
/// bytes: ECDSA malleability or plain garbage) and serves that envelope.
struct GenesisTwin<'a> {
    inner: &'a mut SimHome,
}
impl Wire for GenesisTwin<'_> {
    fn call(&mut self, host: &Host, req: &Request, now: i64) -> Response {
        let path = req.url.strip_prefix("https://home.example").unwrap_or("");
        let twin = || {
            let real = self.inner.files["authority/00000001.json"].clone();
            let mut v: Value = serde_json::from_slice(&real).unwrap();
            v["signature"] = json!(b64(&[9u8; 64]));
            canonical(&v).unwrap()
        };
        if path.starts_with("/changes") {
            let t = twin();
            let mut r = self.inner.call(host, req, now);
            let mut v: Value = serde_json::from_slice(&r.body).unwrap();
            for e in v["entries"].as_array_mut().unwrap() {
                if e["path"] == "authority/00000001.json" {
                    e["sha256"] = json!(sha_hex(&t));
                }
            }
            r.body = serde_json::to_vec(&v).unwrap();
            return r;
        }
        if path == "/records/authority/00000001.json" {
            return Response {
                status: 200,
                headers: vec![],
                body: twin(),
            };
        }
        self.inner.call(host, req, now)
    }
}

/// F-2 (exchange): the genesis check loops for ever. `on_genesis` accepts the same body
/// and re-queues the change feed with the *old* cursor; the feed lists the twin's digest again,
/// which differs from the local envelope's, so the check is queued again. No fault, no end.
#[test]
fn check_genesis_twin_makes_a_pass_that_never_ends() {
    let mut w = home_world();
    let home = w.s.home.clone();
    // A second device of the phone's member: no cursor yet, so the feed lists the genesis.
    let src = device_source(&w.s);
    let mut fresh = member_engine(&w.s.f, &w.host, &src, &w.phone_id, NOW);
    let mut wire = GenesisTwin {
        inner: &mut w.s.sim,
    };
    let (sent, done) = bounded_pass(
        &mut fresh,
        &src,
        &home,
        &mut wire,
        &w.host,
        NOW + 1_000,
        3_000,
    );
    let checks = sent
        .iter()
        .filter(|r| r.as_str() == "Get /records/authority/00000001.json")
        .count();
    assert!(done, "a twin of the genesis is one object: the pass ends");
    assert!(
        checks <= 1,
        "the same body is checked once and never queued again: {checks}"
    );
}

/// A home that answers every change-feed request with the same entry, a fresh cursor and
/// `more: true`.
struct EndlessFeed<'a> {
    inner: &'a mut SimHome,
    n: u64,
}
impl Wire for EndlessFeed<'_> {
    fn call(&mut self, host: &Host, req: &Request, now: i64) -> Response {
        let path = req.url.strip_prefix("https://home.example").unwrap_or("");
        if path.starts_with("/changes") {
            self.n += 1;
            let first = self.inner.log[0].clone();
            let sha = sha_hex(&self.inner.files[&first]);
            return resp(
                200,
                json!({"entries": [{"path": first, "size": 1, "sha256": sha}],
                       "cursor": format!("c{}", self.n), "more": true}),
            );
        }
        self.inner.call(host, req, now)
    }
}

/// F-3 (exchange): the change feed has no bound on pages per pass. A page that repeats an
/// entry under a new cursor counts as progress, so a home can keep one pass going for ever.
#[test]
fn check_change_feed_has_no_page_bound() {
    let mut w = home_world();
    let home = w.s.home.clone();
    let mut wire = EndlessFeed {
        inner: &mut w.s.sim,
        n: 0,
    };
    let (sent, done) = bounded_pass(
        &mut w.phone,
        &w.phone_src,
        &home,
        &mut wire,
        &w.host,
        NOW + 1_000,
        3_000,
    );
    let pages = sent
        .iter()
        .filter(|r| r.starts_with("Get /changes"))
        .count();
    assert!(done, "no answer from a home keeps a pass going");
    assert!(
        pages <= 3,
        "a repeated entry under a fresh cursor ends the pass: {pages} pages"
    );
}

/// F-4 (live, exchange): a device whose local slot is older than the home's PUTs its older
/// head with `If-Match` naming the home's newer bytes, which it has not verified when it plans
/// the PUT, and so overwrites the newer value on the home (0.3 §8.2: "Keep a newer local head
/// on a race; re-list and retry instead of overwriting it").
#[test]
fn check_live_put_overwrites_a_newer_value_on_the_home() {
    let mut w = home_world();
    let home = w.s.home.clone();
    let first = engine_live(
        &mut w.phone,
        &mut w.host,
        &w.phone_src,
        position("e1", 10.0),
    );
    let f = sync_pass(
        &mut w.phone,
        &w.phone_src,
        &home,
        &mut w.s.sim,
        &w.host,
        NOW + 1_000,
    );
    assert!(f.is_empty(), "{f:?}");
    // The device's store as it was then (a restore, or the provider brought an older copy).
    let old = MemSource::new();
    for p in w.phone_src.listing() {
        old.put(&p, w.phone_src.get(&p).unwrap());
    }
    let second = engine_live(
        &mut w.phone,
        &mut w.host,
        &w.phone_src,
        position("e1", 20.0),
    );
    let f = sync_pass(
        &mut w.phone,
        &w.phone_src,
        &home,
        &mut w.s.sim,
        &w.host,
        NOW + 2_000,
    );
    // (F-7: an honest home already makes this pass report a rollback.)
    assert!(f.is_empty(), "{f:?}");
    let (slot, newer) = second.stores.last().unwrap().clone();
    assert_eq!(
        w.s.sim.files[&slot], newer,
        "the home holds the newer value"
    );
    // The restored device syncs.
    let mut restored = member_engine(&w.s.f, &w.host, &old, &w.phone_id, NOW + 3_000);
    let f = sync_pass(
        &mut restored,
        &old,
        &home,
        &mut w.s.sim,
        &w.host,
        NOW + 3_000,
    );
    // It learns the newer value itself...
    let g_new = restored.account().live_heads()[0].generation;
    assert_eq!(g_new, OperationHeaderClock::of(&newer));
    // ...but the home now holds the older one.
    let (_, older) = first.stores.last().unwrap().clone();
    let _ = older;
    assert_eq!(
        w.s.sim.files[&slot], newer,
        "the home keeps the newer value: an older head never replaces it; faults {f:?}"
    );
}
struct OperationHeaderClock;
impl OperationHeaderClock {
    fn of(b: &[u8]) -> u64 {
        colophon_core::v05::records::OperationHeader::parse(b)
            .unwrap()
            .0
            .clock
    }
}

/// F-7 (live, exchange): an honest home and one device. The device writes a second live sample
/// and syncs: its remote set still names the slot's first value, so the pass pulls that value
/// back, finds it below the witness and reports `Fault::Rollback` against an honest home.
#[test]
fn check_an_honest_second_live_sample_reports_a_rollback() {
    let mut w = home_world();
    let home = w.s.home.clone();
    engine_live(
        &mut w.phone,
        &mut w.host,
        &w.phone_src,
        position("e1", 10.0),
    );
    let f = sync_pass(
        &mut w.phone,
        &w.phone_src,
        &home,
        &mut w.s.sim,
        &w.host,
        NOW + 1_000,
    );
    assert!(f.is_empty(), "{f:?}");
    engine_live(
        &mut w.phone,
        &mut w.host,
        &w.phone_src,
        position("e1", 20.0),
    );
    let f = sync_pass(
        &mut w.phone,
        &w.phone_src,
        &home,
        &mut w.s.sim,
        &w.host,
        NOW + 2_000,
    );
    assert!(
        f.is_empty(),
        "an honest home is not reported as rolling back: {f:?}"
    );
}

/// A home that lists `n` made-up `ops/` paths and serves garbage at each.
struct Garbage<'a> {
    inner: &'a mut SimHome,
    n: usize,
}
fn garbage_at(i: usize) -> (String, Vec<u8>) {
    let author = format!("{:032x}", 0xabcdef00u64 + i as u64);
    let id = format!("{:032x}", 0x1234u64 + i as u64);
    let path = format!("ops/{author}/{LISTEN}/{:012}-{id}.json", i + 1);
    let bytes = canonical(
        &json!({"body": b64(format!("junk {i}").as_bytes()), "signature": b64(&[1u8; 64])}),
    )
    .unwrap();
    (path, bytes)
}
impl Wire for Garbage<'_> {
    fn call(&mut self, host: &Host, req: &Request, now: i64) -> Response {
        let path = req.url.strip_prefix("https://home.example").unwrap_or("");
        if path.starts_with("/changes") {
            let mut r = self.inner.call(host, req, now);
            let mut v: Value = serde_json::from_slice(&r.body).unwrap();
            for i in 0..self.n {
                let (p, b) = garbage_at(i);
                v["entries"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"path": p, "size": b.len(), "sha256": sha_hex(&b)}));
            }
            r.body = serde_json::to_vec(&v).unwrap();
            return r;
        }
        if let Some(rec) = path.strip_prefix("/records/ops/") {
            for i in 0..self.n {
                let (p, b) = garbage_at(i);
                if p == format!("ops/{rec}") {
                    return Response {
                        status: 200,
                        headers: vec![],
                        body: b,
                    };
                }
            }
        }
        self.inner.call(host, req, now)
    }
}

/// F-5 (exchange, memory): garbage a home serves under made-up paths is refused and not
/// stored, but the account keeps every byte string in memory for the session, and each pass
/// fetches it again. Held records count toward the account's 262,144-object / 1 GiB bound, past
/// which every merge (real records included) is refused whole.
#[test]
fn check_home_garbage_stays_in_the_account() {
    let mut w = home_world();
    let home = w.s.home.clone();
    let before = w.phone.account().records().len();
    let mut wire = Garbage {
        inner: &mut w.s.sim,
        n: 300,
    };
    let (sent1, done) = bounded_pass(
        &mut w.phone,
        &w.phone_src,
        &home,
        &mut wire,
        &w.host,
        NOW + 1_000,
        5_000,
    );
    assert!(done);
    let held = w.phone.account().records().len();
    assert!(
        w.phone_src
            .listing()
            .iter()
            .all(|p| !p.contains("000000000000000000000000abc")),
        "garbage is not stored"
    );
    assert_eq!(
        held, before,
        "garbage is dropped after judgement and never stays in the account"
    );
    let (sent2, _) = bounded_pass(
        &mut w.phone,
        &w.phone_src,
        &home,
        &mut wire,
        &w.host,
        NOW + 2_000,
        5_000,
    );
    let pulls = |s: &[String]| {
        s.iter()
            .filter(|r| r.contains("000000000000000000000000abc"))
            .count()
    };
    assert_eq!(pulls(&sent1), 300);
    eprintln!(
        "garbage pulls: pass 1 {}, pass 2 {}",
        pulls(&sent1),
        pulls(&sent2)
    );
    assert_eq!(
        pulls(&sent2),
        0,
        "and, remembered by digest, not fetched again"
    );
}

/// Tickets: an answer to a ticket that was never issued, or a second answer, is refused.
#[test]
fn check_tickets_cannot_be_forged_or_reused() {
    let mut w = home_world();
    let home = w.s.home.clone();
    w.phone.advance(NOW + 1_000).unwrap();
    let Step::Request(r) = w.phone.exchange_next(&home).unwrap() else {
        panic!()
    };
    assert!(w
        .phone
        .exchange_answer(&home, r.ticket + 1, resp(200, json!({})))
        .is_err());
    assert!(w
        .phone
        .exchange_answer("another", r.ticket, resp(200, json!({})))
        .is_err());
    let a = w.s.sim.call(&w.host, &r, NOW + 1_000);
    w.phone.exchange_answer(&home, r.ticket, a.clone()).unwrap();
    assert!(w.phone.exchange_answer(&home, r.ticket, a).is_err());
}

/// Hostile answers to every request of a pass: random status codes and bodies. No panic, and
/// verified state never moves.
#[test]
fn check_random_answers_do_not_panic_or_move_state() {
    let mut w = home_world();
    let home = w.s.home.clone();
    let want = (w.phone.account().head(), admitted_ids(&w.phone, LISTEN));
    let mut seed: u64 = 0x9e3779b97f4a7c15;
    let mut rnd = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let bodies: Vec<Vec<u8>> = vec![
        vec![],
        b"{}".to_vec(),
        b"null".to_vec(),
        b"[]".to_vec(),
        vec![0xff; 100],
        b"{\"entries\":[{\"path\":\"ops/x\",\"sha256\":1}],\"more\":true,\"cursor\":7}".to_vec(),
        b"{\"objects\":[{\"seq\":18446744073709551615,\"envelope\":{}}],\"more\":true}".to_vec(),
        b"{\"entries\":null,\"receipts\":{},\"more\":\"yes\"}".to_vec(),
        format!("{}{}", "[".repeat(5000), "]".repeat(5000)).into_bytes(),
        b"{\"body\":\"AAAA\",\"signature\":\"AAAA\"}".to_vec(),
    ];
    for round in 0..40 {
        w.phone.advance(NOW + 1_000 + round).unwrap();
        for _ in 0..200 {
            match w.phone.exchange_next(&home).unwrap() {
                Step::Done => break,
                Step::Waiting => panic!(),
                Step::NeedCall(n) => {
                    let _ = w.phone.exchange_provide_call(&home, n.ticket, b"x");
                }
                Step::Request(r) => {
                    let status = [200u16, 201, 404, 409, 410, 412, 421, 422, 428, 500]
                        [(rnd() % 10) as usize];
                    let body = bodies[(rnd() % bodies.len() as u64) as usize].clone();
                    let _ = w.phone.exchange_answer(
                        &home,
                        r.ticket,
                        Response {
                            status,
                            headers: vec![],
                            body,
                        },
                    );
                }
            }
        }
    }
    assert_eq!(
        (w.phone.account().head(), admitted_ids(&w.phone, LISTEN)),
        want
    );
}

// ---------------------------------------------------------------------------------------------
// Live state and revocation.

struct Shared {
    f: Fixture,
    host: Host,
    src: MemSource,
}
fn shared(namespaces: &[&str]) -> Shared {
    let mut f = create(namespaces);
    let host = std::mem::replace(&mut f.host, Host::new());
    f.host = Host::new();
    let src = MemSource::new();
    src.store_account(&f.account);
    Shared { f, host, src }
}
impl Shared {
    fn admit(&mut self, seed: u8, terms: Value) -> String {
        std::mem::swap(&mut self.f.host, &mut self.host);
        let id = self.f.host.identity(seed);
        admit(&mut self.f, &id, "Device", "device", terms.clone(), terms);
        std::mem::swap(&mut self.f.host, &mut self.host);
        self.src.store_account(&self.f.account);
        id
    }
    fn engine(&self, member: &str) -> Engine<MemSource> {
        member_engine(&self.f, &self.host, &self.src, member, NOW)
    }
}

/// F-6 (records, `chain_heads`): a retained live copy under `ops/` (0.3 §5.1, written because a
/// later sample relied on it) is no longer a chain head, so `begin_revoke(Everything)` neither
/// names it as a head nor lists it in `kept`. After the revocation the retained copy is no longer
/// admitted, though the owner asked to keep everything.
#[test]
fn check_keep_everything_revocation_loses_retained_live_copies() {
    let mut s = shared(&[LISTEN]);
    let id = s.admit(31, terms_for(&[(LISTEN, "write")]));
    let ctl_id = s.f.d.clone();
    let mut e = s.engine(&id);
    engine_write(&mut e, &mut s.host, &s.src, LISTEN, "follow", follow());
    engine_live(&mut e, &mut s.host, &s.src, position("e1", 10.0));
    let prior = e.account().live_heads()[0].id.clone();
    let third = engine_live(
        &mut e,
        &mut s.host,
        &s.src,
        json!({"id": "e1", "show": "show", "seconds": 30.0, "expect": prior}),
    );
    let retained = third.stores[0].0.clone();
    assert!(retained.starts_with("ops/"));
    let follow_path = s
        .src
        .listing()
        .into_iter()
        .find(|p| p.starts_with("ops/") && *p != retained)
        .unwrap();
    let reader_id = s.admit(34, terms_for(&[(LISTEN, "read")]));
    let mut r = s.engine(&reader_id);
    r.refresh(s.src.listing()).unwrap();
    assert_eq!(
        r.account().record_verdict(&retained).as_deref(),
        Some("admitted")
    );
    let mut ctl = controller_engine(&s.f, &s.host, &s.src, &ctl_id, NOW);
    let seed = s.host.fresh();
    let action = ctl
        .account()
        .begin_revoke(&id, &RevokeKeep::Everything, &[ctl_id.clone()], seed)
        .unwrap();
    engine_finish(&mut ctl, &s.host, &s.src, action);
    r.refresh(s.src.listing()).unwrap();
    assert_eq!(
        r.account().record_verdict(&follow_path).as_deref(),
        Some("admitted"),
        "the chained record is kept"
    );
    let after = r.account().record_verdict(&retained);
    assert_eq!(
        after.as_deref(),
        Some("admitted"),
        "a keep-everything revocation keeps the retained live copy: {after:?}"
    );
}

/// §9.5 (E12): a `revoke` `heads` item that names a retained live copy starts no walk and is not
/// an error, as an item naming another author's header: the copy is kept only when `kept` lists
/// it. Revoking with exactly that item as a head keeps nothing of it; listing it in `kept` keeps it.
#[test]
fn a_live_copy_named_as_a_revoke_head_is_kept_only_by_kept() {
    for by_kept in [false, true] {
        let mut s = shared(&[LISTEN]);
        let id = s.admit(31, terms_for(&[(LISTEN, "write")]));
        let ctl_id = s.f.d.clone();
        let mut e = s.engine(&id);
        engine_write(&mut e, &mut s.host, &s.src, LISTEN, "follow", follow());
        engine_live(&mut e, &mut s.host, &s.src, position("e1", 10.0));
        let prior = e.account().live_heads()[0].id.clone();
        let third = engine_live(
            &mut e,
            &mut s.host,
            &s.src,
            json!({"id": "e1", "show": "show", "seconds": 30.0, "expect": prior}),
        );
        let (retained, bytes) = third.stores[0].clone();
        assert!(retained.starts_with("ops/"));
        let env: Value = serde_json::from_slice(&bytes).unwrap();
        let body = base64::Engine::decode(&STANDARD, env["body"].as_str().unwrap()).unwrap();
        let digest: String = Sha256::digest(&body)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let reader_id = s.admit(34, terms_for(&[(LISTEN, "read")]));
        let mut r = s.engine(&reader_id);
        r.refresh(s.src.listing()).unwrap();
        assert_eq!(
            r.account().record_verdict(&retained).as_deref(),
            Some("admitted")
        );
        let keep = if by_kept {
            RevokeKeep::Explicit {
                kept: vec![digest.clone()],
                heads: vec![],
            }
        } else {
            RevokeKeep::Explicit {
                kept: vec![],
                heads: vec![(LISTEN.to_string(), digest.clone())],
            }
        };
        let mut ctl = controller_engine(&s.f, &s.host, &s.src, &ctl_id, NOW);
        let seed = s.host.fresh();
        let action = ctl
            .account()
            .begin_revoke(&id, &keep, &[ctl_id.clone()], seed)
            .unwrap();
        engine_finish(&mut ctl, &s.host, &s.src, action);
        r.refresh(s.src.listing()).unwrap();
        let after = r.account().record_verdict(&retained);
        if by_kept {
            assert_eq!(after.as_deref(), Some("admitted"), "kept by name");
        } else {
            assert_ne!(
                after.as_deref(),
                Some("admitted"),
                "a live copy named only as a head is not kept: {after:?}"
            );
        }
    }
}

/// Q2 (live): a `kinds` on another `records` entry does not make the writer caveated in the
/// engine's reading. Under "terms have no ... kinds" it would.
#[test]
fn check_kinds_on_another_entry_is_treated_as_uncaveated() {
    let mut s = shared(&[LISTEN, NOTES]);
    let id = s.admit(
        35,
        json!({"records": [
            {"namespace": LISTEN, "access": "write"},
            {"namespace": NOTES, "access": "write", "kinds": ["createNotebook"]}
        ]}),
    );
    let e = s.engine(&id);
    let seed = s.host.fresh();
    let r = e
        .begin_live_write(LISTEN, "position", position("e1", 1.0), seed)
        .unwrap();
    assert!(r.is_ok(), "{r:?}");
}

/// A member cannot write into another member's slot: a header signed by B at A's slot path is
/// not a live record, and B's own valid sample at a higher generation does not touch A's head.
#[test]
fn check_a_member_cannot_set_another_members_slot() {
    let mut s = shared(&[LISTEN]);
    let a = s.admit(31, terms_for(&[(LISTEN, "write")]));
    let b = s.admit(32, terms_for(&[(LISTEN, "write")]));
    let mut ea = s.engine(&a);
    let mut eb = s.engine(&b);
    let wa = engine_live(&mut ea, &mut s.host, &s.src, position("e1", 10.0));
    let wb = engine_live(
        &mut eb,
        &mut s.host,
        &MemSource::new(),
        position("e1", 99.0),
    );
    let (pa, _) = wa.stores.last().unwrap().clone();
    let (_, bb) = wb.stores.last().unwrap().clone();
    let mut r = s.engine(&a);
    r.apply_live(vec![HeldRecord {
        path: pa.clone(),
        bytes: bb,
    }])
    .unwrap();
    let heads: Vec<_> = r
        .account()
        .live_heads()
        .iter()
        .map(|h| (h.author.clone(), h.path.clone()))
        .collect();
    assert_eq!(heads, vec![(a.clone(), pa)]);
}

// ---------------------------------------------------------------------------------------------
// Incremental equals full: authority arriving after the records it governs.

/// Records arrive before the grant of their author and before a revocation of that author;
/// then the authority arrives. The engine must end where a cold open over the same files does.
#[test]
fn check_records_before_their_grant_and_revocation_equal_a_cold_open() {
    let mut w = notes(6);
    // A second member, granted later, writes; then the first is revoked keeping nothing.
    let second = w.f.host.identity(41);
    admit(
        &mut w.f,
        &second,
        "Tablet",
        "device",
        terms("write"),
        terms("write"),
    );
    let mut sess = member_session(&w.f, &second);
    for i in 0..4 {
        let seed = w.f.host.fresh();
        let action = sess
            .begin_write(
                NOTES,
                "createNotebook",
                json!({"id": format!("t{i}"), "title": "t"}),
                Level::Write,
                seed,
            )
            .unwrap()
            .unwrap();
        let done = run(&mut sess, &w.f.host, action);
        w.src.publish(&done);
    }
    let d = w.f.d.clone();
    let seed = w.f.host.fresh();
    let action =
        w.f.account
            .begin_revoke(&w.member, &RevokeKeep::Nothing, &[d.clone()], seed)
            .unwrap();
    let done = run(&mut w.f.account, &w.f.host, action);
    w.src.publish(&done);
    w.src.store_account(&w.f.account);
    // The cold reference, opened by the controller.
    let cold = controller_engine(&w.f, &w.f.host, &w.src, &d, w.f.account.now_ms());
    let want = admitted_ids(&cold, NOTES);
    let verdicts = |e: &Engine<MemSource>| {
        let mut v: Vec<(String, Option<String>)> = w
            .src
            .listing()
            .into_iter()
            .filter(|p| p.starts_with("ops/"))
            .map(|p| (p.clone(), e.account().record_verdict(&p)))
            .collect();
        v.sort();
        v
    };
    let want_verdicts = verdicts(&cold);
    // A device that holds every record but authority only up to before the second grant.
    let auth: Vec<String> = w
        .src
        .listing()
        .into_iter()
        .filter(|p| p.starts_with("authority/"))
        .collect();
    let max = auth.len();
    for cut in [max - 2, max - 1] {
        let part = MemSource::new();
        for p in w.src.listing() {
            if p.starts_with("authority/") && auth.iter().position(|a| *a == p).unwrap() >= cut {
                continue;
            }
            part.put(&p, w.src.get(&p).unwrap());
        }
        let mut e = controller_engine(&w.f, &w.f.host, &part, &d, w.f.account.now_ms());
        for p in auth.iter().skip(cut) {
            part.put(p, w.src.get(p).unwrap());
        }
        e.refresh(part.listing()).unwrap();
        assert_eq!(admitted_ids(&e, NOTES), want, "cut {cut}");
        assert_eq!(verdicts(&e), want_verdicts, "cut {cut}");
        assert_eq!(e.revision(NOTES), cold.revision(NOTES), "cut {cut}");
    }
}

// ---------------------------------------------------------------------------------------------
// Cost: open, refresh, one write, against a library of N records. N from E6_N (default 300).

#[test]
#[ignore]
fn check_cost_of_open_refresh_and_write() {
    let n: usize = std::env::var("E6_N")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300);
    let t = Instant::now();
    let mut w = notes(n);
    eprintln!("build N={n}: {:?}", t.elapsed());
    // Unit: one full judgement of the N records (N signature checks, N decryptions).
    let records: Vec<HeldRecord> = w
        .src
        .listing()
        .into_iter()
        .filter(|p| p.starts_with("ops/"))
        .map(|p| HeldRecord {
            bytes: w.src.get(&p).unwrap(),
            path: p,
        })
        .collect();
    let eng = open_notes(&w, &w.src, None).unwrap();
    let auth = eng.account();
    let _ = auth;
    drop(eng);
    let t = Instant::now();
    let mut e = open_notes(&w, &w.src, None).unwrap();
    let cold = t.elapsed();
    let st = e.stats();
    eprintln!(
        "cold open+load: {cold:?}; signatures {}, decryptions {}, reads {}",
        st.signatures_verified, st.payloads_decrypted, st.records_read
    );
    let saved = e.save([5; 32]).unwrap();
    let t = Instant::now();
    let r = open_notes(&w, &w.src, Some(&saved)).unwrap();
    let st = r.stats();
    eprintln!(
        "resumed open+load: {:?}; signatures {}, decryptions {}, mode {:?}",
        t.elapsed(),
        st.signatures_verified,
        st.payloads_decrypted,
        r.open_mode()
    );
    let _ = &records;
    // Refresh with one new record.
    write_note(&mut w, n + 1);
    let t = Instant::now();
    e.refresh(w.src.listing()).unwrap();
    let st = e.stats();
    eprintln!(
        "refresh +1: {:?}; walked {}, folds applied {}",
        t.elapsed(),
        st.walked_last,
        st.folds_applied_last
    );
    // One write through the engine.
    let mut host = std::mem::replace(&mut w.f.host, Host::new());
    let t = Instant::now();
    let seed = host.fresh();
    let action = e
        .begin_write(
            NOTES,
            "createNotebook",
            json!({"id": "w1", "title": "w"}),
            Level::Write,
            seed,
        )
        .unwrap()
        .unwrap();
    let begin = t.elapsed();
    let sigs = host.sign(action.steps());
    let t2 = Instant::now();
    e.finish_write(action, sigs).unwrap();
    eprintln!("write: begin {begin:?}, finish {:?}", t2.elapsed());
    // A live write on a listening account is measured separately (see the report).
    let _ = judge_records;
    let _ = STANDARD;
    let _ = Method::Get;
}

/// Cost of live state: L slots held; then one refresh that adds one durable record, and one
/// live write. `judge_live` re-verifies and re-decrypts every held live candidate on every
/// derivation (no memo). L from E6_L (default 200).
#[test]
#[ignore]
fn check_cost_of_live_slots() {
    let l: usize = std::env::var("E6_L")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(200);
    let mut s = shared(&[LISTEN]);
    let id = s.admit(31, terms_for(&[(LISTEN, "write")]));
    let mut e = s.engine(&id);
    engine_write(&mut e, &mut s.host, &s.src, LISTEN, "follow", follow());
    let t = Instant::now();
    for i in 0..l {
        engine_live(
            &mut e,
            &mut s.host,
            &s.src,
            position(&format!("ep{i}"), 1.0),
        );
    }
    eprintln!("L={l}: {l} live writes took {:?}", t.elapsed());
    let mut r = s.engine(&id);
    let t = Instant::now();
    r.refresh(s.src.listing()).unwrap();
    eprintln!("open of a reader with L slots + refresh: {:?}", t.elapsed());
    // One durable record from the writer, then a refresh of the reader.
    engine_write(
        &mut e,
        &mut s.host,
        &s.src,
        LISTEN,
        "queue",
        json!({"episodes": ["ep0"]}),
    );
    let t = Instant::now();
    r.refresh(s.src.listing()).unwrap();
    eprintln!(
        "refresh +1 durable record with L live slots: {:?}",
        t.elapsed()
    );
    let t = Instant::now();
    engine_live(&mut e, &mut s.host, &s.src, position("ep0", 2.0));
    eprintln!("one live write with L live slots: {:?}", t.elapsed());
}

/// F-8 (exchange): the engine pushes whatever bytes its source holds at a listed `ops/` path,
/// even bytes it judged to be no record at all. A garbage twin of a real record (same body,
/// a signature from nobody) planted in a device's folder reaches the home first; under §11.8
/// ("different envelope bytes over an identical body are identical (200, the first envelope is
/// kept)") a conforming home then keeps the twin when the real record arrives, and every other
/// device pulls a twin that is not a record.
#[test]
fn check_the_engine_pushes_a_garbage_twin_it_judged_not_a_record() {
    let mut w = home_world();
    let home = w.s.home.clone();
    // A record the phone writes and does not sync yet.
    let written = engine_write(
        &mut w.phone,
        &mut w.host,
        &w.phone_src,
        LISTEN,
        "queue",
        json!({"episodes": ["e9"]}),
    );
    let (path, real) = written
        .stores
        .iter()
        .find(|(p, _)| p.starts_with("ops/"))
        .unwrap()
        .clone();
    let mut v: Value = serde_json::from_slice(&real).unwrap();
    v["signature"] = json!(b64(&[7u8; 64]));
    let twin = canonical(&v).unwrap();
    // A second device of the account whose folder got the twin (a hostile folder writer).
    let lap_id = w.s.f.host.identity(32);
    let _ = lap_id;
    let src = device_source(&w.s);
    let mut laptop = member_engine(&w.s.f, &w.host, &src, &w.phone_id, NOW);
    src.put(&path, twin.clone());
    laptop.refresh(src.listing()).unwrap();
    assert_eq!(
        laptop
            .account()
            .record_verdict(&path)
            .map(|c| c.starts_with("refused:") || c.starts_with("held:") || c == "admitted"),
        Some(false),
        "the laptop judged it not a record"
    );
    let f = sync_pass(&mut laptop, &src, &home, &mut w.s.sim, &w.host, NOW + 1_000);
    let _ = f;
    assert_ne!(
        w.s.sim.files.get(&path),
        Some(&twin),
        "the engine does not upload bytes it judged not a record"
    );
}

/// A home that requires `Authorization: Colophon` on every request but `/head` and refuses a
/// call it has seen before (§12.3 step 3, §12.4: "Later identical calls are refused:replay").
struct OneShotCalls<'a> {
    inner: &'a mut SimHome,
    seen: std::collections::BTreeSet<String>,
}
impl Wire for OneShotCalls<'_> {
    fn call(&mut self, host: &Host, req: &Request, now: i64) -> Response {
        let path = req.url.strip_prefix("https://home.example").unwrap_or("");
        let auth = req
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
            .map(|(_, v)| v.clone());
        if path != "/head" {
            match auth {
                Some(a) if a.starts_with("Colophon ") && self.seen.insert(a.clone()) => {}
                _ => {
                    return Response {
                        status: 401,
                        headers: vec![],
                        body: vec![],
                    }
                }
            }
        }
        self.inner.call(host, req, now)
    }
}

/// H3 fixed: the engine never reuses a call. A request that needs one says so (`NeedCall`,
/// with the exact audience, purpose and request); the host gives a fresh call for that ticket;
/// the public `/head` and the two submissions that need "no other authorization" carry none.
#[test]
fn check_one_call_is_replayed_on_every_request() {
    let mut w = home_world();
    let home = w.s.home.clone();
    let mut wire = OneShotCalls {
        inner: &mut w.s.sim,
        seen: Default::default(),
    };
    w.phone.advance(NOW + 1_000).unwrap();
    let mut auth_headers = Vec::new();
    let mut needs = Vec::new();
    let mut finished = false;
    for _ in 0..2_000 {
        match w.phone.exchange_next(&home).unwrap() {
            Step::Done => {
                finished = true;
                break;
            }
            Step::Waiting => panic!(),
            Step::NeedCall(n) => {
                assert_eq!(n.audience, "https://home.example");
                assert!(n.purpose == "colophon.home.read" || n.purpose == "colophon.home.write");
                // A call for another ticket is refused; for this one it is bound to it.
                assert!(w
                    .phone
                    .exchange_provide_call(&home, n.ticket + 1, b"x")
                    .is_err());
                needs.push(n.clone());
                w.phone
                    .exchange_provide_call(&home, n.ticket, format!("call-{}", n.ticket).as_bytes())
                    .unwrap();
            }
            Step::Request(r) => {
                if let Some((_, a)) = r.headers.iter().find(|(k, _)| k == "Authorization") {
                    auth_headers.push(a.clone());
                }
                let public = r.url.ends_with("/head")
                    || (r.method == Method::Post
                        && (r.url.ends_with("/authority") || r.url.ends_with("/pending")));
                if public {
                    assert!(
                        !r.headers.iter().any(|(k, _)| k == "Authorization"),
                        "{}",
                        r.url
                    );
                }
                let a = wire.call(&w.host, &r, NOW + 1_000);
                let rep = w.phone.exchange_answer(&home, r.ticket, a).unwrap();
                assert!(
                    !rep.faults.iter().any(|f| matches!(
                        f,
                        colophon_core::v05::engine::exchange::Fault::Unauthorized { .. }
                    )),
                    "{:?}",
                    rep.faults
                );
            }
        }
    }
    assert!(
        finished,
        "the pass completes against a home that refuses every replayed call"
    );
    let distinct: std::collections::BTreeSet<_> = auth_headers.iter().collect();
    assert_eq!(distinct.len(), auth_headers.len(), "no call went out twice");
    assert!(!auth_headers.is_empty() && auth_headers.len() == needs.len());
    // A second pass needs fresh calls again (none carried over).
    // The public head comes first (it carries no call), then the first read needs a new call.
    w.phone.advance(NOW + 2_000).unwrap();
    let Step::Request(head) = w.phone.exchange_next(&home).unwrap() else {
        panic!("the pass starts with the head")
    };
    assert!(head.url.ends_with("/head") && !head.headers.iter().any(|(k, _)| k == "Authorization"));
    let a = wire.call(&w.host, &head, NOW + 2_000);
    w.phone.exchange_answer(&home, head.ticket, a).unwrap();
    let first = w.phone.exchange_next(&home).unwrap();
    assert!(matches!(first, Step::NeedCall(_)), "{first:?}");
}

/// F-11 (exchange): a listed path whose digest differs from the local bytes is neither pulled
/// nor reported (0.3 §8.4 step 3 asks for a reported conflict). With garbage at the path
/// locally and the real record on the home, the device never gets the record.
#[test]
fn check_a_digest_conflict_with_local_garbage_is_silent_and_the_record_never_arrives() {
    let mut w = home_world();
    let home = w.s.home.clone();
    let written = engine_write(
        &mut w.phone,
        &mut w.host,
        &w.phone_src,
        LISTEN,
        "queue",
        json!({"episodes": ["e9"]}),
    );
    let (path, _real) = written
        .stores
        .iter()
        .find(|(p, _)| p.starts_with("ops/"))
        .unwrap()
        .clone();
    let f = sync_pass(
        &mut w.phone,
        &w.phone_src,
        &home,
        &mut w.s.sim,
        &w.host,
        NOW + 1_000,
    );
    assert!(f.is_empty(), "{f:?}");
    // A device whose folder holds garbage at that path.
    let src = device_source(&w.s);
    src.put(&path, b"{}".to_vec());
    let mut other = member_engine(&w.s.f, &w.host, &src, &w.phone_id, NOW + 2_000);
    let f = sync_pass(&mut other, &src, &home, &mut w.s.sim, &w.host, NOW + 2_000);
    let _ = f;
    assert_ne!(
        src.get(&path),
        Some(b"{}".to_vec()),
        "the real record arrives over the garbage"
    );
    assert_eq!(
        other.account().record_verdict(&path).as_deref(),
        Some("admitted")
    );
}
