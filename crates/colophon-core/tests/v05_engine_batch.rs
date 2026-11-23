//! Batch record reads in the exchange (proposed 0.6, `docs/colophon-0.6-w1-batch.md`): a home
//! that serves them is read in batches of at most 256 paths, one call each, instead of one GET
//! and one call per record; a home that does not (a 0.5 home answers 405) is read singly in the
//! same pass and not asked again this session. Every batch item is judged as a single GET's
//! answer is, and an answer that is not exactly the documented shape fails the whole batch and
//! is read singly, never used as data.
#![allow(clippy::unwrap_used, clippy::too_many_arguments)]
#[path = "v05_engine_support/mod.rs"]
mod support;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use colophon_core::v05::calls::{
    verify_home_batch, verify_home_request, AccountView, CallConfig, HomeRequest,
};
use colophon_core::v05::engine::exchange::{Fault, Request, Response, Step};
use colophon_core::v05::engine::Engine;
use colophon_core::v05::history::{verify_history, Objects, Persisted};
use colophon_core::v05::replay::MemoryReplayStore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use support::*;

const NOW: i64 = T0 + 3 * HOUR;
const NS: &str = "notes";
const BASE: &str = "https://home.example";

/// A writer that has written `n` notebooks and pushed them to a home that requires calls, and a
/// reader's engine that holds the authority only.
struct World {
    s: Setup,
    host: Host,
    reader: String,
}
fn world(n: usize) -> World {
    let (mut s, ids) = setup(NS, &[("Writer", 31, "write"), ("Reader", 32, "write")]);
    let mut host = std::mem::replace(&mut s.f.host, Host::new());
    let src = device_source(&s);
    let mut w = member_engine(&s.f, &host, &src, &ids[0], NOW);
    for i in 0..n {
        engine_write(
            &mut w,
            &mut host,
            &src,
            NS,
            "createNotebook",
            json!({"id": format!("n{i}"), "title": format!("Notebook {i}")}),
        );
    }
    s.sim.require_calls = true;
    let home = s.home.clone();
    let f = sync_pass(&mut w, &src, &home, &mut s.sim, &host, NOW);
    assert!(f.is_empty(), "{f:?}");
    World {
        s,
        host,
        reader: ids[1].clone(),
    }
}
impl World {
    fn reader(&self) -> (Engine<MemSource>, MemSource) {
        let src = device_source(&self.s);
        let e = member_engine(&self.s.f, &self.host, &src, &self.reader, NOW);
        (e, src)
    }
}
fn view(e: &Engine<MemSource>) -> colophon_core::model::NamespaceView {
    match e.view(NS).unwrap() {
        colophon_core::model::Outcome::Success { value, .. } => value,
        colophon_core::model::Outcome::Failure { reason, .. } => panic!("{reason}"),
    }
}
/// Admitted records of the namespace.
fn notebooks(e: &Engine<MemSource>) -> usize {
    view(e).admitted.len()
}
fn count(reqs: &[String], prefix: &str) -> usize {
    reqs.iter().filter(|r| r.starts_with(prefix)).count()
}

#[test]
fn a_home_that_serves_batches_is_read_in_ceil_n_over_256_calls_instead_of_n() {
    const N: usize = 600;
    let mut w = world(N);
    let home = w.s.home.clone();

    // Before: the same home answering batches 405, as 0.5.2 does.
    let mut old = w.s.sim.clone();
    old.batch = false;
    old.requests.clear();
    let (mut a, a_src) = w.reader();
    let f = sync_pass(&mut a, &a_src, &home, &mut old, &w.host, NOW + 1_000);
    assert!(f.is_empty(), "a refused batch is no fault: {f:?}");
    assert_eq!(notebooks(&a), N);
    assert_eq!(a.exchange_batch_support(&home), Some(false));
    let before = old.requests.clone();
    assert_eq!(count(&before, "Get /records/ops/"), N);
    assert_eq!(count(&before, "Post /records/batch"), 1, "tried once");
    // Remembered for the session: the next pass does not ask again.
    let mark = old.requests.len();
    let f = sync_pass(&mut a, &a_src, &home, &mut old, &w.host, NOW + 2_000);
    assert!(f.is_empty(), "{f:?}");
    assert_eq!(count(&old.requests[mark..], "Post /records/batch"), 0);

    // After: batches.
    w.s.sim.requests.clear();
    let (mut b, b_src) = w.reader();
    let f = sync_pass(&mut b, &b_src, &home, &mut w.s.sim, &w.host, NOW + 1_000);
    assert!(f.is_empty(), "{f:?}");
    assert_eq!(notebooks(&b), N);
    assert_eq!(b.exchange_batch_support(&home), Some(true));
    let after = w.s.sim.requests.clone();
    assert_eq!(count(&after, "Get /records/ops/"), 0);
    assert_eq!(count(&after, "Post /records/batch"), N.div_ceil(256));
    println!(
        "cold catch-up of {N} records: {} round trips per-record, {} with batches",
        before.len(),
        after.len()
    );
    assert!(after.len() + N - N.div_ceil(256) <= before.len());
    // Same records, same state.
    assert_eq!(a.account().head(), b.account().head());
    assert_eq!(view(&a).state, view(&b).state);
    let ra: Vec<String> = a_src
        .listing()
        .into_iter()
        .filter(|p| p.starts_with("ops/"))
        .collect();
    let rb: Vec<String> = b_src
        .listing()
        .into_iter()
        .filter(|p| p.starts_with("ops/"))
        .collect();
    assert_eq!(ra, rb);
}

#[test]
fn a_lone_record_is_read_singly_and_a_home_that_needs_no_calls_is_never_batched() {
    let mut w = world(1);
    let home = w.s.home.clone();
    w.s.sim.requests.clear();
    let (mut e, src) = w.reader();
    let f = sync_pass(&mut e, &src, &home, &mut w.s.sim, &w.host, NOW + 1_000);
    assert!(f.is_empty(), "{f:?}");
    assert_eq!(count(&w.s.sim.requests, "Post /records/batch"), 0);
    assert_eq!(count(&w.s.sim.requests, "Get /records/ops/"), 1);

    // A home whose reads carry no call costs nothing per GET: batching it would add signatures.
    let mut w = world(5);
    w.s.sim.require_calls = false;
    w.s.sim.requests.clear();
    let (mut e, src) = w.reader();
    let f = sync_pass(&mut e, &src, &home, &mut w.s.sim, &w.host, NOW + 1_000);
    assert!(f.is_empty(), "{f:?}");
    assert_eq!(count(&w.s.sim.requests, "Post /records/batch"), 0);
    assert_eq!(notebooks(&e), 5);
}

#[test]
fn a_truncated_answer_is_continued_with_a_fresh_call_and_a_413_item_is_read_singly() {
    const N: usize = 40;
    let mut w = world(N);
    let home = w.s.home.clone();
    // An answer budget that fits a few records only.
    let one =
        w.s.sim
            .files
            .iter()
            .find(|(p, _)| p.starts_with("ops/"))
            .map(|(_, b)| b.len())
            .unwrap();
    w.s.sim.batch_budget = one * 6;
    w.s.sim.requests.clear();
    let (mut e, src) = w.reader();
    let mut calls = Vec::new();
    e.advance(NOW + 1_000).unwrap();
    e.refresh(src.listing()).unwrap();
    let mut faults = Vec::new();
    loop {
        match e.exchange_next(&home).unwrap() {
            Step::Done => break,
            Step::Waiting => panic!(),
            Step::NeedCall(n) => {
                calls.push((
                    n.ticket,
                    n.path.clone(),
                    n.purpose.clone(),
                    n.body_sha256.clone(),
                ));
                e.exchange_provide_call(&home, n.ticket, b"call").unwrap();
            }
            Step::Request(r) => {
                if r.url.ends_with("/records/batch") {
                    // Each batch carries the call made for exactly its body.
                    let sha = hex(&Sha256::digest(&r.body));
                    assert!(calls.iter().any(|(t, p, purpose, b)| *t == r.ticket
                        && p == "/records/batch"
                        && purpose == "colophon.home.read"
                        && *b == sha));
                }
                let a = w.s.sim.call(&w.host, &r, NOW + 1_000);
                let rep = e.exchange_answer(&home, r.ticket, a).unwrap();
                src.publish_stores(&rep.store);
                faults.extend(rep.faults);
            }
        }
    }
    assert!(faults.is_empty(), "{faults:?}");
    assert_eq!(notebooks(&e), N);
    let batches = count(&w.s.sim.requests, "Post /records/batch");
    assert!(batches > 1, "the answer was continued: {batches}");
    // No call was reused: every batch had its own.
    let batch_calls = calls.iter().filter(|c| c.1 == "/records/batch").count();
    assert_eq!(batch_calls, batches);

    // A record larger than the whole budget comes back 413 and is read with a single GET.
    let mut w = world(3);
    let one =
        w.s.sim
            .files
            .iter()
            .find(|(p, _)| p.starts_with("ops/"))
            .map(|(_, b)| b.len())
            .unwrap();
    w.s.sim.batch_budget = one / 2;
    w.s.sim.requests.clear();
    let (mut e, src) = w.reader();
    let f = sync_pass(&mut e, &src, &home, &mut w.s.sim, &w.host, NOW + 1_000);
    assert!(f.is_empty(), "{f:?}");
    assert_eq!(notebooks(&e), 3);
    assert_eq!(count(&w.s.sim.requests, "Get /records/ops/"), 3);
}

/// What a hostile home does to its batch answers.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Hostile {
    /// Item 0 carries another record's bytes, with an etag that matches them.
    WrongRecord,
    /// An extra item for a path that was not asked for.
    Extra,
    /// Item 0's etag does not match its bytes.
    Corrupt,
    /// The last item is dropped, `truncated` stays false.
    Partial,
    /// Items 0 and 1 swapped.
    Reordered,
    /// The whole batch fails with 500.
    Fails,
    /// Not JSON.
    Garbage,
}
struct Wrapped<'a> {
    sim: &'a mut SimHome,
    mode: Hostile,
    hits: usize,
}
impl Wire for Wrapped<'_> {
    fn call(&mut self, host: &Host, req: &Request, now: i64) -> Response {
        let mut r = self.sim.call(host, req, now);
        if !req.url.ends_with("/records/batch") || r.status != 200 {
            return r;
        }
        self.hits += 1;
        let mut v: Value = serde_json::from_slice(&r.body).unwrap();
        let items = v["records"].as_array_mut().unwrap();
        match self.mode {
            Hostile::WrongRecord => {
                let other = items[1]["bytes"].clone();
                let etag = items[1]["etag"].clone();
                items[0]["bytes"] = other;
                items[0]["etag"] = etag;
            }
            Hostile::Extra => items.push(json!({"path": "ops/elsewhere.json", "status": 404})),
            Hostile::Corrupt => items[0]["etag"] = json!(format!("\"{}\"", "0".repeat(64))),
            Hostile::Partial => {
                items.pop();
            }
            Hostile::Reordered => items.swap(0, 1),
            Hostile::Fails => {
                return Response {
                    status: 500,
                    headers: vec![],
                    body: b"{}".to_vec(),
                }
            }
            Hostile::Garbage => {
                r.body = b"not json".to_vec();
                return r;
            }
        }
        r.body = serde_json::to_vec(&v).unwrap();
        r
    }
}

#[test]
fn a_hostile_batch_answer_is_never_data_and_the_records_are_read_singly_in_the_same_pass() {
    const N: usize = 6;
    for mode in [
        Hostile::WrongRecord,
        Hostile::Extra,
        Hostile::Corrupt,
        Hostile::Partial,
        Hostile::Reordered,
        Hostile::Fails,
        Hostile::Garbage,
    ] {
        let mut w = world(N);
        let home = w.s.home.clone();
        let (mut e, src) = w.reader();
        let mut wire = Wrapped {
            sim: &mut w.s.sim,
            mode,
            hits: 0,
        };
        wire.sim.requests.clear();
        let faults = sync_pass(&mut e, &src, &home, &mut wire, &w.host, NOW + 1_000);
        assert_eq!(wire.hits, 1, "{mode:?}: one batch, then singles");
        let singles = count(&wire.sim.requests, "Get /records/ops/");
        // Nothing the home put in a bad batch is held: every record present was read singly and
        // verified, or (for the one wrong item of a well-formed answer) refused as a single GET
        // of other bytes would be.
        match mode {
            Hostile::WrongRecord => {
                assert!(
                    faults.iter().any(|f| matches!(f, Fault::Mismatch { .. })),
                    "{faults:?}"
                );
                assert_eq!(notebooks(&e), N - 1, "the wrong item alone is refused");
                assert_eq!(singles, 0, "a well-formed answer is not read again");
                // The next (honest) pass lists again and fetches what was refused.
                let f = sync_pass(&mut e, &src, &home, &mut *wire.sim, &w.host, NOW + 2_000);
                assert!(f.is_empty(), "{f:?}");
                assert_eq!(notebooks(&e), N);
            }
            Hostile::Fails => {
                assert!(
                    faults
                        .iter()
                        .any(|f| matches!(f, Fault::Status { status: 500, .. })),
                    "{faults:?}"
                );
                assert_eq!(singles, N);
                assert_eq!(notebooks(&e), N);
            }
            _ => {
                assert!(
                    faults.iter().any(|f| matches!(f, Fault::Malformed { .. })),
                    "{mode:?}: {faults:?}"
                );
                assert!(
                    faults.iter().all(|f| matches!(f, Fault::Malformed { .. })),
                    "{mode:?}: {faults:?}"
                );
                assert_eq!(singles, N, "{mode:?}");
                assert_eq!(notebooks(&e), N, "{mode:?}");
            }
        }
        // Batches stay on for the session after a bad answer (only a refusal turns them off).
        assert_ne!(e.exchange_batch_support(&home), Some(false), "{mode:?}");
    }
}

/// A home that judges every call it is sent with the home's own rule: singles with
/// `verify_home_request`, batches with `verify_home_batch` (each path as a single GET would be).
struct Judging<'a> {
    sim: &'a mut SimHome,
    batches_accepted: usize,
    refused: Vec<String>,
}
impl Judging<'_> {
    fn view(&self, host: &Host, now: i64) -> AccountView {
        let objects = Objects {
            entries: self.sim.entries.values().cloned().collect(),
            heads: self.sim.head_env(host, now).into_iter().collect(),
            ..Default::default()
        };
        let verdict = verify_history(&objects, &Persisted::default(), now);
        AccountView::from_history_verifier(&verdict, &objects, now).unwrap()
    }
}
impl Wire for Judging<'_> {
    fn call(&mut self, host: &Host, req: &Request, now: i64) -> Response {
        let path = req.url.strip_prefix(BASE).unwrap().to_string();
        let call = req.headers.iter().find_map(|(k, v)| {
            (k == "Authorization")
                .then(|| v.strip_prefix("Colophon "))
                .flatten()
        });
        if let Some(call) = call {
            let bytes = URL_SAFE_NO_PAD.decode(call).unwrap();
            let view = self.view(host, now);
            let audiences = [BASE.to_string()];
            let origins = Default::default();
            let cfg = CallConfig {
                now_ms: now,
                audiences: &audiences,
                call_origins: &origins,
                controller_purposes: &[],
                home_endpoints: &audiences,
            };
            let sha = hex(&Sha256::digest(&req.body));
            let hr = HomeRequest {
                method: req.method.as_str(),
                path: &path,
                body_sha256: &sha,
                writes: &[],
            };
            let mut store = MemoryReplayStore::new();
            let verdict = if path == "/records/batch" {
                let v: Value = serde_json::from_slice(&req.body).unwrap();
                let paths: Vec<String> = v["paths"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|p| p.as_str().unwrap().to_string())
                    .collect();
                verify_home_batch(&bytes, &view, &cfg, &mut store, &hr, &paths).map(|_| ())
            } else if req.method.as_str() == "GET" {
                verify_home_request(&bytes, &view, &cfg, &mut store, &hr).map(|_| ())
            } else {
                Ok(())
            };
            if let Err(e) = verdict {
                self.refused.push(format!("{path}: {}", e.code()));
                return Response {
                    status: 403,
                    headers: vec![],
                    body: json!({"result": e.code()}).to_string().into_bytes(),
                };
            }
            if path == "/records/batch" {
                self.batches_accepted += 1;
            }
        }
        self.sim.call(host, req, now)
    }
}

#[test]
fn the_batch_call_the_engine_builds_is_the_one_the_home_accepts() {
    const N: usize = 300;
    let mut w = world(N);
    let home = w.s.home.clone();
    let (mut e, src) = w.reader();
    let me = w.reader.clone();
    let mut wire = Judging {
        sim: &mut w.s.sim,
        batches_accepted: 0,
        refused: Vec::new(),
    };
    let mut host = std::mem::replace(&mut w.host, Host::new());
    e.advance(NOW + 1_000).unwrap();
    e.refresh(src.listing()).unwrap();
    let mut faults = Vec::new();
    loop {
        match e.exchange_next(&home).unwrap() {
            Step::Done => break,
            Step::Waiting => panic!(),
            Step::NeedCall(n) => {
                let key = host.ids[&me].public().signing;
                let action = e
                    .exchange_begin_call(&home, n.ticket, &key, host.fresh())
                    .unwrap();
                let sigs = host.sign(action.steps());
                let written = e.finish_write(action, sigs).unwrap();
                e.exchange_provide_call(&home, n.ticket, &written.artifact.unwrap())
                    .unwrap();
            }
            Step::Request(r) => {
                let a = wire.call(&host, &r, NOW + 1_000);
                let rep = e.exchange_answer(&home, r.ticket, a).unwrap();
                src.publish_stores(&rep.store);
                faults.extend(rep.faults);
            }
        }
    }
    assert!(faults.is_empty(), "{faults:?}");
    assert!(wire.refused.is_empty(), "{:?}", wire.refused);
    assert_eq!(wire.batches_accepted, N.div_ceil(256));
    assert_eq!(notebooks(&e), N);
    w.host = host;
}

/// The measurement behind `docs/colophon-0.6-sync-stream.md`: a cold catch-up of 2,000 records,
/// per record and with batches. Opt in (it writes 2,000 records):
/// `cargo test -p colophon-core --release --test v05_engine_batch -- --ignored --nocapture`.
#[test]
#[ignore = "measurement: writes 2,000 records"]
fn measure_a_cold_catch_up_of_2000_records() {
    const N: usize = 2_000;
    let w = world(N);
    let home = w.s.home.clone();
    for batch in [false, true] {
        let mut sim = w.s.sim.clone();
        sim.batch = batch;
        sim.requests.clear();
        let (mut e, src) = w.reader();
        let f = sync_pass(&mut e, &src, &home, &mut sim, &w.host, NOW + 1_000);
        assert!(f.is_empty(), "{f:?}");
        assert_eq!(notebooks(&e), N);
        let mut kinds: std::collections::BTreeMap<String, usize> = Default::default();
        for r in &sim.requests {
            let k = r
                .split('/')
                .take(3)
                .collect::<Vec<_>>()
                .join("/")
                .split('?')
                .next()
                .unwrap()
                .to_string();
            *kinds.entry(k).or_default() += 1;
        }
        println!(
            "batch {batch}: {} round trips: {kinds:?}",
            sim.requests.len()
        );
    }
}
