//! The rest of the relay as a home (H2), against the real relay (`bun relay/server.js` with the
//! module): pending objects kept until settled; a fork held, served and resolved; a late veto
//! stored with another home's receipt; an offline home caught up; a Swift library's succession
//! published to and fetched from a home.
#![allow(
    clippy::unwrap_used,
    clippy::too_many_arguments,
    clippy::cloned_ref_to_slice_refs,
    dead_code
)]
#[path = "../../colophon-core/tests/v05_engine_support/mod.rs"]
mod support;
mod support_relay;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use colophon_core::v05::account::Change;
use colophon_core::v05::engine::Engine;
use colophon_core::v05::write::authority::TransitionRule;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use support::*;
use support_relay::*;

const NOW: i64 = T0 + 3 * HOUR;
const NS: &str = "listening.podcasts";

struct World {
    f: Fixture,
    host: Host,
    a: Relay,
    b: Option<Relay>,
    ka: HomeKeys,
    kb: HomeKeys,
    ha: String,
    hb: String,
    pa: u16,
    pb: u16,
    src: MemSource,
    /// Removed when the world is dropped (declared last: the relays stop first).
    scratch: Vec<Scratch>,
}

/// An account (history `history`, `headQuorum` `quorum`) naming one home, or two; `run_b`: the
/// second is running. The whole history is uploaded to each running home as a first upload.
fn world(name: &str, history: &str, quorum: u64, two: bool, run_b: bool) -> Option<World> {
    prerequisites()?;
    let (ka, kb) = (HomeKeys::new(0x77), HomeKeys::new(0x78));
    let mut f = create_with(&[NS], history, quorum);
    if two {
        appoint_homes(&mut f, &[(&ka, BASE_A), (&kb, BASE_B)]);
    } else {
        appoint_homes(&mut f, &[(&ka, BASE_A)]);
    }
    let (pa, pb) = (free_port(), free_port());
    let account = f.account.id().as_str().to_string();
    let scratch = vec![Scratch::new(&format!("h2-{name}-a")), Scratch::new(&format!("h2-{name}-b"))];
    let a = Relay::start_on(&ka, &account, BASE_A, scratch[0].path(), T0, &[(BASE_B, pb)], pa);
    first_upload(&a, &f, T0 + 1_000);
    let b = run_b.then(|| {
        let b = Relay::start_on(&kb, &account, BASE_B, scratch[1].path(), T0, &[(BASE_A, pa)], pb);
        first_upload(&b, &f, T0 + 1_000);
        b
    });
    let src = MemSource::new();
    src.store_account(&f.account);
    let host = std::mem::replace(&mut f.host, Host::new());
    Some(World { host, src, ha: ka.id.clone(), hb: kb.id.clone(), f, a, b, ka, kb, pa, pb, scratch })
}

impl World {
    fn clocks(&self, ms: i64) {
        self.a.set_clock(ms);
        if let Some(b) = &self.b {
            b.set_clock(ms);
        }
    }
    fn wire(&self) -> RealRelay<'_> {
        let mut v = vec![&self.a];
        if let Some(b) = &self.b {
            v.push(b);
        }
        RealRelay::many(v)
    }
    fn controller(&self, now: i64) -> Engine<MemSource> {
        controller_engine(&self.f, &self.host, &self.src, &self.f.d.clone(), now)
    }
    /// One pass with each running home, asserting it reported no fault.
    fn pass_all(&self, e: &mut Engine<MemSource>, now: i64) {
        let mut wire = self.wire();
        let mut homes = vec![self.ha.clone()];
        if self.b.is_some() {
            homes.push(self.hb.clone());
        }
        for (i, h) in homes.iter().enumerate() {
            let faults = relay_pass(e, &self.src, h, &mut wire, &self.host, now + i as i64);
            assert!(faults.is_empty(), "{h}: {faults:?}");
        }
    }
}

/// A policy transition signed by `by` (one unit: not a full set, so it has a delay and can be
/// vetoed). Returns its digest.
fn propose_by(w: &World, ctl: &mut Engine<MemSource>, window: u64, by: &[String]) -> String {
    let had: Vec<String> = ctl.account().pending().iter().map(|t| t.digest.clone()).collect();
    let action = ctl
        .account()
        .begin_transition(&Change::policy(json!({"callWindow": window})), by, TransitionRule::Control)
        .unwrap();
    engine_finish(ctl, &w.host, &w.src, action);
    ctl.account().pending().iter().map(|t| t.digest.clone()).find(|d| !had.contains(d)).unwrap()
}
/// The owner's veto of `digest` from the passkey's unit. Returns the veto envelope.
fn veto_of(w: &World, ctl: &mut Engine<MemSource>, digest: &str) -> Value {
    let action = ctl.account().begin_veto(digest, &[w.f.p.clone()]).unwrap();
    engine_finish(ctl, &w.host, &w.src, action);
    ctl.account()
        .objects()
        .pending
        .iter()
        .map(|b| serde_json::from_slice::<Value>(b).unwrap())
        .find(|v| v.get("body").is_some() && body_of(v)["protocol"] == "colophon/veto/5" && body_of(v)["transition"] == digest)
        .expect("the veto")
}
fn body_of(env: &Value) -> Value {
    serde_json::from_slice(&STANDARD.decode(env["body"].as_str().unwrap()).unwrap()).unwrap()
}
fn digest_of(env: &Value) -> String {
    colophon_core::v05::encoding::digest(&STANDARD.decode(env["body"].as_str().unwrap()).unwrap())
}
fn pending_env(ctl: &Engine<MemSource>, digest: &str) -> Value {
    for p in &ctl.account().objects().pending {
        if pending_path(p).contains(digest) {
            return serde_json::from_slice(p).unwrap();
        }
    }
    panic!("no such pending object");
}
fn pending_list(relay: &Relay) -> Vec<Value> {
    let (s, b) = relay.get("/pending?after=0&limit=64");
    assert_eq!(s, 200);
    serde_json::from_slice::<Value>(&b).unwrap()["objects"].as_array().unwrap().clone()
}
fn listed(relay: &Relay, kind: &str) -> BTreeSet<String> {
    pending_list(relay)
        .iter()
        .filter(|o| o["kind"] == kind)
        .map(|o| o["digest"].as_str().unwrap().to_string())
        .collect()
}
fn entries(relay: &Relay) -> Vec<Value> {
    let (s, b) = relay.get("/authority?after=0&limit=64");
    assert_eq!(s, 200, "{}", String::from_utf8_lossy(&b));
    serde_json::from_slice::<Value>(&b).unwrap()["entries"].as_array().unwrap().clone()
}
fn kinds_at(relay: &Relay) -> Vec<String> {
    entries(relay).iter().map(|e| body_of(e)["kind"].as_str().unwrap().to_string()).collect()
}
/// The head a home serves: `(seq, digest, issued)`, or `None` (404).
fn head_at(relay: &Relay) -> Option<(u64, String, String)> {
    let (s, b) = relay.get("/head");
    if s != 200 {
        return None;
    }
    let h = body_of(&serde_json::from_slice(&b).unwrap());
    Some((
        h["authority"]["seq"].as_u64().unwrap(),
        h["authority"]["digest"].as_str().unwrap().to_string(),
        h["issued"].as_str().unwrap().to_string(),
    ))
}


// ---------------------------------------------------------------------------------------------
// 1. Pending objects are kept until settled.

/// A home restarted on the same data directory (the process killed, then started again).
fn restarted(w: &mut World, at: i64) {
    let a = std::mem::replace(&mut w.a, Relay::attached(0, BASE_A, "", w.scratch[0].path()));
    w.a = a.restart(&HomeKeys::new(0x77), at, &[]);
}

/// A transition is admitted and receipted. Killed and started again three times before it is
/// due, the home still stores and lists it with its receipt and the same cursors. Due, the home
/// records its `activate` and `final`: it leaves the listing (§14) and stays stored. A second
/// transition, vetoed in time, is settled by the `vetoed` the home records at once (§13.1); the
/// transition and the veto stay stored, across another restart.
#[test]
fn pending_objects_are_kept_until_settled_across_restarts() {
    let Some(mut w) = world("kept", "public", 1, false, false) else {
        return;
    };
    let mut ctl = w.controller(NOW);
    w.clocks(NOW);
    let d = w.f.d.clone();
    let t1 = propose_by(&w, &mut ctl, 600, &[d.clone()]);
    w.pass_all(&mut ctl, NOW + 1_000);
    assert_eq!(listed(&w.a, "transition"), BTreeSet::from([t1.clone()]));
    assert_eq!(listed(&w.a, "receipt").len(), 1);
    let before = pending_list(&w.a);
    for (i, at) in [NOW + 10_000, NOW + 600_000, NOW + 3_000_000].into_iter().enumerate() {
        restarted(&mut w, at);
        assert_eq!(pending_list(&w.a), before, "restart {i}: the same objects, the same cursors");
        assert_eq!(w.a.get(&format!("/pending/{t1}")).0, 200, "restart {i}");
    }
    // Due: `activate`, then `final` once the home's head covers it.
    let n = kinds_at(&w.a).len();
    w.a.set_clock(NOW + HOUR + 400_000);
    std::thread::sleep(std::time::Duration::from_millis(500));
    // A head over the activation needs a later `issued` than one signed at the same reading.
    w.a.set_clock(NOW + HOUR + 402_000);
    eventually("activate and final", 60, || kinds_at(&w.a).len() >= n + 2);
    assert_eq!(kinds_at(&w.a)[n..], ["activate", "final"]);
    assert!(listed(&w.a, "transition").is_empty(), "settled: no longer listed");
    // A second transition, vetoed in time by the other unit.
    let at = NOW + HOUR + 500_000;
    w.a.set_clock(at);
    let mut ctl = w.controller(at);
    w.pass_all(&mut ctl, at);
    let t2 = propose_by(&w, &mut ctl, 601, &[d]);
    w.pass_all(&mut ctl, at + 1_000);
    assert_eq!(listed(&w.a, "transition"), BTreeSet::from([t2.clone()]));
    let v = digest_of(&veto_of(&w, &mut ctl, &t2));
    w.pass_all(&mut ctl, at + 2_000);
    eventually("vetoed", 30, || kinds_at(&w.a).len() >= n + 3);
    assert_eq!(kinds_at(&w.a)[n + 2], "vetoed");
    restarted(&mut w, at + 10_000);
    assert!(listed(&w.a, "transition").is_empty() && listed(&w.a, "veto").is_empty());
    for (dir, d) in [("transitions", &t1), ("transitions", &t2), ("vetoes", &v)] {
        let (s, b) = w.a.get(&format!("/records/{dir}/{d}.json"));
        assert_eq!(s, 200, "{dir}/{d} is kept");
        assert_eq!(digest_of(&serde_json::from_slice(&b).unwrap()), *d);
    }
    let mut ctl = w.controller(at + 20_000);
    w.pass_all(&mut ctl, at + 20_000);
    assert!(ctl.account().pending().is_empty(), "the client holds the settled history");
}

// ---------------------------------------------------------------------------------------------
// 2. Forks at a home.

/// Approve a new device through `ctl` (an immediate entry); returns the entry and its seq.
fn approve(f: &Fixture, host: &mut Host, ctl: &mut Engine<MemSource>, src: &MemSource, n: u8, at: i64) -> (u64, Value) {
    let id = host.identity(n);
    let req = request_for(f, host, &id, "Phone", "device", terms_for(&[(NS, "write")]), at);
    let seed = host.fresh();
    let action = ctl
        .account()
        .begin_approve(&req.raw, terms_for(&[(NS, "write")]), &[f.d.clone()], seed)
        .unwrap();
    engine_finish(ctl, host, src, action);
    let (seq, e) = ctl
        .account()
        .objects()
        .entries
        .iter()
        .map(|e| (entry_seq(e), serde_json::from_slice::<Value>(e).unwrap()))
        .max_by_key(|(s, _)| *s)
        .unwrap();
    (seq, e)
}
/// A pass that stops where the engine needs a call: a device at a fork can make none (§8.6
/// rule 3), but it reads a `public` history and the pending feed without one.
fn pass_without_calls(e: &mut Engine<MemSource>, src: &MemSource, home: &str, wire: &mut RealRelay, host: &Host, now: i64) {
    use colophon_core::v05::engine::exchange::Step;
    e.advance(now).unwrap();
    e.refresh(src.listing()).unwrap();
    loop {
        match e.exchange_next(home).unwrap() {
            Step::Request(r) => {
                let a = wire.call(host, &r, now);
                let report = e.exchange_answer(home, r.ticket, a).unwrap();
                if !report.faults.is_empty() {
                    eprintln!("pass without calls: {} {:?}", r.url, report.faults);
                }
                src.publish_stores(&report.store);
            }
            Step::NeedCall(_) | Step::Waiting => {
                let _ = e.exchange_abort(home);
                return;
            }
            Step::Done => return,
        }
    }
}
/// A head over `(seq, digest)` signed with a home's key: what that home would sign.
fn head_by(keys: &HomeKeys, account: &str, seq: u64, digest: &str, issued: i64) -> Value {
    let body = colophon_core::v05::encoding::canonical(&json!({
        "protocol": "colophon/head/5", "account": account,
        "authority": {"seq": seq, "digest": digest},
        "issued": colophon_core::v05::write::format_date(issued), "by": keys.id,
    }))
    .unwrap();
    let sig = keys.sign(&body).signature;
    json!({"body": STANDARD.encode(&body), "signature": STANDARD.encode(sig)})
}
fn put(relay: &Relay, path: &str, body: &Value) -> (u16, Value) {
    let (s, _, b) = http(
        relay.port,
        "PUT",
        &relay.url(path),
        &[("Content-Type".into(), "application/json".into())],
        body.to_string().as_bytes(),
    );
    (s, serde_json::from_slice(&b).unwrap_or(Value::Null))
}
fn at_seq(relay: &Relay, seq: u64) -> Vec<String> {
    let (s, b) = relay.get(&format!("/authority?after={}&limit=64", seq - 1));
    assert_eq!(s, 200);
    serde_json::from_slice::<Value>(&b).unwrap()["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| body_of(e)["seq"].as_u64() == Some(seq))
        .map(digest_of)
        .collect()
}

/// Two devices of the owner each sign an entry at the same seq (X and Y). The primary home A
/// stores X and signs a head over it; A then also signs a head over Y (an equivocating primary,
/// its key used by the test), which reaches the second home B with Y. B now holds a fork (§8.6
/// rule 3: heads for both): it serves both candidates, signs no head, and refuses what depends on
/// either branch (`refused:fork`) — an entry on X's branch and an ordinary transition — but it
/// receipts a `resolve` keeping X (judged on X's branch) and stores the `activate` that records
/// it, and what follows. A device holding the fork, and one that only ever held X, then sync to
/// the resolved history from B.
#[test]
fn a_home_holding_a_fork_serves_it_refuses_what_depends_on_it_and_admits_a_resolve() {
    let Some(mut w) = world("fork", "public", 1, true, true) else {
        return;
    };
    let b = w.b.as_ref().unwrap();
    let account = w.f.account.id().as_str().to_string();
    let t = NOW;
    w.clocks(t);
    // Two devices, each from the history before the fork.
    let src_y = MemSource::new();
    src_y.store_account(&w.f.account);
    let src_both = MemSource::new();
    src_both.store_account(&w.f.account);
    let mut ctl_x = w.controller(t);
    let mut ctl_y = controller_engine(&w.f, &w.host, &src_y, &w.f.d.clone(), t);
    let (n, x) = approve(&w.f, &mut w.host, &mut ctl_x, &w.src, 31, t);
    let (ny, y) = approve(&w.f, &mut w.host, &mut ctl_y, &src_y, 32, t);
    assert_eq!(n, ny, "the same seq");
    let (dx, dy) = (digest_of(&x), digest_of(&y));
    // X at the primary, then at B once A's head over it has reached B.
    w.clocks(t + 5_000);
    let post_x = json!({"from": n, "entries": [x], "receipts": []});
    assert_eq!(w.a.post("/authority", &post_x).0, 200);
    eventually("B stores X", 20, || b.post("/authority", &post_x).0 == 200);
    eventually("B's head over X", 20, || head_at(b).is_some_and(|(s, d, _)| s == n && d == dx));
    // A (equivocating) signs a head over Y; it reaches B, and so does Y.
    let hy = head_by(&w.ka, &account, n, &dy, t + 6_000);
    w.clocks(t + 7_000);
    assert_eq!(put(b, &format!("/records/heads/{}.json", w.ha), &hy).0, 200, "fork evidence is kept");
    let post_y = json!({"from": n, "entries": [y], "receipts": []});
    // The primary, which stores the first valid entry per seq, refuses Y (§14 409).
    assert_eq!(w.a.post("/authority", &post_y).0, 409);
    let (s, out) = b.post("/authority", &post_y);
    assert_eq!(s, 200, "{out}");
    // B serves the fork: both candidates at seq n.
    let mut both = vec![dx.clone(), dy.clone()];
    both.sort();
    let mut got = at_seq(b, n);
    got.sort();
    assert_eq!(got, both);
    // It signs no head while forked: the head it serves is still its head over X.
    std::thread::sleep(std::time::Duration::from_millis(300));
    w.clocks(t + 100_000);
    std::thread::sleep(std::time::Duration::from_millis(300));
    assert_eq!(head_at(b).map(|(s, d, _)| (s, d)), Some((n, dx.clone())));
    // It refuses what depends on either branch: an entry after X, and an ordinary transition.
    let (_, after_x) = approve(&w.f, &mut w.host, &mut ctl_x, &w.src, 33, t + 100_000);
    let (s, out) = b.post("/authority", &json!({"from": n + 1, "entries": [after_x], "receipts": []}));
    assert_eq!((s, out["result"].as_str()), (422, Some("refused:fork")), "{out}");
    let src_t = MemSource::new();
    src_t.store_account(&w.f.account);
    let mut ctl_t = controller_engine(&w.f, &w.host, &src_t, &w.f.d.clone(), t + 100_000);
    let action = ctl_t
        .account()
        .begin_transition(&Change::policy(json!({"callWindow": 700})), &[w.f.d.clone()], TransitionRule::Control)
        .unwrap();
    engine_finish(&mut ctl_t, &w.host, &src_t, action);
    let digest = ctl_t.account().pending()[0].digest.clone();
    let (s, out) = b.post("/pending", &json!({"objects": [pending_env(&ctl_t, &digest)]}));
    assert_eq!((s, out.clone()), (422, json!(["refused:fork"])), "{out}");
    // A device that held only the history before the fork, and A's head over Y (as A served it
    // to that device), pulls from B and holds the fork.
    let at = t + 110_000;
    w.clocks(at);
    src_both.put(&format!("heads/{}.json", w.ha), colophon_core::v05::encoding::canonical(&hy).unwrap());
    let mut ctl_b = controller_engine(&w.f, &w.host, &src_both, &w.f.d.clone(), at);
    let mut wire = w.wire();
    pass_without_calls(&mut ctl_b, &src_both, &w.hb, &mut wire, &w.host, at);
    assert_eq!(ctl_b.account().status().code, "refused:fork");
    // The owner resolves it, keeping X: every control unit and the recovery key sign (a full
    // set: due at its receipt).
    let (p, k) = (w.f.p.clone(), w.f.k.clone());
    let action = ctl_b
        .account()
        .begin_resolve((n, dx.clone()), (n, dx.clone()), &[w.f.d.clone(), p, k], TransitionRule::Control)
        .unwrap();
    engine_finish(&mut ctl_b, &w.host, &src_both, action);
    let resolve = ctl_b
        .account()
        .objects()
        .pending
        .iter()
        .map(|b| serde_json::from_slice::<Value>(b).unwrap())
        .find(|v| body_of(v)["change"].get("resolve").is_some())
        .expect("the resolve");
    let dr = digest_of(&resolve);
    w.clocks(at + 1_000);
    let (s, out) = b.post("/pending", &json!({"objects": [resolve.clone()]}));
    assert_eq!(s, 200, "B receipts the resolve: {out}");
    assert_eq!(out["receipts"].as_array().map(Vec::len), Some(1));
    let (s, out) = w.a.post("/pending", &json!({"objects": [resolve]}));
    assert_eq!(s, 200, "A, which holds no fork, receipts it too: {out}");
    // B records the `activate` on X's branch: the fork is resolved, and B signs heads again.
    w.clocks(at + 3_000);
    eventually("B resolved", 30, || {
        let k = kinds_at(b);
        k.len() > n as usize && k[n as usize] == "activate"
    });
    assert_eq!(at_seq(b, n), vec![dx.clone()], "the standing branch keeps X");
    let e = entries(b);
    let act = body_of(&e[n as usize]);
    let embedded: Value = serde_json::from_slice(&STANDARD.decode(act["transition"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(digest_of(&embedded), dr);
    w.clocks(at + 5_000);
    eventually("B's head over the resolution", 30, || head_at(b).is_some_and(|(s, _, _)| s > n));
    let (s, file) = b.get(&format!("/records/authority/{n:08}.json"));
    assert_eq!((s, digest_of(&serde_json::from_slice(&file).unwrap())), (200, dx.clone()));
    // Both devices sync to the resolved history from B.
    let now = at + 10_000;
    w.clocks(now);
    let mut wire = w.wire();
    // The forked device opened again (an engine that met a 401 at a home asks for a call before
    // every request there; at the fork it can build none).
    let mut ctl_b = controller_engine(&w.f, &w.host, &src_both, &w.f.d.clone(), now);
    pass_without_calls(&mut ctl_b, &src_both, &w.hb, &mut wire, &w.host, now);
    let held: Vec<(u64, String)> = ctl_b.account().objects().entries.iter().map(|e| { let v: Value = serde_json::from_slice(e).unwrap(); (entry_seq(e), body_of(&v)["kind"].as_str().unwrap().to_string()) }).collect();
    assert_eq!(ctl_b.account().status().code, "ok", "{:?} {:?} held {held:?} heads {}", ctl_b.account().status(), kinds_at(b), ctl_b.account().objects().heads.len());
    // (Its calls are the device's matter: it holds A's two heads at one seq, the evidence that
    // A equivocated, §13.3; the home serves it the history without one, under `public`.)
    assert!(ctl_b.account().head().0 > n);
    assert_eq!(ctl_b.account().branch_digests()[n as usize - 1], dx);
    // A device that held only the history before the fork syncs from B to the same history.
    let src_new = MemSource::new();
    src_new.store_account(&w.f.account);
    let mut ctl_new = controller_engine(&w.f, &w.host, &src_new, &w.f.d.clone(), now);
    pass_without_calls(&mut ctl_new, &src_new, &w.hb, &mut wire, &w.host, now + 1);
    assert_eq!(ctl_new.account().status().code, "ok");
    assert_eq!(ctl_new.account().head(), ctl_b.account().head());
    // The device whose entry after X lost to the resolution sees the conflict at that seq: B's
    // head names the `activate` there (the engine reports it; its host signs again, §8.6).
    let faults = relay_pass(&mut ctl_x, &w.src, &w.hb, &mut wire, &w.host, now + 2);
    assert!(faults.iter().any(|f| matches!(f, colophon_core::v05::engine::exchange::Fault::Fork { .. })), "{faults:?}");
}
