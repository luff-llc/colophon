//! The rest of the relay as a home (H2), against the real relay (`bun relay/server.js` with the
//! module): pending objects kept until settled; a fork held, served and resolved; a late veto
//! stored with another home's receipt; an offline home caught up; a Swift library's succession
//! published to and fetched from a home.
//!
//! Protocol time is only the relays' test clocks. No relay here runs a scheduler timer
//! (`tickMs` 0): a head read settles a home by itself, and a test runs each scheduler pass it
//! needs with `Relay::tick` (`ticks_until`, bounded and without waiting). `eventually` (with
//! passes inside it, `forwarded`) is used only where a pass's forwarding to another home, which
//! the pass starts and does not wait for, has to finish.
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
use std::collections::{BTreeMap, BTreeSet};
use support::*;
use support_relay::*;

const NOW: i64 = T0 + 3 * HOUR;
const NS: &str = "listening.podcasts";

/// A relay with no scheduler timer (`tickMs` 0): its passes run only when the test asks.
fn untimed(keys: &HomeKeys, account: &str, base: &str, dir: &std::path::Path, clock_ms: i64, resolve: &[(&str, u16)], port: u16) -> Relay {
    Relay::start_with(keys, account, base, dir, clock_ms, resolve, port, json!({"tickMs": 0}))
}

struct World {
    f: Fixture,
    host: Host,
    a: Relay,
    b: Option<Relay>,
    ka: HomeKeys,
    kb: HomeKeys,
    ha: String,
    hb: String,
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
    let account = f.account.id().as_str().to_string();
    let scratch = vec![Scratch::new(&format!("h2-{name}-a")), Scratch::new(&format!("h2-{name}-b"))];
    let a = untimed(&ka, &account, BASE_A, scratch[0].path(), T0, &[(BASE_B, CLOSED_PORT)], 0);
    first_upload(&a, &f, T0 + 1_000);
    let b = run_b.then(|| {
        let b = untimed(&kb, &account, BASE_B, scratch[1].path(), T0, &[(BASE_A, a.port)], 0);
        a.set_resolve(&[(BASE_B, b.port)]);
        first_upload(&b, &f, T0 + 1_000);
        b
    });
    let src = MemSource::new();
    src.store_account(&f.account);
    let host = std::mem::replace(&mut f.host, Host::new());
    Some(World { host, src, ha: ka.id.clone(), hb: kb.id.clone(), f, a, b, ka, kb, scratch })
}

impl World {
    /// Tell each running home where the other now listens (after a start or a restart).
    fn link(&self) {
        if let Some(b) = &self.b {
            self.a.set_resolve(&[(BASE_B, b.port)]);
            b.set_resolve(&[(BASE_A, self.a.port)]);
        }
    }
    /// The running homes.
    fn homes(&self) -> Vec<&Relay> {
        let mut v = vec![&self.a];
        if let Some(b) = &self.b {
            v.push(b);
        }
        v
    }
    /// Each running home holds the other's head: what the timer's first passes used to forward
    /// before anything else (a home at `headQuorum` 2 answers calls only with both heads).
    fn heads_exchanged(&self, at: i64) {
        if let Some(b) = &self.b {
            heads_exchanged(&self.a, &self.ha, b, &self.hb, at);
        }
    }
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
    w.a.tick();
    // A head over the activation needs a later `issued` than one signed at the same reading.
    w.a.set_clock(NOW + HOUR + 402_000);
    ticks_until("activate and final", 5, &[&w.a], || kinds_at(&w.a).len() >= n + 2);
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
    ticks_until("vetoed", 5, &[&w.a], || kinds_at(&w.a).len() >= n + 3);
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
        .begin_approve(&req.raw, terms_for(&[(NS, "write")]), &[f.d.clone()], seed, paired_on(ctl.account(), &req))
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
    // A's passes forward its head over X, and X, to B. B may have signed a head at this reading
    // before X reached it (A offers the entries before its head, and B answers 421 until it holds
    // that head), so B's clock moves on by a millisecond for the head over X (§13.3).
    forwarded("B stores X", &[&w.a], || b.post("/authority", &post_x).0 == 200);
    b.set_clock(t + 5_001);
    ticks_until("B's head over X", 5, &[b], || head_at(b).is_some_and(|(s, d, _)| s == n && d == dx));
    let hb_x = b.get("/head").1;
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
    // The fork and its evidence are durable: B killed and started again still holds both.
    let rb = w.b.take().unwrap();
    w.b = Some(rb.restart(&HomeKeys::new(0x78), t + 7_000, &[(BASE_A, w.a.port)]));
    w.link();
    let b = w.b.as_ref().unwrap();
    let mut got = at_seq(b, n);
    got.sort();
    assert_eq!(got, both, "after a kill");
    assert_eq!(b.get(&format!("/records/heads/{}.json", w.ha)).0, 200);
    // It signs no head while forked, and serves no older one (§13.3: the head is due and cannot
    // be produced): a retryable 503.
    w.a.tick();
    b.tick();
    w.clocks(t + 100_000);
    w.a.tick();
    b.tick();
    assert_eq!(b.get("/head").0, 503);
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
    // And B's head over X, which B served before it held Y (it serves no head while forked).
    src_both.put(&format!("heads/{}.json", w.hb), hb_x.clone());
    let mut ctl_b = controller_engine(&w.f, &w.host, &src_both, &w.f.d.clone(), at);
    let mut wire = w.wire();
    // Run exchange concurrently with device sync, rather than waiting for convergence.
    // A holds only X, while B serves both equivocations and cannot sign a fresh head.
    w.a.tick();
    b.tick();
    assert_eq!(b.get("/head").0, 503, "an exchanging fork cannot serve a misleading head");
    pass_without_calls(&mut ctl_b, &src_both, &w.hb, &mut wire, &w.host, at);
    assert_eq!(b.get("/head").0, 503, "exchange has not resolved the equivocation");
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
    forwarded("B resolved", &[&w.a, b], || {
        let k = kinds_at(b);
        k.len() > n as usize && k[n as usize] == "activate"
    });
    assert_eq!(at_seq(b, n), vec![dx.clone()], "the standing branch keeps X");
    let e = entries(b);
    let act = body_of(&e[n as usize]);
    let embedded: Value = serde_json::from_slice(&STANDARD.decode(act["transition"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(digest_of(&embedded), dr);
    // The homes' clocks move on, as real clocks do (a head over each new entry needs a later
    // `issued` than the one before, §13.3; both homes now append the activate and the final and
    // give each other their entries).
    let tick = std::cell::Cell::new(at + 5_000);
    // The devices sync once both homes hold the same history and B's head covers all of it (B
    // may still append the `final` after the `activate`).
    forwarded("B's head over the resolution, both homes alike", &[], || {
        tick.set(tick.get() + 50);
        w.clocks(tick.get());
        w.a.tick();
        b.tick();
        let eb = entries(b);
        eb.len() > n as usize + 1
            && eb == entries(&w.a)
            && head_at(b).is_some_and(|(s, _, _)| s == eb.len() as u64)
    });
    let (s, file) = b.get(&format!("/records/authority/{n:08}.json"));
    assert_eq!((s, digest_of(&serde_json::from_slice(&file).unwrap())), (200, dx.clone()));
    // Both devices sync to the resolved history from B.
    let now = tick.get() + 10_000;
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
    assert_eq!(ctl_new.account().head(), ctl_b.account().head(), "B now holds {:?}", kinds_at(b));
    // The device whose entry after X lost to the resolution sees the conflict at that seq, at the
    // primary (A), which takes immediate entries: through the head, `refused:fork` or a head
    // naming the `activate` there, or through the push of its entry, 409 (the engine reports it;
    // its host signs again, §8.6). The clock moves between passes, so a head due at one instant
    // (503) is signed by the next.
    use colophon_core::v05::engine::exchange::Fault;
    let mut seen = Vec::new();
    for i in 0..20 {
        let at = now + 2 + i * 1_000;
        w.clocks(at);
        let faults = relay_pass(&mut ctl_x, &w.src, &w.ha, &mut wire, &w.host, at);
        if faults.iter().any(|f| matches!(f, Fault::Fork { .. } | Fault::Conflict { .. })) {
            seen.clear();
            break;
        }
        seen.push(faults);
        for r in w.homes() {
            r.tick();
        }
    }
    assert!(seen.is_empty(), "the device never saw the conflict: {seen:?}");
}

// ---------------------------------------------------------------------------------------------
// Due heads (§13.3, revision 15).

/// The home signed a head over seq m at clock T. A new entry arrives while the clock still reads
/// T: a head over it is due, and `issued` cannot increase yet. `GET {base}/head` (and the head's
/// record path) fails retryably instead of serving the head over m, which would hide the new
/// entry; once the clock moves the head over it is signed and served. No two heads for one seq,
/// and `issued` never goes back.
#[test]
fn a_due_head_that_cannot_be_signed_yet_is_never_replaced_by_the_older_one() {
    let Some(mut w) = world("due", "public", 1, false, false) else {
        return;
    };
    let t = NOW;
    w.clocks(t);
    // A head read settles the home: the head is signed at T.
    assert!(head_at(&w.a).is_some_and(|(_, _, i)| i == colophon_core::v05::write::format_date(t)), "a head at T");
    let (m, dm, _) = head_at(&w.a).unwrap();
    let mut ctl = w.controller(t);
    let src = w.src.clone();
    let (seq, e) = approve(&w.f, &mut w.host, &mut ctl, &src, 34, t);
    assert_eq!(seq, m + 1);
    let (s, out) = w.a.post("/authority", &json!({"from": seq, "entries": [e], "receipts": []}));
    assert_eq!(s, 200, "{out}");
    assert!(out["head"].is_null(), "the older head is not the answer either: {out}");
    for path in ["/head".to_string(), format!("/records/heads/{}.json", w.ha)] {
        let (s, hs, _) = http(w.a.port, "GET", &w.a.url(&path), &[], &[]);
        assert_eq!(s, 503, "{path}: the head over seq {m} is not served for a history at {seq}");
        assert!(hs.iter().any(|(k, v)| k == "retry-after" && v == "1"));
    }
    // The clock moves on by one millisecond: the head over the new entry.
    w.a.set_clock(t + 1);
    let (s2, d2, i2) = head_at(&w.a).expect("served once it can be signed");
    assert_eq!(s2, seq);
    assert_ne!(d2, dm);
    assert!(colophon_core::v05::encoding::parse_date(&i2).unwrap() > t);
    let (s, b) = w.a.get(&format!("/records/heads/{}.json", w.ha));
    assert_eq!(s, 200);
    assert_eq!(body_of(&serde_json::from_slice(&b).unwrap())["authority"]["seq"].as_u64(), Some(seq));
}

// ---------------------------------------------------------------------------------------------
// 3. A late veto.

/// A restarted home on the same data directory and port, reaching the other home.
fn restart_home(r: Relay, keys: &HomeKeys, at: i64, peer: (&str, u16)) -> Relay {
    r.restart(keys, at, &[peer])
}

/// Two homes at `headQuorum` 2 receipt a transition. Home A is down when the owner vetoes it:
/// B receipts the veto (it cannot record a `vetoed` alone: a veto needs `headQuorum` receipts),
/// and keeps listing it. A comes back more than 300 s after the veto's `issued`. The veto alone is
/// `refused:late` at A and not stored (§13.1). B's forwarding sends it with B's in-window receipt
/// of it: A stores and serves the veto and signs no receipt of its own.
#[test]
fn a_late_veto_is_stored_with_another_homes_in_window_receipt_and_signs_none() {
    let Some(mut w) = world("lateveto", "public", 2, true, true) else {
        return;
    };
    let (ka, kb) = (HomeKeys::new(0x77), HomeKeys::new(0x78));
    let t = NOW;
    w.clocks(t);
    w.heads_exchanged(t);
    let mut ctl = w.controller(t);
    let tr = propose_by(&w, &mut ctl, 600, &[w.f.d.clone()]);
    w.pass_all(&mut ctl, t + 1_000);
    for r in [&w.a, w.b.as_ref().unwrap()] {
        forwarded("both receipts at each home", &w.homes(), || listed(r, "receipt").len() == 2);
    }
    // A goes down, and so does B's way to it; the owner vetoes, and B receipts the veto.
    w.a.stop();
    let veto = veto_of(&w, &mut ctl, &tr);
    let dv = digest_of(&veto);
    let issued = colophon_core::v05::encoding::parse_date(body_of(&veto)["issued"].as_str().unwrap()).unwrap();
    let mut b = w.b.take().unwrap();
    b.set_clock(issued + 1_000);
    let (s, out) = b.post("/pending", &json!({"objects": [veto.clone()]}));
    assert_eq!(s, 200, "{out}");
    assert!(out["receipts"][0].is_object(), "B receipts the veto: {out}");
    assert_eq!(body_of(&out["receipts"][0])["by"], w.hb.as_str());
    b.stop();
    // A comes back 400 s after the veto's `issued`: alone, the veto is late.
    let late = issued + 400_000;
    let a = std::mem::replace(&mut w.a, Relay::attached(0, BASE_A, "", w.scratch[0].path()));
    w.a = restart_home(a, &ka, late, (BASE_B, CLOSED_PORT));
    let (s, out) = w.a.post("/pending", &json!({"objects": [veto.clone()]}));
    assert_eq!((s, out), (422, json!(["refused:late"])), "alone, the late veto is refused");
    assert_eq!(w.a.get(&format!("/pending/{dv}")).0, 404, "and not stored");
    // B comes back and forwards the veto with its receipt: A stores it, and signs nothing.
    w.b = Some(restart_home(b, &kb, late, (BASE_A, w.a.port)));
    w.link();
    forwarded("A stores the late veto", &w.homes(), || w.a.get(&format!("/pending/{dv}")).0 == 200);
    let (s, file) = w.a.get(&format!("/records/vetoes/{dv}.json"));
    assert_eq!((s, digest_of(&serde_json::from_slice(&file).unwrap())), (200, dv.clone()), "stored and served");
    let (_, d) = w.a.get(&format!("/pending/{dv}"));
    let by: Vec<String> = serde_json::from_slice::<Value>(&d).unwrap()["receipts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| body_of(r)["by"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(by, vec![w.hb.clone()], "A holds B's receipt and signed none of its own");
    assert_eq!(w.a.get(&format!("/records/receipts/{dv}/{}.receipt.json", w.ha)).0, 404);
    assert_eq!(w.a.get(&format!("/records/receipts/{dv}/{}.receipt.json", w.hb)).0, 200);
    let _ = kb;
}

// ---------------------------------------------------------------------------------------------
// 4. Offline home catch-up.

/// Every head a home is seen serving: seq -> digests.
fn watch_heads(seen: &mut BTreeMap<u64, BTreeSet<String>>, r: &Relay) {
    if let Some((s, d, _)) = head_at(r) {
        seen.entry(s).or_default().insert(d);
    }
}

/// Two homes at `headQuorum` 2. The second home B is down while the account advances at the
/// primary A (two devices approved, A signing heads). B comes back long after (more than 300 s
/// after those entries' `issued`): a device supplies A's signed covering head, then pushes the
/// entries, which B stores because the primary's head covers them (the clock rule is the
/// primary's to apply; a home that was offline catches up). B then signs heads again, never two
/// for one seq.
#[test]
fn an_offline_home_catches_up_from_a_device_and_signs_heads_again() {
    let Some(mut w) = world("catchup", "public", 2, true, true) else {
        return;
    };
    let kb = HomeKeys::new(0x78);
    let t = NOW;
    w.clocks(t);
    let mut seen: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();
    assert!(head_at(w.b.as_ref().unwrap()).is_some_and(|(_, _, i)| i == colophon_core::v05::write::format_date(t)), "B's head at T");
    watch_heads(&mut seen, w.b.as_ref().unwrap());
    let m = head_at(w.b.as_ref().unwrap()).unwrap().0;
    let mut b = w.b.take().unwrap();
    b.stop();
    // The account advances at the primary while B is down.
    let mut ctl = w.controller(t);
    let src = w.src.clone();
    let mut last = 0;
    for (i, n) in [41u8, 42].into_iter().enumerate() {
        let at = t + 10_000 * (i as i64 + 1);
        w.a.set_clock(at);
        let (seq, e) = approve(&w.f, &mut w.host, &mut ctl, &src, n, at);
        let (s, out) = w.a.post("/authority", &json!({"from": seq, "entries": [e], "receipts": []}));
        assert_eq!(s, 200, "{out}");
        last = seq;
    }
    w.a.set_clock(t + 30_000);
    ticks_until("A's head over the new entries", 5, &[&w.a], || head_at(&w.a).is_some_and(|(s, _, _)| s == last));
    // B comes back 20 minutes later.
    let back = t + 1_200_000;
    w.a.set_clock(back);
    w.b = Some(b.restart(&kb, back, &[(BASE_A, w.a.port)]));
    w.link();
    let b = w.b.as_ref().unwrap();
    watch_heads(&mut seen, b);
    // Without the primary's covering head, this old upload is 422 refused:late. Normal
    // forwarding must not follow that rejection with an ahead-of-entries head. Supply the
    // signed coverage explicitly as part of the device's recovery before pushing entries.
    let (s, out) = b.post("/authority", &json!({"from": 1, "entries": entries(&w.a), "receipts": []}));
    assert_eq!((s, out), (422, json!({"result": "refused:late"})));
    let (s, primary_head) = w.a.get("/head");
    assert_eq!(s, 200);
    let (s, _, out) = http(
        b.port, "PUT", &b.url(&format!("/records/heads/{}.json", w.ha)),
        &[("Content-Type".into(), "application/json".into())], &primary_head,
    );
    assert_eq!(s, 200, "{}", String::from_utf8_lossy(&out));
    // A device's pass brings B up to date.
    let mut ctl = w.controller(back);
    let mut wire = w.wire();
    let _ = relay_pass(&mut ctl, &w.src, &w.hb, &mut wire, &w.host, back + 1_000);
    assert_eq!(kinds_at(b).len() as u64, last, "B holds the whole history");
    assert_eq!(entries(b), entries(&w.a), "the same entries as the primary");
    b.set_clock(back + 2_000);
    ticks_until("B's head over the latest entry", 5, &[b], || {
        watch_heads(&mut seen, b);
        head_at(b).is_some_and(|(s, _, _)| s == last)
    });
    // With both homes' fresh heads, the device's calls work again everywhere.
    w.clocks(back + 3_000);
    let mut wire = w.wire();
    let faults = relay_pass(&mut ctl, &w.src, &w.hb, &mut wire, &w.host, back + 3_000);
    assert!(faults.is_empty(), "{faults:?}");
    watch_heads(&mut seen, b);
    assert!(seen.keys().any(|s| *s == m) && seen.keys().any(|s| *s == last));
    for (s, ds) in &seen {
        assert_eq!(ds.len(), 1, "B signed one head digest at seq {s}: {ds:?}");
    }
}

/// At `headQuorum` 1, B is down while a transition is proposed, receipted by A alone, comes due
/// and is activated at A. B was not serving during the transition's window (its serving interval
/// closed at its last tick, §13.1), so when a device brings it the `activate`, B stores it
/// instead of refusing it for ever as an activation it should have seen.
#[test]
fn a_home_that_was_down_during_a_window_stores_the_activate_it_never_saw() {
    let Some(mut w) = world("downwindow", "public", 1, true, true) else {
        return;
    };
    let kb = HomeKeys::new(0x78);
    let t = NOW;
    w.clocks(t);
    w.b.as_ref().unwrap().tick(); // B ticks at T
    let mut b = w.b.take().unwrap();
    b.stop();
    // B may have served until its last lease (30 s after its last tick): the transition comes
    // after that.
    let mut ctl = w.controller(t + 60_000);
    w.a.set_clock(t + 60_000);
    let tr = propose_by(&w, &mut ctl, 600, &[w.f.d.clone()]);
    let (s, out) = w.a.post("/pending", &json!({"objects": [pending_env(&ctl, &tr)]}));
    assert_eq!(s, 200, "{out}");
    let n = kinds_at(&w.a).len();
    w.a.set_clock(t + HOUR + 400_000);
    ticks_until("A activates it", 5, &[&w.a], || kinds_at(&w.a).len() > n);
    assert_eq!(kinds_at(&w.a)[n], "activate");
    let back = t + HOUR + 500_000;
    w.a.set_clock(back);
    w.b = Some(b.restart(&kb, back, &[(BASE_A, w.a.port)]));
    w.link();
    let b = w.b.as_ref().unwrap();
    let e = entries(&w.a);
    let (s, out) = b.post("/authority", &json!({"from": n + 1, "entries": [e[n]], "receipts": []}));
    assert_eq!(s, 200, "B stores the activate: {out}");
    assert_eq!(kinds_at(b)[n], "activate");
}

// ---------------------------------------------------------------------------------------------
// The H2 check, finding 4: uptime is never under-recorded.

/// A home restarted, serving a request a minute later, and killed before any scheduler tick (the
/// tick is disabled here): on the next start the interval it served in is still recorded. Before
/// the fix, its liveness was written only by a tick, so the next start closed the interval at its
/// own start and erased that minute; a transition withheld from the home over that minute could
/// then get the offline exemption (§13.1).
#[test]
fn a_kill_before_the_first_tick_does_not_erase_uptime() {
    let Some(mut w) = world("lease", "public", 1, false, false) else {
        return;
    };
    let ka = HomeKeys::new(0x77);
    let account = w.f.account.id().as_str().to_string();
    let t = NOW;
    w.a.set_clock(t);
    w.a.tick(); // ticks at T
    let a = std::mem::replace(&mut w.a, Relay::attached(0, BASE_A, "", w.scratch[0].path()));
    let (port, dir) = (a.port, a.dir.clone());
    let mut a = a;
    a.stop();
    // Started again an hour later with no tick; a request a minute after that; killed.
    let t2 = t + HOUR;
    let mut quiet = untimed(&ka, &account, BASE_A, &dir, t2, &[], port);
    quiet.set_clock(t2 + 60_000);
    assert_eq!(quiet.get("/authority?after=0&limit=1").0, 200, "served at T2 + 60 s");
    quiet.stop();
    // The next start: the home was serving at T2 + 60 s.
    w.a = untimed(&ka, &account, BASE_A, &dir, t2 + HOUR, &[], port);
    let serving = w.a.serving();
    let at = t2 + 60_000;
    assert!(
        serving.iter().any(|(from, through)| *from <= at && through.is_none_or(|e| e >= at)),
        "the interval served in is recorded: {serving:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// The H2 check, finding 6: a head the home is due to replace never leaves it.

/// Home A signed a head over seq m at T; an entry arrives while its clock still reads T, so a
/// head over it is due and cannot be signed yet. Peer B comes up then: A's forwarding sends B no
/// head (the head over m would hide the new entry). Once A's clock moves, the new head reaches B.
#[test]
fn a_head_due_to_be_replaced_is_not_forwarded() {
    let Some(mut w) = world("dueforward", "public", 1, true, false) else {
        return;
    };
    let kb = HomeKeys::new(0x78);
    let account = w.f.account.id().as_str().to_string();
    let t = NOW;
    w.a.set_clock(t);
    assert!(head_at(&w.a).is_some_and(|(_, _, i)| i == colophon_core::v05::write::format_date(t)), "a head at T");
    let mut ctl = w.controller(t);
    let src = w.src.clone();
    let (seq, e) = approve(&w.f, &mut w.host, &mut ctl, &src, 35, t);
    let (s, out) = w.a.post("/authority", &json!({"from": seq, "entries": [e], "receipts": []}));
    assert_eq!(s, 200, "{out}");
    assert_eq!(w.a.get("/head").0, 503, "due, and cannot be signed at T");
    // B comes up; A's scheduler forwards to it for a while.
    let b = untimed(&kb, &account, BASE_B, w.scratch[1].path(), t, &[(BASE_A, w.a.port)], 0);
    w.a.set_resolve(&[(BASE_B, b.port)]);
    first_upload(&b, &w.f, t);
    // A pass to B runs: its saved forwarding state then holds B's row, written after the
    // pass's entries were offered and again after its head step.
    let forward = w.scratch[0].path().join("data/home/forward.json");
    forwarded("a forwarding pass from A to B", &[&w.a], || {
        std::fs::read_to_string(&forward).is_ok_and(|t| t.contains(&w.hb))
    });
    w.a.tick();
    assert_eq!(b.get(&format!("/records/heads/{}.json", w.ha)).0, 404, "no stale head was forwarded");
    // The clock moves: A signs the head over the new entry and forwards it.
    w.a.set_clock(t + 1_000);
    forwarded("A's new head at B", &[&w.a], || {
        let (s, body) = b.get(&format!("/records/heads/{}.json", w.ha));
        s == 200 && body_of(&serde_json::from_slice(&body).unwrap())["authority"]["seq"].as_u64() == Some(seq)
    });
    w.b = Some(b);
}

// ---------------------------------------------------------------------------------------------
// Two-home flake (2026-11-16): a head signed at T over the history before an entry due at T.

/// A transition comes due at T. Before any scheduler tick at T (ticks are disabled here), the
/// head is asked for: the home appends the determined `activate` first and signs its head over
/// it, at T. Before the fix it signed a head at T over the history without the `activate`; the
/// tick then appended the `activate`, but a head over it needed an `issued` later than T, so while
/// the clock read T no head covered the activation, and `final` (which needs the witnesses' heads
/// over it) never came: the two-home tests hung exactly this way when a peer's forwarding or a
/// client's GET reached a home between the clock step and its tick.
#[test]
fn a_head_asked_for_at_a_due_time_covers_what_is_due_then() {
    let Some(mut w) = world("settle", "public", 1, false, false) else {
        return;
    };
    let ka = HomeKeys::new(0x77);
    let account = w.f.account.id().as_str().to_string();
    let t = NOW;
    w.a.set_clock(t);
    let mut ctl = w.controller(t);
    propose_by(&w, &mut ctl, 600, &[w.f.d.clone()]);
    w.pass_all(&mut ctl, t + 1_000);
    let n = kinds_at(&w.a).len() as u64;
    // Due at T + 300 s + 3,600 s. The home is started again with no tick, at that instant.
    let due = t + 1_000 + 300_000 + HOUR;
    let a = std::mem::replace(&mut w.a, Relay::attached(0, BASE_A, "", w.scratch[0].path()));
    let (port, dir) = (a.port, a.dir.clone());
    let mut a = a;
    a.stop();
    let mut quiet = untimed(&ka, &account, BASE_A, &dir, due, &[], port);
    let (s, _, _) = head_at(&quiet).expect("a head");
    assert_eq!(s, n + 1, "the head asked for at the due time covers the activate due then");
    quiet.stop();
    // With ticks, at the same clock reading, the activation is made final.
    w.a = untimed(&ka, &account, BASE_A, &dir, due, &[], port);
    ticks_until("final at the same clock reading", 5, &[&w.a], || kinds_at(&w.a).len() as u64 >= n + 2);
    assert_eq!(kinds_at(&w.a)[n as usize..n as usize + 2], ["activate", "final"]);
}

/// Two homes at `headQuorum` 2, the order that left the second one waiting for ever. Both receipt
/// a transition. At its due time A cannot reach B: B appends the `activate` and forwards its head
/// over it to A; A appends the `activate`, then, holding both homes' heads over it, the `final`,
/// and signs its head over the `final`. So the only head A has to give B covers an entry B does
/// not hold, and B's own `final` needs A's head over the activation. Before the fix B waited for
/// ever (homes forwarded heads, transitions, vetoes and receipts, never entries); now A forwards
/// B its history after B's latest head, B appends the same `final`, and both agree.
#[test]
fn a_home_that_recorded_final_first_gives_its_peer_the_entry() {
    let Some(mut w) = world("finalorder", "public", 2, true, true) else {
        return;
    };
    let ka = HomeKeys::new(0x77);
    let t = NOW;
    w.clocks(t);
    w.heads_exchanged(t);
    let mut ctl = w.controller(t);
    propose_by(&w, &mut ctl, 600, &[w.f.d.clone()]);
    w.pass_all(&mut ctl, t + 1_000);
    for r in [&w.a, w.b.as_ref().unwrap()] {
        forwarded("both receipts at each home", &w.homes(), || listed(r, "receipt").len() == 2);
    }
    let n = kinds_at(&w.a).len();
    // A restarted unable to reach B (B's endpoint resolves to a closed port); B reaches A.
    let a = std::mem::replace(&mut w.a, Relay::attached(0, BASE_A, "", w.scratch[0].path()));
    w.a = a.restart(&ka, t + 2_000, &[(BASE_B, CLOSED_PORT)]);
    w.b.as_ref().unwrap().set_resolve(&[(BASE_A, w.a.port)]);
    let due = t + 1_000 + 300_000 + HOUR;
    w.clocks(due);
    for r in w.homes() {
        r.tick();
    }
    w.clocks(due + 2_000);
    forwarded("activate and final at A", &w.homes(), || kinds_at(&w.a).len() > n + 1);
    assert_eq!(kinds_at(&w.a)[n..n + 2], ["activate", "final"]);
    let b = w.b.as_ref().unwrap();
    assert_eq!(kinds_at(b).len(), n + 1, "B holds the activate and no final: it lacks A's head over the activation");
    // A can reach B again; its clock moves on, so nothing here rests on a frozen clock.
    let a = std::mem::replace(&mut w.a, Relay::attached(0, BASE_A, "", w.scratch[0].path()));
    w.a = a.restart(&ka, due + 5_000, &[(BASE_B, w.b.as_ref().unwrap().port)]);
    w.link();
    let b = w.b.as_ref().unwrap();
    b.set_clock(due + 6_000);
    forwarded("B's final", &[&w.a, b], || kinds_at(b).len() > n + 1);
    assert_eq!(entries(b)[..n + 2], entries(&w.a)[..n + 2], "the same history at both homes");
}

// ---------------------------------------------------------------------------------------------
// The check of the forwarding fix (2026-11-16), finding 2: homes on different branches exchange
// candidates (§13.1) and reach the same verdict.

/// A and B both receipt a transition T. B is down while the primary A takes an immediate entry X
/// at seq n before T is due; then A records T's `activate` after X. B comes back unable to reach
/// A and records its own `activate` R at seq n. Once they reach each other, each home's latest
/// head of the other names an entry its own branch lacks at seq n. A forwards its branch from n
/// with its head first; under §8.6 rule 1, X (covered by the primary's head, issued before T's due
/// time) stands against R, so B takes X and follows A's history. Before the fix neither home sent
/// anything: B stayed on R for ever.
#[test]
fn homes_on_different_branches_exchange_candidates_and_converge() {
    let Some(mut w) = world("exchange", "public", 1, true, true) else {
        return;
    };
    let kb = HomeKeys::new(0x78);
    let t = NOW;
    w.clocks(t);
    let mut ctl = w.controller(t);
    let tr = propose_by(&w, &mut ctl, 600, &[w.f.d.clone()]);
    let env = pending_env(&ctl, &tr);
    for r in [&w.a, w.b.as_ref().unwrap()] {
        let (s, out) = r.post("/pending", &json!({"objects": [env.clone()]}));
        assert_eq!(s, 200, "{out}");
        assert!(out["receipts"][0].is_object(), "each home receipts T in its window: {out}");
    }
    // B goes down; A cannot reach it either way.
    let mut b = w.b.take().unwrap();
    b.stop();
    w.a.set_resolve(&[(BASE_B, CLOSED_PORT)]);
    // X at the primary, before T is due.
    w.a.set_clock(t + 2_000);
    let (n, x) = approve(&w.f, &mut w.host, &mut ctl, &w.src, 36, t + 2_000);
    let dx = digest_of(&x);
    let (s, out) = w.a.post("/authority", &json!({"from": n, "entries": [x], "receipts": []}));
    assert_eq!(s, 200, "{out}");
    // Due: A records the activate after X; B, back but unable to reach A, records its own at n.
    let due = t + 300_000 + HOUR + 1_000;
    w.a.set_clock(due);
    ticks_until("A's activate after X", 5, &[&w.a], || kinds_at(&w.a).get(n as usize) == Some(&"activate".to_string()));
    w.b = Some(b.restart(&kb, due, &[(BASE_A, CLOSED_PORT)]));
    let b = w.b.as_ref().unwrap();
    ticks_until("B's own activate at n", 5, &[b], || kinds_at(b).get(n as usize - 1) == Some(&"activate".to_string()));
    let r_at_b = digest_of(&entries(b)[n as usize - 1]);
    assert_ne!(r_at_b, dx);
    // They reach each other again: B comes to follow A's branch.
    w.link();
    w.clocks(due + 5_000);
    forwarded("B takes X and A's history", &w.homes(), || {
        let (ea, eb) = (entries(&w.a), entries(b));
        eb.len() >= n as usize && digest_of(&eb[n as usize - 1]) == dx && eb == ea
    });
    let tick = std::cell::Cell::new(due + 6_000);
    forwarded("B's head over A's history", &w.homes(), || {
        tick.set(tick.get() + 1_000);
        w.clocks(tick.get());
        let last = entries(&w.a).len() as u64;
        head_at(b).is_some_and(|(s, _, _)| s == last)
    });
    // A still serves its own branch, unchanged.
    assert_eq!(digest_of(&entries(&w.a)[n as usize - 1]), dx);
}

// ---------------------------------------------------------------------------------------------
// The check of the forwarding fix, finding 3: one slow peer does not hold up forwarding to the
// others.

/// Three homes: A and B relays, C a peer that accepts connections and never answers. A holds a
/// backlog of objects C has not taken (two transitions and their receipts), re-offered every
/// pass. A new transition reaches A just as A starts an offer to C: B has it well inside its
/// 300 s window (within 3 s here). Before the fix A forwarded to its peers one after another in
/// one pass, every offer to C waiting out its 5 s time limit, so B waited for C's whole backlog.
#[test]
fn a_silent_peer_does_not_hold_up_forwarding_to_the_others() {
    if prerequisites().is_none() {
        return;
    }
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    let (ka, kb, kc) = (HomeKeys::new(0x77), HomeKeys::new(0x78), HomeKeys::new(0x7a));
    let mut f = create_with(&[NS], "public", 1);
    const BASE_C: &str = "https://home-c.example";
    appoint_homes(&mut f, &[(&ka, BASE_A), (&kb, BASE_B), (&kc, BASE_C)]);
    // C: connections are accepted (by the kernel, and here) and never answered. Only A reaches
    // it (B's address for C is a closed port), so each connection here is one of A's offers.
    let silent = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let pc = silent.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicUsize::new(0));
    {
        let accepted = accepted.clone();
        std::thread::spawn(move || {
            let mut held = Vec::new();
            for s in silent.incoming().flatten() {
                held.push(s);
                accepted.fetch_add(1, Ordering::SeqCst);
            }
        });
    }
    let account = f.account.id().as_str().to_string();
    let scratch = vec![Scratch::new("h2-silent-a"), Scratch::new("h2-silent-b")];
    let a = untimed(&ka, &account, BASE_A, scratch[0].path(), T0, &[(BASE_C, pc)], 0);
    let b = untimed(&kb, &account, BASE_B, scratch[1].path(), T0, &[(BASE_A, a.port), (BASE_C, CLOSED_PORT)], 0);
    a.set_resolve(&[(BASE_B, b.port), (BASE_C, pc)]);
    first_upload(&a, &f, T0 + 1_000);
    first_upload(&b, &f, T0 + 1_000);
    let src = MemSource::new();
    src.store_account(&f.account);
    let host = std::mem::replace(&mut f.host, Host::new());
    let t = NOW;
    a.set_clock(t);
    b.set_clock(t);
    let mut ctl = controller_engine(&f, &host, &src, &f.d.clone(), t);
    let propose = |ctl: &mut Engine<MemSource>, window: u64, by: &[String]| -> Value {
        let had: Vec<String> = ctl.account().pending().iter().map(|t| t.digest.clone()).collect();
        let action = ctl
            .account()
            .begin_transition(&Change::policy(json!({"callWindow": window})), by, TransitionRule::Control)
            .unwrap();
        engine_finish(ctl, &host, &src, action);
        let d = ctl.account().pending().iter().map(|t| t.digest.clone()).find(|d| !had.contains(d)).unwrap();
        pending_env(ctl, &d)
    };
    // The backlog: two transitions at A, which C never takes.
    for (i, by) in [vec![f.d.clone()], vec![f.d.clone()]].iter().enumerate() {
        let env = propose(&mut ctl, 600 + i as u64, by);
        assert_eq!(a.post("/pending", &json!({"objects": [env]})).0, 200);
    }
    forwarded("A has offered C its backlog", &[&a], || accepted.load(Ordering::SeqCst) >= 2);
    // A new transition, from the other unit, posted just as A opens another connection to C.
    let env = propose(&mut ctl, 700, &[f.p.clone()]);
    let d3 = digest_of(&env);
    let seen = accepted.load(Ordering::SeqCst);
    forwarded("A starts another offer to C", &[&a], || accepted.load(Ordering::SeqCst) > seen);
    assert_eq!(a.post("/pending", &json!({"objects": [env]})).0, 200);
    let posted = std::time::Instant::now();
    forwarded("B holds the new transition", &[&a], || b.get(&format!("/pending/{d3}")).0 == 200);
    let took = posted.elapsed();
    assert!(took < std::time::Duration::from_secs(3), "B waited {took:?} for a transition A held");
    drop((a, b));
    drop(scratch);
}
