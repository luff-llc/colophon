//! What only a home does (§13, §14), against the real relay: a transition receipted, due,
//! activated and made final across two homes at `headQuorum` 2; primary-home ordering; a veto in
//! time; a late object; forged and replayed objects; calls for another audience and no call; a
//! head the guard refuses; a restart in the middle.
//!
//! No relay here runs a scheduler timer: a head read settles a home by itself, a test runs each
//! other pass it needs (`tick`, `ticks_until`), and `eventually` waits only for forwarding
//! between homes to finish (`forwarded`).
#![allow(
    clippy::unwrap_used,
    clippy::too_many_arguments,
    clippy::cloned_ref_to_slice_refs,
    dead_code
)]
#[path = "../../colophon-core/tests/v05_engine_support/mod.rs"]
mod support;
mod support_relay;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use colophon_core::v05::account::Change;
use colophon_core::v05::engine::Engine;
use colophon_core::v05::write::authority::TransitionRule;
use serde_json::{json, Value};
use std::path::PathBuf;
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
    src: MemSource,
    /// Removed when the world is dropped (declared last: the relays stop first).
    scratch: Vec<Scratch>,
}

fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("colophon-relay-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

/// An account (history `history`, `headQuorum` `quorum`) with one home, or two, running as relay
/// processes that reach each other; the whole history uploaded to each as a first upload.
fn world(name: &str, history: &str, quorum: u64, two: bool) -> Option<World> {
    world_with(name, history, quorum, two, two)
}

/// `two`: the account names two homes; `run_b`: the second is actually running.
fn world_with(name: &str, history: &str, quorum: u64, two: bool, run_b: bool) -> Option<World> {
    prerequisites()?;
    let (ka, kb) = (HomeKeys::new(0x77), HomeKeys::new(0x78));
    let mut f = create_with(&[NS], history, quorum);
    if two {
        appoint_homes(&mut f, &[(&ka, BASE_A), (&kb, BASE_B)]);
    } else {
        appoint_homes(&mut f, &[(&ka, BASE_A)]);
    }
    let account = f.account.id().as_str().to_string();
    let scratch = vec![Scratch::new(&format!("{name}-a")), Scratch::new(&format!("{name}-b")), Scratch::new(&format!("{name}-spare"))];
    let a = Relay::start_on(&ka, &account, BASE_A, scratch[0].path(), T0, &[(BASE_B, CLOSED_PORT)], 0);
    first_upload(&a, &f, T0 + 1_000);
    let b = run_b.then(|| {
        let b = Relay::start_on(&kb, &account, BASE_B, scratch[1].path(), T0, &[(BASE_A, a.port)], 0);
        a.set_resolve(&[(BASE_B, b.port)]);
        first_upload(&b, &f, T0 + 1_000);
        b
    });
    let src = MemSource::new();
    src.store_account(&f.account);
    let host = std::mem::replace(&mut f.host, Host::new());
    Some(World {
        host,
        src,
        ha: ka.id.clone(),
        hb: kb.id.clone(),
        f,
        a,
        b,
        ka,
        kb,
        scratch,
    })
}

impl World {
    /// The running homes.
    fn homes(&self) -> Vec<&Relay> {
        let mut v = vec![&self.a];
        if let Some(b) = &self.b {
            v.push(b);
        }
        v
    }
    fn clocks(&self, ms: i64) {
        self.a.set_clock(ms);
        if let Some(b) = &self.b {
            b.set_clock(ms);
        }
    }
    /// Each running home holds the other's head issued at `at` or later.
    fn heads_exchanged(&self, at: i64) {
        if let Some(b) = &self.b {
            heads_exchanged(&self.a, &self.ha, b, &self.hb, at);
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
}

fn policy_change(window: u64) -> Change {
    Change::policy(json!({"callWindow": window}))
}
fn propose(w: &mut World, ctl: &mut Engine<MemSource>, window: u64) -> String {
    let (d, p) = (w.f.d.clone(), w.f.p.clone());
    propose_by(w, ctl, window, &[d, p])
}
/// A transition signed by one unit is not a full set: it has a delay, and it can be vetoed.
fn propose_by(w: &mut World, ctl: &mut Engine<MemSource>, window: u64, by: &[String]) -> String {
    let had: Vec<String> = ctl.account().pending().iter().map(|t| t.digest.clone()).collect();
    let action = ctl
        .account()
        .begin_transition(&policy_change(window), by, TransitionRule::Control)
        .unwrap();
    engine_finish(ctl, &w.host, &w.src, action);
    ctl.account()
        .pending()
        .iter()
        .map(|t| t.digest.clone())
        .find(|d| !had.contains(d))
        .unwrap()
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
    serde_json::from_slice::<Value>(&b).unwrap()["objects"]
        .as_array()
        .unwrap()
        .clone()
}
fn kinds_of(list: &[Value], kind: &str) -> usize {
    list.iter().filter(|o| o["kind"] == kind).count()
}

#[test]
fn a_transition_is_receipted_due_activated_and_final_across_two_homes_at_quorum_2() {
    let Some(mut w) = world("quorum2", "public", 2, true) else {
        return;
    };
    let b = w.b.as_ref().unwrap();
    // Both homes hold the whole history from the first upload and have signed a head.
    assert_eq!(w.a.get("/head").0, 200);
    assert_eq!(b.get("/head").0, 200);
    let (ha, hb) = (w.ha.clone(), w.hb.clone());
    let mut ctl = w.controller(NOW);
    w.clocks(NOW);
    w.heads_exchanged(NOW);
    // The transition is submitted to both homes; each receipts it.
    let d = w.f.d.clone();
    let digest = propose_by(&mut w, &mut ctl, 600, &[d]);
    let mut wire = w.wire();
    for (i, h) in [&ha, &hb].into_iter().enumerate() {
        let faults = relay_pass(&mut ctl, &w.src, h, &mut wire, &w.host, NOW + 1_000 + i as i64);
        assert!(faults.is_empty(), "{faults:?}");
    }
    let mut seen = ctl.receipted_by(&digest);
    seen.sort();
    let mut both = vec![ha.clone(), hb.clone()];
    both.sort();
    assert_eq!(seen, both, "each home signed one receipt");
    // Before it is due: listed once, with one receipt per home, on each home.
    for r in [&w.a, w.b.as_ref().unwrap()] {
        forwarded("both receipts at a home", &w.homes(), || {
            let l = pending_list(r);
            kinds_of(&l, "transition") == 1 && kinds_of(&l, "receipt") == 2
        });
    }
    // Not yet due: nothing is recorded.
    assert_eq!(kinds(&w.a).last().unwrap(), "activate");
    let before = kinds(&w.a).len();
    // Past the recovery delay (3,600 s): both homes append the `activate`, then each, holding
    // both homes' heads over it, the `final`.
    let later = NOW + 3_600_000 + 400_000;
    w.clocks(later);
    for r in [&w.a, w.b.as_ref().unwrap()] {
        ticks_until("the activate", 5, &[r], || {
            let k = kinds(r);
            k.len() > before && k[before] == "activate"
        });
        assert!(
            kinds(r)[before] == "activate",
            "a: {:?} b: {:?}",
            kinds(&w.a),
            kinds(w.b.as_ref().unwrap())
        );
    }
    // Each home appends the `final` once it holds both homes' heads over the activation.
    for r in [&w.a, w.b.as_ref().unwrap()] {
        forwarded("the final at both homes", &w.homes(), || kinds(r).len() > before + 1);
        assert_eq!(kinds(r)[before + 1], "final");
    }
    // The clocks move on, so each home signs its head over the `final` (§13.3: a later `issued`)
    // and gives it to the other. The real client takes it from the homes and verifies it: the
    // policy changed, no pending.
    w.clocks(later + 2_000);
    w.heads_exchanged(later + 2_000);
    let mut wire = w.wire();
    for h in [&ha, &hb] {
        let faults = relay_pass(&mut ctl, &w.src, h, &mut wire, &w.host, later + 2_000);
        assert!(faults.is_empty(), "{faults:?}");
    }
    assert!(ctl.account().pending().is_empty(), "recorded, no longer pending");
    assert_eq!(ctl.account().head().0 as usize, before + 2);
    // Once recorded the transition is no longer listed.
    assert_eq!(kinds_of(&pending_list(&w.a), "transition"), 0);
    let _ = (&w.ka, &w.kb);
}

#[test]
fn a_non_primary_home_answers_421_until_the_primary_head_covers_the_entry() {
    let Some(mut w) = world("primary", "public", 2, true) else {
        return;
    };
    let mut ctl = w.controller(NOW);
    w.clocks(NOW);
    // A new immediate entry: admit a device.
    let id = w.host.identity(31);
    let req = request_for(
        &w.f,
        &w.host,
        &id,
        "Phone",
        "device",
        terms_for(&[(NS, "write")]),
        NOW,
    );
    let granted = terms_for(&[(NS, "write")]);
    let seed = w.host.fresh();
    let d = w.f.d.clone();
    let action = ctl
        .account()
        .begin_approve(&req.raw, granted, &[d], seed, paired_on(ctl.account(), &req))
        .unwrap();
    engine_finish(&mut ctl, &w.host, &w.src, action);
    let all: Vec<(u64, Value)> = ctl
        .account()
        .objects()
        .entries
        .iter()
        .map(|e| (entry_seq(e), serde_json::from_slice(e).unwrap()))
        .collect();
    let (seq, entry) = all.iter().max_by_key(|(s, _)| *s).unwrap().clone();
    w.clocks(NOW + 5_000); // a head for it needs a larger `issued` than the last one (§13.3)
    let b = w.b.as_ref().unwrap();
    let post = json!({"from": seq, "entries": [entry], "receipts": []});
    // The second home refuses: no primary head covers the entry yet.
    let (status, body) = b.post("/authority", &post);
    assert_eq!(status, 421, "{body}");
    assert_eq!(body["endpoints"], json!(["https://home-a.example"]));
    // The primary stores it and signs a head; that head reaches the second home by forwarding.
    let (status, body) = w.a.post("/authority", &post);
    assert_eq!(status, 200, "{body}");
    // Its answer carries the head over the entry; or, when the primary already signed a head at
    // this very clock reading, none (§13.3: a head is due and `issued` must increase; the older
    // head is not answered), and the head follows once the clock moves.
    if body["head"].is_null() {
        w.clocks(NOW + 6_000);
    } else {
        assert!(body["head"].is_object(), "{body}");
    }
    forwarded("the second home to hold the primary's head over it", &[&w.a], || {
        let r = b.post("/authority", &post);
        if r.0 != 421 {
            eprintln!("second home: {} {}", r.0, r.1);
        }
        r.0 == 200
    });
    // Re-sending what is stored is acknowledged again; a `from` that does not name the first
    // entry is malformed.
    assert_eq!(w.a.post("/authority", &post).0, 200);
    let (status, out) = w.a.post("/authority", &json!({"from": seq + 1, "entries": [entry_json_other(&all, seq)], "receipts": []}));
    assert_eq!((status, out["result"].as_str()), (422, Some("malformed")));
}
fn entry_json_other(all: &[(u64, Value)], seq: u64) -> Value {
    all.iter().find(|(s, _)| *s == seq).unwrap().1.clone()
}

#[test]
fn a_veto_in_time_is_recorded_and_the_transition_never_activates() {
    let Some(mut w) = world_with("veto", "public", 1, true, false) else {
        return;
    };
    let ha = w.ha.clone();
    let mut ctl = w.controller(NOW);
    w.clocks(NOW);
    let d = w.f.d.clone();
    let digest = propose_by(&mut w, &mut ctl, 600, &[d]);
    let mut wire = w.wire();
    let faults = relay_pass(&mut ctl, &w.src, &ha, &mut wire, &w.host, NOW + 1_000);
    assert!(faults.is_empty(), "{faults:?}");
    // The owner vetoes it, in time, from the other unit (the passkey).
    let before = kinds(&w.a).len();
    let p = w.f.p.clone();
    let action = ctl.account().begin_veto(&digest, &[p]).unwrap();
    engine_finish(&mut ctl, &w.host, &w.src, action);
    let faults = relay_pass(&mut ctl, &w.src, &ha, &mut wire, &w.host, NOW + 2_000);
    assert!(faults.is_empty(), "{faults:?}");
    ticks_until("vetoed", 5, &[&w.a], || kinds(&w.a).len() > before);
    // Past the due time (issued + 300 s + the delay) the transition still does not activate.
    w.clocks(NOW + 3_600_000 + 600_000);
    for _ in 0..3 {
        w.a.tick();
    }
    let k = kinds(&w.a);
    assert_eq!(k[before..], ["vetoed"], "{k:?}");
}

#[test]
fn a_late_transition_is_refused_but_kept_and_served_and_a_forged_one_is_neither() {
    let Some(mut w) = world("late", "public", 1, false) else {
        return;
    };
    let mut ctl = w.controller(NOW);
    w.clocks(NOW);
    let digest = propose(&mut w, &mut ctl, 600);
    let env = pending_env(&ctl, &digest);
    // Forged: the body changed under the signature. Refused, stored nowhere, listed nowhere.
    let mut forged = env.clone();
    let body = String::from_utf8(STANDARD.decode(env["body"].as_str().unwrap()).unwrap()).unwrap();
    forged["body"] = json!(STANDARD.encode(body.replace("\"callWindow\":600", "\"callWindow\":601")));
    let (status, out) = w.a.post("/pending", &json!({"objects": [forged]}));
    assert_eq!(status, 422, "{out}");
    assert!(pending_list(&w.a).is_empty(), "nothing is stored that failed admission");
    // Early: the home's clock is before its `issued`.
    w.a.set_clock(NOW - 120_000);
    let (status, out) = w.a.post("/pending", &json!({"objects": [env.clone()]}));
    assert_eq!(status, 422, "{out}");
    assert_eq!(out, json!(["refused:early"]), "one result per refused object, in order");
    // Late: more than 300 s after `issued`. Refused with no receipt, and still kept and served.
    w.a.set_clock(NOW + 400_000);
    let (status, out) = w.a.post("/pending", &json!({"objects": [env.clone()]}));
    assert_eq!(status, 422, "{out}");
    assert_eq!(out, json!(["refused:late"]));
    let l = pending_list(&w.a);
    assert_eq!(kinds_of(&l, "transition"), 1, "served so the owner can veto it");
    assert_eq!(kinds_of(&l, "receipt"), 0, "and no receipt was signed");
}

#[test]
fn calls_an_unauthorized_read_a_replayed_call_and_a_call_for_another_audience() {
    let Some(mut w) = world("calls", "members", 1, false) else {
        return;
    };
    w.clocks(NOW);
    // A head near NOW (a head read settles the home: it signs one at least every
    // headMaxAge / 2), held.
    let mut head = Vec::new();
    ticks_until("a fresh head", 3, &[&w.a], || {
        let (s, b) = w.a.get("/head");
        s == 200 && {
            let v: Value = serde_json::from_slice(&b).unwrap();
            let body = STANDARD.decode(v["body"].as_str().unwrap()).unwrap();
            let h: Value = serde_json::from_slice(&body).unwrap();
            head = b;
            h["issued"].as_str().unwrap() >= "2026-11-11T11:00:00Z"
        }
    });
    w.f.account.advance(NOW).unwrap();
    w.f.account
        .merge(
            colophon_core::v05::account::Incoming {
                objects: colophon_core::v05::history::Objects {
                    heads: vec![head],
                    ..Default::default()
                },
                records: vec![],
            },
            NOW,
        )
        .unwrap();
    let path = "/authority?after=0&limit=2";
    let empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let with = |purpose: &str, audience: &str, args: Value, w: &World| -> Vec<u8> {
        home_call_with(&w.host, &w.f.account, audience, purpose, args, NOW, fresh_request_id())
    };
    let bound = |method: &str, p: &str, body: &str| json!({"method": method, "path": p, "body": body});
    let read = |relay: &Relay, call: Option<&[u8]>| -> (u16, Value) {
        let mut h = vec![];
        if let Some(c) = call {
            h.push(("Authorization".into(), format!("Colophon {}", URL_SAFE_NO_PAD.encode(c))));
        }
        let (s, _, b) = http(relay.port, "GET", &relay.url(path), &h, &[]);
        (s, serde_json::from_slice(&b).unwrap_or(Value::Null))
    };
    // No call: not served, and the answer names the scheme. A bearer token authorizes nothing.
    assert_eq!(read(&w.a, None).0, 401);
    let (s, hs, _) = http(w.a.port, "GET", &w.a.url(path), &Relay::bearer(), &[]);
    assert_eq!(s, 401);
    assert!(hs.iter().any(|(k, v)| k == "www-authenticate" && v == "Colophon"));
    // A call bound to this request: served.
    let good = with("colophon.home.read", BASE_A, bound("GET", path, empty), &w);
    assert_eq!(read(&w.a, Some(&good)).0, 200);
    // `colophon.history.read` (§13.4's purpose for the history) fits a GET too.
    let hist = with("colophon.history.read", BASE_A, bound("GET", path, empty), &w);
    assert_eq!(read(&w.a, Some(&hist)).0, 200);
    // The same call again: `refused:replay`, with a body that is JSON once: {"result": …}.
    assert_eq!(read(&w.a, Some(&good)), (403, json!({"result": "refused:replay"})));
    // A call made for another home's audience.
    let other = with("colophon.home.read", BASE_B, bound("GET", path, empty), &w);
    assert_eq!(read(&w.a, Some(&other)), (403, json!({"result": "refused:audience"})));
    // A purpose that does not fit the method.
    let write = with("colophon.home.write", BASE_A, bound("GET", path, empty), &w);
    assert_eq!(read(&w.a, Some(&write)), (403, json!({"result": "refused:outOfScope"})));
    // Args for another request: another method, another path, another body.
    for (what, args) in [
        ("method", bound("PUT", path, empty)),
        ("path", bound("GET", "/authority?after=0&limit=3", empty)),
        ("body", bound("GET", path, &"0".repeat(64))),
        ("no args", json!({})),
    ] {
        let c = with("colophon.home.read", BASE_A, args, &w);
        assert_eq!(read(&w.a, Some(&c)), (403, json!({"result": "refused:outOfScope"})), "{what}");
    }
}

#[test]
fn a_head_the_guard_refuses_is_not_signed() {
    let Some(mut w) = world("guard", "public", 1, false) else {
        return;
    };
    let mut ctl = w.controller(NOW);
    w.clocks(NOW);
    // A head at NOW exists once the tick has run on this clock.
    let head_seq = |relay: &Relay| -> (u64, String) {
        let (s, b) = relay.get("/head");
        assert_eq!(s, 200);
        let v: Value = serde_json::from_slice(&b).unwrap();
        let h: Value = serde_json::from_slice(&STANDARD.decode(v["body"].as_str().unwrap()).unwrap()).unwrap();
        (h["authority"]["seq"].as_u64().unwrap(), h["issued"].as_str().unwrap().to_string())
    };
    ticks_until("a head at NOW", 3, &[&w.a], || head_seq(&w.a).1.as_str() >= "2026-11-11T11:00:00Z");
    let (seq0, issued0) = head_seq(&w.a);
    // The clock steps back by 10 s and a new entry arrives: the home takes the entry, but a head
    // for it would not have a larger `issued`, so the guard (§13.3) refuses and nothing is signed.
    let id = w.host.identity(32);
    let req = request_for(&w.f, &w.host, &id, "Tablet", "device", terms_for(&[(NS, "write")]), NOW);
    let seed = w.host.fresh();
    let d = w.f.d.clone();
    let action = ctl
        .account()
        .begin_approve(&req.raw, terms_for(&[(NS, "write")]), &[d], seed, paired_on(ctl.account(), &req))
        .unwrap();
    engine_finish(&mut ctl, &w.host, &w.src, action);
    let (seq, entry) = ctl
        .account()
        .objects()
        .entries
        .iter()
        .map(|e| (entry_seq(e), serde_json::from_slice::<Value>(e).unwrap()))
        .max_by_key(|(s, _)| *s)
        .unwrap();
    w.a.set_clock(NOW - 10_000);
    let (status, body) = w.a.post("/authority", &json!({"from": seq, "entries": [entry], "receipts": []}));
    assert_eq!(status, 200, "{body}");
    for _ in 0..3 {
        w.a.tick(); // several passes
    }
    // No head was signed for the new entry, and the older one is not served in its place
    // (§13.3, revision 15: a due head that cannot be produced fails the read, retryably).
    let (s, hs, _) = http(w.a.port, "GET", &w.a.url("/head"), &[], &[]);
    assert_eq!(s, 503, "the due head cannot be produced yet");
    assert!(hs.iter().any(|(k, v)| k == "retry-after" && v == "1"));
    assert_eq!(w.a.get(&format!("/records/heads/{}.json", w.ha)).0, 503, "nor at its record path");
    let _ = (seq0, issued0);
    // The clock moves on: the next head is signed for it.
    w.a.set_clock(NOW + 5_000);
    ticks_until("the head to move on", 3, &[&w.a], || head_seq(&w.a).0 == seq);
}

#[test]
fn a_restart_in_the_middle_loses_nothing_receipts_nothing_twice_and_the_feed_resumes() {
    let Some(mut w) = world("restart", "public", 1, false) else {
        return;
    };
    let ha = w.ha.clone();
    let mut ctl = w.controller(NOW);
    w.clocks(NOW);
    let d = w.f.d.clone();
    let first = propose_by(&mut w, &mut ctl, 600, &[d]);
    let mut wire = w.wire();
    let faults = relay_pass(&mut ctl, &w.src, &ha, &mut wire, &w.host, NOW + 1_000);
    assert!(faults.is_empty(), "{faults:?}");
    let before = pending_list(&w.a);
    assert_eq!(kinds_of(&before, "receipt"), 1);
    let ka = HomeKeys::new(0x77);
    drop(wire);
    // The process is killed and started again on the same data directory (on a new port).
    let account = w.f.account.id().as_str().to_string();
    let a = std::mem::replace(&mut w.a, Relay::start(&ka, &account, BASE_A, w.scratch[2].path(), NOW, &[]));
    w.a = a.restart(&ka, NOW + 2_000, &[]);
    let after = pending_list(&w.a);
    assert_eq!(before, after, "the same objects with the same cursors");
    // The transition arrives again (a client retry): accepted, and no second receipt is made.
    let env = pending_env(&ctl, &first);
    let (status, body) = w.a.post("/pending", &json!({"objects": [env]}));
    assert_eq!(status, 200, "{body}");
    assert_eq!(kinds_of(&pending_list(&w.a), "receipt"), 1, "one receipt per object");
    // A new object gets a cursor above every earlier one: never reused.
    let max_before = before.iter().map(|o| o["seq"].as_u64().unwrap()).max().unwrap();
    let d = w.f.d.clone();
    let second = propose_by(&mut w, &mut ctl, 601, &[d]);
    let mut wire = w.wire();
    let faults = relay_pass(&mut ctl, &w.src, &ha, &mut wire, &w.host, NOW + 3_000);
    assert!(faults.is_empty(), "{faults:?}");
    let l = pending_list(&w.a);
    let new: Vec<u64> = l
        .iter()
        .filter(|o| o["digest"] == second.as_str())
        .map(|o| o["seq"].as_u64().unwrap())
        .collect();
    assert_eq!(new.len(), 1);
    assert!(new[0] > max_before, "new {new:?} after {max_before} in {l:?}");
    // The cursor resumes: from the last seq a client saw, only what came after is listed.
    let (s, b) = w.a.get(&format!("/pending?after={max_before}&limit=64"));
    assert_eq!(s, 200);
    let v: Value = serde_json::from_slice(&b).unwrap();
    assert!(v["objects"].as_array().unwrap().iter().all(|o| o["seq"].as_u64().unwrap() > max_before));
}

// ---------------------------------------------------------------------------------------------
// The 2026-11-15 check's attacks (A1–A11), ported: each failed before this fix round and passes
// after it.

const EMPTY_SHA: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

fn get_with(relay: &Relay, path: &str, call: Option<&[u8]>) -> (u16, Value) {
    let mut h = vec![];
    if let Some(c) = call {
        h.push(("Authorization".to_string(), format!("Colophon {}", URL_SAFE_NO_PAD.encode(c))));
    }
    let (s, _, b) = http(relay.port, "GET", &relay.url(path), &h, &[]);
    (s, serde_json::from_slice(&b).unwrap_or(Value::Null))
}
fn fresh_head(relay: &Relay, after: &str) -> Vec<u8> {
    let mut head = Vec::new();
    ticks_until("a fresh head", 3, &[relay], || {
        let (s, b) = relay.get("/head");
        s == 200 && {
            let v: Value = serde_json::from_slice(&b).unwrap();
            let h: Value = serde_json::from_slice(&STANDARD.decode(v["body"].as_str().unwrap()).unwrap()).unwrap();
            head = b;
            h["issued"].as_str().unwrap() >= after
        }
    });
    head
}
fn take_head(f: &mut Fixture, head: Vec<u8>, now: i64) {
    f.account.advance(now).unwrap();
    f.account
        .merge(
            colophon_core::v05::account::Incoming {
                objects: colophon_core::v05::history::Objects { heads: vec![head], ..Default::default() },
                records: vec![],
            },
            now,
        )
        .unwrap();
}

/// A1 (H1). Before: a stranger's genesis was held (200) and the owner refused for ever (409).
#[test]
fn a1_a_stranger_cannot_squat_a_fresh_home_slot() {
    if prerequisites().is_none() {
        return;
    }
    let ka = HomeKeys::new(0x77);
    let mut owner = create_with(&[NS], "members", 1);
    appoint_homes(&mut owner, &[(&ka, BASE_A)]);
    let squatter = create_with(&[NS], "public", 1);
    let scratch = Scratch::new("a1");
    let a = Relay::start(&ka, owner.account.id().as_str(), BASE_A, scratch.path(), T0 + 1_000, &[]);
    let genesis = entries_json(&squatter)[0].1.clone();
    let (s, b) = a.post("/authority", &json!({"from": 1, "entries": [genesis], "receipts": []}));
    assert_eq!((s, b), (422, json!({"result": "refused:outOfScope"})), "refused, nothing held");
    let all = entries_json(&owner);
    let entries: Vec<&Value> = all.iter().map(|(_, e)| e).collect();
    let (s, b) = a.post("/authority", &json!({"from": 1, "entries": entries, "receipts": []}));
    assert_eq!(s, 200, "the owner's first upload: {b}");
}

/// A2 (H2, L2). Before: a held genesis of a `members` account was served to anyone (200), and
/// `records/heads/*` needed a call.
#[test]
fn a2_an_unappointed_home_serves_nothing_and_the_head_is_always_public() {
    if prerequisites().is_none() {
        return;
    }
    let ka = HomeKeys::new(0x77);
    let mut owner = create_with(&[NS], "members", 1);
    appoint_homes(&mut owner, &[(&ka, BASE_A)]);
    let scratch = Scratch::new("a2");
    let a = Relay::start(&ka, owner.account.id().as_str(), BASE_A, scratch.path(), T0 + 1_000, &[]);
    let all = entries_json(&owner);
    let (s, _) = a.post("/authority", &json!({"from": 1, "entries": [all[0].1], "receipts": []}));
    assert_eq!(s, 200, "held");
    for p in ["/records/authority/00000001.json", "/authority?after=0&limit=64", "/pending?after=0&limit=64", "/head", "/changes"] {
        assert_eq!(a.get(p).0, 404, "{p} before appointment");
    }
    let entries: Vec<&Value> = all.iter().map(|(_, e)| e).collect();
    assert_eq!(a.post("/authority", &json!({"from": 1, "entries": entries, "receipts": []})).0, 200);
    assert_eq!(a.get("/records/authority/00000001.json").0, 401, "members: a call is needed");
    assert_eq!(a.get(&format!("/records/heads/{}.json", ka.id)).0, 200, "the head is public");
    assert_eq!(a.get("/head").0, 200);
}

/// A3 (M1). Before: an upload 400 s after creation was `refused:late`.
#[test]
fn a3_an_account_created_a_week_ago_can_make_its_first_upload() {
    if prerequisites().is_none() {
        return;
    }
    let ka = HomeKeys::new(0x77);
    let mut owner = create_with(&[NS], "public", 1);
    appoint_homes(&mut owner, &[(&ka, BASE_A)]);
    let scratch = Scratch::new("a3");
    let week = T0 + 7 * 24 * HOUR;
    let a = Relay::start(&ka, owner.account.id().as_str(), BASE_A, scratch.path(), week, &[]);
    first_upload(&a, &owner, week);
    assert_eq!(kinds(&a).len(), entries_json(&owner).len());
}

/// A4 (H5, L1). Before: one caller filled the global table and everyone got 429 (with a body
/// JSON-encoded twice). Now the share is per principal: the caller over its share is refused
/// alone, with `{"result":"refused:window"}`, and another principal is still served.
#[test]
fn a4_one_caller_over_its_share_is_refused_alone() {
    if prerequisites().is_none() {
        return;
    }
    let ka = HomeKeys::new(0x77);
    let mut f = create_with(&[NS], "members", 1);
    appoint_homes(&mut f, &[(&ka, BASE_A)]);
    let scratch = Scratch::new("a4");
    let a = Relay::start_with(&ka, f.account.id().as_str(), BASE_A, scratch.path(), T0 + 1_000, &[], 0, json!({"replayRows": 8, "requestsPerMinute": 0}));
    first_upload(&a, &f, T0 + 1_000);
    a.set_clock(NOW);
    let head = fresh_head(&a, "2026-11-11T11:00:00Z");
    take_head(&mut f, head, NOW);
    let path = "/authority?after=0&limit=1";
    let args = json!({"method": "GET", "path": path, "body": EMPTY_SHA});
    let (d, k) = (f.d.clone(), f.k.clone());
    let mut statuses = Vec::new();
    for _ in 0..65 {
        let c = call_as(&f.host, &f.account, "controller", &d, BASE_A, "colophon.home.read", args.clone(), NOW, fresh_request_id());
        statuses.push(get_with(&a, path, Some(&c)));
    }
    assert!(statuses[..64].iter().all(|(s, _)| *s == 200), "the share (64 rows at least) is served");
    assert_eq!(statuses[64], (429, json!({"result": "refused:window"})));
    // The kit is a `recover` controller: §13.4 lets it read the history (`colophon.history.read`).
    let c = call_as(&f.host, &f.account, "controller", &k, BASE_A, "colophon.history.read", args, NOW, fresh_request_id());
    assert_eq!(get_with(&a, path, Some(&c)).0, 200, "another principal is not locked out");
}

/// §12.3 step 7 and §13.4 over the relay: `colophon.history.read` reads the history only. The
/// kit (a `recover`-only controller) reads `/authority` with it, but its call for the change feed
/// or an existing blob chunk is 403 `refused:outOfScope`; a controller holding `control` reads
/// both with `colophon.home.read`. Before, every GET took `colophon.history.read` (200).
#[test]
fn a12_history_read_reads_the_history_and_not_the_records() {
    use sha2::{Digest, Sha256};
    if prerequisites().is_none() {
        return;
    }
    let ka = HomeKeys::new(0x77);
    let mut f = create_with(&[NS], "members", 1);
    appoint_homes(&mut f, &[(&ka, BASE_A)]);
    let scratch = Scratch::new("a12");
    let a = Relay::start(&ka, f.account.id().as_str(), BASE_A, scratch.path(), T0 + 1_000, &[]);
    first_upload(&a, &f, T0 + 1_000);
    a.set_clock(NOW);
    let head = fresh_head(&a, "2026-11-11T11:00:00Z");
    take_head(&mut f, head, NOW);
    let (d, k) = (f.d.clone(), f.k.clone());
    let call = |id: &str, purpose: &str, method: &str, path: &str, body: &[u8]| {
        let args = json!({"method": method, "path": path, "body": hex(&Sha256::digest(body))});
        call_as(&f.host, &f.account, "controller", id, BASE_A, purpose, args, NOW, fresh_request_id())
    };
    // A blob chunk the home holds, written by the controller.
    let chunk = b"a synthetic blob chunk".to_vec();
    let blob = format!("/records/blobs/{}", hex(&Sha256::digest(&chunk)));
    let c = call(&d, "colophon.home.write", "PUT", &blob, &chunk);
    let h = vec![
        ("Authorization".to_string(), format!("Colophon {}", URL_SAFE_NO_PAD.encode(&c))),
        ("If-None-Match".to_string(), "*".to_string()),
    ];
    let (s, _, _) = http(a.port, "PUT", &a.url(&blob), &h, &chunk);
    assert!((200..300).contains(&s), "the blob is stored: {s}");

    let refused = (403, json!({"result": "refused:outOfScope"}));
    for path in ["/changes?limit=500", blob.as_str()] {
        let c = call(&k, "colophon.history.read", "GET", path, b"");
        assert_eq!(get_with(&a, path, Some(&c)), refused, "{path}");
        let c = call(&k, "colophon.home.read", "GET", path, b"");
        assert_eq!(get_with(&a, path, Some(&c)), refused, "{path}");
        let c = call(&d, "colophon.home.read", "GET", path, b"");
        assert_eq!(get_with(&a, path, Some(&c)).0, 200, "{path}");
    }
    let path = "/authority?after=0&limit=1";
    let c = call(&k, "colophon.history.read", "GET", path, b"");
    assert_eq!(get_with(&a, path, Some(&c)).0, 200, "the kit reads the history");
}

/// A6 (H4) over the relay: `home-state.json` after 1 and 40 heads (before: 277,762 and 617,654
/// bytes).
#[test]
fn a6_the_home_state_file_does_not_grow_with_heads() {
    if prerequisites().is_none() {
        return;
    }
    let ka = HomeKeys::new(0x77);
    let mut f = create_with(&[NS], "public", 1);
    appoint_homes(&mut f, &[(&ka, BASE_A)]);
    let scratch = Scratch::new("a6");
    let a = Relay::start(&ka, f.account.id().as_str(), BASE_A, scratch.path(), T0, &[]);
    first_upload(&a, &f, T0 + 1_000);
    let state = scratch.path().join("data/home/home-state.json");
    let mut sizes = Vec::new();
    for i in 0..40i64 {
        let t = NOW + i * 150_000;
        a.set_clock(t);
        let want = colophon_core::v05::write::format_date(t);
        fresh_head(&a, &want);
        sizes.push(std::fs::metadata(&state).unwrap().len());
    }
    eprintln!("A6 home-state.json bytes after 1, 10, 20, 40 heads: {} {} {} {}", sizes[0], sizes[9], sizes[19], sizes[39]);
    assert!(sizes[39] <= sizes[0] + 256, "{sizes:?}");
}

/// A8 (H3). Before: an entry in `receipts` was admitted, never stored, and the home then served
/// no history (404). Now it is malformed and nothing changes.
#[test]
fn a8_an_entry_in_the_receipts_array_is_malformed_and_storage_follows_state() {
    let Some(mut w) = world("a8", "public", 1, false) else {
        return;
    };
    let mut ctl = w.controller(NOW);
    w.clocks(NOW);
    let id = w.host.identity(33);
    let req = request_for(&w.f, &w.host, &id, "Phone", "device", terms_for(&[(NS, "write")]), NOW);
    let seed = w.host.fresh();
    let action = ctl.account().begin_approve(&req.raw, terms_for(&[(NS, "write")]), &[w.f.d.clone()], seed, paired_on(ctl.account(), &req)).unwrap();
    engine_finish(&mut ctl, &w.host, &w.src, action);
    let all: Vec<(u64, Value)> = ctl.account().objects().entries.iter().map(|e| (entry_seq(e), serde_json::from_slice(e).unwrap())).collect();
    let (_, entry) = all.iter().max_by_key(|(s, _)| *s).unwrap().clone();
    let first = all.iter().find(|(s, _)| *s == 1).unwrap().1.clone();
    let before = kinds(&w.a);
    let head = w.a.get("/head").1;
    let (s, b) = w.a.post("/authority", &json!({"from": 1, "entries": [first], "receipts": [entry]}));
    assert_eq!((s, b), (422, json!({"result": "malformed"})));
    assert_eq!(kinds(&w.a), before, "the history is served, unchanged");
    assert_eq!(w.a.get("/head").1, head, "no head over anything new");
}

/// A10 (M2). Before: a peer's 422 `unavailable` moved the forwarding cursor past the objects,
/// and the peer never received them. Now they are offered again until it takes them.
#[test]
fn a10_an_object_a_peer_refused_for_now_is_forwarded_again() {
    let Some(mut w) = world_with("a10", "public", 1, true, false) else {
        return;
    };
    let (ha, kb) = (w.ha.clone(), HomeKeys::new(0x78));
    let x = T0 + 5_000;
    let mut ctl = w.controller(x);
    w.clocks(x);
    // B runs but does not hold the history yet: it answers `unavailable`.
    let b = Relay::start_on(&kb, w.f.account.id().as_str(), BASE_B, w.scratch[1].path(), x, &[(BASE_A, w.a.port)], 0);
    w.a.set_resolve(&[(BASE_B, b.port)]);
    let d = w.f.d.clone();
    propose_by(&mut w, &mut ctl, 600, &[d]);
    let mut wire = w.wire();
    let faults = relay_pass(&mut ctl, &w.src, &ha, &mut wire, &w.host, x + 1_000);
    assert!(faults.is_empty(), "{faults:?}");
    drop(wire);
    // A offers; B is not ready and answers `unavailable`, so A keeps the objects to offer again
    // (its saved forwarding state lists them for B).
    let forward = w.scratch[0].path().join("data/home/forward.json");
    let hb = kb.id.clone();
    forwarded("A's refused offers kept for B", &[&w.a], || {
        std::fs::read_to_string(&forward).ok().and_then(|t| serde_json::from_str::<Value>(&t).ok()).is_some_and(|v| {
            v["peers"][&hb]["retry"].as_array().is_some_and(|r| !r.is_empty())
        })
    });
    first_upload(&b, &w.f, x + 1_500);
    b.set_clock(x + 2_000);
    w.a.set_clock(x + 2_000);
    forwarded("B received the transition and A's receipt by forwarding", &[&w.a], || {
        let l = pending_list(&b);
        kinds_of(&l, "transition") == 1 && kinds_of(&l, "receipt") >= 1
    });
}

/// A11 (M5, M6). Before: the change feed listed a `members` account's history files to the
/// slot's bearer token. Now the bearer authorizes nothing; an authorized call is served.
#[test]
fn a11_the_change_feed_is_served_only_to_an_authorized_caller() {
    let Some(mut w) = world("a11", "members", 1, false) else {
        return;
    };
    w.clocks(NOW);
    let head = fresh_head(&w.a, "2026-11-11T11:00:00Z");
    take_head(&mut w.f, head, NOW);
    let (s, _, _) = http(w.a.port, "GET", &w.a.url("/changes"), &Relay::bearer(), &[]);
    assert_eq!(s, 401, "a bearer token is not a credential here");
    let c = home_call(&w.host, &w.f.account, BASE_A, "GET", "/changes", b"", NOW, fresh_request_id());
    let (s, v) = get_with(&w.a, "/changes", Some(&c));
    assert_eq!(s, 200);
    assert!(v["entries"].as_array().unwrap().iter().any(|e| e["path"].as_str().unwrap().starts_with("authority/")));
}

/// Two honest homes at `headQuorum` 2 append byte-identical `activate`, `final` and `vetoed`.
#[test]
fn two_homes_at_quorum_2_append_identical_activate_vetoed_and_final() {
    let Some(mut w) = world("identical", "public", 2, true) else {
        return;
    };
    let (ha, hb) = (w.ha.clone(), w.hb.clone());
    let d = w.f.d.clone();
    let get = |r: &Relay| -> Vec<Value> {
        let (_, body) = r.get("/authority?after=0&limit=64");
        serde_json::from_slice::<Value>(&body).unwrap()["entries"].as_array().unwrap().clone()
    };
    // A transition that activates: `activate`, then `final`.
    let mut ctl = w.controller(NOW);
    w.clocks(NOW);
    w.heads_exchanged(NOW);
    propose_by(&mut w, &mut ctl, 600, &[d.clone()]);
    let mut wire = w.wire();
    for (i, h) in [&ha, &hb].into_iter().enumerate() {
        let faults = relay_pass(&mut ctl, &w.src, h, &mut wire, &w.host, NOW + 1_000 + i as i64);
        assert!(faults.is_empty(), "{faults:?}");
    }
    drop(wire);
    let b = w.b.as_ref().unwrap();
    // Each home receipted it and gives the other its receipt: both hold both before it is due.
    for r in [&w.a, b] {
        forwarded("both receipts at each home", &w.homes(), || {
            let l = pending_list(r);
            kinds_of(&l, "transition") == 1 && kinds_of(&l, "receipt") == 2
        });
    }
    let before = kinds(&w.a).len();
    let later = NOW + 3_600_000 + 400_000;
    w.clocks(later);
    forwarded("activate and final at both", &w.homes(), || kinds(&w.a).len() >= before + 2 && kinds(b).len() >= before + 2);
    // A second transition, vetoed in time: `vetoed`.
    let t2 = later + 10_000;
    let mut ctl = w.controller(t2);
    w.clocks(t2);
    // The clocks moved on: each home signs its head over the `final` and gives it to the other.
    w.heads_exchanged(t2);
    let mut wire = w.wire();
    for (i, h) in [&ha, &hb].into_iter().enumerate() {
        let faults = relay_pass(&mut ctl, &w.src, h, &mut wire, &w.host, t2 + i as i64);
        assert!(faults.is_empty(), "{faults:?}");
    }
    drop(wire);
    let vetoed = propose_by(&mut w, &mut ctl, 900, &[d]);
    let mut wire = w.wire();
    for (i, h) in [&ha, &hb].into_iter().enumerate() {
        let faults = relay_pass(&mut ctl, &w.src, h, &mut wire, &w.host, t2 + 1_000 + i as i64);
        assert!(faults.is_empty(), "{faults:?}");
    }
    // Both homes hold both receipts of it before it is vetoed.
    for r in w.homes() {
        forwarded("both receipts of the second transition at each home", &w.homes(), || {
            let l = pending_list(r);
            kinds_of(&l, "transition") == 1 && kinds_of(&l, "receipt") == 2
        });
    }
    let p = w.f.p.clone();
    let action = ctl.account().begin_veto(&vetoed, &[p]).unwrap();
    engine_finish(&mut ctl, &w.host, &w.src, action);
    for (i, h) in [&ha, &hb].into_iter().enumerate() {
        let faults = relay_pass(&mut ctl, &w.src, h, &mut wire, &w.host, t2 + 3_000 + i as i64);
        assert!(faults.is_empty(), "{faults:?}");
    }
    drop(wire);
    w.clocks(t2 + 5_000);
    let b = w.b.as_ref().unwrap();
    forwarded("vetoed at both", &w.homes(), || kinds(&w.a).len() >= before + 3 && kinds(b).len() >= before + 3);
    let (ea, eb) = (get(&w.a), get(b));
    let ka = kinds(&w.a);
    assert_eq!(&ka[before..before + 3], &["activate", "final", "vetoed"], "{ka:?}");
    for i in before..before + 3 {
        assert_eq!(ea[i], eb[i], "{} is byte-identical at both homes", ka[i]);
    }
}
