//! What only a home does (§13, §14), against the real relay: a transition receipted, due,
//! activated and made final across two homes at `headQuorum` 2; primary-home ordering; a veto in
//! time; a late object; forged and replayed objects; calls for another audience and no call; a
//! head the guard refuses; a restart in the middle.
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
use colophon_core::v05::account::{CallTarget, Change};
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
    pa: u16,
    pb: u16,
    src: MemSource,
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
    let (pa, pb) = (free_port(), free_port());
    let a = Relay::start_on(&ka, BASE_A, &dir(&format!("{name}-a")), T0, &[(BASE_B, pb)], pa);
    first_upload(&a, &f, T0 + 1_000);
    let b = run_b.then(|| {
        let b = Relay::start_on(&kb, BASE_B, &dir(&format!("{name}-b")), T0, &[(BASE_A, pa)], pb);
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
        pa,
        pb,
    })
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
    // The transition is submitted to both homes; each receipts it.
    let d = w.f.d.clone();
    let digest = propose_by(&mut w, &mut ctl, 600, &[d]);
    let mut wire = w.wire();
    for (i, h) in [&ha, &hb].into_iter().enumerate() {
        let faults = sync_pass(&mut ctl, &w.src, h, &mut wire, &w.host, NOW + 1_000 + i as i64);
        assert!(faults.is_empty(), "{faults:?}");
    }
    let mut seen = ctl.receipted_by(&digest);
    seen.sort();
    let mut both = vec![ha.clone(), hb.clone()];
    both.sort();
    assert_eq!(seen, both, "each home signed one receipt");
    // Before it is due: listed once, with one receipt per home, on each home.
    for r in [&w.a, w.b.as_ref().unwrap()] {
        eventually("both receipts at a home", 20, || {
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
        let end = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while std::time::Instant::now() < end && !{
            let k = kinds(r);
            k.len() > before && k[before] == "activate"
        } {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(
            kinds(r)[before] == "activate",
            "a: {:?} b: {:?}",
            kinds(&w.a),
            kinds(w.b.as_ref().unwrap())
        );
    }
    // The real client takes it from the homes and verifies it: the policy changed, no pending.
    let mut wire = w.wire();
    for h in [&ha, &hb] {
        let faults = sync_pass(&mut ctl, &w.src, h, &mut wire, &w.host, later + 2_000);
        assert!(faults.is_empty(), "{faults:?}");
    }
    assert!(ctl.account().pending().is_empty(), "recorded, no longer pending");
    assert_eq!(ctl.account().head().0 as usize, before + 2);
    // Once recorded the transition is no longer listed.
    assert_eq!(kinds_of(&pending_list(&w.a), "transition"), 0);
    let _ = (w.pa, w.pb, &w.ka, &w.kb);
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
        .begin_approve(&req.raw, granted, &[d], seed)
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
    assert!(body["head"].is_object());
    eventually("the second home to hold the primary's head over it", 20, || {
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
    let faults = sync_pass(&mut ctl, &w.src, &ha, &mut wire, &w.host, NOW + 1_000);
    assert!(faults.is_empty(), "{faults:?}");
    // The owner vetoes it, in time, from the other unit (the passkey).
    let before = kinds(&w.a).len();
    let p = w.f.p.clone();
    let action = ctl.account().begin_veto(&digest, &[p]).unwrap();
    engine_finish(&mut ctl, &w.host, &w.src, action);
    let faults = sync_pass(&mut ctl, &w.src, &ha, &mut wire, &w.host, NOW + 2_000);
    assert!(faults.is_empty(), "{faults:?}");
    eventually("vetoed", 30, || kinds(&w.a).len() > before);
    // Past the due time (issued + 300 s + the delay) the transition still does not activate.
    w.clocks(NOW + 3_600_000 + 600_000);
    std::thread::sleep(std::time::Duration::from_millis(500));
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
    assert_eq!(out[0]["result"], "refused:early");
    // Late: more than 300 s after `issued`. Refused with no receipt, and still kept and served.
    w.a.set_clock(NOW + 400_000);
    let (status, out) = w.a.post("/pending", &json!({"objects": [env.clone()]}));
    assert_eq!(status, 422, "{out}");
    assert_eq!(out[0]["result"], "refused:late");
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
    // Wait for a head near NOW (the home signs one at least every headMaxAge / 2), and hold it.
    let mut head = Vec::new();
    eventually("a fresh head", 20, || {
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
    let d_point = w.host.ids[&w.f.d].public().signing;
    let call = |audience: &str, id: u8, w: &mut World| -> Vec<u8> {
        let action = w
            .f
            .account
            .begin_call(
                &d_point,
                &[],
                audience,
                "colophon.history.read",
                json!({}),
                [id; 32],
                CallTarget {
                    audiences: vec![audience.to_string()],
                    home_endpoints: vec![audience.to_string()],
                    ..Default::default()
                },
            )
            .unwrap();
        let sigs = w.host.sign(action.steps());
        w.f.account.finish(action, sigs).unwrap().artifact.unwrap()
    };
    let read = |relay: &Relay, call: Option<&[u8]>| -> (u16, Vec<u8>) {
        let mut h = vec![];
        if let Some(c) = call {
            h.push(("Authorization".into(), format!("Colophon {}", URL_SAFE_NO_PAD.encode(c))));
        }
        let (s, _, b) = http(relay.port, "GET", &relay.url("/authority?after=0&limit=2"), &h, &[]);
        (s, b)
    };
    // No call: not served. A bearer token is storage access only: not served either.
    assert_eq!(read(&w.a, None).0, 401);
    let (s, _, _) = http(
        w.a.port,
        "GET",
        &w.a.url("/authority?after=0&limit=2"),
        &Relay::bearer(),
        &[],
    );
    assert_eq!(s, 401);
    // A valid call: served.
    let good = call(BASE_A, 1, &mut w);
    assert_eq!(read(&w.a, Some(&good)).0, 200);
    // The same call again: `refused:replay`.
    let (s, b) = read(&w.a, Some(&good));
    assert_eq!(s, 403);
    assert!(String::from_utf8_lossy(&b).contains("refused:replay"), "{}", String::from_utf8_lossy(&b));
    // A call made for another audience.
    let other = call(BASE_B, 2, &mut w);
    let (s, b) = read(&w.a, Some(&other));
    assert_eq!(s, 403);
    assert!(String::from_utf8_lossy(&b).contains("refused:audience"), "{}", String::from_utf8_lossy(&b));
    // A call with the wrong purpose for this endpoint.
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
    eventually("a head at NOW", 20, || head_seq(&w.a).1.as_str() >= "2026-11-11T11:00:00Z");
    let (seq0, issued0) = head_seq(&w.a);
    // The clock steps back by 10 s and a new entry arrives: the home takes the entry, but a head
    // for it would not have a larger `issued`, so the guard (§13.3) refuses and nothing is signed.
    let id = w.host.identity(32);
    let req = request_for(&w.f, &w.host, &id, "Tablet", "device", terms_for(&[(NS, "write")]), NOW);
    let seed = w.host.fresh();
    let d = w.f.d.clone();
    let action = ctl
        .account()
        .begin_approve(&req.raw, terms_for(&[(NS, "write")]), &[d], seed)
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
    std::thread::sleep(std::time::Duration::from_millis(400)); // several ticks
    let (seq1, issued1) = head_seq(&w.a);
    assert_eq!((seq1, issued1), (seq0, issued0), "no head was signed for the new entry");
    // The clock moves on: the next head is signed for it.
    w.a.set_clock(NOW + 5_000);
    eventually("the head to move on", 20, || head_seq(&w.a).0 == seq);
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
    let faults = sync_pass(&mut ctl, &w.src, &ha, &mut wire, &w.host, NOW + 1_000);
    assert!(faults.is_empty(), "{faults:?}");
    let before = pending_list(&w.a);
    assert_eq!(kinds_of(&before, "receipt"), 1);
    let ka = HomeKeys::new(0x77);
    drop(wire);
    // The process is killed and started again on the same data directory and port.
    let a = std::mem::replace(&mut w.a, Relay::start(&ka, BASE_A, &dir("restart-spare"), NOW, &[]));
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
    let faults = sync_pass(&mut ctl, &w.src, &ha, &mut wire, &w.host, NOW + 3_000);
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
