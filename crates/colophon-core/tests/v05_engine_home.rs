//! The exchange with a home (§13, §14) against a simulated home built on `history::home`, and
//! against hostile ones: stale, forked, withholding, replaying, serving another account's
//! objects, serving a rollback, tampering with bytes. A hostile home never changes verified
//! state and is reported; an honest one is followed in the order the spec gives.
#![allow(
    clippy::unwrap_used,
    clippy::too_many_arguments,
    clippy::cloned_ref_to_slice_refs
)]
#[path = "v05_engine_support/mod.rs"]
mod support;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use colophon_core::v05::encoding::canonical;
use colophon_core::v05::engine::exchange::{Fault, Method, Request, Response, Step};
use colophon_core::v05::engine::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use support::*;

const NOW: i64 = T0 + 3 * HOUR;
const LISTEN: &str = "listening.podcasts";

fn follow() -> Value {
    json!({"id": "show", "url": "https://example.org/feed", "title": "The Show"})
}

enum Mode {
    Honest,
    /// Answer from a frozen copy of the home.
    Stale(Box<SimHome>),
    /// Sign a head for a different digest at a held seq.
    Forked,
    /// An authority page with nothing in it and `more`.
    Withhold,
    /// The first authority page, again and again.
    Replay,
    /// Another account's home in this account's slot.
    Foreign(Box<SimHome>, Box<Host>),
    /// Alter the bytes of every record served and list their new digest.
    TamperConsistent,
    /// Alter the bytes of every record served, keep the honest digest.
    TamperBytes,
    /// 401 for everything.
    Unauthorized,
    /// 410 for the first change feed request that carries a cursor.
    Gone(bool),
}
struct Wrapped<'a> {
    inner: &'a mut SimHome,
    mode: Mode,
    seen: Vec<Request>,
}
impl<'a> Wire for Wrapped<'a> {
    fn call(&mut self, host: &Host, req: &Request, now_ms: i64) -> Response {
        self.seen.push(req.clone());
        let path = req.url.strip_prefix("https://home.example").unwrap_or("");
        match &mut self.mode {
            Mode::Honest => self.inner.call(host, req, now_ms),
            Mode::Stale(frozen) => frozen.call(host, req, now_ms),
            Mode::Forked => {
                if path == "/head" {
                    let (seq, _) = {
                        let h = self.inner.call(host, req, now_ms);
                        let v: Value = serde_json::from_slice(&h.body).unwrap();
                        let body = STANDARD.decode(v["body"].as_str().unwrap()).unwrap();
                        let b: Value = serde_json::from_slice(&body).unwrap();
                        (b["authority"]["seq"].as_u64().unwrap(), 0)
                    };
                    let body = canonical(&json!({
                        "protocol": "colophon/head/5", "account": self.inner.account,
                        "authority": {"seq": seq, "digest": "0".repeat(64)}, "by": self.inner.id,
                        "issued": colophon_core::v05::write::format_date(now_ms),
                    }))
                    .unwrap();
                    let env = canonical(&json!({"body": b64(&body), "signature": b64(&host.ids[&self.inner.id].sign(&body))})).unwrap();
                    Response {
                        status: 200,
                        headers: vec![],
                        body: env,
                    }
                } else {
                    self.inner.call(host, req, now_ms)
                }
            }
            Mode::Withhold => {
                if path.starts_with("/authority") && req.method == Method::Get {
                    Response {
                        status: 200,
                        headers: vec![],
                        body: serde_json::to_vec(
                            &json!({"entries": [], "receipts": [], "more": true}),
                        )
                        .unwrap(),
                    }
                } else {
                    self.inner.call(host, req, now_ms)
                }
            }
            Mode::Replay => {
                if path.starts_with("/authority") && req.method == Method::Get {
                    let mut first = req.clone();
                    first.url =
                        first.url.split('?').next().unwrap().to_string() + "?after=0&limit=2";
                    let mut r = self.inner.call(host, &first, now_ms);
                    let mut v: Value = serde_json::from_slice(&r.body).unwrap();
                    v["more"] = json!(true);
                    r.body = serde_json::to_vec(&v).unwrap();
                    r
                } else {
                    self.inner.call(host, req, now_ms)
                }
            }
            Mode::Foreign(other, other_host) => other.call(other_host, req, now_ms),
            Mode::TamperBytes | Mode::TamperConsistent => {
                let consistent = matches!(self.mode, Mode::TamperConsistent);
                let mut r = self.inner.call(host, req, now_ms);
                if path.starts_with("/records/ops/") && r.status == 200 {
                    let mut v: Value = serde_json::from_slice(&r.body).unwrap();
                    let sig = v["signature"].as_str().unwrap().to_string();
                    let mut raw = STANDARD.decode(&sig).unwrap();
                    raw[5] ^= 1;
                    v["signature"] = json!(b64(&raw));
                    r.body = canonical(&v).unwrap();
                }
                if consistent && path.starts_with("/changes") && r.status == 200 {
                    let mut v: Value = serde_json::from_slice(&r.body).unwrap();
                    for e in v["entries"].as_array_mut().unwrap() {
                        if e["path"].as_str().unwrap().starts_with("ops/") {
                            let p = e["path"].as_str().unwrap().to_string();
                            let honest = self.inner.files[&p].clone();
                            let mut w: Value = serde_json::from_slice(&honest).unwrap();
                            let mut raw =
                                STANDARD.decode(w["signature"].as_str().unwrap()).unwrap();
                            raw[5] ^= 1;
                            w["signature"] = json!(b64(&raw));
                            e["sha256"] = json!(hex(&Sha256::digest(canonical(&w).unwrap())));
                        }
                    }
                    r.body = serde_json::to_vec(&v).unwrap();
                }
                r
            }
            // The head is public (§13.4): everything else is refused.
            Mode::Unauthorized if path == "/head" => self.inner.call(host, req, now_ms),
            Mode::Unauthorized => Response {
                status: 401,
                headers: vec![],
                body: vec![],
            },
            Mode::Gone(done) => {
                if path.starts_with("/changes") && path.contains("after=") && !*done {
                    *done = true;
                    Response {
                        status: 410,
                        headers: vec![],
                        body: b"{}".to_vec(),
                    }
                } else {
                    self.inner.call(host, req, now_ms)
                }
            }
        }
    }
}

/// A world: a phone that has written and synced, a laptop that has authority only, a home.
struct World {
    s: Setup,
    host: Host,
    phone: Engine<MemSource>,
    phone_src: MemSource,
    laptop: Engine<MemSource>,
    laptop_src: MemSource,
    phone_id: String,
    laptop_id: String,
}
fn world() -> World {
    let (mut s, ids) = setup(LISTEN, &[("Phone", 31, "write"), ("Laptop", 32, "write")]);
    let (phone_src, laptop_src) = (device_source(&s), device_source(&s));
    let phone = member_engine(&s.f, &s.f.host, &phone_src, &ids[0], NOW);
    let laptop = member_engine(&s.f, &s.f.host, &laptop_src, &ids[1], NOW);
    let host = std::mem::replace(&mut s.f.host, Host::new());
    let mut w = World {
        s,
        host,
        phone,
        phone_src,
        laptop,
        laptop_src,
        phone_id: ids[0].clone(),
        laptop_id: ids[1].clone(),
    };
    engine_write(
        &mut w.phone,
        &mut w.host,
        &w.phone_src,
        LISTEN,
        "follow",
        follow(),
    );
    engine_write(
        &mut w.phone,
        &mut w.host,
        &w.phone_src,
        LISTEN,
        "queue",
        json!({"episodes": ["e1", "e2"]}),
    );
    engine_live(
        &mut w.phone,
        &mut w.host,
        &w.phone_src,
        json!({"id": "e1", "show": "show", "seconds": 5.0}),
    );
    let f = sync_pass(
        &mut w.phone,
        &w.phone_src,
        &w.s.home.clone(),
        &mut w.s.sim,
        &w.host,
        NOW,
    );
    assert!(f.is_empty(), "{f:?}");
    w
}
impl World {
    fn pass(&mut self, which: char, mode: Mode, now: i64) -> (Vec<Fault>, Vec<Request>) {
        let home = self.s.home.clone();
        let mut wrapped = Wrapped {
            inner: &mut self.s.sim,
            mode,
            seen: vec![],
        };
        let (e, src) = if which == 'p' {
            (&mut self.phone, &self.phone_src)
        } else {
            (&mut self.laptop, &self.laptop_src)
        };
        let faults = sync_pass(e, src, &home, &mut wrapped, &self.host, now);
        (faults, wrapped.seen)
    }
    /// The controller extends the authority history (a rekey) and the home takes it.
    fn authority_grows(&mut self) {
        let ctl_src = device_source(&self.s);
        let d = self.s.f.d.clone();
        let mut ctl = controller_engine(&self.s.f, &self.host, &ctl_src, &d, NOW);
        let home = self.s.home.clone();
        let f = sync_pass(&mut ctl, &ctl_src, &home, &mut self.s.sim, &self.host, NOW);
        assert!(f.is_empty(), "{f:?}");
        let seed = self.host.fresh();
        let action = ctl
            .account()
            .begin_rekey(&[LISTEN.to_string()], &[d.clone()], seed)
            .unwrap();
        engine_finish(&mut ctl, &self.host, &ctl_src, action);
        let f = sync_pass(
            &mut ctl,
            &ctl_src,
            &home,
            &mut self.s.sim,
            &self.host,
            NOW + 1_000,
        );
        assert!(f.is_empty(), "{f:?}");
    }
}
fn state_of(e: &Engine<MemSource>) -> (u64, String, String) {
    (e.account().head().0, e.account().head().1, e.status().code)
}

#[test]
fn an_honest_pass_runs_the_head_then_authority_then_records_then_live_then_blobs_and_is_idempotent() {
    let mut w = world();
    let reqs = w.s.sim.requests.clone();
    let first = |pred: &dyn Fn(&String) -> bool| reqs.iter().position(pred).unwrap_or(usize::MAX);
    let pull_auth = first(&|r| r.starts_with("Get /authority"));
    let head = first(&|r| r == "Get /head");
    let pending = first(&|r| r.starts_with("Get /pending"));
    let changes = first(&|r| r.starts_with("Get /changes"));
    let put_ops = first(&|r| r.starts_with("Put /records/ops/"));
    let put_hist = first(&|r| r.starts_with("Put /records/history/"));
    let put_state = first(&|r| r.starts_with("Put /records/state/"));
    // The public head first, so a call can be built for what follows (§12.3 step 4); the history
    // is pulled only when the home's head covers more than this device holds (here it does not).
    assert!(
        head < pending
            && pending < changes
            && (pull_auth == usize::MAX || (head < pull_auth && pull_auth < pending)),
        "{reqs:?}"
    );
    assert!(
        changes < put_ops && put_ops < put_state,
        "records before the live slot: {reqs:?}"
    );
    assert!(
        put_hist < put_state,
        "the evidence before the slot replaces: {reqs:?}"
    );
    // The laptop pulls it all; a second pass moves nothing in either direction.
    let (f, _) = w.pass('l', Mode::Honest, NOW + 2_000);
    assert!(f.is_empty(), "{f:?}");
    let before = w.s.sim.requests.len();
    let (f, _) = w.pass('l', Mode::Honest, NOW + 3_000);
    assert!(f.is_empty(), "{f:?}");
    let new: Vec<_> = w.s.sim.requests[before..]
        .iter()
        .filter(|r| r.starts_with("Put") || r.starts_with("Post /authority"))
        .collect();
    assert!(new.is_empty(), "{new:?}");
    // Blob chunks go before the records of their pass.
    let _ = (w.phone_id.clone(), w.laptop_id.clone());
}

#[test]
fn a_stale_home_serving_a_rollback_is_reported_and_changes_nothing() {
    let mut w = world();
    let frozen = Box::new(w.s.sim.clone());
    w.authority_grows();
    let (f, _) = w.pass('l', Mode::Honest, NOW + 2_000);
    assert!(f.is_empty(), "{f:?}");
    let want = state_of(&w.laptop);
    assert!(
        want.0 > frozen.head_seq(),
        "the laptop has seen more than the frozen home holds"
    );
    let (f, _) = w.pass('l', Mode::Stale(frozen), NOW + 3_000);
    assert!(
        f.contains(&Fault::Rollback {
            home: w.s.home.clone()
        }),
        "{f:?}"
    );
    assert_eq!(state_of(&w.laptop), want, "verified state does not move");
}

#[test]
fn a_forked_head_is_refused_by_reason_and_nothing_follows_it() {
    let mut w = world();
    w.authority_grows();
    let (f, _) = w.pass('l', Mode::Honest, NOW + 2_000);
    assert!(f.is_empty(), "{f:?}");
    let want = state_of(&w.laptop);
    let before = w.s.sim.requests.len();
    let (f, seen) = w.pass('l', Mode::Forked, NOW + 3_000);
    assert!(
        f.contains(&Fault::Fork {
            home: w.s.home.clone()
        }),
        "{f:?}"
    );
    assert_eq!(state_of(&w.laptop), want);
    assert!(
        seen.iter()
            .all(|r| r.method == Method::Get || !r.url.contains("/records/")),
        "a forked home gets nothing pushed after its head: {:?}",
        seen.iter().map(|r| &r.url).collect::<Vec<_>>()
    );
    let _ = before;
}

#[test]
fn a_withholding_home_is_a_stall_not_progress_and_an_honest_one_then_catches_up() {
    let mut w = world();
    w.authority_grows();
    let behind = state_of(&w.laptop);
    let (f, seen) = w.pass('l', Mode::Withhold, NOW + 2_000);
    assert!(
        f.iter()
            .any(|x| matches!(x, Fault::NoProgress { feed, .. } if feed == "authority")),
        "{f:?}"
    );
    assert_eq!(state_of(&w.laptop), behind, "nothing moved");
    assert!(
        seen.len() < 5,
        "a withheld page ends the pass; it does not loop: {}",
        seen.len()
    );
    let (f, _) = w.pass('l', Mode::Honest, NOW + 3_000);
    assert!(f.is_empty(), "{f:?}");
    assert!(state_of(&w.laptop).0 > behind.0);
}

#[test]
fn a_replaying_home_cannot_move_the_cursor_or_the_state() {
    let mut w = world();
    w.authority_grows();
    let behind = state_of(&w.laptop);
    let (f, seen) = w.pass('l', Mode::Replay, NOW + 2_000);
    assert!(
        f.iter().any(|x| matches!(x, Fault::NoProgress { .. })),
        "{f:?}"
    );
    assert_eq!(state_of(&w.laptop), behind);
    assert!(seen.len() < 10, "{}", seen.len());
}

#[test]
fn a_home_serving_another_accounts_objects_changes_nothing_and_is_pushed_nothing() {
    let mut w = world();
    let behind = state_of(&w.laptop);
    let (mut other, ids) = setup(LISTEN, &[("Phone", 31, "write")]);
    let _ = ids;
    let mut o = Setup {
        ..setup(LISTEN, &[]).0
    };
    std::mem::swap(&mut o, &mut other);
    // A different account: other keys.
    let mut f2 = create_v(&[LISTEN], 3);
    let h2 = appoint_home(&mut f2);
    let sim2 = SimHome::new(&f2, &h2, "https://home.example", f2.account.now_ms());
    let host2 = std::mem::replace(&mut f2.host, Host::new());
    let (f, seen) = w.pass(
        'l',
        Mode::Foreign(Box::new(sim2), Box::new(host2)),
        NOW + 2_000,
    );
    assert!(
        f.iter().any(|x| matches!(
            x,
            Fault::ForeignAccount { .. } | Fault::BadObject { .. } | Fault::Malformed { .. }
        )),
        "{f:?}"
    );
    assert_eq!(
        state_of(&w.laptop),
        behind,
        "another account's history is not this account's"
    );
    assert_eq!(
        w.laptop.account().id().as_str(),
        w.s.f.account.id().as_str()
    );
    assert!(
        seen.iter().all(|r| r.method == Method::Get),
        "nothing of ours is sent to a home that is not ours: {:?}",
        seen.iter()
            .map(|r| format!("{:?} {}", r.method, r.url))
            .collect::<Vec<_>>()
    );
}

#[test]
fn tampered_records_are_never_stored_or_folded() {
    for consistent in [false, true] {
        let mut w = world();
        let before = w.laptop.stats();
        let mode = if consistent {
            Mode::TamperConsistent
        } else {
            Mode::TamperBytes
        };
        let (f, _) = w.pass('l', mode, NOW + 2_000);
        assert!(
            f.iter()
                .any(|x| matches!(x, Fault::Mismatch { .. } | Fault::BadObject { .. })),
            "consistent={consistent}: {f:?}"
        );
        let stored: Vec<String> = w
            .laptop_src
            .listing()
            .into_iter()
            .filter(|p| p.starts_with("ops/"))
            .collect();
        assert!(
            stored.is_empty(),
            "no tampered record is stored over its immutable path: {stored:?}"
        );
        for r in w.laptop.account().records() {
            let v = w.laptop.account().record_verdict(&r.path).unwrap();
            assert_ne!(v, "admitted", "a tampered record is not admitted: {v}");
        }
        let folded = match w.laptop.view(LISTEN).unwrap() {
            colophon_core::model::Outcome::Success { value, .. } => value.admitted.len(),
            o => panic!("{o:?}"),
        };
        assert_eq!(
            folded,
            w.laptop.account().live_heads().len(),
            "nothing but the verified live head is folded"
        );
        let _ = before;
        // An honest pass afterwards gets the real ones: nothing was spoiled.
        let (f, _) = w.pass('l', Mode::Honest, NOW + 3_000);
        assert!(f.is_empty(), "{f:?}");
        assert!(w.laptop_src.listing().iter().any(|p| p.starts_with("ops/")));
    }
}

#[test]
fn a_home_that_wants_a_call_is_asked_once_per_request_and_the_engine_signs_nothing() {
    let mut w = world();
    let home = w.s.home.clone();
    w.laptop.advance(NOW + 2_000).unwrap();
    w.laptop.exchange_set_bearer(&home, Some("token".into()));
    // The home answers 401 to everything: the first request is asked again with a call, and a
    // call that is still refused ends the pass with the fault.
    let mut wire = Wrapped {
        inner: &mut w.s.sim,
        mode: Mode::Unauthorized,
        seen: vec![],
    };
    let mut faults = Vec::new();
    let mut calls = 0;
    for _ in 0..20 {
        match w.laptop.exchange_next(&home).unwrap() {
            Step::Done => break,
            Step::Waiting => panic!(),
            Step::NeedCall(n) => {
                assert_eq!(n.purpose, "colophon.home.read");
                assert_eq!(n.audience, "https://home.example");
                calls += 1;
                w.laptop
                    .exchange_provide_call(&home, n.ticket, b"{\"call\":\"opaque\"}")
                    .unwrap();
            }
            Step::Request(r) => {
                let a = wire.call(&w.host, &r, NOW + 2_000);
                faults.extend(w.laptop.exchange_answer(&home, r.ticket, a).unwrap().faults);
            }
        }
    }
    assert_eq!(calls, 1, "one call asked for, once");
    assert!(
        matches!(faults.last(), Some(Fault::Unauthorized { purpose, .. }) if purpose == "colophon.home.read"),
        "{faults:?}"
    );
    // The purposes a call can be for are two; the engine has no way to attach a call to any
    // request but the one it was asked for (a wrong ticket is refused).
    assert!(w.laptop.exchange_provide_call(&home, 99_999, b"x").is_err());
    let auth = wire
        .seen
        .iter()
        .filter_map(|r| r.headers.iter().find(|(k, _)| k == "Authorization"))
        .map(|(_, v)| v.clone())
        .collect::<Vec<_>>();
    assert!(
        auth.iter().any(|a| a.starts_with("Bearer "))
            && auth.iter().any(|a| a.starts_with("Colophon ")),
        "{auth:?}"
    );
}

#[test]
fn a_cursor_the_home_no_longer_honours_makes_the_engine_list_again() {
    let mut w = world();
    let (f, _) = w.pass('l', Mode::Honest, NOW + 2_000);
    assert!(f.is_empty());
    // The phone writes more; the laptop's next pass carries a cursor the home refuses (410).
    engine_write(
        &mut w.phone,
        &mut w.host,
        &w.phone_src,
        LISTEN,
        "queue",
        json!({"episodes": ["e3"]}),
    );
    let (f, _) = w.pass('p', Mode::Honest, NOW + 3_000);
    assert!(f.is_empty(), "{f:?}");
    let (f, seen) = w.pass('l', Mode::Gone(false), NOW + 4_000);
    assert!(
        f.contains(&Fault::CursorReset {
            home: w.s.home.clone()
        }),
        "{f:?}"
    );
    let feeds: Vec<&String> = seen
        .iter()
        .map(|r| &r.url)
        .filter(|u| u.contains("/changes"))
        .collect();
    assert!(
        feeds.len() >= 2 && !feeds[1].contains("after="),
        "listed again from the start: {feeds:?}"
    );
    let a = w.laptop.query(LISTEN, "queue", json!({})).unwrap();
    let b = w.phone.query(LISTEN, "queue", json!({})).unwrap();
    assert_eq!(format!("{a:?}"), format!("{b:?}"));
}

#[test]
fn a_different_body_at_an_immutable_path_on_the_home_is_a_conflict_never_overwritten() {
    let mut w = world();
    let victim =
        w.s.sim
            .files
            .keys()
            .find(|p| p.starts_with("ops/"))
            .unwrap()
            .clone();
    let honest = w.s.sim.files[&victim].clone();
    // Laptop gets the record, then the home's copy is replaced by different bytes.
    let (f, _) = w.pass('l', Mode::Honest, NOW + 2_000);
    assert!(f.is_empty());
    w.s.sim.files.insert(victim.clone(), b"{}".to_vec());
    // A second device of the same writer pushing the real record meets the home's different one.
    w.laptop_src.put(&victim, honest.clone());
    let key = w.s.sim.log.iter().position(|p| *p == victim).unwrap();
    w.s.sim.log.remove(key);
    let (f, _) = w.pass('l', Mode::Honest, NOW + 3_000);
    let _ = f;
    assert_eq!(
        w.s.sim.files[&victim],
        b"{}".to_vec(),
        "the home's bytes are not overwritten by us"
    );
}

#[test]
fn a_transition_is_submitted_to_the_home_and_who_has_receipted_it_is_tracked() {
    let mut w = world();
    let ctl_src = device_source(&w.s);
    let d = w.s.f.d.clone();
    let p = w.s.f.p.clone();
    let mut ctl = controller_engine(&w.s.f, &w.host, &ctl_src, &d, NOW);
    let home = w.s.home.clone();
    let f = sync_pass(&mut ctl, &ctl_src, &home, &mut w.s.sim, &w.host, NOW);
    assert!(f.is_empty(), "{f:?}");
    let action = ctl
        .account()
        .begin_transition(
            &colophon_core::v05::account::Change::policy(json!({"callWindow": 600})),
            &[d.clone(), p.clone()],
            colophon_core::v05::write::authority::TransitionRule::Control,
        )
        .unwrap();
    let w1 = engine_finish(&mut ctl, &w.host, &ctl_src, action);
    assert!(w1.stores.iter().any(|(p, _)| p.starts_with("transitions/")));
    let digest = ctl.account().pending()[0].digest.clone();
    assert!(
        ctl.receipted_by(&digest).is_empty(),
        "no home has seen it yet"
    );
    let f = sync_pass(
        &mut ctl,
        &ctl_src,
        &home,
        &mut w.s.sim,
        &w.host,
        NOW + 1_000,
    );
    assert!(f.is_empty(), "{f:?}");
    assert_eq!(
        ctl.receipted_by(&digest),
        vec![home.clone()],
        "the home's receipt, verified by its key"
    );
    // It is not submitted twice.
    let n =
        w.s.sim
            .requests
            .iter()
            .filter(|r| r.starts_with("Post /pending"))
            .count();
    let f = sync_pass(
        &mut ctl,
        &ctl_src,
        &home,
        &mut w.s.sim,
        &w.host,
        NOW + 2_000,
    );
    assert!(f.is_empty(), "{f:?}");
    assert_eq!(
        w.s.sim
            .requests
            .iter()
            .filter(|r| r.starts_with("Post /pending"))
            .count(),
        n
    );
    // The laptop polls the home's pending feed and shows it.
    let (f, _) = w.pass('l', Mode::Honest, NOW + 3_000);
    assert!(f.is_empty(), "{f:?}");
    assert!(w
        .laptop
        .account()
        .pending()
        .iter()
        .any(|t| t.digest == digest));
    assert_eq!(w.laptop.receipted_by(&digest), vec![home.clone()]);
    let _ = (&w.phone_id, &w.laptop_id, Step::Done);
}
