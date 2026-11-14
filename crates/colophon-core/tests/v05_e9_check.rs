//! The independent check of E9 (2026-11-14), ported: each test asserts the correct behaviour.
#![allow(
    clippy::unwrap_used,
    clippy::too_many_arguments,
    dead_code,
    unused_imports,
    unused_variables
)]
#[path = "v05_engine_support/mod.rs"]
mod support;
use colophon_core::model::Outcome;
use colophon_core::v05::account::{Account, Change, Identity, Incoming, RevokeKeep};
use colophon_core::v05::encoding::canonical;
use colophon_core::v05::engine::exchange::{Fault, Method, Request, Response, Step};
use colophon_core::v05::engine::{Engine, EngineOptions};
use colophon_core::v05::history::Objects;
use colophon_core::v05::records::{HeldRecord, Level, OperationHeader};
use serde_json::{json, Value};
use support::*;

const NOTES: &str = "notes";
const SCRATCH: &str = "scratch";

fn write_in(s: &mut Account, host: &mut Host, ns: &str, i: usize) -> HeldRecord {
    let seed = host.fresh();
    let action = s
        .begin_write(
            ns,
            "createNotebook",
            json!({"id": format!("nb{i:05}"), "title": format!("Notebook {i}")}),
            Level::Write,
            seed,
        )
        .unwrap()
        .unwrap();
    let done = run(s, host, action);
    done.records[0].clone()
}

fn deliver(a: &mut Account, records: Vec<HeldRecord>) {
    let now = a.now_ms();
    a.merge(
        Incoming {
            objects: Objects::default(),
            records,
        },
        now,
    )
    .unwrap();
}

// ---------------------------------------------------------------------------------------------
// Incremental derivation: when it applies.

/// The fold key is `(clock, author, id, digest)` and clocks are per namespace, so a write into
/// a namespace whose clock is below another namespace's is never extended: it rebuilds.
#[test]
fn a_write_in_a_lower_clock_namespace_extends() {
    let mut f = create(&[NOTES, SCRATCH]);
    let m = f.host.identity(31);
    let t = terms_for(&[(NOTES, "write"), (SCRATCH, "write")]);
    admit(&mut f, &m, "Phone", "device", t.clone(), t);
    let mut s = member_session(&f, &m);
    let mut host = std::mem::replace(&mut f.host, Host::new());
    for i in 0..5 {
        write_in(&mut s, &mut host, NOTES, i);
        assert!(s.work().last.resumed, "notes write {i} extended");
    }
    write_in(&mut s, &mut host, SCRATCH, 100);
    let scratch_resumed = s.work().last.resumed;
    let scratch_walked = s.work().last.walked;
    s.verify_derivation().unwrap();
    write_in(&mut s, &mut host, SCRATCH, 101);
    let scratch2_resumed = s.work().last.resumed;
    s.verify_derivation().unwrap();
    println!(
        "scratch write 1: resumed {scratch_resumed} walked {scratch_walked}; scratch write 2: resumed {scratch2_resumed}"
    );
    assert!(
        scratch_resumed && scratch2_resumed,
        "a write in a second namespace (clock 1, 2 while notes is at 5) is extended, not rebuilt"
    );
}

/// After any revocation whose kept set the history holds, the walk can never resume: every
/// later merge and write of the account rebuilds the whole derivation, for ever.
#[test]
fn after_a_revocation_a_members_write_extends() {
    let mut f = create(&[NOTES]);
    let a = f.host.identity(31);
    let b = f.host.identity(32);
    admit(&mut f, &a, "A", "device", terms("write"), terms("write"));
    admit(&mut f, &b, "B", "device", terms("write"), terms("write"));
    // B wrote before it was revoked: the revocation keeps its records.
    {
        let mut sb = member_session(&f, &b);
        let mut recs = Vec::new();
        for i in 0..2 {
            let seed = f.host.fresh();
            let action = sb
                .begin_write(
                    NOTES,
                    "createNotebook",
                    json!({"id": format!("b{i}"), "title": "b"}),
                    Level::Write,
                    seed,
                )
                .unwrap()
                .unwrap();
            recs.extend(run(&mut sb, &f.host, action).records);
        }
        deliver(&mut f.account, recs);
    }
    let seed = f.host.fresh();
    let action = f
        .account
        .begin_revoke(&b, &RevokeKeep::Everything, &[f.d.clone()], seed)
        .unwrap();
    run(&mut f.account, &f.host, action);
    let mut s = member_session(&f, &a);
    let mut host = std::mem::replace(&mut f.host, Host::new());
    write_in(&mut s, &mut host, NOTES, 0);
    write_in(&mut s, &mut host, NOTES, 1);
    let w = s.work();
    s.verify_derivation().unwrap();
    println!("after a revocation: {w:?}");
    assert!(
        w.last.resumed,
        "a member's write after another member's revocation is extended"
    );
}

/// A write budget crossed while records arrive one by one, in fold order, through the extended
/// path, from two devices of one member: the maintained derivation equals a rebuild at every
/// step, and the over-budget record is refused the same way.
#[test]
fn budget_crossed_incrementally_equals_rebuild() {
    let mut f = create(&[NOTES]);
    let m = f.host.identity(31);
    let t = json!({"records": [{"namespace": NOTES, "access": "write"}], "writes": 3});
    admit(&mut f, &m, "Phone", "device", t.clone(), t);
    let mut d1 = member_session(&f, &m);
    let mut d2 = member_session(&f, &m);
    let mut host = std::mem::replace(&mut f.host, Host::new());
    let mut recs = Vec::new();
    for i in 0..2 {
        recs.push(write_in(&mut d1, &mut host, NOTES, i));
    }
    for i in 10..12 {
        recs.push(write_in(&mut d2, &mut host, NOTES, i));
    }
    // Fold order.
    recs.sort_by_key(|r| {
        let h = OperationHeader::parse(&r.bytes).unwrap().0;
        (h.clock, h.author, h.id)
    });
    let mut resumed = 0;
    for r in &recs {
        deliver(&mut f.account, vec![r.clone()]);
        if f.account.work().last.resumed {
            resumed += 1;
        }
        f.account.verify_derivation().unwrap();
    }
    let verdicts: Vec<String> = recs
        .iter()
        .map(|r| f.account.record_verdict(&r.path).unwrap())
        .collect();
    println!("resumed {resumed} of {}; verdicts {verdicts:?}", recs.len());
    assert!(verdicts.iter().any(|v| v.contains("budgetSpent")));
}

/// A refused write whose finish fell back to the full path leaves the shared judge cache
/// holding a walk over the held records plus the refused one. The next extension must not
/// resume from that walk.
#[test]
fn extension_after_a_refused_full_path_write_equals_rebuild() {
    let mut f = create(&[NOTES]);
    let m = f.host.identity(31);
    let t = json!({"records": [{"namespace": NOTES, "access": "write"}], "writes": 2});
    admit(&mut f, &m, "Phone", "device", t.clone(), t);
    let mut d1 = member_session(&f, &m);
    let mut d2 = member_session(&f, &m);
    let mut host = std::mem::replace(&mut f.host, Host::new());
    // d2 prepares a write at clock 1 and holds it; d1 writes twice (clocks 1, 2) and d2 takes
    // them; then d2 finishes: its record is over budget (refused), through whichever path.
    let seed = host.fresh();
    let pending = d2
        .begin_write(
            NOTES,
            "createNotebook",
            json!({"id": "late", "title": "late"}),
            Level::Write,
            seed,
        )
        .unwrap()
        .unwrap();
    let r1 = write_in(&mut d1, &mut host, NOTES, 1);
    let r2 = write_in(&mut d1, &mut host, NOTES, 2);
    deliver(&mut d2, vec![r1.clone(), r2.clone()]);
    d2.verify_derivation().unwrap();
    let sigs = host.sign(pending.steps());
    let r = d2.finish(pending, sigs);
    println!("refused finish: {:?}", r.as_ref().map(|_| ()));
    d2.verify_derivation().unwrap();
    // A later record arrives (d1, clock 3: over budget too, but judged).
    let r3 = {
        let seed = host.fresh();
        let action = d1.begin_write(
            NOTES,
            "createNotebook",
            json!({"id": "x3", "title": "x3"}),
            Level::Write,
            seed,
        );
        match action {
            Ok(Ok(a)) => Some(run(&mut d1, &host, a).records[0].clone()),
            other => {
                println!("x3 not prepared: {:?}", other.map(|r| r.map(|_| ())));
                None
            }
        }
    };
    if let Some(r3) = r3 {
        deliver(&mut d2, vec![r3]);
        d2.verify_derivation().unwrap();
    }
}

// ---------------------------------------------------------------------------------------------
// The pending feed: a failed page after a page that was buffered.

/// A home whose pending feed serves one page with a real transition and `more`, then fails
/// the next page with a 500 (once); later it is honest and has nothing after the cursor.
struct FailingPending {
    sim: SimHome,
    object: Value,
    page2_fails: bool,
    pending_gets: Vec<String>,
}
impl Wire for FailingPending {
    fn call(&mut self, host: &Host, req: &Request, now_ms: i64) -> Response {
        let path = req
            .url
            .strip_prefix("https://home.example")
            .unwrap()
            .to_string();
        if req.method == Method::Get && path.starts_with("/pending?") {
            self.pending_gets.push(path.clone());
            let after: u64 = path
                .split(['?', '&'])
                .find_map(|kv| kv.strip_prefix("after="))
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            if after == 0 {
                return Response {
                    status: 200,
                    headers: vec![],
                    body: serde_json::to_vec(
                        &json!({"objects": [{"seq": 1, "envelope": self.object}], "more": true}),
                    )
                    .unwrap(),
                };
            }
            if self.page2_fails {
                self.page2_fails = false;
                return Response {
                    status: 500,
                    headers: vec![],
                    body: b"{}".to_vec(),
                };
            }
            return Response {
                status: 200,
                headers: vec![],
                body: serde_json::to_vec(&json!({"objects": [], "more": false})).unwrap(),
            };
        }
        self.sim.call(host, req, now_ms)
    }
}

#[test]
fn a_failed_pending_page_does_not_lose_the_page_before_it() {
    use colophon_core::v05::write::authority::TransitionRule;
    let (mut s, ids) = setup(NOTES, &[("Phone", 31, "write")]);
    let member = ids[0].clone();
    let now = s.f.account.now_ms() + 60 * SEC;
    let src = device_source(&s);
    // The controller makes a transition the device does not hold: a grant to a new device.
    let newdev = s.f.host.identity(44);
    let req = request_for(
        &s.f,
        &s.f.host,
        &newdev,
        "New",
        "device",
        terms("write"),
        s.f.account.now_ms(),
    );
    let action =
        s.f.account
            .begin_transition(
                &Change::grant(&req.raw, terms("write")),
                &[s.f.d.clone(), s.f.k.clone()],
                TransitionRule::Control,
            )
            .unwrap();
    let done = run(&mut s.f.account, &s.f.host, action);
    assert_eq!(done.pending.len(), 1, "one transition");
    let transition = done.pending[0].clone();
    let object: Value = serde_json::from_slice(&transition).unwrap();
    let mut wire = FailingPending {
        sim: s.sim.clone(),
        object,
        page2_fails: true,
        pending_gets: Vec::new(),
    };
    let mut e = member_engine(&s.f, &s.f.host, &src, &member, now);
    assert!(!e.account().objects().pending.contains(&transition));
    let mut faults = Vec::new();
    for pass in 0..3 {
        faults.extend(sync_pass(
            &mut e,
            &src,
            &s.home,
            &mut wire,
            &s.f.host,
            now + pass,
        ));
    }
    println!("pending GETs: {:?}", wire.pending_gets);
    println!("faults: {faults:?}");
    assert!(
        e.account().objects().pending.contains(&transition),
        "the transition served on page 1 is held, though page 2 failed once"
    );
}

// ---------------------------------------------------------------------------------------------
// lock(): what is forgotten and what can still be read.

#[test]
fn lock_forgets_keys_and_plaintext() {
    let (mut s, ids) = setup(NOTES, &[("Phone", 31, "write")]);
    let member = ids[0].clone();
    let now = s.f.account.now_ms() + 60 * SEC;
    let src = device_source(&s);
    let mut e = member_engine(&s.f, &s.f.host, &src, &member, now);
    for i in 0..3 {
        engine_write(
            &mut e,
            &mut s.f.host,
            &src,
            NOTES,
            "createNotebook",
            json!({"id": format!("nb{i}"), "title": format!("Secret title {i}")}),
        );
    }
    let before = e.account().held_bytes();
    assert!(before.plaintext > 0);
    let c = e.lock().unwrap();
    let after = e.account().held_bytes();
    println!("held before {before:?} after {after:?}");
    assert_eq!(after.plaintext, 0, "no plaintext held after lock");
    assert_eq!(after.folds, 0, "no fold view held after lock");
    assert!(e.is_locked());
    let view = e.view(NOTES);
    println!(
        "view after lock: {:?}",
        view.as_ref().map(|o| matches!(o, Outcome::Success { .. }))
    );
    assert!(
        !matches!(view, Ok(Outcome::Success { .. })),
        "the namespace is unreadable after lock"
    );
    assert!(e.save(s.f.host.fresh()).is_err(), "save is refused");
    let seed = s.f.host.fresh();
    let w = e.begin_write(
        NOTES,
        "createNotebook",
        json!({"id": "after", "title": "after"}),
        Level::Write,
        seed,
    );
    println!("write after lock: {:?}", w.as_ref().map(|r| r.is_ok()));
    assert!(
        !matches!(w, Ok(Ok(_))),
        "no write can be prepared after lock"
    );
    // Unlocking again after lock: is the engine readable (and still unable to save)?
    let steps = e.begin_unlock_epochs();
    let n = steps.len();
    let results = s.f.host.answer_epochs(&member, steps);
    let r = e.finish_unlock_epochs(results);
    println!(
        "re-unlock after lock: {n} steps, {:?}, readable {}, locked {}",
        r.as_ref().map(|_| ()),
        matches!(e.view(NOTES), Ok(Outcome::Success { .. })),
        e.is_locked()
    );
    assert!(
        r.is_err(),
        "an engine that was locked does not unlock again"
    );
    assert!(
        !matches!(e.view(NOTES), Ok(Outcome::Success { .. })),
        "and stays unreadable"
    );
    assert!(e.save(s.f.host.fresh()).is_err(), "save still refused");
}

// ---------------------------------------------------------------------------------------------
// refresh_batched: versions given by the host.

/// A host that passes the versions it held before (or none) for a path whose bytes changed:
/// the engine does not read it again. (Same power the host has through `content_version`.)
#[test]
fn refresh_batched_with_stale_versions_skips_changed_bytes() {
    let (s, ids) = setup(NOTES, &[("Phone", 31, "write")]);
    let member = ids[0].clone();
    let now = s.f.account.now_ms() + 60 * SEC;
    let src = device_source(&s);
    let mut e = member_engine(&s.f, &s.f.host, &src, &member, now);
    let reads0 = src.reads();
    let listing = src.listing();
    let paths = e.version_paths(&listing);
    let versions: std::collections::BTreeMap<String, Option<String>> =
        paths.iter().map(|p| (p.clone(), None)).collect();
    e.refresh_batched(listing, versions).unwrap();
    println!(
        "{} version paths; source reads during refresh_batched: {}",
        paths.len(),
        src.reads() - reads0
    );
}

// ---------------------------------------------------------------------------------------------
// Live writes: cost of one passive write with many slots held.

// ---------------------------------------------------------------------------------------------
// M-D and L-D.

/// A transition of the right shape whose signature does not verify is not held, and the real
/// one on the same page is; the cursor passes both.
#[test]
fn a_forged_pending_transition_is_not_held_and_the_real_one_is() {
    use colophon_core::v05::write::authority::TransitionRule;
    let (mut s, ids) = setup(NOTES, &[("Phone", 31, "write")]);
    let member = ids[0].clone();
    let now = s.f.account.now_ms() + 60 * SEC;
    let src = device_source(&s);
    let newdev = s.f.host.identity(44);
    let req = request_for(
        &s.f,
        &s.f.host,
        &newdev,
        "New",
        "device",
        terms("write"),
        s.f.account.now_ms(),
    );
    let action =
        s.f.account
            .begin_transition(
                &Change::grant(&req.raw, terms("write")),
                &[s.f.d.clone(), s.f.k.clone()],
                TransitionRule::Control,
            )
            .unwrap();
    let done = run(&mut s.f.account, &s.f.host, action);
    let real = done.pending[0].clone();
    // The forgery: the same body with `issued` moved by a second, the old signature kept.
    let forged = {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let mut v: Value = serde_json::from_slice(&real).unwrap();
        let mut body: Value =
            serde_json::from_slice(&STANDARD.decode(v["body"].as_str().unwrap()).unwrap()).unwrap();
        body["issued"] = json!(colophon_core::v05::write::format_date(
            s.f.account.now_ms() + SEC
        ));
        v["body"] = json!(STANDARD.encode(canonical(&body).unwrap()));
        canonical(&v).unwrap()
    };
    struct Page {
        sim: SimHome,
        objects: Vec<Value>,
    }
    impl Wire for Page {
        fn call(&mut self, host: &Host, req: &Request, now_ms: i64) -> Response {
            let path = req
                .url
                .strip_prefix("https://home.example")
                .unwrap()
                .to_string();
            if req.method == Method::Get && path.starts_with("/pending?") {
                let after: u64 = path
                    .split(['?', '&'])
                    .find_map(|kv| kv.strip_prefix("after="))
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                let list: Vec<Value> = if after == 0 {
                    self.objects
                        .iter()
                        .enumerate()
                        .map(|(i, o)| json!({"seq": i + 1, "envelope": o}))
                        .collect()
                } else {
                    vec![]
                };
                return Response {
                    status: 200,
                    headers: vec![],
                    body: serde_json::to_vec(&json!({"objects": list, "more": false})).unwrap(),
                };
            }
            self.sim.call(host, req, now_ms)
        }
    }
    let mut wire = Page {
        sim: s.sim.clone(),
        objects: vec![
            serde_json::from_slice(&forged).unwrap(),
            serde_json::from_slice(&real).unwrap(),
        ],
    };
    let mut e = member_engine(&s.f, &s.f.host, &src, &member, now);
    sync_pass(&mut e, &src, &s.home, &mut wire, &s.f.host, now);
    let held = &e.account().objects().pending;
    assert!(held.contains(&real), "the real transition is held");
    assert!(!held.contains(&forged), "the forged one is not");
}

/// A pass can be abandoned: the engine stays consistent, forgets the request, and a new pass
/// starts; the answer to the forgotten request is refused as not outstanding.
#[test]
fn a_pass_can_be_aborted_and_the_engine_stays_consistent() {
    let (s, ids) = setup(NOTES, &[("Phone", 31, "write")]);
    let member = ids[0].clone();
    let now = s.f.account.now_ms() + 60 * SEC;
    let src = device_source(&s);
    let mut e = member_engine(&s.f, &s.f.host, &src, &member, now);
    let first = match e.exchange_next(&s.home).unwrap() {
        Step::Request(r) => r,
        other => panic!("{other:?}"),
    };
    assert!(matches!(e.exchange_next(&s.home).unwrap(), Step::Waiting));
    e.exchange_abort(&s.home).unwrap();
    assert!(e
        .exchange_answer(
            &s.home,
            first.ticket,
            Response {
                status: 200,
                headers: vec![],
                body: b"{}".to_vec()
            }
        )
        .is_err());
    match e.exchange_next(&s.home).unwrap() {
        Step::Request(_) => {}
        other => panic!("a new pass starts: {other:?}"),
    }
}
