//! Freeze package, stream W3-G: a stopped account is a first-class, stable state of the account
//! and the engine (§1 "A stop", §12.3 step 4, §20 "The upgrade door";
//! `docs/design-freeze-package.md` §S).
//!
//! Once an activation raising the layout above 2 is final, the account keeps reading what it
//! holds (records, the member list, as of the stop) and builds nothing: every authority, record,
//! seed-transfer or move action is refused `newerFormat` and every link, call and exchange pass
//! `unavailable`, before a signature is asked for. The state is a function of the held objects,
//! so it survives a reopen from the objects, from saved state and from a checkpoint. A raise that
//! is provisional or vetoed stops nothing.
//!
//! **The raising transition is built by a test-only helper below the 0.5 builders**
//! ([`raise_transition`] in this file): 0.5's write side deliberately builds no `layout`
//! component (§20), so the helper takes the body of a transition the builder made, replaces its
//! `change` with `{"layout": 3}` and signs it with the controller's key. The `activate` that makes
//! it final is the account's own `record_due`.
#![allow(clippy::unwrap_used)]
#[path = "v05_engine_support/mod.rs"]
mod support;
use base64::{engine::general_purpose::STANDARD, Engine};
use colophon_core::v05::account::*;
use colophon_core::v05::encoding::canonical;
use colophon_core::v05::history::{Objects, Persisted};
use colophon_core::v05::pairing::FailureLimiter;
use colophon_core::v05::records::Level;
use colophon_core::v05::slots::SlotPlan;
use colophon_core::v05::engine::{Engine as AccountEngine, EngineOptions};
use support::{Host, MemSource};
use colophon_core::v05::write::authority::TransitionRule;
use colophon_core::v05::write::calls::RequestSpec;
use colophon_core::v05::write::{format_date, SignatureResult};
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;

use support::{KEY, T0};
const NOBODY: &str = "00000000000000000000000000000000";

struct Fixture {
    host: Host,
    d: String,
    member: String,
    account: Account,
}

fn run(a: &mut Account, host: &Host, action: PendingAction) -> Finished {
    let sigs = host.sign(action.steps());
    a.finish(action, sigs).unwrap()
}

/// One device key (approve, control), no recovery set and no home: an activation is final at
/// once (§8.7), and a raise needs only the control rule (§8.4). A member `notes` writer is
/// admitted and writes one notebook.
fn fixture() -> Fixture {
    let mut host = Host::new();
    let d = host.identity(10);
    let p = host.ids[&d].public();
    let params = CreateParams {
        label: "Stopped account".into(),
        namespaces: vec!["notes".into()],
        controllers: vec![json!({
            "key": {"form": "raw", "signing": STANDARD.encode(&p.signing),
                    "agreement": STANDARD.encode(&p.agreement)},
            "label": "Mac", "roles": ["approve", "control"]})],
        slots: vec![SlotPlan {
            controllers: vec![d.clone()],
            label: "Mac".into(),
        }],
        threshold: None,
        recover_threshold: None,
        add_threshold: None,
        count_by_holders: false,
        policy: None,
        signers: vec![d.clone()],
        rekey_signers: vec![d.clone()],
        vault_seed: host.fresh(),
        entropy: host.fresh(),
        epoch_seed: host.fresh(),
    };
    let creation = Creation::begin(params, Identity::Controller(d.clone()), T0).unwrap();
    let sigs = host.sign(creation.steps());
    let mut progress = creation.provide_signatures(sigs).unwrap();
    let mut account = loop {
        match progress {
            CreateProgress::Continue(c) => {
                let sigs = host.sign(c.steps());
                progress = c.provide_signatures(sigs).unwrap();
            }
            CreateProgress::Done(a) => break *a,
        }
    };
    // A member that writes notes.
    let member = host.identity(30);
    let mp = host.ids[&member].public();
    let created = format_date(account.now_ms());
    let terms = json!({"records": [{"namespace": "notes", "access": "write"}]});
    let prepared = prepare_request(&RequestSpec {
        account: account.id(),
        signing: &mp.signing,
        agreement: &mp.agreement,
        label: "Notes",
        kind: "app",
        terms: terms.clone(),
        created: &created,
        custody: None,
        operator: None,
        endpoints: None,
    })
    .unwrap();
    let sig = SignatureResult {
        signature: host.ids[&member].sign(prepared.step().body()).to_vec(),
        assertion: None,
    };
    let req = finish_request(&prepared, &sig).unwrap();
    let pairing = colophon_core::v05::pairing::scanned_request(
        account.id(),
        &req.raw,
        FailureLimiter::new().permit(account.now_ms()).unwrap(),
    )
    .unwrap();
    let seed = host.fresh();
    let action = account
        .begin_approve(&req.raw, terms, std::slice::from_ref(&d), seed, pairing)
        .unwrap();
    run(&mut account, &host, action);
    let mut f = Fixture {
        host,
        d,
        member,
        account,
    };
    let mut m = member_session(&f, None);
    let seed = f.host.fresh();
    let action = m
        .begin_write(
            "notes",
            "createNotebook",
            json!({"id": "nb1", "title": "Before the stop"}),
            Level::Write,
            seed,
        )
        .unwrap()
        .unwrap();
    let done = run(&mut m, &f.host, action);
    f.account
        .merge(
            Incoming {
                objects: Objects::default(),
                records: done.records,
            },
            f.account.now_ms(),
        )
        .unwrap();
    f
}

/// The member's session over the controller's objects and records, unlocked through its share.
fn member_session(f: &Fixture, stored: Option<&[u8]>) -> Account {
    let mut m = Account::open(
        f.account.objects().clone(),
        f.account.records().to_vec(),
        stored.map(|b| (b, &KEY)),
        Identity::Member(f.member.clone()),
        f.account.now_ms(),
    )
    .unwrap();
    let steps = m.begin_unlock_epochs();
    assert!(!steps.is_empty(), "the member holds a share");
    let answers = steps
        .into_iter()
        .map(|s| EpochSecret {
            shared: f.host.ids[&f.member].agree(&s.peer).unwrap(),
            step: s,
        })
        .collect();
    m.finish_unlock_epochs(answers).unwrap();
    m
}

/// **Test-only, below the 0.5 builders.** A transition raising the layout to `to`: the body of a
/// policy transition the builder made (anchor, issued, signers exactly as it writes them), with
/// its `change` replaced by `{"layout": to}`, re-encoded canonically and signed by the device
/// key. 0.5 writes no `layout` component (§20), so nothing outside tests can make one.
fn raise_transition(f: &mut Fixture, to: u64) -> Vec<u8> {
    let action = f
        .account
        .begin_transition(
            &Change::policy(json!({"callWindow": 120})),
            std::slice::from_ref(&f.d),
            TransitionRule::Control,
        )
        .unwrap();
    let step = &action.steps()[0];
    let mut body: Value = serde_json::from_slice(step.body()).unwrap();
    body["change"] = json!({"layout": to});
    let bytes = canonical(&body).unwrap();
    let sig = f.host.ids[&f.d].sign(&bytes);
    canonical(&json!({"body": STANDARD.encode(&bytes), "signature": STANDARD.encode(sig)}))
        .unwrap()
}

/// Hold the raise and record its `activate` (final at once: no home).
fn stop(f: &mut Fixture) -> Vec<Finished> {
    let t = raise_transition(f, 3);
    f.account
        .merge(
            Incoming {
                objects: Objects {
                    pending: vec![t],
                    ..Default::default()
                },
                records: Vec::new(),
            },
            f.account.now_ms(),
        )
        .unwrap();
    assert_eq!(f.account.stopped(), None, "a held transition stops nothing");
    f.account.record_due().unwrap()
}

fn notebook_titles(a: &Account) -> Vec<String> {
    let colophon_core::model::Outcome::Success { value: view, .. } = a.view("notes").unwrap() else {
        panic!("the notes are readable");
    };
    assert!(!view.admitted.is_empty(), "the held notes are admitted");
    let text = serde_json::to_string(&view.state).unwrap();
    ["Before the stop", "After"]
        .iter()
        .filter(|t| text.contains(*t))
        .map(|t| t.to_string())
        .collect()
}

fn assert_actions_refused(a: &Account, d: &str, host: &mut Host) {
    let code = |r: colophon_core::v05::Result<PendingAction>| match r {
        Ok(_) => "built".to_string(),
        Err(e) => e.code(),
    };
    // Authority: an immediate entry, a transition, a rekey, a veto.
    let edit = KeyringEdit {
        policy: Some(json!({"callWindow": 120})),
        ..Default::default()
    };
    assert_eq!(code(a.begin_keyring(&edit, &[d.to_string()])), "newerFormat");
    assert_eq!(
        code(a.begin_transition(
            &Change::policy(json!({"callWindow": 120})),
            &[d.to_string()],
            TransitionRule::Control
        )),
        "newerFormat"
    );
    assert_eq!(
        code(a.begin_rekey(&["notes".to_string()], &[d.to_string()], host.fresh())),
        "newerFormat"
    );
    assert_eq!(
        code(a.begin_veto(&"0".repeat(64), &[d.to_string()])),
        "newerFormat"
    );
    // Calls: `unavailable`, before any signature is asked for (§12.3 step 4).
    let key = host.ids[d].public().signing;
    assert_eq!(
        code(a.begin_call(
            &key,
            &[],
            "https://projects.example/scopes/7",
            "task.read",
            json!({}),
            [7; 32],
            CallTarget::default(),
        )),
        "unavailable"
    );
    let home = HomeCall {
        audience: "https://home.example/v1/accounts/x".into(),
        method: "GET".into(),
        path: "/authority".into(),
        body_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
        as_of: None,
    };
    assert_eq!(code(a.begin_home_call(&key, &home, [8; 32])), "unavailable");
}

#[test]
fn a_final_raise_stops_the_account_reads_go_on_and_nothing_is_built() {
    let mut f = fixture();
    let before = f.account.head();
    let recorded = stop(&mut f);
    assert_eq!(recorded.len(), 1, "the raise's activate is recorded");
    let seq = before.0 + 1;
    let st = f.account.status();
    assert_eq!(st.code, "newerFormat");
    assert_eq!(st.stopped, Some(Stopped { seq, layout: Some(3) }));
    assert_eq!(f.account.stopped(), st.stopped);
    // What it held stays readable: the members and the controllers, as of the stop.
    assert!(f.account.members().iter().any(|m| m.member.id == f.member));
    assert_eq!(f.account.controllers().len(), 1);
    // Nothing more is due, and nothing is recorded.
    assert!(f.account.record_due().unwrap().is_empty());
    let d = f.d.clone();
    assert_actions_refused(&f.account, &d, &mut f.host);

    // The member, opened afterwards from the same objects: it unlocks and reads its notes.
    let mut m = member_session(&f, None);
    assert_eq!(m.stopped(), Some(Stopped { seq, layout: Some(3) }));
    assert_eq!(notebook_titles(&m), vec!["Before the stop".to_string()]);
    // A record and a link are refused, with no signature asked for.
    let seed = f.host.fresh();
    let got = m.begin_write(
        "notes",
        "createNotebook",
        json!({"id": "nb2", "title": "After"}),
        Level::Write,
        seed,
    );
    assert_eq!(got.err().map(|e| e.code()).as_deref(), Some("newerFormat"));
    let to = f.host.ids[&f.d].public().signing;
    let got = m.begin_link(&[], &to, json!({}), T0, T0 + 60_000);
    assert_eq!(got.err().map(|e| e.code()).as_deref(), Some("unavailable"));

    // A cold reopen from saved state keeps it, and so does one from the objects alone.
    let saved = m.export_persisted(&KEY, [3; 32]).unwrap();
    let again = member_session(&f, Some(&saved));
    assert_eq!(again.stopped(), Some(Stopped { seq, layout: Some(3) }));
    assert_eq!(notebook_titles(&again), vec!["Before the stop".to_string()]);
    let bare = Account::open(
        f.account.objects().clone(),
        Vec::new(),
        None,
        Identity::Controller(f.d.clone()),
        f.account.now_ms() + 86_400_000,
    )
    .unwrap();
    assert_eq!(bare.stopped(), Some(Stopped { seq, layout: Some(3) }));

    // A checkpoint (format 7) carries it.
    let objects = f.account.objects().clone();
    let cp = Persisted::checkpoint(&objects, &Persisted::default(), f.account.now_ms());
    let restored = Persisted::from_bytes(&cp.to_bytes().unwrap()).unwrap();
    assert_eq!(restored.stopped(), Some(seq));
}

#[test]
fn the_engine_runs_no_exchange_pass_when_stopped() {
    // The engine over a stopped account: no pass starts and no call is prepared.
    let mut f = fixture();
    stop(&mut f);
    let source = MemSource::new();
    source.store_account(&f.account);
    let mut engine = AccountEngine::open(
        source.clone(),
        source.listing(),
        Identity::Controller(f.d.clone()),
        EngineOptions::new(f.account.id().as_str(), support::DEVICE_KEY),
        None,
        f.account.now_ms(),
    )
    .unwrap();
    assert!(engine.stopped().is_some());
    assert!(engine.status().stopped.is_some());
    let idx = engine.slots().unwrap()[0].index;
    let inputs = engine.begin_unlock_slot(idx).unwrap();
    engine
        .finish_unlock_slot(idx, &f.host.answer_unlock(&inputs))
        .unwrap();
    let err = engine.exchange_next("any-home").unwrap_err();
    assert_eq!(err.code(), "unavailable");
    let err = engine
        .exchange_begin_call("any-home", 1, &[4; 65], [1; 32])
        .unwrap_err();
    assert_eq!(err.code(), "unavailable");
    let seed = f.host.fresh();
    let err = engine
        .begin_write(
            "notes",
            "createNotebook",
            json!({"id": "x", "title": "x"}),
            Level::Write,
            seed,
        )
        .err()
        .unwrap();
    assert_eq!(err.code(), "newerFormat");
}

// ---------------------------------------------------------------------------------------------
// The generator's vectors, opened as accounts: only a final raise stops.

fn rules_case(name: &str) -> (Objects, i64) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/0.5/rules")
        .join(name);
    let mut entries = Vec::new();
    for sub in ["records/authority", "branch-activate/authority"] {
        if let Ok(rd) = fs::read_dir(dir.join(sub)) {
            let mut paths: Vec<PathBuf> = rd.map(|e| e.unwrap().path()).collect();
            paths.sort();
            entries.extend(paths.iter().map(|p| fs::read(p).unwrap()));
        }
    }
    let case: Value = serde_json::from_slice(&fs::read(dir.join("case.json")).unwrap()).unwrap();
    let now = colophon_core::v05::encoding::parse_date(case["verifier"]["now"].as_str().unwrap())
        .unwrap();
    (
        Objects {
            entries,
            ..Default::default()
        },
        now,
    )
}

fn open_case(name: &str) -> Account {
    let (objects, now) = rules_case(name);
    Account::open(objects, Vec::new(), None, Identity::Member(NOBODY.into()), now).unwrap()
}

#[test]
fn only_a_final_raise_stops_an_account_and_it_names_its_layout() {
    for (name, want) in [
        ("f3-layout-3", Some(Stopped { seq: 2, layout: Some(3) })),
        ("f3-raise-final", Some(Stopped { seq: 3, layout: Some(3) })),
        ("f3-raise-final-then-entry", Some(Stopped { seq: 3, layout: Some(3) })),
        ("f3-raise-provisional", None),
        ("f3-raise-vetoed", None),
    ] {
        let a = open_case(name);
        assert_eq!(a.stopped(), want, "{name}");
        assert_eq!(a.status().stopped, want, "{name}");
        // A stopped account opens and reads; a provisional or vetoed raise leaves it writable
        // as far as the stop is concerned.
        if want.is_some() {
            assert_eq!(a.status().code, "newerFormat", "{name}");
            let key = vec![4u8; 65];
            let home = HomeCall {
                audience: "https://home.example/v1/accounts/x".into(),
                method: "GET".into(),
                path: "/head".into(),
                body_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    .into(),
                as_of: None,
            };
            assert_eq!(
                a.begin_home_call(&key, &home, [1; 32]).unwrap_err().code(),
                "unavailable",
                "{name}"
            );
        } else {
            assert_ne!(a.status().code, "newerFormat", "{name}");
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Fix round: prepared work, ingestion, the persisted floor, outstanding exchange tickets, and a
// stop that arrives from a home in the middle of a pass.

/// Prepared before the stop, finished after it: refused with the result its begin would now give,
/// and dropped. Covers an authority transition, a record, a link, a call and a home call.
#[test]
fn work_prepared_before_the_stop_is_refused_at_its_next_step() {
    let mut f = fixture();
    let mut m = member_session(&f, None);
    let d = f.d.clone();
    // Prepared on the controller: a transition and a home call.
    let transition = f
        .account
        .begin_transition(
            &Change::policy(json!({"callWindow": 120})),
            std::slice::from_ref(&d),
            TransitionRule::Control,
        )
        .unwrap();
    let key = f.host.ids[&d].public().signing;
    let home_call = f
        .account
        .begin_home_call(
            &key,
            &HomeCall {
                audience: "https://home.example/v1/accounts/x".into(),
                method: "GET".into(),
                path: "/authority".into(),
                body_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
                as_of: None,
            },
            [8; 32],
        )
        .unwrap();
    // Prepared on the member: a record, a link and a call.
    let seed = f.host.fresh();
    let write = m
        .begin_write("notes", "createNotebook", json!({"id": "late", "title": "Late"}), Level::Write, seed)
        .unwrap()
        .unwrap();
    let mkey = f.host.ids[&f.member].public().signing;
    let to = f.host.ids[&d].public().signing;
    let link = m.begin_link(&[], &to, json!({}), T0, T0 + 60_000);
    let call = m.begin_call(
        &mkey,
        &[],
        "https://projects.example/scopes/7",
        "task.read",
        json!({}),
        [7; 32],
        CallTarget::default(),
    );
    // The stop arrives at both.
    let recorded = stop(&mut f);
    let objects = f.account.objects().clone();
    m.merge(
        Incoming {
            objects,
            records: Vec::new(),
        },
        f.account.now_ms(),
    )
    .unwrap();
    assert!(m.stopped().is_some());
    assert_eq!(recorded.len(), 1);
    let finish = |a: &mut Account, action: PendingAction| {
        let sigs = f.host.sign(action.steps());
        a.finish(action, sigs).map(|_| ()).unwrap_err().code()
    };
    let held = f.account.objects().pending.len();
    assert_eq!(finish(&mut f.account, transition), "newerFormat");
    assert_eq!(f.account.objects().pending.len(), held, "nothing is held for it");
    assert_eq!(finish(&mut f.account, home_call), "unavailable");
    let records = m.records().len();
    assert_eq!(finish(&mut m, write), "newerFormat");
    assert_eq!(m.records().len(), records, "nothing is stored for it");
    // The member is depth 0 with no links: `begin_link` may refuse for its own reason before the
    // stop; when it was prepared, its finish is refused by the stop.
    if let Ok(link) = link {
        assert_eq!(finish(&mut m, link), "unavailable");
    }
    assert_eq!(finish(&mut m, call.unwrap()), "unavailable");
}

/// After the stop nothing that arrives is admitted, in a later merge or in the merge that brings
/// the stop: the fold as it stood when the stop was verified is what stays readable.
#[test]
fn records_that_arrive_after_the_stop_are_not_admitted() {
    let mut f = fixture();
    // Two notes written by the member and not yet delivered to the controller.
    let mut m = member_session(&f, None);
    let mut late = Vec::new();
    for (id, title) in [("nb-a", "Arrives with the stop"), ("nb-b", "Arrives after the stop")] {
        let seed = f.host.fresh();
        let action = m
            .begin_write("notes", "createNotebook", json!({"id": id, "title": title}), Level::Write, seed)
            .unwrap()
            .unwrap();
        late.push(run(&mut m, &f.host, action).records);
    }
    // A second session of the member, to see the stop and the records arrive together.
    let mut together = member_session(&f, None);
    let admitted_before = |a: &Account| match a.view("notes").unwrap() {
        colophon_core::model::Outcome::Success { value, .. } => value.admitted.len(),
        _ => panic!("readable"),
    };
    let base = admitted_before(&together);
    stop(&mut f);
    // The stop and the first note in one merge.
    together
        .merge(
            Incoming {
                objects: f.account.objects().clone(),
                records: late[0].clone(),
            },
            f.account.now_ms(),
        )
        .unwrap();
    assert!(together.stopped().is_some());
    assert_eq!(admitted_before(&together), base, "a record that came with the stop is not admitted");
    // The second note after the stop.
    together
        .merge(
            Incoming {
                objects: Objects::default(),
                records: late[1].clone(),
            },
            f.account.now_ms(),
        )
        .unwrap();
    assert_eq!(admitted_before(&together), base, "a record that came after the stop is not admitted");
    // The controller, stopped, ignores the member's notes too.
    let held = f.account.records().len();
    f.account
        .merge(
            Incoming {
                objects: Objects::default(),
                records: late.concat(),
            },
            f.account.now_ms(),
        )
        .unwrap();
    assert_eq!(f.account.records().len(), held);
}

/// The persisted floor: a stop once verified survives evidence that goes missing.
#[test]
fn a_verified_stop_is_persisted_as_a_floor() {
    let mut f = fixture();
    let before: Objects = f.account.objects().clone();
    stop(&mut f);
    let seq = f.account.stopped().unwrap().seq;
    // Saved state carries it, and a reopen whose store no longer holds the raise stays stopped.
    let saved = f.account.export_persisted(&KEY, [9; 32]).unwrap();
    let again = Account::open(
        before.clone(),
        f.account.records().to_vec(),
        Some((&saved, &KEY)),
        Identity::Controller(f.d.clone()),
        f.account.now_ms(),
    )
    .unwrap();
    assert_eq!(again.stopped().map(|s| s.seq), Some(seq));
    assert_eq!(again.status().stopped.map(|s| (s.seq, s.layout)), Some((seq, Some(3))));
    let edit = KeyringEdit {
        policy: Some(json!({"callWindow": 120})),
        ..Default::default()
    };
    assert_eq!(
        again.begin_keyring(&edit, std::slice::from_ref(&f.d)).unwrap_err().code(),
        "newerFormat"
    );
    // The floor itself, with no evidence held at all: through a checkpoint's bytes and through a
    // rebuild after a format change, whose retained objects are dropped.
    let floor = Persisted::default().with_stop_floor(seq, Some(3));
    let cp = Persisted::checkpoint(&before, &floor, f.account.now_ms());
    let bytes = cp.to_bytes().unwrap();
    assert_eq!(Persisted::from_bytes(&bytes).unwrap().stop_floor(), Some((seq, Some(3))));
    let rebuilt = Persisted::rebuild(&before, &bytes, f.account.now_ms());
    assert_eq!(rebuilt.stopped(), None, "the objects alone do not show the stop");
    assert_eq!(rebuilt.stop_floor(), Some((seq, Some(3))), "the floor is kept");
    // Monotone: a later floor does not replace the first.
    assert_eq!(floor.with_stop_floor(99, None).stop_floor(), Some((seq, Some(3))));
}

/// A home world: the support fixture (device key, passkey, kit) with a home. Device A raises the
/// layout (a transition under the control rule with the recovery set's consent, signed below the
/// builders), the home receipts it, A records the provisional `activate`, pushes it, takes the
/// home's head over it and records the `final`: A is stopped. A 0.5 device cannot push what stops
/// it, so the `activate` and `final` reach the home as a later-format device would bring them
/// (put into the simulated home's served history). Device B has seen none of it.
struct HomeWorld {
    s: support::Setup,
    host: Host,
    b: AccountEngine<MemSource>,
    b_src: MemSource,
    stop_entries: Vec<(String, Vec<u8>)>,
    now: i64,
}

fn home_world() -> HomeWorld {
    use colophon_core::v05::engine::exchange::Step;
    let (mut s, _) = support::setup("notes", &[]);
    let host = std::mem::replace(&mut s.f.host, Host::new());
    let (d, k) = (s.f.d.clone(), s.f.k.clone());
    let home = s.home.clone();
    let now = s.f.account.now_ms();
    let a_src = support::device_source(&s);
    let b_src = support::device_source(&s);
    let mut a = support::controller_engine(&s.f, &host, &a_src, &d, now);
    let b = support::controller_engine(&s.f, &host, &b_src, &d, now);
    assert!(support::sync_pass(&mut a, &a_src, &home, &mut s.sim, &host, now).is_empty());
    // The raise, below the builders: a builder's transition body with its change replaced.
    let action = a
        .account()
        .begin_transition(
            &Change::policy(json!({"callWindow": 120})),
            &[d.clone(), k.clone()],
            TransitionRule::Control,
        )
        .unwrap();
    let mut body: Value = serde_json::from_slice(action.steps()[0].body()).unwrap();
    body["change"] = json!({"layout": 3});
    let bytes = canonical(&body).unwrap();
    let sign = |id: &str| STANDARD.encode(host.ids[id].sign(&bytes));
    let env = canonical(&json!({
        "body": STANDARD.encode(&bytes),
        "signature": sign(&d),
        "cosignatures": [{"signer": k, "signature": sign(&k)}],
    }))
    .unwrap();
    let digest = colophon_core::v05::encoding::digest(&bytes);
    a_src.put(&format!("transitions/{digest}.json"), env);
    let t1 = now + 1_000;
    assert!(support::sync_pass(&mut a, &a_src, &home, &mut s.sim, &host, t1).is_empty());
    assert_eq!(a.receipted_by(&digest), vec![home.clone()], "the home receipted the raise");
    // Due after the witness window and the recovery delay: the provisional activate.
    let t2 = t1 + (300 + 3_600 + 60) * 1_000;
    a.advance(t2).unwrap();
    let mut stop_entries = Vec::new();
    for w in a.record_due().unwrap() {
        for (p, b) in w.stores {
            a_src.put(&p, b.clone());
            stop_entries.push((p, b));
        }
    }
    assert_eq!(stop_entries.len(), 1, "the activate");
    assert!(a.stopped().is_none(), "a provisional raise stops nothing");
    // Push it; the home signs a head over it; A takes the head and records the final.
    assert!(support::sync_pass(&mut a, &a_src, &home, &mut s.sim, &host, t2).is_empty());
    let t3 = t2 + 1_000;
    a.advance(t3).unwrap();
    a.refresh(a_src.listing()).unwrap();
    let mut steps = 0;
    loop {
        steps += 1;
        assert!(steps < 10_000);
        match a.exchange_next(&home).unwrap() {
            Step::Done => break,
            Step::NeedCall(n) => a
                .exchange_provide_call(&home, n.ticket, format!("call-{}", n.ticket).as_bytes())
                .unwrap(),
            Step::Request(r) => {
                let ans = support::Wire::call(&mut s.sim, &host, &r, t3);
                for (p, b) in a.exchange_answer(&home, r.ticket, ans).unwrap().store {
                    a_src.put(&p, b);
                }
            }
            Step::Waiting => panic!("waiting"),
        }
    }
    for w in a.record_due().unwrap() {
        for (p, b) in w.stores {
            a_src.put(&p, b.clone());
            stop_entries.push((p, b));
        }
    }
    assert!(a.stopped().is_some(), "A is stopped: {:?}", a.status());
    // The home serves the activate and the final (as a later-format device would bring them).
    for (p, b) in &stop_entries {
        if let Some(seq) = p.strip_prefix("authority/").and_then(|s| s.strip_suffix(".json")) {
            let seq: u64 = seq.parse().unwrap();
            s.sim.entries.insert(seq, b.clone());
            s.sim.files.insert(p.clone(), b.clone());
            s.sim.log.push(p.clone());
        }
    }
    HomeWorld {
        s,
        host,
        b,
        b_src,
        stop_entries,
        now: t3 + 1_000,
    }
}

/// The stop arrives from the home in the middle of B's pass (its pull of the authority history):
/// the pass ends there, with `unavailable`, and no further request is made.
#[test]
fn a_stop_that_arrives_from_a_home_in_the_middle_of_a_pass_ends_the_pass() {
    use colophon_core::v05::engine::exchange::Step;
    let mut w = home_world();
    let home = w.s.home.clone();
    assert!(w.b.stopped().is_none());
    w.b.advance(w.now).unwrap();
    w.b.refresh(w.b_src.listing()).unwrap();
    let mut stopped_at = None;
    for n in 0..10_000 {
        match w.b.exchange_next(&home) {
            Err(e) => {
                assert_eq!(e.code(), "unavailable");
                stopped_at = Some(n);
                break;
            }
            Ok(Step::Done) => break,
            Ok(Step::NeedCall(c)) => w
                .b
                .exchange_provide_call(&home, c.ticket, format!("call-{}", c.ticket).as_bytes())
                .unwrap(),
            Ok(Step::Request(r)) => {
                let ans = support::Wire::call(&mut w.s.sim, &w.host, &r, w.now);
                for (p, b) in w.b.exchange_answer(&home, r.ticket, ans).unwrap().store {
                    w.b_src.put(&p, b);
                }
            }
            Ok(Step::Waiting) => panic!("waiting"),
        }
    }
    assert!(stopped_at.is_some(), "the pass ended at the stop, not at Done");
    assert_eq!(w.b.stopped().map(|s| s.layout), Some(Some(3)), "{:?}", w.b.status());
    let sent = w.s.sim.requests.len();
    assert_eq!(w.b.exchange_next(&home).unwrap_err().code(), "unavailable");
    assert_eq!(w.s.sim.requests.len(), sent, "no request after the stop");
    w.b.exchange_abort(&home).unwrap();
}

/// A ticket obtained before the stop: its answer is discarded and nothing it carries is merged; a
/// call is not attached; a blob is not queued; abort still works.
#[test]
fn an_exchange_ticket_from_before_the_stop_is_discarded() {
    use colophon_core::v05::engine::exchange::Step;
    let mut w = home_world();
    let home = w.s.home.clone();
    w.b.advance(w.now).unwrap();
    w.b.refresh(w.b_src.listing()).unwrap();
    let request = loop {
        match w.b.exchange_next(&home).unwrap() {
            Step::Request(r) => break r,
            Step::NeedCall(c) => w
                .b
                .exchange_provide_call(&home, c.ticket, format!("call-{}", c.ticket).as_bytes())
                .unwrap(),
            other => panic!("{other:?}"),
        }
    };
    let answer = support::Wire::call(&mut w.s.sim, &w.host, &request, w.now);
    // The stop reaches B through its own store before the answer is given.
    for (p, b) in &w.stop_entries {
        w.b_src.put(p, b.clone());
    }
    w.b.refresh(w.b_src.listing()).unwrap();
    assert!(w.b.stopped().is_some());
    let head = w.b.status().seq;
    assert_eq!(w.b.exchange_answer(&home, request.ticket, answer).unwrap_err().code(), "unavailable");
    assert_eq!(w.b.status().seq, head, "nothing was merged");
    assert_eq!(
        w.b.exchange_provide_call(&home, request.ticket, b"call").unwrap_err().code(),
        "unavailable"
    );
    assert_eq!(
        w.b.exchange_want_blob(&home, "notes", &"0".repeat(64)).unwrap_err().code(),
        "unavailable"
    );
    w.b.exchange_abort(&home).unwrap();
}

/// A home's `403 {"result":"refused:<name>"}` to a request that carried no call refuses that
/// request: it is not asked again with a call.
#[test]
fn an_unsigned_request_refused_by_name_is_not_retried_with_a_call() {
    use colophon_core::v05::engine::exchange::{Fault, Response, Step};
    let (s, _) = support::setup("notes", &[]);
    let host = &s.f.host;
    let src = support::device_source(&s);
    let now = s.f.account.now_ms();
    let mut e = support::controller_engine(&s.f, host, &src, &s.f.d, now);
    let home = s.home.clone();
    let r = match e.exchange_next(&home).unwrap() {
        Step::Request(r) => r,
        other => panic!("{other:?}"),
    };
    assert!(!r.headers.iter().any(|(n, _)| n.eq_ignore_ascii_case("authorization")));
    let report = e
        .exchange_answer(
            &home,
            r.ticket,
            Response {
                status: 403,
                headers: vec![],
                body: br#"{"result":"refused:notProvisioned","detail":"x"}"#.to_vec(),
            },
        )
        .unwrap();
    assert!(
        report.faults.iter().any(|f| matches!(f, Fault::Refused { code, .. } if code == "refused:notProvisioned")),
        "{:?}",
        report.faults
    );
    // The same request is not asked again with a call.
    for _ in 0..100 {
        match e.exchange_next(&home).unwrap() {
            Step::NeedCall(n) => assert_ne!(n.path, r.url.trim_start_matches("https://home.example"), "asked for a call"),
            Step::Request(next) => {
                assert_ne!(next.url, r.url, "the refused request was sent again");
                e.exchange_answer(&home, next.ticket, Response { status: 404, headers: vec![], body: b"{}".to_vec() })
                    .unwrap();
            }
            Step::Done | Step::Waiting => break,
        }
    }
}

/// What the device held as of the stop, through the engine: a reopen from the saved state made
/// while stopped reads the records that state covered, and a record put into the store afterwards
/// (while the app was closed) is not admitted.
#[test]
fn a_reopened_stopped_engine_reads_what_it_held_and_nothing_added_later() {
    let mut f = fixture();
    // A note the controller has not seen yet.
    let mut m = member_session(&f, None);
    let seed = f.host.fresh();
    let action = m
        .begin_write("notes", "createNotebook", json!({"id": "nb-late", "title": "Late"}), Level::Write, seed)
        .unwrap()
        .unwrap();
    let late = run(&mut m, &f.host, action).records;
    stop(&mut f);
    let src = MemSource::new();
    src.store_account(&f.account);
    let open = |saved: Option<&colophon_core::v05::engine::Saved>| {
        let mut e = AccountEngine::open(
            src.clone(),
            src.listing(),
            Identity::Controller(f.d.clone()),
            EngineOptions::new(f.account.id().as_str(), support::DEVICE_KEY),
            saved,
            f.account.now_ms(),
        )
        .unwrap();
        let idx = e.slots().unwrap()[0].index;
        let inputs = e.begin_unlock_slot(idx).unwrap();
        e.finish_unlock_slot(idx, &f.host.answer_unlock(&inputs)).unwrap();
        e
    };
    let admitted = |e: &AccountEngine<MemSource>| match e.view("notes").unwrap() {
        colophon_core::model::Outcome::Success { value, .. } => value.admitted.len(),
        _ => panic!("readable"),
    };
    let mut first = open(None);
    assert!(first.stopped().is_some());
    let held = admitted(&first);
    assert!(held > 0, "the note written before the stop is readable");
    let saved = first.save([4; 32]).unwrap();
    // While closed, the store gains the late note.
    for r in &late {
        src.put(&r.path, r.bytes.clone());
    }
    let again = open(Some(&saved));
    assert!(again.stopped().is_some());
    assert_eq!(admitted(&again), held, "a record added after the stop is not admitted on reopen");
    // And a running stopped engine ignores it on refresh.
    first.refresh(src.listing()).unwrap();
    assert_eq!(admitted(&first), held);
}
