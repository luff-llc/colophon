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
        .join("../../conformance/0.5/candidate/rules")
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
