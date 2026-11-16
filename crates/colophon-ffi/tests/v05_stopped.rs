//! Freeze package, stream W3-G: a stopped account through the exports (§1 "A stop", §20).
//!
//! The engine's status reports `stopped` with the seq of the raising activation and the layout
//! it names; reads go on; every write is `NewerFormat` and every call, link and exchange pass
//! `Unavailable`, before a signature is asked for; the stop survives a reopen from saved state.
//!
//! **The raising transition is built by a test-only helper below the 0.5 builders**
//! ([`raise`] in this file): the exports, like the core's write side, build no `layout`
//! component (§20). The helper takes the body of a policy transition `begin_transition` made,
//! replaces its `change` with `{"layout":3}` and signs it with the device key; the account's own
//! `record_due` then records the `activate`, final at once in an account with no home.
#![allow(clippy::unwrap_used)]
mod v05_support;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::sync::Arc;
use v05_support::*;

const NOW: i64 = T0 + 3 * HOUR;

fn open(src: &MemSource, identity: &str, account: &str, saved: SavedState) -> Arc<AccountEngine> {
    AccountEngine::open(
        Box::new(src.clone()),
        src.listing(),
        ident(identity),
        account.into(),
        vec![],
        0,
        saved,
        DEVICE_KEY.to_vec(),
        NOW,
    )
    .unwrap()
}
fn empty() -> SavedState {
    SavedState {
        verifier: vec![],
        checkpoint: vec![],
        parts: vec![],
    }
}
fn unlock(engine: &AccountEngine, host: &Host) {
    let slot = engine.slots().unwrap().remove(0);
    let inputs = engine.begin_unlock_slot(slot.index).unwrap();
    engine
        .finish_unlock_slot(slot.index, host.answer_slot(&inputs))
        .unwrap();
}

/// **Test-only, below the builders**: a `layout` raise signed by `d` (see the module comment).
fn raise(engine: &AccountEngine, host: &Host, d: &str) -> (String, Vec<u8>) {
    let action = engine
        .begin_transition(
            json!({"policy": {"callWindow": 120}}).to_string(),
            vec![d.to_string()],
            RuleKind::Control,
            vec![],
        )
        .unwrap();
    let body = action.steps().unwrap().remove(0).body;
    let mut v: Value = serde_json::from_slice(&body).unwrap();
    v["change"] = json!({"layout": 3});
    let bytes = colophon_core::v05::encoding::canonical(&v).unwrap();
    let sig = host.sign_one(&bytes, d, false).signature;
    let env = colophon_core::v05::encoding::canonical(
        &json!({"body": STANDARD.encode(&bytes), "signature": STANDARD.encode(sig)}),
    )
    .unwrap();
    let path = format!(
        "transitions/{}.json",
        colophon_core::v05::encoding::digest(&bytes)
    );
    (path, env)
}

fn kind(e: &AccountError) -> &'static str {
    match e {
        AccountError::NewerFormat { .. } => "newerFormat",
        AccountError::Unavailable { .. } => "unavailable",
        _ => "other",
    }
}

#[test]
fn the_status_reports_the_stop_reads_go_on_and_nothing_is_built() {
    let mut host = Host::new();
    let d = host.identity(10);
    let params = CreateParams {
        label: "Stopped".into(),
        namespaces: vec!["notes".into()],
        controllers: vec![host.raw_controller(&d, "Mac", &["approve", "control"])],
        slots: vec![SlotPlan {
            controllers: vec![d.clone()],
            label: "Mac".into(),
        }],
        threshold: None,
        recover_threshold: None,
        add_threshold: None,
        count_by_holders: false,
        policy_json: String::new(),
        signers: vec![d.clone()],
        rekey_signers: vec![d.clone()],
    };
    let creation =
        AccountCreation::begin(params, ident(&format!("controller:{d}")), T0, host.fresh(96))
            .unwrap();
    while creation.stage().unwrap() != CreateStage::Done {
        let steps = creation.steps().unwrap();
        creation.provide_signatures(host.sign(&steps)).unwrap();
    }
    let created = creation.take_result().unwrap();
    let account = created.account.clone();
    let src = MemSource::new();
    src.store(&created.stores);
    let me = format!("controller:{d}");
    let e = open(&src, &me, &account, empty());
    unlock(&e, &host);
    assert_eq!(e.status().unwrap().stopped.map(|s| s.seq), None);

    // The raise, held, then recorded: final at once (no home).
    let head = e.head_seq().unwrap();
    let (path, env) = raise(&e, &host, &d);
    src.put(&path, env);
    e.refresh(src.listing()).unwrap();
    assert!(e.status().unwrap().stopped.is_none(), "a held raise stops nothing");
    let due = e.record_due().unwrap();
    assert_eq!(due.len(), 1);
    src.store(&due[0].stores);
    let status = e.status().unwrap();
    assert_eq!(status.kind, StatusKind::NewerFormat);
    let stop = status.stopped.unwrap();
    assert_eq!((stop.seq, stop.layout), (head + 1, Some(3)));
    assert!(e.record_due().unwrap().is_empty(), "nothing more is recorded");

    // Reads go on.
    let view: Value = serde_json::from_str(&e.view_json("notes".into()).unwrap()).unwrap();
    assert_eq!(view["ok"], true, "{view}");
    assert_eq!(e.controllers().unwrap().len(), 1);

    // Writes are `NewerFormat`; calls, links and exchange passes `Unavailable`.
    let err = e
        .begin_keyring(vec![], vec![], json!({"callWindow": 120}).to_string(), vec![d.clone()], vec![])
        .err()
        .unwrap();
    assert_eq!(kind(&err), "newerFormat", "{err:?}");
    let key = host.keys[&d].public().signing;
    let err = e
        .begin_call(
            key.clone(),
            vec![],
            "https://projects.example/scopes/7".into(),
            "task.read".into(),
            "{}".into(),
            CallTarget {
                audiences: vec![],
                call_origins: vec![],
                controller_purposes: vec![],
                home_endpoints: vec![],
            },
            host.fresh(32),
        )
        .err()
        .unwrap();
    assert_eq!(kind(&err), "unavailable", "{err:?}");
    let err = e.exchange_next("home".into()).err().unwrap();
    assert_eq!(kind(&err), "unavailable", "{err:?}");

    // A cold reopen from saved state, and one from the files alone, keep the stop.
    let saved = e.save(host.fresh(32)).unwrap();
    let again = open(&src, &me, &account, saved);
    assert_eq!(again.status().unwrap().stopped.map(|s| (s.seq, s.layout)), Some((head + 1, Some(3))));
    let bare = open(&src, &me, &account, empty());
    assert_eq!(bare.status().unwrap().stopped.map(|s| s.seq), Some(head + 1));
}
