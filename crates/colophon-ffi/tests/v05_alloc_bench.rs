//! Opt-in benchmark of the zero-on-free allocator through the exports: a cold open, 1,000 writes
//! and a refresh, three rounds, the best of each. Run it twice, once with the allocator and once
//! without, and compare (it prints `BENCH ...` lines):
//!
//! ```sh
//! cargo test -p colophon-ffi --release --test v05_alloc_bench -- --ignored --nocapture
//! cargo test -p colophon-ffi --release --no-default-features --features native05 \
//!     --test v05_alloc_bench -- --ignored --nocapture
//! ```
//!
//! `allocator` in the output says which one ran. The engine cost test
//! (`colophon-core/tests/v05_engine_cost.rs`) runs inside `colophon-core`, which does not use the
//! allocator; this one goes through `colophon-ffi`, which does.
#![allow(clippy::unwrap_used, dead_code)]
mod v05_support;
use serde_json::json;
use std::sync::Arc;
use std::time::Instant;
use v05_support::*;

const WRITES: usize = 1000;

fn empty() -> SavedState {
    SavedState {
        verifier: vec![],
        checkpoint: vec![],
        parts: vec![],
    }
}
fn open(src: &MemSource, account: &str, identity: &str) -> Arc<AccountEngine> {
    AccountEngine::open(
        Box::new(src.clone()),
        src.listing(),
        ident(identity),
        account.to_string(),
        vec![],
        0,
        empty(),
        DEVICE_KEY.to_vec(),
        T0 + 3 * HOUR,
    )
    .unwrap()
}

/// One round: (writes, cold open, refresh) in milliseconds.
fn round() -> (f64, f64, f64) {
    let mut host = Host::new();
    let d = host.identity(10);
    let m = host.identity(31);
    let creation = AccountCreation::begin(
        CreateParams {
            label: "A".into(),
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
        },
        ident(&format!("controller:{d}")),
        T0,
        host.fresh(96),
    )
    .unwrap();
    loop {
        let steps = creation.steps().unwrap();
        if creation.provide_signatures(host.sign(&steps)).unwrap() == CreateStage::Done {
            break;
        }
    }
    let created = creation.take_result().unwrap();
    let src = MemSource::new();
    src.store(&created.stores);
    let ctl = open(&src, &created.account, &format!("controller:{d}"));
    let ins = ctl.begin_unlock_slot(0).unwrap();
    ctl.finish_unlock_slot(0, host.answer_slot(&ins)).unwrap();
    let p = host.keys[&m].public();
    // A grant with no write budget: 1,000 writes are allowed.
    let terms = json!({"records": [{"namespace": "notes", "access": "write"}]});
    let req = AccountRequest::prepare(RequestSpec {
        account: created.account.clone(),
        signing: p.signing,
        agreement: p.agreement,
        label: "Phone".into(),
        kind: AccountMemberKind::Device,
        terms_json: terms.to_string(),
        created: account_format_date(T0 + HOUR).unwrap(),
        custody: None,
        operator: None,
        endpoints: vec![],
    })
    .unwrap();
    let step = req.step().unwrap();
    let info = req.finish(host.sign_one(&step.body, &m, false)).unwrap();
    let a = ctl
        .begin_approve(info.raw, terms.to_string(), vec![d.clone()], host.fresh(32))
        .unwrap();
    let w = ctl
        .finish(a.clone(), host.sign(&a.steps().unwrap()))
        .unwrap();
    src.store(&w.stores);
    let me = open(&src, &created.account, &format!("member:{m}"));
    me.finish_unlock_epochs(host.answer_epochs(&m, &me.begin_unlock_epochs().unwrap()))
        .unwrap();

    let t = Instant::now();
    for i in 0..WRITES {
        let a = me
            .begin_write(
                "notes".into(),
                "createNotebook".into(),
                json!({"id": format!("n{i}"), "title": "A title of ordinary length"}).to_string(),
                host.fresh(32),
            )
            .unwrap();
        let w = me
            .finish(a.clone(), host.sign(&a.steps().unwrap()))
            .unwrap();
        src.store(&w.stores);
    }
    let writes = t.elapsed().as_secs_f64() * 1000.0;

    let t = Instant::now();
    let cold = open(&src, &created.account, &format!("member:{m}"));
    cold.finish_unlock_epochs(host.answer_epochs(&m, &cold.begin_unlock_epochs().unwrap()))
        .unwrap();
    let open_ms = t.elapsed().as_secs_f64() * 1000.0;
    assert!(cold.stats().unwrap().records_read as usize >= WRITES);

    let t = Instant::now();
    for _ in 0..20 {
        cold.refresh(src.listing()).unwrap();
    }
    let refresh = t.elapsed().as_secs_f64() * 1000.0 / 20.0;
    (writes, open_ms, refresh)
}

#[test]
#[ignore = "a benchmark: run it with --ignored --release"]
fn cold_open_a_thousand_writes_and_a_refresh() {
    let allocator = if cfg!(feature = "zero-on-free") {
        "zero-on-free"
    } else {
        "system"
    };
    let rounds: Vec<_> = (0..3).map(|_| round()).collect();
    let best = |f: fn(&(f64, f64, f64)) -> f64| rounds.iter().map(f).fold(f64::MAX, f64::min);
    let (w, o, r) = (best(|x| x.0), best(|x| x.1), best(|x| x.2));
    println!(
        "BENCH allocator={allocator} writes_ms={w:.1} cold_open_ms={o:.1} refresh_ms={r:.2} total_ms={:.1}",
        w + o + r
    );
}
