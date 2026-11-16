//! H2 (2026-11-15), the core's part of the home: a non-primary home takes entries a primary head
//! covers when the head names a later entry of the same upload, and is not bound by the 300 s
//! clock rule for them (it was offline; the primary applied the rule); heads over another digest
//! at a held seq are kept as fork evidence, at most four per home.
#![allow(clippy::unwrap_used, dead_code, clippy::too_many_arguments, clippy::cloned_ref_to_slice_refs)]
#[path = "v05_engine_support/mod.rs"]
mod support;
#[path = "../../colophon-home-wasm/tests/support_relay/mod.rs"]
mod support_relay;
use base64::{engine::general_purpose::STANDARD, Engine};
use colophon_core::v05::encoding::{canonical, digest};
use colophon_core::v05::history::home::{admit, admit_with, HomeState, Refusal, ServingInterval};
use colophon_core::v05::write::format_date;
use serde_json::{json, Value};
use support::*;
use support_relay::{appoint_homes, create_with, HomeKeys, BASE_A, BASE_B};

const NS: &str = "listening.podcasts";

fn head(keys: &HomeKeys, account: &str, seq: u64, digest_: &str, issued: i64) -> Vec<u8> {
    let body = canonical(&json!({"protocol": "colophon/head/5", "account": account,
        "authority": {"seq": seq, "digest": digest_}, "issued": format_date(issued), "by": keys.id}))
    .unwrap();
    canonical(&json!({"body": STANDARD.encode(&body), "signature": STANDARD.encode(keys.sign(&body).signature)}))
        .unwrap()
}
fn body_digest(env: &[u8]) -> String {
    let v: Value = serde_json::from_slice(env).unwrap();
    digest(&STANDARD.decode(v["body"].as_str().unwrap()).unwrap())
}

/// Two homes, A the primary. Returns the fixture, B's home state, and A's and B's keys.
fn setup() -> (Fixture, HomeState, HomeKeys) {
    let (ka, kb) = (HomeKeys::new(0x77), HomeKeys::new(0x78));
    let mut f = create_with(&[NS], "public", 1);
    appoint_homes(&mut f, &[(&ka, BASE_A), (&kb, BASE_B)]);
    let now = f.account.now_ms();
    let b = HomeState::new(
        kb.id.clone(),
        f.account.objects(),
        vec![ServingInterval { from_ms: now, through_ms: None }],
        now,
    )
    .unwrap();
    (f, b, ka)
}
fn approve(f: &mut Fixture, n: u8, at: i64) -> Vec<u8> {
    f.account.advance(at).unwrap();
    let id = f.host.identity(n);
    let req = request_for(f, &f.host, &id, "Phone", "device", terms_for(&[(NS, "write")]), at);
    let seed = f.host.fresh();
    let action = f.account.begin_approve(&req.raw, terms_for(&[(NS, "write")]), &[f.d.clone()], seed).unwrap();
    run(&mut f.account, &f.host, action).entries[0].1.clone()
}

#[test]
fn a_non_primary_home_takes_an_upload_a_primary_head_covers_after_being_offline() {
    let (mut f, b, ka) = setup();
    let account = f.account.id().as_str().to_string();
    let t = f.account.now_ms() + 60_000;
    let e1 = approve(&mut f, 41, t);
    let e2 = approve(&mut f, 42, t + 10_000);
    let (s1, s2) = (entry_seq(&e1), entry_seq(&e2));
    assert_eq!(s2, s1 + 1);
    // B was offline for 20 minutes: the entries are far more than 300 s behind its clock.
    let now = format_date(t + 1_200_000);
    let b = admit(&b, &head(&ka, &account, s2, &body_digest(&e2), t + 20_000), &now).state;
    // Alone, E1 is not covered (A's head names E2, which B does not hold yet), so the clock rule
    // applies to it and it is late.
    let alone = admit(&b, &e1, &now);
    assert_eq!(alone.result, Err(Refusal::Late));
    // With E2 from the same upload, A's head covers E1: stored, not refused late.
    let a = admit_with(&b, &e1, std::slice::from_ref(&e2), &now);
    assert_eq!(a.result, Ok(()));
    let a = admit(&a.state, &e2, &now);
    assert_eq!(a.result, Ok(()));
    assert_eq!(a.state.persisted().unwrap().high_water.map(|(s, _)| s), Some(s2));
    // At the primary (A), the same late entry is refused: the clock rule is the primary's.
    let (mut f2, _, ka2) = setup();
    let now2 = f2.account.now_ms();
    let a_home = HomeState::new(ka2.id.clone(), f2.account.objects(),
        vec![ServingInterval { from_ms: now2, through_ms: None }], now2).unwrap();
    let late = approve(&mut f2, 43, now2 + 60_000);
    let r = admit(&a_home, &late, &format_date(now2 + 60_000 + 1_200_000));
    assert_eq!(r.result, Err(Refusal::Late));
}

#[test]
fn fork_evidence_heads_are_kept_but_at_most_four_per_home() {
    let (mut f, b, ka) = setup();
    let account = f.account.id().as_str().to_string();
    let t = f.account.now_ms() + 60_000;
    let e1 = approve(&mut f, 41, t);
    let (s1, d1) = (entry_seq(&e1), body_digest(&e1));
    let now = format_date(t + 20_000);
    let mut st = admit(&b, &head(&ka, &account, s1, &d1, t + 1_000), &now).state;
    let a = admit(&st, &e1, &now);
    assert_eq!(a.result, Ok(()));
    st = a.state;
    for i in 0..6u8 {
        let other = digest(&[i; 8]);
        let a = admit(&st, &head(&ka, &account, s1, &other, t + 2_000 + i64::from(i) * 1_000), &now);
        assert_eq!(a.result, Ok(()), "a current home's head over another digest is evidence, kept");
        st = a.state;
    }
    let heads = st.persisted().unwrap().objects().unwrap().heads.clone();
    let off = heads
        .iter()
        .filter(|h| {
            let v: Value = serde_json::from_slice(h).unwrap();
            let b: Value = serde_json::from_slice(&STANDARD.decode(v["body"].as_str().unwrap()).unwrap()).unwrap();
            b["authority"]["digest"] != d1.as_str()
        })
        .count();
    assert_eq!(off, 4, "the newest four of six");
    assert_eq!(heads.len(), 5, "and the head over the held entry");
}
