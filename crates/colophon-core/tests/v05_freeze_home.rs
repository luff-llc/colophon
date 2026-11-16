//! H4: §13.6 at the admission boundary, including trusted-state restart.
#![allow(dead_code, clippy::unwrap_used, clippy::cloned_ref_to_slice_refs)]
#[path = "v05_engine_support/mod.rs"]
mod support;
#[path = "../../colophon-home-wasm/tests/support_relay/mod.rs"]
mod support_relay;
mod v05_stopped_support;
use colophon_core::v05::encoding::canonical;
use colophon_core::v05::history::home::{admit, finish_receipt, HomeState, ServingInterval};
use colophon_core::v05::history::{verify_history, Objects, Persisted};
use colophon_core::v05::write::format_date;
use serde_json::json;
use support_relay::{HomeKeys, BASE_A};
use v05_stopped_support::*;

struct Stopped {
    f: support::Fixture,
    home: HomeState,
    keys: HomeKeys,
    target: Vec<u8>,
    raise: Vec<u8>,
}
fn take(home: HomeState, keys: &HomeKeys, object: &[u8], now: i64) -> HomeState {
    let a = admit(&home, object, &format_date(now));
    assert_eq!(a.result, Ok(()));
    assert_eq!(a.receipts.len(), 1);
    let signed = receipt(keys, body(object)["account"].as_str().unwrap(), object, now);
    finish_receipt(&a.state, &object_digest(object), &signed, &format_date(now)).unwrap()
}
fn setup() -> Stopped {
    setup_with_competing_entry(false)
}
fn setup_with_competing_entry(competing: bool) -> Stopped {
    let keys = HomeKeys::new(0x77);
    let f = fixture("public", &[(&keys, BASE_A)]);
    let home = HomeState::new(
        keys.id.clone(),
        f.account.objects(),
        vec![ServingInterval {
            from_ms: 0,
            through_ms: None,
        }],
        NOW,
    )
    .unwrap();
    let raise = transition(&f, json!({"layout":3}), &f.k, NOW);
    let home = take(home, &keys, &raise, NOW);
    let target = transition(
        &f,
        json!({"policy":{"callWindow":600}}),
        &f.d,
        DUE - 100_000,
    );
    let home = take(home, &keys, &target, DUE - 100_000);
    let mut objects = home.persisted().unwrap().objects().unwrap().clone();
    let e = activate(&mut objects, &raise, DUE);
    let a = admit(&home, &e, &format_date(DUE));
    assert_eq!(a.result, Ok(()));
    assert!(
        !a.state.is_stopped(DUE).unwrap(),
        "provisional raises do not stop"
    );
    let h = head(&keys, &objects, DUE);
    let a = admit(&a.state, &h, &format_date(DUE));
    assert_eq!(a.result, Ok(()));
    objects.heads.push(h);
    let mut home = a.state;
    if competing {
        use colophon_core::v05::account::{Account, Identity};
        let mut account = Account::open(
            objects.clone(),
            vec![],
            None,
            Identity::Controller(f.d.clone()),
            DUE,
        )
        .unwrap();
        let action = account
            .begin_end_sessions(&keys.id, &[f.d.clone()])
            .unwrap();
        let done = support::run(&mut account, &f.host, action);
        let a = admit(&home, &done.entries[0].1, &format_date(DUE));
        assert_eq!(a.result, Ok(()));
        assert!(!a.state.is_stopped(DUE).unwrap());
        home = a.state;
    }
    let e = final_entry(&mut objects, support::entry_seq(&e), DUE);
    let a = admit(&home, &e, &format_date(DUE));
    assert_eq!(a.result, Ok(()), "the final itself is stored");
    assert!(a.state.is_stopped(DUE).unwrap());
    let home = HomeState::from_bytes(&a.state.to_bytes().unwrap()).unwrap();
    Stopped {
        f,
        home,
        keys,
        target,
        raise,
    }
}

#[test]
fn a_competing_final_recording_is_retained_when_it_stops_the_home() {
    let s = setup_with_competing_entry(true);
    let (_, v) = s.home.verified_history(DUE).unwrap();
    let state = v.state.unwrap();
    assert!(v.stopped.is_some());
    assert_eq!(state.history().len(), 5);
    let last = state.history().last().unwrap();
    let p = s.home.persisted().unwrap();
    assert!(p
        .objects()
        .unwrap()
        .entries
        .iter()
        .any(|e| object_digest(e) == *last && body(e)["kind"] == "final"));
}

#[test]
fn a_stopped_home_keeps_its_verified_prefix_and_pending_objects_across_restart() {
    let s = setup();
    let p = s.home.persisted().unwrap();
    let v = verify_history(&Objects::default(), &p, DUE);
    assert!(v.is_stopped());
    assert_eq!(v.state.unwrap().history().len(), 5);
    let page = s.home.pending_page(0, 64, DUE).unwrap();
    assert_eq!(
        page.objects.len(),
        2,
        "unrecorded target and its receipt still served"
    );
    assert_eq!(
        s.home
            .pending_object(&object_digest(&s.target), DUE)
            .unwrap()
            .unwrap()
            .receipts
            .len(),
        1
    );
    assert_eq!(
        p.objects().unwrap().pending.len(),
        4,
        "recorded objects are kept too"
    );
    let duplicate = admit(&s.home, &s.target, &format_date(DUE));
    assert_eq!(duplicate.result, Ok(()), "held objects remain idempotent");
    assert!(duplicate.receipts.is_empty());
    assert!(
        s.home.is_stopped(NOW).unwrap(),
        "a clock reset cannot clear the stop"
    );
}

#[test]
fn no_head_or_entry_or_unrelated_pending_object_is_admitted_after_stop() {
    let s = setup();
    let p = s.home.persisted().unwrap();
    let v = verify_history(&Objects::default(), &p, DUE);
    let st = v.state.unwrap();
    assert!(s
        .home
        .guard_head(
            st.history().len() as u64,
            st.history().last().unwrap(),
            &format_date(DUE + 1),
            &format_date(DUE + 1)
        )
        .is_err());
    let mut extra = body(p.objects().unwrap().entries.last().unwrap());
    extra["seq"] = json!(6);
    extra["previous"] = json!(st.history().last().unwrap());
    let entry = canonical(&json!({"body":support::b64(&canonical(&extra).unwrap())})).unwrap();
    let additive = transition(&s.f, json!({"policy":{"callWindow":600}}), &s.f.d, DUE);
    let successor = transition(
        &s.f,
        json!({"successor":{"account":"a".repeat(64)}}),
        &s.f.k,
        DUE,
    );
    let other = fixture("members", &[(&s.keys, BASE_A)]);
    let genesis = other
        .account
        .objects()
        .entries
        .iter()
        .find(|e| support::entry_seq(e) == 1)
        .unwrap()
        .clone();
    let unrelated_receipt = receipt(&s.keys, s.f.account.id().as_str(), &genesis, DUE);
    for object in [
        entry,
        additive,
        successor,
        genesis,
        unrelated_receipt,
        head(&s.keys, p.objects().unwrap(), DUE + 1),
    ] {
        let a = admit(&s.home, &object, &format_date(DUE + 1));
        assert_eq!(a.result.unwrap_err().code(), "newerFormat");
        assert!(a.receipts.is_empty());
        assert_eq!(
            a.state.to_bytes().unwrap(),
            s.home.to_bytes().unwrap(),
            "no storage or facts change"
        );
    }
}

#[test]
fn stopped_home_receipts_vetoes_and_removals_at_or_before_n_and_only_in_window() {
    let mut s = setup();
    let v = veto(&s.f, &s.target, &s.f.k, DUE);
    s.home = take(s.home, &s.keys, &v, DUE);
    // The stopped-home receipt witnesses arrival, even for the final raise itself. It
    // cannot make a receipt after that transition's deadline valid in a recording entry.
    let raise_veto = veto(&s.f, &s.raise, &s.f.d, DUE);
    s.home = take(s.home, &s.keys, &raise_veto, DUE);
    let removal = transition(&s.f, json!({"policy":{"callWindow":120}}), &s.f.d, DUE);
    // Anchor exactly at N, not just before it.
    let p = s.home.persisted().unwrap();
    let state = verify_history(&Objects::default(), &p, DUE).state.unwrap();
    let mut at_n = body(&removal);
    at_n["anchor"] = json!({"seq":state.history().len(), "digest":state.history().last().unwrap()});
    let removal = signed(&s.f, at_n.clone());
    s.home = take(s.home, &s.keys, &removal, DUE + 300_000);
    assert!(s.home.is_stopped(DUE + 300_000).unwrap());
    at_n["issued"] = json!(format_date(DUE + 1));
    let late = signed(&s.f, at_n.clone());
    let a = admit(&s.home, &late, &format_date(DUE + 300_002));
    assert_eq!(a.result.unwrap_err().code(), "newerFormat");
    assert!(a.receipts.is_empty());
    at_n["anchor"] = json!({"seq":state.history().len() + 1, "digest":"a".repeat(64)});
    let a = admit(&s.home, &signed(&s.f, at_n), &format_date(DUE + 1));
    assert_eq!(a.result.unwrap_err().code(), "newerFormat");
    // A previously drafted additive receipt must not be signed after a stop either.
    assert!(finish_receipt(
        &s.home,
        &object_digest(&s.raise),
        &receipt(&s.keys, s.f.account.id().as_str(), &s.raise, DUE),
        &format_date(DUE)
    )
    .is_err());
}

#[test]
fn a_provisional_raise_is_receipted_and_a_vetoed_displaces_it_without_stopping() {
    use colophon_core::v05::write::authority::prepare_vetoed;
    let keys = HomeKeys::new(0x77);
    let f = fixture("public", &[(&keys, BASE_A)]);
    let home = HomeState::new(keys.id.clone(), f.account.objects(), vec![], NOW).unwrap();
    let raise = transition(&f, json!({"layout":3}), &f.k, NOW);
    let home = take(home, &keys, &raise, NOW);
    let v = veto(&f, &raise, &f.d, NOW + 1_000);
    // The recorder has the timely veto but the activation can arrive first.
    let mut objects = home.persisted().unwrap().objects().unwrap().clone();
    let e = activate(&mut objects, &raise, DUE);
    let a = admit(&home, &e, &format_date(DUE));
    assert_eq!(a.result, Ok(()));
    assert!(!a.state.is_stopped(DUE).unwrap());
    let state = verify_history(&objects, &Persisted::default(), DUE)
        .state
        .unwrap();
    assert!(a
        .state
        .guard_head(
            state.history().len() as u64,
            state.history().last().unwrap(),
            &format_date(DUE),
            &format_date(DUE)
        )
        .is_ok());
    // The veto was receipted in its window in the pre-activation state.
    let with_veto = take(home, &keys, &v, NOW + 1_000);
    let before_activation = with_veto.persisted().unwrap().objects().unwrap().clone();
    let rec = prepare_vetoed(
        &before_activation,
        DUE,
        &object_digest(&raise),
        &object_digest(&v),
    )
    .unwrap()
    .finish(vec![])
    .unwrap();
    let a = admit(&a.state, &rec.entries[0].1, &format_date(DUE));
    assert_eq!(a.result, Ok(()));
    let p = a.state.persisted().unwrap();
    let v = verify_history(&Objects::default(), &p, DUE);
    assert!(!v.is_stopped());
    assert!(v.state.unwrap().stopped_at().is_none());
    assert!(p
        .objects()
        .unwrap()
        .entries
        .iter()
        .any(|e| body(e)["kind"] == "vetoed"));
}
