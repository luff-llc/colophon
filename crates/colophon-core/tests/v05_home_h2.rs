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
use colophon_core::v05::history::home::{
    admit, admit_pending_batch, admit_with, finish_receipt, HomeState, Refusal, ServingInterval,
};
use colophon_core::v05::account::{Change, Incoming};
use colophon_core::v05::history::Objects;
use colophon_core::v05::write::authority::TransitionRule;
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
    let pairing = paired(&f, &req);
    let action = f.account.begin_approve(&req.raw, terms_for(&[(NS, "write")]), &[f.d.clone()], seed, pairing).unwrap();
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

// ---------------------------------------------------------------------------------------------
// The H2 check (2026-11-15), finding 1: receipts of objects the home does not hold.

/// Three homes, A the primary; the home state of A.
fn three_homes() -> (Fixture, HomeState, [HomeKeys; 3]) {
    let keys = [HomeKeys::new(0x77), HomeKeys::new(0x78), HomeKeys::new(0x7a)];
    let mut f = create_with(&[NS], "public", 1);
    appoint_homes(&mut f, &[(&keys[0], BASE_A), (&keys[1], BASE_B), (&keys[2], "https://home-c.example")]);
    let now = f.account.now_ms();
    let a = HomeState::new(keys[0].id.clone(), f.account.objects(),
        vec![ServingInterval { from_ms: now, through_ms: None }], now).unwrap();
    (f, a, keys)
}
fn receipt(keys: &HomeKeys, account: &str, object: &str, received: i64) -> Vec<u8> {
    let body = canonical(&json!({"protocol": "colophon/receipt/5", "account": account, "object": object,
        "received": format_date(received), "by": keys.id})).unwrap();
    canonical(&json!({"body": STANDARD.encode(&body), "signature": STANDARD.encode(keys.sign(&body).signature)})).unwrap()
}
fn merge(f: &mut Fixture, pending: Vec<Vec<u8>>, at: i64) {
    f.account.merge(Incoming { objects: Objects { pending, ..Objects::default() }, records: vec![] }, at).unwrap();
}

/// A transition by one unit, receipted by home A. Returns (transition, its digest, A's state).
fn receipted(f: &mut Fixture, a: HomeState, ka: &HomeKeys, t: i64) -> (Vec<u8>, String, HomeState) {
    receipted_with(f, a, ka, t, 600)
}
fn receipted_with(f: &mut Fixture, a: HomeState, ka: &HomeKeys, t: i64, window: u64) -> (Vec<u8>, String, HomeState) {
    f.account.advance(t).unwrap();
    let action = f
        .account
        .begin_transition(&Change::policy(json!({"callWindow": window})), &[f.d.clone()], TransitionRule::Control)
        .unwrap();
    let tr = run(&mut f.account, &f.host, action).pending[0].clone();
    let d = body_digest(&tr);
    let now = format_date(t + 1_000);
    let adm = admit(&a, &tr, &now);
    assert_eq!(adm.result, Ok(()));
    let draft = &adm.receipts[0];
    let env = canonical(&json!({"body": STANDARD.encode(&draft.body),
        "signature": STANDARD.encode(ka.sign(&draft.body).signature)})).unwrap();
    let a = finish_receipt(&adm.state, &d, &env, &now).unwrap();
    merge(f, vec![env], t + 1_000);
    (tr, d, a)
}

/// A hostile current home (B) fills the buffer of receipts for objects A does not hold with
/// receipts of random digests. The owner's veto reaches A late, in one batch with B's in-window
/// receipt of it: A stores the veto (§13.1) whatever the buffer holds. Another home's (C's)
/// receipts still find room: one home cannot use another's share. And the buffer's items expire.
#[test]
fn a_late_veto_with_its_receipt_is_stored_however_full_the_unmatched_buffer() {
    let (mut f, a, [ka, kb, kc]) = three_homes();
    let account = f.account.id().as_str().to_string();
    let t = f.account.now_ms() + 60_000;
    let (_tr, d, mut a) = receipted(&mut f, a, &ka, t);
    // B floods A: 4,096 receipts of objects nobody holds.
    let flood_at = t + 2_000;
    for chunk in (0..4_096u32).collect::<Vec<_>>().chunks(16) {
        let objs: Vec<Vec<u8>> = chunk.iter().map(|i| receipt(&kb, &account, &digest(&i.to_le_bytes()), flood_at)).collect();
        let (next, _, _) = admit_pending_batch(&a, &objs, &format_date(flood_at)).unwrap();
        a = next;
    }
    // The owner's veto, from the other unit; B receipts it in time; it reaches A 400 s late.
    let veto_at = t + 3_000;
    f.account.advance(veto_at).unwrap();
    let action = f.account.begin_veto(&d, &[f.p.clone()]).unwrap();
    let veto = run(&mut f.account, &f.host, action).pending.iter().find(|p| {
        let v: Value = serde_json::from_slice(p).unwrap();
        let b: Value = serde_json::from_slice(&STANDARD.decode(v["body"].as_str().unwrap()).unwrap()).unwrap();
        b["protocol"] == "colophon/veto/5"
    }).unwrap().clone();
    let dv = body_digest(&veto);
    let rb = receipt(&kb, &account, &dv, veto_at + 10_000);
    let late = format_date(veto_at + 400_000);
    let (next, results, own) = admit_pending_batch(&a, &[veto.clone(), rb], &late).unwrap();
    assert_eq!(results, vec![Ok(()), Ok(())], "the late veto and its receipt are stored");
    assert!(own.is_empty(), "A signs no receipt of a late veto");
    let held = next.pending_object(&dv, veto_at + 400_000).unwrap().expect("the veto is held and listed");
    assert_eq!(held.receipts.len(), 1);
    // C's share is its own: its receipt of an object A does not hold yet is kept, and counts
    // once the object arrives (here: a second transition C receipted before A saw it).
    let t2 = veto_at + 500_000;
    f.account.advance(t2).unwrap();
    let action = f
        .account
        .begin_transition(&Change::policy(json!({"callWindow": 601})), &[f.d.clone(), f.p.clone()], TransitionRule::Control)
        .unwrap();
    let tr2 = run(&mut f.account, &f.host, action).pending[0].clone();
    let d2 = body_digest(&tr2);
    let rc = receipt(&kc, &account, &d2, t2 + 1_000);
    let a2 = admit(&next, &rc, &format_date(t2 + 1_500)).state;
    let a2 = admit(&a2, &tr2, &format_date(t2 + 2_000)).state;
    let by: Vec<String> = a2.pending_object(&d2, t2 + 2_000).unwrap().unwrap().receipts.iter()
        .map(|r| { let v: Value = serde_json::from_slice(r).unwrap(); let b: Value = serde_json::from_slice(&STANDARD.decode(v["body"].as_str().unwrap()).unwrap()).unwrap(); b["by"].as_str().unwrap().to_string() })
        .collect();
    assert!(by.contains(&kc.id), "C's receipt was kept although B's share is full: {by:?}");
    // B's receipts expire 300 s + the recovery delay + 7 days after their `received`: then B's
    // share is free again.
    let later = flood_at + 300_000 + 3_600_000 + 7 * 86_400_000 + 1_000;
    let r_new = receipt(&kb, &account, &digest(b"new object"), later);
    let after = admit(&a2, &r_new, &format_date(later));
    assert_ne!(after.result, Err(Refusal::Verification(colophon_core::v05::Failure::Unavailable("unmatched receipt capacity of this home".into()))));
}

// ---------------------------------------------------------------------------------------------
// The H2 check, finding 3: the 10,368 cap counts what is listed, and settled objects are dropped
// 7 days after their transition's due time.

/// A long-lived home holds more than 10,368 settled objects (receipts of a transition whose
/// `activate` is on the branch). A new transition, its veto and another home's receipts of both
/// are still stored. Seven days after the settled transition's due time, the home drops them.
#[test]
fn settled_objects_do_not_count_toward_the_cap_and_are_dropped_after_seven_days() {
    let (mut f, a, [ka, kb, _kc]) = three_homes();
    let account = f.account.id().as_str().to_string();
    let t = f.account.now_ms() + 60_000;
    let (_tr, d1, a) = receipted(&mut f, a, &ka, t);
    // Due (issued + 300 s + 3,600 s): the activate, recorded and admitted at A.
    let due = t + 3_900_000;
    f.account.advance(due + 1_000).unwrap();
    let rec = f.account.record_due().unwrap();
    let act = rec[0].entries[0].1.clone();
    let adm = admit(&a, &act, &format_date(due + 1_000));
    assert_eq!(adm.result, Ok(()));
    let mut a = adm.state;
    // A long life of settled objects: more than the cap, all naming the recorded transition.
    a.pad_for_tests(&d1, 10_400, due + 7 * 86_400_000);
    assert!(a.stored_objects() > 10_368);
    // A new transition, receipted by A and by B, then vetoed, the veto receipted by B.
    let t2 = due + 60_000;
    let (tr2, d2, a2) = receipted_with(&mut f, a, &ka, t2, 700);
    let rb = receipt(&kb, &account, &d2, t2 + 2_000);
    let r = admit(&a2, &rb, &format_date(t2 + 2_500));
    assert_eq!(r.result, Ok(()), "B's receipt of the new transition is stored");
    let a2 = r.state;
    f.account.advance(t2 + 3_000).unwrap();
    let action = f.account.begin_veto(&d2, &[f.p.clone()]).unwrap();
    let veto = run(&mut f.account, &f.host, action).pending.iter().find(|p| {
        let v: Value = serde_json::from_slice(p).unwrap();
        let b: Value = serde_json::from_slice(&STANDARD.decode(v["body"].as_str().unwrap()).unwrap()).unwrap();
        b["protocol"] == "colophon/veto/5"
    }).unwrap().clone();
    let dv = body_digest(&veto);
    let rv = receipt(&kb, &account, &dv, t2 + 4_000);
    let (a3, results, own) = admit_pending_batch(&a2, &[veto, rv], &format_date(t2 + 4_000)).unwrap();
    assert_eq!(results, vec![Ok(()), Ok(())], "the veto and B's receipt of it are stored");
    assert_eq!(own.len(), 1, "A receipts the veto");
    let _ = tr2;
    // Seven days after the first transition's due time, its objects are dropped.
    let later = due + 7 * 86_400_000 + 1_000;
    let r = admit(&a3, &receipt(&kb, &account, &digest(b"x"), later), &format_date(later));
    assert!(r.state.stored_objects() < 100, "{}", r.state.stored_objects());
}

// ---------------------------------------------------------------------------------------------
// The check of the forwarding fix (2026-11-16), finding 1: an `activate` that arrives as a
// candidate against another entry at its seq passes the same late-activation rule as one that
// extends the branch.

/// A (the primary, serving throughout) never saw transition T within 300 s of its `issued`, and
/// did not receipt it; B did. After T's due time A holds an immediate entry X at seq n, and the
/// `activate` of T at seq n arrives: a candidate against X. It is `refused:late` for ever, as it
/// is when it extends A's branch, and A still lists T and B's receipt of it.
#[test]
fn a_late_activate_is_refused_when_it_arrives_as_a_candidate() {
    use colophon_core::v05::account::{Account, Identity};
    let (mut f, a, [_ka, kb, _kc]) = three_homes();
    let account = f.account.id().as_str().to_string();
    let t = f.account.now_ms() + 60_000;
    f.account.advance(t).unwrap();
    let action = f
        .account
        .begin_transition(&Change::policy(json!({"callWindow": 650})), &[f.d.clone()], TransitionRule::Control)
        .unwrap();
    let tr = run(&mut f.account, &f.host, action).pending[0].clone();
    let d = body_digest(&tr);
    merge(&mut f, vec![receipt(&kb, &account, &d, t + 1_000)], t + 1_000);
    // A second copy of the account, before X: the activate comes from it.
    let mut other = Account::open(f.account.objects().clone(), f.account.records().to_vec(), None,
        Identity::Controller(f.d.clone()), t + 2_000).unwrap();
    let due = t + 3_900_000;
    other.advance(due + 1_000).unwrap();
    let act = other.record_due().unwrap()[0].entries[0].1.clone();
    f.account.advance(due + 500).unwrap();
    let id = f.host.identity(44);
    let req = request_for(&f, &f.host, &id, "Phone", "device", terms_for(&[(NS, "write")]), due + 500);
    let seed = f.host.fresh();
    let pairing = paired(&f, &req);
    let action = f.account.begin_approve(&req.raw, terms_for(&[(NS, "write")]), &[f.d.clone()], seed, pairing).unwrap();
    let x = run(&mut f.account, &f.host, action).entries[0].1.clone();
    assert_eq!(entry_seq(&x), entry_seq(&act), "X and the activate are at the same seq");
    // Extending A's branch, the activate is refused late (the rule as it stood).
    let at = format_date(due + 2_000);
    assert_eq!(admit(&a, &act, &at).result, Err(Refusal::Late));
    // As a candidate against X, the same.
    let with_x = admit(&a, &x, &format_date(due + 1_000));
    assert_eq!(with_x.result, Ok(()));
    let cand = admit(&with_x.state, &act, &at);
    assert_eq!(cand.result, Err(Refusal::Late), "a candidate must not bypass the late-activation rule");
    // For ever: later, and again.
    let again = admit(&cand.state, &act, &format_date(due + 60_000));
    assert_eq!(again.result, Err(Refusal::Late));
    // T and B's receipt are still listed, so a veto can still be judged.
    let held = again.state.pending_object(&d, due + 60_000).unwrap().expect("T is held");
    assert_eq!(held.receipts.len(), 1);
    let x_seq = entry_seq(&x) as usize;
    let entries = again.state.persisted().unwrap().objects().unwrap().entries.clone();
    assert!(!entries.iter().any(|e| body_digest(e) == body_digest(&act)), "the activate is not stored");
    assert!(entries.len() >= x_seq);
}

// ---------------------------------------------------------------------------------------------
// The check of the forwarding fix, finding 2: candidate exchange at the core.

/// The primary A holds an immediate entry X at seq n, covered by its own head and issued before
/// transition T's due time; T's `activate` R at seq n comes from another copy of the history.
/// Under §8.6 rule 1, X stands. R alone is refused (409) and not stored; once A holds B's head
/// over R, R is stored as evidence and still answered 409, and A's branch is unchanged. A second
/// such candidate R2 covered only by B is not stored (B has its slot at that seq); covered by C
/// too, it is.
#[test]
fn a_candidate_another_homes_head_covers_is_kept_as_evidence_one_per_home() {
    use colophon_core::v05::account::{Account, Identity};
    let (mut f, a, [ka, kb, kc]) = three_homes();
    let account = f.account.id().as_str().to_string();
    let t = f.account.now_ms() + 60_000;
    let (_tr, d, a) = receipted(&mut f, a, &ka, t);
    let open = |f: &Fixture| {
        Account::open(f.account.objects().clone(), f.account.records().to_vec(), None,
            Identity::Controller(f.d.clone()), t + 2_000).unwrap()
    };
    let mut other = open(&f);
    // R2 comes from a copy that holds B's receipt of T instead of A's, so its body differs.
    let mut objects = f.account.objects().clone();
    objects.pending.retain(|p| {
        let v: Value = serde_json::from_slice(p).unwrap();
        let b: Value = serde_json::from_slice(&STANDARD.decode(v["body"].as_str().unwrap()).unwrap()).unwrap();
        !(b["protocol"] == "colophon/receipt/5" && b["by"] == ka.id.as_str())
    });
    objects.pending.push(receipt(&kb, &account, &d, t + 1_500));
    let mut other2 = Account::open(objects, f.account.records().to_vec(), None,
        Identity::Controller(f.d.clone()), t + 2_000).unwrap();
    // X at A before T is due, and A's head over it.
    f.account.advance(t + 3_000).unwrap();
    let id = f.host.identity(45);
    let req = request_for(&f, &f.host, &id, "Phone", "device", terms_for(&[(NS, "write")]), t + 3_000);
    let seed = f.host.fresh();
    let pairing = paired(&f, &req);
    let action = f.account.begin_approve(&req.raw, terms_for(&[(NS, "write")]), &[f.d.clone()], seed, pairing).unwrap();
    let x = run(&mut f.account, &f.host, action).entries[0].1.clone();
    let (n, dx) = (entry_seq(&x), body_digest(&x));
    let a = admit(&a, &x, &format_date(t + 3_000));
    assert_eq!(a.result, Ok(()));
    let a = admit(&a.state, &head(&ka, &account, n, &dx, t + 4_000), &format_date(t + 4_000));
    assert_eq!(a.result, Ok(()));
    let a = a.state;
    // R and R2: T's activate at n, from the two other copies.
    let due = t + 3_900_000;
    other.advance(due + 1_000).unwrap();
    let r = other.record_due().unwrap()[0].entries[0].1.clone();
    other2.advance(due + 1_500).unwrap();
    let r2 = other2.record_due().unwrap()[0].entries[0].1.clone();
    let (dr, dr2) = (body_digest(&r), body_digest(&r2));
    assert_eq!((entry_seq(&r), entry_seq(&r2)), (n, n));
    assert_ne!(dr, dr2);
    let held = |s: &HomeState, d: &str| {
        s.persisted().unwrap().objects().unwrap().entries.iter().any(|e| body_digest(e) == d)
    };
    let now = format_date(due + 2_000);
    // Alone, R is refused and not stored.
    let alone = admit(&a, &r, &now);
    assert_eq!(alone.result, Err(Refusal::Conflict));
    assert!(!held(&alone.state, &dr));
    // With B's head over R, R is kept as evidence, still 409; A's branch keeps X.
    let a = admit(&a, &head(&kb, &account, n, &dr, due + 1_500), &now).state;
    let with = admit(&a, &r, &now);
    assert_eq!(with.result, Err(Refusal::Conflict));
    assert!(held(&with.state, &dr), "kept as evidence");
    let a = with.state;
    let branch_n = |s: &HomeState| {
        let h = admit(s, &head(&ka, &account, n, &dx, due + 3_000), &format_date(due + 3_000));
        h.result
    };
    assert_eq!(branch_n(&a), Ok(()), "A can still sign over X: its verdict is unchanged");
    // R2 covered by B only: B already covers a candidate at n, so it is not stored.
    let a = admit(&a, &head(&kb, &account, n, &dr2, due + 1_800), &now).state;
    let b_only = admit(&a, &r2, &now);
    assert_eq!(b_only.result, Err(Refusal::Conflict));
    assert!(!held(&b_only.state, &dr2), "one slot per covering home");
    // Covered by C too: C's own slot.
    let a = admit(&a, &head(&kc, &account, n, &dr2, due + 1_900), &now).state;
    let c_too = admit(&a, &r2, &now);
    assert_eq!(c_too.result, Err(Refusal::Conflict));
    assert!(held(&c_too.state, &dr2));
}
