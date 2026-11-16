//! Freeze package item P and L2 (design §P, §9; spec §7.3, §9.1, §17.1).
//!
//! P: the account prepares a `grant`, or a transition's `grant` component, only by spending a
//! confirmed pairing the core issued on the approving device for this account and exactly the
//! request's `member.signing`. The code ceremony and the scanned request envelope each issue
//! one; another key, another account, the joining side's pairing, the pairing QR (it moves the
//! seed only), an expired pairing and no pairing at all are refused. A pairing is spent by moving it (it is not `Clone`; see the
//! `compile_fail` example on `ConfirmedPairing`), so it cannot approve twice.
//!
//! L2: a composite change whose new member uses a key the same change adds to the keyring is
//! refused at preparation, before any signature is asked for.
#![allow(clippy::unwrap_used)]
#[path = "v05_engine_support/mod.rs"]
mod support;
use colophon_core::v05::account::{AccessRequest, Change};
use colophon_core::v05::ids::AccountId;
use colophon_core::v05::pairing::{
    scanned_request, ConfirmedPairing, ExistingWaiting, FailureLimiter, Joiner, PairingAbort,
    QrJoiner, QrPayload, ScannedQr, CONFIRMED_PAIRING_LIFETIME_MS,
};
use colophon_core::v05::write::authority::TransitionRule;
use colophon_core::v05::write::calls::RequestSpec;
use colophon_core::v05::write::{format_date, SignatureResult};
use serde_json::json;
use support::*;

/// A fixture with one requesting device `m` (not yet a member) and its signed request.
fn with_request() -> (Fixture, String, AccessRequest) {
    let mut f = create(&["notes"]);
    let m = f.host.identity(40);
    let req = request_for(&f, &f.host, &m, "Phone", "device", terms("write"), f.account.now_ms());
    (f, m, req)
}

/// The §7.3 code ceremony between J (holding `e`) and H, confirmed on H at `now`.
fn code_pairing(account: &AccountId, e: &[u8], now: i64) -> (ConfirmedPairing, ConfirmedPairing) {
    let mut lim = FailureLimiter::new();
    let (j, c) = Joiner::begin(account, e, [7; 32]).unwrap();
    let h = ExistingWaiting::receive_commitment(account, c, lim.permit(now).unwrap());
    let (h, na) = h.send_nonce([9; 32]);
    let (reveal, j_code) = j.reveal(na).unwrap();
    let h_code = h.finish_limited(&reveal.e, &reveal.nb, &mut lim, now).unwrap();
    assert_eq!(h_code.digits(), j_code.digits(), "both screens show one code");
    assert_eq!(h_code.digits().len(), 6);
    (h_code.confirm(), j_code.confirm())
}

/// The request scanned from J's screen on H at `now`.
fn scan(account: &AccountId, req: &AccessRequest, now: i64) -> ConfirmedPairing {
    scanned_request(account, &req.raw, FailureLimiter::new().permit(now).unwrap()).unwrap()
}

fn signing(f: &Fixture, id: &str) -> Vec<u8> {
    f.host.ids[id].public().signing
}

fn is_member(f: &Fixture, id: &str) -> bool {
    f.account.members().iter().any(|m| m.member.id == id)
}

fn refused(r: colophon_core::v05::Result<colophon_core::v05::account::PendingAction>) -> String {
    match r {
        Ok(_) => panic!("the approval was prepared"),
        Err(e) => e.code(),
    }
}

// ---------------------------------------------------------------------------------------------
// Each path issues one.

#[test]
fn the_code_ceremony_issues_a_pairing_that_approves_the_request() {
    let (mut f, m, req) = with_request();
    let now = f.account.now_ms();
    let (h, _j) = code_pairing(&f.account.id().clone(), &signing(&f, &m), now);
    assert!(h.may_approve());
    let seed = f.host.fresh();
    let action = f
        .account
        .begin_approve(&req.raw, terms("write"), &[f.d.clone()], seed, h)
        .unwrap();
    run(&mut f.account, &f.host, action);
    assert!(is_member(&f, &m));
}

#[test]
fn the_scanned_request_issues_a_pairing_that_approves_the_request() {
    let (mut f, m, req) = with_request();
    let now = f.account.now_ms();
    let token = scan(&f.account.id().clone(), &req, now);
    assert!(token.may_approve());
    assert!(!token.can_move_seed(), "a scanned request carries no nonces");
    let seed = f.host.fresh();
    let action = f
        .account
        .begin_approve(&req.raw, terms("write"), &[f.d.clone()], seed, token)
        .unwrap();
    run(&mut f.account, &f.host, action);
    assert!(is_member(&f, &m));
}

#[test]
/// The scan path has exactly one payload, the canonical request envelope (§9.1, revision 17).
/// The pairing QR moves the seed but does not approve, even with `E` = `member.signing`.
fn the_pairing_qr_does_not_approve_even_with_the_member_key() {
    let (mut f, m, req) = with_request();
    let now = f.account.now_ms();
    let acct = f.account.id().clone();
    let qr = QrJoiner::begin(&acct, &signing(&f, &m), [3; 32]).unwrap().payload();
    let qr = QrPayload::from_bytes(&qr.to_bytes().unwrap()).unwrap();
    let (token, _na) = ScannedQr::scan(&acct, &qr, FailureLimiter::new().permit(now).unwrap())
        .unwrap()
        .send_nonce([4; 32]);
    assert!(!token.may_approve() && token.can_move_seed());
    let seed = f.host.fresh();
    let r = f.account.begin_approve(&req.raw, terms("write"), &[f.d.clone()], seed, token);
    assert_eq!(refused(r), "refused:outOfScope");
    assert!(!is_member(&f, &m));
}

// ---------------------------------------------------------------------------------------------
// Refusals.

/// The attack of finding 12: a relay substitutes a request whose key it chose. The person
/// paired the real device's key; the substituted request names another, so the approval is
/// refused, whatever any ID prefix says.
#[test]
fn a_pairing_for_another_key_is_refused() {
    let (mut f, m, _real) = with_request();
    let attacker = f.host.identity(41);
    let substituted = request_for(&f, &f.host, &attacker, "Phone", "device", terms("write"), f.account.now_ms());
    let now = f.account.now_ms();
    let (h, _) = code_pairing(&f.account.id().clone(), &signing(&f, &m), now);
    let seed = f.host.fresh();
    let r = f.account.begin_approve(&substituted.raw, terms("write"), &[f.d.clone()], seed, h);
    assert_eq!(refused(r), "refused:outOfScope");
    assert!(!is_member(&f, &attacker));
    // The scan path binds the same way.
    let token = scan(&f.account.id().clone(), &_real, now);
    let seed = f.host.fresh();
    let r = f.account.begin_approve(&substituted.raw, terms("write"), &[f.d.clone()], seed, token);
    assert_eq!(refused(r), "refused:outOfScope");
}

#[test]
fn a_pairing_for_another_account_is_refused() {
    let (mut f, m, req) = with_request();
    let other = create_v(&["notes"], 3);
    let now = f.account.now_ms();
    let (h, _) = code_pairing(&other.account.id().clone(), &signing(&f, &m), now);
    let seed = f.host.fresh();
    let r = f.account.begin_approve(&req.raw, terms("write"), &[f.d.clone()], seed, h);
    assert_eq!(refused(r), "refused:outOfScope");
    assert!(!is_member(&f, &m));
}

#[test]
fn the_joining_sides_pairing_does_not_approve() {
    let (mut f, m, req) = with_request();
    let now = f.account.now_ms();
    let (_h, j) = code_pairing(&f.account.id().clone(), &signing(&f, &m), now);
    assert!(!j.may_approve());
    let seed = f.host.fresh();
    let r = f.account.begin_approve(&req.raw, terms("write"), &[f.d.clone()], seed, j);
    assert_eq!(refused(r), "refused:outOfScope");
    // Nor does the QR joiner's.
    let acct = f.account.id().clone();
    let jq = QrJoiner::begin(&acct, &signing(&f, &m), [5; 32]).unwrap().receive_nonce([6; 32]);
    let seed = f.host.fresh();
    let r = f.account.begin_approve(&req.raw, terms("write"), &[f.d.clone()], seed, jq);
    assert_eq!(refused(r), "refused:outOfScope");
}

#[test]
fn an_expired_pairing_is_refused_and_one_at_its_limit_approves() {
    let (mut f, m, req) = with_request();
    let now = f.account.now_ms();
    let acct = f.account.id().clone();
    let old = scan(&acct, &req, now - CONFIRMED_PAIRING_LIFETIME_MS - 1);
    let seed = f.host.fresh();
    let r = f.account.begin_approve(&req.raw, terms("write"), &[f.d.clone()], seed, old);
    assert_eq!(refused(r), "refused:expired");
    let (h, _) = code_pairing(&acct, &signing(&f, &m), now - CONFIRMED_PAIRING_LIFETIME_MS);
    let seed = f.host.fresh();
    let action = f
        .account
        .begin_approve(&req.raw, terms("write"), &[f.d.clone()], seed, h)
        .unwrap();
    run(&mut f.account, &f.host, action);
    assert!(is_member(&f, &m));
}

/// Without a pairing there is no approval: `begin_approve` cannot be called without one (the
/// argument is a value only the pairing functions make), and a transition's `grant` component
/// is refused by the plain transition call.
#[test]
fn a_grant_component_without_a_pairing_is_refused() {
    let (f, _m, req) = with_request();
    let change = Change::grant(&req.raw, terms("write"));
    let r = f.account.begin_transition(&change, &[f.d.clone(), f.k.clone()], TransitionRule::Control);
    assert_eq!(refused(r), "refused:outOfScope");
}

#[test]
fn a_grant_transition_spends_a_pairing_for_exactly_its_request() {
    let (mut f, m, req) = with_request();
    let now = f.account.now_ms();
    let acct = f.account.id().clone();
    let attacker = f.host.identity(42);
    let substituted = request_for(&f, &f.host, &attacker, "Phone", "device", terms("write"), now);
    // A pairing for the real key does not carry the substituted request.
    let change = Change::grant(&substituted.raw, terms("write"));
    let (h, _) = code_pairing(&acct, &signing(&f, &m), now);
    let r = f.account.begin_grant_transition(&change, &[f.d.clone(), f.k.clone()], TransitionRule::Control, h);
    assert_eq!(refused(r), "refused:outOfScope");
    // A change without a grant spends nothing and is malformed.
    let r = f.account.begin_grant_transition(
        &Change::thresholds(None, None, Some(1)),
        &[f.d.clone(), f.k.clone()],
        TransitionRule::Control,
        scan(&acct, &req, now),
    );
    assert_eq!(refused(r), "malformed");
    // The right pairing prepares the transition.
    let change = Change::grant(&req.raw, terms("write"));
    let action = f
        .account
        .begin_grant_transition(&change, &[f.d.clone(), f.k.clone()], TransitionRule::Control, scan(&acct, &req, now))
        .unwrap();
    let done = run(&mut f.account, &f.host, action);
    assert_eq!(done.pending.len(), 1, "a pending transition was made");
}

// ---------------------------------------------------------------------------------------------
// The scan path's own refusals.

#[test]
fn a_scanned_request_must_verify_and_name_the_account() {
    let (f, _m, req) = with_request();
    let other = create_v(&["notes"], 4);
    let mut lim = FailureLimiter::new();
    let now = f.account.now_ms();
    assert_eq!(
        scanned_request(other.account.id(), &req.raw, lim.permit(now).unwrap()).unwrap_err(),
        PairingAbort::WrongAccount
    );
    let mut tampered = req.raw.clone();
    let at = tampered.len() / 2;
    tampered[at] ^= 1;
    assert_eq!(
        scanned_request(f.account.id(), &tampered, lim.permit(now).unwrap()).unwrap_err(),
        PairingAbort::InvalidRequest
    );
    assert_eq!(
        scanned_request(f.account.id(), b"not a request", lim.permit(now).unwrap()).unwrap_err(),
        PairingAbort::InvalidRequest
    );
    // The one payload is the canonical envelope (§9.1): the same envelope with a space added
    // is not it.
    let mut spaced = b" ".to_vec();
    spaced.extend_from_slice(&req.raw);
    assert_eq!(
        scanned_request(f.account.id(), &spaced, lim.permit(now).unwrap()).unwrap_err(),
        PairingAbort::InvalidRequest
    );
}

#[test]
fn a_scanned_request_cannot_move_the_seed() {
    let (f, _m, req) = with_request();
    let token = scan(&f.account.id().clone(), &req, f.account.now_ms());
    assert!(token.transfer_info().is_empty());
}

// ---------------------------------------------------------------------------------------------
// L2: a composite change is judged against the state its own components produce.

#[test]
fn l2_a_member_with_a_key_the_same_change_adds_is_refused_at_preparation() {
    let mut f = create(&["notes"]);
    let x = f.host.identity(71);
    let p = f.host.ids[&x].public();
    let prepared = colophon_core::v05::account::prepare_request(&RequestSpec {
        account: f.account.id(),
        signing: &p.signing,
        agreement: &p.agreement,
        label: "Home",
        kind: "server",
        terms: json!({"serves": ["home"]}),
        created: &format_date(f.account.now_ms()),
        custody: None,
        operator: None,
        endpoints: Some(vec!["https://home.example/".into()]),
    })
    .unwrap();
    let sig = SignatureResult {
        signature: f.host.ids[&x].sign(prepared.step().body()).to_vec(),
        assertion: None,
    };
    let req = colophon_core::v05::account::finish_request(&prepared, &sig).unwrap();
    let change = Change::add_controllers(vec![f.host.raw_controller(&x, "Spare", &["approve"])]).and(
        Change::homes(json!({"appoint": [{"request": b64(&req.raw), "terms": {"serves": ["home"]}}]})),
    );
    let r = f.account.begin_transition(&change, &[f.d.clone(), f.k.clone()], TransitionRule::Control);
    match r {
        Ok(_) => panic!("a doomed composite was prepared for signing"),
        Err(e) => assert_eq!(e.code(), "malformed", "{e}"),
    }
    // Each component alone prepares.
    let alone = Change::homes(json!({"appoint": [{"request": b64(&req.raw), "terms": {"serves": ["home"]}}]}));
    assert!(f.account.begin_transition(&alone, &[f.d.clone(), f.k.clone()], TransitionRule::Control).is_ok());
}
