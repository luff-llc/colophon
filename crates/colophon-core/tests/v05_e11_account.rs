//! E11: an engine over a just-created account (unlocked at once), and who signed what admitted
//! each member and controller (the removal follow-up of §17.5).
#![allow(clippy::unwrap_used, clippy::cloned_ref_to_slice_refs)]
#[path = "v05_engine_support/mod.rs"]
mod support;
use colophon_core::v05::account::{CreateProgress, Creation, Identity, KeyringEdit};
use colophon_core::v05::engine::{Engine, EngineOptions};
use colophon_core::v05::records::Level;
use serde_json::json;
use support::*;

/// The journeys' creation, stopped before the fixture takes the account.
fn created() -> (Host, String, colophon_core::v05::account::Account) {
    let mut host = Host::new();
    let d = host.identity(10);
    let k = host.kit(20);
    let p = host.passkey();
    let params = params(&mut host, &d, &p, &k, &["notes"]);
    let mut creation = Creation::begin(params, Identity::Controller(d.clone()), T0).unwrap();
    let results = host.answer_prf(creation.prf_requests());
    creation = creation.provide_prf(results).unwrap();
    let sigs = host.sign(creation.steps());
    let mut progress = creation.provide_signatures(sigs).unwrap();
    loop {
        match progress {
            CreateProgress::Continue(c) => {
                let sigs = host.sign(c.steps());
                progress = c.provide_signatures(sigs).unwrap();
            }
            CreateProgress::Done(a) => return (host, d, *a),
        }
    }
}

/// The engine over a creation's stores is unlocked and loaded: the owner writes at once, with
/// no second unlock (an engine opened with `open` cannot until it unlocks a slot).
#[test]
fn an_engine_over_a_created_account_is_unlocked_at_once() {
    let (mut host, d, account) = created();
    let src = MemSource::new();
    src.store_account(&account);
    let id = account.id().as_str().to_string();
    let m = host.identity(31);
    let fake = Fixture { host: Host::new(), d: d.clone(), p: String::new(), k: String::new(), account: colophon_core::v05::account::Account::open(account.objects().clone(), account.records().to_vec(), None, Identity::Controller(d.clone()), T0).unwrap() };
    let req = request_for(&fake, &host, &m, "Phone", "device", terms_for(&[("notes", "write")]), T0);
    let cold = Engine::open(src.clone(), src.listing(), Identity::Controller(d.clone()), EngineOptions::new(&id, DEVICE_KEY), None, T0).unwrap();
    assert!(cold.account().begin_approve(&req.raw, terms_for(&[("notes", "write")]), &[d.clone()], host.fresh()).is_err(), "a cold engine needs an unlock first");
    let mut e = Engine::open_created(src.clone(), src.listing(), account, EngineOptions::new(&id, DEVICE_KEY), T0).unwrap();
    let action = e.account().begin_approve(&req.raw, terms_for(&[("notes", "write")]), &[d.clone()], host.fresh()).unwrap();
    let w = engine_finish(&mut e, &host, &src, action);
    assert!(!w.stores.is_empty(), "the owner approved a member without unlocking again");
    let _ = (&mut host, Level::Write, json!({}));
}

/// A source that does not hold exactly what the creation made is refused, and nothing is kept.
#[test]
fn an_engine_over_a_created_account_refuses_another_source() {
    let (_host, _d, account) = created();
    let src = MemSource::new();
    src.store_account(&account);
    let id = account.id().as_str().to_string();
    let last = src.listing().into_iter().filter(|p| p.starts_with("authority/")).max().unwrap();
    src.remove(&last);
    let r = Engine::open_created(src.clone(), src.listing(), account, EngineOptions::new(&id, DEVICE_KEY), T0);
    assert_eq!(r.err().map(|e| e.code()).as_deref(), Some("malformed"));
}

/// Who signed what admitted each member and controller: a grant's signers, an immediate
/// controller addition's signers, nobody for the genesis and for a home a recording entry added.
#[test]
fn members_and_controllers_say_who_signed_their_admission() {
    let mut f = create(&["notes"]);
    let home = appoint_home(&mut f);
    let m = f.host.identity(31);
    admit(&mut f, &m, "Phone", "device", terms_for(&[("notes", "write")]), terms_for(&[("notes", "write")]));
    let s = f.host.identity(40);
    let added = f.host.raw_controller(&s, "Laptop", &["approve"]);
    let action = f.account.begin_keyring(&KeyringEdit { add_controllers: vec![added], ..Default::default() }, &[f.d.clone()]).unwrap();
    run(&mut f.account, &f.host, action);
    let members = f.account.members();
    let phone = members.iter().find(|x| x.member.id == m).unwrap();
    assert_eq!(phone.granted_by, vec![f.d.clone()]);
    let h = members.iter().find(|x| x.member.id == home).unwrap();
    assert!(h.granted_by.is_empty(), "a recording entry has no signer");
    let controllers = f.account.controllers();
    let laptop = controllers.iter().find(|c| c.id == s).unwrap();
    assert_eq!(laptop.added_by, vec![f.d.clone()]);
    assert_eq!(laptop.added_seq, f.account.head().0);
    let mac = controllers.iter().find(|c| c.id == f.d).unwrap();
    assert!(mac.added_by.is_empty() && mac.added_seq == 1, "the genesis has no adder");
}
