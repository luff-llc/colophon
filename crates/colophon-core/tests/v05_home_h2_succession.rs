//! The H2 check (2026-11-15), finding 2: §15.1 fixes the homes that receipt a successor's
//! genesis (and a veto of the succession) at the succession window's entry. A receipt by such a
//! home stays valid at a home after that home's revocation is final.
#![allow(clippy::unwrap_used, dead_code, unused_imports, clippy::too_many_arguments)]
#[path = "v05_engine_support/mod.rs"]
mod support;
#[path = "../../colophon-home-wasm/tests/support_relay/mod.rs"]
mod support_relay;
#[path = "v05_e7_support/mod.rs"]
mod e7;
#[path = "v05_swift_support/mod.rs"]
mod swift;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use colophon_core::v05::account::*;
use colophon_core::v05::descriptor::Controller;
use colophon_core::v05::encoding::{canonical, digest};
use colophon_core::v05::history::home::{admit, HomeState, ServingInterval};
use colophon_core::v05::history::Objects;
use colophon_core::v05::slots::{PrfAssertion, PrfResult, SlotBuild, SlotPlan, SlotTarget};
use colophon_core::v05::swift_slots::*;
use colophon_core::v05::vault::VaultSeed;
use colophon_core::v05::write::authority::TransitionRule;
use colophon_core::v05::write::calls::RequestSpec;
use colophon_core::v05::write::succession::*;
use colophon_core::v05::write::{format_date, SignatureResult};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use serde_json::{json, Value};
use support_relay::{HomeKeys, BASE_A};
use swift::{keyring_library_with, sha, Host, SwiftFixture};

const T0: i64 = 1_794_384_000_000;
const SEC: i64 = 1_000;
const RP: &str = "id.example";
const ORIGIN: &str = "https://id.example";

fn e7_id(n: u8) -> String {
    let k = p256::ecdsa::SigningKey::from_slice(&[n; 32]).unwrap();
    colophon_core::v05::ids::key_id(k.verifying_key().to_encoded_point(false).as_bytes())
}
/// The fixture's keys: software identities by the host, the passkey and the security key by
/// WebAuthn (scalars [9;32] and [10;32]).
fn sign(host: &Host, steps: &[colophon_core::v05::write::SigningStep]) -> Vec<SignatureResult> {
    steps
        .iter()
        .map(|s| match s.challenge() {
            None => SignatureResult {
                signature: host.sign(s.signer(), s.body()),
                assertion: None,
            },
            Some(ch) => {
                let rp = s.descriptor().unwrap().webauthn().unwrap().rp().to_string();
                let scalar = if s.signer() == e7_id(9) { [9u8; 32] } else { [10u8; 32] };
                e7::key_from_scalar(&scalar).sign_webauthn(&rp, &format!("https://{rp}"), 0x05, ch)
            }
        })
        .collect()
}
fn run(a: &mut Account, host: &Host, action: PendingAction) -> Finished {
    let sigs = sign(host, action.steps());
    a.finish(action, sigs).unwrap()
}
fn b64(b: &[u8]) -> String {
    STANDARD.encode(b)
}
fn body_of(env: &Value) -> Value {
    serde_json::from_slice(&STANDARD.decode(env["body"].as_str().unwrap()).unwrap()).unwrap()
}

/// The successor of a Swift keyring library, with the relay's key as its home: the genesis with
/// its hand-over, the slots rebuilt, the home appointed (the window opens at the activation).
fn successor(host: &mut Host, homes: &[&HomeKeys]) -> (Account, SwiftFixture, String) {
    let f = keyring_library_with(host, false, false, false);
    let pred = f.entries.clone();
    let lib = SwiftLibrary::read(&pred).unwrap();
    let ctl = f.device.id.clone();
    let mut opts = CarryOptions::default();
    for id in [&f.passkey_id, &f.security_id] {
        opts.authority_origins.insert(id.clone(), vec![ORIGIN.into()]);
    }
    let carried = swift_carried_controllers(&pred, &opts).unwrap();
    let new_seed = VaultSeed::from_host_random([0x77; 32]);
    let mut policy = default_policy();
    policy["recoveryDelay"] = json!(3600);
    // Public history: a device that holds nothing yet fetches it without a call (§13.4).
    policy["history"] = json!("public");
    let mut base = json!({"controllers": carried, "threshold": 1, "recoverThreshold": 1, "addThreshold": 1,
        "countBy": "keys", "policy": policy, "vault": new_seed.public().unwrap().to_value(), "slots": []});
    let controllers: std::collections::BTreeMap<String, Controller> = carried
        .iter()
        .map(|v| Controller::parse(v.clone(), "carried").unwrap())
        .map(|c| (c.id(), c))
        .collect();
    let target = SlotTarget::genesis(&new_seed, &controllers).unwrap();
    let mut slots = Vec::new();
    for (n, (id, label)) in [(ctl.clone(), "Device"), (f.passkey_id.clone(), "Passkey")].iter().enumerate() {
        let build = SlotBuild::begin(
            &SlotPlan { controllers: vec![id.clone()], label: label.to_string() },
            &target,
            [0x40 + n as u8; 32],
        )
        .unwrap();
        let results: Vec<PrfResult> = if id == &f.passkey_id {
            let (cers, _) = lib.pair_ceremonies(1, build.prf_requests()).unwrap();
            let c = &cers[0];
            let key = e7::key_from_scalar(&f.passkey_key.to_bytes());
            let client = canonical(&json!({"type": "webauthn.get", "origin": ORIGIN,
                "challenge": colophon_core::v05::encoding::encode_base64url(&c.new_request.challenge)}))
            .unwrap();
            let mut auth = sha(RP.as_bytes());
            auth.push(0x05);
            auth.extend([0, 0, 0, 0]);
            let a = key.sign_assertion(&auth, &client);
            let (ad, cd) = a.assertion.clone().unwrap();
            vec![PrfResult {
                assertion: PrfAssertion { authenticator_data: ad, client_data: cd, signature: a.signature },
                output: Host::prf(&c.new_request.salt),
            }]
        } else {
            vec![]
        };
        slots.push(build.finish(&new_seed, &results).unwrap().to_value().unwrap());
    }
    base["slots"] = Value::Array(slots);
    let pending = prepare_swift_genesis(
        &SwiftGenesisParams {
            label: "Library".into(),
            namespaces: vec!["notes".into(), "reading.saved".into()],
            keyring: base,
            issued_ms: T0 - 60 * SEC,
            predecessor: pred.clone(),
            signers: vec![ctl.clone()],
            handover: vec![ctl.clone()],
            earlier_attempts: vec![],
        },
        T0,
    )
    .unwrap();
    let sigs = sign(host, pending.steps());
    let genesis = pending.finish(sigs).unwrap().entries[0].1.clone();
    let mut acct = Account::open(
        Objects { entries: vec![genesis], predecessor: pred, ..Objects::default() },
        vec![],
        None,
        Identity::Controller(ctl.clone()),
        T0,
    )
    .unwrap();
    let ins = acct.begin_unlock_slot(0).unwrap();
    acct.finish_unlock_slot(0, &host.answer(&ins)).unwrap();
    let mut appoint = Vec::new();
    for (n, home) in homes.iter().enumerate() {
        let (_, _, agreement) = host.identity(70 + n as u8);
        let prepared = prepare_request(&RequestSpec {
            account: acct.id(),
            signing: &home.point,
            agreement: &agreement,
            label: "Home",
            kind: "server",
            terms: json!({"serves": ["home"]}),
            created: &format_date(acct.now_ms()),
            custody: None,
            operator: None,
            endpoints: Some(vec![format!("https://home-{n}.example")]),
        })
        .unwrap();
        let req = finish_request(&prepared, &home.sign(prepared.step().body())).unwrap();
        appoint.push(json!({"request": b64(&req.raw), "terms": {"serves": ["home"]}}));
    }
    let change = Change::homes(json!({"appoint": appoint}));
    let action = acct
        .begin_transition(&change, &[ctl.clone(), f.passkey_id.clone()], TransitionRule::Control)
        .unwrap();
    run(&mut acct, host, action);
    assert_eq!(acct.record_due().unwrap().len(), 1);
    assert_eq!(acct.swift_succession().unwrap().stage, MoveStage::Waiting);
    (acct, f, ctl)
}


fn receipt(keys: &HomeKeys, account: &str, object: &str, received: i64) -> Vec<u8> {
    let body = canonical(&json!({"protocol": "colophon/receipt/5", "account": account, "object": object,
        "received": format_date(received), "by": keys.id})).unwrap();
    canonical(&json!({"body": STANDARD.encode(&body), "signature": STANDARD.encode(keys.sign(&body).signature)})).unwrap()
}
fn head(keys: &HomeKeys, account: &str, seq: u64, d: &str, issued: i64) -> Vec<u8> {
    let body = canonical(&json!({"protocol": "colophon/head/5", "account": account,
        "authority": {"seq": seq, "digest": d}, "issued": format_date(issued), "by": keys.id})).unwrap();
    canonical(&json!({"body": STANDARD.encode(&body), "signature": STANDARD.encode(keys.sign(&body).signature)})).unwrap()
}
fn give(a: &mut Account, o: Objects, at: i64) {
    a.merge(Incoming { objects: o, records: vec![] }, at).unwrap();
}

#[test]
fn a_genesis_receipt_by_a_window_home_counts_after_that_home_is_revoked() {
    let (ka, kb) = (HomeKeys::new(0x79), HomeKeys::new(0x7b));
    let mut host = Host::new();
    let (mut acct, f, ctl) = successor(&mut host, &[&ka, &kb]);
    let account = acct.id().as_str().to_string();
    let status = acct.swift_succession().unwrap().status;
    let t = status.timing.clone().unwrap();
    assert!(t.homes.contains(&kb.id), "B is a home of the window's entry");
    // A receipts the genesis inside the window (it is held by the account and by A).
    let ra = receipt(&ka, &account, &status.genesis_digest, t.window_start_ms + 20 * SEC);
    give(&mut acct, Objects { pending: vec![ra.clone()], ..Objects::default() }, t.window_start_ms + 20 * SEC);
    // B is revoked by every key (a full set, the stronger authority: B is no witness of it).
    let at = t.window_start_ms + 3_600 * SEC;
    acct.advance(at).unwrap();
    let action = acct
        .begin_transition(&Change::homes(json!({"revoke": [kb.id]})), &[ctl.clone(), f.passkey_id.clone(), f.security_id.clone()], TransitionRule::Control)
        .unwrap();
    let tr = run(&mut acct, &host, action).pending[0].clone();
    let td = swift::body_digest(&tr);
    give(&mut acct, Objects { pending: vec![receipt(&ka, &account, &td, at + SEC)], ..Objects::default() }, at + SEC);
    acct.advance(at + 2 * SEC).unwrap();
    assert!(!acct.record_due().unwrap().is_empty(), "the revocation activates");
    let (seq, d) = acct.head();
    give(&mut acct, Objects { heads: vec![head(&ka, &account, seq, &d, at + 3 * SEC)], ..Objects::default() }, at + 3 * SEC);
    acct.advance(at + 4 * SEC).unwrap();
    let _ = acct.record_due().unwrap();
    assert!(!acct.homes().iter().any(|h| h.id == kb.id), "B's revocation is final: {:?}", acct.homes());
    // Home A, holding that history, gets B's receipt of the genesis, made inside the window.
    let now = at + 10 * SEC;
    let objects = acct.objects().clone();
    let a = HomeState::new(ka.id.clone(), &objects, vec![ServingInterval { from_ms: t.window_start_ms, through_ms: None }], now).unwrap();
    let rb = receipt(&kb, &account, &status.genesis_digest, t.window_start_ms + 40 * SEC);
    let r = admit(&a, &rb, &format_date(now));
    assert_eq!(r.result, Ok(()), "a window home's receipt stays valid after its revocation");
    assert!(r.state.succession_receipts().contains(&rb));
}
