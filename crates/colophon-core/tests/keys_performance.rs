//! Colophon 0.4 keys performance (Galley F2 budgets): WebAuthn verification under 1 ms (met), and
//! a 200-entry, 20-controller keyring history fold. Its 20 ms budget is NOT met: replay costs
//! ~55 ms on an M-series host, dominated by ~0.3 ms per pure-Rust P-256 verification at the
//! workspace's opt-level "s". That is a recorded deviation (Galley DEVIATIONS.md, D-F2-1); this
//! test guards against regression at 100 ms until faster verification lands.
//! Run explicitly: `cargo test --release -p colophon-core --test keys_performance -- --ignored --nocapture`.
#![allow(clippy::unwrap_used, clippy::expect_used)]
mod support;

use colophon_core::{
    authority::{Authority, Controller, Role},
    keys::{testing::SyntheticAuthenticator, verify_webauthn, KeyDescriptor},
    model::Outcome,
    slots::{OpeningInput, OpeningSecret},
};
use std::time::Instant;
use support::{keys, NOW};

const RP: &str = "id.luff.works";

#[test]
#[ignore = "performance budget; run explicitly in release"]
fn webauthn_verification_is_under_one_millisecond() {
    let auth = SyntheticAuthenticator::new().unwrap();
    let key = auth.descriptor(RP, None).unwrap();
    let body = br#"{"protocol":"colophon/authority/4","seq":2}"#;
    let signed = auth.assertion(body, RP, "https://id.luff.works", 0x05, true).unwrap();
    let runs = 2_000;
    let start = Instant::now();
    for _ in 0..runs {
        verify_webauthn(
            &key,
            body,
            &signed.signature,
            &signed.assertion.authenticator_data,
            &signed.assertion.client_data,
            true,
        )
        .unwrap();
    }
    let per = start.elapsed() / runs;
    println!("webauthn verify: {per:?} per signature");
    assert!(per.as_micros() < 1_000, "{per:?}");
}

#[test]
#[ignore = "performance budget; run explicitly in release"]
fn a_200_entry_keyring_history_fold_stays_within_the_recorded_deviation() {
    let (mut lib, member, owner) = support::create();
    // Twenty controllers: the owner plus nineteen raw approve controllers.
    for n in 0..19u8 {
        let k = keys(100 + n);
        let controller = Controller {
            key: KeyDescriptor::Raw {
                signing: k.public().signing,
                agreement: Some(k.public().agreement),
            },
            label: format!("Device {n}"),
            roles: vec![Role::Approve],
            verification: None,
        };
        let pending = lib
            .begin_add_controller(controller, None, &[owner.public().id()], NOW)
            .unwrap();
        support::apply(&mut lib, pending, &member);
    }
    // Open the vault through the owner's sealed slot, then rekey until the history has 200 entries.
    let owner_id = owner.public().id();
    let index = lib
        .authority()
        .keyring
        .slots
        .iter()
        .position(|s| s.controllers() == [owner_id.clone()])
        .unwrap();
    let enc = match lib.begin_unlock_slot(index).unwrap().as_slice() {
        [OpeningInput::Ecdh { enc, .. }] => enc.to_vec(),
        _ => panic!("owner slot is sealed"),
    };
    let shared = owner.agree(&enc).unwrap();
    lib.finish_unlock_slot(index, &[OpeningSecret::Ecdh(&shared)]).unwrap();
    let mut seed = 0u8;
    while lib.authority().latest < 200 {
        seed = seed.wrapping_add(1);
        match lib.begin_rekey(&["notes".into()], NOW, [seed; 32]).unwrap() {
            Outcome::Success { value, .. } => support::apply(&mut lib, value, &member),
            other => panic!("rekey refused: {other:?}"),
        }
    }
    assert_eq!(lib.authority().latest, 200);
    assert_eq!(lib.authority().keyring.controllers.len(), 20);
    let records = lib.records().clone();
    let _ = Authority::replay(&records).unwrap();
    let runs = 20u32;
    let start = Instant::now();
    for _ in 0..runs {
        let _ = Authority::replay(&records).unwrap();
    }
    let per = start.elapsed() / runs;
    println!("200-entry, 20-controller keyring replay: {per:?} (budget 20 ms, deviation D-F2-1)");
    assert!(per.as_millis() < 100, "regression beyond the recorded deviation: {per:?}");
}

#[test]
#[ignore = "performance breakdown; run explicitly in release"]
fn raw_p256_verification_cost() {
    let k = keys(7);
    let body = vec![7u8; 600];
    let sig = k.sign(&body);
    let runs = 2_000;
    let start = Instant::now();
    for _ in 0..runs {
        colophon_core::keys::verify_raw(&k.public().signing, &body, &sig).unwrap();
    }
    println!("raw P-256 verify: {:?} per signature", start.elapsed() / runs);
}
