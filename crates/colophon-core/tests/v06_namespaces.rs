//! Post-genesis namespace replay, epoch sealing, member scope, and the engine fold.
#![allow(clippy::unwrap_used)]
#[path = "v05_engine_support/mod.rs"]
mod support;

use colophon_core::model::Outcome;
use colophon_core::v05::encoding::canonical;
use colophon_core::v05::records::{Level, RecordAuthority};
use colophon_core::v05::write::{envelope, Signature};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use support::*;

const LISTEN: &str = "listening.podcasts";
const SAVED: &str = "reading.saved";
const FOUNDRY: &str = "game.foundry";
const WORLD: &str = "app.acme.world";

#[test]
fn adding_namespaces_preserves_the_account_and_opens_the_fold_to_a_scoped_member() {
    let mut f = create(&[LISTEN, SAVED]);
    let src = MemSource::new();
    src.store_account(&f.account);
    let now = f.account.now_ms();
    let mut controller = controller_engine(&f, &f.host, &src, &f.d, now);
    let id = f.account.id().clone();
    let original_seq = f.account.head().0;
    let foreman = f.host.identity(91);
    let terms = terms_for(&[(FOUNDRY, "write")]);
    let request = request_for(
        &f,
        &f.host,
        &foreman,
        "AI Foreman",
        "agent",
        terms.clone(),
        now,
    );
    assert!(controller
        .account()
        .begin_approve(
            &request.raw,
            terms.clone(),
            std::slice::from_ref(&f.d),
            f.host.fresh(),
            paired_on(controller.account(), &request),
        )
        .is_err());

    let action = controller
        .account()
        .begin_add_namespaces(
            &[FOUNDRY.into(), WORLD.into()],
            std::slice::from_ref(&f.d),
            f.host.fresh(),
        )
        .unwrap();
    engine_finish(&mut controller, &f.host, &src, action);
    let auth = RecordAuthority::from_objects(controller.account().objects(), now).unwrap();
    assert_eq!(auth.account(), &id);
    assert_eq!(auth.namespaces(), [WORLD, FOUNDRY, LISTEN, SAVED]);
    assert_eq!(auth.epoch_at(FOUNDRY, original_seq), None);
    for ns in [FOUNDRY, WORLD] {
        assert_eq!(auth.epoch_at(ns, original_seq + 1), Some(1));
        assert_eq!(auth.sealed_to(ns, 1), BTreeSet::from([auth.vault().id()]));
    }
    assert_eq!(auth.latest_epoch(LISTEN), 1);
    assert_eq!(auth.latest_epoch(SAVED), 1);

    // Reopen through the original slot to prove the published vault seal opens after replay.
    let mut controller = controller_engine(&f, &f.host, &src, &f.d, now);
    let action = controller
        .account()
        .begin_approve(
            &request.raw,
            terms,
            std::slice::from_ref(&f.d),
            f.host.fresh(),
            paired_on(controller.account(), &request),
        )
        .unwrap();
    engine_finish(&mut controller, &f.host, &src, action);

    let mut member = member_engine(&f, &f.host, &src, &foreman, now);
    assert!(member.account().is_namespace_open(FOUNDRY));
    assert!(!member.account().is_namespace_open(SAVED));
    assert!(!member.account().is_namespace_open(WORLD));
    assert_eq!(
        member
            .account()
            .begin_add_namespaces(&["game.other".into()], &[foreman], f.host.fresh())
            .err()
            .unwrap()
            .code(),
        "badSignature"
    );
    let saved_write = member.begin_write(SAVED, "save", json!({}), Level::Write, f.host.fresh());
    assert_eq!(saved_write.unwrap().err().unwrap().reason, "notGranted");
    let payload = json!({"machine": "smelter"});
    let written = engine_write(
        &mut member,
        &mut f.host,
        &src,
        FOUNDRY,
        "machine.place",
        payload.clone(),
    );
    let (_, bytes) = &written.stores[0];
    assert!(!String::from_utf8_lossy(bytes).contains("smelter"));
    let controller = controller_engine(&f, &f.host, &src, &f.d, now);
    for engine in [&member, &controller] {
        let Outcome::Success { value, .. } = engine.view(FOUNDRY).unwrap() else {
            panic!("Foundry is unreadable");
        };
        assert_eq!(value.admitted.len(), 1);
        assert_eq!(value.admitted[0].kind, "machine.place");
        assert_eq!(value.admitted[0].payload, payload);
    }
}

#[test]
fn preparation_and_replay_refuse_duplicate_names_and_unauthorized_signers() {
    let mut f = create(&[LISTEN, SAVED]);
    let controller = std::slice::from_ref(&f.d);
    let now = f.account.now_ms();
    for names in [vec![SAVED.into()], vec![FOUNDRY.into(), FOUNDRY.into()]] {
        assert_eq!(
            f.account
                .begin_add_namespaces(&names, controller, f.host.fresh())
                .err()
                .unwrap()
                .code(),
            "malformed",
        );
    }
    assert_eq!(
        f.account
            .begin_add_namespaces(
                &[FOUNDRY.into()],
                std::slice::from_ref(&f.k),
                f.host.fresh(),
            )
            .err()
            .unwrap()
            .code(),
        "badSignature",
    );
    let action = f
        .account
        .begin_add_namespaces(&[FOUNDRY.into()], controller, f.host.fresh())
        .unwrap();
    let entry: Value = serde_json::from_slice(action.steps()[0].body()).unwrap();
    let before = f.account.objects().clone();
    run(&mut f.account, &f.host, action);
    let (seq, previous) = f.account.head();
    let mut duplicate = entry.clone();
    duplicate["seq"] = json!(seq + 1);
    duplicate["previous"] = json!(previous);
    let mut wrong_epoch = entry.clone();
    wrong_epoch["epochs"][0]["epoch"] = json!(2);
    let mut missing_seal = entry.clone();
    missing_seal["epochs"][0]["seals"] = json!({});

    for (objects, mut body, signer, expected) in [
        (f.account.objects(), duplicate, &f.d, "malformed"),
        (&before, wrong_epoch, &f.d, "malformed"),
        (&before, missing_seal, &f.d, "malformed"),
        (&before, entry, &f.k, "badSignature"),
    ] {
        body["by"] = json!(signer);
        let body = canonical(&body).unwrap();
        let signature = Signature {
            signer: signer.clone(),
            signature: f.host.ids[signer].sign(&body).to_vec(),
            assertion: None,
        };
        let mut objects = objects.clone();
        objects
            .entries
            .push(envelope(&body, Some(&signature), &[], &[], &[]).unwrap());
        assert_eq!(
            RecordAuthority::from_objects(&objects, now)
                .err()
                .unwrap()
                .code(),
            expected
        );
    }
}
