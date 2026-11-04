#![allow(clippy::unwrap_used)]
mod support;
use colophon_core::{
    authority::Action,
    crypto::SoftwareKeys,
    library::Library,
    model::*,
    records::{canonical, SignedRecord},
};
use serde_json::{json, Value};
use support::*;

fn resign(raw: &[u8], signer: &SoftwareKeys, mutate: impl FnOnce(&mut Value)) -> Vec<u8> {
    let record: SignedRecord = serde_json::from_slice(raw).unwrap();
    let mut body: Value = serde_json::from_slice(&record.body).unwrap();
    mutate(&mut body);
    let body = canonical(&body).unwrap();
    let signature = signer.sign(&body);
    SignedRecord::finish_sign(body, signature, &signer.public().signing)
        .unwrap()
        .encode()
        .unwrap()
}
#[test]
fn authority_failures_are_atomic_and_fail_closed() {
    let (mut root, owner, _) = create();
    let before = root.records().clone();
    let pending = success(root.begin_rekey(&["notes".into()], NOW, [40; 32]).unwrap());
    let records = finish(pending, &owner);
    let (path, raw) = records.iter().next().unwrap();
    for mutation in ["previous", "kind", "by"] {
        let bad = resign(raw, &owner, |v| v[mutation] = json!("unknown"));
        assert!(root.merge(Records::from([(path.clone(), bad)])).is_err());
        assert_eq!(root.records(), &before);
    }
    let mut signature: SignedRecord = serde_json::from_slice(raw).unwrap();
    signature.signature[0] ^= 1;
    assert!(root
        .merge(Records::from([(path.clone(), signature.encode().unwrap())]))
        .is_err());
    assert_eq!(root.records(), &before);
    let wrong_path = Records::from([("authority/00000004.json".into(), raw.clone())]);
    assert!(root.merge(wrong_path).is_err());
    root.merge(records.clone()).unwrap();
    root.merge(records.clone()).unwrap();
    assert_eq!(root.authority().latest, 3);
    assert!(root
        .merge(Records::from([(
            path.clone(),
            resign(raw, &owner, |v| v["issued"] = json!(LATER))
        )]))
        .is_err());
}
#[test]
fn revoke_cannot_omit_recovery_or_keep_revoked_recipient() {
    let (mut root, owner, recovery) = create();
    let agent = keys(4);
    enroll(
        &mut root,
        &owner,
        &agent,
        "Agent",
        MemberKind::Agent,
        grant(&["notes", "reading.saved"], None),
        41,
    );
    let pending = success(
        root.begin_revoke(&agent.public().id(), NOW, [42; 32])
            .unwrap(),
    );
    let records = finish(pending, &owner);
    let (path, raw) = records.iter().next().unwrap();
    for which in 0..3 {
        let bad = resign(raw, &owner, |v| match which {
            0 => {
                v["epochs"][0]["seals"]
                    .as_object_mut()
                    .unwrap()
                    .remove(&recovery.public().id());
            }
            1 => {
                let seal = v["epochs"][0]["seals"][owner.public().id()].clone();
                v["epochs"][0]["seals"][agent.public().id()] = seal;
            }
            _ => {
                v["epochs"].as_array_mut().unwrap().pop();
            }
        });
        assert!(root.merge(Records::from([(path.clone(), bad)])).is_err());
    }
    root.merge(records).unwrap();
    for ns in ["notes", "reading.saved"] {
        assert!(!root.authority().epochs[ns][&2]
            .1
            .seals
            .contains_key(&agent.public().id()));
        assert!(root.authority().epochs[ns][&2]
            .1
            .seals
            .contains_key(&recovery.public().id()));
    }
}
#[test]
fn handover_reshares_before_authority_and_requires_all_keys() {
    let (mut root, owner, _) = create();
    write(
        &mut root,
        &owner,
        "notes",
        "createNotebook",
        json!({"id":"book","title":"Book"}),
        43,
    );
    let target = keys(8);
    let locked = Library::open(root.records().clone(), owner.public()).unwrap();
    assert!(locked
        .begin_handover(target.public(), "Next".into(), NOW, [44; 32])
        .is_err());
    let pending = success(
        root.begin_handover(target.public(), "Next".into(), NOW, [44; 32])
            .unwrap(),
    );
    assert_eq!(pending.steps.len(), 2);
    let first: Value = serde_json::from_slice(&pending.steps[0].body).unwrap();
    let second: Value = serde_json::from_slice(&pending.steps[1].body).unwrap();
    assert_eq!(first["kind"], "reshare");
    assert_eq!(second["kind"], "handover");
    apply(&mut root, pending, &owner);
    for epochs in root.authority().epochs.values() {
        let epoch = &epochs.last_key_value().unwrap().1 .1;
        assert!(!epoch.seals.contains_key(&owner.public().id()));
        assert!(epoch.seals.contains_key(&target.public().id()));
    }
    let mut next = opened(root.records().clone(), &target);
    assert_eq!(
        success(next.view("notes", NOW).unwrap()).state["notebooks"][0]["title"],
        "Book"
    );
    write(
        &mut next,
        &target,
        "notes",
        "addNote",
        json!({"id":"note","notebook":"book","text":"Recovered data"}),
        45,
    );
    root.merge(next.records().clone()).unwrap();
    assert!(
        matches!(root.begin_write("notes","addNote",json!({}),NOW,[46;32]).unwrap(),Outcome::Failure {reason,..} if reason == "revoked")
    );
    assert!(matches!(
        next.authority().entries[next.authority().entries.len() - 2].action,
        Action::Reshare { .. }
    ));
}
#[test]
fn expiry_budget_and_future_authority_admission() {
    let (mut root, owner, _) = create();
    let app = keys(3);
    let mut scope = grant(&["notes", "reading.saved"], Some(1));
    scope.expires = Some("2026-11-04T12:00:00Z".into());
    enroll(&mut root, &owner, &app, "App", MemberKind::App, scope, 47);
    let mut app_lib = opened(root.records().clone(), &app);
    write(
        &mut app_lib,
        &app,
        "reading.saved",
        "capture",
        json!({"id":"link","url":"https://example.org/"}),
        48,
    );
    assert!(
        matches!(app_lib.begin_write("notes","createNotebook",json!({"id":"b","title":"B"}),NOW,[49;32]).unwrap(),Outcome::Failure {reason,..} if reason == "budgetSpent")
    );
    assert!(
        matches!(app_lib.view("notes",LATER).unwrap(),Outcome::Failure {reason,..} if reason == "expired")
    );
    root.merge(app_lib.records().clone()).unwrap();
    let at = root.authority().latest;
    let future = adversarial(
        &root,
        &owner,
        &app,
        "notes",
        op(
            "createNotebook",
            9,
            at + 1,
            json!({"id":"future","title":"Future"}),
        ),
        1,
        50,
    );
    root.merge(future).unwrap();
    assert_eq!(
        success(root.view("notes", NOW).unwrap()).held[0].reason,
        "authorityBehind"
    );
    let over = adversarial(
        &root,
        &owner,
        &app,
        "notes",
        op("createNotebook", 8, at, json!({"id":"over","title":"Over"})),
        1,
        51,
    );
    root.merge(over).unwrap();
    assert!(success(root.view("notes", NOW).unwrap())
        .refused
        .iter()
        .any(|r| r.reason == "budgetSpent"));
    let mut expired_op = op(
        "createNotebook",
        10,
        at,
        json!({"id":"expired","title":"Expired"}),
    );
    expired_op.created = LATER.into();
    root.merge(adversarial(&root, &owner, &app, "notes", expired_op, 1, 52))
        .unwrap();
    assert!(success(root.view("notes", NOW).unwrap())
        .refused
        .iter()
        .any(|r| r.reason == "expired"));
    let rekey = success(
        root.begin_rekey(&["notes".into()], LATER, [53; 32])
            .unwrap(),
    );
    apply(&mut root, rekey, &owner);
    assert!(!root.authority().epochs["notes"][&2]
        .1
        .seals
        .contains_key(&app.public().id()));
}
#[test]
fn signed_payload_binding_and_wrong_epochs_are_refused() {
    let (mut root, owner, _) = create();
    write(
        &mut root,
        &owner,
        "notes",
        "createNotebook",
        json!({"id":"book","title":"Book"}),
        54,
    );
    let at = root.authority().latest;
    let mut op = op(
        "addNote",
        3,
        at,
        json!({"id":"n","notebook":"book","text":"Text"}),
    );
    let rekey = success(root.begin_rekey(&["notes".into()], NOW, [55; 32]).unwrap());
    apply(&mut root, rekey, &owner);
    op.authority = root.authority().latest;
    root.merge(adversarial(&root, &owner, &owner, "notes", op, 1, 56))
        .unwrap();
    assert!(success(root.view("notes", NOW).unwrap())
        .refused
        .iter()
        .any(|r| r.reason == "wrongEpoch"));
    let pending = success(
        root.begin_write(
            "notes",
            "addNote",
            json!({"id":"good","notebook":"book","text":"Good"}),
            NOW,
            [57; 32],
        )
        .unwrap(),
    );
    let records = finish(pending, &owner);
    let (path, raw) = records.iter().next().unwrap();
    let bad = resign(raw, &owner, |v| v["created"] = json!(LATER));
    root.merge(Records::from([(path.clone(), bad)])).unwrap();
    let view = success(root.view("notes", NOW).unwrap());
    assert!(view.refused.iter().any(|r| r.reason == "invalidPayload"));
    assert_eq!(view.state["notes"].as_array().unwrap().len(), 0);
}
#[test]
fn requests_are_library_bound_and_grants_cannot_expand_or_add_unknown_caveats() {
    let (root, owner, _) = create();
    let app = keys(3);
    let raw = request(&root, &app, "App", MemberKind::App, vec!["notes".into()]);
    assert!(Library::finish_request(raw.clone(), "another-library").is_err());
    assert!(root
        .begin_approve(
            raw.clone(),
            Some(grant(&["reading.saved"], None)),
            NOW,
            [58; 32]
        )
        .is_err());
    let pending = success(
        root.begin_approve(raw, Some(grant(&["notes"], None)), NOW, [59; 32])
            .unwrap(),
    );
    let records = finish(pending, &owner);
    let (path, raw) = records.iter().next().unwrap();
    let bad = resign(raw, &owner, |v| {
        v["grant"]["unknownRestriction"] = json!(true)
    });
    let mut root = root;
    assert!(root.merge(Records::from([(path.clone(), bad)])).is_err());
}
#[test]
fn ordering_ignores_dates_unknown_kinds_skip_unknown_fields_survive() {
    let (mut root, owner, _) = create();
    let at = root.authority().latest;
    let mut early_clock = op(
        "createNotebook",
        1,
        at,
        json!({"id":"book","title":"Book","extension":{"future":42}}),
    );
    early_clock.created = LATER.into();
    root.merge(adversarial(
        &root,
        &owner,
        &owner,
        "notes",
        early_clock,
        1,
        60,
    ))
    .unwrap();
    let later_clock = op(
        "addNote",
        2,
        at,
        json!({"id":"n","notebook":"book","text":"Text","origin":"ai","future":"keep"}),
    );
    root.merge(adversarial(
        &root,
        &owner,
        &owner,
        "notes",
        later_clock,
        1,
        61,
    ))
    .unwrap();
    write(
        &mut root,
        &owner,
        "notes",
        "futureOperation",
        json!({"id":"unknown"}),
        62,
    );
    let before = success(root.view("notes", NOW).unwrap());
    assert_eq!(
        before.admitted.iter().map(|o| o.clock).collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert_eq!(
        before.state["notebooks"][0]["extensions"]["extension"]["future"],
        42
    );
    assert_eq!(before.state["notes"][0]["origin"], "person");
    write(
        &mut root,
        &owner,
        "notes",
        "editNote",
        json!({"id":"n","notebook":"book","text":"Edit"}),
        63,
    );
    let view = success(root.view("notes", NOW).unwrap());
    assert_eq!(view.state["notes"][0]["extensions"]["future"], "keep");
    write(
        &mut root,
        &owner,
        "notes",
        "editNote",
        json!({"id":"n","notebook":"book","text":"Stale","expect":"wrong"}),
        64,
    );
    let view = success(root.view("notes", NOW).unwrap());
    assert_eq!(view.state["notes"][0]["text"], "Edit");
    assert_eq!(view.state["conflicts"].as_array().unwrap().len(), 1);
}
#[test]
fn dates_and_untrusted_lengths_never_panic() {
    for s in [
        "",
        "x",
        "2026-99-01T00:00:00Z",
        "2025-02-29T00:00:00Z",
        "2026-01-01T00:00:00+01:00",
        "2026-01-01T00:00:00.12Z",
        "🌻🌻🌻🌻🌻",
    ] {
        assert!(time_key(s).is_err());
    }
    assert_eq!(
        time_key("2024-02-29T12:00:00Z").unwrap(),
        time_key("2024-02-29T12:00:00.000Z").unwrap()
    );
    let (mut root, _, _) = create();
    root.merge(Records::from([("ops/invalid.json".into(), vec![0xff])]))
        .unwrap();
    assert!(root.ledger().iter().any(|e| e.event == "refused"));
}

#[test]
fn domain_tombstones_progress_queue_and_notebook_boundaries() {
    let (mut root, owner, _) = create();
    write(
        &mut root,
        &owner,
        "reading.saved",
        "capture",
        json!({"id":"saved","url":"https://example.org/"}),
        65,
    );
    write(
        &mut root,
        &owner,
        "reading.saved",
        "delete",
        json!({"id":"saved"}),
        66,
    );
    write(
        &mut root,
        &owner,
        "reading.saved",
        "editMetadata",
        json!({"id":"saved","title":"Cannot resurrect"}),
        67,
    );
    let shelf = success(root.view("reading.saved", NOW).unwrap());
    assert_eq!(shelf.state["items"][0]["deleted"], true);
    assert_eq!(shelf.state["conflicts"].as_array().unwrap().len(), 1);
    write(
        &mut root,
        &owner,
        "listening.podcasts",
        "follow",
        json!({"id":"show","url":"https://example.org/feed"}),
        68,
    );
    write(
        &mut root,
        &owner,
        "listening.podcasts",
        "unfollow",
        json!({"id":"show"}),
        69,
    );
    write(
        &mut root,
        &owner,
        "listening.podcasts",
        "position",
        json!({"id":"e","seconds":100}),
        70,
    );
    write(
        &mut root,
        &owner,
        "listening.podcasts",
        "position",
        json!({"id":"e","seconds":20}),
        71,
    );
    assert_eq!(
        success(root.view("listening.podcasts", NOW).unwrap()).state["episodes"][0]["seconds"],
        100
    );
    write(
        &mut root,
        &owner,
        "listening.podcasts",
        "position",
        json!({"id":"e","seconds":20,"seek":true}),
        72,
    );
    write(
        &mut root,
        &owner,
        "listening.podcasts",
        "queue",
        json!({"episodes":["e"]}),
        73,
    );
    write(
        &mut root,
        &owner,
        "listening.podcasts",
        "queue",
        json!({"episodes":[],"expect":"stale"}),
        74,
    );
    let podcasts = success(root.view("listening.podcasts", NOW).unwrap());
    assert_eq!(podcasts.state["episodes"][0]["seconds"], 20);
    assert_eq!(podcasts.state["shows"][0]["followed"], false);
    assert_eq!(podcasts.state["queue"]["episodes"], json!(["e"]));
    assert_eq!(podcasts.state["conflicts"].as_array().unwrap().len(), 1);
    write(
        &mut root,
        &owner,
        "notes",
        "createNotebook",
        json!({"id":"a","title":"A"}),
        75,
    );
    write(
        &mut root,
        &owner,
        "notes",
        "createNotebook",
        json!({"id":"b","title":"B"}),
        76,
    );
    write(
        &mut root,
        &owner,
        "notes",
        "addNote",
        json!({"id":"n","notebook":"a","text":"Original"}),
        77,
    );
    write(
        &mut root,
        &owner,
        "notes",
        "editNote",
        json!({"id":"n","notebook":"b","text":"Foreign"}),
        78,
    );
    let notes = success(root.view("notes", NOW).unwrap());
    assert_eq!(notes.state["notes"][0]["text"], "Original");
    assert_eq!(notes.state["invalid"].as_array().unwrap().len(), 1);
    assert!(root
        .begin_call(
            "listening.podcasts__queue",
            json!({"episodes":[1]}),
            NOW,
            [79; 32]
        )
        .is_err());
}

#[test]
fn hostile_headers_cannot_poison_write_clocks() {
    let (mut root, owner, _) = create();
    let agent = keys(4);
    enroll(
        &mut root,
        &owner,
        &agent,
        "Agent",
        MemberKind::Agent,
        grant(&["notes"], None),
        80,
    );
    let revoke = success(
        root.begin_revoke(&agent.public().id(), NOW, [81; 32])
            .unwrap(),
    );
    apply(&mut root, revoke, &owner);
    for (ns, signer, authority, clock, reason) in [
        (
            "reading.saved",
            &agent,
            9_007_199_254_740_991,
            9_007_199_254_740_991,
            "notGranted",
        ),
        (
            "notes",
            &agent,
            9_007_199_254_740_991,
            9_007_199_254_740_991,
            "revoked",
        ),
        (
            "reading.saved",
            &owner,
            root.authority().latest,
            9_007_199_254_740_991,
            "clockJump",
        ),
    ] {
        let records = adversarial(
            &root,
            &owner,
            signer,
            ns,
            op("future", clock, authority, json!({})),
            1,
            82,
        );
        root.merge(records).unwrap();
        assert!(success(root.view(ns, NOW).unwrap())
            .refused
            .iter()
            .any(|r| r.reason == reason));
    }
    // Even an otherwise eligible future header or an invalid payload cannot move the clock.
    for (authority, seed) in [
        (root.authority().latest + 1, 83),
        (root.authority().latest, 84),
    ] {
        let records = adversarial(
            &root,
            &owner,
            &owner,
            "reading.saved",
            op("future", 100, authority, json!({})),
            1,
            seed,
        );
        let (path, raw) = records.into_iter().next().unwrap();
        let bad = resign(&raw, &owner, |v| {
            v["ciphertext"] = json!("AAAAAAAAAAAAAAAAAAAAAA==")
        });
        root.merge(Records::from([(path, bad)])).unwrap();
    }
    write(
        &mut root,
        &owner,
        "reading.saved",
        "capture",
        json!({"id":"ok","url":"https://example.org"}),
        85,
    );
    let view = success(root.view("reading.saved", NOW).unwrap());
    assert_eq!(view.admitted.len(), 1);
    assert_eq!(view.admitted[0].clock, 1);
}

#[test]
fn invalid_duplicate_cannot_remove_a_valid_or_kept_operation() {
    let (mut root, owner, _) = create();
    let agent = keys(4);
    enroll(
        &mut root,
        &owner,
        &agent,
        "Agent",
        MemberKind::Agent,
        grant(&["notes"], Some(1)),
        86,
    );
    let mut replica = opened(root.records().clone(), &agent);
    // Clock 2 leaves room for an invalid competitor to sort before the valid record.
    let original = adversarial(
        &root,
        &owner,
        &agent,
        "notes",
        op(
            "createNotebook",
            2,
            root.authority().latest,
            json!({"id":"book","title":"Book"}),
        ),
        1,
        87,
    );
    replica.merge(original.clone()).unwrap();
    root.merge(original.clone()).unwrap();
    let raw = original.values().next().unwrap();
    for clock in [1, 3] {
        let bad = resign(raw, &agent, |v| v["clock"] = json!(clock));
        let signed: SignedRecord = serde_json::from_slice(&bad).unwrap();
        let header: OperationHeader = serde_json::from_slice(&signed.body).unwrap();
        root.merge(Records::from([(
            colophon_core::library::operation_path(&header.meta),
            bad,
        )]))
        .unwrap();
    }
    assert_eq!(success(root.view("notes", NOW).unwrap()).admitted.len(), 1);
    let revoke = success(
        root.begin_revoke(&agent.public().id(), NOW, [88; 32])
            .unwrap(),
    );
    apply(&mut root, revoke, &owner);
    let body: SignedRecord = serde_json::from_slice(raw).unwrap();
    assert!(root.authority().members[&agent.public().id()]
        .kept
        .contains(&colophon_core::records::digest(&body.body)));
    let bad = resign(raw, &agent, |v| {
        v["clock"] = json!(4);
        v["authority"] = json!(9_007_199_254_740_991u64);
    });
    let signed: SignedRecord = serde_json::from_slice(&bad).unwrap();
    let header: OperationHeader = serde_json::from_slice(&signed.body).unwrap();
    root.merge(Records::from([(
        colophon_core::library::operation_path(&header.meta),
        bad,
    )]))
    .unwrap();
    let view = success(root.view("notes", NOW).unwrap());
    assert_eq!(view.admitted.len(), 1);
    assert_eq!(view.state["notebooks"][0]["title"], "Book");
    assert!(view.refused.iter().any(|r| r.reason == "revoked"));
    assert_eq!(
        json!(view),
        json!(success(
            opened(root.records().clone(), &owner)
                .view("notes", NOW)
                .unwrap()
        ))
    );
}

#[test]
fn fractional_payloads_keep_their_ids_through_write_and_replay() {
    assert_eq!(
        String::from_utf8(
            canonical(&json!([
                1,
                1.0,
                -0.0,
                1e-6,
                1e-5,
                6.713554789312184e-10,
                123456789.12345679
            ]))
            .unwrap()
        )
        .unwrap(),
        "[1,1.0,-0.0,1e-6,0.00001,6.713554789312184e-10,123456789.12345679]"
    );
    let (mut root, owner, _) = create();
    for (i, seconds) in [6.713554789312184e-10_f64, 123456789.12345679]
        .into_iter()
        .enumerate()
    {
        write(
            &mut root,
            &owner,
            "listening.podcasts",
            "position",
            json!({"id":format!("e{i}"),"seconds":seconds}),
            90 + i as u8,
        );
        let view = success(root.view("listening.podcasts", NOW).unwrap());
        assert_eq!(view.admitted.len(), i + 1);
        assert_eq!(
            view.admitted[i].payload["seconds"]
                .as_f64()
                .unwrap()
                .to_bits(),
            seconds.to_bits()
        );
        let replay = success(
            opened(root.records().clone(), &owner)
                .view("listening.podcasts", NOW)
                .unwrap(),
        );
        assert_eq!(json!(view), json!(replay));
    }
}

#[test]
fn extensions_cannot_mutate_controlled_domain_fields() {
    let (mut root, owner, _) = create();
    write(
        &mut root,
        &owner,
        "listening.podcasts",
        "position",
        json!({"id":"e","seconds":100}),
        92,
    );
    let before =
        success(root.view("listening.podcasts", NOW).unwrap()).state["episodes"][0].clone();
    write(
        &mut root,
        &owner,
        "listening.podcasts",
        "episode",
        json!({"id":"e","title":"Title","seconds":0,"positionRevision":"fake","revision":"fake","extensions":{"seconds":-1}}),
        93,
    );
    let view = success(root.view("listening.podcasts", NOW).unwrap());
    let episode = &view.state["episodes"][0];
    assert_eq!(episode["seconds"], 100);
    assert_eq!(episode["positionRevision"], before["positionRevision"]);
    assert_ne!(episode["revision"], "fake");
    assert_eq!(episode["extensions"]["seconds"], 0);
    assert_eq!(episode["extensions"]["positionRevision"], "fake");
    assert_eq!(episode["extensions"]["extensions"]["seconds"], -1);
    write(
        &mut root,
        &owner,
        "listening.podcasts",
        "position",
        json!({"id":"e","seconds":10,"expect":"fake"}),
        94,
    );
    assert_eq!(
        success(root.view("listening.podcasts", NOW).unwrap()).state["episodes"][0]["seconds"],
        100
    );
    write(
        &mut root,
        &owner,
        "reading.saved",
        "capture",
        json!({"id":"r","url":"https://example.org","deleted":true}),
        95,
    );
    write(
        &mut root,
        &owner,
        "reading.saved",
        "setState",
        json!({"id":"r","state":"read","url":"evil","deleted":true}),
        96,
    );
    let shelf = success(root.view("reading.saved", NOW).unwrap());
    assert_eq!(shelf.state["items"][0]["url"], "https://example.org");
    assert_eq!(shelf.state["items"][0]["state"], "read");
    assert!(shelf.state["items"][0]["deleted"].is_null());
    assert_eq!(shelf.state["items"][0]["extensions"]["deleted"], true);
    write(
        &mut root,
        &owner,
        "notes",
        "createNotebook",
        json!({"id":"b","title":"B","text":"not a note","origin":"ai"}),
        97,
    );
    write(
        &mut root,
        &owner,
        "notes",
        "addNote",
        json!({"id":"n","notebook":"b","text":"Text","title":"extension","author":"fake"}),
        98,
    );
    write(
        &mut root,
        &owner,
        "notes",
        "editNote",
        json!({"id":"n","notebook":"b","text":"Edited"}),
        99,
    );
    let notes = success(root.view("notes", NOW).unwrap());
    assert!(notes.state["notebooks"][0]["text"].is_null());
    assert_eq!(notes.state["notes"][0]["extensions"]["title"], "extension");
    assert_eq!(notes.state["notes"][0]["author"], owner.public().id());
}

#[test]
fn ledger_interleaves_authority_requests_and_writes_as_a_story() {
    let (mut root, owner, _) = create();
    write(
        &mut root,
        &owner,
        "notes",
        "createNotebook",
        json!({"id":"b","title":"B"}),
        100,
    );
    let before_id = success(root.view("notes", NOW).unwrap()).admitted[0]
        .id
        .clone();
    let agent = keys(4);
    enroll(
        &mut root,
        &owner,
        &agent,
        "Muse on MacBook",
        MemberKind::Agent,
        grant(&["notes"], None),
        101,
    );
    let at = root.authority().latest;
    let mut expected = Vec::new();
    for (signer, clock, created, seed) in [
        (&owner, 20, LATER, 102),
        (&agent, 21, NOW, 103),
        (&owner, 22, NOW, 104),
        (&agent, 23, "2026-11-04T12:00:00Z", 105),
    ] {
        let mut operation = op(
            "addNote",
            clock,
            at,
            json!({"id":format!("n{seed}"),"notebook":"b","text":"Text"}),
        );
        operation.created = created.into();
        let records = adversarial(&root, &owner, signer, "notes", operation, 1, seed);
        let record: SignedRecord =
            serde_json::from_slice(records.values().next().unwrap()).unwrap();
        let header: OperationHeader = serde_json::from_slice(&record.body).unwrap();
        expected.push((
            time_key(created).unwrap(),
            signer.public().id(),
            header.meta.id,
        ));
        root.merge(records).unwrap();
    }
    let revoke = success(
        root.begin_revoke(&agent.public().id(), LATER, [106; 32])
            .unwrap(),
    );
    apply(&mut root, revoke, &owner);
    let ledger = root.ledger();
    let index = |event: &str| ledger.iter().position(|e| e.event == event).unwrap();
    let before = ledger
        .iter()
        .position(|e| e.subject.as_ref() == Some(&before_id))
        .unwrap();
    assert!(before < index("requested"));
    assert!(index("requested") < index("granted"));
    expected.sort();
    let actual: Vec<_> = ledger[index("granted") + 1..index("revoked")]
        .iter()
        .filter(|e| e.event == "wrote")
        .map(|e| e.subject.clone().unwrap())
        .collect();
    assert_eq!(
        actual,
        expected
            .into_iter()
            .map(|(_, _, id)| id)
            .collect::<Vec<_>>()
    );
    for (i, entry) in ledger.iter().enumerate() {
        assert_eq!(entry.sequence, i as u64 + 1);
    }
    let mut replay = create().0;
    // Merge operation records before authority, then the complete verified history.
    replay
        .merge(
            root.records()
                .iter()
                .filter(|(p, _)| p.starts_with("ops/"))
                .map(|(p, r)| (p.clone(), r.clone()))
                .collect(),
        )
        .unwrap();
    replay.merge(root.records().clone()).unwrap();
    unlock(&mut replay, &owner);
    assert_eq!(replay.ledger(), ledger);
}

#[test]
fn ledger_uses_module_language_and_one_rekey_summary() {
    let (mut root, owner, _) = create();
    let agent = keys(4);
    let request = request(
        &root,
        &agent,
        "Muse on MacBook",
        MemberKind::Agent,
        vec!["listening.podcasts".into(), "notes".into()],
    );
    let approve = success(
        root.begin_approve(
            request,
            Some(grant(&["listening.podcasts", "notes"], None)),
            NOW,
            [107; 32],
        )
        .unwrap(),
    );
    apply(&mut root, approve, &owner);
    write(
        &mut root,
        &owner,
        "notes",
        "createNotebook",
        json!({"id":"b","title":"B"}),
        108,
    );
    let mut muse = opened(root.records().clone(), &agent);
    for i in 0..3 {
        write(
            &mut muse,
            &agent,
            "notes",
            "addNote",
            json!({"id":format!("n{i}"),"notebook":"b","text":"Text"}),
            109 + i,
        );
    }
    write(
        &mut muse,
        &agent,
        "notes",
        "editNote",
        json!({"id":"n0","notebook":"b","text":"Edit"}),
        112,
    );
    root.merge(muse.records().clone()).unwrap();
    let revoke = success(
        root.begin_revoke(&agent.public().id(), NOW, [113; 32])
            .unwrap(),
    );
    apply(&mut root, revoke, &owner);
    let ledger = root.ledger();
    let texts: Vec<_> = ledger.iter().map(|e| e.text.as_str()).collect();
    assert_eq!(texts[0], "Owner created this library. Listening, notes and reading are sealed with keys only its members hold.");
    for expected in [
        "Muse on MacBook asked to read and write listening and notes.",
        "Owner let Muse on MacBook read and write listening and notes.",
        "Owner started a notebook.",
        "Muse on MacBook added a note.",
        "Muse on MacBook edited a note.",
        "Owner ended Muse on MacBook's access. Its 3 notes stay; what it already read can't be unread.",
        "Listening and notes were rekeyed without Muse on MacBook.",
    ] { assert!(texts.contains(&expected), "Missing: {expected}; got {texts:?}"); }
    assert_eq!(ledger.iter().filter(|e| e.event == "rekeyed").count(), 1);
    assert!(texts
        .iter()
        .all(|text| !text.contains("epoch") && !text.contains("listening.podcasts")));
    for (ns, kind, payload, phrase, seed) in [
        (
            "reading.saved",
            "capture",
            json!({"id":"l","url":"https://example.org"}),
            "saved a link",
            114,
        ),
        (
            "listening.podcasts",
            "follow",
            json!({"id":"s","url":"https://example.org"}),
            "followed a show",
            115,
        ),
        (
            "listening.podcasts",
            "episode",
            json!({"id":"e"}),
            "added an episode",
            116,
        ),
        (
            "listening.podcasts",
            "position",
            json!({"id":"e","seconds":1}),
            "updated playback",
            117,
        ),
    ] {
        write(&mut root, &owner, ns, kind, payload, seed);
        assert!(root
            .ledger()
            .iter()
            .any(|e| e.text == format!("Owner {phrase}.")));
    }
}

#[test]
fn ledger_write_metadata_supports_authenticated_ui_grouping() {
    let (mut root, owner, _) = create();
    write(
        &mut root,
        &owner,
        "reading.saved",
        "capture",
        json!({"id":"l","url":"https://example.org","origin":"ai"}),
        118,
    );
    let agent = keys(4);
    enroll(
        &mut root,
        &owner,
        &agent,
        "Muse",
        MemberKind::Agent,
        grant(&["notes"], None),
        119,
    );
    let mut muse = opened(root.records().clone(), &agent);
    write(
        &mut muse,
        &agent,
        "notes",
        "createNotebook",
        json!({"id":"b","title":"B","origin":"person"}),
        120,
    );
    root.merge(muse.records().clone()).unwrap();
    let ledger = json!(root.ledger());
    let entries = ledger.as_array().unwrap();
    for (actor, namespace, kind, origin) in [
        (owner.public().id(), "reading.saved", "capture", "person"),
        (agent.public().id(), "notes", "createNotebook", "ai"),
    ] {
        let entry = entries
            .iter()
            .find(|e| e["event"] == "wrote" && e["actor"] == actor)
            .unwrap();
        assert_eq!(entry["namespace"], namespace);
        assert_eq!(entry["kind"], kind);
        assert_eq!(entry["origin"], origin);
    }
    assert!(entries
        .iter()
        .filter(|e| e["event"] != "wrote")
        .all(|e| e.get("namespace").is_none() && e.get("kind").is_none()));
    // Readers without a namespace key can see signed attribution but never the encrypted kind.
    let locked = Library::open(root.records().clone(), owner.public()).unwrap();
    for entry in json!(locked.ledger())
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["event"] == "wrote")
    {
        assert!(entry.get("namespace").is_some());
        assert!(entry.get("kind").is_none());
        assert!(entry.get("origin").is_some());
    }
}
