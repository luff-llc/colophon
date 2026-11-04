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
    assert_eq!(before.state["notebooks"][0]["extension"]["future"], 42);
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
    assert_eq!(view.state["notes"][0]["future"], "keep");
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
