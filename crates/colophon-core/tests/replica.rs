//! Multi-member grant, operation and revocation scenario using authority/4 fixtures.
#![allow(clippy::unwrap_used)]
mod support;
use colophon_core::model::*;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use support::*;
fn scenario() -> (Records, Value) {
    let (mut root, owner, _controller) = create();
    let device = keys(2);
    let app = keys(3);
    let agent = keys(4);
    enroll(
        &mut root,
        &owner,
        &device,
        "Laptop",
        MemberKind::Device,
        grant(&["reading.saved", "listening.podcasts", "notes"], None),
        11,
    );
    enroll(
        &mut root,
        &owner,
        &app,
        "Reader app",
        MemberKind::App,
        grant(&["reading.saved"], None),
        12,
    );
    enroll(
        &mut root,
        &owner,
        &agent,
        "Research agent",
        MemberKind::Agent,
        grant(&["notes"], Some(2)),
        13,
    );
    write(
        &mut root,
        &owner,
        "notes",
        "createNotebook",
        json!({"id":"inbox","title":"Inbox","futureField":{"kept":true}}),
        20,
    );
    let mut laptop = opened(root.records().clone(), &device);
    write(
        &mut laptop,
        &device,
        "listening.podcasts",
        "follow",
        json!({"id":"show","url":"https://example.org/feed.xml","title":"A podcast"}),
        21,
    );
    write(
        &mut laptop,
        &device,
        "listening.podcasts",
        "episode",
        json!({"id":"episode","show":"show","title":"An episode","transcriptExcerpt":"A short transcript excerpt."}),
        22,
    );
    write(
        &mut laptop,
        &device,
        "listening.podcasts",
        "position",
        json!({"id":"episode","seconds":42}),
        23,
    );
    write(
        &mut laptop,
        &device,
        "listening.podcasts",
        "queue",
        json!({"episodes":["episode"]}),
        24,
    );
    root.merge(laptop.records().clone()).unwrap();
    let mut reader = opened(root.records().clone(), &app);
    write(
        &mut reader,
        &app,
        "reading.saved",
        "capture",
        json!({"id":"link","url":"https://example.org/article","title":"Article","custom":"preserved"}),
        25,
    );
    write(
        &mut reader,
        &app,
        "reading.saved",
        "setState",
        json!({"id":"link","state":"reading"}),
        26,
    );
    write(
        &mut reader,
        &app,
        "reading.saved",
        "editMetadata",
        json!({"id":"link","title":"Edited title"}),
        27,
    );
    root.merge(reader.records().clone()).unwrap();
    let mut agent_lib = opened(root.records().clone(), &agent);
    write(
        &mut agent_lib,
        &agent,
        "notes",
        "addNote",
        json!({"id":"ai-note","notebook":"inbox","text":"An agent contribution","origin":"person"}),
        28,
    );
    write(
        &mut agent_lib,
        &agent,
        "notes",
        "editNote",
        json!({"id":"ai-note","notebook":"inbox","text":"An edited contribution"}),
        29,
    );
    root.merge(agent_lib.records().clone()).unwrap();
    let outside = agent_lib
        .begin_write(
            "reading.saved",
            "capture",
            json!({"id":"no","url":"https://example.org/"}),
            NOW,
            [30; 32],
        )
        .unwrap();
    assert!(matches!(outside,Outcome::Failure {ref reason,..} if reason == "notGranted"));
    let exhausted = agent_lib
        .begin_write(
            "notes",
            "addNote",
            json!({"id":"over","notebook":"inbox","text":"Over budget"}),
            NOW,
            [31; 32],
        )
        .unwrap();
    assert!(matches!(exhausted,Outcome::Failure {ref reason,..} if reason == "budgetSpent"));
    let at = root.authority().latest;
    let refused_outside = adversarial(
        &root,
        &owner,
        &agent,
        "reading.saved",
        op(
            "capture",
            50,
            at,
            json!({"id":"no","url":"https://example.org/"}),
        ),
        1,
        32,
    );
    let refused_budget = adversarial(
        &root,
        &owner,
        &agent,
        "notes",
        op(
            "addNote",
            51,
            at,
            json!({"id":"over","notebook":"inbox","text":"Over budget"}),
        ),
        1,
        33,
    );
    root.merge(refused_outside).unwrap();
    root.merge(refused_budget).unwrap();
    let before_revoke = success(root.view("notes", NOW).unwrap());
    assert!(before_revoke
        .refused
        .iter()
        .any(|r| r.reason == "budgetSpent"));
    // An offline operation only arrives after revocation. It must be held, even if backdated.
    let late = adversarial(
        &root,
        &owner,
        &agent,
        "notes",
        op(
            "addNote",
            52,
            at,
            json!({"id":"late","notebook":"inbox","text":"Backdated unseen write"}),
        ),
        1,
        34,
    );
    let revoke = success(
        root.begin_revoke(&agent.public().id(), LATER, [35; 32])
            .unwrap(),
    );
    apply(&mut root, revoke, &owner);
    root.merge(late).unwrap();
    let after = success(root.view("notes", LATER).unwrap());
    assert_eq!(after.admitted.len(), 3);
    assert_eq!(after.state["notes"][0]["origin"], "ai");
    assert!(after.held.iter().any(|r| r.reason == "revokedBackdated"));
    assert!(!root.authority().epochs["notes"][&2]
        .1
        .seals
        .contains_key(&agent.public().id()));
    agent_lib.merge(root.records().clone()).unwrap();
    assert!(
        matches!(agent_lib.begin_write("notes","addNote",json!({}),LATER,[36;32]).unwrap(),Outcome::Failure {reason,..} if reason == "revoked")
    );
    let rekey = success(
        root.begin_rekey(
            &["reading.saved".into(), "listening.podcasts".into()],
            LATER,
            [37; 32],
        )
        .unwrap(),
    );
    apply(&mut root, rekey, &owner);
    write(
        &mut root,
        &owner,
        "reading.saved",
        "capture",
        json!({"id":"after-rekey","url":"https://example.org/new"}),
        38,
    );
    let restored = root;
    let views: BTreeMap<_, _> = restored
        .authority()
        .namespaces
        .iter()
        .map(|n| (n.clone(), success(restored.view(n, LATER).unwrap())))
        .collect();
    assert_eq!(
        views["notes"].state["notes"][0]["text"],
        "An edited contribution"
    );
    assert_eq!(views["reading.saved"].admitted.len(), 4);
    let expected = json!({"libraryID":restored.id(),"views":views,"ledger":restored.ledger(),"members":restored.members(),"beforeRevokeNotes":before_revoke,"localRefusals":{"outsideGrant":"notGranted","budget":"budgetSpent","afterRevoke":"revoked"},"epochCount":restored.authority().epochs.values().map(|e| e.len()).sum::<usize>()});
    (restored.records().clone(), expected)
}

#[test]
fn deterministic_multi_member_replica_and_revocation_replay() {
    let (records, expected) = scenario();
    let (again, again_expected) = scenario();
    assert_eq!(records, again);
    assert_eq!(expected, again_expected);
    let lib = opened(records, &keys(1));
    assert_eq!(json!(lib.members()), expected["members"]);
    assert_eq!(json!(lib.ledger()), expected["ledger"]);
    for namespace in &lib.authority().namespaces {
        assert_eq!(
            json!(success(lib.view(namespace, LATER).unwrap())),
            expected["views"][namespace]
        );
    }
}
