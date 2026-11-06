#![allow(clippy::unwrap_used)]
mod support;
use base64::{engine::general_purpose::STANDARD, Engine};
use colophon_core::{
    domain::{ListeningPodcasts, Notes, ReadingSaved, Reducer},
    engine::CheckpointPolicy,
    library::Library,
    model::{MemberKind, OperationView, Records},
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use support::*;

fn equal_rebuild(lib: &Library) {
    let rebuilt = opened(lib.records().clone(), &keys(1));
    for ns in lib.authority().namespaces.clone() {
        let current = success(lib.view(&ns, NOW).unwrap());
        assert_eq!(
            json!(current),
            json!(success(rebuilt.view(&ns, NOW).unwrap()))
        );
        if let Some(module) = colophon_core::domain::module(&ns) {
            assert_eq!(current.state, module.fold(&current.admitted));
        }
    }
    assert_eq!(json!(lib.members()), json!(rebuilt.members()));
}

fn rng(seed: &mut u64) -> u64 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed
}
fn check_reducer<M: Reducer>(module: M, operations: &[OperationView]) {
    let mut state = M::State::default();
    for (i, operation) in operations.iter().enumerate() {
        module.apply(&mut state, operation);
        assert_eq!(
            module.query(&state, "read", &json!({})).unwrap(),
            module.fold(&operations[..=i])
        );
    }
    // Serialization round-trips must retain exactly the reducer state, including alternatives.
    let restored: M::State = serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
    assert_eq!(
        module.query(&restored, "read", &json!({})).unwrap(),
        module.fold(operations)
    );
}
#[test]
fn reducers_match_replay_for_fixed_seed_random_orders() {
    let mut seed = 0xabad1dea_u64;
    let mut operations = Vec::new();
    for i in 0..80 {
        let id = format!("object{}", rng(&mut seed) % 8);
        let (kind, payload) = match rng(&mut seed) % 14 {
            0 => (
                "capture",
                json!({"id":id,"url":"https://example.org","unknown":i}),
            ),
            1 => ("setState", json!({"id":id,"state":"done","expect":"stale"})),
            2 => (
                "editMetadata",
                json!({"id":id,"title":format!("Title {i}")}),
            ),
            3 => ("delete", json!({"id":id})),
            4 => (
                "position",
                json!({"id":id,"seconds":rng(&mut seed)%100,"seek":i%3==0}),
            ),
            5 => ("episode", json!({"id":id,"title":"Episode"})),
            6 => ("follow", json!({"id":id,"url":"https://example.org/feed"})),
            7 => ("unfollow", json!({"id":id})),
            8 => ("queue", json!({"episodes":[id]})),
            9 => ("createNotebook", json!({"id":id,"title":"Notebook"})),
            10 => (
                "addNote",
                json!({"id":id,"notebook":"object0","text":"Note"}),
            ),
            11 => (
                "editNote",
                json!({"id":id,"notebook":"object0","text":"Edited","expect":"stale"}),
            ),
            12 => ("position", json!({"id":id,"seconds":-1})),
            _ => ("futureKind", json!({"id":id})),
        };
        operations.push(OperationView {
            id: format!("op{i}"),
            kind: kind.into(),
            payload,
            author: format!("author{}", i % 3),
            author_label: "Member".into(),
            origin: "person".into(),
            clock: i + 1,
            created: NOW.into(),
        });
    }
    for _ in 0..8 {
        for i in (1..operations.len()).rev() {
            let j = rng(&mut seed) as usize % (i + 1);
            operations.swap(i, j);
        }
        check_reducer(ReadingSaved, &operations);
        check_reducer(ListeningPodcasts, &operations);
        check_reducer(Notes, &operations);
    }
}

#[test]
fn incremental_script_replays_revocation_and_held_operations() {
    let (mut root, owner, _) = create();
    root.set_checkpoint_policy(CheckpointPolicy {
        every: 2,
        retain: 20,
    });
    let device = keys(2);
    enroll(
        &mut root,
        &owner,
        &device,
        "Device",
        MemberKind::Device,
        grant(&["listening.podcasts"], None),
        21,
    );
    equal_rebuild(&root);
    let mut offline = opened(root.records().clone(), &device);
    // A second verified authority record known only to the writer makes its write held here.
    let rekey = success(root.begin_rekey(&["notes".into()], NOW, [22; 32]).unwrap());
    let authority = finish(rekey, &owner);
    offline.merge(authority.clone()).unwrap();
    let pending = success(
        offline
            .begin_write(
                "listening.podcasts",
                "position",
                json!({"id":"ep","seconds":50}),
                NOW,
                [23; 32],
            )
            .unwrap(),
    );
    let future = finish(pending, &device);
    root.merge(future).unwrap();
    assert_eq!(
        success(root.view("listening.podcasts", NOW).unwrap()).held[0].reason,
        "authorityBehind"
    );
    equal_rebuild(&root);
    root.merge(authority).unwrap();
    unlock(&mut root, &owner);
    assert_eq!(
        success(
            root.query("listening.podcasts", "getEpisode", json!({"id":"ep"}), NOW)
                .unwrap()
        )["seconds"],
        50
    );
    equal_rebuild(&root);
    // Revoke from a replica which never saw another offline write. That write must disappear.
    let mut revoker = root.clone();
    let pending = success(
        offline
            .begin_write(
                "listening.podcasts",
                "position",
                json!({"id":"ep","seconds":90}),
                NOW,
                [24; 32],
            )
            .unwrap(),
    );
    let unseen = finish(pending, &device);
    root.merge(unseen).unwrap();
    equal_rebuild(&root);
    let before = root.checkpoint("listening.podcasts").unwrap();
    let pending = success(
        revoker
            .begin_revoke(&device.public().id(), NOW, [25; 32])
            .unwrap(),
    );
    let revocation = finish(pending, &owner);
    revoker.merge(revocation.clone()).unwrap();
    root.merge(revocation).unwrap();
    unlock(&mut root, &owner);
    assert!(!root
        .restore_checkpoint("listening.podcasts", &before)
        .unwrap());
    assert_eq!(
        success(root.view("listening.podcasts", NOW).unwrap()).held[0].reason,
        "revokedBackdated"
    );
    equal_rebuild(&root);
    // Protocol 0.2 regrant uses a fresh identity, not a replacement grant on the old identity.
    let replacement = keys(3);
    enroll(
        &mut root,
        &owner,
        &replacement,
        "Rejoined",
        MemberKind::Device,
        grant(&["listening.podcasts"], None),
        26,
    );
    equal_rebuild(&root);
    let mut joined = opened(root.records().clone(), &replacement);
    write(
        &mut joined,
        &replacement,
        "listening.podcasts",
        "position",
        json!({"id":"ep","seconds":100}),
        27,
    );
    root.merge(joined.records().clone()).unwrap();
    equal_rebuild(&root);
}

#[test]
fn append_and_nearest_checkpoint_replay_counts_and_paging() {
    let (mut root, owner, _) = create();
    root.set_checkpoint_policy(CheckpointPolicy {
        every: 4,
        retain: 10,
    });
    for i in 1..=20 {
        let prior = root.applied_operations("listening.podcasts");
        write(
            &mut root,
            &owner,
            "listening.podcasts",
            "episode",
            json!({"id":format!("ep{i}")}),
            i,
        );
        assert_eq!(root.applied_operations("listening.podcasts"), prior + 1);
        assert_eq!(root.changes().namespaces.len(), 1);
    }
    let rev = root.revision("listening.podcasts");
    assert!(root
        .merge_with_changes(root.records().clone())
        .unwrap()
        .namespaces
        .is_empty());
    assert_eq!(root.revision("listening.podcasts"), rev);
    let page = success(
        root.query(
            "listening.podcasts",
            "episodes",
            json!({"offset":18,"limit":2}),
            NOW,
        )
        .unwrap(),
    );
    assert_eq!(page["items"].as_array().unwrap().len(), 2);
    assert_eq!(page["nextOffset"], Value::Null);
    assert!(root
        .query("listening.podcasts", "episodes", json!({"limit":201}), NOW)
        .is_err());
    let prior = root.applied_operations("listening.podcasts");
    let inserted = adversarial(
        &root,
        &owner,
        &owner,
        "listening.podcasts",
        op(
            "position",
            10,
            root.authority().latest,
            json!({"id":"ep1","seconds":7}),
        ),
        1,
        92,
    );
    let changed = root.merge_with_changes(inserted).unwrap();
    assert_eq!(changed.namespaces.len(), 1);
    // First eight operations are checkpointed, then the remaining 13 are replayed.
    assert_eq!(root.applied_operations("listening.podcasts") - prior, 13);
    equal_rebuild(&root);
}

#[test]
fn checkpoint_authentication_prefix_identity_version_and_suffix_admission() {
    let (mut root, owner, _) = create();
    write(
        &mut root,
        &owner,
        "notes",
        "createNotebook",
        json!({"id":"n","title":"Notebook"}),
        30,
    );
    let checkpoint = root.checkpoint("notes").unwrap();
    let old_records = root.records().clone();
    write(
        &mut root,
        &owner,
        "notes",
        "addNote",
        json!({"id":"one","notebook":"n","text":"First"}),
        31,
    );
    let checkpoints = BTreeMap::from([("notes".into(), checkpoint.clone())]);
    let mut cold =
        Library::open_with_checkpoints(root.records().clone(), owner.public(), checkpoints)
            .unwrap();
    unlock(&mut cold, &owner);
    assert_eq!(cold.applied_operations("notes"), 1); // Only suffix applied.
    assert_eq!(
        success(cold.query("notes", "read", json!({}), NOW).unwrap()),
        success(root.query("notes", "read", json!({}), NOW).unwrap())
    );
    assert!(cold.restore_checkpoint("notes", &checkpoint).unwrap());
    for field in [
        "version",
        "identity",
        "library",
        "namespace",
        "state",
        "digest",
        "position",
    ] {
        let mut envelope: Value = serde_json::from_slice(&checkpoint).unwrap();
        let mut body: Value =
            serde_json::from_slice(&STANDARD.decode(envelope["body"].as_str().unwrap()).unwrap())
                .unwrap();
        match field {
            "version" => body["version"] = json!(99),
            "state" => {
                body["snapshot"]["state"]["Notes"]["notebooks"]["n"]["title"] = json!("Tampered")
            }
            "digest" => body["snapshot"]["digest"][0] = json!(255),
            "position" => body["snapshot"]["position"] = json!(0),
            other => body[other] = json!("wrong"),
        }
        envelope["body"] = json!(STANDARD.encode(serde_json::to_vec(&body).unwrap()));
        assert!(
            !cold
                .restore_checkpoint("notes", &serde_json::to_vec(&envelope).unwrap())
                .unwrap(),
            "{field}"
        );
    }
    assert!(!cold.restore_checkpoint("notes", b"truncated").unwrap());
    assert!(!cold
        .restore_checkpoint("reading.saved", &checkpoint)
        .unwrap());
    let mut no_prefix = opened(
        old_records
            .into_iter()
            .filter(|(p, _)| !p.starts_with("ops/"))
            .collect(),
        &owner,
    );
    assert!(!no_prefix.restore_checkpoint("notes", &checkpoint).unwrap());
    // A signed suffix citing unavailable authority must still be held after restoring a prefix.
    let future = adversarial(
        &root,
        &owner,
        &owner,
        "notes",
        op(
            "addNote",
            3,
            root.authority().latest + 1,
            json!({"id":"future","notebook":"n","text":"Held"}),
        ),
        1,
        32,
    );
    root.merge(future).unwrap();
    let mut cold = Library::open_with_checkpoints(
        root.records().clone(),
        owner.public(),
        BTreeMap::from([("notes".into(), checkpoint)]),
    )
    .unwrap();
    unlock(&mut cold, &owner);
    assert_eq!(
        success(cold.view("notes", NOW).unwrap()).held[0].reason,
        "authorityBehind"
    );
    equal_rebuild(&cold);
}

#[test]
fn shuffled_record_arrivals_match_full_replay_after_each_merge() {
    let (mut writer, owner, _) = create();
    let mut replica = writer.clone();
    let mut records = Vec::new();
    for i in 0..24u8 {
        let (ns, kind, payload) = match i % 3 {
            0 => (
                "listening.podcasts",
                "position",
                json!({"id":format!("ep{}",i%4),"seconds":i}),
            ),
            1 => (
                "reading.saved",
                "capture",
                json!({"id":format!("link{i}"),"url":"https://example.org"}),
            ),
            _ => (
                "notes",
                "createNotebook",
                json!({"id":format!("book{i}"),"title":"Notebook"}),
            ),
        };
        let record = finish(
            success(
                writer
                    .begin_write(ns, kind, payload, NOW, [i + 50; 32])
                    .unwrap(),
            ),
            &owner,
        );
        writer.merge(record.clone()).unwrap();
        records.push(record);
    }
    let mut seed = 0xdecafbad;
    for i in (1..records.len()).rev() {
        let j = rng(&mut seed) as usize % (i + 1);
        records.swap(i, j);
    }
    for batch in records {
        replica.merge(batch).unwrap();
        equal_rebuild(&replica);
    }
    let rev = replica.revision("notes");
    let conflicting = Records::from([("authority/00000001.json".into(), vec![])]);
    assert!(replica.merge(conflicting).is_err());
    assert_eq!(replica.revision("notes"), rev);
}

#[test]
fn quiet_namespace_append_and_cross_namespace_budget_reordering() {
    let (mut root, owner, _) = create();
    for i in 0..12 {
        write(
            &mut root,
            &owner,
            "listening.podcasts",
            "position",
            json!({"id":"ep","seconds":i}),
            i + 10,
        );
    }
    let listening_revision = root.revision("listening.podcasts");
    write(
        &mut root,
        &owner,
        "notes",
        "createNotebook",
        json!({"id":"book","title":"Book"}),
        29,
    );
    assert_eq!(root.changes().namespaces.len(), 1);
    assert_eq!(root.revision("listening.podcasts"), listening_revision);
    equal_rebuild(&root);
    let limited = keys(2);
    enroll(
        &mut root,
        &owner,
        &limited,
        "Limited",
        MemberKind::Agent,
        grant(&["notes", "reading.saved"], Some(1)),
        30,
    );
    let at = root.authority().latest;
    let later = adversarial(
        &root,
        &owner,
        &limited,
        "notes",
        op(
            "addNote",
            8,
            at,
            json!({"id":"n","notebook":"book","text":"Note"}),
        ),
        1,
        31,
    );
    root.merge(later).unwrap();
    assert_eq!(
        success(root.query("notes", "notes", json!({}), NOW).unwrap())["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let earlier = adversarial(
        &root,
        &owner,
        &limited,
        "reading.saved",
        op(
            "capture",
            2,
            at,
            json!({"id":"link","url":"https://example.org"}),
        ),
        1,
        32,
    );
    let changes = root.merge_with_changes(earlier).unwrap();
    assert_eq!(changes.namespaces.len(), 2);
    assert!(changes.namespaces.contains_key("notes"));
    assert_eq!(
        success(root.view("notes", NOW).unwrap()).refused[0].reason,
        "budgetSpent"
    );
    equal_rebuild(&root);
}

#[test]
fn batch_unlock_is_atomic_and_checkpoint_cold_open_supports_sequential_unlock() {
    let (mut root, owner, _) = create();
    write(
        &mut root,
        &owner,
        "notes",
        "createNotebook",
        json!({"id":"book","title":"Book"}),
        40,
    );
    let rekey = success(root.begin_rekey(&["notes".into()], NOW, [41; 32]).unwrap());
    apply(&mut root, rekey, &owner);
    let checkpoint = root.checkpoint("notes").unwrap();
    let mut cold = Library::open_with_checkpoints(
        root.records().clone(),
        owner.public(),
        BTreeMap::from([("notes".into(), checkpoint.clone())]),
    )
    .unwrap();
    let mut results: Vec<_> = cold
        .begin_unlock()
        .into_iter()
        .map(|step| {
            let shared = owner.agree(&step.peer).unwrap();
            (step.namespace, step.epoch, shared)
        })
        .collect();
    let count = results.len();
    results.last_mut().unwrap().2[0] ^= 1;
    assert!(cold.finish_unlock_many(results).is_err());
    assert_eq!(cold.begin_unlock().len(), count);
    unlock(&mut cold, &owner);
    assert_eq!(cold.applied_operations("notes"), 0);
    equal_rebuild(&cold);
    // An invalid pending cache must fall back to replay, not produce an empty namespace.
    let mut envelope: Value = serde_json::from_slice(&checkpoint).unwrap();
    envelope["tag"] = json!(STANDARD.encode([0; 32]));
    let mut fallback = Library::open_with_checkpoints(
        root.records().clone(),
        owner.public(),
        BTreeMap::from([("notes".into(), serde_json::to_vec(&envelope).unwrap())]),
    )
    .unwrap();
    unlock(&mut fallback, &owner);
    assert_eq!(fallback.applied_operations("notes"), 1);
    equal_rebuild(&fallback);
}

#[test]
fn query_tools_keep_write_names_and_restored_checkpoint_is_reused() {
    use colophon_core::{domain::DomainModule, library::Call};
    let (mut root, owner, _) = create();
    root.set_checkpoint_policy(CheckpointPolicy {
        every: 0,
        retain: 1,
    });
    for i in 1..=8 {
        write(
            &mut root,
            &owner,
            "listening.podcasts",
            "position",
            json!({"id":"ep","seconds":i}),
            i + 100,
        );
    }
    let checkpoint = root.checkpoint("listening.podcasts").unwrap();
    assert!(root
        .restore_checkpoint("listening.podcasts", &checkpoint)
        .unwrap());
    write(
        &mut root,
        &owner,
        "listening.podcasts",
        "position",
        json!({"id":"ep","seconds":9}),
        110,
    );
    write(
        &mut root,
        &owner,
        "listening.podcasts",
        "position",
        json!({"id":"ep","seconds":10}),
        111,
    );
    let applied = root.applied_operations("listening.podcasts");
    let middle = adversarial(
        &root,
        &owner,
        &owner,
        "listening.podcasts",
        op(
            "position",
            9,
            root.authority().latest,
            json!({"id":"ep","seconds":11}),
        ),
        1,
        112,
    );
    root.merge(middle).unwrap();
    assert_eq!(root.applied_operations("listening.podcasts") - applied, 3);
    equal_rebuild(&root);
    let queries = ListeningPodcasts.queries();
    let operations = ListeningPodcasts.operations();
    assert!(queries
        .iter()
        .all(|q| operations.iter().all(|op| op.name != q.name)));
    let call = success(
        root.begin_call(
            "listening.podcasts__getEpisode",
            json!({"id":"ep"}),
            NOW,
            [113; 32],
        )
        .unwrap(),
    );
    assert!(matches!(call,Call::Read {value} if value["seconds"]==11));
    let call = success(
        root.begin_call(
            "listening.podcasts__episode",
            json!({"id":"ep","title":"Title"}),
            NOW,
            [114; 32],
        )
        .unwrap(),
    );
    assert!(matches!(call, Call::Write { .. }));
    // Prefix digests hash raw signed-body digests, with the all-zero H(0) seed.
    use sha2::{Digest, Sha256};
    let mut entries: Vec<_> = root
        .records()
        .iter()
        .filter(|(p, _)| p.starts_with("ops/"))
        .map(|(_, raw)| {
            let signed: colophon_core::records::SignedRecord = serde_json::from_slice(raw).unwrap();
            let header: colophon_core::model::OperationHeader =
                serde_json::from_slice(&signed.body).unwrap();
            (
                (header.meta.clock, header.meta.author, header.meta.id),
                signed.body,
            )
        })
        .collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut hash = [0u8; 32];
    for (_, body) in entries {
        let mut hasher = Sha256::new();
        hasher.update(hash);
        hasher.update(Sha256::digest(body));
        hash = hasher.finalize().into();
    }
    let envelope: Value =
        serde_json::from_slice(&root.checkpoint("listening.podcasts").unwrap()).unwrap();
    let body: Value =
        serde_json::from_slice(&STANDARD.decode(envelope["body"].as_str().unwrap()).unwrap())
            .unwrap();
    assert_eq!(body["snapshot"]["digest"], json!(hash));
}

#[test]
fn authenticated_domain_roles_survive_incremental_replay_and_checkpoints() {
    let (mut root, owner, _) = create();
    let agent_keys = keys(7);
    let server_keys = keys(8);
    enroll(
        &mut root,
        &owner,
        &agent_keys,
        "Agent",
        MemberKind::Agent,
        grant(&["listening.podcasts"], None),
        81,
    );
    enroll(
        &mut root,
        &owner,
        &server_keys,
        "Server",
        MemberKind::Server,
        grant(&["listening.podcasts"], None),
        82,
    );
    let audio = json!({"digest":"a".repeat(64),"size":12,"mediaType":"application/json"});
    let request = json!({"id":"job","episode":"e","show":"s","worker":agent_keys.public().id(),"audio":audio,"recording":"a".repeat(64),"language":"en"});
    write(
        &mut root,
        &owner,
        "listening.podcasts",
        "requestTranscript",
        request.clone(),
        83,
    );
    let jobs = success(
        root.query(
            "listening.podcasts",
            "jobs",
            json!({"kind":"transcript"}),
            NOW,
        )
        .unwrap(),
    );
    assert_eq!(jobs["value"]["total"], 1);
    let request_revision = jobs["value"]["rows"][0]["requestRevision"].clone();
    let mut agent = opened(root.records().clone(), &agent_keys);
    write(
        &mut agent,
        &agent_keys,
        "listening.podcasts",
        "supplyTranscript",
        json!({"id":"job","request":request_revision,"result":audio}),
        84,
    );
    root.merge(agent.records().clone()).unwrap();
    let mut server = opened(root.records().clone(), &server_keys);
    let mut forbidden = request;
    forbidden["id"] = json!("forbidden");
    // Person origin is insufficient: only authority-derived app/device kind may request work.
    write(
        &mut server,
        &server_keys,
        "listening.podcasts",
        "requestTranscript",
        forbidden,
        85,
    );
    root.merge(server.records().clone()).unwrap();
    let expected = success(
        root.query(
            "listening.podcasts",
            "jobs",
            json!({"kind":"transcript"}),
            NOW,
        )
        .unwrap(),
    );
    assert_eq!(expected["value"]["total"], 1);
    assert!(expected["value"]["rows"][0]["responseRevision"].is_string());
    let refused = success(
        root.query(
            "listening.podcasts",
            "conflicts",
            json!({"object":"forbidden"}),
            NOW,
        )
        .unwrap(),
    );
    assert_eq!(refused["value"]["total"], 1);
    assert_eq!(refused["value"]["rows"][0]["outcome"], "roleDenied");
    let checkpoint = root.checkpoint("listening.podcasts").unwrap();
    let mut cold = opened(root.records().clone(), &owner);
    assert_eq!(
        expected,
        success(
            cold.query(
                "listening.podcasts",
                "jobs",
                json!({"kind":"transcript"}),
                NOW
            )
            .unwrap()
        )
    );
    assert!(cold
        .restore_checkpoint("listening.podcasts", &checkpoint)
        .unwrap());
    assert_eq!(
        expected,
        success(
            cold.query(
                "listening.podcasts",
                "jobs",
                json!({"kind":"transcript"}),
                NOW
            )
            .unwrap()
        )
    );
}
