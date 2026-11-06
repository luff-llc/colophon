#![allow(clippy::unwrap_used)]
mod support;
use colophon_core::{
    blobs::{BlobVerifier, CHUNK_BYTES},
    engine::{Engine, EngineOptions},
    imports::{self, ImportBatch, ImportChild},
    model::{MemberKind, Outcome},
    records::{canonical, digest},
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use support::*;
fn batch(key: &str) -> ImportBatch {
    ImportBatch {
        key: key.into(),
        evidence: json!({"sourceLibrary":"old","authorID":"old-author","authorLabel":"Old author","signedBodyDigest":"a".repeat(64),"claimedDate":-42,"domainOutcome":"applied","losingCandidates":[{"text":"rejected old write"}]}),
        children: vec![ImportChild {
            key: "create".into(),
            kind: "createNotebook".into(),
            payload: json!({"id":key,"title":"Imported"}),
            baseline: false,
        }],
        alternatives: vec![],
        identities: BTreeMap::new(),
        blobs: vec![],
    }
}
fn query(lib: &colophon_core::library::Library, name: &str, args: Value) -> Value {
    success(lib.query("notes", name, args, NOW).unwrap())
}
#[test]
fn atomic_publication_evidence_receipts_retries_and_replay() {
    let (mut lib, owner, _) = create();
    let old = lib.records().clone();
    let mut b = batch("unit");
    b.children.push(ImportChild { key:"cell".into(),kind:"putCell".into(),payload:json!({"id":"cell","notebook":"unit","kind":"markdown","source":"Imported text","expect":null}),baseline:false });
    let pending = success(
        lib.begin_write("notes", imports::BATCH_KIND, json!(b), NOW, [80; 32])
            .unwrap(),
    );
    assert_eq!(pending.steps.len(), 1);
    assert_eq!(
        query(&lib, "importEvidence", json!({}))["value"]["rows"],
        json!([])
    );
    let records = finish(pending, &owner);
    assert_eq!(records.len(), 1);
    assert!(!String::from_utf8_lossy(records.values().next().unwrap()).contains("Old author"));
    lib.merge(records.clone()).unwrap();
    let evidence = query(&lib, "importEvidence", json!({}));
    assert_eq!(evidence["value"]["rows"][0]["evidence"]["claimedDate"], -42);
    let id = imports::output_id(lib.id(), "notes", "unit", "cell").unwrap();
    assert_eq!(
        query(&lib, "importReceipt", json!({"key":"unit"}))["outputOperationIDs"]["cell"],
        id
    );
    let state = query(&lib, "read", json!({}));
    write(&mut lib, &owner, "notes", imports::BATCH_KIND, json!(b), 81);
    assert_eq!(query(&lib, "read", json!({})), state);
    b.children[0].payload["title"] = json!("Changed retry");
    assert!(lib
        .begin_write("notes", imports::BATCH_KIND, json!(b), NOW, [82; 32])
        .is_err());
    let restored = opened(lib.records().clone(), &owner);
    assert_eq!(query(&restored, "read", json!({})), state);
    assert_eq!(
        query(&restored, "importReceipt", json!({"key":"unit"})),
        query(&lib, "importReceipt", json!({"key":"unit"}))
    );
    let mut partial = old;
    let (path, mut raw) = records.into_iter().next().unwrap();
    raw.truncate(raw.len() / 2);
    partial.insert(path, raw);
    let partial = opened(partial, &owner);
    assert_eq!(
        query(&partial, "importEvidence", json!({}))["value"]["rows"],
        json!([])
    );
}
#[test]
fn grants_root_fence_paging_and_namespace_encryption() {
    let (mut lib, owner, _) = create();
    let member = keys(3);
    let other = keys(4);
    enroll(
        &mut lib,
        &owner,
        &member,
        "App",
        MemberKind::App,
        grant(&["notes"], None),
        33,
    );
    enroll(
        &mut lib,
        &owner,
        &other,
        "Other",
        MemberKind::Device,
        grant(&["reading.saved"], None),
        34,
    );
    write(
        &mut lib,
        &owner,
        "notes",
        imports::BATCH_KIND,
        json!(batch("one")),
        35,
    );
    write(
        &mut lib,
        &owner,
        "notes",
        imports::BATCH_KIND,
        json!(batch("two")),
        36,
    );
    let app = opened(lib.records().clone(), &member);
    assert!(matches!(
        app.begin_write(
            "notes",
            imports::BATCH_KIND,
            json!(batch("evil")),
            NOW,
            [37; 32]
        )
        .unwrap(),
        Outcome::Failure { .. }
    ));
    assert_eq!(
        query(&app, "importEvidence", json!({"limit":1}))["value"]["rows"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let cursor = query(&app, "importEvidence", json!({"limit":1}))["value"]["next"].clone();
    let page = query(&app, "importEvidence", json!({"limit":1,"cursor":cursor}));
    assert!(page["value"]["next"].is_null());
    let unauthorized = opened(lib.records().clone(), &other);
    assert!(matches!(
        unauthorized
            .query("notes", "importEvidence", json!({}), NOW)
            .unwrap(),
        Outcome::Failure { .. }
    ));
    write(
        &mut lib,
        &owner,
        "notes",
        "unknown",
        json!({"memberKind":"device"}),
        38,
    );
    assert!(lib
        .query("notes", "importEvidence", json!({"cursor":cursor}), NOW)
        .is_err());
    let pending = success(
        lib.begin_revoke(&member.public().id(), NOW, [39; 32])
            .unwrap(),
    );
    apply(&mut lib, pending, &owner);
    let app = opened(lib.records().clone(), &member);
    assert!(matches!(
        app.query("notes", "importEvidence", json!({}), NOW)
            .unwrap(),
        Outcome::Failure { .. }
    ));
}
#[test]
fn historical_reconciliation_never_makes_rejected_writes_effective() {
    let (mut lib, owner, _) = create();
    write(
        &mut lib,
        &owner,
        "notes",
        imports::BATCH_KIND,
        json!(batch("book")),
        40,
    );
    write(
        &mut lib,
        &owner,
        "notes",
        "addNote",
        json!({"id":"n","notebook":"book","text":"Native"}),
        41,
    );
    let before = query(&lib, "read", json!({}));
    let alternatives = imports::reconcile_prefix(
        &BTreeMap::from([("old".into(), json!({"outcome":"applied"}))]),
        &BTreeMap::from([
            ("old".into(), json!({"outcome":"conflict","text":"losing"})),
            ("earlier".into(), json!({"text":"late offline"})),
        ]),
        &json!({"text":"imported-head"}),
    );
    assert_eq!(alternatives.len(), 2);
    let mut b = batch("reconcile");
    b.children.clear();
    b.alternatives = alternatives;
    write(&mut lib, &owner, "notes", imports::BATCH_KIND, json!(b), 42);
    assert_eq!(query(&lib, "read", json!({})), before);
    let overlay = query(&lib, "historicalAlternatives", json!({}));
    let ids: Vec<_> = overlay["value"]["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["id"].clone())
        .collect();
    write(
        &mut lib,
        &owner,
        "notes",
        "colophon.resolveHistorical",
        json!({"alternatives":[],"expectedRevision":overlay["revision"]}),
        43,
    );
    assert_eq!(
        query(&lib, "historicalAlternatives", json!({}))["value"]["rows"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let revision = query(&lib, "historicalAlternatives", json!({}))["revision"].clone();
    write(
        &mut lib,
        &owner,
        "notes",
        "colophon.resolveHistorical",
        json!({"alternatives":ids,"expectedRevision":revision}),
        44,
    );
    assert_eq!(
        query(&lib, "historicalAlternatives", json!({}))["value"]["rows"],
        json!([])
    );
    assert_eq!(query(&lib, "read", json!({})), before);
    assert_eq!(
        query(&lib, "importReceipt", json!({"key":"reconcile"}))["alternatives"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}
#[test]
fn identity_reservations_bind_retries_and_protect_native_tombstones() {
    let (mut lib, owner, _) = create();
    write(
        &mut lib,
        &owner,
        "notes",
        "createNotebook",
        json!({"id":"native","title":"Native"}),
        50,
    );
    let mut b = batch("source");
    b.children[0].payload["id"] = json!("native");
    b.identities.insert(
        "old/notebook/native/create-digest".into(),
        imports::IdentityReservation {
            category: "notebook".into(),
            id: "native".into(),
        },
    );
    assert!(lib
        .begin_write("notes", imports::BATCH_KIND, json!(b), NOW, [51; 32])
        .is_err());
    let id = imports::occurrence_id(
        lib.id(),
        "notes",
        &json!(["old", "notebook", "native", "creation-digest"]),
    )
    .unwrap();
    b.children[0].payload["id"] = json!(id);
    b.identities.values_mut().for_each(|v| v.id = id.clone());
    write(&mut lib, &owner, "notes", imports::BATCH_KIND, json!(b), 52);
    assert_eq!(
        query(
            &lib,
            "importIdentity",
            json!({"key":"old/notebook/native/create-digest","preferred":"native","category":"notebook"})
        )["reserved"],
        id
    );
    write(&mut lib, &owner, "notes", imports::BATCH_KIND, json!(b), 53);
    assert_eq!(
        query(&lib, "importEvidence", json!({}))["value"]["rows"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}
#[test]
fn blobs_stream_encrypt_authenticate_reference_count_and_lazy_host_reads() {
    let (mut lib, owner, _) = create();
    let mut writer = match lib
        .begin_blob("notes", "text/plain".into(), NOW, [60; 32])
        .unwrap()
    {
        Outcome::Success { value, .. } => value,
        _ => panic!(),
    };
    let first = vec![b'a'; CHUNK_BYTES];
    let second = b"last chunk";
    let (p1, c1) = writer.push(&first).unwrap();
    let (p2, c2) = writer.push(second).unwrap();
    assert!(writer.push(&vec![0; CHUNK_BYTES + 1]).is_err());
    let manifest = writer.finish().unwrap();
    let content_digest = manifest.descriptor.digest.clone();
    assert_eq!(content_digest, digest(&[first.as_slice(), second].concat()));
    let mut b = batch("blob-unit");
    b.blobs.push(manifest.clone());
    write(&mut lib, &owner, "notes", imports::BATCH_KIND, json!(b), 61);
    let mut verifier = BlobVerifier::default();
    for (i, bytes) in [&c1, &c2].into_iter().enumerate() {
        let clear = success(
            lib.open_blob_chunk("notes", &content_digest, i, bytes, NOW)
                .unwrap(),
        );
        verifier.update(&clear);
    }
    verifier.finish(&manifest.descriptor).unwrap();
    assert!(lib
        .open_blob_chunk("notes", &content_digest, 0, &c2, NOW)
        .is_err());
    assert_eq!(
        query(&lib, "blob", json!({"digest":content_digest}))["references"],
        1
    );
    write(
        &mut lib,
        &owner,
        "notes",
        "colophon.blobReference",
        json!({"digest":content_digest,"reference":"blob-unit","retain":false}),
        62,
    );
    assert_eq!(
        query(&lib, "blob", json!({"digest":content_digest}))["references"],
        0
    );
    // Blob ciphertext is supplied by the same host source, outside the operation listing.
    let listing = lib.records().keys().cloned().collect();
    let mut source = lib.records().clone();
    source.insert(p1, c1);
    source.insert(p2, c2);
    let mut engine = Engine::open(
        source,
        listing,
        owner.public(),
        EngineOptions {
            library_id: lib.id().into(),
            checkpoint_key: [8; 32],
            content_cache_bytes: 0,
        },
        None,
    )
    .unwrap();
    engine
        .finish_unlock_many(
            engine
                .begin_unlock()
                .into_iter()
                .map(|s| (s.namespace, s.epoch, owner.agree(&s.peer).unwrap()))
                .collect(),
        )
        .unwrap();
    assert_eq!(
        success(
            engine
                .read_blob_chunk("notes", &content_digest, 1, NOW)
                .unwrap()
        ),
        second
    );
    let cache = engine.checkpoint().unwrap();
    let listing = lib.records().keys().cloned().collect();
    let mut restored = Engine::open(
        engine.source().clone(),
        listing,
        owner.public(),
        EngineOptions {
            library_id: lib.id().into(),
            checkpoint_key: [8; 32],
            content_cache_bytes: 0,
        },
        Some(&cache),
    )
    .unwrap();
    restored
        .finish_unlock_many(
            restored
                .begin_unlock()
                .into_iter()
                .map(|s| (s.namespace, s.epoch, owner.agree(&s.peer).unwrap()))
                .collect(),
        )
        .unwrap();
    assert_eq!(restored.stats().records_read, 0);
    assert_eq!(
        success(
            restored
                .query("notes", "importEvidence", json!({}), NOW)
                .unwrap()
        ),
        query(&lib, "importEvidence", json!({}))
    );
    assert_eq!(
        success(
            restored
                .read_blob_chunk("notes", &content_digest, 0, NOW)
                .unwrap()
        ),
        first
    );
    assert!(canonical(&manifest).unwrap().len() < 2048);
}

#[test]
fn role_fences_apply_before_signing_and_forged_import_metadata_never_grants_root() {
    let (mut lib, owner, _) = create();
    let server = keys(5);
    enroll(
        &mut lib,
        &owner,
        &server,
        "Server",
        MemberKind::Server,
        grant(&["notes"], None),
        70,
    );
    let app = opened(lib.records().clone(), &server);
    assert!(app
        .begin_write(
            "notes",
            "reviewProposal",
            json!({"id":"p","notebook":"n","keep":false}),
            NOW,
            [71; 32]
        )
        .is_err());
    assert!(!app
        .tools(NOW)
        .unwrap()
        .iter()
        .any(|s| s.name == "notes__reviewProposal"));
    let mut b = batch("forged");
    b.evidence["root"] = json!(true);
    b.evidence["memberKind"] = json!("device");
    let raw = adversarial(
        &lib,
        &owner,
        &server,
        "notes",
        colophon_core::model::Operation {
            id: String::new(),
            kind: imports::BATCH_KIND.into(),
            v: 1,
            clock: 1,
            authority: lib.authority().latest,
            created: NOW.into(),
            payload: json!(b),
        },
        1,
        72,
    );
    lib.merge(raw).unwrap();
    assert_eq!(
        query(&lib, "importEvidence", json!({}))["value"]["rows"],
        json!([])
    );
    assert_eq!(
        query(&lib, "importInvalid", json!({}))
            .as_array()
            .unwrap()
            .len(),
        1
    );
}
#[test]
fn authenticated_baseline_receipts_cannot_overwrite_native_progress() {
    let (mut lib, owner, _) = create();
    write(
        &mut lib,
        &owner,
        "listening.podcasts",
        "position",
        json!({"id":"episode","seconds":120,"seek":true}),
        75,
    );
    let mut b = batch("baseline");
    b.children = vec![ImportChild {
        key: "position".into(),
        kind: "position".into(),
        payload: json!({"id":"episode","seconds":10,"seek":true}),
        baseline: true,
    }];
    write(
        &mut lib,
        &owner,
        "listening.podcasts",
        imports::BATCH_KIND,
        json!(b),
        76,
    );
    let result = success(
        lib.query(
            "listening.podcasts",
            "getEpisode",
            json!({"id":"episode"}),
            NOW,
        )
        .unwrap(),
    );
    assert_eq!(result["seconds"], 120);
    let receipt = success(
        lib.query(
            "listening.podcasts",
            "importReceipt",
            json!({"key":"baseline"}),
            NOW,
        )
        .unwrap(),
    );
    assert_eq!(
        receipt["baselineOutputs"]["position"],
        receipt["outputOperationIDs"]["position"]
    );
    assert!(receipt["baselineOutputs"]["position"].is_string());
    let rebuilt = opened(lib.records().clone(), &owner);
    assert_eq!(
        success(
            rebuilt
                .query(
                    "listening.podcasts",
                    "getEpisode",
                    json!({"id":"episode"}),
                    NOW
                )
                .unwrap()
        ),
        result
    );
}

#[test]
fn loan_and_review_use_authenticated_app_context_on_replay_and_checkpoint_suffix() {
    let owner = keys(1);
    let app = keys(7);
    let server = keys(8);
    let p = colophon_core::library::Library::begin_create(
        colophon_core::library::CreateOptions {
            owner: owner.public(),
            recovery: keys(9).public(),
            label: "Roles".into(),
            owner_label: "Owner".into(),
            namespaces: vec!["reading.books".into(), "notes".into()],
        },
        NOW,
        [90; 32],
    )
    .unwrap();
    let mut root = opened(finish(p, &owner), &owner);
    enroll(
        &mut root,
        &owner,
        &app,
        "App",
        MemberKind::App,
        grant(&["reading.books", "notes"], None),
        91,
    );
    enroll(
        &mut root,
        &owner,
        &server,
        "Server",
        MemberKind::Server,
        grant(&["reading.books", "notes"], None),
        92,
    );
    write(
        &mut root,
        &owner,
        "reading.books",
        "addBook",
        json!({"id":"b","title":"Book","creator":"Author"}),
        93,
    );
    write(
        &mut root,
        &owner,
        "notes",
        "createNotebook",
        json!({"id":"n","title":"Notes"}),
        94,
    );
    write(
        &mut root,
        &owner,
        "notes",
        "putEntry",
        json!({"id":"e","notebook":"n","tags":[]}),
        100,
    );
    write(
        &mut root,
        &owner,
        "notes",
        "proposeEntry",
        json!({"id":"p","notebook":"n","entry":"e","markdown":"Proposal","inputs":{}}),
        95,
    );
    let cache = root.checkpoint("notes").unwrap();
    let mut replica = opened(root.records().clone(), &app);
    write(
        &mut replica,
        &app,
        "reading.books",
        "setCopyLoan",
        json!({"id":"b","status":"needsReturn","requestID":"request"}),
        96,
    );
    write(
        &mut replica,
        &app,
        "notes",
        "reviewProposal",
        json!({"id":"p","notebook":"n","keep":false}),
        97,
    );
    root.merge(replica.records().clone()).unwrap();
    let book = success(
        root.query("reading.books", "book", json!({"id":"b"}), NOW)
            .unwrap(),
    );
    assert_eq!(book["value"]["loan"]["status"], "needsReturn");
    let reviews = query(
        &root,
        "proposals",
        json!({"notebook":"n","entry":"e","status":"dismissed"}),
    );
    assert_eq!(reviews["value"]["rows"][0]["status"], "dismissed");
    let mut replay = opened(root.records().clone(), &owner);
    assert!(replay.restore_checkpoint("notes", &cache).unwrap());
    assert_eq!(
        query(
            &replay,
            "proposals",
            json!({"notebook":"n","entry":"e","status":"dismissed"})
        ),
        reviews
    );
    let wrong = opened(root.records().clone(), &server);
    assert!(wrong
        .begin_write(
            "reading.books",
            "setCopyLoan",
            json!({"id":"b","status":"none","requestID":"bad","memberKind":"device"}),
            NOW,
            [98; 32]
        )
        .is_err());
    assert!(wrong
        .begin_write(
            "notes",
            "reviewProposal",
            json!({"id":"p","notebook":"n","keep":true,"role":"root"}),
            NOW,
            [99; 32]
        )
        .is_err());
}

#[test]
fn blob_availability_and_revocation_never_expose_an_empty_success() {
    use colophon_core::blobs::BlobRead;
    let (mut lib, owner, _) = create();
    let member = keys(6);
    enroll(
        &mut lib,
        &owner,
        &member,
        "Reader",
        MemberKind::App,
        grant(&["notes"], None),
        110,
    );
    let mut writer = match lib
        .begin_blob("notes", "text/plain".into(), NOW, [111; 32])
        .unwrap()
    {
        Outcome::Success { value, .. } => value,
        _ => panic!(),
    };
    let (path, ciphertext) = writer.push(b"private blob").unwrap();
    let manifest = writer.finish().unwrap();
    let digest = manifest.descriptor.digest.clone();
    write(
        &mut lib,
        &owner,
        "notes",
        "colophon.blobPublish",
        json!({"manifest":manifest,"reference":"attachment"}),
        112,
    );
    let app = opened(lib.records().clone(), &member);
    assert_eq!(
        success(
            app.open_blob_chunk("notes", &digest, 0, &ciphertext, NOW)
                .unwrap()
        ),
        b"private blob"
    );
    let pending = success(
        lib.begin_revoke(&member.public().id(), NOW, [113; 32])
            .unwrap(),
    );
    apply(&mut lib, pending, &owner);
    let revoked = opened(lib.records().clone(), &member);
    assert!(matches!(
        revoked
            .open_blob_chunk("notes", &digest, 0, &ciphertext, NOW)
            .unwrap(),
        Outcome::Failure { .. }
    ));
    let listing = lib.records().keys().cloned().collect();
    let mut engine = Engine::open(
        lib.records().clone(),
        listing,
        owner.public(),
        EngineOptions {
            library_id: lib.id().into(),
            checkpoint_key: [2; 32],
            content_cache_bytes: 0,
        },
        None,
    )
    .unwrap();
    engine
        .finish_unlock_many(
            engine
                .begin_unlock()
                .into_iter()
                .map(|s| (s.namespace, s.epoch, owner.agree(&s.peer).unwrap()))
                .collect(),
        )
        .unwrap();
    assert_eq!(
        engine.blob_chunk("notes", &digest, 0, NOW).unwrap(),
        BlobRead::Missing
    );
    let mut source = lib.records().clone();
    source.insert(path, vec![0]);
    let listing = lib.records().keys().cloned().collect();
    let mut broken = Engine::open(
        source,
        listing,
        owner.public(),
        EngineOptions {
            library_id: lib.id().into(),
            checkpoint_key: [2; 32],
            content_cache_bytes: 0,
        },
        None,
    )
    .unwrap();
    broken
        .finish_unlock_many(
            broken
                .begin_unlock()
                .into_iter()
                .map(|s| (s.namespace, s.epoch, owner.agree(&s.peer).unwrap()))
                .collect(),
        )
        .unwrap();
    assert!(matches!(
        broken.blob_chunk("notes", &digest, 0, NOW).unwrap(),
        BlobRead::Invalid(_)
    ));
}
#[test]
fn invalid_children_are_atomic_and_reservations_are_category_scoped() {
    let (mut lib, owner, _) = create();
    let mut b = batch("same-id");
    b.identities.insert(
        "notebook-source".into(),
        imports::IdentityReservation {
            category: "notebook".into(),
            id: "same-id".into(),
        },
    );
    write(
        &mut lib,
        &owner,
        "notes",
        imports::BATCH_KIND,
        json!(b),
        120,
    );
    let mut cell = batch("cell-unit");
    cell.children = vec![ImportChild {
        key: "cell".into(),
        kind: "putCell".into(),
        payload: json!({"id":"same-id","notebook":"same-id","kind":"markdown","source":"Separate category","expect":null}),
        baseline: false,
    }];
    cell.identities.insert(
        "cell-source".into(),
        imports::IdentityReservation {
            category: "cell".into(),
            id: "same-id".into(),
        },
    );
    write(
        &mut lib,
        &owner,
        "notes",
        imports::BATCH_KIND,
        json!(cell),
        121,
    );
    assert_eq!(
        query(&lib, "cell", json!({"notebook":"same-id","id":"same-id"}))["value"]["source"],
        "Separate category"
    );
    let before = query(&lib, "read", json!({}));
    let mut bad = batch("bad-unit");
    bad.children.push(ImportChild {
        key: "bad".into(),
        kind: "putCell".into(),
        payload: json!({"id":"bad"}),
        baseline: false,
    });
    assert!(lib
        .begin_write("notes", imports::BATCH_KIND, json!(bad), NOW, [122; 32])
        .is_err());
    let raw = adversarial(
        &lib,
        &owner,
        &owner,
        "notes",
        colophon_core::model::Operation {
            id: String::new(),
            kind: imports::BATCH_KIND.into(),
            v: 1,
            clock: 3,
            authority: lib.authority().latest,
            created: NOW.into(),
            payload: json!(bad),
        },
        1,
        123,
    );
    lib.merge(raw).unwrap();
    assert_eq!(query(&lib, "read", json!({})), before);
    assert!(query(&lib, "importReceipt", json!({"key":"bad-unit"})).is_null());
}
