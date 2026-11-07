#![allow(clippy::unwrap_used)]
mod support;
use colophon_core::{
    crypto::SoftwareKeys,
    engine::{Engine, EngineOptions, OpenMode, RecordSource},
    library::Library,
    model::{MemberKind, Records},
    records::SignedRecord,
    verification::{BatchVerifier, VerificationTask},
    Error, Result,
};
use serde_json::json;
use std::{
    cell::RefCell,
    rc::Rc,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
use support::*;
fn resign(
    raw: &[u8],
    signer: &SoftwareKeys,
    mutate: impl FnOnce(&mut serde_json::Value),
) -> Vec<u8> {
    let record: SignedRecord = serde_json::from_slice(raw).unwrap();
    let mut body: serde_json::Value = serde_json::from_slice(&record.body).unwrap();
    mutate(&mut body);
    let body = colophon_core::records::canonical(&body).unwrap();
    SignedRecord {
        signature: signer.sign(&body),
        body,
    }
    .encode()
    .unwrap()
}
#[derive(Clone)]
struct Source(Rc<RefCell<Records>>, Rc<RefCell<Vec<String>>>);
impl Source {
    fn new(records: Records) -> Self {
        Self(
            Rc::new(RefCell::new(records)),
            Rc::new(RefCell::new(Vec::new())),
        )
    }
    fn listing(&self) -> Vec<String> {
        self.0.borrow().keys().cloned().collect()
    }
    fn add(&self, records: Records) -> Vec<String> {
        let paths = records.keys().cloned().collect();
        self.0.borrow_mut().extend(records);
        paths
    }
}
impl RecordSource for Source {
    fn read(&self, path: &str) -> Result<Vec<u8>> {
        self.1.borrow_mut().push(path.into());
        self.0
            .borrow()
            .get(path)
            .cloned()
            .ok_or_else(|| Error(format!("Missing record {path}")))
    }
}
fn options(lib: &Library) -> EngineOptions {
    EngineOptions {
        library_id: lib.id().into(),
        checkpoint_key: [71; 32],
        content_cache_bytes: 512,
        namespaces: Vec::new(),
    }
}
fn engine(lib: &Library, owner: &SoftwareKeys) -> Engine<Source> {
    let source = Source::new(lib.records().clone());
    let mut engine = Engine::open(
        source.clone(),
        source.listing(),
        owner.public(),
        options(lib),
        None,
    )
    .unwrap();
    unlock_engine(&mut engine, owner);
    engine
}
fn unlock_engine(engine: &mut Engine<Source>, owner: &SoftwareKeys) {
    let results = engine
        .begin_unlock()
        .into_iter()
        .map(|s| (s.namespace, s.epoch, owner.agree(&s.peer).unwrap()))
        .collect();
    engine.finish_unlock_many(results).unwrap();
}
fn strip_live_revisions(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            map.remove("revision");
            if map.contains_key("next") {
                map.insert("next".into(), serde_json::Value::Null);
            }
            for child in map.values_mut() {
                strip_live_revisions(child);
            }
        }
        serde_json::Value::Array(items) => {
            for child in items {
                strip_live_revisions(child);
            }
        }
        _ => {}
    }
}
fn equal(engine: &mut Engine<Source>, lib: &Library) {
    for ns in lib.authority().namespaces.clone() {
        if ns == "listening.podcasts" {
            // Live slots are current overlay: engine history lists immutable ops,
            // while the library view may still name the current live revision.
            continue;
        }
        assert_eq!(
            json!(engine.view(&ns, NOW).unwrap()),
            json!(lib.view(&ns, NOW).unwrap()),
            "{ns}"
        );
    }
}
fn write(lib: &mut Library, owner: &SoftwareKeys, n: u8) -> Records {
    let pending = success(
        lib.begin_write(
            "listening.podcasts",
            "position",
            json!({"id":"ep","seconds":n,"seek":true}),
            NOW,
            [n; 32],
        )
        .unwrap(),
    );
    let records = finish(pending, owner);
    lib.merge(records.clone()).unwrap();
    records
}
#[test]
fn trusted_open_has_no_historical_reads_and_bounded_lazy_content() {
    let (mut root, owner, _) = create();
    for n in 1..40 {
        write(&mut root, &owner, n);
    }
    let mut first = engine(&root, &owner);
    equal(&mut first, &root);
    let checkpoint = first.checkpoint().unwrap();
    let source = first.source().clone();
    source.1.borrow_mut().clear();
    let mut cold = Engine::open(
        source.clone(),
        source.listing(),
        owner.public(),
        options(&root),
        Some(&checkpoint),
    )
    .unwrap();
    assert_eq!(cold.open_mode(), &OpenMode::VerifiedPrefix);
    unlock_engine(&mut cold, &owner);
    assert!(source.1.borrow().is_empty());
    assert_eq!(cold.stats().payloads_decrypted, 0);
    assert_eq!(cold.stats().signatures_verified, 0);
    assert_eq!(cold.stats().applied_operations, 0);
    cold.query("listening.podcasts", "getEpisode", json!({"id":"ep"}), NOW)
        .unwrap();
    assert!(source.1.borrow().is_empty());
    let page = success(cold.history("listening.podcasts", 0, 1, NOW).unwrap());
    assert_eq!(page.items.len(), 1);
    assert_eq!(cold.stats().payloads_decrypted, 1);
    cold.history("listening.podcasts", 0, 1, NOW).unwrap();
    assert_eq!(cold.stats().payloads_decrypted, 1);
    for i in 1..39 {
        cold.history("listening.podcasts", i, 1, NOW).unwrap();
        assert!(cold.stats().cached_content_bytes <= 512);
    }
    for capacity in [0, 1] {
        let mut opts = options(&root);
        opts.content_cache_bytes = capacity;
        let mut uncached = Engine::open(
            source.clone(),
            source.listing(),
            owner.public(),
            opts,
            Some(&checkpoint),
        )
        .unwrap();
        unlock_engine(&mut uncached, &owner);
        uncached.history("listening.podcasts", 0, 1, NOW).unwrap();
        uncached.history("listening.podcasts", 0, 1, NOW).unwrap();
        assert_eq!(uncached.stats().payloads_decrypted, 2);
        assert_eq!(uncached.stats().cached_content_bytes, 0);
    }
    let added = write(&mut root, &owner, 50);
    let paths = source.add(added);
    let before = cold.stats();
    cold.apply_paths(paths).unwrap();
    assert_eq!(
        cold.stats().payloads_decrypted - before.payloads_decrypted,
        1
    );
    assert_eq!(
        cold.stats().signatures_verified - before.signatures_verified,
        1
    );
    equal(&mut cold, &root);
    let cp = cold.checkpoint().unwrap();
    let added = write(&mut root, &owner, 51);
    source.add(added);
    let mut suffix = Engine::open(
        source.clone(),
        source.listing(),
        owner.public(),
        options(&root),
        Some(&cp),
    )
    .unwrap();
    unlock_engine(&mut suffix, &owner);
    assert_eq!(suffix.stats().payloads_decrypted, 1);
    assert_eq!(suffix.stats().signatures_verified, 1);
    equal(&mut suffix, &root);
}
#[test]
fn stale_tampered_wrong_identity_version_and_key_fall_back() {
    let (mut root, owner, _) = create();
    for n in 1..6 {
        write(&mut root, &owner, n);
    }
    let first = engine(&root, &owner);
    let cp = first.checkpoint().unwrap();
    let source = first.source().clone();
    let mut altered = cp.clone();
    altered[40] ^= 1;
    let mut version = cp.clone();
    version[7] ^= 1;
    // A correctly authenticated unknown version also falls back, before interpreting its fields.
    let end = version.len() - 32;
    let mut tag = [0; 32];
    hkdf::Hkdf::<sha2::Sha256>::new(Some(&[71; 32]), &version[..end])
        .expand(b"colophon/verified-prefix/2", &mut tag)
        .unwrap();
    version[end..].copy_from_slice(&tag);
    for bytes in [&altered[..], &version[..], &cp[..20]] {
        let mut e = Engine::open(
            source.clone(),
            source.listing(),
            owner.public(),
            options(&root),
            Some(bytes),
        )
        .unwrap();
        assert!(matches!(e.open_mode(), OpenMode::Invalidated(_)));
        unlock_engine(&mut e, &owner);
        equal(&mut e, &root);
    }
    let mut opts = options(&root);
    opts.checkpoint_key = [0; 32];
    let mut e = Engine::open(
        source.clone(),
        source.listing(),
        owner.public(),
        opts,
        Some(&cp),
    )
    .unwrap();
    assert!(matches!(e.open_mode(), OpenMode::Invalidated(_)));
    unlock_engine(&mut e, &owner);
    equal(&mut e, &root);
    let other = keys(22);
    let e = Engine::open(
        source.clone(),
        source.listing(),
        other.public(),
        options(&root),
        Some(&cp),
    )
    .unwrap();
    assert!(matches!(e.open_mode(), OpenMode::Invalidated(_)));
    let removed = source
        .listing()
        .into_iter()
        .find(|p| p.starts_with("ops/"))
        .unwrap();
    source.0.borrow_mut().remove(&removed);
    let rebuilt = opened(source.0.borrow().clone(), &owner);
    let mut e = Engine::open(
        source.clone(),
        source.listing(),
        owner.public(),
        options(&root),
        Some(&cp),
    )
    .unwrap();
    assert!(matches!(e.open_mode(), OpenMode::Invalidated(_)));
    unlock_engine(&mut e, &owner);
    equal(&mut e, &rebuilt);
}
#[test]
fn background_and_history_corruption_are_sticky_integrity_errors() {
    let (mut root, owner, _) = create();
    write(&mut root, &owner, 1);
    let first = engine(&root, &owner);
    let cp = first.checkpoint().unwrap();
    for background in [true, false] {
        let source = Source::new(root.records().clone());
        let mut e = Engine::open(
            source.clone(),
            source.listing(),
            owner.public(),
            options(&root),
            Some(&cp),
        )
        .unwrap();
        unlock_engine(&mut e, &owner);
        let progress = e.verify_batch(1).unwrap();
        assert_eq!(progress.checked, 1);
        let path = source
            .listing()
            .into_iter()
            .find(|p| p.starts_with("ops/"))
            .unwrap();
        source.0.borrow_mut().get_mut(&path).unwrap().push(b' ');
        let error = if background {
            e.verify_batch(100).unwrap_err()
        } else {
            e.history("listening.podcasts", 0, 1, NOW).unwrap_err()
        };
        assert!(error.0.contains("Integrity error"));
        assert!(error.0.contains(&path));
        assert!(e
            .query("listening.podcasts", "read", json!({}), NOW)
            .is_err());
        assert!(e.checkpoint().is_err());
        assert!(e
            .begin_write(
                "listening.podcasts",
                "position",
                json!({"id":"ep","seconds":2}),
                NOW,
                [5; 32]
            )
            .is_err());
    }
    let mut advancing = engine(&root, &owner);
    assert_eq!(advancing.verify_batch(1).unwrap().checked, 1);
    let added = write(&mut root, &owner, 2);
    let paths = advancing.source().add(added);
    advancing.apply_paths(paths).unwrap();
    let progress = advancing.verify_batch(1).unwrap();
    assert_eq!(progress.remaining, advancing.stats().indexed_records - 2);
    let mut e = engine(&root, &owner);
    let mut checked = 0;
    loop {
        let p = e.verify_batch(1).unwrap();
        checked += p.checked;
        if p.remaining == 0 {
            break;
        }
    }
    assert_eq!(checked, root.records().len());
    assert_eq!(e.verify_batch(0).unwrap().checked, 0);
}
#[test]
fn earlier_arrivals_budget_displacement_revocation_and_new_epochs_match_library() {
    let (mut root, owner, _) = create();
    let device = keys(2);
    enroll(
        &mut root,
        &owner,
        &device,
        "Writer",
        MemberKind::Device,
        grant(&["notes", "listening.podcasts"], Some(2)),
        21,
    );
    let mut member = opened(root.records().clone(), &device);
    let mut e = engine(&root, &owner);
    for n in [4, 2, 3, 1] {
        let records = adversarial(
            &root,
            &device,
            &owner,
            "listening.podcasts",
            op(
                "position",
                n,
                root.authority().latest,
                json!({"id":"ep","seconds":n}),
            ),
            1,
            n as u8 + 30,
        );
        root.merge(records.clone()).unwrap();
        let paths = e.source().add(records);
        e.apply_paths(paths).unwrap();
        equal(&mut e, &root);
    }
    // Advance authority on an offline writer: future-authority record is held until its authority arrives.
    let rekey = success(root.begin_rekey(&["notes".into()], NOW, [70; 32]).unwrap());
    let records = finish(rekey, &owner);
    member.merge(records.clone()).unwrap();
    unlock(&mut member, &device);
    let future = adversarial(
        &member,
        &device,
        &owner,
        "listening.podcasts",
        op(
            "position",
            5,
            member.authority().latest,
            json!({"id":"ep","seconds":5}),
        ),
        1,
        75,
    );
    root.merge(future.clone()).unwrap();
    let paths = e.source().add(future);
    e.apply_paths(paths).unwrap();
    equal(&mut e, &root);
    root.merge(records.clone()).unwrap();
    unlock(&mut root, &owner);
    let paths = e.source().add(records);
    e.apply_paths(paths).unwrap();
    unlock_engine(&mut e, &owner);
    equal(&mut e, &root);
    let revoke = success(
        root.begin_revoke(&device.public().id(), NOW, [80; 32])
            .unwrap(),
    );
    let records = finish(revoke, &owner);
    root.merge(records.clone()).unwrap();
    unlock(&mut root, &owner);
    let paths = e.source().add(records);
    e.apply_paths(paths).unwrap();
    unlock_engine(&mut e, &owner);
    equal(&mut e, &root);
    let materialized = e.materialize_library().unwrap();
    assert_eq!(json!(materialized.members()), json!(root.members()));
    assert_eq!(json!(materialized.ledger()), json!(root.ledger()));
    assert!(materialized.checkpoint("notes").is_ok());
    let cp = e.checkpoint().unwrap();
    let source = e.source().clone();
    let mut cold = Engine::open(
        source.clone(),
        source.listing(),
        owner.public(),
        options(&root),
        Some(&cp),
    )
    .unwrap();
    unlock_engine(&mut cold, &owner);
    equal(&mut cold, &root);
}
struct HostVerifier(AtomicUsize);
impl BatchVerifier for HostVerifier {
    fn verify(&self, tasks: &[VerificationTask<'_>]) -> Result<Vec<bool>> {
        self.0.fetch_add(tasks.len(), Ordering::Relaxed);
        Ok(tasks
            .iter()
            .map(|t| {
                SignedRecord {
                    body: t.body.to_vec(),
                    signature: t.signature.to_vec(),
                }
                .verify(t.public_key)
                .is_ok()
            })
            .collect())
    }
}
struct BadCount;
impl BatchVerifier for BadCount {
    fn verify(&self, _: &[VerificationTask<'_>]) -> Result<Vec<bool>> {
        Ok(Vec::new())
    }
}
#[test]
fn host_verifier_does_not_decide_admission_and_failure_is_closed() {
    let (mut root, owner, _) = create();
    write(&mut root, &owner, 1);
    let bad = adversarial(
        &root,
        &owner,
        &owner,
        "listening.podcasts",
        op(
            "position",
            10_000,
            root.authority().latest,
            json!({"id":"ep","seconds":900}),
        ),
        1,
        100,
    );
    root.merge(bad).unwrap();
    let source = Source::new(root.records().clone());
    let verifier = Arc::new(HostVerifier(AtomicUsize::new(0)));
    let mut e = Engine::open_with_verifier(
        source.clone(),
        source.listing(),
        owner.public(),
        options(&root),
        None,
        Some(verifier.clone()),
    )
    .unwrap();
    unlock_engine(&mut e, &owner);
    equal(&mut e, &root);
    assert_eq!(verifier.0.load(Ordering::Relaxed), 2);
    let mut e = Engine::open_with_verifier(
        source.clone(),
        source.listing(),
        owner.public(),
        options(&root),
        None,
        Some(Arc::new(BadCount)),
    )
    .unwrap();
    assert!(e
        .finish_unlock_many(Vec::new())
        .unwrap_err()
        .0
        .contains("result count"));
    assert!(e
        .query("listening.podcasts", "read", json!({}), NOW)
        .is_err());
}
#[test]
fn shuffled_refresh_and_noop_match_rebuild() {
    let (mut root, owner, _) = create();
    let base = root.records().clone();
    let operations: Vec<_> = (1..30).map(|n| write(&mut root, &owner, n)).collect();
    let mut expected = opened(base, &owner);
    let mut e = engine(&expected, &owner);
    for i in (0..29).map(|i| (i * 17) % 29) {
        expected.merge(operations[i].clone()).unwrap();
        e.source().add(operations[i].clone());
        e.refresh(e.source().listing()).unwrap();
        equal(&mut e, &expected);
    }
    let before = e.stats();
    assert!(e
        .refresh(e.source().listing())
        .unwrap()
        .namespaces
        .is_empty());
    assert_eq!(e.stats().payloads_decrypted, before.payloads_decrypted);
    assert!(e.apply_paths(Vec::new()).unwrap().namespaces.is_empty());
}

#[test]
fn duplicates_invalid_signatures_and_partial_unlock_keep_reference_semantics() {
    use colophon_core::{library::operation_path, model::OperationHeader};
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
    root.merge(original.clone()).unwrap();
    let raw = original.values().next().unwrap();
    for clock in [1, 3] {
        let bad = resign(raw, &agent, |v| v["clock"] = json!(clock));
        let signed: SignedRecord = serde_json::from_slice(&bad).unwrap();
        let header: OperationHeader = serde_json::from_slice(&signed.body).unwrap();
        root.merge(Records::from([(operation_path(&header.meta), bad)]))
            .unwrap();
    }
    // Fill a native parallel batch, including a rejected signature at the end.
    for n in 1..=140 {
        let records = adversarial(
            &root,
            &owner,
            &owner,
            "listening.podcasts",
            op(
                "position",
                n,
                root.authority().latest,
                json!({"id":"ep","seconds":n}),
            ),
            1,
            n as u8,
        );
        root.merge(records).unwrap();
    }
    let mut bad = adversarial(
        &root,
        &owner,
        &owner,
        "notes",
        op("future", 1, root.authority().latest, json!({})),
        1,
        160,
    );
    for raw in bad.values_mut() {
        let mut signed: SignedRecord = serde_json::from_slice(raw).unwrap();
        signed.signature[0] ^= 128;
        *raw = signed.encode().unwrap();
    }
    root.merge(bad).unwrap();
    let mut e = engine(&root, &owner);
    equal(&mut e, &root);
    let cp = e.checkpoint().unwrap();
    let source = e.source().clone();
    let mut cold = Engine::open(
        source.clone(),
        source.listing(),
        owner.public(),
        options(&root),
        Some(&cp),
    )
    .unwrap();
    // A restored projection cannot expose data while its current key remains locked.
    cold.finish_unlock_many(Vec::new()).unwrap();
    assert!(matches!(
        cold.query("notes", "read", json!({}), NOW).unwrap(),
        colophon_core::model::Outcome::Failure { .. }
    ));
    unlock_engine(&mut cold, &owner);
    equal(&mut cold, &root);
    let valid = cold.verify_batch(usize::MAX).unwrap();
    assert_eq!(valid.remaining, 0);
}

#[test]
fn removed_paths_missing_bytes_and_conflicting_explicit_deltas_fail_as_documented() {
    let (mut root, owner, _) = create();
    write(&mut root, &owner, 1);
    let mut e = engine(&root, &owner);
    let source = e.source().clone();
    let path = source
        .listing()
        .into_iter()
        .find(|p| p.starts_with("ops/"))
        .unwrap();
    source.0.borrow_mut().remove(&path);
    assert!(e
        .verify_batch(usize::MAX)
        .unwrap_err()
        .0
        .contains("Integrity error"));
    let mut e = engine(&root, &owner);
    let source = e.source().clone();
    source.0.borrow_mut().get_mut(&path).unwrap().push(b' ');
    assert!(e
        .apply_paths(vec![path])
        .unwrap_err()
        .0
        .contains("Integrity error"));
    assert!(e.checkpoint().is_err());
}

#[test]
fn invalidation_does_not_erase_authenticated_immutability_evidence() {
    let (mut root, owner, _) = create();
    write(&mut root, &owner, 1);
    let first = engine(&root, &owner);
    let cp = first.checkpoint().unwrap();
    let rekey = success(root.begin_rekey(&["notes".into()], NOW, [89; 32]).unwrap());
    let added = finish(rekey, &owner);
    for authority_tamper in [false, true] {
        let source = Source::new(root.records().clone());
        source.add(added.clone());
        let path = source
            .listing()
            .into_iter()
            .find(|p| {
                p.starts_with(if authority_tamper {
                    "authority/"
                } else {
                    "ops/"
                })
            })
            .unwrap();
        // Whitespace leaves signature validation intact, but violates exact-envelope immutability.
        source.0.borrow_mut().get_mut(&path).unwrap().push(b' ');
        let opened = Engine::open(
            source.clone(),
            source.listing(),
            owner.public(),
            options(&root),
            Some(&cp),
        );
        if authority_tamper {
            assert!(opened.err().unwrap().0.contains("Integrity error"));
        } else {
            let mut e = opened.unwrap();
            let results = e
                .begin_unlock()
                .into_iter()
                .map(|s| (s.namespace, s.epoch, owner.agree(&s.peer).unwrap()))
                .collect();
            let error = e.finish_unlock_many(results).unwrap_err();
            assert!(error.0.contains("Integrity error"));
            assert!(error.0.contains(&path));
            assert!(e.checkpoint().is_err());
        }
    }
}

#[test]
fn all_domain_vectors_restore_without_reads_and_fetch_history_lazily() {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use serde_json::Value;
    let folder = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance/0.3");
    let read = |name: &str| -> Value {
        serde_json::from_slice(&std::fs::read(folder.join(name)).unwrap()).unwrap()
    };
    for (ns, record_file, expected_file, seed) in [
        (
            "reading.books",
            "reading.books/records.json",
            "reading.books/expected.json",
            5,
        ),
        ("notes", "notes.json", "notes.json", 1),
        (
            "reading.saved",
            "reading.saved.json",
            "reading.saved.json",
            1,
        ),
        (
            "listening.podcasts",
            "listening.podcasts.records.json",
            "listening.podcasts.expected.json",
            1,
        ),
    ] {
        let vector = read(record_file);
        let records = vector
            .get("records")
            .unwrap_or(&vector)
            .as_object()
            .unwrap()
            .iter()
            .map(|(p, b)| (p.clone(), STANDARD.decode(b.as_str().unwrap()).unwrap()))
            .collect();
        let owner = keys(seed);
        let lib = opened(records, &owner);
        let first = engine(&lib, &owner);
        let cp = first.checkpoint().unwrap();
        let source = first.source().clone();
        source.1.borrow_mut().clear();
        let mut cold = Engine::open(
            source.clone(),
            source.listing(),
            owner.public(),
            options(&lib),
            Some(&cp),
        )
        .unwrap();
        unlock_engine(&mut cold, &owner);
        assert_eq!(cold.open_mode(), &OpenMode::VerifiedPrefix, "{ns}");
        let expected = read(expected_file);
        for q in expected
            .get("queries")
            .unwrap_or(&expected)
            .as_array()
            .unwrap()
        {
            let name = q.get("name").unwrap_or(&q["query"]).as_str().unwrap();
            let args = q.get("args").unwrap_or(&q["arguments"]).clone();
            let result = q.get("result").unwrap_or(&q["expected"]);
            let mut got = success(cold.query(ns, name, args, NOW).unwrap());
            let mut expected_row = result.clone();
            strip_live_revisions(&mut got);
            strip_live_revisions(&mut expected_row);
            assert_eq!(&got, &expected_row, "{ns}/{name}");
        }
        assert!(source.1.borrow().is_empty(), "{ns} queries fetched history");
        assert_eq!(cold.stats().applied_operations, 0);
        assert_eq!(cold.stats().payloads_decrypted, 0);
        let page = success(cold.history(ns, 0, 1, NOW).unwrap());
        assert_eq!(
            json!(page.items),
            json!(success(lib.view(ns, NOW).unwrap()).admitted[..1])
        );
        assert_eq!(source.1.borrow().len(), 1);
        assert_eq!(cold.stats().payloads_decrypted, 1);
        equal(&mut cold, &lib);
    }
}

#[test]
fn four_domain_writes_and_suffix_replay_share_the_registered_reducers() {
    let owner = keys(1);
    let pending = Library::begin_create(
        colophon_core::library::CreateOptions {
            owner: owner.public(),
            recovery: keys(9).public(),
            label: "Four domains".into(),
            owner_label: "Owner".into(),
            namespaces: colophon_core::domain::NAMESPACES
                .iter()
                .map(|ns| (*ns).into())
                .collect(),
        },
        NOW,
        [10; 32],
    )
    .unwrap();
    let mut lib = opened(finish(pending, &owner), &owner);
    let mut live = engine(&lib, &owner);
    let cp = live.checkpoint().unwrap();
    for (i, (ns, kind, payload)) in [
        (
            "reading.books",
            "addBook",
            json!({"id":"book","title":"Book","creator":"Writer"}),
        ),
        (
            "reading.saved",
            "capture",
            json!({"id":"saved","url":"https://example.org"}),
        ),
        (
            "notes",
            "createNotebook",
            json!({"id":"notebook","title":"Notebook"}),
        ),
        (
            "listening.podcasts",
            "follow",
            json!({"id":"show","url":"https://example.org/feed"}),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let pending = success(
            live.begin_write(ns, kind, payload, NOW, [i as u8 + 30; 32])
                .unwrap(),
        );
        let records = finish(pending, &owner);
        lib.merge(records.clone()).unwrap();
        let paths = live.source().add(records);
        live.apply_paths(paths).unwrap();
    }
    assert_eq!(live.stats().applied_operations, 4);
    let source = live.source().clone();
    source.1.borrow_mut().clear();
    let mut suffix = Engine::open(
        source.clone(),
        source.listing(),
        owner.public(),
        options(&lib),
        Some(&cp),
    )
    .unwrap();
    unlock_engine(&mut suffix, &owner);
    assert_eq!(suffix.open_mode(), &OpenMode::VerifiedPrefix);
    assert_eq!(suffix.stats().records_read, 4);
    assert_eq!(suffix.stats().signatures_verified, 4);
    assert_eq!(suffix.stats().payloads_decrypted, 4);
    assert_eq!(suffix.stats().applied_operations, 4);
    equal(&mut suffix, &lib);
    equal(&mut live, &lib);
}

#[test]
fn authenticated_roles_survive_storage_append_and_checkpoint_suffix_without_query_reads() {
    let (mut lib, owner, _) = create();
    let agent = keys(7);
    let server = keys(8);
    for (member, kind, seed) in [
        (&agent, MemberKind::Agent, 81),
        (&server, MemberKind::Server, 82),
    ] {
        enroll(
            &mut lib,
            &owner,
            member,
            "Worker",
            kind,
            grant(&["listening.podcasts"], None),
            seed,
        );
    }
    let mut live = engine(&lib, &owner);
    let source = live.source().clone();
    let ns = "listening.podcasts";
    let audio = json!({"digest":"a".repeat(64),"size":12,"mediaType":"application/json"});
    let request = json!({"id":"job","episode":"e","show":"s","worker":agent.public().id(),
        "audio":audio,"recording":"a".repeat(64),"language":"en"});
    let records = finish(
        success(
            lib.begin_write(ns, "requestTranscript", request.clone(), NOW, [83; 32])
                .unwrap(),
        ),
        &owner,
    );
    lib.merge(records.clone()).unwrap();
    live.apply_paths(source.add(records)).unwrap();
    let jobs = success(
        live.query(ns, "jobs", json!({"kind":"transcript"}), NOW)
            .unwrap(),
    );
    assert_eq!(jobs["value"]["total"], 1);
    let checkpoint = live.checkpoint().unwrap();
    let agent_lib = opened(lib.records().clone(), &agent);
    let response =
        json!({"id":"job","request":jobs["value"]["rows"][0]["requestRevision"],"result":audio});
    let records = finish(
        success(
            agent_lib
                .begin_write(ns, "supplyTranscript", response, NOW, [84; 32])
                .unwrap(),
        ),
        &agent,
    );
    lib.merge(records.clone()).unwrap();
    live.apply_paths(source.add(records)).unwrap();
    let server_lib = opened(lib.records().clone(), &server);
    let mut forbidden = request;
    forbidden["id"] = json!("forbidden");
    let records = finish(
        success(
            server_lib
                .begin_write(ns, "requestTranscript", forbidden, NOW, [85; 32])
                .unwrap(),
        ),
        &server,
    );
    lib.merge(records.clone()).unwrap();
    live.apply_paths(source.add(records)).unwrap();
    let mut suffix = Engine::open(
        source.clone(),
        source.listing(),
        owner.public(),
        options(&lib),
        Some(&checkpoint),
    )
    .unwrap();
    unlock_engine(&mut suffix, &owner);
    assert_eq!(suffix.open_mode(), &OpenMode::VerifiedPrefix);
    assert_eq!(suffix.stats().records_read, 2);
    assert_eq!(suffix.stats().payloads_decrypted, 2);
    assert_eq!(suffix.stats().applied_operations, 2);
    let rebuilt = engine(&lib, &owner);
    source.1.borrow_mut().clear();
    for replica in [&live, &suffix, &rebuilt] {
        let jobs = success(
            replica
                .query(ns, "jobs", json!({"kind":"transcript"}), NOW)
                .unwrap(),
        );
        assert_eq!(jobs["value"]["total"], 1);
        assert!(jobs["value"]["rows"][0]["responseRevision"].is_string());
        assert_eq!(
            jobs,
            success(
                lib.query(ns, "jobs", json!({"kind":"transcript"}), NOW)
                    .unwrap()
            )
        );
        let conflicts = success(
            replica
                .query(ns, "conflicts", json!({"object":"forbidden"}), NOW)
                .unwrap(),
        );
        assert_eq!(conflicts["value"]["total"], 1);
        assert_eq!(conflicts["value"]["rows"][0]["outcome"], "roleDenied");
    }
    assert!(
        source.1.borrow().is_empty(),
        "named queries fetched history"
    );
}

#[test]
fn authenticated_old_reducer_schemas_fall_back_to_full_replay() {
    let (mut lib, owner, _) = create();
    write(&mut lib, &owner, 1);
    let first = engine(&lib, &owner);
    let cp = first.checkpoint().unwrap();
    let length = u32::from_le_bytes(cp[8..12].try_into().unwrap()) as usize;
    let original: serde_json::Value = serde_json::from_slice(&cp[12..12 + length]).unwrap();
    for schema in [None, Some(json!(1)), Some(json!(2)), Some(json!(999))] {
        let mut meta = original.clone();
        match schema {
            Some(value) => {
                meta["reducer_schema"] = value;
            }
            None => {
                meta.as_object_mut().unwrap().remove("reducer_schema");
            }
        }
        let bytes = serde_json::to_vec(&meta).unwrap();
        let mut old = cp[..8].to_vec();
        old.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        old.extend(bytes);
        old.extend_from_slice(&cp[12 + length..cp.len() - 32]);
        let mut tag = [0; 32];
        hkdf::Hkdf::<sha2::Sha256>::new(Some(&[71; 32]), &old)
            .expand(b"colophon/verified-prefix/2", &mut tag)
            .unwrap();
        old.extend(tag);
        let source = first.source().clone();
        let mut cold = Engine::open(
            source.clone(),
            source.listing(),
            owner.public(),
            options(&lib),
            Some(&old),
        )
        .unwrap();
        assert!(matches!(cold.open_mode(), OpenMode::Invalidated(_)));
        unlock_engine(&mut cold, &owner);
        assert_eq!(cold.stats().signatures_verified, 1);
        assert_eq!(cold.stats().applied_operations, 1);
        equal(&mut cold, &lib);
    }
}

#[test]
fn parallel_domain_reduction_keeps_global_budget_admission_and_stream_order() {
    let (mut lib, owner, _) = create();
    let device = keys(2);
    enroll(
        &mut lib,
        &owner,
        &device,
        "Budgeted device",
        MemberKind::Device,
        grant(&["reading.saved", "notes", "listening.podcasts"], Some(400)),
        21,
    );
    let mut replica = engine(&lib, &owner);
    let mut batch = Records::new();
    for i in 0..600 {
        let (ns, kind, payload) = match i % 3 {
            0 => (
                "listening.podcasts",
                "requestTranscript",
                json!({"id":format!("job{i}"),"episode":"episode","show":"show",
                    "worker":device.public().id(),"audio":{"digest":"a".repeat(64),"size":12,"mediaType":"application/json"},
                    "recording":"a".repeat(64),"language":"en"}),
            ),
            1 => (
                "reading.saved",
                "capture",
                json!({"id":format!("link{i}"),"url":"https://example.org"}),
            ),
            _ => (
                "notes",
                "createNotebook",
                json!({"id":format!("notebook{i}"),"title":"Notebook"}),
            ),
        };
        batch.extend(adversarial(
            &lib,
            &owner,
            &device,
            ns,
            op(kind, i + 1, lib.authority().latest, payload),
            1,
            i as u8,
        ));
    }
    lib.merge(batch.clone()).unwrap();
    let paths = replica.source().add(batch);
    replica.apply_paths(paths).unwrap();
    assert_eq!(replica.stats().applied_operations, 400);
    let jobs = success(
        replica
            .query(
                "listening.podcasts",
                "jobs",
                json!({"kind":"transcript"}),
                NOW,
            )
            .unwrap(),
    );
    assert_eq!(jobs["value"]["total"], 134);
    equal(&mut replica, &lib);
    let cp = replica.checkpoint().unwrap();
    let source = replica.source().clone();
    let mut cold = Engine::open(
        source.clone(),
        source.listing(),
        owner.public(),
        options(&lib),
        Some(&cp),
    )
    .unwrap();
    unlock_engine(&mut cold, &owner);
    assert_eq!(cold.stats().records_read, 0);
    equal(&mut cold, &lib);
}
