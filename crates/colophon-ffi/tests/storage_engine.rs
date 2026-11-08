#![allow(clippy::unwrap_used)]
#[path = "../../colophon-core/tests/support/mod.rs"]
mod support;
use colophon_ffi::*;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use support::*;
#[derive(Clone)]
struct Source(Arc<Mutex<Records>>);
impl EngineRecordSource for Source {
    fn read(&self, path: String) -> colophon_ffi::Result<Vec<u8>> {
        self.0
            .lock()
            .unwrap()
            .get(&path)
            .cloned()
            .ok_or(BindingError::InvalidData {
                detail: format!("Missing {path}"),
            })
    }
}
fn public(keys: &colophon_core::crypto::SoftwareKeys) -> PublicKeys {
    PublicKeys {
        signing: keys.public().signing,
        agreement: keys.public().agreement,
    }
}
fn ready(engine: &NativeEngine, keys: &colophon_core::crypto::SoftwareKeys) {
    let results = engine
        .begin_unlock()
        .unwrap()
        .into_iter()
        .map(|step| UnlockResult {
            shared: keys.agree(&step.peer).unwrap(),
            step,
        })
        .collect();
    engine.finish_unlock_many(results).unwrap();
}
#[test]
fn protected_prefix_suffix_versions_and_stale_actions() {
    let (mut library, owner, _) = create();
    write(
        &mut library,
        &owner,
        "notes",
        "createNotebook",
        serde_json::json!({"id":"n","title":"N"}),
        1,
    );
    let source = Source(Arc::new(Mutex::new(
        library.records().clone().into_iter().collect(),
    )));
    let listing = source.0.lock().unwrap().keys().cloned().collect::<Vec<_>>();
    let versions = listing
        .iter()
        .map(|p| (p.clone(), "1".into()))
        .collect::<HashMap<_, _>>();
    let key = NativeCheckpointPreparation::new(library.id().into(), public(&owner), vec![81; 32])
        .unwrap();
    let key = key
        .finish(owner.sign(&key.signing_body().unwrap()))
        .unwrap();
    let engine = NativeEngine::open(
        Box::new(source.clone()),
        listing.clone(),
        versions.clone(),
        public(&owner),
        library.id().into(),
        vec![],
        key,
    )
    .unwrap();
    ready(&engine, &owner);
    let checkpoint = engine.checkpoint(vec![82; 32]).unwrap();
    let opening =
        NativeCheckpointOpening::new(checkpoint, library.id().into(), public(&owner)).unwrap();
    let key = opening
        .finish(owner.agree(&opening.agreement_peer().unwrap()).unwrap())
        .unwrap();
    let restored = NativeEngine::open(
        Box::new(source.clone()),
        listing,
        versions.clone(),
        public(&owner),
        library.id().into(),
        vec![],
        key,
    )
    .unwrap();
    ready(&restored, &owner);
    let work = restored.work().unwrap();
    assert_eq!(work.open_mode, "VerifiedPrefix");
    assert_eq!(work.signatures_verified, 0);
    assert_eq!(work.payloads_decrypted, 0);
    let prepare = |id: &str, seed: u8| match restored
        .begin_write(
            "notes".into(),
            "addNote".into(),
            serde_json::to_vec(&serde_json::json!({"id":id,"notebook":"n","text":id})).unwrap(),
            NOW.into(),
            vec![seed; 32],
        )
        .unwrap()
    {
        PreparedAction::Ready { action } => action,
        _ => panic!("denied"),
    };
    let first = prepare("first", 83);
    let stale = prepare("stale", 84);
    let signatures = first
        .signing_steps()
        .iter()
        .map(|s| owner.sign(&s.body))
        .collect();
    restored.commit(first.clone(), signatures).unwrap();
    let signatures = stale
        .signing_steps()
        .iter()
        .map(|s| owner.sign(&s.body))
        .collect();
    assert!(matches!(
        restored.commit(stale, signatures),
        Err(BindingError::StaleAction)
    ));
    let path = first
        .record_paths()
        .into_iter()
        .find(|p| p.starts_with("ops/"))
        .unwrap();
    assert!(matches!(
        restored
            .operation_at(path, "notes".into(), NOW.into())
            .unwrap(),
        OperationOutcome::Success { .. }
    ));
    assert_eq!(restored.work().unwrap().applied_operations, 1);
    // A changed provider token cannot keep the verified-prefix signature/decryption shortcut.
    let path = source
        .0
        .lock()
        .unwrap()
        .keys()
        .find(|p| p.starts_with("ops/"))
        .unwrap()
        .clone();
    let bytes = source.0.lock().unwrap()[&path].clone();
    restored
        .merge_observed(
            Records::from([(path.clone(), bytes)]),
            HashMap::from([(path, "2".into())]),
        )
        .unwrap();
    assert!(restored.work().unwrap().signatures_verified >= 3);
    assert!(restored
        .query(
            "notes".into(),
            "note".into(),
            br#"{"id":"first"}"#.to_vec(),
            NOW.into()
        )
        .is_ok());
}

#[test]
fn third_review_observed_bytes_do_not_mask_provider_or_replay_twice() {
    let (library, owner, _) = create();
    let source = Source(Arc::new(Mutex::new(
        library.records().clone().into_iter().collect(),
    )));
    let key = NativeCheckpointPreparation::new(library.id().into(), public(&owner), vec![81; 32])
        .unwrap();
    let key = key
        .finish(owner.sign(&key.signing_body().unwrap()))
        .unwrap();
    let listing = source.0.lock().unwrap().keys().cloned().collect();
    let engine = NativeEngine::open(
        Box::new(source.clone()),
        listing,
        HashMap::new(),
        public(&owner),
        library.id().into(),
        vec![],
        key,
    )
    .unwrap();
    ready(&engine, &owner);
    let old = live_at(&library, &owner, 1, 10, 84);
    source.0.lock().unwrap().extend(old.clone());
    engine
        .merge_observed(old.into_iter().collect(), HashMap::new())
        .unwrap();
    ready(&engine, &owner);
    let fresh = live_at(&library, &owner, 2, 20, 85);
    source.0.lock().unwrap().extend(fresh);
    let batch = success(
        library
            .begin_rekey(&["notes".into()], NOW, [86; 32])
            .unwrap(),
    );
    let authority = finish(batch, &owner);
    source.0.lock().unwrap().extend(authority.clone());
    let before = engine.work().unwrap();
    engine
        .merge_observed(authority.into_iter().collect(), HashMap::new())
        .unwrap();
    ready(&engine, &owner);
    let episode = engine
        .query(
            "listening.podcasts".into(),
            "getEpisode".into(),
            br#"{"id":"ep"}"#.to_vec(),
            NOW.into(),
        )
        .unwrap();
    let text = format!("{episode:?}");
    // JSON is returned as bytes by the FFI outcome.
    match episode {
        JsonOutcome::Success { value: json, .. } => {
            let value: serde_json::Value = serde_json::from_slice(&json).unwrap();
            assert_eq!(value["seconds"], 20.0);
        }
        _ => panic!("{text}"),
    }
    assert_eq!(
        engine.work().unwrap().signatures_verified - before.signatures_verified,
        1
    );
    engine.checkpoint(vec![87; 32]).unwrap();
}

#[test]
fn third_review_observed_immutable_bytes_are_released_for_audit() {
    let (mut library, owner, _) = create();
    let source = Source(Arc::new(Mutex::new(
        library.records().clone().into_iter().collect(),
    )));
    let listing = source.0.lock().unwrap().keys().cloned().collect();
    let key = NativeCheckpointPreparation::new(library.id().into(), public(&owner), vec![91; 32])
        .unwrap();
    let key = key
        .finish(owner.sign(&key.signing_body().unwrap()))
        .unwrap();
    let engine = NativeEngine::open(
        Box::new(source.clone()),
        listing,
        HashMap::new(),
        public(&owner),
        library.id().into(),
        vec![],
        key,
    )
    .unwrap();
    ready(&engine, &owner);
    write(
        &mut library,
        &owner,
        "notes",
        "createNotebook",
        serde_json::json!({"id":"n","title":"N"}),
        92,
    );
    let records: Records = library
        .records()
        .iter()
        .filter(|(path, _)| path.starts_with("ops/"))
        .map(|(path, raw)| (path.clone(), raw.clone()))
        .collect();
    let path = records.keys().next().unwrap().clone();
    source.0.lock().unwrap().extend(records.clone());
    engine.merge_observed(records, HashMap::new()).unwrap();
    source.0.lock().unwrap().remove(&path);
    assert!(
        engine.verify_batch(128).is_err(),
        "an audit must fetch the provider, not retained observed bytes"
    );
}
