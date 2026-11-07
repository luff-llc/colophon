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
