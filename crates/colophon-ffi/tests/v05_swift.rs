//! A real Swift keyring library (the fixture the shipped Swift code produced, `conformance/
//! keyring`) read, opened and copied through the exports: the slots of the keyring, the vault
//! opened from the host's ECDH result, the namespace keys, a copy plan over its records with a
//! typed host translator, the plan's omissions and writes. The steps that need a verified 0.5
//! successor of this library (the succession window, veto, F, the import writes, the migration)
//! are exported on `AccountEngine` and are NOT run here: building a successor account with its
//! homes and receipts is `v05_swift_journey` in the core's own tests, and no such fixture is
//! built in this crate (see docs/bindings-05.md, "What was run").
#![allow(clippy::unwrap_used)]
mod v05_support;
use colophon_core::crypto::SoftwareKeys;
use colophon_core::v05::encoding::decode_base64;
use serde_json::Value;
use std::path::PathBuf;
use std::sync::Mutex;
use v05_support::*;

fn strip(mut b: Vec<u8>) -> Vec<u8> {
    if b.last() == Some(&b'\n') {
        b.pop();
    }
    b
}

struct Translator {
    seen: Mutex<Vec<String>>,
}
impl SwiftTranslator for Translator {
    fn translate(&self, op: SwiftOpInfo) -> Result<SwiftBatch, AccountError> {
        self.seen.lock().unwrap().push(op.kind.clone());
        if op.kind != "capture.link" {
            return Err(AccountError::host("this test translates only capture.link"));
        }
        let p: Value = serde_json::from_str(&op.payload_json).unwrap();
        Ok(SwiftBatch {
            children: vec![SwiftChild {
                key: "c".into(),
                kind: "capture".into(),
                payload_json:
                    serde_json::json!({"id": p["item"], "title": p["title"], "url": p["url"]})
                        .to_string(),
                baseline: false,
            }],
            alternatives_json: vec![],
            identities: vec![],
            blobs_json: vec![],
            outcome: "applied".into(),
            evidence_json: String::new(),
        })
    }
}

#[test]
fn a_real_swift_library_is_opened_and_planned_through_the_exports() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/keyring");
    let keys: Value =
        serde_json::from_slice(&std::fs::read(root.join("keys.json")).unwrap()).unwrap();
    let mut files: Vec<_> = std::fs::read_dir(root.join("library/authority"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    files.sort();
    let entries: Vec<ByteString> = files
        .iter()
        .map(|p| ByteString {
            bytes: strip(std::fs::read(p).unwrap()),
        })
        .collect();
    let src = SwiftSource::read(entries).unwrap();
    assert_eq!(src.library().unwrap(), "1e00224caf4fe010167787ad3e943480");
    assert!(src.problems().unwrap().is_empty());
    let slots = src.slots().unwrap();
    assert_eq!(
        slots.iter().map(|s| s.kind).collect::<Vec<_>>(),
        [
            SlotKind::Sealed,
            SlotKind::Prf,
            SlotKind::Sealed,
            SlotKind::Sealed
        ]
    );
    // The owner slot is sealed to an app key: the host answers the ECDH with that key.
    let scalar = decode_base64(keys["owner"]["agreementKey"].as_str().unwrap(), 64).unwrap();
    let owner = SoftwareKeys::from_scalars(&scalar, &scalar).unwrap();
    let inputs = src.begin_open_slot(0).unwrap();
    assert_eq!(inputs[0].kind, UnlockKind::Ecdh);
    // A wrong answer is the typed vaultLocked refusal and opens nothing.
    let bad = src.finish_open_slot(
        0,
        vec![UnlockSecret {
            kind: UnlockKind::Ecdh,
            secret: vec![7; 32],
        }],
    );
    assert!(
        matches!(bad, Err(AccountError::Refused { ref reason, .. }) if reason == "vaultLocked"),
        "{bad:?}"
    );
    assert!(src.open_namespace_keys().is_err(), "no vault yet");
    src.finish_open_slot(
        0,
        vec![UnlockSecret {
            kind: UnlockKind::Ecdh,
            secret: owner.agree(&inputs[0].enc).unwrap(),
        }],
    )
    .unwrap();
    assert!(src.open_namespace_keys().unwrap() >= 1);
    assert!(src
        .epochs()
        .unwrap()
        .iter()
        .any(|e| e.namespace == "reading.saved" && e.epoch == 1));
    // The host's translator turns the real Swift operations into clean children.
    let read = |p: &str| Store {
        path: p.into(),
        bytes: strip(std::fs::read(root.join("library").join(p)).unwrap()),
    };
    let files = vec![
        read("ops/01ff15365188f6561c4c3bc10730a40e/000000000001-cdc1b6a7-765a-4d0d-843f-4b1fdfa5c90f.json"),
        read("ops/b2707a6b90c9551123761aec860bc888/000000000002-e72ef974-83b0-4bf7-9855-b3959fd217eb.json"),
    ];
    let tr = std::sync::Arc::new(Translator {
        seen: Mutex::new(vec![]),
    });
    struct Shared(std::sync::Arc<Translator>);
    impl SwiftTranslator for Shared {
        fn translate(&self, op: SwiftOpInfo) -> Result<SwiftBatch, AccountError> {
            self.0.translate(op)
        }
    }
    let plan = SwiftCopyPlan::read(
        src.clone(),
        files,
        Some(Box::new(Shared(tr.clone()))),
        SwiftCopyDestination::empty(),
    )
    .unwrap();
    assert_eq!(plan.library().unwrap(), "1e00224caf4fe010167787ad3e943480");
    assert_eq!(
        tr.seen.lock().unwrap().len(),
        2,
        "each operation was translated once"
    );
    assert!(plan.omissions().unwrap().is_empty(), "both are copied");
    assert_eq!(plan.pending().unwrap(), 2);
    let batch = plan.next_batch(10).unwrap();
    assert_eq!(batch.len(), 2);
    for b in &batch {
        let p: Value = serde_json::from_str(&b.payload_json).unwrap();
        assert_eq!(
            p["evidence"]["sourceLibrary"],
            "1e00224caf4fe010167787ad3e943480"
        );
        assert_eq!(p["children"][0]["kind"], "capture");
    }
    assert!(plan
        .source_counts()
        .unwrap()
        .iter()
        .any(|c| c.namespace == "reading.saved" && c.count == 2));
    assert!(!src.members().unwrap().is_empty());
    // A translator that fails omits its record with the host's reason, never silently.
    let files = vec![read("ops/01ff15365188f6561c4c3bc10730a40e/000000000001-cdc1b6a7-765a-4d0d-843f-4b1fdfa5c90f.json")];
    struct Refuses;
    impl SwiftTranslator for Refuses {
        fn translate(&self, _: SwiftOpInfo) -> Result<SwiftBatch, AccountError> {
            Err(AccountError::host("no mapping for this kind"))
        }
    }
    let p2 = SwiftCopyPlan::read(
        src,
        files,
        Some(Box::new(Refuses)),
        SwiftCopyDestination::empty(),
    )
    .unwrap();
    let om = p2.omissions().unwrap();
    assert_eq!(om.len(), 1);
    assert!(om[0].reason.contains("no mapping"), "{}", om[0].reason);
}
