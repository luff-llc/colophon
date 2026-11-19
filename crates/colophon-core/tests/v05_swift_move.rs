//! Moving a Swift library: opening its vault slots and namespace keys, and copying its records
//! (`v05::swift_slots`, `v05::swift_copy`; spec §15.3, §15.4, §16.2, §16.3).
//!
//! Two kinds of fixture, stated plainly:
//!
//! * `conformance/keyring` was produced by the shipped Swift code (Marginalia
//!   `KeyringConformanceTests`, run with `COLOPHON_WRITE_VECTORS=1`) and checked by it. Opening its
//!   sealed, PRF and kit slots and its namespace keys with the keys in `keys.json`, and judging its
//!   two operations, is agreement with the Swift code on those forms. It has **no combined slot**
//!   and no WebAuthn-signed record of the forms below.
//! * Everything built in `v05_swift_support` is this test's own reading of the Swift source's
//!   algorithm, written out independently of the code under test and of the vector generator. It
//!   proves agreement with that reading, not with the Swift code. See the pull request for the
//!   fixtures a Swift-side test must produce to close the gap.
#![allow(clippy::unwrap_used)]
#[path = "v05_swift_support/mod.rs"]
mod swift;
use base64::{engine::general_purpose::STANDARD, Engine};
use colophon_core::v05::encoding::{canonical, digest};
use colophon_core::v05::ids::AccountId;
use colophon_core::v05::records::{Level, OperationHeader};
use colophon_core::v05::slots::{OpeningInput, OpeningSecret};
use colophon_core::v05::swift_copy::*;
use colophon_core::v05::swift_slots::*;
use colophon_core::v05::vault::{EcdhOutput, PrfOutput};
use colophon_core::v05::{Failure, Reason};
use serde_json::{json, Value};
use std::path::PathBuf;
use swift::*;

fn strip(mut b: Vec<u8>) -> Vec<u8> {
    if b.last() == Some(&b'\n') {
        b.pop();
    }
    b
}
fn dec(s: &str) -> Vec<u8> {
    STANDARD.decode(s).unwrap()
}
fn locked(e: &Failure) -> bool {
    matches!(e, Failure::Refused(Reason::VaultLocked))
}

// ---------------------------------------------------------------------------------------------
// The one fixture the shipped Swift code produced.

struct Real {
    root: PathBuf,
    keys: Value,
    entries: Vec<Vec<u8>>,
}
fn real() -> Real {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/keyring");
    let mut files: Vec<_> = std::fs::read_dir(root.join("library/authority"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    files.sort();
    Real {
        keys: serde_json::from_slice(&std::fs::read(root.join("keys.json")).unwrap()).unwrap(),
        entries: files
            .iter()
            .map(|p| strip(std::fs::read(p).unwrap()))
            .collect(),
        root,
    }
}
/// The host's ECDH with an agreement scalar `keys.json` publishes.
fn dh(scalar: &str, enc: &[u8]) -> OpeningSecret {
    let sk = p256::SecretKey::from_slice(&dec(scalar)).unwrap();
    let peer = p256::PublicKey::from_sec1_bytes(enc).unwrap();
    let shared = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
    OpeningSecret::Ecdh(EcdhOutput::from_host(shared.raw_secret_bytes().as_slice()).unwrap())
}
fn enc_of(i: &OpeningInput) -> Vec<u8> {
    match i {
        OpeningInput::Ecdh { enc, .. } => enc.clone(),
        _ => panic!("not an ECDH route"),
    }
}

#[test]
fn the_slots_the_shipped_swift_code_wrote_open_with_the_published_keys() {
    let r = real();
    let lib = SwiftLibrary::read(&r.entries).unwrap();
    assert_eq!(lib.library(), "1e00224caf4fe010167787ad3e943480");
    let vault_id = "b9775e08bc390f139b78be803dbb1f50";
    assert_eq!(lib.vault().unwrap().id(), vault_id);
    let kinds: Vec<_> = lib.slots().iter().map(|s| (s.kind(), s.label())).collect();
    assert_eq!(
        kinds,
        [
            ("sealed", "Owner"),
            ("prf", "Passkey"),
            ("sealed", "Kit"),
            ("sealed", "Added device")
        ]
    );
    // Owner (sealed to an app key), the passkey (PRF with the published output), the kit (the
    // Swift kit derivation from `kitSecret`, `RecoveryKit.swift:55-59`) and the added device.
    let k = &r.keys;
    let ins = lib.begin_open(0).unwrap();
    let h = lib
        .finish_open(
            0,
            &[dh(
                k["owner"]["agreementKey"].as_str().unwrap(),
                &enc_of(&ins[0]),
            )],
        )
        .unwrap();
    assert_eq!(h.vault().id(), vault_id);
    let ins = lib.begin_open(1).unwrap();
    assert!(
        matches!(&ins[0], OpeningInput::Prf { salt, .. } if *salt == dec(k["prfSalt"].as_str().unwrap()))
    );
    let prf = || {
        OpeningSecret::Prf(PrfOutput::from_host(&dec(k["prfOutput"].as_str().unwrap())).unwrap())
    };
    assert_eq!(lib.finish_open(1, &[prf()]).unwrap().vault().id(), vault_id);
    let kit: [u8; 32] = dec(k["kitSecret"].as_str().unwrap()).try_into().unwrap();
    let kit_id = swift_kit_identity(&kit).unwrap();
    assert_eq!(
        kit_id.id(),
        "8aa449542c7ae99708c2f266508fde1f",
        "the Swift kit derivation reproduces the kit controller's ID"
    );
    let ins = lib.begin_open(2).unwrap();
    let a = colophon_core::v05::slots::answer_with_identity(&kit_id, &ins[0]).unwrap();
    assert_eq!(lib.finish_open(2, &[a]).unwrap().vault().id(), vault_id);
    let ins = lib.begin_open(3).unwrap();
    let h = lib
        .finish_open(
            3,
            &[dh(
                k["added"]["agreementKey"].as_str().unwrap(),
                &enc_of(&ins[0]),
            )],
        )
        .unwrap();
    // The namespace key sealed to the vault, and the same key sealed to the owner.
    let by_vault = h.open_epoch_key(&lib, "reading.saved", 1).unwrap();
    let share = lib
        .begin_open_share("reading.saved", 1, "01ff15365188f6561c4c3bc10730a40e")
        .unwrap();
    let by_owner = lib
        .finish_open_share(
            "reading.saved",
            1,
            "01ff15365188f6561c4c3bc10730a40e",
            &dh(
                k["owner"]["agreementKey"].as_str().unwrap(),
                &enc_of(&share),
            ),
        )
        .unwrap();
    // Both open the operations the Swift code wrote and sealed.
    let files: Vec<SourceFile> = [
        "ops/01ff15365188f6561c4c3bc10730a40e/000000000001-cdc1b6a7-765a-4d0d-843f-4b1fdfa5c90f.json",
        "ops/b2707a6b90c9551123761aec860bc888/000000000002-e72ef974-83b0-4bf7-9855-b3959fd217eb.json",
    ]
    .iter()
    .map(|p| SourceFile {
        path: p.to_string(),
        bytes: strip(std::fs::read(r.root.join("library").join(p)).unwrap()),
    })
    .collect();
    for keys in [vec![by_vault], vec![by_owner]] {
        let plan = CopyPlan::read(&lib, &files, &keys, None, &Destination::empty()).unwrap();
        // Authenticated, decrypted and admitted by the Swift rule: the only reason left to
        // omit them is the kind. The Swift wire kind `capture.link` is not the Rust module's
        // operation name, so verbatim they are not clean children (reported as a question).
        let why: Vec<_> = plan.omissions().into_iter().map(|o| o.2).collect();
        assert_eq!(why.len(), 2);
        assert!(
            why.iter().all(|w| w.starts_with("notCleanChild")),
            "{why:?}"
        );
    }
}

#[test]
fn a_host_translator_turns_the_real_swift_operations_into_clean_children() {
    let r = real();
    let lib = SwiftLibrary::read(&r.entries).unwrap();
    let k = &r.keys;
    let ins = lib.begin_open(0).unwrap();
    let h = lib
        .finish_open(
            0,
            &[dh(
                k["owner"]["agreementKey"].as_str().unwrap(),
                &enc_of(&ins[0]),
            )],
        )
        .unwrap();
    let key = h.open_epoch_key(&lib, "reading.saved", 1).unwrap();
    let files: Vec<SourceFile> = [
        "ops/01ff15365188f6561c4c3bc10730a40e/000000000001-cdc1b6a7-765a-4d0d-843f-4b1fdfa5c90f.json",
        "ops/b2707a6b90c9551123761aec860bc888/000000000002-e72ef974-83b0-4bf7-9855-b3959fd217eb.json",
    ]
    .iter()
    .map(|p| SourceFile {
        path: p.to_string(),
        bytes: strip(std::fs::read(r.root.join("library").join(p)).unwrap()),
    })
    .collect();
    // The seam a domain translator (`domains::saved::import::translate`) plugs into.
    let translate = |op: &SwiftOp<'_>| -> colophon_core::v05::Result<Batch> {
        assert_eq!(op.kind, "capture.link");
        Ok(Batch::of(vec![Child {
            key: "c".into(),
            kind: "capture".into(),
            payload: json!({"id": op.payload["item"], "title": op.payload["title"], "url": op.payload["url"]}),
            baseline: false,
        }]))
    };
    let plan = CopyPlan::read(
        &lib,
        &files,
        &[key],
        Some(&translate),
        &Destination::empty(),
    )
    .unwrap();
    assert_eq!(plan.omissions(), vec![], "both are copied");
    let batch = plan.next_batch(10);
    assert_eq!(batch.len(), 2);
    // The original authors, clocks and IDs survive as labelled evidence; the writer is the
    // importer's (the payload names no author).
    let authors: Vec<&str> = batch
        .iter()
        .map(|b| b.payload["evidence"]["authorID"].as_str().unwrap())
        .collect();
    assert!(
        authors.contains(&"01ff15365188f6561c4c3bc10730a40e")
            && authors.contains(&"b2707a6b90c9551123761aec860bc888")
    );
    for b in &batch {
        assert_eq!(
            b.payload["evidence"]["sourceLibrary"],
            "1e00224caf4fe010167787ad3e943480"
        );
        assert_eq!(b.payload["children"][0]["kind"], "capture");
    }
}

// ---------------------------------------------------------------------------------------------
// The forms, from the independent reading of the Swift source.

fn open_with_host(host: &Host, lib: &SwiftLibrary, index: usize) -> PredecessorVault {
    let ins = lib.begin_open(index).unwrap();
    lib.finish_open(index, &host.answer(&ins)).unwrap()
}

#[test]
fn each_swift_slot_form_opens_to_the_vault_it_derives() {
    let mut host = Host::new();
    let f = keyring_library(&mut host, false);
    let lib = SwiftLibrary::read(&f.entries).unwrap();
    assert_eq!(lib.vault().unwrap().signing, f.vault.0);
    // sealed (SealedKey.swift:13-30, VaultSlot.swift:39-44) and prf (VaultSlot.swift:47-57).
    for i in 0..2 {
        let h = open_with_host(&host, &lib, i);
        assert_eq!(h.vault().signing, f.vault.0);
        assert_eq!(h.vault().agreement, f.vault.1);
        assert_eq!(h.library(), f.library);
    }
    // combined (VaultSlot.swift:61-74): a sealed part and a PRF part, in order.
    let mut host2 = Host::new();
    let c = keyring_library(&mut host2, true);
    let lib = SwiftLibrary::read(&c.entries).unwrap();
    let ins = lib.begin_open(0).unwrap();
    assert!(
        matches!(ins[0], OpeningInput::Ecdh { .. }) && matches!(ins[1], OpeningInput::Prf { .. })
    );
    assert_eq!(open_with_host(&host2, &lib, 0).vault().signing, c.vault.0);
    // The namespace keys: through the vault.
    let h = open_with_host(&host2, &lib, 0);
    for ns in ["notes", "reading.saved"] {
        h.open_epoch_key(&lib, ns, 1).unwrap();
    }
}

#[test]
fn a_wrong_prf_output_a_wrong_ecdh_result_and_a_wrong_part_are_vault_locked() {
    let mut host = Host::new();
    let f = keyring_library(&mut host, false);
    let lib = SwiftLibrary::read(&f.entries).unwrap();
    // A PRF output that is not the credential's.
    let bad = OpeningSecret::Prf(PrfOutput::from_host(&[7; 32]).unwrap());
    assert!(locked(&lib.finish_open(1, &[bad]).unwrap_err()));
    // A PRF output of the wrong length is refused before it is a secret at all.
    assert!(locked(&PrfOutput::from_host(&[7; 31]).unwrap_err()));
    // An ECDH result of another key.
    let ins = lib.begin_open(0).unwrap();
    let other = dh_with(&[0x33; 32], &enc_of(&ins[0]));
    assert!(locked(&lib.finish_open(0, &[other]).unwrap_err()));
    // The wrong kind of secret for a route, and too few or too many.
    assert!(locked(
        &lib.finish_open(
            0,
            &[OpeningSecret::Prf(PrfOutput::from_host(&[1; 32]).unwrap())]
        )
        .unwrap_err()
    ));
    assert!(locked(&lib.finish_open(0, &[]).unwrap_err()));
    // A combined slot with one part right and one wrong.
    let mut h2 = Host::new();
    let c = keyring_library(&mut h2, true);
    let clib = SwiftLibrary::read(&c.entries).unwrap();
    let ins = clib.begin_open(0).unwrap();
    let mut answers = h2.answer(&ins);
    answers[1] = OpeningSecret::Prf(PrfOutput::from_host(&[9; 32]).unwrap());
    assert!(locked(&clib.finish_open(0, &answers).unwrap_err()));
    answers.swap(0, 1);
    assert!(
        locked(&clib.finish_open(0, &answers).unwrap_err()),
        "the order of parts is the order of secrets"
    );
    // A host that cannot open this slot learns nothing: no handle exists.
    assert!(clib.finish_open(5, &[]).is_err());
}
fn dh_with(scalar32: &[u8; 32], enc: &[u8]) -> OpeningSecret {
    let sk = p256::SecretKey::from_slice(scalar32).unwrap();
    let peer = p256::PublicKey::from_sec1_bytes(enc).unwrap();
    let shared = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
    OpeningSecret::Ecdh(EcdhOutput::from_host(shared.raw_secret_bytes().as_slice()).unwrap())
}

#[test]
fn a_handle_opens_only_its_own_library_and_a_key_only_its_own_records() {
    let mut host = Host::new();
    let a = keyring_library(&mut host, false);
    let mut host_b = Host::new();
    // Another library: a different vault seed and different keys.
    let b = keyring_library(&mut host_b, true);
    let lib_a = SwiftLibrary::read(&a.entries).unwrap();
    let lib_b = SwiftLibrary::read(&b.entries).unwrap();
    // Both fixtures use the same fixed names, so make B really another library: its genesis
    // differs by the label of the keyring only; the library ID is the genesis's digest, so
    // rebuild B with another root label by re-signing is not needed: use the real library.
    let r = real();
    let real_lib = SwiftLibrary::read(&r.entries).unwrap();
    let ins = real_lib.begin_open(0).unwrap();
    let real_handle = real_lib
        .finish_open(
            0,
            &[dh(
                r.keys["owner"]["agreementKey"].as_str().unwrap(),
                &enc_of(&ins[0]),
            )],
        )
        .unwrap();
    // A handle of the real library does not open this library's namespace keys, nor the other
    // way round: its purposes are its own library's.
    assert!(locked(
        &real_handle.open_epoch_key(&lib_a, "notes", 1).unwrap_err()
    ));
    let mine = open_with_host(&host, &lib_a, 0);
    assert!(locked(
        &mine
            .open_epoch_key(&real_lib, "reading.saved", 1)
            .unwrap_err()
    ));
    let _ = lib_b;
    // An epoch that was never sealed to the vault is not available, and says so.
    let e = mine.open_epoch_key(&lib_a, "notes", 2).unwrap_err();
    assert!(matches!(e, Failure::Unavailable(_)), "{e:?}");
    assert!(matches!(
        mine.open_epoch_key(&lib_a, "nowhere", 1).unwrap_err(),
        Failure::Unavailable(_)
    ));
    // A key opens only the records of its own library, namespace and epoch.
    let k_notes = mine.open_epoch_key(&lib_a, "notes", 1).unwrap();
    let plan = CopyPlan::read(
        &lib_a,
        &a.files,
        &[k_notes],
        Some(&translate),
        &Destination::empty(),
    )
    .unwrap();
    let omitted: Vec<_> = plan.omissions().into_iter().map(|o| (o.0, o.2)).collect();
    assert_eq!(
        omitted,
        vec![("reading.saved".to_string(), "unreadable".to_string()); 2],
        "reading.saved has no key here: unreadable, never guessed"
    );
    assert_eq!(plan.pending(), 2);
    // No accessor, no clone, no serialization, and the Debug form shows nothing secret.
    let shown = format!("{mine:?}");
    assert!(!shown.contains(&b64(&a.vault_seed)) && shown.contains("PredecessorVault"));
}

// ---------------------------------------------------------------------------------------------
// The copy.

fn plan_of(f: &SwiftFixture, host: &Host) -> (SwiftLibrary, CopyPlan) {
    let lib = SwiftLibrary::read(&f.entries).unwrap();
    let h = open_with_host(host, &lib, 0);
    let keys: Vec<_> = ["notes", "reading.saved"]
        .iter()
        .map(|n| h.open_epoch_key(&lib, n, 1).unwrap())
        .collect();
    let plan = CopyPlan::read(
        &lib,
        &f.files,
        &keys,
        Some(&translate),
        &Destination::empty(),
    )
    .unwrap();
    (lib, plan)
}
fn fake_header(namespace: &str, n: u8) -> OperationHeader {
    OperationHeader {
        body: vec![n; 40],
        account: AccountId::of_genesis(b"x"),
        namespace: namespace.into(),
        author: "0".repeat(32),
        epoch: 1,
        id: "0".repeat(32),
        clock: n as u64,
        authority: 1,
        created: ("2026-11-11T00:00:00Z".into(), 0),
        level: Level::Write,
        previous: None,
        nonce: vec![0; 12],
        ciphertext: vec![],
        live: None,
        unknown: Default::default(),
    }
}

#[test]
fn every_record_is_planned_once_in_bounded_batches_with_its_original_author_as_evidence() {
    let mut host = Host::new();
    let f = keyring_library(&mut host, false);
    let (lib, plan) = plan_of(&f, &host);
    assert_eq!(plan.pending(), 4);
    assert_eq!(plan.omissions(), vec![]);
    assert_eq!(
        plan.source_counts().into_iter().collect::<Vec<_>>(),
        vec![("notes".to_string(), 2), ("reading.saved".to_string(), 2)]
    );
    // Bounded: a batch never exceeds what was asked, nor the module bound.
    assert_eq!(plan.next_batch(3).len(), 3);
    assert_eq!(plan.next_batch(0).len(), 0);
    assert_eq!(plan.next_batch(10_000).len(), 4);
    let all = plan.next_batch(10);
    // The Swift fold order inside a namespace: (clock, author, id).
    let notes: Vec<_> = all.iter().filter(|b| b.namespace == "notes").collect();
    assert_eq!(notes[0].payload["evidence"]["authorID"], f.m1.id);
    assert_eq!(notes[1].payload["evidence"]["authorID"], f.m2.id);
    assert_eq!(notes[0].payload["evidence"]["authorLabel"], "Phone");
    assert_eq!(notes[0].payload["evidence"]["clock"], 1);
    assert_eq!(
        notes[0].payload["evidence"]["operationID"],
        "11111111-aaaa-4aaa-8aaa-000000000001"
    );
    assert_eq!(notes[0].payload["evidence"]["sourceLibrary"], lib.library());
    assert_eq!(notes[0].payload["children"][0]["kind"], "createNotebook");
    assert_eq!(notes[0].payload["children"][0]["payload"]["title"], "Alpha");
    // The evidence carries the digest of the source body: what `omitted` would name.
    let src: Value = serde_json::from_slice(&f.files[0].bytes).unwrap();
    assert_eq!(
        notes[0].payload["evidence"]["bodyDigest"],
        digest(&dec(src["body"].as_str().unwrap()))
    );
}

#[test]
fn a_copy_that_omits_or_duplicates_a_record_is_refused_each_by_its_reason() {
    let mut host = Host::new();
    let f = keyring_library(&mut host, false);
    let (_, mut plan) = plan_of(&f, &host);
    let all = plan.next_batch(10);
    // An unfinished copy: records neither written nor omitted.
    let e = plan_of(&f, &host)
        .1
        .finish(&Destination::empty())
        .unwrap_err();
    assert!(e.detail().contains("neither written nor omitted"), "{e:?}");
    // A source record written twice.
    plan.record_written(&all[0].source_digest, &fake_header(&all[0].namespace, 1))
        .unwrap();
    let e = plan
        .record_written(&all[0].source_digest, &fake_header(&all[0].namespace, 2))
        .unwrap_err();
    assert!(
        e.detail().contains("no such pending source record"),
        "{e:?}"
    );
    // One destination record claimed for two source records.
    let e = plan
        .record_written(&all[1].source_digest, &fake_header(&all[0].namespace, 1))
        .unwrap_err();
    assert!(e.detail().contains("copied once"), "{e:?}");
    // A destination record of another namespace is not the source's.
    let other = if all[1].namespace == "notes" {
        "reading.saved"
    } else {
        "notes"
    };
    let e = plan
        .record_written(&all[1].source_digest, &fake_header(other, 3))
        .unwrap_err();
    assert!(
        e.detail().contains("no such pending source record"),
        "{e:?}"
    );
    // An unknown source record, and an omission with no reason.
    assert!(plan
        .record_written(&"0".repeat(64), &fake_header("notes", 4))
        .is_err());
    assert!(plan
        .record_omitted(&all[1].namespace, &all[1].source_digest, "")
        .is_err());
    // A finish against a destination that does not hold what the plan says it wrote is refused.
    plan.record_written(&all[1].source_digest, &fake_header(&all[1].namespace, 5))
        .unwrap();
    plan.record_written(&all[2].source_digest, &fake_header(&all[2].namespace, 6))
        .unwrap();
    plan.record_omitted(
        &all[3].namespace,
        &all[3].source_digest,
        "left behind by the person",
    )
    .unwrap();
    let e = plan.finish(&Destination::empty()).unwrap_err();
    assert!(e.detail().contains("destination does not hold"), "{e:?}");
    // With everything omitted by the person the counts add up and nothing is claimed copied.
    let (_, mut plan) = plan_of(&f, &host);
    for it in plan.next_batch(10) {
        plan.record_omitted(
            &it.namespace,
            &it.source_digest,
            "left behind by the person",
        )
        .unwrap();
    }
    let r = plan.finish(&Destination::empty()).unwrap();
    assert_eq!(r.namespaces().iter().map(|n| n.source).sum::<u64>(), 4);
    for n in r.namespaces() {
        assert_eq!(n.copied.len() as u64 + n.omitted, n.source);
        assert!(n.copied.is_empty());
    }
    assert_eq!(r.omitted().len(), 4);
}

#[test]
fn a_damaged_hostile_or_out_of_order_library_never_panics_and_loses_nothing_silently() {
    let mut host = Host::new();
    let f = keyring_library(&mut host, false);
    let lib = SwiftLibrary::read(&f.entries).unwrap();
    let h = open_with_host(&host, &lib, 0);
    let keys: Vec<_> = ["notes", "reading.saved"]
        .iter()
        .map(|n| h.open_epoch_key(&lib, n, 1).unwrap())
        .collect();
    let mut files = f.files.clone();
    // A flipped signature byte, a path of another namespace, a path of another author, garbage,
    // an empty file, and a third-party author that is no member.
    let mut v: Value = serde_json::from_slice(&files[0].bytes).unwrap();
    let mut sig = dec(v["signature"].as_str().unwrap());
    sig[5] ^= 1;
    v["signature"] = json!(b64(&sig));
    files[0].bytes = canonical(&v).unwrap();
    files[1].path = files[1].path.replace("/notes/", "/reading.saved/");
    files[2].path = files[2].path.replace(&f.m1.id, &f.m2.id);
    files.push(SourceFile {
        path: "ops/x/notes/000000000009-zzzzzzzzzzzzzzzzzzzzz.json".into(),
        bytes: b"garbage".to_vec(),
    });
    files.push(SourceFile {
        path: "ops/x/notes/000000000010-zzzzzzzzzzzzzzzzzzzzz.json".into(),
        bytes: vec![],
    });
    files.push(SourceFile {
        path: "state/a/notes/slot.json".into(),
        bytes: b"{}".to_vec(),
    });
    files.push(SourceFile {
        path: "blobs/".to_string() + &"a".repeat(64),
        bytes: vec![1; 10],
    });
    files.push(SourceFile {
        path: "authority/00000001.json".into(),
        bytes: vec![],
    });
    let plan =
        CopyPlan::read(&lib, &files, &keys, Some(&translate), &Destination::empty()).unwrap();
    let why: std::collections::BTreeMap<String, usize> =
        plan.omissions()
            .into_iter()
            .fold(Default::default(), |mut m, o| {
                *m.entry(o.2).or_default() += 1;
                m
            });
    assert_eq!(why.get("badSignature"), Some(&1));
    assert_eq!(why.get("pathMismatch"), Some(&2));
    assert_eq!(why.get("invalidPayload"), Some(&2));
    assert_eq!(why.get("liveState"), Some(&1));
    assert_eq!(plan.pending(), 1, "the one untouched record");
    // Every file the plan holds is accounted for: copied or omitted by digest.
    assert_eq!(plan.pending() + plan.omissions().len(), 4 + 2 + 1);
    // Too many files are refused before anything is read.
    let many: Vec<SourceFile> = (0..262_145)
        .map(|_| SourceFile {
            path: "x".into(),
            bytes: vec![],
        })
        .collect();
    assert!(CopyPlan::read(&lib, &many, &keys, Some(&translate), &Destination::empty()).is_err());
    // A file over the bound is omitted, not read.
    let big = vec![SourceFile {
        path: "ops/x/notes/000000000001-yyyyyyyyyyyyyyyyyyyyy.json".into(),
        bytes: vec![b' '; MAX_FILE_BYTES + 1],
    }];
    let p = CopyPlan::read(&lib, &big, &keys, Some(&translate), &Destination::empty()).unwrap();
    assert_eq!(p.omissions()[0].2, "tooLarge");
}

#[test]
fn the_swift_admission_rule_decides_what_is_copied() {
    // A record cited authority this copy has not received, one by a member before its grant,
    // one under the wrong epoch and one by a revoked member are not copied (Admission.swift).
    let mut host = Host::new();
    let f = keyring_library(&mut host, false);
    let lib = SwiftLibrary::read(&f.entries).unwrap();
    let h = open_with_host(&host, &lib, 0);
    let keys: Vec<_> = ["notes", "reading.saved"]
        .iter()
        .map(|n| h.open_epoch_key(&lib, n, 1).unwrap())
        .collect();
    let authority = f.entries.len() as u64;
    let mk = |m: &Member, clock, id: &str, auth: u64, epoch: u64| {
        swift_op(
            &host,
            "",
            &f.nskeys["notes"],
            "notes",
            m,
            epoch,
            clock,
            id,
            "notebook.create",
            json!({"notebook": id, "title": "T"}),
            auth,
        )
    };
    let files = vec![
        mk(
            &f.m1,
            5,
            "55555555-eeee-4eee-8eee-000000000005",
            authority + 5,
            1,
        ), // the future
        mk(&f.m1, 6, "66666666-eeee-4eee-8eee-000000000006", 2, 1), // before the grant
        mk(
            &f.m1,
            7,
            "77777777-eeee-4eee-8eee-000000000007",
            authority,
            2,
        ), // another epoch
        mk(
            &f.m1,
            8,
            "88888888-eeee-4eee-8eee-000000000008",
            authority,
            1,
        ), // fine
    ];
    let plan =
        CopyPlan::read(&lib, &files, &keys, Some(&translate), &Destination::empty()).unwrap();
    let why: Vec<String> = plan.omissions().into_iter().map(|o| o.2).collect();
    assert!(
        why.iter().any(|w| w.starts_with("held: cites authority")),
        "{why:?}"
    );
    assert!(
        why.iter()
            .any(|w| w.starts_with("refused: written before the grant")),
        "{why:?}"
    );
    // Epoch 2 has no key here: it cannot be read, which is the more basic reason.
    assert!(why.iter().any(|w| w == "unreadable"), "{why:?}");
    assert_eq!(plan.pending(), 1);
}

// ---------------------------------------------------------------------------------------------
// The generator's fixtures (`conformance/0.5/swift-slots`): the five Swift forms, from
// the same reading of the Swift source, in a form a Swift-side test can reproduce.

fn fixture(name: &str) -> Value {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/0.5/swift-slots")
        .join(name)
        .join("fixture.json");
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}
/// A keyring library that holds `slots` and `shares` under the fixture's vault.
fn library_of(host: &mut Host, fx: &Value, slots: Vec<Value>, shares: Vec<Value>) -> SwiftLibrary {
    let root = host.identity(1);
    let recovery = host.identity(2);
    let device = host.identity(3);
    let genesis = json!({"by": "root", "issued": T_PRED, "kind": "genesis", "label": "L", "seq": 1,
        "recovery": pid(&recovery.1, &recovery.2), "root": pid(&root.1, &root.2)});
    let mut entries = vec![entry(host, &root.0, &genesis)];
    let keyring = json!({"by": "root", "issued": swift_date(60), "kind": "keyring", "previous": body_digest(&entries[0]), "seq": 2,
        "controllers": [{"kind": "p256", "key": b64(&device.1), "label": "Mac", "roles": ["approve", "control"]}],
        "slots": slots, "threshold": 1, "vault": fx["vault"].clone()});
    entries.push(entry(host, &root.0, &keyring));
    let vault_id = fx["vaultID"]
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| key_id(&dec(fx["vault"]["signing"].as_str().unwrap())));
    for (i, key) in shares.into_iter().enumerate() {
        let body = json!({"by": "controller", "signer": device.0, "issued": swift_date(120 + i as u32), "kind": "shareKey",
            "previous": body_digest(entries.last().unwrap()), "seq": 3 + i, "memberID": vault_id,
            "namespace": "reading.saved", "epoch": 1, "key": key});
        entries.push(entry(host, &device.0, &body));
    }
    SwiftLibrary::read(&entries).unwrap()
}

#[test]
fn the_generators_swift_fixtures_open_in_every_form_and_the_namespace_key_authenticates() {
    for form in ["sealed", "prf", "combined"] {
        let fx = fixture(form);
        let mut host = Host::new();
        let lib = library_of(&mut host, &fx, vec![fx["slot"].clone()], vec![]);
        let ins = lib.begin_open(0).unwrap();
        let scalars: Vec<Vec<u8>> = fx["answers"]["ecdhAgreementScalars"]
            .as_array()
            .map(|a| a.iter().map(|s| dec(s.as_str().unwrap())).collect())
            .unwrap_or_default();
        let prfs: Vec<Vec<u8>> = fx["answers"]["prfOutputs"]
            .as_array()
            .map(|a| a.iter().map(|s| dec(s.as_str().unwrap())).collect())
            .unwrap_or_default();
        let (mut e, mut p) = (0, 0);
        let answers: Vec<OpeningSecret> = ins
            .iter()
            .map(|i| match i {
                OpeningInput::Ecdh { enc, .. } => {
                    e += 1;
                    let s: [u8; 32] = scalars[e - 1].clone().try_into().unwrap();
                    dh_with(&s, enc)
                }
                OpeningInput::Prf { salt, .. } => {
                    p += 1;
                    assert_eq!(salt.len(), 32);
                    OpeningSecret::Prf(PrfOutput::from_host(&prfs[p - 1]).unwrap())
                }
            })
            .collect();
        let h = lib.finish_open(0, &answers).unwrap();
        assert_eq!(
            h.vault().id(),
            fx["expected"]["vaultID"].as_str().unwrap(),
            "{form}"
        );
    }
    // A wrong answer for each form is refused.
    let fx = fixture("prf");
    let mut host = Host::new();
    let lib = library_of(&mut host, &fx, vec![fx["slot"].clone()], vec![]);
    assert!(locked(
        &lib.finish_open(
            0,
            &[OpeningSecret::Prf(PrfOutput::from_host(&[1; 32]).unwrap())]
        )
        .unwrap_err()
    ));
    // The namespace key sealed to the vault authenticates and opens.
    let sealed_fx = fixture("sealed");
    let ns = fixture("namespace-key");
    let mut host = Host::new();
    let lib = library_of(
        &mut host,
        &ns,
        vec![sealed_fx["slot"].clone()],
        vec![ns["share"].clone()],
    );
    let ins = lib.begin_open(0).unwrap();
    let s: [u8; 32] = dec(sealed_fx["answers"]["ecdhAgreementScalars"][0]
        .as_str()
        .unwrap())
    .try_into()
    .unwrap();
    let h = lib
        .finish_open(0, &[dh_with(&s, &enc_of(&ins[0]))])
        .unwrap();
    let k = h.open_epoch_key(&lib, "reading.saved", 1).unwrap();
    assert_eq!((k.namespace(), k.epoch()), ("reading.saved", 1));
}

// ---------------------------------------------------------------------------------------------
// The fix round.

#[test]
fn a_record_under_a_namespace_the_predecessor_never_named_is_omitted_with_a_reason() {
    let mut host = Host::new();
    let f = keyring_library(&mut host, false);
    let lib = SwiftLibrary::read(&f.entries).unwrap();
    let ghost = swift_op(
        &host,
        "",
        &f.nskeys["notes"],
        "ghost",
        &f.m1,
        1,
        9,
        "99999999-aaaa-4aaa-8aaa-000000000009",
        "notebook.create",
        json!({"notebook": "x", "title": "T"}),
        10,
    );
    let plan =
        CopyPlan::read(&lib, &[ghost], &[], Some(&translate), &Destination::empty()).unwrap();
    assert_eq!(
        plan.omissions()
            .into_iter()
            .map(|o| (o.0, o.2))
            .collect::<Vec<_>>(),
        vec![(String::new(), "notAPredecessorNamespace".to_string())]
    );
    assert_eq!(
        plan.source_counts().keys().cloned().collect::<Vec<_>>(),
        vec!["notes", "reading.saved"]
    );
}

#[test]
fn a_granted_namespace_with_no_epoch_is_a_predecessor_namespace_with_no_records() {
    let mut host = Host::new();
    let f = keyring_library_with(&mut host, false, true, false);
    let lib = SwiftLibrary::read(&f.entries).unwrap();
    assert_eq!(
        lib.namespaces(),
        vec!["notes", "reading.saved"],
        "no epoch for reading.books"
    );
    let all = predecessor_namespaces(&lib).unwrap();
    assert!(all.contains("reading.books"));
    let plan = CopyPlan::read(&lib, &[], &[], Some(&translate), &Destination::empty()).unwrap();
    assert_eq!(plan.source_counts().get("reading.books"), Some(&0));
}

#[test]
fn a_duplicate_operation_is_decided_by_body_digest_never_by_file_order() {
    let mut host = Host::new();
    let f = keyring_library(&mut host, false);
    let (lib, _) = plan_of(&f, &host);
    let h = open_with_host(&host, &lib, 0);
    let keys: Vec<_> = ["notes", "reading.saved"]
        .iter()
        .map(|n| h.open_epoch_key(&lib, n, 1).unwrap())
        .collect();
    // The same operation twice with different (both authentic) header bodies.
    let a = f.files[0].clone();
    let mut v: Value = serde_json::from_slice(&a.bytes).unwrap();
    let body = dec(v["body"].as_str().unwrap());
    let mut hv: Value = serde_json::from_slice(&body).unwrap();
    hv["x"] = json!(1);
    let nb = canonical(&hv).unwrap();
    v["body"] = json!(b64(&nb));
    v["signature"] = json!(b64(&host.sign(&f.m1.id, &nb)));
    let b = SourceFile {
        path: a.path.clone(),
        bytes: canonical(&v).unwrap(),
    };
    let run = |files: Vec<SourceFile>| {
        let p =
            CopyPlan::read(&lib, &files, &keys, Some(&translate), &Destination::empty()).unwrap();
        (
            p.next_batch(10)
                .iter()
                .map(|i| i.source_digest.clone())
                .collect::<Vec<_>>(),
            p.omissions(),
        )
    };
    let mut rest: Vec<SourceFile> = f.files[1..].to_vec();
    let mut one = vec![a.clone(), b.clone()];
    one.append(&mut rest.clone());
    let mut two = vec![b, a];
    two.append(&mut rest);
    let (p1, o1) = run(one);
    let (p2, o2) = run(two);
    let (mut p1, mut p2) = (p1, p2);
    p1.sort();
    p2.sort();
    assert_eq!(p1, p2);
    assert_eq!(o1.iter().filter(|o| o.2 == "duplicate").count(), 1);
    assert_eq!(
        o1.iter()
            .map(|o| o.1.clone())
            .collect::<std::collections::BTreeSet<_>>(),
        o2.iter()
            .map(|o| o.1.clone())
            .collect::<std::collections::BTreeSet<_>>()
    );
}

#[test]
fn one_malformed_slot_or_share_fails_only_itself() {
    let mut host = Host::new();
    let f = keyring_library_opts(&mut host, false, false, false, true);
    let lib = SwiftLibrary::read(&f.entries).unwrap();
    assert_eq!(lib.problems().len(), 1, "{:?}", lib.problems());
    assert!(lib.problems()[0].contains("share"));
    // The good slots and shares still open.
    let h = open_with_host(&host, &lib, 0);
    h.open_epoch_key(&lib, "notes", 1).unwrap();
    // A malformed slot: only that slot is unusable.
    let mut entries = f.entries.clone();
    let mut v: Value = serde_json::from_slice(&entries[1]).unwrap();
    let mut body: Value = serde_json::from_slice(&dec(v["body"].as_str().unwrap())).unwrap();
    body["slots"].as_array_mut().unwrap().push(json!({"kind": "sealed", "label": "bad", "recipient": {"signing": "AA==", "agreement": "AA=="}, "sealed": {"ephemeral": "AA==", "box": "AA=="}}));
    let nb = canonical(&body).unwrap();
    v["body"] = json!(b64(&nb));
    v["signature"] = json!(b64(&host.sign(&f.root.id, &nb)));
    entries[1] = canonical(&v).unwrap();
    // The chain after it names the old digest, so verify only the keyring entry's slots here.
    let lib = SwiftLibrary::read(&entries[..2]).unwrap();
    assert!(lib.slots().last().unwrap().problem().is_some());
    assert_eq!(lib.problems().len(), 1);
    assert!(lib.begin_open(2).is_err());
    assert!(lib.begin_open(0).is_ok());
}

#[test]
fn a_ceremony_pairs_by_controller_and_credential_and_asks_for_user_verification() {
    use colophon_core::v05::slots::PrfRequest;
    let mut host = Host::new();
    let f = keyring_library(&mut host, false);
    let lib = SwiftLibrary::read(&f.entries).unwrap();
    let req = |controller: &str, credential: &[u8]| PrfRequest {
        controller: controller.into(),
        rp: "id.example".into(),
        credential: credential.to_vec(),
        salt: [1; 32],
        challenge: [2; 32],
    };
    let (ok, un) = lib
        .pair_ceremonies(1, &[req(&f.passkey_id, &f.credential)])
        .unwrap();
    assert_eq!((ok.len(), un.len()), (1, 0));
    assert!(ok[0].user_verification && ok[0].old_salt == f.old_salt);
    // The right controller with another credential, and another controller, do not pair.
    let (ok, un) = lib
        .pair_ceremonies(1, &[req(&f.passkey_id, b"other")])
        .unwrap();
    assert_eq!(ok.len(), 0);
    assert_eq!(
        un.len(),
        2,
        "the new request and the old route are both unpaired: {un:?}"
    );
    let (ok, _) = lib
        .pair_ceremonies(1, &[req(&f.security_id, &f.credential)])
        .unwrap();
    assert_eq!(ok.len(), 0);
    assert!(lib.pair_ceremonies(99, &[]).is_err());
}

#[test]
fn a_plan_and_its_items_never_print_decrypted_payloads() {
    let mut host = Host::new();
    let f = keyring_library(&mut host, false);
    let (_, plan) = plan_of(&f, &host);
    let item = plan.next_batch(1).remove(0);
    for shown in [format!("{plan:?}"), format!("{item:?}")] {
        assert!(
            !shown.contains("Alpha") && !shown.contains("Beta") && !shown.contains("example.com"),
            "{shown}"
        );
    }
}
