//! Succession and upgrade object-set/restart checks.
#![allow(clippy::unwrap_used)]
use colophon_core::v05::{
    encoding::parse_date,
    history::{verify_history, Objects, Persisted},
};
use std::{
    fs,
    path::{Path, PathBuf},
};
fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/0.5/candidate")
}
fn files(p: &Path) -> Vec<Vec<u8>> {
    let mut paths: Vec<_> = fs::read_dir(p)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    paths.sort();
    paths.iter().map(|p| fs::read(p).unwrap()).collect()
}
fn load(p: &Path, swift: bool) -> Objects {
    let mut o = Objects {
        entries: files(&p.join(if swift {
            "successor/authority"
        } else {
            "records/authority"
        })),
        ..Default::default()
    };
    if swift {
        o.predecessor = files(&p.join("predecessor/authority"));
        if p.join("genesis-receipt.json").exists() {
            o.pending
                .push(fs::read(p.join("genesis-receipt.json")).unwrap());
        }
        if p.join("successor-head.json").exists() {
            o.heads
                .push(fs::read(p.join("successor-head.json")).unwrap());
        }
    }
    o
}
#[test]
fn succession_and_upgrade_shuffles_and_serialized_restart_agree() {
    let now = parse_date("2026-11-14T10:15:00Z").unwrap();
    for (top, swift) in [("succession", true), ("upgrade", false)] {
        for p in fs::read_dir(root().join(top))
            .unwrap()
            .map(|e| e.unwrap().path())
        {
            let all = load(&p, swift);
            let want = verify_history(&all, &Persisted::default(), now);
            for split in 0..=all.entries.len() {
                let prefix = Objects {
                    entries: all.entries[..split].to_vec(),
                    predecessor: all.predecessor.clone(),
                    ..Default::default()
                };
                let saved = Persisted::checkpoint(&prefix, &Persisted::default(), now);
                let saved = Persisted::from_bytes(&saved.to_bytes().unwrap()).unwrap();
                let mut suffix = all.clone();
                suffix.entries = all.entries[split..].to_vec();
                suffix.entries.reverse();
                suffix.predecessor.reverse();
                suffix.pending.reverse();
                suffix.heads.reverse();
                let got = verify_history(&suffix, &saved, now);
                assert_eq!(
                    (got.code(), got.seq(), &got.branch),
                    (want.code(), want.seq(), &want.branch),
                    "{} split {split}",
                    p.display()
                );
                assert_eq!(
                    serde_json::to_value(got.state).unwrap(),
                    serde_json::to_value(&want.state).unwrap(),
                    "{} split {split}",
                    p.display()
                );
            }
        }
    }
}
#[test]
fn swift_succession_requires_fresh_heads_and_genesis_receipts() {
    let now = parse_date("2026-11-14T10:15:00Z").unwrap();
    let mut o = load(&root().join("succession/swift-keyring"), true);
    assert!(verify_history(&o, &Persisted::default(), now)
        .state
        .unwrap()
        .verified_succession()
        .is_some());
    o.heads.clear();
    assert!(verify_history(&o, &Persisted::default(), now)
        .state
        .unwrap()
        .verified_succession()
        .is_none());
    o = load(&root().join("succession/swift-keyring"), true);
    o.pending.clear();
    assert!(verify_history(&o, &Persisted::default(), now)
        .state
        .unwrap()
        .verified_succession()
        .is_none());
}
#[test]
fn malformed_predecessor_bytes_do_not_panic_or_verify() {
    let now = parse_date("2026-11-14T10:15:00Z").unwrap();
    let base = load(&root().join("succession/swift-keyring"), true);
    for bytes in [
        vec![],
        vec![255],
        b"{}".to_vec(),
        b"{\"body\":\"AA==\"}".to_vec(),
    ] {
        let mut o = base.clone();
        o.predecessor = vec![bytes];
        let got = verify_history(&o, &Persisted::default(), now);
        assert_ne!(got.code(), "ok");
    }
}

#[test]
fn forged_swift_candidate_cannot_create_a_fork() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let entries = files(&root().join("succession/swift-keyring/predecessor/authority"));
    let mut injected = entries.clone();
    let mut envelope: serde_json::Value = serde_json::from_slice(&entries[1]).unwrap();
    let mut body: serde_json::Value =
        serde_json::from_slice(&STANDARD.decode(envelope["body"].as_str().unwrap()).unwrap())
            .unwrap();
    body["threshold"] = serde_json::json!(2);
    envelope["body"] = serde_json::json!(STANDARD.encode(serde_json::to_vec(&body).unwrap()));
    injected.push(serde_json::to_vec(&envelope).unwrap());
    let got = colophon_core::v05::history::swift::verify(&injected).unwrap();
    let want = colophon_core::v05::history::swift::verify(&entries).unwrap();
    assert_eq!(
        got.entries.iter().map(|e| &e.digest).collect::<Vec<_>>(),
        want.entries.iter().map(|e| &e.digest).collect::<Vec<_>>()
    );
}

#[test]
fn malformed_evidence_after_verified_swift_final_does_not_undo_succession() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let now = parse_date("2026-11-14T10:15:00Z").unwrap();
    let mut o = load(&root().join("succession/swift-entry-after-final"), true);
    // No signature, wrong kind, no previous: still evidence after terminal F.
    o.predecessor[3] = serde_json::to_vec(
        &serde_json::json!({"body":STANDARD.encode(b"{\"seq\":4,\"kind\":\"forged\"}")}),
    )
    .unwrap();
    let s = verify_history(&o, &Persisted::default(), now)
        .state
        .unwrap();
    assert!(s.verified_succession().is_some());
    assert_eq!(s.predecessor_evidence(), [4]);
}
