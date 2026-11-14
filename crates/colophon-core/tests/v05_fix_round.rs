//! Regression tests for the fix round after the independent check (2026-11-14). Each test
//! failed before its fix. The forged-`final` and held-candidate cases come from the checker's probes.
#![allow(clippy::unwrap_used)]
use base64::{engine::general_purpose::STANDARD, Engine};
use colophon_core::v05::encoding::{canonical, parse_date};
use colophon_core::v05::history::{verify_history, Objects, Persisted};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

fn cand() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/0.5/candidate")
}
fn files(dir: &Path) -> Vec<Vec<u8>> {
    let mut v: Vec<PathBuf> = fs::read_dir(dir)
        .map(|r| r.map(|e| e.unwrap().path()).collect())
        .unwrap_or_default();
    v.sort();
    v.into_iter()
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .map(|p| fs::read(p).unwrap())
        .collect()
}
fn objects_of(dir: &Path) -> Objects {
    let mut o = Objects {
        entries: files(&dir.join("records/authority")),
        ..Default::default()
    };
    for e in fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("branch-")
        {
            o.entries.extend(files(&p.join("authority")));
        }
    }
    let mut objs: Vec<PathBuf> = fs::read_dir(dir.join("objects"))
        .map(|r| r.map(|e| e.unwrap().path()).collect())
        .unwrap_or_default();
    objs.sort();
    for p in objs {
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        if name.starts_with("head") {
            o.heads.push(fs::read(&p).unwrap());
        } else if name != "call.json" {
            o.pending.push(fs::read(&p).unwrap());
        }
    }
    o
}
fn vector(name: &str) -> (PathBuf, Objects, i64) {
    let dir = cand().join("rules").join(name);
    let case: Value = serde_json::from_slice(&fs::read(dir.join("case.json")).unwrap()).unwrap();
    let now = parse_date(
        case["verifier"]["now"]
            .as_str()
            .unwrap_or("2026-11-20T00:00:00Z"),
    )
    .unwrap();
    (dir.clone(), objects_of(&dir), now)
}
fn body(env: &[u8]) -> Value {
    let env: Value = serde_json::from_slice(env).unwrap();
    serde_json::from_slice(&STANDARD.decode(env["body"].as_str().unwrap()).unwrap()).unwrap()
}
fn body_digest(env: &[u8]) -> String {
    let env: Value = serde_json::from_slice(env).unwrap();
    colophon_core::v05::encoding::digest(&STANDARD.decode(env["body"].as_str().unwrap()).unwrap())
}
fn unsigned_env(b: &Value) -> Vec<u8> {
    let bytes = canonical(b).unwrap();
    serde_json::to_vec(&json!({"body": STANDARD.encode(bytes)})).unwrap()
}

/// A `final` object that no valid branch contains covers nothing (§8.6 rule 1, §8.7).
fn forged_final_for(act: &[u8], seq: u64) -> Vec<u8> {
    let b = body(act);
    unsigned_env(&json!({
        "protocol": "colophon/authority/5", "seq": seq,
        "previous": "0000000000000000000000000000000000000000000000000000000000000000",
        "issued": b["issued"], "by": b["by"], "kind": "final",
        "activation": {"seq": b["seq"], "digest": body_digest(act)}, "heads": []
    }))
}

#[test]
fn h1_forged_final_does_not_flip_vetoed_conflict() {
    let (dir, objects, now) = vector("t-vetoed-beats-activate");
    let honest = verify_history(&objects, &Persisted::default(), now);
    let act = files(&dir.join("branch-activate/authority")).pop().unwrap();
    assert_eq!(body(&act)["kind"], "activate");
    let mut attacked = objects.clone();
    attacked.entries.push(forged_final_for(&act, 4));
    let v = verify_history(&attacked, &Persisted::default(), now);
    assert_eq!(honest.branch, v.branch);
}

#[test]
fn h2_forged_final_does_not_displace_a_covered_entry() {
    let (dir, objects, now) = vector("t-activate-after-covered-entry");
    let honest = verify_history(&objects, &Persisted::default(), now);
    let act = files(&dir.join("branch-activate-first/authority"))
        .pop()
        .unwrap();
    let mut attacked = objects.clone();
    attacked.entries.push(forged_final_for(&act, 99));
    let v = verify_history(&attacked, &Persisted::default(), now);
    assert_eq!(honest.branch, v.branch);
}

#[test]
fn h3_resume_reconsiders_a_candidate_held_at_checkpoint_time() {
    let (_, objects, _) = vector("t-backdated-entry-vs-provisional");
    let early = parse_date("2026-11-14T09:04:30Z").unwrap();
    let late = parse_date("2026-11-14T09:06:00Z").unwrap();
    let saved = Persisted::checkpoint(&objects, &Persisted::default(), early);
    let saved = Persisted::from_bytes(&saved.to_bytes().unwrap()).unwrap();
    // Before the held activate is due, the resumed verdict is the early replay's.
    let still = verify_history(&Objects::default(), &saved, early + 1_000);
    let still_replay = verify_history(&objects, &Persisted::default(), early + 1_000);
    assert_eq!(still.branch, still_replay.branch);
    let resumed = verify_history(&Objects::default(), &saved, late);
    let replay = verify_history(&objects, &Persisted::default(), late);
    assert_eq!(resumed.branch, replay.branch);
    assert_eq!(resumed.conflicts, replay.conflicts);
}

fn chain_objects() -> (Objects, i64) {
    let dir = cand().join("succession/authority5-chain");
    let o = Objects {
        entries: files(&dir.join("successor/authority")),
        predecessor: files(&dir.join("predecessor/authority")),
        ..Default::default()
    };
    (o, parse_date("2026-11-14T10:15:00Z").unwrap())
}

#[test]
fn m3_chained_succession_verifies() {
    let (o, now) = chain_objects();
    let v = verify_history(&o, &Persisted::default(), now);
    assert_eq!(v.code(), "ok");
    let s = v.state.unwrap();
    assert!(s.verified_succession().is_some());
}

#[test]
fn m3_chain_without_the_older_history_is_unavailable() {
    let (mut o, now) = chain_objects();
    o.predecessor.drain(..2); // drop A's two entries, keep B's
    let v = verify_history(&o, &Persisted::default(), now);
    assert_ne!(v.code(), "ok");
}

/// Objects in the supplied set that no step of the chain reaches are ignored (§15.1 "Chain
/// bound"): seventeen unrelated genesis entries do not change the verdict.
#[test]
fn m3_unrelated_genesis_entries_do_not_change_the_verdict() {
    let (mut o, now) = chain_objects();
    let want = verify_history(&o, &Persisted::default(), now);
    let base = body(&o.predecessor[2]);
    assert_eq!(base["kind"], "genesis");
    for i in 0..17 {
        let mut b = base.clone();
        b["issued"] = json!(format!("2026-11-13T09:{:02}:00Z", i));
        b["label"] = json!(format!("Unrelated {i}"));
        o.predecessor.push(unsigned_env(&b));
    }
    let v = verify_history(&o, &Persisted::default(), now);
    assert_eq!(v.code(), want.code());
    assert_eq!(v.code(), "ok");
    assert!(v.state.unwrap().verified_succession().is_some());
}
