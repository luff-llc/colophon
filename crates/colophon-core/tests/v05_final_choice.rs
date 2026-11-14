//! §8.7 "Choosing heads" for a `final` (revision 13): per witness, the covering head with the
//! lowest body digest among the usable ones; enforced over the heads the verifier holds
//! together with the entry's own.
#![allow(clippy::unwrap_used)]
use colophon_core::v05::encoding::parse_date;
use colophon_core::v05::history::{verify_history, Objects, Persisted};
use std::fs;
use std::path::PathBuf;

fn vector(name: &str, skip: &[&str]) -> Objects {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/0.5/candidate/rules")
        .join(name);
    let mut files: Vec<_> = fs::read_dir(dir.join("records/authority"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    files.sort();
    let mut o = Objects {
        entries: files.iter().map(|p| fs::read(p).unwrap()).collect(),
        ..Default::default()
    };
    let mut objs: Vec<_> = fs::read_dir(dir.join("objects"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    objs.sort();
    for p in objs {
        let n = p.file_name().unwrap().to_string_lossy().to_string();
        if skip.iter().any(|s| n == format!("{s}.json")) {
            continue;
        }
        o.heads.push(fs::read(p).unwrap());
    }
    o
}
fn code(o: &Objects, now: &str) -> (String, u64) {
    let v = verify_history(o, &Persisted::default(), parse_date(now).unwrap());
    (v.code(), v.seq())
}
// The vectors' verifier clock is DUE0 + 200 s past the base account's origin.
const NOW: &str = "2026-11-14T00:00:00Z";

fn now_of(name: &str) -> String {
    let c: serde_json::Value = serde_json::from_slice(
        &fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../conformance/0.5/candidate/rules")
                .join(name)
                .join("case.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let _ = NOW;
    c["verifier"]["now"].as_str().unwrap().to_string()
}

#[test]
fn the_lowest_digest_head_is_accepted_and_the_other_is_refused() {
    for (name, want) in [
        ("t-final-head-choice-right", ("ok", 4)),
        ("t-final-head-ahead-ignored", ("ok", 4)),
        ("t-final-head-choice-wrong", ("malformed", 4)),
    ] {
        assert_eq!(
            code(&vector(name, &[]), &now_of(name)),
            (want.0.to_string(), want.1),
            "{name}"
        );
    }
}

#[test]
fn a_verifier_missing_the_lower_head_does_not_refuse() {
    let n = "t-final-head-choice-wrong";
    // Without the lower head the verifier has no evidence the entry chose wrongly.
    assert_eq!(code(&vector(n, &["head-H1-low"]), &now_of(n)).0, "ok");
    let n = "t-final-head-choice-right";
    assert_eq!(code(&vector(n, &["head-H1-high"]), &now_of(n)).0, "ok");
    assert_eq!(code(&vector(n, &["head-H1-low"]), &now_of(n)).0, "ok");
}

#[test]
fn the_verdict_does_not_change_as_the_clock_advances() {
    // A head dated ahead of the entry is not usable, whatever the verifier's clock says later:
    // judging usability by the verifier's clock would turn an `ok` into `malformed` over time.
    let n = "t-final-head-ahead-ignored";
    assert_eq!(
        code(&vector(n, &[]), "2026-11-20T00:00:00Z"),
        ("ok".into(), 4)
    );
}
