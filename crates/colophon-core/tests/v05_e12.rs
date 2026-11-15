//! E12: three verifier fixes found by checking the spec against the code.
//! - §9.3 "A grant inside a transition": the component (and each `homes.appoint` item) is
//!   exactly `{request, terms}`, meets every rule of an immediate grant, and a home refuses
//!   the transition at admission;
//! - §16.3 "Envelopes": an unreadable Swift envelope is ignored where something else stands.
#![allow(clippy::unwrap_used)]
use base64::{engine::general_purpose::STANDARD, Engine};
use colophon_core::v05::encoding::parse_date;
use colophon_core::v05::history::{
    check_admissible_transition, verify_history, Objects, Persisted,
};
use serde_json::Value;
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
fn now_of(dir: &Path) -> i64 {
    let case: Value = serde_json::from_slice(&fs::read(dir.join("case.json")).unwrap()).unwrap();
    parse_date(case["verifier"]["now"].as_str().unwrap()).unwrap()
}
fn body(env: &[u8]) -> Value {
    let v: Value = serde_json::from_slice(env).unwrap();
    serde_json::from_slice(&STANDARD.decode(v["body"].as_str().unwrap()).unwrap()).unwrap()
}

/// The vector's history before its last entry (an `activate`), and the transition it records.
fn before_activation(name: &str) -> (Objects, Vec<u8>, i64) {
    let dir = cand().join("rules").join(name);
    let mut entries = files(&dir.join("records/authority"));
    let last = entries.pop().unwrap();
    let b = body(&last);
    assert_eq!(b["kind"], "activate", "{name}");
    let t = STANDARD.decode(b["transition"].as_str().unwrap()).unwrap();
    (
        Objects {
            entries,
            ..Default::default()
        },
        t,
        now_of(&dir),
    )
}

/// A home (and the write side, which runs the same check before it asks anyone to sign) refuses
/// at admission every transition whose activation §9.3 makes `malformed`, and admits the plain
/// one: the same rule as the verifier, at the head the home holds.
#[test]
fn a_home_refuses_a_bad_grant_inside_a_transition_at_admission() {
    for (name, ok) in [
        ("t-grant-component-shares", false),
        ("t-grant-component-extra-field", false),
        ("t-grant-component-home-key", false),
        ("t-appoint-item-shares", false),
        ("t-appoint-item-plain", true),
        ("t-grant-import-device", true),
    ] {
        let (objects, t, now) = before_activation(name);
        let v = verify_history(&objects, &Persisted::default(), now);
        assert_eq!(v.code(), "ok", "{name}");
        let st = v.state.unwrap();
        let r = check_admissible_transition(&st, &t);
        if ok {
            assert!(r.is_ok(), "{name}: {r:?}");
        } else {
            let f = r.expect_err(name);
            assert_eq!(f.code(), "malformed", "{name}: {f:?}");
        }
    }
}
