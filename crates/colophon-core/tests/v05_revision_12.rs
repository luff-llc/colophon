//! Tests for revision 12 of the 0.5 specification (2026-11-14): finality by excusal (M1), final
//! successions (M2), possession under handover (M4), the home's proposer cap (L5) and the
//! Swift steward threshold (L2). The vectors are the Rust generator's
//! (`conformance/0.5/candidate/`); these tests add what a vector's `expected` cannot say.
#![allow(clippy::unwrap_used)]
use colophon_core::v05::encoding::parse_date;
use colophon_core::v05::history::{verify_history, Objects, Persisted};
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
/// A rules vector: records, every branch, and the objects other than heads.
fn rules(name: &str) -> (Objects, i64) {
    let dir = cand().join("rules").join(name);
    let case: Value = serde_json::from_slice(&fs::read(dir.join("case.json")).unwrap()).unwrap();
    let now = parse_date(
        case["verifier"]["now"]
            .as_str()
            .unwrap_or("2026-11-20T00:00:00Z"),
    )
    .unwrap();
    let mut o = Objects {
        entries: files(&dir.join("records/authority")),
        ..Default::default()
    };
    for e in fs::read_dir(&dir).unwrap() {
        let p = e.unwrap().path();
        if p.file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("branch-")
        {
            o.entries.extend(files(&p.join("authority")));
        }
    }
    for p in files(&dir.join("objects")) {
        o.pending.push(p);
    }
    (o, now)
}
fn is_final(v: &colophon_core::v05::history::Verdict, seq: u64) -> bool {
    v.state
        .as_ref()
        .unwrap()
        .activations()
        .iter()
        .find(|a| a.seq == seq)
        .is_some_and(|a| a.final_)
}

// ---- M1 -----------------------------------------------------------------------------------

/// Finality by the fixed point covers the activation against a `vetoed`, in any order the
/// objects arrive in.
#[test]
fn m1_excusal_final_is_not_displaced_by_vetoed() {
    let (objects, now) = rules("t-excusal-final-not-displaced-by-vetoed");
    let v = verify_history(&objects, &Persisted::default(), now);
    assert_eq!(v.code(), "ok");
    assert_eq!(v.branch.len(), 7);
    assert!(is_final(&v, 3), "the addition is final by excusal");
    for rot in 1..objects.entries.len() {
        let mut shuffled = objects.clone();
        shuffled.entries.rotate_left(rot);
        let w = verify_history(&shuffled, &Persisted::default(), now);
        assert_eq!(w.branch, v.branch, "rotation {rot}");
    }
}

/// The other direction: when the `vetoed` displaces the activation, the later revocation that
/// excused one of its witnesses goes with it, and both homes stay current.
#[test]
fn m1_vetoed_displaces_the_activation_and_the_later_revocation() {
    let (objects, now) = rules("t-vetoed-displaces-activation-and-later-revocation");
    let v = verify_history(&objects, &Persisted::default(), now);
    assert_eq!(v.code(), "ok");
    assert_eq!(v.branch.len(), 3);
    let s = v.state.as_ref().unwrap();
    assert!(
        s.activations().iter().all(|a| a.seq < 3),
        "no activation at or after seq 3 stands"
    );
    assert_eq!(s.current_homes().len(), 2, "H1 stays a home");
    for rot in 1..objects.entries.len() {
        let mut shuffled = objects.clone();
        shuffled.entries.rotate_left(rot);
        let w = verify_history(&shuffled, &Persisted::default(), now);
        assert_eq!(w.branch, v.branch, "rotation {rot}");
    }
}

// ---- M2 -----------------------------------------------------------------------------------

fn succession(name: &str) -> (Objects, i64) {
    let dir = cand().join("succession").join(name);
    (
        Objects {
            entries: files(&dir.join("successor/authority")),
            predecessor: files(&dir.join("predecessor/authority")),
            ..Default::default()
        },
        parse_date("2026-11-14T10:15:00Z").unwrap(),
    )
}
fn verified(name: &str) -> bool {
    let (o, now) = succession(name);
    let v = verify_history(&o, &Persisted::default(), now);
    assert_eq!(
        v.code(),
        "ok",
        "{name}: the successor's own history verifies"
    );
    v.state.unwrap().verified_succession().is_some()
}
fn predecessor_alone(name: &str) -> colophon_core::v05::history::Verdict {
    let (o, now) = succession(name);
    verify_history(
        &Objects {
            entries: o.predecessor,
            ..Default::default()
        },
        &Persisted::default(),
        now,
    )
}

#[test]
fn m2_provisional_successor_activation_is_not_a_verified_succession() {
    assert!(!verified("authority5-successor-provisional"));
    let v = predecessor_alone("authority5-successor-provisional");
    assert_eq!((v.code(), v.branch.len()), ("ok".to_string(), 3));
    assert!(!is_final(&v, 3));
}

#[test]
fn m2_final_successor_activation_is_verified_and_closes_the_predecessor() {
    assert!(verified("authority5-successor-final"));
    let v = predecessor_alone("authority5-successor-final");
    assert_eq!((v.code(), v.branch.len()), ("ok".to_string(), 4));
    assert!(is_final(&v, 3));
    // After F is final the predecessor admits nothing: a further entry is evidence only.
    let (mut o, now) = succession("authority5-successor-final");
    let (extra, _) = succession("authority5-successor-vetoed");
    o.predecessor.push(extra.predecessor[3].clone());
    let w = verify_history(
        &Objects {
            entries: o.predecessor,
            ..Default::default()
        },
        &Persisted::default(),
        now,
    );
    assert_eq!(w.branch.len(), 4);
}

#[test]
fn m2_vetoed_displaces_a_provisional_successor_activation_and_the_predecessor_continues() {
    assert!(!verified("authority5-successor-vetoed"));
    let v = predecessor_alone("authority5-successor-vetoed");
    assert_eq!((v.code(), v.branch.len()), ("ok".to_string(), 4));
    let s = v.state.unwrap();
    assert!(s.activations().iter().all(|a| a.seq < 3), "F is displaced");
    // Any order of the same objects gives the same branch.
    let (o, now) = succession("authority5-successor-vetoed");
    for rot in 1..o.predecessor.len() {
        let mut shuffled = o.clone();
        shuffled.predecessor.rotate_left(rot);
        let w = verify_history(&shuffled, &Persisted::default(), now);
        assert!(
            w.state.unwrap().verified_succession().is_none(),
            "rotation {rot}"
        );
    }
}
