//! Per-home head high-water marks and `refused:rollback` (§13.3, §17.2), over the candidate
//! account vector: its home's head over seq 3 is `account/head.json`, the older head over seq 2
//! is `rules/rollback/head.json`.
#![allow(clippy::unwrap_used)]
use colophon_core::v05::heads::{head_by, HeadContext};
use colophon_core::v05::history::{verify_history, Objects, Persisted};
use colophon_core::v05::{Failure, Reason};
use std::fs;
use std::path::PathBuf;

fn cand() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/0.5/candidate")
}
const NOW: i64 = 1_794_387_660_000; // 2026-11-11T09:01:00Z

struct World {
    objects: Objects,
    new_head: Vec<u8>,
    old_head: Vec<u8>,
}
fn world() -> World {
    let mut files: Vec<_> = fs::read_dir(cand().join("account/records/authority"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    files.sort();
    let objects = Objects {
        entries: files.iter().map(|p| fs::read(p).unwrap()).collect(),
        ..Default::default()
    };
    World {
        objects,
        new_head: fs::read(cand().join("account/head.json")).unwrap(),
        old_head: fs::read(cand().join("rules/rollback/head.json")).unwrap(),
    }
}
fn with_ctx<R>(w: &World, f: impl FnOnce(HeadContext<'_>) -> R) -> R {
    let v = verify_history(&w.objects, &Persisted::default(), NOW);
    let st = v.state.unwrap();
    let homes: Vec<(String, Vec<u8>)> = st
        .current_homes()
        .into_iter()
        .map(|m| (m.request.member_id(), m.request.signing.clone()))
        .collect();
    f(HeadContext {
        account: st.account(),
        history: st.history(),
        homes: &homes,
        now_ms: NOW,
    })
}

#[test]
fn a_head_behind_the_accepted_one_is_a_rollback_and_the_mark_is_per_home() {
    let w = world();
    let home = head_by(&w.new_head).unwrap();
    let mut p = Persisted::default();
    // Accept the head over seq 3; the mark follows it.
    let h = with_ctx(&w, |c| p.accept_head(&w.new_head, c)).unwrap();
    assert_eq!(h.seq(), 3);
    assert_eq!(p.head_mark(&home), Some((3, h.digest())));
    // The older head from the same home is refused, and records nothing.
    let r = with_ctx(&w, |c| p.accept_head(&w.old_head, c));
    assert!(
        matches!(r, Err(Failure::Refused(Reason::Rollback))),
        "{r:?}"
    );
    assert_eq!(p.head_mark(&home).unwrap().0, 3);
    // Another home's mark does not apply to it; with no mark it is fine.
    let other = Persisted::default().with_head_mark(&"ab".repeat(16), 3, &"00".repeat(32));
    assert!(with_ctx(&w, |c| other.check_head(&w.old_head, c)).is_ok());
    // The same head again is not behind itself.
    assert!(with_ctx(&w, |c| p.accept_head(&w.new_head, c)).is_ok());
}

#[test]
fn a_mark_off_the_held_history_is_not_a_rollback() {
    // The marked entry was displaced (§8.7): the home's lower head is for the standing branch.
    let w = world();
    let home = head_by(&w.old_head).unwrap();
    let p = Persisted::default().with_head_mark(&home, 3, &"11".repeat(32));
    assert!(with_ctx(&w, |c| p.check_head(&w.old_head, c)).is_ok());
}

#[test]
fn marks_survive_a_checkpoint_and_a_previous_format_is_refused() {
    let w = world();
    let home = head_by(&w.new_head).unwrap();
    let mut p = Persisted::checkpoint(&w.objects, &Persisted::default(), NOW);
    with_ctx(&w, |c| p.accept_head(&w.new_head, c)).unwrap();
    let bytes = p.to_bytes().unwrap();
    let back = Persisted::from_bytes(&bytes).unwrap();
    assert_eq!(back.head_mark(&home).unwrap().0, 3);
    let r = with_ctx(&w, |c| back.check_head(&w.old_head, c));
    assert!(matches!(r, Err(Failure::Refused(Reason::Rollback))));
    // A checkpoint of the previous format (3) is refused: the caller rebuilds it.
    let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    v["version"] = 3.into();
    v.as_object_mut().unwrap().remove("head_marks");
    assert!(Persisted::from_bytes(&serde_json::to_vec(&v).unwrap()).is_err());
    // Rebuilding from the retained objects gives the same verdict as before.
    let rebuilt = Persisted::checkpoint(&w.objects, &Persisted::default(), NOW);
    assert_eq!(
        verify_history(&Objects::default(), &rebuilt, NOW).code(),
        "ok"
    );
}

#[test]
fn marks_are_shape_checked_and_carried_over_a_rebuild() {
    // M2: marks are local memory a replay cannot rebuild. An edited checkpoint with a malformed
    // mark is refused; a checkpoint of another format is refused, and `rebuild` carries its
    // marks into the checkpoint rebuilt from the retained objects.
    let w = world();
    let home = head_by(&w.new_head).unwrap();
    let mut p = Persisted::checkpoint(&w.objects, &Persisted::default(), NOW);
    with_ctx(&w, |c| p.accept_head(&w.new_head, c)).unwrap();
    let bytes = p.to_bytes().unwrap();
    let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    // A malformed mark: refused.
    let mut bad = v.clone();
    bad["head_marks"] = serde_json::json!({"not-a-member-id": [3, "00"]});
    assert!(Persisted::from_bytes(&serde_json::to_vec(&bad).unwrap()).is_err());
    // Another format: refused by from_bytes, marks carried by rebuild.
    v["version"] = 3.into();
    let old = serde_json::to_vec(&v).unwrap();
    assert!(Persisted::from_bytes(&old).is_err());
    let rebuilt = Persisted::rebuild(&w.objects, &old, NOW);
    assert_eq!(rebuilt.head_mark(&home).unwrap().0, 3);
    let back = Persisted::from_bytes(&rebuilt.to_bytes().unwrap()).unwrap();
    let r = with_ctx(&w, |c| back.check_head(&w.old_head, c));
    assert!(
        matches!(r, Err(Failure::Refused(Reason::Rollback))),
        "{r:?}"
    );
    // Garbage or a malformed mark in the old bytes carries nothing over.
    assert!(Persisted::rebuild(&w.objects, b"not json", NOW)
        .head_mark(&home)
        .is_none());
    let mut broken = v.clone();
    broken["head_marks"] = serde_json::json!({"x": [0, "y"]});
    let none = Persisted::rebuild(&w.objects, &serde_json::to_vec(&broken).unwrap(), NOW);
    assert!(none.head_mark(&home).is_none());
}
