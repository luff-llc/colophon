//! §8.7 "Choosing receipts" for a veto's receipts, enforced by the verifier over the objects it
//! holds together with the entry's own (revision 13). A verifier that does not hold a receipt
//! the recorder held must not refuse a correctly recorded `vetoed`.
#![allow(clippy::unwrap_used)]
use colophon_core::v05::encoding::parse_date;
use colophon_core::v05::history::{verify_history, Objects, Persisted};
use std::fs;
use std::path::PathBuf;

fn vector(name: &str, skip_object: Option<&str>) -> Objects {
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
        if skip_object
            .is_some_and(|s| p.file_name().unwrap().to_string_lossy() == format!("{s}.json"))
        {
            continue;
        }
        o.pending.push(fs::read(p).unwrap());
    }
    o
}
fn now() -> i64 {
    // The vectors' verifier time is DUE0 + 60 s after the base account's clock origin.
    parse_date("2026-11-20T00:00:00Z").unwrap()
}
fn code(o: &Objects) -> (String, u64) {
    let v = verify_history(o, &Persisted::default(), now());
    (v.code(), v.seq())
}

#[test]
fn the_chosen_receipt_is_accepted_and_another_selection_is_refused() {
    assert_eq!(code(&vector("t-vetoed-choice-right", None)).0, "ok");
    assert_eq!(code(&vector("t-vetoed-late-receipt-skipped", None)).0, "ok");
    assert_eq!(
        code(&vector("t-vetoed-wrong-choice", None)),
        ("malformed".into(), 3)
    );
}

#[test]
fn a_verifier_missing_a_receipt_the_recorder_held_does_not_refuse() {
    // The right entry, the verifier holding neither of the veto's receipts outside the entry.
    assert_eq!(
        code(&vector("t-vetoed-choice-right", Some("receipt-low"))).0,
        "ok"
    );
    assert_eq!(
        code(&vector("t-vetoed-choice-right", Some("receipt-high"))).0,
        "ok"
    );
    // Held without the lower receipt, the entry carrying the higher one is the only choice
    // that verifier can see, so it is not refused (the recorder may not have held the other).
    assert_eq!(
        code(&vector("t-vetoed-wrong-choice", Some("receipt-low"))).0,
        "ok"
    );
}

#[test]
fn input_order_does_not_change_the_choice() {
    let mut o = vector("t-vetoed-wrong-choice", None);
    o.pending.reverse();
    o.entries.reverse();
    assert_eq!(code(&o), ("malformed".into(), 3));
}
