//! §8.7 "Choosing receipts" is a rule for a recorder; a verifier judges the receipts an entry
//! carries for validity only (revision 13 fix round).
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
fn an_entry_is_judged_by_the_receipts_it_carries_whatever_else_is_held() {
    // §8.7 (revision 13 fix round): the choosing rule is for a recorder. A verifier checks
    // validity of what the entry carries and never refuses it for a different valid receipt.
    for name in [
        "t-vetoed-choice-right",
        "t-vetoed-late-receipt-skipped",
        "t-vetoed-other-valid-receipt-accepted",
    ] {
        assert_eq!(code(&vector(name, None)), ("ok".into(), 3), "{name}");
    }
    for skip in ["receipt-low", "receipt-high"] {
        for name in [
            "t-vetoed-choice-right",
            "t-vetoed-other-valid-receipt-accepted",
        ] {
            assert_eq!(
                code(&vector(name, Some(skip))).0,
                "ok",
                "{name} without {skip}"
            );
        }
    }
}

#[test]
fn input_order_does_not_change_the_verdict() {
    let mut o = vector("t-vetoed-other-valid-receipt-accepted", None);
    o.pending.reverse();
    o.entries.reverse();
    assert_eq!(code(&o), ("ok".into(), 3));
}
