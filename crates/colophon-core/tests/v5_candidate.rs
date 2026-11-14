//! The generator for every 0.5 candidate vector under `conformance/0.5/candidate/`.
//!
//! One Rust generator owns all the files (it replaces the Python `generate.py`, `rules.py` and
//! `rules_v8.py`). It builds 0.5 bytes from the published test keys and records the outcome the
//! specification says a verifier must return. It does not call the 0.5 verifier
//! (`colophon_core::v05`): canonical JSON, signing and entry building are written out in
//! `v5_candidate/kit.rs`, so the vectors stay independent of the code they test. Signatures are
//! deterministic (RFC 6979 over SHA-256), so a run reproduces every file byte for byte.
//!
//! Opt-in: both tests are `#[ignore]`.
//!
//! ```sh
//! # compare the files on disk with what the generator builds
//! cargo test -p colophon-core --test v5_candidate -- --ignored v5_generator_check
//! # rewrite the files (also needs COLOPHON_WRITE_V5_VECTORS=1)
//! COLOPHON_WRITE_V5_VECTORS=1 cargo test -p colophon-core --test v5_candidate -- --ignored v5_generator_write
//! ```
#![allow(clippy::unwrap_used)]
#[macro_use]
#[path = "v5_candidate/kit.rs"]
mod kit;
#[path = "v5_candidate/cases_a.rs"]
mod cases_a;
#[path = "v5_candidate/cases_v8.rs"]
mod cases_v8;
#[path = "v5_candidate/swift.rs"]
mod swift;

use kit::*;
use serde_json::Value;
use std::path::Path;

fn build() -> (Out, usize) {
    let mut out = Out::new();
    let (_p1, summary) = cases_a::part1(&mut out);
    cases_v8::part3(&mut out);
    let honest = self_check(&out);
    eprintln!(
        "{} files built; {} 0.4 bodies re-canonicalized; {honest} call/link signatures verified",
        out.len(),
        summary.recanonicalized
    );
    (out, summary.recanonicalized)
}

/// Every envelope in the output is canonical JSON, and every honest call and link signature verifies.
fn self_check(out: &Out) -> usize {
    let keys = cases_a::CHECK_KEYS.get().unwrap();
    let mut honest = 0;
    for (rel, data) in out {
        if !rel.ends_with(".json")
            || rel.ends_with("case.json")
            || rel == "keys.json"
            || rel == "identifiers.json"
        {
            continue;
        }
        let env = serde_json::from_slice::<Value>(data)
            .unwrap_or_else(|e| panic!("{rel} is a .json file that does not parse: {e}"));
        let Some(body_text) = env.get("body").and_then(Value::as_str) else {
            continue;
        };
        if rel.contains("non-canonical") {
            continue;
        }
        let body = unb64(body_text);
        let obj: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(canonical(&obj), body, "{rel}");
        if obj["protocol"] == "colophon/call/5" && rel.starts_with("calls/") {
            let ok = verify_raw(
                &unb64(obj["key"].as_str().unwrap()),
                &body,
                &unb64(env["signature"].as_str().unwrap()),
            );
            assert_eq!(ok, !rel.contains("invalid"), "{rel}");
            honest += ok as usize;
            for l in obj
                .get("links")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let le: Value = serde_json::from_slice(&unb64(l.as_str().unwrap())).unwrap();
                let lb = unb64(le["body"].as_str().unwrap());
                let lo: Value = serde_json::from_slice(&lb).unwrap();
                let from = keys
                    .iter()
                    .find(|k| k.id == lo["from"].as_str().unwrap())
                    .unwrap();
                assert!(
                    verify_raw(&from.point, &lb, &unb64(le["signature"].as_str().unwrap())),
                    "{rel}"
                );
                honest += 1;
            }
        }
    }
    honest
}

/// Files under the vector directory that the generator does not produce and that are not one of
/// the hand-kept sources: `README.md` and `probes/swift-der/**`.
fn strays(out: &Out, dir: &Path) -> Vec<String> {
    fn walk(dir: &Path, base: &Path, found: &mut Vec<String>) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in rd {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, base, found);
            } else {
                let rel = path
                    .strip_prefix(base)
                    .unwrap()
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                found.push(rel);
            }
        }
    }
    let mut found = Vec::new();
    walk(dir, dir, &mut found);
    found.retain(|rel| {
        rel != "README.md" && !rel.starts_with("probes/swift-der/") && !out.contains_key(rel)
    });
    found.sort();
    found
}

/// Generated files that are missing or differ from the files on disk.
fn differences(out: &Out, dir: &Path) -> Vec<String> {
    out.iter()
        .filter(|(rel, data)| {
            std::fs::read(dir.join(rel))
                .map(|d| d != **data)
                .unwrap_or(true)
        })
        .map(|(rel, _)| rel.clone())
        .collect()
}

/// `--check`: every generated file matches the file on disk byte for byte, and no other file
/// is there (besides `README.md` and `probes/swift-der/**`).
#[test]
#[ignore = "opt-in: regenerates every candidate vector and compares it with the files on disk"]
fn v5_generator_check() {
    let (out, _) = build();
    let bad = differences(&out, &candidate());
    assert!(
        bad.is_empty(),
        "differs from generator ({} of {}):\n  {}",
        bad.len(),
        out.len(),
        bad.join("\n  ")
    );
    let stray = strays(&out, &candidate());
    assert!(
        stray.is_empty(),
        "files the generator does not produce ({}):\n  {}",
        stray.len(),
        stray.join("\n  ")
    );
    eprintln!("ok: {} files match", out.len());
}

/// Write the files. Needs `COLOPHON_WRITE_V5_VECTORS=1` as well as `--ignored`.
#[test]
#[ignore = "opt-in: rewrites the candidate vectors; also needs COLOPHON_WRITE_V5_VECTORS=1"]
fn v5_generator_write() {
    if std::env::var("COLOPHON_WRITE_V5_VECTORS").as_deref() != Ok("1") {
        eprintln!("set COLOPHON_WRITE_V5_VECTORS=1 to write the vectors");
        return;
    }
    let (out, _) = build();
    let dir = candidate();
    let stray = strays(&out, &dir);
    assert!(
        stray.is_empty(),
        "refusing to write: files the generator does not produce (remove or keep them by hand):\n  {}",
        stray.join("\n  ")
    );
    for (rel, data) in &out {
        let path = dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, data).unwrap();
    }
    eprintln!("wrote {} files", out.len());
}
