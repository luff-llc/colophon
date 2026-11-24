//! Properties of the history verifier (§8):
//! - the verdict is a function of the object set: the same objects in any order give the same
//!   verdict (branch, stop, conflicts, final state);
//! - no panic on hostile input (byte-level and JSON-level mutation of every vector's objects);
//! - the high-water mark detects rollback and never selects a branch.
#![allow(clippy::unwrap_used)]
#[path = "v05_attack_support/mod.rs"]
mod support;
use base64::{engine::general_purpose::STANDARD, Engine};
use colophon_core::v05::encoding::{canonical, parse_date};
use colophon_core::v05::history::{verify_history, Objects, Persisted, Verdict};
use serde_json::Value;
use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use support::Rng;

fn cand() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/0.5")
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
fn cases() -> Vec<(PathBuf, i64)> {
    let mut v: Vec<PathBuf> = fs::read_dir(cand().join("rules"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.join("records/authority").exists())
        .collect();
    v.sort();
    v.into_iter()
        .map(|d| {
            let case: Value =
                serde_json::from_slice(&fs::read(d.join("case.json")).unwrap()).unwrap();
            let now = parse_date(
                case["verifier"]["now"]
                    .as_str()
                    .unwrap_or("2026-11-20T00:00:00Z"),
            )
            .unwrap();
            (d, now)
        })
        .collect()
}
fn summary(v: &Verdict) -> String {
    let state = v.state.as_ref().map(|s| {
        (
            s.keyring().controllers.keys().cloned().collect::<Vec<_>>(),
            s.vault_retiring(),
            s.activations()
                .iter()
                .map(|a| (a.seq, a.final_))
                .collect::<Vec<_>>(),
            s.veto_counts().clone(),
            s.members().len(),
        )
    });
    format!("{:?} {:?} {:?} {:?}", v.branch, v.stop, v.conflicts, state)
}
fn shuffle<T>(r: &mut Rng, v: &mut [T]) {
    for i in (1..v.len()).rev() {
        let j = r.below(i as u64 + 1) as usize;
        v.swap(i, j);
    }
}

#[test]
fn verdict_is_independent_of_object_order() {
    let mut r = Rng(0x0bde_c0de);
    let mut checked = 0;
    for (dir, now) in cases() {
        // The vector, and the vector with broken envelopes over one of its bodies.
        let plain = objects_of(&dir);
        let mut broken = plain.clone();
        if !broken.entries.is_empty() {
            let i = r.below(broken.entries.len() as u64) as usize;
            let copies = broken_copies(&broken.entries[i]);
            broken.entries.extend(copies);
        }
        for base in [plain, broken] {
            let want = full(&verify_history(&base, &Persisted::default(), now));
            for _ in 0..8 {
                let mut o = base.clone();
                shuffle(&mut r, &mut o.entries);
                shuffle(&mut r, &mut o.pending);
                shuffle(&mut r, &mut o.heads);
                // Duplicates of an object change nothing either.
                if r.chance(1, 3) && !o.entries.is_empty() {
                    let i = r.below(o.entries.len() as u64) as usize;
                    let dup = o.entries[i].clone();
                    o.entries.push(dup);
                }
                let got = full(&verify_history(&o, &Persisted::default(), now));
                assert_eq!(got, want, "{}", dir.display());
                checked += 1;
            }
        }
    }
    assert!(checked > 1200, "{checked}");
}

/// The other history vectors, as the conformance runner builds them: `account`, `upgrade/*`
/// (a `/4` prefix incorporated by an `upgrade`) and `succession/*` (a `/5` or Swift
/// predecessor beside the successor).
fn other_cases() -> Vec<(PathBuf, Objects, i64)> {
    let mut v = vec![(
        cand().join("account"),
        objects_of(&cand().join("account")),
        parse_date("2026-11-11T09:01:00Z").unwrap(),
    )];
    for top in ["upgrade", "succession"] {
        let mut dirs: Vec<PathBuf> = fs::read_dir(cand().join(top))
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.join("case.json").exists())
            .collect();
        dirs.sort();
        for d in dirs {
            if top == "upgrade" {
                let o = objects_of(&d);
                v.push((d, o, parse_date("2026-12-01T00:00:00Z").unwrap()));
                continue;
            }
            let case: Value =
                serde_json::from_slice(&fs::read(d.join("case.json")).unwrap()).unwrap();
            let mut o = Objects {
                entries: files(&d.join("successor/authority")),
                predecessor: files(&d.join("predecessor/authority")),
                ..Default::default()
            };
            for (name, list) in [
                ("genesis-receipt.json", &mut o.pending),
                ("successor-head.json", &mut o.heads),
            ] {
                if d.join(name).exists() {
                    list.push(fs::read(d.join(name)).unwrap());
                }
            }
            let now = parse_date(
                case["expected"]["now"]
                    .as_str()
                    .unwrap_or("2026-11-14T10:15:00Z"),
            )
            .unwrap();
            v.push((d, o, now));
        }
    }
    v
}
/// The whole verdict, for comparisons that must be exact: every field of the verdict (branch,
/// stop, rollback, conflicts, held_until) and the whole folded state, by its `Debug` form and by
/// its serialized form (policy, namespaces, members, suspensions, succession, migration...).
fn full(v: &Verdict) -> String {
    format!(
        "{v:?}\n{}",
        serde_json::to_string(&v.state).expect("the state serializes")
    )
}

/// §8.6: the verdict is a function of the object set, for every history vector, however the
/// entries, pending objects, heads and predecessor entries arrive: as stored, reversed, in byte
/// order and shuffled, and the same on every repeat.
#[test]
fn every_history_vector_has_one_verdict_whatever_the_order() {
    let mut r = Rng(0x05de_0dde);
    let mut checked = 0;
    for (dir, plain, now) in other_cases() {
        // The vector, and the vector with broken envelopes over one body of its entries and one
        // of its predecessor entries: the set changes, so its verdict may too, but not with order.
        let mut broken = plain.clone();
        for list in [&mut broken.entries, &mut broken.predecessor] {
            if !list.is_empty() {
                let i = r.below(list.len() as u64) as usize;
                let copies = broken_copies(&list[i]);
                list.extend(copies);
            }
        }
        for base in [plain, broken] {
            let want = full(&verify_history(&base, &Persisted::default(), now));
            for variant in 0..8 {
                let mut o = base.clone();
                match variant {
                    0 => {}
                    1 => {
                        o.entries.reverse();
                        o.pending.reverse();
                        o.heads.reverse();
                        o.predecessor.reverse();
                    }
                    2 => {
                        o.entries.sort();
                        o.pending.sort();
                        o.heads.sort();
                        o.predecessor.sort();
                    }
                    _ => {
                        shuffle(&mut r, &mut o.entries);
                        shuffle(&mut r, &mut o.pending);
                        shuffle(&mut r, &mut o.heads);
                        shuffle(&mut r, &mut o.predecessor);
                    }
                }
                let got = full(&verify_history(&o, &Persisted::default(), now));
                assert_eq!(got, want, "{} (variant {variant})", dir.display());
                checked += 1;
            }
        }
    }
    assert!(checked > 600, "{checked}");
}

/// Copies of an envelope over the same body that do not verify, each broken another way:
/// one bit of the signature flipped (the rest of the bytes as published), a signature that is
/// not base64, and `cosignatures` that is not an array. The `body` field is never touched.
fn broken_copies(envelope: &[u8]) -> Vec<Vec<u8>> {
    let text = std::str::from_utf8(envelope).unwrap();
    let v: Value = serde_json::from_str(text).unwrap();
    let mut out = Vec::new();
    if let Some(sig) = v["signature"].as_str() {
        let mut raw = STANDARD.decode(sig).unwrap();
        *raw.last_mut().unwrap() ^= 1;
        let flipped = STANDARD.encode(raw);
        assert_eq!(flipped.len(), sig.len());
        out.push(text.replacen(sig, &flipped, 1).into_bytes());
        let mut w = v.clone();
        w["signature"] = Value::String("!not base64!".into());
        out.push(serde_json::to_vec(&w).unwrap());
    }
    let mut w = v.clone();
    w["cosignatures"] = Value::from(7);
    out.push(serde_json::to_vec(&w).unwrap());
    for c in &out {
        assert_ne!(c.as_slice(), envelope);
        let cv: Value = serde_json::from_slice(c).unwrap();
        assert_eq!(cv["body"], v["body"]);
    }
    out
}

/// §2.2: several envelopes over one body are one object, valid where any envelope held over it
/// verifies; an envelope that does not verify is ignored and never makes the object fail. A
/// broken envelope over a valid body (a flipped signature bit, a signature that is not base64,
/// `cosignatures` that is not an array) must not stand in for the valid one or defeat it, in a
/// `/5` history, in a `/4` prefix incorporated by an upgrade (§16.1) or in a Swift predecessor
/// (§16.3). Each broken copy is put first, then last: the whole verdict is that of the vector.
#[test]
fn a_broken_envelope_over_a_valid_body_never_stands_in_for_it() {
    fn check(
        what: &str,
        base: &Objects,
        now: i64,
        indices: &[usize],
        list: fn(&mut Objects) -> &mut Vec<Vec<u8>>,
    ) {
        let want = full(&verify_history(base, &Persisted::default(), now));
        for &i in indices {
            let mut probe = base.clone();
            let copies = broken_copies(&list(&mut probe)[i]);
            assert!(copies.len() >= 2, "{what} entry {}", i + 1);
            for (k, bad) in copies.into_iter().enumerate() {
                for first in [true, false] {
                    let mut o = base.clone();
                    if first {
                        list(&mut o).insert(0, bad.clone());
                    } else {
                        list(&mut o).push(bad.clone());
                    }
                    let v = verify_history(&o, &Persisted::default(), now);
                    assert_eq!(
                        full(&v),
                        want,
                        "{what} entry {} copy {k} first={first}: {} at {}",
                        i + 1,
                        v.code(),
                        v.seq()
                    );
                }
            }
        }
    }

    // `/5`: the genesis and the entry at seq 3 of a valid history.
    let (base, now) = vector("i-add-approve");
    let plain = verify_history(&base, &Persisted::default(), now);
    assert_eq!((plain.code(), plain.seq()), ("ok".to_string(), 3));
    check("/5", &base, now, &[0, 2], |o| &mut o.entries);

    // `/4` prefix: the 0.4 genesis and the `upgrade` entry.
    let base = objects_of(&cand().join("upgrade/accept"));
    let now = parse_date("2026-12-01T00:00:00Z").unwrap();
    let plain = verify_history(&base, &Persisted::default(), now);
    assert_eq!((plain.code(), plain.seq()), ("ok".to_string(), 3));
    check("/4", &base, now, &[0, 2], |o| &mut o.entries);

    // Swift predecessor: its genesis and the entry after it.
    let (_, base, now) = other_cases()
        .into_iter()
        .find(|(d, _, _)| d.ends_with("succession/swift-keyring"))
        .unwrap();
    let plain = verify_history(&base, &Persisted::default(), now);
    assert!(plain
        .state
        .as_ref()
        .is_some_and(|s| s.verified_succession().is_some()));
    check("Swift predecessor", &base, now, &[0, 1], |o| {
        &mut o.predecessor
    });
}

/// Envelopes that cannot be read (§16.3 "Envelopes"), beside the entry over `envelope`'s body
/// at its seq: its body's `issued`, then `signer` unreadable (seq still readable); the body not
/// JSON, `body` not a string, the outer JSON unreadable, and over 2 MiB (no seq readable).
fn unreadable_copies(envelope: &[u8]) -> Vec<Vec<u8>> {
    let v: Value = serde_json::from_slice(envelope).unwrap();
    let body: Value =
        serde_json::from_slice(&STANDARD.decode(v["body"].as_str().unwrap()).unwrap()).unwrap();
    let with_body = |b: &Value| {
        let mut w = v.clone();
        w["body"] = Value::String(STANDARD.encode(canonical(b).unwrap()));
        serde_json::to_vec(&w).unwrap()
    };
    let mut issued = body.clone();
    issued["issued"] = Value::from("soon");
    let mut signer = body.clone();
    signer["by"] = Value::from("controller");
    signer["signer"] = Value::from(7);
    let mut not_json = v.clone();
    not_json["body"] = Value::String(STANDARD.encode(b"not json"));
    let mut not_string = v.clone();
    not_string["body"] = Value::from(2);
    let mut big = v.clone();
    big["padding"] = Value::String("x".repeat(2_097_152));
    vec![
        with_body(&issued),
        with_body(&signer),
        serde_json::to_vec(&not_json).unwrap(),
        serde_json::to_vec(&not_string).unwrap(),
        b"{\"body\":".to_vec(),
        serde_json::to_vec(&big).unwrap(),
    ]
}

/// §16.3 "Envelopes", as §2.2 for `/5` and `/4` entries: an envelope that cannot be read is
/// ignored where a readable entry stands at its seq, first or last, in the history verifier and
/// in `swift::verify` called directly (as the library reader and the move paths call it); where
/// nothing readable is at that seq the predecessor fails, with the same failure in every order.
#[test]
fn an_unreadable_swift_envelope_is_ignored_where_another_stands() {
    use colophon_core::v05::history::swift;
    let (_, base, now) = other_cases()
        .into_iter()
        .find(|(d, _, _)| d.ends_with("succession/swift-keyring"))
        .unwrap();
    let want = full(&verify_history(&base, &Persisted::default(), now));
    let direct = format!("{:?}", swift::verify(&base.predecessor).map(|h| h.entries.len()));
    assert!(direct.starts_with("Ok("), "{direct}");
    for i in 0..base.predecessor.len() {
        for (k, bad) in unreadable_copies(&base.predecessor[i]).into_iter().enumerate() {
            for first in [true, false] {
                let mut o = base.clone();
                if first {
                    o.predecessor.insert(0, bad.clone());
                } else {
                    o.predecessor.push(bad.clone());
                }
                let v = verify_history(&o, &Persisted::default(), now);
                assert_eq!(full(&v), want, "entry {} copy {k} first={first}", i + 1);
                let got = format!("{:?}", swift::verify(&o.predecessor).map(|h| h.entries.len()));
                assert_eq!(got, direct, "direct: entry {} copy {k} first={first}", i + 1);
            }
        }
    }
    // Entry 2 replaced by two unreadable envelopes at seq 2: nothing readable stands there, so
    // the predecessor fails, the same way whichever arrives first.
    let copies = unreadable_copies(&base.predecessor[1]);
    let mut o = base.clone();
    o.predecessor[1] = copies[0].clone();
    o.predecessor.push(copies[1].clone());
    let a = swift::verify(&o.predecessor).map(|h| h.entries.len());
    assert!(a.is_err(), "{a:?}");
    let va = full(&verify_history(&o, &Persisted::default(), now));
    o.predecessor.reverse();
    assert_eq!(
        format!("{:?}", swift::verify(&o.predecessor).map(|h| h.entries.len())),
        format!("{a:?}")
    );
    assert_eq!(full(&verify_history(&o, &Persisted::default(), now)), va);
}

#[test]
fn high_water_detects_rollback_and_never_selects_a_branch() {
    let dir = cand().join("rules/t-conflict-no-evidence");
    let o = objects_of(&dir);
    let now = parse_date("2026-11-11T09:01:40Z").unwrap();
    let plain = verify_history(&o, &Persisted::default(), now);
    for e in &o.entries {
        let body: Value = serde_json::from_slice(
            &STANDARD
                .decode(
                    serde_json::from_slice::<Value>(e).unwrap()["body"]
                        .as_str()
                        .unwrap(),
                )
                .unwrap(),
        )
        .unwrap();
        let seq = body["seq"].as_u64().unwrap();
        let d = colophon_core::v05::encoding::digest(
            &STANDARD
                .decode(
                    serde_json::from_slice::<Value>(e).unwrap()["body"]
                        .as_str()
                        .unwrap(),
                )
                .unwrap(),
        );
        let v = verify_history(&o, &Persisted::high_water(seq, d), now);
        assert_eq!(
            summary(&v),
            summary(&plain),
            "the high-water mark selected a branch"
        );
    }
    // A high-water mark past the verified branch is a rollback.
    let ok = verify_history(
        &objects_of(&cand().join("rules/t-remove-after-delay")),
        &Persisted::high_water(9, "0".repeat(64)),
        parse_date("2026-11-14T09:06:00Z").unwrap(),
    );
    assert!(ok.rollback);
}

fn mutate_json(r: &mut Rng, v: &mut Value, depth: u32) {
    match v {
        Value::Object(m) if !m.is_empty() => {
            let keys: Vec<String> = m.keys().cloned().collect();
            let k = &keys[r.below(keys.len() as u64) as usize];
            match r.below(6) {
                0 => {
                    m.remove(k);
                }
                1 => {
                    m.insert(format!("x{}", r.below(9)), Value::Null);
                }
                2 if depth < 6 => mutate_json(r, m.get_mut(k).unwrap(), depth + 1),
                3 => {
                    m.insert(k.clone(), Value::from(r.next() >> r.below(64)));
                }
                4 => {
                    m.insert(k.clone(), Value::String("A".repeat(r.below(70) as usize)));
                }
                _ => {
                    m.insert(k.clone(), Value::Array(vec![]));
                }
            }
        }
        Value::Array(a) if !a.is_empty() => {
            let i = r.below(a.len() as u64) as usize;
            if depth < 6 && r.chance(1, 2) {
                mutate_json(r, &mut a[i], depth + 1);
            } else {
                a.remove(i);
            }
        }
        Value::String(s) => {
            if let Ok(inner) = STANDARD.decode(s.as_bytes()) {
                // Embedded envelopes: mutate inside and re-encode.
                if let Ok(mut iv) = serde_json::from_slice::<Value>(&inner) {
                    mutate_json(r, &mut iv, depth + 1);
                    *s = STANDARD.encode(canonical(&iv).unwrap_or_default());
                    return;
                }
            }
            s.push('x');
        }
        Value::Number(_) => *v = Value::from(-(r.below(1_000) as i64)),
        _ => *v = Value::Bool(true),
    }
}

#[test]
fn no_panics_on_hostile_objects() {
    let mut r = Rng(0xfa22_5eed);
    let mut runs = 0;
    for (dir, now) in cases() {
        let base = objects_of(&dir);
        for _ in 0..15 {
            let mut o = base.clone();
            let pick = r.below(3);
            let list = match pick {
                0 => &mut o.entries,
                1 => &mut o.pending,
                _ => &mut o.heads,
            };
            if list.is_empty() {
                continue;
            }
            let i = r.below(list.len() as u64) as usize;
            let bytes = &mut list[i];
            match r.below(4) {
                0 => {
                    let k = r.below(bytes.len() as u64) as usize;
                    bytes[k] ^= 1 << r.below(8);
                }
                1 => bytes.truncate(r.below(bytes.len() as u64) as usize),
                _ => {
                    // Mutate the signed body (signatures then fail, but every parser runs).
                    let mut env: Value = match serde_json::from_slice(bytes) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    if let Some(b) = env
                        .get("body")
                        .and_then(Value::as_str)
                        .and_then(|b| STANDARD.decode(b).ok())
                    {
                        if let Ok(mut body) = serde_json::from_slice::<Value>(&b) {
                            mutate_json(&mut r, &mut body, 0);
                            env["body"] = Value::String(
                                STANDARD.encode(canonical(&body).unwrap_or_default()),
                            );
                        }
                    }
                    *bytes = serde_json::to_vec(&env).unwrap();
                }
            }
            for clock in [now, i64::MIN, i64::MAX, 0] {
                let res = catch_unwind(AssertUnwindSafe(|| {
                    verify_history(&o, &Persisted::high_water(u64::MAX, "z".into()), clock)
                }));
                assert!(res.is_ok(), "panic on {} (clock {clock})", dir.display());
                runs += 1;
            }
        }
    }
    // Garbage objects.
    for _ in 0..500 {
        let mut garbage = |n: u64| -> Vec<Vec<u8>> {
            (0..r.below(n))
                .map(|_| {
                    let len = r.below(200) as usize;
                    r.bytes(len)
                })
                .collect()
        };
        let o = Objects {
            entries: garbage(4),
            pending: garbage(3),
            heads: garbage(3),
            predecessor: garbage(3),
        };
        assert!(catch_unwind(AssertUnwindSafe(|| verify_history(
            &o,
            &Persisted::default(),
            0
        )))
        .is_ok());
        runs += 1;
    }
    assert!(runs > 3_000, "{runs}");
}

fn vector(name: &str) -> (Objects, i64) {
    let dir = cand().join("rules").join(name);
    let case: Value = serde_json::from_slice(&fs::read(dir.join("case.json")).unwrap()).unwrap();
    (
        objects_of(&dir),
        parse_date(case["verifier"]["now"].as_str().unwrap()).unwrap(),
    )
}
fn body_digest(env: &[u8]) -> String {
    let env: Value = serde_json::from_slice(env).unwrap();
    colophon_core::v05::encoding::digest(&STANDARD.decode(env["body"].as_str().unwrap()).unwrap())
}

#[test]
fn all_witnesses_excused_makes_addition_final_without_empty_final() {
    let (objects, now) = vector("t-all-witnesses-excused");
    // Revoking the first home is final, but the addition still needs the other home.
    let prefix = Objects {
        entries: objects.entries[..5].to_vec(),
        ..Default::default()
    };
    let v = verify_history(&prefix, &Persisted::default(), now);
    assert_eq!(v.code(), "ok");
    assert!(
        !v.state
            .unwrap()
            .activations()
            .iter()
            .find(|a| a.seq == 3)
            .unwrap()
            .final_
    );
    // Revoking the last home makes the addition final; its added key may sign seq 7.
    let v = verify_history(&objects, &Persisted::default(), now);
    assert_eq!((v.code(), v.seq()), ("ok".into(), 7));
    assert!(v.state.unwrap().activations().iter().all(|a| a.final_));
}

#[test]
fn three_candidate_comparison_cycle_is_an_unresolved_fork() {
    let (objects, now) = vector("t-three-candidate-cycle");
    let dir = cand().join("rules/t-three-candidate-cycle");
    let low = body_digest(&files(&dir.join("branch-low/authority"))[0]);
    let high = body_digest(&files(&dir.join("branch-high/authority"))[0]);
    let vetoed = body_digest(&files(&dir.join("records/authority"))[2]);
    // Prove the cycle from actual verification of each two-candidate subset.
    for (excluded, winner) in [(&vetoed, &low), (&low, &high), (&high, &vetoed)] {
        let mut pair = objects.clone();
        pair.entries.retain(|e| body_digest(e) != *excluded);
        let v = verify_history(&pair, &Persisted::default(), now);
        assert_eq!(v.code(), "ok");
        assert_eq!(v.branch.get(2), Some(winner));
    }
    let v = verify_history(&objects, &Persisted::default(), now);
    assert_eq!((v.code(), v.seq()), ("refused:fork".into(), 3));
    assert!(
        v.conflicts.is_empty(),
        "no candidate can be dropped in a cycle"
    );
}

#[test]
fn three_candidates_find_winner_despite_undecided_losing_pair() {
    let (objects, now) = vector("t-three-candidate-winner");
    let v = verify_history(&objects, &Persisted::default(), now);
    assert_eq!((v.code(), v.seq()), ("ok".into(), 3));
    let winner =
        body_digest(&files(&cand().join("rules/t-three-candidate-winner/branch-2/authority"))[0]);
    assert_eq!(v.branch.get(2), Some(&winner));
    assert_eq!(v.conflicts.len(), 1);
    assert_eq!(v.conflicts[0].2.len(), 2);
}

#[test]
fn persisted_folded_state_resumes_suffix_with_replay_equivalent_verdict() {
    let mut rng = Rng(0x1702_cafe);
    for (dir, now) in cases() {
        let all = objects_of(&dir);
        let replay = verify_history(&all, &Persisted::default(), now);
        for split in [1, all.entries.len() / 2, all.entries.len()] {
            let prefix = Objects {
                entries: all.entries[..split].to_vec(),
                ..Default::default()
            };
            let saved = Persisted::checkpoint(&prefix, &Persisted::default(), now);
            let saved = Persisted::from_bytes(&saved.to_bytes().unwrap()).unwrap();
            let mut suffix = Objects {
                entries: all.entries[split..].to_vec(),
                pending: all.pending.clone(),
                heads: all.heads.clone(),
                predecessor: all.predecessor.clone(),
            };
            shuffle(&mut rng, &mut suffix.entries);
            shuffle(&mut rng, &mut suffix.pending);
            shuffle(&mut rng, &mut suffix.heads);
            let resumed = verify_history(&suffix, &saved, now);
            assert_eq!(
                summary(&resumed),
                summary(&replay),
                "{} split {split}",
                dir.display()
            );
            assert_eq!(
                serde_json::to_value(&resumed.state).unwrap(),
                serde_json::to_value(&replay.state).unwrap(),
                "{} folded state",
                dir.display()
            );
        }
    }
}

#[test]
fn checkpoints_taken_before_held_entries_come_due_resume_like_replay() {
    // Checkpoint the whole object set at a clock before `now`, so entries dated after it are
    // held, then resume at `now` with nothing new. The verdict and folded state must equal
    // full replay at `now` (§17.2).
    for (dir, now) in cases() {
        let all = objects_of(&dir);
        let replay = verify_history(&all, &Persisted::default(), now);
        for back in [
            30_000,
            90_000,
            600_000,
            3_600_000,
            86_400_000,
            8 * 86_400_000,
        ] {
            let at = now - back;
            let saved = Persisted::checkpoint(&all, &Persisted::default(), at);
            let saved = Persisted::from_bytes(&saved.to_bytes().unwrap()).unwrap();
            let resumed = verify_history(&Objects::default(), &saved, now);
            assert_eq!(
                summary(&resumed),
                summary(&replay),
                "{} checkpoint {back} ms before now",
                dir.display()
            );
            assert_eq!(
                serde_json::to_value(&resumed.state).unwrap(),
                serde_json::to_value(&replay.state).unwrap(),
                "{} folded state, checkpoint {back} ms before now",
                dir.display()
            );
        }
    }
}

#[test]
fn clock_retries_held_activation_and_expires_suspension_after_restart() {
    let (objects, early) = vector("t-activate-early");
    let held = verify_history(&objects, &Persisted::default(), early);
    assert_eq!(held.code(), "held");
    let saved = Persisted::checkpoint(&objects, &Persisted::default(), early);
    let saved = Persisted::from_bytes(&saved.to_bytes().unwrap()).unwrap();
    let late = early + 8 * 86_400_000;
    let resumed = verify_history(&Objects::default(), &saved, late);
    let replay = verify_history(&objects, &Persisted::default(), late);
    assert_eq!(resumed.code(), "ok");
    assert_eq!(summary(&resumed), summary(&replay));

    let (objects, now) = vector("t-suspend");
    let v = verify_history(&objects, &Persisted::default(), now);
    let st = v.state.unwrap();
    let sp = st.active_suspensions(now)[0];
    let end = sp.ends_ms();
    let saved = Persisted::checkpoint(&objects, &Persisted::default(), now);
    for (clock, expected) in [(end, 1), (end + 1, 0)] {
        let v = verify_history(&Objects::default(), &saved, clock);
        assert_eq!(v.state.unwrap().active_suspensions(clock).len(), expected);
    }
}

#[test]
fn checkpoint_rejects_unknown_format_and_malformed_bytes() {
    assert!(Persisted::from_bytes(b"{}").is_err());
    let (objects, now) = vector("t-suspend");
    let cp = Persisted::checkpoint(&objects, &Persisted::default(), now);
    let mut value: Value = serde_json::from_slice(&cp.to_bytes().unwrap()).unwrap();
    value["version"] = Value::from(99);
    assert!(Persisted::from_bytes(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn clock_retries_future_genesis_and_immediate_entry_at_sixty_second_boundary() {
    let (objects, _) = vector("i-add-approve");
    for split in [1, objects.entries.len()] {
        let subset = Objects {
            entries: objects.entries[..split].to_vec(),
            ..Default::default()
        };
        let env: Value = serde_json::from_slice(subset.entries.last().unwrap()).unwrap();
        let body: Value =
            serde_json::from_slice(&STANDARD.decode(env["body"].as_str().unwrap()).unwrap())
                .unwrap();
        let issued = parse_date(body["issued"].as_str().unwrap()).unwrap();
        let early = issued - 60_001;
        assert_eq!(
            verify_history(&subset, &Persisted::default(), early).code(),
            "held"
        );
        let saved = Persisted::checkpoint(&subset, &Persisted::default(), early);
        let saved = Persisted::from_bytes(&saved.to_bytes().unwrap()).unwrap();
        let resumed = verify_history(&Objects::default(), &saved, issued - 60_000);
        assert_eq!((resumed.code(), resumed.seq()), ("ok".into(), split as u64));
        assert_eq!(
            summary(&resumed),
            summary(&verify_history(
                &subset,
                &Persisted::default(),
                issued - 60_000
            ))
        );
    }
}

/// `verify_history` answers from an unchanged checkpoint without parsing the held objects
/// (`resumes_unchanged`). Its verdict must be the full verifier's, field for field and state
/// for state, wherever it is taken. Over every history vector (ordinary, held, forked, stopped by
/// a format or a final raise, upgraded in place from `/4`, successors of `/5` and Swift
/// predecessors), each checkpointed at several clock readings, resumed from an earlier
/// checkpoint, and with a high-water mark ahead of the branch, the verdict at clock readings
/// before, at and 30 days after the checkpoint's is the full verifier's; wherever the shortcut
/// is taken it is also the replay of the checkpoint's objects from genesis at that clock. A
/// checkpoint read back from bytes is never answered from alone.
#[test]
fn an_unchanged_checkpoint_gives_the_full_verdict() {
    use colophon_core::v05::history::{resumes_unchanged, verify_history_in_full, Stop};
    const DAY: i64 = 86_400_000;
    let mut all: Vec<(PathBuf, Objects, i64)> =
        cases().into_iter().map(|(d, now)| (d.clone(), objects_of(&d), now)).collect();
    all.extend(other_cases());
    let (mut compared, mut resumed, mut cold_equal) = (0usize, 0usize, 0usize);
    let mut cold_differs = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for (dir, objects, now) in &all {
        let none = Objects::default();
        let cold = verify_history(objects, &Persisted::default(), *now);
        seen.insert(match &cold.stop {
            None => "ok",
            Some(Stop::Held { .. }) => "held",
            Some(Stop::Fork { .. }) => "fork",
            Some(Stop::Failed { .. }) if cold.stopped.is_some() => "stopped",
            Some(Stop::Failed { .. }) => "failed",
        });
        if cold.state.as_ref().is_some_and(|s| s.upgrade_seq.is_some()) {
            seen.insert("upgraded");
        }
        if cold.state.as_ref().is_some_and(|s| colophon_core::v05::history::succession_status(s).is_some()) {
            seen.insert("successor");
        }
        let mut checkpoints = Vec::new();
        for at in [*now - 60_000, *now + 7 * DAY] {
            let p = Persisted::checkpoint(objects, &Persisted::default(), at);
            checkpoints.push((at, Persisted::checkpoint(objects, &p, at + 1_000)));
            if let Some(d) = cold.branch.last() {
                let ahead = Persisted::high_water(cold.branch.len() as u64 + 1, d.clone());
                checkpoints.push((at, Persisted::checkpoint(objects, &ahead, at)));
            }
            checkpoints.push((at, p));
        }
        for (at, p) in &checkpoints {
            for t in [at - 1, *at, at + 30 * DAY] {
                let got = full(&verify_history(&none, p, t));
                let want = full(&verify_history_in_full(&none, p, t));
                assert_eq!(got, want, "{} checkpointed at {at}, verified at {t}", dir.display());
                compared += 1;
                if resumes_unchanged(&none, p, t) {
                    resumed += 1;
                    // And a replay from genesis of the checkpoint's objects, with only its
                    // high-water mark, at the same clock.
                    let mark = match &p.high_water {
                        Some((seq, d)) => Persisted::high_water(*seq, d.clone()),
                        None => Persisted::default(),
                    };
                    let cold = full(&verify_history_in_full(p.objects().unwrap(), &mark, t));
                    if cold == got {
                        cold_equal += 1;
                    } else {
                        cold_differs.push(format!("{} checkpointed at {at}, verified at {t}", dir.display()));
                    }
                }
            }
            // Read back from bytes, it is never answered from alone.
            let restored = Persisted::from_bytes(&p.to_bytes().unwrap()).unwrap();
            assert!(!resumes_unchanged(&none, &restored, *at));
            assert_eq!(full(&verify_history(&none, &restored, *at)), full(&verify_history_in_full(&none, &restored, *at)));
            // Anything coming in takes the full path.
            assert!(!resumes_unchanged(objects, p, *at) || objects.entries.is_empty());
        }
    }
    eprintln!("{compared} verdicts compared, {resumed} from an unchanged checkpoint, {cold_equal} of those equal to a replay from genesis; histories: {seen:?}");
    assert!(cold_differs.is_empty(), "a shortcut verdict is not the replay from genesis: {cold_differs:#?}");
    for kind in ["ok", "held", "fork", "stopped", "failed", "upgraded", "successor"] {
        assert!(seen.contains(kind), "no {kind} history among the vectors: {seen:?}");
    }
    assert!(resumed * 8 > compared, "the shortcut was taken for {resumed} of {compared}");
}

/// A checkpoint read from bytes is local memory this verifier did not fold: another verifier (an
/// older one with the same format number) or a damaged copy may have written it. Here the fold
/// ends one entry before the last, and its held entries are that many, but the one at the end
/// is the next entry instead of the fold's own. Nothing comes in. The verdict must be the full
/// verifier's (which resumes the fold and finds the next entry), not the saved fold alone.
#[test]
fn a_checkpoint_read_from_bytes_is_never_answered_from_alone() {
    use colophon_core::v05::history::{resumes_unchanged, verify_history_in_full};
    let (dir, objects, now) = other_cases().into_iter().next().unwrap();
    let n = objects.entries.len();
    assert!(n >= 3, "{}", dir.display());
    let prefix = Objects { entries: objects.entries[..n - 1].to_vec(), ..objects.clone() };
    let p = Persisted::checkpoint(&prefix, &Persisted::default(), now);
    assert!(resumes_unchanged(&Objects::default(), &p, now), "folded here, it is answered from alone");
    let mut cp: Value = serde_json::from_slice(&p.to_bytes().unwrap()).unwrap();
    let held = cp["objects"]["entries"].as_array_mut().unwrap();
    assert_eq!(held.len(), n - 1);
    *held.last_mut().unwrap() = serde_json::to_value(&objects.entries[n - 1]).unwrap();
    let restored = Persisted::from_bytes(&serde_json::to_vec(&cp).unwrap()).unwrap();
    let none = Objects::default();
    let got = verify_history(&none, &restored, now);
    let want = verify_history_in_full(&none, &restored, now);
    assert_eq!(full(&got), full(&want));
    assert_eq!(got.branch.len(), n, "the next entry is found");
    assert!(!resumes_unchanged(&none, &restored, now));
    // The same checkpoint, read back unchanged, is not answered from alone either.
    let again = Persisted::from_bytes(&p.to_bytes().unwrap()).unwrap();
    assert!(!resumes_unchanged(&none, &again, now));
    assert_eq!(full(&verify_history(&none, &again, now)), full(&verify_history_in_full(&none, &again, now)));
    // Rebuilt from its objects, it is folded here again.
    let rebuilt = Persisted::rebuild(&prefix, &p.to_bytes().unwrap(), now);
    assert!(resumes_unchanged(&none, &rebuilt, now));
}

/// The digest [`FOLD_RULES`] ends with: SHA-256 over every file of the history verifier's
/// conformance vectors (`rules`, `upgrade`, `succession`), each as its path, its length and its
/// bytes, in path order; the first 16 hex digits.
fn vectors_digest() -> String {
    use sha2::{Digest, Sha256};
    fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, PathBuf)>) {
        for e in fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(root, &p, out);
            } else {
                let rel = p.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
                out.push((rel, p));
            }
        }
    }
    let mut files = Vec::new();
    for top in ["rules", "upgrade", "succession"] {
        walk(&cand(), &cand().join(top), &mut files);
    }
    files.sort();
    let mut h = Sha256::new();
    for (rel, p) in &files {
        let bytes = fs::read(p).unwrap();
        h.update(rel.as_bytes());
        h.update([0]);
        h.update((bytes.len() as u64).to_le_bytes());
        h.update(&bytes);
    }
    assert!(files.len() > 500, "{} files", files.len());
    colophon_core::v05::encoding::hex(&h.finalize())[..16].to_string()
}

/// [`FOLD_RULES`] names the digest of the history verifier's conformance vectors, so a changed
/// vector (an `expected` verdict above all) fails here until the value is updated. It reads no
/// verifier code: a rule changed in code alone is caught only by raising the revision by hand (and,
/// at a home, by the module build its proof also names).
#[test]
fn the_fold_rules_name_the_conformance_vectors() {
    use colophon_core::v05::history::FOLD_RULES;
    let digest = vectors_digest();
    let (name, named) = FOLD_RULES.rsplit_once('/').unwrap();
    assert!(name.starts_with("colophon-0.5-fold/r"), "{FOLD_RULES}");
    assert_eq!(
        named, digest,
        "the history vectors changed: if a verdict can change, so did the rules. Raise the \
         revision in FOLD_RULES if the rules changed in code too, and set its digest to {digest}"
    );
}

/// The record layer's view from a vouched checkpoint (`RecordAuthority::from_vouched`) is the
/// replay's (`RecordAuthority::from_objects` over the checkpoint's objects), whenever it is given:
/// over every history vector (ordinary, held, forked, failed, stopped, upgraded from `/4`,
/// successors, suspended keys), each checkpointed at several clock readings, resumed, and with a
/// high-water mark ahead, at clock readings before, at and long after the checkpoint's. It is
/// never given for a checkpoint read back from bytes, and it is given for many ordinary ones.
#[test]
fn a_vouched_record_view_is_the_replays() {
    use colophon_core::v05::history::succession_status;
    use colophon_core::v05::records::RecordAuthority;
    const DAY: i64 = 86_400_000;
    let mut all: Vec<(PathBuf, Objects, i64)> =
        cases().into_iter().map(|(d, now)| (d.clone(), objects_of(&d), now)).collect();
    all.extend(other_cases());
    let (mut compared, mut given, mut not_again) = (0usize, 0usize, 0usize);
    let mut kinds = std::collections::BTreeMap::<&str, (usize, usize)>::new();
    for (dir, objects, now) in &all {
        let cold = verify_history(objects, &Persisted::default(), *now);
        let kind = match &cold.stop {
            _ if cold.state.as_ref().is_some_and(|s| succession_status(s).is_some()) => "successor",
            _ if cold.state.as_ref().is_some_and(|s| s.upgrade_seq.is_some()) => "upgraded",
            _ if dir.ends_with("f2-suspended-key-suspends") => "suspended-key",
            None => "ok",
            Some(colophon_core::v05::history::Stop::Held { .. }) => "held",
            Some(colophon_core::v05::history::Stop::Fork { .. }) => "fork",
            Some(_) if cold.stopped.is_some() => "stopped",
            Some(_) => "failed",
        };
        // Each checkpoint, and whether it was folded from genesis in one replay.
        let mut checkpoints = Vec::new();
        for at in [*now - 60_000, *now, *now + 7 * DAY] {
            let p = Persisted::checkpoint(objects, &Persisted::default(), at);
            checkpoints.push((at + 1_000, Persisted::checkpoint(objects, &p, at + 1_000), false));
            if let Some(d) = cold.branch.last() {
                let ahead = Persisted::high_water(cold.branch.len() as u64 + 1, d.clone());
                checkpoints.push((at, Persisted::checkpoint(objects, &ahead, at), true));
            }
            checkpoints.push((at, p, true));
        }
        for (at, p, genesis) in &checkpoints {
            assert!(p.folded_here() || !genesis);
            let held = p.objects().unwrap();
            for t in [at - 1, *at, at + 30 * DAY] {
                compared += 1;
                let entry = kinds.entry(kind).or_default();
                entry.0 += 1;
                let Some(got) = RecordAuthority::from_vouched(p, t) else { continue };
                given += 1;
                entry.1 += 1;
                let want = RecordAuthority::from_objects(held, t);
                assert_eq!(
                    format!("{got:?}"),
                    format!("{want:?}"),
                    "{} checkpointed at {at}, at {t}",
                    dir.display()
                );
            }
            let restored = Persisted::from_bytes(&p.to_bytes().unwrap()).unwrap();
            assert!(!restored.folded_here());
            assert!(RecordAuthority::from_vouched(&restored, *at).is_none());
            // Verified again from genesis, a checkpoint folded in one replay is this build's fold
            // once more, with the same bytes. One resumed from an earlier checkpoint that is not
            // verified again is never taken as this build's fold.
            // The same checkpoint written with other spacing is not the replay's bytes.
            let bytes = p.to_bytes().unwrap();
            let mut spaced = b"{ ".to_vec();
            spaced.extend_from_slice(&bytes[1..]);
            let respaced = Persisted::from_bytes(&spaced).unwrap();
            assert!(Persisted::verified_from(&spaced).is_none(), "{} respaced", dir.display());
            assert!(!respaced.folded_here());
            match Persisted::verified_from(&bytes) {
                Some(again) => {
                    assert!(again.folded_here());
                    assert_eq!(again.to_bytes().unwrap(), bytes);
                }
                None => {
                    assert!(!genesis, "{} checkpointed at {at} is not verified again", dir.display());
                    assert!(!p.folded_here(), "{} checkpointed at {at} is taken as this build's fold but is not verified again", dir.display());
                    not_again += 1;
                }
            }
        }
    }
    eprintln!("{compared} clock readings, {given} answered from the fold, {not_again} resumed checkpoints not verified again; by history: {kinds:?}");
    for k in ["ok", "held", "fork", "failed", "stopped", "upgraded", "successor", "suspended-key"] {
        assert!(kinds.contains_key(k), "no {k} history: {kinds:?}");
    }
    // Per kind of history: ordinary ones are answered from the fold at many readings; a fork, a
    // failed or stopped history, an upgraded account, a successor and the suspended key's refused
    // suspend never are.
    let ok = kinds["ok"];
    assert!(ok.1 * 3 > ok.0, "ordinary histories answered from the fold {} of {}", ok.1, ok.0);
    for k in ["fork", "failed", "stopped", "upgraded", "successor", "suspended-key"] {
        assert_eq!(kinds[k].1, 0, "{k} answered from the fold: {kinds:?}");
    }
}

/// A fold another build made under other rules is not this build's fold: verified again, the
/// replay differs, so it is never taken as one. Here the fold of
/// `f2-suspended-key-suspends` accepts the suspend a suspended key signed (seq 3), which these
/// rules refuse (`badSignature`), as an older verifier with the same checkpoint format might.
#[test]
fn a_fold_made_under_other_rules_is_not_verified_again() {
    use colophon_core::v05::records::RecordAuthority;
    let (objects, now) = vector("f2-suspended-key-suspends");
    let p = older_rules_fold(&objects, now);
    let restored = Persisted::from_bytes(&p).unwrap();
    assert_eq!(verify_history(&Objects::default(), &restored, now).branch.len(), 3, "the older fold took seq 3");
    assert!(Persisted::verified_from(&p).is_none());
    assert!(RecordAuthority::from_vouched(&restored, now).is_none());
    let replay = RecordAuthority::from_objects(restored.objects().unwrap(), now);
    assert_eq!(replay.unwrap_err().code(), "badSignature");
}

/// The checkpoint an older verifier would write for `objects` if it accepted every entry: this
/// build's fold through seq 2, with seq 3 appended to the state as accepted (its digest, `issued`,
/// and per-seq memory carried over unchanged). Bytes, as a host stores them.
pub fn older_rules_fold(objects: &Objects, now: i64) -> Vec<u8> {
    let two = Objects { entries: objects.entries[..2].to_vec(), ..objects.clone() };
    let p = Persisted::checkpoint(&two, &Persisted::default(), now);
    assert_eq!(verify_history(&Objects::default(), &p, now).branch.len(), 2);
    let mut cp: Value = serde_json::from_slice(&p.to_bytes().unwrap()).unwrap();
    let third = &objects.entries[2];
    let env: Value = serde_json::from_slice(third).unwrap();
    let body = STANDARD.decode(env["body"].as_str().unwrap()).unwrap();
    let issued = parse_date(serde_json::from_slice::<Value>(&body).unwrap()["issued"].as_str().unwrap()).unwrap();
    let st = &mut cp["state"];
    st["digests"].as_array_mut().unwrap().push(Value::String(body_digest(third)));
    st["issued"].as_array_mut().unwrap().push(issued.into());
    for k in ["keyring_at", "delay_at", "rule_at"] {
        let a = st[k].as_array_mut().unwrap();
        let last = a.last().unwrap().clone();
        a.push(last);
    }
    cp["objects"]["entries"].as_array_mut().unwrap().push(serde_json::to_value(third).unwrap());
    cp["high_water"] = serde_json::json!([3, body_digest(third)]);
    serde_json::to_vec(&cp).unwrap()
}

/// A successor's checkpoint does not carry what its genesis was judged by: the predecessor's
/// history and its release conditions, which the replay judges again at its own clock. So a fold
/// can hold a state, or another state, where the replay from genesis at a later clock holds or
/// refuses the genesis. Among the succession vectors such clock readings exist, and at every one
/// the vouched record view is not given (`None`): the caller replays.
#[test]
fn a_successors_fold_is_never_the_record_view() {
    use colophon_core::v05::records::RecordAuthority;
    const DAY: i64 = 86_400_000;
    let mut differs = Vec::new();
    for (dir, objects, now) in other_cases() {
        if !dir.to_string_lossy().contains("succession") {
            continue;
        }
        for at in [now - 30 * DAY, now - DAY, now, now + 7 * DAY] {
            let p = Persisted::checkpoint(&objects, &Persisted::default(), at);
            for t in [at, at + DAY, at + 30 * DAY, at + 400 * DAY] {
                let fold = verify_history(&Objects::default(), &p, t);
                let Some(state) = fold.state.as_ref() else { continue };
                let replay = RecordAuthority::from_objects(&objects, t);
                let same = replay.as_ref().is_ok_and(|ra| format!("{:?}", ra.state()) == format!("{state:?}"));
                assert!(RecordAuthority::from_vouched(&p, t).is_none(), "{} at {at}, {t}", dir.display());
                if !same {
                    differs.push(format!("{} checkpointed at {at}, at {t}", dir.display()));
                }
            }
        }
    }
    eprintln!("{} successor readings where the fold is not the replay, first {:?}", differs.len(), differs.first());
    assert!(!differs.is_empty(), "no successor fold differs from its replay at a later clock");
}

/// A checkpoint whose verdict has a candidate held beside a valid one (`held_until`, §8.1) keeps
/// that due time through every checkpoint taken from it before it comes due, as the replay's
/// checkpoint at that clock has it, so the candidate is judged again once it is due. Over every
/// history vector checkpointed at several clock readings, wherever such a due time is pending.
#[test]
fn a_checkpoint_taken_before_a_due_time_keeps_it() {
    let mut all: Vec<(PathBuf, Objects, i64)> =
        cases().into_iter().map(|(d, now)| (d.clone(), objects_of(&d), now)).collect();
    all.extend(other_cases());
    let held = |p: &Persisted| -> Value {
        serde_json::from_slice::<Value>(&p.to_bytes().unwrap()).unwrap()["held_until"].clone()
    };
    let mut pending = 0;
    for (dir, objects, now) in &all {
        for at in [*now - 3_600_000, *now - 60_000, *now] {
            let p = Persisted::checkpoint(objects, &Persisted::default(), at);
            let Some(due) = held(&p).as_i64() else { continue };
            if due <= at + 1_000 {
                continue;
            }
            pending += 1;
            let between = Persisted::checkpoint(&Objects::default(), &p, at + 1_000);
            let cold = Persisted::checkpoint(objects, &Persisted::default(), at + 1_000);
            assert_eq!(held(&between), held(&cold), "{} checkpointed at {at}", dir.display());
            for t in [due, due + 86_400_000] {
                let later = verify_history(&Objects::default(), &between, t);
                let replay = verify_history(objects, &Persisted::default(), t);
                // Everything but the rollback mark, which reads the checkpoint's high water.
                let fold = |v: &Verdict| format!("{:?} {:?} {:?} {:?} {:?} {}", v.branch, v.stop, v.conflicts,
                    v.held_until, v.stopped, serde_json::to_string(&v.state).unwrap());
                assert_eq!(fold(&later), fold(&replay), "{} checkpointed at {at}, at {t}", dir.display());
            }
        }
    }
    eprintln!("{pending} checkpoints with a pending due time");
    assert!(pending > 0, "no vector holds a candidate beside a valid one");
}

/// Every checkpoint taken as this build's fold reproduces itself: a replay of its objects from
/// genesis at its own clock, with its local memory, gives exactly its bytes. Over every history
/// vector, along chains of checkpoints each taken from the one before (from genesis, resumed with
/// nothing new, resumed with every object again, and much later), at clock readings from an hour
/// before the case's clock to 400 days after: wherever `folded_here` is set, `verified_from` of the
/// bytes holds. A resume that would carry a fold the replay at its clock does not give (a
/// successor's verified succession whose head has aged out, say) is not taken as this build's.
#[test]
fn every_fold_taken_as_this_builds_reproduces_at_its_own_clock() {
    const DAY: i64 = 86_400_000;
    let mut all: Vec<(PathBuf, Objects, i64)> =
        cases().into_iter().map(|(d, now)| (d.clone(), objects_of(&d), now)).collect();
    all.extend(other_cases());
    let (mut folded, mut not_folded) = (0usize, 0usize);
    let mut wrong = Vec::new();
    for (dir, objects, now) in &all {
        for start in [*now - 3_600_000, *now] {
            let mut p = Persisted::checkpoint(objects, &Persisted::default(), start);
            for (step, (incoming, t)) in [
                (Objects::default(), start + 1_000),
                (objects.clone(), start + 7 * DAY),
                (Objects::default(), start + 400 * DAY),
            ]
            .into_iter()
            .enumerate()
            {
                for q in [&p] {
                    if q.folded_here() {
                        folded += 1;
                        let bytes = q.to_bytes().unwrap();
                        if Persisted::verified_from(&bytes).is_none() {
                            wrong.push(format!("{} from {start}, step {step}", dir.display()));
                        }
                    } else {
                        not_folded += 1;
                    }
                }
                p = Persisted::checkpoint(&incoming, &p, t);
            }
            if p.folded_here() {
                folded += 1;
                if Persisted::verified_from(&p.to_bytes().unwrap()).is_none() {
                    wrong.push(format!("{} from {start}, last", dir.display()));
                }
            } else {
                not_folded += 1;
            }
        }
    }
    eprintln!("{folded} checkpoints taken as this build's fold, {not_folded} not");
    assert!(wrong.is_empty(), "taken as this build's fold but not reproduced: {wrong:#?}");
    assert!(folded > not_folded, "{folded} {not_folded}");
}
