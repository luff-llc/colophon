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
        let base = objects_of(&dir);
        let want = summary(&verify_history(&base, &Persisted::default(), now));
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
            let got = summary(&verify_history(&o, &Persisted::default(), now));
            assert_eq!(got, want, "{}", dir.display());
            checked += 1;
        }
    }
    assert!(checked > 600, "{checked}");
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
        let v = verify_history(
            &o,
            &Persisted {
                high_water: Some((seq, d)),
            },
            now,
        );
        assert_eq!(
            summary(&v),
            summary(&plain),
            "the high-water mark selected a branch"
        );
    }
    // A high-water mark past the verified branch is a rollback.
    let ok = verify_history(
        &objects_of(&cand().join("rules/t-remove-after-delay")),
        &Persisted {
            high_water: Some((9, "0".repeat(64))),
        },
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
                    verify_history(
                        &o,
                        &Persisted {
                            high_water: Some((u64::MAX, "z".into())),
                        },
                        clock,
                    )
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
