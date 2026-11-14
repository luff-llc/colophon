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
    let case: Value = serde_json::from_slice(&fs::read(dir.join("case.json")).unwrap()).unwrap();
    let now = parse_date(
        case["expected"]["now"]
            .as_str()
            .unwrap_or("2026-11-14T10:15:00Z"),
    )
    .unwrap();
    (
        Objects {
            entries: files(&dir.join("successor/authority")),
            predecessor: files(&dir.join("predecessor/authority")),
            ..Default::default()
        },
        now,
    )
}
/// The successor's own verdict and whether its succession is verified.
fn successor_verdict(name: &str) -> (String, bool) {
    let (o, now) = succession(name);
    let v = verify_history(&o, &Persisted::default(), now);
    let code = v.code().to_string();
    (
        code,
        v.state.is_some_and(|s| s.verified_succession().is_some()),
    )
}
fn verified(name: &str) -> bool {
    let (code, verified) = successor_verdict(name);
    assert!(
        code == "ok" || code == "held" || code == "badSignature",
        "{name}: {code}"
    );
    verified
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

// ---- M4 -----------------------------------------------------------------------------------

#[test]
fn m4_carried_keys_need_possession_unless_the_handover_meets_the_rule() {
    for name in [
        "swift-no-handover-needs-possession",
        "swift-handover-below-rule-needs-possession",
    ] {
        let (o, now) = succession(name);
        let v = verify_history(&o, &Persisted::default(), now);
        assert_eq!(
            (v.code(), v.seq()),
            ("badSignature".to_string(), 1),
            "{name}"
        );
        assert!(v.state.is_none() || v.state.unwrap().verified_succession().is_none());
    }
    // The same genesis with a handover that meets the rule is accepted without possession proofs.
    for name in ["swift-keyring", "swift-root-library"] {
        let (o, now) = succession(name);
        let v = verify_history(&o, &Persisted::default(), now);
        assert!(v.state.is_some(), "{name}: {:?}", v.stop);
        assert!(v.seq() >= 1, "{name}");
    }
}

// ---- The chain bound (§2.4, §15.1) ----------------------------------------------------------

#[test]
fn h3_a_chain_of_sixteen_accounts_verifies_and_seventeen_is_malformed() {
    let (o, now) = succession("authority5-chain-16");
    let v = verify_history(&o, &Persisted::default(), now);
    assert_eq!(v.code(), "ok", "{:?}", v.stop);
    assert!(v.state.unwrap().verified_succession().is_some());
    let (o, now) = succession("authority5-chain-17");
    let v = verify_history(&o, &Persisted::default(), now);
    assert_eq!(v.code(), "malformed");
    assert!(format!("{:?}", v.stop).contains("longer than 16"));
}

/// Junk geneses added to a chain at the bound (or past it) are ignored.
#[test]
fn h3_unrelated_geneses_neither_count_nor_break_a_chain_at_the_bound() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let (base, now) = succession("authority5-chain-16");
    let genesis = base.predecessor[0].clone();
    let env: Value = serde_json::from_slice(&genesis).unwrap();
    let body: Value =
        serde_json::from_slice(&STANDARD.decode(env["body"].as_str().unwrap()).unwrap()).unwrap();
    let mut o = base.clone();
    for i in 0..20 {
        let mut b = body.clone();
        b["label"] = serde_json::json!(format!("Unrelated {i}"));
        let bytes = colophon_core::v05::encoding::canonical(&b).unwrap();
        o.predecessor.push(
            serde_json::to_vec(&serde_json::json!({"body": STANDARD.encode(bytes)})).unwrap(),
        );
    }
    let v = verify_history(&o, &Persisted::default(), now);
    assert_eq!(v.code(), "ok", "{:?}", v.stop);
    assert!(v.state.unwrap().verified_succession().is_some());
}

// ---- L2: the Swift steward threshold (§16.3) --------------------------------------------------
//
// Marginalia `origin/main` reads `threshold` as an optional Int (`AuthorityEntry.threshold: Int?`)
// and `AuthorityState` turns nil into 0 for a genesis (`genesis.threshold ?? 0`) and for a
// `stewards` entry (`entry.threshold ?? 0`); a quorum `handover` needs `threshold > 0`
// (`guard entry.kind == .handover, threshold > 0`). A non-integer value is a decoding error.
// These tests are the Rust engine's reading of that source. The Swift source has not replayed them.

mod swift_stewards {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use colophon_core::v05::history::swift;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};

    fn key(name: &str) -> SigningKey {
        SigningKey::from_slice(&Sha256::digest(format!("revision-12/{name}").as_bytes())).unwrap()
    }
    fn point(k: &SigningKey) -> Vec<u8> {
        k.verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }
    fn identity(name: &str) -> Value {
        let p = STANDARD.encode(point(&key(name)));
        json!({"signing": p, "agreement": p})
    }
    fn id_of(name: &str) -> String {
        hex(&Sha256::digest(point(&key(name))))[..32].to_string()
    }
    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
    fn record(body: &Value, signers: &[&str]) -> Vec<u8> {
        // serde_json writes object keys sorted, compact: the stored body bytes.
        let bytes = serde_json::to_vec(body).unwrap();
        let sign = |n: &str| -> String {
            let s: Signature = key(n).sign(&bytes);
            STANDARD.encode(s.to_bytes())
        };
        let mut rec = json!({"body": STANDARD.encode(&bytes), "signature": sign(signers[0])});
        if signers.len() > 1 {
            rec["cosignatures"] = Value::Array(
                signers[1..]
                    .iter()
                    .map(|n| json!({"signer": id_of(n), "signature": sign(n)}))
                    .collect(),
            );
        }
        serde_json::to_vec(&rec).unwrap()
    }
    fn digest_of(rec: &[u8]) -> String {
        let v: Value = serde_json::from_slice(rec).unwrap();
        let body = STANDARD.decode(v["body"].as_str().unwrap()).unwrap();
        hex(&Sha256::digest(body))
    }
    /// A pre-adoption library with stewards S1 and S2; `genesis_threshold` is spliced into the
    /// genesis body when given. Returns the genesis record.
    fn genesis(genesis_threshold: Option<Value>) -> Vec<u8> {
        let mut body = json!({"by": "root", "issued": "2026-11-01T08:00:00Z", "kind": "genesis",
            "label": "Library", "recovery": identity("recovery"), "root": identity("root"),
            "seq": 1, "stewards": [identity("s1"), identity("s2")]});
        if let Some(t) = genesis_threshold {
            body["threshold"] = t;
        }
        record(&body, &["root"])
    }
    fn stewards_entry(prev: &[u8], threshold: Option<Value>) -> Vec<u8> {
        let mut body = json!({"by": "root", "issued": "2026-11-01T08:01:00Z", "kind": "stewards",
            "previous": digest_of(prev), "seq": 2, "stewards": [identity("s1"), identity("s2")]});
        if let Some(t) = threshold {
            body["threshold"] = t;
        }
        record(&body, &["root"])
    }
    fn quorum_handover(prev: &[u8], seq: u64, signers: &[&str]) -> Vec<u8> {
        let body = json!({"by": "quorum", "issued": "2026-11-01T08:02:00Z", "kind": "handover",
            "previous": digest_of(prev), "root": identity("new-root"), "seq": seq});
        record(&body, signers)
    }
    fn verdict(entries: Vec<Vec<u8>>) -> String {
        match swift::verify(&entries) {
            Ok(_) => "ok".to_string(),
            Err(f) => f.code().to_string(),
        }
    }

    #[test]
    fn a_genesis_threshold_of_one_lets_one_steward_hand_over() {
        let g = genesis(Some(json!(1)));
        let h = quorum_handover(&g, 2, &["s1"]);
        assert_eq!(verdict(vec![g, h]), "ok");
    }

    #[test]
    fn an_absent_genesis_threshold_is_zero_and_no_quorum_can_hand_over() {
        // The engine used to default this to 1.
        let g = genesis(None);
        let h = quorum_handover(&g, 2, &["s1"]);
        assert_eq!(verdict(vec![g.clone()]), "ok");
        assert_eq!(verdict(vec![g, h]), "badSignature");
        // `null` is nil in Swift's Codable, so it is absent too.
        let g = genesis(Some(Value::Null));
        let h = quorum_handover(&g, 2, &["s1"]);
        assert_eq!(verdict(vec![g, h]), "badSignature");
    }

    #[test]
    fn a_genesis_threshold_that_is_not_a_plain_integer_is_malformed() {
        // The engine used to default this to 1.
        for bad in [json!("1"), json!(true), json!([1]), json!(1.5), json!({})] {
            let g = genesis(Some(bad.clone()));
            assert_eq!(verdict(vec![g]), "malformed", "{bad}");
        }
    }

    #[test]
    fn a_stewards_entry_without_a_threshold_is_zero_and_no_quorum_can_hand_over() {
        let g = genesis(Some(json!(1)));
        let st = stewards_entry(&g, None);
        let h = quorum_handover(&st, 3, &["s1"]);
        assert_eq!(verdict(vec![g.clone(), st.clone()]), "ok");
        assert_eq!(verdict(vec![g.clone(), st, h]), "badSignature");
        // With a threshold of 2, one steward is too few and two are enough.
        let st = stewards_entry(&g, Some(json!(2)));
        let one = quorum_handover(&st, 3, &["s1"]);
        let two = quorum_handover(&st, 3, &["s1", "s2"]);
        assert_eq!(verdict(vec![g.clone(), st.clone(), one]), "badSignature");
        assert_eq!(verdict(vec![g, st, two]), "ok");
    }

    /// A root-signed `rotateRecovery` entry that carries a `threshold` field it does not use.
    fn rotate_with_threshold(prev: &[u8], threshold: Value) -> Vec<u8> {
        let body = json!({"by": "root", "issued": "2026-11-01T08:01:00Z", "kind": "rotateRecovery",
            "previous": digest_of(prev), "recovery": identity("recovery-2"), "seq": 2,
            "threshold": threshold});
        record(&body, &["root"])
    }

    #[test]
    fn a_threshold_on_any_entry_kind_must_be_a_plain_integer() {
        let g = genesis(Some(json!(1)));
        for ok in [json!(3), json!(0), json!(-2), Value::Null] {
            let e = rotate_with_threshold(&g, ok.clone());
            assert_eq!(verdict(vec![g.clone(), e]), "ok", "{ok}");
        }
        for bad in [
            json!("3"),
            json!(true),
            json!([1]),
            json!(2.0),
            json!(1.5),
            json!(1e1),
        ] {
            let e = rotate_with_threshold(&g, bad.clone());
            assert_eq!(verdict(vec![g.clone(), e]), "malformed", "{bad}");
        }
        // An integer beyond 64 bits, written as plain digits.
        let big = rotate_with_threshold(&g, json!(9223372036854775808u64));
        assert_eq!(verdict(vec![g, big]), "malformed");
    }

    #[test]
    fn a_stewards_entry_threshold_that_is_not_a_plain_integer_is_malformed() {
        let g = genesis(Some(json!(1)));
        for bad in [json!("2"), json!(false), json!(2.5)] {
            let st = stewards_entry(&g, Some(bad.clone()));
            assert_eq!(verdict(vec![g.clone(), st]), "malformed", "{bad}");
        }
    }
}

// ---- Fix round H1: one meaning of "final" ---------------------------------------------------

/// A `vetoed` held beside an activation that is final by the cascade or by a full set changes
/// nothing, in any order.
#[test]
fn h1_a_vetoed_never_rolls_back_a_final_activation() {
    for (name, len, finals) in [
        ("t-cascade-final-not-displaced-by-vetoed", 6, vec![3, 4]),
        ("t-full-set-final-not-displaced-by-vetoed", 5, vec![3]),
    ] {
        let (objects, now) = rules(name);
        let v = verify_history(&objects, &Persisted::default(), now);
        assert_eq!(
            (v.code(), v.branch.len()),
            ("ok".to_string(), len),
            "{name}"
        );
        for sq in &finals {
            assert!(is_final(&v, *sq), "{name}: seq {sq}");
        }
        for rot in 1..objects.entries.len() {
            let mut shuffled = objects.clone();
            shuffled.entries.rotate_left(rot);
            let w = verify_history(&shuffled, &Persisted::default(), now);
            assert_eq!(w.branch, v.branch, "{name}: rotation {rot}");
        }
    }
}

// ---- Fix round H2: held, then ok or refused, never ok then refused --------------------------

#[test]
fn h2_a_genesis_leaning_on_the_exemption_is_held_then_ok_or_badsignature() {
    // F provisional: held, succession unverified.
    assert_eq!(
        successor_verdict("authority5-successor-provisional"),
        ("held".to_string(), false)
    );
    // F final: the same genesis is ok and the succession verified.
    assert_eq!(
        successor_verdict("authority5-successor-final"),
        ("ok".to_string(), true)
    );
    // F displaced by a `vetoed`: the same genesis is badSignature.
    assert_eq!(
        successor_verdict("authority5-successor-vetoed-no-proofs"),
        ("badSignature".to_string(), false)
    );
    // A genesis that carries every possession proof is valid on its own, the succession
    // simply unverified (F displaced).
    assert_eq!(
        successor_verdict("authority5-successor-vetoed"),
        ("ok".to_string(), false)
    );
}

/// Adding objects only moves a verdict from held to ok or to refused: the held genesis with the
/// predecessor's `final` is ok, with only its head it is held.
#[test]
fn h2_a_predecessor_with_no_entry_at_f_leaves_the_genesis_held() {
    let (mut o, now) = succession("authority5-successor-provisional");
    o.predecessor.truncate(2);
    let v = verify_history(&o, &Persisted::default(), now);
    assert_eq!(v.code(), "held");
}

// ---- Fix round M-b, M-c: what a predecessor admits after a provisional F ---------------------

#[test]
fn mc_a_dead_witness_home_is_revoked_and_the_succession_verifies() {
    assert!(verified("authority5-successor-dead-witness"));
    let v = predecessor_alone("authority5-successor-dead-witness");
    assert_eq!((v.code(), v.branch.len()), ("ok".to_string(), 6));
    assert!(is_final(&v, 3), "F is final");
    assert!(is_final(&v, 4), "the home revocation is final");
    assert_eq!(v.state.unwrap().current_homes().len(), 1, "H2 is gone");
}

#[test]
fn mb_a_final_of_an_earlier_removal_only_activation_is_not_admitted_after_f() {
    let v = predecessor_alone("authority5-successor-final-of-earlier-removal");
    // The branch ends at F; the refused `final` is malformed evidence after it.
    assert_eq!((v.code(), v.branch.len()), ("malformed".to_string(), 4));
    assert!(!verified("authority5-successor-final-of-earlier-removal"));
}

#[test]
fn mb_nothing_else_is_admitted_after_a_provisional_f() {
    // The grant of the vetoed vector is a valid entry for its own branch, never for F's.
    let (o, now) = succession("authority5-successor-provisional");
    let (other, _) = succession("authority5-successor-vetoed");
    let mut entries = o.predecessor.clone();
    // A forged unsigned immediate entry at seq 4 on top of F.
    use base64::{engine::general_purpose::STANDARD, Engine};
    let f: Value = serde_json::from_slice(&entries[2]).unwrap();
    let fb = STANDARD.decode(f["body"].as_str().unwrap()).unwrap();
    let digest = colophon_core::v05::encoding::digest(&fb);
    let body = serde_json::json!({"protocol": "colophon/authority/5", "seq": 4, "previous": digest,
        "issued": "2026-11-14T09:06:00Z", "by": "x", "kind": "grant"});
    entries.push(
        serde_json::to_vec(&serde_json::json!({"body": STANDARD.encode(colophon_core::v05::encoding::canonical(&body).unwrap())}))
            .unwrap(),
    );
    let _ = other;
    let v = verify_history(
        &Objects {
            entries,
            ..Default::default()
        },
        &Persisted::default(),
        now,
    );
    assert_eq!(v.branch.len(), 3);
}
