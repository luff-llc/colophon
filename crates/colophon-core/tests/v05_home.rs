//! Home-side facts are inputs: local caps/cursors can depend on admission order, while
//! authority validity and receipt validity depend on signed objects and the explicit clock.
#![allow(clippy::unwrap_used)]
use base64::{engine::general_purpose::STANDARD, Engine};
use colophon_core::v05::{
    encoding::{canonical, digest, parse_date},
    history::home::{
        admit, admit_pending_batch, finish_receipt, HomeState, Refusal, ServingInterval,
    },
    history::{verify_history, Objects, Persisted},
};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};
fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn fixture(name: &str, path: &str) -> Vec<u8> {
    fs::read(
        root()
            .join("conformance/0.5/candidate/rules")
            .join(name)
            .join(path),
    )
    .unwrap()
}
fn body(bytes: &[u8]) -> Value {
    let env: Value = serde_json::from_slice(bytes).unwrap();
    serde_json::from_slice(&STANDARD.decode(env["body"].as_str().unwrap()).unwrap()).unwrap()
}
fn stamp(ms: i64) -> String {
    let base = parse_date("2026-11-11T00:00:00Z").unwrap();
    let t = ms - base;
    let sec = t.div_euclid(1000);
    format!(
        "2026-11-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        11 + sec.div_euclid(86400),
        sec.rem_euclid(86400) / 3600,
        sec.rem_euclid(3600) / 60,
        sec.rem_euclid(60),
        t.rem_euclid(1000)
    )
}
fn time(bytes: &[u8]) -> i64 {
    parse_date(body(bytes)["issued"].as_str().unwrap()).unwrap()
}
fn key_for(id: &str) -> SigningKey {
    let keys: Value =
        serde_json::from_slice(&fs::read(root().join("conformance/0.4/keys/keys.json")).unwrap())
            .unwrap();
    for k in keys["software"].as_array().unwrap() {
        if k["id"] == id {
            return SigningKey::from_slice(
                &STANDARD
                    .decode(k["signingScalar"].as_str().unwrap())
                    .unwrap(),
            )
            .unwrap();
        }
    }
    for name in [
        "r4/home1/signing",
        "r4/home2/signing",
        "r5/phone",
        "r4/new-device",
    ] {
        let scalar = Sha256::digest(format!("colophon-0.5-candidate/{name}").as_bytes());
        let k = SigningKey::from_slice(&scalar).unwrap();
        let point = k.verifying_key().to_encoded_point(false);
        if &digest(point.as_bytes())[..32] == id {
            return k;
        }
    }
    panic!("unknown published fixture key {id}")
}
fn signed(value: &Value) -> Vec<u8> {
    let bytes = canonical(value).unwrap();
    let sig: Signature = key_for(value["by"].as_str().unwrap()).sign(&bytes);
    canonical(&json!({"body":STANDARD.encode(&bytes), "signature":STANDARD.encode(sig.to_bytes())}))
        .unwrap()
}
fn setup(name: &str, second: bool, serving: Vec<ServingInterval>, now: i64) -> HomeState {
    let objects = Objects {
        entries: (1..=2)
            .map(|seq| fixture(name, &format!("records/authority/{seq:08}.json")))
            .collect(),
        ..Default::default()
    };
    let v = verify_history(&objects, &Persisted::default(), now);
    let st = v.state.unwrap();
    let id = st.current_homes()[usize::from(second)].request.member_id();
    HomeState::new(id, &objects, serving, now).unwrap()
}
fn always() -> Vec<ServingInterval> {
    vec![ServingInterval {
        from_ms: i64::MIN,
        through_ms: None,
    }]
}
fn restore(state: &HomeState) -> HomeState {
    HomeState::from_bytes(&state.to_bytes().unwrap()).unwrap()
}

#[test]
fn receipt_window_retry_restart_signature_and_pending_pagination() {
    let t = fixture("t-remove-after-delay", "objects/transition.json");
    let at = time(&t);
    let home = setup("t-remove-after-delay", false, always(), at);
    let early = admit(&home, &t, &stamp(at - 1));
    assert_eq!(early.result, Err(Refusal::Early));
    assert!(early
        .state
        .pending_page(0, 64, at)
        .unwrap()
        .objects
        .is_empty());
    let admitted = admit(&restore(&early.state), &t, &stamp(at));
    assert_eq!(admitted.result, Ok(()));
    assert_eq!(admitted.receipts.len(), 1);
    let retry = admit(&restore(&admitted.state), &t, &stamp(at + 1));
    assert_eq!(retry.receipts, admitted.receipts);
    let receipt_value: Value = serde_json::from_slice(&retry.receipts[0].body).unwrap();
    let receipt = signed(&receipt_value);
    assert!(finish_receipt(
        &retry.state,
        &retry.receipts[0].object,
        &receipt,
        &stamp(at + 300_001)
    )
    .is_err());
    let home = finish_receipt(
        &retry.state,
        &retry.receipts[0].object,
        &receipt,
        &stamp(at + 300_000),
    )
    .unwrap();
    let page = restore(&home).pending_page(0, 1, at + 300_000).unwrap();
    assert_eq!(page.objects.len(), 1);
    assert!(page.more);
    let next = home
        .pending_page(page.objects[0].seq, 1, at + 300_000)
        .unwrap();
    assert_eq!(next.objects[0].kind, "receipt");
    assert!(!next.more);
    assert_eq!(
        home.pending_object(&page.objects[0].digest, at + 300_000)
            .unwrap()
            .unwrap()
            .receipts,
        vec![receipt]
    );
    assert!(admit(&home, &t, &stamp(at + 300_001)).receipts.is_empty());
}

#[test]
fn late_activation_decision_survives_restart_and_keeps_transition_and_receipts() {
    let entry = fixture("t-remove-after-delay", "records/authority/00000003.json");
    let at = time(&entry);
    let home = setup("t-remove-after-delay", true, always(), at);
    let late = admit(&home, &entry, &stamp(at));
    assert_eq!(late.result, Err(Refusal::Late));
    let page = late.state.pending_page(0, 64, at).unwrap();
    assert_eq!(
        page.objects
            .iter()
            .map(|p| p.kind.as_str())
            .collect::<Vec<_>>(),
        vec!["transition", "receipt"]
    );
    let home = restore(&late.state).with_serving(Vec::new()).unwrap();
    assert_eq!(admit(&home, &entry, &stamp(at)).result, Err(Refusal::Late));
}

#[test]
fn downtime_exception_requires_no_serving_during_the_receipt_window() {
    let entry = fixture("t-remove-after-delay", "records/authority/00000003.json");
    let t = fixture("t-remove-after-delay", "objects/transition.json");
    let at = time(&t);
    let due = time(&entry);
    let down = setup(
        "t-remove-after-delay",
        true,
        vec![ServingInterval {
            from_ms: at + 300_001,
            through_ms: None,
        }],
        due,
    );
    assert_eq!(admit(&down, &entry, &stamp(due)).result, Ok(()));
    let partial = setup(
        "t-remove-after-delay",
        true,
        vec![ServingInterval {
            from_ms: at,
            through_ms: Some(at),
        }],
        due,
    );
    assert_eq!(
        admit(&partial, &entry, &stamp(due)).result,
        Err(Refusal::Late)
    );
}

#[test]
fn forwarded_receipt_before_transition_counts_only_after_its_window_is_validated() {
    let t = fixture("t-remove-after-delay", "objects/transition.json");
    let r = fixture("t-remove-after-delay", "objects/receipt.json");
    let entry = fixture("t-remove-after-delay", "records/authority/00000003.json");
    let at = time(&t);
    let due = time(&entry);
    for invalid in [false, true] {
        let home = setup("t-remove-after-delay", true, always(), at);
        let receipt = if invalid {
            let mut b = body(&r);
            b["received"] = Value::from(stamp(at + 300_001));
            signed(&b)
        } else {
            r.clone()
        };
        let unseen = admit(&home, &receipt, &stamp(at + 1));
        assert_eq!(unseen.result.as_ref().unwrap_err().code(), "unavailable");
        assert!(unseen
            .state
            .pending_page(0, 64, at + 1)
            .unwrap()
            .objects
            .is_empty());
        let late_t = admit(&restore(&unseen.state), &t, &stamp(due));
        assert_eq!(late_t.result, Err(Refusal::Late));
        let activation = admit(&restore(&late_t.state), &entry, &stamp(due));
        assert_eq!(
            activation.result,
            if invalid { Err(Refusal::Late) } else { Ok(()) }
        );
    }
}

#[test]
fn proposer_cap_never_evicts_and_returns_per_object_batch_results() {
    let t = fixture("t-remove-after-delay", "objects/transition.json");
    let at = time(&t);
    let home = setup("t-remove-after-delay", false, always(), at);
    let mut proposals = Vec::new();
    for offset in 0..3 {
        let mut b = body(&t);
        b["issued"] = Value::from(stamp(at + offset));
        proposals.push(signed(&b));
    }
    let (state, results, drafts) = admit_pending_batch(&home, &proposals, &stamp(at + 10)).unwrap();
    assert_eq!(results, vec![Ok(()), Ok(()), Err(Refusal::ProposerFull)]);
    assert_eq!(drafts.len(), 2);
    assert_eq!(state.pending_page(0, 64, at + 10).unwrap().objects.len(), 2);
    assert!(admit_pending_batch(&state, &[], &stamp(at)).is_err());
}

#[test]
fn immediate_clock_conflict_and_non_primary_ordering() {
    let entry = fixture("i-add-approve", "records/authority/00000003.json");
    let at = time(&entry);
    let primary = setup("i-add-approve", false, always(), at);
    assert_eq!(
        admit(&primary, &entry, &stamp(at - 60_001)).result,
        Err(Refusal::Early)
    );
    assert_eq!(
        admit(&primary, &entry, &stamp(at + 300_001)).result,
        Err(Refusal::Late)
    );
    let admitted = admit(&primary, &entry, &stamp(at));
    assert_eq!(admitted.result, Ok(()));
    assert_eq!(
        admit(&restore(&admitted.state), &entry, &stamp(at)).result,
        Ok(())
    );
    let different = fixture("i-tighten-policy", "records/authority/00000003.json");
    assert_eq!(
        admit(&admitted.state, &different, &stamp(at)).result,
        Err(Refusal::Conflict)
    );
    let other = setup("i-add-approve", true, always(), at);
    assert!(matches!(
        admit(&other, &entry, &stamp(at)).result,
        Err(Refusal::PrimaryRequired(_))
    ));
    // A primary head may arrive before the entry whose storage it authorizes.
    let objects = Objects {
        entries: (1..=2)
            .map(|seq| fixture("i-add-approve", &format!("records/authority/{seq:08}.json")))
            .collect(),
        ..Default::default()
    };
    let v = verify_history(&objects, &Persisted::default(), at);
    let st = v.state.unwrap();
    let env: Value = serde_json::from_slice(&entry).unwrap();
    let head = signed(
        &json!({"protocol":"colophon/head/5", "account":st.account().as_str(), "by":st.current_homes()[0].request.member_id(), "issued":stamp(at), "authority":{"seq":3,"digest":digest(&STANDARD.decode(env["body"].as_str().unwrap()).unwrap())}}),
    );
    let head_result = admit(&other, &head, &stamp(at));
    assert_eq!(head_result.result, Ok(()));
    assert_eq!(
        admit(&restore(&head_result.state), &entry, &stamp(at)).result,
        Ok(())
    );
}

#[test]
fn receipt_and_transition_arrival_order_preserves_activation_verdict() {
    let t = fixture("t-remove-after-delay", "objects/transition.json");
    let at = time(&t);
    let r = fixture("t-remove-after-delay", "objects/receipt.json");
    let entry = fixture("t-remove-after-delay", "records/authority/00000003.json");
    let due = time(&entry);
    for order in [[&t, &r], [&r, &t]] {
        let mut home = setup("t-remove-after-delay", true, always(), at);
        for bytes in order {
            home = restore(&admit(&home, bytes, &stamp(at + 2)).state);
        }
        let result = admit(&home, &entry, &stamp(due));
        assert_eq!(result.result, Ok(()));
        assert!(result
            .state
            .pending_page(0, 64, due)
            .unwrap()
            .objects
            .is_empty());
    }
}

#[test]
fn hostile_home_objects_and_checkpoints_never_panic() {
    let t = fixture("t-remove-after-delay", "objects/transition.json");
    let at = time(&t);
    let home = setup("t-remove-after-delay", false, always(), at);
    for n in 0..t.len() {
        let mut bytes = t.clone();
        bytes[n] ^= 0x80;
        assert!(std::panic::catch_unwind(|| admit(&home, &bytes, &stamp(at))).is_ok());
    }
    for bytes in [b"".as_slice(), b"{}", b"{\"version\":2}"] {
        assert!(HomeState::from_bytes(bytes).is_err());
    }
    assert!(admit(&home, &t, "0000-01-01T00:00:00Z").result.is_err());
}

#[test]
fn veto_cap_is_per_unit_and_valid_veto_blocks_activation_until_recorded() {
    let recording = body(&fixture(
        "t-vetoed-by-target",
        "records/authority/00000003.json",
    ));
    let t = STANDARD
        .decode(recording["transition"].as_str().unwrap())
        .unwrap();
    let tr = STANDARD
        .decode(recording["transitionReceipts"][0].as_str().unwrap())
        .unwrap();
    let v = STANDARD
        .decode(recording["veto"].as_str().unwrap())
        .unwrap();
    let vr = STANDARD
        .decode(recording["receipts"][0].as_str().unwrap())
        .unwrap();
    let at = time(&t);
    let va = time(&v);
    let home = setup("t-vetoed-by-target", false, always(), at);
    let home = admit(&home, &t, &stamp(at + 1)).state;
    let home = admit(&home, &tr, &stamp(at + 2)).state;
    let first = admit(&home, &v, &stamp(va));
    assert_eq!(first.result, Ok(()));
    let mut variant = body(&v);
    variant["issued"] = Value::from(stamp(va + 1));
    let second = admit(&first.state, &signed(&variant), &stamp(va + 1));
    assert_eq!(second.result, Err(Refusal::VetoFull));
    let home = admit(&restore(&first.state), &vr, &stamp(va + 1)).state;
    // The corpus's corresponding activation embeds the same transition and receipt.
    let t_body = body(&t);
    let due = at + 300_000 + 259_200_000;
    let prefix_last = fixture("t-vetoed-by-target", "records/authority/00000002.json");
    let prefix_env: Value = serde_json::from_slice(&prefix_last).unwrap();
    let activation = json!({"protocol":"colophon/authority/5", "seq":3,
        "previous":digest(&STANDARD.decode(prefix_env["body"].as_str().unwrap()).unwrap()),
        "issued":stamp(due), "by":t_body["by"], "kind":"activate",
        "transition":STANDARD.encode(&t), "receipts":[STANDARD.encode(&tr)]});
    let entry =
        canonical(&json!({"body":STANDARD.encode(canonical(&activation).unwrap())})).unwrap();
    let refusal = admit(&home, &entry, &stamp(due)).result.unwrap_err();
    assert!(matches!(refusal, Refusal::Verification(_)));
    assert_eq!(refusal.code(), "malformed");
}

#[test]
fn pending_batch_reports_malformed_objects_without_losing_valid_results() {
    let t = fixture("t-remove-after-delay", "objects/transition.json");
    let at = time(&t);
    let home = setup("t-remove-after-delay", false, always(), at);
    let (home, results, _) =
        admit_pending_batch(&home, &[b"garbage".to_vec(), t], &stamp(at)).unwrap();
    assert_eq!(results[0].as_ref().unwrap_err().code(), "malformed");
    assert_eq!(results[1], Ok(()));
    assert_eq!(home.pending_page(0, 64, at).unwrap().objects.len(), 1);
}

#[test]
fn account_cap_follows_proposer_cap_and_retains_receipted_late_evidence() {
    let t = fixture("t-remove-after-delay", "objects/transition.json");
    let r = fixture("t-remove-after-delay", "objects/receipt.json");
    let original_entry = fixture("t-remove-after-delay", "records/authority/00000003.json");
    let at = time(&t);
    let due = time(&original_entry);
    let mut home = setup("t-remove-after-delay", true, always(), at);
    // Foreign receipted transitions embedded in refused activations must still be served.
    // They do not receive this home's receipt and cannot evict earlier pending proposals.
    for offset in 0..10 {
        let mut tb = body(&t);
        tb["issued"] = Value::from(stamp(at + offset));
        let transition = signed(&tb);
        let mut rb = body(&r);
        let te: Value = serde_json::from_slice(&transition).unwrap();
        rb["object"] = Value::from(digest(
            &STANDARD.decode(te["body"].as_str().unwrap()).unwrap(),
        ));
        rb["received"] = Value::from(stamp(at + offset + 1));
        let receipt = signed(&rb);
        let mut entry = body(&original_entry);
        entry["transition"] = Value::from(STANDARD.encode(transition));
        entry["receipts"] = json!([STANDARD.encode(receipt)]);
        entry["issued"] = Value::from(stamp(due + offset));
        let bytes =
            canonical(&json!({"body":STANDARD.encode(canonical(&entry).unwrap())})).unwrap();
        let result = admit(&home, &bytes, &stamp(due + offset));
        assert_eq!(result.result, Err(Refusal::Late));
        home = restore(&result.state);
    }
    let now = due + 20;
    let mut proposed = body(&t);
    proposed["issued"] = Value::from(stamp(now));
    assert_eq!(
        admit(&home, &signed(&proposed), &stamp(now)).result,
        Err(Refusal::ProposerFull)
    );
    let scalar = Sha256::digest(b"colophon-0.5-candidate/r5/phone");
    let phone = SigningKey::from_slice(&scalar).unwrap();
    let id = digest(phone.verifying_key().to_encoded_point(false).as_bytes())[..32].to_string();
    proposed["by"] = Value::from(id.clone());
    proposed["signers"] = json!([id]);
    assert_eq!(
        admit(&home, &signed(&proposed), &stamp(now)).result,
        Err(Refusal::PendingFull)
    );
    assert_eq!(
        home.pending_page(0, 64, now)
            .unwrap()
            .objects
            .iter()
            .filter(|p| p.kind == "transition")
            .count(),
        10
    );
}

#[test]
fn shuffled_pending_objects_converge_after_unavailable_dependencies_are_retried() {
    let recorded = fixture("t-vetoed-by-target", "records/authority/00000003.json");
    let b = body(&recorded);
    let objects = [
        STANDARD.decode(b["transition"].as_str().unwrap()).unwrap(),
        STANDARD
            .decode(b["transitionReceipts"][0].as_str().unwrap())
            .unwrap(),
        STANDARD.decode(b["veto"].as_str().unwrap()).unwrap(),
        STANDARD.decode(b["receipts"][0].as_str().unwrap()).unwrap(),
    ];
    let now = time(&recorded);
    let clock = stamp(now);
    for a in 0..4 {
        for b in 0..4 {
            for c in 0..4 {
                for d in 0..4 {
                    let order = [a, b, c, d];
                    if (0..4).any(|i| (i + 1..4).any(|j| order[i] == order[j])) {
                        continue;
                    }
                    let mut home = setup("t-vetoed-by-target", false, always(), now);
                    let mut retry = Vec::new();
                    for i in order {
                        let admission = admit(&home, &objects[i], &clock);
                        if admission
                            .result
                            .as_ref()
                            .is_err_and(|r| r.code() == "unavailable")
                        {
                            retry.push(i);
                        } else {
                            assert!(
                                admission.result.is_ok() || admission.result == Err(Refusal::Late)
                            );
                        }
                        home = restore(&admission.state);
                    }
                    for _ in 0..4 {
                        retry.retain(|i| {
                            let admission = admit(&home, &objects[*i], &clock);
                            let unavailable = admission
                                .result
                                .as_ref()
                                .is_err_and(|r| r.code() == "unavailable");
                            assert!(admission.result.is_ok() || unavailable);
                            home = restore(&admission.state);
                            unavailable
                        });
                    }
                    assert!(retry.is_empty(), "order {order:?}");
                    let recorded = admit(&home, &recorded, &clock);
                    assert_eq!(recorded.result, Ok(()), "order {order:?}");
                    assert!(recorded
                        .state
                        .pending_page(0, 64, now)
                        .unwrap()
                        .objects
                        .is_empty());
                }
            }
        }
    }
}
