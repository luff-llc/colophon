//! Differential and work-count regressions for pending-object selection.
use super::*;
use crate::v05::encoding::{canonical, decode_base64, digest, encode_base64};
use crate::v05::history::{verify_history, work::PENDING_CHECKS, Persisted};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};

fn reference(
    objects: &Objects,
    state: &crate::v05::history::State,
) -> (Objects, BTreeSet<Vec<u8>>) {
    use crate::v05::encoding::bounds;
    use crate::v05::history::{check_pending_transition, check_pending_veto};
    use crate::v05::write::authority::choose_receipts;
    let mut groups: BTreeMap<(String, String), Vec<&Vec<u8>>> = BTreeMap::new();
    let mut rest: Vec<&Vec<u8>> = Vec::new();
    for b in &objects.pending {
        let parsed = AuthEnvelope::parse(
            b,
            bounds::TRANSITION_ENVELOPE,
            bounds::TRANSITION_ENVELOPE,
            true,
        );
        match parsed {
            Ok(e) => match e.value.get("protocol").and_then(Value::as_str) {
                Some(p @ ("colophon/transition/5" | "colophon/veto/5")) => {
                    groups.entry((p.to_string(), e.digest)).or_default().push(b)
                }
                _ => rest.push(b),
            },
            Err(_) => rest.push(b),
        }
    }
    let mut chosen: BTreeMap<(String, String), Vec<u8>> = BTreeMap::new();
    let mut verified: BTreeSet<Vec<u8>> = BTreeSet::new();
    let transition_of = |digest: &str, chosen: &BTreeMap<(String, String), Vec<u8>>| {
        chosen
            .get(&("colophon/transition/5".to_string(), digest.to_string()))
            .cloned()
    };
    for protocol in ["colophon/transition/5", "colophon/veto/5"] {
        for ((p, digest), list) in &groups {
            if p != protocol {
                continue;
            }
            let mut list = list.clone();
            list.sort();
            let found = list
                .iter()
                .find(|b| {
                    if protocol == "colophon/transition/5" {
                        return check_pending_transition(state, b).is_ok();
                    }
                    let Ok(v) =
                        AuthEnvelope::parse(b, bounds::VETO_BODY, bounds::VETO_ENVELOPE, true)
                    else {
                        return false;
                    };
                    let Some(t) = v
                        .value
                        .get("transition")
                        .and_then(Value::as_str)
                        .and_then(|d| transition_of(d, &chosen))
                    else {
                        return false;
                    };
                    let Ok(te) = AuthEnvelope::parse(
                        &t,
                        bounds::TRANSITION_ENVELOPE,
                        bounds::TRANSITION_ENVELOPE,
                        true,
                    ) else {
                        return false;
                    };
                    let issued = te
                        .value
                        .get("issued")
                        .and_then(Value::as_str)
                        .and_then(crate::v05::encoding::parse_date)
                        .unwrap_or(0);
                    choose_receipts(state, &objects.pending, &te.digest, issued, None)
                        .is_ok_and(|r| check_pending_veto(state, &t, &r, b).is_ok())
                })
                .map(|b| (**b).clone());
            if let Some(b) = &found {
                verified.insert(b.clone());
            }
            let pick = found.or_else(|| list.first().map(|b| (**b).clone()));
            if let Some(b) = pick {
                chosen.insert((p.clone(), digest.clone()), b);
            }
        }
    }
    let mut out = objects.clone();
    out.pending = rest
        .into_iter()
        .cloned()
        .chain(chosen.into_values())
        .collect();
    out.pending.sort();
    (out, verified)
}

fn envelope(value: &Value) -> Vec<u8> {
    canonical(value).expect("valid test fixture")
}
fn body(env: &Value) -> Value {
    serde_json::from_slice(
        &decode_base64(env["body"].as_str().expect("valid test fixture"), 1 << 20)
            .expect("valid test fixture"),
    )
    .expect("valid test fixture")
}
fn resign(env: &Value, value: &Value, keys: &BTreeMap<String, SigningKey>) -> Vec<u8> {
    let bytes = canonical(value).expect("valid test fixture");
    let mut env = env.clone();
    env["body"] = Value::String(encode_base64(&bytes));
    let sign = |id: &str| {
        let sig: Signature = keys
            .get(id)
            .unwrap_or_else(|| panic!("missing public test secret {id}"))
            .sign(&bytes);
        Value::String(encode_base64(&sig.to_bytes()))
    };
    env["signature"] = sign(value["by"].as_str().expect("valid test fixture"));
    for field in ["cosignatures", "additions"] {
        if let Some(items) = env.get_mut(field).and_then(Value::as_array_mut) {
            for item in items {
                item["signature"] = sign(item["signer"].as_str().expect("valid test fixture"));
            }
        }
    }
    envelope(&env)
}
fn fixture() -> (
    Objects,
    crate::v05::history::State,
    Value,
    Value,
    Value,
    BTreeMap<String, SigningKey>,
) {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance/0.5/rules");
    let dir = root.join("t-vetoed-displaces-activation-and-later-revocation/records/authority");
    let entries: Vec<_> = (1..=2)
        .map(|i| std::fs::read(dir.join(format!("{i:08}.json"))).expect("valid test fixture"))
        .collect();
    let objects = Objects {
        entries,
        ..Objects::default()
    };
    let state = verify_history(&objects, &Persisted::default(), 1_795_132_800_000)
        .state
        .expect("valid test fixture");
    let entry: Value = serde_json::from_slice(
        &std::fs::read(dir.join("00000003.json")).expect("valid test fixture"),
    )
    .expect("valid test fixture");
    let value = body(&entry);
    let decode = |v: &Value| {
        serde_json::from_slice::<Value>(
            &decode_base64(v.as_str().expect("valid test fixture"), 1 << 20)
                .expect("valid test fixture"),
        )
        .expect("valid test fixture")
    };
    let transition = decode(&value["transition"]);
    let receipt = decode(&value["transitionReceipts"][0]);
    let veto = decode(&value["veto"]);
    let mut keys = BTreeMap::new();
    let software: Value = serde_json::from_slice(
        &std::fs::read(root.join("../../0.4/keys/keys.json")).expect("valid test fixture"),
    )
    .expect("valid test fixture");
    for value in software["software"].as_array().expect("valid test fixture") {
        keys.insert(
            value["id"].as_str().expect("valid test fixture").into(),
            SigningKey::from_slice(
                &decode_base64(
                    value["signingScalar"].as_str().expect("valid test fixture"),
                    32,
                )
                .expect("valid test fixture"),
            )
            .expect("valid test fixture"),
        );
    }
    let published: Value = serde_json::from_slice(
        &std::fs::read(root.join("keys-r4.json")).expect("valid test fixture"),
    )
    .expect("valid test fixture");
    for value in published["keys"]
        .as_object()
        .expect("valid test fixture")
        .values()
    {
        keys.insert(
            value["id"].as_str().expect("valid test fixture").into(),
            SigningKey::from_slice(
                &decode_base64(value["scalar"].as_str().expect("valid test fixture"), 32)
                    .expect("valid test fixture"),
            )
            .expect("valid test fixture"),
        );
    }
    (objects, state, transition, receipt, veto, keys)
}

#[test]
fn effective_selection_matches_reference_and_receipt_work_is_linear() {
    let (base, state, transition, receipt, veto, keys) = fixture();
    let run = |n: usize| {
        let mut objects = base.clone();
        let mut good = 0;
        for i in 0..n {
            let mut t = body(&transition);
            // An ignored unknown field would change verdicts; changing a controller label is a real valid transition.
            t["change"]["keyring"]["add"][0]["label"] = Value::String(format!("Phone {i}"));
            let t_bytes = resign(&transition, &t, &keys);
            let td = digest(&canonical(&t).expect("valid test fixture"));
            let mut r = body(&receipt);
            r["object"] = Value::String(td.clone());
            let r_bytes = resign(&receipt, &r, &keys);
            objects.pending.extend([
                t_bytes.clone(),
                t_bytes.clone(),
                r_bytes.clone(),
                r_bytes.clone(),
            ]);
            for j in 0..3 {
                let mut v = body(&veto);
                v["transition"] = Value::String(td.clone());
                v["issued"] = Value::String(format!("2026-11-11T09:10:{j:02}Z"));
                let valid = resign(&veto, &v, &keys);
                crate::v05::history::check_pending_veto(
                    &state,
                    &t_bytes,
                    std::slice::from_ref(&r_bytes),
                    &valid,
                )
                .expect("valid synthetic veto");
                good += 1;
                let mut bad: Value = serde_json::from_slice(&valid).expect("valid test fixture");
                bad["signature"] = Value::String(encode_base64(&[0; 64]));
                objects
                    .pending
                    .extend([valid.clone(), valid, envelope(&bad)]);
            }
        }
        objects.pending.push(b"malformed".to_vec());
        // Noncanonical receipt envelopes must still count, while noncanonical auth envelopes do not group.
        objects
            .pending
            .push(serde_json::to_vec_pretty(&receipt).expect("valid test fixture"));
        let want = reference(&objects, &state);
        PENDING_CHECKS.with(|c| c.set((0, 0)));
        let got = effective_objects(&objects, &state);
        let work = PENDING_CHECKS.with(std::cell::Cell::get);
        assert_eq!(got.0.pending, want.0.pending);
        assert_eq!(got.1, want.1);
        assert_eq!(got.1.len(), n + good);
        assert!(work.0 <= n * 2, "transition checks: {work:?}");
        assert!(work.1 <= n * 3 + 1, "receipt signature checks: {work:?}");
        work
    };
    let small = run(4);
    let large = run(12);
    assert!(large.0 <= small.0 * 3);
    assert!(large.1 <= small.1 * 3);
}

#[test]
fn selection_parity_for_missing_receipts_invalid_transitions_and_unmatched_vetoes() {
    let (base, state, transition, receipt, veto, _) = fixture();
    let t = envelope(&transition);
    let r = envelope(&receipt);
    let v = envelope(&veto);
    let mut bad_t = transition.clone();
    bad_t["signature"] = Value::String(encode_base64(&[0; 64]));
    let mut bad_r = receipt.clone();
    bad_r["signature"] = Value::String(encode_base64(&[0; 64]));
    let mut unknown_v = body(&veto);
    unknown_v["transition"] = Value::String("a".repeat(64));
    let mut unmatched = veto.clone();
    unmatched["body"] = Value::String(encode_base64(
        &canonical(&unknown_v).expect("valid test fixture"),
    ));
    for pending in [
        vec![t.clone(), r.clone()],
        vec![t.clone(), v.clone()],
        vec![t.clone(), envelope(&bad_r), v.clone()],
        vec![envelope(&bad_t), r.clone(), v.clone()],
        vec![envelope(&bad_t), t.clone(), r.clone(), v.clone()],
        vec![t.clone(), r.clone(), envelope(&unmatched)],
        vec![r.clone(), v.clone()],
        vec![
            serde_json::to_vec_pretty(&transition).expect("valid test fixture"),
            r,
            v,
        ],
    ] {
        let objects = Objects {
            pending,
            ..base.clone()
        };
        assert_eq!(
            format!("{:?}", effective_objects(&objects, &state)),
            format!("{:?}", reference(&objects, &state))
        );
    }
    // Common no-veto opens must not introduce receipt verification or a second transition check.
    let objects = Objects {
        pending: vec![t, envelope(&receipt)],
        ..base
    };
    PENDING_CHECKS.with(|c| c.set((0, 0)));
    effective_objects(&objects, &state);
    assert_eq!(PENDING_CHECKS.with(std::cell::Cell::get), (1, 0));
}
