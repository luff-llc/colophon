//! Synthetic later-format writer shared by H4's core and real-relay tests.
#![allow(dead_code, clippy::unwrap_used, clippy::cloned_ref_to_slice_refs)]
use crate::support::*;
use crate::support_relay::{appoint_homes, HomeKeys};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use colophon_core::v05::account::*;
use colophon_core::v05::encoding::{canonical, digest};
use colophon_core::v05::history::Objects;
use colophon_core::v05::write::authority::{prepare_activate, prepare_final, TransitionRule};
use colophon_core::v05::write::format_date;
use serde_json::{json, Value};

pub const NOW: i64 = T0 + 3 * HOUR;
pub const DUE: i64 = NOW + 3_901_000;
pub const NS: &str = "notes";

pub fn fixture(history: &str, homes: &[(&HomeKeys, &str)]) -> Fixture {
    let mut host = Host::new();
    let d = host.identity(10);
    let k = host.kit(20);
    let p = host.passkey();
    let mut params = params(&mut host, &d, &p, &k, &[NS]);
    // One raw key can propose a vetoable raise with recovery consent; another unit can veto.
    params.controllers[1]["roles"] = json!(["approve", "control"]);
    params.controllers[2]["roles"] = json!(["control", "recover"]);
    params.policy.as_mut().unwrap()["history"] = json!(history);
    let mut c = Creation::begin(params, Identity::Controller(d.clone()), T0).unwrap();
    let prf = host.answer_prf(c.prf_requests());
    c = c.provide_prf(prf).unwrap();
    let sigs = host.sign(c.steps());
    let mut progress = c.provide_signatures(sigs).unwrap();
    let account = loop {
        match progress {
            CreateProgress::Continue(next) => {
                let sigs = host.sign(next.steps());
                progress = next.provide_signatures(sigs).unwrap();
            }
            CreateProgress::Done(account) => break *account,
        }
    };
    let mut f = Fixture {
        host,
        d,
        p,
        k,
        account,
    };
    appoint_homes(&mut f, homes);
    f
}

pub fn body(bytes: &[u8]) -> Value {
    let env: Value = serde_json::from_slice(bytes).unwrap();
    serde_json::from_slice(&STANDARD.decode(env["body"].as_str().unwrap()).unwrap()).unwrap()
}
pub fn object_digest(bytes: &[u8]) -> String {
    digest(&canonical(&body(bytes)).unwrap())
}
pub fn value(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap()
}

pub fn signed(f: &Fixture, body: Value) -> Vec<u8> {
    let bytes = canonical(&body).unwrap();
    let by = body["by"].as_str().unwrap();
    let cos: Vec<Value> = body["signers"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|s| s.as_str())
        .filter(|s| *s != by)
        .map(|s| json!({"signer": s, "signature": b64(&f.host.ids[s].sign(&bytes))}))
        .collect();
    let mut env = json!({"body": b64(&bytes), "signature": b64(&f.host.ids[by].sign(&bytes))});
    if !cos.is_empty() {
        env["cosignatures"] = json!(cos);
    }
    canonical(&env).unwrap()
}
pub fn transition(f: &Fixture, change: Value, signer: &str, now: i64) -> Vec<u8> {
    let action = f
        .account
        .begin_transition(
            &Change::policy(json!({"callWindow": 120})),
            &[signer.to_string()],
            TransitionRule::Control,
        )
        .unwrap();
    let mut v: Value = serde_json::from_slice(action.steps()[0].body()).unwrap();
    v["change"] = change;
    v["issued"] = json!(format_date(now));
    signed(f, v)
}
pub fn veto(f: &Fixture, t: &[u8], signer: &str, now: i64) -> Vec<u8> {
    signed(
        f,
        json!({"protocol": "colophon/veto/5", "account": f.account.id().as_str(),
        "transition": object_digest(t), "issued": format_date(now), "by": signer, "signers": [signer]}),
    )
}
pub fn receipt(keys: &HomeKeys, account: &str, object: &[u8], now: i64) -> Vec<u8> {
    let bytes = canonical(&json!({"protocol":"colophon/receipt/5", "account":account,
        "object":object_digest(object), "received":format_date(now), "by":keys.id}))
    .unwrap();
    canonical(&json!({"body":b64(&bytes), "signature":b64(&keys.sign(&bytes).signature)})).unwrap()
}
pub fn head(keys: &HomeKeys, objects: &Objects, now: i64) -> Vec<u8> {
    let last = objects.entries.iter().max_by_key(|e| entry_seq(e)).unwrap();
    let genesis = objects.entries.iter().find(|e| entry_seq(e) == 1).unwrap();
    let bytes = canonical(
        &json!({"protocol":"colophon/head/5", "account":object_digest(genesis),
        "authority":{"seq":entry_seq(last), "digest":object_digest(last)},
        "issued":format_date(now), "by":keys.id}),
    )
    .unwrap();
    canonical(&json!({"body":b64(&bytes), "signature":b64(&keys.sign(&bytes).signature)})).unwrap()
}
pub fn activate(objects: &mut Objects, t: &[u8], now: i64) -> Vec<u8> {
    let done = prepare_activate(objects, now, &object_digest(t))
        .unwrap()
        .finish(vec![])
        .unwrap();
    let e = done.entries[0].1.clone();
    objects.entries.push(e.clone());
    e
}
pub fn final_entry(objects: &mut Objects, seq: u64, now: i64) -> Vec<u8> {
    let done = prepare_final(objects, now, seq)
        .unwrap()
        .finish(vec![])
        .unwrap();
    let e = done.entries[0].1.clone();
    objects.entries.push(e.clone());
    e
}
