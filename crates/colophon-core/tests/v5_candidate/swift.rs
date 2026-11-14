//! Swift-format keyring predecessors (spec §15.1, §16.3), replayed by the Swift verifier too.
#![allow(clippy::unwrap_used)]
use crate::kit::*;
use serde_json::{json, Value};
use std::sync::LazyLock;

pub const SWIFT_T: &str = "2026-11-01T08:00:00Z";

pub static ROOT_S: LazyLock<Key> = LazyLock::new(|| derived("swift/root/signing"));
pub static ROOT_A: LazyLock<Key> = LazyLock::new(|| derived("swift/root/agreement"));
pub static REC_S: LazyLock<Key> = LazyLock::new(|| derived("swift/recovery/signing"));
pub static REC_A: LazyLock<Key> = LazyLock::new(|| derived("swift/recovery/agreement"));
pub static VAULT_S: LazyLock<Key> = LazyLock::new(|| derived("swift/vault/signing"));
pub static VAULT_A: LazyLock<Key> = LazyLock::new(|| derived("swift/vault/agreement"));
pub static SP: LazyLock<Authenticator> =
    LazyLock::new(|| Authenticator::new("swift-passkey", "id.example", json!({})));
pub static SY: LazyLock<Authenticator> =
    LazyLock::new(|| Authenticator::new("swift-security-key", "id.example", json!({})));

pub fn pid(sign: &Key, agree: &Key) -> Value {
    json!({"agreement": b64(&agree.point), "signing": b64(&sign.point)})
}

pub fn swift_ctrl(k: &Key, roles: &[&str], label: &str) -> Value {
    json!({"key": b64(&k.point), "kind": "p256", "label": label, "roles": roles})
}

pub fn swift_record(body: &Value, primary: &Key, cos: &[&Key]) -> Value {
    let b = canonical(body);
    let mut rec = json!({"body": b64(&b), "signature": b64(&primary.sign(&b))});
    if !cos.is_empty() {
        rec["cosignatures"] = json!(cos
            .iter()
            .map(|k| json!({"signer": k.id, "signature": b64(&k.sign(&b))}))
            .collect::<Vec<_>>());
    }
    rec
}

fn body_digest(rec: &Value) -> String {
    sha(&unb64(rec["body"].as_str().unwrap()))
}

fn slot_a() -> Value {
    let a: &Key = &A;
    let agree = a.agreement.clone().unwrap();
    let seed = sha_raw(b"swift/vault-seed");
    json!({"controller": a.id, "kind": "sealed", "label": "Mac",
           "recipient": {"agreement": b64(&agree), "signing": b64(&a.point)},
           "sealed": swift_sealed(&seed, &a.point, &agree, "swift/slot-eph")})
}

fn swift_genesis() -> Value {
    let g = json!({"by": "root", "issued": SWIFT_T, "kind": "genesis", "label": "Library", "recovery": pid(&REC_S, &REC_A),
                   "root": pid(&ROOT_S, &ROOT_A), "seq": 1});
    swift_record(&g, &ROOT_S, &[])
}

/// The genesis alone (`adopt` false) or genesis and the keyring that adopts the Mac and the kit.
pub fn swift_library(adopt: bool) -> Vec<Value> {
    let mut recs = vec![swift_genesis()];
    if !adopt {
        return recs;
    }
    let ctrls = vec![
        swift_ctrl(&A, &["approve", "control"], "Mac"),
        swift_ctrl(&K1, &["recover"], "Kit"),
    ];
    let k = json!({"by": "root", "controllers": ctrls, "issued": "2026-11-01T08:01:00Z", "kind": "keyring",
                   "previous": body_digest(&recs[0]), "seq": 2, "slots": [slot_a()], "threshold": 1,
                   "vault": pid(&VAULT_S, &VAULT_A)});
    recs.push(swift_record(&k, &ROOT_S, &[]));
    recs
}

/// A root-signed layout freeze.
pub fn swift_freeze_root(recs: &[Value], successor: &str, issued: &str) -> Value {
    let seq = recs.len() + 1;
    let f = json!({"by": "root", "issued": issued, "kind": "layout", "layout": 3,
                   "previous": body_digest(&recs[seq - 2]), "seq": seq, "successor": successor});
    swift_record(&f, &ROOT_S, &[])
}

pub fn swift_signed(body: &Value, primary: &dyn Signer, cos: &[&dyn Signer]) -> Value {
    let b = canonical(body);
    let item = |k: &dyn Signer| -> (String, Option<Value>) {
        if k.is_authenticator() {
            let (der, assertion) = k.webauthn_sign(&b, &format!("https://{}", rp_of(k)), 0x05);
            (b64(&der), Some(assertion))
        } else {
            (b64(&raw_sign(k, &b)), None)
        }
    };
    let (sig, asr) = item(primary);
    let mut rec = json!({"body": b64(&b), "signature": sig});
    if let Some(a) = asr {
        rec["assertion"] = a;
    }
    if !cos.is_empty() {
        let mut list = Vec::new();
        for k in cos {
            let (s2, a2) = item(*k);
            let mut c2 = json!({"signer": k.id(), "signature": s2});
            if let Some(a) = a2 {
                c2["assertion"] = a;
            }
            list.push(c2);
        }
        rec["cosignatures"] = Value::Array(list);
    }
    rec
}

fn rp_of(k: &dyn Signer) -> String {
    k.descriptor()["rp"].as_str().unwrap().to_string()
}
fn raw_sign(k: &dyn Signer, body: &[u8]) -> Vec<u8> {
    unb64(k.sig_item(body, None, 0x05)["signature"].as_str().unwrap())
}

pub fn swift_webauthn_ctrl(a: &Authenticator, roles: &[&str], label: &str) -> Value {
    json!({"credential": b64(&a.credential), "key": b64(&a.point), "kind": "webauthn", "label": label,
           "roles": roles, "rpID": a.rp, "verification": true})
}

pub fn swift_webauthn_library() -> Vec<Value> {
    let mut recs = swift_library(false);
    let ctrls = vec![
        swift_ctrl(&A, &["approve", "control"], "Mac"),
        swift_webauthn_ctrl(&SP, &["approve", "recover"], "Passkey"),
        swift_webauthn_ctrl(&SY, &["approve", "control"], "Security key"),
    ];
    let k = json!({"by": "root", "controllers": ctrls, "issued": "2026-11-01T08:01:00Z", "kind": "keyring",
                   "previous": body_digest(&recs[0]), "seq": 2, "slots": [slot_a()], "threshold": 1,
                   "vault": pid(&VAULT_S, &VAULT_A)});
    recs.push(swift_record(&k, &ROOT_S, &[]));
    recs
}

pub fn swift_freeze_signed(
    recs: &[Value],
    successor: &str,
    signer: &dyn Signer,
    issued: &str,
) -> Value {
    let f = json!({"by": "controller", "issued": issued, "kind": "layout", "layout": 3,
                   "previous": body_digest(recs.last().unwrap()), "seq": recs.len() + 1, "signer": signer.id(),
                   "successor": successor});
    swift_signed(&f, signer, &[])
}

pub fn genesis_from(
    recs: &[Value],
    ctrls: Vec<Value>,
    rt: i64,
    handover: Sl,
    label: &str,
) -> Chain {
    let pred = json!({"format": "colophon/swift-keyring/2", "account": &body_digest(&recs[0])[..32],
                      "head": {"seq": recs.len(), "digest": body_digest(recs.last().unwrap())}});
    let mut g = Chain::new();
    genesis(
        &mut g,
        &keyring(
            ctrls,
            Kr {
                rt,
                ..Kr::default()
            },
        ),
        sg![A],
        Gen {
            label,
            predecessor: Some(pred),
            opt: Opt {
                handover,
                origin: Some("https://id.example"),
                ..Opt::default()
            },
            ..Gen::default()
        },
    );
    g
}

pub fn new_genesis(pred_recs: &[Value], head_seq: usize, handover: Sl, label: &str) -> Chain {
    let lib_id = body_digest(&pred_recs[0])[..32].to_string();
    let ctrls = vec![
        ctrl(&*A, &["approve", "control"], Some("Mac"), json!({})),
        ctrl(&*K1, &["recover"], Some("Kit"), json!({})),
    ];
    let kr_new = keyring(
        ctrls,
        Kr {
            rt: 1,
            ..Kr::default()
        },
    );
    let head = &pred_recs[head_seq - 1];
    let pred = json!({"format": "colophon/swift-keyring/2", "account": lib_id,
                      "head": {"seq": head_seq, "digest": body_digest(head)}});
    let head_issued = body_json(head)["issued"].as_str().unwrap().to_string();
    let issued = std::cmp::max(T0.to_string(), head_issued);
    let mut g = Chain::new();
    g.add(
        "genesis",
        &*A,
        &issued,
        &*A,
        Opt {
            handover,
            ..Opt::default()
        },
        json!({"label": label, "namespaces": [], "keyring": kr_new, "predecessor": pred}),
    );
    g
}

pub fn write_swift(
    o: &mut Out,
    name: &str,
    recs: &[Value],
    g5: Option<&Chain>,
    expected: Value,
    why: &str,
    extra: Vec<(String, Value)>,
) {
    for (i, r) in recs.iter().enumerate() {
        write(
            o,
            &format!("succession/{name}/predecessor/authority/{:08}.json", i + 1),
            r,
        );
    }
    for (rel, r) in &extra {
        write(o, &format!("succession/{name}/{rel}"), r);
    }
    if let Some(g) = g5 {
        write(o, &format!("succession/{name}/genesis.json"), &g.envs[0]);
    }
    write(
        o,
        &format!("succession/{name}/case.json"),
        &json!({"description": why, "sections": ["15.1", "16.3"], "expected": expected}),
    );
}
