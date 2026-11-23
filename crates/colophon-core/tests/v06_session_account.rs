//! `SessionAccount::from_history_state` against a real verified 0.5 history: a member granted
//! `records` on the namespace, its sessions ended twice, then revoked (§S1, §S2).
#![allow(clippy::unwrap_used, dead_code)]
use base64::{engine::general_purpose::STANDARD, Engine};
use colophon_core::v05::encoding::canonical;
use colophon_core::v05::history::{verify_history, Objects, Persisted, State};
use colophon_core::v05::ids::{key_id, AccountId};
use colophon_core::v05::terms::Access;
use colophon_core::v05::write::authority::*;
use colophon_core::v05::write::*;
use colophon_core::v06::session::keys::SessionAccount;
use p256::ecdsa::{signature::Signer, Signature as P256Signature, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const T0: i64 = 1_794_384_000_000; // 2026-11-11T08:00:00Z
const SEC: i64 = 1_000;
const RP: &str = "id.luff.works";

fn b64(b: &[u8]) -> String {
    STANDARD.encode(b)
}

// ---------------------------------------------------------------------------------------------
// The host's side: keys and signing.

#[derive(Clone)]
struct Key {
    sk: SigningKey,
    point: Vec<u8>,
    id: String,
}
fn key_from_scalar(scalar: &[u8]) -> Key {
    let sk = SigningKey::from_slice(scalar).unwrap();
    let point = sk
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let id = key_id(&point);
    Key { sk, point, id }
}
fn key(n: u8) -> Key {
    key_from_scalar(&[n; 32])
}
fn der_int(x: &[u8]) -> Vec<u8> {
    let mut v: Vec<u8> = x.iter().copied().skip_while(|b| *b == 0).collect();
    if v.is_empty() {
        v.push(0);
    }
    if v[0] & 0x80 != 0 {
        v.insert(0, 0);
    }
    let mut out = vec![2, v.len() as u8];
    out.extend(v);
    out
}
fn der(raw: &[u8]) -> Vec<u8> {
    let mut inner = der_int(&raw[..32]);
    inner.extend(der_int(&raw[32..]));
    let mut out = vec![0x30, inner.len() as u8];
    out.extend(inner);
    out
}
impl Key {
    fn sign_raw(&self, body: &[u8]) -> Vec<u8> {
        let s: P256Signature = self.sk.sign(body);
        s.to_bytes().to_vec()
    }
    fn sign_webauthn(&self, auth: &[u8], client: &[u8]) -> Vec<u8> {
        let mut m = auth.to_vec();
        m.extend(Sha256::digest(client));
        der(&self.sign_raw(&m))
    }
}

/// A host holding keys by ID.
#[derive(Default)]
struct Host {
    keys: BTreeMap<String, Key>,
}
impl Host {
    fn add(&mut self, k: &Key) {
        self.keys.insert(k.id.clone(), k.clone());
    }
    /// Sign every step: raw keys over the body, WebAuthn keys with a synthetic authenticator
    /// (UP and UV set, the step's challenge, the account's ceremony origin).
    fn sign(&self, steps: &[SigningStep]) -> Vec<SignatureResult> {
        steps
            .iter()
            .map(|s| {
                let k = &self.keys[s.signer()];
                match s.challenge() {
                    None => SignatureResult {
                        signature: k.sign_raw(s.body()),
                        assertion: None,
                    },
                    Some(ch) => {
                        let ch = ch.to_string();
                        let mut auth = Sha256::digest(RP.as_bytes()).to_vec();
                        auth.push(0x05);
                        auth.extend([0, 0, 0, 1]);
                        let client = canonical(&json!({
                            "type": "webauthn.get",
                            "challenge": ch,
                            "origin": format!("https://{RP}"),
                        }))
                        .unwrap();
                        SignatureResult {
                            signature: k.sign_webauthn(&auth, &client),
                            assertion: Some((auth, client)),
                        }
                    }
                }
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------------------------
// Fixtures: controllers, keyrings, requests, receipts, heads.

fn raw_controller(k: &Key, agreement: &Key, label: &str, roles: &[&str]) -> Value {
    json!({
        "key": {"form": "raw", "signing": b64(&k.point), "agreement": b64(&agreement.point)},
        "label": label,
        "roles": roles,
    })
}
fn passkey_controller(k: &Key, label: &str, roles: &[&str]) -> Value {
    json!({
        "key": {"form": "webauthn", "signing": b64(&k.point), "rp": RP, "credential": "AQ=="},
        "label": label,
        "roles": roles,
        "verification": true,
    })
}
fn slot_for(id: &str, label: &str) -> Value {
    // Opaque slot values (package E2 builds real ones): right sizes, never opened here.
    json!({
        "kind": "sealed",
        "controllers": [id],
        "label": label,
        "sealed": {"enc": b64(&key(0x70).point), "ciphertext": b64(&[7u8; 48])},
    })
}
fn controller_id(c: &Value) -> String {
    let p = STANDARD
        .decode(c["key"]["signing"].as_str().unwrap())
        .unwrap();
    key_id(&p)
}
fn policy() -> Value {
    json!({
        "callWindow": 300, "headMaxAge": 300, "headQuorum": 1, "history": "members",
        "linkMaxAge": 86400, "memberRule": "single",
        "rate": {"account": {"bytes": 16777216, "entries": 256},
                 "signer": {"bytes": 4194304, "entries": 64}},
        "recoveryDelay": 3600
    })
}
fn keyring(controllers: Vec<Value>, slots: Vec<Value>, threshold: u64, recover: u64) -> Value {
    let mut c = controllers;
    c.sort_by_key(controller_id);
    json!({
        "controllers": c, "threshold": threshold, "recoverThreshold": recover,
        "addThreshold": 1, "countBy": "keys", "policy": policy(),
        "vault": {"signing": b64(&key(0x60).point), "agreement": b64(&key(0x61).point)},
        "slots": slots,
    })
}

struct Chain {
    objects: Objects,
    now: i64,
}
impl Chain {
    fn state(&self) -> State {
        let v = verify_history(&self.objects, &Persisted::default(), self.now);
        assert!(v.stop.is_none(), "history stops: {:?}", v.stop);
        v.state.unwrap()
    }
    fn run(&mut self, host: &Host, batch: PendingBatch) {
        let sigs = host.sign(batch.steps());
        let r = batch.finish(sigs).unwrap_or_else(|e| panic!("finish: {e}"));
        self.objects.entries.extend(r.entries.iter().map(|(_, b)| b.clone()));
        self.objects.pending.extend(r.pending.iter().cloned());
    }
    fn signed(&mut self, host: &Host, kind: Kind, issued: i64, signer: &Key) {
        let batch = prepare_signed(&self.objects, self.now, kind, issued, std::slice::from_ref(&signer.id)).unwrap();
        self.run(host, batch);
    }
}

fn request(account: &str, m: &Key, magree: &Key, terms: Value) -> Vec<u8> {
    let body = json!({
        "protocol": "colophon/request/5", "account": account,
        "member": {"signing": b64(&m.point), "agreement": b64(&magree.point)},
        "label": "Kitchen iPad", "kind": "device", "terms": terms, "created": "2026-11-11T07:59:00Z",
    });
    let body = canonical(&body).unwrap();
    canonical(&json!({"body": b64(&body), "signature": b64(&m.sign_raw(&body))})).unwrap()
}

#[test]
fn the_session_view_follows_a_verified_history() {
    let (a, ag, b) = (key(1), key(2), key(3));
    let mut host = Host::default();
    host.add(&a);
    host.add(&b);
    let kr = keyring(
        vec![raw_controller(&a, &ag, "A", &["approve", "control", "recover"]), raw_controller(&b, &key(4), "B", &["control"])],
        vec![slot_for(&a.id, "A"), slot_for(&b.id, "B")],
        1,
        1,
    );
    let mut chain = Chain { objects: Objects::default(), now: T0 + 3_600 * SEC };
    let batch = prepare_genesis(
        &GenesisParams {
            label: "Library".into(),
            namespaces: vec!["listening.podcasts".into()],
            keyring: kr,
            issued_ms: T0,
            signers: vec![a.id.clone()],
        },
        chain.now,
    )
    .unwrap();
    chain.run(&host, batch);
    let epoch = json!({"namespace": "listening.podcasts", "epoch": 1,
        "seals": {a.id.clone(): {"enc": b64(&key(0x70).point), "ciphertext": b64(&[3u8; 48])}}});
    chain.signed(&host, Kind::Rekey { epochs: vec![epoch] }, T0 + SEC, &a);
    let account = AccountId::parse(chain.state().account().as_str()).unwrap();
    let (m, magree) = (key(20), key(21));
    let (r, ragree) = (key(22), key(23));
    host.add(&m);
    for (k, ka, access) in [(&m, &magree, "write"), (&r, &ragree, "read")] {
        let terms = json!({"records": [{"namespace": "listening.podcasts", "access": access}]});
        let req = request(account.as_str(), k, ka, terms.clone());
        let share = json!({"namespace": "listening.podcasts", "epoch": 1,
            "seals": {k.id.clone(): {"enc": b64(&key(0x71).point), "ciphertext": b64(&[5u8; 48])}}});
        chain.signed(&host, Kind::Grant { request: req, terms, shares: vec![share] }, T0 + 2 * SEC, &a);
    }
    let view = |chain: &Chain| SessionAccount::from_history_state(&account, &chain.state(), chain.now);
    let v = view(&chain);
    assert_eq!(v.account(), account.as_str());
    assert_eq!(v.access(&m.id, "listening.podcasts", chain.now), Some(Access::Write));
    assert_eq!(v.access(&r.id, "listening.podcasts", chain.now), Some(Access::Read));
    assert_eq!(v.access(&m.id, "notes", chain.now), None);
    assert_eq!(v.member(&m.id).unwrap().session, 0);
    assert_eq!(v.member(&m.id).unwrap().signing, m.point);
    assert_eq!(v.writers("listening.podcasts", chain.now), vec![m.id.clone()]);
    assert!(v.member(&a.id).is_none(), "a controller is not a member");
    // Sessions ended twice: once by a controller, once by the member.
    chain.signed(&host, Kind::EndSessions { member: m.id.clone() }, T0 + 3 * SEC, &a);
    let batch = prepare_end_sessions_by_member(&chain.objects, chain.now, &m.id, T0 + 4 * SEC).unwrap();
    chain.run(&host, batch);
    assert_eq!(view(&chain).member(&m.id).unwrap().session, 2);
    // Revoked: gone from the view, and so from the writers.
    let seal = |id: &str| (id.to_owned(), json!({"enc": b64(&key(0x72).point), "ciphertext": b64(&[6u8; 48])}));
    let seals: serde_json::Map<String, Value> = [seal(&a.id), seal(&r.id)].into_iter().collect();
    let epoch2 = json!({"namespace": "listening.podcasts", "epoch": 2, "seals": seals});
    chain.signed(&host, Kind::Revoke { member: m.id.clone(), kept: vec![], heads: vec![], epochs: vec![epoch2] }, T0 + 5 * SEC, &a);
    let v = view(&chain);
    assert!(v.member(&m.id).is_none());
    assert!(v.writers("listening.podcasts", chain.now).is_empty());
    assert_eq!(v.access(&r.id, "listening.podcasts", chain.now), Some(Access::Read));
}
