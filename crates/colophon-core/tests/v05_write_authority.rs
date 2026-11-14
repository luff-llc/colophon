//! Tests of the 0.5 authority builders (`v05::write::authority`): each entry kind builds
//! through prepare and finish and verifies; signatures that don't meet the rule return nothing;
//! and the builders reproduce the candidate vectors' entry bytes from their published keys.
//!
//! The signing here is the host's side of the interface: it holds the scalars and signs the
//! exact bodies the steps carry. Nothing in this file shares encoding code with the vector
//! generator (`tests/v5_candidate/`).
#![allow(clippy::unwrap_used)]
use base64::{engine::general_purpose::STANDARD, Engine};
use colophon_core::v05::encoding::{canonical, digest, parse_date};
use colophon_core::v05::history::{verify_history, Objects, Persisted, State};
use colophon_core::v05::ids::key_id;
use colophon_core::v05::write::authority::*;
use colophon_core::v05::write::*;
use colophon_core::v05::Failure;
use p256::ecdsa::{signature::Signer, Signature as P256Signature, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::PathBuf;

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

struct Fixture {
    a: Key,
    b: Key,
    host: Host,
}
/// A (approve, control, recover) and B (control), both with slots, threshold 1.
fn fixture() -> Fixture {
    let (a, b) = (key(1), key(3));
    let mut host = Host::default();
    host.add(&a);
    host.add(&b);
    Fixture { a, b, host }
}
fn fixture_keyring(f: &Fixture) -> Value {
    keyring(
        vec![
            raw_controller(&f.a, &key(2), "A", &["approve", "control", "recover"]),
            raw_controller(&f.b, &key(4), "B", &["control"]),
        ],
        vec![slot_for(&f.a.id, "A"), slot_for(&f.b.id, "B")],
        1,
        1,
    )
}

/// An account under construction: the held objects and the clock.
struct Chain {
    objects: Objects,
    now: i64,
}
impl Chain {
    fn new(now: i64) -> Self {
        Self {
            objects: Objects::default(),
            now,
        }
    }
    fn verdict(&self) -> colophon_core::v05::history::Verdict {
        verify_history(&self.objects, &Persisted::default(), self.now)
    }
    fn state(&self) -> State {
        let v = self.verdict();
        assert!(v.stop.is_none(), "history stops: {:?}", v.stop);
        v.state.unwrap()
    }
    /// The account ID from the first held entry, even when the history forks.
    fn account_of_genesis(&self) -> String {
        body_digest_of_env(&self.objects.entries[0])
    }
    fn account(&self) -> String {
        self.state().account().as_str().to_string()
    }
    fn seq(&self) -> u64 {
        self.state().history().len() as u64
    }
    /// Finish a batch with the host's signatures and hold what it returns.
    fn run(&mut self, host: &Host, batch: PendingBatch) -> Records {
        let sigs = host.sign(batch.steps());
        let r = batch.finish(sigs).unwrap_or_else(|e| panic!("finish: {e}"));
        self.hold(&r);
        r
    }
    fn hold(&mut self, r: &Records) {
        self.objects
            .entries
            .extend(r.entries.iter().map(|(_, b)| b.clone()));
        self.objects.pending.extend(r.pending.iter().cloned());
    }
    fn genesis(&mut self, host: &Host, label: &str, ns: &[&str], kr: Value, signers: &[String]) {
        let batch = prepare_genesis(
            &GenesisParams {
                label: label.into(),
                namespaces: ns.iter().map(|s| s.to_string()).collect(),
                keyring: kr,
                issued_ms: T0,
                signers: signers.to_vec(),
            },
            self.now,
        )
        .unwrap();
        self.run(host, batch);
    }
    fn signed(&mut self, host: &Host, kind: Kind, issued: i64, signers: &[&Key]) -> Records {
        let ids: Vec<String> = signers.iter().map(|k| k.id.clone()).collect();
        let batch = prepare_signed(&self.objects, self.now, kind, issued, &ids).unwrap();
        self.run(host, batch)
    }
}

/// A membership request (§9.1), signed raw by the member's signing key.
fn request(account: &str, m: &Key, magree: &Key, label: &str, kind: &str, terms: Value) -> Vec<u8> {
    let mut body = json!({
        "protocol": "colophon/request/5", "account": account,
        "member": {"signing": b64(&m.point), "agreement": b64(&magree.point)},
        "label": label, "kind": kind, "terms": terms, "created": "2026-11-11T07:59:00Z",
    });
    if kind == "server" {
        body["service"] =
            json!({"endpoints": [format!("https://home.example/v1/accounts/{account}")]});
    }
    let body = canonical(&body).unwrap();
    canonical(&json!({"body": b64(&body), "signature": b64(&m.sign_raw(&body))})).unwrap()
}
fn agent_terms() -> Value {
    json!({"services": [{"audience": "https://projects.example/scopes/7", "purposes": ["task.read"]}]})
}
fn granted_terms(expires: &str) -> Value {
    json!({"services": [{"audience": "https://projects.example/scopes/7", "purposes": ["task.read"]}],
           "expires": expires, "depth": 1})
}
fn home_terms() -> Value {
    json!({"serves": ["home"]})
}

/// A home's receipt (§13.5) of an object, signed raw by the home.
fn receipt(account: &str, home: &Key, object: &str, received_ms: i64) -> Vec<u8> {
    let body = canonical(&json!({
        "protocol": "colophon/receipt/5", "account": account, "object": object,
        "received": format_date(received_ms), "by": home.id,
    }))
    .unwrap();
    canonical(&json!({"body": b64(&body), "signature": b64(&home.sign_raw(&body))})).unwrap()
}
/// A home's head (§13.2) over a seq and digest.
fn head(account: &str, home: &Key, seq: u64, dg: &str, issued_ms: i64) -> Vec<u8> {
    let body = canonical(&json!({
        "protocol": "colophon/head/5", "account": account,
        "authority": {"seq": seq, "digest": dg}, "by": home.id, "issued": format_date(issued_ms),
    }))
    .unwrap();
    canonical(&json!({"body": b64(&body), "signature": b64(&home.sign_raw(&body))})).unwrap()
}
fn body_digest_of_env(env: &[u8]) -> String {
    let v: Value = serde_json::from_slice(env).unwrap();
    digest(&STANDARD.decode(v["body"].as_str().unwrap()).unwrap())
}

// ---------------------------------------------------------------------------------------------
// Genesis.

#[test]
fn genesis_single_signer_verifies() {
    let f = fixture();
    let mut chain = Chain::new(T0 + 60 * SEC);
    let ids = vec![f.a.id.clone()];
    // B's possession proof is needed too: B is a controller other than `by`.
    let batch = prepare_genesis(
        &GenesisParams {
            label: "Test".into(),
            namespaces: vec![],
            keyring: fixture_keyring(&f),
            issued_ms: T0,
            signers: ids,
        },
        chain.now,
    )
    .unwrap();
    let roles: Vec<_> = batch
        .steps()
        .iter()
        .map(|s| (s.signer().to_string(), s.role()))
        .collect();
    assert_eq!(roles[0], (f.a.id.clone(), StepRole::Primary));
    assert!(roles.contains(&(f.b.id.clone(), StepRole::Possession)));
    assert!(batch.steps().iter().all(|s| s.challenge().is_none()));
    chain.run(&f.host, batch);
    let st = chain.state();
    assert_eq!(st.history().len(), 1);
    assert_eq!(st.keyring().controllers.len(), 2);
}

#[test]
fn genesis_refuses_signers_below_the_control_rule() {
    let f = fixture();
    // Threshold 2 over two control keys; one signer cannot meet it.
    let kr = keyring(
        vec![
            raw_controller(&f.a, &key(2), "A", &["approve", "control", "recover"]),
            raw_controller(&f.b, &key(4), "B", &["control"]),
        ],
        vec![slot_for(&f.a.id, "A")],
        2,
        1,
    );
    let r = prepare_genesis(
        &GenesisParams {
            label: "x".into(),
            namespaces: vec![],
            keyring: kr.clone(),
            issued_ms: T0,
            signers: vec![f.a.id.clone()],
        },
        T0,
    );
    assert!(matches!(r, Err(Failure::BadSignature(_))));
    // Both sign: accepted.
    let mut chain = Chain::new(T0 + 60 * SEC);
    chain.genesis(&f.host, "x", &[], kr, &[f.a.id.clone(), f.b.id.clone()]);
    assert_eq!(chain.state().history().len(), 1);
}

#[test]
fn genesis_with_a_webauthn_signer_carries_an_assertion() {
    let f = fixture();
    let w = key(9);
    let mut host = Host::default();
    host.add(&w);
    let kr = keyring(
        vec![passkey_controller(
            &w,
            "Passkey",
            &["approve", "control", "recover"],
        )],
        vec![
            json!({"kind": "prf", "controllers": [w.id], "label": "Passkey",
                    "salt": b64(&[1u8; 32]), "box": b64(&[2u8; 60])}),
        ],
        1,
        1,
    );
    let batch = prepare_genesis(
        &GenesisParams {
            label: "Passkey account".into(),
            namespaces: vec![],
            keyring: kr,
            issued_ms: T0,
            signers: vec![w.id.clone()],
        },
        T0 + 60 * SEC,
    )
    .unwrap();
    let step = &batch.steps()[0];
    assert!(step.uv());
    assert_eq!(
        step.challenge(),
        Some(colophon_core::v05::signature::challenge(step.body()).as_str())
    );
    let sigs = host.sign(batch.steps());
    assert!(sigs[0].assertion.is_some());
    let r = batch.finish(sigs).unwrap();
    assert_eq!(r.entries.len(), 1);
    let _ = f;
}

#[test]
fn a_bad_signature_returns_nothing() {
    let f = fixture();
    let batch = prepare_genesis(
        &GenesisParams {
            label: "x".into(),
            namespaces: vec![],
            keyring: fixture_keyring(&f),
            issued_ms: T0,
            signers: vec![f.a.id.clone()],
        },
        T0 + 60 * SEC,
    )
    .unwrap();
    let mut sigs = f.host.sign(batch.steps());
    sigs[0].signature[10] ^= 1;
    assert!(matches!(batch.finish(sigs), Err(Failure::BadSignature(_))));
}

// ---------------------------------------------------------------------------------------------
// The immediate entries.

#[test]
fn immediate_entries_each_verify() {
    let f = fixture();
    let mut chain = Chain::new(T0 + 3_600 * SEC);
    chain.genesis(
        &f.host,
        "Identity",
        &[],
        fixture_keyring(&f),
        std::slice::from_ref(&f.a.id),
    );
    let account = chain.account();
    let (m, magree) = (key(20), key(21));
    let mut host = Host::default();
    host.keys = f.host.keys.clone();
    host.add(&m);

    // grant
    let req = request(&account, &m, &magree, "Agent", "agent", agent_terms());
    chain.signed(
        &host,
        Kind::Grant {
            request: req,
            terms: granted_terms("2026-11-18T08:00:00Z"),
            shares: vec![],
        },
        T0 + SEC,
        &[&f.a],
    );
    // renew
    chain.signed(
        &host,
        Kind::Renew {
            member: m.id.clone(),
            expires: "2026-11-25T08:00:00Z".into(),
            shares: vec![],
        },
        T0 + 2 * SEC,
        &[&f.a],
    );
    // endSessions by a controller under the single rule
    chain.signed(
        &host,
        Kind::EndSessions {
            member: m.id.clone(),
        },
        T0 + 3 * SEC,
        &[&f.a],
    );
    // endSessions by the member itself (raw, one signer)
    let batch =
        prepare_end_sessions_by_member(&chain.objects, chain.now, &m.id, T0 + 4 * SEC).unwrap();
    assert_eq!(batch.steps().len(), 1);
    assert_eq!(batch.steps()[0].signer(), m.id);
    chain.run(&host, batch);
    // keyring: add an approve controller C (possession proof by C, signed by A)
    let c = key(30);
    host.add(&c);
    let mut kr = chain.state().keyring().raw.clone();
    let mut ctrls = kr["controllers"].as_array().unwrap().clone();
    ctrls.push(raw_controller(&c, &key(31), "C", &["approve"]));
    ctrls.sort_by_key(controller_id);
    kr["controllers"] = Value::Array(ctrls);
    let mut slots = kr["slots"].as_array().unwrap().clone();
    slots.push(slot_for(&c.id, "C"));
    kr["slots"] = Value::Array(slots);
    let batch = prepare_signed(
        &chain.objects,
        chain.now,
        Kind::Keyring { keyring: kr },
        T0 + 5 * SEC,
        std::slice::from_ref(&f.a.id),
    )
    .unwrap();
    assert!(batch
        .steps()
        .iter()
        .any(|s| s.signer() == c.id && s.role() == StepRole::Possession));
    chain.run(&host, batch);
    // revoke
    chain.signed(
        &host,
        Kind::Revoke {
            member: m.id.clone(),
            kept: vec![],
            heads: vec![],
            epochs: vec![],
        },
        T0 + 6 * SEC,
        &[&f.a],
    );
    let st = chain.state();
    assert_eq!(st.history().len(), 7);
    assert!(st.keyring().controllers.contains_key(&c.id));
    let mem = &st.members()[0];
    assert_eq!(mem.revoked_seq, Some(7));
    assert_eq!(mem.end_sessions, vec![4, 5]);
    assert_eq!(mem.renewals.len(), 1);
}

#[test]
fn entries_the_signers_cannot_make_are_refused_at_prepare() {
    let f = fixture();
    let mut chain = Chain::new(T0 + 3_600 * SEC);
    chain.genesis(
        &f.host,
        "Identity",
        &[],
        fixture_keyring(&f),
        std::slice::from_ref(&f.a.id),
    );
    let account = chain.account();
    let (m, magree) = (key(20), key(21));
    let req = request(&account, &m, &magree, "Agent", "agent", agent_terms());
    let grant = Kind::Grant {
        request: req,
        terms: granted_terms("2026-11-18T08:00:00Z"),
        shares: vec![],
    };
    // B holds control, not approve: the single rule is not met.
    let r = prepare_signed(
        &chain.objects,
        chain.now,
        grant.clone(),
        T0 + SEC,
        std::slice::from_ref(&f.b.id),
    );
    assert!(matches!(r, Err(Failure::BadSignature(_))));
    // Two signers are not "exactly one signer holding approve".
    let r = prepare_signed(
        &chain.objects,
        chain.now,
        grant.clone(),
        T0 + SEC,
        &[f.a.id.clone(), f.b.id.clone()],
    );
    assert!(matches!(r, Err(Failure::BadSignature(_))));
    // A foreign key is not a signer.
    let r = prepare_signed(
        &chain.objects,
        chain.now,
        grant.clone(),
        T0 + SEC,
        &[key(99).id],
    );
    assert!(matches!(r, Err(Failure::BadSignature(_))));
    // A vault entry while the vault is not retiring.
    let r = prepare_signed(
        &chain.objects,
        chain.now,
        Kind::Vault {
            vault: json!({"signing": b64(&key(0x62).point), "agreement": b64(&key(0x63).point)}),
            slots: vec![slot_for(&f.a.id, "A")],
            previous_vault: json!({"enc": b64(&key(0x70).point), "ciphertext": b64(&[1u8; 48])}),
        },
        T0 + SEC,
        std::slice::from_ref(&f.a.id),
    );
    assert!(matches!(r, Err(Failure::BadSignature(_))));
    // A rule the signers meet but a body the verifier refuses: finish returns nothing.
    let bad = Kind::Rekey {
        epochs: vec![json!({"namespace": "undeclared", "epoch": 1, "seals": {}})],
    };
    let batch = prepare_signed(
        &chain.objects,
        chain.now,
        bad,
        T0 + SEC,
        std::slice::from_ref(&f.a.id),
    )
    .unwrap();
    let sigs = f.host.sign(batch.steps());
    assert!(matches!(batch.finish(sigs), Err(Failure::Malformed(_))));
    // issued earlier than the preceding entry is refused up front.
    let r = prepare_signed(
        &chain.objects,
        chain.now,
        grant,
        T0 - SEC,
        std::slice::from_ref(&f.a.id),
    );
    assert!(matches!(r, Err(Failure::Malformed(_))));
}

#[test]
fn seq_two_is_a_rekey_when_namespaces_are_declared() {
    let f = fixture();
    let mut chain = Chain::new(T0 + 3_600 * SEC);
    chain.genesis(
        &f.host,
        "Notes",
        &["notes"],
        fixture_keyring(&f),
        std::slice::from_ref(&f.a.id),
    );
    // A grant at seq 2 is refused by the verifier: finish returns nothing.
    let account = chain.account();
    let (m, magree) = (key(20), key(21));
    let req = request(&account, &m, &magree, "Agent", "agent", agent_terms());
    let batch = prepare_signed(
        &chain.objects,
        chain.now,
        Kind::Grant {
            request: req,
            terms: granted_terms("2026-11-18T08:00:00Z"),
            shares: vec![],
        },
        T0 + SEC,
        std::slice::from_ref(&f.a.id),
    )
    .unwrap();
    let sigs = f.host.sign(batch.steps());
    assert!(batch.finish(sigs).is_err());
    // The rekey introducing epoch 1 is accepted. Seals are opaque values from package E4.
    let epoch = json!({"namespace": "notes", "epoch": 1,
        "seals": {f.a.id.clone(): {"enc": b64(&key(0x70).point), "ciphertext": b64(&[3u8; 48])}}});
    chain.signed(
        &f.host,
        Kind::Rekey {
            epochs: vec![epoch],
        },
        T0 + SEC,
        &[&f.a],
    );
    assert_eq!(chain.seq(), 2);
}

// ---------------------------------------------------------------------------------------------
// Transitions, vault rotation, homes, vetoes, suspend, activation and finality.

fn transition_params(
    _chain: &Chain,
    issued: i64,
    signers: &[&Key],
    change: Value,
) -> TransitionParams {
    TransitionParams {
        anchor: None,
        issued_ms: issued,
        signers: signers.iter().map(|k| k.id.clone()).collect(),
        rule: TransitionRule::Control,
        change,
    }
}

#[test]
fn genesis_and_keyring_builders_validate_slots_with_the_slot_module() {
    let f = fixture();
    // A slot the verifier's own keyring check lets through but E2's validation refuses: a
    // sealed box of the wrong length.
    let mut short = slot_for(&f.a.id, "A");
    short["sealed"]["ciphertext"] = json!(b64(&[7u8; 47]));
    let kr = keyring(
        vec![
            raw_controller(&f.a, &key(2), "A", &["approve", "control", "recover"]),
            raw_controller(&f.b, &key(4), "B", &["control"]),
        ],
        vec![short.clone()],
        1,
        1,
    );
    let r = prepare_genesis(
        &GenesisParams {
            label: "x".into(),
            namespaces: vec![],
            keyring: kr,
            issued_ms: T0,
            signers: vec![f.a.id.clone()],
        },
        T0,
    );
    assert!(matches!(r, Err(Failure::Malformed(_))), "{r:?}");
    // The same on a keyring entry that adds a slot.
    let mut chain = Chain::new(T0 + 3_600 * SEC);
    chain.genesis(
        &f.host,
        "Slots",
        &[],
        fixture_keyring(&f),
        std::slice::from_ref(&f.a.id),
    );
    let mut kr = chain.state().keyring().raw.clone();
    let mut slots = kr["slots"].as_array().unwrap().clone();
    let mut bad = slot_for(&f.b.id, "B2");
    bad["sealed"]["ciphertext"] = json!(b64(&[7u8; 47]));
    slots.push(bad);
    kr["slots"] = Value::Array(slots);
    let r = prepare_signed(
        &chain.objects,
        chain.now,
        Kind::Keyring { keyring: kr },
        T0 + SEC,
        std::slice::from_ref(&f.a.id),
    );
    assert!(matches!(r, Err(Failure::Malformed(_))), "{r:?}");
}

#[test]
fn removing_a_slotted_key_retires_the_vault_and_a_vault_entry_ends_it() {
    let f = fixture();
    let mut chain = Chain::new(T0 + 3_600 * SEC);
    chain.genesis(
        &f.host,
        "Vault",
        &[],
        fixture_keyring(&f),
        std::slice::from_ref(&f.a.id),
    );
    // No home: no delay, no veto. A removes B (a slotted key) by the control rule.
    let change = json!({"keyring": {"remove": [f.b.id]}});
    let batch = prepare_transition(
        &chain.objects,
        chain.now,
        &transition_params(&chain, T0 + 10 * SEC, &[&f.a], change),
    )
    .unwrap();
    let r = chain.run(&f.host, batch);
    assert_eq!(r.pending.len(), 1);
    let t_digest = body_digest_of_env(&r.pending[0]);
    let act = prepare_activate(&chain.objects, chain.now, &t_digest).unwrap();
    assert!(
        act.steps().is_empty(),
        "a recording entry needs no signature"
    );
    chain.run(&f.host, act);
    let st = chain.state();
    assert!(st.vault_retiring());
    assert_eq!(st.keyring().controllers.len(), 1);
    // A, holding the seed, rotates the vault.
    chain.signed(
        &f.host,
        Kind::Vault {
            vault: json!({"signing": b64(&key(0x62).point), "agreement": b64(&key(0x63).point)}),
            slots: vec![slot_for(&f.a.id, "A")],
            previous_vault: json!({"enc": b64(&key(0x70).point), "ciphertext": b64(&[1u8; 48])}),
        },
        T0 + 3_600 * SEC,
        &[&f.a],
    );
    assert!(!chain.state().vault_retiring());
}

#[test]
fn activate_before_its_due_time_is_held() {
    let f = fixture();
    let mut chain = Chain::new(T0 + 3_600 * SEC);
    chain.genesis(
        &f.host,
        "Held",
        &[],
        fixture_keyring(&f),
        std::slice::from_ref(&f.a.id),
    );
    // `issued` is 60 s in the future of the clock but within the allowed 60 s skew.
    let change = json!({"keyring": {"remove": [f.b.id]}});
    let issued = chain.now + 30 * SEC;
    let batch = prepare_transition(
        &chain.objects,
        chain.now,
        &transition_params(&chain, issued, &[&f.a], change),
    )
    .unwrap();
    let r = chain.run(&f.host, batch);
    let t = body_digest_of_env(&r.pending[0]);
    let early = prepare_activate(&chain.objects, chain.now, &t);
    assert!(matches!(early, Err(Failure::Unavailable(_))), "{early:?}");
    let ok = prepare_activate(&chain.objects, issued + SEC, &t).unwrap();
    let rec = ok.finish(vec![]).unwrap();
    assert_eq!(rec.entries[0].0, 2);
}

#[test]
fn a_transition_the_signers_cannot_propose_is_refused() {
    let f = fixture();
    let mut chain = Chain::new(T0 + 3_600 * SEC);
    chain.genesis(
        &f.host,
        "Rules",
        &[],
        fixture_keyring(&f),
        std::slice::from_ref(&f.a.id),
    );
    let change = json!({"keyring": {"remove": [f.b.id]}});
    // B holds no recover role: it cannot meet the recovery rule.
    let mut p = transition_params(&chain, T0 + SEC, &[&f.b], change.clone());
    p.rule = TransitionRule::Recovery;
    assert!(matches!(
        prepare_transition(&chain.objects, chain.now, &p),
        Err(Failure::BadSignature(_))
    ));
    // A wrong anchor.
    let mut p = transition_params(&chain, T0 + SEC, &[&f.a], change.clone());
    p.anchor = Some((1, "0".repeat(64)));
    assert!(prepare_transition(&chain.objects, chain.now, &p).is_err());
    // Removing every controller would be void at activation (§6, §8.7 "Delta at
    // activation"): finish runs the admission delta check, so nothing is returned.
    let change = json!({"keyring": {"remove": [f.a.id, f.b.id]}});
    let p = transition_params(&chain, T0 + SEC, &[&f.a], change);
    let batch = prepare_transition(&chain.objects, chain.now, &p).unwrap();
    let sigs = f.host.sign(batch.steps());
    match batch.finish(sigs) {
        Err(Failure::Malformed(m)) => assert!(m.contains("void"), "{m}"),
        other => panic!("a void transition must return nothing: {other:?}"),
    }
}

#[test]
fn prepare_refuses_a_transition_lacking_consent_escalation_or_the_right_rule() {
    let f = fixture();
    let mut chain = Chain::new(T0 + 3_600 * SEC);
    chain.genesis(
        &f.host,
        "Consent",
        &[],
        fixture_keyring(&f),
        std::slice::from_ref(&f.a.id),
    );
    // B (control, no recover) alone changing recoveryDelay: the verifier needs recovery-set
    // consent, so a host is never asked to sign it.
    let p = transition_params(
        &chain,
        T0 + SEC,
        &[&f.b],
        json!({"policy": {"recoveryDelay": 7200}}),
    );
    assert!(matches!(
        prepare_transition(&chain.objects, chain.now, &p),
        Err(Failure::BadSignature(_))
    ));
    // A holds recover: consent is met, and the change verifies.
    let p = transition_params(
        &chain,
        T0 + SEC,
        &[&f.a],
        json!({"policy": {"recoveryDelay": 7200}}),
    );
    let batch = prepare_transition(&chain.objects, chain.now, &p).unwrap();
    let sigs = f.host.sign(batch.steps());
    assert_eq!(batch.finish(sigs).unwrap().pending.len(), 1);
    // `keep` needs the recovery rule: under the control rule it is refused up front.
    let p = transition_params(
        &chain,
        T0 + SEC,
        &[&f.a],
        json!({"keyring": {"remove": [f.b.id], "keep": []}}),
    );
    assert!(matches!(
        prepare_transition(&chain.objects, chain.now, &p),
        Err(Failure::BadSignature(_))
    ));
    // Under the recovery rule a policy change is not open.
    let mut p = transition_params(
        &chain,
        T0 + SEC,
        &[&f.a],
        json!({"policy": {"callWindow": 600}}),
    );
    p.rule = TransitionRule::Recovery;
    assert!(matches!(
        prepare_transition(&chain.objects, chain.now, &p),
        Err(Failure::BadSignature(_))
    ));
}

/// An account with A and B and a home H appointed by an activated transition.
fn account_with_home(f: &Fixture) -> (Chain, Key, Host) {
    let mut chain = Chain::new(T0 + 10 * 86_400 * SEC);
    chain.genesis(
        &f.host,
        "Home",
        &[],
        fixture_keyring(f),
        std::slice::from_ref(&f.a.id),
    );
    let account = chain.account();
    let h = key(40);
    let hagree = key(41);
    let mut host = Host::default();
    host.keys = f.host.keys.clone();
    host.add(&h);
    let req = request(&account, &h, &hagree, "Home", "server", home_terms());
    let change = json!({"homes": {"appoint": [{
        "request": b64(&req), "terms": home_terms()}]}});
    let batch = prepare_transition(
        &chain.objects,
        chain.now,
        &transition_params(&chain, T0 + 10 * SEC, &[&f.a], change),
    )
    .unwrap();
    let r = chain.run(&host, batch);
    let t = body_digest_of_env(&r.pending[0]);
    let act = prepare_activate(&chain.objects, chain.now, &t).unwrap();
    chain.run(&host, act);
    assert_eq!(chain.state().current_homes().len(), 1);
    (chain, h, host)
}

#[test]
fn home_appointment_transition_and_activation_verify() {
    let f = fixture();
    let (chain, h, _) = account_with_home(&f);
    assert_eq!(chain.seq(), 2);
    assert_eq!(chain.state().current_homes()[0].request.member_id(), h.id);
}

#[test]
fn veto_suspend_vetoed_activate_and_final_verify() {
    let f = fixture();
    let (mut chain, h, host) = account_with_home(&f);
    let account = chain.account();
    // T2: A proposes removing B. The home receipts it.
    let t2_issued = T0 + 100 * SEC;
    let batch = prepare_transition(
        &chain.objects,
        chain.now,
        &transition_params(
            &chain,
            t2_issued,
            &[&f.a],
            json!({"keyring": {"remove": [f.b.id]}}),
        ),
    )
    .unwrap();
    let r = chain.run(&host, batch);
    let t2 = r.pending[0].clone();
    let t2_digest = body_digest_of_env(&t2);
    let r2 = receipt(&account, &h, &t2_digest, t2_issued + 10 * SEC);
    chain.objects.pending.push(r2.clone());

    // Before its due time it can't be activated.
    assert!(prepare_activate(&chain.objects, t2_issued + 60 * SEC, &t2_digest).is_err());

    // A suspends B while T2 is pending.
    chain.signed_suspend(&host, &f, &t2_digest, t2_issued + 20 * SEC);
    let during = t2_issued + 60 * SEC;
    assert_eq!(chain.state().active_suspensions(during).len(), 1);

    // B (suspended, but a suspended key may veto) vetoes. The home receipts the veto.
    let v_issued = t2_issued + 30 * SEC;
    let batch = prepare_veto(
        &chain.objects,
        chain.now,
        &VetoParams {
            transition: t2.clone(),
            transition_receipts: vec![r2.clone()],
            issued_ms: v_issued,
            signers: vec![f.b.id.clone()],
        },
    )
    .unwrap();
    let r = chain.run(&host, batch);
    let veto = r.pending[0].clone();
    let v_digest = body_digest_of_env(&veto);
    chain
        .objects
        .pending
        .push(receipt(&account, &h, &v_digest, v_issued + 5 * SEC));

    // The home builds the `vetoed`; the suspension ends with it.
    let batch = prepare_vetoed(&chain.objects, chain.now, &t2_digest, &v_digest).unwrap();
    assert!(batch.steps().is_empty());
    chain.run(&host, batch);
    let st = chain.state();
    assert!(st.active_suspensions(during).is_empty());
    assert_eq!(st.veto_counts().get(&f.a.id), Some(&1));

    // Escalation: A now needs two units. A and B propose a policy change; due after the delay.
    let t3_issued = T0 + 200 * SEC;
    let batch = prepare_transition(
        &chain.objects,
        chain.now,
        &transition_params(
            &chain,
            t3_issued,
            &[&f.a, &f.b],
            json!({"policy": {"callWindow": 600}}),
        ),
    )
    .unwrap();
    let r = chain.run(&host, batch);
    let t3_digest = body_digest_of_env(&r.pending[0]);
    chain
        .objects
        .pending
        .push(receipt(&account, &h, &t3_digest, t3_issued + 10 * SEC));
    let act = prepare_activate(&chain.objects, chain.now, &t3_digest).unwrap();
    let rec = act.finish(vec![]).unwrap();
    chain.hold(&rec);
    let st = chain.state();
    let a = st.activations().last().unwrap().clone();
    assert!(
        !a.final_,
        "the home is a witness: provisional until a final"
    );
    assert!(a.witnesses.contains(&h.id));

    // The home's head over the activation; the `final` records it.
    chain
        .objects
        .heads
        .push(head(&account, &h, a.seq, &a.digest, T0 + 5_000 * SEC));
    let fin = prepare_final(&chain.objects, chain.now, a.seq).unwrap();
    chain.run(&host, fin);
    let st = chain.state();
    assert!(st.activations().last().unwrap().final_);

    // The honest home must not be convicted: H receipted the veto of T2, which was recorded as
    // `vetoed`, and signed the head for the `final` of T3, a different transition.
    let final_entry = chain.objects.entries.last().unwrap().clone();
    let activation = rec.entries[0].1.clone();
    let rcpt = receipt(&account, &h, &v_digest, v_issued + 5 * SEC);
    let ctx = EvidenceContext {
        objects: &chain.objects,
        now_ms: chain.now,
    };
    assert!(
        equivocation_of_veto(&account, &activation, &veto, &rcpt, &final_entry, &ctx).is_err(),
        "a veto of T2 and the final of T3 convict nobody"
    );
}

impl Chain {
    fn signed_suspend(&mut self, host: &Host, f: &Fixture, t: &str, issued: i64) {
        let batch = prepare_suspend(&self.objects, self.now, &f.b.id, t, issued, &f.a.id).unwrap();
        self.run(host, batch);
    }
}

#[test]
fn receipts_are_chosen_by_lowest_home_then_lowest_digest() {
    let f = fixture();
    let (chain, h, _) = account_with_home(&f);
    let st = chain.state();
    let account = chain.account();
    let object = "a".repeat(64);
    let issued = T0 + 100 * SEC;
    // Two valid receipts by the one home; the lower body digest is chosen, in either order.
    let r1 = receipt(&account, &h, &object, issued + 10 * SEC);
    let r2 = receipt(&account, &h, &object, issued + 20 * SEC);
    let want = if body_digest_of_env(&r1) < body_digest_of_env(&r2) {
        r1.clone()
    } else {
        r2.clone()
    };
    let a = choose_receipts(&st, &[r1.clone(), r2.clone()], &object, issued, None).unwrap();
    let b = choose_receipts(&st, &[r2.clone(), r1.clone()], &object, issued, None).unwrap();
    assert_eq!(a, vec![want.clone()]);
    assert_eq!(a, b);
    // A receipt outside its window, by a stranger, or of another object does not count.
    let late = receipt(&account, &h, &object, issued + 301 * SEC);
    let stranger = receipt(&account, &key(55), &object, issued + 10 * SEC);
    let other = receipt(&account, &h, &"b".repeat(64), issued + 10 * SEC);
    let r = choose_receipts(&st, &[late, stranger, other], &object, issued, None);
    assert!(matches!(r, Err(Failure::Unavailable(_))));
}

// ---------------------------------------------------------------------------------------------
// Resolve and equivocation evidence.

fn two_grants_at_seq_two(f: &Fixture) -> (Chain, Host, Vec<Vec<u8>>) {
    let mut chain = Chain::new(T0 + 3_600 * SEC);
    chain.genesis(
        &f.host,
        "Fork",
        &[],
        fixture_keyring(f),
        std::slice::from_ref(&f.a.id),
    );
    let account = chain.account();
    let mut host = Host::default();
    host.keys = f.host.keys.clone();
    // Two different grants at seq 2 (no home: an unresolved fork).
    let mut branches = Vec::new();
    for n in [20u8, 22] {
        let (m, magree) = (key(n), key(n + 1));
        host.add(&m);
        let req = request(&account, &m, &magree, "Agent", "agent", agent_terms());
        let batch = prepare_signed(
            &chain.objects,
            chain.now,
            Kind::Grant {
                request: req,
                terms: granted_terms("2026-11-18T08:00:00Z"),
                shares: vec![],
            },
            T0 + SEC,
            std::slice::from_ref(&f.a.id),
        )
        .unwrap();
        let sigs = host.sign(batch.steps());
        let rec = batch.finish(sigs).unwrap();
        branches.push(rec.entries[0].1.clone());
    }
    chain.objects.entries.extend(branches.iter().cloned());
    assert_eq!(chain.verdict().code(), "refused:fork");
    (chain, host, branches)
}

#[test]
fn entries_evidence_is_built_from_two_valid_conflicting_entries() {
    let f = fixture();
    let (chain, _host, branches) = two_grants_at_seq_two(&f);
    let account = chain.account_of_genesis();
    let ctx = EvidenceContext {
        objects: &chain.objects,
        now_ms: chain.now,
    };
    let ev = equivocation_of_entries(&account, &branches[0], &branches[1], &ctx).unwrap();
    assert_eq!(
        verify_evidence(&ev, &account, &ctx).unwrap(),
        Evidence::Entries { seq: 2 }
    );
    assert_eq!(
        ev,
        equivocation_of_entries(&account, &branches[1], &branches[0], &ctx).unwrap()
    );
    assert!(equivocation_of_entries(&account, &branches[0], &branches[0], &ctx).is_err());
}

#[test]
fn entries_evidence_from_fabricated_entries_convicts_nobody() {
    // The checker's H2: two made-up envelopes with garbage signatures at one seq and previous.
    let f = fixture();
    let (chain, _host, _branches) = two_grants_at_seq_two(&f);
    let account = chain.account_of_genesis();
    let genesis_digest = body_digest_of_env(&chain.objects.entries[0]);
    let ctx = EvidenceContext {
        objects: &chain.objects,
        now_ms: chain.now,
    };
    let mk = |previous: &str, member: &str| {
        let b = canonical(&json!({"protocol": "colophon/authority/5", "seq": 2,
            "previous": previous, "issued": "2026-11-11T09:00:00Z", "by": f.a.id,
            "kind": "endSessions", "member": member}))
        .unwrap();
        canonical(&json!({"body": b64(&b), "signature": b64(&[1u8; 64])})).unwrap()
    };
    // Previous not held: unavailable, never a conviction.
    let (a, b) = (
        mk(&"33".repeat(32), &"55".repeat(16)),
        mk(&"33".repeat(32), &"66".repeat(16)),
    );
    assert!(matches!(
        equivocation_of_entries(&account, &a, &b, &ctx),
        Err(Failure::Unavailable(_))
    ));
    // Previous held, signatures garbage: badSignature.
    let (a, b) = (
        mk(&genesis_digest, &"55".repeat(16)),
        mk(&genesis_digest, &"66".repeat(16)),
    );
    assert!(matches!(
        equivocation_of_entries(&account, &a, &b, &ctx),
        Err(Failure::BadSignature(_))
    ));
}

#[test]
fn resolve_finish_returns_nothing_while_the_verifier_cannot_apply_it() {
    // Verifier gap (checker M3): `resolve` changes nothing under `apply_delta`, so it is void
    // at activation and admission refuses it. finish runs that admission check and returns
    // nothing. Not E1's to fix; this records the behaviour.
    let f = fixture();
    let (chain, host, branches) = two_grants_at_seq_two(&f);
    let (dx, dy) = (
        body_digest_of_env(&branches[0]),
        body_digest_of_env(&branches[1]),
    );
    let batch = prepare_resolve(
        &chain.objects,
        chain.now,
        (2, dx),
        (2, dy),
        T0 + 10 * SEC,
        vec![f.a.id.clone()],
        TransitionRule::Control,
    )
    .unwrap();
    assert!(
        batch.finish(vec![]).is_err(),
        "no signatures: nothing returned"
    );
    let (dx, dy) = (
        body_digest_of_env(&branches[0]),
        body_digest_of_env(&branches[1]),
    );
    let batch = prepare_resolve(
        &chain.objects,
        chain.now,
        (2, dx),
        (2, dy),
        T0 + 10 * SEC,
        vec![f.a.id.clone()],
        TransitionRule::Control,
    )
    .unwrap();
    let sigs = host.sign(batch.steps());
    match batch.finish(sigs) {
        Err(Failure::Malformed(m)) => assert!(m.contains("void"), "{m}"),
        other => panic!("expected a void refusal: {other:?}"),
    }
}

/// A transition T2 (A removes B) receipted by H, vetoed by B; the veto receipted by H.
fn vetoable(
    f: &Fixture,
    v_offset: i64,
    v_receipt_offset: i64,
) -> (Chain, Key, Host, String, String, i64) {
    let (mut chain, h, host) = account_with_home(f);
    let account = chain.account();
    let t2_issued = T0 + 100 * SEC;
    let batch = prepare_transition(
        &chain.objects,
        chain.now,
        &transition_params(
            &chain,
            t2_issued,
            &[&f.a],
            json!({"keyring": {"remove": [f.b.id]}}),
        ),
    )
    .unwrap();
    let r = chain.run(&host, batch);
    let t2 = r.pending[0].clone();
    let t2_digest = body_digest_of_env(&t2);
    let r2 = receipt(&account, &h, &t2_digest, t2_issued + 10 * SEC);
    chain.objects.pending.push(r2.clone());
    let v_issued = t2_issued + v_offset;
    let batch = prepare_veto(
        &chain.objects,
        chain.now,
        &VetoParams {
            transition: t2,
            transition_receipts: vec![r2],
            issued_ms: v_issued,
            signers: vec![f.b.id.clone()],
        },
    )
    .unwrap();
    let r = chain.run(&host, batch);
    let v_digest = body_digest_of_env(&r.pending[0]);
    chain.objects.pending.push(receipt(
        &account,
        &h,
        &v_digest,
        v_issued + v_receipt_offset,
    ));
    (chain, h, host, t2_digest, v_digest, t2_issued)
}

#[test]
fn heads_evidence_does_not_convict_an_honest_displacement() {
    // The checker's H3. An honest home signs a head over a provisional `activate`, then
    // receives the `vetoed` that displaces it (§8.6 rule 1) and signs a head over that.
    let f = fixture();
    let (chain, h, _host, t2, v, _) = vetoable(&f, 30 * SEC, 5 * SEC);
    let account = chain.account();
    let act = prepare_activate(&chain.objects, chain.now, &t2)
        .unwrap()
        .finish(vec![])
        .unwrap();
    let vet = prepare_vetoed(&chain.objects, chain.now, &t2, &v)
        .unwrap()
        .finish(vec![])
        .unwrap();
    let (x, y) = (act.entries[0].1.clone(), vet.entries[0].1.clone());
    assert_eq!((act.entries[0].0, vet.entries[0].0), (3, 3));
    let mut all = chain.objects.clone();
    all.entries.extend([x.clone(), y.clone()]);
    let verdict = verify_history(&all, &Persisted::default(), chain.now);
    assert!(verdict.stop.is_none(), "{:?}", verdict.stop);
    assert_eq!(
        verdict.branch[2],
        body_digest_of_env(&y),
        "the vetoed stands"
    );
    let ctx = EvidenceContext {
        objects: &all,
        now_ms: chain.now,
    };
    let early_over_x = head(&account, &h, 3, &body_digest_of_env(&x), T0 + 5_000 * SEC);
    let later_over_y = head(&account, &h, 3, &body_digest_of_env(&y), T0 + 5_100 * SEC);
    let r = equivocation_of_heads(&account, &early_over_x, &later_over_y, &ctx);
    assert!(
        matches!(r, Err(Failure::Malformed(ref m)) if m.contains("rule 1")),
        "{r:?}"
    );
    // The other order is a regression, not a displacement: the home signed over the entry
    // that stands and later over the one it displaced.
    let early_over_y = head(&account, &h, 3, &body_digest_of_env(&y), T0 + 5_000 * SEC);
    let later_over_x = head(&account, &h, 3, &body_digest_of_env(&x), T0 + 5_100 * SEC);
    let ev = equivocation_of_heads(&account, &early_over_y, &later_over_x, &ctx).unwrap();
    assert_eq!(
        verify_evidence(&ev, &account, &ctx).unwrap(),
        Evidence::Heads {
            home: h.id.clone(),
            seq: 3
        }
    );
    // The two orders of arguments build the same evidence.
    assert_eq!(
        ev,
        equivocation_of_heads(&account, &later_over_x, &early_over_y, &ctx).unwrap()
    );
}

#[test]
fn heads_evidence_needs_the_history_and_verified_heads() {
    let f = fixture();
    let (chain, h, _) = account_with_home(&f);
    let account = chain.account();
    let ctx = EvidenceContext {
        objects: &chain.objects,
        now_ms: chain.now,
    };
    let a = head(&account, &h, 3, &"1".repeat(64), T0 + 100 * SEC);
    let b = head(&account, &h, 3, &"2".repeat(64), T0 + 101 * SEC);
    // The held history stops at seq 2: unavailable, never a conviction.
    assert!(matches!(
        equivocation_of_heads(&account, &a, &b, &ctx),
        Err(Failure::Unavailable(_))
    ));
    // Refusals: the same entry, different seqs, a stranger, a forged signature.
    let same = head(&account, &h, 3, &"1".repeat(64), T0 + 102 * SEC);
    assert!(equivocation_of_heads(&account, &a, &same, &ctx).is_err());
    let other_seq = head(&account, &h, 4, &"2".repeat(64), T0 + 101 * SEC);
    assert!(equivocation_of_heads(&account, &a, &other_seq, &ctx).is_err());
    let stranger = key(56);
    let sa = head(&account, &stranger, 3, &"1".repeat(64), T0 + 100 * SEC);
    let sb = head(&account, &stranger, 3, &"2".repeat(64), T0 + 101 * SEC);
    assert!(matches!(
        equivocation_of_heads(&account, &sa, &sb, &ctx),
        Err(Failure::BadSignature(_))
    ));
    assert!(equivocation_of_heads(&account, &a, &sb, &ctx).is_err());
    let mut forged = b.clone();
    let n = forged.len();
    forged[n - 6] ^= 1;
    assert!(equivocation_of_heads(&account, &a, &forged, &ctx).is_err());
    // Entries a head covers that are not held: unavailable even when the history reaches.
    let (chain, h, _host, t2, _v, _) = vetoable(&f, 30 * SEC, 5 * SEC);
    let act = prepare_activate(&chain.objects, chain.now, &t2)
        .unwrap()
        .finish(vec![])
        .unwrap();
    let mut held = chain.objects.clone();
    held.entries.push(act.entries[0].1.clone());
    let ctx = EvidenceContext {
        objects: &held,
        now_ms: chain.now,
    };
    let account = chain.account();
    let x = head(
        &account,
        &h,
        3,
        &body_digest_of_env(&act.entries[0].1),
        T0 + 5_000 * SEC,
    );
    let unknown = head(&account, &h, 3, &"2".repeat(64), T0 + 5_100 * SEC);
    assert!(matches!(
        equivocation_of_heads(&account, &x, &unknown, &ctx),
        Err(Failure::Unavailable(_))
    ));
    // Evidence over the wrong account does not verify.
    assert!(verify_evidence(b"{}", &"c".repeat(64), &ctx).is_err());
}

/// An activation of T2 (removing B) that H witnesses with a head, recorded by a `final`, with
/// B's veto of T2 receipted by H `v_receipt_offset` after the veto's `issued`.
fn final_over_a_vetoed_activation(
    f: &Fixture,
    v_offset: i64,
    v_receipt_offset: i64,
) -> (Chain, Key, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let (mut chain, h, host, t2, v, _) = vetoable(f, v_offset, v_receipt_offset);
    let account = chain.account();
    let veto = chain
        .objects
        .pending
        .iter()
        .find(|b| body_digest_of_env(b) == v)
        .unwrap()
        .clone();
    let rcpt = chain
        .objects
        .pending
        .iter()
        .find(|b| {
            let e: Value = serde_json::from_slice(b).unwrap();
            let body: Value =
                serde_json::from_slice(&STANDARD.decode(e["body"].as_str().unwrap()).unwrap())
                    .unwrap();
            body["protocol"] == "colophon/receipt/5" && body["object"] == v.as_str()
        })
        .unwrap()
        .clone();
    let act = prepare_activate(&chain.objects, chain.now, &t2).unwrap();
    let r = chain.run(&host, act);
    let activation = r.entries[0].1.clone();
    let a = chain.state().activations().last().unwrap().clone();
    chain
        .objects
        .heads
        .push(head(&account, &h, a.seq, &a.digest, T0 + 5_000 * SEC));
    let fin = prepare_final(&chain.objects, chain.now, a.seq).unwrap();
    let r = chain.run(&host, fin);
    (chain, h, activation, veto, rcpt, r.entries[0].1.clone())
}

#[test]
fn veto_evidence_convicts_only_a_home_that_receipted_in_time_and_witnessed_the_final() {
    let f = fixture();
    let (chain, h, activation, veto, rcpt, fin) =
        final_over_a_vetoed_activation(&f, 30 * SEC, 5 * SEC);
    let account = chain.account();
    let ctx = EvidenceContext {
        objects: &chain.objects,
        now_ms: chain.now,
    };
    let ev = equivocation_of_veto(&account, &activation, &veto, &rcpt, &fin, &ctx).unwrap();
    assert_eq!(
        verify_evidence(&ev, &account, &ctx).unwrap(),
        Evidence::Veto { home: h.id.clone() }
    );
    // A final whose head is forged does not convict (the checker's H1: heads were never
    // signature-checked).
    let fin_body: Value = serde_json::from_slice(
        &STANDARD
            .decode(
                serde_json::from_slice::<Value>(&fin).unwrap()["body"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap(),
    )
    .unwrap();
    let real_head = dec(fin_body["heads"][0].as_str().unwrap()).unwrap();
    let mut hv: Value = serde_json::from_slice(&real_head).unwrap();
    hv["signature"] = json!(b64(&[0u8; 64]));
    let fake_head = canonical(&hv).unwrap();
    let header = Header {
        seq: fin_body["seq"].as_u64().unwrap(),
        previous: fin_body["previous"].as_str().map(str::to_string),
        issued: fin_body["issued"].as_str().unwrap().to_string(),
        by: fin_body["by"].as_str().unwrap().to_string(),
    };
    let forged_body = Kind::Final {
        activation_seq: fin_body["activation"]["seq"].as_u64().unwrap(),
        activation_digest: fin_body["activation"]["digest"]
            .as_str()
            .unwrap()
            .to_string(),
        heads: vec![fake_head],
    }
    .body(&header)
    .unwrap();
    let forged_final = envelope(&forged_body, None, &[], &[], &[]).unwrap();
    assert!(matches!(
        equivocation_of_veto(&account, &activation, &veto, &rcpt, &forged_final, &ctx),
        Err(Failure::BadSignature(_))
    ));
    // A receipt of another veto, a veto of another transition: no link, no conviction.
    let other_rcpt = receipt(&account, &h, &"9".repeat(64), T0 + 150 * SEC);
    assert!(equivocation_of_veto(&account, &activation, &veto, &other_rcpt, &fin, &ctx).is_err());
}

#[test]
fn veto_evidence_refuses_a_receipt_after_the_deadline() {
    // T2's veto deadline is its `issued` + 3,600 s. The veto is issued at +3,500 s and the
    // home receipts it at +3,700 s: too late to have stopped anything.
    let f = fixture();
    let (chain, _h, activation, veto, rcpt, fin) =
        final_over_a_vetoed_activation(&f, 3_500 * SEC, 200 * SEC);
    let account = chain.account();
    let ctx = EvidenceContext {
        objects: &chain.objects,
        now_ms: chain.now,
    };
    match equivocation_of_veto(&account, &activation, &veto, &rcpt, &fin, &ctx) {
        Err(Failure::Malformed(m)) => assert!(m.contains("deadline"), "{m}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn vetoed_skips_a_receipt_after_the_deadline() {
    // The checker's H4. The lowest home's receipt of the veto is late; the other home's is
    // timely. The late one is skipped, not chosen, and the `vetoed` verifies.
    let f = fixture();
    let (mut chain, lo, hi, host) = account_with_two_homes(&f);
    let account = chain.account();
    let t2_issued = T0 + 100 * SEC;
    let batch = prepare_transition(
        &chain.objects,
        chain.now,
        &transition_params(
            &chain,
            t2_issued,
            &[&f.a],
            json!({"keyring": {"remove": [f.b.id]}}),
        ),
    )
    .unwrap();
    let r = chain.run(&host, batch);
    let t2 = r.pending[0].clone();
    let t2_digest = body_digest_of_env(&t2);
    let r2 = receipt(&account, &lo, &t2_digest, t2_issued + 10 * SEC);
    chain.objects.pending.push(r2.clone());
    let v_issued = t2_issued + 3_500 * SEC;
    let batch = prepare_veto(
        &chain.objects,
        chain.now,
        &VetoParams {
            transition: t2,
            transition_receipts: vec![r2],
            issued_ms: v_issued,
            signers: vec![f.b.id.clone()],
        },
    )
    .unwrap();
    let r = chain.run(&host, batch);
    let v_digest = body_digest_of_env(&r.pending[0]);
    let late = receipt(&account, &lo, &v_digest, v_issued + 200 * SEC);
    let timely = receipt(&account, &hi, &v_digest, v_issued + 10 * SEC);
    chain.objects.pending.extend([late, timely]);
    let rec = prepare_vetoed(&chain.objects, chain.now, &t2_digest, &v_digest)
        .unwrap()
        .finish(vec![])
        .expect("one late receipt must not block a valid vetoed");
    assert_eq!(rec.entries[0].0, 3);
}

fn account_with_two_homes(f: &Fixture) -> (Chain, Key, Key, Host) {
    let mut chain = Chain::new(T0 + 10 * 86_400 * SEC);
    chain.genesis(
        &f.host,
        "Homes",
        &[],
        fixture_keyring(f),
        std::slice::from_ref(&f.a.id),
    );
    let account = chain.account();
    let (h1, h2) = (key(40), key(42));
    let mut host = Host::default();
    host.keys = f.host.keys.clone();
    host.add(&h1);
    host.add(&h2);
    let mut appoint: Vec<(String, Value)> = [(&h1, key(41)), (&h2, key(43))]
        .iter()
        .map(|(h, ag)| {
            (
                h.id.clone(),
                json!({"request": b64(&request(&account, h, ag, "Home", "server", home_terms())),
                       "terms": home_terms()}),
            )
        })
        .collect();
    appoint.sort_by(|a, b| a.0.cmp(&b.0));
    let change =
        json!({"homes": {"appoint": appoint.into_iter().map(|x| x.1).collect::<Vec<_>>()}});
    let batch = prepare_transition(
        &chain.objects,
        chain.now,
        &transition_params(&chain, T0 + 10 * SEC, &[&f.a], change),
    )
    .unwrap();
    let r = chain.run(&host, batch);
    let t = body_digest_of_env(&r.pending[0]);
    let act = prepare_activate(&chain.objects, chain.now, &t).unwrap();
    chain.run(&host, act);
    assert_eq!(chain.state().current_homes().len(), 2);
    let (lo, hi) = if h1.id < h2.id { (h1, h2) } else { (h2, h1) };
    (chain, lo, hi, host)
}

#[test]
fn the_chooser_treats_a_reformatted_receipt_like_the_canonical_one() {
    // Like a home: canonicalize a held receipt rather than skip it.
    let f = fixture();
    let (chain, h, _) = account_with_home(&f);
    let st = chain.state();
    let account = chain.account();
    let object = "a".repeat(64);
    let issued = T0 + 100 * SEC;
    let canonical_receipt = receipt(&account, &h, &object, issued + 10 * SEC);
    let pretty =
        serde_json::to_vec_pretty(&serde_json::from_slice::<Value>(&canonical_receipt).unwrap())
            .unwrap();
    assert_ne!(pretty, canonical_receipt);
    let chosen = choose_receipts(&st, &[pretty], &object, issued, None).unwrap();
    assert_eq!(chosen, vec![canonical_receipt]);
}

#[test]
fn prepare_refuses_what_only_finish_would_refuse() {
    let f = fixture();
    let mut chain = Chain::new(T0 + 3_600 * SEC);
    chain.genesis(
        &f.host,
        "Early",
        &[],
        fixture_keyring(&f),
        std::slice::from_ref(&f.a.id),
    );
    // An issued time that is no §2.2 date.
    for bad in [i64::MAX, i64::MIN, 253_402_300_800_000] {
        let r = prepare_signed(
            &chain.objects,
            chain.now,
            Kind::EndSessions { member: key(77).id },
            bad,
            std::slice::from_ref(&f.a.id),
        );
        assert!(matches!(r, Err(Failure::Malformed(_))), "{bad}: {r:?}");
    }
    assert!(prepare_genesis(
        &GenesisParams {
            label: "x".into(),
            namespaces: vec![],
            keyring: fixture_keyring(&f),
            issued_ms: i64::MAX,
            signers: vec![f.a.id.clone()],
        },
        chain.now
    )
    .is_err());
    // endSessions, renew and revoke of a member that does not exist.
    let ghost = key(77).id;
    for kind in [
        Kind::EndSessions {
            member: ghost.clone(),
        },
        Kind::Revoke {
            member: ghost.clone(),
            kept: vec![],
            heads: vec![],
            epochs: vec![],
        },
    ] {
        let r = prepare_signed(
            &chain.objects,
            chain.now,
            kind,
            T0 + SEC,
            std::slice::from_ref(&f.a.id),
        );
        assert!(matches!(r, Err(Failure::Malformed(_))), "{r:?}");
    }
    assert!(prepare_end_sessions_by_member(&chain.objects, chain.now, &ghost, T0 + SEC).is_err());
    // A body over the bound is refused from its embedded objects, before serializing.
    let big = Kind::Grant {
        request: vec![0u8; 800_000],
        terms: json!({}),
        shares: vec![],
    };
    let header = Header {
        seq: 2,
        previous: Some("0".repeat(64)),
        issued: "2026-11-11T08:00:00Z".into(),
        by: f.a.id.clone(),
    };
    assert!(matches!(big.body(&header), Err(Failure::Malformed(_))));
}

#[test]
fn final_ignores_a_head_dated_ahead_of_the_clock() {
    // The checker's L5. A witness's future-dated head with the lower digest must not hold
    // back a `final` when a usable head exists.
    let f = fixture();
    let (mut chain, h, host, _t2, _v, _) = vetoable(&f, 30 * SEC, 5 * SEC);
    let account = chain.account();
    // A transition T3 by A and B, activated; H is its witness.
    let t3_issued = T0 + 200 * SEC;
    let batch = prepare_transition(
        &chain.objects,
        chain.now,
        &transition_params(
            &chain,
            t3_issued,
            &[&f.a, &f.b],
            json!({"policy": {"callWindow": 600}}),
        ),
    )
    .unwrap();
    let r = chain.run(&host, batch);
    let t3 = body_digest_of_env(&r.pending[0]);
    chain
        .objects
        .pending
        .push(receipt(&account, &h, &t3, t3_issued + 10 * SEC));
    let act = prepare_activate(&chain.objects, chain.now, &t3).unwrap();
    chain.run(&host, act);
    let a = chain.state().activations().last().unwrap().clone();
    let good = head(&account, &h, a.seq, &a.digest, T0 + 5_000 * SEC);
    // Several future-dated heads: one of them is sure to have the lowest digest.
    let mut futures = Vec::new();
    for n in 0..6 {
        futures.push(head(
            &account,
            &h,
            a.seq,
            &a.digest,
            chain.now + 3_600 * SEC + n * SEC,
        ));
    }
    chain.objects.heads.extend(futures);
    chain.objects.heads.push(good.clone());
    let rec = prepare_final(&chain.objects, chain.now, a.seq)
        .unwrap()
        .finish(vec![])
        .unwrap();
    let body: Value = serde_json::from_slice(
        &STANDARD
            .decode(
                serde_json::from_slice::<Value>(&rec.entries[0].1).unwrap()["body"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap(),
    )
    .unwrap();
    assert_eq!(dec(body["heads"][0].as_str().unwrap()).unwrap(), good);
}

// ---------------------------------------------------------------------------------------------
// The determined bodies are a function of the held objects.

#[test]
fn recording_bodies_do_not_depend_on_the_order_objects_were_held() {
    let f = fixture();
    let (chain, h, host) = account_with_home(&f);
    let account = chain.account();
    let issued = T0 + 100 * SEC;
    let mut c = Chain::new(chain.now);
    c.objects = chain.objects.clone();
    let batch = prepare_transition(
        &c.objects,
        c.now,
        &transition_params(&c, issued, &[&f.a], json!({"policy": {"callWindow": 900}})),
    )
    .unwrap();
    let r = c.run(&host, batch);
    let t = body_digest_of_env(&r.pending[0]);
    let r1 = receipt(&account, &h, &t, issued + 10 * SEC);
    let r2 = receipt(&account, &h, &t, issued + 20 * SEC);
    let mut a = c.objects.clone();
    a.pending.extend([r1.clone(), r2.clone()]);
    let mut b = c.objects.clone();
    b.pending.extend([r2, r1]);
    b.pending.reverse();
    let ra = prepare_activate(&a, c.now, &t)
        .unwrap()
        .finish(vec![])
        .unwrap();
    let rb = prepare_activate(&b, c.now, &t)
        .unwrap()
        .finish(vec![])
        .unwrap();
    assert_eq!(
        ra, rb,
        "two homes holding the same objects build identical bytes"
    );
}

// ---------------------------------------------------------------------------------------------
// Candidate vectors: the builders reproduce the published entries.

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn read_json(p: &std::path::Path) -> Value {
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}
fn dec(s: &str) -> Option<Vec<u8>> {
    STANDARD.decode(s).ok()
}

fn published_scalars() -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut put = |public: &str, scalar: &str| {
        if let (Some(p), Some(s)) = (dec(public), dec(scalar)) {
            out.insert(key_id(&p), s);
        }
    };
    let c = repo().join("conformance/0.5/candidate");
    for f in ["keys.json", "rules/keys-r4.json"] {
        let v = read_json(&c.join(f));
        for k in v["keys"].as_object().unwrap().values() {
            put(
                k["signing"].as_str().unwrap(),
                k["scalar"].as_str().unwrap(),
            );
        }
    }
    let v = read_json(&repo().join("conformance/0.4/keys/keys.json"));
    for a in v["authenticators"].as_array().unwrap() {
        put(
            a["descriptor"]["signing"].as_str().unwrap(),
            a["signingScalar"].as_str().unwrap(),
        );
    }
    for s in v["software"].as_array().unwrap() {
        put(
            s["public"]["signing"].as_str().unwrap(),
            s["signingScalar"].as_str().unwrap(),
        );
    }
    out
}

fn files_named(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd {
        let p = e.unwrap().path();
        if p.is_dir() {
            if p.file_name().is_some_and(|n| n == "authority") {
                let mut v: Vec<PathBuf> = std::fs::read_dir(&p)
                    .unwrap()
                    .map(|e| e.unwrap().path())
                    .filter(|p| p.extension().is_some_and(|x| x == "json"))
                    .collect();
                v.sort();
                out.extend(v);
            } else {
                files_named(&p, out);
            }
        }
    }
}

fn list(v: &Value) -> Option<Vec<Vec<u8>>> {
    v.as_array()?.iter().map(|x| dec(x.as_str()?)).collect()
}
fn strs(v: &Value) -> Option<Vec<String>> {
    v.as_array()?
        .iter()
        .map(|x| x.as_str().map(str::to_string))
        .collect()
}
fn vals(v: &Value) -> Option<Vec<Value>> {
    v.as_array().cloned()
}

/// The builder's kind and the set of body fields it can carry, from a vector body.
fn kind_of(b: &Value) -> Option<(Kind, &'static [&'static str])> {
    let kind = b["kind"].as_str()?;
    Some(match kind {
        "genesis" => (
            Kind::Genesis {
                label: b["label"].as_str()?.into(),
                namespaces: strs(&b["namespaces"])?,
                keyring: b["keyring"].clone(),
                predecessor: b.get("predecessor").cloned(),
            },
            &["label", "namespaces", "keyring", "predecessor"],
        ),
        "rekey" => (
            Kind::Rekey {
                epochs: vals(&b["epochs"])?,
            },
            &["epochs"],
        ),
        "grant" => (
            Kind::Grant {
                request: dec(b["request"].as_str()?)?,
                terms: b["terms"].clone(),
                shares: vals(&b["shares"])?,
            },
            &["request", "terms", "shares"],
        ),
        "renew" => (
            Kind::Renew {
                member: b["member"].as_str()?.into(),
                expires: b["expires"].as_str()?.into(),
                shares: vals(&b["shares"])?,
            },
            &["member", "expires", "shares"],
        ),
        "revoke" => (
            Kind::Revoke {
                member: b["member"].as_str()?.into(),
                kept: strs(&b["kept"])?,
                heads: b["heads"]
                    .as_array()?
                    .iter()
                    .map(|h| {
                        Some(KeptHead {
                            namespace: h["namespace"].as_str()?.into(),
                            digest: h["digest"].as_str()?.into(),
                        })
                    })
                    .collect::<Option<_>>()?,
                epochs: vals(&b["epochs"])?,
            },
            &["member", "kept", "heads", "epochs"],
        ),
        "endSessions" => (
            Kind::EndSessions {
                member: b["member"].as_str()?.into(),
            },
            &["member"],
        ),
        "keyring" => (
            Kind::Keyring {
                keyring: b["keyring"].clone(),
            },
            &["keyring"],
        ),
        "vault" => (
            Kind::Vault {
                vault: b["vault"].clone(),
                slots: vals(&b["slots"])?,
                previous_vault: b["previousVault"].clone(),
            },
            &["vault", "slots", "previousVault"],
        ),
        "suspend" => (
            Kind::Suspend {
                key: b["key"].as_str()?.into(),
                transition: dec(b["transition"].as_str()?)?,
                receipts: list(&b["receipts"])?,
            },
            &["key", "transition", "receipts"],
        ),
        "activate" => (
            Kind::Activate {
                transition: dec(b["transition"].as_str()?)?,
                receipts: list(&b["receipts"])?,
            },
            &["transition", "receipts"],
        ),
        "vetoed" => (
            Kind::Vetoed {
                transition: dec(b["transition"].as_str()?)?,
                transition_receipts: list(&b["transitionReceipts"])?,
                veto: dec(b["veto"].as_str()?)?,
                receipts: list(&b["receipts"])?,
            },
            &["transition", "transitionReceipts", "veto", "receipts"],
        ),
        "final" => (
            Kind::Final {
                activation_seq: b["activation"]["seq"].as_u64()?,
                activation_digest: b["activation"]["digest"].as_str()?.into(),
                heads: list(&b["heads"])?,
            },
            &["activation", "heads"],
        ),
        "successionVetoed" => (
            Kind::SuccessionVetoed {
                veto: dec(b["veto"].as_str()?)?,
                receipts: list(&b["receipts"])?,
                genesis_receipts: list(&b["genesisReceipts"])?,
            },
            &["veto", "receipts", "genesisReceipts"],
        ),
        _ => return None,
    })
}

#[test]
fn kind_body_round_trips_the_candidate_vectors_field_names_and_encoding() {
    // What this proves, and no more: `Kind::body` puts the vector's own field values under the
    // right names, spells the header and `kind`, base64-embeds objects and encodes canonically.
    // Keyrings, terms, receipts and heads are copied from the vector as opaque values here; the
    // state-aware replay test below is the one that builds from held objects.
    let scalars = published_scalars();
    let mut files = Vec::new();
    files_named(&repo().join("conformance/0.5/candidate"), &mut files);
    let (mut total, mut body_same, mut env_same) = (0, 0, 0);
    let mut by_kind: BTreeMap<String, (usize, usize, usize)> = BTreeMap::new();
    let mut skipped: BTreeMap<&str, usize> = BTreeMap::new();
    let mut body_mismatch = Vec::new();
    let mut env_mismatch = Vec::new();
    for p in files {
        total += 1;
        let mut raw = std::fs::read(&p).unwrap();
        // Some vector files end with a newline: file formatting, not envelope content.
        if raw.last() == Some(&b'\n') {
            raw.pop();
        }
        let rel = p.strip_prefix(repo()).unwrap().display().to_string();
        let Ok(env): Result<Value, _> = serde_json::from_slice(&raw) else {
            *skipped.entry("not json").or_default() += 1;
            continue;
        };
        let Some(body) = env["body"].as_str().and_then(dec) else {
            *skipped.entry("no body").or_default() += 1;
            continue;
        };
        let Ok(bv) = serde_json::from_slice::<Value>(&body) else {
            *skipped.entry("body not json").or_default() += 1;
            continue;
        };
        if bv["protocol"] != "colophon/authority/5" {
            *skipped
                .entry("not a /5 entry (0.4 or Swift, package E7)")
                .or_default() += 1;
            continue;
        }
        if canonical(&bv).ok().as_deref() != Some(&body[..]) {
            *skipped
                .entry("body is not canonical on purpose (a negative vector)")
                .or_default() += 1;
            continue;
        }
        let Some((kind, fields)) = kind_of(&bv) else {
            *skipped.entry("kind not built here").or_default() += 1;
            continue;
        };
        let header_keys = ["by", "issued", "kind", "previous", "protocol", "seq"];
        let extra = bv
            .as_object()
            .unwrap()
            .keys()
            .any(|k| !header_keys.contains(&k.as_str()) && !fields.contains(&k.as_str()));
        if extra {
            *skipped
                .entry("body carries unknown fields (vector tests unknown content)")
                .or_default() += 1;
            continue;
        }
        let header = Header {
            seq: bv["seq"].as_u64().unwrap(),
            previous: bv["previous"].as_str().map(str::to_string),
            issued: bv["issued"].as_str().unwrap().to_string(),
            by: bv["by"].as_str().unwrap().to_string(),
        };
        let name = kind.name().to_string();
        let e = by_kind.entry(name).or_default();
        e.0 += 1;
        match kind.body(&header) {
            Ok(b) if b == body => {
                body_same += 1;
                e.1 += 1;
            }
            other => {
                body_mismatch.push(format!("{rel}: {:?}", other.map(|b| b.len())));
                continue;
            }
        }
        // Signatures: reproduce every item from the published scalar; a WebAuthn item reuses
        // the vector's assertion (the host's input) and signs over it.
        let resign = |signer: &str, item: &Value| -> Option<Signature> {
            let k = key_from_scalar(scalars.get(signer)?);
            Some(match item.get("assertion") {
                None => Signature {
                    signer: signer.to_string(),
                    signature: k.sign_raw(&body),
                    assertion: None,
                },
                Some(a) => {
                    let (d, c) = (
                        dec(a["authenticatorData"].as_str()?)?,
                        dec(a["clientData"].as_str()?)?,
                    );
                    Signature {
                        signer: signer.to_string(),
                        signature: k.sign_webauthn(&d, &c),
                        assertion: Some((d, c)),
                    }
                }
            })
        };
        if kind.is_recording() {
            let rebuilt = envelope(&body, None, &[], &[], &[]).unwrap();
            if rebuilt == raw {
                env_same += 1;
                by_kind.get_mut(kind.name()).unwrap().2 += 1;
            } else {
                env_mismatch.push(format!("{rel}: unsigned"));
            }
            continue;
        }
        if env.get("handover").is_some() {
            *skipped
                .entry("handover (successor genesis, package E7)")
                .or_default() += 1;
            continue;
        }
        let items = |f: &str| -> Option<Vec<Signature>> {
            env.get(f)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .map(|i| resign(i["signer"].as_str()?, i))
                .collect()
        };
        let primary = resign(bv["by"].as_str().unwrap(), &env);
        let (cos, add) = (items("cosignatures"), items("additions"));
        let (Some(primary), Some(cos), Some(add)) = (primary, cos, add) else {
            *skipped
                .entry("a signer's scalar is not published")
                .or_default() += 1;
            continue;
        };
        match envelope(&body, Some(&primary), &cos, &add, &[]) {
            Ok(r) if r == raw => {
                env_same += 1;
                by_kind.get_mut(kind.name()).unwrap().2 += 1;
            }
            Ok(_) => env_mismatch.push(format!("{rel}: signature or envelope bytes differ")),
            Err(e) => env_mismatch.push(format!("{rel}: {e}")),
        }
    }
    println!("vector entries: {total}; body bytes reproduced: {body_same}; envelopes reproduced: {env_same}");
    for (k, (n, b, e)) in &by_kind {
        println!("  {k}: {n} built, {b} bodies, {e} envelopes identical");
    }
    for (why, n) in &skipped {
        println!("  skipped {n}: {why}");
    }
    for m in &env_mismatch {
        println!("  ENVELOPE DIFFERS {m}");
    }
    assert!(
        body_mismatch.is_empty(),
        "body bytes differ: {body_mismatch:#?}"
    );
    assert!(
        env_mismatch.is_empty(),
        "envelope bytes differ: {env_mismatch:#?}"
    );
    assert!(body_same > 0);
    let _ = parse_date;
}

#[test]
fn the_account_vector_rebuilds_through_prepare_and_finish() {
    // Genesis, grant and the determined `activate` of the identity account, built from the
    // vector's inputs and the published keys, and verified: the same bytes at every step.
    let dir = repo().join("conformance/0.5/candidate/account/records/authority");
    let read = |n: &str| std::fs::read(dir.join(n)).unwrap();
    let scalars = published_scalars();
    let g_env: Value = serde_json::from_slice(&read("00000001.json")).unwrap();
    let g_body: Value =
        serde_json::from_slice(&STANDARD.decode(g_env["body"].as_str().unwrap()).unwrap()).unwrap();
    let by = g_body["by"].as_str().unwrap().to_string();
    let mut host = Host::default();
    host.add(&key_from_scalar(&scalars[&by]));
    let now = parse_date("2026-11-11T09:01:00Z").unwrap();
    let mut chain = Chain::new(now);
    let batch = prepare_genesis(
        &GenesisParams {
            label: g_body["label"].as_str().unwrap().into(),
            namespaces: vec![],
            keyring: g_body["keyring"].clone(),
            issued_ms: parse_date(g_body["issued"].as_str().unwrap()).unwrap(),
            signers: vec![by.clone()],
        },
        now,
    )
    .unwrap();
    let r = chain.run(&host, batch);
    assert_eq!(r.entries[0].1, read("00000001.json"), "genesis bytes");

    let grant: Value = serde_json::from_slice(
        &STANDARD
            .decode(
                serde_json::from_slice::<Value>(&read("00000002.json")).unwrap()["body"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap(),
    )
    .unwrap();
    let batch = prepare_signed(
        &chain.objects,
        now,
        Kind::Grant {
            request: dec(grant["request"].as_str().unwrap()).unwrap(),
            terms: grant["terms"].clone(),
            shares: vec![],
        },
        parse_date(grant["issued"].as_str().unwrap()).unwrap(),
        std::slice::from_ref(&by),
    )
    .unwrap();
    let r = chain.run(&host, batch);
    assert_eq!(r.entries[0].1, read("00000002.json"), "grant bytes");

    // The activate: the transition is embedded in the vector's entry; the builder picks it
    // up as a held object and produces the determined entry.
    let act: Value = serde_json::from_slice(
        &STANDARD
            .decode(
                serde_json::from_slice::<Value>(&read("00000003.json")).unwrap()["body"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap(),
    )
    .unwrap();
    chain
        .objects
        .pending
        .push(dec(act["transition"].as_str().unwrap()).unwrap());
    let t_digest = body_digest_of_env(&dec(act["transition"].as_str().unwrap()).unwrap());
    let batch = prepare_activate(&chain.objects, now, &t_digest).unwrap();
    let r = batch.finish(vec![]).unwrap();
    assert_eq!(r.entries[0].1, read("00000003.json"), "activate bytes");
}

// ---------------------------------------------------------------------------------------------
// The state-aware replay: prepare and finish from held objects against the vectors.

fn client_challenge(client: &[u8]) -> Option<String> {
    serde_json::from_slice::<Value>(client)
        .ok()?
        .get("challenge")?
        .as_str()
        .map(str::to_string)
}

/// Replay one vector's primary chain through the state-aware builders. Each entry's inputs are
/// held objects and fields (the transition and receipts of an `activate` are pending objects,
/// the heads of a `final` are held heads), never the vector's finished bytes; the vector's
/// bytes are held afterwards so the next entry has its history. Returns per kind
/// (identical, refused by the builder, different bytes, skipped).
fn replay_vector(
    dir: &std::path::Path,
    scalars: &BTreeMap<String, Vec<u8>>,
    stats: &mut BTreeMap<String, [usize; 4]>,
    notes: &mut Vec<String>,
) {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir.join("records/authority"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    let case = read_json(&dir.join("case.json"));
    let base_now = case["verifier"]["now"]
        .as_str()
        .and_then(parse_date)
        .unwrap_or_else(|| parse_date("2026-11-20T00:00:00Z").unwrap());
    // The rate-limit vectors hold 60+ entries; replaying each against its whole history is
    // quadratic. Their earlier entries are only held; the last three are replayed.
    let replay_from = if files.len() > 12 { files.len() - 3 } else { 0 };
    let expected_ok_through = match (
        case["expected"]["result"].as_str(),
        case["expected"]["seq"].as_u64(),
    ) {
        (Some("ok"), Some(n)) => n,
        _ => 0,
    };
    let mut objects = Objects::default();
    for (idx, p) in files.into_iter().enumerate() {
        let mut raw = std::fs::read(&p).unwrap();
        if raw.last() == Some(&b'\n') {
            raw.pop();
        }
        if idx < replay_from {
            objects.entries.push(raw);
            continue;
        }
        let rel = p.strip_prefix(repo()).unwrap().display().to_string();
        let env: Value = serde_json::from_slice(&raw).unwrap();
        let body_bytes = dec(env["body"].as_str().unwrap()).unwrap();
        let bv: Value = serde_json::from_slice(&body_bytes).unwrap();
        let kind_name = bv["kind"].as_str().unwrap_or("?").to_string();
        let cell = stats.entry(kind_name.clone()).or_default();
        let hold = |objects: &mut Objects| objects.entries.push(raw.clone());
        // A body that is not canonical on purpose is a negative vector for the verifier; a
        // builder only writes canonical bytes.
        if canonical(&bv).ok().as_deref() != Some(&body_bytes[..]) {
            cell[3] += 1;
            hold(&mut objects);
            continue;
        }
        if bv["protocol"] != "colophon/authority/5" || env.get("handover").is_some() {
            cell[3] += 1;
            hold(&mut objects);
            continue;
        }
        let issued = bv["issued"].as_str().and_then(parse_date).unwrap_or(0);
        let now = base_now.max(issued);
        let by = bv["by"].as_str().unwrap().to_string();
        let ids = |f: &str| -> Vec<String> {
            env.get(f)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|i| i["signer"].as_str().map(str::to_string))
                .collect()
        };
        let mut signers = vec![by.clone()];
        signers.extend(ids("cosignatures"));
        // Prepare from held objects.
        let mut held = objects.clone();
        let prepared = (|| -> Option<Result<PendingBatch, Failure>> {
            let bytes = |f: &str| dec(bv[f].as_str()?);
            Some(match kind_name.as_str() {
                "genesis" => prepare_genesis(
                    &GenesisParams {
                        label: bv["label"].as_str()?.into(),
                        namespaces: strs(&bv["namespaces"])?,
                        keyring: bv["keyring"].clone(),
                        issued_ms: issued,
                        signers: signers.clone(),
                    },
                    now,
                ),
                "activate" => {
                    let t = bytes("transition")?;
                    held.pending.push(t.clone());
                    held.pending.extend(list(&bv["receipts"])?);
                    prepare_activate(&held, now, &body_digest_of_env(&t))
                }
                "vetoed" => {
                    let (t, v) = (bytes("transition")?, bytes("veto")?);
                    held.pending.extend([t.clone(), v.clone()]);
                    held.pending.extend(list(&bv["transitionReceipts"])?);
                    held.pending.extend(list(&bv["receipts"])?);
                    prepare_vetoed(&held, now, &body_digest_of_env(&t), &body_digest_of_env(&v))
                }
                "final" => {
                    held.heads.extend(list(&bv["heads"])?);
                    prepare_final(&held, now, bv["activation"]["seq"].as_u64()?)
                }
                "suspend" => {
                    let t = bytes("transition")?;
                    held.pending.push(t.clone());
                    held.pending.extend(list(&bv["receipts"])?);
                    prepare_suspend(
                        &held,
                        now,
                        bv["key"].as_str()?,
                        &body_digest_of_env(&t),
                        issued,
                        &by,
                    )
                }
                "endSessions" if !env["cosignatures"].is_array() => {
                    // Signed by the member itself under the member rule, or by a controller.
                    match prepare_end_sessions_by_member(&held, now, &by, issued) {
                        Ok(b) => Ok(b),
                        Err(_) => {
                            let (kind, _) = kind_of(&bv)?;
                            prepare_signed(&held, now, kind, issued, &signers)
                        }
                    }
                }
                _ => {
                    let (kind, _) = kind_of(&bv)?;
                    if matches!(kind, Kind::Genesis { .. }) || kind.is_recording() {
                        return None;
                    }
                    prepare_signed(&held, now, kind, issued, &signers)
                }
            })
        })();
        let Some(prepared) = prepared else {
            cell[3] += 1;
            hold(&mut objects);
            continue;
        };
        let outcome = (|| -> Result<Vec<u8>, String> {
            let batch = prepared.map_err(|e| format!("prepare: {e}"))?;
            // The vector item for each step, by role and signer.
            let item = |step: &SigningStep| -> Option<Value> {
                if step.role() == StepRole::Primary {
                    return Some(env.clone());
                }
                let list = if step.role() == StepRole::Cosignature {
                    "cosignatures"
                } else {
                    "additions"
                };
                env.get(list)?
                    .as_array()?
                    .iter()
                    .find(|i| i["signer"] == step.signer())
                    .cloned()
            };
            let mut sigs = Vec::new();
            for step in batch.steps() {
                let k = key_from_scalar(scalars.get(step.signer()).ok_or("scalar not published")?);
                let it = item(step).ok_or("the vector has no such signature item")?;
                match step.challenge() {
                    None => sigs.push(SignatureResult {
                        signature: k.sign_raw(step.body()),
                        assertion: None,
                    }),
                    Some(ch) => {
                        let a = it.get("assertion").ok_or("no vector assertion")?;
                        let (d, c) = (
                            dec(a["authenticatorData"].as_str().unwrap()).unwrap(),
                            dec(a["clientData"].as_str().unwrap()).unwrap(),
                        );
                        // The step's challenge is the challenge the vector's clientData carries.
                        if client_challenge(&c).as_deref() != Some(ch) {
                            return Err("DIFFERENT: the WebAuthn challenge differs".into());
                        }
                        sigs.push(SignatureResult {
                            signature: k.sign_webauthn(&d, &c),
                            assertion: Some((d, c)),
                        });
                    }
                }
            }
            let rec = batch.finish(sigs).map_err(|e| format!("finish: {e}"))?;
            Ok(rec.entries[0].1.clone())
        })();
        match outcome {
            Ok(built) if built == raw => cell[0] += 1,
            Ok(_) => {
                cell[2] += 1;
                notes.push(format!(
                    "DIFFERENT {rel}: finish succeeded with other bytes"
                ));
            }
            Err(e) if e.starts_with("DIFFERENT") => {
                cell[2] += 1;
                notes.push(format!("{e} {rel}"));
            }
            Err(e) if e == "scalar not published" || e.starts_with("the vector has no") => {
                cell[3] += 1
            }
            Err(e) => {
                cell[1] += 1;
                // The builder may refuse only what the case says is refused.
                if bv["seq"].as_u64().unwrap_or(0) <= expected_ok_through {
                    notes.push(format!("DIFFERENT {rel}: refused a valid entry: {e}"));
                } else {
                    notes.push(format!("refused {rel}: {e}"));
                }
            }
        }
        hold(&mut objects);
    }
}

#[test]
fn state_aware_builders_reproduce_vector_entries_from_held_objects() {
    let scalars = published_scalars();
    let mut stats: BTreeMap<String, [usize; 4]> = BTreeMap::new();
    let mut notes = Vec::new();
    let root = repo().join("conformance/0.5/candidate");
    let mut dirs = vec![root.join("account")];
    for e in std::fs::read_dir(root.join("rules")).unwrap() {
        let p = e.unwrap().path();
        if p.join("records/authority").is_dir() && p.join("case.json").exists() {
            dirs.push(p);
        }
    }
    dirs.sort();
    for d in &dirs {
        replay_vector(d, &scalars, &mut stats, &mut notes);
    }
    println!("replayed {} vector histories", dirs.len());
    for (k, [same, refused, diff, skipped]) in &stats {
        println!(
            "  {k}: {same} identical, {refused} refused by the builder, {diff} different, {skipped} skipped"
        );
    }
    for n in notes.iter().take(60) {
        println!("  {n}");
    }
    let different: Vec<_> = notes
        .iter()
        .filter(|n| n.starts_with("DIFFERENT"))
        .collect();
    assert!(
        different.is_empty(),
        "bytes differ from the vectors: {different:#?}"
    );
    for kind in [
        "genesis", "grant", "activate", "keyring", "rekey", "revoke", "vault", "suspend", "vetoed",
        "final",
    ] {
        assert!(
            stats.get(kind).is_some_and(|c| c[0] > 0),
            "no {kind} entry was reproduced through prepare and finish"
        );
    }
}
