//! The host side of the 0.5 journeys: software and synthetic-WebAuthn keys, an account creation
//! fixture, an in-memory record source, a simulated home.
#![allow(dead_code, unused_imports, clippy::unwrap_used, clippy::cloned_ref_to_slice_refs)]
use base64::{engine::general_purpose::STANDARD, Engine};
use colophon_core::keys::testing::SyntheticAuthenticator;
use colophon_core::v05::account::*;
use colophon_core::v05::encoding::{canonical, digest};
use colophon_core::v05::history::{Objects, Persisted};

/// The host's device-held key for stored verifier state.
pub const KEY: [u8; 32] = [0x5a; 32];
use colophon_core::v05::ids::key_id;
use colophon_core::v05::pairing::{ExistingWaiting, FailureLimiter, Joiner, TransferKey};
use colophon_core::v05::records::{HeldRecord, Level};
use colophon_core::v05::slots::{
    answer_with_identity, OpeningInput, OpeningSecret, PrfAssertion, PrfRequest, PrfResult,
    SlotPlan,
};
use colophon_core::v05::vault::{kit_identity, PrfOutput, SoftwareIdentity};
use colophon_core::v05::write::authority::TransitionRule;
use colophon_core::v05::write::calls::RequestSpec;
use colophon_core::v05::write::{SignatureResult, SigningStep};
use colophon_core::v05::{Failure, Reason};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const T0: i64 = 1_794_384_000_000; // 2026-11-11T08:00:00Z
pub const SEC: i64 = 1_000;
pub const HOUR: i64 = 3_600 * SEC;
pub const RP: &str = "id.luff.works";
pub const ORIGIN: &str = "https://id.luff.works";

pub fn b64(b: &[u8]) -> String {
    STANDARD.encode(b)
}

// ---------------------------------------------------------------------------------------------
// The host.

pub struct Host {
    pub ids: BTreeMap<String, SoftwareIdentity>,
    pub passkey: Option<(SyntheticAuthenticator, String)>,
    pub counter: u8,
}
impl Host {
    pub fn new() -> Self {
        Self {
            ids: BTreeMap::new(),
            passkey: None,
            counter: 0,
        }
    }
    /// A software identity from a fixed byte: its ID.
    pub fn identity(&mut self, n: u8) -> String {
        let i = SoftwareIdentity::from_seed(&[n; 32]).unwrap();
        let id = i.id();
        self.ids.insert(id.clone(), i);
        id
    }
    pub fn kit(&mut self, n: u8) -> String {
        let i = kit_identity(&[n; 32]).unwrap();
        let id = i.id();
        self.ids.insert(id.clone(), i);
        id
    }
    pub fn passkey(&mut self) -> String {
        let a = SyntheticAuthenticator::new().unwrap();
        let point = {
            let sk = p256::ecdsa::SigningKey::from_slice(&[1; 32]).unwrap();
            sk.verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec()
        };
        let id = key_id(&point);
        self.passkey = Some((a, id.clone()));
        id
    }
    pub fn raw_controller(&self, id: &str, label: &str, roles: &[&str]) -> Value {
        let p = self.ids[id].public();
        json!({"key": {"form": "raw", "signing": b64(&p.signing), "agreement": b64(&p.agreement)},
               "label": label, "roles": roles})
    }
    pub fn passkey_controller(&self, label: &str, roles: &[&str]) -> Value {
        let sk = p256::ecdsa::SigningKey::from_slice(&[1; 32]).unwrap();
        let point = sk
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        json!({"key": {"form": "webauthn", "signing": b64(&point), "rp": RP, "credential": "AQ=="},
               "label": label, "roles": roles, "verification": true})
    }
    pub fn fresh(&mut self) -> [u8; 32] {
        self.counter += 1;
        [self.counter; 32]
    }
    pub fn sign(&self, steps: &[SigningStep]) -> Vec<SignatureResult> {
        steps
            .iter()
            .map(|s| match s.challenge() {
                None => SignatureResult {
                    signature: self.ids[s.signer()].sign(s.body()).to_vec(),
                    assertion: None,
                },
                Some(_) => {
                    let (auth, id) = self.passkey.as_ref().unwrap();
                    assert_eq!(id, s.signer());
                    let a = auth.assertion(s.body(), RP, ORIGIN, 0x05, false).unwrap();
                    SignatureResult {
                        signature: a.signature,
                        assertion: Some((a.assertion.authenticator_data, a.assertion.client_data)),
                    }
                }
            })
            .collect()
    }
    /// The PRF output of the passkey for a salt: a fixed function of the salt.
    pub fn prf(&self, salt: &[u8]) -> PrfOutput {
        let mut h = Sha256::new();
        h.update(b"test-prf");
        h.update(salt);
        PrfOutput::from_host(&h.finalize()).unwrap()
    }
    pub fn answer_prf(&self, reqs: &[PrfRequest]) -> Vec<PrfResult> {
        reqs.iter()
            .map(|r| {
                let (auth, _) = self.passkey.as_ref().unwrap();
                let client = canonical(&json!({
                    "type": "webauthn.get",
                    "challenge": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r.challenge),
                    "origin": ORIGIN,
                }))
                .unwrap();
                let mut ad = Sha256::digest(RP.as_bytes()).to_vec();
                ad.push(0x05);
                ad.extend([0, 0, 0, 0]);
                let a = auth.sign_bytes(ad, client, false).unwrap();
                PrfResult {
                    assertion: PrfAssertion {
                        authenticator_data: a.assertion.authenticator_data,
                        client_data: a.assertion.client_data,
                        signature: a.signature,
                    },
                    output: self.prf(&r.salt),
                }
            })
            .collect()
    }
    /// Answer the routes of a slot with the keys this host holds. `None` for a route it
    /// cannot answer.
    pub fn answer_unlock(&self, inputs: &[OpeningInput]) -> Vec<OpeningSecret> {
        inputs
            .iter()
            .map(|i| match i {
                OpeningInput::Ecdh { controller, .. } => {
                    answer_with_identity(&self.ids[controller], i).unwrap()
                }
                OpeningInput::Prf { salt, .. } => OpeningSecret::Prf(self.prf(salt)),
            })
            .collect()
    }
    /// A member's ECDH for each share the account asks for.
    pub fn answer_epochs(&self, member: &str, steps: Vec<EpochAgreement>) -> Vec<EpochSecret> {
        steps
            .into_iter()
            .map(|s| EpochSecret {
                shared: self.ids[member].agree(&s.peer).unwrap(),
                step: s,
            })
            .collect()
    }
}

pub fn run(a: &mut Account, host: &Host, action: PendingAction) -> Finished {
    let sigs = host.sign(action.steps());
    a.finish(action, sigs).unwrap()
}

pub struct Fixture {
    pub host: Host,
    pub d: String,
    pub p: String,
    pub k: String,
    pub account: Account,
}

pub fn params(host: &mut Host, d: &str, p: &str, k: &str, namespaces: &[&str]) -> CreateParams {
    CreateParams {
        label: "Mike's account".into(),
        namespaces: namespaces.iter().map(|s| s.to_string()).collect(),
        controllers: vec![
            host.raw_controller(d, "Mac", &["approve", "control"]),
            host.passkey_controller("Passkey", &["approve", "control", "recover"]),
            host.raw_controller(k, "Kit", &["recover"]),
        ],
        slots: vec![
            SlotPlan {
                controllers: vec![d.to_string()],
                label: "Mac".into(),
            },
            SlotPlan {
                controllers: vec![k.to_string()],
                label: "Kit".into(),
            },
            SlotPlan {
                controllers: vec![p.to_string()],
                label: "Passkey".into(),
            },
            SlotPlan {
                controllers: vec![d.to_string(), p.to_string()],
                label: "Mac and passkey".into(),
            },
        ],
        threshold: None,
        recover_threshold: None,
        add_threshold: None,
        count_by_holders: false,
        policy: Some({
            let mut p = default_policy();
            p["recoveryDelay"] = json!(3600);
            p
        }),
        signers: vec![d.to_string()],
        rekey_signers: vec![d.to_string()],
        vault_seed: host.fresh(),
        entropy: host.fresh(),
        epoch_seed: host.fresh(),
    }
}

/// Create the account of the journeys: a device key, a passkey and a recovery kit; four slots
/// (sealed, sealed, prf, combined).
pub fn create(namespaces: &[&str]) -> Fixture {
    create_v(namespaces, 0)
}
/// The same, with every key different (`v`): another account.
pub fn create_v(namespaces: &[&str], v: u8) -> Fixture {
    let mut host = Host::new();
    host.counter = v.wrapping_mul(50);
    let d = host.identity(10 + v);
    let k = host.kit(20 + v);
    let p = host.passkey();
    let params = params(&mut host, &d, &p, &k, namespaces);
    let mut creation = Creation::begin(params, Identity::Controller(d.clone()), T0).unwrap();
    assert_eq!(
        creation.prf_requests().len(),
        2,
        "a prf slot and a combined slot"
    );
    let results = host.answer_prf(creation.prf_requests());
    creation = creation.provide_prf(results).unwrap();
    let sigs = host.sign(creation.steps());
    let mut progress = creation.provide_signatures(sigs).unwrap();
    loop {
        match progress {
            CreateProgress::Continue(c) => {
                let sigs = host.sign(c.steps());
                progress = c.provide_signatures(sigs).unwrap();
            }
            CreateProgress::Done(account) => {
                return Fixture {
                    host,
                    d,
                    p,
                    k,
                    account: *account,
                }
            }
        }
    }
}

pub fn terms(access: &str) -> Value {
    json!({"records": [{"namespace": "notes", "access": access}]})
}

// ---------------------------------------------------------------------------------------------
// Create and unlock.
pub fn request_for(
    f: &Fixture,
    host: &Host,
    member: &str,
    label: &str,
    kind: &str,
    terms: Value,
    created_ms: i64,
) -> AccessRequest {
    let p = host.ids[member].public();
    let created = colophon_core::v05::write::format_date(created_ms);
    let prepared = prepare_request(&RequestSpec {
        account: f.account.id(),
        signing: &p.signing,
        agreement: &p.agreement,
        label,
        kind,
        terms,
        created: &created,
        custody: None,
        operator: None,
        endpoints: None,
    })
    .unwrap();
    let sig = SignatureResult {
        signature: host.ids[member].sign(prepared.step().body()).to_vec(),
        assertion: None,
    };
    finish_request(&prepared, &sig).unwrap()
}

/// Admit `member` with `granted` terms, signed by the device key.
pub fn admit(f: &mut Fixture, member: &str, label: &str, kind: &str, asked: Value, granted: Value) {
    let host = &f.host;
    let req = request_for(f, host, member, label, kind, asked, f.account.now_ms());
    let seed = f.host.fresh();
    let action = f
        .account
        .begin_approve(&req.raw, granted, &[f.d.clone()], seed)
        .unwrap();
    run(&mut f.account, &f.host, action);
}

pub fn agent_terms(access: &str) -> Value {
    json!({"records": [{"namespace": "notes", "access": access}],
           "expires": colophon_core::v05::write::format_date(T0 + 7 * 24 * HOUR)})
}

/// A member's session: opened from the controller's objects and unlocked through its shares.
pub fn member_session(f: &Fixture, member: &str) -> Account {
    let mut m = Account::open(
        f.account.objects().clone(),
        f.account.records().to_vec(),
        None,
        Identity::Member(member.to_string()),
        f.account.now_ms(),
    )
    .unwrap();
    let steps = m.begin_unlock_epochs();
    assert!(!steps.is_empty(), "the member holds a share");
    let results = f.host.answer_epochs(member, steps);
    m.finish_unlock_epochs(results).unwrap();
    m
}

pub fn unlock_controller(host: &Host, a: &mut Account, id: &str) {
    let idx = a
        .slots()
        .unwrap()
        .into_iter()
        .find(|o| o.controllers.len() == 1 && o.controllers[0].0 == id)
        .unwrap()
        .index;
    let inputs = a.begin_unlock_slot(idx).unwrap();
    a.finish_unlock_slot(idx, &host.answer_unlock(&inputs))
        .unwrap();
}
pub fn merge_done(a: &mut Account, done: &Finished, now: i64) -> Changes {
    a.merge(
        Incoming {
            objects: Objects {
                entries: done.entries.iter().map(|(_, e)| e.clone()).collect(),
                pending: done.pending.clone(),
                ..Default::default()
            },
            records: done.records.clone(),
        },
        now,
    )
    .unwrap()
}

// ---------------------------------------------------------------------------------------------
// An in-memory record source.

use colophon_core::v05::engine::RecordSource;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Inner {
    files: BTreeMap<String, Vec<u8>>,
    versions: BTreeMap<String, u64>,
    versioned: bool,
    reads: u64,
}
/// Host storage the engine reads from: clonable, so a test keeps a handle while the engine
/// owns another.
#[derive(Clone, Default)]
pub struct MemSource {
    inner: Arc<Mutex<Inner>>,
}
impl MemSource {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn versioned() -> Self {
        let s = Self::default();
        s.inner.lock().unwrap().versioned = true;
        s
    }
    pub fn put(&self, path: &str, bytes: Vec<u8>) {
        let mut i = self.inner.lock().unwrap();
        *i.versions.entry(path.to_string()).or_default() += 1;
        i.files.insert(path.to_string(), bytes);
    }
    pub fn get(&self, path: &str) -> Option<Vec<u8>> {
        self.inner.lock().unwrap().files.get(path).cloned()
    }
    pub fn remove(&self, path: &str) {
        self.inner.lock().unwrap().files.remove(path);
    }
    pub fn listing(&self) -> Vec<String> {
        self.inner.lock().unwrap().files.keys().cloned().collect()
    }
    pub fn reads(&self) -> u64 {
        self.inner.lock().unwrap().reads
    }
    /// Store what a finished action produced.
    pub fn publish(&self, f: &Finished) {
        for (p, b) in stores_of(f) {
            self.put(&p, b);
        }
    }
    pub fn publish_stores(&self, stores: &[(String, Vec<u8>)]) {
        for (p, b) in stores {
            self.put(p, b.clone());
        }
    }
    /// Store every object an account holds.
    pub fn store_account(&self, a: &Account) {
        for e in &a.objects().entries {
            self.put(&format!("authority/{:08}.json", entry_seq(e)), e.clone());
        }
        for p in &a.objects().pending {
            self.put(&pending_path(p), p.clone());
        }
        for r in a.records() {
            self.put(&r.path, r.bytes.clone());
        }
    }
}
impl RecordSource for MemSource {
    fn read(&self, path: &str) -> colophon_core::Result<Vec<u8>> {
        let mut i = self.inner.lock().unwrap();
        i.reads += 1;
        i.files
            .get(path)
            .cloned()
            .ok_or_else(|| colophon_core::Error(format!("missing {path}")))
    }
    fn content_version(&self, path: &str) -> colophon_core::Result<Option<String>> {
        let i = self.inner.lock().unwrap();
        Ok(i.versioned
            .then(|| i.versions.get(path).map(|v| v.to_string()))
            .flatten())
    }
}

pub fn stores_of(f: &Finished) -> Vec<(String, Vec<u8>)> {
    let paths = f.record_paths();
    let mut bytes: Vec<Vec<u8>> = f.entries.iter().map(|(_, b)| b.clone()).collect();
    bytes.extend(f.pending.iter().cloned());
    bytes.extend(f.records.iter().map(|r| r.bytes.clone()));
    assert_eq!(paths.len(), bytes.len());
    paths.into_iter().zip(bytes).collect()
}
pub fn entry_seq(bytes: &[u8]) -> u64 {
    let v: Value = serde_json::from_slice(bytes).unwrap();
    let body = STANDARD.decode(v["body"].as_str().unwrap()).unwrap();
    let b: Value = serde_json::from_slice(&body).unwrap();
    b["seq"].as_u64().unwrap()
}
pub fn pending_path(bytes: &[u8]) -> String {
    let v: Value = serde_json::from_slice(bytes).unwrap();
    let body = STANDARD.decode(v["body"].as_str().unwrap()).unwrap();
    let b: Value = serde_json::from_slice(&body).unwrap();
    let dir = match b["protocol"].as_str().unwrap() {
        "colophon/veto/5" => "vetoes",
        "colophon/receipt/5" => {
            return format!(
                "receipts/{}/{}.receipt.json",
                b["object"].as_str().unwrap(),
                b["by"].as_str().unwrap()
            )
        }
        _ => "transitions",
    };
    format!("{dir}/{}.json", digest(&body))
}

pub fn terms_for(namespaces: &[(&str, &str)]) -> Value {
    json!({"records": namespaces.iter().map(|(n, a)| json!({"namespace": n, "access": a})).collect::<Vec<_>>()})
}

/// A fixed-seed shuffle (xorshift).
pub fn shuffled<T: Clone>(items: &[T], mut seed: u64) -> Vec<T> {
    let mut v = items.to_vec();
    for i in (1..v.len()).rev() {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        v.swap(i, (seed % (i as u64 + 1)) as usize);
    }
    v
}
