//! The host side of the 0.5 journeys: software and synthetic-WebAuthn keys, an account creation
//! fixture, an in-memory record source, a simulated home.
#![allow(
    dead_code,
    unused_imports,
    clippy::unwrap_used,
    clippy::cloned_ref_to_slice_refs,
    clippy::too_many_arguments
)]
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
    pub counter: u32,
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
        let mut seed = [self.counter as u8; 32];
        seed[..4].copy_from_slice(&self.counter.to_le_bytes());
        seed
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
    host.counter = u32::from(v) * 50;
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
    fn read_blob(&self, path: &str) -> colophon_core::Result<colophon_core::blobs::BlobRead> {
        let i = self.inner.lock().unwrap();
        Ok(i.files.get(path).cloned().map_or(
            colophon_core::blobs::BlobRead::Missing,
            colophon_core::blobs::BlobRead::Available,
        ))
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

// ---------------------------------------------------------------------------------------------
// A simulated home: the relay's wire (0.3 §8, 0.5 §14) over `history::home` admission.

use colophon_core::v05::engine::exchange::{Fault, Method, Request, Response, Step};
use colophon_core::v05::engine::Engine as AccountEngine;
use colophon_core::v05::history::home::{
    admit as home_admit, admit_pending_batch, HomeState, ServingInterval,
};
use colophon_core::v05::write::calls::prepare_receipt;
use colophon_core::v05::write::format_date;

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub trait Wire {
    fn call(&mut self, host: &Host, req: &Request, now_ms: i64) -> Response;
}

#[derive(Clone)]
pub struct SimHome {
    pub id: String,
    pub base: String,
    pub state: HomeState,
    pub entries: BTreeMap<u64, Vec<u8>>,
    pub files: BTreeMap<String, Vec<u8>>,
    /// The change log, in the order the home accepted each path (a replacement appears again).
    pub log: Vec<String>,
    pub requests: Vec<String>,
    pub account: String,
}
fn resp(status: u16, body: Value) -> Response {
    Response {
        status,
        headers: vec![],
        body: serde_json::to_vec(&body).unwrap(),
    }
}
fn bytes_resp(status: u16, body: Vec<u8>) -> Response {
    Response {
        status,
        headers: vec![],
        body,
    }
}
fn q_get(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == key).then(|| v.to_string())
    })
}
impl SimHome {
    /// A home that holds the history `f.account` holds now.
    pub fn new(f: &Fixture, home: &str, base: &str, now_ms: i64) -> Self {
        let state = HomeState::new(
            home.to_string(),
            f.account.objects(),
            vec![ServingInterval {
                from_ms: 0,
                through_ms: None,
            }],
            now_ms,
        )
        .unwrap();
        let mut entries = BTreeMap::new();
        for e in &f.account.objects().entries {
            entries.insert(entry_seq(e), e.clone());
        }
        let mut files = BTreeMap::new();
        let mut log = Vec::new();
        for (s, e) in &entries {
            let p = format!("authority/{s:08}.json");
            files.insert(p.clone(), e.clone());
            log.push(p);
        }
        Self {
            id: home.to_string(),
            base: base.trim_end_matches('/').to_string(),
            state,
            entries,
            files,
            log,
            requests: Vec::new(),
            account: f.account.id().as_str().to_string(),
        }
    }
    pub fn head_seq(&self) -> u64 {
        self.entries.keys().max().copied().unwrap_or(0)
    }
    fn head_env(&self, host: &Host, now_ms: i64) -> Option<Vec<u8>> {
        let seq = self.head_seq();
        if seq == 0 {
            return None;
        }
        let e = &self.entries[&seq];
        let v: Value = serde_json::from_slice(e).unwrap();
        let body = STANDARD.decode(v["body"].as_str().unwrap()).unwrap();
        let body = canonical(&json!({
            "protocol": "colophon/head/5", "account": self.account,
            "authority": {"seq": seq, "digest": digest(&body)}, "by": self.id,
            "issued": format_date(now_ms),
        }))
        .unwrap();
        Some(
            canonical(
                &json!({"body": b64(&body), "signature": b64(&host.ids[&self.id].sign(&body))}),
            )
            .unwrap(),
        )
    }
    fn sign_receipts(
        &mut self,
        host: &Host,
        reqs: Vec<colophon_core::v05::history::home::ReceiptToSign>,
        now_ms: i64,
    ) -> Vec<Value> {
        let now = format_date(now_ms);
        let mut out = Vec::new();
        for r in reqs {
            let prepared = prepare_receipt(&r).unwrap();
            let sig = SignatureResult {
                signature: host.ids[&self.id].sign(prepared.step().body()).to_vec(),
                assertion: None,
            };
            if let Ok((env, next)) =
                colophon_core::v05::write::calls::finish_receipt(&self.state, &prepared, &sig, &now)
            {
                self.state = next;
                out.push(serde_json::from_slice(&env).unwrap());
            }
        }
        out
    }
    fn store(&mut self, path: &str, bytes: Vec<u8>) {
        self.files.insert(path.to_string(), bytes);
        self.log.push(path.to_string());
    }
}
impl Wire for SimHome {
    fn call(&mut self, host: &Host, req: &Request, now_ms: i64) -> Response {
        let rest = req
            .url
            .strip_prefix(&self.base)
            .expect("another home's URL");
        let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
        self.requests.push(format!("{:?} {}", req.method, path));
        let now = format_date(now_ms);
        match (req.method, path) {
            (Method::Get, "/head") => match self.head_env(host, now_ms) {
                Some(h) => bytes_resp(200, h),
                None => resp(404, json!({})),
            },
            (Method::Get, "/authority") => {
                let after: u64 = q_get(query, "after")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                let limit: usize = q_get(query, "limit")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(64);
                let all: Vec<&Vec<u8>> = self.entries.range(after + 1..).map(|(_, e)| e).collect();
                let page: Vec<Value> = all
                    .iter()
                    .take(limit.min(64))
                    .map(|e| serde_json::from_slice(e).unwrap())
                    .collect();
                resp(
                    200,
                    json!({"entries": page, "receipts": [], "more": all.len() > limit.min(64)}),
                )
            }
            (Method::Post, "/authority") => {
                let v: Value = serde_json::from_slice(&req.body).unwrap();
                let mut receipts = Vec::new();
                for e in v["entries"].as_array().unwrap() {
                    let b = canonical(e).unwrap();
                    let a = home_admit(&self.state, &b, &now);
                    self.state = a.state.clone();
                    match a.result {
                        Ok(()) => {
                            let seq = entry_seq(&b);
                            self.entries.entry(seq).or_insert_with(|| b.clone());
                            let p = format!("authority/{seq:08}.json");
                            if !self.files.contains_key(&p) {
                                self.store(&p, b);
                            }
                            receipts.extend(self.sign_receipts(host, a.receipts, now_ms));
                        }
                        Err(colophon_core::v05::history::home::Refusal::Conflict) => {
                            let h = self
                                .head_env(host, now_ms)
                                .map(|h| serde_json::from_slice::<Value>(&h).unwrap())
                                .unwrap_or(json!({}));
                            return resp(409, h);
                        }
                        Err(colophon_core::v05::history::home::Refusal::PrimaryRequired(eps)) => {
                            return resp(421, json!({"endpoints": eps}));
                        }
                        Err(r) => return resp(422, json!({"result": r.code()})),
                    }
                }
                let head = self
                    .head_env(host, now_ms)
                    .map(|h| serde_json::from_slice::<Value>(&h).unwrap());
                resp(200, json!({"head": head, "receipts": receipts}))
            }
            (Method::Get, "/pending") => {
                let after: u64 = q_get(query, "after")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                let limit: usize = q_get(query, "limit")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(64);
                let page = self
                    .state
                    .pending_page(after, limit.min(64), now_ms)
                    .unwrap();
                resp(
                    200,
                    json!({
                        "objects": page.objects.iter().map(|o| json!({"seq": o.seq, "digest": o.digest, "kind": o.kind, "envelope": serde_json::from_slice::<Value>(&o.envelope).unwrap()})).collect::<Vec<_>>(),
                        "more": page.more,
                    }),
                )
            }
            (Method::Post, "/pending") => {
                let v: Value = serde_json::from_slice(&req.body).unwrap();
                let objs: Vec<Vec<u8>> = v["objects"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|o| canonical(o).unwrap())
                    .collect();
                let (next, results, receipts) =
                    admit_pending_batch(&self.state, &objs, &now).unwrap();
                self.state = next;
                let refused: Vec<Value> = results
                    .iter()
                    .filter_map(|r| r.as_ref().err().map(|e| json!(e.code())))
                    .collect();
                if !refused.is_empty() {
                    return resp(422, json!(refused));
                }
                let rs = self.sign_receipts(host, receipts, now_ms);
                resp(200, json!({"receipts": rs}))
            }
            (Method::Get, "/changes") => {
                let after: usize = q_get(query, "after")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                let limit: usize = q_get(query, "limit")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(500)
                    .min(500);
                if after > self.log.len() {
                    return resp(410, json!({}));
                }
                let slice = &self.log[after..];
                let page: Vec<&String> = slice.iter().take(limit).collect();
                let entries: Vec<Value> = page.iter().map(|p| json!({"path": p, "size": self.files[*p].len(), "sha256": hex(&Sha256::digest(&self.files[*p]))})).collect();
                resp(
                    200,
                    json!({"entries": entries, "cursor": (after + page.len()).to_string(), "more": slice.len() > limit}),
                )
            }
            (Method::Get, p) if p.starts_with("/records/") => {
                let rec = &p["/records/".len()..];
                match self.files.get(rec) {
                    Some(b) => bytes_resp(200, b.clone()),
                    None => resp(404, json!({})),
                }
            }
            (Method::Put, p) if p.starts_with("/records/") => {
                let rec = p["/records/".len()..].to_string();
                let h = |k: &str| {
                    req.headers
                        .iter()
                        .find(|(n, _)| n.eq_ignore_ascii_case(k))
                        .map(|(_, v)| v.clone())
                };
                if let Some(name) = rec.strip_prefix("blobs/") {
                    if hex(&Sha256::digest(&req.body)) != name {
                        return resp(400, json!({}));
                    }
                }
                let live = rec.starts_with("state/");
                match (
                    self.files.get(&rec).cloned(),
                    h("If-None-Match"),
                    h("If-Match"),
                ) {
                    (None, Some(_), None) => {
                        self.store(&rec, req.body.clone());
                        resp(201, json!({}))
                    }
                    (Some(old), Some(_), None) if !live => {
                        if old == req.body {
                            resp(200, json!({}))
                        } else {
                            resp(412, json!({}))
                        }
                    }
                    (Some(old), None, Some(m)) if live => {
                        if format!("\"{}\"", hex(&Sha256::digest(&old))) == m {
                            self.store(&rec, req.body.clone());
                            resp(200, json!({}))
                        } else {
                            resp(412, json!({}))
                        }
                    }
                    (Some(old), Some(_), None) if live => {
                        if old == req.body {
                            resp(200, json!({}))
                        } else {
                            resp(412, json!({}))
                        }
                    }
                    _ => resp(428, json!({})),
                }
            }
            _ => resp(404, json!({})),
        }
    }
}

/// Run one full pass of `e` with `home` over `wire`; the engine's stores go to `src`.
pub fn sync_pass<S: RecordSource>(
    e: &mut AccountEngine<S>,
    src: &MemSource,
    home: &str,
    wire: &mut dyn Wire,
    host: &Host,
    now_ms: i64,
) -> Vec<Fault> {
    let mut faults = Vec::new();
    // The host lists its store before a pass (it wrote chunks and evidence the engine did not
    // read), then the pass exchanges.
    e.advance(now_ms).unwrap();
    e.refresh(src.listing()).unwrap();
    for _ in 0..10_000 {
        match e.exchange_next(home).unwrap() {
            Step::Done => return faults,
            Step::Waiting => panic!("the loop answers every request"),
            Step::Request(r) => {
                let a = wire.call(host, &r, now_ms);
                let report = e.exchange_answer(home, r.ticket, a).unwrap();
                for (p, b) in report.store {
                    src.put(&p, b);
                }
                faults.extend(report.faults);
            }
        }
    }
    panic!("a pass did not end");
}

// ---------------------------------------------------------------------------------------------
// Journeys: homes, engines for members and controllers, writes through an engine.

use colophon_core::v05::engine::EngineOptions as AccountEngineOptions;

pub const DEVICE_KEY: [u8; 32] = [0x77; 32];

/// Appoint a home (a transition recorded at once: there is no home yet to witness time).
pub fn appoint_home(f: &mut Fixture) -> String {
    let h = f.host.identity(70);
    let p = f.host.ids[&h].public();
    let created = format_date(f.account.now_ms());
    let prepared = prepare_request(&RequestSpec {
        account: f.account.id(),
        signing: &p.signing,
        agreement: &p.agreement,
        label: "Home",
        kind: "server",
        terms: json!({"serves": ["home"]}),
        created: &created,
        custody: None,
        operator: None,
        endpoints: Some(vec!["https://home.example/".into()]),
    })
    .unwrap();
    let sig = SignatureResult {
        signature: f.host.ids[&h].sign(prepared.step().body()).to_vec(),
        assertion: None,
    };
    let req = finish_request(&prepared, &sig).unwrap();
    let change = Change::homes(
        json!({"appoint": [{"request": b64(&req.raw), "terms": {"serves": ["home"]}}]}),
    );
    let action = f
        .account
        .begin_transition(
            &change,
            &[f.d.clone(), f.k.clone()],
            TransitionRule::Control,
        )
        .unwrap();
    run(&mut f.account, &f.host, action);
    let rec = f.account.record_due().unwrap();
    assert_eq!(rec.len(), 1);
    h
}

/// A member's engine over `src`: opened, unlocked by its shares, records loaded.
pub fn member_engine(
    f: &Fixture,
    host: &Host,
    src: &MemSource,
    member: &str,
    now_ms: i64,
) -> AccountEngine<MemSource> {
    let mut e = AccountEngine::open(
        src.clone(),
        src.listing(),
        Identity::Member(member.to_string()),
        AccountEngineOptions::new(f.account.id().as_str(), DEVICE_KEY),
        None,
        now_ms,
    )
    .unwrap();
    let steps = e.begin_unlock_epochs();
    let results = host.answer_epochs(member, steps);
    e.finish_unlock_epochs(results).unwrap();
    e
}

/// A controller's engine over `src`, unlocked through its own device slot.
pub fn controller_engine(
    f: &Fixture,
    host: &Host,
    src: &MemSource,
    id: &str,
    now_ms: i64,
) -> AccountEngine<MemSource> {
    let mut e = AccountEngine::open(
        src.clone(),
        src.listing(),
        Identity::Controller(id.to_string()),
        AccountEngineOptions::new(f.account.id().as_str(), DEVICE_KEY),
        None,
        now_ms,
    )
    .unwrap();
    let idx = e
        .slots()
        .unwrap()
        .into_iter()
        .find(|o| o.controllers.len() == 1 && o.controllers[0].0 == id)
        .unwrap()
        .index;
    let inputs = e.begin_unlock_slot(idx).unwrap();
    e.finish_unlock_slot(idx, &host.answer_unlock(&inputs))
        .unwrap();
    e
}

/// Write one operation through an engine and store what it returns in `src`.
pub fn engine_write(
    e: &mut AccountEngine<MemSource>,
    host: &mut Host,
    src: &MemSource,
    ns: &str,
    kind: &str,
    payload: Value,
) -> colophon_core::v05::engine::Written {
    let seed = host.fresh();
    let action = e
        .begin_write(ns, kind, payload, Level::Write, seed)
        .unwrap()
        .unwrap();
    let sigs = host.sign(action.steps());
    let w = e.finish_write(action, sigs).unwrap();
    src.publish_stores(&w.stores);
    w
}
/// Finish any prepared action through an engine (revoke, rekey, transition...).
pub fn engine_finish(
    e: &mut AccountEngine<MemSource>,
    host: &Host,
    src: &MemSource,
    action: PendingAction,
) -> colophon_core::v05::engine::Written {
    let sigs = host.sign(action.steps());
    let w = e.finish_write(action, sigs).unwrap();
    src.publish_stores(&w.stores);
    w
}
/// A live position sample through an engine.
pub fn engine_live(
    e: &mut AccountEngine<MemSource>,
    host: &mut Host,
    src: &MemSource,
    payload: Value,
) -> colophon_core::v05::engine::live::LiveWritten {
    let seed = host.fresh();
    let pending = e
        .begin_live_write("listening.podcasts", "position", payload, seed)
        .unwrap()
        .unwrap();
    let step = pending.step();
    let sig = SignatureResult {
        signature: host.ids[step.signer()].sign(step.body()).to_vec(),
        assertion: None,
    };
    let w = e.finish_live_write(pending, sig).unwrap();
    src.publish_stores(&w.stores);
    w
}
/// Upload a blob through an engine: the ciphertext chunks go to `src`, the manifest is
/// published with `colophon.blobPublish`.
pub fn engine_blob(
    e: &mut AccountEngine<MemSource>,
    host: &mut Host,
    src: &MemSource,
    ns: &str,
    media: &str,
    bytes: &[u8],
    reference: &str,
    required: bool,
) -> colophon_core::blobs::BlobDescriptor {
    let seed = host.fresh();
    let mut writer = match e.begin_blob(ns, media.to_string(), seed).unwrap() {
        colophon_core::model::Outcome::Success { value, .. } => value,
        colophon_core::model::Outcome::Failure { reason, .. } => panic!("{reason}"),
    };
    for chunk in bytes.chunks(colophon_core::blobs::CHUNK_BYTES) {
        let (path, ct) = writer.push(chunk).unwrap();
        src.put(&path, ct);
    }
    let manifest = writer.finish().unwrap();
    let descriptor = manifest.descriptor.clone();
    let mut payload = json!({"manifest": manifest, "reference": reference});
    if required {
        payload["required"] = json!(true);
    }
    engine_write(e, host, src, ns, "colophon.blobPublish", payload);
    descriptor
}

/// An account with a home, and the home simulated.
pub struct Setup {
    pub f: Fixture,
    pub home: String,
    pub sim: SimHome,
    pub authority: MemSource,
}
pub fn setup(ns: &str, members: &[(&str, u8, &str)]) -> (Setup, Vec<String>) {
    let mut f = create(&[ns]);
    let home = appoint_home(&mut f);
    let mut ids = Vec::new();
    for (label, seed, access) in members {
        let id = f.host.identity(*seed);
        admit(
            &mut f,
            &id,
            label,
            "device",
            terms_for(&[(ns, access)]),
            terms_for(&[(ns, access)]),
        );
        ids.push(id);
    }
    let authority = MemSource::new();
    authority.store_account(&f.account);
    let sim = SimHome::new(&f, &home, "https://home.example", f.account.now_ms());
    (
        Setup {
            f,
            home,
            sim,
            authority,
        },
        ids,
    )
}
pub fn device_source(s: &Setup) -> MemSource {
    let src = MemSource::new();
    for p in s.authority.listing() {
        src.put(&p, s.authority.get(&p).unwrap());
    }
    src
}
