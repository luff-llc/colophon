//! The 0.5 account (`v05::account`): the 0.4 library journeys ported, the attacks each security
//! property needs, and the order-independence and resume properties.
//!
//! The host's side of the interface lives here: it holds every private key (software identities
//! and a synthetic WebAuthn authenticator, `keys/testing.rs`), signs exactly the bodies the steps
//! carry, answers the slot routes the account asks for, and does the ECDH a member's shares need.
//! Nothing in this file shares encoding code with the vector generator.
#![allow(clippy::unwrap_used)]
use base64::{engine::general_purpose::STANDARD, Engine};
use colophon_core::keys::testing::SyntheticAuthenticator;
use colophon_core::v05::account::*;
use colophon_core::v05::encoding::{canonical, digest};
use colophon_core::v05::history::{Objects, Persisted};
use colophon_core::v05::ids::key_id;
use colophon_core::v05::pairing::{
    ExistingWaiting, FailureLimiter, Joiner, TransferKey,
};
use colophon_core::v05::records::{HeldRecord, Level};
use colophon_core::v05::slots::{
    answer_with_identity, OpeningInput, OpeningSecret, PrfAssertion, PrfRequest, PrfResult,
    SlotPlan,
};
use colophon_core::v05::vault::{kit_identity, EcdhOutput, PrfOutput, SoftwareIdentity};
use colophon_core::v05::write::authority::TransitionRule;
use colophon_core::v05::write::calls::RequestSpec;
use colophon_core::v05::write::{SignatureResult, SigningStep};
use colophon_core::v05::{Failure, Reason};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const T0: i64 = 1_794_384_000_000; // 2026-11-11T08:00:00Z
const SEC: i64 = 1_000;
const HOUR: i64 = 3_600 * SEC;
const RP: &str = "id.luff.works";
const ORIGIN: &str = "https://id.luff.works";

fn b64(b: &[u8]) -> String {
    STANDARD.encode(b)
}

// ---------------------------------------------------------------------------------------------
// The host.

struct Host {
    ids: BTreeMap<String, SoftwareIdentity>,
    passkey: Option<(SyntheticAuthenticator, String)>,
    counter: u8,
}
impl Host {
    fn new() -> Self {
        Self {
            ids: BTreeMap::new(),
            passkey: None,
            counter: 0,
        }
    }
    /// A software identity from a fixed byte: its ID.
    fn identity(&mut self, n: u8) -> String {
        let i = SoftwareIdentity::from_seed(&[n; 32]).unwrap();
        let id = i.id();
        self.ids.insert(id.clone(), i);
        id
    }
    fn kit(&mut self, n: u8) -> String {
        let i = kit_identity(&[n; 32]).unwrap();
        let id = i.id();
        self.ids.insert(id.clone(), i);
        id
    }
    fn passkey(&mut self) -> String {
        let a = SyntheticAuthenticator::new().unwrap();
        let point = {
            let sk = p256::ecdsa::SigningKey::from_slice(&[1; 32]).unwrap();
            sk.verifying_key().to_encoded_point(false).as_bytes().to_vec()
        };
        let id = key_id(&point);
        self.passkey = Some((a, id.clone()));
        id
    }
    fn raw_controller(&self, id: &str, label: &str, roles: &[&str]) -> Value {
        let p = self.ids[id].public();
        json!({"key": {"form": "raw", "signing": b64(&p.signing), "agreement": b64(&p.agreement)},
               "label": label, "roles": roles})
    }
    fn passkey_controller(&self, label: &str, roles: &[&str]) -> Value {
        let sk = p256::ecdsa::SigningKey::from_slice(&[1; 32]).unwrap();
        let point = sk.verifying_key().to_encoded_point(false).as_bytes().to_vec();
        json!({"key": {"form": "webauthn", "signing": b64(&point), "rp": RP, "credential": "AQ=="},
               "label": label, "roles": roles, "verification": true})
    }
    fn fresh(&mut self) -> [u8; 32] {
        self.counter += 1;
        [self.counter; 32]
    }
    fn sign(&self, steps: &[SigningStep]) -> Vec<SignatureResult> {
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
    fn prf(&self, salt: &[u8]) -> PrfOutput {
        let mut h = Sha256::new();
        h.update(b"test-prf");
        h.update(salt);
        PrfOutput::from_host(&h.finalize()).unwrap()
    }
    fn answer_prf(&self, reqs: &[PrfRequest]) -> Vec<PrfResult> {
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
    fn answer_unlock(&self, inputs: &[OpeningInput]) -> Vec<OpeningSecret> {
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
    fn answer_epochs(&self, member: &str, steps: Vec<EpochAgreement>) -> Vec<EpochSecret> {
        steps
            .into_iter()
            .map(|s| EpochSecret {
                shared: self.ids[member].agree(&s.peer).unwrap(),
                step: s,
            })
            .collect()
    }
}

fn run(a: &mut Account, host: &Host, action: PendingAction) -> Finished {
    let sigs = host.sign(action.steps());
    a.finish(action, sigs).unwrap()
}
fn run_err(a: &mut Account, host: &Host, action: PendingAction) -> Failure {
    let sigs = host.sign(action.steps());
    a.finish(action, sigs).unwrap_err()
}

struct Fixture {
    host: Host,
    d: String,
    p: String,
    k: String,
    account: Account,
}

fn params(host: &mut Host, d: &str, p: &str, k: &str, namespaces: &[&str]) -> CreateParams {
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
fn create(namespaces: &[&str]) -> Fixture {
    create_v(namespaces, 0)
}
/// The same, with every key different (`v`): another account.
fn create_v(namespaces: &[&str], v: u8) -> Fixture {
    let mut host = Host::new();
    host.counter = v.wrapping_mul(50);
    let d = host.identity(10 + v);
    let k = host.kit(20 + v);
    let p = host.passkey();
    let params = params(&mut host, &d, &p, &k, namespaces);
    let mut creation = Creation::begin(params, Identity::Controller(d.clone()), T0).unwrap();
    assert_eq!(creation.prf_requests().len(), 2, "a prf slot and a combined slot");
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

fn terms(access: &str) -> Value {
    json!({"records": [{"namespace": "notes", "access": access}]})
}

// ---------------------------------------------------------------------------------------------
// Create and unlock.

#[test]
fn create_makes_an_unlocked_account_with_a_passkey_a_device_and_a_kit() {
    let f = create(&["notes"]);
    let a = &f.account;
    assert_eq!(a.status().code, "ok");
    assert_eq!(a.status().seq, 2, "genesis and the first rekey");
    assert!(a.is_unlocked());
    let ctl: BTreeSet<String> = a.controllers().into_iter().map(|c| c.id).collect();
    assert_eq!(ctl, [f.d.clone(), f.p.clone(), f.k.clone()].into_iter().collect());
    assert_eq!(a.slots().unwrap().len(), 4);
    assert!(a.controllers().iter().all(|c| c.has_slot));
    assert_eq!(a.latest_epoch("notes"), 1);
    let v = a.view("notes").unwrap();
    assert!(matches!(v, colophon_core::model::Outcome::Success { .. }));
    let p = a.policy();
    assert_eq!((p.threshold, p.recover_threshold, p.add_threshold), (1, 1, 1));
}

#[test]
fn a_fresh_open_is_locked_and_each_slot_kind_unlocks_it() {
    let f = create(&["notes"]);
    let objects = f.account.objects().clone();
    let kinds: Vec<String> = f.account.slots().unwrap().into_iter().map(|s| s.kind).collect();
    assert_eq!(kinds, ["sealed", "sealed", "prf", "combined"].map(String::from));
    for index in 0..4 {
        let mut a = Account::open(
            objects.clone(),
            vec![],
            None,
            Identity::Controller(f.d.clone()),
            T0,
        )
        .unwrap();
        assert!(!a.is_unlocked());
        // Locked: the namespace is not readable.
        assert!(matches!(
            a.view("notes").unwrap(),
            colophon_core::model::Outcome::Failure { ref reason, .. } if reason == "notReadable"
        ));
        let inputs = a.begin_unlock_slot(index).unwrap();
        let secrets = f.host.answer_unlock(&inputs);
        a.finish_unlock_slot(index, &secrets).unwrap();
        assert!(a.is_unlocked(), "slot {index}");
        assert!(matches!(
            a.view("notes").unwrap(),
            colophon_core::model::Outcome::Success { .. }
        ));
    }
}

#[test]
fn a_wrong_secret_is_vault_locked_and_changes_nothing() {
    let f = create(&["notes"]);
    let mut a = Account::open(
        f.account.objects().clone(),
        vec![],
        None,
        Identity::Controller(f.d.clone()),
        T0,
    )
    .unwrap();
    // The prf slot with the wrong PRF output.
    let inputs = a.begin_unlock_slot(2).unwrap();
    let wrong: Vec<OpeningSecret> = inputs
        .iter()
        .map(|_| OpeningSecret::Prf(PrfOutput::from_host(&[9; 32]).unwrap()))
        .collect();
    let before = a.status();
    let e = a.finish_unlock_slot(2, &wrong).unwrap_err();
    assert_eq!(e, Failure::Refused(Reason::VaultLocked));
    assert!(!a.is_unlocked());
    assert_eq!(a.status(), before);
    // The right device slot opened with the kit's identity (not a controller of that slot).
    let inputs = a.begin_unlock_slot(0).unwrap();
    let mut other = Host::new();
    other.kit(77);
    let answers: Vec<OpeningSecret> = inputs
        .iter()
        .map(|i| match i {
            OpeningInput::Ecdh { controller, .. } => {
                // A different identity under the same slot: the answer is refused by the core.
                answer_with_identity(&other.ids[&other.ids.keys().next().unwrap().clone()], i)
                    .unwrap_or_else(|_| {
                        let _ = controller;
                        OpeningSecret::Ecdh(EcdhOutput::from_host(&[3; 32]).unwrap())
                    })
            }
            OpeningInput::Prf { .. } => unreachable!(),
        })
        .collect();
    assert_eq!(
        a.finish_unlock_slot(0, &answers).unwrap_err(),
        Failure::Refused(Reason::VaultLocked)
    );
    assert!(!a.is_unlocked());
}

#[test]
fn secrets_never_appear_in_debug_or_serialization() {
    let f = create(&["notes"]);
    let text = format!("{:?}", f.account);
    assert!(text.starts_with("Account("));
    assert!(!text.contains("seed:"), "{text}");
    // The persisted state and the held objects are public bytes; neither names a seed or key.
    let mut a = f.account;
    let persisted = a.export_persisted().unwrap();
    let text = String::from_utf8_lossy(&persisted).to_lowercase();
    assert!(!text.contains("\"seed\""));
    assert!(!text.contains("epoch_key"));
    assert!(!text.contains("scalar"));
}

// ---------------------------------------------------------------------------------------------
// Members: request, approve, write, read, merge.

fn request_for(
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
fn admit(f: &mut Fixture, member: &str, label: &str, kind: &str, asked: Value, granted: Value) {
    let host = &f.host;
    let req = request_for(f, host, member, label, kind, asked, f.account.now_ms());
    let seed = f.host.fresh();
    let action = f
        .account
        .begin_approve(&req.raw, granted, &[f.d.clone()], seed)
        .unwrap();
    run(&mut f.account, &f.host, action);
}

fn agent_terms(access: &str) -> Value {
    json!({"records": [{"namespace": "notes", "access": access}],
           "expires": colophon_core::v05::write::format_date(T0 + 7 * 24 * HOUR)})
}

/// A member's session: opened from the controller's objects and unlocked through its shares.
fn member_session(f: &Fixture, member: &str) -> Account {
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

fn write_note(m: &mut Account, host: &mut Host, id: &str, title: &str) -> Finished {
    let seed = host.fresh();
    let action = m
        .begin_write(
            "notes",
            "createNotebook",
            json!({"id": id, "title": title}),
            Level::Write,
            seed,
        )
        .unwrap()
        .unwrap();
    run(m, host, action)
}

#[test]
fn approve_an_agent_it_writes_and_a_reader_reads() {
    let mut f = create(&["notes"]);
    let agent = f.host.identity(30);
    let reader = f.host.identity(40);
    admit(&mut f, &agent, "Claude", "agent", agent_terms("write"), agent_terms("write"));
    admit(&mut f, &reader, "Viewer", "app", terms("read"), terms("read"));
    assert_eq!(f.account.status().seq, 4);
    // The grant carried shares: each member opens epoch 1 with its own agreement key.
    let mut a = member_session(&f, &agent);
    let mut host = std::mem::replace(&mut f.host, Host::new());
    let wrote = write_note(&mut a, &mut host, "b1", "Plans");
    f.host = host;
    assert_eq!(wrote.records.len(), 1);
    assert!(wrote.changes.namespaces.contains_key("notes"));
    let view = match a.view("notes").unwrap() {
        colophon_core::model::Outcome::Success { value, .. } => value,
        other => panic!("{other:?}"),
    };
    assert_eq!(view.admitted.len(), 1);
    assert_eq!(view.admitted[0].origin, "ai", "an agent's records are attributed to AI");
    assert_eq!(view.admitted[0].author_label, "Claude");
    // The controller merges the agent's record and reads it; a reader reads it too.
    let ch = f
        .account
        .merge(
            Incoming {
                objects: Objects::default(),
                records: wrote.records.clone(),
            },
            f.account.now_ms(),
        )
        .unwrap();
    assert!(ch.namespaces.contains_key("notes"), "{ch:?}");
    let got = f
        .account
        .query("notes", "notebooks", json!({}))
        .unwrap();
    assert!(format!("{got:?}").contains("Plans"), "{got:?}");
    let mut r = member_session(&f, &reader);
    assert!(format!("{:?}", r.query("notes", "notebooks", json!({})).unwrap()).contains("Plans"));
    // A reader may not write: refused before a host is asked to sign.
    let seed = f.host.fresh();
    let denied = r
        .begin_write("notes", "createNotebook", json!({"id": "x", "title": "X"}), Level::Write, seed)
        .unwrap();
    assert_eq!(denied.unwrap_err().reason, "notGranted");
    // The members list counts admitted writes by authority, not counters.
    let m = f.account.members();
    assert_eq!(
        m.iter().find(|m| m.member.id == agent).unwrap().member.writes,
        1
    );
    let _ = &mut r;
}

#[test]
fn a_merged_record_of_another_account_does_not_mix() {
    let mut f1 = create(&["notes"]);
    let mut f2 = create_v(&["notes"], 1);
    let agent = f1.host.identity(30);
    admit(&mut f1, &agent, "Claude", "agent", agent_terms("write"), agent_terms("write"));
    let mut a = member_session(&f1, &agent);
    let mut host = std::mem::replace(&mut f1.host, Host::new());
    let wrote = write_note(&mut a, &mut host, "b1", "Plans");
    f1.host = host;
    // Account 2 is a different account (a different vault, different genesis time seeds are
    // the same fixtures, so only the ID differs).
    assert_ne!(f1.account.id(), f2.account.id(), "two creations, two accounts");
    let before = f2.account.status();
    let ch = f2
        .account
        .merge(
            Incoming {
                objects: f1.account.objects().clone(),
                records: wrote.records.clone(),
            },
            f2.account.now_ms(),
        )
        .unwrap();
    // The other account's entries do not extend this history; its records are not admitted.
    assert_eq!(ch.foreign, 1, "the other account's genesis is ignored");
    assert_eq!(f2.account.status().seq, before.seq);
    assert!(ch.namespaces.is_empty());
    let view = match f2.account.view("notes").unwrap() {
        colophon_core::model::Outcome::Success { value, .. } => value,
        other => panic!("{other:?}"),
    };
    assert!(view.admitted.is_empty());
    assert!(!view.refused.is_empty(), "the foreign header is refused: {view:?}");
    // And a prepared action of one account is refused by the other at finish.
    let seed = f1.host.fresh();
    let action = f1
        .account
        .begin_rekey(&["notes".to_string()], &[f1.d.clone()], seed)
        .unwrap();
    let sigs = f1.host.sign(action.steps());
    assert!(f2.account.finish(action, sigs).is_err());
}
