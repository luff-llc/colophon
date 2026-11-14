//! The 0.5 account (`v05::account`): the 0.4 library journeys ported, the attacks each security
//! property needs, and the order-independence and resume properties.
//!
//! The host's side of the interface lives here: it holds every private key (software identities
//! and a synthetic WebAuthn authenticator, `keys/testing.rs`), signs exactly the bodies the steps
//! carry, answers the slot routes the account asks for, and does the ECDH a member's shares need.
//! Nothing in this file shares encoding code with the vector generator.
#![allow(clippy::unwrap_used, clippy::cloned_ref_to_slice_refs)]
use base64::{engine::general_purpose::STANDARD, Engine};
use colophon_core::keys::testing::SyntheticAuthenticator;
use colophon_core::v05::account::*;
use colophon_core::v05::encoding::{canonical, digest};
use colophon_core::v05::history::{Objects, Persisted};

/// The host's device-held key for stored verifier state.
const KEY: [u8; 32] = [0x5a; 32];
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
            sk.verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec()
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
        let point = sk
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
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
    assert_eq!(
        ctl,
        [f.d.clone(), f.p.clone(), f.k.clone()]
            .into_iter()
            .collect()
    );
    assert_eq!(a.slots().unwrap().len(), 4);
    assert!(a.controllers().iter().all(|c| c.has_slot));
    assert_eq!(a.latest_epoch("notes"), 1);
    let v = a.view("notes").unwrap();
    assert!(matches!(v, colophon_core::model::Outcome::Success { .. }));
    let p = a.policy();
    assert_eq!(
        (p.threshold, p.recover_threshold, p.add_threshold),
        (1, 1, 1)
    );
}

#[test]
fn a_fresh_open_is_locked_and_each_slot_kind_unlocks_it() {
    let f = create(&["notes"]);
    let objects = f.account.objects().clone();
    let kinds: Vec<String> = f
        .account
        .slots()
        .unwrap()
        .into_iter()
        .map(|s| s.kind)
        .collect();
    assert_eq!(
        kinds,
        ["sealed", "sealed", "prf", "combined"].map(String::from)
    );
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
    // The device's slot, answered by a different identity's ECDH: also locked.
    let inputs = a.begin_unlock_slot(0).unwrap();
    let other = SoftwareIdentity::from_seed(&[77; 32]).unwrap();
    let answers: Vec<OpeningSecret> = inputs
        .iter()
        .map(|i| match i {
            OpeningInput::Ecdh { enc, .. } => OpeningSecret::Ecdh(other.agree(enc).unwrap()),
            OpeningInput::Prf { .. } => unreachable!(),
        })
        .collect();
    assert_eq!(
        a.finish_unlock_slot(0, &answers).unwrap_err(),
        Failure::Refused(Reason::VaultLocked)
    );
    assert!(!a.is_unlocked());
    // A slot index that does not exist.
    assert!(a.finish_unlock_slot(99, &[]).is_err());
}

#[test]
fn secrets_never_appear_in_debug_or_serialization() {
    let f = create(&["notes"]);
    let text = format!("{:?}", f.account);
    assert!(text.starts_with("Account("));
    assert!(!text.contains("seed:"), "{text}");
    // The persisted state and the held objects are public bytes; neither names a seed or key.
    let mut a = f.account;
    let persisted = a.export_persisted(&KEY, [3; 32]).unwrap();
    let text = String::from_utf8_lossy(&persisted).to_lowercase();
    assert!(!text.contains("\"seed\""));
    assert!(
        !text.contains("controllers"),
        "the stored state is protected, not plain"
    );
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
    admit(
        &mut f,
        &agent,
        "Claude",
        "agent",
        agent_terms("write"),
        agent_terms("write"),
    );
    admit(
        &mut f,
        &reader,
        "Viewer",
        "app",
        terms("read"),
        terms("read"),
    );
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
    assert_eq!(
        view.admitted[0].origin, "ai",
        "an agent's records are attributed to AI"
    );
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
    let got = f.account.query("notes", "notebooks", json!({})).unwrap();
    assert!(format!("{got:?}").contains("Plans"), "{got:?}");
    let mut r = member_session(&f, &reader);
    assert!(format!("{:?}", r.query("notes", "notebooks", json!({})).unwrap()).contains("Plans"));
    // A reader may not write: refused before a host is asked to sign.
    let seed = f.host.fresh();
    let denied = r
        .begin_write(
            "notes",
            "createNotebook",
            json!({"id": "x", "title": "X"}),
            Level::Write,
            seed,
        )
        .unwrap();
    assert_eq!(denied.unwrap_err().reason, "notGranted");
    // The members list counts admitted writes by authority, not counters.
    let m = f.account.members();
    assert_eq!(
        m.iter()
            .find(|m| m.member.id == agent)
            .unwrap()
            .member
            .writes,
        1
    );
    let _ = &mut r;
}

#[test]
fn a_merged_record_of_another_account_does_not_mix() {
    let mut f1 = create(&["notes"]);
    let mut f2 = create_v(&["notes"], 1);
    let agent = f1.host.identity(30);
    admit(
        &mut f1,
        &agent,
        "Claude",
        "agent",
        agent_terms("write"),
        agent_terms("write"),
    );
    let mut a = member_session(&f1, &agent);
    let mut host = std::mem::replace(&mut f1.host, Host::new());
    let wrote = write_note(&mut a, &mut host, "b1", "Plans");
    f1.host = host;
    // Account 2 is a different account (a different vault, different genesis time seeds are
    // the same fixtures, so only the ID differs).
    assert_ne!(
        f1.account.id(),
        f2.account.id(),
        "two creations, two accounts"
    );
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
    assert!(
        !view.refused.is_empty(),
        "the foreign header is refused: {view:?}"
    );
    // And a prepared action of one account is refused by the other at finish.
    let seed = f1.host.fresh();
    let action = f1
        .account
        .begin_rekey(&["notes".to_string()], &[f1.d.clone()], seed)
        .unwrap();
    let sigs = f1.host.sign(action.steps());
    assert!(f2.account.finish(action, sigs).is_err());
}

// ---------------------------------------------------------------------------------------------
// A second device: pairing and seed transfer (§7.3, §7.4, §17.3).

/// Pair `joiner_key`'s transfer key with `existing` and move the seed.
fn pair_and_transfer(
    host: &mut Host,
    existing: &Account,
    joining: &mut Account,
    now: i64,
) -> TransferKey {
    let tk = TransferKey::new(host.fresh()).unwrap();
    let (nb, na) = (host.fresh(), host.fresh());
    let (joiner, c) = Joiner::begin(existing.id(), &tk.public(), nb).unwrap();
    let mut limiter = FailureLimiter::new();
    let waiting =
        ExistingWaiting::receive_commitment(existing.id(), c, limiter.permit(now).unwrap());
    let (awaiting, na_sent) = waiting.send_nonce(na);
    let (reveal, j_code) = joiner.reveal(na_sent).unwrap();
    let h_code = awaiting.finish(&reveal.e, &reveal.nb).unwrap();
    assert_eq!(
        h_code.digits(),
        j_code.digits(),
        "the two screens show one code"
    );
    let (hp, jp) = (h_code.confirm(), j_code.confirm());
    let sealed = existing.transfer_seed(&hp, host.fresh()).unwrap();
    joining.accept_seed_transfer(&tk, &sealed, &jp).unwrap();
    tk
}

/// Add a second device `d2` (approve and control) as a controller with a slot of its own, by
/// the ceremony of §17.3: pair, move the seed, add it at once, the new core builds its slot.
fn add_second_device(f: &mut Fixture, roles: &[&str]) -> String {
    let d2 = f.host.identity(50);
    let mut s2 = Account::open(
        f.account.objects().clone(),
        vec![],
        None,
        Identity::Controller(d2.clone()),
        f.account.now_ms(),
    )
    .unwrap();
    assert!(!s2.is_unlocked());
    assert!(
        matches!(s2.me(), Standing::Unknown(ref id) if *id == d2),
        "a prospective identity"
    );
    let now = f.account.now_ms();
    let mut host = std::mem::replace(&mut f.host, Host::new());
    pair_and_transfer(&mut host, &f.account, &mut s2, now);
    f.host = host;
    assert!(
        s2.is_unlocked(),
        "the transferred seed opens the account's vault"
    );
    // An approve and sign controller is added at once; its possession proof is a step.
    let c = f.host.raw_controller(&d2, "Studio", roles);
    let action = f.account.begin_add_controller(&AddController {
        controller: c,
        mode: AddMode::Immediate {
            signers: vec![f.d.clone()],
        },
    });
    // control and recover roles are not an immediate add (§8.4): the transition path is used.
    let action = match action {
        Ok(a) => a,
        Err(e) => panic!("{e}"),
    };
    assert!(
        action.steps().iter().any(|s| s.signer() == d2),
        "its possession proof"
    );
    let done = run(&mut f.account, &f.host, action);
    s2.merge(
        Incoming {
            objects: Objects {
                entries: done.entries.iter().map(|(_, e)| e.clone()).collect(),
                ..Default::default()
            },
            records: vec![],
        },
        now,
    )
    .unwrap();
    assert!(s2.controllers().iter().any(|c| c.id == d2));
    assert!(matches!(s2.me(), Standing::Controller(ref c) if c.id == d2 && !c.has_slot));
    // The new core builds the slot (a sealed slot: no PRF), signed by the new key.
    let entropy = f.host.fresh();
    let action = s2
        .begin_add_slot(
            &d2,
            SlotPlan {
                controllers: vec![d2.clone()],
                label: "Studio".into(),
            },
            entropy,
        )
        .unwrap();
    let done = run(&mut s2, &f.host, action);
    f.account
        .merge(
            Incoming {
                objects: Objects {
                    entries: done.entries.iter().map(|(_, e)| e.clone()).collect(),
                    ..Default::default()
                },
                records: vec![],
            },
            now,
        )
        .unwrap();
    d2
}

#[test]
fn a_second_device_joins_by_pairing_and_seed_transfer_and_unlocks_by_its_own_slot() {
    let mut f = create(&["notes"]);
    let d2 = add_second_device(&mut f, &["approve"]);
    assert_eq!(f.account.status().seq, 4, "genesis, rekey, add, self-slot");
    assert!(
        f.account
            .controllers()
            .iter()
            .find(|c| c.id == d2)
            .unwrap()
            .has_slot
    );
    // A fresh session on the second device unlocks through its slot alone.
    let mut s = Account::open(
        f.account.objects().clone(),
        vec![],
        None,
        Identity::Controller(d2.clone()),
        f.account.now_ms(),
    )
    .unwrap();
    assert!(!s.is_unlocked());
    let idx = s
        .slots()
        .unwrap()
        .into_iter()
        .find(|o| o.controllers.len() == 1 && o.controllers[0].0 == d2)
        .unwrap()
        .index;
    let inputs = s.begin_unlock_slot(idx).unwrap();
    s.finish_unlock_slot(idx, &f.host.answer_unlock(&inputs))
        .unwrap();
    assert!(s.is_unlocked());
    // Its seed is the account's: it can seal the transfer for a third device in turn.
    assert!(matches!(
        s.view("notes").unwrap(),
        colophon_core::model::Outcome::Success { .. }
    ));
}

#[test]
fn a_seed_cannot_be_moved_by_a_pairing_for_another_account_or_a_wrong_key() {
    let mut f1 = create(&["notes"]);
    let f2 = create_v(&["notes"], 1);
    let tk = TransferKey::new(f1.host.fresh()).unwrap();
    // A pairing confirmed for account 2 seals nothing from account 1.
    let (nb, na) = (f1.host.fresh(), f1.host.fresh());
    let (joiner, c) = Joiner::begin(f2.account.id(), &tk.public(), nb).unwrap();
    let mut lim = FailureLimiter::new();
    let w = ExistingWaiting::receive_commitment(f2.account.id(), c, lim.permit(T0).unwrap());
    let (aw, na) = w.send_nonce(na);
    let (rev, jc) = joiner.reveal(na).unwrap();
    let hc = aw.finish(&rev.e, &rev.nb).unwrap();
    let (hp, jp) = (hc.confirm(), jc.confirm());
    let e = f1.account.transfer_seed(&hp, f1.host.fresh()).unwrap_err();
    assert_eq!(e.code(), "malformed");
    // The other way: a seal made by account 2 cannot be installed in account 1.
    let sealed = f2.account.transfer_seed(&hp, f1.host.fresh()).unwrap();
    let mut a1 = Account::open(
        f1.account.objects().clone(),
        vec![],
        None,
        Identity::Controller(f1.d.clone()),
        T0,
    )
    .unwrap();
    assert_eq!(
        a1.accept_seed_transfer(&tk, &sealed, &jp)
            .unwrap_err()
            .code(),
        "malformed"
    );
    assert!(!a1.is_unlocked());
}

// ---------------------------------------------------------------------------------------------
// Revoke with kept records; remove a controller, rotate the vault, rekey.

fn merge_done(a: &mut Account, done: &Finished, now: i64) -> Changes {
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

#[test]
fn revoke_keeps_the_records_it_names_and_the_revoked_member_cannot_read_what_follows() {
    let mut f = create(&["notes"]);
    let agent = f.host.identity(30);
    admit(
        &mut f,
        &agent,
        "Claude",
        "agent",
        agent_terms("write"),
        agent_terms("write"),
    );
    let mut a = member_session(&f, &agent);
    let mut host = std::mem::replace(&mut f.host, Host::new());
    let r1 = write_note(&mut a, &mut host, "b1", "Kept");
    let r2 = write_note(&mut a, &mut host, "b2", "Also kept");
    f.host = host;
    let now = f.account.now_ms();
    merge_done(&mut f.account, &r1, now);
    merge_done(&mut f.account, &r2, now);
    let seed = f.host.fresh();
    let action = f
        .account
        .begin_revoke(&agent, &RevokeKeep::Everything, &[f.d.clone()], seed)
        .unwrap();
    assert!(!action.info().rekey_owed);
    assert_eq!(
        action.info().heads.len(),
        1,
        "the author chain's one maximal head"
    );
    let done = run(&mut f.account, &f.host, action);
    assert!(done.changes.authority.members_revoked.contains(&agent));
    assert_eq!(
        f.account.latest_epoch("notes"),
        2,
        "a new epoch sealed without the member"
    );
    // The kept records are still admitted.
    let view = match f.account.view("notes").unwrap() {
        colophon_core::model::Outcome::Success { value, .. } => value,
        other => panic!("{other:?}"),
    };
    assert_eq!(view.admitted.len(), 2, "{view:?}");
    // The revoked agent, once it learns of the revocation, holds no share of epoch 2 and is
    // refused a read.
    merge_done(&mut a, &done, now);
    assert!(
        a.begin_unlock_epochs().is_empty(),
        "no seal of epoch 2 is addressed to it"
    );
    match a.view("notes").unwrap() {
        colophon_core::model::Outcome::Failure { reason, .. } => assert_eq!(reason, "revoked"),
        other => panic!("{other:?}"),
    }
    // A record the agent writes after the revocation is not admitted by anyone.
    let before = f
        .account
        .members()
        .iter()
        .find(|m| m.member.id == agent)
        .unwrap()
        .member
        .writes;
    assert_eq!(before, 2);
}

/// Add D2 with its slot as an approve and control device, as the removal journeys need.
fn with_removable_device() -> (Fixture, String) {
    let mut f = create(&["notes"]);
    // Control roles are a pending transition (§8.4); the immediate add is approve only.
    let d2 = add_second_device(&mut f, &["approve"]);
    (f, d2)
}

#[test]
fn removing_a_slotted_controller_rotates_the_vault_at_once_and_a_rekey_follows() {
    let (mut f, d2) = with_removable_device();
    let agent = f.host.identity(30);
    admit(
        &mut f,
        &agent,
        "Claude",
        "agent",
        agent_terms("write"),
        agent_terms("write"),
    );
    // The removed device's session still holds the old seed and epoch 1.
    let mut s2 = Account::open(
        f.account.objects().clone(),
        f.account.records().to_vec(),
        None,
        Identity::Controller(d2.clone()),
        f.account.now_ms(),
    )
    .unwrap();
    let idx = s2
        .slots()
        .unwrap()
        .into_iter()
        .find(|o| o.controllers.len() == 1 && o.controllers[0].0 == d2)
        .unwrap()
        .index;
    let inputs = s2.begin_unlock_slot(idx).unwrap();
    s2.finish_unlock_slot(idx, &f.host.answer_unlock(&inputs))
        .unwrap();
    // A record written under epoch 1 before the removal.
    let mut a = member_session(&f, &agent);
    let mut host = std::mem::replace(&mut f.host, Host::new());
    let old = write_note(&mut a, &mut host, "b1", "Before");
    f.host = host;
    let now = f.account.now_ms();
    merge_done(&mut f.account, &old, now);
    // Remove D2 by a pending transition that rotates the vault at once.
    let (nseed, entropy) = (f.host.fresh(), f.host.fresh());
    let action = f
        .account
        .begin_remove_controller(
            &[d2.clone()],
            &[],
            // A vault change needs the recovery set's consent (§8.4): the kit co-signs.
            &[f.d.clone(), f.k.clone()],
            TransitionRule::Control,
            Some((nseed, entropy)),
        )
        .unwrap();
    // The prf slot and the combined slot name the passkey: rebuilding them needs its PRF.
    assert_eq!(action.prf_requests().len(), 2);
    let results = f.host.answer_prf(action.prf_requests());
    let action = f.account.provide_prf(action, results).unwrap();
    let done = run(&mut f.account, &f.host, action);
    assert_eq!(done.pending.len(), 1, "a pending transition, not an entry");
    assert_eq!(f.account.pending().len(), 1);
    assert!(
        f.account.controllers().iter().any(|c| c.id == d2),
        "not removed yet"
    );
    // Time passes; the activation is determined, and records the new vault.
    f.account.advance(now + 2 * HOUR).unwrap();
    let recorded = f.account.record_due().unwrap();
    assert_eq!(recorded.len(), 1);
    assert!(!f.account.controllers().iter().any(|c| c.id == d2));
    assert!(recorded[0].changes.authority.vault_changed);
    assert!(f.account.is_unlocked(), "the new seed is the current one");
    // Then the rekey (§8.3): epoch 2, sealed to the new vault and the agent only.
    let seed = f.host.fresh();
    let action = f
        .account
        .begin_rekey(&["notes".to_string()], &[f.d.clone()], seed)
        .unwrap();
    run(&mut f.account, &f.host, action);
    assert_eq!(f.account.latest_epoch("notes"), 2);
    // A fresh session through the new slot reads epoch 1 through `previousVault` and epoch 2.
    let mut fresh = Account::open(
        f.account.objects().clone(),
        f.account.records().to_vec(),
        None,
        Identity::Controller(f.d.clone()),
        f.account.now_ms(),
    )
    .unwrap();
    let didx = fresh
        .slots()
        .unwrap()
        .into_iter()
        .find(|o| o.controllers.len() == 1 && o.controllers[0].0 == f.d)
        .unwrap()
        .index;
    let inputs = fresh.begin_unlock_slot(didx).unwrap();
    fresh
        .finish_unlock_slot(didx, &f.host.answer_unlock(&inputs))
        .unwrap();
    let text = format!(
        "{:?}",
        fresh.query("notes", "notebooks", json!({})).unwrap()
    );
    assert!(
        text.contains("Before"),
        "the epoch 1 record opens through previousVault: {text}"
    );
    // The removed device (old seed) learns of everything and can no longer read the namespace:
    // epoch 2 is sealed to the new vault only.
    s2.merge(
        Incoming {
            objects: f.account.objects().clone(),
            records: vec![],
        },
        f.account.now_ms(),
    )
    .unwrap();
    assert!(
        !s2.controllers().iter().any(|c| c.id == d2),
        "it learns it was removed"
    );
    match s2.view("notes").unwrap() {
        colophon_core::model::Outcome::Failure { reason, .. } => assert_eq!(reason, "notGranted"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn removing_without_a_rotation_retires_the_vault_and_a_vault_entry_then_a_rekey_follow() {
    let (mut f, d2) = with_removable_device();
    let agent = f.host.identity(30);
    admit(
        &mut f,
        &agent,
        "Claude",
        "agent",
        agent_terms("write"),
        agent_terms("write"),
    );
    let now = f.account.now_ms();
    let action = f
        .account
        .begin_remove_controller(
            &[d2.clone()],
            &[],
            &[f.d.clone()],
            TransitionRule::Control,
            None,
        )
        .unwrap();
    run(&mut f.account, &f.host, action);
    f.account.advance(now + 2 * HOUR).unwrap();
    f.account.record_due().unwrap();
    assert!(f.account.notices(0, &BTreeSet::new(), &[]).vault_retiring);
    // A rekey is refused while the vault retires (§8.3); a revoke carries no epochs and says so.
    let seed = f.host.fresh();
    assert!(f
        .account
        .begin_rekey(&["notes".to_string()], &[f.d.clone()], seed)
        .is_err());
    let seed = f.host.fresh();
    let action = f
        .account
        .begin_revoke(&agent, &RevokeKeep::Nothing, &[f.d.clone()], seed)
        .unwrap();
    assert!(action.info().rekey_owed);
    assert_eq!(action.info().owed_namespaces, ["notes".to_string()]);
    run(&mut f.account, &f.host, action);
    assert_eq!(
        f.account.latest_epoch("notes"),
        1,
        "no epoch while retiring"
    );
    // The vault entry: a fresh identity, the sealed slots, previousVault.
    let (nseed, entropy) = (f.host.fresh(), f.host.fresh());
    let action = f
        .account
        .begin_rotate_vault(&f.d, nseed, None, entropy)
        .unwrap();
    assert!(
        action.prf_requests().is_empty(),
        "only sealed slots are rebuilt by default"
    );
    run(&mut f.account, &f.host, action);
    assert!(!f.account.notices(0, &BTreeSet::new(), &[]).vault_retiring);
    // The passkey's slots were not rebuilt: it is reported as having none (§6.4).
    let n = f.account.notices(0, &BTreeSet::new(), &[]);
    assert!(n.controllers_without_slot.contains(&f.p), "{n:?}");
    let seed = f.host.fresh();
    let action = f
        .account
        .begin_rekey(&["notes".to_string()], &[f.d.clone()], seed)
        .unwrap();
    run(&mut f.account, &f.host, action);
    assert_eq!(
        f.account.latest_epoch("notes"),
        2,
        "the rekey after the rotation"
    );
}

// ---------------------------------------------------------------------------------------------
// A pending change vetoed; a fork resolved.

fn unlock_controller(host: &Host, a: &mut Account, id: &str) {
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

/// A home's receipt (§13.5) of an object, signed raw by the home.
fn receipt(account: &str, host: &Host, home: &str, object: &str, received_ms: i64) -> Vec<u8> {
    let body = canonical(&json!({
        "protocol": "colophon/receipt/5", "account": account, "object": object,
        "received": colophon_core::v05::write::format_date(received_ms), "by": home,
    }))
    .unwrap();
    canonical(&json!({"body": b64(&body), "signature": b64(&host.ids[home].sign(&body))})).unwrap()
}
fn hold_pending(a: &mut Account, objects: Vec<Vec<u8>>) {
    let now = a.now_ms();
    a.merge(
        Incoming {
            objects: Objects {
                pending: objects,
                ..Default::default()
            },
            records: vec![],
        },
        now,
    )
    .unwrap();
}
fn pending_digest(env: &[u8]) -> String {
    digest_of(env)
}

/// Appoint a home (a transition, recorded at once because there is no home yet to witness
/// time): the account then has a witness, and every later transition needs its receipt.
fn appoint_home(f: &mut Fixture) -> String {
    let h = f.host.identity(70);
    let p = f.host.ids[&h].public();
    let created = colophon_core::v05::write::format_date(f.account.now_ms());
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
    assert_eq!(rec.len(), 1, "no home yet: due when issued");
    assert_eq!(f.account.homes().len(), 1);
    h
}

#[test]
fn a_pending_removal_is_shown_and_vetoed_by_another_control_key() {
    let mut f = create(&["notes"]);
    let d2 = add_second_device(&mut f, &["approve"]);
    let h = appoint_home(&mut f);
    let now = f.account.now_ms();
    let acct = f.account.id().as_str().to_string();
    // The device alone proposes removing the second device.
    let action = f
        .account
        .begin_remove_controller(
            &[d2.clone()],
            &[],
            &[f.d.clone()],
            TransitionRule::Control,
            None,
        )
        .unwrap();
    let done = run(&mut f.account, &f.host, action);
    let t_digest = pending_digest(&done.pending[0]);
    hold_pending(
        &mut f.account,
        vec![receipt(&acct, &f.host, &h, &t_digest, now + 10 * SEC)],
    );
    let pending = f.account.pending();
    assert_eq!(pending.len(), 1);
    let t = &pending[0];
    assert_eq!(t.removes, [d2.clone()]);
    assert_eq!(t.signers, [(f.d.clone(), "Mac".to_string())]);
    assert_eq!(t.first_seen_seq, Some(5), "first held at verified seq 5");
    assert_eq!(
        t.due_ms,
        Some(now + 300 * SEC + HOUR),
        "issued + 300 s + the delay"
    );
    assert_eq!(t.veto_deadline_ms, Some(now + HOUR));
    assert_eq!(t.full_set, Some(false));
    // Not due yet: nothing is recorded.
    assert!(f.account.record_due().unwrap().is_empty());
    // The passkey's own session is shown it, may veto it, and does.
    let mut p_session = Account::open(
        f.account.objects().clone(),
        vec![],
        None,
        Identity::Controller(f.p.clone()),
        now,
    )
    .unwrap();
    assert!(p_session.pending()[0].vetoable);
    let notices = p_session.notices(0, &BTreeSet::new(), &[f.p.clone()]);
    assert_eq!(notices.pending.len(), 1);
    // Having shown it, the host does not show it again.
    let shown: BTreeSet<String> = [t.digest.clone()].into();
    assert!(p_session
        .notices(0, &shown, &[f.p.clone()])
        .pending
        .is_empty());
    let veto = p_session.begin_veto(&t.digest, &[f.p.clone()]).unwrap();
    let vdone = run(&mut p_session, &f.host, veto);
    assert_eq!(vdone.pending.len(), 1);
    // The device merges the veto (and the home's receipt of it) and records it.
    let v_digest = pending_digest(&vdone.pending[0]);
    hold_pending(
        &mut f.account,
        vec![
            vdone.pending[0].clone(),
            receipt(&acct, &f.host, &h, &v_digest, now + 20 * SEC),
        ],
    );
    let recorded = f.account.record_due().unwrap();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].entries.len(), 1);
    f.account.advance(now + 3 * HOUR).unwrap();
    assert!(f.account.record_due().unwrap().is_empty());
    assert!(
        f.account.controllers().iter().any(|c| c.id == d2),
        "the second device stays"
    );
    assert!(f.account.pending().is_empty());
    // Escalation (§8.7): the device that was vetoed now needs two units for its next proposal.
    let again = f
        .account
        .begin_remove_controller(
            &[d2.clone()],
            &[],
            &[f.d.clone()],
            TransitionRule::Control,
            None,
        )
        .unwrap_err();
    assert_eq!(again.code(), "badSignature", "{again}");
}

#[test]
fn an_unvetoed_removal_activates_when_due_and_missed_activations_are_shown() {
    let mut f = create(&["notes"]);
    let h = appoint_home(&mut f);
    let now = f.account.now_ms();
    let acct = f.account.id().as_str().to_string();
    let action = f
        .account
        .begin_remove_controller(
            &[f.p.clone()],
            &[],
            &[f.d.clone(), f.k.clone()],
            TransitionRule::Control,
            None,
        )
        .unwrap();
    let done = run(&mut f.account, &f.host, action);
    let t_digest = pending_digest(&done.pending[0]);
    hold_pending(
        &mut f.account,
        vec![receipt(&acct, &f.host, &h, &t_digest, now + 10 * SEC)],
    );
    // Nothing is due yet.
    assert!(f.account.record_due().unwrap().is_empty());
    f.account.advance(now + 2 * HOUR).unwrap();
    let rec = f.account.record_due().unwrap();
    assert_eq!(rec.len(), 1);
    assert!(rec[0].changes.authority.controllers_removed.contains(&f.p));
    // §17.5: the passkey's host, next time it is used, is shown the activation no key on it
    // signed; the device's host (which signed) is not.
    let n = f.account.notices(3, &BTreeSet::new(), &[f.p.clone()]);
    assert_eq!(n.activations.len(), 1, "{n:?}");
    assert_eq!(n.activations[0].signers.len(), 2);
    assert_eq!(
        n.activations[0].receipted.len(),
        1,
        "when the home receipted it"
    );
    let n = f.account.notices(3, &BTreeSet::new(), &[f.d.clone()]);
    assert!(n.activations.is_empty());
    assert!(!n.no_home);
}

#[test]
fn a_fork_is_reported_reads_continue_and_a_resolve_chooses_a_branch() {
    let f = create(&["notes"]);
    let now = f.account.now_ms();
    let (mut host, d, p, k) = (f.host, f.d.clone(), f.p.clone(), f.k.clone());
    let e1 = host.identity(60);
    let e2 = host.identity(61);
    let objects = f.account.objects().clone();
    let open = || {
        let mut a = Account::open(
            objects.clone(),
            vec![],
            None,
            Identity::Controller(d.clone()),
            now,
        )
        .unwrap();
        unlock_controller(&host, &mut a, &d);
        a
    };
    let (mut a1, mut a2) = (open(), open());
    // Two devices each add a different key at seq 3.
    let add = |a: &Account, who: &str| {
        a.begin_add_controller(&AddController {
            controller: host.raw_controller(who, "New", &["approve"]),
            mode: AddMode::Immediate {
                signers: vec![d.clone()],
            },
        })
        .unwrap()
    };
    let x1 = {
        let act = add(&a1, &e1);
        run(&mut a1, &host, act)
    };
    let x2 = {
        let act = add(&a2, &e2);
        run(&mut a2, &host, act)
    };
    a1.merge(
        Incoming {
            objects: Objects {
                entries: vec![x2.entries[0].1.clone()],
                ..Default::default()
            },
            records: vec![],
        },
        now,
    )
    .unwrap();
    a2.merge(
        Incoming {
            objects: Objects {
                entries: vec![x1.entries[0].1.clone()],
                ..Default::default()
            },
            records: vec![],
        },
        now,
    )
    .unwrap();
    for a in [&a1, &a2] {
        assert_eq!(a.status().code, "refused:fork", "{:?}", a.status());
        assert_eq!(a.status().seq, 2, "the verified prefix before the fork");
        // Reading continues from the last good state.
        assert!(matches!(
            a.view("notes").unwrap(),
            colophon_core::model::Outcome::Success { .. }
        ));
        assert_eq!(a.fork_candidates().len(), 2);
    }
    // The same fork from either side: the object set decides, not the order it arrived in.
    assert_eq!(a1.status(), a2.status());
    // Writes are refused until the fork is resolved.
    assert_eq!(
        a1.begin_rekey(&["notes".to_string()], &[d.clone()], [9; 32])
            .unwrap_err(),
        Failure::Refused(Reason::Fork)
    );
    // Resolve: keep x1's entry. Every control unit and a recovery key sign (so it is due at once).
    let (seq, kept, _) = a1
        .fork_candidates()
        .into_iter()
        .find(|(_, dg, _)| *dg == digest_of(&x1.entries[0].1))
        .unwrap();
    let action = a1
        .begin_resolve(
            (seq, kept.clone()),
            (seq, kept.clone()),
            &[d.clone(), p.clone(), k.clone()],
            TransitionRule::Control,
        )
        .unwrap();
    run(&mut a1, &host, action);
    assert_eq!(a1.status().code, "refused:fork", "not until it is recorded");
    let rec = a1.record_due().unwrap();
    assert_eq!(rec.len(), 1);
    assert_eq!(a1.status().code, "ok", "{:?}", a1.status());
    let ids: BTreeSet<String> = a1.controllers().into_iter().map(|c| c.id).collect();
    assert!(ids.contains(&e1) && !ids.contains(&e2));
    // The other device takes the resolution and agrees.
    a2.merge(
        Incoming {
            objects: a1.objects().clone(),
            records: vec![],
        },
        now,
    )
    .unwrap();
    assert_eq!(a2.status().code, "ok");
    assert_eq!(a2.status(), a1.status());
}

fn digest_of(env: &[u8]) -> String {
    let v: Value = serde_json::from_slice(env).unwrap();
    digest(&STANDARD.decode(v["body"].as_str().unwrap()).unwrap())
}

// ---------------------------------------------------------------------------------------------
// Links and calls (§12).

const AUDIENCE: &str = "https://svc.example/api";

fn service_terms(purposes: &[&str]) -> Value {
    json!({"services": [{"audience": AUDIENCE, "purposes": purposes}]})
}
fn agent_with_services() -> Value {
    json!({"records": [{"namespace": "notes", "access": "write"}],
           "services": [{"audience": AUDIENCE, "purposes": ["task.read", "task.write"]}],
           "expires": colophon_core::v05::write::format_date(T0 + 7 * 24 * HOUR),
           "depth": 1})
}

/// A home's head (§13.2) over the account's current head, signed raw by the home.
fn head_of(a: &Account, host: &Host, home: &str, issued_ms: i64) -> Vec<u8> {
    let (seq, dg) = a.head();
    let body = canonical(&json!({
        "protocol": "colophon/head/5", "account": a.id().as_str(),
        "authority": {"seq": seq, "digest": dg}, "by": home,
        "issued": colophon_core::v05::write::format_date(issued_ms),
    }))
    .unwrap();
    canonical(&json!({"body": b64(&body), "signature": b64(&host.ids[home].sign(&body))})).unwrap()
}
fn hold_head_at(a: &mut Account, host: &Host, home: &str, issued_ms: i64) -> Changes {
    let head = head_of(a, host, home, issued_ms);
    hold_head(a, head)
}
fn hold_head(a: &mut Account, head: Vec<u8>) -> Changes {
    let now = a.now_ms();
    a.merge(
        Incoming {
            objects: Objects {
                heads: vec![head],
                ..Default::default()
            },
            records: vec![],
        },
        now,
    )
    .unwrap()
}

#[test]
fn a_member_links_a_service_key_and_calls_and_ended_sessions_end_the_link() {
    let mut f = create(&["notes"]);
    let h = appoint_home(&mut f);
    let agent = f.host.identity(30);
    let svc = f.host.identity(80);
    admit(
        &mut f,
        &agent,
        "Claude",
        "agent",
        agent_with_services(),
        agent_with_services(),
    );
    let mut a = member_session(&f, &agent);
    let svc_point = f.host.ids[&svc].public().signing;
    let now = a.now_ms();
    let ch = hold_head_at(&mut a, &f.host, &h, now + SEC);
    assert_eq!(ch.heads.accepted, [h.clone()]);
    // The link: the member's key grants the service key `task.read` at the audience.
    let action = a
        .begin_link(
            &[],
            &svc_point,
            service_terms(&["task.read"]),
            now,
            now + HOUR,
        )
        .unwrap();
    let link = run(&mut a, &f.host, action).artifact.unwrap();
    // A call by the service key, with the link chain.
    let target = || CallTarget {
        audiences: vec![AUDIENCE.into()],
        ..Default::default()
    };
    let call = |a: &mut Account, host: &Host, purpose: &str, id: u8| {
        let action = a
            .begin_call(
                &svc_point,
                &[link.clone()],
                AUDIENCE,
                purpose,
                json!({"task": 7}),
                [id; 32],
                target(),
            )
            .unwrap();
        let sigs = host.sign(action.steps());
        a.finish(action, sigs)
    };
    assert!(call(&mut a, &f.host, "task.read", 1)
        .unwrap()
        .artifact
        .is_some());
    // The link grants read only: a write purpose is outside it.
    let e = call(&mut a, &f.host, "task.write", 2).unwrap_err();
    assert_eq!(e, Failure::Refused(Reason::OutOfScope));
    // The member's own call, with no link, may use its terms.
    let own_point = f.host.ids[&agent].public().signing;
    let action = a
        .begin_call(
            &own_point,
            &[],
            AUDIENCE,
            "task.write",
            json!({}),
            [3; 32],
            target(),
        )
        .unwrap();
    let sigs = f.host.sign(action.steps());
    assert!(a.finish(action, sigs).unwrap().artifact.is_some());
    // Ending the member's sessions ends the link (§9.6): the same call is now refused.
    let action = f
        .account
        .begin_end_sessions(&agent, &[f.d.clone()])
        .unwrap();
    let ended = run(&mut f.account, &f.host, action);
    merge_done(&mut a, &ended, now);
    hold_head_at(&mut a, &f.host, &h, now + 2 * SEC);
    let e = call(&mut a, &f.host, "task.read", 4).unwrap_err();
    assert_eq!(e, Failure::Refused(Reason::Ended));
    // A new link carries the new session number, from the verified history.
    let action = a
        .begin_link(
            &[],
            &svc_point,
            service_terms(&["task.read"]),
            now,
            now + HOUR,
        )
        .unwrap();
    let relink = run(&mut a, &f.host, action).artifact.unwrap();
    assert_ne!(relink, link);
    // A controller may call too, through its own key.
    let mut c = Account::open(
        f.account.objects().clone(),
        vec![],
        None,
        Identity::Controller(f.d.clone()),
        now,
    )
    .unwrap();
    hold_head_at(&mut c, &f.host, &h, now + 3 * SEC);
    let dpoint = f.host.ids[&f.d].public().signing;
    let purposes = ["colophon.history.read".to_string()];
    let action = c
        .begin_call(
            &dpoint,
            &[],
            AUDIENCE,
            "colophon.history.read",
            json!({}),
            [5; 32],
            CallTarget {
                audiences: vec![AUDIENCE.into()],
                controller_purposes: purposes.to_vec(),
                ..Default::default()
            },
        )
        .unwrap();
    let sigs = f.host.sign(action.steps());
    assert!(c.finish(action, sigs).unwrap().artifact.is_some());
}

// ---------------------------------------------------------------------------------------------
// Proposals (§11.6).

#[test]
fn a_proposal_folds_once_when_accepted_and_not_before() {
    let mut f = create(&["notes"]);
    let proposer = f.host.identity(31);
    let writer = f.host.identity(32);
    admit(
        &mut f,
        &proposer,
        "Claude",
        "agent",
        agent_terms("propose"),
        agent_terms("propose"),
    );
    admit(
        &mut f,
        &writer,
        "Phone",
        "device",
        terms("write"),
        terms("write"),
    );
    let mut p = member_session(&f, &proposer);
    let seed = f.host.fresh();
    let action = p
        .begin_propose(
            "notes",
            "createNotebook",
            json!({"id": "pb", "title": "Proposed"}),
            seed,
        )
        .unwrap()
        .unwrap();
    let done = run(&mut p, &f.host, action);
    let mut w = member_session(&f, &writer);
    let now = w.now_ms();
    w.merge(
        Incoming {
            objects: Objects::default(),
            records: done.records.clone(),
        },
        now,
    )
    .unwrap();
    // Held as a proposal, not folded.
    let props = w.proposals("notes");
    assert_eq!(props.len(), 1);
    assert_eq!(props[0].state, "pending");
    assert!(
        !format!("{:?}", w.query("notes", "notebooks", json!({})).unwrap()).contains("Proposed")
    );
    // The writer accepts; the proposal folds once, at its accept's position.
    let seed = f.host.fresh();
    let action = w
        .begin_resolution("notes", true, &[props[0].id.clone()], seed)
        .unwrap();
    run(&mut w, &f.host, action);
    assert_eq!(w.proposals("notes")[0].state, "accepted");
    assert!(
        !w.proposals("notes")[0].final_,
        "an acceptance is never final"
    );
    assert!(
        format!("{:?}", w.query("notes", "notebooks", json!({})).unwrap()).contains("Proposed")
    );
    let view = match w.view("notes").unwrap() {
        colophon_core::model::Outcome::Success { value, .. } => value,
        other => panic!("{other:?}"),
    };
    assert_eq!(
        view.admitted.len(),
        1,
        "the accept itself is not an operation"
    );
    assert_eq!(
        view.admitted[0].author, proposer,
        "attributed to the proposer"
    );
    // A second resolution of the same proposal is evidence only: the first stands.
    let seed = f.host.fresh();
    let action = w
        .begin_resolution("notes", false, &[props[0].id.clone()], seed)
        .unwrap();
    run(&mut w, &f.host, action);
    assert_eq!(w.proposals("notes")[0].state, "accepted");
}

// ---------------------------------------------------------------------------------------------
// Order independence and resume.

/// Everything a long journey produced, as the bytes a store would hold.
struct Story {
    objects: Objects,
    records: Vec<HeldRecord>,
    now: i64,
    d: String,
    host: Host,
    /// The persisted state exported when the story was half told, and the objects it covered.
    mid: Vec<u8>,
    mid_entries: usize,
    mid_covered: BTreeSet<Vec<u8>>,
}

/// create, a second device, an agent admitted and writing, a revoke, a removal that rotates the
/// vault (with the passkey's PRF), a rekey, and a pending transition left open.
fn story() -> Story {
    let mut f = create(&["notes"]);
    let d2 = add_second_device(&mut f, &["approve"]);
    let agent = f.host.identity(30);
    let other = f.host.identity(31);
    admit(
        &mut f,
        &agent,
        "Claude",
        "agent",
        agent_terms("write"),
        agent_terms("write"),
    );
    admit(
        &mut f,
        &other,
        "Viewer",
        "app",
        terms("read"),
        terms("read"),
    );
    let mid = f.account.export_persisted(&KEY, [1; 32]).unwrap();
    let mid_covered: BTreeSet<Vec<u8>> = f.account.objects().entries.iter().cloned().collect();
    let mid_entries = f.account.objects().entries.len();
    let now = f.account.now_ms();
    let mut a = member_session(&f, &agent);
    let mut host = std::mem::replace(&mut f.host, Host::new());
    let w1 = write_note(&mut a, &mut host, "b1", "One");
    let w2 = write_note(&mut a, &mut host, "b2", "Two");
    f.host = host;
    merge_done(&mut f.account, &w1, now);
    merge_done(&mut f.account, &w2, now);
    let seed = f.host.fresh();
    let action = f
        .account
        .begin_revoke(&agent, &RevokeKeep::Everything, &[f.d.clone()], seed)
        .unwrap();
    run(&mut f.account, &f.host, action);
    let (nseed, entropy) = (f.host.fresh(), f.host.fresh());
    let action = f
        .account
        .begin_remove_controller(
            &[d2],
            &[],
            &[f.d.clone(), f.k.clone()],
            TransitionRule::Control,
            Some((nseed, entropy)),
        )
        .unwrap();
    let results = f.host.answer_prf(action.prf_requests());
    let action = f.account.provide_prf(action, results).unwrap();
    run(&mut f.account, &f.host, action);
    f.account.advance(now + 2 * HOUR).unwrap();
    f.account.record_due().unwrap();
    let seed = f.host.fresh();
    let action = f
        .account
        .begin_rekey(&["notes".to_string()], &[f.d.clone()], seed)
        .unwrap();
    run(&mut f.account, &f.host, action);
    // A transition left pending at the end.
    let action = f
        .account
        .begin_transition(
            &Change::policy(json!({"callWindow": 600})),
            &[f.d.clone(), f.p.clone()],
            TransitionRule::Control,
        )
        .unwrap();
    run(&mut f.account, &f.host, action);
    Story {
        objects: f.account.objects().clone(),
        records: f.account.records().to_vec(),
        now: f.account.now_ms(),
        d: f.d.clone(),
        host: f.host,
        mid,
        mid_entries,
        mid_covered,
    }
}

/// What a session shows, as one value: no secret, no local memory (the head marks, the seq at
/// which a transition was first held).
fn fingerprint(a: &Account, host: &Host, d: &str) -> Value {
    let mut pending = serde_json::to_value(a.pending()).unwrap();
    for p in pending.as_array_mut().unwrap() {
        p["first_seen_seq"] = Value::Null;
    }
    let view = match a.view("notes").unwrap() {
        colophon_core::model::Outcome::Success { value, .. } => {
            serde_json::to_value(value).unwrap()
        }
        colophon_core::model::Outcome::Failure { reason, .. } => json!(reason),
    };
    let _ = (host, d);
    json!({
        "status": a.status(),
        "head": a.head(),
        "controllers": a.controllers(),
        "members": a.members(),
        "policy": a.policy(),
        "homes": a.homes(),
        "pending": pending,
        "owed": a.owed_shares(),
        "view": view,
        "ledger": a.ledger(),
        "revision": a.revision("notes"),
    })
}

/// A fixed-seed shuffle (xorshift): the same order for the same seed.
fn shuffled<T: Clone>(items: &[T], mut seed: u64) -> Vec<T> {
    let mut v = items.to_vec();
    for i in (1..v.len()).rev() {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        v.swap(i, (seed % (i as u64 + 1)) as usize);
    }
    v
}

fn open_unlocked(
    s: &Story,
    objects: Objects,
    records: Vec<HeldRecord>,
    p: Option<&[u8]>,
) -> Account {
    let mut a = Account::open(
        objects,
        records,
        p.map(|b| (b, &KEY)),
        Identity::Controller(s.d.clone()),
        s.now,
    )
    .unwrap();
    unlock_controller(&s.host, &mut a, &s.d);
    a
}

#[test]
fn the_same_objects_in_any_order_give_the_same_account() {
    let s = story();
    let base = open_unlocked(&s, s.objects.clone(), s.records.clone(), None);
    let want = fingerprint(&base, &s.host, &s.d);
    assert_eq!(base.status().code, "ok", "{:?}", base.status());
    assert!(
        want["view"]["admitted"].as_array().unwrap().len() == 2,
        "{}",
        want["view"]
    );
    for seed in [1u64, 2, 3, 0xdead_beef, 0x1234_5678_9abc] {
        let o = Objects {
            entries: shuffled(&s.objects.entries, seed),
            pending: shuffled(&s.objects.pending, seed + 1),
            heads: shuffled(&s.objects.heads, seed + 2),
            predecessor: vec![],
        };
        let a = open_unlocked(&s, o, shuffled(&s.records, seed + 3), None);
        assert_eq!(fingerprint(&a, &s.host, &s.d), want, "open, seed {seed}");
    }
    // Merged in pieces, in shuffled order, from an account that holds only the genesis.
    let genesis = s
        .objects
        .entries
        .iter()
        .find(|e| digest_of(e) == base.objects_first())
        .unwrap()
        .clone();
    for seed in [7u64, 11, 13, 17] {
        let mut a = Account::open(
            Objects {
                entries: vec![genesis.clone()],
                ..Default::default()
            },
            vec![],
            None,
            Identity::Controller(s.d.clone()),
            s.now,
        )
        .unwrap();
        let mut pieces: Vec<Incoming> = Vec::new();
        for (i, e) in shuffled(&s.objects.entries, seed).into_iter().enumerate() {
            let mut inc = Incoming::default();
            inc.objects.entries.push(e);
            if i % 3 == 0 {
                inc.objects
                    .pending
                    .extend(s.objects.pending.iter().cloned());
            }
            pieces.push(inc);
        }
        pieces.push(Incoming {
            objects: Objects {
                pending: shuffled(&s.objects.pending, seed),
                heads: s.objects.heads.clone(),
                ..Default::default()
            },
            records: shuffled(&s.records, seed),
        });
        for p in pieces {
            a.merge(p, s.now).unwrap();
        }
        unlock_controller(&s.host, &mut a, &s.d);
        assert_eq!(fingerprint(&a, &s.host, &s.d), want, "merge, seed {seed}");
    }
}

#[test]
fn a_resumed_account_and_a_replayed_one_agree() {
    let s = story();
    let replayed = open_unlocked(&s, s.objects.clone(), s.records.clone(), None);
    let want = fingerprint(&replayed, &s.host, &s.d);
    // Open with only what came after the state exported half way through the story: the
    // authenticated state retains the earlier objects.
    assert_eq!(s.mid_covered.len(), s.mid_entries);
    let rest = Objects {
        entries: s
            .objects
            .entries
            .iter()
            .filter(|e| !s.mid_covered.contains(*e))
            .cloned()
            .collect(),
        pending: s.objects.pending.clone(),
        heads: s.objects.heads.clone(),
        predecessor: vec![],
    };
    // Sensitivity: the mid-story state alone is a different account state.
    let mid_only = open_unlocked(&s, Objects::default(), vec![], Some(&s.mid));
    assert_ne!(fingerprint(&mid_only, &s.host, &s.d), want);
    assert_eq!(mid_only.status().seq as usize, s.mid_entries);
    let resumed = open_unlocked(&s, rest.clone(), s.records.clone(), Some(&s.mid));
    assert_eq!(fingerprint(&resumed, &s.host, &s.d), want);
    assert_eq!(
        serde_json::to_value(resumed.objects()).unwrap(),
        serde_json::to_value(replayed.objects()).unwrap().clone(),
        "the same held objects"
    );
    // Export from the resumed account, open a fresh one with no objects at all: the retained
    // objects come with the state.
    let mut resumed = resumed;
    let bytes = resumed.export_persisted(&KEY, [2; 32]).unwrap();
    let again = open_unlocked(&s, Objects::default(), s.records.clone(), Some(&bytes));
    assert_eq!(fingerprint(&again, &s.host, &s.d), want);
}

#[test]
fn stored_state_that_does_not_authenticate_means_a_silent_replay() {
    let s = story();
    let want = fingerprint(
        &open_unlocked(&s, s.objects.clone(), s.records.clone(), None),
        &s.host,
        &s.d,
    );
    let open = |bytes: Option<(&[u8], &[u8; 32])>, me: Identity| {
        let mut a = Account::open(s.objects.clone(), s.records.clone(), bytes, me, s.now).unwrap();
        unlock_controller(&s.host, &mut a, &s.d);
        a
    };
    let me = || Identity::Controller(s.d.clone());
    // Each of these must open and must replay: the same account as with no stored state.
    let mut tampered = s.mid.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    let mut header_tampered = s.mid.clone();
    header_tampered[20] ^= 1;
    let wrong_key = [0x5bu8; 32];
    let mut plain_json = serde_json::to_vec(&json!({"version": 4, "state": {}})).unwrap();
    plain_json.extend_from_slice(&[0; 40]);
    let cases: Vec<(&str, Vec<u8>, [u8; 32], Identity)> = vec![
        ("a flipped tag byte", tampered, KEY, me()),
        ("a flipped header byte", header_tampered, KEY, me()),
        ("a wrong key", s.mid.clone(), wrong_key, me()),
        (
            "another identity",
            s.mid.clone(),
            KEY,
            Identity::Member(s.d.clone()),
        ),
        ("bare JSON", plain_json, KEY, me()),
        ("truncated", s.mid[..30].to_vec(), KEY, me()),
        ("empty", vec![], KEY, me()),
        (
            "huge header length",
            {
                let mut b = s.mid.clone();
                b[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
                b
            },
            KEY,
            me(),
        ),
    ];
    for (name, bytes, key, who) in cases {
        let member = matches!(who, Identity::Member(_));
        let a = open(Some((&bytes, &key)), who);
        if !member {
            assert_eq!(fingerprint(&a, &s.host, &s.d), want, "{name}");
        } else {
            assert_eq!(a.status().code, "ok", "{name}");
        }
    }
    // With no key supplied the account always replays; it loses the head marks only.
    assert_eq!(fingerprint(&open(None, me()), &s.host, &s.d), want);
    // With the right key the state is used: with no objects the account still opens.
    let a = Account::open(
        Objects::default(),
        vec![],
        Some((&s.mid, &KEY)),
        me(),
        s.now,
    )
    .unwrap();
    assert_eq!(a.status().seq as usize, s.mid_entries);
    // Without a verified state and without objects there is nothing to replay: an error.
    assert!(Account::open(
        Objects::default(),
        vec![],
        Some((&s.mid, &wrong_key)),
        me(),
        s.now
    )
    .is_err());
}

#[test]
fn two_envelopes_over_one_body_give_one_verdict_whichever_arrived_first() {
    // §2.2: envelopes over one body are one object, valid when any of them verifies. A
    // keyless envelope that sorts first changes nothing, in either order and one by one.
    let mut f = create(&["notes"]);
    let seed = f.host.fresh();
    let action = f
        .account
        .begin_rekey(&["notes".to_string()], &[f.d.clone()], seed)
        .unwrap();
    let before = f.account.objects().clone();
    let done = run(&mut f.account, &f.host, action);
    let good = done.entries[0].1.clone();
    let bad = twin_first(&good);
    for order in [[&good, &bad], [&bad, &good]] {
        let mut o = before.clone();
        o.entries.extend(order.iter().map(|e| (*e).clone()));
        let a = Account::open(o, vec![], None, Identity::Controller(f.d.clone()), T0).unwrap();
        assert_eq!(a.status().code, "ok", "{:?}", a.status());
        assert_eq!(a.status().seq, 3);
        let mut m = Account::open(
            before.clone(),
            vec![],
            None,
            Identity::Controller(f.d.clone()),
            T0,
        )
        .unwrap();
        for e in order {
            m.merge(
                Incoming {
                    objects: Objects {
                        entries: vec![e.clone()],
                        ..Default::default()
                    },
                    records: vec![],
                },
                T0,
            )
            .unwrap();
        }
        assert_eq!(m.status(), a.status());
    }
}

/// An envelope over the same body with a garbage signature that sorts before the real one.
fn twin_first(env: &[u8]) -> Vec<u8> {
    let mut v: Value = serde_json::from_slice(env).unwrap();
    v["signature"] = json!(b64(&[0xf8u8; 64]));
    let twin = canonical(&v).unwrap();
    assert!(twin.as_slice() < env, "the twin sorts first");
    twin
}

#[test]
fn a_keyless_twin_of_a_pending_object_changes_nothing() {
    // Before the fix a twin that sorted first made `pending()` list the transition twice and
    // could be the envelope the builders embedded (and the verifier refused).
    let mut f = create(&["notes"]);
    let d2 = add_second_device(&mut f, &["approve"]);
    let h = appoint_home(&mut f);
    let now = f.account.now_ms();
    let acct = f.account.id().as_str().to_string();
    let action = f
        .account
        .begin_remove_controller(
            &[d2.clone()],
            &[],
            &[f.d.clone()],
            TransitionRule::Control,
            None,
        )
        .unwrap();
    let done = run(&mut f.account, &f.host, action);
    let t_digest = pending_digest(&done.pending[0]);
    let r = receipt(&acct, &f.host, &h, &t_digest, now + 10 * SEC);
    hold_pending(
        &mut f.account,
        vec![twin_first(&done.pending[0]), twin_first(&r), r.clone()],
    );
    assert_eq!(f.account.pending().len(), 1, "one transition, once");
    // The veto, and its receipt, each with a twin that sorts first.
    let mut p_session = Account::open(
        f.account.objects().clone(),
        vec![],
        None,
        Identity::Controller(f.p.clone()),
        now,
    )
    .unwrap();
    let veto = p_session.begin_veto(&t_digest, &[f.p.clone()]).unwrap();
    let vdone = run(&mut p_session, &f.host, veto);
    let v_digest = pending_digest(&vdone.pending[0]);
    let vr = receipt(&acct, &f.host, &h, &v_digest, now + 20 * SEC);
    hold_pending(
        &mut f.account,
        vec![
            twin_first(&vdone.pending[0]),
            vdone.pending[0].clone(),
            twin_first(&vr),
            vr.clone(),
        ],
    );
    assert_eq!(f.account.pending().len(), 1);
    assert_eq!(f.account.pending()[0].vetoes.len(), 1, "the veto once");
    let rec = f.account.record_due().unwrap();
    assert_eq!(rec.len(), 1, "the vetoed entry is recorded");
    assert!(f.account.controllers().iter().any(|c| c.id == d2));
    assert_eq!(f.account.status().code, "ok");
}

#[test]
fn a_keyless_twin_of_a_due_transition_does_not_stop_its_activation() {
    let mut f = create(&["notes"]);
    let now = f.account.now_ms();
    let action = f
        .account
        .begin_transition(
            &Change::policy(json!({"callWindow": 600})),
            &[f.d.clone()],
            TransitionRule::Control,
        )
        .unwrap();
    let done = run(&mut f.account, &f.host, action);
    hold_pending(&mut f.account, vec![twin_first(&done.pending[0])]);
    assert_eq!(f.account.pending().len(), 1);
    f.account.advance(now + 2 * HOUR).unwrap();
    assert_eq!(f.account.record_due().unwrap().len(), 1);
}

#[test]
fn another_accounts_secrets_open_nothing_here_and_a_member_ends_its_own_sessions() {
    let f1 = create(&["notes"]);
    let f2 = create_v(&["notes"], 1);
    let mut a1 = Account::open(
        f1.account.objects().clone(),
        vec![],
        None,
        Identity::Controller(f1.d.clone()),
        T0,
    )
    .unwrap();
    // Account 2's device answers account 1's device slot: a different key, a different vault.
    let inputs = a1.begin_unlock_slot(0).unwrap();
    let wrong: Vec<OpeningSecret> = inputs
        .iter()
        .map(|i| match i {
            OpeningInput::Ecdh { enc, .. } => {
                OpeningSecret::Ecdh(f2.host.ids[&f2.d].agree(enc).unwrap())
            }
            OpeningInput::Prf { .. } => unreachable!(),
        })
        .collect();
    assert_eq!(
        a1.finish_unlock_slot(0, &wrong).unwrap_err(),
        Failure::Refused(Reason::VaultLocked)
    );
    assert!(!a1.is_unlocked());
    // A member ends its own sessions with its own key (§8.4 "Member rule").
    let mut f = create(&["notes"]);
    let agent = f.host.identity(30);
    admit(
        &mut f,
        &agent,
        "Claude",
        "agent",
        agent_terms("write"),
        agent_terms("write"),
    );
    let mut a = member_session(&f, &agent);
    let action = a.begin_end_my_sessions().unwrap();
    assert_eq!(action.steps().len(), 1);
    assert_eq!(action.steps()[0].signer(), agent);
    let done = run(&mut a, &f.host, action);
    assert_eq!(done.changes.authority.entries[0].1, "endSessions");
    assert_eq!(a.members()[0].session, 1);
    // A controller session cannot.
    assert!(f.account.begin_end_my_sessions().is_err());
    // Creation refuses more controllers than §6.2 allows, before allocating for them.
    let mut host = Host::new();
    let (d, k) = (host.identity(10), host.kit(20));
    let p = host.passkey();
    let mut params = params(&mut host, &d, &p, &k, &["notes"]);
    params.controllers = vec![params.controllers[0].clone(); 65];
    assert!(Creation::begin(params, Identity::Controller(d), T0).is_err());
}

// ---------------------------------------------------------------------------------------------
// Thresholds and policy.

#[test]
fn policy_tightens_at_once_and_thresholds_change_by_a_transition() {
    let mut f = create(&["notes"]);
    // Lowering a window is an immediate `keyring` entry (§8.4).
    let action = f
        .account
        .begin_keyring(
            &KeyringEdit {
                policy: Some(json!({"callWindow": 120})),
                ..Default::default()
            },
            &[f.d.clone()],
        )
        .unwrap();
    run(&mut f.account, &f.host, action);
    assert_eq!(f.account.policy().call_window, 120);
    // Loosening it again is not: the verifier refuses at finish, and nothing changes.
    let before = f.account.status();
    let action = f.account.begin_keyring(
        &KeyringEdit {
            policy: Some(json!({"callWindow": 600})),
            ..Default::default()
        },
        &[f.d.clone()],
    );
    match action {
        Err(e) => assert_eq!(e.code(), "malformed", "{e}"),
        Ok(a) => {
            let sigs = f.host.sign(a.steps());
            assert_eq!(f.account.finish(a, sigs).unwrap_err().code(), "malformed");
        }
    }
    assert_eq!(f.account.status(), before);
    assert_eq!(f.account.policy().call_window, 120);
    // The threshold rises to 2 by a transition every control key and a recovery key sign
    // (raising needs consent, §18): a full set, due at once.
    let action = f
        .account
        .begin_transition(
            &Change::thresholds(Some(2), None, None),
            &[f.d.clone(), f.p.clone(), f.k.clone()],
            TransitionRule::Control,
        )
        .unwrap();
    run(&mut f.account, &f.host, action);
    assert_eq!(f.account.policy().threshold, 1);
    assert_eq!(f.account.record_due().unwrap().len(), 1);
    assert_eq!(f.account.policy().threshold, 2);
    // Member actions are still one approver (memberRule single); a rekey now needs the
    // `single` rule's one approver too.
    let seed = f.host.fresh();
    let action = f
        .account
        .begin_rekey(&["notes".to_string()], &[f.d.clone()], seed)
        .unwrap();
    run(&mut f.account, &f.host, action);
    // The ledger tells the story in order.
    let ledger = f.account.ledger();
    assert_eq!(ledger[0].event, "created");
    assert!(ledger.iter().any(|l| l.event == "activated"));
    assert_eq!(
        ledger.iter().map(|l| l.sequence).collect::<Vec<_>>(),
        (1..=ledger.len() as u64).collect::<Vec<_>>()
    );
}

#[test]
fn a_write_prepared_before_the_member_was_revoked_is_not_returned() {
    let mut f = create(&["notes"]);
    let agent = f.host.identity(30);
    admit(
        &mut f,
        &agent,
        "Claude",
        "agent",
        agent_terms("write"),
        agent_terms("write"),
    );
    let mut a = member_session(&f, &agent);
    let seed = f.host.fresh();
    let action = a
        .begin_write(
            "notes",
            "createNotebook",
            json!({"id": "b", "title": "T"}),
            Level::Write,
            seed,
        )
        .unwrap()
        .unwrap();
    let sigs = f.host.sign(action.steps());
    // The revocation lands first (keeping nothing).
    let seed = f.host.fresh();
    let revoke = f
        .account
        .begin_revoke(&agent, &RevokeKeep::Nothing, &[f.d.clone()], seed)
        .unwrap();
    let done = run(&mut f.account, &f.host, revoke);
    let now = a.now_ms();
    merge_done(&mut a, &done, now);
    let before = a.records().len();
    let e = a.finish(action, sigs).unwrap_err();
    assert_eq!(e.code(), "unavailable", "{e}");
    assert!(e.detail().contains("revokedBackdated"), "{e}");
    assert_eq!(a.records().len(), before, "nothing was held");
}

// ---------------------------------------------------------------------------------------------
// Renew and its shares, demotion, suspension.

#[test]
fn renew_carries_the_shares_of_epochs_made_while_a_member_was_expired() {
    let mut f = create(&["notes"]);
    let agent = f.host.identity(30);
    let t = json!({"records": [{"namespace": "notes", "access": "write"}],
                   "expires": colophon_core::v05::write::format_date(T0 + 2 * HOUR)});
    admit(&mut f, &agent, "Claude", "agent", t.clone(), t);
    // After it expired, a new epoch is introduced: the expired member is not sealed to it.
    f.account.advance(T0 + 3 * HOUR).unwrap();
    let seed = f.host.fresh();
    let action = f
        .account
        .begin_rekey(&["notes".to_string()], &[f.d.clone()], seed)
        .unwrap();
    run(&mut f.account, &f.host, action);
    let owed = f.account.owed_shares();
    assert_eq!(owed.len(), 1);
    assert_eq!(
        (owed[0].member.as_str(), owed[0].epoch),
        (agent.as_str(), 2)
    );
    assert_eq!(f.account.notices(0, &BTreeSet::new(), &[]).owed.len(), 1);
    // The renewal carries it (§9.4).
    let seed = f.host.fresh();
    let action = f
        .account
        .begin_renew(&agent, T0 + 48 * HOUR, &[f.d.clone()], seed)
        .unwrap();
    run(&mut f.account, &f.host, action);
    assert!(f.account.owed_shares().is_empty());
    let m = f.account.members();
    assert_eq!(m[0].expires_ms, Some(T0 + 48 * HOUR));
    // The member, once it holds the renewal, opens epoch 2 with its own key.
    let mut a = Account::open(
        f.account.objects().clone(),
        vec![],
        None,
        Identity::Member(agent.clone()),
        T0 + 3 * HOUR,
    )
    .unwrap();
    let steps = a.begin_unlock_epochs();
    assert_eq!(steps.len(), 2, "epochs 1 and 2");
    a.finish_unlock_epochs(f.host.answer_epochs(&agent, steps))
        .unwrap();
    assert!(matches!(
        a.view("notes").unwrap(),
        colophon_core::model::Outcome::Success { .. }
    ));
}

#[test]
fn a_demotion_drops_the_slot_and_retires_the_vault() {
    let mut f = create(&["notes"]);
    // The passkey loses `control` and `recover`: the recovery set consents (the kit signs).
    let demoted = f.host.passkey_controller("Passkey", &["approve"]);
    let action = f
        .account
        .begin_transition(
            &Change::update_controllers(vec![demoted]),
            &[f.d.clone(), f.k.clone()],
            TransitionRule::Control,
        )
        .unwrap();
    run(&mut f.account, &f.host, action);
    let rec = f.account.record_due().unwrap();
    assert_eq!(rec.len(), 1);
    let p = f
        .account
        .controllers()
        .into_iter()
        .find(|c| c.id == f.p)
        .unwrap();
    assert_eq!(p.roles, ["approve"]);
    assert!(!p.has_slot, "its slots are dropped at activation");
    let n = f.account.notices(0, &BTreeSet::new(), &[]);
    assert!(n.vault_retiring, "the demoted key may still know the seed");
}

#[test]
fn a_key_a_pending_removal_would_remove_is_suspended_by_a_signer_of_it() {
    let mut f = create(&["notes"]);
    let d2 = add_second_device(&mut f, &["approve"]);
    let h = appoint_home(&mut f);
    let now = f.account.now_ms();
    let acct = f.account.id().as_str().to_string();
    let action = f
        .account
        .begin_remove_controller(
            &[d2.clone()],
            &[],
            &[f.d.clone()],
            TransitionRule::Control,
            None,
        )
        .unwrap();
    let done = run(&mut f.account, &f.host, action);
    let t = pending_digest(&done.pending[0]);
    hold_pending(
        &mut f.account,
        vec![receipt(&acct, &f.host, &h, &t, now + 10 * SEC)],
    );
    assert!(
        !f.account
            .controllers()
            .iter()
            .find(|c| c.id == d2)
            .unwrap()
            .suspended
    );
    // A suspension is by a signer of the transition, of a key the transition removes.
    let e = f.account.begin_suspend(&f.p, &t, &f.d).unwrap_err();
    assert_eq!(e.code(), "malformed", "{e}");
    let action = f.account.begin_suspend(&d2, &t, &f.d).unwrap();
    run(&mut f.account, &f.host, action);
    assert!(
        f.account
            .controllers()
            .iter()
            .find(|c| c.id == d2)
            .unwrap()
            .suspended
    );
    // A suspended key's own signature is refused by prepare.
    let seed = f.host.fresh();
    assert!(f
        .account
        .begin_keyring(
            &KeyringEdit {
                policy: Some(json!({"callWindow": 100})),
                ..Default::default()
            },
            &[d2.clone()],
        )
        .is_err());
    let _ = seed;
}

#[test]
fn the_stored_state_of_another_account_is_not_mixed_into_this_one() {
    let mut f1 = create(&["notes"]);
    let mut f2 = create_v(&["notes"], 1);
    // Account 2's state, exported for account 2's identity under the same key.
    let theirs = f2.account.export_persisted(&KEY, [4; 32]).unwrap();
    let a = Account::open(
        f1.account.objects().clone(),
        vec![],
        Some((&theirs, &KEY)),
        Identity::Controller(f1.d.clone()),
        T0,
    )
    .unwrap();
    assert_eq!(a.id(), f1.account.id());
    assert_eq!(a.status().seq, f1.account.status().seq);
    // Even for the same identity ID it is account 1's objects that stand, not account 2's.
    let b = Account::open(
        f1.account.objects().clone(),
        vec![],
        Some((&theirs, &KEY)),
        Identity::Controller(f2.d.clone()),
        T0,
    )
    .unwrap();
    assert_eq!(
        b.id(),
        f1.account.id(),
        "the blob claims another account and is dropped"
    );
    let _ = &mut f1;
}

// ---------------------------------------------------------------------------------------------
// Ported from the independent check (2026-11-14).
fn review_entries(done: &Finished) -> Incoming {
    Incoming {
        objects: Objects {
            entries: done.entries.iter().map(|(_, e)| e.clone()).collect(),
            pending: done.pending.clone(),
            ..Default::default()
        },
        records: done.records.clone(),
    }
}

/// A garbage envelope over a real entry's body, made with no key, sorts first and is the one
/// the verifier keeps: the valid entry is never judged.
#[test]
fn review_q1_a_garbage_envelope_over_a_real_body_truncates_the_history() {
    use colophon_core::v05::history::verify_history;
    let mut f = create(&["notes"]);
    let seed = f.host.fresh();
    let action = f
        .account
        .begin_rekey(&["notes".to_string()], &[f.d.clone()], seed)
        .unwrap();
    let done3 = run(&mut f.account, &f.host, action);
    let seed = f.host.fresh();
    let action = f
        .account
        .begin_rekey(&["notes".to_string()], &[f.d.clone()], seed)
        .unwrap();
    run(&mut f.account, &f.host, action);
    assert_eq!(f.account.status().seq, 4);
    assert_eq!(f.account.status().code, "ok");
    let good = done3.entries[0].1.clone();
    let mut v: Value = serde_json::from_slice(&good).unwrap();
    v["signature"] = json!(b64(&[0u8; 64]));
    let bad = canonical(&v).unwrap();
    assert!(bad < good, "the forged envelope sorts first");
    // The verifier, both orders.
    let mut first_good = f.account.objects().clone();
    first_good.entries.push(bad.clone());
    let mut first_bad = f.account.objects().clone();
    first_bad.entries.insert(0, bad.clone());
    let vg = verify_history(&first_good, &Persisted::default(), f.account.now_ms());
    let vb = verify_history(&first_bad, &Persisted::default(), f.account.now_ms());
    eprintln!(
        "verifier: good first -> {} seq {}; bad first -> {} seq {}",
        vg.code(),
        vg.branch.len(),
        vb.code(),
        vb.branch.len()
    );
    // The account: an honest account at seq 4 that is sent the garbage envelope.
    let before = f.account.status();
    let ch = f
        .account
        .merge(
            Incoming {
                objects: Objects {
                    entries: vec![bad.clone()],
                    ..Default::default()
                },
                records: vec![],
            },
            f.account.now_ms(),
        )
        .unwrap();
    let after = f.account.status();
    eprintln!(
        "account before {before:?}\naccount after {after:?}\nreorganized {}",
        ch.authority.reorganized
    );
    // And it never recovers: the genuine envelope is already held.
    let again = f
        .account
        .merge(
            Incoming {
                objects: Objects {
                    entries: vec![good.clone()],
                    ..Default::default()
                },
                records: vec![],
            },
            f.account.now_ms(),
        )
        .unwrap();
    eprintln!("after re-sending the genuine envelope: {:?}", again.status);
    let seed = f.host.fresh();
    let w = f
        .account
        .begin_rekey(&["notes".to_string()], &[f.d.clone()], seed);
    eprintln!("a write: {:?}", w.as_ref().err());
    assert_eq!(
        vg.code(),
        "ok",
        "the verifier keeps the valid entry whichever arrived first"
    );
    assert_eq!(
        vb.code(),
        "ok",
        "the verifier keeps the valid entry whichever arrived first"
    );
    assert_eq!(
        after.code, "ok",
        "a keyless envelope must not truncate an honest account"
    );
    assert_eq!(after.seq, 4);
}

/// Q8 / §17.2: the stored fold is never trusted on its bare bytes. A forged blob (here any
/// tampering, since the attacker has no key) ends in a replay: the revoked member stays
/// revoked and its late record is refused.
#[test]
fn review_q8_forged_persisted_state_unrevokes_a_member_and_admits_its_records() {
    let mut f = create(&["notes"]);
    let agent = f.host.identity(30);
    admit(
        &mut f,
        &agent,
        "Claude",
        "agent",
        agent_terms("write"),
        agent_terms("write"),
    );
    let mut m = member_session(&f, &agent);
    let seed = f.host.fresh();
    let action = f
        .account
        .begin_revoke(&agent, &RevokeKeep::Nothing, &[f.d.clone()], seed)
        .unwrap();
    run(&mut f.account, &f.host, action);
    // The revoked agent, which has not seen the revocation, writes.
    let mut host = std::mem::replace(&mut f.host, Host::new());
    let late = write_note(&mut m, &mut host, "x", "Written after revocation");
    f.host = host;
    let bytes = f.account.export_persisted(&KEY, [6; 32]).unwrap();
    let now = f.account.now_ms();
    let open = |stored: Option<(&[u8], &[u8; 32])>| {
        let mut a = Account::open(
            f.account.objects().clone(),
            late.records.clone(),
            stored,
            Identity::Controller(f.d.clone()),
            now,
        )
        .unwrap();
        unlock_controller(&f.host, &mut a, &f.d);
        a
    };
    let honest = open(None);
    let hv = format!("{:?}", honest.view("notes").unwrap());
    assert!(!hv.contains("Written after revocation"));
    let revoked_at = |a: &Account| {
        a.members()
            .into_iter()
            .find(|x| x.member.id == agent)
            .unwrap()
            .member
            .revoked_at
    };
    assert!(revoked_at(&honest).is_some());
    // A blob edited to say otherwise (bytes changed anywhere in the ciphertext) is dropped.
    for at in [bytes.len() - 1, bytes.len() / 2, bytes.len() - 20] {
        let mut forged = bytes.clone();
        forged[at] ^= 0x40;
        let a = open(Some((&forged, &KEY)));
        let fv = format!("{:?}", a.view("notes").unwrap());
        assert!(!fv.contains("Written after revocation"), "byte {at}");
        assert_eq!(revoked_at(&a), revoked_at(&honest), "byte {at}");
    }
    // The genuine blob is used and agrees with the replay.
    let a = open(Some((&bytes, &KEY)));
    assert_eq!(revoked_at(&a), revoked_at(&honest));
    assert!(!format!("{:?}", a.view("notes").unwrap()).contains("Written after revocation"));
}

/// Q10: a `control` controller added by a transition, then its own slot by a self-slot entry.
#[test]
fn review_q10_a_control_controller_added_by_a_transition_then_its_slot() {
    let mut f = create(&["notes"]);
    let d3 = f.host.identity(52);
    let mut s3 = Account::open(
        f.account.objects().clone(),
        vec![],
        None,
        Identity::Controller(d3.clone()),
        f.account.now_ms(),
    )
    .unwrap();
    let now = f.account.now_ms();
    let mut host = std::mem::replace(&mut f.host, Host::new());
    pair_and_transfer(&mut host, &f.account, &mut s3, now);
    f.host = host;
    let c = f
        .host
        .raw_controller(&d3, "Laptop", &["approve", "control"]);
    let action = f
        .account
        .begin_add_controller(&AddController {
            controller: c,
            mode: AddMode::Transition {
                signers: vec![f.d.clone()],
                rule: TransitionRule::Control,
            },
        })
        .unwrap();
    let done = run(&mut f.account, &f.host, action);
    assert_eq!(done.pending.len(), 1);
    f.account.advance(now + 2 * HOUR).unwrap();
    let rec = f.account.record_due().unwrap();
    eprintln!(
        "recorded {} entries: {:?}",
        rec.len(),
        rec.iter()
            .map(|r| r.entries.iter().map(|(s, _)| *s).collect::<Vec<_>>())
            .collect::<Vec<_>>()
    );
    assert!(f.account.controllers().iter().any(|c| c.id == d3));
    s3.merge(
        Incoming {
            objects: f.account.objects().clone(),
            records: vec![],
        },
        now + 2 * HOUR,
    )
    .unwrap();
    eprintln!("s3 standing {:?}", s3.me());
    let entropy = f.host.fresh();
    let action = s3.begin_add_slot(
        &d3,
        SlotPlan {
            controllers: vec![d3.clone()],
            label: "Laptop".into(),
        },
        entropy,
    );
    let action = match action {
        Ok(a) => a,
        Err(e) => panic!("begin_add_slot: {e}"),
    };
    let sigs = f.host.sign(action.steps());
    let r = s3.finish(action, sigs);
    eprintln!(
        "self-slot after a transition: {:?}",
        r.as_ref()
            .map(|d| d.entries.len())
            .map_err(|e| e.to_string())
    );
    let done = r.unwrap();
    f.account
        .merge(review_entries(&done), now + 2 * HOUR)
        .unwrap();
    assert!(
        f.account
            .controllers()
            .iter()
            .find(|c| c.id == d3)
            .unwrap()
            .has_slot
    );
}

/// `RevokeKeep::Explicit`: exactly the named header is kept; the other is refused.
#[test]
fn review_explicit_keep_keeps_only_what_it_names() {
    let mut f = create(&["notes"]);
    let agent = f.host.identity(30);
    admit(
        &mut f,
        &agent,
        "Claude",
        "agent",
        agent_terms("write"),
        agent_terms("write"),
    );
    let mut a = member_session(&f, &agent);
    let mut host = std::mem::replace(&mut f.host, Host::new());
    let r1 = write_note(&mut a, &mut host, "b1", "Kept one");
    let r2 = write_note(&mut a, &mut host, "b2", "Dropped two");
    f.host = host;
    let now = f.account.now_ms();
    merge_done(&mut f.account, &r1, now);
    merge_done(&mut f.account, &r2, now);
    let d1 = digest_of(&r1.records[0].bytes);
    let seed = f.host.fresh();
    let action = f
        .account
        .begin_revoke(
            &agent,
            &RevokeKeep::Explicit {
                kept: vec![d1.clone()],
                heads: vec![],
            },
            &[f.d.clone()],
            seed,
        )
        .unwrap();
    assert_eq!(action.info().kept, vec![d1]);
    run(&mut f.account, &f.host, action);
    let v = format!("{:?}", f.account.view("notes").unwrap());
    assert!(v.contains("Kept one"), "{v}");
    assert!(!v.contains("Dropped two") || v.contains("refused"), "{v}");
    let admitted = match f.account.view("notes").unwrap() {
        colophon_core::model::Outcome::Success { value, .. } => value.admitted.len(),
        _ => panic!(),
    };
    assert_eq!(admitted, 1);
    // A head naming a header this account does not hold is refused at prepare.
    let seed = f.host.fresh();
    let other = f.host.identity(31);
    admit(
        &mut f,
        &other,
        "Other",
        "agent",
        agent_terms("write"),
        agent_terms("write"),
    );
    let e = f.account.begin_revoke(
        &other,
        &RevokeKeep::Explicit {
            kept: vec![],
            heads: vec![("notes".into(), "0".repeat(64))],
        },
        &[f.d.clone()],
        seed,
    );
    assert!(e.is_err());
}

/// The last `control` key removed by a transition (§6.2: at least one holds `control`).
#[test]
fn review_removing_every_control_key_is_refused() {
    let mut f = create(&["notes"]);
    let r = f.account.begin_remove_controller(
        &[f.d.clone(), f.p.clone()],
        &[],
        &[f.d.clone(), f.p.clone(), f.k.clone()],
        TransitionRule::Control,
        None,
    );
    match r {
        Err(e) => eprintln!("prepare refuses: {e}"),
        Ok(action) => {
            let sigs = f.host.sign(action.steps());
            let done = f.account.finish(action, sigs);
            eprintln!(
                "finish: {:?}",
                done.as_ref()
                    .map(|d| d.pending.len())
                    .map_err(|e| e.to_string())
            );
            if done.is_ok() {
                let now = f.account.now_ms();
                f.account.advance(now + 2 * HOUR).unwrap();
                let rec = f.account.record_due();
                eprintln!(
                    "record_due: {:?}",
                    rec.as_ref().map(|v| v.len()).map_err(|e| e.to_string())
                );
                eprintln!(
                    "controllers now: {:?}",
                    f.account
                        .controllers()
                        .iter()
                        .map(|c| (c.id.clone(), c.roles.clone()))
                        .collect::<Vec<_>>()
                );
                assert!(f
                    .account
                    .controllers()
                    .iter()
                    .any(|c| c.roles.iter().any(|r| r == "control")));
            }
        }
    }
}

/// A pending transition whose only signer is removed (by an earlier-due transition) before it
/// is due: it must not activate, and `record_due` must not fail as a whole.
#[test]
fn review_a_pending_transition_whose_signer_is_removed_first() {
    let mut f = create(&["notes"]);
    let now = f.account.now_ms();
    // B: remove the passkey, signed by the device and the kit.
    let b = f
        .account
        .begin_remove_controller(
            &[f.p.clone()],
            &[],
            &[f.d.clone(), f.k.clone()],
            TransitionRule::Control,
            None,
        )
        .unwrap();
    run(&mut f.account, &f.host, b);
    // A: a policy change signed by the passkey alone, issued later.
    f.account.advance(now + 10 * SEC).unwrap();
    let a = f
        .account
        .begin_transition(
            &Change::policy(json!({"callWindow": 600})),
            &[f.p.clone()],
            TransitionRule::Control,
        )
        .unwrap();
    run(&mut f.account, &f.host, a);
    assert_eq!(f.account.pending().len(), 2);
    f.account.advance(now + 3 * HOUR).unwrap();
    let rec = f.account.record_due();
    eprintln!(
        "record_due: {:?}",
        rec.as_ref().map(|v| v.len()).map_err(|e| e.to_string())
    );
    let rec = rec.unwrap();
    for r in &rec {
        eprintln!(
            "recorded: controllers_removed {:?} policy_changed {}",
            r.changes.authority.controllers_removed, r.changes.authority.policy_changed
        );
    }
    eprintln!(
        "status {:?}; pending now {}; callWindow {}",
        f.account.status(),
        f.account.pending().len(),
        f.account.policy().call_window
    );
    assert!(!f.account.controllers().iter().any(|c| c.id == f.p));
    assert_eq!(rec.len(), 1, "only the removal activates");
    assert_eq!(f.account.status().code, "ok");
}

/// `revision` is local memory: the same objects merged in pieces give a different revision
/// than opened at once (the builder's order test only compares sessions unlocked last).
#[test]
fn review_revision_depends_on_merge_history() {
    let mut f = create(&["notes"]);
    let agent = f.host.identity(30);
    admit(
        &mut f,
        &agent,
        "Claude",
        "agent",
        agent_terms("write"),
        agent_terms("write"),
    );
    let mut m = member_session(&f, &agent);
    let mut host = std::mem::replace(&mut f.host, Host::new());
    let w: Vec<Finished> = (0..3)
        .map(|i| write_note(&mut m, &mut host, &format!("b{i}"), "T"))
        .collect();
    f.host = host;
    let recs: Vec<HeldRecord> = w.iter().flat_map(|d| d.records.clone()).collect();
    let now = f.account.now_ms();
    let mut once = Account::open(
        f.account.objects().clone(),
        recs.clone(),
        None,
        Identity::Controller(f.d.clone()),
        now,
    )
    .unwrap();
    unlock_controller(&f.host, &mut once, &f.d);
    let mut piecewise = Account::open(
        f.account.objects().clone(),
        vec![],
        None,
        Identity::Controller(f.d.clone()),
        now,
    )
    .unwrap();
    unlock_controller(&f.host, &mut piecewise, &f.d);
    for r in recs {
        piecewise
            .merge(
                Incoming {
                    objects: Objects::default(),
                    records: vec![r],
                },
                now,
            )
            .unwrap();
    }
    eprintln!(
        "revision at once {} / piecewise {}",
        once.revision("notes"),
        piecewise.revision("notes")
    );
    assert_eq!(
        fingerprint(&once, &f.host, &f.d)["view"],
        fingerprint(&piecewise, &f.host, &f.d)["view"]
    );
}

/// Hostile stored bytes must not panic and must not block opening.
#[test]
fn review_hostile_persisted_state_does_not_panic() {
    let mut f = create(&["notes"]);
    let bytes = f.account.export_persisted(&KEY, [8; 32]).unwrap();
    let now = f.account.now_ms();
    let mut cases: Vec<Vec<u8>> = vec![
        vec![],
        vec![0; 7],
        b"COLOPS05".to_vec(),
        bytes[..bytes.len() / 2].to_vec(),
    ];
    for len in [0u32, 1, 1024, 1025, u32::MAX] {
        let mut b = bytes.clone();
        b[8..12].copy_from_slice(&len.to_le_bytes());
        cases.push(b);
    }
    for (i, junk) in cases.into_iter().enumerate() {
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Account::open(
                f.account.objects().clone(),
                vec![],
                Some((&junk, &KEY)),
                Identity::Controller(f.d.clone()),
                now,
            )
            .map(|a| a.status().code)
        }));
        assert_eq!(r.unwrap().unwrap(), "ok", "case {i}");
    }
}

fn review_resign(v: &mut Value, sig: &str) {
    match v {
        Value::Object(m) => {
            for (k, x) in m.iter_mut() {
                if k == "signature" && x.is_string() {
                    *x = json!(sig);
                } else {
                    review_resign(x, sig);
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(|x| review_resign(x, sig)),
        _ => {}
    }
}

/// The pending side of Q1: `Pending::parse` keeps the LAST held envelope over a transition body
/// (a map insert), and the account holds pending objects in byte order. A keyless envelope over
/// a real pending transition's body that sorts last replaces it.
#[test]
fn review_q1_a_garbage_envelope_over_a_pending_transition_blocks_its_activation() {
    let mut f = create(&["notes"]);
    let now = f.account.now_ms();
    let action = f
        .account
        .begin_transition(
            &Change::policy(json!({"callWindow": 600})),
            &[f.d.clone()],
            TransitionRule::Control,
        )
        .unwrap();
    let done = run(&mut f.account, &f.host, action);
    let real = done.pending[0].clone();
    let mut v: Value = serde_json::from_slice(&real).unwrap();
    eprintln!(
        "transition envelope keys: {:?}",
        v.as_object().unwrap().keys().collect::<Vec<_>>()
    );
    let zz: Vec<u8> = [0xCFu8, 0x3C, 0xF3]
        .iter()
        .cycle()
        .take(64)
        .cloned()
        .collect();
    review_resign(&mut v, &b64(&zz));
    let forged = canonical(&v).unwrap();
    assert!(forged > real, "sorts last");
    // A second account holding the same objects, and the forged one.
    let mut a = Account::open(
        f.account.objects().clone(),
        vec![],
        None,
        Identity::Controller(f.d.clone()),
        now,
    )
    .unwrap();
    a.merge(
        Incoming {
            objects: Objects {
                pending: vec![forged],
                ..Default::default()
            },
            records: vec![],
        },
        now,
    )
    .unwrap();
    eprintln!(
        "pending before: honest {} / attacked {}",
        f.account.pending().len(),
        a.pending().len()
    );
    f.account.advance(now + 2 * HOUR).unwrap();
    a.advance(now + 2 * HOUR).unwrap();
    let h = f.account.record_due().unwrap().len();
    let x = a.record_due();
    eprintln!(
        "honest recorded {h}; attacked: {:?}; attacked policy callWindow {}",
        x.as_ref().map(|v| v.len()).map_err(|e| e.to_string()),
        a.policy().call_window
    );
    assert_eq!(h, 1);
    assert_eq!(
        x.unwrap().len(),
        1,
        "a keyless envelope must not stop a valid transition"
    );
}
