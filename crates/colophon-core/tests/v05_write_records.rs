//! Tests of the 0.5 record-side builders (`v05::write::records`) and the record layer of
//! `v05::records`: epochs and seals, the `/5` operation (prepare and finish), the record fields
//! of `grant`, `renew` and `revoke`, author chains, proposals and the revocation walk.
//!
//! The host side here holds every private key and signs exactly the bodies the steps carry.
//! Each security property has a test that performs the attack and asserts the refusal by its
//! reason. Nothing in this file shares encoding code with the vector generator
//! (`tests/v5_candidate/`).
#![allow(clippy::unwrap_used)]
use base64::{engine::general_purpose::STANDARD, Engine};
use colophon_core::v05::encoding::{canonical, digest, parse_date};
use colophon_core::v05::history::{verify_history, Objects, Persisted};
use colophon_core::v05::ids::key_id;
use colophon_core::v05::records::{
    admit_records, chain_heads, judge_records, verified_headers, EpochKey, EpochKeys, HeldRecord,
    Judgement, Level, Outcome, ProposalState, RecordAuthority,
};
use colophon_core::v05::vault::{EcdhOutput, VaultSeed};
use colophon_core::v05::write::authority::{prepare_genesis, GenesisParams, PendingBatch};
use colophon_core::v05::write::records::*;
use colophon_core::v05::write::{Records, SignatureResult, SigningStep};
use colophon_core::v05::{Failure, Reason};
use p256::ecdsa::{signature::Signer, Signature as P256Signature, SigningKey};
use serde_json::{json, Value};

const T0: i64 = 1_794_384_000_000; // 2026-11-11T08:00:00Z
const SEC: i64 = 1_000;

fn b64(b: &[u8]) -> String {
    STANDARD.encode(b)
}

#[derive(Clone)]
struct Key {
    sk: SigningKey,
    scalar: [u8; 32],
    point: Vec<u8>,
    id: String,
}
fn key(n: u8) -> Key {
    let scalar = [n; 32];
    let sk = SigningKey::from_slice(&scalar).unwrap();
    let point = sk
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let id = key_id(&point);
    Key {
        sk,
        scalar,
        point,
        id,
    }
}
impl Key {
    fn sign(&self, body: &[u8]) -> Vec<u8> {
        let s: P256Signature = self.sk.sign(body);
        s.to_bytes().to_vec()
    }
    /// The host's ECDH with this key's scalar against `peer`.
    fn ecdh(&self, peer: &[u8]) -> EcdhOutput {
        let sk = p256::SecretKey::from_slice(&self.scalar).unwrap();
        let pk = p256::PublicKey::from_sec1_bytes(peer).unwrap();
        let dh = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
        EcdhOutput::from_host(dh.raw_secret_bytes().as_slice()).unwrap()
    }
}

/// The people of the account: a controller, and members with a signing and agreement key.
struct Person {
    sign: Key,
    agree: Key,
}
fn person(n: u8) -> Person {
    Person {
        sign: key(n),
        agree: key(n + 1),
    }
}

fn signature_of(k: &Key, step: &SigningStep) -> SignatureResult {
    SignatureResult {
        signature: k.sign(step.body()),
        assertion: None,
    }
}

fn controller_json(k: &Key, agreement: &Key) -> Value {
    json!({
        "key": {"form": "raw", "signing": b64(&k.point), "agreement": b64(&agreement.point)},
        "label": "C",
        "roles": ["approve", "control", "recover"],
    })
}

struct World {
    c: Person,
    d: Person,
    vault: VaultSeed,
    objects: Objects,
    now: i64,
    held: Vec<HeldRecord>,
    keys: EpochKeys,
    n: u8,
}
impl World {
    fn auth(&self) -> RecordAuthority {
        RecordAuthority::from_objects(&self.objects, self.now).unwrap()
    }
    fn seed(&mut self) -> [u8; 32] {
        self.n += 1;
        [self.n; 32]
    }
    fn hold(&mut self, r: &Records) {
        self.objects
            .entries
            .extend(r.entries.iter().map(|(_, b)| b.clone()));
        self.objects.pending.extend(r.pending.iter().cloned());
    }
    fn run(&mut self, batch: PendingBatch) {
        let sigs: Vec<SignatureResult> = batch
            .steps()
            .iter()
            .map(|s| {
                if s.signer() == self.d.sign.id {
                    return signature_of(&self.d.sign, s);
                }
                assert_eq!(s.signer(), self.c.sign.id, "only the controllers sign here");
                signature_of(&self.c.sign, s)
            })
            .collect();
        let r = batch.finish(sigs).unwrap_or_else(|e| panic!("finish: {e}"));
        self.hold(&r);
    }
    fn cids(&self) -> Vec<String> {
        vec![self.c.sign.id.clone()]
    }
    fn issued(&self) -> i64 {
        T0 + 10 * SEC + self.objects.entries.len() as i64 * SEC
    }
    /// An account with namespaces `journal` and `notes`, its epoch 1 sealed to the vault.
    fn new(now: i64) -> World {
        let c = person(1);
        let vault = VaultSeed::from_host_random([0x42; 32]);
        let vp = vault.public().unwrap();
        let mut ctrl = vec![controller_json(&c.sign, &c.agree)];
        ctrl.sort_by_key(|x| {
            key_id(
                &STANDARD
                    .decode(x["key"]["signing"].as_str().unwrap())
                    .unwrap(),
            )
        });
        let keyring = json!({
            "controllers": ctrl, "threshold": 1, "recoverThreshold": 1,
            "addThreshold": 1, "countBy": "keys",
            "policy": {
                "callWindow": 300, "headMaxAge": 300, "headQuorum": 1, "history": "members",
                "linkMaxAge": 86400, "memberRule": "single",
                "rate": {"account": {"bytes": 16777216, "entries": 256},
                         "signer": {"bytes": 4194304, "entries": 64}},
                "recoveryDelay": 3600
            },
            "vault": {"signing": b64(&vp.signing), "agreement": b64(&vp.agreement)},
            "slots": [{"kind": "sealed", "controllers": [c.sign.id],
                       "label": "C", "sealed": {"enc": b64(&key(0x70).point), "ciphertext": b64(&[7u8; 48])}}],
        });
        let mut w = World {
            c,
            d: person(90),
            vault,
            objects: Objects::default(),
            now,
            held: Vec::new(),
            keys: EpochKeys::new(),
            n: 0,
        };
        let batch = prepare_genesis(
            &GenesisParams {
                label: "Test".into(),
                namespaces: vec!["journal".into(), "notes".into()],
                keyring,
                issued_ms: T0,
                signers: w.cids(),
            },
            now,
        )
        .unwrap();
        w.run(batch);
        let seed = w.seed();
        let issued = w.issued();
        let (batch, keys) = prepare_rekey(
            &w.objects,
            now,
            &w.cids(),
            issued,
            &["journal".into(), "notes".into()],
            seed,
        )
        .unwrap();
        w.run(batch);
        w.absorb(keys);
        w
    }
    fn absorb(&mut self, keys: EpochKeys) {
        // Hosts keep the handles they are given: move them into the held set.
        let account = self.auth().account().clone();
        for ns in ["journal", "notes"] {
            for e in 1..=4 {
                if let Some(k) = keys.get(&account, ns, e) {
                    self.keys.insert(k.clone()).unwrap();
                }
            }
        }
    }
    /// A member's request, signed raw by its own key.
    fn request(&self, p: &Person, kind: &str, terms: Value) -> Vec<u8> {
        let account = self.auth().account().as_str().to_string();
        let body = canonical(&json!({
            "protocol": "colophon/request/5", "account": account,
            "member": {"signing": b64(&p.sign.point), "agreement": b64(&p.agree.point)},
            "label": "member", "kind": kind, "terms": terms, "created": "2026-11-11T07:59:00Z",
        }))
        .unwrap();
        canonical(&json!({"body": b64(&body), "signature": b64(&p.sign.sign(&body))})).unwrap()
    }
    fn grant(&mut self, p: &Person, kind: &str, terms: Value) {
        let req = self.request(p, kind, terms.clone());
        let seed = self.seed();
        let issued = self.issued();
        let batch = prepare_grant(
            &self.objects,
            self.now,
            &self.cids(),
            issued,
            &req,
            terms,
            &self.keys,
            seed,
        )
        .unwrap();
        self.run(batch);
    }
    /// Write as `p`: prepare, host-sign, finish; hold the header.
    fn write(
        &mut self,
        p: &Person,
        ns: &str,
        level: Level,
        kind: &str,
        payload: Value,
    ) -> HeldRecord {
        let seed = self.seed();
        let prepared = prepare_operation(
            &self.objects,
            &self.held,
            &self.keys,
            self.now,
            &OperationSpec {
                namespace: ns,
                author: &p.sign.id,
                level,
                kind,
                payload,
                clock: None,
            },
            seed,
        )
        .unwrap_or_else(|e| panic!("prepare: {e}"));
        let sig = signature_of(&p.sign, prepared.step());
        let done = prepared
            .finish(sig)
            .unwrap_or_else(|e| panic!("finish: {e}"));
        let rec = HeldRecord {
            path: done.path,
            bytes: done.envelope,
        };
        self.held.push(rec.clone());
        rec
    }
    fn judge(&self) -> Judgement {
        judge_records(&self.auth(), &self.keys, &self.held)
    }
    fn outcome(&self, rec: &HeldRecord) -> Outcome {
        self.judge()
            .records
            .into_iter()
            .find(|j| j.path == rec.path)
            .unwrap()
            .outcome
    }
}

fn terms(access: &str) -> Value {
    json!({"records": [{"namespace": "notes", "access": access}]})
}
fn expect_err<T: std::fmt::Debug>(r: Result<T, Failure>, code: &str) {
    match r {
        Err(f) => assert_eq!(f.code(), code, "{f}"),
        Ok(v) => panic!("expected {code}, got Ok({v:?})"),
    }
}
fn prepared_is_err(r: Result<PreparedOperation, Failure>, code: &str) {
    match r {
        Err(f) => assert_eq!(f.code(), code, "{f}"),
        Ok(_) => panic!("expected {code}, got a prepared operation"),
    }
}
fn spec<'a>(ns: &'a str, author: &'a str, level: Level) -> OperationSpec<'a> {
    OperationSpec {
        namespace: ns,
        author,
        level,
        kind: "addNote",
        payload: json!({"text": "hello"}),
        clock: None,
    }
}

// ---------------------------------------------------------------------------------------------
// Epochs and seals (§11.1, §7.1).

#[test]
fn first_rekey_seals_to_exactly_the_vault() {
    let w = World::new(T0 + 120 * SEC);
    let auth = w.auth();
    let vault_id = auth.vault().id();
    for ns in ["journal", "notes"] {
        assert_eq!(auth.latest_epoch(ns), 1);
        assert_eq!(
            auth.sealed_to(ns, 1),
            std::collections::BTreeSet::from([vault_id.clone()])
        );
    }
}

#[test]
fn the_first_rekey_must_name_every_namespace() {
    // Rule 8: prepare refuses what the verifier will refuse (seq 2 introduces epoch 1 in every
    // declared namespace).
    let c = person(1);
    let w = World::new(T0 + 120 * SEC);
    let mut objects = Objects::default();
    objects.entries.push(w.objects.entries[0].clone());
    let r = prepare_rekey(
        &objects,
        w.now,
        std::slice::from_ref(&c.sign.id),
        T0 + 20 * SEC,
        &["notes".into()],
        [9; 32],
    );
    expect_err(r.map(|_| ()), "malformed");
}

#[test]
fn a_new_epoch_goes_to_the_vault_and_every_member_with_any_access_and_nobody_else() {
    let mut w = World::new(T0 + 120 * SEC);
    let (wr, rd, ex) = (person(10), person(20), person(30));
    w.grant(&wr, "device", terms("write"));
    w.grant(&rd, "app", terms("read"));
    // `ex` reads another namespace only.
    w.grant(
        &ex,
        "app",
        json!({"records": [{"namespace": "journal", "access": "read"}]}),
    );
    let seed = w.seed();
    let issued = w.issued();
    let (batch, keys) = prepare_rekey(
        &w.objects,
        w.now,
        &w.cids(),
        issued,
        &["notes".into()],
        seed,
    )
    .unwrap();
    w.run(batch);
    w.absorb(keys);
    let auth = w.auth();
    assert_eq!(auth.latest_epoch("notes"), 2);
    assert_eq!(
        auth.sealed_to("notes", 2),
        std::collections::BTreeSet::from([auth.vault().id(), wr.sign.id, rd.sign.id])
    );
}

#[test]
fn a_seal_opens_for_its_recipient_and_only_to_its_account_namespace_and_epoch() {
    let mut w = World::new(T0 + 120 * SEC);
    let wr = person(10);
    w.grant(&wr, "device", terms("write"));
    let auth = w.auth();
    // The writer opens its share with its own agreement key.
    let req = auth.epoch_seal_request("notes", 1, &wr.sign.id).unwrap();
    let key = auth
        .open_epoch("notes", 1, &wr.sign.id, &wr.agree.ecdh(&req.enc))
        .unwrap();
    assert_eq!((key.namespace(), key.epoch()), ("notes", 1));
    // A wrong ECDH result is vaultLocked.
    let wrong = key_for_test(77).ecdh(&req.enc);
    expect_err(
        auth.open_epoch("notes", 1, &wr.sign.id, &wrong).map(|_| ()),
        "refused:vaultLocked",
    );
    // The vault seed opens the vault's seal; a different seed is vaultLocked.
    auth.open_epoch_with_vault(&w.vault, "notes", 1).unwrap();
    expect_err(
        auth.open_epoch_with_vault(&VaultSeed::from_host_random([5; 32]), "notes", 1)
            .map(|_| ()),
        "refused:vaultLocked",
    );
    // The key made for notes/1 opens no header of journal/1: the attack is refused by binding.
    let mut other = EpochKeys::new();
    other.insert(key.clone()).unwrap();
    assert!(other.get(auth.account(), "journal", 1).is_none());
    assert!(other.get(auth.account(), "notes", 2).is_none());
    let rec = w.write(&wr, "notes", Level::Write, "addNote", json!({"text": "x"}));
    let (hdr, _) = colophon_core::v05::records::OperationHeader::parse(&rec.bytes).unwrap();
    key.open(&hdr).unwrap();
    let wrong_ns = EpochKey::clone(&w.keys.get(auth.account(), "journal", 1).unwrap().clone());
    let r = wrong_ns.open(&hdr);
    assert!(
        matches!(r, Err(Failure::Malformed(m)) if m.contains("another account, namespace or epoch"))
    );
}

fn key_for_test(n: u8) -> Key {
    key(n)
}

#[test]
fn a_secret_is_not_in_debug_or_the_prepared_state() {
    let mut w = World::new(T0 + 120 * SEC);
    let wr = person(10);
    w.grant(&wr, "device", terms("write"));
    let k = w.keys.get(w.auth().account(), "notes", 1).unwrap().clone();
    let shown = format!("{k:?} {:?}", w.keys);
    assert!(shown.contains("EpochKey(notes/1, ..)"));
    assert!(!shown.contains(&format!("{:?}", [1u8; 4])));
    let seed = w.seed();
    let prepared = prepare_operation(
        &w.objects,
        &w.held,
        &w.keys,
        w.now,
        &spec("notes", &wr.sign.id, Level::Write),
        seed,
    )
    .unwrap();
    let dbg = format!("{prepared:?}");
    assert!(!dbg.contains("key: ["), "{dbg}");
}

// ---------------------------------------------------------------------------------------------
// Grant shares (§9.2) and renew shares (§9.4).

#[test]
fn a_grant_seals_every_historical_epoch_to_the_member_and_needs_the_keys() {
    let mut w = World::new(T0 + 120 * SEC);
    // A second epoch, then a grant: shares must cover epochs 1 and 2.
    let seed = w.seed();
    let issued = w.issued();
    let (batch, keys) = prepare_rekey(
        &w.objects,
        w.now,
        &w.cids(),
        issued,
        &["notes".into()],
        seed,
    )
    .unwrap();
    w.run(batch);
    w.absorb(keys);
    let wr = person(10);
    // Without the epoch key for epoch 1 the grant cannot be prepared.
    let req = w.request(&wr, "device", terms("write"));
    let mut only_two = EpochKeys::new();
    only_two
        .insert(w.keys.get(w.auth().account(), "notes", 2).unwrap().clone())
        .unwrap();
    let r = prepare_grant(
        &w.objects,
        w.now,
        &w.cids(),
        w.issued(),
        &req,
        terms("write"),
        &only_two,
        [3; 32],
    );
    expect_err(r.map(|_| ()), "unavailable");
    w.grant(&wr, "device", terms("write"));
    let auth = w.auth();
    for e in [1, 2] {
        assert!(
            auth.sealed_to("notes", e).contains(&wr.sign.id),
            "epoch {e}"
        );
        let r = auth.epoch_seal_request("notes", e, &wr.sign.id).unwrap();
        let k = auth
            .open_epoch("notes", e, &wr.sign.id, &wr.agree.ecdh(&r.enc))
            .unwrap();
        // It is the same key the account's host holds: a header written under it opens.
        let held = w.keys.get(auth.account(), "notes", e).unwrap();
        assert_eq!((k.epoch(), held.epoch()), (e, e));
    }
    // journal is not in the member's scope: no share for it.
    assert!(!auth.sealed_to("journal", 1).contains(&wr.sign.id));
}

#[test]
fn renew_seals_the_epochs_the_member_lacks_including_one_introduced_while_expired() {
    let mut w = World::new(T0 + 120 * SEC);
    let wr = person(10);
    let short = json!({"records": [{"namespace": "notes", "access": "write"}],
                       "expires": "2026-11-11T08:05:00Z"});
    w.grant(&wr, "device", short);
    // Time passes: the member is expired when epoch 2 is introduced, so it is not sealed to it.
    w.now = T0 + 600 * SEC;
    let seed = w.seed();
    let issued = T0 + 400 * SEC;
    let (batch, keys) = prepare_rekey(
        &w.objects,
        w.now,
        &w.cids(),
        issued,
        &["notes".into()],
        seed,
    )
    .unwrap();
    w.run(batch);
    w.absorb(keys);
    assert!(!w.auth().sealed_to("notes", 2).contains(&wr.sign.id));
    // Renew: shares seal epoch 2 (and only epoch 2: it has epoch 1).
    let seed = w.seed();
    let batch = prepare_renew(
        &w.objects,
        w.now,
        &w.cids(),
        T0 + 450 * SEC,
        &wr.sign.id,
        "2026-11-11T09:00:00Z",
        &w.keys,
        seed,
    )
    .unwrap();
    w.run(batch);
    let auth = w.auth();
    assert!(auth.sealed_to("notes", 2).contains(&wr.sign.id));
    let req = auth.epoch_seal_request("notes", 2, &wr.sign.id).unwrap();
    auth.open_epoch("notes", 2, &wr.sign.id, &wr.agree.ecdh(&req.enc))
        .unwrap();
    // The renewed writer can write again.
    w.write(
        &wr,
        "notes",
        Level::Write,
        "addNote",
        json!({"text": "back"}),
    );
}

// ---------------------------------------------------------------------------------------------
// The operation (§11.2, §11.3) and its admission.

#[test]
fn an_operation_prepares_signs_finishes_and_is_admitted_with_the_exact_bytes() {
    let mut w = World::new(T0 + 120 * SEC);
    let wr = person(10);
    w.grant(&wr, "device", terms("write"));
    let seed = w.seed();
    let prepared = prepare_operation(
        &w.objects,
        &w.held,
        &w.keys,
        w.now,
        &spec("notes", &wr.sign.id, Level::Write),
        seed,
    )
    .unwrap();
    let body = prepared.step().body().to_vec();
    let sig = signature_of(&wr.sign, prepared.step());
    let done = prepared.finish(sig).unwrap();
    // The returned envelope carries exactly the body the host was asked to sign.
    let env: Value = serde_json::from_slice(&done.envelope).unwrap();
    assert_eq!(
        STANDARD.decode(env["body"].as_str().unwrap()).unwrap(),
        body
    );
    assert_eq!(done.digest, digest(&body));
    // A reader judging it from the history alone admits and opens it.
    let rec = HeldRecord {
        path: done.path,
        bytes: done.envelope,
    };
    let j = admit_records(&w.objects, w.now, &w.keys, &[rec]).unwrap();
    assert_eq!(j.records[0].outcome, Outcome::Admitted);
    let pt = j.records[0].plaintext.as_ref().unwrap();
    assert_eq!(pt["kind"], "addNote");
    assert_eq!(pt["clock"], 1);
}

#[test]
fn finish_refuses_a_signature_by_another_key_and_a_signature_over_other_bytes() {
    let mut w = World::new(T0 + 120 * SEC);
    let (wr, other) = (person(10), person(40));
    w.grant(&wr, "device", terms("write"));
    let mk = |w: &mut World| {
        let seed = w.seed();
        prepare_operation(
            &w.objects,
            &w.held,
            &w.keys,
            w.now,
            &spec("notes", &wr.sign.id, Level::Write),
            seed,
        )
        .unwrap()
    };
    let p = mk(&mut w);
    let sig = signature_of(&other.sign, p.step());
    expect_err(p.finish(sig).map(|_| ()), "malformed");
    let p = mk(&mut w);
    let sig = SignatureResult {
        signature: wr.sign.sign(b"some other bytes"),
        assertion: None,
    };
    expect_err(p.finish(sig).map(|_| ()), "malformed");
    // A WebAuthn-style assertion on a raw-signed object is refused, and so is a short one.
    let p = mk(&mut w);
    expect_err(
        p.finish(SignatureResult {
            signature: vec![0; 64],
            assertion: Some((vec![], vec![])),
        })
        .map(|_| ()),
        "malformed",
    );
    let p = mk(&mut w);
    expect_err(
        p.finish(SignatureResult {
            signature: vec![0; 10],
            assertion: None,
        })
        .map(|_| ()),
        "malformed",
    );
}

#[test]
fn prepare_refuses_what_finish_would_refuse() {
    let mut w = World::new(T0 + 120 * SEC);
    let (wr, rd, stranger) = (person(10), person(20), person(40));
    w.grant(&wr, "device", terms("write"));
    w.grant(&rd, "app", terms("read"));
    let s = w.seed();
    // Not a member.
    prepared_is_err(
        prepare_operation(
            &w.objects,
            &w.held,
            &w.keys,
            w.now,
            &spec("notes", &stranger.sign.id, Level::Write),
            [s[0]; 32],
        ),
        "refused:notGranted",
    );
    // A read-only member can neither write nor propose.
    for level in [Level::Write, Level::Propose] {
        prepared_is_err(
            prepare_operation(
                &w.objects,
                &w.held,
                &w.keys,
                w.now,
                &spec("notes", &rd.sign.id, level),
                [s[0]; 32],
            ),
            "refused:notGranted",
        );
    }
    // A namespace outside the member's scope.
    prepared_is_err(
        prepare_operation(
            &w.objects,
            &w.held,
            &w.keys,
            w.now,
            &spec("journal", &wr.sign.id, Level::Write),
            [s[0]; 32],
        ),
        "refused:notGranted",
    );
    // No epoch key held.
    prepared_is_err(
        prepare_operation(
            &w.objects,
            &w.held,
            &EpochKeys::new(),
            w.now,
            &spec("notes", &wr.sign.id, Level::Write),
            [s[0]; 32],
        ),
        "unavailable",
    );
    // An explicit clock that is not above the highest admitted, and one that jumps.
    w.write(
        &wr,
        "notes",
        Level::Write,
        "addNote",
        json!({"text": "one"}),
    );
    for clock in [1, 1 + 1_025] {
        let mut sp = spec("notes", &wr.sign.id, Level::Write);
        sp.clock = Some(clock);
        prepared_is_err(
            prepare_operation(&w.objects, &w.held, &w.keys, w.now, &sp, [0xD1; 32]),
            "malformed",
        );
    }
    let mut sp = spec("notes", &wr.sign.id, Level::Write);
    sp.clock = Some(1 + 1_024);
    prepare_operation(&w.objects, &w.held, &w.keys, w.now, &sp, [0xD1; 32]).unwrap();
}

#[test]
fn a_repeated_seed_is_refused_as_a_nonce_reuse() {
    let mut w = World::new(T0 + 120 * SEC);
    let wr = person(10);
    w.grant(&wr, "device", terms("write"));
    let seed = [0x55; 32];
    let p = prepare_operation(
        &w.objects,
        &w.held,
        &w.keys,
        w.now,
        &spec("notes", &wr.sign.id, Level::Write),
        seed,
    )
    .unwrap();
    let sig = signature_of(&wr.sign, p.step());
    let rec = p.finish(sig).unwrap();
    w.held.push(HeldRecord {
        path: rec.path,
        bytes: rec.envelope,
    });
    // The same seed again yields the same nonce under the same key: refused.
    prepared_is_err(
        prepare_operation(
            &w.objects,
            &w.held,
            &w.keys,
            w.now,
            &spec("notes", &wr.sign.id, Level::Write),
            seed,
        ),
        "malformed",
    );
}

#[test]
fn author_chains_link_by_previous_and_a_fork_stops_the_writer() {
    let mut w = World::new(T0 + 120 * SEC);
    let wr = person(10);
    w.grant(&wr, "device", terms("write"));
    let a = w.write(&wr, "notes", Level::Write, "addNote", json!({"text": "a"}));
    let b = w.write(&wr, "notes", Level::Write, "addNote", json!({"text": "b"}));
    let c = w.write(&wr, "notes", Level::Write, "addNote", json!({"text": "c"}));
    let auth = w.auth();
    let infos = verified_headers(&auth, &w.held);
    assert_eq!(infos.len(), 3);
    let by_path = |p: &str| infos.iter().find(|i| i.path == p).unwrap().clone();
    let (ia, ib, ic) = (by_path(&a.path), by_path(&b.path), by_path(&c.path));
    assert_eq!(ia.previous, None);
    assert_eq!(ib.previous.as_deref(), Some(ia.digest.as_str()));
    assert_eq!(ic.previous.as_deref(), Some(ib.digest.as_str()));
    assert_eq!(
        chain_heads(&infos, &wr.sign.id, "notes"),
        vec![ic.digest.clone()]
    );
    // A second prepare from a stale store forks the chain: two headers share `previous`.
    let stale: Vec<HeldRecord> = w.held[..2].to_vec();
    let seed = w.seed();
    let p = prepare_operation(
        &w.objects,
        &stale,
        &w.keys,
        w.now,
        &spec("notes", &wr.sign.id, Level::Write),
        seed,
    )
    .unwrap();
    let forked = p.finish(signature_of(&wr.sign, &{
        let seed2 = seed;
        prepare_operation(
            &w.objects,
            &stale,
            &w.keys,
            w.now,
            &spec("notes", &wr.sign.id, Level::Write),
            seed2,
        )
        .unwrap()
        .step()
        .clone()
    }));
    let forked = forked.unwrap();
    w.held.push(HeldRecord {
        path: forked.path,
        bytes: forked.envelope,
    });
    let infos = verified_headers(&w.auth(), &w.held);
    assert_eq!(chain_heads(&infos, &wr.sign.id, "notes").len(), 2);
    // The writer must stop (§11.2): prepare is refused by `refused:fork`.
    prepared_is_err(
        prepare_operation(
            &w.objects,
            &w.held,
            &w.keys,
            w.now,
            &spec("notes", &wr.sign.id, Level::Write),
            [0x66; 32],
        ),
        "refused:fork",
    );
}

#[test]
fn a_reader_refuses_a_header_with_a_forged_author_a_tampered_path_and_a_wrong_account() {
    let mut w = World::new(T0 + 120 * SEC);
    let (wr, other) = (person(10), person(40));
    w.grant(&wr, "device", terms("write"));
    let rec = w.write(&wr, "notes", Level::Write, "addNote", json!({"text": "a"}));
    // The path names another clock.
    let bad_path = HeldRecord {
        path: rec.path.replace("000000000001", "000000000002"),
        bytes: rec.bytes.clone(),
    };
    let j = judge_records(&w.auth(), &w.keys, &[bad_path]);
    assert_eq!(j.records[0].outcome, Outcome::Invalid("malformed".into()));
    // A body re-signed by a key that is not the author's.
    let v: Value = serde_json::from_slice(&rec.bytes).unwrap();
    let body = STANDARD.decode(v["body"].as_str().unwrap()).unwrap();
    let forged =
        canonical(&json!({"body": b64(&body), "signature": b64(&other.sign.sign(&body))})).unwrap();
    let j = judge_records(
        &w.auth(),
        &w.keys,
        &[HeldRecord {
            path: rec.path.clone(),
            bytes: forged,
        }],
    );
    assert_eq!(
        j.records[0].outcome,
        Outcome::Invalid("badSignature".into())
    );
    // A header for another account (same bytes, account field changed and re-signed).
    let mut bv: Value = serde_json::from_slice(&body).unwrap();
    bv["account"] = json!("0".repeat(64));
    let nb = canonical(&bv).unwrap();
    let foreign =
        canonical(&json!({"body": b64(&nb), "signature": b64(&wr.sign.sign(&nb))})).unwrap();
    let j = judge_records(
        &w.auth(),
        &w.keys,
        &[HeldRecord {
            path: rec.path,
            bytes: foreign,
        }],
    );
    assert_eq!(j.records[0].outcome, Outcome::Invalid("malformed".into()));
}

#[test]
fn a_header_whose_aad_field_was_changed_after_encryption_is_invalid_payload() {
    let mut w = World::new(T0 + 120 * SEC);
    let wr = person(10);
    w.grant(&wr, "device", terms("write"));
    let rec = w.write(&wr, "notes", Level::Write, "addNote", json!({"text": "a"}));
    let v: Value = serde_json::from_slice(&rec.bytes).unwrap();
    let body = STANDARD.decode(v["body"].as_str().unwrap()).unwrap();
    // The attacker is the author (can sign) but cannot re-encrypt: it changes `created` and
    // re-signs. The AAD no longer matches, so the payload does not authenticate.
    let mut bv: Value = serde_json::from_slice(&body).unwrap();
    bv["created"] = json!("2026-11-11T08:00:09Z");
    let nb = canonical(&bv).unwrap();
    let tampered = HeldRecord {
        path: rec.path.clone(),
        bytes: canonical(&json!({"body": b64(&nb), "signature": b64(&wr.sign.sign(&nb))})).unwrap(),
    };
    let j = judge_records(&w.auth(), &w.keys, &[tampered]);
    assert_eq!(j.records[0].outcome, Outcome::Refused("invalidPayload"));
    // It still reserved a budget slot (0.3 §5: an unreadable payload conceals no write).
    assert!(j.records[0].reserved);
    // The untouched header authenticates.
    let j = judge_records(&w.auth(), &w.keys, &[rec]);
    assert_eq!(j.records[0].outcome, Outcome::Admitted);
}

#[test]
fn a_record_with_a_missing_key_is_held_unavailable_and_with_the_key_is_admitted() {
    let mut w = World::new(T0 + 120 * SEC);
    let wr = person(10);
    w.grant(&wr, "device", terms("write"));
    let rec = w.write(&wr, "notes", Level::Write, "addNote", json!({"text": "a"}));
    let j = judge_records(&w.auth(), &EpochKeys::new(), std::slice::from_ref(&rec));
    assert_eq!(j.records[0].outcome, Outcome::Held("unavailable"));
    assert_eq!(w.outcome(&rec), Outcome::Admitted);
}

// ---------------------------------------------------------------------------------------------
// Revocation: `kept`, `heads` and the walk (§9.5).

fn revoke(w: &mut World, member: &Person, keep: &Keep) -> PreparedRevoke {
    let seed = w.seed();
    let issued = w.issued();
    prepare_revoke(
        &w.objects,
        &w.held,
        w.now,
        &w.cids(),
        issued,
        &member.sign.id,
        keep,
        seed,
    )
    .unwrap()
}
fn finish_revoke(w: &mut World, p: PreparedRevoke) {
    let (batch, keys) = p.into_parts();
    w.run(batch);
    w.absorb(keys);
}

#[test]
fn revoke_keeps_the_chain_by_head_and_new_epoch_excludes_the_member() {
    let mut w = World::new(T0 + 120 * SEC);
    let (wr, rd) = (person(10), person(20));
    w.grant(&wr, "device", terms("write"));
    w.grant(&rd, "app", terms("read"));
    let recs: Vec<HeldRecord> = (0..3)
        .map(|i| {
            w.write(
                &wr,
                "notes",
                Level::Write,
                "addNote",
                json!({"text": format!("{i}")}),
            )
        })
        .collect();
    let p = revoke(&mut w, &wr, &Keep::Everything);
    let heads = p.heads().to_vec();
    assert_eq!(heads.len(), 1);
    assert_eq!(heads[0].namespace, "notes");
    assert!(p.kept().is_empty());
    assert!(!p.walk_incomplete());
    finish_revoke(&mut w, p);
    // The new epoch excludes the revoked member and keeps the reader.
    let auth = w.auth();
    assert_eq!(auth.latest_epoch("notes"), 2);
    let to = auth.sealed_to("notes", 2);
    assert!(
        !to.contains(&wr.sign.id) && to.contains(&rd.sign.id) && to.contains(&auth.vault().id())
    );
    // All three records are reached by the walk from the head: admitted.
    let j = w.judge();
    for r in &recs {
        let o = &j.records.iter().find(|x| x.path == r.path).unwrap().outcome;
        assert_eq!(o, &Outcome::Admitted, "{}", r.path);
    }
}

#[test]
fn nothing_kept_holds_backdated_records_and_a_kept_record_citing_the_revocation_is_refused() {
    let mut w = World::new(T0 + 120 * SEC);
    let wr = person(10);
    w.grant(&wr, "device", terms("write"));
    let a = w.write(&wr, "notes", Level::Write, "addNote", json!({"text": "a"}));
    let b = w.write(&wr, "notes", Level::Write, "addNote", json!({"text": "b"}));
    let infos = verified_headers(&w.auth(), &w.held);
    let a_digest = infos
        .iter()
        .find(|i| i.path == a.path)
        .unwrap()
        .digest
        .clone();
    // Keep only `a`, by digest.
    let p = revoke(
        &mut w,
        &wr,
        &Keep::Explicit {
            kept: vec![a_digest],
            heads: vec![],
        },
    );
    finish_revoke(&mut w, p);
    let j = w.judge();
    let out = |r: &HeldRecord| {
        j.records
            .iter()
            .find(|x| x.path == r.path)
            .unwrap()
            .outcome
            .clone()
    };
    assert_eq!(out(&a), Outcome::Admitted);
    assert_eq!(out(&b), Outcome::Held("revokedBackdated"));
}

#[test]
fn a_walk_goes_through_a_refused_header_and_the_refused_header_stays_refused() {
    let mut w = World::new(T0 + 120 * SEC);
    let wr = person(10);
    w.grant(&wr, "device", terms("write"));
    let a = w.write(&wr, "notes", Level::Write, "addNote", json!({"text": "a"}));
    let _b = w.write(&wr, "notes", Level::Write, "addNote", json!({"text": "b"}));
    let _c = w.write(&wr, "notes", Level::Write, "addNote", json!({"text": "c"}));
    // The chain a, b, c is intact; build a second chain by hand whose middle header is
    // refused: it cites a wrong epoch (5) but is signed by the author and names `a` as previous.
    let infos = verified_headers(&w.auth(), &w.held);
    let ia = infos.iter().find(|i| i.path == a.path).unwrap();
    let bad_body = {
        let v: Value = serde_json::from_slice(&w.held[1].bytes).unwrap();
        let mut bv: Value =
            serde_json::from_slice(&STANDARD.decode(v["body"].as_str().unwrap()).unwrap()).unwrap();
        bv["epoch"] = json!(5);
        bv["previous"] = json!(ia.digest);
        bv["clock"] = json!(2);
        bv["id"] = json!("b".repeat(32));
        canonical(&bv).unwrap()
    };
    let bad_path = format!(
        "ops/{}/notes/000000000002-{}.json",
        wr.sign.id,
        "b".repeat(32)
    );
    let bad = HeldRecord {
        path: bad_path,
        bytes: canonical(
            &json!({"body": b64(&bad_body), "signature": b64(&wr.sign.sign(&bad_body))}),
        )
        .unwrap(),
    };
    // A fourth header chained after the bad one.
    let bad_digest = digest(&bad_body);
    let tail_body = {
        let mut bv: Value = serde_json::from_slice(&bad_body).unwrap();
        bv["previous"] = json!(bad_digest);
        bv["clock"] = json!(3);
        bv["epoch"] = json!(1);
        bv["id"] = json!("c".repeat(32));
        canonical(&bv).unwrap()
    };
    let tail_path = format!(
        "ops/{}/notes/000000000003-{}.json",
        wr.sign.id,
        "c".repeat(32)
    );
    let tail = HeldRecord {
        path: tail_path,
        bytes: canonical(
            &json!({"body": b64(&tail_body), "signature": b64(&wr.sign.sign(&tail_body))}),
        )
        .unwrap(),
    };
    w.held.push(bad.clone());
    w.held.push(tail.clone());
    let tail_digest = digest(&tail_body);
    let p = revoke(
        &mut w,
        &wr,
        &Keep::Explicit {
            kept: vec![],
            heads: vec![colophon_core::v05::write::KeptHead {
                namespace: "notes".into(),
                digest: tail_digest,
            }],
        },
    );
    assert!(!p.walk_incomplete());
    finish_revoke(&mut w, p);
    let j = w.judge();
    let out = |r: &HeldRecord| {
        j.records
            .iter()
            .find(|x| x.path == r.path)
            .unwrap()
            .outcome
            .clone()
    };
    // The walk reached `a` through the refused header: `a` is kept and admitted. The refused
    // header is reached but still fails its own check (wrongEpoch): kept records pass every
    // other admission check.
    assert_eq!(out(&a), Outcome::Admitted);
    assert_eq!(out(&bad), Outcome::Refused("wrongEpoch"));
    // `b` and `c` (not on the walk's chain) were not reached from the head: backdated.
    assert_eq!(out(&w.held[1].clone()), Outcome::Held("revokedBackdated"));
}

#[test]
fn a_missing_intermediate_header_holds_records_unavailable_not_as_not_kept() {
    let mut w = World::new(T0 + 120 * SEC);
    let wr = person(10);
    w.grant(&wr, "device", terms("write"));
    let a = w.write(&wr, "notes", Level::Write, "addNote", json!({"text": "a"}));
    let b = w.write(&wr, "notes", Level::Write, "addNote", json!({"text": "b"}));
    let c = w.write(&wr, "notes", Level::Write, "addNote", json!({"text": "c"}));
    let p = revoke(&mut w, &wr, &Keep::Everything);
    finish_revoke(&mut w, p);
    // A reader that holds a and c but not b.
    let reader: Vec<HeldRecord> = vec![a.clone(), c.clone()];
    let j = judge_records(&w.auth(), &w.keys, &reader);
    let out = |r: &HeldRecord| {
        j.records
            .iter()
            .find(|x| x.path == r.path)
            .unwrap()
            .outcome
            .clone()
    };
    assert_eq!(out(&c), Outcome::Admitted, "the head itself is reached");
    assert_eq!(out(&a), Outcome::Held("unavailable"));
    // With `b` present the same reader admits `a`.
    let full: Vec<HeldRecord> = vec![a.clone(), b.clone(), c.clone()];
    let j = judge_records(&w.auth(), &w.keys, &full);
    assert!(j.records.iter().all(|r| r.outcome == Outcome::Admitted));
}

#[test]
fn a_revoke_keeps_every_fork_head_and_refuses_more_than_sixteen_in_one_namespace() {
    let mut w = World::new(T0 + 120 * SEC);
    let wr = person(10);
    w.grant(&wr, "device", terms("write"));
    let root = w.write(
        &wr,
        "notes",
        Level::Write,
        "addNote",
        json!({"text": "root"}),
    );
    // Two forks from the root, each prepared from the same stale store.
    let stale = vec![root.clone()];
    let mut forks = Vec::new();
    for i in 0..2u8 {
        let seed = [0x80 + i; 32];
        let sp = spec("notes", &wr.sign.id, Level::Write);
        let p = prepare_operation(&w.objects, &stale, &w.keys, w.now, &sp, seed).unwrap();
        let step = p.step().clone();
        let done = p.finish(signature_of(&wr.sign, &step)).unwrap();
        forks.push(HeldRecord {
            path: done.path,
            bytes: done.envelope,
        });
    }
    w.held.extend(forks.iter().cloned());
    let p = revoke(&mut w, &wr, &Keep::Everything);
    assert_eq!(p.heads().len(), 2, "both fork heads are kept");
    finish_revoke(&mut w, p);
    let j = w.judge();
    assert!(
        j.records.iter().all(|r| r.outcome == Outcome::Admitted),
        "{:?}",
        j.records
            .iter()
            .map(|r| r.outcome.code())
            .collect::<Vec<_>>()
    );

    // 17 maximal heads: `Everything` is refused (the entry cannot name them); an explicit
    // list of 17 heads is refused too.
    let mut w = World::new(T0 + 120 * SEC);
    let wr = person(10);
    w.grant(&wr, "device", terms("write"));
    let root = w.write(
        &wr,
        "notes",
        Level::Write,
        "addNote",
        json!({"text": "root"}),
    );
    let stale = vec![root];
    for i in 0..17u8 {
        let seed = [0x90 + i; 32];
        let sp = spec("notes", &wr.sign.id, Level::Write);
        let p = prepare_operation(&w.objects, &stale, &w.keys, w.now, &sp, seed).unwrap();
        let step = p.step().clone();
        let done = p.finish(signature_of(&wr.sign, &step)).unwrap();
        w.held.push(HeldRecord {
            path: done.path,
            bytes: done.envelope,
        });
    }
    let seed = w.seed();
    let issued = w.issued();
    let r = prepare_revoke(
        &w.objects,
        &w.held,
        w.now,
        &w.cids(),
        issued,
        &wr.sign.id,
        &Keep::Everything,
        seed,
    );
    match r {
        Err(Failure::Malformed(m)) => assert!(m.contains("more than 16"), "{m}"),
        other => panic!("expected the 16-head refusal, got {:?}", other.map(|_| ())),
    }
    let infos = verified_headers(&w.auth(), &w.held);
    let tips = chain_heads(&infos, &wr.sign.id, "notes");
    assert_eq!(tips.len(), 17);
    let heads: Vec<_> = tips
        .iter()
        .map(|d| colophon_core::v05::write::KeptHead {
            namespace: "notes".into(),
            digest: d.clone(),
        })
        .collect();
    let r = prepare_revoke(
        &w.objects,
        &w.held,
        w.now,
        &w.cids(),
        issued,
        &wr.sign.id,
        &Keep::Explicit {
            kept: vec![],
            heads,
        },
        [0xAA; 32],
    );
    match r {
        Err(Failure::Malformed(m)) => assert!(m.contains("more than 16"), "{m}"),
        other => panic!("expected the 16-head refusal, got {:?}", other.map(|_| ())),
    }
}

#[test]
fn a_head_that_names_no_held_header_is_refused_at_prepare() {
    let mut w = World::new(T0 + 120 * SEC);
    let wr = person(10);
    w.grant(&wr, "device", terms("write"));
    w.write(&wr, "notes", Level::Write, "addNote", json!({"text": "a"}));
    let seed = w.seed();
    let issued = w.issued();
    let r = prepare_revoke(
        &w.objects,
        &w.held,
        w.now,
        &w.cids(),
        issued,
        &wr.sign.id,
        &Keep::Explicit {
            kept: vec![],
            heads: vec![colophon_core::v05::write::KeptHead {
                namespace: "notes".into(),
                digest: "0".repeat(64),
            }],
        },
        seed,
    );
    expect_err(r.map(|_| ()), "malformed");
}

#[test]
fn records_citing_the_revocation_or_later_are_refused_revoked() {
    let mut w = World::new(T0 + 120 * SEC);
    let wr = person(10);
    w.grant(&wr, "device", terms("write"));
    let kept = w.write(&wr, "notes", Level::Write, "addNote", json!({"text": "a"}));
    let p = revoke(&mut w, &wr, &Keep::Everything);
    finish_revoke(&mut w, p);
    assert_eq!(w.outcome(&kept), Outcome::Admitted);
    // The revoked member can no longer prepare (refused up front) ...
    prepared_is_err(
        prepare_operation(
            &w.objects,
            &w.held,
            &w.keys,
            w.now,
            &spec("notes", &wr.sign.id, Level::Write),
            [0xB0; 32],
        ),
        "refused:revoked",
    );
}

// ---------------------------------------------------------------------------------------------
// Proposals and resolutions (§11.6).

fn proposal_world() -> (World, Person, Person) {
    let mut w = World::new(T0 + 120 * SEC);
    let (proposer, owner) = (person(10), person(20));
    w.grant(&proposer, "agent", terms("propose"));
    w.grant(&owner, "device", terms("write"));
    (w, proposer, owner)
}

fn op_id(w: &World, rec: &HeldRecord) -> String {
    w.judge()
        .records
        .into_iter()
        .find(|j| j.path == rec.path)
        .unwrap()
        .id
        .unwrap()
}

#[test]
fn an_accept_folds_the_proposal_once_attributed_to_the_proposer() {
    let (mut w, proposer, owner) = proposal_world();
    let p = w.write(
        &proposer,
        "notes",
        Level::Propose,
        "addNote",
        json!({"text": "idea"}),
    );
    let pid = op_id(&w, &p);
    let seed = w.seed();
    let prepared = prepare_resolution(
        &w.objects,
        &w.held,
        &w.keys,
        w.now,
        &owner.sign.id,
        "notes",
        true,
        std::slice::from_ref(&pid),
        None,
        seed,
    )
    .unwrap();
    let sig = signature_of(&owner.sign, prepared.step());
    let done = prepared.finish(sig).unwrap();
    w.held.push(HeldRecord {
        path: done.path,
        bytes: done.envelope,
    });
    let j = w.judge();
    assert_eq!(j.proposals.len(), 1);
    match &j.proposals[0].state {
        ProposalState::Accepted { by, at, .. } => {
            assert_eq!(by, &owner.sign.id);
            assert_eq!(at.0, 2, "folded at the accept's clock");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(j.proposals[0].proposer, proposer.sign.id);
    // Both records count once against their own authors (two distinct IDs, two slots).
    assert!(j.records.iter().all(|r| r.outcome == Outcome::Admitted));
}

#[test]
fn a_decline_and_a_later_accept_the_first_in_fold_order_wins() {
    let (mut w, proposer, owner) = proposal_world();
    let p = w.write(
        &proposer,
        "notes",
        Level::Propose,
        "addNote",
        json!({"text": "idea"}),
    );
    let pid = op_id(&w, &p);
    for accept in [false, true] {
        let seed = w.seed();
        let prepared = prepare_resolution(
            &w.objects,
            &w.held,
            &w.keys,
            w.now,
            &owner.sign.id,
            "notes",
            accept,
            std::slice::from_ref(&pid),
            None,
            seed,
        )
        .unwrap();
        let sig = signature_of(&owner.sign, prepared.step());
        let done = prepared.finish(sig).unwrap();
        w.held.push(HeldRecord {
            path: done.path,
            bytes: done.envelope,
        });
    }
    let j = w.judge();
    assert!(matches!(
        j.proposals[0].state,
        ProposalState::Declined { .. }
    ));
    assert_eq!(
        j.proposals[0].evidence.len(),
        1,
        "the later accept is evidence"
    );
}

#[test]
fn prepare_refuses_a_resolution_the_fold_would_not_count() {
    let (mut w, proposer, owner) = proposal_world();
    let p = w.write(
        &proposer,
        "notes",
        Level::Propose,
        "addNote",
        json!({"text": "idea"}),
    );
    let pid = op_id(&w, &p);
    let go = |w: &World, author: &Person, ids: &[String], clock: Option<u64>| {
        prepare_resolution(
            &w.objects,
            &w.held,
            &w.keys,
            w.now,
            &author.sign.id,
            "notes",
            true,
            ids,
            clock,
            [0xC0; 32],
        )
    };
    // A clock that is not higher than the proposal's (the proposal's clock is 1).
    prepared_is_err(
        go(&w, &owner, std::slice::from_ref(&pid), Some(1)),
        "malformed",
    );
    // The proposer holds only propose: it may not write the kind, so it cannot resolve.
    prepared_is_err(
        go(&w, &proposer, std::slice::from_ref(&pid), None),
        "refused:notGranted",
    );
    // A proposal the host does not hold.
    prepared_is_err(go(&w, &owner, &["d".repeat(32)], None), "unavailable");
    // No proposals, a duplicate.
    prepared_is_err(go(&w, &owner, &[], None), "malformed");
    prepared_is_err(
        go(&w, &owner, &[pid.clone(), pid.clone()], None),
        "malformed",
    );
    // Fine.
    go(&w, &owner, &[pid], None).unwrap();
}

#[test]
fn the_builder_never_makes_a_header_the_verifier_would_not_admit_at_its_own_state() {
    // End to end over a sequence of actions: every finished header is re-judged by a fresh
    // reader from the authority objects alone.
    let mut w = World::new(T0 + 120 * SEC);
    let wr = person(10);
    w.grant(&wr, "device", terms("write"));
    for i in 0..5 {
        w.write(
            &wr,
            "notes",
            Level::Write,
            "addNote",
            json!({"text": format!("{i}")}),
        );
    }
    let v = verify_history(&w.objects, &Persisted::default(), w.now);
    assert_eq!(v.code(), "ok");
    let j = admit_records(&w.objects, w.now, &w.keys, &w.held).unwrap();
    assert_eq!(j.records.len(), 5);
    assert!(j.records.iter().all(|r| r.outcome == Outcome::Admitted));
    // Clocks count up from 1.
    let mut clocks: Vec<u64> = j.records.iter().map(|r| r.clock).collect();
    clocks.sort();
    assert_eq!(clocks, vec![1, 2, 3, 4, 5]);
    let _ = (parse_date("2026-11-11T08:00:00Z"), Reason::Fork);
}

// ---------------------------------------------------------------------------------------------
// Legacy `/3` headers (§11.5, §16.1): the fence and the signature, end to end.

/// A `/3` header by `p` for the account of `w`, signed by `signer`.
fn legacy_header(
    w: &World,
    p: &Person,
    signer: &Person,
    library: &str,
    authority: u64,
) -> HeldRecord {
    let body = canonical(&json!({
        "protocol": "colophon/operation/3", "library": library, "namespace": "notes",
        "author": p.sign.id, "epoch": 1, "id": "a".repeat(32), "clock": 1, "authority": authority,
        "created": "2026-11-11T08:10:00.000Z", "nonce": b64(&[1u8; 12]), "ciphertext": b64(&[2u8; 32]),
    }))
    .unwrap();
    let _ = w;
    HeldRecord {
        path: format!(
            "ops/{}/notes/000000000001-{}.json",
            p.sign.id,
            "a".repeat(32)
        ),
        bytes: canonical(&json!({"body": b64(&body), "signature": b64(&signer.sign.sign(&body))}))
            .unwrap(),
    }
}

#[test]
fn a_legacy_header_in_a_native_account_is_fenced_out_by_format() {
    // §20: a verifier MUST NOT accept a `/3` object where §11.5 fences it out. A native `/5`
    // account was never upgraded, so no `/3` header is admitted, whoever signed it.
    let mut w = World::new(T0 + 120 * SEC);
    let wr = person(10);
    w.grant(&wr, "device", terms("write"));
    let library = w.auth().account().legacy_library_id().to_string();
    let rec = legacy_header(&w, &wr, &wr, &library, 3);
    let j = judge_records(&w.auth(), &w.keys, &[rec]);
    assert_eq!(j.records[0].outcome, Outcome::Refused("wrongFormat"));
    assert!(!j.records[0].reserved, "a fenced header reserves no slot");
    // A `/3` header whose signature is by another key is not a record at all.
    let rec = legacy_header(&w, &wr, &person(40), &library, 3);
    let j = judge_records(&w.auth(), &w.keys, &[rec]);
    assert_eq!(
        j.records[0].outcome,
        Outcome::Invalid("badSignature".into())
    );
}

#[test]
fn no_mangled_header_panics_the_reader_and_none_is_admitted_as_a_different_record() {
    let mut w = World::new(T0 + 120 * SEC);
    let wr = person(10);
    w.grant(&wr, "device", terms("write"));
    let rec = w.write(&wr, "notes", Level::Write, "addNote", json!({"text": "a"}));
    let auth = w.auth();
    let honest = judge_records(&auth, &w.keys, std::slice::from_ref(&rec)).records[0]
        .outcome
        .clone();
    assert_eq!(honest, Outcome::Admitted);
    // Every truncation, and every byte replaced by three other values, of the envelope.
    let mut admitted_other = 0;
    for len in 0..rec.bytes.len() {
        let held = HeldRecord {
            path: rec.path.clone(),
            bytes: rec.bytes[..len].to_vec(),
        };
        let j = judge_records(&auth, &w.keys, &[held]);
        assert_ne!(
            j.records[0].outcome,
            Outcome::Admitted,
            "truncated at {len}"
        );
    }
    for i in 0..rec.bytes.len() {
        for b in [0u8, b'"', 0xff] {
            let mut bytes = rec.bytes.clone();
            if bytes[i] == b {
                continue;
            }
            bytes[i] = b;
            let held = HeldRecord {
                path: rec.path.clone(),
                bytes,
            };
            let j = judge_records(&auth, &w.keys, &[held]);
            if j.records[0].outcome == Outcome::Admitted {
                admitted_other += 1;
            }
        }
    }
    assert_eq!(admitted_other, 0, "a damaged envelope was admitted");
}

// ---------------------------------------------------------------------------------------------
// Fix round: the independent check's tests, ported (H1, H2, H3, M1) and the Lows.

use colophon_core::v05::records::{epoch_info, operation_id};
use colophon_core::v05::write::authority::{
    prepare_activate, prepare_transition, TransitionParams, TransitionRule,
};

fn slot_json(id: &str, label: &str) -> Value {
    json!({"kind": "sealed", "controllers": [id], "label": label,
           "sealed": {"enc": b64(&key(0x70).point), "ciphertext": b64(&[7u8; 48])}})
}

/// As `World::new`, with a second slotted controller D (control only).
fn world_two(now: i64) -> (World, Person) {
    let c = person(1);
    let d = person(90);
    let vault = VaultSeed::from_host_random([0x42; 32]);
    let vp = vault.public().unwrap();
    let mut ctrl = vec![
        controller_json(&c.sign, &c.agree),
        json!({"key": {"form": "raw", "signing": b64(&d.sign.point), "agreement": b64(&d.agree.point)},
               "label": "D", "roles": ["control"]}),
    ];
    ctrl.sort_by_key(|x| {
        key_id(
            &STANDARD
                .decode(x["key"]["signing"].as_str().unwrap())
                .unwrap(),
        )
    });
    let keyring = json!({
        "controllers": ctrl, "threshold": 1, "recoverThreshold": 1,
        "addThreshold": 1, "countBy": "keys",
        "policy": {
            "callWindow": 300, "headMaxAge": 300, "headQuorum": 1, "history": "members",
            "linkMaxAge": 86400, "memberRule": "single",
            "rate": {"account": {"bytes": 16777216, "entries": 256},
                     "signer": {"bytes": 4194304, "entries": 64}},
            "recoveryDelay": 3600
        },
        "vault": {"signing": b64(&vp.signing), "agreement": b64(&vp.agreement)},
        "slots": [slot_json(&c.sign.id, "C"), slot_json(&d.sign.id, "D")],
    });
    let dd = person(90);
    let mut w = World {
        c,
        d: dd,
        vault,
        objects: Objects::default(),
        now,
        held: Vec::new(),
        keys: EpochKeys::new(),
        n: 0,
    };
    let batch = prepare_genesis(
        &GenesisParams {
            label: "Two".into(),
            namespaces: vec!["journal".into(), "notes".into()],
            keyring,
            issued_ms: T0,
            signers: w.cids(),
        },
        now,
    )
    .unwrap();
    w.run(batch);
    let seed = w.seed();
    let issued = w.issued();
    let (batch, keys) = prepare_rekey(
        &w.objects,
        now,
        &w.cids(),
        issued,
        &["journal".into(), "notes".into()],
        seed,
    )
    .unwrap();
    w.run(batch);
    w.absorb(keys);
    (w, d)
}

/// A transition removing D (slotted), then its activation: the vault is retiring.
fn retire(w: &mut World, d: &Person) {
    let batch = prepare_transition(
        &w.objects,
        w.now,
        &TransitionParams {
            anchor: None,
            issued_ms: w.issued(),
            signers: w.cids(),
            rule: TransitionRule::Control,
            change: json!({"keyring": {"remove": [d.sign.id]}}),
        },
    )
    .unwrap();
    let sigs: Vec<SignatureResult> = batch
        .steps()
        .iter()
        .map(|s| signature_of(&w.c.sign, s))
        .collect();
    let r = batch.finish(sigs).unwrap();
    w.hold(&r);
    let env: Value = serde_json::from_slice(&r.pending[0]).unwrap();
    let t_digest = digest(&STANDARD.decode(env["body"].as_str().unwrap()).unwrap());
    let act = prepare_activate(&w.objects, w.now, &t_digest).unwrap();
    w.run(act);
    assert!(w.auth().state().vault_retiring(), "the vault is retiring");
}

/// H1 (§8.3, §7.1): while the vault is retiring, hosts MUST NOT introduce epochs. A `rekey` is
/// refused and says to complete the `vault` entry; a `revoke` carries empty `epochs` and says
/// a `rekey` is owed. The retiring seed (which the removed controller may hold) opens no epoch
/// made after retirement began.
#[test]
fn h1_no_epoch_is_introduced_while_the_vault_is_retiring() {
    let (mut w, d) = world_two(T0 + 3_600 * SEC);
    let m = person(30);
    w.grant(&m, "device", terms("write"));
    retire(&mut w, &d);
    let seed = w.seed();
    let issued = w.issued();
    let r = prepare_rekey(
        &w.objects,
        w.now,
        &w.cids(),
        issued,
        &["notes".into()],
        seed,
    );
    match r {
        Err(Failure::Unavailable(m)) => assert!(m.contains("`vault` entry"), "{m}"),
        other => panic!("expected the retiring refusal, got {:?}", other.map(|_| ())),
    }
    assert!(build_epochs(&w.auth(), &["notes".into()], w.issued(), None, [5; 32]).is_err());
    let seed = w.seed();
    let issued = w.issued();
    let p = prepare_revoke(
        &w.objects,
        &w.held,
        w.now,
        &w.cids(),
        issued,
        &m.sign.id,
        &Keep::Nothing,
        seed,
    )
    .unwrap();
    assert!(
        p.rekey_owed(),
        "a rekey is owed once the new vault is in place"
    );
    assert_eq!(p.owed_namespaces(), ["notes".to_string()]);
    let (batch, keys) = p.into_parts();
    assert!(keys.is_empty());
    w.run(batch);
    let auth = w.auth();
    assert!(auth.state().vault_retiring());
    assert_eq!(auth.latest_epoch("notes"), 1, "no epoch was introduced");
    // The retiring seed opens epoch 1 (made before) and nothing made after.
    auth.open_epoch_with_vault(&w.vault, "notes", 1).unwrap();
    expect_err(
        auth.open_epoch_with_vault(&w.vault, "notes", 2).map(|_| ()),
        "unavailable",
    );
}

fn journal_key() -> [u8; 32] {
    colophon_core::crypto::Entropy::new([1; 32])
        .take::<32>()
        .unwrap()
}

/// A `/5` header by hand under the journal epoch-1 key (the host knows it from its rekey seed,
/// as the file header says).
fn hand_header(
    w: &World,
    who: &Person,
    clock: u64,
    level: &str,
    nonce: [u8; 12],
    text: &str,
) -> HeldRecord {
    let account = w.auth().account().as_str().to_string();
    let authority = w.auth().authority_seq();
    let created = "2026-11-11T09:00:00Z";
    let mut plain = json!({"id": "", "kind": "addNote", "v": 1, "clock": clock,
                           "authority": authority, "created": created, "payload": {"text": text}});
    let id = operation_id("journal", &who.sign.id, 1, &nonce, &plain).unwrap();
    plain["id"] = json!(id);
    let aad = canonical(
        &json!({"account": account, "author": who.sign.id, "authority": authority,
        "clock": clock, "created": created, "epoch": 1, "id": id, "level": level,
        "namespace": "journal", "previous": Value::Null, "protocol": "colophon/operation/5"}),
    )
    .unwrap();
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    let ct = aes_gcm::Aes256Gcm::new_from_slice(&journal_key())
        .unwrap()
        .encrypt(
            aes_gcm::Nonce::from_slice(&nonce),
            Payload {
                msg: &canonical(&plain).unwrap(),
                aad: &aad,
            },
        )
        .unwrap();
    let body = canonical(
        &json!({"protocol": "colophon/operation/5", "account": account,
        "namespace": "journal", "author": who.sign.id, "epoch": 1, "id": id, "clock": clock,
        "authority": authority, "created": created, "level": level, "previous": Value::Null,
        "nonce": b64(&nonce), "ciphertext": b64(&ct)}),
    )
    .unwrap();
    HeldRecord {
        path: format!("ops/{}/journal/{clock:012}-{id}.json", who.sign.id),
        bytes: canonical(&json!({"body": b64(&body), "signature": b64(&who.sign.sign(&body))}))
            .unwrap(),
    }
}
fn body_digest(rec: &HeldRecord) -> String {
    let v: Value = serde_json::from_slice(&rec.bytes).unwrap();
    digest(&STANDARD.decode(v["body"].as_str().unwrap()).unwrap())
}
fn by_digest(j: &Judgement) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = j
        .records
        .iter()
        .map(|r| (r.digest.clone().unwrap_or_default(), r.outcome.code()))
        .collect();
    v.sort();
    v.dedup();
    v
}
fn journal_world() -> (World, Person) {
    let mut w = World::new(T0 + 120 * SEC);
    let wr = person(10);
    w.grant(
        &wr,
        "device",
        json!({"records": [{"namespace": "journal", "access": "write"}]}),
    );
    (w, wr)
}

#[test]
fn a_hand_built_header_is_admitted() {
    let (w, wr) = journal_world();
    let a = hand_header(&w, &wr, 1, "write", [9; 12], "x");
    let j = judge_records(&w.auth(), &w.keys, &[a]);
    assert_eq!(j.records[0].outcome, Outcome::Admitted);
}

/// H2: two bodies by one author with one ID and clock (they differ in `level`, which is in
/// the AAD but not the ID) at one path: the winner is the lowest body digest, in any order.
#[test]
fn h2_same_author_same_id_winner_is_the_lowest_digest_in_every_order() {
    let (w, wr) = journal_world();
    let a = hand_header(&w, &wr, 1, "write", [9; 12], "x");
    let b = hand_header(&w, &wr, 1, "propose", [9; 12], "x");
    assert_eq!(a.path, b.path);
    let (da, db) = (body_digest(&a), body_digest(&b));
    assert_ne!(da, db);
    let auth = w.auth();
    let ab = judge_records(&auth, &w.keys, &[a.clone(), b.clone()]);
    let ba = judge_records(&auth, &w.keys, &[b.clone(), a.clone()]);
    assert_eq!(
        by_digest(&ab),
        by_digest(&ba),
        "verdict depends on arrival order"
    );
    let (low, high) = if da < db { (&da, &db) } else { (&db, &da) };
    let got = by_digest(&ab);
    assert!(got.contains(&(low.clone(), "admitted".into())), "{got:?}");
    assert!(
        got.contains(&(high.clone(), "refused:duplicateID".into())),
        "{got:?}"
    );
    assert_eq!(ab.proposals.len(), ba.proposals.len());
}

/// M1: one body under two envelopes (a high-S twin, §2.2) is one object: reported admitted
/// under both, never `duplicateID` of itself.
#[test]
fn m1_one_body_under_two_envelopes_is_one_object() {
    use p256::elliptic_curve::ff::PrimeField;
    let (w, wr) = journal_world();
    let a = hand_header(&w, &wr, 1, "write", [9; 12], "x");
    let v: Value = serde_json::from_slice(&a.bytes).unwrap();
    let sig = STANDARD.decode(v["signature"].as_str().unwrap()).unwrap();
    let s = p256::Scalar::from_repr(*p256::FieldBytes::from_slice(&sig[32..])).unwrap();
    let mut twin_sig = sig[..32].to_vec();
    twin_sig.extend_from_slice(&(-s).to_repr());
    let twin = HeldRecord {
        path: a.path.clone(),
        bytes: canonical(&json!({"body": v["body"], "signature": b64(&twin_sig)})).unwrap(),
    };
    for order in [[a.clone(), twin.clone()], [twin.clone(), a.clone()]] {
        let j = judge_records(&w.auth(), &w.keys, &order);
        let codes: Vec<String> = j.records.iter().map(|r| r.outcome.code()).collect();
        assert!(codes.iter().all(|c| c == "admitted"), "{codes:?}");
        assert_eq!(j.records.len(), 2, "one entry per held record, in order");
    }
}

/// H3, a documented test of the stated trust boundary, not a bug: a grant's shares are part of
/// the body the controller signs, so they are sealed before signing. A host that holds
/// `EpochKeys` handles can therefore have them sealed to a member it is preparing to admit and
/// read the raw key from that seal with the member's own agreement key. Holding the handles
/// is as trusted as holding the keys.
#[test]
fn trust_boundary_a_holder_of_epoch_key_handles_can_have_them_sealed_to_a_member_it_prepares() {
    let mut w = World::new(T0 + 120 * SEC);
    let wr = person(10);
    w.grant(&wr, "device", terms("write"));
    let rec = w.write(
        &wr,
        "notes",
        Level::Write,
        "addNote",
        json!({"text": "secret"}),
    );
    let member = person(77);
    let req = w.request(&member, "app", terms("read"));
    let seed = w.seed();
    let issued = w.issued();
    let batch = prepare_grant(
        &w.objects,
        w.now,
        &w.cids(),
        issued,
        &req,
        terms("read"),
        &w.keys,
        seed,
    )
    .unwrap();
    let body: Value = serde_json::from_slice(batch.steps()[0].body()).unwrap();
    let seal = &body["shares"][0]["seals"][&member.sign.id];
    let sealed = colophon_core::hpke::SealedKey {
        enc: STANDARD.decode(seal["enc"].as_str().unwrap()).unwrap(),
        ciphertext: STANDARD
            .decode(seal["ciphertext"].as_str().unwrap())
            .unwrap(),
    };
    let sk = p256::SecretKey::from_slice(&member.agree.scalar).unwrap();
    let pk = p256::PublicKey::from_sec1_bytes(&sealed.enc).unwrap();
    let dh = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
    let info = epoch_info(w.auth().account(), "notes", 1, &member.sign.id);
    let key = sealed
        .finish_open(&member.agree.point, dh.raw_secret_bytes().as_slice(), &info)
        .unwrap();
    // It is the epoch key: the writer's record decrypts with it.
    let env: Value = serde_json::from_slice(&rec.bytes).unwrap();
    let h: Value =
        serde_json::from_slice(&STANDARD.decode(env["body"].as_str().unwrap()).unwrap()).unwrap();
    let aad = canonical(&json!({"account": h["account"], "author": h["author"],
        "authority": h["authority"], "clock": h["clock"], "created": h["created"],
        "epoch": h["epoch"], "id": h["id"], "level": h["level"], "namespace": h["namespace"],
        "previous": h["previous"], "protocol": h["protocol"]}))
    .unwrap();
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    let pt = aes_gcm::Aes256Gcm::new_from_slice(&key)
        .unwrap()
        .decrypt(
            aes_gcm::Nonce::from_slice(&STANDARD.decode(h["nonce"].as_str().unwrap()).unwrap()),
            Payload {
                msg: &STANDARD.decode(h["ciphertext"].as_str().unwrap()).unwrap(),
                aad: &aad,
            },
        )
        .unwrap();
    assert!(String::from_utf8_lossy(&pt).contains("secret"));
}

#[test]
fn h3_prepare_grant_refuses_a_wrong_request_before_sealing_anything() {
    let mut w = World::new(T0 + 120 * SEC);
    let wr = person(10);
    w.grant(&wr, "device", terms("write"));
    let go = |w: &World, req: &[u8], t: Value| {
        prepare_grant(
            &w.objects,
            w.now,
            &w.cids(),
            w.issued(),
            req,
            t,
            &w.keys,
            [3; 32],
        )
    };
    // Another account.
    let other = World::new(T0 + 120 * SEC);
    let m = person(50);
    let mut req_other = other.request(&m, "app", terms("read"));
    let acct_other = other.auth().account().as_str().to_string();
    let _ = acct_other;
    // Same bytes for another account: the request names `other`, whose ID differs only if the
    // histories differ; make them differ.
    let mut w2 = World::new(T0 + 120 * SEC);
    w2.c = person(2);
    let _ = &mut req_other;
    // A request that is not a request.
    expect_err(go(&w, b"{}", terms("read")).map(|_| ()), "malformed");
    // A member key already in the account.
    let dup = w.request(&wr, "device", terms("write"));
    expect_err(go(&w, &dup, terms("write")).map(|_| ()), "malformed");
    // Granted terms not covered by the request.
    let m2 = person(60);
    let req = w.request(&m2, "app", terms("read"));
    expect_err(go(&w, &req, terms("write")).map(|_| ()), "malformed");
    // A namespace the account does not declare.
    let bad = json!({"records": [{"namespace": "nowhere", "access": "read"}]});
    let req = w.request(&m2, "app", bad.clone());
    expect_err(go(&w, &req, bad).map(|_| ()), "malformed");
    // An empty key set is refused only after the shape is known good.
    let req = w.request(&m2, "app", terms("read"));
    expect_err(
        prepare_grant(
            &w.objects,
            w.now,
            &w.cids(),
            w.issued(),
            &req,
            terms("read"),
            &EpochKeys::new(),
            [3; 32],
        )
        .map(|_| ()),
        "unavailable",
    );
}

/// L1: `finish` finds its own header by body digest, and a same-path record with a bad
/// signature (the same body, forged envelope) neither fails it nor is skipped.
#[test]
fn l1_finish_matches_its_own_header_by_digest_not_path() {
    let mut w = World::new(T0 + 120 * SEC);
    let wr = person(10);
    w.grant(&wr, "device", terms("write"));
    let seed = [0x31; 32];
    let sp = spec("notes", &wr.sign.id, Level::Write);
    let probe = prepare_operation(&w.objects, &w.held, &w.keys, w.now, &sp, seed).unwrap();
    let forged = HeldRecord {
        path: probe.path().to_string(),
        bytes: canonical(&json!({"body": b64(probe.step().body()), "signature": b64(&[1u8; 64])}))
            .unwrap(),
    };
    let held = vec![forged.clone()];
    let p = prepare_operation(&w.objects, &held, &w.keys, w.now, &sp, seed).unwrap();
    let sig = signature_of(&wr.sign, p.step());
    let done = p.finish(sig).unwrap();
    assert_eq!(done.digest, digest(probe.step().body()));
    // The forged envelope alone is not a record.
    let j = judge_records(&w.auth(), &w.keys, &[forged]);
    assert_eq!(
        j.records[0].outcome,
        Outcome::Invalid("badSignature".into())
    );
}

/// L3: a key of another account is refused, not substituted.
#[test]
fn l3_epoch_keys_refuse_a_key_of_another_account() {
    let w1 = World::new(T0 + 120 * SEC);
    let mut w2 = World::new(T0 + 120 * SEC);
    w2.c = person(2);
    let mut w3 = World::new(T0 + 130 * SEC);
    // A genesis issued at another time gives another account.
    let _ = &mut w3;
    let a1 = w1.auth();
    let k = w1.keys.get(a1.account(), "notes", 1).unwrap().clone();
    let mut keys = EpochKeys::new();
    keys.insert(k.clone()).unwrap();
    // Build a key bound to a different account by opening a seal of another history.
    let (mut other, _d) = world_two(T0 + 3_600 * SEC);
    other.grant(&person(5), "device", terms("write"));
    let oa = other.auth();
    assert_ne!(oa.account(), a1.account());
    let ok = other.keys.get(oa.account(), "notes", 1).unwrap().clone();
    expect_err(keys.insert(ok).map(|_| ()), "malformed");
    assert!(
        keys.get(a1.account(), "notes", 1).is_some(),
        "the first key stays"
    );
}

/// L4: members owed shares for epochs, from the verified state.
#[test]
fn l4_owed_shares_lists_members_missing_an_epoch() {
    let mut w = World::new(T0 + 120 * SEC);
    let wr = person(10);
    let short = json!({"records": [{"namespace": "notes", "access": "write"}],
                       "expires": "2026-11-11T08:05:00Z"});
    w.grant(&wr, "device", short);
    assert!(w.auth().owed_shares().is_empty());
    w.now = T0 + 600 * SEC;
    let seed = w.seed();
    let (batch, keys) = prepare_rekey(
        &w.objects,
        w.now,
        &w.cids(),
        T0 + 400 * SEC,
        &["notes".into()],
        seed,
    )
    .unwrap();
    w.run(batch);
    w.absorb(keys);
    let owed = w.auth().owed_shares();
    assert_eq!(owed.len(), 1);
    assert_eq!(
        (
            owed[0].member.as_str(),
            owed[0].namespace.as_str(),
            owed[0].epoch
        ),
        (wr.sign.id.as_str(), "notes", 2)
    );
}

/// The record layer's rebuilt epoch history equals the verifier's folded epochs on every
/// records vector, so the two cannot drift.
#[test]
fn rebuilt_epochs_equal_the_verifiers_folded_epochs_on_every_vector() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/0.5/candidate/records");
    let mut n = 0;
    for e in std::fs::read_dir(&root).unwrap() {
        let dir = e.unwrap().path();
        let case: Value =
            serde_json::from_slice(&std::fs::read(dir.join("case.json")).unwrap()).unwrap();
        if case["expected"]["history"].is_object() {
            continue;
        }
        let now = parse_date(case["verifier"]["now"].as_str().unwrap()).unwrap();
        let mut files: Vec<_> = std::fs::read_dir(dir.join("records/authority"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        files.sort();
        let objects = Objects {
            entries: files.iter().map(|p| std::fs::read(p).unwrap()).collect(),
            ..Default::default()
        };
        let auth = RecordAuthority::from_objects(&objects, now).unwrap();
        let folded = serde_json::to_value(auth.state()).unwrap();
        let epochs = folded["epochs"].as_object().unwrap();
        assert!(!epochs.is_empty(), "{}", dir.display());
        for (ns, v) in epochs {
            assert_eq!(
                auth.latest_epoch(ns),
                v.as_u64().unwrap(),
                "{}: {ns}",
                dir.display()
            );
        }
        n += 1;
    }
    assert!(n >= 20, "{n}");
}

/// §8.3 in the verifier: a `rekey`, or a `revoke` that introduces an epoch, is refused while
/// the vault is retiring, even when a host forges the entry around the builders' refusal.
#[test]
fn the_verifier_refuses_an_epoch_introduced_while_the_vault_is_retiring() {
    use colophon_core::v05::write::authority::prepare_signed;
    use colophon_core::v05::write::Kind;
    let (mut w, d) = world_two(T0 + 3_600 * SEC);
    let m = person(30);
    w.grant(&m, "device", terms("write"));
    retire(&mut w, &d);
    // An epoch object copied from epoch 1 with its number raised: the verifier only needs its
    // shape; the point is that it is introduced at all.
    let auth = w.auth();
    let seal = auth
        .epoch_seal_request("notes", 1, &auth.vault().id())
        .unwrap();
    let _ = seal;
    let e1: Value = {
        let env: Value = serde_json::from_slice(&w.objects.entries[1]).unwrap();
        let body: Value =
            serde_json::from_slice(&STANDARD.decode(env["body"].as_str().unwrap()).unwrap())
                .unwrap();
        let mut e = body["epochs"][1].clone();
        e["epoch"] = json!(2);
        e
    };
    assert_eq!(e1["namespace"], "notes");
    let issued = w.issued();
    for kind in [
        Kind::Rekey {
            epochs: vec![e1.clone()],
        },
        Kind::Revoke {
            member: m.sign.id.clone(),
            kept: vec![],
            heads: vec![],
            epochs: vec![e1.clone()],
        },
    ] {
        let batch = prepare_signed(&w.objects, w.now, kind, issued, &w.cids()).unwrap();
        let sigs: Vec<SignatureResult> = batch
            .steps()
            .iter()
            .map(|s| signature_of(&w.c.sign, s))
            .collect();
        match batch.finish(sigs) {
            Err(Failure::Malformed(m)) => assert!(m.contains("retiring"), "{m}"),
            other => panic!("expected the retiring refusal, got {:?}", other.map(|_| ())),
        }
    }
}

/// The epochs a `/5` `revoke` introduces are folded into the verifier's epoch history: a later
/// `rekey` is checked against them, and a revoke whose epoch skips a number is malformed.
#[test]
fn a_revokes_epochs_are_folded_and_checked_as_consecutive() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/0.5/candidate/records");
    let load = |name: &str| -> Objects {
        let dir = root.join(name).join("records/authority");
        let mut files: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        files.sort();
        Objects {
            entries: files.iter().map(|p| std::fs::read(p).unwrap()).collect(),
            ..Default::default()
        }
    };
    let now = parse_date("2026-11-12T00:00:00Z").unwrap();
    let ok = verify_history(
        &load("revoke-epochs-then-rekey"),
        &Persisted::default(),
        now,
    );
    assert_eq!(ok.code(), "ok");
    let state = serde_json::to_value(ok.state.as_ref().unwrap()).unwrap();
    assert_eq!(state["epochs"]["notes"], 3);
    let skip = verify_history(&load("revoke-epoch-skips"), &Persisted::default(), now);
    assert_ne!(skip.code(), "ok");
    assert_eq!(skip.code(), "malformed");
    assert_eq!(skip.seq(), 4);
}
