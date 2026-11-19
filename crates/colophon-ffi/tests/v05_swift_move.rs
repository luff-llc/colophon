//! A Swift keyring library moved to a 0.5 account, **through the exports only** on the client
//! side: the successor genesis (`SwiftSuccessorCreation`, with the one-assertion passkey
//! ceremony), `swift_succession`, the veto branch, the unvetoed branch through F,
//! `accept_predecessor_entry`, a copier that opens its shares from the host's own store, the
//! copy writes with a test translator, `finish_swift_copy`, the migration, and a cold reopen at
//! every stage from exactly the objects the exports handed to the host.
//!
//! What is simulated is the HOME (marked `HOME:` below): its receipts of the genesis and of
//! the pending objects, its signed heads, and its `successionVetoed` entry. They are built with
//! core code and put into the host's store as the exchange would have. Everything the CLIENT
//! produces is stored from the exports' own `stores`, never recomputed by the test.
//!
//! The Swift library is the repository's conformance fixture (`conformance/keyring`): four
//! controllers, four vault slots, a passkey whose slot is a PRF slot, and two records.
#![allow(clippy::unwrap_used, dead_code)]
mod v05_support;
use colophon_core::crypto::SoftwareKeys;
use colophon_core::v05::encoding::{canonical, decode_base64, digest, encode_base64};
use colophon_core::v05::swift_slots::swift_kit_identity;
use colophon_core::v05::write::calls::{finish_genesis_receipt, prepare_genesis_receipt};
use colophon_core::v05::write::succession::map_swift_role;
use colophon_core::v05::write::{format_date, SignatureResult};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;
use v05_support::*;

const SEC: i64 = 1000;
static CTR: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1000);
/// Fresh bytes for an action, the way a host draws them.
fn ent(n: usize) -> Vec<u8> {
    let c = CTR.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut out = Vec::new();
    for i in 0..n.div_ceil(32) {
        out.extend(sha(&[&c.to_le_bytes()[..], &[i as u8]].concat()));
    }
    out.truncate(n);
    out
}
fn strip(mut b: Vec<u8>) -> Vec<u8> {
    if b.last() == Some(&b'\n') {
        b.pop();
    }
    b
}
fn body_of(env: &[u8]) -> Vec<u8> {
    let v: Value = serde_json::from_slice(env).unwrap();
    decode_base64(v["body"].as_str().unwrap(), 1 << 22).unwrap()
}
/// HOME: where the home stores a pending object it receipts or an entry it records.
fn pending_path(env: &[u8]) -> String {
    let body = body_of(env);
    let b: Value = serde_json::from_slice(&body).unwrap();
    match b["protocol"].as_str() {
        Some("colophon/veto/5") => format!("vetoes/{}.json", digest(&body)),
        Some("colophon/receipt/5") => format!(
            "receipts/{}/{}.receipt.json",
            b["object"].as_str().unwrap(),
            b["by"].as_str().unwrap()
        ),
        _ => format!("transitions/{}.json", digest(&body)),
    }
}
fn empty_saved() -> SavedState {
    SavedState {
        verifier: vec![],
        checkpoint: vec![],
        parts: vec![],
    }
}

/// The host's key custody for the fixture: software keys, the kit, and the passkey.
struct World {
    host: Host,
    /// The host's account store: everything the exports handed over, and what the home put.
    store: MemSource,
    account: String,
    owner: String,
    kit: String,
    kit_secret: [u8; 32],
    entries: Vec<Vec<u8>>,
    files: Vec<Store>,
    home: String,
    copier: String,
    prf_output: Vec<u8>,
}
impl World {
    fn sign(&self, steps: &[AccountSigningStep]) -> Vec<Signature> {
        steps
            .iter()
            .map(|s| {
                if s.signer == self.kit {
                    let k = swift_kit_identity(&self.kit_secret).unwrap();
                    Signature {
                        signature: k.sign(&s.body).to_vec(),
                        authenticator_data: None,
                        client_data: None,
                    }
                } else {
                    self.host
                        .sign_one(&s.body, &s.signer, s.challenge.is_some())
                }
            })
            .collect()
    }
}
/// A cold open over the host's store alone, unlocked by the first slot of `controller` (or the
/// shares of a member).
fn open(w: &World, who: &str, now: i64) -> Arc<AccountEngine> {
    open_in(w, &w.store, who, now)
}
fn open_in(w: &World, store: &MemSource, who: &str, now: i64) -> Arc<AccountEngine> {
    let e = AccountEngine::open(
        Box::new(store.clone()),
        store.listing(),
        ident(who),
        w.account.clone(),
        vec![],
        0,
        empty_saved(),
        DEVICE_KEY.to_vec(),
        now,
    )
    .unwrap();
    if who.starts_with("controller:") {
        let slot = e
            .slots()
            .unwrap()
            .into_iter()
            .find(|s| {
                s.controllers.iter().any(|c| who.ends_with(&c.id)) && s.kind == SlotKind::Sealed
            })
            .unwrap();
        let ins = e.begin_unlock_slot(slot.index).unwrap();
        e.finish_unlock_slot(slot.index, w.host.answer_slot(&ins))
            .unwrap();
    }
    e
}
/// What stage a cold reopen from the host's store sees.
fn reopened_stage(w: &World, now: i64) -> MoveStage {
    open(w, &format!("controller:{}", w.owner), now)
        .swift_succession()
        .unwrap()
        .stage
}
fn head_env(w: &World, e: &AccountEngine, at: i64) -> Vec<u8> {
    let body = canonical(&json!({"protocol": "colophon/head/5", "account": w.account,
        "authority": {"seq": e.head_seq().unwrap(), "digest": e.head_digest().unwrap()},
        "issued": format_date(at), "by": w.home}))
    .unwrap();
    canonical(&json!({"body": encode_base64(&body),
        "signature": encode_base64(&w.host.keys[&w.home].sign(&body))}))
    .unwrap()
}
/// HOME: the home publishes a fresh signed head; the host stores it and tells the engine.
fn home_head(w: &World, e: &AccountEngine, at: i64) {
    let p = format!("heads/{}.json", w.home);
    w.store.put(&p, head_env(w, e, at));
    e.apply_paths(vec![ListedPath {
        path: p,
        version: None,
    }])
    .unwrap();
}
/// HOME: a receipt for `object`.
fn home_receipt(w: &World, object: &str, at: i64) -> Vec<u8> {
    let rbody = canonical(
        &json!({"protocol": "colophon/receipt/5", "account": w.account,
        "object": object, "received": format_date(at), "by": w.home}),
    )
    .unwrap();
    canonical(&json!({"body": encode_base64(&rbody),
        "signature": encode_base64(&w.host.keys[&w.home].sign(&rbody))}))
    .unwrap()
}
/// The host stored `path` itself (it came from the home): tell the engine.
fn put_apply(w: &World, e: &AccountEngine, path: &str, bytes: Vec<u8>) -> Changes {
    w.store.put(path, bytes);
    e.apply_paths(vec![ListedPath {
        path: path.into(),
        version: None,
    }])
    .unwrap()
}
/// The host stores exactly what an export handed it, and tells the engine nothing: a cold
/// reopen must see it.
fn store_all(w: &World, stores: &[Store]) {
    w.store.store(stores);
}
fn store_paths(stores: &[Store]) -> Vec<String> {
    stores.iter().map(|s| s.path.clone()).collect()
}

struct Tr;
impl SwiftTranslator for Tr {
    fn translate(&self, op: SwiftOpInfo) -> Result<SwiftBatch, AccountError> {
        let p: Value = serde_json::from_str(&op.payload_json).unwrap();
        if op.kind != "capture.link" {
            return Err(AccountError::host(format!("no mapping for {}", op.kind)));
        }
        Ok(SwiftBatch {
            children: vec![SwiftChild {
                key: "c".into(),
                kind: "capture".into(),
                payload_json: json!({"id": p["item"], "title": p["title"], "url": p["url"],
                    // 600 small numbers, compact: an ordinary app value that a density rule
                    // once refused (the copy then never drained).
                    "pages": (0..600).map(|i| i % 10).collect::<Vec<_>>()})
                .to_string(),
                baseline: false,
            }],
            alternatives_json: vec![],
            identities: vec![],
            blobs_json: vec![],
            outcome: "applied".into(),
            evidence_json: String::new(),
        })
    }
}

/// The Swift library's host-held keys and the successor genesis, through the export, up to an
/// engine unlocked as the owner at the `Waiting` stage.
fn build() -> (World, Arc<AccountEngine>) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/keyring");
    let keys: Value =
        serde_json::from_slice(&std::fs::read(root.join("keys.json")).unwrap()).unwrap();
    let k = |a: &str, b: &str| decode_base64(keys[a][b].as_str().unwrap(), 64).unwrap();
    let expected: Value =
        serde_json::from_slice(&std::fs::read(root.join("expected.json")).unwrap()).unwrap();
    let mut host = Host::new();
    let ok =
        SoftwareKeys::from_scalars(&k("owner", "signingKey"), &k("owner", "agreementKey")).unwrap();
    let owner = colophon_core::v05::ids::key_id(&ok.public().signing);
    assert_eq!(owner, expected["controllers"]["owner"].as_str().unwrap());
    host.keys.insert(owner.clone(), ok);
    let kit_secret: [u8; 32] = decode_base64(keys["kitSecret"].as_str().unwrap(), 64)
        .unwrap()
        .try_into()
        .unwrap();
    let kit = swift_kit_identity(&kit_secret).unwrap().id();
    assert_eq!(kit, expected["controllers"]["kit"].as_str().unwrap());
    let webauthn = expected["controllers"]["webauthn"]
        .as_str()
        .unwrap()
        .to_string();
    let scalar: [u8; 32] = decode_base64(keys["webauthnScalar"].as_str().unwrap(), 64)
        .unwrap()
        .try_into()
        .unwrap();
    host.passkey = Some((
        colophon_core::keys::testing::SyntheticAuthenticator::from_scalar(&scalar).unwrap(),
        webauthn.clone(),
    ));
    let prf_output = decode_base64(keys["prfOutput"].as_str().unwrap(), 64).unwrap();
    let prf_salt = decode_base64(keys["prfSalt"].as_str().unwrap(), 64).unwrap();

    let mut paths: Vec<_> = std::fs::read_dir(root.join("library/authority"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    paths.sort();
    let entries: Vec<Vec<u8>> = paths
        .iter()
        .map(|p| strip(std::fs::read(p).unwrap()))
        .collect();
    let read = |p: &str| Store {
        path: p.into(),
        bytes: strip(std::fs::read(root.join("library").join(p)).unwrap()),
    };
    let files = vec![
        read("ops/01ff15365188f6561c4c3bc10730a40e/000000000001-cdc1b6a7-765a-4d0d-843f-4b1fdfa5c90f.json"),
        read("ops/b2707a6b90c9551123761aec860bc888/000000000002-e72ef974-83b0-4bf7-9855-b3959fd217eb.json"),
    ];

    // --- The successor genesis, through the export. ---
    let source = SwiftSource::read(
        entries
            .iter()
            .map(|b| ByteString { bytes: b.clone() })
            .collect(),
    )
    .unwrap();
    assert!(source.problems().unwrap().is_empty());
    let mut policy: Value = serde_json::from_str(&account_default_policy().unwrap()).unwrap();
    policy["recoveryDelay"] = json!(3600);
    let creation = SwiftSuccessorCreation::begin(
        source.clone(),
        SwiftSuccessorParams {
            label: "Library".into(),
            namespaces: vec!["reading.saved".into()],
            include_stewards: false,
            authority_origins: vec![OriginsFor {
                controller: webauthn.clone(),
                origins: vec![ORIGIN.into()],
            }],
            agreements: vec![],
            threshold: Some(1),
            recover_threshold: Some(1),
            add_threshold: Some(1),
            count_by_holders: false,
            policy_json: policy.to_string(),
            signers: vec![owner.clone()],
            handover: vec![owner.clone()],
            issued_ms: T0 - 60 * SEC,
            earlier_attempts: vec![],
        },
        T0,
        ent(64),
    )
    .unwrap();
    // One passkey had a slot: one PRF request, one ceremony, ONE assertion that answers it and
    // opens the Swift slot.
    assert_eq!(creation.stage().unwrap(), CreateStage::Prf);
    let requests = creation.prf_requests().unwrap();
    let ceremonies = creation.ceremonies().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(ceremonies.len(), 1);
    assert!(creation.unpaired().unwrap().is_empty());
    let c = &ceremonies[0];
    assert_eq!(
        (c.request, c.controller.as_str(), c.rp.as_str()),
        (0, webauthn.as_str(), RP)
    );
    assert!(c.user_verification);
    assert_eq!(c.old_salt, prf_salt, "the old salt is the Swift slot's own");
    assert_eq!(c.new_salt, requests[0].salt);
    assert_eq!(c.challenge, requests[0].challenge);
    let one_assertion = host.answer_prf(&requests);
    creation.provide_prf(one_assertion).unwrap();
    // The same assertion's second output opens the Swift slot (the first would be the new one).
    source
        .finish_open_slot(
            c.old_slot,
            vec![UnlockSecret {
                kind: UnlockKind::Prf,
                secret: prf_output.clone(),
            }],
        )
        .unwrap();
    assert_eq!(creation.stage().unwrap(), CreateStage::Genesis);
    let steps = creation.steps().unwrap();
    // The genesis (the owner), then the handover (the owner, under its Swift descriptor).
    assert_eq!(
        steps
            .iter()
            .map(|s| (s.signer.as_str(), s.role))
            .collect::<Vec<_>>(),
        [
            (owner.as_str(), StepRole::Primary),
            (owner.as_str(), StepRole::Handover)
        ]
    );
    let world0 = host.sign(&steps);
    assert_eq!(
        creation.provide_signatures(world0).unwrap(),
        CreateStage::Done
    );
    let created = creation.take_result().unwrap();
    assert!(created
        .stores
        .iter()
        .any(|s| s.path == "authority/00000001.json"));
    assert_eq!(
        created
            .stores
            .iter()
            .filter(|s| s.path.starts_with("predecessor/authority/"))
            .count(),
        entries.len()
    );
    assert!(matches!(
        creation.take_result(),
        Err(AccountError::Consumed { .. })
    ));

    let store = MemSource::new();
    store.store(&created.stores);
    let mut w = World {
        host,
        store,
        account: created.account,
        owner: owner.clone(),
        kit,
        kit_secret,
        entries,
        files,
        home: String::new(),
        copier: String::new(),
        prf_output,
    };

    // --- From here: exports only (and the HOME). ---
    let e = open(&w, &format!("controller:{owner}"), T0);
    let s = e.swift_succession().unwrap();
    assert_eq!(s.stage, MoveStage::WindowNotOpen);
    assert_eq!(s.predecessor, "1e00224caf4fe010167787ad3e943480");
    // The home, appointed by a transition.
    let home = w.host.identity(70);
    w.home = home.clone();
    let hp = w.host.keys[&home].public();
    let req = AccountRequest::prepare(RequestSpec {
        account: w.account.clone(),
        signing: hp.signing,
        agreement: hp.agreement,
        label: "Home".into(),
        kind: AccountMemberKind::Server,
        terms_json: json!({"serves": ["home"]}).to_string(),
        created: account_format_date(T0).unwrap(),
        custody: None,
        operator: None,
        endpoints: vec!["https://home.example/".into()],
    })
    .unwrap();
    let st = req.step().unwrap();
    let info = req.finish(w.host.sign_one(&st.body, &home, false)).unwrap();
    let signers = vec![owner.clone(), w.kit.clone()];
    let change = json!({"homes": {"appoint": [{"request": encode_base64(&info.raw), "terms": {"serves": ["home"]}}]}});
    let a = e
        .begin_transition(
            change.to_string(),
            signers.clone(),
            RuleKind::Control,
            vec![],
        )
        .unwrap();
    let wr = e.finish(a.clone(), w.sign(&a.steps().unwrap())).unwrap();
    store_all(&w, &wr.stores);
    for d in e.record_due().unwrap() {
        store_all(&w, &d.stores);
    }
    // HOME: it receipts the genesis inside the window.
    let received = T0 + 30 * SEC;
    e.advance(received).unwrap();
    let all: Vec<Store> = w
        .store
        .files
        .lock()
        .unwrap()
        .iter()
        .map(|(p, b)| Store {
            path: p.clone(),
            bytes: b.clone(),
        })
        .collect();
    let (objects, _) = objects_of(&all);
    let prepared = prepare_genesis_receipt(&objects, &home, received).unwrap();
    let sig = SignatureResult {
        signature: w.host.keys[&home].sign(prepared.step().body()),
        assertion: None,
    };
    let receipt = finish_genesis_receipt(&prepared, &sig).unwrap();
    put_apply(&w, &e, &pending_path(&receipt), receipt);
    // The first epoch of the namespace.
    let a = e
        .begin_rekey(vec!["reading.saved".into()], vec![owner.clone()], ent(32))
        .unwrap();
    let wr = e.finish(a.clone(), w.sign(&a.steps().unwrap())).unwrap();
    store_all(&w, &wr.stores);
    // The copier, granted with `import` by a transition.
    let copier = w.host.identity(80);
    w.copier = copier.clone();
    let cp = w.host.keys[&copier].public();
    let terms = json!({"records": [{"namespace": "reading.saved", "access": "write"}]});
    let req = AccountRequest::prepare(RequestSpec {
        account: w.account.clone(),
        signing: cp.signing,
        agreement: cp.agreement,
        label: "Copier".into(),
        kind: AccountMemberKind::Device,
        terms_json: terms.to_string(),
        created: account_format_date(received).unwrap(),
        custody: None,
        operator: None,
        endpoints: vec![],
    })
    .unwrap();
    let st = req.step().unwrap();
    let cinfo = req
        .finish(w.host.sign_one(&st.body, &copier, false))
        .unwrap();
    let expires = T0 + 30 * 86_400 * SEC;
    let gterms = json!({"records": [{"namespace": "reading.saved", "access": "write"}],
        "expires": format_date(expires), "import": true});
    let at = received + 2 * SEC;
    e.advance(at).unwrap();
    let change = json!({"grant": {"request": encode_base64(&cinfo.raw), "terms": gterms}});
    let a = e
        .begin_grant_transition(change.to_string(), signers, RuleKind::Control, scanned(&e, &cinfo.raw, at), vec![])
        .unwrap();
    let wr = e.finish(a.clone(), w.sign(&a.steps().unwrap())).unwrap();
    store_all(&w, &wr.stores);
    let t_digest = wr.changes.pending_added.first().cloned().unwrap();
    e.advance(at + 5 * SEC).unwrap();
    let r = home_receipt(&w, &t_digest, at + 5 * SEC);
    put_apply(&w, &e, &pending_path(&r), r);
    assert_eq!(e.swift_succession().unwrap().stage, MoveStage::Waiting);
    // A cold reopen from the host's store alone is at the same stage.
    assert_eq!(reopened_stage(&w, at + 5 * SEC), MoveStage::Waiting);
    (w, e)
}

#[test]
fn the_successor_genesis_export_refuses_a_step_out_of_order() {
    // A step in the wrong stage is a typed refusal and ends the genesis.
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/keyring");
    let mut paths: Vec<_> = std::fs::read_dir(root.join("library/authority"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    paths.sort();
    let entries: Vec<ByteString> = paths
        .iter()
        .map(|p| ByteString {
            bytes: strip(std::fs::read(p).unwrap()),
        })
        .collect();
    let source = SwiftSource::read(entries).unwrap();
    let expected: Value =
        serde_json::from_slice(&std::fs::read(root.join("expected.json")).unwrap()).unwrap();
    let who = expected["controllers"]["owner"]
        .as_str()
        .unwrap()
        .to_string();
    let stranger = Host::new().identity(5);
    let params = |signers: Vec<String>, handover: Vec<String>| SwiftSuccessorParams {
        label: "Library".into(),
        namespaces: vec!["reading.saved".into()],
        include_stewards: false,
        authority_origins: vec![],
        agreements: vec![],
        threshold: None,
        recover_threshold: None,
        add_threshold: None,
        count_by_holders: false,
        policy_json: String::new(),
        signers,
        handover,
        issued_ms: T0 - 60 * SEC,
        earlier_attempts: vec![],
    };
    // Wrong entropy length: a typed bound, and the entropy is not kept.
    assert!(matches!(
        SwiftSuccessorCreation::begin(
            source.clone(),
            params(vec![who.clone()], vec![who.clone()]),
            T0,
            vec![0; 63]
        ),
        Err(AccountError::Bound { .. })
    ));
    // A genesis that cannot succeed is refused BEFORE the person is asked for a passkey
    // assertion: a signer, or a handover key, that is not a controller; a signer twice.
    for (signers, handover) in [
        (vec![stranger.clone()], vec![who.clone()]),
        (vec![who.clone()], vec![stranger.clone()]),
        (vec![who.clone(), who.clone()], vec![who.clone()]),
    ] {
        let r =
            SwiftSuccessorCreation::begin(source.clone(), params(signers, handover), T0, ent(64));
        assert!(
            matches!(
                r,
                Err(AccountError::Malformed { .. } | AccountError::BadSignature { .. })
            ),
            "a doomed genesis is refused at begin, before any ceremony"
        );
    }
    // Signatures before the passkey ceremony: refused, and the genesis is spent.
    let c = SwiftSuccessorCreation::begin(
        source.clone(),
        params(vec![who.clone()], vec![who.clone()]),
        T0,
        ent(64),
    )
    .unwrap();
    assert_eq!(c.stage().unwrap(), CreateStage::Prf);
    assert!(matches!(
        c.provide_signatures(vec![]),
        Err(AccountError::Malformed { .. })
    ));
    assert_eq!(c.stage().unwrap(), CreateStage::Spent);
    assert!(matches!(
        c.provide_prf(vec![]),
        Err(AccountError::Consumed { .. })
    ));
    assert!(matches!(
        c.take_result(),
        Err(AccountError::Consumed { .. })
    ));
}

#[test]
fn the_veto_branch() {
    let (w, e) = build();
    let t = e.swift_succession().unwrap().timing.unwrap();
    let veto_at = (t.window_start_ms + 60 * SEC).max(T0 + 40 * SEC);
    e.advance(veto_at).unwrap();
    let mv = e.begin_swift_veto(veto_at, vec![w.owner.clone()]).unwrap();
    assert_eq!(mv.kind().unwrap(), MoveKind::SwiftVeto);
    let steps = mv.steps().unwrap();
    // A veto finishes on its own: `finish_move` refuses it by name and does not consume it.
    let r = e.finish_move(mv.clone(), w.sign(&steps));
    assert!(
        matches!(r, Err(AccountError::Malformed { .. })),
        "a veto finishes on its own"
    );
    assert_eq!(mv.kind().unwrap(), MoveKind::SwiftVeto);
    let done = mv.finish(w.sign(&steps)).unwrap();
    // The veto comes back with its path and the store to write: the host computes nothing.
    let veto = done.veto.clone().unwrap();
    let path = done.veto_path.clone().unwrap();
    assert!(path.starts_with("vetoes/") && path.ends_with(".json"));
    assert_eq!(done.stores.len(), 1);
    assert_eq!(
        (done.stores[0].path.as_str(), &done.stores[0].bytes),
        (path.as_str(), &veto)
    );
    assert_eq!(mv.kind().unwrap(), MoveKind::Finished);
    store_all(&w, &done.stores);
    e.apply_paths(vec![ListedPath {
        path: path.clone(),
        version: None,
    }])
    .unwrap();
    // A second veto is not prepared while the first is held, on this engine or a cold one.
    assert!(e.begin_swift_veto(veto_at, vec![w.owner.clone()]).is_err());
    let cold = open(&w, &format!("controller:{}", w.owner), veto_at);
    assert!(cold
        .begin_swift_veto(veto_at, vec![w.owner.clone()])
        .is_err());
    let veto_digest = digest(&body_of(&veto));
    assert_eq!(path, format!("vetoes/{veto_digest}.json"));
    // HOME: it receipts the veto and records `successionVetoed`.
    let at = veto_at + 20 * SEC;
    e.advance(at).unwrap();
    let r = home_receipt(&w, &veto_digest, veto_at + 10 * SEC);
    put_apply(&w, &e, &pending_path(&r), r);
    let all: Vec<Store> = w
        .store
        .files
        .lock()
        .unwrap()
        .iter()
        .map(|(p, b)| Store {
            path: p.clone(),
            bytes: b.clone(),
        })
        .collect();
    let (objects, _) = objects_of(&all);
    let rec = colophon_core::v05::write::succession::prepare_succession_vetoed(
        &objects,
        at,
        &veto_digest,
    )
    .and_then(|b| b.finish(vec![]))
    .unwrap();
    for (seq, env) in rec.entries {
        put_apply(&w, &e, &format!("authority/{seq:08}.json"), env);
    }
    assert_eq!(e.swift_succession().unwrap().stage, MoveStage::Vetoed);
    // A cold reopen from the host's store alone is vetoed too.
    assert_eq!(reopened_stage(&w, at), MoveStage::Vetoed);
    // F is refused after the due time.
    e.advance(t.due_ms + 120 * SEC).unwrap();
    assert!(e
        .begin_swift_freeze(vec![w.owner.clone()], t.due_ms + 61 * SEC, vec![])
        .is_err());
}

#[test]
fn the_unvetoed_branch_from_f_to_the_migration() {
    let (w, e) = build();
    let owner_id = format!("controller:{}", w.owner);
    let t = e.swift_succession().unwrap().timing.unwrap();
    let now = t.due_ms + 120 * SEC;
    e.advance(now).unwrap();
    assert_eq!(e.swift_succession().unwrap().stage, MoveStage::Due);
    for d in e.record_due().unwrap() {
        store_all(&w, &d.stores);
    }
    assert_eq!(reopened_stage(&w, now), MoveStage::Due);

    // --- F. Two are prepared while the succession is due; only one can be finished. ---
    let issued = t.due_ms + 61 * SEC;
    let mv = e
        .begin_swift_freeze(vec![w.owner.clone()], issued, vec![])
        .unwrap();
    let mv_again = e
        .begin_swift_freeze(vec![w.owner.clone()], issued + 30 * SEC, vec![])
        .unwrap();
    assert_eq!(mv.kind().unwrap(), MoveKind::SwiftFreeze);
    // F finishes on the engine: standalone is refused and does not consume the step.
    assert!(mv.finish(w.sign(&mv.steps().unwrap())).is_err());
    let mr = e
        .finish_move(mv.clone(), w.sign(&mv.steps().unwrap()))
        .unwrap();
    let f = mr.frozen_entry.clone().unwrap();
    let f_seq = mr.frozen_seq.unwrap();
    // The account's own copy of F is handed over as a store, with its path.
    let f_path = format!("predecessor/authority/{f_seq:08}.json");
    assert_eq!(mr.stores.len(), 1);
    assert_eq!(
        (mr.stores[0].path.as_str(), &mr.stores[0].bytes),
        (f_path.as_str(), &f)
    );
    assert_eq!(e.swift_succession().unwrap().stage, MoveStage::Frozen);
    // A second, different F cannot be finished (the first is held), and cannot be prepared.
    let again = e.finish_move(mv_again.clone(), w.sign(&mv_again.steps().unwrap()));
    assert!(again.is_err(), "a second F at the same seq is refused");
    assert!(e
        .begin_swift_freeze(vec![w.owner.clone()], issued + 60 * SEC, vec![])
        .is_err());
    // The host stores exactly that; the Swift side appends `frozen_entry` to the library.
    store_all(&w, &mr.stores);
    // After a cold reopen from the stored objects the stage is what it was, and a second F is
    // still refused.
    assert_eq!(reopened_stage(&w, now), MoveStage::Frozen);
    let cold = open(&w, &owner_id, now);
    assert!(cold
        .begin_swift_freeze(vec![w.owner.clone()], issued + 90 * SEC, vec![])
        .is_err());
    // Another device that learned F from the Swift side takes it in with
    // `accept_predecessor_entry`: before it, a store without F is `Due`; after, `Frozen`.
    {
        let bare = w.store.copy_of();
        bare.files.lock().unwrap().remove(&f_path);
        let other = open_in(&w, &bare, &owner_id, now);
        assert_eq!(other.swift_succession().unwrap().stage, MoveStage::Due);
        other.accept_predecessor_entry(f.clone(), now).unwrap();
        assert_eq!(other.swift_succession().unwrap().stage, MoveStage::Frozen);
    }
    // A second successor genesis, made while the first is not yet verified (F is written, the
    // home's head has not covered it): the first is still live and blocks it, and this is known
    // before any passkey ceremony (`begin` refuses). Without the first's objects it is refused too.
    {
        let mut lib = w.entries.clone();
        lib.push(f.clone());
        let src2 = SwiftSource::read(
            lib.iter()
                .map(|b| ByteString { bytes: b.clone() })
                .collect(),
        )
        .unwrap();
        let first: Vec<Store> = w
            .store
            .files
            .lock()
            .unwrap()
            .iter()
            .map(|(p, b)| Store {
                path: p.clone(),
                bytes: b.clone(),
            })
            .collect();
        let (objs, _) = objects_of(&first);
        let attempt = |attempts: Vec<AuthorityObjects>| {
            SwiftSuccessorCreation::begin(
                src2.clone(),
                SwiftSuccessorParams {
                    label: "Library".into(),
                    namespaces: vec!["reading.saved".into()],
                    include_stewards: false,
                    authority_origins: vec![],
                    agreements: vec![],
                    threshold: None,
                    recover_threshold: None,
                    add_threshold: None,
                    count_by_holders: false,
                    policy_json: String::new(),
                    signers: vec![w.owner.clone()],
                    handover: vec![w.owner.clone()],
                    issued_ms: issued + 120 * SEC,
                    earlier_attempts: attempts,
                },
                now,
                ent(64),
            )
        };
        assert!(
            attempt(vec![]).is_err(),
            "the earlier attempt's objects are required"
        );
        match attempt(vec![authority_objects(&objs)]) {
            Err(AccountError::Malformed { detail, .. }) => {
                assert!(detail.contains("still live"), "{detail}")
            }
            Err(other) => panic!("{other:?}"),
            Ok(_) => panic!("a live earlier attempt must block a new genesis"),
        }
    }
    // HOME: its fresh head covers F, the succession is verified.
    home_head(&w, &e, now);
    assert_eq!(e.swift_succession().unwrap().stage, MoveStage::Verified);
    assert_eq!(reopened_stage(&w, now), MoveStage::Verified);

    // --- The copier's shares, from the host's own store with no relay. ---
    let now2 = now + 5 * SEC;
    e.advance(now2).unwrap();
    home_head(&w, &e, now2);
    for d in e.record_due().unwrap() {
        store_all(&w, &d.stores);
    }
    assert!(!e.owed_shares().unwrap().is_empty());
    let mv = e
        .begin_swift_copier_shares(w.copier.clone(), vec![w.owner.clone()], ent(32))
        .unwrap();
    // A second shares step prepared at the same head (two taps, two devices).
    let mv_twin = e
        .begin_swift_copier_shares(w.copier.clone(), vec![w.owner.clone()], ent(32))
        .unwrap();
    assert_eq!(mv.kind().unwrap(), MoveKind::RenewShares);
    let head_before = e.head_seq().unwrap();
    let mr = e
        .finish_move(mv.clone(), w.sign(&mv.steps().unwrap()))
        .unwrap();
    let head_after = e.head_seq().unwrap();
    assert_eq!(head_after, head_before + 1);
    // The twin was prepared on a head that has since moved: `refused:fork`, nothing returned,
    // nothing changed, and the head stays.
    let twin = e.finish_move(mv_twin.clone(), w.sign(&mv_twin.steps().unwrap()));
    assert!(
        matches!(twin, Err(AccountError::Refused { ref reason, .. }) if reason == "fork"),
        "a second shares step at a superseded head is refused as a fork"
    );
    assert_eq!(e.head_seq().unwrap(), head_after);
    // And once the shares are sealed there is no second shares step to prepare.
    assert!(e
        .begin_swift_copier_shares(w.copier.clone(), vec![w.owner.clone()], ent(32))
        .is_err());
    assert_eq!(mr.stores.len(), 1, "the shares entry");
    assert!(
        mr.stores[0].path.starts_with("authority/"),
        "{:?}",
        store_paths(&mr.stores)
    );
    store_all(&w, &mr.stores);
    assert_eq!(reopened_stage(&w, now2), MoveStage::Verified);
    let ce = open(&w, &format!("member:{}", w.copier), now2);
    let agreements = ce.begin_unlock_epochs().unwrap();
    assert!(
        !agreements.is_empty(),
        "the copier opens its shares from the host's store"
    );
    ce.finish_unlock_epochs(w.host.answer_epochs(&w.copier, &agreements))
        .unwrap();

    // --- The copy: a source opened by the host's answers, a plan with a translator. ---
    let lib_entries: Vec<ByteString> = w
        .entries
        .iter()
        .map(|b| ByteString { bytes: b.clone() })
        .collect();
    let source = SwiftSource::read(lib_entries).unwrap();
    let slot = source
        .slots()
        .unwrap()
        .into_iter()
        .position(|s| s.kind == SlotKind::Prf)
        .unwrap();
    let ins = source.begin_open_slot(slot as u64).unwrap();
    assert_eq!(ins[0].kind, UnlockKind::Prf);
    source
        .finish_open_slot(
            slot as u64,
            vec![UnlockSecret {
                kind: UnlockKind::Prf,
                secret: w.prf_output.clone(),
            }],
        )
        .unwrap();
    assert!(source.open_namespace_keys().unwrap() >= 1);
    let dest = ce
        .swift_copy_destination(source.library().unwrap())
        .unwrap();
    let plan = SwiftCopyPlan::read(
        source.clone(),
        w.files
            .iter()
            .map(|f| Store {
                path: f.path.clone(),
                bytes: f.bytes.clone(),
            })
            .collect(),
        Some(Box::new(Tr)),
        dest,
    )
    .unwrap();
    let mut written = 0;
    while plan.pending().unwrap() > 0 {
        for item in plan.next_batch(2).unwrap() {
            let cw = ce
                .begin_swift_copy_write(plan.clone(), item, ent(32))
                .unwrap();
            let wr = ce
                .finish_swift_copy_write(plan.clone(), cw.clone(), w.sign(&cw.steps().unwrap()))
                .unwrap();
            store_all(&w, &wr.stores);
            written += 1;
        }
    }
    assert_eq!(written, 2);
    let result = ce.finish_swift_copy(plan.clone()).unwrap();
    let out = result.outcome();
    assert_eq!(
        out.namespaces
            .iter()
            .map(|n| (
                n.namespace.as_str(),
                n.source,
                n.copied.len() as u64,
                n.omitted
            ))
            .collect::<Vec<_>>(),
        [("reading.saved", 2, 2, 0)]
    );

    // --- The migration, with the members' fates. ---
    let members: Vec<MigratedMemberInput> = source
        .members()
        .unwrap()
        .into_iter()
        .map(|m| MigratedMemberInput {
            kind: match m.role.as_deref().and_then(map_swift_role) {
                Some("app") => AccountMemberKind::App,
                Some("agent") => AccountMemberKind::Agent,
                Some("server") => AccountMemberKind::Server,
                _ => AccountMemberKind::Device,
            },
            id: m.id,
            label: m.label,
            dropped: None,
        })
        .collect();
    let (from, until) = (issued, issued + 600 * SEC);
    let at = until + 5 * SEC;
    e.advance(at).unwrap();
    home_head(&w, &e, at);
    let mv = e
        .begin_swift_migration(
            result.clone(),
            members,
            from,
            until,
            until,
            vec![w.owner.clone(), w.kit.clone()],
        )
        .unwrap();
    assert_eq!(mv.kind().unwrap(), MoveKind::SwiftMigration);
    // A second migration prepared before the first is finished (a different drain window).
    let mv_twin = e.begin_swift_migration(
        result.clone(),
        vec![],
        from,
        until + 60 * SEC,
        until,
        vec![w.owner.clone(), w.kit.clone()],
    );
    let mr = e
        .finish_move(mv.clone(), w.sign(&mv.steps().unwrap()))
        .unwrap();
    // Once one is pending no second is prepared, and a twin prepared earlier does not finish.
    assert!(e
        .begin_swift_migration(
            result.clone(),
            vec![],
            from,
            until,
            until,
            vec![w.owner.clone(), w.kit.clone()]
        )
        .is_err());
    if let Ok(twin) = mv_twin {
        assert!(e
            .finish_move(twin.clone(), w.sign(&twin.steps().unwrap()))
            .is_err());
    }
    assert_eq!(
        e.pending()
            .unwrap()
            .iter()
            .filter(|p| p.components.iter().any(|c| c == "migration"))
            .count(),
        1
    );
    let ch = mr.changes.as_ref().unwrap();
    let t_digest = ch.pending_added[0].clone();
    // The transition is handed to the host at its path, and a restart between the finish and
    // the activation keeps it pending.
    assert_eq!(mr.stores.len(), 1);
    assert_eq!(mr.stores[0].path, format!("transitions/{t_digest}.json"));
    store_all(&w, &mr.stores);
    let cold = open(&w, &owner_id, at);
    assert_eq!(
        cold.pending()
            .unwrap()
            .iter()
            .map(|p| p.digest.clone())
            .collect::<Vec<_>>(),
        std::slice::from_ref(&t_digest)
    );
    assert_eq!(cold.swift_succession().unwrap().stage, MoveStage::Verified);
    // HOME: it receipts the transition; after its delay it is recorded and the migration holds.
    let r = home_receipt(&w, &t_digest, at + 10 * SEC);
    put_apply(&w, &e, &pending_path(&r), r);
    let later = at + 7_200 * SEC;
    e.advance(later).unwrap();
    home_head(&w, &e, later);
    for d in e.record_due().unwrap() {
        store_all(&w, &d.stores);
    }
    assert_eq!(e.swift_succession().unwrap().stage, MoveStage::Migrated);
    assert_eq!(reopened_stage(&w, later), MoveStage::Migrated);
}
