//! A whole move, driven only through the builders and the account (spec §15, §16.2, §16.3): a
//! Swift library with a passkey (PRF slot), a device key (sealed slot) and a security key, or a
//! root library, moves into a 0.5 account. The same keys control it, each slot is rebuilt with
//! one assertion, the records are copied and readable, `migration` matches what was copied, and
//! the succession verifies. The Swift side is the independent fixture of `v05_swift_support`.
#![allow(clippy::unwrap_used)]
#[path = "v05_e7_support/mod.rs"]
mod e7;
#[path = "v05_swift_support/mod.rs"]
mod swift;
use colophon_core::v05::account::*;
use colophon_core::v05::encoding::{canonical, digest};
use colophon_core::v05::descriptor::Controller;
use colophon_core::v05::history::{verify_history, Objects, Persisted};
use colophon_core::v05::records::{HeldRecord, Level, OperationHeader};
use colophon_core::v05::slots::{
    answer_with_identity, OpeningInput, OpeningSecret, PrfAssertion, PrfResult, SlotBuild, SlotPlan,
    SlotTarget,
};
use colophon_core::v05::swift_copy::*;
use colophon_core::v05::swift_slots::*;
use colophon_core::v05::vault::VaultSeed;
use colophon_core::v05::write::authority::TransitionRule;
use colophon_core::v05::write::calls::{finish_genesis_receipt, prepare_genesis_receipt, RequestSpec};
use colophon_core::v05::write::succession::*;
use colophon_core::v05::write::swift_veto::SwiftVetoParams;
use colophon_core::v05::write::{format_date, SignatureResult};
use colophon_core::v05::{Failure, Reason};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use swift::*;

const T0: i64 = 1_794_384_000_000; // 2026-11-11T08:00:00Z
const SEC: i64 = 1_000;
const RP: &str = "id.example";
const ORIGIN: &str = "https://id.example";

/// A root library: genesis, two members granted by the root, epoch-1 keys sealed to the root and
/// each member (a library that never adopted a keyring has no vault and no slots).
fn root_library(host: &mut Host) -> SwiftFixture {
    let mut f = keyring_library(host, false);
    let root = &f.root;
    let mut entries = vec![f.entries[0].clone()];
    let mut seq = 1u64;
    let mut add = |host: &Host, entries: &mut Vec<Vec<u8>>, mut body: Value| {
        seq += 1;
        body["seq"] = json!(seq);
        body["previous"] = json!(body_digest(entries.last().unwrap()));
        body["by"] = json!("root");
        body["issued"] = json!(swift_date(60 + seq as u32 * 60));
        entries.push(entry(host, &root.id, &body));
    };
    for (m, label, role) in [(&f.m1, "Phone", "device"), (&f.m2, "Tablet", "app")] {
        add(host, &mut entries, json!({"kind": "grant", "member": pid(&m.signing, &m.agreement), "role": role,
            "custody": "software", "label": label, "namespaces": ["notes", "reading.saved"], "write": true}));
    }
    for ns in ["notes", "reading.saved"] {
        for m in [&f.root, &f.m1, &f.m2] {
            add(host, &mut entries, json!({"kind": "shareKey", "memberID": m.id, "namespace": ns, "epoch": 1,
                "key": swift_sealed(&f.nskeys[ns], &m.signing, &m.agreement, &format!("rshare/{ns}/{}", m.id))}));
        }
    }
    let authority = entries.len() as u64;
    let lib = f.library.clone();
    let mut files = Vec::new();
    for (ns, kind, m, clock, id, payload) in [
        ("notes", "createNotebook", &f.m1, 1, "11111111-aaaa-4aaa-8aaa-000000000001", json!({"id": "nb1", "title": "Alpha"})),
        ("notes", "createNotebook", &f.m2, 2, "22222222-bbbb-4bbb-8bbb-000000000002", json!({"id": "nb2", "title": "Beta"})),
        ("reading.saved", "capture", &f.m1, 1, "33333333-cccc-4ccc-8ccc-000000000003", json!({"id": "i1", "title": "One", "url": "https://example.com/1"})),
        ("reading.saved", "capture", &f.m2, 2, "44444444-dddd-4ddd-8ddd-000000000004", json!({"id": "i2", "title": "Two", "url": "https://example.com/2"})),
    ] {
        files.push(swift_op(host, &lib, &f.nskeys[ns], ns, m, 1, clock, id, kind, payload, authority));
    }
    f.entries = entries;
    f.files = files;
    f
}

/// What a journey leaves for the assertions.
struct Journey {
    acct: Account,
    host: Host,
    f: SwiftFixture,
    ctl: String,
    home: String,
    copier: String,
    w0: i64,
    due: i64,
    now: i64,
}

fn e7_id(n: u8) -> String {
    let k = p256::ecdsa::SigningKey::from_slice(&[n; 32]).unwrap();
    key_id(k.verifying_key().to_encoded_point(false).as_bytes())
}
fn sign(host: &Host, steps: &[colophon_core::v05::write::SigningStep]) -> Vec<SignatureResult> {
    steps
        .iter()
        .map(|s| {
            match s.challenge() {
                None => SignatureResult { signature: host.sign(s.signer(), s.body()), assertion: None },
                Some(ch) => {
                    // The fixture's passkey and security key: scalars [9;32] and [10;32].
                    let rp = s.descriptor().unwrap().webauthn().unwrap().rp().to_string();
                    let scalar = if s.signer() == e7_id(9) { [9u8; 32] } else { [10u8; 32] };
                    e7::key_from_scalar(&scalar).sign_webauthn(&rp, &format!("https://{rp}"), 0x05, ch)
                }
            }
        })
        .collect()
}
fn run(a: &mut Account, host: &Host, action: PendingAction) -> Finished {
    let sigs = sign(host, action.steps());
    a.finish(action, sigs).unwrap()
}
fn passkey_sign(
    key: &p256::ecdsa::SigningKey,
    steps: &[colophon_core::v05::write::SigningStep],
    host: &Host,
) -> Vec<SignatureResult> {
    let k = e7::key_from_scalar(&key.to_bytes());
    steps
        .iter()
        .map(|s| match s.challenge() {
            None => SignatureResult { signature: host.sign(s.signer(), s.body()), assertion: None },
            Some(ch) => {
                let rp = s.descriptor().unwrap().webauthn().unwrap().rp().to_string();
                k.sign_webauthn(&rp, &format!("https://{rp}"), 0x05, ch)
            }
        })
        .collect()
}

/// The first half of every journey: open the old keys, rebuild the slots with one assertion per
/// passkey, build the genesis with its hand-over, open the account, appoint the home, receipt the
/// genesis, make the epochs and admit the copying member. Stops in the wait.
fn start(root_lib: bool) -> (Journey, Vec<SwiftEpochKey>) {
    let mut host = Host::new();
    let f = if root_lib { root_library(&mut host) } else { keyring_library(&mut host, false) };
    let pred = f.entries.clone();
    let lib = SwiftLibrary::read(&pred).unwrap();
    let ctl = if root_lib { f.root.id.clone() } else { f.device.id.clone() };
    let mut opts = CarryOptions::default();
    for id in [&f.passkey_id, &f.security_id] {
        opts.authority_origins.insert(id.clone(), vec![ORIGIN.into()]);
    }
    let carried = swift_carried_controllers(&pred, &opts).unwrap();
    // The successor's vault is a new seed (§7.1).
    let new_seed = VaultSeed::from_host_random([0x77; 32]);
    let mut policy = default_policy();
    policy["recoveryDelay"] = json!(3600);
    let mut base = json!({"controllers": carried, "threshold": 1, "recoverThreshold": 1, "addThreshold": 1, "countBy": "keys",
        "policy": policy, "vault": new_seed.public().unwrap().to_value(), "slots": []});
    let controllers: std::collections::BTreeMap<String, Controller> = carried
        .iter()
        .map(|v| Controller::parse(v.clone(), "carried").unwrap())
        .map(|c| (c.id(), c))
        .collect();
    let target = SlotTarget::genesis(&new_seed, &controllers).unwrap();
    let slotted = swift_slotted_controllers(&pred).unwrap();
    let mut want = if root_lib { vec![] } else { vec![f.device.id.clone(), f.passkey_id.clone()] };
    want.sort();
    assert_eq!(slotted.iter().cloned().collect::<Vec<_>>(), want, "the controllers that had a slot");
    let mut plans = vec![(ctl.clone(), "Device".to_string())];
    if !root_lib {
        plans.push((f.passkey_id.clone(), "Passkey".to_string()));
    }
    let mut assertions = 0;
    let mut vault: Option<PredecessorVault> = None;
    let mut slots = Vec::new();
    for (n, (id, label)) in plans.iter().enumerate() {
        let build = SlotBuild::begin(
            &SlotPlan { controllers: vec![id.clone()], label: label.clone() },
            &target,
            [0x40 + n as u8; 32],
        )
        .unwrap();
        let results: Vec<PrfResult> = if id == &f.passkey_id {
            let old = lib.begin_open(1).unwrap();
            let (cers, unpaired) = pair_ceremonies(&old, build.prf_requests());
            assert_eq!((cers.len(), unpaired.len()), (1, 0), "one ceremony rebuilds the slot");
            let c = &cers[0];
            assert_eq!((c.rp.as_str(), &c.credential), (RP, &f.credential));
            // ONE assertion over the core's challenge; it evaluates the old and the new salt.
            assertions += 1;
            let key = e7::key_from_scalar(&f.passkey_key.to_bytes());
            let client = canonical(&json!({"type": "webauthn.get", "origin": ORIGIN,
                "challenge": colophon_core::v05::encoding::encode_base64url(&c.new_request.challenge)}))
            .unwrap();
            let mut auth = sha(RP.as_bytes());
            auth.push(0x05);
            auth.extend([0, 0, 0, 0]);
            let (ad, cd) = {
                let a = key.sign_assertion(&auth, &client);
                a.assertion.unwrap()
            };
            let a = key.sign_assertion(&auth, &client);
            vault = Some(lib.finish_open(1, &[OpeningSecret::Prf(Host::prf(&c.old_salt))]).unwrap());
            vec![PrfResult {
                assertion: PrfAssertion { authenticator_data: ad, client_data: cd, signature: a.signature },
                output: Host::prf(&c.new_request.salt),
            }]
        } else {
            assert!(build.prf_requests().is_empty(), "a sealed slot needs no ceremony");
            vec![]
        };
        slots.push(build.finish(&new_seed, &results).unwrap().to_value().unwrap());
    }
    assert_eq!(assertions, if root_lib { 0 } else { 1 }, "one assertion per passkey");
    // The old namespace keys: through the vault (a keyring library) or the root's own shares.
    let keys: Vec<SwiftEpochKey> = ["notes", "reading.saved"]
        .iter()
        .map(|ns| match &vault {
            Some(v) => v.open_epoch_key(&lib, ns, 1).unwrap(),
            None => {
                let i = lib.begin_open_share(ns, 1, &f.root.id).unwrap();
                let a = host.answer(&[i]);
                lib.finish_open_share(ns, 1, &f.root.id, &a[0]).unwrap()
            }
        })
        .collect();
    base["slots"] = Value::Array(slots);
    let pending = prepare_swift_genesis(
        &SwiftGenesisParams {
            label: "Library".into(),
            namespaces: vec!["notes".into(), "reading.saved".into()],
            keyring: base,
            issued_ms: T0 - 60 * SEC,
            predecessor: pred.clone(),
            signers: vec![ctl.clone()],
            handover: vec![ctl.clone()],
            earlier_attempts: vec![],
        },
        T0,
    )
    .unwrap();
    let sigs = sign(&host, pending.steps());
    let genesis = pending.finish(sigs).unwrap().entries[0].1.clone();
    let mut acct = Account::open(
        Objects { entries: vec![genesis], predecessor: pred, ..Objects::default() },
        vec![],
        None,
        Identity::Controller(ctl.clone()),
        T0,
    )
    .unwrap();
    assert_eq!(acct.status().code, "ok");
    assert_eq!(acct.swift_succession().unwrap().stage, MoveStage::WindowNotOpen);
    // Unlock with the controller's new slot (slot 0).
    let ins = acct.begin_unlock_slot(0).unwrap();
    acct.finish_unlock_slot(0, &host.answer(&ins)).unwrap();
    // Appoint the successor's home: the window opens at the activation.
    let (home, hs, ha) = host.identity(70);
    let prepared = prepare_request(&RequestSpec {
        account: acct.id(),
        signing: &hs,
        agreement: &ha,
        label: "Home",
        kind: "server",
        terms: json!({"serves": ["home"]}),
        created: &format_date(acct.now_ms()),
        custody: None,
        operator: None,
        endpoints: Some(vec!["https://home.example/".into()]),
    })
    .unwrap();
    let sig = SignatureResult { signature: host.sign(&home, prepared.step().body()), assertion: None };
    let req = finish_request(&prepared, &sig).unwrap();
    let change = Change::homes(json!({"appoint": [{"request": b64(&req.raw), "terms": {"serves": ["home"]}}]}));
    let recover = if root_lib { host.identity(2).0 } else { f.passkey_id.clone() };
    let action = acct.begin_transition(&change, &[ctl.clone(), recover], TransitionRule::Control).unwrap();
    run(&mut acct, &host, action);
    assert_eq!(acct.record_due().unwrap().len(), 1);
    let w0 = T0;
    assert_eq!(acct.swift_succession().unwrap().stage, MoveStage::Waiting);
    // The home receipts the genesis inside the window.
    let received = w0 + 30 * SEC;
    acct.advance(received).unwrap();
    let prepared = prepare_genesis_receipt(acct.objects(), &home, received).unwrap();
    let sig = SignatureResult { signature: host.sign(&home, prepared.step().body()), assertion: None };
    let receipt = finish_genesis_receipt(&prepared, &sig).unwrap();
    acct.merge(
        Incoming { objects: Objects { pending: vec![receipt], ..Objects::default() }, records: vec![] },
        received,
    )
    .unwrap();
    // The epochs, then the copying member with the `import` term (§9.3, §15.3 step 3).
    let action = acct
        .begin_rekey(&["notes".to_string(), "reading.saved".to_string()], &[ctl.clone()], [0x51; 32])
        .unwrap();
    run(&mut acct, &host, action);
    let (copier, cs, ca) = host.identity(80);
    let reqd = prepare_request(&RequestSpec {
        account: acct.id(),
        signing: &cs,
        agreement: &ca,
        label: "Copier",
        kind: "device",
        terms: json!({"records": [{"namespace": "notes", "access": "write"}, {"namespace": "reading.saved", "access": "write"}]}),
        created: &format_date(acct.now_ms()),
        custody: None,
        operator: None,
        endpoints: None,
    })
    .unwrap();
    let sig = SignatureResult { signature: host.sign(&copier, reqd.step().body()), assertion: None };
    let creq = finish_request(&reqd, &sig).unwrap();
    // §15.3 step 3: the import grant is proposed now, to fall due with the succession.
    let expires = T0 + 30 * 86_400 * SEC;
    let terms = json!({"records": [{"namespace": "notes", "access": "write"}, {"namespace": "reading.saved", "access": "write"}],
        "expires": format_date(expires), "import": true});
    let change = Change(serde_json::Map::from_iter([(
        "grant".to_string(),
        json!({"request": b64(&creq.raw), "terms": terms}),
    )]));
    let at = received + 2 * SEC;
    acct.advance(at).unwrap();
    let recover = if root_lib { host.identity(2).0 } else { f.passkey_id.clone() };
    let action = acct.begin_transition(&change, &[ctl.clone(), recover], TransitionRule::Control).unwrap();
    let t_env = run(&mut acct, &host, action).pending[0].clone();
    let t_digest = body_digest(&t_env);
    acct.advance(at + 5 * SEC).unwrap();
    let rbody = canonical(&json!({"protocol": "colophon/receipt/5", "account": acct.id().as_str(),
        "object": t_digest, "received": format_date(at + 5 * SEC), "by": home}))
    .unwrap();
    let receipt = canonical(&json!({"body": b64(&rbody), "signature": b64(&host.sign(&home, &rbody))})).unwrap();
    acct.merge(
        Incoming { objects: Objects { pending: vec![receipt], ..Objects::default() }, records: vec![] },
        at + 5 * SEC,
    )
    .unwrap();
    let due = w0 + 300 * SEC + 3600 * SEC;
    (Journey { acct, host, f, ctl, home, copier, w0, due, now: at + 5 * SEC }, keys)
}

/// The home's head over everything the account holds, issued at `at`.
fn head_of(j: &Journey, at: i64) -> Vec<u8> {
    let (seq, dg) = j.acct.head();
    let body = canonical(&json!({"protocol": "colophon/head/5", "account": j.acct.id().as_str(),
        "authority": {"seq": seq, "digest": dg}, "issued": format_date(at), "by": j.home}))
    .unwrap();
    canonical(&json!({"body": b64(&body), "signature": b64(&j.host.sign(&j.home, &body))})).unwrap()
}
fn give(j: &mut Journey, o: Objects, at: i64) {
    j.acct.merge(Incoming { objects: o, records: vec![] }, at).unwrap();
}

/// Everything up to and including the verified succession and the copier's shares.
fn through_f(root_lib: bool) -> (Journey, Vec<SwiftEpochKey>, i64, Frozen) {
    let (mut j, keys) = start(root_lib);
    let s = j.acct.swift_succession().unwrap();
    assert_eq!(s.stage, MoveStage::Waiting);
    let t = s.status.timing.clone().unwrap();
    assert_eq!((t.window_start_ms, t.due_ms, t.quorum, t.keys_needed), (j.w0, j.due, 1, 1));
    // Out of order: F before it is due.
    let e = j.acct.begin_swift_freeze(vec![], vec![j.ctl.clone()], j.due + 61 * SEC).unwrap_err();
    assert!(e.detail().contains("F is written once the succession is due"), "{e:?}");
    // The grant falls due with the succession.
    let now = j.due + 120 * SEC;
    j.acct.advance(now).unwrap();
    assert_eq!(j.acct.swift_succession().unwrap().stage, MoveStage::Due);
    let rec = j.acct.record_due().unwrap();
    assert!(!rec.is_empty(), "the import grant activates");
    // F, by the keys that may write it: exact Swift-format bytes for the Swift side to append.
    let issued = j.due + 61 * SEC;
    let p = j.acct.begin_swift_freeze(vec![], vec![j.ctl.clone()], issued).unwrap();
    let sigs = sign(&j.host, p.steps());
    let Moved::Frozen(frozen) = j.acct.finish_move(p, sigs).unwrap() else { panic!() };
    let fv: Value = serde_json::from_slice(&frozen.entry).unwrap();
    let body: Value = serde_json::from_slice(&STANDARD.decode(fv["body"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!((body["kind"].as_str(), body["layout"].as_u64()), (Some("layout"), Some(3)));
    assert_eq!(body["successor"].as_str(), Some(j.acct.id().as_str()));
    assert_eq!(body["issued"].as_str(), Some(format_date(issued).as_str()));
    // Not yet verified: the home's fresh head is missing. Then F and the head arrive.
    j.acct.accept_predecessor_entry(frozen.entry.clone(), now).unwrap();
    assert_eq!(j.acct.swift_succession().unwrap().stage, MoveStage::Due);
    let head = head_of(&j, now);
    give(&mut j, Objects { heads: vec![head], ..Objects::default() }, now);
    assert_eq!(j.acct.swift_succession().unwrap().stage, MoveStage::Verified);
    j.now = now;
    (j, keys, issued, frozen)
}

/// The copy (§15.3 step 5): the copying member's session writes every item of the plan.
fn copy_all(
    j: &mut Journey,
    keys: &[SwiftEpochKey],
    translate: Option<&Translator<'_>>,
) -> (Account, CopyResult) {
    let lib = SwiftLibrary::read(&j.f.entries).unwrap();
    let mut plan = CopyPlan::read(&lib, &j.f.files, keys, translate).unwrap();
    // The copier's shares: the import grant is final once the home's head covers its activation,
    // and a member that was provisional when the epochs were made is sealed to them by a renew.
    let now = j.now + 5 * SEC;
    let head = head_of(j, now);
    give(j, Objects { heads: vec![head], ..Objects::default() }, now);
    j.acct.record_due().unwrap();
    let owed = j.acct.owed_shares();
    assert!(!owed.is_empty(), "the copier is owed its shares");
    let action = j
        .acct
        .begin_renew(&j.copier, T0 + 31 * 86_400 * SEC, &[j.ctl.clone()], [0x53; 32])
        .unwrap();
    run(&mut j.acct, &j.host, action);
    assert!(j.acct.owed_shares().is_empty());
    // The copying member's own session.
    let mut c = Account::open(
        j.acct.objects().clone(),
        j.acct.records().to_vec(),
        None,
        Identity::Member(j.copier.clone()),
        now,
    )
    .unwrap();
    let steps = c.begin_unlock_epochs();
    let secrets: Vec<EpochSecret> = steps
        .into_iter()
        .map(|s| EpochSecret { shared: j.host.ids[&j.copier].agree(&s.peer).unwrap(), step: s })
        .collect();
    c.finish_unlock_epochs(secrets).unwrap();
    let mut written = 0;
    while plan.pending() > 0 {
        let batch = plan.next_batch(2);
        assert!(batch.len() <= 2);
        for item in batch {
            let action = c.begin_swift_copy_write(&plan, &item, [0x60 + written as u8; 32]).unwrap();
            let sigs = sign(&j.host, action.steps());
            c.finish_swift_copy_write(&mut plan, &item, action, sigs).unwrap();
            written += 1;
        }
    }
    let result = plan.finish().unwrap();
    (c, result)
}

/// The body digests of the destination headers a session holds, by namespace (computed here
/// from the envelope bytes, not by the code under test).
fn destination_digests(records: &[HeldRecord]) -> std::collections::BTreeMap<String, Vec<String>> {
    let mut out: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    for r in records {
        let env: Value = serde_json::from_slice(&r.bytes).unwrap();
        let body = STANDARD.decode(env["body"].as_str().unwrap()).unwrap();
        let h: Value = serde_json::from_slice(&body).unwrap();
        out.entry(h["namespace"].as_str().unwrap().to_string()).or_default().push(digest(&body));
    }
    out
}

fn e2_recovery(j: &Journey) -> String {
    j.host.ids.iter().find(|(_, i)| i.public().signing == j.f.root_recovery_signing()).map(|(id, _)| id.clone()).unwrap()
}

fn journey(root_lib: bool) {
    let (mut j, keys, f_issued, _frozen) = through_f(root_lib);
    // Out of order: nothing is copied before the succession is verified is tested elsewhere; the
    // copy itself, and then the migration.
    let (c, result) = copy_all(&mut j, &keys, None);
    // Every record is readable in the successor, through admission and the account's views.
    for (ns, titles) in [("notes", vec!["Alpha", "Beta"]), ("reading.saved", vec!["One", "Two"])] {
        let colophon_core::model::Outcome::Success { value: view, .. } = c.view(ns).unwrap() else {
            panic!("{ns} is not readable")
        };
        assert_eq!(view.admitted.len(), 2, "{ns}: both copies admitted");
        assert!(view.admitted.iter().all(|o| o.kind == "colophon.importBatch" && o.author == j.copier));
        assert!(view.held.is_empty() && view.refused.is_empty(), "{:?} {:?}", view.held, view.refused);
        let text = serde_json::to_string(&view.state).unwrap();
        for t in titles {
            assert!(text.contains(t), "{ns}: {t} is in the view: {text}");
        }
        // The original author and clock survive as labelled evidence, not as authorship.
        let ev = c.query(ns, "importEvidence", json!({})).unwrap();
        let colophon_core::model::Outcome::Success { value, .. } = ev else { panic!() };
        let rows = serde_json::to_string(&value).unwrap();
        assert!(rows.contains(&j.f.m1.id) && rows.contains(&j.f.m2.id), "{rows}");
    }
    // The controllers read the copies too, once they hold the records.
    j.acct.merge(Incoming { objects: Objects::default(), records: c.records().to_vec() }, j.now + 10 * SEC).unwrap();
    for ns in ["notes", "reading.saved"] {
        let colophon_core::model::Outcome::Success { value: v, .. } = j.acct.view(ns).unwrap() else { panic!() };
        assert_eq!(v.admitted.len(), 2);
    }
    // The counts and digests the copy reports are the destination records' own.
    let dest = destination_digests(c.records());
    assert_eq!(result.namespaces.len(), 2);
    for n in &result.namespaces {
        assert_eq!((n.source, n.omitted, n.copied.len() as u64), (2, 0, 2), "{}", n.namespace);
        let mut mine = n.copied.clone();
        let mut theirs = dest[&n.namespace].clone();
        mine.sort();
        theirs.sort();
        assert_eq!(mine, theirs);
    }
    assert!(result.omitted.is_empty());
    // `migration`, after the drain window, from the copy's own result.
    let lib = SwiftLibrary::read(&j.f.entries).unwrap();
    let members: Vec<MigratedMember> = swift_members(&lib)
        .unwrap()
        .into_iter()
        .map(|m| MigratedMember {
            kind: map_swift_role(m.role.as_deref().unwrap()).unwrap().to_string(),
            id: m.id,
            label: m.label,
            dropped: None,
        })
        .collect();
    assert_eq!(members.len(), 2);
    let (from, until) = (f_issued, f_issued + 600 * SEC);
    let recover = if root_lib { e2_recovery(&j) } else { j.f.passkey_id.clone() };
    let signers = vec![j.ctl.clone(), recover];
    // Out of order: before the drain window's end.
    let e = j.acct.begin_swift_migration(&result, members.clone(), from, until, until, signers.clone()).unwrap_err();
    assert!(e.detail().contains("after the drain window"), "{e:?}");
    let at = until + 5 * SEC;
    j.acct.advance(at).unwrap();
    // A home keeps issuing fresh heads; the succession stays verified only while they come.
    let head = head_of(&j, at);
    give(&mut j, Objects { heads: vec![head], ..Objects::default() }, at);
    let p = j.acct.begin_swift_migration(&result, members, from, until, until, signers).unwrap();
    let sigs = sign(&j.host, p.steps());
    let Moved::Migration(ch) = j.acct.finish_move(p, sigs).unwrap() else { panic!() };
    assert_eq!(ch.pending.added.len(), 1);
    let t_digest = ch.pending.added[0].clone();
    // The home receipts the transition; after its due time it is recorded.
    let rbody = canonical(&json!({"protocol": "colophon/receipt/5", "account": j.acct.id().as_str(),
        "object": t_digest, "received": format_date(at + 10 * SEC), "by": j.home}))
    .unwrap();
    let receipt = canonical(&json!({"body": b64(&rbody), "signature": b64(&j.host.sign(&j.home, &rbody))})).unwrap();
    give(&mut j, Objects { pending: vec![receipt], ..Objects::default() }, at + 10 * SEC);
    let later = at + 7_200 * SEC;
    j.acct.advance(later).unwrap();
    let head = head_of(&j, later);
    give(&mut j, Objects { heads: vec![head], ..Objects::default() }, later);
    j.acct.record_due().unwrap();
    assert_eq!(j.acct.swift_succession().unwrap().stage, MoveStage::Migrated);
    let m = verify_history(j.acct.objects(), &Persisted::default(), later)
        .state
        .unwrap()
        .migration
        .unwrap();
    for n in m["namespaces"].as_array().unwrap() {
        let ns = n["namespace"].as_str().unwrap();
        let mut d = dest[ns].clone();
        d.sort();
        assert_eq!((n["source"].as_u64(), n["copied"].as_u64(), n["omitted"].as_u64()), (Some(2), Some(2), Some(0)));
        assert_eq!(n["view"].as_str().unwrap(), digest(d.join("\n").as_bytes()), "{ns}");
    }
    assert_eq!(m["predecessor"]["account"], lib.library());
    assert_eq!(m["drain"]["from"], format_date(from));
    let slot_of: std::collections::BTreeMap<String, bool> = m["controllers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| (c["id"].as_str().unwrap().to_string(), c["slot"].as_bool().unwrap()))
        .collect();
    if root_lib {
        assert_eq!(slot_of.len(), 2);
        assert_eq!(slot_of[&j.f.root.id], true, "the root has the new slot the successor built for it");
    } else {
        assert_eq!(slot_of[&j.f.device.id], true);
        assert_eq!(slot_of[&j.f.passkey_id], true);
        assert_eq!(slot_of[&j.f.security_id], false, "the security key never had a slot");
    }
    // Out of order: a second migration is refused.
    assert!(j.acct.swift_succession().unwrap().stage == MoveStage::Migrated);
}

#[test]
fn a_swift_keyring_library_moves_with_its_keys_slots_and_records() {
    journey(false);
}
#[test]
fn a_swift_root_library_moves_the_same_way() {
    journey(true);
}
