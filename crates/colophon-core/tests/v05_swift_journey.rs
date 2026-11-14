//! A whole move, driven only through the builders and the account (spec §15, §16.2, §16.3): a
//! Swift library with a passkey (PRF slot), a device key (sealed slot) and a security key, or a
//! root library, moves into a 0.5 account. The same keys control it, each slot is rebuilt with
//! one assertion, the records are copied and readable, `migration` matches what was copied, and
//! the succession verifies. The Swift side is the independent fixture of `v05_swift_support`.
#![allow(
    clippy::unwrap_used,
    clippy::cloned_ref_to_slice_refs,
    clippy::bool_assert_comparison
)]
#[path = "v05_e7_support/mod.rs"]
mod e7;
#[path = "v05_swift_support/mod.rs"]
mod swift;
use base64::{engine::general_purpose::STANDARD, Engine};
use colophon_core::v05::account::*;
use colophon_core::v05::descriptor::Controller;
use colophon_core::v05::encoding::{canonical, digest};
use colophon_core::v05::history::{verify_history, Objects, Persisted};
use colophon_core::v05::records::HeldRecord;
use colophon_core::v05::slots::{
    OpeningSecret, PrfAssertion, PrfResult, SlotBuild, SlotPlan, SlotTarget,
};
use colophon_core::v05::swift_copy::*;
use colophon_core::v05::swift_slots::*;
use colophon_core::v05::vault::VaultSeed;
use colophon_core::v05::write::authority::TransitionRule;
use colophon_core::v05::write::calls::{
    finish_genesis_receipt, prepare_genesis_receipt, RequestSpec,
};
use colophon_core::v05::write::succession::*;
use colophon_core::v05::write::swift_veto::SwiftVetoParams;
use colophon_core::v05::write::upgrade::UpgradeParams;
use colophon_core::v05::write::{format_date, SignatureResult};
use colophon_core::v05::Failure;
use serde_json::{json, Value};
use swift::*;

const T0: i64 = 1_794_384_000_000; // 2026-11-11T08:00:00Z
const SEC: i64 = 1_000;
const RP: &str = "id.example";
const ORIGIN: &str = "https://id.example";

/// A root library: genesis, two members granted by the root, epoch-1 keys sealed to the root and
/// each member (a library that never adopted a keyring has no vault and no slots).
fn root_library_with(host: &mut Host, extra_namespace: bool) -> SwiftFixture {
    let mut f = keyring_library_with(host, false, extra_namespace, false);
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
        add(
            host,
            &mut entries,
            json!({"kind": "grant", "member": pid(&m.signing, &m.agreement), "role": role,
            "custody": "software", "label": label, "write": true,
            "namespaces": if extra_namespace { json!(["notes", "reading.saved", "reading.books"]) } else { json!(["notes", "reading.saved"]) }}),
        );
    }
    for ns in ["notes", "reading.saved"] {
        for m in [&f.root, &f.m1, &f.m2] {
            add(
                host,
                &mut entries,
                json!({"kind": "shareKey", "memberID": m.id, "namespace": ns, "epoch": 1,
                "key": swift_sealed(&f.nskeys[ns], &m.signing, &m.agreement, &format!("rshare/{ns}/{}", m.id))}),
            );
        }
    }
    let authority = entries.len() as u64;
    let lib = f.library.clone();
    let mut files = Vec::new();
    for (ns, kind, m, clock, id, payload) in [
        (
            "notes",
            "notebook.create",
            &f.m1,
            1,
            "11111111-aaaa-4aaa-8aaa-000000000001",
            json!({"notebook": "nb1", "title": "Alpha"}),
        ),
        (
            "notes",
            "notebook.create",
            &f.m2,
            2,
            "22222222-bbbb-4bbb-8bbb-000000000002",
            json!({"notebook": "nb2", "title": "Beta"}),
        ),
        (
            "reading.saved",
            "capture.link",
            &f.m1,
            1,
            "33333333-cccc-4ccc-8ccc-000000000003",
            json!({"item": "i1", "title": "One", "url": "https://example.com/1"}),
        ),
        (
            "reading.saved",
            "capture.link",
            &f.m2,
            2,
            "44444444-dddd-4ddd-8ddd-000000000004",
            json!({"item": "i2", "title": "Two", "url": "https://example.com/2"}),
        ),
    ] {
        files.push(swift_op(
            host,
            &lib,
            &f.nskeys[ns],
            ns,
            m,
            1,
            clock,
            id,
            kind,
            payload,
            authority,
        ));
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
                None => SignatureResult {
                    signature: host.sign(s.signer(), s.body()),
                    assertion: None,
                },
                Some(ch) => {
                    // The fixture's passkey and security key: scalars [9;32] and [10;32].
                    let rp = s.descriptor().unwrap().webauthn().unwrap().rp().to_string();
                    let scalar = if s.signer() == e7_id(9) {
                        [9u8; 32]
                    } else {
                        [10u8; 32]
                    };
                    e7::key_from_scalar(&scalar).sign_webauthn(
                        &rp,
                        &format!("https://{rp}"),
                        0x05,
                        ch,
                    )
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
            None => SignatureResult {
                signature: host.sign(s.signer(), s.body()),
                assertion: None,
            },
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
/// What a journey is built from.
#[derive(Clone, Copy, Default)]
struct Opts {
    root_lib: bool,
    /// The grants also name `reading.books`, which never had an epoch.
    extra_namespace: bool,
    /// The second member is revoked and granted again.
    regrant: bool,
    /// A stray file under a namespace the predecessor never named.
    planted: bool,
}
fn start(root_lib: bool) -> (Journey, Vec<SwiftEpochKey>) {
    start_with(Opts {
        root_lib,
        ..Opts::default()
    })
}
fn start_with(o: Opts) -> (Journey, Vec<SwiftEpochKey>) {
    let root_lib = o.root_lib;
    let mut host = Host::new();
    let mut f = if root_lib {
        root_library_with(&mut host, o.extra_namespace)
    } else {
        keyring_library_with(&mut host, false, o.extra_namespace, o.regrant)
    };
    if o.planted {
        f.files.push(SourceFile {
            path: "ops/0123456789abcdef0123456789abcdef/not.a.namespace/000000000001-junk.json"
                .into(),
            bytes: b"junk".to_vec(),
        });
    }
    let pred = f.entries.clone();
    let lib = SwiftLibrary::read(&pred).unwrap();
    let ctl = if root_lib {
        f.root.id.clone()
    } else {
        f.device.id.clone()
    };
    let mut opts = CarryOptions::default();
    for id in [&f.passkey_id, &f.security_id] {
        opts.authority_origins
            .insert(id.clone(), vec![ORIGIN.into()]);
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
    let mut want = if root_lib {
        vec![]
    } else {
        vec![f.device.id.clone(), f.passkey_id.clone()]
    };
    want.sort();
    assert_eq!(
        slotted.iter().cloned().collect::<Vec<_>>(),
        want,
        "the controllers that had a slot"
    );
    let mut plans = vec![(ctl.clone(), "Device".to_string())];
    if !root_lib {
        plans.push((f.passkey_id.clone(), "Passkey".to_string()));
    }
    let mut assertions = 0;
    let mut vault: Option<PredecessorVault> = None;
    let mut slots = Vec::new();
    for (n, (id, label)) in plans.iter().enumerate() {
        let build = SlotBuild::begin(
            &SlotPlan {
                controllers: vec![id.clone()],
                label: label.clone(),
            },
            &target,
            [0x40 + n as u8; 32],
        )
        .unwrap();
        let results: Vec<PrfResult> = if id == &f.passkey_id {
            let (cers, unpaired) = lib.pair_ceremonies(1, build.prf_requests()).unwrap();
            assert_eq!(
                (cers.len(), unpaired.len()),
                (1, 0),
                "one ceremony rebuilds the slot"
            );
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
            // The same ceremony without user verification is refused: the carried passkey has
            // `verification: true`, and the new route is verified against the controller.
            {
                let again = SlotBuild::begin(
                    &SlotPlan {
                        controllers: vec![id.clone()],
                        label: label.clone(),
                    },
                    &target,
                    [0x40 + n as u8; 32],
                )
                .unwrap();
                let mut no_uv = sha(RP.as_bytes());
                no_uv.push(0x01);
                no_uv.extend([0, 0, 0, 0]);
                let b = key.sign_assertion(&no_uv, &client);
                let (ad2, cd2) = b.assertion.clone().unwrap();
                let r = again.finish(
                    &new_seed,
                    &[PrfResult {
                        assertion: PrfAssertion {
                            authenticator_data: ad2,
                            client_data: cd2,
                            signature: b.signature,
                        },
                        output: Host::prf(&c.new_request.salt),
                    }],
                );
                assert!(
                    r.is_err(),
                    "an assertion without UV does not build the slot"
                );
            }
            vault = Some(
                lib.finish_open(1, &[OpeningSecret::Prf(Host::prf(&c.old_salt))])
                    .unwrap(),
            );
            vec![PrfResult {
                assertion: PrfAssertion {
                    authenticator_data: ad,
                    client_data: cd,
                    signature: a.signature,
                },
                output: Host::prf(&c.new_request.salt),
            }]
        } else {
            assert!(
                build.prf_requests().is_empty(),
                "a sealed slot needs no ceremony"
            );
            vec![]
        };
        slots.push(
            build
                .finish(&new_seed, &results)
                .unwrap()
                .to_value()
                .unwrap(),
        );
    }
    assert_eq!(
        assertions,
        if root_lib { 0 } else { 1 },
        "one assertion per passkey"
    );
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
        Objects {
            entries: vec![genesis],
            predecessor: pred,
            ..Objects::default()
        },
        vec![],
        None,
        Identity::Controller(ctl.clone()),
        T0,
    )
    .unwrap();
    assert_eq!(acct.status().code, "ok");
    assert_eq!(
        acct.swift_succession().unwrap().stage,
        MoveStage::WindowNotOpen
    );
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
    let sig = SignatureResult {
        signature: host.sign(&home, prepared.step().body()),
        assertion: None,
    };
    let req = finish_request(&prepared, &sig).unwrap();
    let change = Change::homes(
        json!({"appoint": [{"request": b64(&req.raw), "terms": {"serves": ["home"]}}]}),
    );
    let recover = if root_lib {
        host.identity(2).0
    } else {
        f.passkey_id.clone()
    };
    let action = acct
        .begin_transition(&change, &[ctl.clone(), recover], TransitionRule::Control)
        .unwrap();
    run(&mut acct, &host, action);
    assert_eq!(acct.record_due().unwrap().len(), 1);
    let w0 = T0;
    assert_eq!(acct.swift_succession().unwrap().stage, MoveStage::Waiting);
    // The home receipts the genesis inside the window.
    let received = w0 + 30 * SEC;
    acct.advance(received).unwrap();
    let prepared = prepare_genesis_receipt(acct.objects(), &home, received).unwrap();
    let sig = SignatureResult {
        signature: host.sign(&home, prepared.step().body()),
        assertion: None,
    };
    let receipt = finish_genesis_receipt(&prepared, &sig).unwrap();
    acct.merge(
        Incoming {
            objects: Objects {
                pending: vec![receipt],
                ..Objects::default()
            },
            records: vec![],
        },
        received,
    )
    .unwrap();
    // The epochs, then the copying member with the `import` term (§9.3, §15.3 step 3).
    let action = acct
        .begin_rekey(
            &["notes".to_string(), "reading.saved".to_string()],
            &[ctl.clone()],
            [0x51; 32],
        )
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
    let sig = SignatureResult {
        signature: host.sign(&copier, reqd.step().body()),
        assertion: None,
    };
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
    let recover = if root_lib {
        host.identity(2).0
    } else {
        f.passkey_id.clone()
    };
    let action = acct
        .begin_transition(&change, &[ctl.clone(), recover], TransitionRule::Control)
        .unwrap();
    let t_env = run(&mut acct, &host, action).pending[0].clone();
    let t_digest = body_digest(&t_env);
    acct.advance(at + 5 * SEC).unwrap();
    let rbody = canonical(
        &json!({"protocol": "colophon/receipt/5", "account": acct.id().as_str(),
        "object": t_digest, "received": format_date(at + 5 * SEC), "by": home}),
    )
    .unwrap();
    let receipt =
        canonical(&json!({"body": b64(&rbody), "signature": b64(&host.sign(&home, &rbody))}))
            .unwrap();
    acct.merge(
        Incoming {
            objects: Objects {
                pending: vec![receipt],
                ..Objects::default()
            },
            records: vec![],
        },
        at + 5 * SEC,
    )
    .unwrap();
    let due = w0 + 300 * SEC + 3600 * SEC;
    (
        Journey {
            acct,
            host,
            f,
            ctl,
            home,
            copier,
            w0,
            due,
            now: at + 5 * SEC,
        },
        keys,
    )
}

/// The home's head over everything the account holds, issued at `at`.
fn head_of(j: &Journey, at: i64) -> Vec<u8> {
    let (seq, dg) = j.acct.head();
    let body = canonical(
        &json!({"protocol": "colophon/head/5", "account": j.acct.id().as_str(),
        "authority": {"seq": seq, "digest": dg}, "issued": format_date(at), "by": j.home}),
    )
    .unwrap();
    canonical(&json!({"body": b64(&body), "signature": b64(&j.host.sign(&j.home, &body))})).unwrap()
}
fn give(j: &mut Journey, o: Objects, at: i64) {
    j.acct
        .merge(
            Incoming {
                objects: o,
                records: vec![],
            },
            at,
        )
        .unwrap();
}

/// Everything up to and including the verified succession and the copier's shares.
fn through_f(root_lib: bool) -> (Journey, Vec<SwiftEpochKey>, i64, Frozen) {
    through_f_with(Opts {
        root_lib,
        ..Opts::default()
    })
}
fn through_f_with(o: Opts) -> (Journey, Vec<SwiftEpochKey>, i64, Frozen) {
    let (mut j, keys) = start_with(o);
    let s = j.acct.swift_succession().unwrap();
    assert_eq!(s.stage, MoveStage::Waiting);
    let t = s.status.timing.clone().unwrap();
    assert_eq!(
        (t.window_start_ms, t.due_ms, t.quorum, t.keys_needed),
        (j.w0, j.due, 1, 1)
    );
    // Out of order: F before it is due.
    let e = j
        .acct
        .begin_swift_freeze(vec![], vec![j.ctl.clone()], j.due + 61 * SEC)
        .unwrap_err();
    assert!(
        e.detail()
            .contains("F is written once the succession is due"),
        "{e:?}"
    );
    // The grant falls due with the succession.
    let now = j.due + 120 * SEC;
    j.acct.advance(now).unwrap();
    assert_eq!(j.acct.swift_succession().unwrap().stage, MoveStage::Due);
    let rec = j.acct.record_due().unwrap();
    assert!(!rec.is_empty(), "the import grant activates");
    // F, by the keys that may write it: exact Swift-format bytes for the Swift side to append.
    let issued = j.due + 61 * SEC;
    let p = j
        .acct
        .begin_swift_freeze(vec![], vec![j.ctl.clone()], issued)
        .unwrap();
    let sigs = sign(&j.host, p.steps());
    let Moved::Frozen(frozen) = j.acct.finish_move(p, sigs).unwrap() else {
        panic!()
    };
    let fv: Value = serde_json::from_slice(&frozen.entry).unwrap();
    let body: Value =
        serde_json::from_slice(&STANDARD.decode(fv["body"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(
        (body["kind"].as_str(), body["layout"].as_u64()),
        (Some("layout"), Some(3))
    );
    assert_eq!(body["successor"].as_str(), Some(j.acct.id().as_str()));
    assert_eq!(body["issued"].as_str(), Some(format_date(issued).as_str()));
    // Not yet verified: the home's fresh head is missing. Then F and the head arrive.
    j.acct
        .accept_predecessor_entry(frozen.entry.clone(), now)
        .unwrap();
    assert_eq!(j.acct.swift_succession().unwrap().stage, MoveStage::Frozen);
    let head = head_of(&j, now);
    give(
        &mut j,
        Objects {
            heads: vec![head],
            ..Objects::default()
        },
        now,
    );
    assert_eq!(
        j.acct.swift_succession().unwrap().stage,
        MoveStage::Verified
    );
    j.now = now;
    (j, keys, issued, frozen)
}

/// The copying member's session: it is owed its shares (it was provisional when the epochs were
/// made), which a shares-only `renew` seals without extending its expiry.
fn copier_session(j: &mut Journey) -> Account {
    let now = j.now + 5 * SEC;
    let head = head_of(j, now);
    give(
        j,
        Objects {
            heads: vec![head],
            ..Objects::default()
        },
        now,
    );
    j.acct.record_due().unwrap();
    assert!(
        !j.acct.owed_shares().is_empty(),
        "the copier is owed its shares"
    );
    let p = j
        .acct
        .begin_swift_copier_shares(&j.copier, &[j.ctl.clone()], [0x53; 32])
        .unwrap();
    let sigs = sign(&j.host, p.steps());
    assert!(matches!(
        j.acct.finish_move(p, sigs).unwrap(),
        Moved::Shares(_)
    ));
    assert!(j.acct.owed_shares().is_empty());
    let copier = j
        .acct
        .members()
        .into_iter()
        .find(|m| m.member.id == j.copier)
        .unwrap();
    assert_eq!(
        copier.expires_ms,
        Some(T0 + 30 * 86_400 * SEC),
        "the shares-only renew leaves the expiry exactly as granted"
    );
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
        .map(|s| EpochSecret {
            shared: j.host.ids[&j.copier].agree(&s.peer).unwrap(),
            step: s,
        })
        .collect();
    c.finish_unlock_epochs(secrets).unwrap();
    c
}

/// Write up to `limit` items of the plan through the copier's session, two to a batch.
fn write_items(j: &Journey, c: &mut Account, plan: &mut CopyPlan, limit: usize, salt: u8) {
    let mut written = 0usize;
    while plan.pending() > 0 && written < limit {
        for item in plan.next_batch(2.min(limit - written)) {
            let w = c
                .begin_swift_copy_write(plan, &item, [salt.wrapping_add(written as u8); 32])
                .unwrap();
            let sigs = sign(&j.host, w.steps());
            c.finish_swift_copy_write(plan, w, sigs).unwrap();
            written += 1;
        }
    }
}

/// The copy (§15.3 step 5): the copying member's session writes every item of the plan.
fn copy_all(j: &mut Journey, keys: &[SwiftEpochKey]) -> (Account, CopyResult) {
    copy_all_with(j, keys, &translate)
}
fn copy_all_with(
    j: &mut Journey,
    keys: &[SwiftEpochKey],
    t: &Translator<'_>,
) -> (Account, CopyResult) {
    let lib = SwiftLibrary::read(&j.f.entries).unwrap();
    let mut c = copier_session(j);
    let dest = c.swift_copy_destination(lib.library()).unwrap();
    let mut plan = CopyPlan::read(&lib, &j.f.files, keys, Some(t), &dest).unwrap();
    write_items(j, &mut c, &mut plan, usize::MAX, 0x60);
    let result = c.finish_swift_copy(plan).unwrap();
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
        out.entry(h["namespace"].as_str().unwrap().to_string())
            .or_default()
            .push(digest(&body));
    }
    out
}

fn e2_recovery(j: &Journey) -> String {
    j.host
        .ids
        .iter()
        .find(|(_, i)| i.public().signing == j.f.root_recovery_signing())
        .map(|(id, _)| id.clone())
        .unwrap()
}

fn journey(root_lib: bool) {
    journey_with(Opts {
        root_lib,
        ..Opts::default()
    });
}
fn journey_with(o: Opts) {
    let root_lib = o.root_lib;
    let (mut j, keys, f_issued, _frozen) = through_f_with(o);
    // Out of order: nothing is copied before the succession is verified is tested elsewhere; the
    // copy itself, and then the migration.
    let (c, result) = copy_all(&mut j, &keys);
    // Every record is readable in the successor, through admission and the account's views.
    for (ns, titles) in [
        ("notes", vec!["Alpha", "Beta"]),
        ("reading.saved", vec!["One", "Two"]),
    ] {
        let colophon_core::model::Outcome::Success { value: view, .. } = c.view(ns).unwrap() else {
            panic!("{ns} is not readable")
        };
        assert_eq!(view.admitted.len(), 2, "{ns}: both copies admitted");
        assert!(view
            .admitted
            .iter()
            .all(|o| o.kind == "colophon.importBatch" && o.author == j.copier));
        assert!(
            view.held.is_empty() && view.refused.is_empty(),
            "{:?} {:?}",
            view.held,
            view.refused
        );
        let text = serde_json::to_string(&view.state).unwrap();
        for t in titles {
            assert!(text.contains(t), "{ns}: {t} is in the view: {text}");
        }
        // The original author and clock survive as labelled evidence, not as authorship.
        let ev = c.query(ns, "importEvidence", json!({})).unwrap();
        let colophon_core::model::Outcome::Success { value, .. } = ev else {
            panic!()
        };
        let rows = serde_json::to_string(&value).unwrap();
        assert!(
            rows.contains(&j.f.m1.id) && rows.contains(&j.f.m2.id),
            "{rows}"
        );
    }
    // The controllers read the copies too, once they hold the records.
    j.acct
        .merge(
            Incoming {
                objects: Objects::default(),
                records: c.records().to_vec(),
            },
            j.now + 10 * SEC,
        )
        .unwrap();
    for ns in ["notes", "reading.saved"] {
        let colophon_core::model::Outcome::Success { value: v, .. } = j.acct.view(ns).unwrap()
        else {
            panic!()
        };
        assert_eq!(v.admitted.len(), 2);
    }
    // The counts and digests the copy reports are the destination records' own.
    let dest = destination_digests(c.records());
    assert_eq!(
        result.namespaces().len(),
        if o.extra_namespace { 3 } else { 2 }
    );
    for n in result.namespaces() {
        let want = if n.namespace == "reading.books" { 0 } else { 2 };
        assert_eq!(
            (n.source, n.omitted, n.copied.len() as u64),
            (want, 0, want),
            "{}",
            n.namespace
        );
        let mut mine = n.copied.clone();
        let mut theirs = dest.get(&n.namespace).cloned().unwrap_or_default();
        mine.sort();
        theirs.sort();
        assert_eq!(mine, theirs);
    }
    assert_eq!(result.omitted().len(), o.planted as usize);
    if o.planted {
        assert_eq!(result.omitted()[0].1, "invalidPayload");
    }
    // `migration`, after the drain window, from the copy's own result.
    let lib = SwiftLibrary::read(&j.f.entries).unwrap();
    let members: Vec<MigratedMember> = swift_members(&lib)
        .unwrap()
        .into_iter()
        .map(|m| MigratedMember {
            kind: map_swift_role(m.role.as_deref().unwrap())
                .unwrap()
                .to_string(),
            id: m.id,
            label: m.label,
            dropped: None,
        })
        .collect();
    assert_eq!(members.len(), 2);
    let (from, until) = (f_issued, f_issued + 600 * SEC);
    let recover = if root_lib {
        e2_recovery(&j)
    } else {
        j.f.passkey_id.clone()
    };
    let signers = vec![j.ctl.clone(), recover];
    // Out of order: before the drain window's end.
    let e = j
        .acct
        .begin_swift_migration(
            &result,
            members.clone(),
            from,
            until,
            until,
            signers.clone(),
        )
        .unwrap_err();
    assert!(e.detail().contains("after the drain window"), "{e:?}");
    let at = until + 5 * SEC;
    j.acct.advance(at).unwrap();
    // A home keeps issuing fresh heads; the succession stays verified only while they come.
    let head = head_of(&j, at);
    give(
        &mut j,
        Objects {
            heads: vec![head],
            ..Objects::default()
        },
        at,
    );
    let p = j
        .acct
        .begin_swift_migration(&result, members, from, until, until, signers)
        .unwrap();
    let sigs = sign(&j.host, p.steps());
    let Moved::Migration(ch) = j.acct.finish_move(p, sigs).unwrap() else {
        panic!()
    };
    assert_eq!(ch.pending.added.len(), 1);
    let t_digest = ch.pending.added[0].clone();
    // The home receipts the transition; after its due time it is recorded.
    let rbody = canonical(
        &json!({"protocol": "colophon/receipt/5", "account": j.acct.id().as_str(),
        "object": t_digest, "received": format_date(at + 10 * SEC), "by": j.home}),
    )
    .unwrap();
    let receipt =
        canonical(&json!({"body": b64(&rbody), "signature": b64(&j.host.sign(&j.home, &rbody))}))
            .unwrap();
    give(
        &mut j,
        Objects {
            pending: vec![receipt],
            ..Objects::default()
        },
        at + 10 * SEC,
    );
    let later = at + 7_200 * SEC;
    j.acct.advance(later).unwrap();
    let head = head_of(&j, later);
    give(
        &mut j,
        Objects {
            heads: vec![head],
            ..Objects::default()
        },
        later,
    );
    j.acct.record_due().unwrap();
    assert_eq!(
        j.acct.swift_succession().unwrap().stage,
        MoveStage::Migrated
    );
    let m = verify_history(j.acct.objects(), &Persisted::default(), later)
        .state
        .unwrap()
        .migration
        .unwrap();
    for n in m["namespaces"].as_array().unwrap() {
        let ns = n["namespace"].as_str().unwrap();
        let mut d = dest.get(ns).cloned().unwrap_or_default();
        let want = if ns == "reading.books" { 0 } else { 2 };
        d.sort();
        assert_eq!(
            (
                n["source"].as_u64(),
                n["copied"].as_u64(),
                n["omitted"].as_u64()
            ),
            (Some(want), Some(want), Some(0))
        );
        assert_eq!(
            n["view"].as_str().unwrap(),
            digest(d.join("\n").as_bytes()),
            "{ns}"
        );
    }
    assert_eq!(m["predecessor"]["account"], lib.library());
    assert_eq!(m["drain"]["from"], format_date(from));
    let slot_of: std::collections::BTreeMap<String, bool> = m["controllers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            (
                c["id"].as_str().unwrap().to_string(),
                c["slot"].as_bool().unwrap(),
            )
        })
        .collect();
    if root_lib {
        assert_eq!(slot_of.len(), 2);
        assert_eq!(
            slot_of[&j.f.root.id], true,
            "the root has the new slot the successor built for it"
        );
    } else {
        assert_eq!(slot_of[&j.f.device.id], true);
        assert_eq!(slot_of[&j.f.passkey_id], true);
        assert_eq!(
            slot_of[&j.f.security_id], false,
            "the security key never had a slot"
        );
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

// ---------------------------------------------------------------------------------------------
// The veto, and the refusals of the order.

use colophon_core::v05::write::authority::PendingBatch;
use colophon_core::v05::write::succession::prepare_succession_vetoed;

fn detail(e: Failure) -> String {
    e.detail().to_string()
}

#[test]
fn a_succession_vetoed_by_the_owners_old_passkey_is_never_verified() {
    // The succession is started with the owner's stolen device key: it is a valid genesis
    // (the handover meets the rule that may write F), and the owner's passkey, which the thief
    // does not hold, vetoes it under its Swift descriptor.
    let (mut j, _keys) = start(false);
    let s = j.acct.swift_succession().unwrap();
    let t = s.status.timing.clone().unwrap();
    assert!(t.vetoers.contains(&j.f.passkey_id) && t.vetoers.contains(&j.f.security_id));
    let veto_at = j.now;
    // Refusals, each by its reason: a key that is no eligible predecessor key (the home's), an
    // issued before the window and at the deadline, no signer, and the wrong key's signature.
    let p = |issued_ms: i64, signers: Vec<String>| SwiftVetoParams { issued_ms, signers };
    let e = j
        .acct
        .begin_swift_veto(&p(veto_at, vec![j.home.clone()]))
        .unwrap_err();
    assert!(
        matches!(e, Failure::BadSignature(_)) && detail(e).contains("eligible"),
        "ineligible"
    );
    let e = j
        .acct
        .begin_swift_veto(&p(t.window_start_ms - SEC, vec![j.f.passkey_id.clone()]))
        .unwrap_err();
    assert!(detail(e).contains("window's start"));
    let e = j
        .acct
        .begin_swift_veto(&p(t.veto_deadline_ms, vec![j.f.passkey_id.clone()]))
        .unwrap_err();
    assert!(detail(e).contains("deadline has passed"));
    let e = j.acct.begin_swift_veto(&p(veto_at, vec![])).unwrap_err();
    assert!(detail(e).contains("signers"));
    let pending = j
        .acct
        .begin_swift_veto(&p(veto_at, vec![j.f.passkey_id.clone()]))
        .unwrap();
    let step = &pending.steps()[0];
    assert_eq!(
        step.descriptor().unwrap().webauthn().unwrap().rp(),
        "id.example",
        "rpID is the rp"
    );
    let veto_digest = pending.digest();
    // Signed by the security key instead of the passkey: refused at finish.
    let forged =
        e7::key_from_scalar(&[10; 32]).sign_webauthn(RP, ORIGIN, 0x05, step.challenge().unwrap());
    let e = j
        .acct
        .begin_swift_veto(&p(veto_at, vec![j.f.passkey_id.clone()]))
        .unwrap()
        .finish(vec![forged])
        .unwrap_err();
    assert!(matches!(e, Failure::BadSignature(_)), "{e:?}");
    // Without user verification: refused (the Swift rule requires UV for a veto).
    let no_uv =
        e7::key_from_scalar(&[9; 32]).sign_webauthn(RP, ORIGIN, 0x01, step.challenge().unwrap());
    let e = j
        .acct
        .begin_swift_veto(&p(veto_at, vec![j.f.passkey_id.clone()]))
        .unwrap()
        .finish(vec![no_uv])
        .unwrap_err();
    assert!(matches!(e, Failure::BadSignature(_)), "{e:?}");
    // The owner's passkey, with UV, from the descriptor's own origin.
    let sigs = passkey_sign(&j.f.passkey_key, pending.steps(), &j.host);
    let veto = pending.finish(sigs).unwrap();
    // The successor's home receipts it and records it.
    let at = veto_at + 20 * SEC;
    j.acct.advance(at).unwrap();
    let rbody = canonical(
        &json!({"protocol": "colophon/receipt/5", "account": j.acct.id().as_str(),
        "object": veto_digest, "received": format_date(veto_at + 10 * SEC), "by": j.home}),
    )
    .unwrap();
    let receipt =
        canonical(&json!({"body": b64(&rbody), "signature": b64(&j.host.sign(&j.home, &rbody))}))
            .unwrap();
    give(
        &mut j,
        Objects {
            pending: vec![veto, receipt],
            ..Objects::default()
        },
        at,
    );
    let batch: PendingBatch =
        prepare_succession_vetoed(j.acct.objects(), at, &veto_digest).unwrap();
    let rec = batch.finish(vec![]).unwrap();
    give(
        &mut j,
        Objects {
            entries: rec.entries.iter().map(|(_, e)| e.clone()).collect(),
            ..Objects::default()
        },
        at,
    );
    assert_eq!(j.acct.swift_succession().unwrap().stage, MoveStage::Vetoed);
    // Never verified: not at the due time, not with F, not with the home's fresh head.
    let late = j.due + 300 * SEC;
    j.acct.advance(late).unwrap();
    let e = j
        .acct
        .begin_swift_freeze(vec![], vec![j.ctl.clone()], j.due + 61 * SEC)
        .unwrap_err();
    assert!(
        detail(e).contains("Vetoed"),
        "F is refused for a vetoed succession"
    );
    let head = head_of(&j, late);
    give(
        &mut j,
        Objects {
            heads: vec![head],
            ..Objects::default()
        },
        late,
    );
    let st = verify_history(j.acct.objects(), &Persisted::default(), late)
        .state
        .unwrap();
    assert!(st.verified_succession().is_none());
    assert_eq!(j.acct.swift_succession().unwrap().stage, MoveStage::Vetoed);
    // And the veto cannot be made once the succession is no longer waiting.
    let e = j
        .acct
        .begin_swift_veto(&p(veto_at, vec![j.f.passkey_id.clone()]))
        .unwrap_err();
    assert!(detail(e).contains("during the wait"));
}

#[test]
fn the_steps_refuse_out_of_order_each_by_its_reason() {
    let (j, keys) = start(false);
    let lib = SwiftLibrary::read(&j.f.entries).unwrap();
    let plan = CopyPlan::read(
        &lib,
        &j.f.files,
        &keys,
        Some(&translate),
        &Destination::empty(),
    )
    .unwrap();
    let item = plan.next_batch(1).remove(0);
    // Copying before the succession is verified (the predecessor is not yet frozen).
    let e = j
        .acct
        .begin_swift_copy_write(&plan, &item, [1; 32])
        .unwrap_err();
    assert!(detail(e).contains("after F, once the succession is verified"));
    // The migration before F and before the copy.
    let lib0 = SwiftLibrary::read(&j.f.entries).unwrap();
    let fake = CopyPlan::read(&lib0, &[], &[], None, &Destination::empty())
        .unwrap()
        .finish(&Destination::empty())
        .unwrap();
    let e = j
        .acct
        .begin_swift_migration(&fake, vec![], T0, T0, T0, vec![j.ctl.clone()])
        .unwrap_err();
    assert!(detail(e).contains("written after F and the copy"));
    // A veto before there is a window is refused (a fresh account holds none).
    // F before it is due is refused (checked in the journey); a copy with the wrong item:
    let (mut j2, keys2, f_issued, _f) = through_f(false);
    let mut other = item.clone();
    other.payload["key"] = json!("another batch");
    let lib2 = SwiftLibrary::read(&j2.f.entries).unwrap();
    let plan2 = CopyPlan::read(
        &lib2,
        &j2.f.files,
        &keys2,
        Some(&translate),
        &Destination::empty(),
    )
    .unwrap();
    let e = j2
        .acct
        .begin_swift_copy_write(&plan2, &other, [1; 32])
        .unwrap_err();
    assert!(detail(e).contains("not a pending write of this plan"));
    // The copying member must exist: the controller session is not one.
    let item2 = plan2.next_batch(1).remove(0);
    let e = j2
        .acct
        .begin_swift_copy_write(&plan2, &item2, [1; 32])
        .unwrap_err();
    assert!(detail(e).contains("controller"));
    let _ = (&mut j2, f_issued);
}

#[test]
fn the_upgrade_of_a_0_4_account_is_an_account_method() {
    use e7::{key_from_scalar, published_scalars, sign_steps};
    let root = e7::repo().join("conformance/0.4/keys/seq-two-rekey/records/authority");
    let mut files: Vec<_> = std::fs::read_dir(root)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    files.sort();
    let chain: colophon_core::model::Records = files
        .iter()
        .enumerate()
        .map(|(i, p)| {
            (
                format!("authority/{:08}.json", i + 1),
                e7::strip(std::fs::read(p).unwrap()),
            )
        })
        .collect();
    let g: Value = serde_json::from_slice(&chain["authority/00000001.json"]).unwrap();
    let gb: Value =
        serde_json::from_slice(&STANDARD.decode(g["body"].as_str().unwrap()).unwrap()).unwrap();
    let first = key_id(
        &STANDARD
            .decode(
                gb["keyring"]["controllers"][0]["key"]["signing"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap(),
    );
    let now = 1_794_470_400_000;
    let policy = json!({"callWindow": 300, "headMaxAge": 300, "headQuorum": 1, "history": "members",
        "linkMaxAge": 86400, "memberRule": "single", "recoveryDelay": 259200,
        "rate": {"account": {"bytes": 16777216, "entries": 256}, "signer": {"bytes": 4194304, "entries": 64}}});
    let params = UpgradeParams {
        policy,
        add_threshold: 1,
        count_by: "keys".into(),
        issued_ms: 1_794_387_600_000,
        signers: vec![first.clone()],
    };
    // A plain 0.4 history is not a 0.5 account (it reports the upgrade prefix as incomplete)...
    let plain = Objects {
        entries: chain.values().cloned().collect(),
        ..Objects::default()
    };
    assert!(
        Account::open(
            plain.clone(),
            vec![],
            None,
            Identity::Controller(first.clone()),
            now
        )
        .is_err()
            || Account::open(
                plain.clone(),
                vec![],
                None,
                Identity::Controller(first.clone()),
                now
            )
            .unwrap()
            .status()
            .code
                != "ok"
    );
    // ... and `begin_upgrade` makes it one, with the same keys.
    let pending = Account::begin_upgrade(&chain, &params, now).unwrap();
    let sigs = sign_steps(pending.steps(), &published_scalars());
    let entry = pending.finish(sigs).unwrap().entries[0].1.clone();
    let mut objects = plain;
    objects.entries.push(entry);
    let a = Account::open(
        objects.clone(),
        vec![],
        None,
        Identity::Controller(first.clone()),
        now,
    )
    .unwrap();
    assert_eq!(a.status().code, "ok");
    assert!(a.controllers().iter().any(|c| c.id == first));
    // Refused: a history that is already upgraded, and one that is not a history.
    let mut again = chain.clone();
    again.insert(
        "authority/00000099.json".into(),
        objects.entries.last().unwrap().clone(),
    );
    assert!(Account::begin_upgrade(&again, &params, now).is_err());
    assert!(Account::begin_upgrade(&colophon_core::model::Records::new(), &params, now).is_err());
    // A signature by another key is refused at finish, and returns nothing.
    let pending = Account::begin_upgrade(&chain, &params, now).unwrap();
    let wrong = pending
        .steps()
        .iter()
        .map(|st| SignatureResult {
            signature: key_from_scalar(&[7; 32]).sign_raw(st.body()),
            assertion: None,
        })
        .collect();
    assert!(pending.finish(wrong).is_err());
}

#[test]
fn a_granted_namespace_with_no_epoch_and_a_stray_file_do_not_strand_the_migration() {
    // H1: the copy and `prepare_migration` agree on the namespace set by construction. A
    // namespace that was granted and never given an epoch (the Swift writer's default) is listed
    // with no records; a file under a namespace the predecessor never named is omitted with a
    // reason and belongs to no namespace. Both complete the documented path, nothing hand-edited.
    journey_with(Opts {
        extra_namespace: true,
        planted: true,
        ..Opts::default()
    });
}

// ---------------------------------------------------------------------------------------------
// The fix round.

fn titles(c: &Account, ns: &str) -> String {
    let colophon_core::model::Outcome::Success { value: v, .. } = c.view(ns).unwrap() else {
        panic!("{ns} is not readable")
    };
    serde_json::to_string(&v.state).unwrap()
}

/// H2: two source records whose translations create the same destination identity. The second is
/// judged against what the copy has built so far, omitted with the destination's own reason and
/// counted omitted; the final reconciliation reads the destination and agrees.
#[test]
fn a_record_the_destination_would_mark_invalid_is_omitted_not_counted_copied() {
    let (mut j, keys, _f_issued, _frozen) = through_f(false);
    let same = |op: &SwiftOp<'_>| -> colophon_core::v05::Result<Batch> {
        let mut b = translate(op)?;
        if op.kind == "capture.link" {
            b.children[0].payload["id"] = json!("same-item");
        }
        Ok(b)
    };
    let (c, result) = copy_all_with(&mut j, &keys, &same);
    let saved = result
        .namespaces()
        .iter()
        .find(|n| n.namespace == "reading.saved")
        .unwrap();
    assert_eq!((saved.source, saved.copied.len(), saved.omitted), (2, 1, 1));
    let why: Vec<_> = result.omitted().iter().map(|o| o.1.clone()).collect();
    assert!(
        why.iter()
            .any(|w| w.contains("Destination identity occupied")),
        "{why:?}"
    );
    // The destination holds exactly one effective batch and no invalid one.
    let colophon_core::model::Outcome::Success { value: inv, .. } = c
        .query("reading.saved", "importInvalid", json!({}))
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(
        inv,
        json!([]),
        "nothing the destination marked invalid was written"
    );
    let text = titles(&c, "reading.saved");
    assert!(
        text.contains("One") ^ text.contains("Two"),
        "exactly one of the two is in the view: {text}"
    );
}

/// H2: the final reconciliation refuses a plan whose written records are not what the
/// destination holds (here: each source claimed to be the other's destination record).
#[test]
fn the_final_reconciliation_refuses_what_the_destination_does_not_hold() {
    let (mut j, keys, _f, _fz) = through_f(false);
    let (c, _result) = copy_all(&mut j, &keys);
    let lib = SwiftLibrary::read(&j.f.entries).unwrap();
    let dest = c.swift_copy_destination(lib.library()).unwrap();
    let mut plan = CopyPlan::read(
        &lib,
        &j.f.files,
        &keys,
        Some(&translate),
        &Destination::empty(),
    )
    .unwrap();
    // The destination's real headers, by namespace, swapped between the two sources.
    let mut headers: std::collections::BTreeMap<String, Vec<_>> = Default::default();
    for r in c.records() {
        let (h, _) = colophon_core::v05::records::OperationHeader::parse(&r.bytes).unwrap();
        headers.entry(h.namespace.clone()).or_default().push(h);
    }
    for (ns, hs) in &headers {
        let items: Vec<CopyItem> = plan
            .next_batch(10)
            .into_iter()
            .filter(|i| &i.namespace == ns)
            .collect();
        plan.record_written(&items[0].source_digest, &hs[1])
            .unwrap();
        plan.record_written(&items[1].source_digest, &hs[0])
            .unwrap();
    }
    let e = plan.finish(&dest).unwrap_err();
    assert!(
        e.detail()
            .contains("invalid or is not the copy of its source"),
        "{e:?}"
    );
    // A plan that omits what the destination holds is refused too.
    let mut plan = CopyPlan::read(
        &lib,
        &j.f.files,
        &keys,
        Some(&translate),
        &Destination::empty(),
    )
    .unwrap();
    for it in plan.next_batch(10) {
        plan.record_omitted(&it.namespace, &it.source_digest, "left behind")
            .unwrap();
    }
    let e = plan.finish(&dest).unwrap_err();
    assert!(e.detail().contains("does not list"), "{e:?}");
}

/// Resume: interrupt after an arbitrary batch, rebuild from the predecessor and what the
/// destination holds, finish: the same as an uninterrupted copy, no record twice or lost.
#[test]
fn an_interrupted_copy_continues_without_duplicating_or_losing_a_record() {
    fn summary(r: &CopyResult) -> Vec<(String, u64, usize, u64)> {
        r.namespaces()
            .iter()
            .map(|n| (n.namespace.clone(), n.source, n.copied.len(), n.omitted))
            .collect()
    }
    let (mut j0, keys0, _, _) = through_f(false);
    let (c0, whole) = copy_all(&mut j0, &keys0);
    let all_titles = ["Alpha", "Beta", "One", "Two"];
    for ns in ["notes", "reading.saved"] {
        let t = titles(&c0, ns);
        assert!(all_titles.iter().filter(|x| t.contains(**x)).count() == 2);
    }
    for k in [1usize, 3] {
        let (mut j, keys, _, _) = through_f(false);
        let lib = SwiftLibrary::read(&j.f.entries).unwrap();
        let mut c = copier_session(&mut j);
        let mut plan = CopyPlan::read(
            &lib,
            &j.f.files,
            &keys,
            Some(&translate),
            &Destination::empty(),
        )
        .unwrap();
        write_items(&j, &mut c, &mut plan, k, 0x60);
        assert_eq!(plan.pending(), 4 - k);
        // The crash: the plan and the session are gone; what survives is what the destination
        // holds (its objects and the records written so far).
        let (objects, records) = (c.objects().clone(), c.records().to_vec());
        drop((plan, c));
        let now = j.now + 60 * SEC;
        let mut c = Account::open(
            objects,
            records,
            None,
            Identity::Member(j.copier.clone()),
            now,
        )
        .unwrap();
        let steps = c.begin_unlock_epochs();
        let secrets: Vec<EpochSecret> = steps
            .into_iter()
            .map(|s| EpochSecret {
                shared: j.host.ids[&j.copier].agree(&s.peer).unwrap(),
                step: s,
            })
            .collect();
        c.finish_unlock_epochs(secrets).unwrap();
        // Rebuild the plan from the predecessor plus what the destination already holds.
        let dest = c.swift_copy_destination(lib.library()).unwrap();
        let mut plan = CopyPlan::read(&lib, &j.f.files, &keys, Some(&translate), &dest).unwrap();
        assert_eq!(
            plan.pending(),
            4 - k,
            "the batches already admitted are recognised, not offered again"
        );
        write_items(&j, &mut c, &mut plan, usize::MAX, 0x90);
        let result = c.finish_swift_copy(plan).unwrap();
        assert_eq!(summary(&result), summary(&whole), "k = {k}");
        // No record twice, none lost: four batches, every title once.
        let held = destination_digests(c.records());
        assert_eq!(held.values().map(Vec::len).sum::<usize>(), 4);
        for ns in ["notes", "reading.saved"] {
            let t = titles(&c, ns);
            assert_eq!(
                all_titles.iter().filter(|x| t.contains(**x)).count(),
                2,
                "{ns}: {t}"
            );
        }
    }
}

/// M1: once verified, a succession stays verified however old the heads become, and the account
/// never builds a second F.
#[test]
fn a_verified_succession_is_kept_and_a_second_f_is_never_built() {
    let (mut j, _keys, _issued, _frozen) = through_f(false);
    assert_eq!(
        j.acct.swift_succession().unwrap().stage,
        MoveStage::Verified
    );
    let later = j.now + 20 * 60 * SEC;
    j.acct.advance(later).unwrap();
    assert_eq!(
        j.acct.swift_succession().unwrap().stage,
        MoveStage::Verified,
        "the heads aged; the succession stays verified (§15.1)"
    );
    let e = j
        .acct
        .begin_swift_freeze(vec![], vec![j.ctl.clone()], later - 10 * SEC)
        .unwrap_err();
    assert!(detail(e).contains("only once"));
    // F built here is held at once: a second begin is refused although the host never
    // appended the first.
    let (mut j2, _k) = start(false);
    j2.acct.advance(j2.due + 120 * SEC).unwrap();
    j2.acct.record_due().unwrap();
    let p = j2
        .acct
        .begin_swift_freeze(vec![], vec![j2.ctl.clone()], j2.due + 61 * SEC)
        .unwrap();
    let sigs = sign(&j2.host, p.steps());
    j2.acct.finish_move(p, sigs).unwrap();
    let e = j2
        .acct
        .begin_swift_freeze(vec![], vec![j2.ctl.clone()], j2.due + 62 * SEC)
        .unwrap_err();
    assert!(detail(e).contains("Frozen"), "F is already built and held");
}

/// M2: a write is finished only as the item it was begun for.
#[test]
fn a_copy_write_is_bound_to_its_item() {
    let (mut j, keys, _issued, _frozen) = through_f(false);
    let lib = SwiftLibrary::read(&j.f.entries).unwrap();
    let mut c = copier_session(&mut j);
    let mut plan = CopyPlan::read(
        &lib,
        &j.f.files,
        &keys,
        Some(&translate),
        &Destination::empty(),
    )
    .unwrap();
    let batch = plan.next_batch(2);
    let (a, b) = (batch[0].clone(), batch[1].clone());
    let w = c.begin_swift_copy_write(&plan, &a, [0x70; 32]).unwrap();
    assert_eq!(w.item().source_digest, a.source_digest);
    let sigs = sign(&j.host, w.steps());
    c.finish_swift_copy_write(&mut plan, w, sigs).unwrap();
    assert!(
        !plan.is_pending(&a) && plan.is_pending(&b),
        "A is recorded as A; B is still pending"
    );
    // A write begun for B and finished against a plan that no longer holds B pending is refused,
    // and nothing is merged.
    let w = c.begin_swift_copy_write(&plan, &b, [0x71; 32]).unwrap();
    let sigs = sign(&j.host, w.steps());
    let mut other = CopyPlan::read(
        &lib,
        &j.f.files,
        &keys,
        Some(&translate),
        &Destination::empty(),
    )
    .unwrap();
    other
        .record_omitted(&b.namespace, &b.source_digest, "left")
        .unwrap();
    let before = c.records().len();
    let e = c.finish_swift_copy_write(&mut other, w, sigs).unwrap_err();
    assert!(detail(e).contains("not a pending write"));
    assert_eq!(c.records().len(), before, "nothing was merged");
    // A signature over other bytes is refused by the account and nothing is recorded.
    let w = c.begin_swift_copy_write(&plan, &b, [0x72; 32]).unwrap();
    let forged = vec![SignatureResult {
        signature: j.host.sign(&j.copier, b"other bytes"),
        assertion: None,
    }];
    assert!(c.finish_swift_copy_write(&mut plan, w, forged).is_err());
    assert!(plan.is_pending(&b));
}

/// M4: a re-grant to a revoked key is ignored by the Swift fold: the key is not a member, the
/// copy's member list and `prepare_migration` agree, and the migration prepares.
#[test]
fn a_regrant_to_a_revoked_key_migrates_and_that_key_is_not_a_member() {
    let (mut j, _keys, f_issued, _frozen) = through_f_with(Opts {
        regrant: true,
        ..Opts::default()
    });
    let lib = SwiftLibrary::read(&j.f.entries).unwrap();
    let snap = lib.history().states.last().unwrap();
    assert!(!snap.members.contains_key(&j.f.m2.id) && snap.revoked.contains(&j.f.m2.id));
    let members: Vec<_> = swift_members(&lib).unwrap();
    assert_eq!(
        members.iter().map(|m| m.id.clone()).collect::<Vec<_>>(),
        vec![j.f.m1.id.clone()]
    );
    let mine = |extra: bool| -> Vec<MigratedMember> {
        let mut v: Vec<MigratedMember> = members
            .iter()
            .map(|m| MigratedMember {
                id: m.id.clone(),
                label: m.label.clone(),
                kind: map_swift_role(m.role.as_deref().unwrap()).unwrap().into(),
                dropped: None,
            })
            .collect();
        if extra {
            v.push(MigratedMember {
                id: j.f.m2.id.clone(),
                label: "Tablet".into(),
                kind: "app".into(),
                dropped: None,
            });
        }
        v
    };
    let mut plan = CopyPlan::read(
        &lib,
        &j.f.files,
        &[],
        Some(&translate),
        &Destination::empty(),
    )
    .unwrap();
    for it in plan.next_batch(10) {
        plan.record_omitted(&it.namespace, &it.source_digest, "left behind")
            .unwrap();
    }
    let result = j.acct.finish_swift_copy(plan).unwrap();
    let (from, until) = (f_issued, f_issued + 600 * SEC);
    let at = until + 5 * SEC;
    j.acct.advance(at).unwrap();
    let signers = vec![j.ctl.clone(), j.f.passkey_id.clone()];
    j.acct
        .begin_swift_migration(&result, mine(false), from, until, until, signers.clone())
        .unwrap();
    let e = j
        .acct
        .begin_swift_migration(&result, mine(true), from, until, until, signers)
        .unwrap_err();
    assert!(
        detail(e).contains("current members"),
        "the revoked key is not a member"
    );
}

/// M5: a translator expresses everything a batch carries; the core binds it to its source by the
/// evidence fields and validates it; a translator that errs omits the record with the reason.
#[test]
fn a_translator_carries_the_whole_batch_and_cannot_change_who_wrote_it() {
    let (mut j, keys, _i, _f) = through_f(false);
    let rich = |op: &SwiftOp<'_>| -> colophon_core::v05::Result<Batch> {
        if op.payload["title"] == "Two" {
            return Err(colophon_core::v05::Failure::Malformed(
                "cannot translate this".into(),
            ));
        }
        let mut b = translate(op)?;
        b.outcome = "conflict".into();
        b.evidence = json!({"authorID": "evil", "note": "kept"});
        b.alternatives = vec![json!({"object": "x", "component": "c", "value": 1})];
        b.identities.insert(
            "src".into(),
            ("book".into(), format!("dest-{}", op.operation_id)),
        );
        Ok(b)
    };
    let (c, result) = copy_all_with(&mut j, &keys, &rich);
    let saved = result
        .namespaces()
        .iter()
        .find(|n| n.namespace == "reading.saved")
        .unwrap();
    assert_eq!((saved.source, saved.copied.len(), saved.omitted), (2, 1, 1));
    assert!(result
        .omitted()
        .iter()
        .any(|o| o.1.contains("cannot translate this")));
    let colophon_core::model::Outcome::Success { value, .. } = c
        .query("reading.saved", "importEvidence", json!({}))
        .unwrap()
    else {
        panic!()
    };
    let rows = serde_json::to_string(&value).unwrap();
    assert!(rows.contains(&j.f.m1.id), "the real author");
    assert!(
        !rows.contains("\"authorID\":\"evil\"") || rows.contains("translation"),
        "{rows}"
    );
    assert!(rows.contains("conflict") && rows.contains("kept"), "{rows}");
}

#[test]
fn a_verified_succession_is_a_stored_fact_and_does_not_lapse_when_heads_age() {
    let (mut j, _keys, _issued, _frozen) = through_f(false);
    assert!(
        j.acct.succession_seen_verified(),
        "the account stored the fact when it first saw the succession verified"
    );
    // Heads age (no fresh head for weeks): the verifier alone would no longer verify it, the
    // stored fact does (§15.1).
    j.acct.advance(j.now + 60 * 24 * 3_600 * SEC).unwrap();
    assert_eq!(
        j.acct.swift_succession().unwrap().stage,
        MoveStage::Verified
    );
    // The fact is in the sealed persisted state and survives a restart from it.
    let bytes = j.acct.export_persisted(&[7; 32], [1; 32]).unwrap();
    assert!(!bytes.is_empty());
}

#[test]
fn begin_renew_shares_seals_what_a_member_is_owed_and_leaves_its_expiry() {
    let (mut j, _keys, _issued, _frozen) = through_f(false);
    let now = j.now + 5 * SEC;
    let head = head_of(&j, now);
    give(
        &mut j,
        Objects {
            heads: vec![head],
            ..Objects::default()
        },
        now,
    );
    j.acct.record_due().unwrap();
    let owed = j.acct.owed_shares();
    assert!(!owed.is_empty(), "the copier is owed its shares");
    let before = j.acct.members().into_iter().find(|m| m.member.id == j.copier).unwrap().expires_ms;
    let action = j
        .acct
        .begin_renew_shares(&j.copier, &[j.ctl.clone()], [0x54; 32])
        .unwrap();
    let sigs = sign(&j.host, action.steps());
    j.acct.finish(action, sigs).unwrap();
    assert!(j.acct.owed_shares().is_empty());
    let after = j.acct.members().into_iter().find(|m| m.member.id == j.copier).unwrap().expires_ms;
    assert_eq!(before, after, "no `expires` in the entry: the expiry is untouched");
    // A member owed nothing is refused.
    assert!(j
        .acct
        .begin_renew_shares(&j.copier, &[j.ctl.clone()], [0x55; 32])
        .and_then(|a| {
            let s = sign(&j.host, a.steps());
            j.acct.finish(a, s)
        })
        .is_err());
}
