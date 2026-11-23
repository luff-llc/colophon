//! Two journeys through the typed 0.5 exports, with a host written the way an app writes one:
//! it holds the keys, signs what the exports show it, implements the record source callback and
//! performs the exchange against a simulated home from the values the engine emits.
//!
//! 1. Create an account with a passkey-like controller and a device key, unlock, approve a
//!    member, write and read, run the pairing ceremony for a second device, and sync two engines
//!    through an in-memory home.
//! 2. Upgrade a 0.4 library in place, read its old records, write a new one.
//!
//! Both use only the exports: the home is appointed and its activation recorded through the
//! engine, and the second device receives the seed by pairing and seed transfer.
#![allow(clippy::unwrap_used, clippy::too_many_arguments)]
mod v05_support;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
use std::sync::Arc;
use v05_support::*;

const NOW: i64 = T0 + 3 * HOUR;

fn drive_creation(creation: &AccountCreation, host: &Host) {
    let reqs = creation.prf_requests().unwrap();
    if !reqs.is_empty() {
        assert_eq!(creation.stage().unwrap(), CreateStage::Prf);
        creation.provide_prf(host.answer_prf(&reqs)).unwrap();
    }
    loop {
        assert_eq!(
            creation.stage().unwrap(),
            if creation.stage().unwrap() == CreateStage::Rekey {
                CreateStage::Rekey
            } else {
                CreateStage::Genesis
            }
        );
        let steps = creation.steps().unwrap();
        if creation.provide_signatures(host.sign(&steps)).unwrap() == CreateStage::Done {
            break;
        }
    }
}
fn request(
    host: &Host,
    account: &str,
    member: &str,
    label: &str,
    kind: AccountMemberKind,
    terms: Value,
    endpoints: Vec<String>,
) -> RequestInfo {
    let p = host.keys[member].public();
    let req = AccountRequest::prepare(RequestSpec {
        account: account.into(),
        signing: p.signing,
        agreement: p.agreement,
        label: label.into(),
        kind,
        terms_json: terms.to_string(),
        created: account_format_date(NOW - 2 * HOUR).unwrap(),
        custody: None,
        operator: None,
        endpoints,
    })
    .unwrap();
    let step = req.step().unwrap();
    req.finish(host.sign_one(&step.body, member, false))
        .unwrap()
}
fn open_engine(src: &MemSource, identity: &str, account: &str) -> Arc<AccountEngine> {
    AccountEngine::open(
        Box::new(src.clone()),
        src.listing(),
        ident(identity),
        account.into(),
        vec![],
        0,
        SavedState {
            verifier: vec![],
            checkpoint: vec![],
            parts: vec![],
        },
        DEVICE_KEY.to_vec(),
        NOW,
    )
    .unwrap()
}
fn unlock_slot(engine: &AccountEngine, host: &Host, controller: &str) {
    let slot = engine
        .slots()
        .unwrap()
        .into_iter()
        .find(|o| o.controllers.len() == 1 && o.controllers[0].id == controller)
        .unwrap();
    let inputs = engine.begin_unlock_slot(slot.index).unwrap();
    engine
        .finish_unlock_slot(slot.index, host.answer_slot(&inputs))
        .unwrap();
}
fn unlock_member(engine: &AccountEngine, host: &Host, m: &str) {
    engine
        .finish_unlock_epochs(host.answer_epochs(m, &engine.begin_unlock_epochs().unwrap()))
        .unwrap();
}
fn finish(engine: &Arc<AccountEngine>, host: &Host, action: Arc<AccountAction>) -> Written {
    assert!(action.denial().unwrap().is_none());
    let prf = action.prf_requests().unwrap();
    if !prf.is_empty() {
        engine
            .provide_prf(action.clone(), host.answer_prf(&prf))
            .unwrap();
    }
    let sigs = host.sign(&action.steps().unwrap());
    engine.finish(action, sigs).unwrap()
}
fn notes(engine: &AccountEngine) -> Vec<Value> {
    let v: Value = serde_json::from_str(&engine.view_json("notes".into()).unwrap()).unwrap();
    assert_eq!(v["ok"], true, "{v}");
    v["value"]["admitted"].as_array().unwrap().clone()
}
fn create_params(host: &Host, ids: &[&str; 3], policy: Option<String>) -> CreateParams {
    let [d, p, k] = ids;
    CreateParams {
        label: "Test account".into(),
        namespaces: vec!["notes".into()],
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
        policy_json: policy.unwrap_or_default(),
        signers: vec![d.to_string()],
        rekey_signers: vec![d.to_string()],
    }
}

#[test]
fn a_control_owner_publishes_a_slot_from_the_passkeys_possession_assertion() {
    let mut host = Host::new();
    let owner_id = host.identity(10);
    let passkey_id = host.passkey();
    let signers = vec![owner_id.clone()];
    let creation = AccountCreation::begin(
        CreateParams {
            label: "Test account".into(),
            namespaces: vec!["notes".into()],
            controllers: vec![host.raw_controller(
                &owner_id,
                "Owner",
                &["approve", "control", "recover"],
            )],
            slots: vec![SlotPlan {
                controllers: signers.clone(),
                label: "Owner".into(),
            }],
            threshold: None,
            recover_threshold: None,
            add_threshold: None,
            count_by_holders: false,
            policy_json: String::new(),
            signers: signers.clone(),
            rekey_signers: signers.clone(),
        },
        ident(&format!("controller:{owner_id}")),
        T0,
        host.fresh(96),
    )
    .unwrap();
    drive_creation(&creation, &host);
    let created = creation.take_result().unwrap();
    let mut stores = created.stores;
    let src = MemSource::new();
    src.store(&stores);
    let owner = open_engine(&src, &format!("controller:{owner_id}"), &created.account);
    unlock_slot(&owner, &host, &owner_id);
    let passkey = host.passkey_controller("Passkey", &["control", "recover"]);
    let transition = owner
        .begin_add_controller(
            passkey,
            AddMode::Transition,
            signers.clone(),
            RuleKind::Control,
            vec![],
        )
        .unwrap();
    let steps = transition.steps().unwrap();
    assert_eq!(steps[1].role, StepRole::Possession);
    assert_eq!(steps[1].signer, passkey_id);
    let salt = host.fresh(32);
    let challenge = URL_SAFE_NO_PAD
        .decode(steps[1].challenge.as_ref().unwrap())
        .unwrap();
    let signatures = host.sign(&steps);
    let answer = PrfAnswer {
        authenticator_data: signatures[1].authenticator_data.clone().unwrap(),
        client_data: signatures[1].client_data.clone().unwrap(),
        signature: signatures[1].signature.clone(),
        output: host.prf(&salt),
    };
    let written = owner.finish(transition, signatures).unwrap();
    src.store(&written.stores);
    stores.extend(written.stores);
    let due = owner.record_due().unwrap();
    assert_eq!(due.len(), 1);
    src.store(&due[0].stores);
    stores.extend(due.into_iter().flat_map(|written| written.stores));

    let plan = SlotPlan {
        controllers: vec![passkey_id.clone()],
        label: "Passkey".into(),
    };
    let slot = owner
        .begin_add_slot_with_signers(
            signers,
            plan,
            Some(salt.clone()),
            Some(challenge.clone()),
            host.fresh(32),
        )
        .unwrap();
    let requests = slot.prf_requests().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].salt, salt);
    assert_eq!(requests[0].challenge, challenge);
    owner.provide_prf(slot.clone(), vec![answer]).unwrap();
    let steps = slot.steps().unwrap();
    assert_eq!(steps.len(), 1);
    assert_eq!(steps[0].signer, owner_id);
    assert_eq!(steps[0].form, SignForm::Raw);
    let written = owner.finish(slot, host.sign(&steps)).unwrap();
    src.store(&written.stores);
    stores.extend(written.stores);
    let (objects, _) = objects_of(&stores);
    let report = account_verify_history(authority_objects(&objects), NOW).unwrap();
    assert_eq!(report.code, "ok");
    let reopened = open_engine(&src, &format!("controller:{passkey_id}"), &created.account);
    assert!(!reopened.is_unlocked().unwrap());
    unlock_slot(&reopened, &host, &passkey_id);
    assert!(reopened.is_unlocked().unwrap());
}

#[test]
fn journey_one_create_approve_write_pair_and_sync_two_engines() {
    let mut host = Host::new();
    let d = host.identity(10);
    let k = host.kit(20);
    let p = host.passkey();
    let d2 = host.identity(11);
    let m1 = host.identity(31);
    let home = host.identity(70);

    // --- Create: a device key, a passkey and a kit; four slots (sealed x2, prf, combined).
    let mut policy: Value = serde_json::from_str(&account_default_policy().unwrap()).unwrap();
    policy["recoveryDelay"] = json!(3600);
    let params = create_params(&host, &[&d, &p, &k], Some(policy.to_string()));
    let creation = AccountCreation::begin(
        params,
        ident(&format!("controller:{d}")),
        T0,
        host.fresh(96),
    )
    .unwrap();
    assert_eq!(creation.stage().unwrap(), CreateStage::Prf);
    assert_eq!(
        creation.prf_requests().unwrap().len(),
        2,
        "a prf slot and a combined slot"
    );
    drive_creation(&creation, &host);
    let created = creation.take_result().unwrap();
    assert!(creation.take_result().is_err(), "a creation is one-shot");
    assert_eq!(created.account.len(), 64);
    let account = created.account.clone();
    let (objs, _) = objects_of(&created.stores);
    let report = account_verify_history(authority_objects(&objs), NOW).unwrap();
    assert_eq!(
        (report.code.as_str(), report.account.as_deref()),
        ("ok", Some(account.as_str()))
    );

    let auth = MemSource::new();
    auth.store(&created.stores);

    // --- The controller's engine appoints a home, records its activation, approves a member
    // who may write notes, and adds the laptop as a controller.
    let ctl = open_engine(&auth, &format!("controller:{d}"), &account);
    assert!(!ctl.is_unlocked().unwrap());
    unlock_slot(&ctl, &host, &d);
    assert!(ctl.is_unlocked().unwrap());
    assert_eq!(ctl.status().unwrap().code, "ok");
    let home_req = request(
        &host,
        &account,
        &home,
        "Home",
        AccountMemberKind::Server,
        json!({"serves": ["home"]}),
        vec!["https://home.example/".into()],
    );
    let change = json!({"homes": {"appoint": [{"request": colophon_core::v05::encoding::encode_base64(&home_req.raw), "terms": {"serves": ["home"]}}]}});
    let a = ctl
        .begin_transition(
            change.to_string(),
            vec![d.clone(), k.clone()],
            RuleKind::Control,
            vec![],
        )
        .unwrap();
    auth.store(&finish(&ctl, &host, a).stores);
    let due = ctl.record_due().unwrap();
    assert_eq!(due.len(), 1, "the activation is recorded");
    auth.store(&due[0].stores);
    assert_eq!(ctl.homes().unwrap().len(), 1);
    assert_eq!(ctl.controllers().unwrap().len(), 3);
    let terms = json!({"records": [{"namespace": "notes", "access": "write"}]});
    let r1 = request(
        &host,
        &account,
        &m1,
        "Phone",
        AccountMemberKind::Device,
        terms.clone(),
        vec![],
    );
    assert_eq!(r1.kind, AccountMemberKind::Device);
    let approve = ctl
        .begin_approve(r1.raw.clone(), terms.to_string(), vec![d.clone()], scanned(&ctl, &r1.raw, NOW), host.fresh(32))
        .unwrap();
    assert_eq!(approve.kind().unwrap(), ActionKind::Approve);
    let w = finish(&ctl, &host, approve);
    assert!(!w.stores.is_empty() && w.changes.members_added.len() == 1);
    auth.store(&w.stores);
    assert!(ctl
        .members()
        .unwrap()
        .iter()
        .any(|m| m.label == "Phone" && !m.provisional));
    assert_eq!(ctl.me().unwrap().kind, StandingKind::Controller);
    let laptop = host.raw_controller(&d2, "Laptop", &["approve"]);
    let a = ctl
        .begin_add_controller(
            laptop,
            AddMode::Immediate,
            vec![d.clone()],
            RuleKind::Control,
            vec![],
        )
        .unwrap();
    auth.store(&finish(&ctl, &host, a).stores);

    // --- The second device: the pairing ceremony, then the seed travels sealed to it.
    let sb = auth.copy_of();
    let eb = open_engine(&sb, &format!("controller:{d2}"), &account);
    assert!(!eb.is_unlocked().unwrap());
    let tk = PairingTransferKey::create(host.fresh(32)).unwrap();
    let joiner = AccountPairing::join(account.clone(), tk.public(), host.fresh(32)).unwrap();
    assert_eq!(joiner.stage().unwrap(), PairingStage::Joiner);
    let limiter = PairingFailureLimiter::fresh();
    let existing = AccountPairing::existing_receive_commitment(
        account.clone(),
        joiner.commitment().unwrap(),
        limiter.clone(),
        NOW,
    )
    .unwrap();
    // The ledger is sealed (persisted, in an app) before the nonce leaves (§7.3).
    limiter.seal(DEVICE_KEY.to_vec(), account.clone(), host.fresh(32)).unwrap();
    let na = existing.send_nonce(host.fresh(32)).unwrap();
    let reveal = joiner.receive_nonce(na).unwrap().unwrap();
    let shown = existing
        .receive_reveal(reveal.e, reveal.nb, limiter.clone(), NOW)
        .unwrap();
    assert_eq!(
        shown,
        joiner.digits().unwrap(),
        "both screens show one code"
    );
    existing.confirm().unwrap();
    joiner.confirm().unwrap();
    assert!(existing.confirm().is_err(), "a step consumes its state");
    assert_eq!(
        existing.stage().unwrap(),
        PairingStage::Confirmed,
        "a wrong-stage call consumes nothing"
    );
    assert!(limiter.may_start(NOW).unwrap(), "the confirmed ceremony gave its reservation back");
    let sealed = ctl.transfer_seed(existing.clone(), host.fresh(32)).unwrap();
    // A seed sealed to another pairing's key is refused.
    let other = PairingTransferKey::create(host.fresh(32)).unwrap();
    assert!(eb
        .accept_seed_transfer(
            other,
            joiner.clone(),
            SealedSeed {
                enc: sealed.enc.clone(),
                ciphertext: sealed.ciphertext.clone()
            }
        )
        .is_err());
    assert!(!eb.is_unlocked().unwrap());
    eb.accept_seed_transfer(tk, joiner, sealed).unwrap();
    eb.load().unwrap();
    assert!(eb.is_unlocked().unwrap(), "the new device holds the seed");
    // It builds its own slot, so it unlocks without its peer from now on.
    let a = eb
        .begin_add_slot(
            d2.clone(),
            SlotPlan {
                controllers: vec![d2.clone()],
                label: "Laptop".into(),
            },
            host.fresh(32),
        )
        .unwrap();
    let w = finish(&eb, &host, a);
    sb.store(&w.stores);
    auth.store(&w.stores);
    let eb = open_engine(&sb, &format!("controller:{d2}"), &account);
    unlock_slot(&eb, &host, &d2);

    // --- Engines over host stores: the member writes, the second device reads after a sync.
    let sa = auth.copy_of();
    let ea = open_engine(&sa, &format!("member:{m1}"), &account);
    unlock_member(&ea, &host, &m1);
    assert!(
        ea.access("notes".into()).unwrap().is_none(),
        "the member may read notes now"
    );
    for (kind, payload) in [
        ("createNotebook", json!({"id": "n", "title": "Journey"})),
        (
            "addNote",
            json!({"id": "n1", "notebook": "n", "text": "hello"}),
        ),
    ] {
        let a = ea
            .begin_write(
                "notes".into(),
                kind.into(),
                payload.to_string(),
                host.fresh(32),
            )
            .unwrap();
        let w = finish(&ea, &host, a);
        sa.store(&w.stores);
    }
    assert_eq!(notes(&ea).len(), 2);
    let before = ea.revision("notes".into()).unwrap();
    assert!(
        before > 0
            && ea
                .revisions()
                .unwrap()
                .iter()
                .any(|r| r.namespace == "notes" && r.revision == before)
    );
    let q: Value = serde_json::from_str(
        &ea.query_json(
            "notes".into(),
            "notes".into(),
            json!({"notebook": "n"}).to_string(),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(q["ok"], true, "{q}");
    let hist: Value =
        serde_json::from_str(&ea.history_json("notes".into(), 0, 10).unwrap()).unwrap();
    assert_eq!(hist["value"]["items"].as_array().unwrap().len(), 2);
    assert!(ea.stats().unwrap().signatures_verified > 0);

    assert_eq!(notes(&eb).len(), 0, "nothing synced yet");

    let (o, _) = objects_of(
        &auth
            .files
            .lock()
            .unwrap()
            .iter()
            .map(|(p, b)| Store {
                path: p.clone(),
                bytes: b.clone(),
            })
            .collect::<Vec<_>>(),
    );
    let home_id = eb.homes().unwrap()[0].id.clone();
    assert_eq!(home_id, home);
    let mut sim = SimHome::new(&account, &home_id, "https://home.example", &o, NOW);
    let f1 = sync_pass(&ea, &sa, &home_id, &mut sim, &host, NOW);
    assert!(
        f1.is_empty(),
        "an honest home raises no fault: {}",
        f1.len()
    );
    assert!(
        sim.files.keys().any(|p| p.starts_with("ops/")),
        "the home holds the member's records"
    );
    let f2 = sync_pass(&eb, &sb, &home_id, &mut sim, &host, NOW);
    assert!(f2.is_empty());
    assert_eq!(
        notes(&eb).len(),
        2,
        "the second device reads what the first wrote"
    );
    assert_eq!(notes(&ea), notes(&eb));

    // --- The rest of the session: read scope, batched versions, faults, abort, lock.
    assert!(eb.set_read_scope(vec!["notes".into()]).is_ok());
    assert_eq!(notes(&eb).len(), 2, "still readable in scope");
    assert!(eb.source_faults().unwrap().is_empty());
    let want = eb.version_paths(vec!["ops/x".into()]).unwrap();
    assert!(
        want.contains(&"ops/x".to_string()) && want.iter().any(|p| p.starts_with("authority/"))
    );
    let aborted = eb.exchange_abort(home_id.clone()).unwrap();
    assert!(aborted.faults.is_empty());
    assert!(!ea.is_locked().unwrap());
    let locked = ea.lock().unwrap();
    assert!(ea.is_locked().unwrap());
    let _ = locked;
    let v: Value = serde_json::from_str(
        &ea.view_json("notes".into())
            .unwrap_or_else(|_| "{\"ok\":false}".into()),
    )
    .unwrap();
    assert_eq!(
        v["ok"], false,
        "a locked engine shows no record content: {v}"
    );
    assert!(
        ea.save(host.fresh(32)).is_err(),
        "a locked engine cannot save"
    );
    assert!(
        ea.finish_unlock_epochs(host.answer_epochs(&m1, &[]))
            .is_err(),
        "a locked engine does not unlock again"
    );

    // --- Saved state resumes: a sealed checkpoint, then a cheap open.
    let ea = open_engine(&sa, &format!("member:{m1}"), &account);
    unlock_member(&ea, &host, &m1);
    let saved = ea.save(host.fresh(32)).unwrap();
    assert!(!saved.verifier.is_empty() && !saved.parts.is_empty());
    assert!(
        !saved.verifier.windows(32).any(|w| w == DEVICE_KEY),
        "the key is not in what it seals"
    );
    let resumed = AccountEngine::open(
        Box::new(sa.clone()),
        sa.listing(),
        ident(&format!("member:{m1}")),
        account.clone(),
        vec![],
        0,
        saved,
        DEVICE_KEY.to_vec(),
        NOW,
    )
    .unwrap();
    assert_eq!(resumed.open_info().unwrap().mode, OpenMode::Resumed);
    unlock_member(&resumed, &host, &m1);
    assert_eq!(notes(&resumed).len(), 2);
    let wrong = AccountEngine::open(
        Box::new(sa.clone()),
        sa.listing(),
        ident(&format!("member:{m1}")),
        account.clone(),
        vec![],
        0,
        ea.save(host.fresh(32)).unwrap(),
        vec![9; 32],
        NOW,
    )
    .unwrap();
    let info = wrong.open_info().unwrap();
    assert!(matches!(info.mode, OpenMode::Invalidated | OpenMode::Cold));
}

#[test]
fn a_prepared_action_cannot_be_altered_replayed_or_finished_elsewhere() {
    let mut host = Host::new();
    let d = host.identity(10);
    let k = host.kit(20);
    let params = CreateParams {
        label: "A".into(),
        namespaces: vec!["notes".into()],
        controllers: vec![
            host.raw_controller(&d, "Mac", &["approve", "control"]),
            host.raw_controller(&k, "Kit", &["recover"]),
        ],
        slots: vec![
            SlotPlan {
                controllers: vec![d.clone()],
                label: "Mac".into(),
            },
            SlotPlan {
                controllers: vec![k.clone()],
                label: "Kit".into(),
            },
        ],
        threshold: None,
        recover_threshold: None,
        add_threshold: None,
        count_by_holders: false,
        policy_json: String::new(),
        signers: vec![d.clone()],
        rekey_signers: vec![d.clone()],
    };
    let creation = AccountCreation::begin(
        params,
        ident(&format!("controller:{d}")),
        T0,
        host.fresh(96),
    )
    .unwrap();
    drive_creation(&creation, &host);
    let created = creation.take_result().unwrap();
    let src = MemSource::new();
    src.store(&created.stores);
    let engine = open_engine(&src, &format!("controller:{d}"), &created.account);
    unlock_slot(&engine, &host, &d);
    let m = host.identity(31);
    let terms = json!({"records": [{"namespace": "notes", "access": "read"}]});
    let r = request(
        &host,
        &created.account,
        &m,
        "App",
        AccountMemberKind::App,
        terms.clone(),
        vec![],
    );
    let begin = |e: &Arc<AccountEngine>, host: &mut Host, raw: &Vec<u8>| {
        e.begin_approve(
            raw.clone(),
            terms.to_string(),
            vec![d.clone()],
            scanned(e, raw, NOW),
            host.fresh(32),
        )
    };
    // Wrong entropy length is a typed bound error, before anything is built.
    assert!(matches!(
        engine.begin_approve(
            r.raw.clone(),
            terms.to_string(),
            vec![d.clone()],
            scanned(&engine, &r.raw, NOW),
            vec![1; 31]
        ),
        Err(AccountError::Bound { .. })
    ));
    let a = begin(&engine, &mut host, &r.raw).unwrap();
    // The host gets copies of what to sign; it cannot hand anything but signatures back.
    let mut sigs = host.sign(&a.steps().unwrap());
    sigs[0].signature[5] ^= 1;
    let revision_before = engine.revisions().unwrap();
    let err = engine.finish(a.clone(), sigs).err().unwrap();
    assert!(matches!(err, AccountError::BadSignature { .. }), "{err:?}");
    assert_eq!(err.code(), "badSignature");
    assert_eq!(
        engine.revisions().unwrap().len(),
        revision_before.len(),
        "a failed finish changes nothing"
    );
    assert!(!engine.members().unwrap().iter().any(|x| x.label == "App"));
    let good = host.sign(&a.steps().unwrap());
    assert!(
        matches!(engine.finish(a, good), Err(AccountError::Consumed { .. })),
        "a failed finish consumes the action"
    );
    // An action finished on another session is refused and not consumed.
    let b = begin(&engine, &mut host, &r.raw).unwrap();
    let other = open_engine(&src, &format!("controller:{d}"), &created.account);
    unlock_slot(&other, &host, &d);
    let g = host.sign(&b.steps().unwrap());
    assert!(matches!(
        other.finish(b.clone(), host.sign(&b.steps().unwrap())),
        Err(AccountError::WrongObject { .. })
    ));
    let done = engine.finish(b, g).unwrap();
    assert!(!done.stores.is_empty());
    // Hostile arguments are typed errors, never panics.
    assert!(matches!(
        engine.begin_approve(vec![1, 2], "not json".into(), vec![], scanned(&engine, &r.raw, NOW), host.fresh(32)),
        Err(AccountError::Malformed { .. }) | Err(AccountError::Unavailable { .. })
    ));
    assert!(engine
        .begin_approve(
            vec![1, 2],
            terms.to_string(),
            vec![d.clone()],
            scanned(&engine, &r.raw, NOW),
            host.fresh(32)
        )
        .is_err());
    assert!(matches!(
        engine.begin_rekey(vec!["x".into(); 300], vec![], host.fresh(32)),
        Err(AccountError::Bound { .. })
    ));
    assert!(matches!(
        account_key_id(vec![0; 1000]),
        Err(AccountError::Bound { .. })
    ));
    assert!(matches!(
        AccountEngine::open(
            Box::new(src.clone()),
            src.listing(),
            AccountIdentity {
                kind: AccountIdentityKind::Controller,
                id: "nobody".into(),
            },
            created.account.clone(),
            vec![],
            0,
            SavedState {
                verifier: vec![],
                checkpoint: vec![],
                parts: vec![]
            },
            DEVICE_KEY.to_vec(),
            NOW
        ),
        Err(AccountError::Malformed { .. })
    ));
    // The history verifier reports a verdict for any objects.
    let report = account_verify_history(
        AuthorityObjects {
            entries: vec![],
            pending: vec![],
            heads: vec![],
            predecessor: vec![],
        },
        T0,
    )
    .unwrap();
    assert!(
        report.account.is_none() && report.seq == 0,
        "an empty history has no account"
    );
}

#[test]
fn a_hostile_record_source_gets_typed_errors_not_panics_deadlocks_or_wrong_blame() {
    let mut host = Host::new();
    let d = host.identity(10);
    let params = CreateParams {
        label: "A".into(),
        namespaces: vec!["notes".into()],
        controllers: vec![host.raw_controller(&d, "Mac", &["approve", "control"])],
        slots: vec![SlotPlan {
            controllers: vec![d.clone()],
            label: "Mac".into(),
        }],
        threshold: None,
        recover_threshold: None,
        add_threshold: None,
        count_by_holders: false,
        policy_json: String::new(),
        signers: vec![d.clone()],
        rekey_signers: vec![d.clone()],
    };
    let creation = AccountCreation::begin(
        params,
        ident(&format!("controller:{d}")),
        T0,
        host.fresh(96),
    )
    .unwrap();
    drive_creation(&creation, &host);
    let created = creation.take_result().unwrap();
    let account = created.account.clone();
    let src = MemSource::new();
    src.store(&created.stores);
    let open = |s: &MemSource| {
        AccountEngine::open(
            Box::new(s.clone()),
            s.listing(),
            ident(&format!("controller:{d}")),
            account.clone(),
            vec![],
            0,
            SavedState {
                verifier: vec![],
                checkpoint: vec![],
                parts: vec![],
            },
            DEVICE_KEY.to_vec(),
            NOW,
        )
    };
    // Garbage: judged by the core, never trusted.
    let garbage = src.copy_of();
    *garbage.mode.lock().unwrap() = 1;
    assert!(open(&garbage).is_err());
    // A callback that fails is `Host` with the host's own message, not "no verified genesis".
    let boom = src.copy_of();
    *boom.mode.lock().unwrap() = 2;
    match open(&boom) {
        Err(AccountError::Host { code, detail }) => {
            assert_eq!(code, "host");
            assert!(detail.contains("boom"), "{detail}");
        }
        Err(other) => panic!("{other:?}"),
        Ok(_) => panic!("opened"),
    }
    // Bad arguments.
    let empty = SavedState {
        verifier: vec![],
        checkpoint: vec![],
        parts: vec![],
    };
    let bad = |key: Vec<u8>, listing: Vec<ListedPath>| {
        AccountEngine::open(
            Box::new(src.clone()),
            listing,
            ident(&format!("controller:{d}")),
            account.clone(),
            vec![],
            0,
            SavedState {
                verifier: vec![],
                checkpoint: vec![],
                parts: vec![],
            },
            key,
            NOW,
        )
    };
    assert!(matches!(
        bad(vec![1; 5], src.listing()),
        Err(AccountError::Bound { .. })
    ));
    let mut with_junk = src.listing();
    with_junk.push(ListedPath {
        path: "not/a/path".into(),
        version: None,
    });
    assert!(
        bad(DEVICE_KEY.to_vec(), with_junk).is_ok(),
        "an unknown path is ignored"
    );
    let _ = empty;
    // A callback that calls back into the engine that is reading it is refused, not deadlocked.
    struct Reenter {
        inner: MemSource,
        engine: Mutex<Option<Arc<AccountEngine>>>,
        seen: Mutex<Vec<String>>,
    }
    use std::sync::Mutex;
    impl HostSource for Reenter {
        fn read(&self, path: String) -> Result<Vec<u8>, AccountError> {
            if let Some(e) = self.engine.lock().unwrap().as_ref() {
                if let Err(err) = e.status() {
                    self.seen.lock().unwrap().push(err.code());
                }
            }
            self.inner.read(path)
        }
        fn read_blob(&self, p: String) -> Result<Vec<u8>, AccountError> {
            self.inner.read_blob(p)
        }
    }
    struct Shared(Arc<Reenter>);
    impl HostSource for Shared {
        fn read(&self, p: String) -> Result<Vec<u8>, AccountError> {
            self.0.read(p)
        }
        fn read_blob(&self, p: String) -> Result<Vec<u8>, AccountError> {
            self.0.read_blob(p)
        }
    }
    let re = Arc::new(Reenter {
        inner: src.clone(),
        engine: Mutex::new(None),
        seen: Mutex::new(vec![]),
    });
    let engine = AccountEngine::open(
        Box::new(Shared(re.clone())),
        src.listing(),
        ident(&format!("controller:{d}")),
        account.clone(),
        vec![],
        0,
        SavedState {
            verifier: vec![],
            checkpoint: vec![],
            parts: vec![],
        },
        DEVICE_KEY.to_vec(),
        NOW,
    )
    .unwrap();
    *re.engine.lock().unwrap() = Some(engine.clone());
    unlock_slot(&engine, &host, &d);
    let junk = format!(
        "ops/{}/notes/000000000001-{}.json",
        "ab".repeat(16),
        "cd".repeat(16)
    );
    src.put(&junk, vec![0xff; 40]);
    let _ = engine.refresh(src.listing());
    assert_eq!(
        engine.status().unwrap().code,
        "ok",
        "still usable after a hostile read"
    );
    let seen = re.seen.lock().unwrap().clone();
    assert!(
        !seen.is_empty() && seen.iter().all(|c| c == "reentered"),
        "{seen:?}"
    );

    // Another thread waits for the lock: it does not fail as `Reentered`.
    let slow = src.copy_of();
    let e2 = open(&slow).unwrap();
    unlock_slot(&e2, &host, &d);
    slow.put(&junk, vec![0xff; 40]);
    *slow.mode.lock().unwrap() = 3; // each read sleeps
    let (e3, listing) = (e2.clone(), slow.listing());
    let t = std::thread::spawn(move || e3.refresh(listing));
    std::thread::sleep(std::time::Duration::from_millis(40));
    let id = e2.id();
    assert!(id.is_ok(), "a call from another thread waits: {id:?}");
    let _ = t.join().unwrap();
}

#[test]
fn journey_two_upgrade_a_04_library_in_place_then_read_old_records_and_write_a_new_one() {
    #[path = "../../colophon-core/tests/support/mod.rs"]
    mod old;
    let (mut lib, owner, controller) = old::create();
    old::write(
        &mut lib,
        &owner,
        "notes",
        "createNotebook",
        json!({"id": "old", "title": "Old notebook"}),
        1,
    );
    old::write(
        &mut lib,
        &owner,
        "notes",
        "addNote",
        json!({"id": "o1", "notebook": "old", "text": "from 0.4"}),
        2,
    );
    let all: std::collections::BTreeMap<String, Vec<u8>> =
        lib.records().clone().into_iter().collect();
    let history = LegacyHistory {
        records: all
            .iter()
            .filter(|(p, _)| p.starts_with("authority/"))
            .map(|(p, b)| Store {
                path: p.clone(),
                bytes: b.clone(),
            })
            .collect(),
    };
    let controller_id = colophon_core::v05::ids::key_id(&controller.public().signing);
    let policy = json!({"callWindow": 300, "headMaxAge": 300, "headQuorum": 1, "history": "members",
        "linkMaxAge": 86400, "memberRule": "single", "recoveryDelay": 259200,
        "rate": {"account": {"bytes": 16777216, "entries": 256}, "signer": {"bytes": 4194304, "entries": 64}}});
    let params = UpgradeParams {
        policy_json: policy.to_string(),
        add_threshold: 1,
        count_by: CountBy::Keys,
        issued_ms: 1_794_000_000_000,
        signers: vec![controller_id],
    };
    let now = 1_794_100_000_000i64;
    let upgrade = AccountMove::begin_upgrade(history, params, now).unwrap();
    assert_eq!(upgrade.kind().unwrap(), MoveKind::Upgrade);
    let steps = upgrade.steps().unwrap();
    assert_eq!(steps.len(), 1);
    let sig = Signature {
        signature: controller.sign(&steps[0].body),
        authenticator_data: None,
        client_data: None,
    };
    let done = upgrade.finish(vec![sig]).unwrap();
    assert!(upgrade.finish(vec![]).is_err(), "one-shot");
    // The host stores the new entry beside the old ones and the old records, untouched.
    let src = MemSource::new();
    for (p, b) in &all {
        src.put(p, b.clone());
    }
    src.store(&done.stores);
    assert_eq!(done.stores.len(), 1);
    let member = colophon_core::v05::ids::key_id(&owner.public().signing);
    let stores: Vec<Store> = src
        .files
        .lock()
        .unwrap()
        .iter()
        .map(|(p, b)| Store {
            path: p.clone(),
            bytes: b.clone(),
        })
        .collect();
    let (o, _) = objects_of(&stores);
    let report = account_verify_history(authority_objects(&o), now).unwrap();
    assert_eq!(report.code, "ok");
    let account = report.account.unwrap();
    let engine = AccountEngine::open(
        Box::new(src.clone()),
        src.listing(),
        ident(&format!("member:{member}")),
        account,
        vec![],
        0,
        SavedState {
            verifier: vec![],
            checkpoint: vec![],
            parts: vec![],
        },
        DEVICE_KEY.to_vec(),
        now,
    )
    .unwrap();
    // The member's keys are the 0.4 keys: its shares open, and the old records read.
    let answers = engine
        .begin_unlock_epochs()
        .unwrap()
        .iter()
        .map(|x| EpochAnswer {
            namespace: x.namespace.clone(),
            epoch: x.epoch,
            shared: owner.agree(&x.peer).unwrap(),
        })
        .collect();
    engine.finish_unlock_epochs(answers).unwrap();
    assert_eq!(
        notes(&engine).len(),
        2,
        "the 0.4 records read through the 0.5 engine"
    );
    let action = engine
        .begin_write(
            "notes".into(),
            "addNote".into(),
            json!({"id": "n2", "notebook": "old", "text": "from 0.5"}).to_string(),
            vec![7; 32],
        )
        .unwrap();
    assert!(action.denial().unwrap().is_none());
    let step = &action.steps().unwrap()[0];
    let sig = Signature {
        signature: owner.sign(&step.body),
        authenticator_data: None,
        client_data: None,
    };
    let written = engine.finish(action, vec![sig]).unwrap();
    src.store(&written.stores);
    assert_eq!(notes(&engine).len(), 3);
}

#[test]
fn a_record_changed_under_the_engine_is_a_typed_integrity_failure() {
    let mut host = Host::new();
    let d = host.identity(10);
    let m = host.identity(31);
    let params = CreateParams {
        label: "A".into(),
        namespaces: vec!["notes".into()],
        controllers: vec![host.raw_controller(&d, "Mac", &["approve", "control"])],
        slots: vec![SlotPlan {
            controllers: vec![d.clone()],
            label: "Mac".into(),
        }],
        threshold: None,
        recover_threshold: None,
        add_threshold: None,
        count_by_holders: false,
        policy_json: String::new(),
        signers: vec![d.clone()],
        rekey_signers: vec![d.clone()],
    };
    let creation = AccountCreation::begin(
        params,
        ident(&format!("controller:{d}")),
        T0,
        host.fresh(96),
    )
    .unwrap();
    drive_creation(&creation, &host);
    let created = creation.take_result().unwrap();
    let src = MemSource::new();
    src.store(&created.stores);
    let ctl = open_engine(&src, &format!("controller:{d}"), &created.account);
    unlock_slot(&ctl, &host, &d);
    let terms = json!({"records": [{"namespace": "notes", "access": "write"}]});
    let r = request(
        &host,
        &created.account,
        &m,
        "Phone",
        AccountMemberKind::Device,
        terms.clone(),
        vec![],
    );
    let a = ctl
        .begin_approve(r.raw.clone(), terms.to_string(), vec![d.clone()], scanned(&ctl, &r.raw, NOW), host.fresh(32))
        .unwrap();
    src.store(&finish(&ctl, &host, a).stores);
    let me = open_engine(&src, &format!("member:{m}"), &created.account);
    unlock_member(&me, &host, &m);
    let a = me
        .begin_write(
            "notes".into(),
            "createNotebook".into(),
            json!({"id": "n", "title": "T"}).to_string(),
            host.fresh(32),
        )
        .unwrap();
    let w = finish(&me, &host, a);
    src.store(&w.stores);
    let op = w
        .stores
        .iter()
        .find(|s| s.path.starts_with("ops/"))
        .unwrap();
    assert_eq!(me.verify_batch(1000).unwrap().remaining, 0);
    // The stored bytes change under the engine.
    let mut changed = op.bytes.clone();
    let n = changed.len();
    changed[n / 2] ^= 1;
    src.put(&op.path, changed);
    let err = me.verify_batch(1000).err().unwrap();
    let _ = err;
    // From now on a failing call is `Integrity`, not a mistake in the call.
    let again = me.view_json("notes".into()).err().unwrap();
    assert!(matches!(again, AccountError::Integrity { .. }), "{again:?}");
    assert_eq!(again.code(), "integrity");
}
