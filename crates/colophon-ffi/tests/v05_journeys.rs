//! Two journeys through the 0.5 exports only, with a host written the way an app writes one:
//! it holds the keys, signs what the exports show it, implements the record source callback and
//! performs the exchange against a simulated home from the values the engine emits.
//!
//! 1. Create an account with a passkey-like controller and a device key, unlock, approve a
//!    member, write and read, add a second device by pairing, and sync two engines through an
//!    in-memory home.
//! 2. Upgrade a 0.4 library in place, read its old records, write a new one.
#![allow(clippy::unwrap_used, clippy::too_many_arguments)]
mod v05_support;
use colophon_core::v05::encoding::decode_base64;
use colophon_ffi::v05::api::*;
use serde_json::{json, Value};
use std::sync::Arc;
use v05_support::*;

const NOW: i64 = T0 + 3 * HOUR;

/// The objects and records of a list of stores, as the exports take them.
fn objects_of(stores: &Value) -> (String, String) {
    let mut o = json!({"entries": [], "pending": [], "heads": [], "predecessor": []});
    let mut records = Vec::new();
    for it in stores.as_array().unwrap() {
        let path = it["path"].as_str().unwrap();
        let bytes = it["bytes"].clone();
        let key = if path.starts_with("authority/") {
            "entries"
        } else if path.starts_with("predecessor/") {
            "predecessor"
        } else if path.starts_with("heads/") {
            "heads"
        } else if path.starts_with("transitions/")
            || path.starts_with("vetoes/")
            || path.starts_with("receipts/")
        {
            "pending"
        } else {
            records.push(json!({"path": path, "bytes": bytes}));
            continue;
        };
        o[key].as_array_mut().unwrap().push(bytes);
    }
    (s(&o), s(&Value::Array(records)))
}

/// Prepare, answer PRF requests if any, sign and finish an action on an account object.
fn run_core(core: &Arc<AccountCore>, host: &mut Host, spec: Value, entropy: usize) -> Value {
    let action = core.begin(s(&spec), host.fresh(entropy)).unwrap();
    assert_eq!(action.denial().unwrap(), "", "{spec}");
    let prf = action.prf_requests().unwrap();
    if prf != "[]" {
        core.provide_prf(action.clone(), host.answer_prf(&prf))
            .unwrap();
    }
    let sigs = host.sign(&action.steps().unwrap());
    let done = j(&core.finish(action, sigs).unwrap());
    // What to store is exactly what the finish produced: no path without bytes, none dropped.
    let n = |k: &str| done[k].as_array().unwrap().len();
    assert_eq!(
        n("stores"),
        n("entries") + n("pending") + n("records"),
        "{spec}"
    );
    done
}
fn run_engine(engine: &Arc<AccountEngine>, host: &mut Host, spec: Value, entropy: usize) -> Value {
    let action = engine.begin(s(&spec), host.fresh(entropy)).unwrap();
    assert_eq!(action.denial().unwrap(), "", "{spec}");
    let sigs = host.sign(&action.steps().unwrap());
    j(&engine.finish(action, sigs).unwrap())
}
fn request(
    host: &Host,
    account: &str,
    member: &str,
    label: &str,
    kind: &str,
    terms: Value,
    endpoints: Option<Value>,
) -> Value {
    let p = host.keys[member].public();
    let mut spec = json!({"account": account, "signing": b64(&p.signing), "agreement": b64(&p.agreement),
        "label": label, "kind": kind, "terms": terms, "created": account_format_date(NOW - 2 * HOUR).unwrap()});
    if let Some(e) = endpoints {
        spec["endpoints"] = e;
    }
    let req = AccountRequest::prepare(s(&spec)).unwrap();
    let step = req.step().unwrap();
    let sigs = host.sign(&format!("[{step}]"));
    j(&req.finish(sigs).unwrap())
}
fn open_engine(src: &MemSource, identity: &str, account: &str) -> Arc<AccountEngine> {
    AccountEngine::open(
        Box::new(src.clone()),
        src.listing(),
        identity.into(),
        account.into(),
        "[]".into(),
        0,
        String::new(),
        DEVICE_KEY.to_vec(),
        NOW,
    )
    .unwrap()
}
fn unlock_slot(engine: &AccountEngine, host: &Host, controller: &str) {
    let slots = j(&engine.slots().unwrap());
    let slot = slots
        .as_array()
        .unwrap()
        .iter()
        .find(|o| {
            let c = o["controllers"].as_array().unwrap();
            c.len() == 1 && c[0]["id"] == controller
        })
        .unwrap();
    let idx = slot["index"].as_u64().unwrap();
    let inputs = engine.begin_unlock_slot(idx).unwrap();
    engine
        .finish_unlock_slot(idx, host.answer_slot(&inputs))
        .unwrap();
}
fn notes_view(engine: &AccountEngine) -> Value {
    let v = j(&engine.view("notes".into()).unwrap());
    assert_eq!(v["ok"], true, "{v}");
    v["value"].clone()
}

#[test]
fn journey_one_create_approve_write_pair_and_sync_two_engines() {
    let mut host = Host::new();
    let d = host.identity(10);
    let k = host.kit(20);
    let p = host.passkey();
    let d2 = host.identity(11);
    let home = host.identity(70);
    let m1 = host.identity(31);

    // --- Create: a device key, a passkey and a kit; four slots (sealed, sealed, prf, combined).
    let mut policy = j(&account_default_policy().unwrap());
    policy["recoveryDelay"] = json!(3600);
    let params = json!({
        "label": "Test account", "namespaces": ["notes"],
        "controllers": [host.raw_controller(&d, "Mac", &["approve", "control"]),
                        host.passkey_controller("Passkey", &["approve", "control", "recover"]),
                        host.raw_controller(&k, "Kit", &["recover"])],
        "slots": [{"controllers": [d], "label": "Mac"}, {"controllers": [k], "label": "Kit"},
                  {"controllers": [p], "label": "Passkey"}, {"controllers": [d, p], "label": "Mac and passkey"}],
        "policy": policy, "signers": [d], "rekeySigners": [d],
    });
    let creation =
        AccountCreation::begin(s(&params), format!("controller:{d}"), T0, host.fresh(96)).unwrap();
    assert_eq!(creation.stage().unwrap(), "prf");
    let reqs = creation.prf_requests().unwrap();
    assert_eq!(
        j(&reqs).as_array().unwrap().len(),
        2,
        "a prf slot and a combined slot"
    );
    creation.provide_prf(host.answer_prf(&reqs)).unwrap();
    let mut rounds = 0;
    loop {
        rounds += 1;
        let steps = creation.steps().unwrap();
        if creation.provide_signatures(host.sign(&steps)).unwrap() == "done" {
            break;
        }
    }
    assert_eq!(rounds, 2, "genesis, then the first rekey");
    let core = creation.take_account().unwrap();
    assert!(creation.take_account().is_err(), "a creation is one-shot");
    let account = core.id().unwrap();
    assert_eq!(account.len(), 64);
    assert!(core.is_unlocked().unwrap());
    let status = j(&core.status().unwrap());
    assert_eq!(status["code"], "ok");

    // --- A home is appointed (a transition, recorded at once: there is no home to witness time).
    let home_req = request(
        &host,
        &account,
        &home,
        "Home",
        "server",
        json!({"serves": ["home"]}),
        Some(json!(["https://home.example/"])),
    );
    let fin = run_core(
        &core,
        &mut host,
        json!({"action": "transition",
        "change": {"homes": {"appoint": [{"request": home_req["raw"], "terms": {"serves": ["home"]}}]}},
        "signers": [d, k], "rule": "control"}),
        0,
    );
    assert!(!fin["stores"].as_array().unwrap().is_empty());
    let due = j(&core.record_due().unwrap());
    assert_eq!(
        due.as_array().unwrap().len(),
        1,
        "the activation is recorded"
    );
    assert_eq!(j(&core.homes().unwrap()).as_array().unwrap().len(), 1);

    // --- Approve a member who may write notes.
    let terms = json!({"records": [{"namespace": "notes", "access": "write"}]});
    let r1 = request(&host, &account, &m1, "Phone", "device", terms.clone(), None);
    assert_eq!(r1["kind"], "device");
    run_core(
        &core,
        &mut host,
        json!({"action": "approve", "request": r1["raw"], "terms": terms, "signers": [d]}),
        32,
    );
    let members = j(&core.members().unwrap());
    assert!(members
        .as_array()
        .unwrap()
        .iter()
        .any(|m| m["member"]["label"] == "Phone"));

    // --- Add a second device: a controller entry, then pairing moves the seed to it.
    let laptop = host.raw_controller(&d2, "Laptop", &["approve"]);
    run_core(
        &core,
        &mut host,
        json!({"action": "add_controller", "mode": "immediate", "signers": [d],
        "controller": laptop}),
        0,
    );
    let tk = PairingTransferKey::create(host.fresh(32)).unwrap();
    let joiner = AccountPairing::join(account.clone(), tk.public(), host.fresh(32)).unwrap();
    let limiter = PairingFailureLimiter::from_json(String::new()).unwrap();
    let existing = AccountPairing::existing_receive_commitment(
        account.clone(),
        joiner.commitment().unwrap(),
        limiter.clone(),
        NOW,
    )
    .unwrap();
    let na = existing.send_nonce(host.fresh(32)).unwrap();
    let reveal = j(&joiner.receive_nonce(na).unwrap());
    let shown_existing = existing
        .receive_reveal(
            unb64(reveal["e"].as_str().unwrap()),
            unb64(reveal["nb"].as_str().unwrap()),
            limiter.clone(),
            NOW,
        )
        .unwrap();
    assert_eq!(
        shown_existing,
        joiner.digits().unwrap(),
        "both screens show one code"
    );
    existing.confirm().unwrap();
    joiner.confirm().unwrap();
    assert!(existing.confirm().is_err(), "a step consumes its state");
    let sealed = core
        .transfer_seed(existing.clone(), host.fresh(32))
        .unwrap();
    assert!(
        !sealed.contains(&b64(&[0u8; 4])),
        "only a ciphertext leaves"
    );
    let (objs, recs) = objects_of(&j(&core.stores().unwrap()));
    let core2 =
        AccountCore::open(objs, recs, vec![], vec![], format!("controller:{d2}"), NOW).unwrap();
    assert!(!core2.is_unlocked().unwrap());
    core2
        .accept_seed_transfer(tk.clone(), sealed.clone(), joiner.clone())
        .unwrap();
    assert!(
        core2.is_unlocked().unwrap(),
        "the new device holds the seed"
    );
    // A sealed seed for another pairing's key is refused.
    let other = PairingTransferKey::create(host.fresh(32)).unwrap();
    assert!(core2.accept_seed_transfer(other, sealed, joiner).is_err());
    // The new device builds its own slot, so it can unlock without its peer.
    run_core(
        &core2,
        &mut host,
        json!({"action": "add_slot", "signer": d2,
        "plan": {"controllers": [d2], "label": "Laptop"}}),
        32,
    );

    // --- Engines over host stores: the member writes, the second device reads after a sync.
    let all = j(&core2.stores().unwrap());
    let auth = MemSource::new();
    auth.store(&all);
    let (sa, sb) = (auth.copy_of(), auth.copy_of());
    let ea = open_engine(&sa, &format!("member:{m1}"), &account);
    ea.finish_unlock_epochs(host.answer_epochs(&m1, &ea.begin_unlock_epochs().unwrap()))
        .unwrap();
    assert_eq!(
        ea.access("notes".into()).unwrap(),
        "",
        "the member may read notes now"
    );
    let w = run_engine(
        &ea,
        &mut host,
        json!({"action": "write", "namespace": "notes", "kind": "createNotebook",
        "payload": {"id": "n", "title": "Journey"}}),
        32,
    );
    sa.store(&w["stores"]);
    let w2 = run_engine(
        &ea,
        &mut host,
        json!({"action": "write", "namespace": "notes", "kind": "addNote",
        "payload": {"id": "n1", "notebook": "n", "text": "hello"}}),
        32,
    );
    sa.store(&w2["stores"]);
    let before = ea.revision("notes".into()).unwrap();
    let view = notes_view(&ea);
    assert_eq!(view["admitted"].as_array().unwrap().len(), 2);
    assert!(before > 0);
    let q = j(&ea
        .query(
            "notes".into(),
            "notes".into(),
            json!({"notebook": "n"}).to_string(),
        )
        .unwrap());
    assert_eq!(q["ok"], true, "{q}");
    let hist = j(&ea.history("notes".into(), 0, 10).unwrap());
    assert_eq!(hist["value"]["items"].as_array().unwrap().len(), 2);

    let eb = open_engine(&sb, &format!("controller:{d2}"), &account);
    unlock_slot(&eb, &host, &d2);
    assert_eq!(
        notes_view(&eb)["admitted"].as_array().unwrap().len(),
        0,
        "nothing synced yet"
    );

    let objects = {
        let (o, _) = objects_of(&all);
        let v = j(&o);
        colophon_core::v05::history::Objects {
            entries: v["entries"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| unb64(x.as_str().unwrap()))
                .collect(),
            pending: v["pending"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| unb64(x.as_str().unwrap()))
                .collect(),
            heads: vec![],
            predecessor: vec![],
        }
    };
    let home_id = j(&core2.homes().unwrap())[0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(home_id, home);
    let mut sim = SimHome::new(&account, &home_id, "https://home.example", &objects, NOW);
    let f1 = sync_pass(&ea, &sa, &home_id, &mut sim, &host, NOW);
    assert!(f1.is_empty(), "an honest home raises no fault: {f1:?}");
    assert!(
        sim.files.keys().any(|p| p.starts_with("ops/")),
        "the home holds the member's records"
    );
    let f2 = sync_pass(&eb, &sb, &home_id, &mut sim, &host, NOW);
    assert!(f2.is_empty(), "{f2:?}");
    let seen = notes_view(&eb);
    assert_eq!(
        seen["admitted"].as_array().unwrap().len(),
        2,
        "the second device reads what the first wrote"
    );
    assert_eq!(notes_view(&ea)["admitted"], seen["admitted"]);

    // --- Saved state resumes: a sealed checkpoint, then a cheap open.
    let saved = ea.save(host.fresh(32)).unwrap();
    assert!(!saved.contains(&b64(&DEVICE_KEY)));
    let resumed = AccountEngine::open(
        Box::new(sa.clone()),
        sa.listing(),
        format!("member:{m1}"),
        account.clone(),
        "[]".into(),
        0,
        saved,
        DEVICE_KEY.to_vec(),
        NOW,
    )
    .unwrap();
    assert_eq!(resumed.open_mode().unwrap(), "resumed");
    resumed
        .finish_unlock_epochs(host.answer_epochs(&m1, &resumed.begin_unlock_epochs().unwrap()))
        .unwrap();
    assert_eq!(
        notes_view(&resumed)["admitted"].as_array().unwrap().len(),
        2
    );
    // A key that is not the device's: the state is a cache, and the open says so.
    let wrong = AccountEngine::open(
        Box::new(sa.clone()),
        sa.listing(),
        format!("member:{m1}"),
        account.clone(),
        "[]".into(),
        0,
        ea.save(host.fresh(32)).unwrap(),
        vec![9; 32],
        NOW,
    )
    .unwrap();
    assert!(
        wrong.open_mode().unwrap().starts_with("invalidated")
            || wrong.open_mode().unwrap() == "cold"
    );
}

#[test]
fn a_prepared_action_cannot_be_altered_replayed_or_finished_elsewhere() {
    let mut host = Host::new();
    let d = host.identity(10);
    let k = host.kit(20);
    let params = json!({"label": "A", "namespaces": ["notes"],
        "controllers": [host.raw_controller(&d, "Mac", &["approve", "control"]), host.raw_controller(&k, "Kit", &["recover"])],
        "slots": [{"controllers": [d], "label": "Mac"}, {"controllers": [k], "label": "Kit"}],
        "signers": [d], "rekeySigners": [d]});
    let creation =
        AccountCreation::begin(s(&params), format!("controller:{d}"), T0, host.fresh(96)).unwrap();
    loop {
        let steps = creation.steps().unwrap();
        if creation.provide_signatures(host.sign(&steps)).unwrap() == "done" {
            break;
        }
    }
    let core = creation.take_account().unwrap();
    let m = host.identity(31);
    let terms = json!({"records": [{"namespace": "notes", "access": "read"}]});
    let r = request(
        &host,
        &core.id().unwrap(),
        &m,
        "App",
        "app",
        terms.clone(),
        None,
    );
    let spec = json!({"action": "approve", "request": r["raw"], "terms": terms, "signers": [d]});
    // Wrong entropy length is a typed bound error, before anything is built.
    assert!(matches!(
        core.begin(s(&spec), vec![1; 31]),
        Err(AccountError::Bound { .. })
    ));
    let a = core.begin(s(&spec), host.fresh(32)).unwrap();
    let steps = j(&a.steps().unwrap());
    // The steps are copies: the host sees the exact body and cannot change what finish uses.
    let good = host.sign(&a.steps().unwrap());
    let mut sigs = j(&good);
    let mut sig = unb64(sigs[0]["signature"].as_str().unwrap());
    sig[5] ^= 1;
    sigs[0]["signature"] = json!(b64(&sig));
    let revision_before = core.revision("notes".into()).unwrap();
    let err = core.finish(a.clone(), s(&sigs)).unwrap_err();
    assert!(matches!(err, AccountError::BadSignature { .. }), "{err:?}");
    assert_eq!(err.code(), "badSignature");
    assert_eq!(
        core.revision("notes".into()).unwrap(),
        revision_before,
        "a failed finish changes nothing"
    );
    assert!(core.members().unwrap().contains("[]") || !core.members().unwrap().contains("App"));
    // A failed finish consumed the action: the same signatures cannot be tried again.
    assert!(matches!(
        core.finish(a, good.clone()),
        Err(AccountError::Consumed { .. })
    ));
    // Another action finished on another account object is refused as the wrong object.
    let b = core.begin(s(&spec), host.fresh(32)).unwrap();
    let other = AccountCore::open(
        objects_of(&j(&core.stores().unwrap())).0,
        "[]".into(),
        vec![],
        vec![],
        format!("controller:{d}"),
        T0 + HOUR,
    )
    .unwrap();
    let g = host.sign(&b.steps().unwrap());
    assert!(matches!(
        other.finish(b.clone(), g.clone()),
        Err(AccountError::WrongObject { .. })
    ));
    // The right object still can: a wrong-object refusal did not consume it.
    let _ = steps;
    let done = core.finish(b, g).unwrap();
    assert!(!j(&done)["stores"].as_array().unwrap().is_empty());
    // Hostile arguments are typed errors, never panics.
    assert!(matches!(
        core.begin("not json".into(), vec![]),
        Err(AccountError::Malformed { .. })
    ));
    assert!(matches!(
        core.begin(s(&json!({"action": "nothing"})), vec![]),
        Err(AccountError::Malformed { .. })
    ));
    assert!(core
        .begin(
            s(&json!({"action": "approve", "request": "!!", "terms": {}, "signers": []})),
            host.fresh(32)
        )
        .is_err());
    assert!(matches!(
        AccountCore::open(
            "{\"entries\":[\"%%%\"]}".into(),
            "[]".into(),
            vec![],
            vec![],
            format!("controller:{d}"),
            T0
        ),
        Err(AccountError::Malformed { .. })
    ));
    assert!(account_verify_history("{\"entries\":[]}".into(), T0).is_ok());
    assert!(matches!(
        account_key_id(vec![0; 1000]),
        Err(AccountError::Bound { .. })
    ));
}

#[test]
fn a_hostile_record_source_gets_errors_not_panics_or_deadlocks() {
    let mut host = Host::new();
    let d = host.identity(10);
    let params = json!({"label": "A", "namespaces": ["notes"],
        "controllers": [host.raw_controller(&d, "Mac", &["approve", "control"])],
        "slots": [{"controllers": [d], "label": "Mac"}], "signers": [d], "rekeySigners": [d]});
    let creation =
        AccountCreation::begin(s(&params), format!("controller:{d}"), T0, host.fresh(96)).unwrap();
    loop {
        let steps = creation.steps().unwrap();
        if creation.provide_signatures(host.sign(&steps)).unwrap() == "done" {
            break;
        }
    }
    let core = creation.take_account().unwrap();
    let account = core.id().unwrap();
    let src = MemSource::new();
    src.store(&j(&core.stores().unwrap()));
    // A source that returns garbage for everything it is asked: the open does not read records
    // before unlock, and what it reads is judged, never trusted.
    let hostile = src.copy_of();
    *hostile.garbage.lock().unwrap() = true;
    let r = AccountEngine::open(
        Box::new(hostile),
        src.listing(),
        format!("controller:{d}"),
        account.clone(),
        "[]".into(),
        0,
        String::new(),
        DEVICE_KEY.to_vec(),
        NOW,
    );
    assert!(r.is_err(), "no genesis can be read from garbage");
    // Bad arguments.
    let e = |key: Vec<u8>, ns: &str, listing: String| {
        AccountEngine::open(
            Box::new(src.clone()),
            listing,
            format!("controller:{d}"),
            account.clone(),
            ns.into(),
            0,
            String::new(),
            key,
            NOW,
        )
    };
    assert!(matches!(
        e(vec![1; 5], "[]", src.listing()),
        Err(AccountError::Bound { .. })
    ));
    assert!(matches!(
        e(DEVICE_KEY.to_vec(), "not json", src.listing()),
        Err(AccountError::Malformed { .. })
    ));
    assert!(e(DEVICE_KEY.to_vec(), "[]", "[1,2]".into()).is_err());
    // A source that calls back into the engine that is reading it is refused, not deadlocked.
    struct Reenter {
        inner: MemSource,
        engine: std::sync::Mutex<Option<Arc<AccountEngine>>>,
        seen: std::sync::Mutex<Vec<String>>,
    }
    impl HostSource for Reenter {
        fn read(&self, path: String) -> Result<Vec<u8>, AccountError> {
            if let Some(e) = self.engine.lock().unwrap().as_ref() {
                if let Err(err) = e.status() {
                    self.seen.lock().unwrap().push(err.code());
                }
            }
            self.inner.read(path)
        }
        fn version(&self, p: String) -> Result<String, AccountError> {
            self.inner.version(p)
        }
        fn read_blob(&self, p: String) -> Result<Vec<u8>, AccountError> {
            self.inner.read_blob(p)
        }
    }
    let re = Arc::new(Reenter {
        inner: src.clone(),
        engine: Default::default(),
        seen: Default::default(),
    });
    struct Shared(Arc<Reenter>);
    impl HostSource for Shared {
        fn read(&self, p: String) -> Result<Vec<u8>, AccountError> {
            self.0.read(p)
        }
        fn version(&self, p: String) -> Result<String, AccountError> {
            self.0.version(p)
        }
        fn read_blob(&self, p: String) -> Result<Vec<u8>, AccountError> {
            self.0.read_blob(p)
        }
    }
    let engine = AccountEngine::open(
        Box::new(Shared(re.clone())),
        src.listing(),
        format!("controller:{d}"),
        account,
        "[]".into(),
        0,
        String::new(),
        DEVICE_KEY.to_vec(),
        NOW,
    )
    .unwrap();
    *re.engine.lock().unwrap() = Some(engine.clone());
    unlock_slot(&engine, &host, &d);
    // A new path appears in the listing with junk behind it; reading it calls the host, which
    // calls back into the engine that is reading: refused, and the engine stays usable.
    let junk = format!(
        "ops/{}/notes/000000000001-{}.json",
        "ab".repeat(16),
        "cd".repeat(16)
    );
    src.put(&junk, vec![0xff; 40]);
    let mut listing: Vec<Value> = j(&src.listing()).as_array().unwrap().clone();
    listing.sort_by_key(|v| v.to_string());
    let _ = engine.refresh(s(&Value::Array(listing)));
    assert_eq!(
        j(&engine.status().unwrap())["code"],
        "ok",
        "still usable after a hostile read"
    );
    let seen = re.seen.lock().unwrap().clone();
    assert!(
        !seen.is_empty(),
        "the engine read through the callback while it was locked"
    );
    assert!(seen.iter().all(|c| c == "reentered"), "{seen:?}");
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
    let history: serde_json::Map<String, Value> = all
        .iter()
        .filter(|(p, _)| p.starts_with("authority/"))
        .map(|(p, b)| (p.clone(), json!(b64(b))))
        .collect();
    let controller_id = colophon_core::v05::ids::key_id(&controller.public().signing);
    let params = json!({"policy": {"callWindow": 300, "headMaxAge": 300, "headQuorum": 1, "history": "members",
            "linkMaxAge": 86400, "memberRule": "single", "recoveryDelay": 259200,
            "rate": {"account": {"bytes": 16777216, "entries": 256}, "signer": {"bytes": 4194304, "entries": 64}}},
        "addThreshold": 1, "countBy": "keys", "issuedMs": 1_794_000_000_000i64, "signers": [controller_id]});
    let now = 1_794_100_000_000i64;
    let upgrade = AccountMove::begin_upgrade(s(&Value::Object(history)), s(&params), now).unwrap();
    assert_eq!(upgrade.kind().unwrap(), "upgrade");
    let steps = j(&upgrade.steps().unwrap());
    assert_eq!(steps.as_array().unwrap().len(), 1);
    let body = unb64(steps[0]["body"].as_str().unwrap());
    let sigs = json!([{"signature": b64(&controller.sign(&body))}]);
    let done = j(&upgrade.finish(s(&sigs)).unwrap());
    assert!(upgrade.finish("[]".into()).is_err(), "one-shot");
    let entry = &done["entries"][0];
    // The host stores the new entry beside the old ones and the old records, untouched.
    let src = MemSource::new();
    for (p, b) in &all {
        src.put(p, b.clone());
    }
    src.put(
        &format!("authority/{:08}.json", entry["seq"].as_u64().unwrap()),
        unb64(entry["bytes"].as_str().unwrap()),
    );
    let member = colophon_core::v05::ids::key_id(&owner.public().signing);
    let stores: Vec<Value> = src
        .files
        .lock()
        .unwrap()
        .iter()
        .map(|(p, b)| json!({"path": p, "bytes": b64(b)}))
        .collect();
    let (o, r) = objects_of(&Value::Array(stores));
    let probe = AccountCore::open(o, r, vec![], vec![], format!("member:{member}"), now).unwrap();
    assert_eq!(j(&probe.status().unwrap())["code"], "ok");
    let account = probe.id().unwrap();
    assert_eq!(account.len(), 64);
    let engine = AccountEngine::open(
        Box::new(src.clone()),
        src.listing(),
        format!("member:{member}"),
        account,
        "[]".into(),
        0,
        String::new(),
        DEVICE_KEY.to_vec(),
        now,
    )
    .unwrap();
    // The member's keys are the 0.4 keys: its shares open, and the old records read.
    let answers = {
        let a = j(&engine.begin_unlock_epochs().unwrap());
        let out: Vec<Value> = a
            .as_array()
            .unwrap()
            .iter()
            .map(|x| {
                json!({"namespace": x["namespace"], "epoch": x["epoch"],
            "shared": b64(&owner.agree(&unb64(x["peer"].as_str().unwrap())).unwrap())})
            })
            .collect();
        s(&Value::Array(out))
    };
    engine.finish_unlock_epochs(answers).unwrap();
    let before = notes_view(&engine);
    assert_eq!(
        before["admitted"].as_array().unwrap().len(),
        2,
        "the 0.4 records read through the 0.5 engine"
    );
    // Write a new record: a 0.5 operation signed by the same member key.
    let action = engine
        .begin(
            s(
                &json!({"action": "write", "namespace": "notes", "kind": "addNote",
        "payload": {"id": "n2", "notebook": "old", "text": "from 0.5"}}),
            ),
            vec![7; 32],
        )
        .unwrap();
    assert_eq!(action.denial().unwrap(), "");
    let step = j(&action.steps().unwrap());
    let sig = json!([{"signature": b64(&owner.sign(&unb64(step[0]["body"].as_str().unwrap())))}]);
    let written = j(&engine.finish(action, s(&sig)).unwrap());
    src.store(&written["stores"]);
    let after = notes_view(&engine);
    assert_eq!(after["admitted"].as_array().unwrap().len(), 3);
    let _ = decode_base64;
}
