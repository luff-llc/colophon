//! The wasm build's exports, driven natively through `AccountCore`: the engine needs a JS
//! record source and cannot be constructed outside a browser or Node. This runs the same
//! journey as the UniFFI crate's up to the engine: create with a passkey-like controller,
//! approve a member, the member writes and reads, a second device pairs and receives the seed,
//! and the hostile-argument cases. The engine, the exchange and the JS callbacks are NOT run
//! here (see docs/bindings-05.md, "What was run").
#![allow(clippy::unwrap_used)]
#[path = "../../colophon-ffi/tests/v05_support/host.rs"]
mod host;
use colophon_wasm::v05::*;
use host::*;
use serde_json::{json, Value};

const NOW: i64 = T0 + 3 * HOUR;

fn objects_of(stores: &Value) -> (String, String) {
    let mut o = json!({"entries": [], "pending": [], "heads": [], "predecessor": []});
    let mut records = Vec::new();
    for it in stores.as_array().unwrap() {
        let path = it["path"].as_str().unwrap();
        let key = if path.starts_with("authority/") {
            "entries"
        } else if path.starts_with("transitions/")
            || path.starts_with("vetoes/")
            || path.starts_with("receipts/")
        {
            "pending"
        } else {
            records.push(it.clone());
            continue;
        };
        o[key].as_array_mut().unwrap().push(it["bytes"].clone());
    }
    (s(&o), s(&Value::Array(records)))
}
fn run(core: &AccountCore, host: &mut Host, spec: Value, entropy: usize) -> Value {
    let action = core.begin(s(&spec), host.fresh(entropy)).unwrap();
    assert_eq!(action.denial().unwrap(), "");
    let prf = action.prf_requests().unwrap();
    if prf != "[]" {
        core.provide_prf(&action, host.answer_prf(&prf)).unwrap();
    }
    let sigs = host.sign(&action.steps().unwrap());
    j(&core.finish(&action, sigs).unwrap())
}
fn request(host: &Host, account: &str, member: &str, terms: Value) -> Value {
    let p = host.keys[member].public();
    let spec = json!({"account": account, "signing": b64(&p.signing), "agreement": b64(&p.agreement),
        "label": "Phone", "kind": "device", "terms": terms,
        "created": account_format_date(NOW - 2 * HOUR).unwrap()});
    let req = AccountRequest::prepare(s(&spec)).unwrap();
    let sigs = host.sign(&format!("[{}]", req.step().unwrap()));
    j(&req.finish(sigs).unwrap())
}

#[test]
fn the_web_build_creates_approves_writes_pairs_and_refuses_hostile_input() {
    let mut host = Host::new();
    let d = host.identity(10);
    let k = host.kit(20);
    let p = host.passkey();
    let d2 = host.identity(11);
    let m1 = host.identity(31);
    let mut policy = j(&account_default_policy().unwrap());
    policy["recoveryDelay"] = json!(3600);
    let params = json!({"label": "Web", "namespaces": ["notes"],
        "controllers": [host.raw_controller(&d, "Mac", &["approve", "control"]),
                        host.passkey_controller("Passkey", &["approve", "control", "recover"]),
                        host.raw_controller(&k, "Kit", &["recover"])],
        "slots": [{"controllers": [d], "label": "Mac"}, {"controllers": [k], "label": "Kit"},
                  {"controllers": [p], "label": "Passkey"}, {"controllers": [d, p], "label": "Both"}],
        "policy": policy, "signers": [d], "rekeySigners": [d]});
    let creation =
        AccountCreation::begin(s(&params), format!("controller:{d}"), T0, host.fresh(96)).unwrap();
    let reqs = creation.prf_requests().unwrap();
    assert_eq!(j(&reqs).as_array().unwrap().len(), 2);
    creation.provide_prf(host.answer_prf(&reqs)).unwrap();
    loop {
        let steps = creation.steps().unwrap();
        if creation.provide_signatures(host.sign(&steps)).unwrap() == "done" {
            break;
        }
    }
    let core = creation.take_account().unwrap();
    let account = core.id().unwrap();
    // The history verifier needs no identity and agrees.
    let (objs, _) = objects_of(&j(&core.stores().unwrap()));
    let v = j(&account_verify_history(objs, NOW).unwrap());
    assert_eq!(v["code"], "ok");
    assert_eq!(v["account"], account.as_str());
    // Approve a member, who reads and writes through its own shares.
    let terms = json!({"records": [{"namespace": "notes", "access": "write"}]});
    let r = request(&host, &account, &m1, terms.clone());
    run(
        &core,
        &mut host,
        json!({"action": "approve", "request": r["raw"], "terms": terms, "signers": [d]}),
        32,
    );
    let (o, rec) = objects_of(&j(&core.stores().unwrap()));
    let member = AccountCore::open(o, rec, vec![], vec![], format!("member:{m1}"), NOW).unwrap();
    member
        .finish_unlock_epochs(host.answer_epochs(&m1, &member.begin_unlock_epochs().unwrap()))
        .unwrap();
    assert_eq!(member.access("notes".into()).unwrap(), "");
    run(
        &member,
        &mut host,
        json!({"action": "write", "namespace": "notes", "kind": "createNotebook",
        "payload": {"id": "n", "title": "Web"}}),
        32,
    );
    let view = j(&member.view("notes".into()).unwrap());
    assert_eq!(view["value"]["admitted"].as_array().unwrap().len(), 1);
    // A second device pairs and receives the seed.
    let laptop = host.raw_controller(&d2, "Laptop", &["approve"]);
    run(
        &core,
        &mut host,
        json!({"action": "add_controller", "mode": "immediate", "signers": [d], "controller": laptop}),
        0,
    );
    let tk = PairingTransferKey::create(host.fresh(32)).unwrap();
    let joiner = AccountPairing::join(account.clone(), tk.public(), host.fresh(32)).unwrap();
    let limiter = PairingFailureLimiter::from_json(String::new()).unwrap();
    let existing = AccountPairing::existing_receive_commitment(
        account.clone(),
        joiner.commitment().unwrap(),
        &limiter,
        NOW,
    )
    .unwrap();
    let na = existing.send_nonce(host.fresh(32)).unwrap();
    let reveal = j(&joiner.receive_nonce(na).unwrap());
    let shown = existing
        .receive_reveal(
            unb64(reveal["e"].as_str().unwrap()),
            unb64(reveal["nb"].as_str().unwrap()),
            &limiter,
            NOW,
        )
        .unwrap();
    assert_eq!(shown, joiner.digits().unwrap());
    existing.confirm().unwrap();
    joiner.confirm().unwrap();
    assert!(existing.confirm().is_err());
    let sealed = core.transfer_seed(&existing, host.fresh(32)).unwrap();
    let (o, rec) = objects_of(&j(&core.stores().unwrap()));
    let second =
        AccountCore::open(o, rec, vec![], vec![], format!("controller:{d2}"), NOW).unwrap();
    assert!(!second.is_unlocked().unwrap());
    second.accept_seed_transfer(&tk, sealed, &joiner).unwrap();
    assert!(second.is_unlocked().unwrap());
    // Hostile input is a typed error.
    let a = core
        .begin(
            s(&json!({"action": "rekey", "namespaces": ["notes"], "signers": [d]})),
            host.fresh(32),
        )
        .unwrap();
    assert!(matches!(
        core.finish(&a, "[{\"signature\":\"AAAA\"}]".into()),
        Err(AccountError::BadSignature { .. })
    ));
    assert!(matches!(
        core.finish(&a, "[]".into()),
        Err(AccountError::Consumed { .. })
    ));
    assert!(matches!(
        core.begin("x".into(), vec![]),
        Err(AccountError::Malformed { .. })
    ));
    assert!(matches!(
        core.begin(
            s(&json!({"action": "rekey", "namespaces": [], "signers": []})),
            vec![1; 3]
        ),
        Err(AccountError::Bound { .. })
    ));
    assert_eq!(
        AccountError::from(colophon_core::v05::Failure::Refused(
            colophon_core::v05::Reason::Audience
        ))
        .code(),
        "refused:audience"
    );
}
