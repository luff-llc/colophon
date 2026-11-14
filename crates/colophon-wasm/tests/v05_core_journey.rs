//! The wasm build's exports, driven natively: everything that needs no JS host. The engine needs
//! a JS record source and cannot be constructed outside a browser or Node, so it, the exchange,
//! the JS callbacks and the thrown `AccountFault` are NOT run here (see docs/bindings-05.md,
//! "What was run"). This runs creation with a passkey-like controller (PRF), a member's
//! request, the history verifier, the pairing ceremony and the typed errors, through the web
//! build's own types (`Vec<Record>` fields, `Option<Record>` getters and setters).
#![allow(clippy::unwrap_used)]
pub use colophon_wasm::v05::*;
#[path = "../../colophon-ffi/tests/v05_support/host.rs"]
mod host;
use colophon_core::v05::history::Objects;
use host::*;
use serde_json::json;

const NOW: i64 = T0 + 3 * HOUR;

#[test]
fn the_web_build_creates_verifies_requests_pairs_and_refuses_hostile_input() {
    let mut host = Host::new();
    let d = host.identity(10);
    let k = host.kit(20);
    let p = host.passkey();
    let mut policy: serde_json::Value =
        serde_json::from_str(&account_default_policy().unwrap()).unwrap();
    policy["recoveryDelay"] = json!(3600);
    let params = CreateParams::new(
        "Web".into(),
        vec!["notes".into()],
        vec![
            host.raw_controller(&d, "Mac", &["approve", "control"]),
            host.passkey_controller("Passkey", &["approve", "control", "recover"]),
            host.raw_controller(&k, "Kit", &["recover"]),
        ],
        vec![
            SlotPlan::new(vec![d.clone()], "Mac".into()),
            SlotPlan::new(vec![k.clone()], "Kit".into()),
            SlotPlan::new(vec![p.clone()], "Passkey".into()),
            SlotPlan::new(vec![d.clone(), p.clone()], "Both".into()),
        ],
        None,
        None,
        None,
        false,
        policy.to_string(),
        vec![d.clone()],
        vec![d.clone()],
    );
    let creation =
        AccountCreation::begin(params, format!("controller:{d}"), T0, host.fresh(96)).unwrap();
    let reqs = creation.prf_requests().unwrap();
    assert_eq!(reqs.len(), 2);
    creation.provide_prf(host.answer_prf(&reqs)).unwrap();
    while creation
        .provide_signatures(host.sign(&creation.steps().unwrap()))
        .unwrap()
        != CreateStage::Done
    {}
    let created = creation.take_result().unwrap();
    assert_eq!(created.account.len(), 64);
    // The history verifier needs no identity and agrees.
    let mut o = Objects::default();
    for s in &created.stores {
        if s.path.starts_with("authority/") {
            o.entries.push(s.bytes.clone());
        }
    }
    let blobs = |v: &Vec<Vec<u8>>| v.iter().map(|b| Blob::new(b.clone())).collect::<Vec<_>>();
    let report = account_verify_history(
        AuthorityObjects::new(blobs(&o.entries), vec![], vec![], vec![]),
        NOW,
    )
    .unwrap();
    assert_eq!(report.code, "ok");
    assert_eq!(report.account.as_deref(), Some(created.account.as_str()));
    // A member's request, signed with the member's own key.
    let m = host.identity(31);
    let pk = host.keys[&m].public();
    let req = AccountRequest::prepare(RequestSpec::new(
        created.account.clone(),
        pk.signing,
        pk.agreement,
        "Phone".into(),
        AccountMemberKind::Device,
        json!({"records": [{"namespace": "notes", "access": "write"}]}).to_string(),
        account_format_date(NOW - 2 * HOUR).unwrap(),
        String::new(),
        String::new(),
        vec![],
    ))
    .unwrap();
    let step = req.step().unwrap();
    assert_eq!(step.form, SignForm::Raw);
    let info = req.finish(host.sign_one(&step.body, &m, false)).unwrap();
    assert_eq!(info.kind, AccountMemberKind::Device);
    assert_eq!(
        account_request_info(info.raw.clone()).unwrap().member,
        info.member
    );
    assert!(
        req.finish(host.sign_one(&step.body, &m, false)).is_err(),
        "one-shot"
    );
    // Pairing.
    let tk = PairingTransferKey::create(host.fresh(32)).unwrap();
    let joiner =
        AccountPairing::join(created.account.clone(), tk.public(), host.fresh(32)).unwrap();
    let limiter = PairingFailureLimiter::from_state(String::new()).unwrap();
    let existing = AccountPairing::existing_receive_commitment(
        created.account.clone(),
        joiner.commitment().unwrap(),
        &limiter,
        NOW,
    )
    .unwrap();
    let na = existing.send_nonce(host.fresh(32)).unwrap();
    let reveal = joiner.receive_nonce(na).unwrap().unwrap();
    let shown = existing
        .receive_reveal(reveal.e.clone(), reveal.nb.clone(), &limiter, NOW)
        .unwrap();
    assert_eq!(shown, joiner.digits().unwrap());
    existing.confirm().unwrap();
    assert!(existing.confirm().is_err());
    assert_eq!(existing.stage().unwrap(), PairingStage::Confirmed);
    // The web build's typed records round-trip their fields.
    let mut sig = Signature::new(vec![1, 2, 3], None, None);
    sig.authenticator_data = Some(vec![9]);
    assert_eq!(sig.authenticator_data.clone().unwrap(), vec![9]);
    // Typed errors.
    assert!(matches!(
        account_key_id(vec![0; 1000]),
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
