//! The rules an SDK author must follow, each as a test: a callback that waits on another thread
//! that calls the engine does not deadlock forever; a locked engine refuses (typed `Locked`)
//! everything that would use a secret and does not consume a prepared action; an engine whose
//! source was found inconsistent answers nothing, reads included; the typed values that
//! replaced strings (identity, kinds, verdicts, status, controllers).
#![allow(clippy::unwrap_used, dead_code)]
mod v05_support;
use serde_json::json;
use std::sync::{Arc, Mutex};

/// The wait limit is process-wide: the two tests that set it take turns.
static CALLBACK_LIMIT: Mutex<()> = Mutex::new(());
use v05_support::*;

fn empty() -> SavedState {
    SavedState {
        verifier: vec![],
        checkpoint: vec![],
        parts: vec![],
    }
}
fn open(src: &MemSource, account: &str, identity: &str) -> Arc<AccountEngine> {
    open_over(Box::new(src.clone()), src, account, identity)
}
fn open_over(
    source: Box<dyn HostSource>,
    src: &MemSource,
    account: &str,
    identity: &str,
) -> Arc<AccountEngine> {
    AccountEngine::open(
        source,
        src.listing(),
        ident(identity),
        account.to_string(),
        vec![],
        0,
        empty(),
        DEVICE_KEY.to_vec(),
        T0 + 3 * HOUR,
    )
    .unwrap()
}
/// A controller account with one approved member who wrote one record.
fn world(host: &mut Host) -> (MemSource, String, String, String) {
    let d = host.identity(10);
    let m = host.identity(31);
    let creation = AccountCreation::begin(
        CreateParams {
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
        },
        ident(&format!("controller:{d}")),
        T0,
        host.fresh(96),
    )
    .unwrap();
    loop {
        let steps = creation.steps().unwrap();
        if creation.provide_signatures(host.sign(&steps)).unwrap() == CreateStage::Done {
            break;
        }
    }
    let created = creation.take_result().unwrap();
    let src = MemSource::new();
    src.store(&created.stores);
    let ctl = open(&src, &created.account, &format!("controller:{d}"));
    let ins = ctl.begin_unlock_slot(0).unwrap();
    ctl.finish_unlock_slot(0, host.answer_slot(&ins)).unwrap();
    let p = host.keys[&m].public();
    let terms = json!({"records": [{"namespace": "notes", "access": "write"}]});
    let req = AccountRequest::prepare(RequestSpec {
        account: created.account.clone(),
        signing: p.signing,
        agreement: p.agreement,
        label: "Phone".into(),
        kind: AccountMemberKind::Device,
        terms_json: terms.to_string(),
        created: account_format_date(T0 + HOUR).unwrap(),
        custody: None,
        operator: None,
        endpoints: vec![],
    })
    .unwrap();
    let step = req.step().unwrap();
    let info = req.finish(host.sign_one(&step.body, &m, false)).unwrap();
    let a = ctl
        .begin_approve(info.raw, terms.to_string(), vec![d.clone()], host.fresh(32))
        .unwrap();
    let w = ctl
        .finish(a.clone(), host.sign(&a.steps().unwrap()))
        .unwrap();
    src.store(&w.stores);
    let me = open(&src, &created.account, &format!("member:{m}"));
    me.finish_unlock_epochs(host.answer_epochs(&m, &me.begin_unlock_epochs().unwrap()))
        .unwrap();
    let a = me
        .begin_write(
            "notes".into(),
            "createNotebook".into(),
            json!({"id": "n", "title": "T"}).to_string(),
            host.fresh(32),
        )
        .unwrap();
    let w = me
        .finish(a.clone(), host.sign(&a.steps().unwrap()))
        .unwrap();
    src.store(&w.stores);
    (src, created.account, d, m)
}

#[test]
fn a_callback_that_waits_on_a_thread_that_calls_the_engine_is_refused_not_deadlocked() {
    let mut host = Host::new();
    let (src, account, d, _m) = world(&mut host);
    // The rule: a callback must not call the engine and must not block on anything that does.
    // This callback breaks it: it starts a thread that calls the engine, and waits for it.
    struct Waits {
        inner: MemSource,
        engine: Mutex<Option<Arc<AccountEngine>>>,
        outcome: Mutex<Option<String>>,
        armed: Mutex<bool>,
    }
    struct Shared(Arc<Waits>);
    impl HostSource for Shared {
        fn read(&self, path: String) -> Result<Vec<u8>, AccountError> {
            let first = std::mem::replace(&mut *self.0.armed.lock().unwrap(), false);
            if first {
                let e = self.0.engine.lock().unwrap().clone().unwrap();
                let t = std::thread::spawn(move || e.status().err().map(|e| e.kind()));
                // Waiting for it is the mistake: it can only finish by being refused.
                *self.0.outcome.lock().unwrap() = Some(t.join().unwrap().unwrap_or_default());
            }
            self.0.inner.read(path)
        }
        fn read_blob(&self, p: String) -> Result<Vec<u8>, AccountError> {
            self.0.inner.read_blob(p)
        }
    }
    let w = Arc::new(Waits {
        inner: src.clone(),
        engine: Mutex::new(None),
        outcome: Mutex::new(None),
        armed: Mutex::new(false),
    });
    set_callback_wait_ms(300);
    let e = open_over(
        Box::new(Shared(w.clone())),
        &src,
        &account,
        &format!("controller:{d}"),
    );
    *w.engine.lock().unwrap() = Some(e.clone());
    *w.armed.lock().unwrap() = true;
    let ins = e.begin_unlock_slot(0).unwrap();
    // `load` reads records: the first read waits on the thread, which is refused after the wait.
    e.finish_unlock_slot(0, host.answer_slot(&ins)).unwrap();
    set_callback_wait_ms(30_000);
    assert_eq!(w.outcome.lock().unwrap().as_deref(), Some("Reentered"));
    // The engine is intact.
    assert!(e.is_unlocked().unwrap());
}

#[test]
fn an_honest_slow_source_never_fails_a_waiting_thread_only_one_callback_past_the_limit_does() {
    let mut host = Host::new();
    let (src, account, d, _m) = world(&mut host);
    // Many short callbacks (100 ms each), the whole call longer than the 250 ms limit: the
    // waiter's clock is the CURRENT callback's, so it is never refused.
    struct Slow(MemSource);
    impl HostSource for Slow {
        fn read(&self, p: String) -> Result<Vec<u8>, AccountError> {
            std::thread::sleep(std::time::Duration::from_millis(100));
            self.0.read(p)
        }
        fn read_blob(&self, p: String) -> Result<Vec<u8>, AccountError> {
            self.0.read_blob(p)
        }
    }
    set_callback_wait_ms(300);
    let e = open_over(
        Box::new(Slow(src.clone())),
        &src,
        &account,
        &format!("controller:{d}"),
    );
    let ins = e.begin_unlock_slot(0).unwrap();
    e.finish_unlock_slot(0, host.answer_slot(&ins)).unwrap();
    let e2 = e.clone();
    let started = std::time::Instant::now();
    // `verify_batch` re-reads every held path from the source: several slow callbacks in a row.
    let holder = std::thread::spawn(move || e2.verify_batch(1000).map(|_| ()));
    std::thread::sleep(std::time::Duration::from_millis(60));
    let waited = e.status();
    let total = started.elapsed();
    holder.join().unwrap().unwrap();
    set_callback_wait_ms(30_000);
    assert!(waited.is_ok(), "{:?}", waited.err());
    assert!(
        total > std::time::Duration::from_millis(300),
        "the call outlasted the limit: {total:?}"
    );
}

#[test]
fn a_locked_engine_refuses_typed_and_does_not_consume_what_was_prepared() {
    let mut host = Host::new();
    let (src, account, d, _m) = world(&mut host);
    let e = open(&src, &account, &format!("controller:{d}"));
    let ins = e.begin_unlock_slot(0).unwrap();
    e.finish_unlock_slot(0, host.answer_slot(&ins)).unwrap();
    let prepared = e
        .begin_rekey(vec!["notes".into()], vec![d.clone()], host.fresh(32))
        .unwrap();
    assert!(!e.is_locked().unwrap());
    e.lock().unwrap();
    assert!(e.is_locked().unwrap());
    // A prepared action does not finish after `lock`, and is not consumed by the refusal.
    let r = e.finish(prepared.clone(), host.sign(&prepared.steps().unwrap()));
    assert!(matches!(r, Err(AccountError::Locked { .. })), "finish");
    assert!(
        !prepared.steps().unwrap().is_empty(),
        "the refusal does not consume it"
    );
    // Nothing new is prepared, unlocked, saved or loaded.
    assert!(matches!(
        e.begin_rekey(vec!["notes".into()], vec![d.clone()], host.fresh(32)),
        Err(AccountError::Locked { .. })
    ));
    assert!(matches!(
        e.save(host.fresh(32)),
        Err(AccountError::Locked { .. })
    ));
    assert!(matches!(
        e.finish_unlock_slot(0, host.answer_slot(&ins)),
        Err(AccountError::Locked { .. })
    ));
    assert!(matches!(e.load(), Err(AccountError::Locked { .. })));
    let a = AccountError::locked();
    assert_eq!((a.kind().as_str(), a.code().as_str()), ("Locked", "locked"));
    // The verified history still answers.
    assert_eq!(e.status().unwrap().kind, StatusKind::Ok);
    assert!(!e.members().unwrap().is_empty());
}

#[test]
fn an_engine_whose_source_changed_answers_nothing_more_not_even_a_read() {
    let mut host = Host::new();
    let (src, account, d, _m) = world(&mut host);
    let e = open(&src, &account, &format!("controller:{d}"));
    let ins = e.begin_unlock_slot(0).unwrap();
    e.finish_unlock_slot(0, host.answer_slot(&ins)).unwrap();
    assert_eq!(e.status().unwrap().kind, StatusKind::Ok);
    // The source changes bytes it must never change.
    let path = src
        .files
        .lock()
        .unwrap()
        .keys()
        .find(|p| p.starts_with("ops/"))
        .cloned()
        .unwrap();
    let mut b = src.get(&path).unwrap();
    b.push(b' ');
    src.put(&path, b);
    let r = e.verify_batch(100);
    assert!(
        matches!(r, Err(AccountError::Integrity { .. })),
        "{:?}",
        r.err()
    );
    // Every later call is `Integrity`, a read included.
    assert!(matches!(e.status(), Err(AccountError::Integrity { .. })));
    assert!(matches!(e.members(), Err(AccountError::Integrity { .. })));
}

#[test]
fn identity_kinds_verdicts_status_and_controllers_are_typed() {
    let mut host = Host::new();
    let (src, account, d, m) = world(&mut host);
    let e = open(&src, &account, &format!("controller:{d}"));
    let ins = e.begin_unlock_slot(0).unwrap();
    e.finish_unlock_slot(0, host.answer_slot(&ins)).unwrap();
    // The identity is a record, not text.
    let who = e.identity().unwrap();
    assert_eq!(
        (who.kind, who.id.as_str()),
        (AccountIdentityKind::Controller, d.as_str())
    );
    let bad = AccountEngine::open(
        Box::new(src.clone()),
        src.listing(),
        AccountIdentity {
            kind: AccountIdentityKind::Member,
            id: "short".into(),
        },
        account.clone(),
        vec![],
        0,
        empty(),
        DEVICE_KEY.to_vec(),
        T0,
    );
    assert!(matches!(bad, Err(AccountError::Malformed { .. })));
    // Roles and form are enums; the slot kind too.
    let c = e.controllers().unwrap().remove(0);
    assert_eq!(c.roles, [ControllerRole::Approve, ControllerRole::Control]);
    assert_eq!(c.form, SignForm::Raw);
    // The controller carries its key descriptor and the raw role strings.
    assert_eq!((c.key.form, c.key.signing.len()), (SignForm::Raw, 65));
    assert!(c.key.agreement.is_some());
    assert_eq!(c.roles_raw, ["approve", "control"]);
    // A failed WebAuthn check is a typed field beside the code.
    let bad = account_webauthn_check(
        KeyDescriptorView {
            form: SignForm::Raw,
            signing: vec![1; 65],
            agreement: None,
            rp: None,
            credential: None,
            origins: vec![],
            authority_origins: vec![],
        },
        vec![],
        vec![],
        vec![],
        vec![],
        WebauthnMode {
            kind: CheckKind::Call,
            rule: AuthorityRuleKind::Single,
            verification: false,
            sign_controller: false,
            origins: vec![],
            uv_required: false,
        },
    );
    assert!(matches!(
        bad,
        Err(AccountError::BadSignature { check: Some(_), .. })
            | Err(AccountError::Malformed { .. })
    ));
    assert_eq!(
        account_map_swift_role("service".into()),
        Some(AccountMemberKind::Server)
    );
    assert_eq!(
        account_map_swift_role("web".into()),
        Some(AccountMemberKind::App)
    );
    assert!(account_map_swift_role("robot".into()).is_none());
    assert_eq!(e.slots().unwrap()[0].kind, SlotKind::Sealed);
    // The status keeps the protocol's code and splits it.
    let s = e.status().unwrap();
    assert_eq!(
        (s.code.as_str(), s.kind, s.reason.as_deref()),
        ("ok", StatusKind::Ok, None)
    );
    // A verdict on a record: kind and reason, not `held:<why>` text.
    let path = src
        .files
        .lock()
        .unwrap()
        .keys()
        .find(|p| p.starts_with("ops/"))
        .cloned()
        .unwrap();
    let me = open(&src, &account, &format!("member:{m}"));
    me.finish_unlock_epochs(host.answer_epochs(&m, &me.begin_unlock_epochs().unwrap()))
        .unwrap();
    let v = me.record_verdict(path.clone()).unwrap().unwrap();
    assert_eq!((v.kind, v.reason.clone()), (VerdictKind::Admitted, None));
    assert!(me.record_verdict("ops/none".into()).unwrap().is_none());
    let held = me
        .verdict_of(path.clone(), src.get(&path).unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(held.kind, VerdictKind::Admitted);
    assert!(
        me.verdict_of(path, vec![1, 2, 3]).unwrap().is_none(),
        "not the held bytes"
    );
    // The history verifier splits a refusal the same way.
    let r = account_verify_history(
        AuthorityObjects {
            entries: vec![ByteString {
                bytes: vec![1, 2, 3],
            }],
            pending: vec![],
            heads: vec![],
            predecessor: vec![],
        },
        T0,
    )
    .unwrap();
    assert_eq!((r.code.as_str(), r.kind), ("ok", StatusKind::Ok));
    // A typed controller to add: a passkey is not a base64 JSON document the SDK writes.
    let d2 = host.identity(11);
    let mut spec = host.raw_controller(&d2, "Laptop", &["approve"]);
    let a = e
        .begin_add_controller(
            spec.clone_spec(),
            AddMode::Immediate,
            vec![d.clone()],
            RuleKind::Control,
            vec![],
        )
        .unwrap();
    assert_eq!(a.kind().unwrap(), ActionKind::AddController);
    // A role this surface does not create is refused before the core is asked.
    spec.roles = vec![ControllerRole::Unknown];
    assert!(matches!(
        e.begin_add_controller(
            spec,
            AddMode::Immediate,
            vec![d.clone()],
            RuleKind::Control,
            vec![]
        ),
        Err(AccountError::Malformed { .. })
    ));
}

trait CloneSpec {
    fn clone_spec(&self) -> ControllerSpec;
}
impl CloneSpec for ControllerSpec {
    fn clone_spec(&self) -> ControllerSpec {
        ControllerSpec {
            key: KeyDescriptorView {
                form: self.key.form,
                signing: self.key.signing.clone(),
                agreement: self.key.agreement.clone(),
                rp: self.key.rp.clone(),
                credential: self.key.credential.clone(),
                origins: self.key.origins.clone(),
                authority_origins: self.key.authority_origins.clone(),
            },
            label: self.label.clone(),
            roles: self.roles.clone(),
            verification: self.verification,
            holder: self.holder.clone(),
            audiences: self.audiences.clone(),
        }
    }
}
