//! Two probes of what the typed surface leaves behind and allocates, with a counting global
//! allocator (this binary only):
//!
//! * after a call that takes a host secret (an ECDH result, an epoch share, a PRF output), no
//!   freed heap block holds the secret in any encoding (raw, base64, base64url, hex). The
//!   checker's probe found 2 freed blocks with the raw secret and 3 with its base64 on the
//!   JSON-string surface; the typed surface wipes every copy it makes.
//! * a 64 MiB argument is refused on its raw length: peak memory stays near the argument's own
//!   size (the JSON-string surface reached 1.07 GiB for the same call).
#![allow(clippy::unwrap_used, dead_code)]
mod v05_support;
use colophon_core::v05::encoding::{encode_base64, encode_base64url};
use serde_json::json;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use v05_support::*;

static ARMED: AtomicBool = AtomicBool::new(false);
static NEEDLES: OnceLock<Vec<Vec<u8>>> = OnceLock::new();
static HITS: AtomicUsize = AtomicUsize::new(0);
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static SERIAL: Mutex<()> = Mutex::new(());

fn holds(hay: &[u8], needle: &[u8]) -> bool {
    hay.len() >= needle.len() && hay.windows(needle.len()).any(|w| w == needle)
}
struct Scan;
unsafe impl GlobalAlloc for Scan {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let now = LIVE.fetch_add(l.size(), Ordering::Relaxed) + l.size();
        PEAK.fetch_max(now, Ordering::Relaxed);
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size(), Ordering::Relaxed);
        if ARMED.load(Ordering::Relaxed) {
            if let Some(ns) = NEEDLES.get() {
                let s = unsafe { std::slice::from_raw_parts(p, l.size()) };
                if ns.iter().any(|n| holds(s, n)) {
                    HITS.fetch_add(1, Ordering::Relaxed);
                    if std::env::var_os("TRACE_HITS").is_some() {
                        ARMED.store(false, Ordering::SeqCst);
                        eprintln!(
                            "HIT size {}\n{}",
                            l.size(),
                            std::backtrace::Backtrace::force_capture()
                        );
                        ARMED.store(true, Ordering::SeqCst);
                    }
                }
            }
        }
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        // A moved block is freed: scan it like any other.
        if ARMED.load(Ordering::Relaxed) {
            if let Some(ns) = NEEDLES.get() {
                let s = unsafe { std::slice::from_raw_parts(p, l.size()) };
                if ns.iter().any(|n| holds(s, n)) {
                    HITS.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        let now = LIVE.fetch_add(new, Ordering::Relaxed) + new - l.size();
        LIVE.fetch_sub(0, Ordering::Relaxed);
        PEAK.fetch_max(now, Ordering::Relaxed);
        unsafe { System.realloc(p, l, new) }
    }
}
#[global_allocator]
static A: Scan = Scan;

fn needles_of(secret: &[u8]) -> Vec<Vec<u8>> {
    let hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();
    vec![
        secret.to_vec(),
        encode_base64(secret).into_bytes(),
        encode_base64url(secret).into_bytes(),
        hex.into_bytes(),
    ]
}
fn world(host: &mut Host) -> (std::sync::Arc<AccountEngine>, String, MemSource, String) {
    let (a, b, c, d, _) = world_d(host);
    (a, b, c, d)
}
fn world_d(
    host: &mut Host,
) -> (
    std::sync::Arc<AccountEngine>,
    String,
    MemSource,
    String,
    String,
) {
    let d = host.identity(10);
    let m = host.identity(31);
    let params = CreateParams {
        label: "A".into(),
        namespaces: vec!["notes".into()],
        controllers_json: vec![host.raw_controller(&d, "Mac", &["approve", "control"])],
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
    let creation =
        AccountCreation::begin(params, format!("controller:{d}"), T0, host.fresh(96)).unwrap();
    loop {
        let steps = creation.steps().unwrap();
        if creation.provide_signatures(host.sign(&steps)).unwrap() == CreateStage::Done {
            break;
        }
    }
    let created = creation.take_result().unwrap();
    let src = MemSource::new();
    src.store(&created.stores);
    let open = |identity: String| {
        AccountEngine::open(
            Box::new(src.clone()),
            src.listing(),
            identity,
            created.account.clone(),
            vec![],
            0,
            SavedState {
                verifier: vec![],
                checkpoint: vec![],
                parts: vec![],
            },
            DEVICE_KEY.to_vec(),
            T0 + 3 * HOUR,
        )
        .unwrap()
    };
    let ctl = open(format!("controller:{d}"));
    let slot = ctl.slots().unwrap().remove(0);
    let inputs = ctl.begin_unlock_slot(slot.index).unwrap();
    ctl.finish_unlock_slot(slot.index, host.answer_slot(&inputs))
        .unwrap();
    // Approve the member so it holds a share.
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
        custody: String::new(),
        operator: String::new(),
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
    let member = open(format!("member:{m}"));
    (member, m, src, created.account, d)
}

/// Freed blocks holding `secret` (any encoding) during `f`.
fn hits_during(secret: &[u8], f: impl FnOnce()) -> usize {
    let _ = NEEDLES.set(needles_of(secret));
    HITS.store(0, Ordering::SeqCst);
    ARMED.store(true, Ordering::SeqCst);
    f();
    ARMED.store(false, Ordering::SeqCst);
    HITS.load(Ordering::SeqCst)
}

#[test]
fn the_binding_leaves_no_copy_of_a_host_secret_beyond_what_the_core_itself_leaves() {
    let _g = SERIAL.lock().unwrap();
    let mut host = Host::new();
    let (member, m, src, account) = world(&mut host);
    // The same share, given to the core directly (the floor: the core's own `hpke::extract`
    // builds a temporary that it does not erase; nothing the binding adds is in it).
    let (objects, records) = objects_of(
        &src.files
            .lock()
            .unwrap()
            .iter()
            .map(|(p, b)| Store {
                path: p.clone(),
                bytes: b.clone(),
            })
            .collect::<Vec<_>>(),
    );
    let mut core = colophon_core::v05::account::Account::open(
        objects,
        records,
        None,
        colophon_core::v05::account::Identity::Member(m.clone()),
        T0 + 3 * HOUR,
    )
    .unwrap();
    let want = core.begin_unlock_epochs();
    let secret = host.keys[&m].agree(&want[0].peer).unwrap();
    let results = want
        .iter()
        .map(|w| colophon_core::v05::account::EpochSecret {
            step: w.clone(),
            shared: colophon_core::v05::vault::EcdhOutput::from_host(&secret).unwrap(),
        })
        .collect();
    let core_hits = hits_during(&secret, || {
        core.finish_unlock_epochs(results).unwrap();
    });
    let answers = host.answer_epochs(&m, &member.begin_unlock_epochs().unwrap());
    assert!(!answers.is_empty() && answers[0].shared == secret);
    let binding_hits = hits_during(&secret, || {
        member.finish_unlock_epochs(answers).unwrap();
    });
    println!("account {}: freed blocks holding the secret: core alone {core_hits}, through the binding {binding_hits}", &account[..8]);
    assert!(
        binding_hits <= core_hits,
        "the binding left {binding_hits} copies, the core alone leaves {core_hits}"
    );
}

#[test]
fn a_64_mib_argument_is_refused_on_its_raw_length_with_memory_near_its_own_size() {
    let _g = SERIAL.lock().unwrap();
    let mut host = Host::new();
    let (member, _m, _src, _account) = world(&mut host);
    let big = "x".repeat(64 << 20);
    let baseline = LIVE.load(Ordering::SeqCst);
    PEAK.store(baseline, Ordering::SeqCst);
    // A JSON document argument over its 4 MiB cap, a payload as the JSON-string surface took it.
    let e = member
        .begin_write("notes".into(), "createNotebook".into(), big, host.fresh(32))
        .err()
        .unwrap();
    assert!(matches!(e, AccountError::Bound { .. }), "{e:?}");
    let extra = PEAK.load(Ordering::SeqCst).saturating_sub(baseline);
    println!(
        "64 MiB payload refused; peak extra allocation above the argument itself: {extra} bytes"
    );
    assert!(
        extra < (1 << 20),
        "refusing must not allocate in proportion to the argument: {extra}"
    );
    // A list over its bound and a list of oversized items are refused before anything is built.
    let many = vec![String::new(); 300];
    assert!(matches!(
        member.begin_rekey(many, vec![], host.fresh(32)),
        Err(AccountError::Bound { .. })
    ));
    let blob = vec![Blob {
        bytes: vec![0; 41 << 20],
    }];
    let baseline = LIVE.load(Ordering::SeqCst);
    PEAK.store(baseline, Ordering::SeqCst);
    let e = account_verify_history(
        AuthorityObjects {
            entries: blob,
            pending: vec![],
            heads: vec![],
            predecessor: vec![],
        },
        0,
    )
    .err()
    .unwrap();
    assert!(matches!(e, AccountError::Bound { .. }), "{e:?}");
    assert!(PEAK.load(Ordering::SeqCst).saturating_sub(baseline) < (1 << 20));
}

#[test]
fn finish_unlock_slot_leaves_no_copy_of_the_ecdh_result_beyond_the_core() {
    use colophon_core::v05::slots::OpeningSecret;
    let _g = SERIAL.lock().unwrap();
    let mut host = Host::new();
    let (_member, _m, src, account, d) = world_d(&mut host);
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
    let (objects, records) = objects_of(&stores);
    let mut core = colophon_core::v05::account::Account::open(
        objects,
        records,
        None,
        colophon_core::v05::account::Identity::Controller(d.clone()),
        T0 + 3 * HOUR,
    )
    .unwrap();
    let inputs = core.begin_unlock_slot(0).unwrap();
    let colophon_core::v05::slots::OpeningInput::Ecdh { enc, .. } = &inputs[0] else {
        panic!("sealed slot")
    };
    let secret = host.keys[&d].agree(enc).unwrap();
    let core_hits = hits_during(&secret, || {
        let s = colophon_core::v05::vault::EcdhOutput::from_host(&secret).unwrap();
        core.finish_unlock_slot(0, &[OpeningSecret::Ecdh(s)])
            .unwrap();
    });
    let engine = AccountEngine::open(
        Box::new(src.clone()),
        src.listing(),
        format!("controller:{d}"),
        account,
        vec![],
        0,
        SavedState {
            verifier: vec![],
            checkpoint: vec![],
            parts: vec![],
        },
        DEVICE_KEY.to_vec(),
        T0 + 3 * HOUR,
    )
    .unwrap();
    let answers = host.answer_slot(&engine.begin_unlock_slot(0).unwrap());
    assert_eq!(answers[0].secret, secret);
    let binding_hits = hits_during(&secret, || {
        engine.finish_unlock_slot(0, answers).unwrap();
    });
    println!("finish_unlock_slot: freed blocks holding the ECDH result: core alone {core_hits}, through the binding {binding_hits}");
    assert!(binding_hits <= core_hits);
}
