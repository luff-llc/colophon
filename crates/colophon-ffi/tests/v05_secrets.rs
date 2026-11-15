//! What the typed surface leaves behind in freed memory, and what it allocates, measured with
//! the observer of the crate's own zero-on-free allocator (`colophon_ffi::v05::zero_alloc`), which
//! sees every free twice: before the wipe (what a plain allocator would leave behind) and after it.
//!
//! * `before`: a freed block that still holds the secret before the allocator wipes it. The
//!   binding's own code must leave none (every Rust-API path scans 0); the UniFFI scaffolding
//!   leaves one per secret that crosses (the `RustBuffer` it reads by copying and frees without
//!   overwriting): the real exported scaffolding symbols are called here and the scan sees it,
//!   which is also the positive control.
//! * `after`: what a freed block holds once the allocator has run: the claim in the doc. 0
//!   everywhere.
//! * peak allocation of the worst accepted JSON input, and a list of 4 MiB items refused on its
//!   total before anything is parsed.
//!
//! The needle is per scan (not a `OnceLock`), every secret is looked for in four encodings, and
//! the scans run in one process one after the other.
#![cfg(feature = "zero-on-free")]
#![allow(clippy::unwrap_used, dead_code)]
mod v05_support;
use colophon_core::v05::encoding::{encode_base64, encode_base64url};
use colophon_ffi::v05::zero_alloc::{set_observer, Event};
use colophon_ffi::UniFfiTag;
use serde_json::json;
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use uniffi::{Lower, RustBuffer, RustCallStatus};
use v05_support::*;

static ARMED: AtomicBool = AtomicBool::new(false);
static NEEDLES: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());
static BEFORE: AtomicUsize = AtomicUsize::new(0);
static AFTER: AtomicUsize = AtomicUsize::new(0);
/// Live bytes since the observer was set (signed: blocks allocated before it was set are freed
/// after).
static LIVE: AtomicIsize = AtomicIsize::new(0);
static PEAK: AtomicIsize = AtomicIsize::new(0);
static SERIAL: Mutex<()> = Mutex::new(());

fn holds(hay: &[u8], needle: &[u8]) -> bool {
    hay.len() >= needle.len() && hay.windows(needle.len()).any(|w| w == needle)
}
thread_local! {
    /// Set while this thread is inside the observer: looking (or printing) may allocate.
    static BUSY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
fn check(p: *const u8, size: usize, hits: &AtomicUsize) {
    if !ARMED.load(Ordering::Relaxed) || BUSY.with(|b| b.replace(true)) {
        return;
    }
    {
        // Other threads free blocks too (the harness); each waits its turn, none allocates.
        let ns = NEEDLES.lock().unwrap_or_else(|e| e.into_inner());
        let s = unsafe { std::slice::from_raw_parts(p, size) };
        if ns.iter().any(|n| !n.is_empty() && holds(s, n)) {
            hits.fetch_add(1, Ordering::Relaxed);
            if std::env::var_os("TRACE_HITS").is_some() {
                eprintln!(
                    "HIT size {size}\n{}",
                    std::backtrace::Backtrace::force_capture()
                );
            }
        }
    }
    BUSY.with(|b| b.set(false));
}
fn observe(e: Event) {
    match e {
        Event::Alloc(n) => {
            let now = LIVE.fetch_add(n as isize, Ordering::Relaxed) + n as isize;
            PEAK.fetch_max(now, Ordering::Relaxed);
        }
        Event::Free(n) => {
            LIVE.fetch_sub(n as isize, Ordering::Relaxed);
        }
        Event::BeforeWipe(p, n) => check(p, n, &BEFORE),
        Event::AfterWipe(p, n) => check(p, n, &AFTER),
    }
}
fn install() {
    set_observer(Some(observe));
}

fn needles_of(secret: &[u8]) -> Vec<Vec<u8>> {
    let hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();
    vec![
        secret.to_vec(),
        encode_base64(secret).into_bytes(),
        encode_base64url(secret).into_bytes(),
        hex.into_bytes(),
    ]
}
/// Freed blocks holding `secret` (any encoding) during `f`: (before the wipe, after it).
fn scan(name: &str, secret: &[u8], f: impl FnOnce()) -> (usize, usize) {
    install();
    *NEEDLES.lock().unwrap() = needles_of(secret);
    BEFORE.store(0, Ordering::SeqCst);
    AFTER.store(0, Ordering::SeqCst);
    ARMED.store(true, Ordering::SeqCst);
    f();
    ARMED.store(false, Ordering::SeqCst);
    let r = (BEFORE.load(Ordering::SeqCst), AFTER.load(Ordering::SeqCst));
    println!("SCAN {name}: before the wipe {}, after {}", r.0, r.1);
    r
}
/// The binding's own code leaves nothing, and the allocator leaves nothing either.
fn clean(name: &str, secret: &[u8], f: impl FnOnce()) {
    let (b, a) = scan(name, secret, f);
    assert_eq!((b, a), (0, 0), "{name}");
}

extern "C" {
    fn uniffi_colophon_ffi_fn_method_accountengine_finish_unlock_slot(
        ptr: u64,
        index: u64,
        secrets: RustBuffer,
        st: &mut RustCallStatus,
    ) -> RustBuffer;
    fn uniffi_colophon_ffi_fn_method_accountengine_finish_unlock_epochs(
        ptr: u64,
        answers: RustBuffer,
        st: &mut RustCallStatus,
    ) -> RustBuffer;
    fn uniffi_colophon_ffi_fn_constructor_accountcreation_begin(
        params: RustBuffer,
        identity: RustBuffer,
        now_ms: i64,
        entropy: RustBuffer,
        st: &mut RustCallStatus,
    ) -> u64;
    fn uniffi_colophon_ffi_fn_method_accountcreation_provide_prf(
        ptr: u64,
        results: RustBuffer,
        st: &mut RustCallStatus,
    );
    fn uniffi_colophon_ffi_fn_method_swiftsource_finish_open_slot(
        ptr: u64,
        index: u64,
        secrets: RustBuffer,
        st: &mut RustCallStatus,
    );
}
/// The raw handle a foreign host holds for an object (`Handle` is `repr(transparent)` over u64).
fn handle<T: Send + Sync + 'static>(a: Arc<T>) -> u64
where
    Arc<T>: Lower<UniFfiTag>,
{
    let h = <Arc<T> as Lower<UniFfiTag>>::lower(a);
    unsafe { std::mem::transmute_copy(&h) }
}
fn ok(st: &RustCallStatus) {
    assert!(
        st.code == uniffi::RustCallStatusCode::Success,
        "the scaffolding call failed"
    );
}

fn params(host: &Host, d: &str) -> CreateParams {
    CreateParams {
        label: "A".into(),
        namespaces: vec!["notes".into()],
        controllers: vec![host.raw_controller(d, "Mac", &["approve", "control"])],
        slots: vec![SlotPlan {
            controllers: vec![d.to_string()],
            label: "Mac".into(),
        }],
        threshold: None,
        recover_threshold: None,
        add_threshold: None,
        count_by_holders: false,
        policy_json: String::new(),
        signers: vec![d.to_string()],
        rekey_signers: vec![d.to_string()],
    }
}
fn empty() -> SavedState {
    SavedState {
        verifier: vec![],
        checkpoint: vec![],
        parts: vec![],
    }
}
fn open(src: &MemSource, account: &str, identity: &str) -> Arc<AccountEngine> {
    AccountEngine::open(
        Box::new(src.clone()),
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
/// A controller account with an approved member; returns (src, account, controller id, member id).
fn world(host: &mut Host) -> (MemSource, String, String, String) {
    let d = host.identity(10);
    let m = host.identity(31);
    let creation = AccountCreation::begin(
        params(host, &d),
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
    let inputs = ctl.begin_unlock_slot(0).unwrap();
    ctl.finish_unlock_slot(0, host.answer_slot(&inputs))
        .unwrap();
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
    // The member writes one record, so that opening its shares reads something.
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

fn entries_of_keyring() -> (Vec<ByteString>, colophon_core::crypto::SoftwareKeys) {
    let root =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/keyring");
    let keys: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("keys.json")).unwrap()).unwrap();
    let mut files: Vec<_> = std::fs::read_dir(root.join("library/authority"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    files.sort();
    let entries = files
        .iter()
        .map(|p| {
            let mut b = std::fs::read(p).unwrap();
            if b.last() == Some(&b'\n') {
                b.pop();
            }
            ByteString { bytes: b }
        })
        .collect();
    let scalar = colophon_core::v05::encoding::decode_base64(
        keys["owner"]["agreementKey"].as_str().unwrap(),
        64,
    )
    .unwrap();
    (
        entries,
        colophon_core::crypto::SoftwareKeys::from_scalars(&scalar, &scalar).unwrap(),
    )
}

#[test]
fn the_scanner_sees_an_unwiped_block_and_the_allocator_wipes_it() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let secret = vec![0xA5u8; 32];
    let (b, a) = scan(
        "control: a Vec holding the secret is dropped",
        &secret,
        || {
            let v = secret.clone();
            drop(std::hint::black_box(v));
        },
    );
    assert!(b >= 1, "the scanner must see the block before the wipe");
    assert_eq!(a, 0, "the allocator wipes a freed block");
    // A grown Vec: the old block is freed by realloc and is wiped too.
    let (b, a) = scan(
        "control: a Vec that grows past its first block",
        &secret,
        || {
            let mut v = Vec::with_capacity(32);
            v.extend_from_slice(&secret);
            v.extend_from_slice(&[7u8; 4096]);
            drop(std::hint::black_box(v));
        },
    );
    assert!(b >= 1);
    assert_eq!(a, 0);
}

#[test]
fn every_rust_api_path_leaves_no_copy_in_a_freed_block_and_the_scaffolding_copy_is_wiped() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let mut host = Host::new();
    let (src, account, d, m) = world(&mut host);

    // finish_unlock_slot.
    let e = open(&src, &account, &format!("controller:{d}"));
    let ans = host.answer_slot(&e.begin_unlock_slot(0).unwrap());
    let secret = ans[0].secret.clone();
    clean("rust-api finish_unlock_slot", &secret, || {
        e.finish_unlock_slot(0, ans).unwrap();
    });
    let e = open(&src, &account, &format!("controller:{d}"));
    let ans = host.answer_slot(&e.begin_unlock_slot(0).unwrap());
    let secret = ans[0].secret.clone();
    let buf = <Vec<UnlockSecret> as Lower<UniFfiTag>>::lower(ans);
    let h = handle(e.clone());
    let (before, after) = scan(
        "scaffolding finish_unlock_slot (RustBuffer lift)",
        &secret,
        || {
            let mut st = RustCallStatus::default();
            let out = unsafe {
                uniffi_colophon_ffi_fn_method_accountengine_finish_unlock_slot(h, 0, buf, &mut st)
            };
            ok(&st);
            out.destroy();
        },
    );
    assert!(
        before >= 1,
        "the scaffolding leaves one freed transfer buffer: the allocator's job"
    );
    assert_eq!(after, 0);
    assert!(e.is_unlocked().unwrap());

    // finish_unlock_epochs: the Rust API, the scaffolding, and a refusal before the shares are
    // converted (a call from inside a callback, which is `Reentered`).
    let me = open(&src, &account, &format!("member:{m}"));
    let answers = host.answer_epochs(&m, &me.begin_unlock_epochs().unwrap());
    let share = answers[0].shared.clone();
    clean("rust-api finish_unlock_epochs", &share, || {
        me.finish_unlock_epochs(answers).unwrap();
    });
    let me = open(&src, &account, &format!("member:{m}"));
    let answers = host.answer_epochs(&m, &me.begin_unlock_epochs().unwrap());
    let share = answers[0].shared.clone();
    let buf = <Vec<EpochAnswer> as Lower<UniFfiTag>>::lower(answers);
    let h = handle(me.clone());
    let (before, after) = scan(
        "scaffolding finish_unlock_epochs (RustBuffer lift)",
        &share,
        || {
            let mut st = RustCallStatus::default();
            let out = unsafe {
                uniffi_colophon_ffi_fn_method_accountengine_finish_unlock_epochs(h, buf, &mut st)
            };
            ok(&st);
            out.destroy();
        },
    );
    assert!(before >= 1);
    assert_eq!(after, 0);

    #[derive(Clone)]
    struct Reenter {
        inner: MemSource,
        eng: Arc<OnceLock<Arc<AccountEngine>>>,
        second: Arc<Mutex<Option<Vec<EpochAnswer>>>>,
        result: Arc<Mutex<Option<String>>>,
    }
    impl HostSource for Reenter {
        fn read(&self, path: String) -> Result<Vec<u8>, AccountError> {
            let second = self.second.lock().unwrap().take();
            if let Some(a) = second {
                let e = self.eng.get().unwrap().clone();
                let r = e.finish_unlock_epochs(a);
                *self.result.lock().unwrap() = Some(r.err().map(|e| e.kind()).unwrap_or_default());
            }
            self.inner.read(path)
        }
        fn read_blob(&self, path: String) -> Result<Vec<u8>, AccountError> {
            self.inner.read_blob(path)
        }
    }
    let re = Reenter {
        inner: src.clone(),
        eng: Arc::new(OnceLock::new()),
        second: Arc::new(Mutex::new(None)),
        result: Arc::new(Mutex::new(None)),
    };
    let me = AccountEngine::open(
        Box::new(re.clone()),
        src.listing(),
        ident(&format!("member:{m}")),
        account.clone(),
        vec![],
        0,
        empty(),
        DEVICE_KEY.to_vec(),
        T0 + 3 * HOUR,
    )
    .unwrap();
    let _ = re.eng.set(me.clone());
    let first = host.answer_epochs(&m, &me.begin_unlock_epochs().unwrap());
    let second = host.answer_epochs(&m, &me.begin_unlock_epochs().unwrap());
    let share2 = second[0].shared.clone();
    *re.second.lock().unwrap() = Some(second);
    // The inner call is refused `Reentered` before it converts its shares; the outer call
    // proceeds. Neither may leave the inner share behind.
    clean(
        "error path: finish_unlock_epochs refused Reentered",
        &share2,
        || {
            me.finish_unlock_epochs(first).unwrap();
        },
    );
    assert_eq!(re.result.lock().unwrap().as_deref(), Some("Reentered"));

    // Error paths of finish_unlock_slot.
    let e = open(&src, &account, &format!("controller:{d}"));
    let ans = host.answer_slot(&e.begin_unlock_slot(0).unwrap());
    let secret = ans[0].secret.clone();
    clean(
        "error path: finish_unlock_slot, index out of range",
        &secret,
        || {
            let _ = e.finish_unlock_slot(u64::MAX, ans);
        },
    );
    let mut ans = host.answer_slot(&e.begin_unlock_slot(0).unwrap());
    let secret = ans[0].secret.clone();
    ans.push(UnlockSecret {
        kind: UnlockKind::Prf,
        secret: vec![1; 5],
    });
    clean(
        "error path: finish_unlock_slot, a malformed extra secret",
        &secret,
        || {
            let _ = e.finish_unlock_slot(0, ans);
        },
    );

    // The entropy of an action: the new epoch's seed, and the NEW vault seed of a rotation,
    // also when the call is refused.
    let ec = open(&src, &account, &format!("controller:{d}"));
    let ins = ec.begin_unlock_slot(0).unwrap();
    ec.finish_unlock_slot(0, host.answer_slot(&ins)).unwrap();
    let ent = host.fresh(32);
    let n = ent.clone();
    clean("begin_rekey (the new epoch's seed)", &n, || {
        let _a = ec
            .begin_rekey(vec!["notes".into()], vec![d.clone()], ent)
            .unwrap();
    });
    let ent = host.fresh(64);
    let n = ent[..32].to_vec();
    clean(
        "begin_rotate_vault refused (the new vault seed)",
        &n,
        || {
            let _ = ec.begin_rotate_vault(d.clone(), false, vec![], ent);
        },
    );
    let ent = host.fresh(64);
    let n = ent[..32].to_vec();
    clean(
        "begin_rotate_vault, unknown signer (the new vault seed)",
        &n,
        || {
            let _ = ec.begin_rotate_vault(
                "00000000000000000000000000000000".into(),
                false,
                vec![],
                ent,
            );
        },
    );
    let ent = host.fresh(64);
    let n = ent[..32].to_vec();
    clean(
        "begin_rotate_vault, a plan that does not convert (the new vault seed)",
        &n,
        || {
            let plans = vec![SlotPlan {
                controllers: vec![String::new(); 1000],
                label: String::new(),
            }];
            let _ = ec.begin_rotate_vault(d.clone(), true, plans, ent);
        },
    );

    // AccountCreation: the vault seed is the first 32 bytes of the entropy. The parameters the
    // creation holds are erased when it drops.
    let mut h2 = Host::new();
    let d2 = h2.identity(12);
    let ent = h2.fresh(96);
    let seed = ent[..32].to_vec();
    let p = params(&h2, &d2);
    clean(
        "AccountCreation.begin, dropped (the vault seed)",
        &seed,
        || {
            let _c =
                AccountCreation::begin(p, ident(&format!("controller:{d2}")), T0, ent).unwrap();
        },
    );
    let ent = h2.fresh(96);
    let seed = ent[..32].to_vec();
    let pbuf = <CreateParams as Lower<UniFfiTag>>::lower(params(&h2, &d2));
    let ibuf = <AccountIdentity as Lower<UniFfiTag>>::lower(ident(&format!("controller:{d2}")));
    let ebuf = <Vec<u8> as Lower<UniFfiTag>>::lower(ent);
    let (before, after) = scan(
        "scaffolding AccountCreation.begin (the vault seed)",
        &seed,
        || {
            let mut st = RustCallStatus::default();
            let _h = unsafe {
                uniffi_colophon_ffi_fn_constructor_accountcreation_begin(
                    pbuf, ibuf, T0, ebuf, &mut st,
                )
            };
            ok(&st);
        },
    );
    assert!(before >= 1);
    assert_eq!(after, 0);
    let mut ent = h2.fresh(96);
    ent.truncate(95);
    let seed = ent[..32].to_vec();
    let p = params(&h2, &d2);
    clean(
        "error path: AccountCreation.begin with 95 bytes",
        &seed,
        || {
            let _ = AccountCreation::begin(p, ident(&format!("controller:{d2}")), T0, ent);
        },
    );
    let ent = h2.fresh(96);
    let seed = ent[..32].to_vec();
    let p = params(&h2, &d2);
    // The core's by-value API moves `Creation` out of its box; the freed box keeps the old
    // bytes until the allocator wipes them. That is the compiler's move, not a copy the binding
    // made, and `after` is 0.
    let (before, after) = scan(
        "AccountCreation, begin to take_result (the vault seed)",
        &seed,
        || {
            let c = AccountCreation::begin(p, ident(&format!("controller:{d2}")), T0, ent).unwrap();
            loop {
                let steps = c.steps().unwrap();
                if c.provide_signatures(h2.sign(&steps)).unwrap() == CreateStage::Done {
                    break;
                }
            }
            let _ = c.take_result().unwrap();
        },
    );
    assert!(before <= 2, "only the two moved-from boxes: {before}");
    assert_eq!(after, 0);

    // provide_prf: a creation with a passkey slot (the Rust API, then the scaffolding).
    for ffi in [false, true] {
        let mut h3 = Host::new();
        let d3 = h3.identity(13);
        let p3 = h3.passkey();
        let mut cp = params(&h3, &d3);
        cp.controllers
            .push(h3.passkey_controller("Passkey", &["approve", "control", "recover"]));
        cp.slots.push(SlotPlan {
            controllers: vec![p3.clone()],
            label: "Passkey".into(),
        });
        let c = AccountCreation::begin(cp, ident(&format!("controller:{d3}")), T0, h3.fresh(96))
            .unwrap();
        let answers = h3.answer_prf(&c.prf_requests().unwrap());
        assert!(!answers.is_empty());
        let out = answers[0].output.clone();
        if ffi {
            let buf = <Vec<PrfAnswer> as Lower<UniFfiTag>>::lower(answers);
            let h = handle(c.clone());
            let (before, after) = scan(
                "scaffolding AccountCreation.provide_prf (RustBuffer lift)",
                &out,
                || {
                    let mut st = RustCallStatus::default();
                    unsafe {
                        uniffi_colophon_ffi_fn_method_accountcreation_provide_prf(h, buf, &mut st)
                    };
                    ok(&st);
                },
            );
            assert!(before >= 1);
            assert_eq!(after, 0);
        } else {
            clean("rust-api AccountCreation.provide_prf", &out, || {
                c.provide_prf(answers).unwrap();
            });
        }
    }

    // A Swift slot (the real conformance keyring, the owner's ECDH).
    let (entries, owner) = entries_of_keyring();
    let again = |e: &Vec<ByteString>| {
        e.iter()
            .map(|b| ByteString {
                bytes: b.bytes.clone(),
            })
            .collect()
    };
    let s1 = SwiftSource::read(again(&entries)).unwrap();
    let ins = s1.begin_open_slot(0).unwrap();
    let ecdh = owner.agree(&ins[0].enc).unwrap();
    let sec = vec![UnlockSecret {
        kind: UnlockKind::Ecdh,
        secret: ecdh.clone(),
    }];
    clean("rust-api SwiftSource.finish_open_slot", &ecdh, || {
        s1.finish_open_slot(0, sec).unwrap();
    });
    let s2 = SwiftSource::read(again(&entries)).unwrap();
    let ins = s2.begin_open_slot(0).unwrap();
    let ecdh = owner.agree(&ins[0].enc).unwrap();
    let buf = <Vec<UnlockSecret> as Lower<UniFfiTag>>::lower(vec![UnlockSecret {
        kind: UnlockKind::Ecdh,
        secret: ecdh.clone(),
    }]);
    let h = handle(s2.clone());
    let (before, after) = scan(
        "scaffolding SwiftSource.finish_open_slot (RustBuffer lift)",
        &ecdh,
        || {
            let mut st = RustCallStatus::default();
            unsafe {
                uniffi_colophon_ffi_fn_method_swiftsource_finish_open_slot(h, 0, buf, &mut st)
            };
            ok(&st);
        },
    );
    assert!(before >= 1);
    assert_eq!(after, 0);
    // 0.4's pattern, a top-level `Vec<u8>` lifted and then wiped, leaves the same one copy
    // before the allocator and none after it.
    let raw = vec![0x5Au8; 32];
    let b = <Vec<u8> as Lower<UniFfiTag>>::lower(raw.clone());
    let (before, after) = scan(
        "a top-level Vec<u8> lifted and wiped (0.4's pattern)",
        &raw,
        || {
            let mut v = <Vec<u8> as uniffi::Lift<UniFfiTag>>::try_lift(b).unwrap();
            v.fill(0);
            drop(std::hint::black_box(v));
        },
    );
    assert!(before >= 1);
    assert_eq!(after, 0);
}

#[test]
fn a_64_mib_argument_is_refused_on_its_raw_length_with_memory_near_its_own_size() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    install();
    let mut host = Host::new();
    let (src, account, _d, m) = world(&mut host);
    let member = open(&src, &account, &format!("member:{m}"));
    let big = "x".repeat(64 << 20);
    let baseline = LIVE.load(Ordering::SeqCst);
    PEAK.store(baseline, Ordering::SeqCst);
    let e = member
        .begin_write("notes".into(), "createNotebook".into(), big, host.fresh(32))
        .err()
        .unwrap();
    assert!(matches!(e, AccountError::Bound { .. }), "{e:?}");
    let extra = (PEAK.load(Ordering::SeqCst) - baseline).max(0) as usize;
    println!(
        "64 MiB payload refused; peak extra allocation above the argument itself: {extra} bytes"
    );
    assert!(
        extra < (1 << 20),
        "refusing must not allocate in proportion to the argument: {extra}"
    );
    let many = vec![String::new(); 300];
    assert!(matches!(
        member.begin_rekey(many, vec![], host.fresh(32)),
        Err(AccountError::Bound { .. })
    ));
    let blob = vec![ByteString {
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
    assert!(((PEAK.load(Ordering::SeqCst) - baseline).max(0) as usize) < (1 << 20));
}

/// A JSON array of strings: one structural element per 9 bytes, the densest the bound accepts
/// (it allows one per 8 bytes plus an allowance), each a heap string once parsed.
fn dense_array(bytes: usize) -> String {
    let mut s = String::with_capacity(bytes + 16);
    s.push('[');
    while s.len() + 24 < bytes {
        s.push_str("\"abcdef\",");
    }
    s.push_str("\"z\"]");
    s
}
/// A JSON object with a short key and value per entry: the densest object the bound accepts.
fn dense_object(bytes: usize) -> String {
    let mut s = String::with_capacity(bytes + 16);
    s.push('{');
    let mut i = 0u32;
    while s.len() + 24 < bytes {
        s.push_str(&format!("\"{i:05}\":1,"));
        i += 1;
    }
    s.push_str("\"zzzzzz\":1}");
    s
}

#[test]
fn json_lists_are_bounded_in_total_before_any_item_is_parsed_and_the_worst_accepted_peak_is_known()
{
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    install();
    let mut host = Host::new();
    let (src, account, d, m) = world(&mut host);
    let ctl = open(&src, &account, &format!("controller:{d}"));
    let ins = ctl.begin_unlock_slot(0).unwrap();
    ctl.finish_unlock_slot(0, host.answer_slot(&ins)).unwrap();
    let member = open(&src, &account, &format!("member:{m}"));
    member
        .finish_unlock_epochs(host.answer_epochs(&m, &member.begin_unlock_epochs().unwrap()))
        .unwrap();
    let peak_of = |f: &mut dyn FnMut()| {
        let baseline = LIVE.load(Ordering::SeqCst);
        PEAK.store(baseline, Ordering::SeqCst);
        f();
        (PEAK.load(Ordering::SeqCst) - baseline).max(0) as usize
    };
    // Eight 4 MiB items (the checker's 1,088 MiB case): refused on the total, before parsing.
    let mut items = Some(
        (0..8)
            .map(|_| dense_array(4 << 20))
            .collect::<Vec<String>>(),
    );
    let mut r = None;
    let extra = peak_of(&mut || {
        r = Some(ctl.begin_keyring(
            vec![],
            items.take().unwrap(),
            String::new(),
            vec![d.clone()],
            vec![],
        ));
    });
    assert!(matches!(r.unwrap(), Err(AccountError::Bound { .. })));
    println!("begin_keyring, eight 4 MiB slot items: refused Bound; peak above the arguments: {extra} bytes");
    assert!(extra < (1 << 20), "{extra}");
    // One 4 MiB slot item: over the 1 MiB bound.
    let mut one = Some(vec![dense_array(4 << 20)]);
    let mut r = None;
    let extra = peak_of(&mut || {
        r = Some(ctl.begin_keyring(
            vec![],
            one.take().unwrap(),
            String::new(),
            vec![d.clone()],
            vec![],
        ));
    });
    assert!(matches!(r.unwrap(), Err(AccountError::Bound { .. })));
    println!(
        "begin_keyring, one 4 MiB slot item: refused Bound; peak above the argument: {extra} bytes"
    );
    assert!(extra < (1 << 20), "{extra}");
    // Values the app writes, taken to completion (prepared, signed, finished): small numbers
    // compact (600 of them is 1.2 KB), 100,000 of them, one 1 MiB string, and the densest
    // 1 MiB object. Each is accepted; the peak is what the whole write costs above its text.
    let write = |extra: serde_json::Value, text_len: usize, name: &str, host: &mut Host| {
        let payload = json!({"id": "n", "title": "T", "extra": extra}).to_string();
        assert!(payload.len() <= MAX_JSON, "{name}: {}", payload.len());
        let mut done = None;
        let peak = peak_of(&mut || {
            let a = member
                .begin_write(
                    "notes".into(),
                    "createNotebook".into(),
                    payload.clone(),
                    host.fresh(32),
                )
                .unwrap();
            let w = member
                .finish(a.clone(), host.sign(&a.steps().unwrap()))
                .unwrap();
            done = Some(w.stores.len());
        });
        let over = peak.saturating_sub(payload.len());
        println!(
            "valid write, {name} ({} KiB text): written, peak above the text {} KiB ({:.1} times)",
            payload.len() >> 10,
            over >> 10,
            over as f64 / payload.len() as f64
        );
        assert!(done.is_some());
        let _ = text_len;
    };
    let nums = |n: usize| json!((0..n).map(|i| i % 10).collect::<Vec<_>>());
    write(nums(600), 0, "600 small numbers", &mut host);
    write(nums(100_000), 0, "100,000 small numbers", &mut host);
    write(
        json!("a".repeat(MAX_JSON - 200)),
        0,
        "one long string",
        &mut host,
    );
    let mut dense = serde_json::Map::new();
    let mut i = 0u32;
    while dense.len() * 11 + 8 < MAX_JSON - 400 {
        dense.insert(format!("{i:06}"), json!(1));
        i += 1;
    }
    write(
        serde_json::Value::Object(dense),
        0,
        "densest object",
        &mut host,
    );
    let mut arr = String::new();
    let mut strs = vec![];
    while arr.len() < MAX_JSON - 400 {
        strs.push("abcdef");
        arr.push_str("\"abcdef\",");
    }
    write(json!(strs), 0, "array of 6-byte strings", &mut host);
    // An authority document (a transition's `change`) is accepted by the bound the same way;
    // the account then refuses it as invalid, which is not `Bound`.
    for (name, doc) in [
        ("authority array", dense_array(MAX_AUTH_JSON)),
        ("authority object", dense_object(MAX_AUTH_JSON)),
    ] {
        let mut r = None;
        let peak = peak_of(&mut || {
            r = Some(
                ctl.begin_transition(doc.clone(), vec![d.clone()], RuleKind::Control, vec![])
                    .err(),
            );
        });
        assert!(
            !matches!(r.unwrap(), Some(AccountError::Bound { .. })),
            "{name}"
        );
        println!("{name} of {} KiB: accepted by the bound, refused by the account; peak above its text {} KiB", doc.len() >> 10, peak.saturating_sub(doc.len()) >> 10);
    }
    // One element per byte is no longer refused by shape: 1 MiB of `0,` is accepted (it costs
    // 16 MiB to parse, well inside the budget).
    let dense = format!("[{}0]", "0,".repeat(MAX_JSON / 2 - 2));
    assert!(dense.len() <= MAX_JSON);
    let e = member
        .begin_write(
            "notes".into(),
            "createNotebook".into(),
            dense,
            host.fresh(32),
        )
        .err()
        .unwrap();
    assert!(!matches!(e, AccountError::Bound { .. }), "{e:?}");
}
