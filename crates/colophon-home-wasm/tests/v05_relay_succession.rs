//! H2 item 5, against the real relay: a library moved from a Swift keyring (§15.1, §16.3) is
//! published to and fetched from a home. The successor's genesis is uploaded with the transition
//! appointing the home; the home receipts the genesis inside the succession window (§13.5) and
//! serves the receipt in `GET {base}/authority` `receipts`; a device publishes the predecessor's
//! entries by `PUT {base}/predecessor/authority/<8 digits>.json` under a controller's call; a
//! second device fetches the history, the receipt and the predecessor from the home alone and
//! sees the succession waiting; once it is due the first device writes F and publishes it, and
//! the second device, from the home, sees the succession verified (the home's fresh head after
//! the due time). A member's call cannot publish a predecessor entry, and a forged entry is
//! refused.
#![allow(
    clippy::unwrap_used,
    clippy::too_many_arguments,
    clippy::cloned_ref_to_slice_refs,
    dead_code,
    unused_imports
)]
#[path = "../../colophon-core/tests/v05_engine_support/mod.rs"]
mod support;
mod support_relay;
#[path = "../../colophon-core/tests/v05_e7_support/mod.rs"]
mod e7;
#[path = "../../colophon-core/tests/v05_swift_support/mod.rs"]
mod swift;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use colophon_core::v05::account::*;
use colophon_core::v05::descriptor::Controller;
use colophon_core::v05::encoding::{canonical, digest};
use colophon_core::v05::engine::exchange::{Fault, Method, Response, Step};
use colophon_core::v05::engine::{Engine, EngineOptions, RecordSource};
use colophon_core::v05::history::Objects;
use colophon_core::v05::slots::{PrfAssertion, PrfResult, SlotBuild, SlotPlan, SlotTarget};
use colophon_core::v05::swift_slots::*;
use colophon_core::v05::vault::VaultSeed;
use colophon_core::v05::write::authority::TransitionRule;
use colophon_core::v05::write::calls::RequestSpec;
use colophon_core::v05::write::succession::*;
use colophon_core::v05::write::{format_date, SignatureResult};
use serde_json::{json, Value};
use support::MemSource;
use support_relay::{http, prerequisites, ticks_until, HomeKeys, Relay, Scratch, BASE_A};
use swift::{body_digest, keyring_library_with, sha, Host, SwiftFixture};

const T0: i64 = 1_794_384_000_000; // 2026-11-11T08:00:00Z
const SEC: i64 = 1_000;
const RP: &str = "id.example";
const ORIGIN: &str = "https://id.example";

fn e7_id(n: u8) -> String {
    let k = p256::ecdsa::SigningKey::from_slice(&[n; 32]).unwrap();
    colophon_core::v05::ids::key_id(k.verifying_key().to_encoded_point(false).as_bytes())
}
/// The fixture's keys: software identities by the host, the passkey and the security key by
/// WebAuthn (scalars [9;32] and [10;32]).
fn sign(host: &Host, steps: &[colophon_core::v05::write::SigningStep]) -> Vec<SignatureResult> {
    steps
        .iter()
        .map(|s| match s.challenge() {
            None => SignatureResult {
                signature: host.sign(s.signer(), s.body()),
                assertion: None,
            },
            Some(ch) => {
                let rp = s.descriptor().unwrap().webauthn().unwrap().rp().to_string();
                let scalar = if s.signer() == e7_id(9) { [9u8; 32] } else { [10u8; 32] };
                e7::key_from_scalar(&scalar).sign_webauthn(&rp, &format!("https://{rp}"), 0x05, ch)
            }
        })
        .collect()
}
fn run(a: &mut Account, host: &Host, action: PendingAction) -> Finished {
    let sigs = sign(host, action.steps());
    a.finish(action, sigs).unwrap()
}
fn b64(b: &[u8]) -> String {
    STANDARD.encode(b)
}
fn body_of(env: &Value) -> Value {
    serde_json::from_slice(&STANDARD.decode(env["body"].as_str().unwrap()).unwrap()).unwrap()
}

/// The successor of a Swift keyring library, with the relay's key as its home: the genesis with
/// its hand-over, the slots rebuilt, the home appointed (the window opens at the activation).
fn successor(host: &mut Host, home: &HomeKeys) -> (Account, SwiftFixture, String) {
    let f = keyring_library_with(host, false, false, false);
    let pred = f.entries.clone();
    let lib = SwiftLibrary::read(&pred).unwrap();
    let ctl = f.device.id.clone();
    let mut opts = CarryOptions::default();
    for id in [&f.passkey_id, &f.security_id] {
        opts.authority_origins.insert(id.clone(), vec![ORIGIN.into()]);
    }
    let carried = swift_carried_controllers(&pred, &opts).unwrap();
    let new_seed = VaultSeed::from_host_random([0x77; 32]);
    let mut policy = default_policy();
    policy["recoveryDelay"] = json!(3600);
    // Public history: a device that holds nothing yet fetches it without a call (§13.4).
    policy["history"] = json!("public");
    let mut base = json!({"controllers": carried, "threshold": 1, "recoverThreshold": 1, "addThreshold": 1,
        "countBy": "keys", "policy": policy, "vault": new_seed.public().unwrap().to_value(), "slots": []});
    let controllers: std::collections::BTreeMap<String, Controller> = carried
        .iter()
        .map(|v| Controller::parse(v.clone(), "carried").unwrap())
        .map(|c| (c.id(), c))
        .collect();
    let target = SlotTarget::genesis(&new_seed, &controllers).unwrap();
    let mut slots = Vec::new();
    for (n, (id, label)) in [(ctl.clone(), "Device"), (f.passkey_id.clone(), "Passkey")].iter().enumerate() {
        let build = SlotBuild::begin(
            &SlotPlan { controllers: vec![id.clone()], label: label.to_string() },
            &target,
            [0x40 + n as u8; 32],
        )
        .unwrap();
        let results: Vec<PrfResult> = if id == &f.passkey_id {
            let (cers, _) = lib.pair_ceremonies(1, build.prf_requests()).unwrap();
            let c = &cers[0];
            let key = e7::key_from_scalar(&f.passkey_key.to_bytes());
            let client = canonical(&json!({"type": "webauthn.get", "origin": ORIGIN,
                "challenge": colophon_core::v05::encoding::encode_base64url(&c.new_request.challenge)}))
            .unwrap();
            let mut auth = sha(RP.as_bytes());
            auth.push(0x05);
            auth.extend([0, 0, 0, 0]);
            let a = key.sign_assertion(&auth, &client);
            let (ad, cd) = a.assertion.clone().unwrap();
            vec![PrfResult {
                assertion: PrfAssertion { authenticator_data: ad, client_data: cd, signature: a.signature },
                output: Host::prf(&c.new_request.salt),
            }]
        } else {
            vec![]
        };
        slots.push(build.finish(&new_seed, &results).unwrap().to_value().unwrap());
    }
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
    let sigs = sign(host, pending.steps());
    let genesis = pending.finish(sigs).unwrap().entries[0].1.clone();
    let mut acct = Account::open(
        Objects { entries: vec![genesis], predecessor: pred, ..Objects::default() },
        vec![],
        None,
        Identity::Controller(ctl.clone()),
        T0,
    )
    .unwrap();
    let ins = acct.begin_unlock_slot(0).unwrap();
    acct.finish_unlock_slot(0, &host.answer(&ins)).unwrap();
    // The home: the relay's key, an agreement point of the host's.
    let (_, _, agreement) = host.identity(70);
    let prepared = prepare_request(&RequestSpec {
        account: acct.id(),
        signing: &home.point,
        agreement: &agreement,
        label: "Home",
        kind: "server",
        terms: json!({"serves": ["home"]}),
        created: &format_date(acct.now_ms()),
        custody: None,
        operator: None,
        endpoints: Some(vec![BASE_A.into()]),
    })
    .unwrap();
    let req = finish_request(&prepared, &home.sign(prepared.step().body())).unwrap();
    let change = Change::homes(json!({"appoint": [{"request": b64(&req.raw), "terms": {"serves": ["home"]}}]}));
    let action = acct
        .begin_transition(&change, &[ctl.clone(), f.passkey_id.clone()], TransitionRule::Control)
        .unwrap();
    run(&mut acct, host, action);
    assert_eq!(acct.record_due().unwrap().len(), 1);
    assert_eq!(acct.swift_succession().unwrap().stage, MoveStage::Waiting);
    (acct, f, ctl)
}

/// The device's store: the account's files and the predecessor's entries.
fn store(src: &MemSource, a: &Account) {
    src.store_account(a);
    for e in &a.objects().predecessor {
        let seq = body_of(&serde_json::from_slice(e).unwrap())["seq"].as_u64().unwrap();
        src.put(&format!("predecessor/authority/{seq:08}.json"), e.clone());
    }
}

/// One pass with the home: every request sent to the relay, every call built and signed by the
/// controller `ctl` (its key held by `host`).
fn pass(e: &mut Engine<MemSource>, src: &MemSource, home_id: &str, relay: &Relay, host: &Host, ctl: &str, now: i64) -> (Vec<Fault>, Vec<String>) {
    e.advance(now).unwrap();
    e.refresh(src.listing()).unwrap();
    relay.set_clock(now);
    let mut faults = Vec::new();
    let mut sent = Vec::new();
    for _ in 0..10_000 {
        match e.exchange_next(home_id).unwrap() {
            Step::Done => return (faults, sent),
            Step::Waiting => panic!("the loop answers every request"),
            Step::NeedCall(n) => {
                let key = host.ids[ctl].public().signing;
                let mut rid = [0u8; 32];
                rid[..8].copy_from_slice(&(sent.len() as u64 + now as u64).to_le_bytes());
                rid[8] = 0x5c;
                let action = e.exchange_begin_call(home_id, n.ticket, &key, rid).unwrap();
                let sigs = sign(host, action.steps());
                let w = e.finish_write(action, sigs).expect("the engine's own check of its call");
                e.exchange_provide_call(home_id, n.ticket, &w.artifact.unwrap()).unwrap();
            }
            Step::Request(r) => {
                let rest = r.url.strip_prefix(BASE_A).expect("the home's URL").to_string();
                let method = match r.method {
                    Method::Get => "GET",
                    Method::Post => "POST",
                    Method::Put => "PUT",
                };
                sent.push(format!("{method} {}", rest.split('?').next().unwrap()));
                let (status, headers, body) = http(relay.port, method, &relay.url(&rest), &r.headers, &r.body);
                let report = e.exchange_answer(home_id, r.ticket, Response { status, headers, body }).unwrap();
                src.publish_stores(&report.store);
                faults.extend(report.faults);
            }
        }
    }
    panic!("a pass did not end");
}

/// What a device with nothing fetches from the home without a call under `public`: the history
/// with the genesis receipts (`GET /authority`), and the predecessor's entries through `through`.
fn fetch_all(relay: &Relay, src: &MemSource, through: u64) {
    let (s, _, b) = http(relay.port, "GET", &relay.url("/authority?after=0&limit=64"), &[], &[]);
    assert_eq!(s, 200);
    let v: Value = serde_json::from_slice(&b).unwrap();
    for e in v["entries"].as_array().unwrap() {
        let bytes = canonical(e).unwrap();
        src.put(&format!("authority/{:08}.json", support::entry_seq(&bytes)), bytes);
    }
    for r in v["receipts"].as_array().unwrap() {
        let bytes = canonical(r).unwrap();
        src.put(&support::pending_path(&bytes), bytes);
    }
    for seq in 1..=through {
        let (s, _, b) = http(relay.port, "GET", &relay.url(&format!("/predecessor/authority/{seq:08}.json")), &[], &[]);
        if s == 200 {
            src.put(&format!("predecessor/authority/{seq:08}.json"), b);
        }
    }
}

fn put_pred(relay: &Relay, seq: u64, e: &[u8]) -> (u16, String) {
    let (s, _, b) = http(relay.port, "PUT", &relay.url(&format!("/predecessor/authority/{seq:08}.json")),
        &[("Content-Type".into(), "application/json".into())], e);
    (s, String::from_utf8_lossy(&b).to_string())
}
/// Publish the predecessor to a home before its first upload: from the claimed head down.
fn stage(relay: &Relay, acct: &Account) {
    let mut by_seq: Vec<(u64, Vec<u8>)> = acct
        .objects()
        .predecessor
        .iter()
        .map(|e| (body_of(&serde_json::from_slice(e).unwrap())["seq"].as_u64().unwrap(), e.clone()))
        .collect();
    by_seq.sort_by_key(|(s, _)| std::cmp::Reverse(*s));
    for (seq, e) in by_seq {
        let (s, b) = put_pred(relay, seq, &e);
        assert_eq!(s, 201, "seq {seq}: {b}");
        let (s, _, _) = http(relay.port, "GET", &relay.url(&format!("/predecessor/authority/{seq:08}.json")), &[], &[]);
        assert_eq!(s, 404, "held, not served, before the home is appointed");
    }
}
/// Fake predecessor entries: the genuine one at a seq with its `issued` changed, the signature
/// kept. Four at seq 1, one at the claimed head.
fn fakes_of(acct: &Account, head_seq: u64) -> Vec<(u64, Vec<u8>)> {
    let mut out = Vec::new();
    for e in &acct.objects().predecessor {
        let v: Value = serde_json::from_slice(e).unwrap();
        let mut b = body_of(&v);
        let seq = b["seq"].as_u64().unwrap();
        let n = if seq == 1 { 4 } else if seq == head_seq { 1 } else { 0 };
        for i in 0..n {
            b["issued"] = json!(format!("2026-10-0{}T00:00:00Z", i + 1));
            let mut f = v.clone();
            f["body"] = json!(b64(&canonical(&b).unwrap()));
            out.push((seq, canonical(&f).unwrap()));
        }
    }
    out
}

fn open_device(src: &MemSource, a: &Account, ctl: &str, host: &Host, now: i64) -> Engine<MemSource> {
    let mut e = Engine::open(
        src.clone(),
        src.listing(),
        Identity::Controller(ctl.to_string()),
        EngineOptions::new(a.id().as_str(), [0x66; 32]),
        None,
        now,
    )
    .unwrap();
    let ins = e.begin_unlock_slot(0).unwrap();
    e.finish_unlock_slot(0, &host.answer(&ins)).unwrap();
    e
}

#[test]
fn a_swift_library_moved_is_published_to_and_fetched_from_a_real_home() {
    if prerequisites().is_none() {
        return;
    }
    let keys = HomeKeys::new(0x79);
    let mut host = Host::new();
    let (mut acct, f, ctl) = successor(&mut host, &keys);
    let account = acct.id().as_str().to_string();
    let status = acct.swift_succession().unwrap().status;
    let t = status.timing.clone().unwrap();
    let genesis = status.genesis_digest.clone();
    let scratch = Scratch::new("succession");
    // The first upload, 30 s into the succession window.
    let relay = Relay::start(&keys, &account, BASE_A, scratch.path(), t.window_start_ms + 30 * SEC, &[]);
    let entries: Vec<Value> = {
        let mut v: Vec<(u64, Value)> = acct
            .objects()
            .entries
            .iter()
            .map(|e| (support::entry_seq(e), serde_json::from_slice(e).unwrap()))
            .collect();
        v.sort_by_key(|(s, _)| *s);
        v.into_iter().map(|(_, e)| e).collect()
    };
    // An attacker with HTTP access stages fake predecessor entries before anyone uploads: four
    // at seq 1 and one at the claimed head (the genuine entries with a field changed).
    let fakes: Vec<(u64, Vec<u8>)> = fakes_of(&acct, status.head_seq);
    for (seq, fake) in &fakes {
        assert_ne!(put_pred(&relay, *seq, fake).0 / 100, 2, "nothing unverifiable is staged before the genesis");
    }
    // Without its predecessor the genesis cannot be verified (§15.1): the first upload is refused
    // (422 `unavailable`) and only the provisioned account's genesis is held. The predecessor is
    // then published from its head down (no call: the home knows nobody yet), every fake refused
    // because it is not the entry the claimed chain names; then the upload.
    let (s, out) = relay.post("/authority", &json!({"from": 1, "entries": entries, "receipts": []}));
    assert_eq!((s, out["result"].as_str()), (422, Some("unavailable")), "{out}");
    for (seq, fake) in &fakes {
        assert_ne!(put_pred(&relay, *seq, fake).0 / 100, 2, "a fake does not fit the claimed chain");
    }
    stage(&relay, &acct);
    for (seq, fake) in &fakes {
        assert_ne!(put_pred(&relay, *seq, fake).0 / 100, 2, "nor once the genuine entry is there");
    }
    let (s, out) = relay.post("/authority", &json!({"from": 1, "entries": entries, "receipts": []}));
    assert_eq!(s, 200, "{out}");
    // The home receipted the genesis inside the window, once, and serves the receipt.
    let receipts = out["receipts"].as_array().unwrap().clone();
    assert_eq!(receipts.len(), 1, "{out}");
    let r = body_of(&receipts[0]);
    assert_eq!((r["object"].as_str(), r["by"].as_str()), (Some(genesis.as_str()), Some(keys.id.as_str())));
    assert_eq!(relay.post("/authority", &json!({"from": 1, "entries": entries, "receipts": []})).1["receipts"], json!([]), "one receipt per object");
    // A device's pass: the home already lists the predecessor's entries (stored at the
    // appointment, in the change feed).
    let src1 = MemSource::new();
    store(&src1, &acct);
    let now = t.window_start_ms + 60 * SEC;
    let mut d1 = open_device(&src1, &acct, &ctl, &host, now);
    let (faults, sent) = pass(&mut d1, &src1, &keys.id, &relay, &host, &ctl, now);
    assert!(faults.is_empty(), "{faults:?} {sent:?}");
    let puts = sent.iter().filter(|s| s.starts_with("PUT /predecessor/")).count();
    assert_eq!(puts, 0, "the home lists every predecessor entry it holds, so none is sent again: {sent:?}");
    for (i, e) in acct.objects().predecessor.iter().enumerate() {
        let seq = body_of(&serde_json::from_slice(e).unwrap())["seq"].as_u64().unwrap();
        let (s, _, b) = http(relay.port, "GET", &relay.url(&format!("/records/predecessor/authority/{seq:08}.json")), &[], &[]);
        let _ = i;
        if s == 200 {
            assert_eq!(serde_json::from_slice::<Value>(&b).unwrap(), serde_json::from_slice::<Value>(e).unwrap());
        } else {
            assert_eq!(s, 401, "the history needs a call under `members`");
        }
    }
    // A second device, holding nothing, fetches the history, the genesis receipt and the
    // predecessor from the home (public paths, no call), opens the account and passes.
    let src2 = MemSource::new();
    fetch_all(&relay, &src2, status.head_seq + 1);
    let mut d2 = open_device(&src2, &acct, &ctl, &host, now + SEC);
    let (faults, _) = pass(&mut d2, &src2, &keys.id, &relay, &host, &ctl, now + SEC);
    assert!(faults.is_empty(), "{faults:?}");
    assert_eq!(d2.account().head(), acct.head(), "the successor's history, from the home");
    assert_eq!(d2.account().objects().predecessor.len(), acct.objects().predecessor.len(), "the predecessor, from the home");
    let s2 = d2.account().swift_succession().unwrap();
    assert_eq!(s2.stage, MoveStage::Waiting, "{s2:?}");
    // Due: the first device writes F (the freezing `layout`) and publishes it to the home.
    let at = t.due_ms + 120 * SEC;
    acct.merge(
        Incoming {
            objects: Objects { pending: vec![canonical(&receipts[0]).unwrap()], ..Objects::default() },
            records: vec![],
        },
        at,
    )
    .unwrap();
    acct.advance(at).unwrap();
    assert_eq!(acct.swift_succession().unwrap().stage, MoveStage::Due);
    let p = acct.begin_swift_freeze(vec![], vec![ctl.clone()], t.due_ms + 61 * SEC).unwrap();
    let sigs = sign(&host, p.steps());
    let Moved::Frozen(frozen) = acct.finish_move(p, sigs).unwrap() else { panic!() };
    let fseq = status.head_seq + 1;
    src1.put(&format!("predecessor/authority/{fseq:08}.json"), frozen.entry.clone());
    let mut d1 = open_device(&src1, &acct, &ctl, &host, at);
    let (faults, sent) = pass(&mut d1, &src1, &keys.id, &relay, &host, &ctl, at);
    assert!(faults.is_empty(), "{faults:?}");
    assert!(sent.iter().any(|s| *s == format!("PUT /predecessor/authority/{fseq:08}.json")), "{sent:?}");
    // The second device, from the home: F and the home's fresh head after the due time.
    fetch_all(&relay, &src2, status.head_seq + 1);
    let mut d2 = open_device(&src2, &acct, &ctl, &host, at + SEC);
    let (faults, _) = pass(&mut d2, &src2, &keys.id, &relay, &host, &ctl, at + SEC);
    assert!(faults.is_empty(), "{faults:?}");
    assert_eq!(d2.account().swift_succession().unwrap().stage, MoveStage::Verified);
    // Who may publish a predecessor entry: a member's call is refused (the home's own key, a
    // current member); a controller's call for another entry at F's seq is a conflict.
    let mut other: Value = serde_json::from_slice(&frozen.entry).unwrap();
    let mut b = body_of(&other);
    b["issued"] = json!(format_date(t.due_ms + 62 * SEC));
    other["body"] = json!(b64(&canonical(&b).unwrap()));
    let bytes = canonical(&other).unwrap();
    let path = format!("/predecessor/authority/{fseq:08}.json");
    let (seq, dg) = acct.head();
    let call = |kind: &str, id: &str, point: &[u8], signer: &dyn Fn(&[u8]) -> Vec<u8>, n: u8| -> String {
        use sha2::Digest as _;
        let hexd: String = sha2::Sha256::digest(&bytes).iter().map(|x| format!("{x:02x}")).collect();
        let body = canonical(&json!({
            "protocol": "colophon/call/5", "account": account, "asOf": {"seq": seq, "digest": dg},
            "signer": {kind: id}, "key": b64(point), "audience": BASE_A, "purpose": "colophon.home.write",
            "args": {"method": "PUT", "path": path, "body": hexd},
            "requestId": URL_SAFE_NO_PAD.encode([n; 32]), "created": format_date(at + 2 * SEC),
        }))
        .unwrap();
        let env = serde_json::to_vec(&json!({"body": b64(&body), "signature": b64(&signer(&body))})).unwrap();
        format!("Colophon {}", URL_SAFE_NO_PAD.encode(env))
    };
    relay.set_clock(at + 2 * SEC);
    let put = |auth: String| {
        let (s, _, b) = http(relay.port, "PUT", &relay.url(&path),
            &[("Content-Type".into(), "application/json".into()), ("Authorization".into(), auth)], &bytes);
        (s, serde_json::from_slice::<Value>(&b).unwrap_or(Value::Null))
    };
    let member = call("member", &keys.id, &keys.point, &|b| keys.sign(b).signature, 1);
    let (s, out) = put(member);
    assert_eq!(s, 403, "a member publishes no predecessor entry: {out}");
    let ctl_point = host.ids[&ctl].public().signing;
    let controller = call("controller", &ctl, &ctl_point, &|b| host.sign(&ctl, b), 2);
    assert_eq!(put(controller).0, 412, "another entry at F's seq");
    let (s, _, b) = http(relay.port, "GET", &relay.url(&path), &[], &[]);
    assert_eq!((s, serde_json::from_slice::<Value>(&b).unwrap()), (200, serde_json::from_slice::<Value>(&frozen.entry).unwrap()), "F is kept");
    let _ = (&f, digest(b""));
}

/// A veto of the succession, signed by the owner's old passkey inside the window: the successor's
/// home stores and receipts it, and records the one `successionVetoed` (§15.1 step 4); the
/// succession is then never verified.
#[test]
fn a_successor_home_records_successionvetoed_for_a_valid_veto() {
    if prerequisites().is_none() {
        return;
    }
    let keys = HomeKeys::new(0x79);
    let mut host = Host::new();
    let (mut acct, f, _ctl) = successor(&mut host, &keys);
    let account = acct.id().as_str().to_string();
    let t = acct.swift_succession().unwrap().status.timing.clone().unwrap();
    let scratch = Scratch::new("succession-veto");
    let relay = Relay::start(&keys, &account, BASE_A, scratch.path(), t.window_start_ms + 30 * SEC, &[]);
    // The first upload holds the genesis; the predecessor follows from its head down.
    let _ = relay.post("/authority", &json!({"from": 1, "entries": [serde_json::from_slice::<Value>(&acct.objects().entries.iter().find(|e| support::entry_seq(e) == 1).unwrap().clone()).unwrap()], "receipts": []}));
    stage(&relay, &acct);
    let mut entries: Vec<(u64, Value)> = acct
        .objects()
        .entries
        .iter()
        .map(|e| (support::entry_seq(e), serde_json::from_slice(e).unwrap()))
        .collect();
    entries.sort_by_key(|(s, _)| *s);
    let entries: Vec<Value> = entries.into_iter().map(|(_, e)| e).collect();
    let n = entries.len();
    assert_eq!(relay.post("/authority", &json!({"from": 1, "entries": entries, "receipts": []})).0, 200);
    // The owner's old passkey vetoes the succession, inside the window.
    let veto_at = t.window_start_ms + 60 * SEC;
    acct.advance(veto_at).unwrap();
    let pending = acct
        .begin_swift_veto(&colophon_core::v05::write::swift_veto::SwiftVetoParams {
            issued_ms: veto_at,
            signers: vec![f.passkey_id.clone()],
        })
        .unwrap();
    let k = e7::key_from_scalar(&f.passkey_key.to_bytes());
    let sigs: Vec<SignatureResult> = pending
        .steps()
        .iter()
        .map(|s| match s.challenge() {
            None => SignatureResult { signature: host.sign(s.signer(), s.body()), assertion: None },
            Some(ch) => {
                let rp = s.descriptor().unwrap().webauthn().unwrap().rp().to_string();
                k.sign_webauthn(&rp, &format!("https://{rp}"), 0x05, ch)
            }
        })
        .collect();
    let veto = pending.finish(sigs).unwrap();
    relay.set_clock(veto_at + 10 * SEC);
    let (s, out) = relay.post("/pending", &json!({"objects": [serde_json::from_slice::<Value>(&veto).unwrap()]}));
    assert_eq!(s, 200, "{out}");
    assert_eq!(out["receipts"].as_array().map(Vec::len), Some(1), "the home receipts the veto");
    ticks_until("successionVetoed recorded", 5, &[&relay], || {
        let (s, _, b) = http(relay.port, "GET", &relay.url("/authority?after=0&limit=64"), &[], &[]);
        s == 200
            && serde_json::from_slice::<Value>(&b).unwrap()["entries"]
                .as_array()
                .unwrap()
                .get(n)
                .is_some_and(|e| body_of(e)["kind"] == "successionVetoed")
    });
}

/// Staging survives kills: the relay is killed (SIGKILL) and started again after the genesis is
/// held and after every predecessor entry is staged; each entry sent again is acknowledged as held
/// (200), and the first upload then appoints the home and receipts the genesis.
#[test]
fn predecessor_staging_survives_kills() {
    if prerequisites().is_none() {
        return;
    }
    let keys = HomeKeys::new(0x79);
    let mut host = Host::new();
    let (acct, _f, _ctl) = successor(&mut host, &keys);
    let account = acct.id().as_str().to_string();
    let t = acct.swift_succession().unwrap().status.timing.clone().unwrap();
    let scratch = Scratch::new("succession-kills");
    let at = t.window_start_ms + 30 * SEC;
    let mut relay = Relay::start_on(&keys, &account, BASE_A, scratch.path(), at, &[], 0);
    let mut entries: Vec<(u64, Value)> = acct.objects().entries.iter()
        .map(|e| (support::entry_seq(e), serde_json::from_slice(e).unwrap())).collect();
    entries.sort_by_key(|(s, _)| *s);
    let entries: Vec<Value> = entries.into_iter().map(|(_, e)| e).collect();
    assert_eq!(relay.post("/authority", &json!({"from": 1, "entries": entries, "receipts": []})).0, 422);
    relay = relay.restart(&keys, at, &[]);
    let mut by_seq: Vec<(u64, Vec<u8>)> = acct.objects().predecessor.iter()
        .map(|e| (body_of(&serde_json::from_slice(e).unwrap())["seq"].as_u64().unwrap(), e.clone())).collect();
    by_seq.sort_by_key(|(s, _)| std::cmp::Reverse(*s));
    for (seq, e) in &by_seq {
        assert_eq!(put_pred(&relay, *seq, e).0, 201, "seq {seq}");
        relay = relay.restart(&keys, at, &[]);
        assert_eq!(put_pred(&relay, *seq, e).0, 200, "seq {seq} is still held after a kill");
    }
    let (s, out) = relay.post("/authority", &json!({"from": 1, "entries": entries, "receipts": []}));
    assert_eq!(s, 200, "{out}");
    assert_eq!(out["receipts"].as_array().map(Vec::len), Some(1));
}
