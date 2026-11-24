//! A read-only (suspended) slot against the REAL relay (`relay/server.js` on Bun, the home module
//! in WebAssembly): an account provisions its slot through the door with the provisioning token,
//! appoints the home, and syncs two devices; the operator suspends the slot with the same token
//! (`POST /v1/operator/slots/<slot>/suspend`); a device's write is then refused with
//! `refused:subscriptionLapsed` while the other device still pulls everything already written, and
//! a member change to the account is still taken; the operator resumes the slot and the write
//! goes through.
#![allow(clippy::unwrap_used, clippy::too_many_arguments, dead_code)]
#[path = "../../colophon-core/tests/v05_engine_support/mod.rs"]
mod support;
mod support_relay;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use colophon_core::model::Outcome;
use colophon_core::v05::account::Change;
use colophon_core::v05::write::authority::TransitionRule;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use support::*;
use support_relay::*;

const NS: &str = "listening.podcasts";
/// The slot the helpers in `support_relay` address (`/v1/libraries/home`).
const SLOT: &str = "home";
const PREFIX: &str = "https://home-s.example/v1/libraries/";
/// A test token: it protects nothing.
const TOKEN: &str = "operator-token-0123456789abcdef";

fn base() -> String {
    format!("{PREFIX}{SLOT}")
}

fn bearer() -> Vec<(String, String)> {
    vec![("Authorization".into(), format!("Bearer {TOKEN}"))]
}

/// A relay with provisioning on behind gate "token" and no slot configured, on the test clock.
fn start(keys: &HomeKeys, dir: &std::path::Path, clock_ms: i64) -> (Child, u16) {
    let (relay, wasm) = prerequisites().expect("prerequisites");
    std::fs::create_dir_all(dir).unwrap();
    write_clock(&dir.join("clock"), clock_ms);
    let config = dir.join("config.json");
    let token_sha256: String = Sha256::digest(TOKEN.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    std::fs::write(
        &config,
        json!({
            "provision": {"enabled": true, "prefix": PREFIX, "slotPattern": "^[a-z]{4,64}$",
                "gate": "token", "tokenSha256": token_sha256},
            "limits": {"requestsPerMinute": 0},
        })
        .to_string(),
    )
    .unwrap();
    let mut child = Command::new("bun")
        .arg(relay)
        .arg("--test-clock")
        .arg("--config")
        .arg(&config)
        .env("COLOPHON_RELAY_PORT", "0")
        .env("COLOPHON_RELAY_DATA", dir.join("data"))
        .env_remove("COLOPHON_RELAY_HOME_SLOTS")
        .env("COLOPHON_HOME_KEY", keys.jwk())
        .env("COLOPHON_HOME_WASM", wasm)
        .env("COLOPHON_RELAY_CLOCK_FILE", dir.join("clock"))
        .env("COLOPHON_RELAY_TICK_MS", "0")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.as_mut().unwrap())
        .read_line(&mut line)
        .unwrap();
    let v: Value = serde_json::from_str(&line).expect("the listening line");
    (child, v["listening"]["port"].as_u64().unwrap() as u16)
}

/// Appoint the home with exactly the member request bytes the door answered.
fn appoint_with(f: &mut Fixture, request: &[u8]) {
    let change = Change::homes(
        json!({"appoint": [{"request": STANDARD.encode(request), "terms": {"serves": ["home"]}}]}),
    );
    let action = f
        .account
        .begin_transition(
            &change,
            &[f.d.clone(), f.k.clone()],
            TransitionRule::Control,
        )
        .unwrap();
    run(&mut f.account, &f.host, action);
    assert_eq!(f.account.record_due().unwrap().len(), 1);
}

fn q(e: &colophon_core::v05::engine::Engine<MemSource>, name: &str, args: Value) -> Value {
    match e.query(NS, name, args).unwrap() {
        Outcome::Success { value, .. } => value["value"].clone(),
        Outcome::Failure { reason, detail, .. } => panic!("{reason}: {detail}"),
    }
}

/// The operator's state of the slot (`GET /v1/operator/slots/<slot>`).
fn operator_state(port: u16) -> Value {
    let (status, _, body) = http(
        port,
        "GET",
        &format!("/v1/operator/slots/{SLOT}"),
        &bearer(),
        b"",
    );
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    serde_json::from_slice(&body).unwrap()
}

fn operate(port: u16, action: &str) {
    let (status, _, body) = http(
        port,
        "POST",
        &format!("/v1/operator/slots/{SLOT}/{action}"),
        &bearer(),
        b"",
    );
    assert_eq!(status, 204, "{action}: {}", String::from_utf8_lossy(&body));
}

#[test]
fn a_suspended_slot_refuses_writes_with_subscription_lapsed_serves_every_read_and_resumes() {
    if prerequisites().is_none() {
        return;
    }
    let keys = HomeKeys::new(0x5b);
    let scratch = Scratch::new("suspend-journey");
    let mut f = create_public(&[NS]);
    let account = f.account.id().as_str().to_string();
    let (mut child, port) = start(&keys, scratch.path(), f.account.now_ms());
    let relay = Relay::attached(port, &base(), &account, scratch.path());

    // The door, with the provisioning token.
    let mut headers = bearer();
    headers.push(("Content-Type".into(), "application/json".into()));
    let body = json!({"slot": SLOT, "base": base(), "account": account}).to_string();
    let (status, _, request) = http(port, "POST", "/v1/provision", &headers, body.as_bytes());
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&request));
    appoint_with(&mut f, &request);
    let phone_id = f.host.identity(31);
    let laptop_id = f.host.identity(32);
    for (id, label) in [(&phone_id, "Phone"), (&laptop_id, "Laptop")] {
        admit(
            &mut f,
            id,
            label,
            "device",
            terms_for(&[(NS, "write")]),
            terms_for(&[(NS, "write")]),
        );
    }
    let now = f.account.now_ms() + 1_000;
    first_upload(&relay, &f, now);
    assert_eq!(
        operator_state(port),
        json!({"slot": SLOT, "provisioned": true, "suspended": false})
    );

    let authority = MemSource::new();
    authority.store_account(&f.account);
    let source = || {
        let src = MemSource::new();
        for p in authority.listing() {
            src.put(&p, authority.get(&p).unwrap());
        }
        src
    };
    let (phone_src, laptop_src) = (source(), source());
    let mut phone = member_engine(&f, &f.host, &phone_src, &phone_id, now + 1_000);
    let mut host = std::mem::replace(&mut f.host, Host::new());
    let mut wire = RealRelay::new(&relay);

    // Before: the phone writes and syncs.
    engine_write(
        &mut phone,
        &mut host,
        &phone_src,
        NS,
        "follow",
        json!({"id": "show", "url": "https://example.org/feed", "title": "The Show"}),
    );
    let faults = relay_pass(
        &mut phone,
        &phone_src,
        &keys.id,
        &mut wire,
        &host,
        now + 2_000,
    );
    assert!(faults.is_empty(), "{faults:?}");

    // Suspended: read-only.
    operate(port, "suspend");
    assert_eq!(
        operator_state(port),
        json!({"slot": SLOT, "provisioned": true, "suspended": true})
    );

    // Every read still works: the laptop pulls what the phone wrote before the suspension.
    let mut laptop = member_engine(&f, &host, &laptop_src, &laptop_id, now + 3_000);
    let faults = relay_pass(
        &mut laptop,
        &laptop_src,
        &keys.id,
        &mut wire,
        &host,
        now + 3_000,
    );
    assert!(
        faults.is_empty(),
        "a pull from a suspended slot: {faults:?}"
    );
    let laptop_view = member_engine(&f, &host, &laptop_src, &laptop_id, now + 4_000);
    assert!(
        q(&laptop_view, "shows", json!({}))
            .to_string()
            .contains("The Show"),
        "the laptop reads the show from the suspended slot"
    );
    let (status, _) = relay.get("/head");
    assert_eq!(status, 200, "the head is served");

    // A write is refused, with the code the app shows as "sync is paused".
    engine_write(
        &mut phone,
        &mut host,
        &phone_src,
        NS,
        "follow",
        json!({"id": "second", "url": "https://example.org/second", "title": "The Second Show"}),
    );
    wire.requests.clear();
    let faults = relay_pass(
        &mut phone,
        &phone_src,
        &keys.id,
        &mut wire,
        &host,
        now + 5_000,
    );
    // The engine sends the write with its call (the home asked for one on the first write) and is
    // refused: a 403 to a request that carried a call ends that home's pass after its pulls, and
    // the engine reports it as the call refused. The session layers read the answer's
    // `refused:subscriptionLapsed` from the body (HomeRefusal) and show it as received.
    assert!(
        matches!(faults.as_slice(), [colophon_core::v05::engine::exchange::Fault::Unauthorized { purpose, .. }] if purpose == "colophon.home.write"),
        "the write is refused: {faults:?}"
    );
    assert!(
        wire.requests
            .last()
            .is_some_and(|r| r.starts_with("PUT /records/ops/")),
        "the pass pulled, then the write was refused: {:?}",
        wire.requests
    );
    // The account's authority history is never held back: a member change made now is uploaded
    // and taken, so a lapsed account can still appoint another home and revoke this one.
    std::mem::swap(&mut f.host, &mut host);
    f.account.advance(now + 5_500).unwrap();
    let from = entries_json(&f).last().unwrap().0 + 1;
    let tablet_id = f.host.identity(33);
    admit(
        &mut f,
        &tablet_id,
        "Tablet",
        "device",
        terms_for(&[(NS, "write")]),
        terms_for(&[(NS, "write")]),
    );
    std::mem::swap(&mut f.host, &mut host);
    let entries: Vec<Value> = entries_json(&f)
        .into_iter()
        .filter(|(s, _)| *s >= from)
        .map(|(_, e)| e)
        .collect();
    assert!(!entries.is_empty(), "the member change is an entry");
    relay.set_clock(now + 5_500);
    let (status, out) = relay.post(
        "/authority",
        &json!({"from": from, "entries": entries, "receipts": []}),
    );
    assert_eq!(status, 200, "an authority change while suspended: {out}");
    let (status, page) = relay.get(&format!("/authority?after={}", from - 1));
    assert_eq!(status, 200);
    let page: Value = serde_json::from_slice(&page).unwrap();
    assert_eq!(
        page["entries"].as_array().map(Vec::len),
        Some(entries.len()),
        "the home holds the member change: {page}"
    );
    let mut laptop = member_engine(&f, &host, &laptop_src, &laptop_id, now + 6_000);
    let faults = relay_pass(
        &mut laptop,
        &laptop_src,
        &keys.id,
        &mut wire,
        &host,
        now + 6_000,
    );
    assert!(faults.is_empty(), "{faults:?}");
    let laptop_view = member_engine(&f, &host, &laptop_src, &laptop_id, now + 6_000);
    assert!(
        !q(&laptop_view, "shows", json!({}))
            .to_string()
            .contains("The Second Show"),
        "nothing of the refused write was stored"
    );

    // Resumed: the phone's write goes through, and the laptop reads it.
    operate(port, "resume");
    let faults = relay_pass(
        &mut phone,
        &phone_src,
        &keys.id,
        &mut wire,
        &host,
        now + 7_000,
    );
    assert!(faults.is_empty(), "{faults:?}");
    let mut laptop = member_engine(&f, &host, &laptop_src, &laptop_id, now + 8_000);
    let faults = relay_pass(
        &mut laptop,
        &laptop_src,
        &keys.id,
        &mut wire,
        &host,
        now + 8_000,
    );
    assert!(faults.is_empty(), "{faults:?}");
    let laptop_view = member_engine(&f, &host, &laptop_src, &laptop_id, now + 9_000);
    assert!(
        q(&laptop_view, "shows", json!({}))
            .to_string()
            .contains("The Second Show"),
        "the laptop reads the write made after the resume"
    );
    let _ = child.kill();
    let _ = child.wait();
}
