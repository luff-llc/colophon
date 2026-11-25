//! An account's removal of its hosted home, and the operator's deletion of the slot, against the
//! REAL relay (`relay/server.js` on Bun, the home module in WebAssembly). Operator behaviour of
//! the reference home, not protocol: an account provisions its slot through the door with the
//! provisioning token and appoints the home; the operator reads the home's standing in the
//! account (`GET /v1/operator/slots/<slot>`: "home"); the account's controllers revoke the home
//! (a `homes.revoke` transition) and upload it to the home, which still takes authority uploads;
//! the standing is then the revocation as the home verified it; the operator suspends the slot
//! and deletes it (`DELETE /v1/operator/slots/<slot>?generation=`), its data and its row.
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
const PREFIX: &str = "https://home-d.example/v1/libraries/";
/// A test token: it protects nothing.
const TOKEN: &str = "operator-token-0123456789abcdef";

fn base() -> String {
    format!("{PREFIX}{SLOT}")
}

fn bearer() -> Vec<(String, String)> {
    vec![("Authorization".into(), format!("Bearer {TOKEN}"))]
}

/// A relay with provisioning on behind gate "token" and no slot configured, on the test clock.
/// Returns the process, the public port and the private port.
fn start(keys: &HomeKeys, dir: &std::path::Path, clock_ms: i64) -> (Child, u16, u16) {
    start_with(keys, dir, clock_ms, json!({"requestsPerMinute": 0}))
}

fn start_with(
    keys: &HomeKeys,
    dir: &std::path::Path,
    clock_ms: i64,
    limits: Value,
) -> (Child, u16, u16) {
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
            "limits": limits,
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
        .env("COLOPHON_PRIVATE_LISTEN", "127.0.0.1:0")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.as_mut().unwrap())
        .read_line(&mut line)
        .unwrap();
    let v: Value = serde_json::from_str(&line).expect("the listening line");
    (
        child,
        v["listening"]["port"].as_u64().unwrap() as u16,
        v["listening"]["private"]["port"].as_u64().unwrap() as u16,
    )
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

/// The operator's state of the slot (`GET /v1/operator/slots/<slot>`), on the private listener.
fn operator_state(port: u16) -> Value {
    let (status, _, body) = http(
        port,
        "GET",
        &format!("/v1/operator/slots/{SLOT}"),
        &bearer(),
        b"",
    );
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let mut v: Value = serde_json::from_slice(&body).unwrap();
    let generation = v
        .as_object_mut()
        .unwrap()
        .remove("generation")
        .expect("a generation");
    assert!(generation.as_str().is_some_and(|g| g.len() == 32));
    v
}

/// Suspend or resume with the slot's current generation, as the provisioner does.
fn operate(port: u16, action: &str) {
    let (_, _, body) = http(
        port,
        "GET",
        &format!("/v1/operator/slots/{SLOT}"),
        &bearer(),
        b"",
    );
    let generation = serde_json::from_slice::<Value>(&body).unwrap()["generation"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, _, body) = http(
        port,
        "POST",
        &format!("/v1/operator/slots/{SLOT}/{action}?generation={generation}"),
        &bearer(),
        b"",
    );
    assert_eq!(status, 204, "{action}: {}", String::from_utf8_lossy(&body));
}

fn generation(private: u16) -> String {
    operator_read(private)["generation"]
        .as_str()
        .unwrap()
        .to_string()
}

fn operator_read(private: u16) -> Value {
    let (status, _, body) = http(
        private,
        "GET",
        &format!("/v1/operator/slots/{SLOT}"),
        &bearer(),
        b"",
    );
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    serde_json::from_slice(&body).unwrap()
}

fn delete(private: u16, generation: &str) -> (u16, Value) {
    let (status, _, b) = http(
        private,
        "DELETE",
        &format!("/v1/operator/slots/{SLOT}?generation={generation}"),
        &bearer(),
        b"",
    );
    (status, serde_json::from_slice(&b).unwrap_or(Value::Null))
}

/// Upload the account's entries from `from` to the slot, in pages of 64.
fn upload_from(relay: &Relay, f: &Fixture, from: u64, now: i64) {
    relay.set_clock(now);
    let all: Vec<(u64, Value)> = entries_json(f)
        .into_iter()
        .filter(|(s, _)| *s >= from)
        .collect();
    for chunk in all.chunks(64) {
        let entries: Vec<&Value> = chunk.iter().map(|(_, e)| e).collect();
        let (status, body) = relay.post(
            "/authority",
            &json!({"from": chunk[0].0, "entries": entries, "receipts": []}),
        );
        assert_eq!(status, 200, "upload from {}: {body}", chunk[0].0);
    }
}

#[test]
fn the_account_revokes_its_hosted_home_the_home_reports_it_and_the_suspended_slot_is_deleted() {
    if prerequisites().is_none() {
        return;
    }
    let keys = HomeKeys::new(0x5d);
    let scratch = Scratch::new("delete-journey");
    let mut f = create_public(&[NS]);
    let account = f.account.id().as_str().to_string();
    let (mut child, port, private) = start(&keys, scratch.path(), f.account.now_ms());
    let relay = Relay::attached(port, &base(), &account, scratch.path());

    let mut headers = bearer();
    headers.push(("Content-Type".into(), "application/json".into()));
    let body = json!({"slot": SLOT, "base": base(), "account": account}).to_string();
    let (status, _, request) = http(private, "POST", "/v1/provision", &headers, body.as_bytes());
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&request));
    let g = generation(private);
    assert_eq!(
        operator_read(private)["standing"],
        json!("unappointed"),
        "before the first upload"
    );

    appoint_with(&mut f, &request);
    let phone = f.host.identity(31);
    admit(
        &mut f,
        &phone,
        "Phone",
        "device",
        terms_for(&[(NS, "write")]),
        terms_for(&[(NS, "write")]),
    );
    let now = f.account.now_ms() + 1_000;
    first_upload(&relay, &f, now);
    assert_eq!(
        operator_read(private)["standing"],
        json!("home"),
        "appointed"
    );
    assert_eq!(generation(private), g, "appointing changes no generation");

    // The account's controllers remove this home: a `homes.revoke` transition signed by the full
    // set, recorded with no receipt (an app's owner alone submits it to the home for its receipt
    // first), and uploaded to it.
    let from = entries_json(&f).last().unwrap().0 + 1;
    let change = Change::homes(json!({"revoke": [keys.id]}));
    let action = f
        .account
        .begin_transition(
            &change,
            &[f.d.clone(), f.p.clone(), f.k.clone()],
            TransitionRule::Control,
        )
        .unwrap();
    run(&mut f.account, &f.host, action);
    assert_eq!(
        f.account.record_due().unwrap().len(),
        1,
        "the full set's activation"
    );
    assert!(f.account.homes().is_empty(), "the account names no home");
    let now = f.account.now_ms() + 1_000;
    upload_from(&relay, &f, from, now);
    let standing = operator_read(private)["standing"].clone();
    assert!(
        standing == json!("revocationPending") || standing == json!("revoked"),
        "the home reports the account's removal of it: {standing}"
    );

    // The delete follows a suspension; then the appointed slot goes, data and row.
    assert_eq!(
        delete(private, &g),
        (409, json!({"result": "refused:notSuspended"}))
    );
    operate(private, "suspend");
    assert_eq!(
        delete(private, &"f".repeat(32)),
        (409, json!({"result": "refused:staleGeneration"}))
    );
    assert!(scratch.path().join("data").join(SLOT).exists());
    assert_eq!(delete(private, &g).0, 204);
    assert!(
        !scratch.path().join("data").join(SLOT).exists(),
        "the slot's data is gone"
    );
    let table: Value = serde_json::from_slice(
        &std::fs::read(scratch.path().join("data/provisioned.json")).unwrap(),
    )
    .unwrap();
    assert!(table.get(SLOT).is_none(), "and its row");
    let (status, _) = relay.get("/head");
    assert_eq!(status, 404, "nothing is served for it");
    assert_eq!(
        delete(private, &g),
        (404, json!({"result": "refused:notProvisioned"}))
    );

    // The name can be provisioned again, with a new generation.
    let (status, _, _) = http(private, "POST", "/v1/provision", &headers, body.as_bytes());
    assert_eq!(status, 200);
    assert_ne!(generation(private), g);
    let _ = child.kill();
    let _ = child.wait();
}
