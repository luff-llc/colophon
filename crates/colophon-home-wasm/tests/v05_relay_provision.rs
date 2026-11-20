//! Provisioning against the REAL relay (`relay/server.js` on Bun, the home module in
//! WebAssembly): a relay started with no slot at all, an account that asks the door
//! (`POST /v1/provision`) for its slot, appoints the home with exactly the member request the door
//! answered, makes its first upload, and syncs two devices, with no restart anywhere. Then the
//! door's durability: the relay killed between the durable write of `provisioned.json` and the
//! answer, and the same request completing after the restart.
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
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};
use support::*;
use support_relay::*;

const NS: &str = "listening.podcasts";
/// The slot the helpers in `support_relay` address (`/v1/libraries/home`); this test allows
/// four-letter names with `slotPattern`.
const SLOT: &str = "home";
const PREFIX: &str = "https://home-p.example/v1/libraries/";

fn base() -> String {
    format!("{PREFIX}{SLOT}")
}

/// A relay with provisioning on and no slot configured, on the test clock. `crash_at` names a
/// trace point where the process kills itself (the relay's test hook).
fn start(
    keys: &HomeKeys,
    dir: &std::path::Path,
    clock_ms: i64,
    crash_at: Option<&str>,
) -> (Child, u16) {
    let (relay, wasm) = prerequisites().expect("prerequisites");
    std::fs::create_dir_all(dir).unwrap();
    write_clock(&dir.join("clock"), clock_ms);
    let config = dir.join("config.json");
    std::fs::write(
        &config,
        json!({
            "provision": {"enabled": true, "prefix": PREFIX, "slotPattern": "^[a-z]{4,64}$"},
            "limits": {"requestsPerMinute": 0},
        })
        .to_string(),
    )
    .unwrap();
    let mut cmd = Command::new("bun");
    cmd.arg(relay)
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
        .stderr(Stdio::null());
    if let Some(point) = crash_at {
        cmd.env("COLOPHON_RELAY_TRACE", "1")
            .env("COLOPHON_RELAY_CRASH_AT", point);
    }
    let mut child = cmd.spawn().unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.as_mut().unwrap())
        .read_line(&mut line)
        .unwrap();
    let v: Value = serde_json::from_str(&line).expect("the listening line");
    (child, v["listening"]["port"].as_u64().unwrap() as u16)
}

fn provision_body(slot: &str, base: &str, account: &str) -> Vec<u8> {
    json!({"slot": slot, "base": base, "account": account})
        .to_string()
        .into_bytes()
}

/// `POST /v1/provision` as the test apps send it (`Content-Type: application/json`, a
/// `Content-Length`). `None` when the process died before it answered.
fn provision(port: u16, slot: &str, base: &str, account: &str) -> Option<(u16, Vec<u8>)> {
    let body = provision_body(slot, base, account);
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).ok()?;
    s.set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .ok()?;
    let head = format!(
        "POST /v1/provision HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    s.write_all(head.as_bytes()).ok()?;
    s.write_all(&body).ok()?;
    let mut raw = Vec::new();
    let _ = s.read_to_end(&mut raw);
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let status = String::from_utf8_lossy(&raw[..split])
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    Some((status, raw[split + 4..].to_vec()))
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

fn table(dir: &std::path::Path) -> Value {
    serde_json::from_slice(&std::fs::read(dir.join("data/provisioned.json")).unwrap()).unwrap()
}

fn q(e: &colophon_core::v05::engine::Engine<MemSource>, name: &str, args: Value) -> Value {
    match e.query(NS, name, args).unwrap() {
        Outcome::Success { value, .. } => value["value"].clone(),
        Outcome::Failure { reason, detail, .. } => panic!("{reason}: {detail}"),
    }
}

#[test]
fn a_fresh_account_provisions_its_slot_appoints_the_home_uploads_and_a_second_device_reads_it() {
    if prerequisites().is_none() {
        return;
    }
    let keys = HomeKeys::new(0x5a);
    let scratch = Scratch::new("provision-journey");
    let mut f = create_public(&[NS]);
    let account = f.account.id().as_str().to_string();
    let (mut child, port) = start(&keys, scratch.path(), f.account.now_ms(), None);
    let relay = Relay::attached(port, &base(), &account, scratch.path());

    // Before: the slot is not held.
    let (status, body) = relay.get("");
    assert_eq!(status, 404);
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap()["result"],
        "refused:notProvisioned"
    );

    // The door answers the home's member request for this account; the account appoints the
    // home with those bytes.
    let (status, request) = provision(port, SLOT, &base(), &account).expect("an answer");
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&request));
    let env: Value = serde_json::from_slice(&request).unwrap();
    let body: Value =
        serde_json::from_slice(&STANDARD.decode(env["body"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(body["member"]["signing"], STANDARD.encode(&keys.point));
    assert_eq!(
        body["service"]["endpoints"],
        json!([format!("{}/", base())])
    );
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

    // The first upload, to the slot added at run time.
    let now = f.account.now_ms() + 1_000;
    first_upload(&relay, &f, now);
    let (status, body) = relay.get("");
    assert_eq!(status, 200);
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap()["home"]["member"],
        keys.id
    );

    // Two devices: the phone writes and syncs, the laptop syncs and reads it.
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
    let mut laptop = member_engine(&f, &f.host, &laptop_src, &laptop_id, now + 1_000);
    let mut host = std::mem::replace(&mut f.host, Host::new());
    let mut wire = RealRelay::new(&relay);
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
    let faults = relay_pass(
        &mut laptop,
        &laptop_src,
        &keys.id,
        &mut wire,
        &host,
        now + 3_000,
    );
    assert!(faults.is_empty(), "{faults:?}");
    let laptop = member_engine(&f, &host, &laptop_src, &laptop_id, now + 4_000);
    let phone = member_engine(&f, &host, &phone_src, &phone_id, now + 4_000);
    assert_eq!(
        q(&laptop, "shows", json!({})),
        q(&phone, "shows", json!({})),
        "the laptop reads what the phone wrote"
    );
    assert!(
        q(&laptop, "shows", json!({}))
            .to_string()
            .contains("The Show"),
        "the show is on the laptop"
    );
    assert_eq!(laptop.revision(NS), phone.revision(NS));
    assert!(
        wire.requests.iter().any(|r| r.starts_with("PUT /records/")),
        "the phone uploaded: {:?}",
        wire.requests
    );

    // A claimed slot is never released as unclaimed, however long after.
    relay.set_clock(now + 25 * HOUR);
    let (status, _) =
        provision(port, "other", &format!("{PREFIX}other"), &"ef".repeat(32)).expect("an answer");
    assert_eq!(status, 200);
    assert_eq!(relay.get("").0, 200);
    assert!(table(scratch.path()).get(SLOT).is_some());
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn killed_between_the_durable_write_and_the_answer_the_same_request_completes_after_restart() {
    if prerequisites().is_none() {
        return;
    }
    let keys = HomeKeys::new(0x5b);
    let scratch = Scratch::new("provision-kill");
    let mut f = create_public(&[NS]);
    let account = f.account.id().as_str().to_string();

    // The relay kills itself right after provisioned.json is written, before it answers.
    let (mut child, port) = start(
        &keys,
        scratch.path(),
        f.account.now_ms(),
        Some("provision written"),
    );
    assert!(
        provision(port, SLOT, &base(), &account).is_none(),
        "no answer: the process died"
    );
    let exit = child.wait().unwrap();
    assert!(!exit.success(), "killed: {exit:?}");
    let written = table(scratch.path());
    assert_eq!(written[SLOT]["account"], account.as_str());
    let stored = STANDARD
        .decode(written[SLOT]["request"].as_str().unwrap())
        .unwrap();

    // Restarted (no crash point): the same request completes with the bytes that were written,
    // and again with the same bytes.
    let (mut child, port) = start(&keys, scratch.path(), f.account.now_ms(), None);
    let (status, request) = provision(port, SLOT, &base(), &account).expect("an answer");
    assert_eq!(status, 200);
    assert_eq!(request, stored);
    assert_eq!(provision(port, SLOT, &base(), &account).unwrap().1, stored);
    let relay = Relay::attached(port, &base(), &account, scratch.path());
    assert_eq!(relay.get("").0, 200);

    // And it is a request that works: the account appoints the home and makes its first upload.
    appoint_with(&mut f, &request);
    first_upload(&relay, &f, f.account.now_ms() + 1_000);
    assert_eq!(kinds(&relay).len(), entries_json(&f).len());
    let _ = child.kill();
    let _ = child.wait();
}

/// The same relay, traced, waiting at the trace point `pause_at` (the first time) until the file
/// `dir/resume` exists; its trace markers arrive on the returned channel.
fn start_paused(
    keys: &HomeKeys,
    dir: &std::path::Path,
    clock_ms: i64,
    pause_at: &str,
) -> (Child, u16, std::sync::mpsc::Receiver<String>) {
    let (relay, wasm) = prerequisites().expect("prerequisites");
    std::fs::create_dir_all(dir).unwrap();
    write_clock(&dir.join("clock"), clock_ms);
    let config = dir.join("config.json");
    std::fs::write(
        &config,
        json!({
            "provision": {"enabled": true, "prefix": PREFIX, "slotPattern": "^[a-z]{4,64}$"},
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
        .env("COLOPHON_RELAY_TRACE", "1")
        .env("COLOPHON_RELAY_PAUSE_AT", pause_at)
        .env("COLOPHON_RELAY_RESUME_FILE", dir.join("resume"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let err = child.stderr.take().unwrap();
    std::thread::spawn(move || {
        for line in BufReader::new(err).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let mut line = String::new();
    BufReader::new(child.stdout.as_mut().unwrap())
        .read_line(&mut line)
        .unwrap();
    let v: Value = serde_json::from_str(&line).expect("the listening line");
    (child, v["listening"]["port"].as_u64().unwrap() as u16, rx)
}

/// Wait for the trace marker `what` (a bound, not a timing assertion: the marker is the event).
fn marker(rx: &std::sync::mpsc::Receiver<String>, what: &str) {
    loop {
        let line = rx
            .recv_timeout(std::time::Duration::from_secs(120))
            .unwrap_or_else(|_| panic!("no trace marker {what}"));
        if line == format!("trace {what}") {
            return;
        }
    }
}

#[test]
fn a_first_upload_paused_after_its_access_check_wins_over_a_release_and_a_provision_for_another_account(
) {
    if prerequisites().is_none() {
        return;
    }
    let keys = HomeKeys::new(0x5c);
    let scratch = Scratch::new("provision-race");
    let mut f = create_public(&[NS]);
    let account = f.account.id().as_str().to_string();
    let t0 = f.account.now_ms();
    let (mut child, port, rx) = start_paused(&keys, scratch.path(), t0, "access authority");
    let relay = Relay::attached(port, &base(), &account, scratch.path());
    let (status, request) = provision(port, SLOT, &base(), &account).expect("an answer");
    assert_eq!(status, 200);
    appoint_with(&mut f, &request);

    // A's first upload (the genesis and its history) pauses right after its access check.
    let entries: Vec<Value> = entries_json(&f).into_iter().map(|(_, e)| e).collect();
    assert!(entries.len() <= 64, "one page");
    let body = json!({"from": 1, "entries": entries, "receipts": []}).to_string();
    let path = relay.url("/authority");
    let upload = std::thread::spawn(move || {
        http(
            port,
            "POST",
            &path,
            &[("Content-Type".into(), "application/json".into())],
            body.as_bytes(),
        )
    });
    marker(&rx, "access authority");

    // Past unclaimedHours, another account asks for the name: the release starts, takes the
    // slot out of dispatch, and waits for A.
    relay.set_clock(t0 + 25 * HOUR);
    let other = "ef".repeat(32);
    let b = std::thread::spawn({
        let (base, other) = (base(), other.clone());
        move || provision(port, SLOT, &base, &other)
    });
    marker(&rx, &format!("release draining {SLOT}"));
    let (status, body) = relay.get("");
    assert_eq!(status, 404, "closing: out of dispatch");
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap()["result"],
        "refused:notProvisioned"
    );

    // A resumes and stores the genesis: the release is abandoned and B is refused.
    std::fs::write(scratch.path().join("resume"), b"").unwrap();
    let (a_status, _, a_body) = upload.join().unwrap();
    assert_eq!(a_status, 200, "{}", String::from_utf8_lossy(&a_body));
    let (b_status, _) = b.join().unwrap().expect("an answer");
    assert_eq!(b_status, 409, "the slot is A's: never both");
    assert_eq!(table(scratch.path())[SLOT]["account"], account.as_str());
    assert_eq!(relay.get("").0, 200, "back in service");
    assert_eq!(
        kinds(&relay).len(),
        entries_json(&f).len(),
        "A's history, on A's slot"
    );
    let _ = child.kill();
    let _ = child.wait();

    // A restart finds no account mismatch.
    let (mut child, port) = start(&keys, scratch.path(), t0 + 25 * HOUR, None);
    let relay = Relay::attached(port, &base(), &account, scratch.path());
    assert_eq!(relay.get("").0, 200);
    assert_eq!(kinds(&relay).len(), entries_json(&f).len());
    let _ = child.kill();
    let _ = child.wait();
}
