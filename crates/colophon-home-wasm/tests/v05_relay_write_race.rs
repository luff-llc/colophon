//! A record write and a revocation of its writer, racing at the real relay (`relay/server.js` on
//! Bun, the home module in WebAssembly). The write's call is judged against the committed state
//! under the slot's lock: a write that waits for an upload revoking its writer is judged after
//! that upload commits, and refused. Every clock is the relay's test clock; the interleaving is
//! forced with the relay's trace pause, not with timing. A long poll of the change feed, judged
//! once when it arrived, ends with an empty page when the authority changes, so its caller is
//! judged again on its next poll.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::too_many_arguments,
    clippy::cloned_ref_to_slice_refs
)]
#[path = "../../colophon-core/tests/v05_engine_support/mod.rs"]
mod support;
mod support_relay;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use colophon_core::v05::account::RevokeKeep;
use colophon_core::v05::encoding::{canonical, digest};
use colophon_core::v05::write::format_date;
use serde_json::{json, Value};
use support::*;
use support_relay::*;

const NS: &str = "notes";

fn sha_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    sha2::Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A signed, opaque operation record by `member` (a home never decrypts it).
fn op_record(f: &Fixture, member: &str, now: i64) -> (String, Vec<u8>) {
    let id = "c".repeat(32);
    let header = json!({"protocol": "colophon/operation/5", "account": f.account.id().as_str(),
        "namespace": NS, "author": member, "epoch": 1, "id": id, "clock": 1,
        "authority": f.account.status().seq, "created": format_date(now), "level": "write",
        "previous": null, "nonce": b64(&[0; 12]), "ciphertext": b64(&[0; 16])});
    let body = canonical(&header).unwrap();
    let env =
        canonical(&json!({"body": b64(&body), "signature": b64(&f.host.ids[member].sign(&body))}))
            .unwrap();
    (
        format!("/records/ops/{member}/{NS}/000000000001-{id}.json"),
        env,
    )
}

/// The headers of a `PUT` of `bytes` at `path` with a write call signed by `member` over the
/// history `f` holds now.
fn write_headers(
    f: &Fixture,
    member: &str,
    path: &str,
    bytes: &[u8],
    now: i64,
) -> Vec<(String, String)> {
    let call = call_as(
        &f.host,
        &f.account,
        "member",
        member,
        BASE_A,
        "colophon.home.write",
        json!({"method": "PUT", "path": path, "body": sha_hex(bytes)}),
        now,
        fresh_request_id(),
    );
    vec![
        (
            "Authorization".to_string(),
            format!("Colophon {}", URL_SAFE_NO_PAD.encode(&call)),
        ),
        ("If-None-Match".to_string(), "*".to_string()),
    ]
}

fn send(
    port: u16,
    method: &str,
    path: &str,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
) -> std::thread::JoinHandle<(u16, Vec<u8>)> {
    let (method, url) = (method.to_string(), format!("/v1/libraries/home{path}"));
    std::thread::spawn(move || {
        let (s, _, b) = http(port, &method, &url, &headers, &body);
        (s, b)
    })
}

fn result(body: &[u8]) -> String {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| v["result"].as_str().map(str::to_string))
        .unwrap_or_default()
}

#[test]
fn a_write_waiting_behind_its_writers_revocation_is_judged_after_it_and_refused() {
    if prerequisites().is_none() {
        return;
    }
    let keys = HomeKeys::new(0x5b);
    let mut f = create_v(&[NS], 6);
    appoint_home_keys(&mut f, &keys, BASE_A);
    let m = f.host.identity(42);
    admit(&mut f, &m, "Writer", "app", terms("write"), terms("write"));
    let scratch = Scratch::new("write-race");
    let now = f.account.now_ms() + 1_000;
    let account = f.account.id().as_str().to_string();
    let mut setup = Relay::start_with(
        &keys,
        &account,
        BASE_A,
        scratch.path(),
        now,
        &[],
        0,
        json!({"tickMs": 0}),
    );
    first_upload(&setup, &f, now);
    setup.stop();
    drop(setup);
    // Restarted traced: the revocation's upload pauses once it holds the slot's lock.
    let (relay, rx) = Relay::start_paused(
        &keys,
        &account,
        BASE_A,
        scratch.path(),
        now,
        "authority locked",
    );
    let port = relay.port;

    // M's writes, with calls over the history the home holds now (before the revocation): an
    // operation record and a blob.
    let (op_path, op_bytes) = op_record(&f, &m, now);
    let op_headers = write_headers(&f, &m, &op_path, &op_bytes, now);
    let blob = b"synthetic blob for the race".to_vec();
    let blob_path = format!("/records/blobs/{}", digest(&blob));
    let blob_headers = write_headers(&f, &m, &blob_path, &blob, now);

    // The revocation of M is uploaded and pauses holding the lock.
    f.account.advance(now).unwrap();
    let from = entries_json(&f).last().unwrap().0 + 1;
    let action = f
        .account
        .begin_revoke(&m, &RevokeKeep::Nothing, &[f.d.clone()], [9; 32])
        .unwrap();
    run(&mut f.account, &f.host, action);
    let entry = entries_json(&f)
        .into_iter()
        .find(|(s, _)| *s == from)
        .unwrap()
        .1;
    let body = json!({"from": from, "entries": [entry], "receipts": []}).to_string();
    let revoke = send(
        port,
        "POST",
        "/authority",
        vec![("Content-Type".into(), "application/json".into())],
        body.into_bytes(),
    );
    trace_marker(&rx, &["authority locked"]);

    // Both writes arrive while the revocation holds the lock. Each is let go once it is either
    // past its judgement ("access records") or queued for the lock ("records locking").
    let op = send(port, "PUT", &op_path, op_headers, op_bytes);
    trace_marker(&rx, &["access records", "records locking"]);
    let blob_put = send(port, "PUT", &blob_path, blob_headers, blob);
    trace_marker(&rx, &["access records", "records locking"]);

    // Released: the revocation commits; only then are the writes judged.
    std::fs::write(scratch.path().join("resume"), b"").unwrap();
    let (s, b) = revoke.join().unwrap();
    assert_eq!(s, 200, "the revocation: {}", String::from_utf8_lossy(&b));
    for (what, put, path) in [
        ("operation record", op, &op_path),
        ("blob", blob_put, &blob_path),
    ] {
        let (s, b) = put.join().unwrap();
        assert_eq!(
            (s, result(&b).as_str()),
            (403, "refused:revoked"),
            "the {what} write of a member revoked before it was judged: {}",
            String::from_utf8_lossy(&b)
        );
        let stored = scratch
            .path()
            .join("data/home")
            .join(path.trim_start_matches('/'));
        assert!(
            !stored.exists(),
            "the {what} was stored after its writer's revocation"
        );
    }
    drop(relay);
}

/// The headers of a `GET` of `path` with a read call signed by `member`.
fn read_headers(f: &Fixture, member: &str, path: &str, now: i64) -> Vec<(String, String)> {
    let call = call_as(
        &f.host,
        &f.account,
        "member",
        member,
        BASE_A,
        "colophon.home.read",
        json!({"method": "GET", "path": path, "body": sha_hex(b"")}),
        now,
        fresh_request_id(),
    );
    vec![(
        "Authorization".to_string(),
        format!("Colophon {}", URL_SAFE_NO_PAD.encode(&call)),
    )]
}

#[test]
fn a_long_poll_ends_empty_when_the_authority_changes_and_serves_no_later_entry() {
    if prerequisites().is_none() {
        return;
    }
    let keys = HomeKeys::new(0x5c);
    let mut f = create_v(&[NS], 7);
    appoint_home_keys(&mut f, &keys, BASE_A);
    let m = f.host.identity(43);
    let other = f.host.identity(44);
    admit(&mut f, &m, "Reader", "app", terms("write"), terms("write"));
    admit(
        &mut f,
        &other,
        "Writer",
        "app",
        terms("write"),
        terms("write"),
    );
    let scratch = Scratch::new("long-poll-revoke");
    let now = f.account.now_ms() + 1_000;
    let account = f.account.id().as_str().to_string();
    let mut setup = Relay::start_with(
        &keys,
        &account,
        BASE_A,
        scratch.path(),
        now,
        &[],
        0,
        json!({"tickMs": 0}),
    );
    first_upload(&setup, &f, now);
    setup.stop();
    drop(setup);
    // Traced: the revocation's upload pauses once its state is committed, before its entry is
    // stored (so before anything could wake the poll but the commit itself).
    let (relay, rx) = Relay::start_paused(
        &keys,
        &account,
        BASE_A,
        scratch.path(),
        now,
        "authority committed",
    );
    let port = relay.port;

    // M lists the feed, then long-polls after its cursor.
    let (s, _, b) = http(
        port,
        "GET",
        "/v1/libraries/home/changes",
        &read_headers(&f, &m, "/changes", now),
        &[],
    );
    assert_eq!(s, 200, "{}", String::from_utf8_lossy(&b));
    let cursor = serde_json::from_slice::<Value>(&b).unwrap()["cursor"]
        .as_str()
        .unwrap()
        .to_string();
    let path = format!("/changes?after={cursor}&wait=30");
    let (polled, answer) = std::sync::mpsc::channel();
    let poll = send(
        port,
        "GET",
        &path,
        read_headers(&f, &m, &path, now),
        Vec::new(),
    );
    std::thread::spawn(move || {
        let _ = polled.send(poll.join().unwrap());
    });
    trace_marker(&rx, &["changes waiting"]);

    // Calls by the other member over the history before the revocation.
    let (op_path, op_bytes) = op_record(&f, &other, now);
    let op_headers = write_headers(&f, &other, &op_path, &op_bytes, now);
    // M is revoked while its poll waits.
    f.account.advance(now).unwrap();
    let from = entries_json(&f).last().unwrap().0 + 1;
    let action = f
        .account
        .begin_revoke(&m, &RevokeKeep::Nothing, &[f.d.clone()], [9; 32])
        .unwrap();
    run(&mut f.account, &f.host, action);
    let entry = entries_json(&f)
        .into_iter()
        .find(|(s, _)| *s == from)
        .unwrap()
        .1;
    let body = json!({"from": from, "entries": [entry], "receipts": []}).to_string();
    let revoke = send(
        port,
        "POST",
        "/authority",
        vec![("Content-Type".into(), "application/json".into())],
        body.into_bytes(),
    );
    trace_marker(&rx, &["authority committed"]);
    // The revocation is committed and its entry not stored yet: the commit alone ends the poll
    // (the bound is far shorter than the poll's own 30 s wait).
    let (s, b) = answer
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("the poll did not end when the authority changed");
    std::fs::write(scratch.path().join("resume"), b"").unwrap();
    let (rs, rb) = revoke.join().unwrap();
    assert_eq!(rs, 200, "the revocation: {}", String::from_utf8_lossy(&rb));
    // Another member's record after it.
    let (ws, wb) = send(port, "PUT", &op_path, op_headers, op_bytes)
        .join()
        .unwrap();
    assert_eq!(ws, 201, "{}", String::from_utf8_lossy(&wb));

    assert_eq!(s, 200, "{}", String::from_utf8_lossy(&b));
    let page: Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(
        page["entries"],
        json!([]),
        "a poll judged before the revocation served what came after it"
    );
    assert_eq!(
        page["cursor"].as_str(),
        Some(cursor.as_str()),
        "the cursor did not move"
    );
    // Its next poll is judged again: M is revoked.
    let (s, _, b) = http(
        port,
        "GET",
        &format!("/v1/libraries/home{path}"),
        &read_headers(&f, &m, &path, now),
        &[],
    );
    assert_eq!(
        (s, result(&b).as_str()),
        (403, "refused:revoked"),
        "{}",
        String::from_utf8_lossy(&b)
    );
    drop(relay);
}

#[test]
fn a_change_feed_read_is_judged_and_listed_over_one_state() {
    if prerequisites().is_none() {
        return;
    }
    let keys = HomeKeys::new(0x5d);
    let mut f = create_v(&[NS], 8);
    appoint_home_keys(&mut f, &keys, BASE_A);
    let m = f.host.identity(45);
    admit(&mut f, &m, "Reader", "app", terms("write"), terms("write"));
    let scratch = Scratch::new("feed-one-state");
    let now = f.account.now_ms() + 1_000;
    let account = f.account.id().as_str().to_string();
    let mut setup = Relay::start_with(
        &keys,
        &account,
        BASE_A,
        scratch.path(),
        now,
        &[],
        0,
        json!({"tickMs": 0}),
    );
    first_upload(&setup, &f, now);
    setup.stop();
    drop(setup);
    // The read pauses right after its call is judged.
    let (relay, rx) = Relay::start_paused(
        &keys,
        &account,
        BASE_A,
        scratch.path(),
        now,
        "access changes",
    );
    let port = relay.port;
    // M reads the feed from the start; the read pauses once its call is judged.
    let read = send(
        port,
        "GET",
        "/changes",
        read_headers(&f, &m, "/changes", now),
        Vec::new(),
    );
    trace_marker(&rx, &["access changes"]);
    // M's revocation is uploaded meanwhile.
    f.account.advance(now).unwrap();
    let from = entries_json(&f).last().unwrap().0 + 1;
    let action = f
        .account
        .begin_revoke(&m, &RevokeKeep::Nothing, &[f.d.clone()], [9; 32])
        .unwrap();
    run(&mut f.account, &f.host, action);
    let entry = entries_json(&f)
        .into_iter()
        .find(|(s, _)| *s == from)
        .unwrap()
        .1;
    let body = json!({"from": from, "entries": [entry], "receipts": []}).to_string();
    let (revoked, revoke_done) = std::sync::mpsc::channel();
    let revoke = send(
        port,
        "POST",
        "/authority",
        vec![("Content-Type".into(), "application/json".into())],
        body.into_bytes(),
    );
    std::thread::spawn(move || {
        let _ = revoked.send(revoke.join().unwrap());
    });
    // While the read holds its judgement, the revocation cannot commit (a bound: it is the
    // property, not a timing assumption).
    let early = revoke_done
        .recv_timeout(std::time::Duration::from_secs(3))
        .ok();
    std::fs::write(scratch.path().join("resume"), b"").unwrap();
    let (s, b) = read.join().unwrap();
    assert_eq!(s, 200, "{}", String::from_utf8_lossy(&b));
    let page: Value = serde_json::from_slice(&b).unwrap();
    let revoking = format!("authority/{from:08}.json");
    assert!(
        !page["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["path"] == json!(revoking)),
        "a read judged before the revocation listed the revoking entry: {page}"
    );
    assert!(
        early.is_none(),
        "the revocation committed between the read's judgement and its page"
    );
    let (rs, rb) = early.unwrap_or_else(|| revoke_done.recv().unwrap());
    assert_eq!(rs, 200, "the revocation: {}", String::from_utf8_lossy(&rb));
    drop(relay);
}

#[test]
fn a_history_file_read_is_judged_and_selected_over_one_state() {
    if prerequisites().is_none() {
        return;
    }
    let keys = HomeKeys::new(0x5e);
    // A members-only history: reading an entry's file needs a member's call.
    let mut f = create_with(&[NS], "members", 1);
    appoint_home_keys(&mut f, &keys, BASE_A);
    let m = f.host.identity(46);
    admit(&mut f, &m, "Reader", "app", terms("write"), terms("write"));
    let scratch = Scratch::new("history-file-one-state");
    let now = f.account.now_ms() + 1_000;
    let account = f.account.id().as_str().to_string();
    let mut setup = Relay::start_with(
        &keys,
        &account,
        BASE_A,
        scratch.path(),
        now,
        &[],
        0,
        json!({"tickMs": 0}),
    );
    first_upload(&setup, &f, now);
    setup.stop();
    drop(setup);
    // The read pauses right after its call is judged.
    let (relay, rx) = Relay::start_paused(
        &keys,
        &account,
        BASE_A,
        scratch.path(),
        now,
        "access records",
    );
    let port = relay.port;
    let from = entries_json(&f).last().unwrap().0 + 1;
    // M reads the file of the entry that will revoke it, before that entry exists.
    let path = format!("/records/authority/{from:08}.json");
    let read = send(
        port,
        "GET",
        &path,
        read_headers(&f, &m, &path, now),
        Vec::new(),
    );
    trace_marker(&rx, &["access records"]);
    f.account.advance(now).unwrap();
    let action = f
        .account
        .begin_revoke(&m, &RevokeKeep::Nothing, &[f.d.clone()], [9; 32])
        .unwrap();
    run(&mut f.account, &f.host, action);
    let entry = entries_json(&f)
        .into_iter()
        .find(|(s, _)| *s == from)
        .unwrap()
        .1;
    let body = json!({"from": from, "entries": [entry], "receipts": []}).to_string();
    let (revoked, revoke_done) = std::sync::mpsc::channel();
    let revoke = send(
        port,
        "POST",
        "/authority",
        vec![("Content-Type".into(), "application/json".into())],
        body.into_bytes(),
    );
    std::thread::spawn(move || {
        let _ = revoked.send(revoke.join().unwrap());
    });
    // While the read holds its judgement, the revocation cannot commit (a bound: it is the
    // property, not a timing assumption).
    let early = revoke_done
        .recv_timeout(std::time::Duration::from_secs(3))
        .ok();
    std::fs::write(scratch.path().join("resume"), b"").unwrap();
    let (s, b) = read.join().unwrap();
    assert_eq!(
        s,
        404,
        "a read judged before the revocation was served the revoking entry: {}",
        String::from_utf8_lossy(&b)
    );
    assert!(
        early.is_none(),
        "the revocation committed between the read's judgement and its file"
    );
    let (rs, rb) = early.unwrap_or_else(|| revoke_done.recv().unwrap());
    assert_eq!(rs, 200, "the revocation: {}", String::from_utf8_lossy(&rb));
    drop(relay);
}
