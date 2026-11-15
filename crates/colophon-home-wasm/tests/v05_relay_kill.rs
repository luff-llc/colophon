//! The kill loop: the relay process is killed at random points while a journey runs (transitions
//! submitted and receipted, coming due, `activate` and `final` recorded, heads signed), at least
//! 200 times, some of them inside `record_due`. After each restart: nothing was receipted twice,
//! no head is signed over an entry that is not served, state and storage agree, and in the end
//! the journey completes.
#![allow(clippy::unwrap_used, clippy::too_many_arguments, dead_code)]
#[path = "../../colophon-core/tests/v05_engine_support/mod.rs"]
mod support;
mod support_relay;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use colophon_core::v05::account::Change;
use colophon_core::v05::write::authority::TransitionRule;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use support::*;
use support_relay::*;

const NS: &str = "listening.podcasts";
const HOUR_MS: i64 = 3_600_000;

/// A relay whose stderr is collected (for the `record_due` trace markers).
struct Traced {
    child: Child,
    port: u16,
    lines: Arc<Mutex<Vec<String>>>,
}
fn start(keys: &HomeKeys, account: &str, dir: &std::path::Path, port: u16) -> Traced {
    let (relay, wasm) = prerequisites().expect("prerequisites");
    std::fs::create_dir_all(dir).unwrap();
    let config = dir.join("config.json");
    std::fs::write(&config, json!({"resolve": {}, "limits": {"requestsPerMinute": 0}}).to_string()).unwrap();
    let mut child = Command::new("bun")
        .arg(relay)
        .arg("--test-clock")
        .arg("--config")
        .arg(&config)
        .env("COLOPHON_RELAY_PORT", port.to_string())
        .env("COLOPHON_RELAY_DATA", dir.join("data"))
        .env("COLOPHON_RELAY_HOME_SLOTS", format!("home={account}@{BASE_A}"))
        .env("COLOPHON_HOME_KEY", keys.jwk())
        .env("COLOPHON_HOME_WASM", wasm)
        .env("COLOPHON_RELAY_CLOCK_FILE", dir.join("clock"))
        .env("COLOPHON_RELAY_TICK_MS", "20")
        .env("COLOPHON_RELAY_TRACE", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let lines = Arc::new(Mutex::new(Vec::new()));
    let sink = lines.clone();
    let mut err = child.stderr.take().unwrap();
    std::thread::spawn(move || {
        let mut buf = String::new();
        let _ = err.read_to_string(&mut buf);
        let mut l = sink.lock().unwrap();
        l.extend(buf.lines().map(str::to_string));
    });
    let mut line = String::new();
    BufReader::new(child.stdout.as_mut().unwrap()).read_line(&mut line).unwrap();
    let v: Value = serde_json::from_str(&line).unwrap_or_else(|_| panic!("the listening line: {line:?}"));
    Traced { child, port: v["listening"]["port"].as_u64().unwrap() as u16, lines }
}
impl Traced {
    /// SIGKILL, wait, and say whether the last trace marker was inside `record_due`.
    fn kill(mut self) -> bool {
        let _ = self.child.kill();
        let _ = self.child.wait();
        // The reader thread ends when the pipe closes.
        for _ in 0..100 {
            if Arc::strong_count(&self.lines) == 1 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let l = self.lines.lock().unwrap();
        l.iter().rev().find(|s| s.starts_with("trace record_due")).is_some_and(|s| s.ends_with("start"))
    }
}
impl Drop for Traced {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// An HTTP exchange that tolerates the process dying under it.
fn try_http(port: u16, method: &str, path: &str, body: &[u8]) -> Option<(u16, Vec<u8>)> {
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).ok()?;
    s.set_read_timeout(Some(std::time::Duration::from_secs(20))).ok()?;
    let head = format!(
        "{method} /v1/libraries/home{path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    s.write_all(head.as_bytes()).ok()?;
    s.write_all(body).ok()?;
    let mut raw = Vec::new();
    let _ = s.read_to_end(&mut raw);
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let status = String::from_utf8_lossy(&raw[..split]).split_whitespace().nth(1)?.parse().ok()?;
    Some((status, raw[split + 4..].to_vec()))
}
fn get_json(port: u16, path: &str) -> (u16, Value) {
    let (s, b) = try_http(port, "GET", path, b"").expect("the relay answers");
    (s, serde_json::from_slice(&b).unwrap_or(Value::Null))
}
fn body_of(env: &Value) -> Value {
    serde_json::from_slice(&STANDARD.decode(env["body"].as_str().unwrap()).unwrap()).unwrap()
}
fn digest_of(env: &Value) -> String {
    colophon_core::v05::encoding::digest(&STANDARD.decode(env["body"].as_str().unwrap()).unwrap())
}

/// The digests a recording entry settles: an `activate`'s transition, a `vetoed`'s transition
/// and veto.
fn settled_by(entries: &[Value]) -> std::collections::BTreeSet<String> {
    let mut out = std::collections::BTreeSet::new();
    for e in entries {
        let b = body_of(e);
        for field in ["transition", "veto"] {
            if let Some(text) = b[field].as_str() {
                let env: Value = serde_json::from_slice(&STANDARD.decode(text).unwrap()).unwrap();
                out.insert(digest_of(&env));
            }
        }
    }
    out
}

/// State and storage agree, no head is over an entry not served, one receipt per home and
/// object, and every receipt is the one first seen (`receipts`: object -> body). Every
/// transition and veto the home answered 200 for (`admitted`: digest -> `transitions` or
/// `vetoes`) is kept: stored at its path, and listed until a recording entry settles it.
fn check(port: u16, receipts: &mut BTreeMap<String, Value>, admitted: &BTreeMap<String, &str>) -> Vec<Value> {
    // The head first: entries only grow, so a head read before them must be over one of them.
    let (head_status, head) = get_json(port, "/head");
    let mut entries = Vec::new();
    loop {
        let (s, page) = get_json(port, &format!("/authority?after={}&limit=64", entries.len()));
        assert_eq!(s, 200);
        entries.extend(page["entries"].as_array().unwrap().iter().cloned());
        if page["more"] != true {
            break;
        }
    }
    for (i, e) in entries.iter().enumerate() {
        let (s, file) = get_json(port, &format!("/records/authority/{:08}.json", i + 1));
        assert_eq!((s, &file), (200, e), "entry {} is stored as served", i + 1);
    }
    if head_status == 200 {
        let h = body_of(&head);
        let seq = h["authority"]["seq"].as_u64().unwrap() as usize;
        assert!(seq >= 1 && seq <= entries.len(), "the head (seq {seq}) is over a served entry ({} served)", entries.len());
        assert_eq!(h["authority"]["digest"].as_str().unwrap(), digest_of(&entries[seq - 1]));
        let (s2, _) = get_json(port, &format!("/records/heads/{}.json", h["by"].as_str().unwrap()));
        assert_eq!(s2, 200, "the head is stored where it is served");
    }
    let (s, pending) = get_json(port, "/pending?after=0&limit=64");
    assert_eq!(s, 200);
    let mut pairs = std::collections::BTreeSet::new();
    for o in pending["objects"].as_array().unwrap() {
        let env = &o["envelope"];
        let path = match o["kind"].as_str().unwrap() {
            "transition" => format!("/records/transitions/{}.json", o["digest"].as_str().unwrap()),
            "veto" => format!("/records/vetoes/{}.json", o["digest"].as_str().unwrap()),
            _ => {
                let b = body_of(env);
                let (obj, by) = (b["object"].as_str().unwrap().to_string(), b["by"].as_str().unwrap().to_string());
                assert!(pairs.insert((obj.clone(), by.clone())), "one receipt per home and object");
                let first = receipts.entry(obj.clone()).or_insert_with(|| b.clone());
                assert_eq!(first, &b, "the receipt of {obj} is the one first signed: nothing receipted twice");
                format!("/records/receipts/{obj}/{by}.receipt.json")
            }
        };
        let (s, file) = get_json(port, &path);
        assert_eq!((s, &file), (200, env), "{path} is stored as listed");
    }
    // Nothing admitted is dropped: stored, and listed until settled (the listing is read after
    // the entries, so an object settled in between is listed or settled by what was read).
    let listed: std::collections::BTreeSet<String> = pending["objects"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|o| o["kind"] != "receipt")
        .map(|o| o["digest"].as_str().unwrap().to_string())
        .collect();
    let mut later = entries.clone();
    if pending["more"] != true {
        let (_, page) = get_json(port, &format!("/authority?after={}&limit=64", entries.len()));
        later.extend(page["entries"].as_array().unwrap().iter().cloned());
    }
    let settled = settled_by(&later);
    for (d, dir) in admitted {
        let (s, _) = get_json(port, &format!("/records/{dir}/{d}.json"));
        assert_eq!(s, 200, "the admitted {dir} {d} is kept");
        assert!(listed.contains(d) || settled.contains(d), "the admitted {dir} {d} is listed until settled");
    }
    entries
}

#[test]
#[ignore = "about 9 minutes: scripts/test-home.sh runs it (cargo test --test v05_relay_kill -- --ignored)"]
fn the_relay_killed_at_random_points_loses_nothing_and_receipts_nothing_twice() {
    if prerequisites().is_none() {
        return;
    }
    let keys = HomeKeys::new(0x77);
    let mut f = create_with(&[NS], "public", 1);
    appoint_homes(&mut f, &[(&keys, BASE_A)]);
    let account = f.account.id().as_str().to_string();
    let scratch = Scratch::new("kill-loop");
    let dir = scratch.path().to_path_buf();
    std::fs::create_dir_all(&dir).unwrap();
    let port = free_port();
    let clock = |ms: i64| std::fs::write(dir.join("clock"), ms.to_string()).unwrap();
    clock(T0 + 1_000);
    let mut relay = start(&keys, &account, &dir, port);
    // The first upload.
    let all = entries_json(&f);
    let values: Vec<&Value> = all.iter().map(|(_, e)| e).collect();
    let body = json!({"from": 1, "entries": values, "receipts": []}).to_string();
    assert_eq!(try_http(relay.port, "POST", "/authority", body.as_bytes()).unwrap().0, 200);
    let src = MemSource::new();
    src.store_account(&f.account);
    let host = std::mem::replace(&mut f.host, Host::new());
    let d = f.d.clone();
    let p = f.p.clone();
    let mut admitted: BTreeMap<String, &str> = BTreeMap::new();
    let mut want = 3usize;
    let mut vetoes = 0usize;
    let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut rnd = |n: u64| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed % n
    };
    let (mut kills, mut inside) = (0usize, 0usize);
    let mut receipts = BTreeMap::new();
    let rounds = 25i64;
    let started = std::time::Instant::now();
    for k in 0..rounds {
        let t = T0 + HOUR_MS + k * 3 * HOUR_MS;
        clock(t);
        // After a `vetoed`, a transition its signer's unit signs alone fails escalation (§8.7):
        // the next one is signed by both units.
        let signers = if k % 3 == 2 { vec![d.clone(), p.clone()] } else { vec![d.clone()] };
        // The controller catches up with the home, then proposes a transition.
        let mut ctl = controller_engine(&f, &host, &src, &d, t);
        let peer = Relay::attached(port, BASE_A, &account, &dir);
        let mut wire = RealRelay::new(&peer);
        let faults = relay_pass(&mut ctl, &src, &keys.id, &mut wire, &host, t);
        assert!(faults.is_empty(), "round {k}: {faults:?}");
        let action = ctl
            .account()
            .begin_transition(&Change::policy(json!({"callWindow": 600 + k})), &signers, TransitionRule::Control)
            .unwrap();
        engine_finish(&mut ctl, &host, &src, action);
        let digest = ctl.account().pending().last().unwrap().digest.clone();
        let env: Value = ctl
            .account()
            .objects()
            .pending
            .iter()
            .find(|p| pending_path(p).contains(&digest))
            .map(|p| serde_json::from_slice(p).unwrap())
            .unwrap();
        // Submitted, with a kill at a random point while the home admits and receipts it; the
        // client retries until it has the home's answer.
        let post = json!({"objects": [env]}).to_string();
        clock(t + 1_000);
        {
            let delay = rnd(30_000);
            let sender = {
                let body = post.clone();
                std::thread::spawn(move || try_http(port, "POST", "/pending", body.as_bytes()))
            };
            std::thread::sleep(std::time::Duration::from_micros(delay));
            inside += usize::from(relay.kill());
            kills += 1;
            let answered = sender.join().unwrap();
            relay = start(&keys, &account, &dir, port);
            check(relay.port, &mut receipts, &admitted);
            // The client retries until it has the home's answer.
            if !answered.is_some_and(|(s, _)| s == 200) {
                let retry = try_http(port, "POST", "/pending", post.as_bytes());
                assert_eq!(retry.map(|(s, _)| s), Some(200), "round {k}: the retry");
            }
            admitted.insert(digest.clone(), "transitions");
            check(relay.port, &mut receipts, &admitted);
        }
        // Every third round the owner vetoes it in time, from the other unit (the passkey),
        // killed at a random point while the home admits and receipts the veto: the veto is kept,
        // and the transition is `vetoed`, never activated.
        let vetoed = k % 3 == 1;
        if vetoed {
            clock(t + 2_000);
            let peer = Relay::attached(port, BASE_A, &account, &dir);
            let mut wire = RealRelay::new(&peer);
            let faults = relay_pass(&mut ctl, &src, &keys.id, &mut wire, &host, t + 2_000);
            assert!(faults.is_empty(), "round {k}: {faults:?}");
            let action = ctl.account().begin_veto(&digest, std::slice::from_ref(&p)).unwrap();
            engine_finish(&mut ctl, &host, &src, action);
            let veto: Value = ctl
                .account()
                .objects()
                .pending
                .iter()
                .filter(|b| pending_path(b).starts_with("vetoes/"))
                .find(|b| body_of(&serde_json::from_slice::<Value>(b).unwrap())["transition"] == digest.as_str())
                .map(|b| serde_json::from_slice(b).unwrap())
                .expect("the veto");
            let veto_digest = digest_of(&veto);
            let post = json!({"objects": [veto]}).to_string();
            clock(t + 3_000);
            let delay = rnd(30_000);
            let sender = {
                let body = post.clone();
                std::thread::spawn(move || try_http(port, "POST", "/pending", body.as_bytes()))
            };
            std::thread::sleep(std::time::Duration::from_micros(delay));
            inside += usize::from(relay.kill());
            kills += 1;
            let answered = sender.join().unwrap();
            relay = start(&keys, &account, &dir, port);
            check(relay.port, &mut receipts, &admitted);
            if !answered.is_some_and(|(s, _)| s == 200) {
                let retry = try_http(port, "POST", "/pending", post.as_bytes());
                assert_eq!(retry.map(|(s, _)| s), Some(200), "round {k}: the veto's retry");
            }
            admitted.insert(veto_digest, "vetoes");
            check(relay.port, &mut receipts, &admitted);
        }
        // Restarts before it is due: everything admitted is still kept and listed.
        clock(t + 60_000);
        for _ in 0..2 {
            std::thread::sleep(std::time::Duration::from_micros(rnd(40_000)));
            inside += usize::from(relay.kill());
            kills += 1;
            relay = start(&keys, &account, &dir, port);
            check(relay.port, &mut receipts, &admitted);
        }
        // Due: the home records `activate`, signs a head, then records `final` (or, vetoed, the
        // `vetoed`). Killed at random points while it does.
        let due = t + HOUR_MS + 400_000;
        clock(due);
        for _ in 0..5 {
            std::thread::sleep(std::time::Duration::from_micros(rnd(120_000)));
            inside += usize::from(relay.kill());
            kills += 1;
            relay = start(&keys, &account, &dir, port);
            check(relay.port, &mut receipts, &admitted);
        }
        // A real clock moves on: a head over the `activate` needs an `issued` after the head
        // the home may have signed at the same clock reading (strictly increasing, §13.3).
        clock(due + 2_000);
        want += if vetoed { 1 } else { 2 };
        let end = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let entries = loop {
            let e = check(relay.port, &mut receipts, &admitted);
            if e.len() >= want || std::time::Instant::now() > end {
                break e;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        };
        let kinds: Vec<String> = entries.iter().map(|e| body_of(e)["kind"].as_str().unwrap().to_string()).collect();
        assert_eq!(kinds.len(), want, "round {k}: {kinds:?}");
        if vetoed {
            assert_eq!(kinds[want - 1], "vetoed", "round {k}");
            vetoes += 1;
        } else {
            assert_eq!(&kinds[want - 2..], &["activate".to_string(), "final".to_string()], "round {k}");
        }
        // Settled, and still kept: the transition (and its veto) stay stored after they leave
        // the listing, across one more restart.
        inside += usize::from(relay.kill());
        kills += 1;
        relay = start(&keys, &account, &dir, port);
        let entries = check(relay.port, &mut receipts, &admitted);
        assert!(settled_by(&entries).contains(&digest), "round {k}: settled");
        eprintln!("kill loop: round {k} done, {kills} kills so far ({inside} inside record_due), {:?}", started.elapsed());
    }
    let _ = relay.kill();
    eprintln!(
        "kill loop: {kills} kills, {inside} of them inside record_due, {} transitions activated and final, {vetoes} vetoed, {} transitions and vetoes kept",
        rounds as usize - vetoes,
        admitted.len()
    );
    assert!(kills >= 200, "{kills}");
    assert!(inside > 0, "some kills landed inside record_due");
}
