//! The kill loop: the relay process is killed at random points while a journey runs (transitions
//! submitted and receipted, coming due, `activate` and `final` recorded, heads signed), at least
//! 200 times, some of them inside `record_due`. After each restart: nothing was receipted twice,
//! no head is signed over an entry that is not served, state and storage agree, and in the end
//! the journey completes.
//!
//! No outcome rests on how much real time passes. The relay runs no scheduler timer: the test
//! asks for each scheduler pass (`tick` on its stdin) and waits for the answer, and an exchange
//! waits for the relay's answer or its death, never for a deadline. Real time only places the
//! random kills; where a kill lands never decides whether the test passes.
#![allow(clippy::unwrap_used, clippy::too_many_arguments, dead_code)]
#[path = "../../colophon-core/tests/v05_engine_support/mod.rs"]
mod support;
mod support_relay;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use colophon_core::v05::account::Change;
use colophon_core::v05::write::authority::TransitionRule;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use support::*;
use support_relay::*;

const NS: &str = "listening.podcasts";
const HOUR_MS: i64 = 3_600_000;

/// What a relay process has said so far: its stderr lines (with the `record_due` trace markers),
/// how many scheduler passes it has answered on stdout, and whether each stream has closed.
#[derive(Default)]
struct Said {
    lines: Vec<String>,
    due_starts: usize,
    ticked: usize,
    out_closed: bool,
    err_closed: bool,
}
type Watch = Arc<(Mutex<Said>, Condvar)>;

/// A relay whose stdout and stderr are read as they come, and whose scheduler runs only when
/// the test asks.
struct Traced {
    child: Child,
    port: u16,
    stdin: Option<ChildStdin>,
    said: Watch,
    readers: Vec<std::thread::JoinHandle<()>>,
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
        .env("COLOPHON_RELAY_TICK_MS", "0")
        .env("COLOPHON_RELAY_TRACE", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let said: Watch = Arc::default();
    let err = child.stderr.take().unwrap();
    let sink = said.clone();
    let err_reader = std::thread::spawn(move || {
        for line in BufReader::new(err).lines() {
            let Ok(line) = line else { break };
            let (m, cv) = &*sink;
            let mut s = m.lock().unwrap();
            if line == "trace record_due start" {
                s.due_starts += 1;
            }
            s.lines.push(line);
            cv.notify_all();
        }
        let (m, cv) = &*sink;
        m.lock().unwrap().err_closed = true;
        cv.notify_all();
    });
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    out.read_line(&mut line).unwrap();
    let Ok(v) = serde_json::from_str::<Value>(&line) else {
        let _ = child.wait();
        let _ = err_reader.join();
        let s = said.0.lock().unwrap();
        let rest = s.lines.iter().filter(|l| !l.starts_with("trace ")).cloned().collect::<Vec<_>>().join("\n");
        panic!("the listening line: {line:?}; the relay said: {rest}")
    };
    let sink = said.clone();
    let out_reader = std::thread::spawn(move || {
        for line in out.lines() {
            let Ok(line) = line else { break };
            if serde_json::from_str::<Value>(&line).ok() == Some(json!({"ticked": true})) {
                let (m, cv) = &*sink;
                m.lock().unwrap().ticked += 1;
                cv.notify_all();
            }
        }
        let (m, cv) = &*sink;
        m.lock().unwrap().out_closed = true;
        cv.notify_all();
    });
    Traced {
        port: v["listening"]["port"].as_u64().unwrap() as u16,
        stdin: child.stdin.take(),
        child,
        said,
        readers: vec![err_reader, out_reader],
    }
}
impl Traced {
    /// Wait (on what the relay says, not on a clock) until `done` holds.
    fn wait_until(&self, mut done: impl FnMut(&Said) -> bool) {
        let (m, cv) = &*self.said;
        let mut s = m.lock().unwrap();
        while !done(&s) {
            s = cv.wait(s).unwrap();
        }
    }
    /// Ask for one scheduler pass and do not wait for it. Returns how many passes had been
    /// answered and how many `record_due` calls had started before it.
    fn tick_start(&mut self) -> (usize, usize) {
        let before = {
            let s = self.said.0.lock().unwrap();
            (s.ticked, s.due_starts)
        };
        // A relay killed meanwhile no longer reads: the pass is simply not run.
        let _ = self.stdin.as_mut().unwrap().write_all(b"tick\n").and_then(|()| self.stdin.as_mut().unwrap().flush());
        before
    }
    /// One scheduler pass (recording entries, heads), waited for.
    fn tick(&mut self) {
        let (ticked, _) = self.tick_start();
        self.wait_until(|s| s.ticked > ticked || s.out_closed);
        assert!(self.said.0.lock().unwrap().ticked > ticked, "the relay exited before it ticked");
    }
    /// A scheduler pass, and a kill as soon as its `record_due` has started (or, when the pass
    /// runs none, once the pass is over).
    fn kill_in_record_due(mut self) -> bool {
        let (ticked, starts) = self.tick_start();
        self.wait_until(|s| s.due_starts > starts || s.ticked > ticked || s.err_closed);
        self.kill()
    }
    /// A scheduler pass, and a kill after `micros` of real time, wherever the pass then is.
    fn kill_while_ticking(mut self, micros: u64) -> bool {
        self.tick_start();
        std::thread::sleep(std::time::Duration::from_micros(micros));
        self.kill()
    }
    /// SIGKILL, wait, and say whether the last trace marker was inside `record_due`.
    fn kill(mut self) -> bool {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.stdin = None;
        // The readers end when the pipes close, which the process's death does.
        for r in std::mem::take(&mut self.readers) {
            let _ = r.join();
        }
        let s = self.said.0.lock().unwrap();
        s.lines.iter().rev().find(|l| l.starts_with("trace record_due")).is_some_and(|l| l.ends_with("start"))
    }
}
impl Drop for Traced {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// An HTTP exchange that tolerates the process dying under it. It waits for the answer however
/// long it takes: a killed relay closes the connection, and a slow one is not a failure.
fn try_http(port: u16, method: &str, path: &str, body: &[u8]) -> Option<(u16, Vec<u8>)> {
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).ok()?;
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
/// The file the relay stores at a record path (`store`: the home slot's `records` directory).
fn stored(store: &std::path::Path, path: &str) -> Value {
    let bytes = std::fs::read(store.join(path)).unwrap_or_else(|e| panic!("{path} is stored: {e}"));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("{path} is stored whole: {e}"))
}

/// The digests a recording entry settles: an `activate`'s transition, a `vetoed`'s transition
/// and veto.
fn settled_by(entries: &[Value]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
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

/// What `check` has seen the relay serve at its record path: the entries up to `entries`, and
/// the admitted objects in `admitted`. Every check compares every entry and every admitted
/// object with storage on disk (cheap), and asks the relay for the files it has not yet seen
/// served, the newest entry and one older entry and object in turn; a `full` check asks for
/// every file again. So a check makes a bounded number of requests, not one per file the
/// history has ever held.
#[derive(Default)]
struct Served {
    entries: usize,
    admitted: BTreeSet<String>,
    checks: usize,
}

/// State and storage agree, no head is over an entry not served, one receipt per home and
/// object, and every receipt is the one first seen (`receipts`: object -> body). Every
/// transition and veto the home answered 200 for (`admitted`: digest -> `transitions` or
/// `vetoes`) is kept: stored at its path, and listed until a recording entry settles it.
fn check(
    port: u16,
    store: &std::path::Path,
    receipts: &mut BTreeMap<String, Value>,
    admitted: &BTreeMap<String, &str>,
    served: &mut Served,
    full: bool,
) -> Vec<Value> {
    served.checks += 1;
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
    assert!(entries.len() >= served.entries, "no entry once served is lost: {} < {}", entries.len(), served.entries);
    for (i, e) in entries.iter().enumerate() {
        let path = format!("authority/{:08}.json", i + 1);
        assert_eq!(&stored(store, &path), e, "entry {} is stored as served", i + 1);
    }
    let n = entries.len();
    let mut ask: BTreeSet<usize> = if full { (0..n).collect() } else { (served.entries..n).collect() };
    if n > 0 {
        ask.insert(n - 1);
        ask.insert(served.checks % n);
    }
    for i in ask {
        let (s, file) = get_json(port, &format!("/records/authority/{:08}.json", i + 1));
        assert_eq!((s, &file), (200, &entries[i]), "entry {} is served at its record path", i + 1);
    }
    served.entries = n;
    if head_status == 200 {
        let h = body_of(&head);
        let seq = h["authority"]["seq"].as_u64().unwrap() as usize;
        assert!(seq >= 1 && seq <= entries.len(), "the head (seq {seq}) is over a served entry ({} served)", entries.len());
        assert_eq!(h["authority"]["digest"].as_str().unwrap(), digest_of(&entries[seq - 1]));
        // Served again at its record path, or, when a head fell due in between (an entry
        // recorded at the same clock reading), refused rather than served stale (§13.3).
        let (s2, again) = get_json(port, &format!("/records/heads/{}.json", h["by"].as_str().unwrap()));
        assert!(s2 == 200 || s2 == 503, "the head is stored where it is served: {s2}");
        if s2 == 200 {
            let a = body_of(&again);
            assert!(a["issued"].as_str() >= h["issued"].as_str(), "never an older head");
        }
    } else {
        assert_eq!(head_status, 503, "a head is served, or a due one is refused retryably");
    }
    let (s, pending) = get_json(port, "/pending?after=0&limit=64");
    assert_eq!(s, 200);
    let mut pairs = BTreeSet::new();
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
    let listed: BTreeSet<String> = pending["objects"]
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
    let turn = if admitted.is_empty() { 0 } else { served.checks % admitted.len() };
    for (i, (d, dir)) in admitted.iter().enumerate() {
        let path = format!("{dir}/{d}.json");
        assert!(store.join(&path).is_file(), "the admitted {dir} {d} is kept");
        if full || i == turn || !served.admitted.contains(d) {
            let (s, _) = get_json(port, &format!("/records/{path}"));
            assert_eq!(s, 200, "the admitted {dir} {d} is served");
            served.admitted.insert(d.clone());
        }
        assert!(listed.contains(d) || settled.contains(d), "the admitted {dir} {d} is listed until settled");
    }
    entries
}

#[test]
#[ignore = "about 5 minutes: scripts/test-home.sh runs it (cargo test --test v05_relay_kill -- --ignored)"]
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
    let store = dir.join("data/home/records");
    let clock = |ms: i64| write_clock(&dir.join("clock"), ms);
    clock(T0 + 1_000);
    let mut relay = start(&keys, &account, &dir, 0);
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
    let mut served = Served::default();
    let mut want = 3usize;
    let mut vetoes = 0usize;
    let mut startup_kills = 0usize;
    let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut rnd = |n: u64| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed % n
    };
    let (mut kills, mut inside) = (0usize, 0usize);
    let mut receipts = BTreeMap::new();
    macro_rules! check {
        ($full:expr) => {
            check(relay.port, &store, &mut receipts, &admitted, &mut served, $full)
        };
    }
    let rounds = 25i64;
    let started = std::time::Instant::now();
    for k in 0..rounds {
        let t = T0 + HOUR_MS + k * 3 * HOUR_MS;
        clock(t);
        // A kill inside the first `record_due` at the round's clock reading; then a kill right
        // after start-up, before any scheduler pass: the home was serving at the round's clock
        // reading (the relay answered), and the next start still records it.
        {
            inside += usize::from(relay.kill_in_record_due());
            kills += 1;
            relay = start(&keys, &account, &dir, 0);
            let _ = get_json(relay.port, "/head");
            inside += usize::from(relay.kill());
            kills += 1;
            startup_kills += 1;
            relay = start(&keys, &account, &dir, 0);
            let serving = Relay::attached(relay.port, BASE_A, &account, &dir).serving();
            assert!(
                serving.iter().any(|(from, through)| *from <= t && through.is_none_or(|e| e >= t)),
                "round {k}: uptime at {t} is recorded after a kill before the first tick: {serving:?}"
            );
        }
        // After a `vetoed`, a transition its signer's unit signs alone fails escalation (§8.7):
        // the next one is signed by both units.
        let signers = if k % 3 == 2 { vec![d.clone(), p.clone()] } else { vec![d.clone()] };
        // The controller catches up with the home, then proposes a transition.
        let mut ctl = controller_engine(&f, &host, &src, &d, t);
        let peer = Relay::attached(relay.port, BASE_A, &account, &dir);
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
                let port = relay.port;
                std::thread::spawn(move || try_http(port, "POST", "/pending", body.as_bytes()))
            };
            std::thread::sleep(std::time::Duration::from_micros(delay));
            inside += usize::from(relay.kill());
            kills += 1;
            let answered = sender.join().unwrap();
            relay = start(&keys, &account, &dir, 0);
            check!(false);
            // The client retries until it has the home's answer.
            if answered.is_none_or(|(s, _)| s != 200) {
                let retry = try_http(relay.port, "POST", "/pending", post.as_bytes());
                assert_eq!(retry.map(|(s, _)| s), Some(200), "round {k}: the retry");
            }
            admitted.insert(digest.clone(), "transitions");
            check!(false);
        }
        // Every third round the owner vetoes it in time, from the other unit (the passkey),
        // killed at a random point while the home admits and receipts the veto: the veto is kept,
        // and the transition is `vetoed`, never activated.
        let vetoed = k % 3 == 1;
        if vetoed {
            clock(t + 2_000);
            let peer = Relay::attached(relay.port, BASE_A, &account, &dir);
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
                let port = relay.port;
                std::thread::spawn(move || try_http(port, "POST", "/pending", body.as_bytes()))
            };
            std::thread::sleep(std::time::Duration::from_micros(delay));
            inside += usize::from(relay.kill());
            kills += 1;
            let answered = sender.join().unwrap();
            relay = start(&keys, &account, &dir, 0);
            check!(false);
            if answered.is_none_or(|(s, _)| s != 200) {
                let retry = try_http(relay.port, "POST", "/pending", post.as_bytes());
                assert_eq!(retry.map(|(s, _)| s), Some(200), "round {k}: the veto's retry");
            }
            admitted.insert(veto_digest, "vetoes");
            check!(false);
        }
        // Restarts before it is due: everything admitted is still kept and listed.
        clock(t + 60_000);
        // The first inside the `record_due` of a scheduler pass at the new clock reading, the
        // second at a random point of a pass.
        for j in 0..2 {
            inside += usize::from(if j == 0 { relay.kill_in_record_due() } else { relay.kill_while_ticking(rnd(40_000)) });
            kills += 1;
            relay = start(&keys, &account, &dir, 0);
            check!(false);
        }
        // Due: the home records `activate`, signs a head, then records `final` (or, vetoed, the
        // `vetoed`). Killed first inside the `record_due` of the first pass at the due clock
        // reading, then at random points of later passes.
        let due = t + HOUR_MS + 400_000;
        clock(due);
        for j in 0..5 {
            inside += usize::from(if j == 0 { relay.kill_in_record_due() } else { relay.kill_while_ticking(rnd(120_000)) });
            kills += 1;
            relay = start(&keys, &account, &dir, 0);
            check!(false);
        }
        // A real clock moves on: a head over the `activate` needs an `issued` after the head
        // the home may have signed at the same clock reading (strictly increasing, §13.3).
        clock(due + 2_000);
        want += if vetoed { 1 } else { 2 };
        // Scheduler passes until it has (a bounded number of passes, not a deadline).
        let mut passes = 0;
        let entries = loop {
            let e = check!(false);
            if e.len() >= want || passes == 20 {
                break e;
            }
            relay.tick();
            passes += 1;
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
        // the listing, across one more restart; and every file is asked for again.
        inside += usize::from(relay.kill());
        kills += 1;
        relay = start(&keys, &account, &dir, 0);
        let entries = check!(true);
        assert!(settled_by(&entries).contains(&digest), "round {k}: settled");
        eprintln!("kill loop: round {k} done, {kills} kills so far ({inside} inside record_due), {:?}", started.elapsed());
    }
    let _ = relay.kill();
    eprintln!(
        "kill loop: {kills} kills, {inside} of them inside record_due, {startup_kills} right after start-up, {} transitions activated and final, {vetoes} vetoed, {} transitions and vetoes kept, {:?}",
        rounds as usize - vetoes,
        admitted.len(),
        started.elapsed()
    );
    assert!(kills >= 200, "{kills}");
    assert!(inside > 0, "some kills landed inside record_due");
}
