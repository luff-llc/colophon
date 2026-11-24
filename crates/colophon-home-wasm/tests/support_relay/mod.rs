//! A relay process started by the test, an HTTP client over `std::net`, and the glue that lets the
//! engine's exchange (sans-IO) talk to it: the test performs each request the engine asks for.
#![allow(
    dead_code,
    unused_imports,
    clippy::unwrap_used,
    clippy::too_many_arguments,
    clippy::cloned_ref_to_slice_refs
)]
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use colophon_core::v05::account::*;
use colophon_core::v05::engine::exchange::{Method, Request, Response};
use colophon_core::v05::ids::key_id;
use colophon_core::v05::write::calls::RequestSpec;
use colophon_core::v05::write::SignatureResult;
use p256::ecdsa::{signature::Signer, SigningKey};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Mutex;

use crate::support::*;

pub const BASE_A: &str = "https://home-a.example";
pub const BASE_B: &str = "https://home-b.example";
pub const TOKEN: &str = "test-token-0123456789abcdef";

/// Where the pieces are, or `None` (with a loud note) when this machine cannot run the relay.
pub fn prerequisites() -> Option<(PathBuf, PathBuf)> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let relay = root.join("relay/server.js");
    let wasm = std::env::var("COLOPHON_HOME_WASM")
        .map(PathBuf::from)
        .ok()
        .or_else(|| {
            let target = std::env::var("CARGO_TARGET_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| root.join("target"));
            Some(target.join("wasm32-unknown-unknown/release/colophon_home_wasm.wasm"))
        })?;
    let bun = Command::new("bun")
        .arg("--version")
        .stdout(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !bun || !wasm.exists() || !relay.exists() {
        let missing = format!(
            "the relay tests need `bun` (found: {bun}) and the wasm build ({}, found: {}): \
             run scripts/test-home.sh, or cargo build --target wasm32-unknown-unknown --release -p colophon-home-wasm",
            wasm.display(),
            wasm.exists()
        );
        // On CI a test that cannot run fails; it never passes by skipping.
        if std::env::var_os("CI").is_some() || std::env::var_os("COLOPHON_REQUIRE_RELAY").is_some() {
            panic!("CI: {missing}");
        }
        eprintln!("SKIPPED: {missing}");
        // Also to the terminal, past cargo's output capture.
        if let Ok(mut tty) = std::fs::OpenOptions::new().write(true).open("/dev/tty") {
            let _ = writeln!(tty, "SKIPPED: {missing}");
        }
        return None;
    }
    Some((relay, wasm))
}

pub fn http(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(std::time::Duration::from_secs(60)))
        .unwrap();
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n");
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    if method != "GET" && method != "HEAD" {
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    head.push_str("\r\n");
    s.write_all(head.as_bytes()).unwrap();
    s.write_all(body).unwrap();
    let mut raw = Vec::new();
    let _ = s.read_to_end(&mut raw);
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("a response head");
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let mut lines = head.lines();
    let status: u16 = lines
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let hs = lines
        .filter_map(|l| l.split_once(": ").map(|(k, v)| (k.to_lowercase(), v.to_string())))
        .collect();
    (status, hs, raw[split + 4..].to_vec())
}

/// A deterministic home key: a private P-256 JWK from a fixed scalar. A test fixture, not a
/// secret: it protects nothing.
pub struct HomeKeys {
    pub sk: SigningKey,
    pub point: Vec<u8>,
    pub id: String,
}
impl HomeKeys {
    pub fn new(n: u8) -> Self {
        let sk = SigningKey::from_slice(&[n; 32]).unwrap();
        let point = sk.verifying_key().to_encoded_point(false).as_bytes().to_vec();
        let id = key_id(&point);
        Self { sk, point, id }
    }
    pub fn jwk(&self) -> String {
        let e = |b: &[u8]| URL_SAFE_NO_PAD.encode(b);
        json!({"kty": "EC", "crv": "P-256", "x": e(&self.point[1..33]), "y": e(&self.point[33..65]),
               "d": e(&self.sk.to_bytes())})
        .to_string()
    }
    pub fn sign(&self, body: &[u8]) -> SignatureResult {
        let sig: p256::ecdsa::Signature = self.sk.sign(body);
        SignatureResult {
            signature: sig.to_bytes().to_vec(),
            assertion: None,
        }
    }
}

/// A running relay process. Dropped, it is killed and waited for.
pub struct Relay {
    child: Option<Child>,
    /// The relay's stdin and the rest of its stdout (after the listening line), for `tick`.
    control: Option<Mutex<(ChildStdin, BufReader<ChildStdout>)>>,
    /// The relay `limits` it was started with (kept across `restart`).
    limits: Value,
    pub port: u16,
    pub dir: PathBuf,
    pub clock: PathBuf,
    pub base: String,
    /// The account the slot is provisioned for.
    pub account: String,
}
impl Relay {
    pub fn start(
        keys: &HomeKeys,
        account: &str,
        base: &str,
        dir: &std::path::Path,
        clock_ms: i64,
        resolve: &[(&str, u16)],
    ) -> Self {
        Self::start_on(keys, account, base, dir, clock_ms, resolve, 0)
    }
    pub fn start_on(
        keys: &HomeKeys,
        account: &str,
        base: &str,
        dir: &std::path::Path,
        clock_ms: i64,
        resolve: &[(&str, u16)],
        port: u16,
    ) -> Self {
        Self::start_with(keys, account, base, dir, clock_ms, resolve, port, json!({}))
    }
    /// The same with relay `limits` set in the config file. No relay started here runs a scheduler
    /// timer unless `tickMs` there asks for one: a head read settles a home by itself, and a test
    /// runs each other scheduler pass it needs with `tick` (or `ticks_until`, `forwarded`), so no
    /// outcome rests on how much real time passes between two requests.
    pub fn start_with(
        keys: &HomeKeys,
        account: &str,
        base: &str,
        dir: &std::path::Path,
        clock_ms: i64,
        resolve: &[(&str, u16)],
        port: u16,
        limits: Value,
    ) -> Self {
        Self::launch(keys, account, base, dir, clock_ms, resolve, port, limits, None).0
    }
    /// A relay with no scheduler timer, traced: it waits at the trace point `pause_at` (the first
    /// time it is reached) until the file `resume` in `dir` exists. Returns the relay and its trace
    /// lines (stderr), for `trace_marker`.
    pub fn start_paused(
        keys: &HomeKeys,
        account: &str,
        base: &str,
        dir: &std::path::Path,
        clock_ms: i64,
        pause_at: &str,
    ) -> (Self, std::sync::mpsc::Receiver<String>) {
        let limits = json!({"tickMs": 0});
        let (relay, rx) = Self::launch(keys, account, base, dir, clock_ms, &[], 0, limits, Some(pause_at));
        (relay, rx.unwrap())
    }
    fn launch(
        keys: &HomeKeys,
        account: &str,
        base: &str,
        dir: &std::path::Path,
        clock_ms: i64,
        resolve: &[(&str, u16)],
        port: u16,
        limits: Value,
        pause_at: Option<&str>,
    ) -> (Self, Option<std::sync::mpsc::Receiver<String>>) {
        let (relay, wasm) = prerequisites().expect("prerequisites");
        std::fs::create_dir_all(dir).unwrap();
        let clock = dir.join("clock");
        write_clock(&clock, clock_ms);
        let config = dir.join("config.json");
        write_resolve(&dir.join("resolve.json"), resolve);
        std::fs::write(&config, json!({"limits": limits}).to_string()).unwrap();
        let mut cmd = Command::new("bun");
        cmd.arg(relay)
            .arg("--test-clock")
            .arg("--config")
            .arg(&config)
            .env("COLOPHON_RELAY_PORT", port.to_string())
            .env("COLOPHON_RELAY_DATA", dir.join("data"))
            .env("COLOPHON_RELAY_HOME_SLOTS", format!("home={account}@{base}"))
            .env("COLOPHON_HOME_KEY", keys.jwk())
            .env("COLOPHON_HOME_WASM", wasm)
            .env("COLOPHON_RELAY_CLOCK_FILE", &clock)
            .env("COLOPHON_RELAY_RESOLVE_FILE", dir.join("resolve.json"))
            .env(
                "COLOPHON_RELAY_TICK_MS",
                limits.get("tickMs").and_then(Value::as_u64).map_or("0".to_string(), |t| t.to_string()),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        if let Some(point) = pause_at {
            cmd.env("COLOPHON_RELAY_TRACE", "1")
                .env("COLOPHON_RELAY_PAUSE_AT", point)
                .env("COLOPHON_RELAY_RESUME_FILE", dir.join("resume"))
                .stderr(Stdio::piped());
        }
        let mut child = cmd.spawn().unwrap();
        let rx = pause_at.map(|_| {
            let (tx, rx) = std::sync::mpsc::channel();
            let err = child.stderr.take().unwrap();
            std::thread::spawn(move || {
                for line in BufReader::new(err).lines().map_while(Result::ok) {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
            });
            rx
        });
        let stdin = child.stdin.take().unwrap();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        let v: Value = serde_json::from_str(&line).expect("the listening line");
        let port = v["listening"]["port"].as_u64().unwrap() as u16;
        let me = Self {
            child: Some(child),
            control: Some(Mutex::new((stdin, stdout))),
            limits,
            port,
            dir: dir.to_path_buf(),
            clock,
            base: base.to_string(),
            account: account.to_string(),
        };
        (me, rx)
    }
    pub fn set_clock(&self, ms: i64) {
        write_clock(&self.clock, ms);
    }
    /// Run one scheduler pass over every home slot (recording entries, heads; forwarding is
    /// started, not awaited) and return once it is done: the relay's `--test-clock` stdin hook,
    /// which answers `{"ticked":true}` on stdout. Other stdout lines are skipped.
    pub fn tick(&self) {
        let control = self.control.as_ref().expect("a relay this test started");
        let mut guard = control.lock().unwrap();
        let (stdin, stdout) = &mut *guard;
        stdin.write_all(b"tick\n").unwrap();
        stdin.flush().unwrap();
        loop {
            let mut line = String::new();
            assert!(stdout.read_line(&mut line).unwrap() > 0, "the relay exited before it ticked");
            if serde_json::from_str::<Value>(&line).ok() == Some(json!({"ticked": true})) {
                return;
            }
        }
    }
    /// Where this relay reaches other homes (base, port), read by the relay at each use.
    pub fn set_resolve(&self, resolve: &[(&str, u16)]) {
        write_resolve(&self.dir.join("resolve.json"), resolve);
    }
    pub fn url(&self, path: &str) -> String {
        format!("/v1/libraries/home{path}")
    }
    pub fn get(&self, path: &str) -> (u16, Vec<u8>) {
        let (s, _, b) = http(self.port, "GET", &self.url(path), &[], &[]);
        (s, b)
    }
    pub fn bearer() -> Vec<(String, String)> {
        vec![("Authorization".into(), format!("Bearer {TOKEN}"))]
    }
    pub fn post(&self, path: &str, body: &Value) -> (u16, Value) {
        let (s, _, b) = http(
            self.port,
            "POST",
            &self.url(path),
            &[("Content-Type".into(), "application/json".into())],
            body.to_string().as_bytes(),
        );
        (s, serde_json::from_slice(&b).unwrap_or(Value::Null))
    }
/// The serving intervals a home slot's committed state holds (`[from, through]`, ms; `through`
    /// `None` while open), read from `home-state.json`.
    pub fn serving(&self) -> Vec<(i64, Option<i64>)> {
        use base64::engine::general_purpose::STANDARD;
        let text = std::fs::read_to_string(self.dir.join("data/home/home-state.json")).unwrap();
        let outer: String = serde_json::from_str(&text).unwrap();
        let slot: Value = serde_json::from_slice(&STANDARD.decode(outer).unwrap()).unwrap();
        let home: Value =
            serde_json::from_slice(&STANDARD.decode(slot["home_state"].as_str().unwrap()).unwrap()).unwrap();
        home["serving"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| (i["from_ms"].as_i64().unwrap(), i["through_ms"].as_i64()))
            .collect()
    }
    /// Stop the process and wait for it.
    pub fn stop(&mut self) {
        if let Some(c) = self.child.as_mut() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
    /// A relay process this test does not own (started and killed elsewhere), to talk to.
    pub fn attached(port: u16, base: &str, account: &str, dir: &std::path::Path) -> Self {
        Self {
            child: None,
            control: None,
            limits: json!({}),
            port,
            dir: dir.to_path_buf(),
            clock: dir.join("clock"),
            base: base.to_string(),
            account: account.to_string(),
        }
    }
    pub fn restart(self, keys: &HomeKeys, clock_ms: i64, resolve: &[(&str, u16)]) -> Self {
        let mut me = self;
        me.stop();
        let (dir, base, account) = (me.dir.clone(), me.base.clone(), me.account.clone());
        let limits = me.limits.clone();
        // A new port (port 0, the one the relay reports): the old one may be taken meanwhile.
        Self::start_with(keys, &account, &base, &dir, clock_ms, resolve, 0, limits)
    }
}
impl Drop for Relay {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The engine's transport to the relay: the test sends each request, rewriting the account's
/// endpoint (an `https://` name §9.1 requires) to the process on localhost.
pub struct RealRelay<'a> {
    pub relays: Vec<&'a Relay>,
    pub requests: Vec<String>,
}
impl<'a> RealRelay<'a> {
    pub fn new(relay: &'a Relay) -> Self {
        Self::many(vec![relay])
    }
    pub fn many(relays: Vec<&'a Relay>) -> Self {
        Self {
            relays,
            requests: Vec::new(),
        }
    }
}
impl Wire for RealRelay<'_> {
    fn call(&mut self, _host: &Host, req: &Request, now_ms: i64) -> Response {
        let relay = *self
            .relays
            .iter()
            .find(|r| req.url.starts_with(&r.base))
            .expect("another home's URL");
        relay.set_clock(now_ms);
        let rest = req.url.strip_prefix(&relay.base).unwrap();
        let method = match req.method {
            Method::Get => "GET",
            Method::Post => "POST",
            Method::Put => "PUT",
        };
        self.requests.push(format!(
            "{method} {}",
            rest.split('?').next().unwrap_or(rest)
        ));
        let headers = req.headers.clone();
        let (status, hs, body) = http(
            relay.port,
            method,
            &relay.url(rest),
            &headers,
            &req.body,
        );
        if status >= 400 && status != 404 {
            eprintln!("{method} {rest} -> {status} {}", String::from_utf8_lossy(&body).chars().take(300).collect::<String>());
        }
        Response {
            status,
            headers: hs,
            body,
        }
    }
}

/// A fixture like `create`, with the history readable by anyone (the engine's reads carry no
/// call in these journeys), and a home whose keys the relay holds.
pub fn create_public(namespaces: &[&str]) -> Fixture {
    create_with(namespaces, "public", 1)
}

/// The same, with the history policy ("public" or "members") and `headQuorum` chosen.
pub fn create_with(namespaces: &[&str], history: &str, quorum: u64) -> Fixture {
    let mut host = Host::new();
    let d = host.identity(10);
    let k = host.kit(20);
    let p = host.passkey();
    let mut params = params(&mut host, &d, &p, &k, namespaces);
    if let Some(policy) = params.policy.as_mut() {
        policy["history"] = json!(history);
        policy["headQuorum"] = json!(quorum);
    }
    let mut creation = Creation::begin(params, Identity::Controller(d.clone()), T0).unwrap();
    let results = host.answer_prf(creation.prf_requests());
    creation = creation.provide_prf(results).unwrap();
    let sigs = host.sign(creation.steps());
    let mut progress = creation.provide_signatures(sigs).unwrap();
    loop {
        match progress {
            CreateProgress::Continue(c) => {
                let sigs = host.sign(c.steps());
                progress = c.provide_signatures(sigs).unwrap();
            }
            CreateProgress::Done(account) => {
                return Fixture {
                    host,
                    d,
                    p,
                    k,
                    account: *account,
                }
            }
        }
    }
}

/// Appoint a home whose key the test holds (a transition recorded at once: there is no home yet
/// to witness time). `endpoints` are `https://` names; the test maps them to processes.
pub fn appoint_home_keys(f: &mut Fixture, keys: &HomeKeys, endpoint: &str) -> String {
    appoint_homes(f, &[(keys, endpoint)]);
    keys.id.clone()
}

/// Appoint several homes in one transition.
pub fn appoint_homes(f: &mut Fixture, homes: &[(&HomeKeys, &str)]) {
    let mut appoint = Vec::new();
    for (n, (keys, endpoint)) in homes.iter().enumerate() {
        let agreement = f.host.identity(71 + n as u8);
        let agreement = f.host.ids[&agreement].public().agreement;
        let created = colophon_core::v05::write::format_date(f.account.now_ms());
        let prepared = prepare_request(&RequestSpec {
            account: f.account.id(),
            signing: &keys.point,
            agreement: &agreement,
            label: "Home",
            kind: "server",
            terms: json!({"serves": ["home"]}),
            created: &created,
            custody: None,
            operator: None,
            endpoints: Some(vec![endpoint.to_string()]),
        })
        .unwrap();
        let sig = keys.sign(prepared.step().body());
        let req = finish_request(&prepared, &sig).unwrap();
        appoint.push(json!({"request": b64(&req.raw), "terms": {"serves": ["home"]}}));
    }
    let change = Change::homes(json!({"appoint": appoint}));
    let action = f
        .account
        .begin_transition(
            &change,
            &[f.d.clone(), f.k.clone()],
            colophon_core::v05::write::authority::TransitionRule::Control,
        )
        .unwrap();
    run(&mut f.account, &f.host, action);
    let rec = f.account.record_due().unwrap();
    assert_eq!(rec.len(), 1);
}

/// The account's entries in seq order, as JSON values.
pub fn entries_json(f: &Fixture) -> Vec<(u64, Value)> {
    let mut v: Vec<(u64, Value)> = f
        .account
        .objects()
        .entries
        .iter()
        .map(|e| (entry_seq(e), serde_json::from_slice(e).unwrap()))
        .collect();
    v.sort_by_key(|(s, _)| *s);
    v
}

/// Upload the whole history to a fresh home as a first upload (§13.1), in pages of 64.
pub fn first_upload(relay: &Relay, f: &Fixture, now_ms: i64) {
    relay.set_clock(now_ms);
    let all = entries_json(f);
    for chunk in all.chunks(64) {
        let from = chunk[0].0;
        let entries: Vec<&Value> = chunk.iter().map(|(_, e)| e).collect();
        let (status, body) = relay.post(
            "/authority",
            &json!({"from": from, "entries": entries, "receipts": []}),
        );
        assert_eq!(status, 200, "first upload at {from}: {body}");
    }
}

/// Set a test clock file atomically (a staged file renamed over it): the relay reads it on every
/// call, and a reading taken mid-write would be empty.
pub fn write_clock(path: &std::path::Path, ms: i64) {
    let staged = path.with_extension(format!("{}.tmp", std::process::id()));
    std::fs::write(&staged, ms.to_string()).unwrap();
    std::fs::rename(&staged, path).unwrap();
}

/// Write a test relay's resolve file atomically: another home's base -> its local URL.
pub fn write_resolve(path: &std::path::Path, resolve: &[(&str, u16)]) {
    let map: serde_json::Map<String, Value> = resolve
        .iter()
        .map(|(b, p)| (b.to_string(), json!(format!("http://127.0.0.1:{p}/v1/libraries/home"))))
        .collect();
    let staged = path.with_extension(format!("{}.tmp", std::process::id()));
    std::fs::write(&staged, Value::Object(map).to_string()).unwrap();
    std::fs::rename(&staged, path).unwrap();
}

/// A local port nothing listens on (a connection is refused at once): port 1 needs privileges
/// to bind, so no test relay can take it. Every relay itself starts on port 0 and reports its
/// port; homes learn one another's through `Relay::set_resolve`.
pub const CLOSED_PORT: u16 = 1;

/// One scheduler pass at each of `relays`, then `done`, at most `max` times; no waiting. For
/// what a home's own passes produce (recording entries, heads), not for forwarding between homes.
pub fn ticks_until(what: &str, max: usize, relays: &[&Relay], mut done: impl FnMut() -> bool) {
    for _ in 0..max {
        for r in relays {
            r.tick();
        }
        if done() {
            return;
        }
    }
    panic!("{what}: not after {max} scheduler passes");
}

/// Forwarding between homes: each poll runs one pass at each of `relays` (which starts their
/// forwarding and does not wait for it); the wait is only for that I/O to finish.
pub fn forwarded(what: &str, relays: &[&Relay], mut done: impl FnMut() -> bool) {
    eventually(what, 30, || {
        for r in relays {
            r.tick();
        }
        done()
    });
}

/// Two running homes each hold the other's head, issued at `at` or later (`id_a`, `id_b`: their
/// member ids): what a timer's passes used to forward before anything else. A home at
/// `headQuorum` 2 answers calls only with both homes' fresh heads.
pub fn heads_exchanged(a: &Relay, id_a: &str, b: &Relay, id_b: &str, at: i64) {
    let since = colophon_core::v05::write::format_date(at);
    let holds = |r: &Relay, id: &str| {
        let (s, bytes) = r.get(&format!("/records/heads/{id}.json"));
        s == 200 && serde_json::from_slice::<Value>(&bytes).ok().and_then(|v| {
            let body = base64::engine::general_purpose::STANDARD.decode(v["body"].as_str()?).ok()?;
            let h: Value = serde_json::from_slice(&body).ok()?;
            Some(h["issued"].as_str()? >= since.as_str())
        }) == Some(true)
    };
    forwarded("each home holds the other's fresh head", &[a, b], || holds(a, id_b) && holds(b, id_a));
}

/// Wait until `f` holds, polling; panics with `what` after `secs` seconds.
pub fn eventually(what: &str, secs: u64, mut f: impl FnMut() -> bool) {
    let end = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    while std::time::Instant::now() < end {
        if f() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    panic!("timed out waiting for {what}");
}

/// The kinds of the entries a home serves, in seq order.
pub fn kinds(relay: &Relay) -> Vec<String> {
    let (s, _, b) = http(
        relay.port,
        "GET",
        &relay.url("/authority?after=0&limit=64"),
        &[],
        &[],
    );
    assert_eq!(s, 200);
    let v: Value = serde_json::from_slice(&b).unwrap();
    v["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            let body = base64::engine::general_purpose::STANDARD
                .decode(e["body"].as_str().unwrap())
                .unwrap();
            let b: Value = serde_json::from_slice(&body).unwrap();
            b["kind"].as_str().unwrap().to_string()
        })
        .collect()
}

/// A call for one home request, in the shape the home binds it to (§12.2, §14): `args` is
/// exactly `{"method", "path", "body"}` (the path and query relative to the home's base as sent,
/// and the lowercase hex SHA-256 of the body), `purpose` is `colophon.home.read` for GET and HEAD
/// and `colophon.home.write` otherwise, and `audience` is the home's base. Signed with the
/// acting principal's own key (no links).
pub fn home_call(
    host: &Host,
    account: &Account,
    audience: &str,
    method: &str,
    path: &str,
    body: &[u8],
    now_ms: i64,
    request_id: [u8; 32],
) -> Vec<u8> {
    use base64::engine::general_purpose::STANDARD;
    use sha2::Digest as _;
    let purpose = if matches!(method, "GET" | "HEAD") {
        "colophon.home.read"
    } else {
        "colophon.home.write"
    };
    let args = json!({"method": method, "path": path, "body": hex(&sha2::Sha256::digest(body))});
    home_call_with(host, account, audience, purpose, args, now_ms, request_id)
}

/// The same with `purpose` and `args` chosen (for the mismatch tests).
pub fn home_call_with(
    host: &Host,
    account: &Account,
    audience: &str,
    purpose: &str,
    args: Value,
    now_ms: i64,
    request_id: [u8; 32],
) -> Vec<u8> {
    let (kind, id) = match account.identity() {
        Identity::Controller(id) => ("controller", id.clone()),
        Identity::Member(id) => ("member", id.clone()),
    };
    call_as(host, account, kind, &id, audience, purpose, args, now_ms, request_id)
}

/// A call signed by the principal `kind` (`member` or `controller`) `id`, whose key the host
/// holds, over what `account` has verified.
pub fn call_as(
    host: &Host,
    account: &Account,
    kind: &str,
    id: &str,
    audience: &str,
    purpose: &str,
    args: Value,
    now_ms: i64,
    request_id: [u8; 32],
) -> Vec<u8> {
    use base64::engine::general_purpose::STANDARD;
    let me = &host.ids[id];
    let (seq, digest) = account.head();
    let body = colophon_core::v05::encoding::canonical(&json!({
        "protocol": "colophon/call/5",
        "account": account.id().as_str(),
        "asOf": {"seq": seq, "digest": digest},
        "signer": {kind: id},
        "key": STANDARD.encode(me.public().signing),
        "audience": audience,
        "purpose": purpose,
        "args": args,
        "requestId": URL_SAFE_NO_PAD.encode(request_id),
        "created": colophon_core::v05::write::format_date(now_ms),
    }))
    .unwrap();
    let sig = me.sign(&body).to_vec();
    serde_json::to_vec(&json!({"body": STANDARD.encode(&body), "signature": STANDARD.encode(sig)}))
        .unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

static REQUEST_IDS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
pub fn fresh_request_id() -> [u8; 32] {
    let n = REQUEST_IDS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut id = [0u8; 32];
    id[..8].copy_from_slice(&n.to_le_bytes());
    id[8..12].copy_from_slice(&std::process::id().to_le_bytes());
    id
}

/// A sync pass against real relays, with real calls: for each `NeedCall` the engine builds the
/// call for exactly the request it will send (`exchange_begin_call`: audience, purpose, method,
/// path and body digest are the engine's), the host signs it with the engine principal's key, and
/// `finish_write` returns it after the signer's own judgement by the home's rule.
pub fn relay_pass<S: colophon_core::v05::engine::RecordSource>(
    e: &mut colophon_core::v05::engine::Engine<S>,
    src: &MemSource,
    home: &str,
    wire: &mut RealRelay,
    host: &Host,
    now_ms: i64,
) -> Vec<colophon_core::v05::engine::exchange::Fault> {
    use colophon_core::v05::engine::exchange::Step;
    let mut faults = Vec::new();
    e.advance(now_ms).unwrap();
    e.refresh(src.listing()).unwrap();
    for _ in 0..1_000_000 {
        match e.exchange_next(home).unwrap() {
            Step::Done => return faults,
            Step::Waiting => panic!("the loop answers every request"),
            Step::NeedCall(n) => provide_call(e, host, home, &n),
            Step::Request(r) => {
                let a = wire.call(host, &r, now_ms);
                let report = e.exchange_answer(home, r.ticket, a).unwrap();
                for (p, b) in report.store {
                    src.put(&p, b);
                }
                faults.extend(report.faults);
            }
        }
    }
    panic!("a pass did not end");
}

/// Answer what an engine has queued (no new pass), with real calls as [`relay_pass`] builds them.
pub fn relay_drain<S: colophon_core::v05::engine::RecordSource>(
    e: &mut colophon_core::v05::engine::Engine<S>,
    src: &MemSource,
    home: &str,
    wire: &mut RealRelay,
    host: &Host,
    now_ms: i64,
) -> Vec<colophon_core::v05::engine::exchange::Fault> {
    use colophon_core::v05::engine::exchange::Step;
    let mut faults = Vec::new();
    loop {
        match e.exchange_next(home).unwrap() {
            Step::NeedCall(n) => provide_call(e, host, home, &n),
            Step::Request(r) => {
                let a = wire.call(host, &r, now_ms);
                let report = e.exchange_answer(home, r.ticket, a).unwrap();
                src.publish_stores(&report.store);
                faults.extend(report.faults);
            }
            _ => return faults,
        }
    }
}

/// Build, sign and give the call a `NeedCall` names, as a host does.
pub fn provide_call<S: colophon_core::v05::engine::RecordSource>(
    e: &mut colophon_core::v05::engine::Engine<S>,
    host: &Host,
    home: &str,
    n: &colophon_core::v05::engine::exchange::CallNeed,
) {
    let me = e.account().identity().id().to_string();
    let key = host.ids[&me].public().signing;
    let action = e
        .exchange_begin_call(home, n.ticket, &key, fresh_request_id())
        .unwrap();
    let sigs = host.sign(action.steps());
    let w = e.finish_write(action, sigs).expect("the engine's own check of its call");
    e.exchange_provide_call(home, n.ticket, &w.artifact.unwrap()).unwrap();
}

/// Wait for the first of the trace markers `any` (a bound, not a timing assertion: the marker is
/// the event). Returns the marker seen and the lines before it.
pub fn trace_marker(
    rx: &std::sync::mpsc::Receiver<String>,
    any: &[&str],
) -> (String, Vec<String>) {
    let mut seen = Vec::new();
    loop {
        let line = rx
            .recv_timeout(std::time::Duration::from_secs(120))
            .unwrap_or_else(|_| panic!("no trace marker {any:?}; saw {seen:?}"));
        if let Some(m) = any.iter().find(|m| line == format!("trace {m}")) {
            return (m.to_string(), seen);
        }
        seen.push(line);
    }
}

/// A test directory under the system's temporary directory, removed when dropped (also after a
/// failed assertion), so runs leave nothing behind.
pub struct Scratch(pub PathBuf);
impl Scratch {
    pub fn new(name: &str) -> Self {
        let d = std::env::temp_dir().join(format!("colophon-relay-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        Self(d)
    }
    pub fn path(&self) -> &std::path::Path {
        &self.0
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
