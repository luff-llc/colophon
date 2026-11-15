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
use std::process::{Child, Command, Stdio};

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
    /// The same with relay `limits` set in the config file.
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
        let (relay, wasm) = prerequisites().expect("prerequisites");
        std::fs::create_dir_all(dir).unwrap();
        let clock = dir.join("clock");
        std::fs::write(&clock, clock_ms.to_string()).unwrap();
        let config = dir.join("config.json");
        let resolve_map: serde_json::Map<String, Value> = resolve
            .iter()
            .map(|(b, p)| {
                (
                    b.to_string(),
                    json!(format!("http://127.0.0.1:{p}/v1/libraries/home")),
                )
            })
            .collect();
        std::fs::write(&config, json!({"resolve": resolve_map, "limits": limits}).to_string()).unwrap();
        let mut child = Command::new("bun")
            .arg(relay)
            .arg("--test-clock")
            .arg("--config")
            .arg(&config)
            .env("COLOPHON_RELAY_PORT", port.to_string())
            .env("COLOPHON_RELAY_DATA", dir.join("data"))
            .env("COLOPHON_RELAY_HOME_SLOTS", format!("home={account}@{base}"))
            .env("COLOPHON_HOME_KEY", keys.jwk())
            .env("COLOPHON_HOME_WASM", wasm)
            .env("COLOPHON_RELAY_CLOCK_FILE", &clock)
            .env("COLOPHON_RELAY_TICK_MS", "50")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.as_mut().unwrap())
            .read_line(&mut line)
            .unwrap();
        let v: Value = serde_json::from_str(&line).expect("the listening line");
        let port = v["listening"]["port"].as_u64().unwrap() as u16;
        Self {
            child: Some(child),
            port,
            dir: dir.to_path_buf(),
            clock,
            base: base.to_string(),
            account: account.to_string(),
        }
    }
    pub fn set_clock(&self, ms: i64) {
        std::fs::write(&self.clock, ms.to_string()).unwrap();
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
        let (dir, base, port, account) = (me.dir.clone(), me.base.clone(), me.port, me.account.clone());
        Self::start_on(keys, &account, &base, &dir, clock_ms, resolve, port)
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

/// A free local port (bound and released: a short race, accepted in a test).
pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
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

/// A sync pass against real relays, with real calls. The engine's `NeedCall` names the
/// audience, purpose, method and URL but not the request body, so the call is built when the
/// request itself is in hand (method, path relative to the base, body digest) and attached in
/// place of the placeholder the engine was given.
pub fn relay_pass<S: colophon_core::v05::engine::RecordSource>(
    e: &mut colophon_core::v05::engine::Engine<S>,
    src: &MemSource,
    home: &str,
    wire: &mut RealRelay,
    host: &Host,
    now_ms: i64,
) -> Vec<colophon_core::v05::engine::exchange::Fault> {
    use colophon_core::v05::engine::exchange::Step;
    const PLACEHOLDER: &[u8] = b"call-built-with-the-request";
    let mut faults = Vec::new();
    e.advance(now_ms).unwrap();
    e.refresh(src.listing()).unwrap();
    for _ in 0..1_000_000 {
        match e.exchange_next(home).unwrap() {
            Step::Done => return faults,
            Step::Waiting => panic!("the loop answers every request"),
            Step::NeedCall(n) => e.exchange_provide_call(home, n.ticket, PLACEHOLDER).unwrap(),
            Step::Request(mut r) => {
                attach_call(e.account(), host, wire, &mut r, PLACEHOLDER, now_ms);
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
    const PLACEHOLDER: &[u8] = b"call-built-with-the-request";
    let mut faults = Vec::new();
    loop {
        match e.exchange_next(home).unwrap() {
            Step::NeedCall(n) => e.exchange_provide_call(home, n.ticket, PLACEHOLDER).unwrap(),
            Step::Request(mut r) => {
                attach_call(e.account(), host, wire, &mut r, PLACEHOLDER, now_ms);
                let a = wire.call(host, &r, now_ms);
                let report = e.exchange_answer(home, r.ticket, a).unwrap();
                src.publish_stores(&report.store);
                faults.extend(report.faults);
            }
            _ => return faults,
        }
    }
}

/// Replace the placeholder call on `r` with a real one bound to `r`.
pub fn attach_call(account: &Account, host: &Host, wire: &RealRelay, r: &mut Request, placeholder: &[u8], now_ms: i64) {
    let marker = format!("Colophon {}", URL_SAFE_NO_PAD.encode(placeholder));
    let Some(h) = r.headers.iter_mut().find(|(k, v)| k == "Authorization" && *v == marker) else {
        return;
    };
    let relay = *wire.relays.iter().find(|x| r.url.starts_with(&x.base)).unwrap();
    let method = match r.method {
        Method::Get => "GET",
        Method::Post => "POST",
        Method::Put => "PUT",
    };
    let path = r.url.strip_prefix(&relay.base).unwrap();
    let call = home_call(host, account, &relay.base, method, path, &r.body, now_ms, fresh_request_id());
    h.1 = format!("Colophon {}", URL_SAFE_NO_PAD.encode(&call));
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
