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
        eprintln!(
            "SKIPPED: the relay journeys need `bun` and the wasm build ({}): \
             cargo build --target wasm32-unknown-unknown --release -p colophon-home-wasm",
            wasm.display()
        );
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
    child: Child,
    pub port: u16,
    pub dir: PathBuf,
    pub clock: PathBuf,
    pub base: String,
}
impl Relay {
    pub fn start(
        keys: &HomeKeys,
        base: &str,
        dir: &std::path::Path,
        clock_ms: i64,
        resolve: &[(&str, u16)],
    ) -> Self {
        Self::start_on(keys, base, dir, clock_ms, resolve, 0)
    }
    pub fn start_on(
        keys: &HomeKeys,
        base: &str,
        dir: &std::path::Path,
        clock_ms: i64,
        resolve: &[(&str, u16)],
        port: u16,
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
        std::fs::write(&config, json!({"resolve": resolve_map}).to_string()).unwrap();
        let mut child = Command::new("bun")
            .arg(relay)
            .arg("--config")
            .arg(&config)
            .env("COLOPHON_RELAY_PORT", port.to_string())
            .env("COLOPHON_RELAY_DATA", dir.join("data"))
            .env("COLOPHON_RELAY_TOKENS", format!("home={TOKEN}"))
            .env("COLOPHON_RELAY_HOME_SLOTS", format!("home={base}"))
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
            child,
            port,
            dir: dir.to_path_buf(),
            clock,
            base: base.to_string(),
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
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
    pub fn restart(self, keys: &HomeKeys, clock_ms: i64, resolve: &[(&str, u16)]) -> Self {
        let mut me = self;
        me.stop();
        let (dir, base, port) = (me.dir.clone(), me.base.clone(), me.port);
        Self::start_on(keys, &base, &dir, clock_ms, resolve, port)
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
        let mut headers = req.headers.clone();
        if !headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("authorization"))
        {
            headers.push(("Authorization".into(), format!("Bearer {TOKEN}")));
        }
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
