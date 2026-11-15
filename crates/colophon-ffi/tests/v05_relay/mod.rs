//! The real relay (`relay/server.js` on Bun, the Rust home module in WebAssembly) as a home for
//! tests through the exports: started on loopback with a temporary data directory and the
//! explicit test clock, one slot provisioned for one account, killed when dropped.
//!
//! Missing Bun or the module fails the test (it never passes by skipping): build the module with
//! `scripts/test-home.sh`, or `cargo build --target wasm32-unknown-unknown --release -p
//! colophon-home-wasm`, and set `COLOPHON_HOME_WASM` if it is not under `CARGO_TARGET_DIR`.
#![allow(dead_code, clippy::unwrap_used)]
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

/// The relay script and the home module, or a panic naming what is missing.
pub fn prerequisites() -> (PathBuf, PathBuf) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let relay = root.join("relay/server.js");
    let wasm = std::env::var("COLOPHON_HOME_WASM").map(PathBuf::from).unwrap_or_else(|_| {
        std::env::var("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| root.join("target"))
            .join("wasm32-unknown-unknown/release/colophon_home_wasm.wasm")
    });
    assert!(
        Command::new("bun").arg("--version").output().is_ok_and(|o| o.status.success()),
        "Bun is required for the relay journeys"
    );
    assert!(wasm.exists(), "the home module is required: {} (build it with scripts/test-home.sh)", wasm.display());
    (relay, wasm)
}

/// A home key: a P-256 scalar, as the relay's private JWK and as the test's signer.
pub struct HomeKey {
    pub scalar: [u8; 32],
    pub point: Vec<u8>,
}
impl HomeKey {
    pub fn jwk(&self) -> String {
        let e = |b: &[u8]| colophon_core::v05::encoding::encode_base64url(b);
        serde_json::json!({"kty": "EC", "crv": "P-256", "x": e(&self.point[1..33]),
                           "y": e(&self.point[33..65]), "d": e(&self.scalar)})
        .to_string()
    }
}

/// A test directory, removed when dropped.
pub struct Scratch(pub PathBuf);
impl Scratch {
    pub fn new(name: &str) -> Self {
        let d = std::env::temp_dir().join(format!("colophon-ffi-relay-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Self(d)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A running relay with one home slot. `base` is the slot's public base (an `https://` name the
/// account's history names); the test maps it to the process.
pub struct Relay {
    child: Child,
    pub port: u16,
    pub base: String,
    clock: PathBuf,
    _dir: Scratch,
}
impl Relay {
    /// Start the relay for `account` at `base`, signing with `key`; `peers` maps other homes'
    /// bases to their ports (for forwarding).
    pub fn start(key: &HomeKey, account: &str, base: &str, clock_ms: i64, peers: &[(&str, u16)], name: &str) -> Self {
        Self::start_on(key, account, base, clock_ms, peers, name, 0)
    }
    /// The same on a chosen port (0: any).
    pub fn start_on(key: &HomeKey, account: &str, base: &str, clock_ms: i64, peers: &[(&str, u16)], name: &str, port: u16) -> Self {
        let (relay, wasm) = prerequisites();
        let dir = Scratch::new(name);
        let clock = dir.0.join("clock");
        std::fs::write(&clock, clock_ms.to_string()).unwrap();
        let resolve: serde_json::Map<String, serde_json::Value> = peers
            .iter()
            .map(|(b, p)| (b.to_string(), serde_json::json!(format!("http://127.0.0.1:{p}/v1/libraries/home"))))
            .collect();
        let config = dir.0.join("config.json");
        std::fs::write(&config, serde_json::json!({"resolve": resolve}).to_string()).unwrap();
        let mut child = Command::new("bun")
            .arg(relay)
            .arg("--test-clock")
            .arg("--config")
            .arg(&config)
            .env("COLOPHON_RELAY_PORT", port.to_string())
            .env("COLOPHON_RELAY_DATA", dir.0.join("data"))
            .env("COLOPHON_RELAY_HOME_SLOTS", format!("home={account}@{base}"))
            .env("COLOPHON_HOME_KEY", key.jwk())
            .env("COLOPHON_HOME_WASM", wasm)
            .env("COLOPHON_RELAY_CLOCK_FILE", &clock)
            .env("COLOPHON_RELAY_TICK_MS", "50")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.as_mut().unwrap()).read_line(&mut line).unwrap();
        let v: serde_json::Value = serde_json::from_str(&line).expect("the relay's listening line");
        let port = v["listening"]["port"].as_u64().unwrap() as u16;
        Self { child, port, base: base.trim_end_matches('/').to_string(), clock, _dir: dir }
    }
    pub fn set_clock(&self, ms: i64) {
        std::fs::write(&self.clock, ms.to_string()).unwrap();
    }
    /// Send one request for `url` (at this relay's base) and return `(status, body)`.
    pub fn send(&self, method: &str, url: &str, headers: &[(String, String)], body: &[u8], now_ms: i64) -> (u16, Vec<u8>) {
        self.set_clock(now_ms);
        let rest = url.strip_prefix(&self.base).expect("a URL at this relay");
        let path = format!("/v1/libraries/home{rest}");
        let mut s = TcpStream::connect(("127.0.0.1", self.port)).unwrap();
        let mut req = format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Length: {}\r\n", body.len());
        for (k, v) in headers {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        req.push_str("\r\n");
        s.write_all(req.as_bytes()).unwrap();
        s.write_all(body).unwrap();
        let mut raw = Vec::new();
        s.read_to_end(&mut raw).unwrap();
        let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        let head = String::from_utf8_lossy(&raw[..split]).to_string();
        let status = head.split(' ').nth(1).unwrap().parse().unwrap();
        let mut body = raw[split + 4..].to_vec();
        if head.to_ascii_lowercase().contains("transfer-encoding: chunked") {
            body = dechunk(&body);
        }
        (status, body)
    }
}
impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
fn dechunk(mut b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let Some(i) = b.windows(2).position(|w| w == b"\r\n") else { return out };
        let n = usize::from_str_radix(String::from_utf8_lossy(&b[..i]).trim(), 16).unwrap_or(0);
        if n == 0 {
            return out;
        }
        out.extend_from_slice(&b[i + 2..i + 2 + n]);
        b = &b[i + 2 + n + 2..];
    }
}

/// A free local port (bound and released: a short race, accepted in a test).
pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}
