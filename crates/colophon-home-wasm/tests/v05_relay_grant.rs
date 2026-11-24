//! Provisioning by a grant from the operator's keyring, against the REAL relay (`relay/server.js`
//! on Bun, the home module in WebAssembly). Operator behaviour of the reference home, not
//! protocol: the operator account is one of this home's own slots (`operator`), an agent is an
//! ordinary member of it with `services` terms for the door's audience and purpose
//! `home.provision`, and the door (`POST /v1/provision`, gate `"grant"`) takes a call signed by
//! that member. Every clock is the relay's test clock: nothing here waits on real time.
#![allow(
    clippy::unwrap_used,
    clippy::too_many_arguments,
    clippy::type_complexity,
    clippy::cloned_ref_to_slice_refs,
    dead_code
)]
#[path = "../../colophon-core/tests/v05_engine_support/mod.rs"]
mod support;
mod support_relay;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use colophon_core::model::Outcome;
use colophon_core::v05::account::{Change, RevokeKeep};
use colophon_core::v05::write::authority::TransitionRule;
use colophon_core::v05::write::format_date;
use serde_json::{json, Value};
use sha2::Digest as _;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::Receiver;
use support::*;
use support_relay::*;

const NS: &str = "listening.podcasts";
const PREFIX: &str = "https://home-g.example/v1/libraries/";
/// The door's own audience (§10.1), unique to this home's door.
const AUD: &str = "https://home-g.example/v1/provision";
const OP_SLOT: &str = "operator";
const PURPOSE: &str = "home.provision";
const DAY: i64 = 24 * HOUR;

fn base(slot: &str) -> String {
    format!("{PREFIX}{slot}")
}
fn sha_hex(b: &[u8]) -> String {
    sha2::Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

/// The condition every grant here carries: slots named `ci-…`, or the one called `home` (the
/// test helpers' slot, for the end-to-end journey).
fn condition() -> Value {
    json!({"any": [{"prefix": ["args.slot", "ci-"]}, {"eq": ["args.slot", "home"]}]})
}
fn grant_terms(expires_ms: i64) -> Value {
    json!({"services": [{"audience": AUD, "purposes": [PURPOSE]}],
           "expires": format_date(expires_ms), "depth": 1, "conditions": [condition()]})
}

/// The operator account (not `create_public`'s keys, so a provisioned account is another one),
/// with this home appointed at its slot and two agents admitted with grants: `m` (30 days) and
/// `m2` (two hours).
struct Operator {
    f: Fixture,
    m: String,
    m2: String,
}
fn operator(keys: &HomeKeys) -> Operator {
    let mut f = create_v(&[NS], 3);
    appoint_home_keys(&mut f, keys, &base(OP_SLOT));
    let m = f.host.identity(40);
    let m2 = f.host.identity(41);
    let now = f.account.now_ms();
    admit(
        &mut f,
        &m,
        "later CI on omarchy",
        "agent",
        grant_terms(now + 30 * DAY),
        grant_terms(now + 30 * DAY),
    );
    admit(
        &mut f,
        &m2,
        "rig two",
        "agent",
        grant_terms(now + 2 * HOUR),
        grant_terms(now + 2 * HOUR),
    );
    Operator { f, m, m2 }
}

#[derive(Default, Clone)]
struct Trace {
    crash_at: Option<String>,
    pause_at: Option<String>,
}

/// One relay process with the grant gate on, the operator slot configured, on a test clock.
struct Home {
    child: Child,
    port: u16,
    rx: Option<Receiver<String>>,
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn config(op_account: &str, provision: &Value) -> Value {
    let mut p = json!({"enabled": true, "prefix": PREFIX, "slotPattern": "^[a-z0-9-]{4,64}$", "gate": "grant",
                       "operator": {"account": op_account, "slot": OP_SLOT}, "audience": AUD});
    for (k, v) in provision.as_object().unwrap() {
        p[k] = v.clone();
    }
    json!({"libraries": {OP_SLOT: {"home": true, "account": op_account, "base": base(OP_SLOT)}},
           "provision": p, "limits": {"requestsPerMinute": 0}})
}

fn start(keys: &HomeKeys, dir: &std::path::Path, cfg: &Value, trace: &Trace) -> Home {
    let (relay, wasm) = prerequisites().expect("prerequisites");
    std::fs::create_dir_all(dir).unwrap();
    let file = dir.join("config.json");
    std::fs::write(&file, cfg.to_string()).unwrap();
    let mut cmd = Command::new("bun");
    cmd.arg(relay)
        .arg("--test-clock")
        .arg("--config")
        .arg(&file)
        .env("COLOPHON_RELAY_PORT", "0")
        .env("COLOPHON_RELAY_DATA", dir.join("data"))
        .env_remove("COLOPHON_RELAY_HOME_SLOTS")
        .env("COLOPHON_HOME_KEY", keys.jwk())
        .env("COLOPHON_HOME_WASM", wasm)
        .env("COLOPHON_RELAY_CLOCK_FILE", dir.join("clock"))
        // No scheduler timer: nothing here waits on one (the door settles a slot itself).
        .env("COLOPHON_RELAY_TICK_MS", "0")
        .stdout(Stdio::piped());
    let traced = trace.crash_at.is_some() || trace.pause_at.is_some();
    if traced {
        cmd.env("COLOPHON_RELAY_TRACE", "1").stderr(Stdio::piped());
    } else {
        cmd.stderr(Stdio::null());
    }
    if let Some(p) = &trace.crash_at {
        cmd.env("COLOPHON_RELAY_CRASH_AT", p);
    }
    if let Some(p) = &trace.pause_at {
        cmd.env("COLOPHON_RELAY_PAUSE_AT", p)
            .env("COLOPHON_RELAY_RESUME_FILE", dir.join("resume"));
    }
    let mut child = cmd.spawn().unwrap();
    let rx = if traced {
        let (tx, rx) = std::sync::mpsc::channel();
        let err = child.stderr.take().unwrap();
        std::thread::spawn(move || {
            for line in BufReader::new(err).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Some(rx)
    } else {
        None
    };
    let mut line = String::new();
    BufReader::new(child.stdout.as_mut().unwrap())
        .read_line(&mut line)
        .unwrap();
    let v: Value = serde_json::from_str(&line).expect("the listening line");
    Home {
        child,
        port: v["listening"]["port"].as_u64().unwrap() as u16,
        rx,
    }
}

/// Wait for the trace marker `what` (a bound, not a timing assertion: the marker is the event).
fn marker(rx: &Receiver<String>, what: &str) -> Vec<String> {
    let mut seen = Vec::new();
    loop {
        let line = rx
            .recv_timeout(std::time::Duration::from_secs(120))
            .unwrap_or_else(|_| panic!("no trace marker {what}; saw {seen:?}"));
        if line == format!("trace {what}") {
            return seen;
        }
        seen.push(line);
    }
}

/// `POST /v1/provision` as an app sends it; `None` when the process died before it answered.
fn door(
    port: u16,
    slot: &str,
    account: &str,
    auth: Option<&str>,
) -> Option<(u16, Vec<(String, String)>, Vec<u8>)> {
    let body = json!({"slot": slot, "base": base(slot), "account": account}).to_string();
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).ok()?;
    s.set_read_timeout(Some(std::time::Duration::from_secs(120)))
        .ok()?;
    let mut head = format!(
        "POST /v1/provision HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        body.len()
    );
    if let Some(a) = auth {
        head.push_str(&format!("Authorization: {a}\r\n"));
    }
    head.push_str("\r\n");
    s.write_all(head.as_bytes()).ok()?;
    s.write_all(body.as_bytes()).ok()?;
    let mut raw = Vec::new();
    let _ = s.read_to_end(&mut raw);
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let mut lines = head.lines();
    let status = lines.next()?.split_whitespace().nth(1)?.parse().ok()?;
    let hs = lines
        .filter_map(|l| {
            l.split_once(": ")
                .map(|(k, v)| (k.to_lowercase(), v.to_string()))
        })
        .collect();
    Some((status, hs, raw[split + 4..].to_vec()))
}
fn result(body: &[u8]) -> String {
    serde_json::from_slice::<Value>(body)
        .map(|v| v["result"].as_str().unwrap_or_default().to_string())
        .unwrap_or_default()
}
fn header(hs: &[(String, String)], name: &str) -> Option<String> {
    hs.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone())
}

fn colophon(envelope: &[u8]) -> String {
    format!("Colophon {}", URL_SAFE_NO_PAD.encode(envelope))
}
fn args(slot: &str, account: &str) -> Value {
    json!({"slot": slot, "base": base(slot), "account": account})
}
/// A provisioning call by the member `id` with its own key, over what `f` has verified.
fn grant_call(f: &Fixture, id: &str, slot: &str, account: &str, now: i64) -> Vec<u8> {
    call_as(
        &f.host,
        &f.account,
        "member",
        id,
        AUD,
        PURPOSE,
        args(slot, account),
        now,
        fresh_request_id(),
    )
}
/// The call's body digest, as the table's `by.call` names it.
fn call_digest(envelope: &[u8]) -> String {
    let v: Value = serde_json::from_slice(envelope).unwrap();
    sha_hex(&STANDARD.decode(v["body"].as_str().unwrap()).unwrap())
}

/// A link (§12.1) from member `m` to the key `to`, signed by `m`'s key, and a call by `to` that
/// carries it.
fn link_call(
    f: &Fixture,
    m: &str,
    to: &str,
    terms: Value,
    slot: &str,
    account: &str,
    now: i64,
    session: u64,
) -> Vec<u8> {
    let enc = |b: &[u8]| STANDARD.encode(b);
    let to_point = f.host.ids[to].public().signing;
    let link_body = colophon_core::v05::encoding::canonical(&json!({
        "protocol": "colophon/link/5", "account": f.account.id().as_str(), "from": m,
        "to": {"signing": enc(&to_point)}, "session": session, "terms": terms,
        "notBefore": format_date(now - 60_000), "expires": format_date(now + HOUR), "created": format_date(now - 60_000),
    }))
    .unwrap();
    let link = colophon_core::v05::encoding::canonical(&json!({
        "body": enc(&link_body), "signature": enc(&f.host.ids[m].sign(&link_body)),
    }))
    .unwrap();
    let (seq, digest) = f.account.head();
    let body = colophon_core::v05::encoding::canonical(&json!({
        "protocol": "colophon/call/5", "account": f.account.id().as_str(),
        "asOf": {"seq": seq, "digest": digest}, "signer": {"member": m}, "key": enc(&to_point),
        "links": [enc(&link)], "audience": AUD, "purpose": PURPOSE, "args": args(slot, account),
        "requestId": URL_SAFE_NO_PAD.encode(fresh_request_id()), "created": format_date(now),
    }))
    .unwrap();
    serde_json::to_vec(&json!({"body": enc(&body), "signature": enc(&f.host.ids[to].sign(&body))}))
        .unwrap()
}

/// Upload the account's entries from `from` to the operator slot, in pages of 64.
fn upload(port: u16, dir: &std::path::Path, f: &Fixture, from: u64, now: i64) {
    write_clock(&dir.join("clock"), now);
    let all: Vec<(u64, Value)> = entries_json(f)
        .into_iter()
        .filter(|(s, _)| *s >= from)
        .collect();
    for chunk in all.chunks(64) {
        let entries: Vec<&Value> = chunk.iter().map(|(_, e)| e).collect();
        let body = json!({"from": chunk[0].0, "entries": entries, "receipts": []}).to_string();
        let (status, _, b) = http(
            port,
            "POST",
            &format!("/v1/libraries/{OP_SLOT}/authority"),
            &[("Content-Type".into(), "application/json".into())],
            body.as_bytes(),
        );
        assert_eq!(
            status,
            200,
            "upload from {}: {}",
            chunk[0].0,
            String::from_utf8_lossy(&b)
        );
    }
}
fn latest_seq(f: &Fixture) -> u64 {
    entries_json(f).last().unwrap().0
}

fn table(dir: &std::path::Path) -> Value {
    std::fs::read(dir.join("data/provisioned.json"))
        .map(|b| serde_json::from_slice(&b).unwrap())
        .unwrap_or(json!({}))
}

/// The operator account, uploaded to a fresh home with the grant gate (`provision` merged into
/// the defaults here). `now` is the relay's clock after the upload.
struct World {
    keys: HomeKeys,
    op: Operator,
    cfg: Value,
    home: Option<Home>,
    now: i64,
    scratch: Scratch,
}
impl World {
    fn new(name: &str, n: u8, provision: Value) -> Option<Self> {
        Self::traced(name, n, provision, Trace::default())
    }
    fn traced(name: &str, n: u8, provision: Value, trace: Trace) -> Option<Self> {
        prerequisites()?;
        let keys = HomeKeys::new(n);
        let op = operator(&keys);
        let scratch = Scratch::new(name);
        let cfg = config(op.f.account.id().as_str(), &provision);
        let now = op.f.account.now_ms() + 1_000;
        std::fs::create_dir_all(scratch.path()).unwrap();
        write_clock(&scratch.path().join("clock"), now);
        let home = start(&keys, scratch.path(), &cfg, &trace);
        upload(home.port, scratch.path(), &op.f, 1, now);
        Some(Self {
            keys,
            op,
            cfg,
            home: Some(home),
            now,
            scratch,
        })
    }
    fn dir(&self) -> &std::path::Path {
        self.scratch.path()
    }
    fn port(&self) -> u16 {
        self.home.as_ref().unwrap().port
    }
    fn clock(&mut self, ms: i64) {
        self.now = ms;
        write_clock(&self.dir().join("clock"), ms);
    }
    fn ask(
        &self,
        slot: &str,
        account: &str,
        auth: Option<&str>,
    ) -> (u16, Vec<(String, String)>, Vec<u8>) {
        door(self.port(), slot, account, auth).expect("an answer")
    }
    /// A fresh call by `id` for `{slot, account}`, sent: status and result.
    fn grant(&self, id: &str, slot: &str, account: &str) -> (u16, String) {
        let call = grant_call(&self.op.f, id, slot, account, self.now);
        let (s, _, b) = self.ask(slot, account, Some(&colophon(&call)));
        (s, result(&b))
    }
    fn restart(&mut self, trace: &Trace) {
        self.home = None;
        self.home = Some(start(&self.keys, self.scratch.path(), &self.cfg, trace));
    }
    /// Make the operator account's next entry (a revoke, an endSessions) at the relay's clock,
    /// and upload it.
    fn operator_entry(
        &mut self,
        make: impl FnOnce(&mut Fixture) -> colophon_core::v05::account::PendingAction,
    ) {
        let now = self.now;
        self.op.f.account.advance(now).unwrap();
        let from = latest_seq(&self.op.f) + 1;
        let action = make(&mut self.op.f);
        run(&mut self.op.f.account, &self.op.f.host, action);
        upload(self.port(), self.scratch.path(), &self.op.f, from, now);
    }
}

fn q(e: &colophon_core::v05::engine::Engine<MemSource>, name: &str, a: Value) -> Value {
    match e.query(NS, name, a).unwrap() {
        Outcome::Success { value, .. } => value["value"].clone(),
        Outcome::Failure { reason, detail, .. } => panic!("{reason}: {detail}"),
    }
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

// ---------------------------------------------------------------------------------------------

#[test]
fn a_grant_provisions_a_fresh_account_end_to_end_a_replay_is_refused_and_the_listing_names_the_grant(
) {
    let Some(mut w) = World::new("grant-journey", 0x61, json!({})) else {
        return;
    };
    let mut f2 = create_public(&[NS]);
    let acct2 = f2.account.id().as_str().to_string();
    let m = w.op.m.clone();

    // M's call provisions the slot: the door answers the home's member request for that account.
    let call = grant_call(&w.op.f, &m, "home", &acct2, w.now);
    let (status, _, request) = w.ask("home", &acct2, Some(&colophon(&call)));
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&request));
    let row = &table(w.dir())["home"];
    assert_eq!(row["account"], acct2.as_str());
    let key_id = colophon_core::v05::ids::key_id(&w.op.f.host.ids[&m].public().signing);
    assert_eq!(
        row["by"],
        json!({"gate": "grant", "member": m, "key": key_id, "call": call_digest(&call)})
    );

    // The same call again: a replay; still one slot. A fresh call for the same {slot, account}:
    // the same bytes.
    let (status, _, body) = w.ask("home", &acct2, Some(&colophon(&call)));
    assert_eq!((status, result(&body).as_str()), (403, "refused:replay"));
    let (status, _, again) = w.ask(
        "home",
        &acct2,
        Some(&colophon(&grant_call(&w.op.f, &m, "home", &acct2, w.now))),
    );
    assert_eq!(status, 200);
    assert_eq!(again, request);
    assert_eq!(table(w.dir()).as_object().unwrap().len(), 1, "counted once");
    assert_eq!(
        table(w.dir())["home"]["by"]["call"],
        call_digest(&call),
        "the row keeps the call that made it"
    );

    // End to end, no restart: the account appoints the home, uploads, and two devices sync.
    appoint_with(&mut f2, &request);
    let phone_id = f2.host.identity(31);
    let laptop_id = f2.host.identity(32);
    for (id, label) in [(&phone_id, "Phone"), (&laptop_id, "Laptop")] {
        admit(
            &mut f2,
            id,
            label,
            "device",
            terms_for(&[(NS, "write")]),
            terms_for(&[(NS, "write")]),
        );
    }
    let relay = Relay::attached(w.port(), &base("home"), &acct2, w.dir());
    let now = w.now + 1_000;
    first_upload(&relay, &f2, now);
    let authority = MemSource::new();
    authority.store_account(&f2.account);
    let source = || {
        let src = MemSource::new();
        for p in authority.listing() {
            src.put(&p, authority.get(&p).unwrap());
        }
        src
    };
    let (phone_src, laptop_src) = (source(), source());
    let mut phone = member_engine(&f2, &f2.host, &phone_src, &phone_id, now + 1_000);
    let mut laptop = member_engine(&f2, &f2.host, &laptop_src, &laptop_id, now + 1_000);
    let mut host = std::mem::replace(&mut f2.host, Host::new());
    let mut wire = RealRelay::new(&relay);
    engine_write(
        &mut phone,
        &mut host,
        &phone_src,
        NS,
        "follow",
        json!({"id": "show", "url": "https://example.org/feed", "title": "The Show"}),
    );
    assert!(relay_pass(
        &mut phone,
        &phone_src,
        &w.keys.id,
        &mut wire,
        &host,
        now + 2_000
    )
    .is_empty());
    assert!(relay_pass(
        &mut laptop,
        &laptop_src,
        &w.keys.id,
        &mut wire,
        &host,
        now + 3_000
    )
    .is_empty());
    let laptop = member_engine(&f2, &host, &laptop_src, &laptop_id, now + 4_000);
    assert!(
        q(&laptop, "shows", json!({}))
            .to_string()
            .contains("The Show"),
        "the laptop reads what the phone wrote"
    );
    w.clock(now + 5_000);

    // The operator's listing: the slot, its account, made by M (named as the operator account
    // names it), claimed.
    let (relay_js, wasm) = prerequisites().unwrap();
    let out = Command::new("bun")
        .arg(relay_js)
        .arg("provisioned")
        .arg(w.dir().join("config.json"))
        .arg("--test-clock")
        .env("COLOPHON_RELAY_DATA", w.dir().join("data"))
        .env("COLOPHON_HOME_WASM", wasm)
        .env("COLOPHON_RELAY_CLOCK_FILE", w.dir().join("clock"))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let list: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(list.as_array().unwrap().len(), 1, "{list}");
    assert_eq!(list[0]["slot"], "home");
    assert_eq!(list[0]["account"], acct2.as_str());
    assert_eq!(list[0]["by"]["member"], m.as_str());
    assert_eq!(list[0]["label"], "later CI on omarchy");
    assert_eq!(list[0]["revoked"], false);
    assert_eq!(list[0]["claimed"], true);
}

#[test]
fn refusals_before_history_work_and_by_the_verifier_make_nothing() {
    let Some(w) = World::new("grant-refusals", 0x62, json!({"perAddressPerHour": 100})) else {
        return;
    };
    let f = &w.op.f;
    let m = w.op.m.clone();
    let acct = "ab".repeat(32);
    let send = |call: &[u8], slot: &str| {
        let (s, _, b) = w.ask(slot, &acct, Some(&colophon(call)));
        (s, result(&b))
    };
    let refused = |code: &str| (403u16, code.to_string());

    // Another home's door, and a slot's base: refused:audience.
    for audience in [
        "https://home-h.example/v1/provision".to_string(),
        base(OP_SLOT),
    ] {
        let call = call_as(
            &f.host,
            &f.account,
            "member",
            &m,
            &audience,
            PURPOSE,
            args("ci-aud", &acct),
            w.now,
            fresh_request_id(),
        );
        assert_eq!(
            send(&call, "ci-aud"),
            refused("refused:audience"),
            "{audience}"
        );
    }
    // Another purpose (the spec's home purposes included).
    for purpose in ["colophon.home.write", "home.provision.more"] {
        let call = call_as(
            &f.host,
            &f.account,
            "member",
            &m,
            AUD,
            purpose,
            args("ci-pur", &acct),
            w.now,
            fresh_request_id(),
        );
        assert_eq!(
            send(&call, "ci-pur"),
            refused("refused:outOfScope"),
            "{purpose}"
        );
    }
    // `args` that differ from the body: another slot, another account, an extra field.
    for a in [
        args("ci-other", &acct),
        args("ci-args", &"cd".repeat(32)),
        json!({"slot": "ci-args", "base": base("ci-args"), "account": acct, "extra": 1}),
    ] {
        let call = call_as(
            &f.host,
            &f.account,
            "member",
            &m,
            AUD,
            PURPOSE,
            a.clone(),
            w.now,
            fresh_request_id(),
        );
        assert_eq!(send(&call, "ci-args"), refused("refused:outOfScope"), "{a}");
    }
    // A member of another account (its own call names its own account): refused before any
    // history work. A key that is not a member of the operator account: refused:revoked.
    let other = create_public(&[NS]);
    let call = call_as(
        &other.host,
        &other.account,
        "controller",
        &other.d,
        AUD,
        PURPOSE,
        args("ci-acct", &acct),
        w.now,
        fresh_request_id(),
    );
    assert_eq!(send(&call, "ci-acct"), refused("refused:outOfScope"));
    let mut host = Host::new();
    let stranger = host.identity(43);
    let call = call_as(
        &host,
        &f.account,
        "member",
        &stranger,
        AUD,
        PURPOSE,
        args("ci-str", &acct),
        w.now,
        fresh_request_id(),
    );
    assert_eq!(send(&call, "ci-str"), refused("refused:revoked"));
    // A controller's call (approve and control): a controller's key is for authority.
    let call = call_as(
        &f.host,
        &f.account,
        "controller",
        &f.d,
        AUD,
        PURPOSE,
        args("ci-ctl", &acct),
        w.now,
        fresh_request_id(),
    );
    assert_eq!(send(&call, "ci-ctl"), refused("refused:outOfScope"));
    // The home's own member (it serves the account as its home).
    let (seq, digest) = f.account.head();
    let body = colophon_core::v05::encoding::canonical(&json!({
        "protocol": "colophon/call/5", "account": f.account.id().as_str(), "asOf": {"seq": seq, "digest": digest},
        "signer": {"member": w.keys.id}, "key": STANDARD.encode(&w.keys.point), "audience": AUD, "purpose": PURPOSE,
        "args": args("ci-home", &acct), "requestId": URL_SAFE_NO_PAD.encode(fresh_request_id()), "created": format_date(w.now),
    }))
    .unwrap();
    let call = serde_json::to_vec(&json!({"body": STANDARD.encode(&body), "signature": STANDARD.encode(w.keys.sign(&body).signature)})).unwrap();
    assert_eq!(send(&call, "ci-home"), refused("refused:outOfScope"));
    // Possession first: a bad signature on a call that is also for another account and another
    // audience is badSignature, not one of the cheap refusals.
    let call = call_as(
        &f.host,
        &other.account,
        "member",
        &m,
        "https://home-h.example/v1/provision",
        PURPOSE,
        args("ci-sig", &acct),
        w.now,
        fresh_request_id(),
    );
    let mut env: Value = serde_json::from_slice(&call).unwrap();
    let mut sig = STANDARD.decode(env["signature"].as_str().unwrap()).unwrap();
    sig[7] ^= 1;
    env["signature"] = json!(STANDARD.encode(sig));
    assert_eq!(
        send(&serde_json::to_vec(&env).unwrap(), "ci-sig"),
        refused("badSignature")
    );
    // The condition: a slot the grant does not name.
    let call = grant_call(f, &m, "other-slot", &acct, w.now);
    assert_eq!(send(&call, "other-slot"), refused("refused:outOfScope"));
    // Not one slot was made, and no call was recorded.
    assert_eq!(table(w.dir()), json!({}));
    let log = std::fs::read_to_string(w.dir().join("data/provision-replay/replay.log"))
        .unwrap_or_default();
    assert_eq!(log, "", "nothing reserved for a refused call");
    // And M's real call still works.
    assert_eq!(w.grant(&m, "ci-ok", &acct).0, 200);
}

#[test]
fn revocation_ended_sessions_expiry_and_links_and_a_revoked_grants_slots_are_left_alone() {
    let Some(mut w) = World::new("grant-revoke", 0x63, json!({"unclaimedHours": 24})) else {
        return;
    };
    let (m, m2) = (w.op.m.clone(), w.op.m2.clone());
    let link_key = w.op.f.host.identity(42);
    let link_terms = json!({"services": [{"audience": AUD, "purposes": [PURPOSE]}], "depth": 0,
                            "conditions": [condition(), {"prefix": ["args.slot", "ci-l"]}]});

    // A link under M with narrower terms provisions, and counts against M.
    let acct = "ab".repeat(32);
    let call = link_call(
        &w.op.f,
        &m,
        &link_key,
        link_terms.clone(),
        "ci-l1",
        &acct,
        w.now,
        0,
    );
    let (s, _, b) = w.ask("ci-l1", &acct, Some(&colophon(&call)));
    assert_eq!(s, 200, "{}", String::from_utf8_lossy(&b));
    let by = &table(w.dir())["ci-l1"]["by"];
    assert_eq!(
        by["member"],
        m.as_str(),
        "the link's slot counts against its member"
    );
    assert_eq!(
        by["key"],
        colophon_core::v05::ids::key_id(&w.op.f.host.ids[&link_key].public().signing)
    );
    // The link's own condition: a slot outside it.
    let call = link_call(
        &w.op.f,
        &m,
        &link_key,
        link_terms.clone(),
        "ci-x1",
        &acct,
        w.now,
        0,
    );
    let (s, _, b) = w.ask("ci-x1", &acct, Some(&colophon(&call)));
    assert_eq!((s, result(&b).as_str()), (403, "refused:outOfScope"));

    // endSessions of M ends the link (M's own key still works).
    w.clock(w.now + 60_000);
    w.operator_entry(|f| f.account.begin_end_sessions(&m, &[f.d.clone()]).unwrap());
    let call = link_call(
        &w.op.f,
        &m,
        &link_key,
        link_terms.clone(),
        "ci-l2",
        &acct,
        w.now,
        0,
    );
    let (s, _, b) = w.ask("ci-l2", &acct, Some(&colophon(&call)));
    assert_eq!((s, result(&b).as_str()), (403, "refused:ended"));

    // M makes an unclaimed slot and one an account appoints and uploads to.
    assert_eq!(w.grant(&m, "ci-u1", &acct).0, 200);
    let mut f2 = create_public(&[NS]);
    let acct2 = f2.account.id().as_str().to_string();
    let call = grant_call(&w.op.f, &m, "home", &acct2, w.now);
    let (s, _, request) = w.ask("home", &acct2, Some(&colophon(&call)));
    assert_eq!(s, 200);
    appoint_with(&mut f2, &request);
    let relay = Relay::attached(w.port(), &base("home"), &acct2, w.dir());
    first_upload(&relay, &f2, w.now + 1_000);
    w.clock(w.now + 2_000);

    // Revoke M (the entry uploaded to the home): its next call, and its link's, are refused.
    w.operator_entry(|f| {
        f.account
            .begin_revoke(&m, &RevokeKeep::Nothing, &[f.d.clone()], [9; 32])
            .unwrap()
    });
    assert_eq!(w.grant(&m, "ci-u2", &acct), (403, "refused:revoked".into()));
    let call = link_call(&w.op.f, &m, &link_key, link_terms, "ci-l3", &acct, w.now, 1);
    let (s, _, b) = w.ask("ci-l3", &acct, Some(&colophon(&call)));
    assert_eq!((s, result(&b).as_str()), (403, "refused:revoked"));

    // M2's expiry passes on the test clock: refused:expired. Its slots are not touched.
    w.clock(w.now + 3 * HOUR);
    assert_eq!(
        w.grant(&m2, "ci-e1", &acct),
        (403, "refused:expired".into())
    );

    // The appointed slot M made keeps being witnessed: a head signed at the new clock.
    let port = w.port();
    let head_issued = || {
        let (s, _, b) = http(port, "GET", "/v1/libraries/home/head", &[], &[]);
        assert_eq!(s, 200);
        let v: Value = serde_json::from_slice(&b).unwrap();
        let body: Value =
            serde_json::from_slice(&STANDARD.decode(v["body"].as_str().unwrap()).unwrap()).unwrap();
        body["issued"].as_str().unwrap().to_string()
    };
    w.clock(w.now + 25 * HOUR);
    let issued = head_issued();
    assert!(
        issued >= format_date(w.now - 300_000),
        "a fresh head at the new clock: {issued}"
    );
    // Past unclaimedHours, at the next request to the door: M's unclaimed slots are released,
    // the appointed one stays.
    let (s, _) = w.grant(&m, "ci-u3", &acct);
    assert_eq!(s, 403);
    let t = table(w.dir());
    assert!(
        t.get("ci-u1").is_none() && t.get("ci-l1").is_none(),
        "unclaimed slots released: {t}"
    );
    assert_eq!(
        t["home"]["account"],
        acct2.as_str(),
        "the appointed slot stays"
    );
    assert_eq!(head_issued(), issued, "still served");
}

#[test]
fn a_grant_has_its_own_limits_a_per_member_override_the_home_wide_cap_and_a_durable_rate() {
    let Some(mut w) = World::new(
        "grant-limits",
        0x64,
        json!({"maxSlots": 5, "grantMaxSlots": 2, "grantPerHour": 4,
        "perAddressPerHour": 100, "grants": {}}),
    ) else {
        return;
    };
    // The override for M2 needs its ID: restart with it.
    let (m, m2) = (w.op.m.clone(), w.op.m2.clone());
    w.cfg["provision"]["grants"] = json!({m2.clone(): {"maxSlots": 5, "perHour": 10}});
    w.restart(&Trace::default());
    let acct = "ab".repeat(32);
    // M: two slots, then its grantMaxSlots (507); M2, with its override, three, then the home is
    // full (507) though M2 is under its own five.
    assert_eq!(w.grant(&m, "ci-a1", &acct).0, 200);
    assert_eq!(w.grant(&m, "ci-a2", &acct).0, 200);
    assert_eq!(
        w.grant(&m, "ci-a3", &acct),
        (507, "refused:overQuota".into())
    );
    for slot in ["ci-b1", "ci-b2", "ci-b3"] {
        assert_eq!(w.grant(&m2, slot, &acct).0, 200, "{slot}");
    }
    assert_eq!(
        w.grant(&m2, "ci-b4", &acct),
        (507, "refused:overQuota".into()),
        "maxSlots caps every grant together"
    );
    // M's rate: every verified call counts (the refused third and an idempotent one too); the
    // fourth verified call is the last this hour.
    assert_eq!(w.grant(&m, "ci-a1", &acct).0, 200, "idempotent, counted");
    let call = grant_call(&w.op.f, &m, "ci-a1", &acct, w.now);
    let (s, hs, b) = w.ask("ci-a1", &acct, Some(&colophon(&call)));
    assert_eq!((s, result(&b).as_str()), (429, "refused:overQuota"));
    assert_eq!(
        header(&hs, "retry-after").as_deref(),
        Some("3600"),
        "until its oldest call leaves the hour"
    );
    // M2 has its own share.
    assert_eq!(w.grant(&m2, "ci-b1", &acct).0, 200);
    // A restart inside the hour keeps the count: it is read from the durable replay table.
    w.clock(w.now + 30 * 60_000);
    w.restart(&Trace::default());
    let call = grant_call(&w.op.f, &m, "ci-a1", &acct, w.now);
    let (s, hs, b) = w.ask("ci-a1", &acct, Some(&colophon(&call)));
    assert_eq!(
        (s, result(&b).as_str()),
        (429, "refused:overQuota"),
        "the rate survives a restart"
    );
    assert_eq!(header(&hs, "retry-after").as_deref(), Some("1800"));
    // An hour after the first: admitted again.
    w.clock(w.now + 30 * 60_000);
    assert_eq!(w.grant(&m, "ci-a1", &acct).0, 200);
    assert_eq!(table(w.dir()).as_object().unwrap().len(), 5);
}

#[test]
fn the_replay_tables_hard_cap_and_refused_requests_count_against_the_address() {
    let Some(mut w) = World::new(
        "grant-caps",
        0x65,
        json!({"replayRows": 2, "perAddressPerHour": 2}),
    ) else {
        return;
    };
    let m = w.op.m.clone();
    let acct = "ab".repeat(32);
    // Admitted calls do not count against the address.
    assert_eq!(w.grant(&m, "ci-c1", &acct).0, 200);
    assert_eq!(w.grant(&m, "ci-c2", &acct).0, 200);
    // The table is full: 429 before any verification, even for a call that would be refused.
    let call = grant_call(&w.op.f, &m, "ci-c3", &acct, w.now);
    let (s, hs, b) = w.ask("ci-c3", &acct, Some(&colophon(&call)));
    assert_eq!((s, result(&b).as_str()), (429, "refused:overQuota"));
    assert!(header(&hs, "retry-after").is_some());
    let (s, _, b) = w.ask("ci-c3", &acct, Some("Colophon e30"));
    assert_eq!(
        (s, result(&b).as_str()),
        (429, "refused:overQuota"),
        "before the module runs"
    );
    // §12.4 retention (7,260 s) frees the rows.
    w.clock(w.now + 7_261_000);
    assert_eq!(w.grant(&m, "ci-c3", &acct).0, 200);
    // Refused requests count against the address: two, then even M's good call is refused here.
    for _ in 0..2 {
        let (s, _, _) = w.ask("ci-c4", &acct, Some("Colophon e30"));
        assert_eq!(s, 403);
    }
    let (s, _, b) = w.ask(
        "ci-c4",
        &acct,
        Some(&colophon(&grant_call(&w.op.f, &m, "ci-c4", &acct, w.now))),
    );
    assert_eq!((s, result(&b).as_str()), (429, "refused:overQuota"));
}

#[test]
fn a_revocation_uploaded_during_an_admitted_provision_waits_for_it_under_the_lock() {
    let trace = Trace {
        pause_at: Some("grant verified".into()),
        ..Default::default()
    };
    let Some(mut w) = World::traced("grant-lock", 0x66, json!({}), trace) else {
        return;
    };
    let m = w.op.m.clone();
    let acct = "ab".repeat(32);
    let rx = w.home.as_mut().unwrap().rx.take().unwrap();
    // A provision by M pauses between its verification and its durable write, holding the
    // operator slot's lock.
    let call = grant_call(&w.op.f, &m, "ci-r1", &acct, w.now);
    let port = w.port();
    let provision = std::thread::spawn({
        let (acct, auth) = (acct.clone(), colophon(&call));
        move || door(port, "ci-r1", &acct, Some(&auth))
    });
    marker(&rx, "grant verified");
    // The revocation of M is made and uploaded meanwhile: it passes its access check and waits
    // for the lock.
    let now = w.now;
    w.op.f.account.advance(now).unwrap();
    let from = latest_seq(&w.op.f) + 1;
    let action =
        w.op.f
            .account
            .begin_revoke(&m, &RevokeKeep::Nothing, &[w.op.f.d.clone()], [9; 32])
            .unwrap();
    run(&mut w.op.f.account, &w.op.f.host, action);
    let entry = entries_json(&w.op.f)
        .into_iter()
        .find(|(s, _)| *s == from)
        .unwrap()
        .1;
    let body = json!({"from": from, "entries": [entry], "receipts": []}).to_string();
    let revoke = std::thread::spawn(move || {
        http(
            port,
            "POST",
            &format!("/v1/libraries/{OP_SLOT}/authority"),
            &[("Content-Type".into(), "application/json".into())],
            body.as_bytes(),
        )
    });
    marker(&rx, "access authority");
    // Resumed: the provision commits first, then the revocation takes the lock.
    std::fs::write(w.dir().join("resume"), b"").unwrap();
    let before = marker(&rx, "authority locked");
    assert!(
        before.iter().any(|l| l == "trace provision written"),
        "the provision committed before the upload took the lock: {before:?}"
    );
    let (s, _, b) = provision.join().unwrap().expect("an answer");
    assert_eq!(s, 200, "{}", String::from_utf8_lossy(&b));
    let (s, _, b) = revoke.join().unwrap();
    assert_eq!(s, 200, "{}", String::from_utf8_lossy(&b));
    // Every verification after the accepted revocation sees it.
    assert_eq!(w.grant(&m, "ci-r2", &acct), (403, "refused:revoked".into()));
    assert!(table(w.dir()).get("ci-r1").is_some());
    assert!(table(w.dir()).get("ci-r2").is_none());
}

/// The rows (reservations) of the provisioning replay table's log.
fn replay_rows(dir: &std::path::Path) -> usize {
    std::fs::read_to_string(dir.join("data/provision-replay/replay.log"))
        .unwrap_or_default()
        .lines()
        .filter(|l| l.contains("\"r\":"))
        .count()
}

#[test]
fn verified_calls_the_room_refuses_count_and_calls_over_the_rate_cost_no_history_work() {
    // Traced (the pause point is never reached), so the markers show what each request did.
    let trace = Trace {
        pause_at: Some("never reached".into()),
        ..Default::default()
    };
    let Some(mut w) = World::traced(
        "grant-spent",
        0x68,
        json!({"grantMaxSlots": 1, "grantPerHour": 3, "perAddressPerHour": 100}),
        trace,
    ) else {
        return;
    };
    let m = w.op.m.clone();
    let rx = w.home.as_mut().unwrap().rx.take().unwrap();
    let (a, b) = ("ab".repeat(32), "cd".repeat(32));
    // Three verified calls: one makes a slot, one is refused by the slot's holder (409), one by
    // the grant's slots held (507). Each is recorded, the refused two completed with no effect.
    assert_eq!(w.grant(&m, "ci-s1", &a).0, 200);
    marker(&rx, "grant verified");
    assert_eq!(w.grant(&m, "ci-s1", &b).0, 409);
    marker(&rx, "grant verified");
    assert_eq!(w.grant(&m, "ci-s2", &a), (507, "refused:overQuota".into()));
    marker(&rx, "grant verified");
    assert_eq!(replay_rows(w.dir()), 3);
    assert_eq!(table(w.dir()).as_object().unwrap().len(), 1);
    // Over the rate, again and again: refused before the operator slot's lock and any history
    // work, and recorded nowhere.
    for _ in 0..2 {
        let call = grant_call(&w.op.f, &m, "ci-s1", &a, w.now);
        let (s, hs, body) = w.ask("ci-s1", &a, Some(&colophon(&call)));
        assert_eq!((s, result(&body).as_str()), (429, "refused:overQuota"));
        assert_eq!(header(&hs, "retry-after").as_deref(), Some("3600"));
        let seen = marker(&rx, "grant refused");
        assert!(
            !seen.iter().any(|l| l == "trace grant locking"),
            "an over-rate call took the operator slot's lock: {seen:?}"
        );
    }
    assert_eq!(replay_rows(w.dir()), 3, "an over-rate call is not recorded");
    // A restart inside the hour keeps the count, the refused calls' rows included.
    w.clock(w.now + 30 * 60_000);
    w.restart(&Trace::default());
    assert_eq!(replay_rows(w.dir()), 3);
    let call = grant_call(&w.op.f, &m, "ci-s1", &a, w.now);
    let (s, hs, body) = w.ask("ci-s1", &a, Some(&colophon(&call)));
    assert_eq!(
        (s, result(&body).as_str()),
        (429, "refused:overQuota"),
        "the refused calls still count after a restart"
    );
    assert_eq!(header(&hs, "retry-after").as_deref(), Some("1800"));
    // An hour after them: admitted again (the same slot, idempotent).
    w.clock(w.now + 30 * 60_000);
    assert_eq!(w.grant(&m, "ci-s1", &a).0, 200);
}

#[test]
fn a_provision_arriving_while_a_revocation_holds_the_lock_waits_for_it_and_is_refused() {
    let Some(mut w) = World::new("grant-lock-rev", 0x69, json!({})) else {
        return;
    };
    // Restarted traced: the upload of the revocation pauses once it holds the operator slot's
    // lock (the set-up upload above was before the pause was armed).
    w.restart(&Trace {
        pause_at: Some("authority locked".into()),
        ..Default::default()
    });
    let m = w.op.m.clone();
    let acct = "ab".repeat(32);
    let rx = w.home.as_mut().unwrap().rx.take().unwrap();
    let port = w.port();
    // M's call, made over the history the home holds now (before the revocation).
    let call = grant_call(&w.op.f, &m, "ci-q1", &acct, w.now);
    // The revocation of M is uploaded and pauses holding the lock.
    let now = w.now;
    w.op.f.account.advance(now).unwrap();
    let from = latest_seq(&w.op.f) + 1;
    let action =
        w.op.f
            .account
            .begin_revoke(&m, &RevokeKeep::Nothing, &[w.op.f.d.clone()], [9; 32])
            .unwrap();
    run(&mut w.op.f.account, &w.op.f.host, action);
    let entry = entries_json(&w.op.f)
        .into_iter()
        .find(|(s, _)| *s == from)
        .unwrap()
        .1;
    let body = json!({"from": from, "entries": [entry], "receipts": []}).to_string();
    let revoke = std::thread::spawn(move || {
        http(
            port,
            "POST",
            &format!("/v1/libraries/{OP_SLOT}/authority"),
            &[("Content-Type".into(), "application/json".into())],
            body.as_bytes(),
        )
    });
    marker(&rx, "authority locked");
    // The provision passes its checks that need no history and waits for the lock.
    let provision = std::thread::spawn({
        let (acct, auth) = (acct.clone(), colophon(&call));
        move || door(port, "ci-q1", &acct, Some(&auth))
    });
    let before = marker(&rx, "grant locking");
    assert!(
        !before.iter().any(|l| l.starts_with("trace grant ")),
        "the provision was judged before it waited for the lock: {before:?}"
    );
    // Released: the revocation commits, then the provision verifies over it.
    std::fs::write(w.dir().join("resume"), b"").unwrap();
    let (s, _, b) = revoke.join().unwrap();
    assert_eq!(s, 200, "{}", String::from_utf8_lossy(&b));
    let (s, _, b) = provision.join().unwrap().expect("an answer");
    assert_eq!(
        (s, result(&b).as_str()),
        (403, "refused:revoked"),
        "{}",
        String::from_utf8_lossy(&b)
    );
    // No slot, and no replay effect.
    assert!(table(w.dir()).get("ci-q1").is_none());
    assert_eq!(table(w.dir()), json!({}));
    assert_eq!(replay_rows(w.dir()), 0, "nothing reserved");
}

#[test]
fn an_operator_slot_with_no_genesis_answers_unavailable() {
    if prerequisites().is_none() {
        return;
    }
    let keys = HomeKeys::new(0x67);
    let op = operator(&keys);
    let scratch = Scratch::new("grant-nogenesis");
    let now = op.f.account.now_ms() + 1_000;
    std::fs::create_dir_all(scratch.path()).unwrap();
    write_clock(&scratch.path().join("clock"), now);
    let home = start(
        &keys,
        scratch.path(),
        &config(op.f.account.id().as_str(), &json!({})),
        &Trace::default(),
    );
    let acct = "ab".repeat(32);
    let call = grant_call(&op.f, &op.m, "ci-n1", &acct, now);
    let (s, _, b) = door(home.port, "ci-n1", &acct, Some(&colophon(&call))).unwrap();
    assert_eq!((s, result(&b).as_str()), (503, "unavailable"));
    // Once the operator uploads its history, the same grant works.
    upload(home.port, scratch.path(), &op.f, 1, now);
    let call = grant_call(&op.f, &op.m, "ci-n1", &acct, now);
    assert_eq!(
        door(home.port, "ci-n1", &acct, Some(&colophon(&call)))
            .unwrap()
            .0,
        200
    );
}

#[test]
fn killed_between_reservation_and_write_the_call_is_abandoned_and_after_the_write_it_completes() {
    let trace = Trace {
        crash_at: Some("grant reserved".into()),
        ..Default::default()
    };
    let Some(mut w) = World::traced("grant-kill", 0x68, json!({}), trace) else {
        return;
    };
    let m = w.op.m.clone();
    let acct = "ab".repeat(32);
    // Killed after the reservation, before provisioned.json is written.
    let call = grant_call(&w.op.f, &m, "ci-k1", &acct, w.now);
    assert!(
        door(w.port(), "ci-k1", &acct, Some(&colophon(&call))).is_none(),
        "the process died"
    );
    let _ = w.home.as_mut().unwrap().child.wait();
    assert_eq!(table(w.dir()), json!({}), "nothing written");
    w.restart(&Trace::default());
    // Abandoned on restart: the call stays a replay; a new call works.
    let (s, _, b) = w.ask("ci-k1", &acct, Some(&colophon(&call)));
    assert_eq!((s, result(&b).as_str()), (403, "refused:replay"));
    let fresh = grant_call(&w.op.f, &m, "ci-k1", &acct, w.now);
    let (s, _, request) = w.ask("ci-k1", &acct, Some(&colophon(&fresh)));
    assert_eq!(s, 200);
    assert_eq!(table(w.dir())["ci-k1"]["by"]["call"], call_digest(&fresh));

    // Killed after the durable write: the row names the call, the reservation completes, and
    // `by` survives the restart.
    w.restart(&Trace {
        crash_at: Some("provision written".into()),
        ..Default::default()
    });
    let call = grant_call(&w.op.f, &m, "ci-k2", &acct, w.now);
    assert!(
        door(w.port(), "ci-k2", &acct, Some(&colophon(&call))).is_none(),
        "the process died"
    );
    let _ = w.home.as_mut().unwrap().child.wait();
    assert_eq!(table(w.dir())["ci-k2"]["by"]["call"], call_digest(&call));
    let stored = STANDARD
        .decode(table(w.dir())["ci-k2"]["request"].as_str().unwrap())
        .unwrap();
    w.restart(&Trace::default());
    let log = std::fs::read_to_string(w.dir().join("data/provision-replay/replay.log")).unwrap();
    // This call's row completed; the first call's row (killed before its write) stays
    // abandoned, as a compaction keeps each row's outcome.
    let outcome = |digest: &str| {
        log.lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .find(|v| v["d"] == json!(digest))
            .and_then(|v| v["t"].as_str().map(str::to_string))
    };
    assert_eq!(
        outcome(&call_digest(&call)).as_deref(),
        Some("completed"),
        "completed, not abandoned: {log}"
    );
    assert!(
        log.contains("\"t\":\"abandoned\""),
        "the first call stays abandoned: {log}"
    );
    let (s, _, b) = w.ask("ci-k2", &acct, Some(&colophon(&call)));
    assert_eq!(
        (s, result(&b).as_str()),
        (403, "refused:replay"),
        "never re-run"
    );
    let (s, _, again) = w.ask(
        "ci-k2",
        &acct,
        Some(&colophon(&grant_call(&w.op.f, &m, "ci-k2", &acct, w.now))),
    );
    assert_eq!(s, 200);
    assert_eq!(again, stored);
    assert_eq!(table(w.dir())["ci-k2"]["by"]["member"], m.as_str());
    let _ = request;
}

#[test]
fn a_gate_list_takes_a_call_by_grant_and_its_refusal_is_final() {
    // ["grant", "open"].
    let Some(mut w) = World::new(
        "grant-lists",
        0x69,
        json!({"gate": ["grant", "open"], "perAddressPerHour": 2}),
    ) else {
        return;
    };
    let m = w.op.m.clone();
    let acct = "ab".repeat(32);
    assert_eq!(w.grant(&m, "ci-g1", &acct).0, 200);
    assert_eq!(table(w.dir())["ci-g1"]["by"]["gate"], "grant");
    // A bad call (its args name another slot) is refused, and nothing falls through to open.
    let call = grant_call(&w.op.f, &m, "ci-g9", &acct, w.now);
    let (s, _, b) = w.ask("ci-g2", &acct, Some(&colophon(&call)));
    assert_eq!((s, result(&b).as_str()), (403, "refused:outOfScope"));
    assert!(table(w.dir()).get("ci-g2").is_none(), "no fallback to open");
    // No Authorization: the open path, bounded by the address.
    assert_eq!(w.ask("ci-g2", &acct, None).0, 200);
    assert_eq!(table(w.dir())["ci-g2"]["by"], json!({"gate": "open"}));
    assert_eq!(w.ask("ci-g3", &acct, None).0, 200);
    let (s, _, b) = w.ask("ci-g4", &acct, None);
    assert_eq!((s, result(&b).as_str()), (429, "refused:overQuota"));
    // The grant path is not bounded by the open share.
    assert_eq!(w.grant(&m, "ci-g4", &acct).0, 200);

    // ["grant", "token"].
    let token = "test-token-0123456789abcdef";
    w.cfg["provision"]["gate"] = json!(["grant", "token"]);
    w.cfg["provision"]["tokenSha256"] = json!(sha_hex(token.as_bytes()));
    w.cfg["provision"]["perAddressPerHour"] = json!(10);
    w.restart(&Trace::default());
    assert_eq!(w.grant(&m, "ci-t1", &acct).0, 200);
    let call = grant_call(&w.op.f, &m, "ci-t9", &acct, w.now);
    let (s, _, b) = w.ask("ci-t2", &acct, Some(&colophon(&call)));
    assert_eq!((s, result(&b).as_str()), (403, "refused:outOfScope"));
    let (s, _, b) = w.ask("ci-t2", &acct, None);
    assert_eq!((s, result(&b).as_str()), (403, "refused:noEntitlement"));
    assert!(table(w.dir()).get("ci-t2").is_none());
    assert_eq!(
        w.ask("ci-t2", &acct, Some(&format!("Bearer {token}"))).0,
        200
    );
    assert_eq!(table(w.dir())["ci-t2"]["by"], json!({"gate": "token"}));
    let _ = w.now;
}
