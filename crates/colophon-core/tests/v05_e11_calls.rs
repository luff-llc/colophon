//! E11: members' calls to a home that requires them, built by the engine and checked by the
//! home's own rule.
//!
//! The home here is the simulated home of the journeys with one addition: every request a real
//! home guards (§13.4, §14) must carry `Authorization: Colophon <call>`, checked with
//! [`verify_home_request`], the function the relay's home module calls, over the home's own view
//! (everything it holds and its own fresh head). So a call the engine builds is accepted exactly
//! when the home's rule accepts it, and the tests below compare the two directly.
//!
//! The three gaps the Swift SDK's checker found, each with the test that failed before:
//! 1. a pass asked for `/authority` before `/head`, so no call could be built under
//!    `policy.history: members` (`a_member_syncs_the_history_with_calls_when_the_history_is_for_members`);
//! 2. a member's `colophon.home.write` call for its own records was refused at build
//!    (`a_member_writes_its_own_records_with_calls_and_nothing_else`);
//! 3. a member approved by another device was refused at build: its own history did not hold its
//!    approval, and fetching it needs a call (`a_device_approved_elsewhere_learns_its_approval_through_the_home`).
#![allow(clippy::unwrap_used, clippy::too_many_arguments, clippy::cloned_ref_to_slice_refs)]
#[path = "v05_engine_support/mod.rs"]
mod support;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use colophon_core::v05::account::{CreateProgress, Creation, HomeCall, Identity, RevokeKeep};
use colophon_core::v05::calls::{
    home_record_writes, verify_home_request, AccountView, CallConfig, HomeRequest,
};
use colophon_core::v05::engine::exchange::{Fault, Method, Request, Response, Step};
use colophon_core::v05::engine::{Engine, EngineOptions};
use colophon_core::v05::history::{verify_history, Objects, Persisted};
use colophon_core::v05::replay::MemoryReplayStore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use support::*;

const NOW: i64 = T0 + 3 * HOUR;
const NS: &str = "notes";
const LISTEN: &str = "listening.podcasts";
const BASE: &str = "https://home.example";

/// The journeys' account with `policy.history` set.
fn fixture(history: &str) -> Fixture {
    fixture_with_namespaces(history, &[NS])
}

fn fixture_with_namespaces(history: &str, namespaces: &[&str]) -> Fixture {
    let mut host = Host::new();
    let d = host.identity(10);
    let k = host.kit(20);
    let p = host.passkey();
    let mut params = params(&mut host, &d, &p, &k, namespaces);
    params.policy.as_mut().unwrap()["history"] = json!(history);
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

/// A home that requires calls where a real home does, judged by the home's own rule.
struct CallingHome {
    sim: SimHome,
    public_history: bool,
    accepted: usize,
    refused: Vec<(String, String)>,
}
impl CallingHome {
    fn new(sim: SimHome, public_history: bool) -> Self {
        Self {
            sim,
            public_history,
            accepted: 0,
            refused: Vec::new(),
        }
    }
    /// The home's view: what it holds and its own head, now.
    fn view(&self, host: &Host, now_ms: i64) -> AccountView {
        let objects = Objects {
            entries: self.sim.entries.values().cloned().collect(),
            heads: self.sim.head_env(host, now_ms).into_iter().collect(),
            ..Default::default()
        };
        let verdict = verify_history(&objects, &Persisted::default(), now_ms);
        AccountView::from_history_verifier(&verdict, &objects, now_ms).unwrap()
    }
    /// The home's judgement of `call` for the request `method path` with `body`.
    fn judge(&self, host: &Host, call: &[u8], method: &str, path: &str, body: &[u8], now_ms: i64) -> Result<(), String> {
        let view = self.view(host, now_ms);
        let audiences = [BASE.to_string()];
        let origins = Default::default();
        let cfg = CallConfig {
            now_ms,
            audiences: &audiences,
            call_origins: &origins,
            controller_purposes: &[],
            home_endpoints: &audiences,
        };
        let record = path.split('?').next().unwrap_or("").strip_prefix("/records/");
        let writes = match (method, record) {
            ("PUT", Some(p)) => home_record_writes(p).unwrap_or_default(),
            _ => Vec::new(),
        };
        let sha = hex(&Sha256::digest(body));
        let req = HomeRequest {
            method,
            path,
            body_sha256: &sha,
            writes: &writes,
        };
        let mut store = MemoryReplayStore::new();
        verify_home_request(call, &view, &cfg, &mut store, &req)
            .map(|_| ())
            .map_err(|e| e.code())
    }
}
impl Wire for CallingHome {
    fn call(&mut self, host: &Host, req: &Request, now_ms: i64) -> Response {
        let path = req.url.strip_prefix(BASE).unwrap().to_string();
        let bare = path.split('?').next().unwrap_or("").to_string();
        let method = req.method.as_str();
        let open = bare == "/head"
            || (method == "POST" && (bare == "/authority" || bare == "/pending"))
            || (method == "PUT" && bare.starts_with("/records/heads/"));
        let history = bare == "/authority" || bare == "/pending" || bare.starts_with("/pending/");
        if !(open || history && self.public_history) {
            let call = req.headers.iter().find_map(|(k, v)| {
                (k == "Authorization").then(|| v.strip_prefix("Colophon ")).flatten()
            });
            let Some(call) = call else {
                return Response {
                    status: 401,
                    headers: vec![("WWW-Authenticate".into(), "Colophon".into())],
                    body: b"{}".to_vec(),
                };
            };
            let bytes = URL_SAFE_NO_PAD.decode(call).unwrap();
            if let Err(code) = self.judge(host, &bytes, method, &path, &req.body, now_ms) {
                self.refused.push((format!("{method} {bare}"), code.clone()));
                return Response {
                    status: 403,
                    headers: vec![],
                    body: json!({"result": code}).to_string().into_bytes(),
                };
            }
            self.accepted += 1;
        }
        self.sim.call(host, req, now_ms)
    }
}

/// What a device's pass produced.
#[derive(Default, Debug)]
struct Pass {
    faults: Vec<Fault>,
    /// Calls the engine's own check refused, with the code.
    unbuilt: Vec<String>,
    calls: usize,
    puts: Vec<String>,
}

/// One pass of `e` with the home, building every call the engine asks for with
/// `exchange_begin_call`, signing it with the device's key and finishing it.
fn pass(e: &mut Engine<MemSource>, src: &MemSource, home: &str, wire: &mut CallingHome, host: &mut Host, me: &str, now: i64) -> Pass {
    let mut out = Pass::default();
    e.advance(now).unwrap();
    e.refresh(src.listing()).unwrap();
    for _ in 0..100_000 {
        match e.exchange_next(home).unwrap() {
            Step::Done => return out,
            Step::Waiting => panic!("the loop answers every request"),
            Step::NeedCall(n) => {
                assert_eq!(n.url, format!("{}{}", n.audience, n.path));
                let key = host.ids[me].public().signing;
                let action = e.exchange_begin_call(home, n.ticket, &key, host.fresh()).unwrap();
                let sigs = host.sign(action.steps());
                match e.finish_write(action, sigs) {
                    Ok(w) => {
                        out.calls += 1;
                        e.exchange_provide_call(home, n.ticket, &w.artifact.unwrap()).unwrap();
                    }
                    Err(x) => {
                        out.unbuilt.push(x.code());
                        e.exchange_abort(home).unwrap();
                        return out;
                    }
                }
            }
            Step::Request(r) => {
                if r.method == Method::Put {
                    out.puts.push(r.url.clone());
                }
                let a = wire.call(host, &r, now);
                let report = e.exchange_answer(home, r.ticket, a).unwrap();
                src.publish_stores(&report.store);
                out.faults.extend(report.faults);
            }
        }
    }
    panic!("a pass did not end");
}

fn is_member(e: &Engine<MemSource>) -> bool {
    matches!(e.me(), colophon_core::v05::account::Standing::Member(_))
}

fn records(e: &Engine<MemSource>) -> usize {
    match e.view(NS).unwrap() {
        colophon_core::model::Outcome::Success { value, .. } => value.admitted.len(),
        colophon_core::model::Outcome::Failure { reason, .. } => panic!("{reason}"),
    }
}

/// Gap 1. Under `policy.history: members` a device holding the history and a fresh head must
/// sync: the pass now fetches the public head first, so the call for `/authority` can be built.
/// Before, the pass asked for `/authority` first and the engine's own check refused every call
/// with `unavailable` ("too few fresh heads").
#[test]
fn a_member_syncs_the_history_with_calls_when_the_history_is_for_members() {
    let mut f = fixture("members");
    let home = appoint_home(&mut f);
    let a = f.host.identity(30);
    admit(&mut f, &a, "Mac", "device", terms_for(&[(NS, "write")]), terms_for(&[(NS, "write")]));
    let src = MemSource::new();
    src.store_account(&f.account);
    let mut e = member_engine(&f, &f.host, &src, &a, NOW);
    let mut home_w = CallingHome::new(SimHome::new(&f, &home, BASE, NOW), false);
    let mut host = std::mem::replace(&mut f.host, Host::new());
    let p = pass(&mut e, &src, &home, &mut home_w, &mut host, &a, NOW);
    assert!(p.unbuilt.is_empty(), "the engine built every call: {p:?}");
    assert!(p.faults.is_empty(), "{p:?}");
    assert!(p.calls >= 2, "the pending and change feed reads each carry a call: {p:?}");
    assert_eq!(home_w.refused, Vec::<(String, String)>::new());
    // The pass's first request is the head, which is public.
    assert_eq!(home_w.sim.requests.first().map(String::as_str), Some("Get /head"));

    // The home moves on (another device is approved): the next pass pulls the history with a call.
    f.host = host;
    let other = f.host.identity(34);
    admit(&mut f, &other, "Tablet", "device", terms_for(&[(NS, "write")]), terms_for(&[(NS, "write")]));
    let mut host = std::mem::replace(&mut f.host, Host::new());
    home_w.sim = SimHome::new(&f, &home, BASE, NOW);
    let before = e.account().head().0;
    let p = pass(&mut e, &src, &home, &mut home_w, &mut host, &a, NOW + 1_000);
    assert!(p.unbuilt.is_empty() && p.faults.is_empty(), "{p:?}");
    assert_eq!(e.account().head().0, before + 1, "the history was pulled");
    assert!(home_w.sim.requests.iter().any(|r| r == "Get /authority"));
    assert_eq!(home_w.refused, Vec::<(String, String)>::new());
}

/// Gap 2. A member writes and pushes its own records with `colophon.home.write` calls although
/// its terms grant no such purpose (§14: "any member writing only paths under its own author
/// ID"); and for every request the engine's own check and the home's rule agree.
#[test]
fn a_member_writes_its_own_records_with_calls_and_nothing_else() {
    let mut f = fixture("members");
    let home = appoint_home(&mut f);
    let a = f.host.identity(30);
    let r = f.host.identity(32);
    admit(&mut f, &a, "Mac", "device", terms_for(&[(NS, "write")]), terms_for(&[(NS, "write")]));
    admit(&mut f, &r, "Reader", "device", terms_for(&[(NS, "read")]), terms_for(&[(NS, "read")]));
    let src = MemSource::new();
    src.store_account(&f.account);
    let mut e = member_engine(&f, &f.host, &src, &a, NOW);
    let mut home_w = CallingHome::new(SimHome::new(&f, &home, BASE, NOW), false);
    let mut host = std::mem::replace(&mut f.host, Host::new());
    engine_write(&mut e, &mut host, &src, NS, "note.put", json!({"id": "n1", "text": "one"}));
    let p = pass(&mut e, &src, &home, &mut home_w, &mut host, &a, NOW);
    assert!(p.unbuilt.is_empty() && p.faults.is_empty(), "{p:?}");
    assert_eq!(home_w.refused, Vec::<(String, String)>::new());
    assert_eq!(home_w.sim.files.keys().filter(|k| k.starts_with("ops/")).count(), 1, "the record reached the home");

    // The engine's own check of a call and the home's rule, for requests the engine would not
    // make: the same verdict both ways.
    let written = home_w.sim.files.keys().find(|k| k.starts_with("ops/")).unwrap().clone();
    let own = format!("/records/{written}");
    let other = own.replace(&a, &r);
    let foreign_ns = own.replace(&format!("/{NS}/"), "/elsewhere/");
    assert!(home_record_writes(&own["/records/".len()..]).is_some());
    for (method, path, member) in [
        ("PUT", own.as_str(), a.as_str()),
        ("PUT", other.as_str(), a.as_str()),
        ("PUT", foreign_ns.as_str(), a.as_str()),
        ("PUT", own.as_str(), r.as_str()),
        ("GET", "/changes?limit=500", r.as_str()),
        ("PUT", &format!("/records/blobs/{}", "a".repeat(64)), r.as_str()),
    ] {
        let msrc = MemSource::new();
        msrc.store_account(&f.account);
        let mut m = member_engine(&f, &host, &msrc, member, NOW);
        // Give the member the home's head, as its pass would.
        let head = home_w.sim.head_env(&host, NOW).unwrap();
        msrc.put(&format!("heads/{home}.json"), head);
        m.refresh(msrc.listing()).unwrap();
        let body = b"{}";
        let call = HomeCall {
            audience: BASE.into(),
            method: method.into(),
            path: path.into(),
            body_sha256: hex(&Sha256::digest(body)),
            as_of: None,
        };
        let action = m.account().begin_home_call(&host.ids[member].public().signing, &call, host.fresh()).unwrap();
        let sigs = host.sign(action.steps());
        let built = m.finish_write(action, sigs);
        let home_said = match &built {
            Ok(w) => home_w.judge(&host, w.artifact.as_ref().unwrap(), method, path, body, NOW),
            Err(_) => Err("not built".into()),
        };
        let expect_ok = (path == own && member == a) || path.starts_with("/changes");
        assert_eq!(built.is_ok(), expect_ok, "{method} {path} by {member}: {:?}", built.as_ref().err());
        assert_eq!(home_said.is_ok(), expect_ok, "{method} {path} by {member}: home {home_said:?}");
        if let Err(x) = &built {
            assert_eq!(x.code(), "refused:outOfScope", "{method} {path} by {member}");
        }
    }
}

#[test]
fn a_shared_folder_pushes_only_the_sessions_records_and_pulls_remote_records() {
    let mut f = fixture_with_namespaces("members", &[LISTEN, NS]);
    let home = appoint_home(&mut f);
    let a = f.host.identity(30);
    let b = f.host.identity(31);
    let writer = terms_for(&[(NS, "write"), (LISTEN, "write")]);
    admit(&mut f, &a, "Mac", "device", writer.clone(), writer.clone());
    admit(&mut f, &b, "Phone", "device", writer.clone(), writer);
    let src = MemSource::new();
    src.store_account(&f.account);
    let mut mac = member_engine(&f, &f.host, &src, &a, NOW);
    let mut phone = member_engine(&f, &f.host, &src, &b, NOW);
    let mut wire = CallingHome::new(SimHome::new(&f, &home, BASE, NOW), false);
    let mut host = std::mem::replace(&mut f.host, Host::new());

    for e in [&mut mac, &mut phone] {
        let author = e.account().identity().id().to_string();
        engine_write(
            e,
            &mut host,
            &src,
            NS,
            "note.put",
            json!({"id": author, "text": "local"}),
        );
        engine_live(
            e,
            &mut host,
            &src,
            json!({"id": "episode", "show": "show", "seconds": 10}),
        );
    }
    let remote = engine_write(
        &mut phone,
        &mut host,
        &src,
        NS,
        "note.put",
        json!({"id": "remote", "text": "from home"}),
    );
    let (remote_path, remote_bytes) = remote
        .stores
        .iter()
        .find(|(p, _)| p.starts_with("ops/"))
        .unwrap();
    src.remove(remote_path);
    wire.sim
        .files
        .insert(remote_path.clone(), remote_bytes.clone());
    wire.sim.log.push(remote_path.clone());

    let p = pass(&mut mac, &src, &home, &mut wire, &mut host, &a, NOW);
    assert!(
        p.unbuilt.is_empty() && p.faults.is_empty() && wire.refused.is_empty(),
        "{p:?}, {:?}",
        wire.refused
    );
    for kind in ["ops", "history", "state"] {
        for (author, expected) in [(&a, true), (&b, false)] {
            let prefix = format!("{kind}/{author}/");
            let paths: Vec<_> = src
                .listing()
                .into_iter()
                .filter(|p| p.starts_with(&prefix) && p != remote_path)
                .collect();
            assert_eq!(paths.len(), 1, "{prefix}: {paths:?}");
            assert_eq!(
                wire.sim.files.contains_key(&paths[0]),
                expected,
                "{}",
                paths[0]
            );
        }
    }
    assert_eq!(src.get(remote_path).as_ref(), Some(remote_bytes));
    assert_eq!(records(&mac), 3);
}

#[test]
fn a_home_write_service_grant_allows_relaying_another_members_record() {
    let mut f = fixture("members");
    let home = appoint_home(&mut f);
    let relay = f.host.identity(30);
    let author = f.host.identity(31);
    let mut grant = terms_for(&[(NS, "read")]);
    grant["services"] = json!([{"audience": BASE, "purposes": ["colophon.home.write"]}]);
    admit(&mut f, &relay, "Relay", "device", grant.clone(), grant);
    let grant = terms_for(&[(NS, "write")]);
    admit(&mut f, &author, "Author", "device", grant.clone(), grant);
    let src = MemSource::new();
    src.store_account(&f.account);
    let mut writer = member_engine(&f, &f.host, &src, &author, NOW);
    let mut wire = CallingHome::new(SimHome::new(&f, &home, BASE, NOW), false);
    let mut host = std::mem::replace(&mut f.host, Host::new());
    let written = engine_write(
        &mut writer,
        &mut host,
        &src,
        NS,
        "note.put",
        json!({"id": "local", "text": "relay me"}),
    );
    let (path, bytes) = written
        .stores
        .iter()
        .find(|(p, _)| p.starts_with("ops/"))
        .unwrap();
    let mut e = member_engine(&f, &host, &src, &relay, NOW);

    let p = pass(&mut e, &src, &home, &mut wire, &mut host, &relay, NOW);
    assert!(
        p.unbuilt.is_empty() && p.faults.is_empty() && wire.refused.is_empty(),
        "{p:?}, {:?}",
        wire.refused
    );
    assert_eq!(wire.sim.files.get(path), Some(bytes));
}

#[test]
fn a_member_skips_its_signed_history_outside_its_namespace_grant() {
    use colophon_core::v05::{encoding::canonical, records::OperationHeader};

    let mut f = fixture_with_namespaces("members", &[LISTEN, NS]);
    let home = appoint_home(&mut f);
    let a = f.host.identity(30);
    let writer = terms_for(&[(LISTEN, "write")]);
    admit(&mut f, &a, "Mac", "device", writer.clone(), writer);
    let src = MemSource::new();
    src.store_account(&f.account);
    let mut mac = member_engine(&f, &f.host, &src, &a, NOW);
    let mut wire = CallingHome::new(SimHome::new(&f, &home, BASE, NOW), false);
    let mut host = std::mem::replace(&mut f.host, Host::new());
    let live = engine_live(
        &mut mac,
        &mut host,
        &src,
        json!({"id": "episode", "show": "show", "seconds": 10}),
    );
    let (own_path, bytes) = live
        .stores
        .iter()
        .find(|(p, _)| p.starts_with("history/"))
        .unwrap();
    // History storage verifies the signed header without opening its ciphertext.
    let (header, envelope) = OperationHeader::parse(bytes).unwrap();
    let mut body = envelope.value;
    body["namespace"] = json!(NS);
    let body = canonical(&body).unwrap();
    let signing = &host.ids[&a];
    let bytes =
        canonical(&json!({"body": b64(&body), "signature": b64(&signing.sign(&body))})).unwrap();
    let path = format!("history/{a}/{NS}/{:012}-{}.json", header.clock, header.id);
    src.put(&path, bytes);

    let p = pass(&mut mac, &src, &home, &mut wire, &mut host, &a, NOW);
    assert!(
        p.unbuilt.is_empty() && p.faults.is_empty() && wire.refused.is_empty(),
        "{p:?}, {:?}",
        wire.refused
    );
    assert!(wire.sim.files.contains_key(own_path));
    assert!(!p.puts.contains(&format!("{BASE}/records/{path}")), "{p:?}");
}

#[test]
fn a_read_only_member_pulls_without_uploading_local_records_blobs_or_live_heads() {
    let mut f = fixture_with_namespaces("members", &[LISTEN, NS]);
    let home = appoint_home(&mut f);
    let a = f.host.identity(30);
    let b = f.host.identity(31);
    for (member, access) in [(&a, "read"), (&b, "write")] {
        let terms = terms_for(&[(NS, access), (LISTEN, access)]);
        admit(&mut f, member, access, "device", terms.clone(), terms);
    }
    let src = MemSource::new();
    src.store_account(&f.account);
    let mut writer = member_engine(&f, &f.host, &src, &b, NOW);
    let mut wire = CallingHome::new(SimHome::new(&f, &home, BASE, NOW), false);
    let mut host = std::mem::replace(&mut f.host, Host::new());
    engine_blob(
        &mut writer,
        &mut host,
        &src,
        NS,
        "application/octet-stream",
        b"local blob",
        "blob",
        false,
    );
    engine_live(
        &mut writer,
        &mut host,
        &src,
        json!({"id": "episode", "show": "show", "seconds": 10}),
    );
    let remote = engine_write(
        &mut writer,
        &mut host,
        &src,
        NS,
        "note.put",
        json!({"id": "remote", "text": "from home"}),
    );
    let (remote_path, remote_bytes) = remote
        .stores
        .iter()
        .find(|(p, _)| p.starts_with("ops/"))
        .unwrap();
    src.remove(remote_path);
    wire.sim
        .files
        .insert(remote_path.clone(), remote_bytes.clone());
    wire.sim.log.push(remote_path.clone());
    let mut reader = member_engine(&f, &host, &src, &a, NOW);
    assert_eq!(records(&reader), 1);
    assert_eq!(reader.account().live_heads().len(), 1);
    assert!(src.listing().iter().any(|path| path.starts_with("blobs/")));

    let p = pass(&mut reader, &src, &home, &mut wire, &mut host, &a, NOW);
    assert!(
        p.unbuilt.is_empty() && p.faults.is_empty() && wire.refused.is_empty(),
        "{p:?}, {:?}",
        wire.refused
    );
    assert!(p.puts.is_empty(), "{p:?}");
    assert_eq!(src.get(remote_path).as_ref(), Some(remote_bytes));
    assert_eq!(records(&reader), 2);
}

/// Gap 3. A device whose history ends before its approval (another device approved it) learns
/// its approval through a home that requires calls for the history, and then reads and writes.
/// It cannot know its standing before it holds its approval: it may only ask the home it is
/// behind to read, with its own key, and the home decides. Before, its own check refused the
/// call (`unavailable`, and with the head in hand `refused:revoked`: it was not in its history).
#[test]
fn a_device_approved_elsewhere_learns_its_approval_through_the_home() {
    let mut f = fixture("members");
    let home = appoint_home(&mut f);
    let a = f.host.identity(30);
    admit(&mut f, &a, "Mac", "device", terms_for(&[(NS, "write")]), terms_for(&[(NS, "write")]));
    // The phone's folder: a copy of the history from before its approval.
    let phone_src = MemSource::new();
    phone_src.store_account(&f.account);
    let b = f.host.identity(31);
    let mut host = std::mem::replace(&mut f.host, Host::new());
    let mut mac_src = MemSource::new();
    mac_src.store_account(&f.account);
    let mut mac = member_engine(&f, &host, &mac_src, &a, NOW);
    engine_write(&mut mac, &mut host, &mac_src, NS, "note.put", json!({"id": "n1", "text": "one"}));
    f.host = host;
    admit(&mut f, &b, "Phone", "device", terms_for(&[(NS, "write")]), terms_for(&[(NS, "write")]));
    let mut host = std::mem::replace(&mut f.host, Host::new());
    let mut home_w = CallingHome::new(SimHome::new(&f, &home, BASE, NOW), false);
    let p = pass(&mut mac, &mac_src, &home, &mut home_w, &mut host, &a, NOW);
    assert!(p.unbuilt.is_empty() && p.faults.is_empty(), "{p:?}");
    let _ = &mut mac_src;

    let mut phone = Engine::open(
        phone_src.clone(),
        phone_src.listing(),
        Identity::Member(b.clone()),
        EngineOptions::new(f.account.id().as_str(), DEVICE_KEY),
        None,
        NOW,
    )
    .unwrap();
    phone.load().unwrap();
    assert!(!is_member(&phone), "the phone does not hold its approval");
    let p = pass(&mut phone, &phone_src, &home, &mut home_w, &mut host, &b, NOW + 1_000);
    assert!(p.unbuilt.is_empty(), "the phone asked the home with its own key: {p:?}");
    assert!(p.faults.is_empty(), "{p:?}");
    assert_eq!(home_w.refused, Vec::<(String, String)>::new(), "the home accepted the phone's calls");
    assert!(is_member(&phone), "the phone holds its approval now");
    let steps = phone.begin_unlock_epochs();
    phone.finish_unlock_epochs(host.answer_epochs(&b, steps)).unwrap();
    let p = pass(&mut phone, &phone_src, &home, &mut home_w, &mut host, &b, NOW + 2_000);
    assert!(p.unbuilt.is_empty() && p.faults.is_empty(), "{p:?}");
    assert_eq!(records(&phone), 1, "the phone reads what the Mac wrote");
    engine_write(&mut phone, &mut host, &phone_src, NS, "note.put", json!({"id": "n2", "text": "two"}));
    let p = pass(&mut phone, &phone_src, &home, &mut home_w, &mut host, &b, NOW + 3_000);
    assert!(p.unbuilt.is_empty() && p.faults.is_empty(), "{p:?}");
    assert_eq!(home_w.sim.files.keys().filter(|k| k.starts_with("ops/")).count(), 2);
}

/// What a signer knows is judged as the home judges it: a device that holds its own revocation
/// builds no call (`refused:revoked`), and the home refuses the calls it would have made. A device
/// that is behind and not a member at all (never approved) may ask; the home refuses it.
#[test]
fn a_revoked_or_unknown_device_is_refused_by_its_own_check_or_by_the_home() {
    let mut f = fixture("members");
    let home = appoint_home(&mut f);
    let a = f.host.identity(30);
    admit(&mut f, &a, "Mac", "device", terms_for(&[(NS, "write")]), terms_for(&[(NS, "write")]));
    let stranger_src = MemSource::new();
    stranger_src.store_account(&f.account);
    let c = f.host.identity(33);
    admit(&mut f, &c, "Old", "device", terms_for(&[(NS, "write")]), terms_for(&[(NS, "write")]));
    let src = MemSource::new();
    src.store_account(&f.account);
    let seed = f.host.fresh();
    let action = f.account.begin_revoke(&c, &RevokeKeep::Everything, &[f.d.clone()], seed).unwrap();
    run(&mut f.account, &f.host, action);
    let mut home_w = CallingHome::new(SimHome::new(&f, &home, BASE, NOW), false);
    let mut host = std::mem::replace(&mut f.host, Host::new());

    // The old device, holding the history up to before its revocation, is behind: it asks and
    // the home refuses (the home holds the revocation).
    let mut old = member_engine(&f, &host, &src, &c, NOW);
    let p = pass(&mut old, &src, &home, &mut home_w, &mut host, &c, NOW);
    assert!(p.unbuilt.is_empty(), "{p:?}");
    assert!(p.faults.iter().any(|f| matches!(f, Fault::Unauthorized { .. })), "{p:?}");
    assert_eq!(home_w.refused.last().map(|r| r.1.as_str()), Some("refused:revoked"));

    // Once it holds its revocation, its own check builds nothing.
    let full = MemSource::new();
    full.store_account(&f.account);
    for p in full.listing() {
        src.put(&p, full.get(&p).unwrap());
    }
    let head = home_w.sim.head_env(&host, NOW).unwrap();
    src.put(&format!("heads/{home}.json"), head);
    old.refresh(src.listing()).unwrap();
    let call = HomeCall {
        audience: BASE.into(),
        method: "GET".into(),
        path: "/authority?after=1&limit=64".into(),
        body_sha256: hex(&Sha256::digest(b"")),
        as_of: None,
    };
    let action = old.account().begin_home_call(&host.ids[&c].public().signing, &call, host.fresh()).unwrap();
    let sigs = host.sign(action.steps());
    assert_eq!(old.finish_write(action, sigs).err().map(|e| e.code()).as_deref(), Some("refused:revoked"));

    // A key that was never approved, behind the home: it may ask, the home refuses.
    let x = host.identity(40);
    let mut stranger = Engine::open(
        stranger_src.clone(),
        stranger_src.listing(),
        Identity::Member(x.clone()),
        EngineOptions::new(f.account.id().as_str(), DEVICE_KEY),
        None,
        NOW,
    )
    .unwrap();
    stranger.load().unwrap();
    let before = home_w.refused.len();
    let p = pass(&mut stranger, &stranger_src, &home, &mut home_w, &mut host, &x, NOW);
    assert!(p.unbuilt.is_empty(), "{p:?}");
    assert_eq!(home_w.refused.len(), before + 1);
    assert_eq!(home_w.refused.last().map(|r| r.1.as_str()), Some("refused:revoked"));
    assert!(!is_member(&stranger));
    // Not behind the home, the stranger's own check refuses at once.
    let full = MemSource::new();
    full.store_account(&f.account);
    let mut s2 = Engine::open(
        full.clone(),
        full.listing(),
        Identity::Member(x.clone()),
        EngineOptions::new(f.account.id().as_str(), DEVICE_KEY),
        None,
        NOW,
    )
    .unwrap();
    s2.load().unwrap();
    full.put(&format!("heads/{home}.json"), home_w.sim.head_env(&host, NOW).unwrap());
    s2.refresh(full.listing()).unwrap();
    let action = s2.account().begin_home_call(&host.ids[&x].public().signing, &call, host.fresh()).unwrap();
    let sigs = host.sign(action.steps());
    assert_eq!(s2.finish_write(action, sigs).err().map(|e| e.code()).as_deref(), Some("refused:revoked"));
    let _ = Method::Get;
    let _: Value = json!({});
}

/// A call signed by the controller `id` (whose key the host holds) over what `f.account` holds.
fn controller_call(f: &Fixture, id: &str, purpose: &str, method: &str, path: &str) -> Vec<u8> {
    use base64::engine::general_purpose::STANDARD;
    let me = &f.host.ids[id];
    let (seq, digest) = f.account.head();
    let body = colophon_core::v05::encoding::canonical(&json!({
        "protocol": "colophon/call/5",
        "account": f.account.id().as_str(),
        "asOf": {"seq": seq, "digest": digest},
        "signer": {"controller": id},
        "key": STANDARD.encode(me.public().signing),
        "audience": BASE,
        "purpose": purpose,
        "args": {"method": method, "path": path, "body": hex(&Sha256::digest(b""))},
        "requestId": URL_SAFE_NO_PAD.encode([path.len() as u8 ^ purpose.len() as u8; 32]),
        "created": colophon_core::v05::write::format_date(NOW),
    }))
    .unwrap();
    let sig = me.sign(&body).to_vec();
    serde_json::to_vec(&json!({"body": STANDARD.encode(&body), "signature": STANDARD.encode(sig)}))
        .unwrap()
}

/// §12.3 step 7 and §13.4: `colophon.history.read` reads the history and nothing else. A
/// `recover`-only controller (the kit) may read the history with it, but a call with that purpose
/// for the change feed, a record or a blob chunk is `refused:outOfScope`, as is its
/// `colophon.home.read` call; a controller entitled to `colophon.home.read` reads them. Before,
/// the home accepted `colophon.history.read` for every GET, so the kit read every record.
#[test]
fn history_read_reads_the_history_and_not_the_records() {
    let mut f = fixture("members");
    let home = appoint_home(&mut f);
    let home_w = CallingHome::new(SimHome::new(&f, &home, BASE, NOW), false);
    let blob = format!("/records/blobs/{}", "ab".repeat(32));
    let op = format!("/records/ops/{}/{NS}/000000000001-{}.json", "0".repeat(32), "1".repeat(32));
    let judge = |id: &str, purpose: &str, path: &str| {
        let call = controller_call(&f, id, purpose, "GET", path);
        home_w.judge(&f.host, &call, "GET", path, b"", NOW)
    };
    let out = Err("refused:outOfScope".to_string());
    for path in ["/changes?limit=500", blob.as_str(), op.as_str()] {
        assert_eq!(judge(&f.k, "colophon.history.read", path), out, "{path}");
        assert_eq!(judge(&f.k, "colophon.home.read", path), out, "{path}");
        assert_eq!(judge(&f.d, "colophon.history.read", path), out, "{path}");
        assert_eq!(judge(&f.d, "colophon.home.read", path), Ok(()), "{path}");
    }
    for path in [
        "/authority?after=0&limit=1",
        "/pending",
        "/records/authority/00000001.json",
    ] {
        assert_eq!(judge(&f.k, "colophon.history.read", path), Ok(()), "{path}");
        assert_eq!(judge(&f.d, "colophon.home.read", path), Ok(()), "{path}");
    }
}
