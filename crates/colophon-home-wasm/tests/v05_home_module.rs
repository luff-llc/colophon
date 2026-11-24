//! The home module (`colophon_home_wasm::handle`) driven directly, no relay and no HTTP: the
//! decisions it returns for a first upload, a transition, a veto, a late object, a forged object,
//! the head guard, recording entries and the call check. The same bytes the relay sees.
#![allow(
    clippy::unwrap_used,
    clippy::too_many_arguments,
    clippy::cloned_ref_to_slice_refs,
    dead_code
)]
#[path = "../../colophon-core/tests/v05_engine_support/mod.rs"]
mod support;
#[path = "../../colophon-core/tests/v05_stopped_support/mod.rs"]
mod stopped_support;
mod support_relay;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use colophon_core::v05::account::{Change, Incoming, RevokeKeep};
use colophon_core::v05::account::HomeCall;
use colophon_core::v05::calls::{
    check_home_batch_as_signer, home_call_args, AccountView, CallConfig, HomeRequest,
};
use colophon_core::v05::history::{verify_history, Persisted};
use colophon_core::v05::encoding::{canonical, digest};
use colophon_core::v05::history::Objects;
use colophon_core::v05::write::authority::TransitionRule;
use colophon_core::v05::write::format_date;
use colophon_home_wasm::handle;
use serde_json::{json, Value};
use support::*;
use support_relay::{appoint_homes, call_as, create_with, entries_json, HomeKeys, BASE_A};

const NOW: i64 = T0 + 3 * HOUR;
const NS: &str = "listening.podcasts";
const BATCH: &str = "/records/batch";

fn batch_request(home: &Home, now: i64, body: &str, authorization: Value) -> Value {
    json!({"op": "access", "state": home.state, "now": now, "base": BASE_A,
           "method": "POST", "section": "records", "rest": "batch",
           "path": BATCH, "batchBody": b(body.as_bytes()), "call": authorization})
}

/// A driver: the module, its state, and the home's key (the host's part).
struct Home {
    keys: HomeKeys,
    state: String,
}
/// The module build these tests name (`build`): a test value, as a host names the SHA-256 of the
/// module it instantiated.
const TEST_BUILD: &str = "b1d0000000000000000000000000000000000000000000000000000000000001";
/// Name the build once for this process, before any request.
fn named() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let out: Value = serde_json::from_slice(&handle(json!({"op": "build", "fingerprint": TEST_BUILD}).to_string().as_bytes())).unwrap();
        assert_eq!(out["ok"], true, "{out}");
    });
}
fn call(req: Value) -> Value {
    named();
    let out = handle(req.to_string().as_bytes());
    let v: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["ok"], true, "{v}");
    v
}
fn b(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}
impl Home {
    fn new(keys: HomeKeys, account: &str) -> Self {
        let state = call(json!({"op": "init", "home": keys.id, "account": account}))["state"]
            .as_str()
            .unwrap()
            .to_string();
        Self { keys, state }
    }
    fn take(&mut self, r: &Value) {
        if let Some(s) = r["state"].as_str() {
            self.state = s.to_string();
        }
    }
    /// Sign what the module asks to be signed, as receipts, and hand the signatures back.
    fn sign_receipts(&mut self, r: &Value, now: i64) -> Vec<Value> {
        let mut out = Vec::new();
        for s in r["sign"].as_array().cloned().unwrap_or_default() {
            let body = STANDARD.decode(s["body"].as_str().unwrap()).unwrap();
            let sig = self.keys.sign(&body).signature;
            let f = call(json!({"op": "finish_receipt", "state": self.state, "object": s["object"],
                                "body": s["body"], "signature": b(&sig), "now": now}));
            self.take(&f);
            out.push(serde_json::from_slice(&STANDARD.decode(f["envelope"].as_str().unwrap()).unwrap()).unwrap());
        }
        out
    }
    fn authority(&mut self, from: u64, entries: &[Value], now: i64) -> Value {
        let body = json!({"from": from, "entries": entries, "receipts": []}).to_string();
        let r = call(json!({"op": "post_authority", "state": self.state, "now": now, "body": b(body.as_bytes())}));
        self.take(&r);
        r
    }
    fn pending(&mut self, objects: &[Value], now: i64) -> Value {
        let body = json!({"objects": objects}).to_string();
        let r = call(json!({"op": "post_pending", "state": self.state, "now": now, "body": b(body.as_bytes())}));
        self.take(&r);
        r
    }
    fn head(&mut self, now: i64) -> Option<Value> {
        let r = call(json!({"op": "head_request", "state": self.state, "now": now}));
        self.take(&r);
        let s = r["sign"].as_object()?;
        let body = STANDARD.decode(s["body"].as_str().unwrap()).unwrap();
        let sig = self.keys.sign(&body).signature;
        let f = call(json!({"op": "finish_head", "state": self.state, "now": now, "seq": s["seq"],
                            "digest": s["digest"], "issued": s["issued"], "signature": b(&sig)}));
        self.take(&f);
        Some(serde_json::from_slice(&STANDARD.decode(f["envelope"].as_str().unwrap()).unwrap()).unwrap())
    }
    fn due(&mut self, now: i64) -> Value {
        let r = call(json!({"op": "record_due", "state": self.state, "now": now}));
        self.take(&r);
        r
    }
    fn kinds(&self) -> Vec<String> {
        let o = call(json!({"op": "objects", "state": self.state}));
        let mut v: Vec<(String, String)> = o["files"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|f| f["path"].as_str().unwrap().starts_with("authority/"))
            .map(|f| {
                let env: Value = serde_json::from_slice(&STANDARD.decode(f["bytes"].as_str().unwrap()).unwrap()).unwrap();
                let body: Value = serde_json::from_slice(&STANDARD.decode(env["body"].as_str().unwrap()).unwrap()).unwrap();
                (f["path"].as_str().unwrap().to_string(), body["kind"].as_str().unwrap().to_string())
            })
            .collect();
        v.sort();
        v.into_iter().map(|(_, k)| k).collect()
    }
}

struct Setup {
    f: Fixture,
    home: Home,
    ctl: colophon_core::v05::engine::Engine<MemSource>,
    src: MemSource,
}
fn setup(history: &str) -> Setup {
    let keys = HomeKeys::new(0x77);
    let mut f = create_with(&[NS], history, 1);
    appoint_homes(&mut f, &[(&keys, BASE_A)]);
    let mut home = Home::new(keys, f.account.id().as_str());
    let entries = entries_json(&f);
    let values: Vec<Value> = entries.iter().map(|(_, e)| e.clone()).collect();
    let r = home.authority(1, &values, T0 + 1_000);
    assert_eq!(r["outcome"], "ok", "{r}");
    assert_eq!(r["appointed"], true);
    let src = MemSource::new();
    src.store_account(&f.account);
    let host = std::mem::replace(&mut f.host, Host::new());
    let d = f.d.clone();
    let ctl = controller_engine(&f, &host, &src, &d, NOW);
    f.host = host;
    Setup { f, home, ctl, src }
}
fn transition(s: &mut Setup, window: u64, by: &[String]) -> (String, Value) {
    let action = s
        .ctl
        .account()
        .begin_transition(&Change::policy(json!({"callWindow": window})), by, TransitionRule::Control)
        .unwrap();
    engine_finish(&mut s.ctl, &s.f.host, &s.src, action);
    let digest = s.ctl.account().pending().last().unwrap().digest.clone();
    let env = s
        .ctl
        .account()
        .objects()
        .pending
        .iter()
        .find(|p| pending_path(p).contains(&digest))
        .map(|p| serde_json::from_slice(p).unwrap())
        .unwrap();
    (digest, env)
}

#[test]
fn a_batch_uses_one_bound_call_for_records_and_members_only_history() {
    let mut f = create_with(&[NS, "notes"], "members", 1);
    let member = f.host.identity(31);
    let revoked = f.host.identity(32);
    let expired = f.host.identity(33);
    let terms = terms_for(&[(NS, "read")]);
    let mut delegating_terms = terms.clone();
    delegating_terms["services"] =
        json!([{"audience": BASE_A, "purposes": ["colophon.home.read"]}]);
    delegating_terms["depth"] = json!(1);
    admit(
        &mut f,
        &member,
        "Reader",
        "device",
        delegating_terms.clone(),
        delegating_terms,
    );
    admit(
        &mut f,
        &revoked,
        "Revoked reader",
        "device",
        terms.clone(),
        terms.clone(),
    );
    let delegate = f.host.identity(34);
    let mut expiring_terms = terms.clone();
    expiring_terms["expires"] = json!(colophon_core::v05::write::format_date(NOW - HOUR));
    admit(
        &mut f,
        &expired,
        "Expiring reader",
        "device",
        expiring_terms.clone(),
        expiring_terms,
    );
    let revoke = f
        .account
        .begin_revoke(&revoked, &RevokeKeep::Nothing, &[f.d.clone()], [0x79; 32])
        .unwrap();
    run(&mut f.account, &f.host, revoke);
    let keys = HomeKeys::new(0x77);
    appoint_homes(&mut f, &[(&keys, BASE_A)]);
    let mut home = Home::new(keys, f.account.id().as_str());
    let entries: Vec<Value> = entries_json(&f)
        .into_iter()
        .map(|(_, entry)| entry)
        .collect();
    let first = home.authority(1, &entries, NOW);
    assert_eq!(first["appointed"], true, "{first}");
    assert!(home.head(NOW).is_some());

    let op = format!("ops/{member}/{NS}/000000000001-{}.json", "a".repeat(32));
    let live = format!("state/{member}/{NS}/current.json");
    let other_namespace = format!(
        "history/{revoked}/notes/000000000001-{}.json",
        "b".repeat(32)
    );
    let blob = format!("blobs/{}", "c".repeat(64));
    let history = "authority/00000001.json";
    let paths = [&op, &live, &other_namespace, &blob, history];
    let body = json!({"paths": paths}).to_string();
    let auth = |id: &str, purpose: &str, method: &str, path: &str, body: &str, at, n| {
        b(&call_as(
            &f.host,
            &f.account,
            "member",
            id,
            BASE_A,
            purpose,
            home_call_args(method, path, &digest(body.as_bytes())),
            at,
            [n; 32],
        ))
    };
    let request = |body: &str, authorization: Value| batch_request(&home, NOW, body, authorization);
    let sign_batch = |id: &str, purpose: &str, body: &str, at, n| {
        json!(auth(id, purpose, "POST", "/records/batch", body, at, n))
    };
    let read = "colophon.home.read";
    let valid = request(&body, sign_batch(&member, read, &body, NOW, 1));
    let allowed = call(valid.clone());
    assert_eq!(allowed["allowed"], true, "{allowed}");
    let decisions = allowed["records"].as_array().unwrap();
    assert_eq!(decisions.len(), paths.len());
    for (decision, path) in decisions.iter().zip(paths) {
        assert_eq!(*decision, json!({"path": path, "status": 200, "kind": kind_of(path)}));
        let relative = format!("/records/{path}");
        for method in ["GET", "HEAD"] {
            let single = call(json!({
                "op": "access", "state": home.state, "now": NOW, "base": BASE_A,
                "method": method, "section": "records", "rest": path, "path": relative,
                "bodySha256": digest(b""), "call": auth(&member, read, method, &relative, "", NOW, 2),
            }));
            assert_eq!(single["allowed"], true, "{method} {path}: {single}");
        }
    }
    let delegate_point = f.host.ids[&delegate].public().signing;
    let link_body = canonical(&json!({
        "protocol": "colophon/link/5", "account": f.account.id().as_str(), "from": member,
        "to": {"signing": b(&delegate_point)}, "session": 0,
        "terms": {"services": [{"audience": BASE_A, "purposes": [read]}], "depth": 0},
        "notBefore": format_date(NOW - 1_000), "expires": format_date(NOW + 60_000),
        "created": format_date(NOW - 1_000),
    }))
    .unwrap();
    let link_signature = f.host.ids[&member].sign(&link_body);
    let linked_call = |signature: &[u8], signed_body: &str| {
        let link = canonical(&json!({"body": b(&link_body), "signature": b(signature)})).unwrap();
        let (seq, digest_at_seq) = f.account.head();
        let call_body = canonical(&json!({
            "protocol": "colophon/call/5", "account": f.account.id().as_str(),
            "asOf": {"seq": seq, "digest": digest_at_seq}, "signer": {"member": member},
            "key": b(&delegate_point), "links": [b(&link)], "audience": BASE_A, "purpose": read,
            "args": home_call_args("POST", BATCH, &digest(signed_body.as_bytes())),
            "requestId": URL_SAFE_NO_PAD.encode([10; 32]), "created": format_date(NOW),
        }))
        .unwrap();
        json!(b(&canonical(&json!({
            "body": b(&call_body), "signature": b(&f.host.ids[&delegate].sign(&call_body)),
        }))
        .unwrap()))
    };
    let linked = call(request(&body, linked_call(&link_signature, &body)));
    assert_eq!(linked["records"], allowed["records"], "{linked}");
    assert_eq!(linked["reserve"]["signer"], format!("member:{member}"));
    let mut forged_link = link_signature;
    forged_link[0] ^= 1;
    let mut replay = valid.clone();
    replay["existing"] = allowed["reserve"].clone();
    let mut over_share = valid;
    over_share["replayRows"] = json!(1);
    over_share["signerRows"] = json!((0..64)
        .map(|key| json!({"at": NOW, "key": key}))
        .collect::<Vec<_>>());
    for (req, status, result) in [
        (request(&body, Value::Null), 401, Value::Null),
        (request(&body, json!(b(b"{}"))), 403, json!("malformed")),
        (
            request(&body, linked_call(&forged_link, &body)),
            403,
            json!("badSignature"),
        ),
        (
            request(&body, linked_call(&link_signature, "{}")),
            403,
            json!("refused:outOfScope"),
        ),
        (
            request(&body, sign_batch(&revoked, read, &body, NOW, 3)),
            403,
            json!("refused:revoked"),
        ),
        (
            request(&body, sign_batch(&expired, read, &body, NOW, 9)),
            403,
            json!("refused:expired"),
        ),
        (
            request(&body, sign_batch(&member, read, "{}", NOW, 4)),
            403,
            json!("refused:outOfScope"),
        ),
        (
            request(
                &body,
                sign_batch(&member, "colophon.history.read", &body, NOW, 5),
            ),
            403,
            json!("refused:outOfScope"),
        ),
        (
            request(&body, sign_batch(&member, read, &body, NOW - HOUR, 6)),
            403,
            json!("refused:window"),
        ),
        (replay, 403, json!("refused:replay")),
        (over_share, 429, json!("refused:window")),
    ] {
        let answer = call(req);
        assert_eq!(answer["status"], status, "{answer}");
        assert_eq!(answer["result"], result);
        assert!(answer.get("records").is_none());
        assert!(answer.get("reserve").is_none());
    }
    let too_many = json!({"paths": (1..=257)
        .map(|i| format!("authority/{i:08}.json")).collect::<Vec<_>>()});
    for invalid in [
        "{".to_string(),
        json!({"paths": []}).to_string(),
        json!({"paths": [history, history]}).to_string(),
        json!({"paths": ["requests/one.json"]}).to_string(),
        too_many.to_string(),
    ] {
        let answer = call(request(
            &invalid,
            sign_batch(&member, read, &invalid, NOW, 7),
        ));
        assert_eq!(answer["status"], 400, "{answer}");
        assert!(answer.get("reserve").is_none());
    }
    let oversized = " ".repeat(64 * 1024 + 1);
    assert_eq!(
        call(request(
            &oversized,
            sign_batch(&member, read, &oversized, NOW, 8)
        ))["status"],
        413
    );
    let waiting = Home::new(HomeKeys::new(0x77), f.account.id().as_str());
    for (body, credential) in [
        (&body[..], Value::Null),
        ("{", sign_batch(&member, read, "{", NOW, 11)),
    ] {
        let answer = call(batch_request(&waiting, NOW, body, credential));
        assert_eq!(answer["status"], 404, "{answer}");
        assert!(answer.get("reserve").is_none());
    }
}

/// A batch reaches no further than single-record reads: conditions on a link or on the member's
/// own terms are judged for every path as a single `GET` of it would carry them, and one path out
/// of scope refuses the whole batch before anything is reserved or served.
#[test]
fn a_conditional_delegation_cannot_batch_paths_it_could_not_get_one_at_a_time() {
    let mut f = create_with(&[NS], "members", 1);
    let member = f.host.identity(41);
    let narrowed = f.host.identity(42);
    let delegate = f.host.identity(43);
    let read = "colophon.home.read";
    let mut delegating = terms_for(&[(NS, "read")]);
    delegating["services"] = json!([{"audience": BASE_A, "purposes": [read]}]);
    delegating["depth"] = json!(1);
    admit(&mut f, &member, "Reader", "device", delegating.clone(), delegating);
    // Member terms of its own: the batch route and live values only.
    let scope = json!([{"any": [{"eq": ["args.path", BATCH]},
                                {"prefix": ["args.path", "/records/state/"]}]}]);
    let mut conditional = terms_for(&[(NS, "read")]);
    conditional["conditions"] = scope.clone();
    admit(&mut f, &narrowed, "Narrow reader", "device", conditional.clone(), conditional);
    let keys = HomeKeys::new(0x77);
    appoint_homes(&mut f, &[(&keys, BASE_A)]);
    let mut home = Home::new(keys, f.account.id().as_str());
    let entries: Vec<Value> = entries_json(&f).into_iter().map(|(_, e)| e).collect();
    assert_eq!(home.authority(1, &entries, NOW)["appointed"], true);
    let home_head = serde_json::to_vec(&home.head(NOW).unwrap()).unwrap();

    let live = format!("state/{member}/{NS}/current.json");
    let op = format!("ops/{member}/{NS}/000000000001-{}.json", "a".repeat(32));
    let delegate_point = f.host.ids[&delegate].public().signing;
    let link_body = canonical(&json!({
        "protocol": "colophon/link/5", "account": f.account.id().as_str(), "from": member,
        "to": {"signing": b(&delegate_point)}, "session": 0,
        "terms": {"services": [{"audience": BASE_A, "purposes": [read]}], "depth": 0,
                  "conditions": scope},
        "notBefore": format_date(NOW - 1_000), "expires": format_date(NOW + 60_000),
        "created": format_date(NOW - 1_000),
    }))
    .unwrap();
    let link = canonical(&json!({"body": b(&link_body),
                                 "signature": b(&f.host.ids[&member].sign(&link_body))}))
    .unwrap();
    let linked = |args: Value, n: u8| {
        let (seq, at) = f.account.head();
        let body = canonical(&json!({
            "protocol": "colophon/call/5", "account": f.account.id().as_str(),
            "asOf": {"seq": seq, "digest": at}, "signer": {"member": member},
            "key": b(&delegate_point), "links": [b(&link)], "audience": BASE_A, "purpose": read,
            "args": args, "requestId": URL_SAFE_NO_PAD.encode([n; 32]), "created": format_date(NOW),
        }))
        .unwrap();
        json!(b(&canonical(&json!({"body": b(&body),
                                   "signature": b(&f.host.ids[&delegate].sign(&body))}))
        .unwrap()))
    };
    let own = |args: Value, n: u8| {
        json!(b(&call_as(&f.host, &f.account, "member", &narrowed, BASE_A, read, args, NOW, [n; 32])))
    };
    let batch_args = |body: &str| home_call_args("POST", BATCH, &digest(body.as_bytes()));
    let get = |path: &str, credential: Value| {
        call(json!({"op": "access", "state": home.state, "now": NOW, "base": BASE_A,
                    "method": "GET", "section": "records", "rest": path,
                    "path": format!("/records/{path}"), "bodySha256": digest(b""),
                    "call": credential}))
    };
    let get_args = |path: &str| home_call_args("GET", &format!("/records/{path}"), &digest(b""));

    // One at a time: the live value is in scope, the operation is not.
    for (who, n) in [(&linked as &dyn Fn(Value, u8) -> Value, 1u8), (&own, 2)] {
        let ok = get(&live, who(get_args(&live), n));
        assert_eq!(ok["allowed"], true, "{ok}");
        let refused = get(&op, who(get_args(&op), n + 10));
        assert_eq!(refused["result"], "refused:outOfScope", "{refused}");
    }
    // In scope: a batch of live values only is served.
    let in_scope = json!({"paths": [&live]}).to_string();
    for (who, n) in [(&linked as &dyn Fn(Value, u8) -> Value, 21u8), (&own, 22)] {
        let ok = call(batch_request(&home, NOW, &in_scope, who(batch_args(&in_scope), n)));
        assert_eq!(ok["allowed"], true, "{ok}");
        assert_eq!(ok["records"], json!([{"path": live, "status": 200, "kind": "live"}]));
    }
    // One path out of scope refuses the whole batch: no per-item results, nothing reserved.
    for body in [json!({"paths": [&live, &op]}), json!({"paths": [&op, &live]})] {
        let body = body.to_string();
        for (who, n) in [(&linked as &dyn Fn(Value, u8) -> Value, 31u8), (&own, 32)] {
            let answer = call(batch_request(&home, NOW, &body, who(batch_args(&body), n)));
            assert_eq!(answer["status"], 403, "{answer}");
            assert_eq!(answer["result"], "refused:outOfScope");
            assert!(answer.get("records").is_none());
            assert!(answer.get("reserve").is_none());
        }
    }
    // The signer's own preflight refuses exactly what the home refuses, by the same rule.
    let mut objects = f.account.objects().clone();
    objects.heads.push(home_head);
    let verdict = verify_history(&objects, &Persisted::default(), NOW);
    let view = AccountView::from_history_verifier(&verdict, &objects, NOW).unwrap();
    let audiences = [BASE_A.to_string()];
    let origins = Default::default();
    let cfg = CallConfig {
        now_ms: NOW,
        audiences: &audiences,
        call_origins: &origins,
        controller_purposes: &[],
        home_endpoints: &audiences,
    };
    let mixed = json!({"paths": [&live, &op]}).to_string();
    for (body, paths) in [(&in_scope, vec![live.clone()]), (&mixed, vec![live.clone(), op.clone()])] {
        for (who, n) in [(&linked as &dyn Fn(Value, u8) -> Value, 41u8), (&own, 42)] {
            let credential = who(batch_args(body), n);
            let envelope = STANDARD.decode(credential.as_str().unwrap()).unwrap();
            let sha = digest(body.as_bytes());
            let req = HomeRequest { method: "POST", path: BATCH, body_sha256: &sha, writes: &[] };
            let signer = check_home_batch_as_signer(&envelope, &view, &cfg, &req, &paths)
                .err()
                .map(|e| e.code());
            let home_said = call(batch_request(&home, NOW, body, credential));
            let home_code = home_said["result"].as_str().map(str::to_string);
            assert_eq!(signer, home_code, "{body}: home {home_said}");
            assert_eq!(signer.is_none(), home_said["allowed"] == true);
        }
    }
    // Through the account: a batch is begun with its body, judged path by path at finish.
    let mut heads = Objects::default();
    heads.heads.push(objects.heads.last().unwrap().clone());
    f.account.merge(Incoming { objects: heads, ..Default::default() }, NOW).unwrap();
    let controller = f.host.ids[&f.d].public().signing;
    let generic = HomeCall {
        audience: BASE_A.into(),
        method: "POST".into(),
        path: BATCH.into(),
        body_sha256: digest(mixed.as_bytes()),
        as_of: None,
    };
    assert!(f.account.begin_home_call(&controller, &generic, [50; 32]).is_err());
    let action = f
        .account
        .begin_home_batch_call(&controller, &[], BASE_A, mixed.as_bytes(), None, [51; 32])
        .unwrap();
    let sigs = f.host.sign(action.steps());
    let finished = f.account.finish(action, sigs).unwrap();
    let built = json!(b(finished.artifact.as_ref().unwrap()));
    let served = call(batch_request(&home, NOW, &mixed, built));
    assert_eq!(served["allowed"], true, "{served}");
}

#[test]
fn recover_only_and_suspended_controllers_cannot_batch_history() {
    let mut recovery = setup("members");
    assert!(recovery.home.head(NOW).is_some());
    assert_history_only(
        &recovery.f,
        &recovery.home,
        &recovery.f.k,
        NOW,
        "refused:outOfScope",
    );

    let keys = HomeKeys::new(0x77);
    let mut f = stopped_support::fixture("members", &[(&keys, BASE_A)]);
    let mut home = Home::new(keys, f.account.id().as_str());
    let entries: Vec<_> = entries_json(&f)
        .into_iter()
        .map(|(_, entry)| entry)
        .collect();
    let now = f.account.now_ms();
    assert_eq!(home.authority(1, &entries, now)["outcome"], "ok");
    let remove = f
        .account
        .begin_remove_controller(
            &[f.d.clone()],
            &[],
            &[f.k.clone()],
            TransitionRule::Control,
            None,
        )
        .unwrap();
    let done = run(&mut f.account, &f.host, remove);
    let transition = &done.pending[0];
    let response = home.pending(&[stopped_support::value(transition)], now);
    assert_eq!(response["outcome"], "ok", "{response}");
    let receipts = home.sign_receipts(&response, now);
    assert_eq!(receipts.len(), 1, "{response}");
    f.account
        .merge(
            Incoming {
                objects: Objects {
                    pending: vec![canonical(&receipts[0]).unwrap()],
                    ..Default::default()
                },
                records: vec![],
            },
            now,
        )
        .unwrap();
    let suspend = f
        .account
        .begin_suspend(&f.d, &stopped_support::object_digest(transition), &f.k)
        .unwrap();
    run(&mut f.account, &f.host, suspend);
    let (seq, entry) = entries_json(&f).pop().unwrap();
    let outcome = home.authority(seq, &[entry], now);
    assert_eq!(outcome["outcome"], "ok", "{outcome}");
    let now = now + 1_000;
    assert!(home.head(now).is_some());
    assert_history_only(&f, &home, &f.d, now, "refused:revoked");
}

fn assert_history_only(f: &Fixture, home: &Home, controller: &str, now: i64, refusal: &str) {
    let history = "authority/00000001.json";
    let path = format!("/records/{history}");
    let auth = |purpose, method, path, body: &[u8]| {
        json!(b(&call_as(
            &f.host,
            &f.account,
            "controller",
            controller,
            BASE_A,
            purpose,
            home_call_args(method, path, &digest(body)),
            now,
            [12; 32],
        )))
    };
    let get = call(
        json!({"op": "access", "state": home.state, "now": now, "base": BASE_A,
        "method": "GET", "section": "records", "rest": history, "path": path,
        "bodySha256": digest(b""), "call": auth("colophon.history.read", "GET", &path, b"")}),
    );
    assert_eq!(get["allowed"], true, "{get}");
    let body = json!({"paths": [history]}).to_string();
    for (purpose, result) in [
        ("colophon.history.read", "refused:outOfScope"),
        ("colophon.home.read", refusal),
    ] {
        let batch = call(batch_request(
            home,
            now,
            &body,
            auth(purpose, "POST", BATCH, body.as_bytes()),
        ));
        assert_eq!(batch["status"], 403, "{batch}");
        assert_eq!(batch["result"], result);
        assert!(batch.get("records").is_none());
        assert!(batch.get("reserve").is_none());
    }
}

#[test]
fn public_history_requires_a_batch_call_and_a_stopped_home_refuses_it() {
    use stopped_support::{activate, final_entry, head, transition, value, DUE};

    let keys = HomeKeys::new(0x77);
    let f = stopped_support::fixture("public", &[(&keys, BASE_A)]);
    let mut home = Home::new(keys, f.account.id().as_str());
    let entries: Vec<_> = entries_json(&f)
        .into_iter()
        .map(|(_, entry)| entry)
        .collect();
    assert_eq!(home.authority(1, &entries, T0)["outcome"], "ok");
    assert!(home.head(NOW).is_some());
    let history = "authority/00000001.json";
    let body = json!({"paths": [history]}).to_string();
    let signed = |now| {
        json!(b(&call_as(
            &f.host,
            &f.account,
            "controller",
            &f.d,
            BASE_A,
            "colophon.home.read",
            home_call_args("POST", BATCH, &digest(body.as_bytes())),
            now,
            [13; 32],
        )))
    };
    let get = |home: &Home, now| {
        call(json!({
            "op": "access", "state": home.state, "now": now, "base": BASE_A,
            "method": "GET", "section": "records", "rest": history, "path": format!("/records/{history}"),
        }))
    };
    assert_eq!(get(&home, NOW)["via"], "public");
    assert_eq!(
        call(batch_request(&home, NOW, &body, Value::Null))["status"],
        401
    );
    let allowed = call(batch_request(&home, NOW, &body, signed(NOW)));
    assert_eq!(allowed["allowed"], true, "{allowed}");

    let raise = transition(&f, json!({"layout": 3}), &f.k, NOW);
    let response = home.pending(&[value(&raise)], NOW);
    let receipts = home.sign_receipts(&response, NOW);
    assert_eq!(receipts.len(), 1, "{response}");
    let mut objects = f.account.objects().clone();
    objects
        .pending
        .extend([raise.clone(), canonical(&receipts[0]).unwrap()]);
    let activation = activate(&mut objects, &raise, DUE);
    objects.heads.push(head(&home.keys, &objects, DUE));
    let finality = final_entry(&mut objects, entry_seq(&activation), DUE);
    let stopped = home.authority(
        entry_seq(&activation),
        &[value(&activation), value(&finality)],
        DUE,
    );
    assert_eq!(stopped["outcome"], "ok", "{stopped}");
    assert_eq!(get(&home, DUE)["via"], "public");
    let batch = call(batch_request(&home, DUE, &body, signed(DUE)));
    assert_eq!(batch["status"], 503, "{batch}");
    assert_eq!(batch["result"], "unavailable");
    assert!(batch.get("records").is_none());
    assert!(batch.get("reserve").is_none());
}

#[test]
fn a_first_upload_appoints_the_home_and_a_head_is_due_then_guarded() {
    let mut s = setup("public");
    let st = call(json!({"op": "status", "state": s.home.state, "now": NOW}));
    assert_eq!(st["appointed"], true);
    assert_eq!(st["seq"], 3);
    // A head is due; signing it twice at the same instant is refused by the guard.
    assert!(s.home.head(NOW).is_some());
    let again = call(json!({"op": "head_request", "state": s.home.state, "now": NOW}));
    assert!(again["sign"].is_null());
    // A head for the same entry is not due again until half of headMaxAge has passed.
    assert!(s.home.head(NOW + 100_000).is_none());
    assert!(s.home.head(NOW + 160_000).is_some());
}

#[test]
fn a_transition_is_receipted_once_then_due_activated_and_recorded() {
    let mut s = setup("public");
    let d = s.f.d.clone();
    let (digest, env) = transition(&mut s, 600, &[d]);
    let r = s.home.pending(&[env.clone()], NOW + 1_000);
    assert_eq!(r["outcome"], "ok", "{r}");
    let receipts = s.home.sign_receipts(&r, NOW + 1_000);
    assert_eq!(receipts.len(), 1);
    // The same transition again: accepted, no second receipt is asked for.
    let again = s.home.pending(&[env], NOW + 2_000);
    assert_eq!(again["outcome"], "ok");
    assert!(again["sign"].as_array().unwrap().is_empty());
    let feed = call(json!({"op": "pending_page", "state": s.home.state, "now": NOW + 2_000, "after": 0, "limit": 64}));
    let kinds: Vec<&str> = feed["objects"].as_array().unwrap().iter().map(|o| o["kind"].as_str().unwrap()).collect();
    assert_eq!(kinds, ["transition", "receipt"]);
    // Not due yet.
    let r = s.home.due(NOW + 60_000);
    assert!(r["store"].as_array().unwrap().is_empty());
    // Due after the delay: the module builds the `activate`; a head over it lets `final` follow.
    let later = NOW + 3_600_000 + 400_000;
    let r = s.home.due(later);
    assert_eq!(r["result"], "ok");
    assert_eq!(r["note"], Value::Null);
    let k = s.home.kinds();
    assert_eq!(k.last().unwrap(), "activate", "{k:?} {r}");
    assert!(s.home.head(later).is_some());
    let r = s.home.due(later + 1_000);
    assert_eq!(r["result"], "ok");
    assert_eq!(s.home.kinds().last().unwrap(), "final", "the head over the activation lets `final` follow");
    let feed = call(json!({"op": "pending_page", "state": s.home.state, "now": later, "after": 0, "limit": 64}));
    assert!(feed["objects"].as_array().unwrap().is_empty(), "recorded: no longer pending");
    let _ = digest;
}


#[test]
fn a_first_upload_may_arrive_in_pieces_and_is_checked_like_any_entry() {
    let keys = HomeKeys::new(0x77);
    let mut f = create_with(&[NS], "public", 1);
    appoint_homes(&mut f, &[(&keys, BASE_A)]);
    let values: Vec<Value> = entries_json(&f).into_iter().map(|(_, e)| e).collect();
    assert_eq!(values.len(), 3, "genesis, rekey, the appointing activate");
    let mut home = Home::new(keys, f.account.id().as_str());
    // The genesis alone: it verifies and is kept, but the home is not appointed in it yet.
    let r = home.authority(1, &values[..1], T0 + 1_000);
    assert_eq!((r["outcome"].as_str(), r["appointed"].as_bool()), (Some("ok"), Some(false)));
    // Re-sent: acknowledged again.
    assert_eq!(home.authority(1, &values[..1], T0 + 1_000)["outcome"], "ok");
    // A gap is a conflict; entries that skip the first are malformed.
    assert_eq!(home.authority(3, &values[2..], T0 + 1_000)["outcome"], "conflict");
    // Too early: more than 60 s ahead of the home's clock.
    let early = home.authority(2, &values[1..2], T0 - 120_000);
    assert_eq!((early["outcome"].as_str(), early["result"].as_str()), (Some("refused"), Some("refused:early")));
    // An entry written long before the home was appointed is not judged by the home's clock
    // (M1: the clock rule applies from the appointment on): a week later, it is held.
    let old = home.authority(2, &values[1..2], T0 + 7 * 24 * HOUR);
    assert_eq!(old["outcome"], "ok", "{old}");
    // The rest: the home is appointed by the last entry.
    let r = home.authority(3, &values[2..], T0 + 7 * 24 * HOUR);
    assert_eq!((r["outcome"].as_str(), r["appointed"].as_bool()), (Some("ok"), Some(true)), "{}", r["result"]);
    // Nothing was stored for the refusals: three files, one per entry.
    let o = call(json!({"op": "objects", "state": home.state}));
    assert_eq!(o["files"].as_array().unwrap().len(), 3);
}

#[test]
fn a_record_is_stored_only_for_a_member_of_the_history_with_a_good_signature_and_path() {
    let s = setup("public");
    let blob = vec![7u8; 100];
    let name = colophon_core::v05::encoding::digest(&blob);
    let ok = call(json!({"op": "check_record", "state": s.home.state, "now": NOW, "path": format!("blobs/{name}"), "bytes": b(&blob)}));
    assert_eq!(ok["allowed"], true);
    let bad = call(json!({"op": "check_record", "state": s.home.state, "now": NOW, "path": format!("blobs/{}", "0".repeat(64)), "bytes": b(&blob)}));
    assert_eq!(bad["allowed"], false);
    // A header from nobody in the history.
    let junk = call(json!({"op": "check_record", "state": s.home.state, "now": NOW,
        "path": format!("ops/{}/{NS}/000000000001-{}.json", "a".repeat(32), "b".repeat(32)), "bytes": b(b"{}")}));
    assert_eq!(junk["allowed"], false);
    // A path outside the store.
    let other = call(json!({"op": "check_record", "state": s.home.state, "now": NOW, "path": "x/y.json", "bytes": b(b"{}")}));
    assert_eq!(other["code"], "malformed");
}

/// H1: a slot provisioned for one account holds nothing of another: a stranger's genesis is
/// refused (`refused:outOfScope`) and the state is unchanged, so the owner's upload goes through.
#[test]
fn a_slot_holds_only_its_own_account_and_a_stranger_cannot_squat_it() {
    let keys = HomeKeys::new(0x77);
    let mut owner = create_with(&[NS], "members", 1);
    appoint_homes(&mut owner, &[(&keys, BASE_A)]);
    let stranger = create_with(&[NS], "public", 1);
    let mut home = Home::new(keys, owner.account.id().as_str());
    let before = home.state.clone();
    let genesis = entries_json(&stranger)[0].1.clone();
    let r = home.authority(1, &[genesis], T0 + 1_000);
    assert_eq!((r["outcome"].as_str(), r["result"].as_str()), (Some("refused"), Some("refused:outOfScope")));
    assert_eq!(home.state, before, "nothing is held");
    assert!(r["store"].as_array().unwrap().is_empty());
    let values: Vec<Value> = entries_json(&owner).into_iter().map(|(_, e)| e).collect();
    let r = home.authority(1, &values, T0 + 1_000);
    assert_eq!((r["outcome"].as_str(), r["appointed"].as_bool()), (Some("ok"), Some(true)), "{r}");
}

/// H3: `receipts` in `POST /authority` holds receipt envelopes only; anything else there is
/// malformed and nothing of the request is admitted.
#[test]
fn an_entry_in_the_receipts_array_is_malformed_and_nothing_is_admitted() {
    let keys = HomeKeys::new(0x77);
    let mut f = create_with(&[NS], "public", 1);
    appoint_homes(&mut f, &[(&keys, BASE_A)]);
    let mut home = Home::new(keys, f.account.id().as_str());
    let values: Vec<Value> = entries_json(&f).into_iter().map(|(_, e)| e).collect();
    let before = home.state.clone();
    let body = json!({"from": 1, "entries": [values[0]], "receipts": [values[2]]}).to_string();
    let r = call(json!({"op": "post_authority", "state": home.state, "now": T0 + 1_000, "body": b(body.as_bytes())}));
    assert_eq!((r["outcome"].as_str(), r["result"].as_str()), (Some("refused"), Some("malformed")));
    assert_eq!(r["state"], json!(before));
    assert!(r["store"].as_array().unwrap().is_empty());
    home.take(&r);
}

/// H4 over the module: the slot state after 1, 40 and 1,000 heads over an unchanged history.
#[test]
fn the_slot_state_does_not_grow_with_heads() {
    let s = setup("public");
    let mut home = s.home;
    let mut sizes = Vec::new();
    for n in 1..=1_000i64 {
        let at = NOW + n * 150_000;
        assert!(home.head(at).is_some(), "head {n} is due");
        if [1, 40, 1_000].contains(&n) {
            sizes.push(home.state.len());
        }
    }
    eprintln!("slot state bytes after 1, 40 and 1,000 heads: {sizes:?}");
    assert!(sizes[2] <= sizes[0] + 256, "{sizes:?}");
}

/// The answer `check_record` gave when it replayed the held history from genesis
/// (`RecordAuthority::from_objects`) rather than reading the home's checkpoint: the same steps in
/// the same order, for the comparison below.
fn check_record_by_replay(state: &str, now: i64, path: &str, bytes: &[u8]) -> Value {
    use colophon_core::v05::engine::paths::{classify, Kind};
    use colophon_core::v05::history::home::HomeState;
    use colophon_core::v05::records::{OperationHeader, RecordAuthority};
    let slot: Value = serde_json::from_slice(&STANDARD.decode(state).unwrap()).unwrap();
    let h = HomeState::from_bytes(&STANDARD.decode(slot["home_state"].as_str().unwrap()).unwrap()).unwrap();
    let refuse = |code: &str| json!({"allowed": false, "code": code, "ok": true});
    if h.is_stopped(now).unwrap() {
        return refuse("unavailable");
    }
    let Some(kind) = classify(path) else { return refuse("malformed") };
    match kind {
        Kind::Blob(name) => {
            if digest(bytes) != name {
                return refuse("malformed");
            }
            json!({"allowed": true, "ok": true})
        }
        Kind::Op { .. } | Kind::Live { .. } | Kind::History => {
            let objects = h.persisted().unwrap().objects().cloned().unwrap_or_default();
            let ra = match RecordAuthority::from_objects(&objects, now) {
                Ok(ra) => ra,
                Err(e) => return json!({"ok": false, "error": e.to_string()}),
            };
            let Ok((header, env)) = OperationHeader::parse(bytes) else { return refuse("malformed") };
            let Some(m) = ra.member(&header.author) else { return refuse("notGranted") };
            if &header.account != ra.account() {
                return refuse("malformed");
            }
            let path_ok = match &kind {
                Kind::Live { author, namespace, slot } => {
                    header.live.as_ref().is_some_and(|s| &s.slot == slot)
                        && &header.author == author
                        && &header.namespace == namespace
                }
                Kind::History => {
                    header.live.is_some()
                        && path
                            == format!(
                                "history/{}/{}/{:012}-{}.json",
                                header.author, header.namespace, header.clock, header.id
                            )
                }
                _ => header.check_path(path).is_ok(),
            };
            if !path_ok {
                return refuse("malformed");
            }
            if OperationHeader::verify(&env, &m.request.signing).is_err() {
                return refuse("badSignature");
            }
            json!({"allowed": true, "ok": true})
        }
        _ => refuse("malformed"),
    }
}

/// `check_record` reads the home's checkpoint once (for the stop and the held entries) and decides
/// who may write by a replay from genesis. Over a home with current members, a member revoked
/// after writing, a member the home has not seen admitted, and a stopped home, at several clock
/// readings, every record (good ones, a swapped signature, a record at another's path, a
/// stranger's, blobs good and bad, paths outside the store) gets exactly the answer the replay
/// gave, with at most the replay besides the checkpoint's verification.
#[test]
fn a_record_check_answers_as_the_replay_from_genesis_did() {
    use colophon_core::v05::history::work;
    let mut f = create_with(&[NS], "members", 1);
    let writer = f.host.identity(41);
    let leaver = f.host.identity(42);
    for (id, label) in [(&writer, "Writer"), (&leaver, "Leaver")] {
        admit(&mut f, id, label, "device", terms_for(&[(NS, "write")]), terms_for(&[(NS, "write")]));
    }
    let keys = HomeKeys::new(0x77);
    appoint_homes(&mut f, &[(&keys, BASE_A)]);
    let mut home = Home::new(keys, f.account.id().as_str());
    let entries: Vec<Value> = entries_json(&f).into_iter().map(|(_, e)| e).collect();
    let uploaded = entries.len() as u64;
    assert_eq!(home.authority(1, &entries, NOW)["appointed"], true);
    assert!(home.head(NOW).is_some());
    // A third member, admitted after the upload: the home has not seen it.
    let late = f.host.identity(43);
    f.account.advance(NOW).unwrap();
    admit(&mut f, &late, "Late", "device", terms_for(&[(NS, "write")]), terms_for(&[(NS, "write")]));

    let src = MemSource::new();
    src.store_account(&f.account);
    let mut host = std::mem::replace(&mut f.host, Host::new());
    let mut records: Vec<(String, Vec<u8>)> = Vec::new();
    for id in [&writer, &leaver, &late] {
        let mut e = member_engine(&f, &host, &src, id, NOW);
        let w = engine_write(&mut e, &mut host, &src, NS, "follow", json!({"id": "show", "url": "https://example.org/feed", "title": "Show"}));
        records.extend(w.stores.into_iter().filter(|(p, _)| p.starts_with("ops/")));
        if id == &writer {
            let l = engine_live(&mut e, &mut host, &src, json!({"id": "e1", "show": "show", "seconds": 1.0}));
            records.extend(l.stores);
        }
    }
    f.host = host;
    assert!(records.iter().any(|(p, _)| p.starts_with("state/")) && records.iter().any(|(p, _)| p.starts_with("history/")));
    // A swapped signature, and a good record presented at another record's path.
    let (op_w, op_l) = (records[0].clone(), records.iter().find(|(p, _)| p.contains(&leaver)).unwrap().clone());
    let mut swapped: Value = serde_json::from_slice(&op_w.1).unwrap();
    let other: Value = serde_json::from_slice(&op_l.1).unwrap();
    swapped["signature"] = other["signature"].clone();
    records.push((op_w.0.clone(), serde_json::to_vec(&swapped).unwrap()));
    records.push((op_l.0.clone(), op_w.1.clone()));
    let blob = vec![9u8; 64];
    records.push((format!("blobs/{}", digest(&blob)), blob.clone()));
    records.push((format!("blobs/{}", "0".repeat(64)), blob));
    records.push(("authority/00000001.json".into(), entries[0].to_string().into_bytes()));
    records.push((format!("ops/{writer}/{NS}/000000000001-{}.json", "a".repeat(32)), b"{}".to_vec()));
    records.push(("x/y.json".into(), b"{}".to_vec()));

    let compare = |home: &Home, now: i64, when: &str| -> Vec<Value> {
        records
            .iter()
            .map(|(path, bytes)| {
                work::reset();
                let out = handle(json!({"op": "check_record", "state": home.state, "now": now,
                                        "path": path, "bytes": b(bytes)}).to_string().as_bytes());
                let verifications = work::get().verifications;
                let got: Value = serde_json::from_slice(&out).unwrap();
                let want = check_record_by_replay(&home.state, now, path, bytes);
                assert_eq!(got, want, "{when}: {path}");
                assert!(verifications <= 2, "{when}: {path}: {verifications} verifications");
                got
            })
            .collect()
    };
    let codes = |answers: &[Value]| -> Vec<String> {
        answers.iter().map(|a| a["code"].as_str().unwrap_or(if a["allowed"] == true { "ok" } else { "error" }).to_string()).collect()
    };
    let before = compare(&home, NOW, "all current");
    let first = codes(&before);
    // The late member's record: notGranted; everyone else's good records are taken.
    assert_eq!(first.iter().filter(|c| *c == "notGranted").count(), 1, "{first:?}");
    assert_eq!(first.iter().filter(|c| *c == "badSignature").count(), 1, "{first:?}");
    for now in [NOW + 1, NOW + HOUR, NOW + 30 * 24 * HOUR] {
        compare(&home, now, "later");
    }

    // The leaver is revoked and the home takes the revocation (and the late admission): the
    // leaver's earlier record still checks (a revoked member's records stay its own), as before.
    f.account.advance(NOW + 1_000).unwrap();
    let revoke = f
        .account
        .begin_revoke(&leaver, &RevokeKeep::Nothing, &[f.d.clone()], [0x7a; 32])
        .unwrap();
    run(&mut f.account, &f.host, revoke);
    let rest: Vec<Value> = entries_json(&f).into_iter().filter(|(s, _)| *s > uploaded).map(|(_, e)| e).collect();
    let r = home.authority(uploaded + 1, &rest, NOW + 2_000);
    assert_eq!(r["outcome"], "ok", "{r}");
    home.head(NOW + 2_000);
    let after = compare(&home, NOW + 2_000, "after the revocation");
    // The late member's admission went up with the revocation: its record is taken now.
    let expected: Vec<String> = first.iter().map(|c| if c == "notGranted" { "ok".into() } else { c.clone() }).collect();
    assert_eq!(codes(&after), expected);
    for now in [NOW + 2_001, NOW + 8 * 24 * HOUR] {
        compare(&home, now, "after, later");
    }
}

/// A stopped home takes no record, from the same verified view.
#[test]
fn a_stopped_home_refuses_every_record_check_as_before() {
    use stopped_support::{activate, final_entry, head, transition, value, DUE};
    let keys = HomeKeys::new(0x77);
    let f = stopped_support::fixture("public", &[(&keys, BASE_A)]);
    let mut home = Home::new(keys, f.account.id().as_str());
    let entries: Vec<_> = entries_json(&f).into_iter().map(|(_, entry)| entry).collect();
    assert_eq!(home.authority(1, &entries, T0)["outcome"], "ok");
    assert!(home.head(NOW).is_some());
    let raise = transition(&f, json!({"layout": 3}), &f.k, NOW);
    let response = home.pending(&[value(&raise)], NOW);
    let receipts = home.sign_receipts(&response, NOW);
    let mut objects = f.account.objects().clone();
    objects.pending.extend([raise.clone(), canonical(&receipts[0]).unwrap()]);
    let activation = activate(&mut objects, &raise, DUE);
    objects.heads.push(head(&home.keys, &objects, DUE));
    let finality = final_entry(&mut objects, entry_seq(&activation), DUE);
    let stopped = home.authority(entry_seq(&activation), &[value(&activation), value(&finality)], DUE);
    assert_eq!(stopped["outcome"], "ok", "{stopped}");
    let blob = vec![1u8; 8];
    for (path, bytes) in [
        (format!("blobs/{}", digest(&blob)), blob.clone()),
        (format!("ops/{}/{NS}/000000000001-{}.json", "a".repeat(32), "b".repeat(32)), b"{}".to_vec()),
        ("x/y.json".to_string(), b"{}".to_vec()),
    ] {
        for now in [DUE, DUE + HOUR] {
            let got = call(json!({"op": "check_record", "state": home.state, "now": now, "path": path, "bytes": b(&bytes)}));
            assert_eq!(got, check_record_by_replay(&home.state, now, &path, &bytes), "{path}");
            assert_eq!(got["code"], "unavailable");
        }
    }
}

/// A call with its signature bytes changed (the body is the same).
fn forge_signature(call: &[u8]) -> Vec<u8> {
    let mut v: Value = serde_json::from_slice(call).unwrap();
    let mut sig = STANDARD.decode(v["signature"].as_str().unwrap()).unwrap();
    let last = sig.len() - 1;
    sig[last] ^= 1;
    v["signature"] = json!(b(&sig));
    serde_json::to_vec(&v).unwrap()
}

/// One authenticated read verifies the home's history once (the call's view of the account is
/// read from the same verdict), and its refusals keep their order: a call that does not parse is
/// `malformed`; a purpose that does not fit the request is `refused:outOfScope` before its
/// signature is looked at; then a bad signature is `badSignature`. The identity and the
/// admission requests read nothing of the slot's state.
#[test]
fn an_authenticated_read_verifies_the_history_once_and_keeps_its_refusal_order() {
    use colophon_core::v05::history::work;
    let mut f = create_with(&[NS], "members", 1);
    let member = f.host.identity(31);
    admit(&mut f, &member, "Reader", "device", terms_for(&[(NS, "read")]), terms_for(&[(NS, "read")]));
    let keys = HomeKeys::new(0x77);
    appoint_homes(&mut f, &[(&keys, BASE_A)]);
    let mut home = Home::new(keys, f.account.id().as_str());
    let entries: Vec<Value> = entries_json(&f).into_iter().map(|(_, e)| e).collect();
    assert_eq!(home.authority(1, &entries, NOW)["appointed"], true);
    assert!(home.head(NOW).is_some());
    let rest = format!("ops/{member}/{NS}/000000000001-{}.json", "a".repeat(32));
    let path = format!("/records/{rest}");
    let signed = |purpose: &str, n: u8| {
        call_as(&f.host, &f.account, "member", &member, BASE_A, purpose,
                home_call_args("GET", &path, &digest(b"")), NOW, [n; 32])
    };
    let ask = |call: &[u8]| {
        json!({"op": "access", "state": home.state, "now": NOW, "base": BASE_A, "method": "GET",
               "section": "records", "rest": rest, "path": path, "bodySha256": digest(b""),
               "call": b(call)})
    };
    work::reset();
    let allowed = call(ask(&signed("colophon.home.read", 1)));
    assert_eq!(work::get().verifications, 1, "one verification of the history");
    assert_eq!(allowed["allowed"], true, "{allowed}");
    assert_eq!(allowed["via"], "call");
    assert_eq!(allowed["signer"], format!("member:{member}"));
    assert_eq!(allowed["kind"], kind_of(&rest), "the record's kind, as classify gives it");
    assert_eq!(allowed["kind"], "op");
    let refused = |call: &[u8]| {
        let r = call_op(ask(call));
        (r["status"].clone(), r["result"].clone())
    };
    assert_eq!(refused(b"{}"), (json!(403), json!("malformed")));
    assert_eq!(refused(&forge_signature(&signed("colophon.home.read", 2))), (json!(403), json!("badSignature")));
    assert_eq!(
        refused(&forge_signature(&signed("colophon.home.write", 3))),
        (json!(403), json!("refused:outOfScope")),
        "the purpose is judged before the signature"
    );
    assert_eq!(refused(&signed("colophon.home.write", 4)), (json!(403), json!("refused:outOfScope")));
    // The replay share (§12.4): the host may send every row of the principal (`signerRows`) or
    // the two numbers it counted by the module's `retained` (`signerLive`, `signerOldest`). Both
    // give the same answer; with the rows the module lists the ones to drop, with the counts the
    // host drops what it found expired wherever the answer has `drop`.
    use colophon_core::v05::replay::{retained, RETENTION_MS};
    let good = signed("colophon.home.read", 5);
    let mut forged = ask(&forge_signature(&good));
    let mut cases = Vec::new();
    for n in [0usize, 3, 63, 64, 70] {
        let rows: Vec<Value> = (0..n)
            .map(|i| {
                let at = match i % 5 {
                    0 => NOW - RETENTION_MS,
                    1 => NOW - RETENTION_MS - 1,
                    2 => NOW + 60_000,
                    3 => NOW - (i as i64) * 1_000,
                    _ => NOW - 2 * RETENTION_MS,
                };
                json!({"key": format!("k{i}"), "at": at})
            })
            .collect();
        cases.push(rows);
    }
    cases.push(vec![json!({"key": "f", "at": 1.5}), json!({"key": "s", "at": "1"}), json!({"key": "m"})]);
    // Over the share: 64 live (one at the boundary, one from a clock that stepped back), 6 not.
    cases.push((0..70).map(|i| json!({"key": format!("o{i}"), "at": match i {
        0 => NOW - RETENTION_MS, 1 => NOW + 5_000, 64.. => NOW - RETENTION_MS - 1 - i, _ => NOW - i * 7_000 }})).collect());
    let mut windows = 0;
    for rows in cases {
        let live: Vec<i64> = rows.iter().filter_map(|r| r["at"].as_i64()).filter(|at| retained(*at, NOW)).collect();
        let expired: Vec<Value> = rows.iter().filter(|r| !r["at"].as_i64().is_some_and(|at| retained(at, NOW))).map(|r| r["key"].clone()).collect();
        for (replay_rows, base) in [(65_536u64, ask(&good)), (1, ask(&good)), (1, forged.clone())] {
            let mut by_rows = base.clone();
            by_rows["replayRows"] = json!(replay_rows);
            by_rows["signerRows"] = json!(rows);
            let mut by_count = base.clone();
            by_count["replayRows"] = json!(replay_rows);
            by_count["signerLive"] = json!(live.len());
            by_count["signerOldest"] = json!(live.iter().min());
            let (mut a, mut c) = (call_op(by_rows), call_op(by_count));
            if a.get("drop").is_some() {
                assert_eq!(a["drop"], json!(expired), "the rows list what is not retained");
                assert_eq!(c["drop"], json!([]), "the counts leave the dropping to the host");
                a["drop"] = json!(null);
                c["drop"] = json!(null);
            } else {
                assert!(c.get("drop").is_none(), "{c}");
            }
            assert_eq!(a, c, "{} rows, table {replay_rows}", rows.len());
            if replay_rows == 1 && live.len() >= 64 && base == ask(&good) {
                assert_eq!(a["status"], 429, "{a}");
                assert_eq!(a["result"], "refused:window");
                windows += 1;
            }
        }
    }
    assert_eq!(windows, 1, "the share was reached once");
    forged["call"] = json!(null);
    assert_eq!(call_op(forged)["status"], 401);

    // Open routes are open over a slot state that loads; a state that does not is an error, as
    // for every other request.
    for (method, section, rest) in [("GET", "", Value::Null), ("POST", "authority", Value::Null),
                                    ("POST", "pending", Value::Null),
                                    ("PUT", "records", json!(format!("heads/{}.json", "b".repeat(32))))] {
        let r = call(json!({"op": "access", "state": home.state, "now": NOW, "method": method,
                            "section": section, "rest": rest}));
        assert_eq!((r["allowed"].clone(), r["via"].clone()), (json!(true), json!("open")), "{method} {section}");
        for state in [json!("not a state"), Value::Null] {
            let r = call_op(json!({"op": "access", "state": state, "now": NOW, "method": method,
                                   "section": section, "rest": rest}));
            assert_eq!(r["ok"], false, "{method} {section}: {r}");
        }
    }
}

/// `call`, without asserting the module answered `ok` (a refusal is still an answer).
fn call_op(req: Value) -> Value {
    named();
    serde_json::from_slice(&handle(req.to_string().as_bytes())).unwrap()
}

/// The kind the module's `classify` gives a path.
fn kind_of(path: &str) -> Value {
    call(json!({"op": "classify", "path": path}))["kind"].clone()
}

/// Writes a per-request benchmark's input to `$COLOPHON_REQUEST_BENCH`: a home slot whose history
/// holds over a hundred entries (members approved and revoked one by one), and the module requests one
/// authenticated record `GET` and one record `PUT` make (`access`, then `check_record`), as the
/// relay sends them. Test keys only: they protect nothing.
#[test]
#[ignore = "writes the per-request benchmark's input; run with COLOPHON_REQUEST_BENCH=<file>"]
fn write_request_bench_input() {
    let Ok(out) = std::env::var("COLOPHON_REQUEST_BENCH") else { return };
    let mut f = create_with(&[NS], "members", 1);
    let writer = f.host.identity(31);
    admit(&mut f, &writer, "Writer", "device", terms_for(&[(NS, "write")]), terms_for(&[(NS, "write")]));
    // 80 devices approved, then 40 of them revoked: 120 entries.
    for i in 0..120u32 {
        let id = f.host.identity(130 + (i % 80) as u8);
        // Spaced out, within the signer's rate.
        let next = f.account.now_ms() + 3 * HOUR;
        f.account.advance(next).unwrap();
        if i >= 80 {
            let revoke = f.account.begin_revoke(&id, &RevokeKeep::Nothing, &[f.d.clone()], [i as u8; 32]).unwrap();
            run(&mut f.account, &f.host, revoke);
        } else {
            admit(&mut f, &id, "Device", "device", terms_for(&[(NS, "read")]), terms_for(&[(NS, "read")]));
        }
    }
    let keys = HomeKeys::new(0x77);
    appoint_homes(&mut f, &[(&keys, BASE_A)]);
    let now = f.account.now_ms() + 1_000;
    let mut home = Home::new(keys, f.account.id().as_str());
    let all = entries_json(&f);
    for chunk in all.chunks(64) {
        let values: Vec<Value> = chunk.iter().map(|(_, e)| e.clone()).collect();
        let r = home.authority(chunk[0].0, &values, now);
        assert_eq!(r["outcome"], "ok", "{r}");
    }
    assert!(home.head(now).is_some());
    let src = MemSource::new();
    src.store_account(&f.account);
    let mut host = std::mem::replace(&mut f.host, Host::new());
    let mut e = member_engine(&f, &host, &src, &writer, now);
    let w = engine_write(&mut e, &mut host, &src, NS, "follow", json!({"id": "show", "url": "https://example.org/feed", "title": "Show"}));
    f.host = host;
    let (rest, bytes) = w.stores.into_iter().find(|(p, _)| p.starts_with("ops/")).unwrap();
    let path = format!("/records/{rest}");
    let signed = |method: &str, body: &[u8], n: u8, purpose: &str| {
        b(&call_as(&f.host, &f.account, "member", &writer, BASE_A, purpose,
                   home_call_args(method, &path, &digest(body)), now, [n; 32]))
    };
    let get = json!({"op": "access", "state": home.state, "now": now, "base": BASE_A, "method": "GET",
                     "section": "records", "rest": rest, "path": path, "bodySha256": digest(b""),
                     "call": signed("GET", b"", 1, "colophon.home.read"), "existing": null, "replayRows": 65_536});
    let put = json!({"op": "access", "state": home.state, "now": now, "base": BASE_A, "method": "PUT",
                     "section": "records", "rest": rest, "path": path, "bodySha256": digest(&bytes),
                     "call": signed("PUT", &bytes, 2, "colophon.home.write"), "existing": null, "replayRows": 65_536});
    assert_eq!(call(get.clone())["allowed"], true);
    assert_eq!(call(put.clone())["allowed"], true);
    let check = json!({"op": "check_record", "state": home.state, "now": now, "path": rest, "bytes": b(&bytes)});
    assert_eq!(call(check.clone())["allowed"], true);
    let entries = call(json!({"op": "status", "state": home.state, "now": now}))["seq"].clone();
    std::fs::write(&out, json!({"entries": entries, "stateBytes": home.state.len(), "get": get, "put": put, "check": check}).to_string()).unwrap();
}

/// `check_record` decides who may write by a replay of the held entries from genesis, never from
/// the folded state a checkpoint carries: a checkpoint is local memory, and one written under
/// other rules (or by an older verifier with the same format number) may fold an entry that
/// these rules refuse. Here the checkpoint's fold names a member whose approval it no longer
/// holds among its entries: the replay does not know the member, so the record is refused.
#[test]
fn a_record_check_does_not_trust_the_fold_a_checkpoint_carries() {
    use colophon_core::v05::history::home::HomeState;
    let mut f = create_with(&[NS], "members", 1);
    let writer = f.host.identity(31);
    admit(&mut f, &writer, "Writer", "device", terms_for(&[(NS, "write")]), terms_for(&[(NS, "write")]));
    let keys = HomeKeys::new(0x77);
    appoint_homes(&mut f, &[(&keys, BASE_A)]);
    let mut home = Home::new(keys, f.account.id().as_str());
    let entries: Vec<(u64, Value)> = entries_json(&f);
    let values: Vec<Value> = entries.iter().map(|(_, e)| e.clone()).collect();
    assert_eq!(home.authority(1, &values, NOW)["appointed"], true);
    let src = MemSource::new();
    src.store_account(&f.account);
    let mut host = std::mem::replace(&mut f.host, Host::new());
    let mut e = member_engine(&f, &host, &src, &writer, NOW);
    let w = engine_write(&mut e, &mut host, &src, NS, "follow", json!({"id": "show", "url": "https://example.org/feed", "title": "Show"}));
    f.host = host;
    let (path, bytes) = w.stores.into_iter().find(|(p, _)| p.starts_with("ops/")).unwrap();
    let check = |state: &str| call(json!({"op": "check_record", "state": state, "now": NOW + 1_000, "path": path, "bytes": b(&bytes)}));
    assert_eq!(check(&home.state)["allowed"], true);
    // The writer's approval (the entry that names it) is dropped from the checkpoint's held
    // entries; the fold, which has the writer, is left as it is.
    let approval = entries
        .iter()
        .find(|(_, e)| String::from_utf8(STANDARD.decode(e["body"].as_str().unwrap()).unwrap()).unwrap().contains(&writer))
        .map(|(_, e)| serde_json::to_vec(e).unwrap())
        .unwrap();
    let mut slot: Value = serde_json::from_slice(&STANDARD.decode(&home.state).unwrap()).unwrap();
    let mut hs: Value = serde_json::from_slice(&STANDARD.decode(slot["home_state"].as_str().unwrap()).unwrap()).unwrap();
    let mut cp: Value = serde_json::from_slice(&STANDARD.decode(hs["checkpoint"].as_str().unwrap()).unwrap()).unwrap();
    let held = cp["objects"]["entries"].as_array_mut().unwrap();
    let before = held.len();
    held.retain(|e| serde_json::from_value::<Vec<u8>>(e.clone()).unwrap() != approval);
    assert_eq!(held.len(), before - 1, "the approval was held");
    hs["checkpoint"] = json!(b(&serde_json::to_vec(&cp).unwrap()));
    slot["home_state"] = json!(b(&serde_json::to_vec(&hs).unwrap()));
    let doctored = b(&serde_json::to_vec(&slot).unwrap());
    let h = HomeState::from_bytes(&STANDARD.decode(slot["home_state"].as_str().unwrap()).unwrap()).unwrap();
    let fold = h.verified_history(NOW + 1_000).unwrap().1;
    assert!(fold.state.unwrap().members().iter().any(|m| m.request.member_id() == writer), "the fold still names the writer");
    let r = call_op(json!({"op": "check_record", "state": doctored, "now": NOW + 1_000, "path": path, "bytes": b(&bytes)}));
    assert_eq!(r, check_record_by_replay(&doctored, NOW + 1_000, &path, &bytes), "the replay's answer");
    assert_ne!(r["allowed"], true, "{r}");
}

// ---------------------------------------------------------------------------------------------
// The slot's proof of its fold (`fold`): a home state whose checkpoint this build folded from
// genesis carries `{"rules": FOLD_RULES, "build": the module's SHA-256, "checkpoint": SHA-256 of
// the checkpoint}`, and with it
// the module answers from the fold where that is the replay's answer.

fn slot_of(state: &str) -> Value {
    serde_json::from_slice(&STANDARD.decode(state).unwrap()).unwrap()
}
fn state_of(slot: &Value) -> String {
    b(&serde_json::to_vec(slot).unwrap())
}
/// The state without its proof.
fn unproved(state: &str) -> String {
    let mut slot = slot_of(state);
    slot.as_object_mut().unwrap().remove("fold");
    state_of(&slot)
}
/// The state with `fold` set to `mark` (`null` removes it).
fn with_fold(state: &str, mark: Value) -> String {
    let mut slot = slot_of(state);
    slot.as_object_mut().unwrap().remove("fold");
    if !mark.is_null() {
        slot["fold"] = mark;
    }
    state_of(&slot)
}
/// The checkpoint bytes of a slot state.
fn checkpoint_of(state: &str) -> Vec<u8> {
    let slot = slot_of(state);
    let hs: Value = serde_json::from_slice(&STANDARD.decode(slot["home_state"].as_str().unwrap()).unwrap()).unwrap();
    STANDARD.decode(hs["checkpoint"].as_str().unwrap()).unwrap()
}
/// The state with its checkpoint replaced by `checkpoint` and no proof.
fn with_checkpoint(state: &str, checkpoint: &[u8]) -> String {
    let mut slot = slot_of(state);
    let mut hs: Value = serde_json::from_slice(&STANDARD.decode(slot["home_state"].as_str().unwrap()).unwrap()).unwrap();
    hs["checkpoint"] = json!(b(checkpoint));
    slot["home_state"] = json!(b(&serde_json::to_vec(&hs).unwrap()));
    slot.as_object_mut().unwrap().remove("fold");
    state_of(&slot)
}
/// The module's raw answer.
fn raw(req: &Value) -> Vec<u8> {
    named();
    handle(req.to_string().as_bytes())
}
/// `req` over `state`, and over `state` without its proof: the same bytes, returned with the
/// number of history replays (verifications that parsed the held objects) the proved state's
/// answer took.
fn same_as_unproved(req: &Value, when: &str) -> (Value, usize) {
    use colophon_core::v05::history::work;
    let state = req["state"].as_str().unwrap();
    let mut cold = req.clone();
    cold["state"] = json!(unproved(state));
    work::reset();
    let warm = raw(req);
    let verifications = work::get().replays;
    let want = raw(&cold);
    assert_eq!(String::from_utf8_lossy(&warm), String::from_utf8_lossy(&want), "{when}");
    (serde_json::from_slice(&warm).unwrap(), verifications)
}

/// A home state is written with the proof of its fold whenever this build folded its checkpoint,
/// and the proof names this build's rules and the checkpoint's exact bytes.
fn assert_proved(state: &str) {
    use colophon_core::v05::history::FOLD_RULES;
    let mark = &slot_of(state)["fold"];
    assert_eq!(mark["rules"], FOLD_RULES, "{mark}");
    assert_eq!(mark["build"], TEST_BUILD, "{mark}");
    assert_eq!(mark["checkpoint"], digest(&checkpoint_of(state)), "{mark}");
}

/// With the proof of its fold, a home answers every record check and every call exactly as it
/// does without it (by the replay from genesis), byte for byte: over a home with current members,
/// a member revoked after writing and a member the home has not seen admitted, before and after
/// the revocation, at clock readings behind, at and after the checkpoint's; good records, a
/// swapped signature, a record at another's path, a stranger's, blobs and paths outside the store;
/// reads and writes by call. Where the history is quiet the record check is answered from the
/// fold: one verification of the history instead of two.
#[test]
fn a_proved_fold_answers_record_checks_and_calls_as_the_replay() {
    let mut f = create_with(&[NS], "members", 1);
    let writer = f.host.identity(41);
    let leaver = f.host.identity(42);
    for (id, label) in [(&writer, "Writer"), (&leaver, "Leaver")] {
        admit(&mut f, id, label, "device", terms_for(&[(NS, "write")]), terms_for(&[(NS, "write")]));
    }
    let keys = HomeKeys::new(0x77);
    appoint_homes(&mut f, &[(&keys, BASE_A)]);
    let mut home = Home::new(keys, f.account.id().as_str());
    let entries: Vec<Value> = entries_json(&f).into_iter().map(|(_, e)| e).collect();
    let uploaded = entries.len() as u64;
    assert_eq!(home.authority(1, &entries, NOW)["appointed"], true);
    assert_proved(&home.state);
    assert!(home.head(NOW).is_some());
    assert_proved(&home.state);
    let late = f.host.identity(43);
    f.account.advance(NOW).unwrap();
    admit(&mut f, &late, "Late", "device", terms_for(&[(NS, "write")]), terms_for(&[(NS, "write")]));
    let src = MemSource::new();
    src.store_account(&f.account);
    let mut host = std::mem::replace(&mut f.host, Host::new());
    let mut records: Vec<(String, Vec<u8>)> = Vec::new();
    for id in [&writer, &leaver, &late] {
        let mut e = member_engine(&f, &host, &src, id, NOW);
        let w = engine_write(&mut e, &mut host, &src, NS, "follow", json!({"id": "show", "url": "https://example.org/feed", "title": "Show"}));
        records.extend(w.stores.into_iter().filter(|(p, _)| p.starts_with("ops/")));
        if id == &writer {
            let l = engine_live(&mut e, &mut host, &src, json!({"id": "e1", "show": "show", "seconds": 1.0}));
            records.extend(l.stores);
        }
    }
    f.host = host;
    let (op_w, op_l) = (records[0].clone(), records.iter().find(|(p, _)| p.contains(&leaver)).unwrap().clone());
    let mut swapped: Value = serde_json::from_slice(&op_w.1).unwrap();
    swapped["signature"] = serde_json::from_slice::<Value>(&op_l.1).unwrap()["signature"].clone();
    records.push((op_w.0.clone(), serde_json::to_vec(&swapped).unwrap()));
    records.push((op_l.0.clone(), op_w.1.clone()));
    let blob = vec![9u8; 64];
    records.push((format!("blobs/{}", digest(&blob)), blob.clone()));
    records.push((format!("blobs/{}", "0".repeat(64)), blob));
    records.push((format!("ops/{writer}/{NS}/000000000001-{}.json", "a".repeat(32)), b"{}".to_vec()));
    records.push(("x/y.json".into(), b"{}".to_vec()));
    // Calls: the writer's read and write of its record, the late member's write of its own.
    let calls: Vec<(String, &str, String, Vec<u8>)> = [(&writer, &op_w), (&late, records.iter().find(|(p, _)| p.contains(&late)).unwrap())]
        .into_iter()
        .enumerate()
        .flat_map(|(i, (who, (rest, bytes)))| {
            let path = format!("/records/{rest}");
            let get = call_as(&f.host, &f.account, "member", who, BASE_A, "colophon.home.read",
                              home_call_args("GET", &path, &digest(b"")), NOW, [i as u8 * 2 + 1; 32]);
            let put = call_as(&f.host, &f.account, "member", who, BASE_A, "colophon.home.write",
                              home_call_args("PUT", &path, &digest(bytes)), NOW, [i as u8 * 2 + 2; 32]);
            [(rest.clone(), "GET", digest(b""), get), (rest.clone(), "PUT", digest(bytes), put)]
        })
        .collect();

    let mut from_fold = 0;
    let mut answers = Vec::new();
    let mut compare = |home: &Home, at: i64, when: &str| {
        for now in [at - 1_000, at, at + 1, at + HOUR, at + 30 * 24 * HOUR] {
            for (path, bytes) in &records {
                let req = json!({"op": "check_record", "state": home.state, "now": now, "path": path, "bytes": b(bytes)});
                let (answer, verifications) = same_as_unproved(&req, &format!("{when} at {now}: {path}"));
                assert_eq!(answer, check_record_by_replay(&home.state, now, path, bytes), "{when} at {now}: {path}");
                // A signed record taken without a replay.
                if verifications == 0 && answer["allowed"] == true && !path.starts_with("blobs/") {
                    from_fold += 1;
                }
            }
            for (rest, method, sha, call) in &calls {
                let path = format!("/records/{rest}");
                let req = json!({"op": "access", "state": home.state, "now": now, "base": BASE_A, "method": method,
                                 "section": "records", "rest": rest, "path": path,
                                 "bodySha256": sha, "call": b(call), "existing": null, "replayRows": 65_536});
                let (answer, _) = same_as_unproved(&req, &format!("{when} at {now}: {method} {rest}"));
                let want = call_by_replay(&home.state, now, method, &path, sha, call);
                assert_eq!(access_answer(&answer), want, "{when} at {now}: {method} {rest}: {answer}");
                answers.push(((when.to_string(), now - at, rest.contains(writer.as_str()), method.to_string()), want));
            }
        }
    };
    compare(&home, NOW, "all current");
    f.account.advance(NOW + 1_000).unwrap();
    let revoke = f.account.begin_revoke(&leaver, &RevokeKeep::Nothing, &[f.d.clone()], [0x7a; 32]).unwrap();
    run(&mut f.account, &f.host, revoke);
    let rest: Vec<Value> = entries_json(&f).into_iter().filter(|(s, _)| *s > uploaded).map(|(_, e)| e).collect();
    assert_eq!(home.authority(uploaded + 1, &rest, NOW + 2_000)["outcome"], "ok");
    assert_proved(&home.state);
    home.head(NOW + 2_000);
    assert_proved(&home.state);
    compare(&home, NOW + 2_000, "after the revocation");
    // Good records at the checkpoint's clock and after: answered from the fold, without a replay;
    // behind the checkpoint's clock, by the replay.
    let ok = |home: &Home, now: i64| {
        let req = json!({"op": "check_record", "state": home.state, "now": now, "path": op_w.0, "bytes": b(&op_w.1)});
        same_as_unproved(&req, "the writer's record")
    };
    let taken = json!({"allowed": true, "ok": true});
    assert_eq!(ok(&home, NOW + 2_000), (taken.clone(), 0));
    assert_eq!(ok(&home, NOW + HOUR), (taken.clone(), 0));
    let (behind, replays) = ok(&home, NOW + 2_000 - 1);
    assert_eq!(behind, taken);
    assert!(replays > 0, "behind the checkpoint's clock it replays");
    assert!(from_fold > 0);
    // The calls name the account's head, which includes the late member's admission: before it
    // went up the home does not hold that seq and every call is unavailable; after, at the
    // checkpoint's clock, the replay takes the writer's and the late member's reads and writes.
    for ((when, offset, by_writer, method), want) in &answers {
        if *offset != 0 {
            continue;
        }
        let who = if *by_writer { "writer" } else { "late member" };
        if when == "all current" {
            assert_eq!(want, &Err("unavailable".to_string()), "{when}: the {who}'s {method}");
        } else {
            assert_eq!(want, &Ok(()), "{when}: the {who}'s {method}");
        }
    }
}

/// The conformance vectors' history files of one kind of case, as a home holds them.
fn vector_objects(dir: &std::path::Path) -> Objects {
    let files = |d: std::path::PathBuf| -> Vec<Vec<u8>> {
        let mut v: Vec<std::path::PathBuf> = std::fs::read_dir(d)
            .map(|r| r.map(|e| e.unwrap().path()).collect())
            .unwrap_or_default();
        v.sort();
        v.into_iter().filter(|p| p.extension().is_some_and(|x| x == "json")).map(|p| std::fs::read(p).unwrap()).collect()
    };
    if dir.join("successor").exists() {
        let mut o = Objects {
            entries: files(dir.join("successor/authority")),
            predecessor: files(dir.join("predecessor/authority")),
            ..Default::default()
        };
        for (name, list) in [("genesis-receipt.json", &mut o.pending), ("successor-head.json", &mut o.heads)] {
            if dir.join(name).exists() {
                list.push(std::fs::read(dir.join(name)).unwrap());
            }
        }
        return o;
    }
    let mut o = Objects { entries: files(dir.join("records/authority")), ..Default::default() };
    let mut subs: Vec<_> = std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().path()).collect();
    subs.sort();
    for p in subs {
        if p.file_name().unwrap().to_string_lossy().starts_with("branch-") {
            o.entries.extend(files(p.join("authority")));
        }
    }
    let mut held: Vec<_> = std::fs::read_dir(dir.join("objects")).map(|r| r.map(|e| e.unwrap().path()).collect()).unwrap_or_default();
    held.sort();
    for p in held {
        let n = p.file_name().unwrap().to_string_lossy().to_string();
        if n.starts_with("head") {
            o.heads.push(std::fs::read(&p).unwrap());
        } else if n != "call.json" {
            o.pending.push(std::fs::read(&p).unwrap());
        }
    }
    o
}
fn vectors_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance/0.5")
}

/// A home whose checkpoint holds each kind of history this build folds (ordinary, forked, held,
/// failed, stopped, upgraded in place from `/4`, a successor, a suspended key's refused suspend),
/// checkpointed at several clock readings: verified again when the home starts (`resume`), it is
/// stored with the proof, and with it every record check and call is answered as without it, byte
/// for byte, at clock readings behind, at and long after the checkpoint's.
#[test]
fn a_proved_fold_of_any_history_answers_as_the_replay() {
    use colophon_core::v05::encoding::parse_date;
    const DAY: i64 = 24 * HOUR;
    let mut f = create_with(&[NS], "members", 1);
    let writer = f.host.identity(41);
    admit(&mut f, &writer, "Writer", "device", terms_for(&[(NS, "write")]), terms_for(&[(NS, "write")]));
    let keys = HomeKeys::new(0x77);
    appoint_homes(&mut f, &[(&keys, BASE_A)]);
    let mut home = Home::new(keys, f.account.id().as_str());
    let entries: Vec<Value> = entries_json(&f).into_iter().map(|(_, e)| e).collect();
    assert_eq!(home.authority(1, &entries, NOW)["appointed"], true);
    let src = MemSource::new();
    src.store_account(&f.account);
    let mut host = std::mem::replace(&mut f.host, Host::new());
    let mut e = member_engine(&f, &host, &src, &writer, NOW);
    let w = engine_write(&mut e, &mut host, &src, NS, "follow", json!({"id": "show", "url": "https://example.org/feed", "title": "Show"}));
    f.host = host;
    let (rest, bytes) = w.stores.into_iter().find(|(p, _)| p.starts_with("ops/")).unwrap();
    let path = format!("/records/{rest}");
    let get = call_as(&f.host, &f.account, "member", &writer, BASE_A, "colophon.home.read",
                      home_call_args("GET", &path, &digest(b"")), NOW, [5; 32]);
    let blob = vec![3u8; 16];
    let records = [(rest.clone(), bytes.clone()), (format!("blobs/{}", digest(&blob)), blob)];

    // History vectors of every kind, at the clock each case is judged at. (Every vector's record
    // view is compared with the replay's in the core, `a_vouched_record_view_is_the_replays`.)
    const PICKED: &[&str] = &[
        "rules/f2-suspended-key-suspends", "rules/call-suspension-expired", "rules/t-resolve-second-fork",
        "rules/t-activate-early", "rules/t-conflict-no-evidence", "rules/f3-layout-2", "rules/f3-layout-3",
        "rules/f3-raise-provisional", "rules/f3-raise-vetoed", "upgrade/accept", "upgrade/then-v4-entry",
        "succession/authority5-successor", "succession/authority5-successor-provisional",
        "succession/swift-migration", "succession/swift-keyring",
    ];
    let mut cases: Vec<(String, std::path::PathBuf, i64)> = Vec::new();
    for (top, default) in [("rules", "2026-11-20T00:00:00Z"), ("upgrade", "2026-12-01T00:00:00Z"), ("succession", "2026-11-14T10:15:00Z")] {
        let mut dirs: Vec<_> = std::fs::read_dir(vectors_dir().join(top)).unwrap().map(|e| e.unwrap().path())
            .filter(|d| d.join("case.json").exists() && (top != "rules" || d.join("records/authority").exists()))
            .collect();
        dirs.sort();
        for d in dirs {
            let case: Value = serde_json::from_slice(&std::fs::read(d.join("case.json")).unwrap()).unwrap();
            let now = case["verifier"]["now"].as_str().or(case["expected"]["now"].as_str()).unwrap_or(default);
            cases.push((format!("{top}/{}", d.file_name().unwrap().to_string_lossy()), d, parse_date(now).unwrap()));
        }
    }
    cases.push(("account".into(), vectors_dir().join("account"), parse_date("2026-11-11T09:01:00Z").unwrap()));
    cases.retain(|(name, _, _)| name == "account" || PICKED.contains(&name.as_str()));
    assert_eq!(cases.len(), PICKED.len() + 1);
    let mut kinds = std::collections::BTreeMap::<&str, usize>::new();
    let mut proved = 0;
    for (name, dir, now) in &cases {
        let objects = vector_objects(dir);
        let cold = verify_history(&objects, &Persisted::default(), *now);
        let kind = match &cold.stop {
            _ if name.starts_with("succession") => "successor",
            _ if name.starts_with("upgrade") && cold.state.as_ref().is_some_and(|s| s.upgrade_seq.is_some()) => "upgraded",
            _ if name.contains("suspended-key") => "suspended-key",
            None => "ok",
            Some(colophon_core::v05::history::Stop::Held { .. }) => "held",
            Some(colophon_core::v05::history::Stop::Fork { .. }) => "fork",
            Some(_) if cold.stopped.is_some() => "stopped",
            Some(_) => "failed",
        };
        let from_fold = kinds.entry(kind).or_default();
        for at in [*now - 60_000, *now + 7 * DAY] {
            let cp = Persisted::checkpoint(&objects, &Persisted::default(), at).to_bytes().unwrap();
            let injected = with_checkpoint(&home.state, &cp);
            let started = call(json!({"op": "resume", "state": injected, "now": at}));
            let state = started["state"].as_str().unwrap().to_string();
            if started["changed"] == true {
                assert_eq!(started["fold"], "verified");
                assert_proved(&state);
                proved += 1;
                // Started again, the proof holds.
                assert_eq!(call(json!({"op": "resume", "state": state, "now": at}))["fold"], "proved");
            }
            for now in [at - 1, at, at + 30 * DAY] {
                for (p, bytes) in &records {
                    let req = json!({"op": "check_record", "state": state, "now": now, "path": p, "bytes": b(bytes)});
                    let (answer, replays) = same_as_unproved(&req, &format!("{name} checkpointed at {at}, at {now}: {p}"));
                    assert_eq!(answer, check_record_by_replay(&state, now, p, bytes), "{name} checkpointed at {at}, at {now}: {p}");
                    if replays == 0 && !p.starts_with("blobs/") {
                        *from_fold += 1;
                    }
                }
                let req = json!({"op": "access", "state": state, "now": now, "base": BASE_A, "method": "GET",
                                 "section": "records", "rest": rest, "path": path, "bodySha256": digest(b""),
                                 "call": b(&get), "existing": null, "replayRows": 65_536});
                let (answer, _) = same_as_unproved(&req, &format!("{name} checkpointed at {at}, at {now}: GET"));
                assert_eq!(access_answer(&answer), call_by_replay(&state, now, "GET", &path, &digest(b""), &get),
                           "{name} checkpointed at {at}, at {now}: GET {answer}");
                let req = json!({"op": "status", "state": state, "now": now});
                same_as_unproved(&req, &format!("{name} checkpointed at {at}, at {now}: status"));
            }
        }
    }
    for k in ["ok", "held", "fork", "failed", "stopped", "upgraded", "successor", "suspended-key"] {
        assert!(kinds.contains_key(k), "no {k} history: {kinds:?}");
    }
    // The record checks answered from the fold, per kind: ordinary histories are; a fork, a
    // failed or stopped history, an upgraded account, a successor and the suspended key's refused
    // suspend never are.
    assert!(kinds["ok"] > 0, "{kinds:?}");
    for k in ["fork", "failed", "stopped", "upgraded", "successor", "suspended-key"] {
        assert_eq!(kinds[k], 0, "{k}: {kinds:?}");
    }
    assert_eq!(proved, cases.len() * 2, "every checkpoint this build folded is verified again");
}

/// A proof is taken only when it names this build's rules and exactly the checkpoint held. Here
/// the checkpoint's fold has lost a member its held entries approve (as a fold under other rules,
/// or an inconsistent copy, may): the replay takes the member's record, the fold would not. With
/// the proof the state was written with (over the checkpoint before it changed), a proof naming
/// other rules, a proof lost by a reader that does not know the field, a truncated or malformed
/// one, the record is taken as the replay takes it, and starting the home does not prove the
/// fold (the replay differs). Only a proof naming this build's rules and these exact bytes, which
/// only this build writes, would take the fold: local state is trusted as a whole.
#[test]
fn a_proof_for_other_bytes_or_rules_is_not_taken() {
    use colophon_core::v05::history::FOLD_RULES;
    let mut f = create_with(&[NS], "members", 1);
    let writer = f.host.identity(31);
    admit(&mut f, &writer, "Writer", "device", terms_for(&[(NS, "write")]), terms_for(&[(NS, "write")]));
    let keys = HomeKeys::new(0x77);
    appoint_homes(&mut f, &[(&keys, BASE_A)]);
    let mut home = Home::new(keys, f.account.id().as_str());
    let entries: Vec<(u64, Value)> = entries_json(&f);
    let values: Vec<Value> = entries.iter().map(|(_, e)| e.clone()).collect();
    assert_eq!(home.authority(1, &values, NOW)["appointed"], true);
    assert_proved(&home.state);
    let src = MemSource::new();
    src.store_account(&f.account);
    let mut host = std::mem::replace(&mut f.host, Host::new());
    let mut e = member_engine(&f, &host, &src, &writer, NOW);
    let w = engine_write(&mut e, &mut host, &src, NS, "follow", json!({"id": "show", "url": "https://example.org/feed", "title": "Show"}));
    f.host = host;
    let (path, bytes) = w.stores.into_iter().find(|(p, _)| p.starts_with("ops/")).unwrap();
    let now = NOW + 1_000;
    let check = |state: &str| call_op(json!({"op": "check_record", "state": state, "now": now, "path": path, "bytes": b(&bytes)}));
    assert_eq!(check(&home.state)["allowed"], true);
    // The fold forgets the writer; its held entries, and so the replay, still approve it.
    let mut cp: Value = serde_json::from_slice(&checkpoint_of(&home.state)).unwrap();
    let fold = verify_history(&Objects::default(), &Persisted::from_bytes(&checkpoint_of(&home.state)).unwrap(), now).state.unwrap();
    let at = fold.members().iter().position(|m| m.request.member_id() == writer).unwrap();
    cp["state"]["members"].as_array_mut().unwrap().remove(at);
    let doctored_cp = serde_json::to_vec(&cp).unwrap();
    let doctored = with_checkpoint(&home.state, &doctored_cp);
    let replayed = check_record_by_replay(&doctored, now, &path, &bytes);
    assert_eq!(replayed["allowed"], true, "the replay takes the record: {replayed}");
    let original = slot_of(&home.state)["fold"].clone();
    let here = digest(&doctored_cp);
    // A reader that does not know the field: it reads the state and writes it without it.
    #[derive(serde::Serialize, serde::Deserialize)]
    struct OlderSlot {
        v: u32,
        home: String,
        account: String,
        booting: Vec<String>,
        #[serde(default)]
        booting_predecessor: Vec<String>,
        home_state: Option<String>,
    }
    let proved_here = with_fold(&doctored, json!({"rules": FOLD_RULES, "build": TEST_BUILD, "checkpoint": here}));
    let older: OlderSlot = serde_json::from_slice(&STANDARD.decode(&proved_here).unwrap()).unwrap();
    let round_tripped = b(&serde_json::to_vec(&older).unwrap());
    assert!(slot_of(&round_tripped).get("fold").is_none(), "an older reader drops what it does not know");
    for (what, state) in [
        ("no proof", with_fold(&doctored, Value::Null)),
        ("the proof of the checkpoint before", with_fold(&doctored, original.clone())),
        ("other rules", with_fold(&doctored, json!({"rules": "colophon-0.5-fold/r0/0000000000000000", "build": TEST_BUILD, "checkpoint": here}))),
        ("other rules, same name", with_fold(&doctored, json!({"rules": format!("{FOLD_RULES}x"), "build": TEST_BUILD, "checkpoint": here}))),
        ("through an older reader", round_tripped.clone()),
        ("a truncated digest", with_fold(&doctored, json!({"rules": FOLD_RULES, "build": TEST_BUILD, "checkpoint": &here[..63]}))),
        ("an upper-case digest", with_fold(&doctored, json!({"rules": FOLD_RULES, "build": TEST_BUILD, "checkpoint": here.to_uppercase()}))),
        ("no digest", with_fold(&doctored, json!({"rules": FOLD_RULES, "build": TEST_BUILD}))),
        ("another build", with_fold(&doctored, json!({"rules": FOLD_RULES, "build": "0".repeat(64), "checkpoint": here}))),
        ("no build", with_fold(&doctored, json!({"rules": FOLD_RULES, "checkpoint": here}))),
        ("no rules", with_fold(&doctored, json!({"build": TEST_BUILD, "checkpoint": here}))),
        ("a number", with_fold(&doctored, json!(7))),
        ("a string", with_fold(&doctored, json!(format!("{FOLD_RULES} {here}")))),
        ("a list", with_fold(&doctored, json!([FOLD_RULES, here]))),
        ("rules of another type", with_fold(&doctored, json!({"rules": 1, "build": TEST_BUILD, "checkpoint": here}))),
    ] {
        assert_eq!(check(&state), replayed, "{what}");
        let started = call(json!({"op": "resume", "state": state, "now": now}));
        assert_eq!(started["changed"], false, "{what}: the replay differs, so nothing is proved");
        assert_eq!(started["fold"], "unproved", "{what}: a start says so");
    }
    // An instance is named one build, once.
    assert_eq!(call_op(json!({"op": "build", "fingerprint": TEST_BUILD}))["ok"], true);
    assert_eq!(call_op(json!({"op": "build", "fingerprint": "0".repeat(64)}))["ok"], false);
    assert_eq!(call_op(json!({"op": "build", "fingerprint": "not hex"}))["ok"], false);
    // This build's own proof for these exact bytes is taken (the state is trusted as a whole):
    // the fold answers, and refuses the writer. So the cases above were answered by the replay.
    assert_eq!(check(&proved_here)["code"], "notGranted");
}

/// An older verifier with the same checkpoint format, under other rules, accepted the suspend that
/// a suspended key signed (`f2-suspended-key-suspends`, seq 3); these rules refuse it
/// (`badSignature`). A home holding that older fold, with no proof or a proof of other rules,
/// answers as the replay does (here, an error for every record check), and starting it does not
/// prove the fold.
#[test]
fn a_fold_under_other_rules_is_refused_as_the_replay_refuses_it() {
    use colophon_core::v05::encoding::parse_date;
    use colophon_core::v05::history::FOLD_RULES;
    let mut f = create_with(&[NS], "members", 1);
    let keys = HomeKeys::new(0x77);
    appoint_homes(&mut f, &[(&keys, BASE_A)]);
    let mut home = Home::new(keys, f.account.id().as_str());
    let values: Vec<Value> = entries_json(&f).into_iter().map(|(_, e)| e).collect();
    assert_eq!(home.authority(1, &values, NOW)["appointed"], true);
    let objects = vector_objects(&vectors_dir().join("rules/f2-suspended-key-suspends"));
    let now = parse_date("2026-11-20T00:00:00Z").unwrap();
    let older = older_rules_fold(&objects, now);
    let state = with_checkpoint(&home.state, &older);
    let path = format!("ops/{}/{NS}/000000000001-{}.json", "a".repeat(32), "b".repeat(32));
    let refused = check_record_by_replay(&state, now, &path, b"{}");
    assert_eq!(refused["ok"], false, "the replay fails at seq 3: {refused}");
    assert!(refused["error"].as_str().unwrap().starts_with("badSignature"), "{refused}");
    for (what, state) in [
        ("no proof", state.clone()),
        ("other rules", with_fold(&state, json!({"rules": "colophon-0.5-fold/r0/0000000000000000", "build": TEST_BUILD, "checkpoint": digest(&older)}))),
    ] {
        for t in [now, now + HOUR] {
            let got = call_op(json!({"op": "check_record", "state": state, "now": t, "path": path, "bytes": b(b"{}")}));
            assert_eq!(got, check_record_by_replay(&state, t, &path, b"{}"), "{what}");
            assert_eq!(got["ok"], false, "{what}: {got}");
        }
        assert_eq!(call(json!({"op": "resume", "state": state, "now": now}))["changed"], false, "{what}");
    }
    // Under this build's proof the older fold would be taken: the record check would reach the
    // record. That is the answer the cases above did not give.
    let forged = with_fold(&state, json!({"rules": FOLD_RULES, "build": TEST_BUILD, "checkpoint": digest(&older)}));
    let taken = call_op(json!({"op": "check_record", "state": forged, "now": now, "path": path, "bytes": b(b"{}")}));
    assert_eq!(taken, json!({"allowed": false, "code": "malformed", "ok": true}), "the record itself is judged");
}

/// The checkpoint an older verifier would write for `objects` if it accepted their third entry:
/// this build's fold through seq 2, with seq 3 appended to the state as accepted. Bytes, as a
/// home stores them.
fn older_rules_fold(objects: &Objects, now: i64) -> Vec<u8> {
    use colophon_core::v05::encoding::parse_date;
    let two = Objects { entries: objects.entries[..2].to_vec(), ..objects.clone() };
    let p = Persisted::checkpoint(&two, &Persisted::default(), now);
    let mut cp: Value = serde_json::from_slice(&p.to_bytes().unwrap()).unwrap();
    let third = &objects.entries[2];
    let env: Value = serde_json::from_slice(third).unwrap();
    let body = STANDARD.decode(env["body"].as_str().unwrap()).unwrap();
    let issued = parse_date(serde_json::from_slice::<Value>(&body).unwrap()["issued"].as_str().unwrap()).unwrap();
    let st = &mut cp["state"];
    st["digests"].as_array_mut().unwrap().push(json!(digest(&body)));
    st["issued"].as_array_mut().unwrap().push(json!(issued));
    for k in ["keyring_at", "delay_at", "rule_at"] {
        let a = st[k].as_array_mut().unwrap();
        let last = a.last().unwrap().clone();
        a.push(last);
    }
    cp["objects"]["entries"].as_array_mut().unwrap().push(serde_json::to_value(third).unwrap());
    cp["high_water"] = json!([3, digest(&body)]);
    let bytes = serde_json::to_vec(&cp).unwrap();
    let back = Persisted::from_bytes(&bytes).unwrap();
    assert_eq!(verify_history(&Objects::default(), &back, now).branch.len(), 3, "the older fold took seq 3");
    bytes
}


/// The answer a replay of the held objects from genesis gives a call at a home, with no saved
/// fold (only the home's permanent stop floor, which no replay can recompute): `Ok(())` for a call
/// the home takes, the refusal's code otherwise. The reference for `access`, independent of it.
fn call_by_replay(state: &str, now: i64, method: &str, path: &str, body_sha: &str, call: &[u8]) -> Result<(), String> {
    use colophon_core::v05::calls::verify_home_request;
    use colophon_core::v05::history::home::HomeState;
    use colophon_core::v05::replay::MemoryReplayStore;
    let slot = slot_of(state);
    let h = HomeState::from_bytes(&STANDARD.decode(slot["home_state"].as_str().unwrap()).unwrap()).unwrap();
    let p = h.persisted().unwrap();
    let objects = p.objects().cloned().unwrap_or_default();
    let mut memory = Persisted::default();
    if let Some((seq, layout)) = p.stop_floor() {
        memory = memory.with_stop_floor(seq, layout);
    }
    let verdict = verify_history(&objects, &memory, now);
    // As the home reads its view: a stop answers unavailable, a failed or held history is an error,
    // a fork leaves the verified prefix.
    if verdict.is_stopped() || p.stop_floor().is_some() {
        return Err("unavailable".into());
    }
    match &verdict.stop {
        None | Some(colophon_core::v05::history::Stop::Fork { .. }) => {}
        Some(_) => return Err(format!("history: {}", verdict.code())),
    }
    if verdict.state.is_none() {
        return Err("no verified history".into());
    }
    let view = AccountView::from_history_verifier(&verdict, &objects, now).map_err(|e| e.to_string())?;
    let audiences = [BASE_A.to_string()];
    let origins = std::collections::BTreeMap::new();
    let cfg = CallConfig { now_ms: now, audiences: &audiences, call_origins: &origins, controller_purposes: &[], home_endpoints: &audiences };
    let writes = colophon_core::v05::calls::home_record_writes(path.trim_start_matches("/records/")).unwrap_or_default();
    let writes = if method == "PUT" { writes } else { Vec::new() };
    let request = HomeRequest { method, path, body_sha256: body_sha, writes: &writes };
    verify_home_request(call, &view, &cfg, &mut MemoryReplayStore::new(), &request).map(|_| ()).map_err(|f| f.code())
}
/// `access`'s answer as `call_by_replay` gives it.
fn access_answer(r: &Value) -> Result<(), String> {
    if r["allowed"] == true {
        Ok(())
    } else if r["ok"] == false {
        Err(r["error"].as_str().unwrap_or_default().to_string())
    } else {
        Err(r["result"].as_str().map(str::to_string).unwrap_or_else(|| r.to_string()))
    }
}

/// A call is judged by the history the home holds, never by a saved fold it has not proved. Here
/// the checkpoint's held entries revoke a member, and a fresh head of the home covers the
/// revocation, but the fold it carries still has the member current (as a fold under other rules,
/// or an inconsistent copy, may). A replay from genesis refuses the member's read; so must the
/// home, with no proof, with the proof of the honest checkpoint, and after a start that could not
/// prove the fold. The other member's read is taken while the head is fresh, and the honest state
/// answers the same; an hour later (the head no longer fresh) every answer is still the replay's.
#[test]
fn a_call_is_judged_by_the_replay_when_the_fold_is_not_proved() {
    let mut f = create_with(&[NS], "members", 1);
    let reader = f.host.identity(41);
    let leaver = f.host.identity(42);
    for (id, label) in [(&reader, "Reader"), (&leaver, "Leaver")] {
        admit(&mut f, id, label, "device", terms_for(&[(NS, "read")]), terms_for(&[(NS, "read")]));
    }
    let keys = HomeKeys::new(0x77);
    appoint_homes(&mut f, &[(&keys, BASE_A)]);
    let mut home = Home::new(keys, f.account.id().as_str());
    let entries: Vec<Value> = entries_json(&f).into_iter().map(|(_, e)| e).collect();
    let uploaded = entries.len() as u64;
    assert_eq!(home.authority(1, &entries, NOW)["appointed"], true);
    assert!(home.head(NOW).is_some());
    f.account.advance(NOW + 1_000).unwrap();
    let revoke = f.account.begin_revoke(&leaver, &RevokeKeep::Nothing, &[f.d.clone()], [0x7b; 32]).unwrap();
    run(&mut f.account, &f.host, revoke);
    let rest: Vec<Value> = entries_json(&f).into_iter().filter(|(s, _)| *s > uploaded).map(|(_, e)| e).collect();
    let at = NOW + 2_000;
    assert_eq!(home.authority(uploaded + 1, &rest, at)["outcome"], "ok");
    assert!(home.head(at).is_some(), "a fresh head over the revocation");
    let honest = home.state.clone();
    assert_proved(&honest);

    // The fold forgets the revocation; the held entries and the head are the honest ones.
    let mut cp: Value = serde_json::from_slice(&checkpoint_of(&honest)).unwrap();
    let fold = verify_history(&Objects::default(), &Persisted::from_bytes(&checkpoint_of(&honest)).unwrap(), at).state.unwrap();
    let i = fold.members().iter().position(|m| m.request.member_id() == leaver).unwrap();
    assert!(fold.members()[i].revoked_seq.is_some());
    cp["state"]["members"][i]["revoked_seq"] = Value::Null;
    let doctored = with_checkpoint(&honest, &serde_json::to_vec(&cp).unwrap());
    let started = call(json!({"op": "resume", "state": doctored, "now": at}));
    assert_eq!(started["changed"], false, "the replay is not the fold: nothing is proved");

    let rest_of = |id: &str| format!("ops/{id}/{NS}/000000000001-{}.json", "a".repeat(32));
    let ask = |state: &str, id: &str, n: u8, now: i64| {
        let rest = rest_of(id);
        let path = format!("/records/{rest}");
        let c = call_as(&f.host, &f.account, "member", id, BASE_A, "colophon.home.read",
                        home_call_args("GET", &path, &digest(b"")), now, [n; 32]);
        let req = json!({"op": "access", "state": state, "now": now, "base": BASE_A, "method": "GET",
                         "section": "records", "rest": rest, "path": path, "bodySha256": digest(b""),
                         "call": b(&c), "existing": null, "replayRows": 65_536});
        (call_op(req), call_by_replay(state, now, "GET", &path, &digest(b""), &c))
    };
    let mut n = 0u8;
    for now in [at, at + 1_000, at + HOUR] {
        for (what, state) in [
            ("honest", honest.clone()),
            ("no proof", doctored.clone()),
            ("the honest checkpoint's proof", with_fold(&doctored, slot_of(&honest)["fold"].clone())),
            ("after a start", started["state"].as_str().unwrap().to_string()),
        ] {
            n += 1;
            let fresh = now < at + HOUR;
            let (got, want) = ask(&state, &leaver, n, now);
            if fresh {
                assert_eq!(want, Err("refused:revoked".to_string()), "{what} at {now}: the replay refuses the revoked member");
            }
            assert_eq!(access_answer(&got), want, "{what} at {now}: {got}");
            n += 1;
            let (got, want) = ask(&state, &reader, n, now);
            if fresh {
                assert_eq!(want, Ok(()), "{what} at {now}: the replay takes the current member");
            }
            assert_eq!(access_answer(&got), want, "{what} at {now}: {got}");
        }
    }
}
