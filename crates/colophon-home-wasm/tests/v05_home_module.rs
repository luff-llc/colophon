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
fn call(req: Value) -> Value {
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
        assert_eq!(*decision, json!({"path": path, "status": 200}));
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
        assert_eq!(ok["records"], json!([{"path": live, "status": 200}]));
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

/// `check_record` reads who may write from the home's verified view (its checkpoint) and no
/// longer replays the history from genesis on every record. Over a home with current members, a
/// member revoked after writing, a member the home has not seen admitted, and a stopped home, at
/// several clock readings, every record (good ones, a swapped signature, a record at another's
/// path, a stranger's, blobs good and bad, paths outside the store) gets exactly the answer the
/// replay gave, and the check runs one verification of the history, not a replay besides it.
#[test]
fn a_record_check_reads_the_home_view_and_answers_as_the_replay_from_genesis_did() {
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
                assert!(verifications <= 1, "{when}: {path}: {verifications} verifications");
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

    // Open routes: allowed whatever the state holds, and nothing of it is decoded.
    for (method, section, rest) in [("GET", "", Value::Null), ("POST", "authority", Value::Null),
                                    ("POST", "pending", Value::Null),
                                    ("PUT", "records", json!(format!("heads/{}.json", "b".repeat(32))))] {
        let r = call(json!({"op": "access", "state": "not a state", "now": NOW, "method": method,
                            "section": section, "rest": rest}));
        assert_eq!((r["allowed"].clone(), r["via"].clone()), (json!(true), json!("open")), "{method} {section}");
    }
}

/// `call`, without asserting the module answered `ok` (a refusal is still an answer).
fn call_op(req: Value) -> Value {
    serde_json::from_slice(&handle(req.to_string().as_bytes())).unwrap()
}
