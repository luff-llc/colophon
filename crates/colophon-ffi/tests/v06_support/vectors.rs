//! The 0.6 session conformance vectors replayed through the exported surface only, as a Swift,
//! Kotlin or JS host replays them: `SessionMachine` for the machine transcripts
//! (`conformance/0.6-sessions/*.json`), `session_clock_sample` for `offset.json`, and
//! `SessionWireReceiver`, `SessionAccountView::supplied`, `SessionEpochs::with_keys` and
//! `SessionEndpoint` for the wire file (`conformance/0.6-sessions/wire/vectors.json`).
//!
//! Shared with the wasm crate's test, which includes it with that crate's exports in scope. The
//! including file supplies `new_endpoint`, the one call whose argument type differs between the
//! two builds (the view is an `Arc` natively, a reference on the web), and `ViewHandle`, the type
//! `SessionAccountView::supplied` returns.
//!
//! Not replayed here, because they are not part of the binding surface: the wire file's
//! intermediate values (frame key, HKDF info, nonce, AAD, signed body, ciphertext and
//! signature), which a host never computes itself; `offset.json`'s `bestOfLast8` sequence, which
//! the machine applies internally; and `bridge.json`, the §S9 carrier layer, which is not part of
//! 0.6 conformance.
#![allow(dead_code, clippy::unwrap_used)]
use super::*;
use colophon_core::v05::encoding::decode_base64;
use serde_json::Value;
use std::path::PathBuf;

pub fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/0.6-sessions")
}
fn read(path: PathBuf) -> Value {
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
}
fn unhex(t: &str) -> Vec<u8> {
    (0..t.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&t[i..i + 2], 16).unwrap())
        .collect()
}
fn st(v: &Value) -> String {
    v.as_str().unwrap().to_owned()
}
fn json_of(text: &str) -> Value {
    serde_json::from_str(text).unwrap()
}

/// Every machine transcript: one `SessionMachine` per member, each step's outputs compared in
/// order, restarts rebuilt from `persisted_json`, then each member's view and digest. Returns
/// how many files were replayed.
pub fn replay_machine_vectors() -> usize {
    let mut names: Vec<PathBuf> = std::fs::read_dir(dir())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    names.sort();
    let mut replayed = 0;
    for path in names {
        let v = read(path.clone());
        if v["format"] != "colophon/session-vectors/6" {
            continue;
        }
        let name = st(&v["name"]);
        let policy = v["policy"].to_string();
        let fixes = v["fixes"].to_string();
        let mut machines = std::collections::BTreeMap::new();
        let mut can_write = std::collections::BTreeMap::new();
        for m in v["members"].as_array().unwrap() {
            let id = st(&m["id"]);
            let w = m["canWrite"].as_bool().unwrap();
            let persisted = (!m["persisted"].is_null()).then(|| m["persisted"].to_string());
            let seed = m["freshSeed"].as_str().map(unhex);
            let machine = SessionMachine::new(
                id.clone(),
                w,
                policy.clone(),
                persisted,
                Some(fixes.clone()),
                seed,
            )
            .unwrap();
            machines.insert(id.clone(), machine);
            can_write.insert(id, w);
        }
        for (k, step) in v["steps"].as_array().unwrap().iter().enumerate() {
            let member = st(&step["member"]);
            if step.get("restart").is_some() {
                let p = machines[&member].persisted_json().unwrap();
                let fresh = SessionMachine::new(
                    member.clone(),
                    can_write[&member],
                    policy.clone(),
                    p,
                    Some(fixes.clone()),
                    None,
                )
                .unwrap();
                machines.insert(member, fresh);
                continue;
            }
            let at = step["at"].as_u64().unwrap();
            let got = machines[&member]
                .handle(step["input"].to_string(), at)
                .unwrap_or_else(|e| panic!("{name}: step {k}: {}", e.code()));
            assert_eq!(
                json_of(&got),
                step["outputs"],
                "{name}: step {k} ({member} at {at})"
            );
        }
        for f in v["final"].as_array().unwrap() {
            let m = st(&f["member"]);
            assert_eq!(
                machines[&m].digest().unwrap(),
                st(&f["digest"]),
                "{name}: digest of {m}"
            );
            assert_eq!(
                json_of(&machines[&m].view_json().unwrap()),
                f["view"],
                "{name}: view of {m}"
            );
        }
        replayed += 1;
    }
    replayed
}

/// `offset.json`'s single-sample cases. Returns how many.
pub fn replay_offset_cases() -> usize {
    let v = read(dir().join("offset.json"));
    let cases = v["cases"].as_array().unwrap();
    for c in cases {
        let g = |k: &str| c[k].as_u64().unwrap();
        let s = session_clock_sample(g("now"), g("t"), g("echo"), g("hold"));
        assert_eq!(
            (s.rtt, s.offset, s.error),
            (g("rtt"), c["offset"].as_i64().unwrap(), g("error")),
            "{c}"
        );
    }
    cases.len()
}

fn member_entries(members: &Value, ns: &str) -> Vec<SessionMemberEntry> {
    members
        .as_array()
        .unwrap()
        .iter()
        .map(|m| SessionMemberEntry {
            signing: decode_base64(m["signing"].as_str().unwrap(), 1024).unwrap(),
            session: m["session"].as_u64().unwrap(),
            expires_ms: None,
            records: vec![SessionRecordEntry {
                namespace: ns.to_owned(),
                access: if m["access"] == "write" {
                    SessionAccess::Write
                } else {
                    SessionAccess::Read
                },
            }],
        })
        .collect()
}

/// The keys a receiver holds and each one's highest `n`: what a drop must leave unchanged.
fn held(rx: &SessionWireReceiver) -> Vec<(String, String, Option<u64>)> {
    rx.keys()
        .unwrap()
        .into_iter()
        .map(|k| {
            let high = rx.window_high(k.member.clone(), k.key.clone()).unwrap();
            (k.member, k.key, high)
        })
        .collect()
}

/// The wire file. Returns (frames, scenario steps, negative cases) checked.
pub fn replay_wire_vectors<E>(
    new_endpoint: impl Fn(&ViewHandle, &Value, String, String) -> E,
) -> (usize, usize, usize)
where
    E: std::borrow::Borrow<SessionEndpoint>,
{
    let v = read(dir().join("wire/vectors.json"));
    let account = st(&v["account"]);
    let ns = st(&v["namespace"]);
    let cell = st(&v["cell"]);
    let clock = v["clockMs"].as_i64().unwrap();
    let max = v["maxPayload"].as_u64().unwrap();
    let me = st(&v["receiver"]);
    let epochs = || {
        let keys = v["epochs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| SessionEpochKey {
                epoch: e["epoch"].as_u64().unwrap(),
                key: unhex(e["key"].as_str().unwrap()),
            })
            .collect();
        SessionEpochs::with_keys(ns.clone(), keys).unwrap()
    };
    let table = epochs();
    assert_eq!(table.current_epoch(), Some(1));
    let view =
        SessionAccountView::supplied(account.clone(), member_entries(&v["members"], &ns)).unwrap();

    // The session key and its delegation, through an endpoint made from the same randomness:
    // the key ID, and the exact delegation body the member signs, then installed.
    let sk = &v["sessionKey"];
    let made = new_endpoint(&view, &v, st(&sk["member"]), st(&sk["privateKey"]));
    let ep: &SessionEndpoint = std::borrow::Borrow::borrow(&made);
    assert_eq!(ep.key_id().unwrap(), st(&sk["id"]));
    let body = ep.begin_delegation(clock, clock + 86_400_000).unwrap();
    assert_eq!(
        body,
        st(&v["delegation"]["body"]).into_bytes(),
        "the delegation body"
    );
    let sig = decode_base64(v["delegation"]["signature"].as_str().unwrap(), 1024).unwrap();
    let c = || SessionClock {
        mono_ms: 0,
        wall_ms: clock,
    };
    ep.finish_delegation(body.clone(), sig.clone(), c())
        .unwrap();
    let mut forged = sig.clone();
    forged[5] ^= 1;
    let e = ep.finish_delegation(body, forged, c()).err().unwrap();
    assert_eq!(e.code(), "session:delegation");

    // Positive frames, in order, through one receiver.
    let rx = SessionWireReceiver::new(account.clone(), ns.clone(), cell.clone(), me.clone());
    let frames = v["frames"].as_array().unwrap();
    for f in frames {
        let name = st(&f["name"]);
        let r = rx
            .open(st(&f["frame"]).into_bytes(), &view, &table, clock, max)
            .unwrap();
        let o = r
            .opened
            .unwrap_or_else(|| panic!("{name}: dropped {}", r.dropped.unwrap().reason));
        assert_eq!(o.plaintext, st(&f["plaintext"]).into_bytes(), "{name}");
        assert_eq!(o.writer, f["writer"].as_bool().unwrap(), "{name}");
        assert_eq!(o.n, f["n"].as_u64().unwrap(), "{name}");
        assert_eq!(o.to, f["to"].as_str().map(str::to_owned), "{name}");
        assert_eq!(o.epoch, 1);
    }

    // Scenarios, each against a fresh receiver.
    let views = &v["views"];
    let mut steps = 0;
    for sc in v["scenarios"].as_array().unwrap() {
        let name = st(&sc["name"]);
        let who = sc.get("receiver").map_or(me.clone(), st);
        let rx = SessionWireReceiver::new(account.clone(), ns.clone(), cell.clone(), who);
        let mut view =
            SessionAccountView::supplied(account.clone(), member_entries(&views["default"], &ns))
                .unwrap();
        for (k, step) in sc["steps"].as_array().unwrap().iter().enumerate() {
            steps += 1;
            let ex = &step["expect"];
            let what = format!("{name} step {k}");
            if let Some(vn) = step.get("setView") {
                view = SessionAccountView::supplied(
                    account.clone(),
                    member_entries(&views[vn.as_str().unwrap()], &ns),
                )
                .unwrap();
                let gone = rx.set_account(&view, clock).unwrap();
                let members: Vec<String> = ex["forgottenMembers"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(st)
                    .collect();
                let keys: Vec<(String, String)> = ex["closedKeys"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|p| (st(&p[0]), st(&p[1])))
                    .collect();
                let got: Vec<(String, String)> =
                    gone.keys.into_iter().map(|k| (k.member, k.key)).collect();
                assert_eq!(gone.members, members, "{what}");
                assert_eq!(got, keys, "{what}");
                continue;
            }
            let at = step.get("clockMs").and_then(Value::as_i64).unwrap_or(clock);
            let before = held(&rx);
            let r = rx
                .open(st(&step["open"]).into_bytes(), &view, &table, at, max)
                .unwrap();
            match (r.opened, r.dropped, ex["drop"].as_str()) {
                (Some(o), None, None) => {
                    if let Some(w) = ex.get("writer") {
                        assert_eq!(o.writer, w.as_bool().unwrap(), "{what}");
                    }
                }
                (None, Some(d), Some(code)) => {
                    assert_eq!(d.reason, code, "{what}");
                    assert_eq!(held(&rx), before, "{what}: a drop changed state");
                    if let Some(h) = ex.get("helloTo") {
                        assert_eq!(d.hello_to.as_deref(), h.as_str(), "{what}");
                    }
                }
                (o, d, want) => panic!(
                    "{what}: opened {}, dropped {:?}, want drop {want:?}",
                    o.is_some(),
                    d.map(|d| d.reason)
                ),
            }
        }
    }

    // Negative frames, each against a fresh receiver.
    let negative = v["negative"].as_array().unwrap();
    for n in negative {
        let name = st(&n["name"]);
        let rx = SessionWireReceiver::new(account.clone(), ns.clone(), cell.clone(), me.clone());
        let at = n.get("clockMs").and_then(Value::as_i64).unwrap_or(clock);
        let maxp = n.get("maxPayload").and_then(Value::as_u64).unwrap_or(max);
        for a in n["accept"].as_array().unwrap() {
            let r = rx
                .open(st(a).into_bytes(), &view, &table, clock, max)
                .unwrap();
            assert!(r.opened.is_some(), "{name}: an accepted frame");
        }
        let before = held(&rx);
        let r = rx
            .open(st(&n["frame"]).into_bytes(), &view, &table, at, maxp)
            .unwrap();
        match n["drop"].as_str() {
            Some(code) => {
                let d = r.dropped.unwrap_or_else(|| panic!("{name}: opened"));
                assert!(r.opened.is_none());
                assert_eq!(d.reason, code, "{name}");
                assert_eq!(held(&rx), before, "{name}: a drop changed state");
            }
            None => assert!(r.opened.is_some() && r.dropped.is_none(), "{name}"),
        }
    }
    (frames.len(), steps, negative.len())
}

/// Strict decoding at the boundary: unknown variants, unknown fields, wrong lengths and
/// malformed persisted claims are typed errors, never defaults.
pub fn strict_inputs_fail_closed() {
    let policy = session_default_policy().unwrap();
    let m = SessionMachine::new("a".into(), true, policy.clone(), None, None, None).unwrap();
    for bad in [
        r#"{"input":"wave"}"#,
        r#"{"input":"tick","extra":1}"#,
        r#"{"input":"app","command":{"command":"jump"}}"#,
        r#"{"input":"app","command":{"command":"join"}}"#,
        "not json",
    ] {
        let e = m.handle(bad.into(), 0).err().unwrap();
        assert_eq!(e.code(), "malformed", "{bad}");
    }
    let mut p: Value = json_of(&policy);
    p["surprise"] = Value::Bool(true);
    let e = SessionMachine::new("a".into(), true, p.to_string(), None, None, None)
        .err()
        .unwrap();
    assert_eq!(e.code(), "malformed");
    let e = SessionMachine::new(
        "a".into(),
        true,
        policy.clone(),
        Some(r#"{"claim":{"term":0,"rank":0,"holder":"a"},"released":false}"#.into()),
        None,
        None,
    )
    .err()
    .unwrap();
    assert_eq!(
        e.code(),
        "malformed",
        "a claim of term 0 is not well formed"
    );
    let e = SessionMachine::new(
        "a".into(),
        true,
        policy.clone(),
        None,
        None,
        Some(vec![0; 15]),
    )
    .err()
    .unwrap();
    assert_eq!(e.code(), "bound");
    let e = SessionEpochs::with_keys(
        "listening.podcasts".into(),
        vec![SessionEpochKey {
            epoch: 1,
            key: vec![1; 31],
        }],
    )
    .err()
    .unwrap();
    assert_eq!(e.code(), "bound");
    let mut tight: Value = json_of(&policy);
    tight["holderTimeoutMs"] = tight["beatMs"].clone();
    let e = session_validate_policy(
        tight.to_string(),
        "c".repeat(64),
        "listening.podcasts".into(),
        "now-playing".into(),
    )
    .err()
    .unwrap();
    assert_eq!(e.code(), "session:policy");
    let largest = session_validate_policy(
        policy,
        "c".repeat(64),
        "listening.podcasts".into(),
        "now-playing".into(),
    )
    .unwrap();
    assert!(largest > 0 && largest <= 16_384);
}
