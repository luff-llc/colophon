//! H4: the stopped-home table over HTTP against the real relay and wasm module.
//! Protocol time is exclusively the relay test clock. Polling only waits for I/O completion.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::cloned_ref_to_slice_refs,
    clippy::too_many_arguments
)]
#[path = "../../colophon-core/tests/v05_stopped_support/mod.rs"]
mod stopped_support;
#[path = "../../colophon-core/tests/v05_engine_support/mod.rs"]
mod support;
mod support_relay;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use colophon_core::v05::account::Incoming;
use colophon_core::v05::encoding::{canonical, digest};
use colophon_core::v05::history::Objects;
use colophon_core::v05::write::format_date;
use serde_json::{json, Value};
use stopped_support::*;
use support::{b64, Fixture, T0};
use support_relay::*;

struct World {
    relay: Relay,
    keys: HomeKeys,
    f: Fixture,
    member: String,
    scratch: Scratch,
}
fn world(name: &str, history: &str) -> Option<World> {
    prerequisites()?;
    let keys = HomeKeys::new(0x77);
    let mut f = fixture(history, &[(&keys, BASE_A)]);
    let member = f.host.identity(30);
    support::admit(
        &mut f,
        &member,
        "Synthetic app",
        "app",
        support::terms("write"),
        support::terms("write"),
    );
    let scratch = Scratch::new(name);
    let relay = Relay::start(
        &keys,
        f.account.id().as_str(),
        BASE_A,
        scratch.path(),
        T0,
        &[],
    );
    first_upload(&relay, &f, T0);
    relay.set_clock(NOW);
    let (s, head) = relay.get("/head");
    assert_eq!(s, 200);
    f.account
        .merge(
            Incoming {
                objects: Objects {
                    heads: vec![head],
                    ..Default::default()
                },
                records: vec![],
            },
            NOW,
        )
        .unwrap();
    Some(World {
        relay,
        keys,
        f,
        member,
        scratch,
    })
}
fn json_get(relay: &Relay, path: &str) -> (u16, Value) {
    let (s, b) = relay.get(path);
    (s, serde_json::from_slice(&b).unwrap_or(Value::Null))
}
fn auth(call: &[u8]) -> Vec<(String, String)> {
    vec![(
        "Authorization".into(),
        format!("Colophon {}", URL_SAFE_NO_PAD.encode(call)),
    )]
}
fn own_call(w: &World, method: &str, path: &str, bytes: &[u8]) -> Vec<u8> {
    home_call(
        &w.f.host,
        &w.f.account,
        BASE_A,
        method,
        path,
        bytes,
        NOW,
        fresh_request_id(),
    )
}
fn post_object(relay: &Relay, object: &[u8]) -> (u16, Value) {
    relay.post("/pending", &json!({"objects":[value(object)]}))
}
fn stop(w: &World, target: Option<&[u8]>) -> (Vec<u8>, Vec<u8>, u64) {
    let raise = transition(&w.f, json!({"layout":3}), &w.f.k, NOW);
    let (s, r) = post_object(&w.relay, &raise);
    assert_eq!(s, 200, "{r}");
    assert_eq!(r["receipts"].as_array().unwrap().len(), 1);
    let mut objects = w.f.account.objects().clone();
    objects
        .pending
        .extend([raise.clone(), canonical(&r["receipts"][0]).unwrap()]);
    if let Some(target) = target {
        w.relay.set_clock(DUE - 100_000);
        let (s, r) = post_object(&w.relay, target);
        assert_eq!(s, 200, "{r}");
        objects
            .pending
            .extend([target.to_vec(), canonical(&r["receipts"][0]).unwrap()]);
    }
    let activation = activate(&mut objects, &raise, DUE);
    objects.heads.push(head(&w.keys, &objects, DUE));
    let finality = final_entry(&mut objects, support::entry_seq(&activation), DUE);
    let n = support::entry_seq(&finality);
    w.relay.set_clock(DUE);
    let (s, r) = w.relay.post(
        "/authority",
        &json!({"from":n-1, "entries":[value(&activation), value(&finality)], "receipts":[]}),
    );
    assert_eq!(
        s, 200,
        "the entry that makes the raise final is stored: {r}"
    );
    assert!(r["head"].is_null(), "no head is signed at N");
    (raise, finality, n)
}
fn assert_head_unavailable(relay: &Relay, home: &str) {
    for path in ["/head".into(), format!("/records/heads/{home}.json")] {
        let (s, headers, _) = http(relay.port, "GET", &relay.url(&path), &[], &[]);
        assert_eq!(s, 503, "{path}");
        assert!(headers
            .iter()
            .any(|(k, v)| k == "retry-after" && !v.is_empty()));
    }
}
fn disk(w: &World, path: &str) -> Vec<u8> {
    std::fs::read(
        w.scratch
            .path()
            .join("data/home/records")
            .join(path.trim_start_matches("/records/")),
    )
    .unwrap()
}
fn assert_unavailable(
    relay: &Relay,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    bytes: &[u8],
) {
    let (s, _, b) = http(relay.port, method, &relay.url(path), headers, bytes);
    assert_eq!(
        (s, serde_json::from_slice::<Value>(&b).unwrap()),
        (503, json!({"result":"unavailable"})),
        "{method} {path}"
    );
}

#[test]
fn normal_and_stopped_base_advertise_layout_2() {
    let Some(w) = world("h4-base-layouts", "public") else {
        return;
    };
    let (status, base) = json_get(&w.relay, "");
    assert_eq!(status, 200);
    assert_eq!(base["layouts"], json!([2]));
    stop(&w, None);
    let (status, base) = json_get(&w.relay, "");
    assert_eq!(status, 200);
    assert_eq!(base["layouts"], json!([2]));
}

// Snapshot every byte, including the log and tmp files Slot.open would otherwise repair.
fn storage_snapshot(root: &std::path::Path) -> std::collections::BTreeMap<std::path::PathBuf, Vec<u8>> {
    fn walk(
        root: &std::path::Path,
        dir: &std::path::Path,
        files: &mut std::collections::BTreeMap<std::path::PathBuf, Vec<u8>>,
    ) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                walk(root, &entry.path(), files);
            } else {
                files.insert(
                    entry.path().strip_prefix(root).unwrap().to_path_buf(),
                    std::fs::read(entry.path()).unwrap(),
                );
            }
        }
    }
    let mut files = std::collections::BTreeMap::new();
    walk(root, root, &mut files);
    files
}

#[test]
fn missing_or_corrupt_checkpoint_cannot_unstop() {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};
    let Some((server, wasm)) = prerequisites() else {
        return;
    };
    for stopped in [false, true] {
        let mut w = world(
            if stopped { "h4-lost-stopped" } else { "h4-lost-appointed" },
            "public",
        ).unwrap();
        if stopped {
            stop(&w, None);
        }
        w.relay.stop();
        let data = w.scratch.path().join("data");
        let checkpoint = data.join("home/home-state.json");
        let backup = std::fs::read(&checkpoint).unwrap();
        std::fs::write(data.join("home/tmp/keep-me"), b"untouched").unwrap();
        for damaged in [
            None, Some(""), Some("{"), Some("{}"), Some("null"), Some("\"not a state\""),
        ] {
            match damaged {
                None => std::fs::remove_file(&checkpoint).unwrap(),
                Some(bytes) => std::fs::write(&checkpoint, bytes).unwrap(),
            }
            let before = storage_snapshot(&data);
            let mut child = Command::new("bun")
                .arg(&server)
                .arg("--test-clock")
                .env("COLOPHON_RELAY_PORT", "0")
                .env("COLOPHON_RELAY_DATA", &data)
                .env(
                    "COLOPHON_RELAY_HOME_SLOTS",
                    format!("home={}@{BASE_A}", w.f.account.id().as_str()),
                )
                .env("COLOPHON_HOME_KEY", w.keys.jwk())
                .env("COLOPHON_HOME_WASM", &wasm)
                .env("COLOPHON_RELAY_CLOCK_FILE", w.scratch.path().join("clock"))
                .env("COLOPHON_RELAY_TICK_MS", "0")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let mut line = String::new();
            BufReader::new(child.stdout.take().unwrap())
                .read_line(&mut line)
                .unwrap();
            // A regression must fail promptly, even if it starts listening. No upload can reach
            // a correctly refused slot because the relay exits before opening its listener.
            if !line.is_empty() {
                child.kill().unwrap();
            }
            let output = child.wait_with_output().unwrap();
            assert!(line.is_empty(), "stopped={stopped}, damaged={damaged:?}: served {line}");
            assert!(!output.status.success(), "a bad checkpoint must fail startup");
            let error = String::from_utf8_lossy(&output.stderr);
            assert!(
                error.contains("Home slot home") && error.contains("home-state.json"),
                "{error}"
            );
            assert_eq!(storage_snapshot(&data), before, "failed open must write nothing");
            std::fs::write(&checkpoint, &backup).unwrap();
        }
        // Restoring the intact checkpoint reopens the original home, including its stop.
        w.relay = w.relay.restart(&w.keys, NOW, &[]);
        assert_eq!(json_get(&w.relay, "").0, 200);
        if stopped {
            assert_head_unavailable(&w.relay, &w.keys.id);
        } else {
            assert_eq!(w.relay.get("/head").0, 200);
        }
    }
}

#[test]
fn stopped_public_home_keeps_every_store_kind_and_serves_only_call_free_reads_after_restart() {
    let Some(mut w) = world("h4-public", "public") else {
        return;
    };
    let member = w.member.clone();
    let mut held = vec![(
        format!("/records/blobs/{}", digest(b"synthetic blob")),
        b"synthetic blob".to_vec(),
    )];
    // Opaque encrypted values with genuine member signatures; a home never decrypts these.
    for live in [false, true] {
        let id = if live { "b".repeat(32) } else { "a".repeat(32) };
        let mut header = json!({"protocol":"colophon/operation/5", "account":w.f.account.id().as_str(),
            "namespace":NS, "author":member, "epoch":1, "id":id, "clock":1,
            "authority":w.f.account.status().seq, "created":format_date(NOW), "level":"write", "previous":null,
            "nonce":b64(&[0;12]), "ciphertext":b64(&[0;16])});
        let path = if live {
            header["live"] = json!({"account":w.f.account.id().as_str(), "slot":"position", "generation":1, "operationID":id});
            format!("/records/state/{member}/{NS}/position.json")
        } else {
            format!("/records/ops/{member}/{NS}/000000000001-{id}.json")
        };
        let body = canonical(&header).unwrap();
        let env = canonical(
            &json!({"body":b64(&body), "signature":b64(&w.f.host.ids[&member].sign(&body))}),
        )
        .unwrap();
        held.push((path, env));
    }
    for (path, bytes) in &held {
        let mut headers = auth(&own_call(&w, "PUT", path, bytes));
        headers.push(("If-None-Match".into(), "*".into()));
        let (s, _, b) = http(w.relay.port, "PUT", &w.relay.url(path), &headers, bytes);
        assert!(
            (200..300).contains(&s),
            "store {path}: {s} {}",
            String::from_utf8_lossy(&b)
        );
    }
    let target = transition(
        &w.f,
        json!({"policy":{"callWindow":600}}),
        &w.f.d,
        DUE - 100_000,
    );
    let (raise, finality, n) = stop(&w, Some(&target));
    assert_eq!(json_get(&w.relay, "").0, 200);
    let (s, page) = json_get(&w.relay, "/authority?after=0&limit=64");
    assert_eq!(s, 200);
    assert_eq!(page["entries"].as_array().unwrap().len(), n as usize);
    assert_eq!(
        page["entries"].as_array().unwrap().last().unwrap(),
        &value(&finality)
    );
    for path in [
        format!("/records/authority/{n:08}.json"),
        format!("/records/transitions/{}.json", object_digest(&raise)),
        format!(
            "/records/receipts/{}/{}.receipt.json",
            object_digest(&target),
            w.keys.id
        ),
        format!("/pending/{}", object_digest(&target)),
        "/pending".into(),
    ] {
        assert_eq!(w.relay.get(&path).0, 200, "{path}");
    }
    let replay_before = std::fs::read(w.scratch.path().join("data/home/replay.log")).unwrap();
    let log_before = std::fs::read(w.scratch.path().join("data/home/log.jsonl")).unwrap();
    let old_head = disk(&w, &format!("/records/heads/{}.json", w.keys.id));
    for (path, bytes) in &held {
        assert_eq!(disk(&w, path), *bytes);
        assert_unavailable(&w.relay, "GET", path, &[], &[]);
        assert_unavailable(
            &w.relay,
            "GET",
            path,
            &auth(&own_call(&w, "GET", path, b"")),
            &[],
        );
        let mut headers = auth(&own_call(&w, "PUT", path, bytes));
        headers.push(("If-None-Match".into(), "*".into()));
        assert_unavailable(&w.relay, "PUT", path, &headers, bytes);
    }
    assert_unavailable(&w.relay, "GET", "/changes", &[], &[]);
    assert_head_unavailable(&w.relay, &w.keys.id);
    // Each head read runs the scheduler. Even far beyond every due time it records nothing.
    w.relay.set_clock(DUE + 86_400_000);
    assert_head_unavailable(&w.relay, &w.keys.id);
    assert_eq!(
        disk(&w, &format!("/records/heads/{}.json", w.keys.id)),
        old_head
    );
    assert_eq!(
        std::fs::read(w.scratch.path().join("data/home/replay.log")).unwrap(),
        replay_before
    );
    assert_eq!(
        std::fs::read(w.scratch.path().join("data/home/log.jsonl")).unwrap(),
        log_before
    );
    w.relay = w.relay.restart(&w.keys, NOW, &[]);
    assert_head_unavailable(&w.relay, &w.keys.id);
    assert_eq!(
        json_get(&w.relay, "/authority").1["entries"]
            .as_array()
            .unwrap()
            .len(),
        n as usize
    );
    for (path, bytes) in &held {
        assert_eq!(disk(&w, path), *bytes);
    }
    let (s, r) = w.relay.post(
        "/authority",
        &json!({"from":n+1, "entries":[value(&finality)], "receipts":[]}),
    );
    assert_eq!(
        (s, r),
        (422, json!({"result":"malformed"})),
        "invalid sequence is still a parse error"
    );
    let mut next = body(&finality);
    next["seq"] = json!(n + 1);
    next["previous"] = json!(object_digest(&finality));
    let next = json!({"body":b64(&canonical(&next).unwrap())});
    let (s, r) = w.relay.post(
        "/authority",
        &json!({"from":n+1, "entries":[next], "receipts":[]}),
    );
    assert_eq!((s, r), (422, json!({"result":"newerFormat"})));
}

#[test]
fn stopped_members_home_never_challenges_or_verifies_a_call_and_rejects_new_pending_kinds() {
    let Some(mut w) = world("h4-members", "members") else {
        return;
    };
    let (_, _, n) = stop(&w, None);
    w.relay = w.relay.restart(&w.keys, NOW, &[]);
    assert_eq!(json_get(&w.relay, "").0, 200);
    assert_head_unavailable(&w.relay, &w.keys.id);
    for path in [
        "/authority".into(),
        "/pending".into(),
        "/changes".into(),
        format!("/records/authority/{n:08}.json"),
        format!("/records/blobs/{}", "a".repeat(64)),
    ] {
        for headers in [
            vec![],
            auth(b"not even a parsed call"),
            auth(&own_call(&w, "GET", &path, b"")),
        ] {
            assert_unavailable(&w.relay, "GET", &path, &headers, b"");
        }
    }
    let additive = transition(&w.f, json!({"policy":{"callWindow":600}}), &w.f.d, DUE);
    let genesis =
        w.f.account
            .objects()
            .entries
            .iter()
            .find(|e| support::entry_seq(e) == 1)
            .unwrap();
    let unrelated = receipt(&w.keys, w.f.account.id().as_str(), genesis, DUE);
    for object in [&additive, genesis, &unrelated] {
        let (s, r) = post_object(&w.relay, object);
        assert_eq!((s, r), (422, json!(["newerFormat"])));
    }
}

#[test]
fn stopped_home_receipts_only_timely_vetoes_and_removals_and_never_records_them() {
    let Some(w) = world("h4-receipts", "public") else {
        return;
    };
    let target = transition(
        &w.f,
        json!({"policy":{"callWindow":600}}),
        &w.f.d,
        DUE - 100_000,
    );
    let (raise, finality, n) = stop(&w, Some(&target));
    let v = veto(&w.f, &target, &w.f.k, DUE);
    let raise_veto = veto(&w.f, &raise, &w.f.d, DUE);
    let removal = transition(&w.f, json!({"policy":{"callWindow":120}}), &w.f.d, DUE);
    let mut at_n = body(&removal);
    at_n["anchor"] = json!({"seq":n,"digest":object_digest(&finality)});
    let removal = signed(&w.f, at_n);
    for object in [&v, &raise_veto, &removal] {
        let (s, r) = post_object(&w.relay, object);
        assert_eq!(s, 200, "{r}");
        assert_eq!(r["receipts"].as_array().unwrap().len(), 1);
        assert_eq!(
            body(&canonical(&r["receipts"][0]).unwrap())["object"],
            object_digest(object)
        );
        let directory = if body(object)["protocol"] == "colophon/transition/5" {
            "transitions"
        } else {
            "vetoes"
        };
        assert_eq!(
            w.relay
                .get(&format!(
                    "/records/{directory}/{}.json",
                    object_digest(object)
                ))
                .0,
            200
        );
        assert_eq!(
            w.relay
                .get(&format!(
                    "/records/receipts/{}/{}.receipt.json",
                    object_digest(object),
                    w.keys.id
                ))
                .0,
            200
        );
    }
    assert_eq!(
        w.relay
            .get(&format!("/records/vetoes/{}.json", object_digest(&v)))
            .0,
        200
    );
    w.relay.set_clock(DUE + 300_001);
    let late = transition(&w.f, json!({"policy":{"callWindow":100}}), &w.f.d, DUE);
    assert_eq!(post_object(&w.relay, &late), (422, json!(["newerFormat"])));
    assert_head_unavailable(&w.relay, &w.keys.id);
    assert_eq!(
        json_get(&w.relay, "/authority").1["entries"]
            .as_array()
            .unwrap()
            .len(),
        n as usize
    );
}

#[test]
fn a_home_witnesses_a_provisional_raise_and_records_the_vetoed_that_displaces_it() {
    if prerequisites().is_none() {
        return;
    }
    let (ka, kb) = (HomeKeys::new(0x77), HomeKeys::new(0x78));
    let f = fixture("public", &[(&ka, BASE_A), (&kb, BASE_B)]);
    let scratch = Scratch::new("h4-provisional");
    let relay = Relay::start(
        &ka,
        f.account.id().as_str(),
        BASE_A,
        scratch.path(),
        NOW,
        &[(BASE_B, CLOSED_PORT)],
    );
    first_upload(&relay, &f, NOW);
    let raise = transition(&f, json!({"layout":3}), &f.k, NOW);
    let (s, r) = post_object(&relay, &raise);
    assert_eq!(s, 200, "{r}");
    let mut objects = f.account.objects().clone();
    objects
        .pending
        .extend([raise.clone(), canonical(&r["receipts"][0]).unwrap()]);
    let v = veto(&f, &raise, &f.d, NOW + 1_000);
    // B witnessed the veto in its window; A sees it after the provisional activate.
    let vr = receipt(&kb, f.account.id().as_str(), &v, NOW + 1_000);
    let activation = activate(&mut objects, &raise, DUE);
    relay.set_clock(DUE);
    let (s,r) = relay.post("/authority",&json!({"from":support::entry_seq(&activation),"entries":[value(&activation)],"receipts":[]}));
    assert_eq!(s, 200, "{r}");
    let (s, h) = relay.get("/head");
    assert_eq!(s, 200, "still provisional: B has signed no head");
    assert_eq!(
        body(&h)["authority"]["seq"],
        support::entry_seq(&activation)
    );
    let (s, r) = relay.post("/pending", &json!({"objects":[value(&v),value(&vr)]}));
    assert_eq!(s, 200, "{r}");
    // A accepts the late, already receipted veto but signs no out-of-window receipt.
    assert!(r["receipts"].as_array().unwrap().is_empty());
    eventually("the provisional raise displaced by vetoed", 30, || {
        let _ = relay.get("/head"); // Runs the scheduler without advancing protocol time.
        json_get(&relay, "/authority").1["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| body(&canonical(e).unwrap())["kind"] == "vetoed")
    });
    relay.set_clock(DUE + 1);
    assert_eq!(
        relay.get("/head").0,
        200,
        "vetoed layout raise stops nothing"
    );
}

#[test]
fn existing_forwarding_sends_stopped_homes_new_removals_vetoes_and_receipts() {
    if prerequisites().is_none() {
        return;
    }
    let (ka, kb) = (HomeKeys::new(0x77), HomeKeys::new(0x78));
    let f = fixture("public", &[(&ka, BASE_A), (&kb, BASE_B)]);
    let (da, db) = (Scratch::new("h4-forward-a"), Scratch::new("h4-forward-b"));
    // Keep the peer unreachable until A has stopped, so observing it at B proves forwarding
    // after the stop rather than a pass that happened before it.
    let a = Relay::start(
        &ka,
        f.account.id().as_str(),
        BASE_A,
        da.path(),
        NOW,
        &[(BASE_B, CLOSED_PORT)],
    );
    first_upload(&a, &f, NOW);
    let raise = transition(&f, json!({"layout":3}), &f.k, NOW);
    let (s, r) = post_object(&a, &raise);
    assert_eq!(s, 200, "{r}");
    let mut objects = f.account.objects().clone();
    objects
        .pending
        .extend([raise.clone(), canonical(&r["receipts"][0]).unwrap()]);
    let target = transition(
        &f,
        json!({"policy":{"callWindow":600}}),
        &f.d,
        DUE - 100_000,
    );
    a.set_clock(DUE - 100_000);
    let (s, r) = post_object(&a, &target);
    assert_eq!(s, 200, "{r}");
    objects
        .pending
        .extend([target.clone(), canonical(&r["receipts"][0]).unwrap()]);
    let act = activate(&mut objects, &raise, DUE);
    objects
        .heads
        .extend([head(&ka, &objects, DUE), head(&kb, &objects, DUE)]);
    let fin = final_entry(&mut objects, support::entry_seq(&act), DUE);
    a.set_clock(DUE);
    let (s, r) = a.post(
        "/authority",
        &json!({"from":support::entry_seq(&act),"entries":[value(&act),value(&fin)],"receipts":[]}),
    );
    assert_eq!(s, 200, "{r}");
    assert_head_unavailable(&a, &ka.id);
    let removal = transition(&f, json!({"policy":{"callWindow":120}}), &f.k, DUE);
    let v = veto(&f, &target, &f.k, DUE);
    for o in [&removal, &v] {
        assert_eq!(post_object(&a, o).0, 200);
    }
    let b = Relay::start(
        &kb,
        f.account.id().as_str(),
        BASE_B,
        db.path(),
        DUE,
        &[(BASE_A, a.port)],
    );
    first_upload(&b, &f, DUE);
    a.set_resolve(&[(BASE_B, b.port)]);
    // Read the actual files: a peer may already have recorded an object and removed it from
    // its pending listing. Its store still proves that the forwarding pass delivered it.
    for (kind, o) in [("transitions", &removal), ("vetoes", &v)] {
        let d = object_digest(o);
        eventually("a stopped home's forwarded object and receipt", 45, || {
            b.get(&format!("/records/{kind}/{d}.json")).0 == 200
                && b.get(&format!("/records/receipts/{d}/{}.receipt.json", ka.id))
                    .0
                    == 200
        });
    }
}
