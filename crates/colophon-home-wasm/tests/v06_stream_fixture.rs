//! Writes `relay/test/home-stream-v2.fixture.json`, the synthetic account the relay's home
//! stream v2 tests use (`relay/test/home-stream-v2.test.js`): one home and four members whose
//! private keys the fixture carries (test keys; they protect nothing):
//!
//! - `a`: `records` read on `notes`;
//! - `b`: `records` write on `notes`;
//! - `c`: `records` read on `books` only (not entitled to `notes`);
//! - `d`: `records` read on `notes` (a third entitled member, for `to` addressing).
//!
//! The fixture is checked in. Regenerate it only when the account format changes:
//! `COLOPHON_WRITE_STREAM_FIXTURE=1 cargo test -p colophon-home-wasm --test v06_stream_fixture
//! -- --ignored`. Without the variable the test only checks that the account still builds.
#![allow(clippy::unwrap_used, dead_code)]
#[path = "../../colophon-core/tests/v05_engine_support/mod.rs"]
mod support;
mod support_relay;
use colophon_core::v05::account::{finish_request, prepare_request};
use colophon_core::v05::write::calls::RequestSpec;
use colophon_core::v05::write::format_date;
use serde_json::{json, Value};
use support::*;
use support_relay::*;

const BASE: &str = "https://home-s.example/v1/libraries/home";

/// Admit a member whose signing key is `keys` (so the fixture can carry its private JWK).
fn admit_keyed(f: &mut Fixture, keys: &HomeKeys, agreement: &HomeKeys, label: &str, terms: Value) {
    let created = format_date(f.account.now_ms());
    let prepared = prepare_request(&RequestSpec {
        account: f.account.id(),
        signing: &keys.point,
        agreement: &agreement.point,
        label,
        kind: "agent",
        terms: terms.clone(),
        created: &created,
        custody: None,
        operator: None,
        endpoints: None,
    })
    .unwrap();
    let req = finish_request(&prepared, &keys.sign(prepared.step().body())).unwrap();
    let seed = f.host.fresh();
    let pairing = paired(f, &req);
    let action = f
        .account
        .begin_approve(&req.raw, terms, std::slice::from_ref(&f.d), seed, pairing)
        .unwrap();
    run(&mut f.account, &f.host, action);
}

fn build() -> Value {
    let home = HomeKeys::new(0x51);
    let mut f = create_with(&["books", "notes"], "members", 1);
    let expires = format_date(T0 + 7 * 24 * HOUR);
    let members = [
        (
            "a",
            0x61u8,
            json!([{"namespace": "notes", "access": "read"}]),
        ),
        (
            "b",
            0x62u8,
            json!([{"namespace": "notes", "access": "write"}]),
        ),
        (
            "c",
            0x63u8,
            json!([{"namespace": "books", "access": "read"}]),
        ),
        (
            "d",
            0x64u8,
            json!([{"namespace": "notes", "access": "read"}]),
        ),
    ];
    let mut out = serde_json::Map::new();
    for (name, n, records) in &members {
        let keys = HomeKeys::new(*n);
        let agreement = HomeKeys::new(n + 0x10);
        admit_keyed(
            &mut f,
            &keys,
            &agreement,
            name,
            json!({"records": records, "expires": expires}),
        );
        let jwk: Value = serde_json::from_str(&keys.jwk()).unwrap();
        out.insert(name.to_string(), json!({"id": keys.id, "key": jwk}));
    }
    // Members first: entries made after a home is appointed wait for that home to take them.
    appoint_homes(&mut f, &[(&home, BASE)]);
    let entries: Vec<Value> = entries_json(&f).into_iter().map(|(_, e)| e).collect();
    let last = entries.last().unwrap();
    let bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        last["body"].as_str().unwrap(),
    )
    .unwrap();
    let last_body: Value = serde_json::from_slice(&bytes).unwrap();
    let digest = colophon_core::v05::encoding::digest(&bytes);
    out.insert("account".into(), json!(f.account.id().as_str()));
    out.insert("base".into(), json!(BASE));
    out.insert("homeKey".into(), serde_json::from_str(&home.jwk()).unwrap());
    out.insert("entries".into(), json!(entries));
    out.insert(
        "asOf".into(),
        json!({"seq": last_body["seq"], "digest": digest}),
    );
    out.insert("now".into(), json!(f.account.now_ms() + 2_000));
    Value::Object(out)
}

#[test]
#[ignore = "writes the relay's stream fixture; run with COLOPHON_WRITE_STREAM_FIXTURE=1"]
fn write_stream_fixture() {
    let fixture = build();
    let entries = fixture["entries"].as_array().unwrap();
    assert_eq!(
        entries.len() as u64,
        fixture["asOf"]["seq"].as_u64().unwrap()
    );
    let kinds: Vec<String> = entries
        .iter()
        .map(|e| {
            let body = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                e["body"].as_str().unwrap(),
            )
            .unwrap();
            serde_json::from_slice::<Value>(&body).unwrap()["kind"]
                .as_str()
                .unwrap_or("genesis")
                .to_string()
        })
        .collect();
    assert_eq!(
        kinds.iter().filter(|k| *k == "grant").count(),
        4,
        "{kinds:?}"
    );
    if std::env::var("COLOPHON_WRITE_STREAM_FIXTURE").as_deref() == Ok("1") {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../relay/test/home-stream-v2.fixture.json"
        );
        std::fs::write(path, serde_json::to_string_pretty(&fixture).unwrap() + "\n").unwrap();
    }
}
