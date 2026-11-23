//! The home stream's decisions as the relay asks for them (0.6 draft, `docs/colophon-0.6-stream.md`):
//! `session_frame`, `subscription` and `route_change`. The rules themselves are tested in
//! `colophon_core::v05::home_stream`; these check the operations' shapes and that every refusal
//! the relay maps to an HTTP status or stream error code comes back as the relay expects.
#![allow(clippy::unwrap_used)]
use super::handle;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use colophon_core::v05::encoding::canonical;
use serde_json::{json, Value};

const ACCOUNT: &str = "1b420a5e226586586d53eab23862f233e12dce1a5532f36e4b1d578fa0edfb6a";
const A: &str = "7f5be46131fa76b0fb7050f5779a5a21";
const B: &str = "3959fc4d14735eaf9b9751593d868541";

fn call(req: Value) -> Value {
    let v: Value = serde_json::from_slice(&handle(req.to_string().as_bytes())).unwrap();
    assert_eq!(v["ok"], true, "{v}");
    v
}

/// A session frame in the codec's form (0.6 sessions §S3): one canonical JSON object. The home
/// never opens the ciphertext or checks the signature, so both are zero bytes of the right
/// lengths.
fn frame(from: &str, extra: Value) -> String {
    let mut body = json!({"protocol": "colophon/session/6", "account": ACCOUNT,
        "namespace": "notes", "cell": "now-playing", "from": from,
        "key": "2bad0fd610d99eae443e932a26142bca", "n": 3, "epoch": 1,
        "ciphertext": STANDARD.encode([0u8; 16]), "signature": STANDARD.encode([0u8; 64])});
    for (k, v) in extra.as_object().unwrap() {
        body[k] = v.clone();
    }
    String::from_utf8(canonical(&body).unwrap()).unwrap()
}

#[test]
fn session_frames_route_by_their_outer_fields() {
    let r = call(
        json!({"op": "session_frame", "frame": frame(A, json!({"to": B, "retain": true})),
        "account": ACCOUNT, "member": A, "entitled": ["notes"]}),
    );
    assert_eq!(r["allowed"], true);
    assert_eq!(
        (r["namespace"].as_str(), r["cell"].as_str()),
        (Some("notes"), Some("now-playing"))
    );
    assert_eq!(
        (r["to"].as_str(), r["retain"].as_bool()),
        (Some(B), Some(true))
    );
    let plain = call(json!({"op": "session_frame", "frame": frame(A, json!({})),
        "account": ACCOUNT, "member": A, "entitled": ["notes"]}));
    assert_eq!(
        (plain["to"].clone(), plain["retain"].clone()),
        (Value::Null, json!(false))
    );
}

#[test]
fn session_frame_refusals_carry_stream_codes() {
    let code = |frame: String, member: &str, entitled: Value| {
        call(
            json!({"op": "session_frame", "frame": frame, "account": ACCOUNT, "member": member,
            "entitled": entitled}),
        )["code"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_eq!(code(frame(A, json!({})), B, json!(["notes"])), "from");
    assert_eq!(
        code(frame(A, json!({})), A, json!(["books"])),
        "notEntitled"
    );
    assert_eq!(
        code(
            frame(A, json!({"account": "0".repeat(64)})),
            A,
            json!(["notes"])
        ),
        "account"
    );
    assert_eq!(
        code(frame(A, json!({"retain": false})), A, json!(["notes"])),
        "badFrame"
    );
    assert_eq!(code("not json".into(), A, json!(["notes"])), "badFrame");
    assert_eq!(code(frame(A, json!({"nonce": "AAAA"})), A, json!(["notes"])), "badFrame");
    assert_eq!(code(frame(A, json!({"signature": "AAAA"})), A, json!(["notes"])), "badFrame");
    assert_eq!(code(frame(A, json!({"key": "k"})), A, json!(["notes"])), "badFrame");
    // The former envelope over a base64 body is not a frame.
    let envelope = json!({"body": STANDARD.encode(frame(A, json!({}))), "signature": "AAAA"});
    assert_eq!(code(envelope.to_string(), A, json!(["notes"])), "badFrame");
    let big = frame(A, json!({"ciphertext": "A".repeat(16_384)}));
    assert_eq!(code(big, A, json!(["notes"])), "tooLarge");
}

#[test]
fn subscriptions_follow_entitlement() {
    let r = call(
        json!({"op": "subscription", "namespace": "notes", "cell": "now-playing", "entitled": ["notes"]}),
    );
    assert_eq!(r["allowed"], true);
    let r = call(
        json!({"op": "subscription", "namespace": "notes", "cell": "now-playing", "entitled": []}),
    );
    assert_eq!(
        (r["allowed"].as_bool(), r["code"].as_str()),
        (Some(false), Some("notEntitled"))
    );
    let r = call(
        json!({"op": "subscription", "namespace": "notes", "cell": "Bad Cell", "entitled": ["notes"]}),
    );
    assert_eq!(r["code"], "badFrame");
}

#[test]
fn route_changes_derive_keyed_ids_and_check_ownership_and_caps() {
    let address = "+15551234567";
    let key = "07".repeat(32);
    let body = STANDARD.encode(json!({"kind": "sms", "address": address, "reaches": "Phone"}).to_string());
    let post = |routes: Value| {
        call(json!({"op": "route_change", "method": "POST", "body": body, "key": key,
            "principal": "member:a", "routes": routes}))
    };
    let created = post(json!([]));
    assert_eq!((created["allowed"].as_bool(), created["created"].as_bool()), (Some(true), Some(true)));
    assert_eq!(created["route"]["address"], address);
    let id = created["id"].as_str().unwrap().to_string();
    let expected = colophon_core::v05::home_stream::route_id(&[7u8; 32], "member:a", "sms", address);
    assert_eq!(id, expected);
    assert_ne!(id, colophon_core::v05::encoding::digest(format!("sms\0{address}").as_bytes()));
    let replaced = post(json!([{"id": id, "by": "member:a"}]));
    assert_eq!((replaced["created"].as_bool(), replaced["id"].as_str()), (Some(false), Some(id.as_str())));
    let delete = |principal: &str, routes: Value| {
        call(json!({"op": "route_change", "method": "DELETE", "id": id, "key": key,
            "principal": principal, "routes": routes}))
    };
    let foreign = delete("controller:c", json!([{"id": id, "by": "member:a"}]));
    assert_eq!((foreign["status"].as_u64(), foreign["result"].as_str()), (Some(403), Some("refused:notGranted")));
    assert_eq!(delete("member:a", json!([]))["status"], 404);
    assert_eq!(delete("member:a", json!([{"id": id, "by": "member:a"}]))["allowed"], true);
    let mine: Vec<Value> = (0..8).map(|i| json!({"id": format!("{i:064}"), "by": "member:a"})).collect();
    let full = post(json!(mine));
    assert_eq!((full["status"].as_u64(), full["result"].as_str()), (Some(507), Some("refused:overQuota")));
    let slot: Vec<Value> = (0..64).map(|i| json!({"id": format!("{i:064}"), "by": format!("member:{i}")})).collect();
    assert_eq!(post(json!(slot))["status"], 507);
    let bad = call(json!({"op": "route_change", "method": "POST", "key": key, "principal": "member:a", "routes": [],
        "body": STANDARD.encode(r#"{"kind":"sms","address":"5551234567","reaches":"Phone"}"#)}));
    assert_eq!(bad["status"], 400);
    let rekeyed = call(json!({"op": "route_id", "key": key, "principal": "member:a", "kind": "sms", "address": address}));
    assert_eq!(rekeyed["id"], expected);
}
