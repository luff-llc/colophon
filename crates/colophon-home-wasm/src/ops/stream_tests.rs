//! The home stream's decisions as the relay asks for them (0.6 draft, `docs/colophon-0.6-stream.md`):
//! `session_frame`, `subscription` and `route_change`. The rules themselves are tested in
//! `colophon_core::v05::home_stream`; these check the operations' shapes and that every refusal
//! the relay maps to an HTTP status or stream error code comes back as the relay expects.
#![allow(clippy::unwrap_used)]
use super::handle;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::{json, Value};

const ACCOUNT: &str = "1b420a5e226586586d53eab23862f233e12dce1a5532f36e4b1d578fa0edfb6a";
const A: &str = "7f5be46131fa76b0fb7050f5779a5a21";
const B: &str = "3959fc4d14735eaf9b9751593d868541";

fn call(req: Value) -> Value {
    let v: Value = serde_json::from_slice(&handle(req.to_string().as_bytes())).unwrap();
    assert_eq!(v["ok"], true, "{v}");
    v
}

fn frame(from: &str, extra: Value) -> String {
    let mut body = json!({"protocol": "colophon/session/6", "account": ACCOUNT,
        "namespace": "notes", "cell": "now-playing", "from": from, "key": "k", "n": 3,
        "epoch": 1, "nonce": "AAAAAAAAAAAAAAAA", "ciphertext": "AAAA"});
    for (k, v) in extra.as_object().unwrap() {
        body[k] = v.clone();
    }
    json!({"body": STANDARD.encode(body.to_string()), "signature": "AAAA"}).to_string()
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
fn route_changes_check_body_ownership_and_caps() {
    let address = "private-device-token";
    let id = colophon_core::v05::home_stream::route_id("push", address);
    let body = STANDARD
        .encode(json!({"kind": "push", "address": address, "reaches": "Phone"}).to_string());
    let change = |owner: Value, principal_routes: u64, total: u64, method: &str| {
        call(
            json!({"op": "route_change", "id": id, "method": method, "body": body,
            "principal": "member:a", "owner": owner, "principalRoutes": principal_routes,
            "totalRoutes": total}),
        )
    };
    let created = change(Value::Null, 0, 0, "PUT");
    assert_eq!(
        (created["allowed"].as_bool(), created["created"].as_bool()),
        (Some(true), Some(true))
    );
    assert_eq!(created["route"]["address"], address);
    let replaced = change(json!("member:a"), 1, 1, "PUT");
    assert_eq!(replaced["created"], false);
    let foreign = change(json!("controller:c"), 0, 1, "DELETE");
    assert_eq!(
        (foreign["status"].as_u64(), foreign["result"].as_str()),
        (Some(403), Some("refused:notGranted"))
    );
    assert_eq!(change(Value::Null, 0, 0, "DELETE")["status"], 404);
    let full = change(Value::Null, 8, 8, "PUT");
    assert_eq!(
        (full["status"].as_u64(), full["result"].as_str()),
        (Some(507), Some("refused:overQuota"))
    );
    assert_eq!(change(Value::Null, 0, 64, "PUT")["status"], 507);
    let wrong = call(
        json!({"op": "route_change", "id": "0".repeat(64), "method": "PUT", "body": body,
        "principal": "member:a", "owner": null, "principalRoutes": 0, "totalRoutes": 0}),
    );
    assert_eq!(
        (wrong["status"].as_u64(), wrong["error"].as_str()),
        (Some(400), Some("Route ID does not match kind and address"))
    );
}
