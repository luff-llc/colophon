//! A history read signed by a passkey before the device is a member (0.5.7, §12.3, §13.4),
//! against the real relay: a device that holds only the account ID, the home's base and a
//! passkey learns the passkey's point from one assertion, reads every page of the history under
//! `members` with `colophon.history.read` calls signed by that passkey, and accepts it only when
//! it verifies from the genesis and ends at the home's fresh signed head. The home serves the read
//! from an authority origin of the controller's descriptor and refuses one from any other origin,
//! from a key that is not a current controller, a replay and another `asOf`.
#![allow(
    clippy::unwrap_used,
    clippy::too_many_arguments,
    clippy::cloned_ref_to_slice_refs,
    dead_code
)]
#[path = "../../colophon-core/tests/v05_engine_support/mod.rs"]
mod support;
mod support_relay;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use colophon_core::keys::testing::SyntheticAuthenticator;
use colophon_core::v05::ids::{key_id, AccountId};
use colophon_core::v05::join::{history_page_path, parse_history_page, passkey_points, verify_with_passkey};
use colophon_core::v05::write::calls::{finish_history_read, prepare_passkey_history_read, HistoryReadSpec};
use colophon_core::v05::write::SignatureResult;
use serde_json::{json, Value};
use support::*;
use support_relay::*;

const NOW: i64 = T0 + 3 * HOUR;
const NS: &str = "listening.podcasts";

fn get_with(relay: &Relay, path: &str, call: Option<&[u8]>) -> (u16, Vec<u8>) {
    let mut h = vec![];
    if let Some(c) = call {
        h.push(("Authorization".to_string(), format!("Colophon {}", URL_SAFE_NO_PAD.encode(c))));
    }
    let (s, _, b) = http(relay.port, "GET", &relay.url(path), &h, &[]);
    (s, b)
}
fn point_of(scalar: u8) -> Vec<u8> {
    p256::ecdsa::SigningKey::from_slice(&[scalar; 32])
        .unwrap()
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec()
}
fn result(body: &[u8]) -> Value {
    serde_json::from_slice::<Value>(body).map(|v| v["result"].clone()).unwrap_or(Value::Null)
}

/// One `colophon.history.read` call for `path`, signed by `signer` as the controller `point`,
/// from `origin`, naming `as_of`.
fn passkey_read(
    account: &AccountId,
    signer: &SyntheticAuthenticator,
    point: &[u8],
    origin: &str,
    as_of: (u64, &str),
    path: &str,
    request_id: [u8; 32],
) -> Vec<u8> {
    let created = colophon_core::v05::write::format_date(NOW);
    let prepared = prepare_passkey_history_read(&HistoryReadSpec {
        account,
        as_of,
        signing: point,
        audience: BASE_A,
        path,
        request_id,
        created: &created,
    })
    .unwrap();
    let a = signer.assertion(prepared.step().body(), RP, origin, 0x05, false).unwrap();
    finish_history_read(
        &prepared,
        &SignatureResult {
            signature: a.signature,
            assertion: Some((a.assertion.authenticator_data, a.assertion.client_data)),
        },
    )
    .unwrap()
}

#[test]
fn a_passkey_reads_the_history_before_its_device_is_a_member() {
    if prerequisites().is_none() {
        return;
    }
    let ka = HomeKeys::new(0x77);
    let mut f = create_with(&[NS], "members", 1);
    appoint_homes(&mut f, &[(&ka, BASE_A)]);
    let scratch = Scratch::new("passkey-read");
    let a = Relay::start(&ka, f.account.id().as_str(), BASE_A, scratch.path(), T0 + 1_000, &[]);
    first_upload(&a, &f, T0 + 1_000);
    a.set_clock(NOW);
    // The home signs a fresh head on a head read (no scheduler runs here).
    let (s, _) = a.get("/head");
    assert_eq!(s, 200);
    let account = f.account.id().clone();
    let genesis = (1, account.as_str());

    // Under `members` a device with nothing gets nothing without a call.
    assert_eq!(get_with(&a, "/authority?after=0&limit=64", None).0, 401);

    // The passkey's point, from one discoverable assertion over a body the device chose.
    let passkey = SyntheticAuthenticator::new().unwrap();
    let body = [0x42u8; 32];
    let id = passkey.assertion(&body, RP, ORIGIN, 0x05, false).unwrap();
    let candidates = passkey_points(
        &body,
        RP,
        &id.assertion.authenticator_data,
        &id.assertion.client_data,
        &id.signature,
        None,
    )
    .unwrap();
    let expected = point_of(1);
    assert!(candidates.contains(&expected));
    // Which candidate is the passkey's: the one whose call verifies the second assertion. An
    // invite gives the key ID and settles it at once.
    let point = passkey_points(
        &body,
        RP,
        &id.assertion.authenticator_data,
        &id.assertion.client_data,
        &id.signature,
        Some(&key_id(&expected)),
    )
    .unwrap()
    .remove(0);

    // Every page, each with its own call.
    let mut entries = Vec::new();
    let mut after = 0u64;
    loop {
        let path = history_page_path(after);
        let call = passkey_read(&account, &passkey, &point, ORIGIN, genesis, &path, fresh_request_id());
        let (s, b) = get_with(&a, &path, Some(&call));
        assert_eq!(s, 200, "the passkey reads {path}: {}", String::from_utf8_lossy(&b));
        let page = parse_history_page(&b).unwrap();
        after += page.entries.len() as u64;
        entries.extend(page.entries);
        if !page.more {
            break;
        }
    }
    let (s, head) = a.get("/head");
    assert_eq!(s, 200);
    let accepted = verify_with_passkey(&account, 1, account.as_str(), &point, BASE_A, &head, entries.clone(), NOW).unwrap();
    assert_eq!(accepted.signer.id, key_id(&point));
    assert!(accepted.signer.roles.iter().any(|r| r == "control"));
    assert!(accepted.signer.own_slot, "the passkey holds a slot of its own");
    assert_eq!(accepted.controllers.len(), 1, "one passkey controller");
    assert_eq!(accepted.files.len(), entries.len());
    assert_eq!(accepted.files[0].0, "authority/00000001.json");
    // Another key is not the signer of this history.
    let other = point_of(2);
    let refused = verify_with_passkey(&account, 1, account.as_str(), &other, BASE_A, &head, entries.clone(), NOW).err().map(|e| e.code());
    assert_eq!(refused.as_deref(), Some("refused:revoked"));
    // Another base is not this home's.
    let refused = verify_with_passkey(&account, 1, account.as_str(), &point, BASE_B, &head, entries.clone(), NOW).err().map(|e| e.code());
    assert_eq!(refused.as_deref(), Some("badSignature"));
    // A stale head is not accepted (a replayed history cannot hide a later removal).
    let refused = verify_with_passkey(&account, 1, account.as_str(), &point, BASE_A, &head, entries, NOW + 48 * HOUR).err().map(|e| e.code());
    assert_eq!(refused.as_deref(), Some("unavailable"));

    let path = history_page_path(0);
    // Not from a subdomain of the rp that is no authority origin of the descriptor: the general
    // rule allows it, the home's history read does not.
    let call = passkey_read(&account, &passkey, &point, "https://keys.id.luff.works", genesis, &path, fresh_request_id());
    let (s, b) = get_with(&a, &path, Some(&call));
    assert_eq!((s, result(&b)), (403, json!("refused:origin")));
    // Not from another relying party's origin at all.
    let call = passkey_read(&account, &passkey, &point, "https://evil.example", genesis, &path, fresh_request_id());
    assert_eq!(get_with(&a, &path, Some(&call)).0, 403);
    // Not a key that is no controller: the same answer a key no grant names gets.
    let stranger = SyntheticAuthenticator::from_scalar(&[2; 32]).unwrap();
    let call = passkey_read(&account, &stranger, &other, ORIGIN, genesis, &path, fresh_request_id());
    let (s, b) = get_with(&a, &path, Some(&call));
    assert_eq!((s, result(&b)), (403, json!("refused:revoked")));
    // Not twice: a replayed call is refused.
    let call = passkey_read(&account, &passkey, &point, ORIGIN, genesis, &path, fresh_request_id());
    assert_eq!(get_with(&a, &path, Some(&call)).0, 200);
    let (s, b) = get_with(&a, &path, Some(&call));
    assert_eq!((s, result(&b)), (403, json!("refused:replay")));
    // Not bound to another request: a call for page 0 does not read page 1.
    let call = passkey_read(&account, &passkey, &point, ORIGIN, genesis, &path, fresh_request_id());
    let (s, b) = get_with(&a, &history_page_path(1), Some(&call));
    assert_eq!((s, result(&b)), (403, json!("refused:outOfScope")));
    // Not naming another entry as the genesis.
    let wrong = "cd".repeat(32);
    let call = passkey_read(&account, &passkey, &point, ORIGIN, (1, &wrong), &path, fresh_request_id());
    let (s, b) = get_with(&a, &path, Some(&call));
    assert_eq!((s, result(&b)), (403, json!("refused:fork")));
    // A passkey reads the history only: not the change feed.
    let feed = "/changes?limit=500";
    let created = colophon_core::v05::write::format_date(NOW);
    let prepared = prepare_passkey_history_read(&HistoryReadSpec {
        account: &account,
        as_of: genesis,
        signing: &point,
        audience: BASE_A,
        path: feed,
        request_id: fresh_request_id(),
        created: &created,
    });
    assert!(prepared.is_err(), "the SDK builds no history read for the change feed");
}
