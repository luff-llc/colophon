//! A member device that syncs with its home for days (0.5.7), against the real relay. Each pass
//! fetches the home's head, and a head over an unchanged history is a new envelope (a later
//! `issued`). Before 0.5.7 the account held every head envelope it was ever given, and once it
//! held more than a view takes (`MAX_VIEW_HEADS`, 64) every call failed `malformed: too many
//! head envelopes`, so the device could no longer exchange at all. Now the account keeps the heads
//! a reader needs (§13.3), and an account opened over more than 64 heads (a device that held them
//! before the upgrade) prunes them and makes calls again, with no rejoin.
#![allow(
    clippy::unwrap_used,
    clippy::too_many_arguments,
    clippy::cloned_ref_to_slice_refs,
    dead_code
)]
#[path = "../../colophon-core/tests/v05_engine_support/mod.rs"]
mod support;
mod support_relay;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use colophon_core::v05::account::{Account, HomeCall, Identity, PRUNE_HEADS_AT};
use colophon_core::v05::calls::MAX_VIEW_HEADS;
use serde_json::Value;
use std::collections::BTreeSet;
use support::*;
use support_relay::*;

const NOW: i64 = T0 + 3 * HOUR;
const NS: &str = "listening.podcasts";

/// The relay's head once it is issued at or after `after` (a head read settles the home).
fn fresh_head(relay: &Relay, after: &str) -> Vec<u8> {
    let mut head = Vec::new();
    ticks_until("a fresh head", 3, &[relay], || {
        let (s, b) = relay.get("/head");
        s == 200 && {
            let v: Value = serde_json::from_slice(&b).unwrap();
            let h: Value = serde_json::from_slice(&STANDARD.decode(v["body"].as_str().unwrap()).unwrap()).unwrap();
            head = b;
            h["issued"].as_str().unwrap() >= after
        }
    });
    head
}

fn claim_of(h: &[u8]) -> (String, u64, String) {
    let v: Value = serde_json::from_slice(h).unwrap();
    let b: Value = serde_json::from_slice(&STANDARD.decode(v["body"].as_str().unwrap()).unwrap()).unwrap();
    (b["by"].as_str().unwrap().to_string(), b["authority"]["seq"].as_u64().unwrap(), b["authority"]["digest"].as_str().unwrap().to_string())
}
fn issued_of(h: &[u8]) -> String {
    let v: Value = serde_json::from_slice(h).unwrap();
    let b: Value = serde_json::from_slice(&STANDARD.decode(v["body"].as_str().unwrap()).unwrap()).unwrap();
    b["issued"].as_str().unwrap().to_string()
}

/// The head as an account holds it: the canonical envelope.
fn canonical(b: &[u8]) -> Vec<u8> {
    colophon_core::v05::encoding::canonical(&serde_json::from_slice::<Value>(b).unwrap()).unwrap()
}

#[test]
fn a_member_that_synced_for_days_keeps_exchanging_and_an_old_device_heals() {
    if prerequisites().is_none() {
        return;
    }
    let keys = HomeKeys::new(0x77);
    let mut f = create_with(&[NS], "members", 1);
    let home = appoint_home_keys(&mut f, &keys, BASE_A);
    let member = f.host.identity(31);
    admit(&mut f, &member, "Phone", "device", terms_for(&[(NS, "write")]), terms_for(&[(NS, "write")]));
    let authority = MemSource::new();
    authority.store_account(&f.account);
    let scratch = Scratch::new("heads-days");
    let relay = Relay::start(&keys, f.account.id().as_str(), BASE_A, scratch.path(), f.account.now_ms(), &[]);
    first_upload(&relay, &f, f.account.now_ms() + 1_000);
    let src = MemSource::new();
    for p in authority.listing() {
        src.put(&p, authority.get(&p).unwrap());
    }
    let mut phone = member_engine(&f, &f.host, &src, &member, NOW);
    let host = std::mem::replace(&mut f.host, Host::new());
    let mut wire = RealRelay::new(&relay);

    // Many passes, each after the home signed a newer head: more distinct head envelopes than a
    // view takes.
    let passes = MAX_VIEW_HEADS as i64 + 16;
    let mut served: BTreeSet<Vec<u8>> = BTreeSet::new();
    let mut at = NOW;
    for i in 0..passes {
        at = NOW + i * 150_000;
        relay.set_clock(at);
        served.insert(canonical(&fresh_head(&relay, &colophon_core::v05::write::format_date(at))));
        let faults = relay_pass(&mut phone, &src, &home, &mut wire, &host, at);
        assert!(faults.is_empty(), "pass {i}: {faults:?}");
        let held = phone.account().objects().heads.len();
        assert!(held <= PRUNE_HEADS_AT + 1, "pass {i}: the account holds {held} heads");
    }
    assert!(served.len() > MAX_VIEW_HEADS, "the home served {} heads", served.len());

    // A device that held every head before 0.5.7: its account opens over all of them, prunes
    // them, and signs a call the home accepts.
    let mut objects = phone.account().objects().clone();
    objects.heads = served.iter().cloned().collect();
    // And a forged copy of the newest head, dated later with the old signature: it does not
    // displace the genuine one.
    let newest_bytes = served
        .iter()
        .max_by_key(|h| issued_of(h))
        .unwrap()
        .clone();
    let mut env: Value = serde_json::from_slice(&newest_bytes).unwrap();
    let mut body: Value = serde_json::from_slice(&STANDARD.decode(env["body"].as_str().unwrap()).unwrap()).unwrap();
    body["issued"] = Value::String(colophon_core::v05::write::format_date(at + 60_000));
    env["body"] = Value::String(STANDARD.encode(colophon_core::v05::encoding::canonical(&body).unwrap()));
    let forged = colophon_core::v05::encoding::canonical(&env).unwrap();
    objects.heads.push(forged.clone());
    assert!(objects.heads.len() > MAX_VIEW_HEADS);
    let mut old = Account::open(objects, vec![], None, Identity::Member(member.clone()), at).unwrap();
    let kept = old.objects().heads.clone();
    // At most three settled heads per claim (the home, the seq and the digest it names), and the
    // forgery, which is not settled and so is kept, as before.
    let claims: BTreeSet<(String, u64, String)> = served.iter().map(|h| claim_of(h)).collect();
    assert!(kept.len() <= 3 * claims.len() + 1, "healed to {} heads over {} claims", kept.len(), claims.len());
    assert!(kept.contains(&newest_bytes), "the home's newest genuine head is kept");
    assert!(kept.contains(&forged), "a head that does not verify is not judged here, only kept");
    let path = "/changes?limit=10";
    let call = HomeCall {
        audience: BASE_A.to_string(),
        method: "GET".into(),
        path: path.into(),
        body_sha256: colophon_core::v05::write::calls::EMPTY_BODY_SHA256.into(),
        as_of: None,
    };
    let key = host.ids[&member].public().signing;
    let action = old.begin_home_call(&key, &call, fresh_request_id()).unwrap();
    let done = run(&mut old, &host, action);
    let envelope = done.artifact.expect("a call");
    let auth = vec![(
        "Authorization".to_string(),
        format!("Colophon {}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&envelope)),
    )];
    let (status, _, body) = http(relay.port, "GET", &relay.url(path), &auth, &[]);
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));

    // Its persisted state keeps only those heads: a relaunch from it does not bring them back.
    let saved = old.export_persisted(&[7u8; 32], [9u8; 32]).unwrap();
    let mut given = old.objects().clone();
    given.heads = kept.clone();
    let again = Account::open(given, vec![], Some((&saved, &[7u8; 32])), Identity::Member(member), at).unwrap();
    assert_eq!(again.objects().heads, kept, "the relaunch holds the pruned heads only");
}
