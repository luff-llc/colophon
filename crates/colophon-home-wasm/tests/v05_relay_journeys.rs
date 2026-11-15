//! The two journeys of `v05_engine_journeys.rs`, with the REAL relay (`relay/server.js` on Bun, the Rust
//! home module in WebAssembly) in place of the simulated home. The engine is sans-IO: this test
//! performs each request it asks for over localhost HTTP.
#![allow(
    clippy::unwrap_used,
    clippy::too_many_arguments,
    clippy::cloned_ref_to_slice_refs
)]
#[path = "../../colophon-core/tests/v05_engine_support/mod.rs"]
mod support;
mod support_relay;
use support_relay::*;
use colophon_core::blobs::BlobRead;
use colophon_core::model::Outcome;
use colophon_core::v05::account::RevokeKeep;
use colophon_core::v05::engine::blobs::BlobAvailability;
use colophon_core::v05::engine::exchange::{Fault, Step};
use serde_json::{json, Value};
use support::*;

const NOW: i64 = T0 + 3 * HOUR;
const LISTEN: &str = "listening.podcasts";
const SAVED: &str = "reading.saved";

fn listed(relay: &Relay) -> Vec<String> {
    let (status, _, body) = http(relay.port, "GET", &relay.url("/changes?limit=1000"), &Relay::bearer(), &[]);
    assert_eq!(status, 200);
    serde_json::from_slice::<Value>(&body).unwrap()["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["path"].as_str().unwrap().to_string())
        .collect()
}

fn q(
    e: &colophon_core::v05::engine::Engine<MemSource>,
    ns: &str,
    name: &str,
    args: Value,
) -> Value {
    match e.query(ns, name, args).unwrap() {
        Outcome::Success { value, .. } => value["value"].clone(),
        Outcome::Failure { reason, detail, .. } => panic!("{reason}: {detail}"),
    }
}

/// An account whose home is the real relay, with the history uploaded to it (the first upload).
struct Setup {
    f: Fixture,
    home: String,
    relay: Relay,
    keys: HomeKeys,
    authority: MemSource,
}
fn setup(ns: &str, members: &[(&str, u8, &str)]) -> Option<(Setup, Vec<String>)> {
    prerequisites()?;
    let keys = HomeKeys::new(0x77);
    let mut f = create_public(&[ns]);
    let home = appoint_home_keys(&mut f, &keys, BASE_A);
    let mut ids = Vec::new();
    for (label, seed, access) in members {
        let id = f.host.identity(*seed);
        admit(
            &mut f,
            &id,
            label,
            "device",
            terms_for(&[(ns, access)]),
            terms_for(&[(ns, access)]),
        );
        ids.push(id);
    }
    let authority = MemSource::new();
    authority.store_account(&f.account);
    let dir = std::env::temp_dir().join(format!("colophon-relay-journey-{}-{}", std::process::id(), ns));
    let _ = std::fs::remove_dir_all(&dir);
    let relay = Relay::start(&keys, BASE_A, &dir, f.account.now_ms(), &[]);
    first_upload(&relay, &f, f.account.now_ms() + 1_000);
    Some((Setup { f, home, relay, keys, authority }, ids))
}
fn open_saved(
    f: &Fixture,
    host: &Host,
    src: &MemSource,
    member: &str,
    saved: &colophon_core::v05::engine::Saved,
    now_ms: i64,
) -> colophon_core::v05::engine::Engine<MemSource> {
    let mut e = colophon_core::v05::engine::Engine::open(
        src.clone(),
        src.listing(),
        colophon_core::v05::account::Identity::Member(member.to_string()),
        colophon_core::v05::engine::EngineOptions::new(f.account.id().as_str(), DEVICE_KEY),
        Some(saved),
        now_ms,
    )
    .unwrap();
    assert_eq!(
        *e.open_mode(),
        colophon_core::v05::engine::OpenMode::Resumed
    );
    let steps = e.begin_unlock_epochs();
    e.finish_unlock_epochs(host.answer_epochs(member, steps))
        .unwrap();
    e
}
fn device_source(s: &Setup) -> MemSource {
    let src = MemSource::new();
    for p in s.authority.listing() {
        src.put(&p, s.authority.get(&p).unwrap());
    }
    src
}

#[test]
fn journey_listening_two_devices_a_live_position_a_transcript_and_an_offline_device() {
    let Some((mut s, ids)) = setup(LISTEN, &[("Phone", 31, "write"), ("Laptop", 32, "write")]) else { return };
    let mut wire = RealRelay::new(&s.relay);
    let (phone_id, laptop_id) = (ids[0].clone(), ids[1].clone());
    let (phone_src, laptop_src) = (device_source(&s), device_source(&s));
    let mut phone = member_engine(&s.f, &s.f.host, &phone_src, &phone_id, NOW);
    let mut laptop = member_engine(&s.f, &s.f.host, &laptop_src, &laptop_id, NOW);
    let mut host = std::mem::replace(&mut s.f.host, Host::new());
    let home = s.home.clone();

    // The phone: a follow, a queue, a transcript blob, a live position at 100 s.
    engine_write(
        &mut phone,
        &mut host,
        &phone_src,
        LISTEN,
        "follow",
        json!({"id": "show", "url": "https://example.org/feed", "title": "The Show"}),
    );
    engine_write(
        &mut phone,
        &mut host,
        &phone_src,
        LISTEN,
        "queue",
        json!({"episodes": ["e1", "e2"]}),
    );
    let transcript_text = "the quick brown fox ".repeat(5_000); // 100 000 bytes: two chunks
    let transcript = engine_blob(
        &mut phone,
        &mut host,
        &phone_src,
        LISTEN,
        "text/plain",
        transcript_text.as_bytes(),
        "transcript:e1",
        true,
    );
    let w = engine_live(
        &mut phone,
        &mut host,
        &phone_src,
        json!({"id": "e1", "show": "show", "seconds": 100.0}),
    );
    assert!(
        w.stores.iter().any(|(p, _)| p.starts_with("history/")),
        "evidence first"
    );
    assert!(
        w.stores.last().unwrap().0.starts_with("state/"),
        "then the slot"
    );
    assert_eq!(phone.account().live_heads().len(), 1);
    let faults = sync_pass(&mut phone, &phone_src, &home, &mut wire, &host, NOW);
    assert!(faults.is_empty(), "{faults:?}");
    assert!(
        listed(&s.relay).iter().any(|p| p.starts_with("state/")),
        "the slot is on the home"
    );
    assert!(
        listed(&s.relay).iter().any(|p| p.starts_with("blobs/")),
        "the chunks are on the home"
    );

    // The laptop was offline all this time. It writes on its own: a queue edit and a live
    // position at 250 s, a later sample than the phone's.
    engine_write(
        &mut laptop,
        &mut host,
        &laptop_src,
        LISTEN,
        "queue",
        json!({"episodes": ["e2", "e1", "e3"]}),
    );
    engine_live(
        &mut laptop,
        &mut host,
        &laptop_src,
        json!({"id": "e1", "show": "show", "seconds": 250.0}),
    );

    // It comes online: the pass pulls the phone's records and slot, pushes its own.
    let faults = sync_pass(
        &mut laptop,
        &laptop_src,
        &home,
        &mut wire,
        &host,
        NOW + 1_000,
    );
    assert!(faults.is_empty(), "{faults:?}");
    // The phone syncs again and sees the laptop.
    let faults = sync_pass(
        &mut phone,
        &phone_src,
        &home,
        &mut wire,
        &host,
        NOW + 2_000,
    );
    assert!(faults.is_empty(), "{faults:?}");
    // Reload the engines from their stores, as a restart would, so reads come from the source.
    let phone2 = member_engine(&s.f, &host, &phone_src, &phone_id, NOW + 3_000);
    let laptop2 = member_engine(&s.f, &host, &laptop_src, &laptop_id, NOW + 3_000);

    // Both devices hold both live slots and the same state.
    assert_eq!(
        phone2.account().live_heads().len(),
        2,
        "one slot per device"
    );
    assert_eq!(laptop2.account().live_heads().len(), 2);
    let a = q(&phone2, LISTEN, "episode", json!({"id": "e1"}));
    let b = q(&laptop2, LISTEN, "episode", json!({"id": "e1"}));
    assert_eq!(a, b, "positions converge");
    assert!(a["row"]["seconds"].as_f64().is_some());
    assert_eq!(phone2.revision(LISTEN), laptop2.revision(LISTEN));
    // The queue edit that sorts last wins on both.
    assert_eq!(
        q(&phone2, LISTEN, "queue", json!({})),
        q(&laptop2, LISTEN, "queue", json!({}))
    );
    // The transcript is on the laptop: fetched, authenticated and verified whole.
    match laptop2.read_blob(LISTEN, &transcript.digest).unwrap() {
        BlobRead::Available(b) => assert_eq!(b, transcript_text.as_bytes()),
        other => panic!("{other:?}"),
    }
    assert_eq!(
        laptop2
            .blob_availability(LISTEN, &transcript.digest)
            .unwrap(),
        BlobAvailability::Complete
    );
    // One more pass moves nothing: nothing is pushed twice, nothing is pulled again.
    let before = wire.requests.len();
    let mut laptop3 = laptop2;
    let faults = sync_pass(
        &mut laptop3,
        &laptop_src,
        &home,
        &mut wire,
        &host,
        NOW + 4_000,
    );
    assert!(faults.is_empty(), "{faults:?}");
    let new: Vec<&String> = wire.requests[before..]
        .iter()
        .filter(|r| r.starts_with("Put") || r.starts_with("Post /authority"))
        .collect();
    assert!(new.is_empty(), "an idle pass pushes nothing: {new:?}");
}

#[test]
fn journey_reading_a_required_original_an_optional_image_and_a_revoked_device() {
    let Some((mut s, ids)) = setup(
        SAVED,
        &[
            ("Phone", 41, "write"),
            ("Tablet", 42, "write"),
            ("Old", 43, "write"),
        ],
    ) else { return };
    let mut wire = RealRelay::new(&s.relay);
    let (phone_id, tablet_id, old_id) = (ids[0].clone(), ids[1].clone(), ids[2].clone());
    let (phone_src, tablet_src, old_src) =
        (device_source(&s), device_source(&s), device_source(&s));
    let ctl_src = device_source(&s);
    let mut phone = member_engine(&s.f, &s.f.host, &phone_src, &phone_id, NOW);
    let mut tablet = member_engine(&s.f, &s.f.host, &tablet_src, &tablet_id, NOW);
    let mut old = member_engine(&s.f, &s.f.host, &old_src, &old_id, NOW);
    let mut host = std::mem::replace(&mut s.f.host, Host::new());
    let home = s.home.clone();

    // Save an item: the original (required) and an image (optional), then the source.
    engine_write(
        &mut phone,
        &mut host,
        &phone_src,
        SAVED,
        "capture",
        json!({"id": "item", "title": "A long read", "url": "https://example.org/read"}),
    );
    let original_bytes = b"%PDF-1.7 synthetic original ".repeat(4_000);
    let original = engine_blob(
        &mut phone,
        &mut host,
        &phone_src,
        SAVED,
        "text/plain",
        &original_bytes,
        "source",
        true,
    );
    let metadata = engine_blob(
        &mut phone,
        &mut host,
        &phone_src,
        SAVED,
        "application/json",
        b"{\"pages\":1}",
        "source",
        true,
    );
    let image_bytes = vec![0x89u8; 70_000];
    let image = engine_blob(
        &mut phone,
        &mut host,
        &phone_src,
        SAVED,
        "image/png",
        &image_bytes,
        "image:item",
        false,
    );
    let mut manifest = json!({"id": "pending",
        "metadata": {"digest": metadata.digest, "size": metadata.size, "mediaType": "application/json"},
        "original": {"digest": original.digest, "size": original.size, "mediaType": "text/plain"},
        "mediaType": "text/plain", "origin": {"kind": "file"},
        "capturedAt": "2026-11-06T00:00:00Z", "extractionVersion": 1, "coverage": "complete"});
    manifest["id"] = json!(colophon_core::domains::saved::source_id(&manifest).unwrap());
    engine_write(
        &mut phone,
        &mut host,
        &phone_src,
        SAVED,
        "retainSource",
        json!({"id": manifest["id"], "item": "item", "manifest": manifest, "select": true, "expect": null}),
    );
    let faults = sync_pass(&mut phone, &phone_src, &home, &mut wire, &host, NOW);
    assert!(faults.is_empty(), "{faults:?}");

    // The old device writes an item of its own, and syncs it.
    engine_write(
        &mut old,
        &mut host,
        &old_src,
        SAVED,
        "capture",
        json!({"id": "from-old", "title": "Written by a device later revoked"}),
    );
    let faults = sync_pass(&mut old, &old_src, &home, &mut wire, &host, NOW + 500);
    assert!(faults.is_empty(), "{faults:?}");

    // The tablet reads: the item, the required original (fetched in the pass), not yet the image.
    let faults = sync_pass(
        &mut tablet,
        &tablet_src,
        &home,
        &mut wire,
        &host,
        NOW + 1_000,
    );
    assert!(faults.is_empty(), "{faults:?}");
    // The tablet restarts from its sealed state: cursors and the remote set come back with it.
    let saved = tablet.save([21; 32]).unwrap();
    let mut tablet = open_saved(&s.f, &host, &tablet_src, &tablet_id, &saved, NOW + 1_500);
    assert_eq!(
        q(&tablet, SAVED, "item", json!({"id": "item"}))["item"]["title"],
        "A long read"
    );
    assert_eq!(
        q(&tablet, SAVED, "item", json!({"id": "from-old"}))["item"]["title"],
        "Written by a device later revoked"
    );
    match tablet.read_blob(SAVED, &original.digest).unwrap() {
        BlobRead::Available(b) => assert_eq!(b, original_bytes),
        other => panic!("{other:?}"),
    }
    assert_eq!(
        tablet.blob_availability(SAVED, &image.digest).unwrap(),
        BlobAvailability::Missing,
        "an optional blob is not fetched eagerly"
    );
    // On first read it is fetched, lazily, through the home.
    let n = tablet
        .exchange_want_blob(&home, SAVED, &image.digest)
        .unwrap();
    assert_eq!(n, 2, "70 000 bytes are two chunks");
    while let Step::Request(r) = tablet.exchange_next(&home).unwrap() {
        let a = wire.call(&host, &r, NOW + 2_000);
        let rep = tablet.exchange_answer(&home, r.ticket, a).unwrap();
        assert!(rep.faults.is_empty());
        tablet_src.publish_stores(&rep.store);
    }
    match tablet.read_blob(SAVED, &image.digest).unwrap() {
        BlobRead::Available(b) => assert_eq!(b, image_bytes),
        other => panic!("{other:?}"),
    }

    // The account revokes the old device, keeping what it wrote. A controller session does it.
    let mut ctl = controller_engine(&s.f, &host, &ctl_src, &s.f.d.clone(), NOW + 3_000);
    // The controller catches up with the home first: the old device's records are what `kept`
    // names (the heads are of what the controller holds).
    let faults = sync_pass(&mut ctl, &ctl_src, &home, &mut wire, &host, NOW + 3_000);
    assert!(faults.is_empty(), "{faults:?}");
    let seed = host.fresh();
    let action = ctl
        .account()
        .begin_revoke(&old_id, &RevokeKeep::Everything, &[s.f.d.clone()], seed)
        .unwrap();
    engine_finish(&mut ctl, &host, &ctl_src, action);
    let faults = sync_pass(&mut ctl, &ctl_src, &home, &mut wire, &host, NOW + 4_000);
    assert!(faults.is_empty(), "{faults:?}");
    assert_eq!(s.relay.get("/head").0, 200, "the home signed a head");

    // The tablet syncs and sees the revocation: the old device's kept record is still there.
    let faults = sync_pass(
        &mut tablet,
        &tablet_src,
        &home,
        &mut wire,
        &host,
        NOW + 5_000,
    );
    assert!(faults.is_empty(), "{faults:?}");
    let tablet = member_engine(&s.f, &host, &tablet_src, &tablet_id, NOW + 5_500);
    assert!(tablet
        .members()
        .iter()
        .any(|m| m.member.id == old_id && m.member.revoked_at.is_some()));
    assert_eq!(
        q(&tablet, SAVED, "item", json!({"id": "from-old"}))["item"]["title"],
        "Written by a device later revoked",
        "kept records stay"
    );
    // The revoked device cannot read what follows: the new epoch is not sealed to it.
    let old_after = {
        let src = device_source(&s);
        for p in tablet_src
            .listing()
            .iter()
            .filter(|p| p.starts_with("authority/"))
        {
            src.put(p, tablet_src.get(p).unwrap());
        }
        let mut e = colophon_core::v05::engine::Engine::open(
            src.clone(),
            src.listing(),
            colophon_core::v05::account::Identity::Member(old_id.clone()),
            colophon_core::v05::engine::EngineOptions::new(s.f.account.id().as_str(), DEVICE_KEY),
            None,
            NOW + 6_000,
        )
        .unwrap();
        let steps = e.begin_unlock_epochs();
        assert!(
            steps.is_empty(),
            "no share of the new epoch is addressed to the revoked device"
        );
        e.load().unwrap();
        e
    };
    assert_eq!(old_after.access(SAVED).unwrap().unwrap().reason, "revoked");
    let _ = Fault::Rollback {
        home: String::new(),
    };
}
