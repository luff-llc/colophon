//! Colophon 0.3: namespaced paths, live playback state, layout authority and cache rules.
#![allow(clippy::unwrap_used)]
mod support;
use colophon_core::{crypto::SoftwareKeys, library::Library, protocol, Result};
use serde_json::json;
use support::*;

fn owner_lib() -> (Library, SoftwareKeys, SoftwareKeys) {
    let (lib, owner, recovery) = create();
    (lib, owner, recovery)
}
fn episode_seconds(lib: &Library, id: &str) -> f64 {
    let view = success(lib.view("listening.podcasts", NOW).unwrap());
    let episodes = &view.state["episodes"];
    let row = episodes.get(id).cloned().or_else(|| {
        episodes
            .as_array()
            .and_then(|rows| rows.iter().find(|episode| episode["id"] == id).cloned())
    });
    let row = row.unwrap_or_else(|| panic!("missing episode {id}: {episodes}"));
    row["seconds"].as_f64().expect("episode seconds")
}

#[test]
fn new_operations_use_namespaced_paths() {
    let (mut lib, owner, _) = owner_lib();
    write(
        &mut lib,
        &owner,
        "notes",
        "createNotebook",
        json!({"id":"n","title":"N"}),
        20,
    );
    let path = lib
        .records()
        .keys()
        .find(|p| p.starts_with("ops/"))
        .cloned()
        .unwrap();
    assert!(path.contains("/notes/"), "{path}");
    assert_eq!(
        protocol::path_scope(&path),
        Some(protocol::PathScope::Namespace("notes"))
    );
}

#[test]
fn header_namespace_must_match_path() {
    let (mut lib, owner, _) = owner_lib();
    write(
        &mut lib,
        &owner,
        "notes",
        "createNotebook",
        json!({"id":"n","title":"N"}),
        21,
    );
    let (path, bytes) = lib
        .records()
        .iter()
        .find(|(p, _)| p.starts_with("ops/"))
        .map(|(p, b)| (p.clone(), b.clone()))
        .unwrap();
    let forged = path.replace("/notes/", "/listening.podcasts/");
    let mut records = lib.records().clone();
    records.remove(&path);
    records.insert(forged, bytes);
    let opened = opened(records, &owner);
    let view = success(opened.view("notes", NOW).unwrap());
    assert!(
        view.admitted.is_empty(),
        "mismatched namespace path must not be admitted: {:?}",
        view.admitted
    );
}

#[test]
fn missing_other_namespace_does_not_block() {
    let (mut root, owner, _) = owner_lib();
    write(
        &mut root,
        &owner,
        "notes",
        "createNotebook",
        json!({"id":"n","title":"N"}),
        22,
    );
    write(
        &mut root,
        &owner,
        "listening.podcasts",
        "follow",
        json!({"id":"show","url":"https://example.org/feed.xml"}),
        23,
    );
    let mut subset = root.records().clone();
    subset.retain(|p, _| protocol::listing_includes(p, &["notes".into()]));
    let notes_only = opened(subset, &owner);
    let view = success(notes_only.view("notes", NOW).unwrap());
    let notebooks = &view.state["notebooks"];
    let present = notebooks
        .as_array()
        .map(|rows| rows.iter().any(|n| n["id"] == "n"))
        .or_else(|| notebooks.as_object().map(|m| m.contains_key("n")))
        .unwrap_or(false);
    assert!(
        present,
        "notes fold must succeed without listening records: {notebooks}"
    );
}

#[test]
fn legacy_flat_ops_remain_readable() {
    let (mut lib, owner, _) = owner_lib();
    write(
        &mut lib,
        &owner,
        "notes",
        "createNotebook",
        json!({"id":"n","title":"N"}),
        24,
    );
    let (path, bytes) = lib
        .records()
        .iter()
        .find(|(p, _)| p.starts_with("ops/"))
        .map(|(p, b)| (p.clone(), b.clone()))
        .unwrap();
    let meta_author = path.split('/').nth(1).unwrap();
    let file = path.rsplit('/').next().unwrap();
    let legacy = format!("ops/{meta_author}/{file}");
    let mut records = lib.records().clone();
    records.remove(&path);
    records.insert(legacy.clone(), bytes);
    let opened = opened(records, &owner);
    let view = success(opened.view("notes", NOW).unwrap());
    let notebooks = &view.state["notebooks"];
    let present = notebooks
        .as_array()
        .map(|rows| rows.iter().any(|n| n["id"] == "n"))
        .or_else(|| notebooks.as_object().map(|m| m.contains_key("n")))
        .unwrap_or(false);
    assert!(present, "legacy flat path must fold: {notebooks}");
}

#[test]
fn live_position_rebuilds_without_episode_parent() {
    let (mut lib, owner, _) = owner_lib();
    write(
        &mut lib,
        &owner,
        "listening.podcasts",
        "position",
        json!({"id":"ep0","seconds":0}),
        10,
    );
    assert_eq!(episode_seconds(&lib, "ep0"), 0.0);
    let rebuilt = opened(lib.records().clone(), &owner);
    assert_eq!(episode_seconds(&rebuilt, "ep0"), 0.0);
}

#[test]
fn new_library_writes_layout_two() {
    let (lib, _, _) = owner_lib();
    assert_eq!(lib.authority().layout, protocol::LAYOUT);
    assert!(lib.records().contains_key("authority/00000003.json"));
}

#[test]
fn unsupported_layout_is_explicit() {
    let (lib, owner, _) = owner_lib();
    let pending = success(lib.begin_layout(99, NOW).unwrap());
    let extra = finish(pending, &owner);
    let mut records = lib.records().clone();
    records.extend(extra);
    let err = match Library::open(records, owner.public()) {
        Err(error) => error,
        Ok(_) => panic!("layout 99 was admitted"),
    };
    assert!(protocol::is_unsupported_layout(&err), "{}", err.0);
}

#[test]
fn passive_position_uses_live_state() {
    let (mut lib, owner, _) = owner_lib();
    write(
        &mut lib,
        &owner,
        "listening.podcasts",
        "follow",
        json!({"id":"show-live","url":"https://example.org/feed.xml"}),
        30,
    );
    write(
        &mut lib,
        &owner,
        "listening.podcasts",
        "episode",
        json!({"id":"episode-live","show":"show-live","title":"Live"}),
        31,
    );
    write(
        &mut lib,
        &owner,
        "listening.podcasts",
        "position",
        json!({"id":"episode-live","seconds":12}),
        32,
    );
    let slot = protocol::live_slot_name("episode-live");
    let state = protocol::live_state_path(&owner.public().id(), "listening.podcasts", &slot);
    assert!(
        lib.records().contains_key(&state),
        "{:?}",
        lib.records().keys().collect::<Vec<_>>()
    );
    assert!(lib
        .records()
        .keys()
        .any(|p| p.starts_with("history/") && p.contains("listening.podcasts")));
    assert_eq!(episode_seconds(&lib, "episode-live"), 12.0);
    write(
        &mut lib,
        &owner,
        "listening.podcasts",
        "position",
        json!({"id":"episode-live","seconds":40}),
        33,
    );
    let history = lib
        .records()
        .keys()
        .filter(|p| p.starts_with("history/"))
        .count();
    assert_eq!(
        episode_seconds(&lib, "episode-live"),
        40.0,
        "history files={history} refused={:?} held={:?} state={:?}",
        success(lib.view("listening.podcasts", NOW).unwrap()).refused,
        success(lib.view("listening.podcasts", NOW).unwrap()).held,
        success(lib.view("listening.podcasts", NOW).unwrap()).state["episodes"]
    );
    let live_files = lib
        .records()
        .keys()
        .filter(|p| p.starts_with("state/"))
        .count();
    assert_eq!(live_files, 1);
    let rebuilt = opened(lib.records().clone(), &owner);
    assert_eq!(
        episode_seconds(&rebuilt, "episode-live"),
        40.0,
        "reopen must apply live state; refused={:?} held={:?} admitted={}",
        success(rebuilt.view("listening.podcasts", NOW).unwrap()).refused,
        success(rebuilt.view("listening.podcasts", NOW).unwrap()).held,
        success(rebuilt.view("listening.podcasts", NOW).unwrap())
            .admitted
            .len()
    );
}

#[test]
fn seek_stays_immutable_and_preserves_live_predecessor() {
    let (mut lib, owner, _) = owner_lib();
    write(
        &mut lib,
        &owner,
        "listening.podcasts",
        "follow",
        json!({"id":"show","url":"https://example.org/feed.xml"}),
        40,
    );
    write(
        &mut lib,
        &owner,
        "listening.podcasts",
        "episode",
        json!({"id":"ep","show":"show","title":"E"}),
        41,
    );
    write(
        &mut lib,
        &owner,
        "listening.podcasts",
        "position",
        json!({"id":"ep","seconds":12.0}),
        42,
    );
    let before = lib
        .records()
        .keys()
        .filter(|p| p.starts_with("ops/"))
        .count();
    write(
        &mut lib,
        &owner,
        "listening.podcasts",
        "position",
        json!({"id":"ep","seconds":3.0,"seek":true}),
        43,
    );
    let after = lib
        .records()
        .keys()
        .filter(|p| p.starts_with("ops/"))
        .count();
    assert!(
        after > before,
        "seek and retained predecessor must be immutable"
    );
    assert_eq!(episode_seconds(&lib, "ep"), 3.0);
}

#[test]
fn revoked_writer_live_state_is_ignored() -> Result<()> {
    let (mut root, owner, _) = owner_lib();
    let device = keys(2);
    enroll(
        &mut root,
        &owner,
        &device,
        "Phone",
        colophon_core::model::MemberKind::Device,
        grant(&["listening.podcasts"], None),
        50,
    );
    let mut phone = opened(root.records().clone(), &device);
    write(
        &mut phone,
        &device,
        "listening.podcasts",
        "follow",
        json!({"id":"show","url":"https://example.org/feed.xml"}),
        51,
    );
    write(
        &mut phone,
        &device,
        "listening.podcasts",
        "episode",
        json!({"id":"ep","show":"show","title":"E"}),
        52,
    );
    write(
        &mut phone,
        &device,
        "listening.podcasts",
        "position",
        json!({"id":"ep","seconds":9.0}),
        53,
    );
    root.merge(phone.records().clone())?;
    let id = device.public().id();
    let pending = success(root.begin_revoke(&id, NOW, [9; 32]).unwrap());
    apply(&mut root, pending, &owner);
    let view = success(root.view("listening.podcasts", NOW).unwrap());
    assert!(
        view.state["episodes"]
            .get("ep")
            .and_then(|e| e.get("seconds"))
            .is_none()
            || view.state["episodes"]["ep"]["seconds"] != 9.0
            || view.state["episodes"]["ep"].is_null(),
        "revoked live slot must not supply current position: {}",
        view.state
    );
    Ok(())
}

#[test]
fn checkpoint_equivocation_and_namespace_listing() {
    use colophon_core::engine::{Engine, EngineOptions, RecordSource};
    use std::cell::RefCell;
    use std::rc::Rc;
    #[derive(Clone)]
    struct Source(Rc<RefCell<colophon_core::model::Records>>);
    impl RecordSource for Source {
        fn read(&self, path: &str) -> Result<Vec<u8>> {
            self.0
                .borrow()
                .get(path)
                .cloned()
                .ok_or_else(|| colophon_core::Error(format!("Missing record {path}")))
        }
    }
    let (mut lib, owner, _) = owner_lib();
    write(
        &mut lib,
        &owner,
        "notes",
        "createNotebook",
        json!({"id": "n", "title": "N"}),
        60,
    );
    let source = Source(Rc::new(RefCell::new(lib.records().clone())));
    let listing: Vec<String> = source.0.borrow().keys().cloned().collect();
    let options = EngineOptions {
        library_id: lib.id().into(),
        checkpoint_key: [9; 32],
        content_cache_bytes: 1024,
        namespaces: vec!["notes".into()],
    };
    let mut engine = Engine::open(
        source.clone(),
        listing.clone(),
        owner.public(),
        options.clone(),
        None,
    )
    .unwrap();
    let results: Vec<_> = engine
        .begin_unlock()
        .into_iter()
        .map(|s| (s.namespace, s.epoch, owner.agree(&s.peer).unwrap()))
        .collect();
    engine.finish_unlock_many(results).unwrap();
    let checkpoint = engine.checkpoint().unwrap();
    let path = listing
        .iter()
        .find(|p| p.starts_with("ops/"))
        .cloned()
        .unwrap();
    source.0.borrow_mut().get_mut(&path).unwrap().push(b' ');
    let mut tampered = Engine::open(
        source.clone(),
        listing.clone(),
        owner.public(),
        options,
        Some(&checkpoint),
    )
    .unwrap();
    let results: Vec<_> = tampered
        .begin_unlock()
        .into_iter()
        .map(|s| (s.namespace, s.epoch, owner.agree(&s.peer).unwrap()))
        .collect();
    tampered.finish_unlock_many(results).unwrap();
    let error = tampered.verify_batch(100).unwrap_err();
    assert!(
        protocol::is_equivocation(&error),
        "changed immutable bytes must be equivocation: {error}"
    );
    let notes_listing: Vec<String> = listing
        .into_iter()
        .filter(|p| protocol::listing_includes(p, &["notes".into()]))
        .collect();
    assert!(
        notes_listing
            .iter()
            .all(|p| !p.contains("/listening.podcasts/")),
        "notes listing must exclude the listening namespace"
    );
}

#[test]
fn live_replacement_preserves_causal_rewind_and_deliberate_barriers() {
    let (mut lib, owner, _) = create();
    write(
        &mut lib,
        &owner,
        "listening.podcasts",
        "position",
        json!({"id":"e","seconds":100}),
        91,
    );
    let head = success(
        lib.query("listening.podcasts", "getEpisode", json!({"id":"e"}), NOW)
            .unwrap(),
    )["positionRevision"]
        .clone();
    write(
        &mut lib,
        &owner,
        "listening.podcasts",
        "position",
        json!({"id":"e","seconds":20,"expect":head}),
        92,
    );
    assert_eq!(episode_seconds(&lib, "e"), 20.0);
    assert_eq!(
        episode_seconds(&opened(lib.records().clone(), &owner), "e"),
        20.0
    );
    assert_eq!(
        lib.records()
            .keys()
            .filter(|p| p.starts_with("ops/"))
            .count(),
        0
    );
    write(
        &mut lib,
        &owner,
        "listening.podcasts",
        "position",
        json!({"id":"e","seconds":3,"seek":true}),
        93,
    );
    assert_eq!(
        episode_seconds(&opened(lib.records().clone(), &owner), "e"),
        3.0
    );
}

#[test]
fn forged_live_signature_and_stale_generation_never_supply_current_state() {
    use colophon_core::records::SignedRecord;
    let (mut lib, owner, _) = create();
    write(
        &mut lib,
        &owner,
        "listening.podcasts",
        "position",
        json!({"id":"e","seconds":10}),
        94,
    );
    let (path, old) = lib
        .records()
        .iter()
        .find(|(p, _)| p.starts_with("state/"))
        .map(|(p, b)| (p.clone(), b.clone()))
        .unwrap();
    write(
        &mut lib,
        &owner,
        "listening.podcasts",
        "position",
        json!({"id":"e","seconds":20}),
        95,
    );
    lib.merge([(path.clone(), old)].into()).unwrap();
    assert_eq!(episode_seconds(&lib, "e"), 20.0);
    let mut forged: SignedRecord = serde_json::from_slice(&lib.records()[&path]).unwrap();
    forged.signature[0] ^= 1;
    let mut records = lib.records().clone();
    records.insert(path, forged.encode().unwrap());
    let reader = opened(records, &owner);
    let episode = success(
        reader
            .query("listening.podcasts", "getEpisode", json!({"id":"e"}), NOW)
            .unwrap(),
    );
    assert!(episode.is_null(), "unverified live overlay: {episode}");
}

#[test]
fn storage_engine_live_refresh_checkpoint_and_revocation_match_library() {
    use colophon_core::engine::{Engine, EngineOptions, RecordSource};
    use std::{cell::RefCell, rc::Rc};
    #[derive(Clone)]
    struct Source(Rc<RefCell<colophon_core::model::Records>>);
    impl RecordSource for Source {
        fn read(&self, path: &str) -> Result<Vec<u8>> {
            self.0
                .borrow()
                .get(path)
                .cloned()
                .ok_or_else(|| colophon_core::Error("missing".into()))
        }
    }
    let (mut lib, owner, _) = create();
    let phone = keys(2);
    enroll(
        &mut lib,
        &owner,
        &phone,
        "Phone",
        colophon_core::model::MemberKind::Device,
        grant(&["listening.podcasts"], None),
        96,
    );
    let mut writer = opened(lib.records().clone(), &phone);
    write(
        &mut writer,
        &phone,
        "listening.podcasts",
        "position",
        json!({"id":"e","seconds":10}),
        97,
    );
    lib.merge(writer.records().clone()).unwrap();
    let source = Source(Rc::new(RefCell::new(lib.records().clone())));
    let opts = EngineOptions {
        library_id: lib.id().into(),
        checkpoint_key: [3; 32],
        content_cache_bytes: 1024,
        namespaces: vec!["listening.podcasts".into()],
    };
    let open = |cache: Option<&[u8]>| {
        let listing = source.0.borrow().keys().cloned().collect();
        let mut engine =
            Engine::open(source.clone(), listing, owner.public(), opts.clone(), cache).unwrap();
        let shared = engine
            .begin_unlock()
            .into_iter()
            .map(|s| (s.namespace, s.epoch, owner.agree(&s.peer).unwrap()))
            .collect();
        engine.finish_unlock_many(shared).unwrap();
        engine
    };
    let mut engine = open(None);
    let query = |e: &Engine<Source>| {
        success(
            e.query("listening.podcasts", "getEpisode", json!({"id":"e"}), NOW)
                .unwrap(),
        )
    };
    assert_eq!(query(&engine)["seconds"], 10.0);
    write(
        &mut writer,
        &phone,
        "listening.podcasts",
        "position",
        json!({"id":"e","seconds":20}),
        98,
    );
    *source.0.borrow_mut() = writer.records().clone();
    engine
        .refresh(source.0.borrow().keys().cloned().collect())
        .unwrap();
    assert_eq!(query(&engine)["seconds"], 20.0);
    let cache = engine.checkpoint().unwrap();
    assert_eq!(query(&open(Some(&cache)))["seconds"], 20.0);
    lib.merge(writer.records().clone()).unwrap();
    let action = success(
        lib.begin_revoke(&phone.public().id(), NOW, [99; 32])
            .unwrap(),
    );
    apply(&mut lib, action, &owner);
    *source.0.borrow_mut() = lib.records().clone();
    engine
        .refresh(source.0.borrow().keys().cloned().collect())
        .unwrap();
    let shared = engine
        .begin_unlock()
        .into_iter()
        .map(|s| (s.namespace, s.epoch, owner.agree(&s.peer).unwrap()))
        .collect();
    engine.finish_unlock_many(shared).unwrap();
    assert!(
        query(&engine).is_null(),
        "revoked live position survived: {}",
        query(&engine)
    );
}

#[test]
fn provider_version_change_reverifies_and_detects_immutable_equivocation() {
    use colophon_core::engine::{Engine, EngineOptions, OpenMode, RecordSource};
    use std::{
        cell::{Cell, RefCell},
        rc::Rc,
    };
    #[derive(Clone)]
    struct Source {
        records: Rc<RefCell<colophon_core::model::Records>>,
        version: Rc<Cell<u32>>,
    }
    impl RecordSource for Source {
        fn read(&self, p: &str) -> Result<Vec<u8>> {
            Ok(self.records.borrow()[p].clone())
        }
        fn content_version(&self, _: &str) -> Result<Option<String>> {
            Ok(Some(self.version.get().to_string()))
        }
    }
    let (mut lib, owner, _) = create();
    write(
        &mut lib,
        &owner,
        "notes",
        "createNotebook",
        json!({"id":"n","title":"N"}),
        100,
    );
    let source = Source {
        records: Rc::new(RefCell::new(lib.records().clone())),
        version: Rc::new(Cell::new(1)),
    };
    let opts = EngineOptions {
        library_id: lib.id().into(),
        checkpoint_key: [7; 32],
        content_cache_bytes: 0,
        namespaces: vec!["notes".into()],
    };
    let open = |cache: Option<&[u8]>| {
        Engine::open(
            source.clone(),
            source.records.borrow().keys().cloned().collect(),
            owner.public(),
            opts.clone(),
            cache,
        )
    };
    let mut engine = open(None).unwrap();
    let shared = engine
        .begin_unlock()
        .into_iter()
        .map(|s| (s.namespace, s.epoch, owner.agree(&s.peer).unwrap()))
        .collect();
    engine.finish_unlock_many(shared).unwrap();
    let cache = engine.checkpoint().unwrap();
    source.version.set(2);
    assert!(matches!(
        open(Some(&cache)).unwrap().open_mode(),
        OpenMode::Invalidated(_)
    ));
    let path = source
        .records
        .borrow()
        .keys()
        .find(|p| p.starts_with("ops/"))
        .unwrap()
        .clone();
    source
        .records
        .borrow_mut()
        .get_mut(&path)
        .unwrap()
        .push(b' ');
    let mut engine = open(Some(&cache)).unwrap();
    let shared = engine
        .begin_unlock()
        .into_iter()
        .map(|s| (s.namespace, s.epoch, owner.agree(&s.peer).unwrap()))
        .collect();
    assert!(protocol::is_equivocation(
        &engine.finish_unlock_many(shared).unwrap_err()
    ));
}

#[test]
fn live_expiry_and_plaintext_slot_binding_are_checked_at_read_time() {
    use colophon_core::{
        model::{LiveStamp, OperationHeader},
        records::{canonical, SignedRecord},
    };
    let (mut lib, owner, _) = create();
    let phone = keys(2);
    let mut access = grant(&["listening.podcasts"], None);
    access.expires = Some("2026-11-08T00:00:00Z".into());
    enroll(
        &mut lib,
        &owner,
        &phone,
        "Phone",
        colophon_core::model::MemberKind::Device,
        access,
        110,
    );
    let mut writer = opened(lib.records().clone(), &phone);
    write(
        &mut writer,
        &phone,
        "listening.podcasts",
        "position",
        json!({"id":"e","seconds":12}),
        111,
    );
    // Caveated local writes correctly use immutable intent. Construct a signed live candidate
    // to verify the receiver's expiry check independently of that writer-side policy.
    let raw = writer
        .records()
        .iter()
        .find(|(p, _)| p.starts_with("ops/"))
        .unwrap()
        .1;
    let record: SignedRecord = serde_json::from_slice(raw).unwrap();
    let mut header: OperationHeader = serde_json::from_slice(&record.body).unwrap();
    let slot = protocol::live_slot_name("e");
    let path = protocol::live_state_path(&phone.public().id(), "listening.podcasts", &slot);
    header.live = Some(LiveStamp {
        library_id: lib.id().into(),
        slot,
        generation: header.meta.clock,
        operation_id: header.meta.id.clone(),
    });
    let body = canonical(&header).unwrap();
    lib.merge(
        [(
            path.clone(),
            SignedRecord {
                signature: phone.sign(&body),
                body,
            }
            .encode()
            .unwrap(),
        )]
        .into(),
    )
    .unwrap();
    assert!(success(lib.view("listening.podcasts", NOW).unwrap())
        .admitted
        .is_empty());
    // A retained copy cannot turn a caveated live stamp into durable intent either.
    let raw = lib.records()[&path].clone();
    lib.merge([(protocol::operation_path(&header.meta), raw)].into())
        .unwrap();
    assert!(success(lib.view("listening.podcasts", NOW).unwrap())
        .admitted
        .is_empty());
    let pending = success(
        lib.begin_write(
            "listening.podcasts",
            "follow",
            json!({"id":"show","url":"https://example.org/feed"}),
            NOW,
            [117; 32],
        )
        .unwrap(),
    );
    assert!(pending.copies.is_empty());
    let expired = success(
        lib.query(
            "listening.podcasts",
            "getEpisode",
            json!({"id":"e"}),
            "2026-11-09T00:00:00Z",
        )
        .unwrap(),
    );
    assert!(
        expired.is_null(),
        "expired live slot supplied current state"
    );
    header.live.as_mut().unwrap().slot = protocol::live_slot_name("different-episode");
    let body = canonical(&header).unwrap();
    let different = protocol::live_state_path(
        &phone.public().id(),
        "listening.podcasts",
        &header.live.as_ref().unwrap().slot,
    );
    let mut records = lib.records().clone();
    records.remove(&path);
    records.insert(
        different,
        SignedRecord {
            signature: phone.sign(&body),
            body,
        }
        .encode()
        .unwrap(),
    );
    let wrong = opened(records, &owner);
    assert!(success(
        wrong
            .query("listening.podcasts", "getEpisode", json!({"id":"e"}), NOW)
            .unwrap()
    )
    .is_null());
}

#[test]
fn live_overlay_rewinds_from_durable_baseline() {
    let (mut lib, owner, _) = create();
    write(
        &mut lib,
        &owner,
        "listening.podcasts",
        "position",
        json!({"id":"e","seconds":100,"seek":true}),
        112,
    );
    write(
        &mut lib,
        &owner,
        "listening.podcasts",
        "position",
        json!({"id":"e","seconds":200}),
        113,
    );
    let head = success(
        lib.query("listening.podcasts", "getEpisode", json!({"id":"e"}), NOW)
            .unwrap(),
    )["positionRevision"]
        .clone();
    write(
        &mut lib,
        &owner,
        "listening.podcasts",
        "position",
        json!({"id":"e","seconds":20,"expect":head}),
        114,
    );
    assert_eq!(
        episode_seconds(&opened(lib.records().clone(), &owner), "e"),
        20.0
    );
}

#[test]
fn checkpoint_key_is_member_sealed_signed_and_encrypts_private_state() {
    use colophon_core::checkpoint::{CheckpointOpening, PreparedCheckpointKey};
    use colophon_core::engine::{Engine, EngineOptions, OpenMode};
    let (lib, owner, _) = create();
    let prepared = PreparedCheckpointKey::new(lib.id(), owner.public(), [141; 32]).unwrap();
    let signature = owner.sign(prepared.signing_body());
    let key = prepared.finish(signature).unwrap();
    let mut options = EngineOptions {
        library_id: lib.id().into(),
        checkpoint_key: key.authentication_key(),
        namespaces: vec!["notes".into()],
        content_cache_bytes: 0,
    };
    let records = lib.records().clone();
    let listing: Vec<_> = records.keys().cloned().collect();
    let mut engine = Engine::open(
        records.clone(),
        listing.clone(),
        owner.public(),
        options.clone(),
        None,
    )
    .unwrap();
    let shared = engine
        .begin_unlock()
        .iter()
        .map(|s| (s.namespace.clone(), s.epoch, owner.agree(&s.peer).unwrap()))
        .collect();
    engine.finish_unlock_many(shared).unwrap();
    let checkpoint = engine.checkpoint().unwrap();
    let protected = key.protect(&checkpoint, [142; 32]).unwrap();
    let opening = CheckpointOpening::begin(&protected, lib.id(), &owner.public()).unwrap();
    let shared = owner.agree(opening.agreement_peer()).unwrap();
    let (restored, plaintext) = opening.finish(&shared).unwrap();
    assert_eq!(plaintext, checkpoint);
    options.checkpoint_key = restored.authentication_key();
    let reopened =
        Engine::open(records, listing, owner.public(), options, Some(&plaintext)).unwrap();
    assert_eq!(reopened.open_mode(), &OpenMode::VerifiedPrefix);
    assert!(CheckpointOpening::begin(&protected, "different-library", &owner.public()).is_err());
    assert!(CheckpointOpening::begin(&protected, lib.id(), &keys(143).public()).is_err());
    let opening = CheckpointOpening::begin(&protected, lib.id(), &owner.public()).unwrap();
    let wrong_shared = keys(143).agree(opening.agreement_peer()).unwrap();
    assert!(opening.finish(&wrong_shared).is_err());
    let prepared = PreparedCheckpointKey::new(lib.id(), owner.public(), [144; 32]).unwrap();
    let forged = keys(143).sign(prepared.signing_body());
    assert!(prepared.finish(forged).is_err());
    let mut corrupt: serde_json::Value = serde_json::from_slice(&protected).unwrap();
    let ciphertext = corrupt["ciphertext"].as_str().unwrap();
    corrupt["ciphertext"] = format!(
        "{}{}",
        if ciphertext.starts_with('A') {
            "B"
        } else {
            "A"
        },
        &ciphertext[1..]
    )
    .into();
    let opening = CheckpointOpening::begin(
        &serde_json::to_vec(&corrupt).unwrap(),
        lib.id(),
        &owner.public(),
    )
    .unwrap();
    let shared = owner.agree(opening.agreement_peer()).unwrap();
    assert!(opening.finish(&shared).is_err());
}

#[test]
fn partial_namespace_replica_never_undercounts_a_cross_namespace_budget() {
    use colophon_core::engine::{Engine, EngineOptions};
    let (mut root, owner, _) = create();
    let agent = keys(151);
    enroll(
        &mut root,
        &owner,
        &agent,
        "Capped",
        colophon_core::model::MemberKind::Agent,
        grant(&["notes", "listening.podcasts"], Some(1)),
        152,
    );
    let baseline = root.records().clone();
    let mut notes = opened(baseline.clone(), &agent);
    let mut podcasts = opened(baseline, &agent);
    write(
        &mut notes,
        &agent,
        "notes",
        "createNotebook",
        json!({"id":"capped","title":"Capped"}),
        153,
    );
    write(
        &mut podcasts,
        &agent,
        "listening.podcasts",
        "position",
        json!({"id":"e","seconds":1}),
        154,
    );
    root.merge(notes.records().clone()).unwrap();
    root.merge(podcasts.records().clone()).unwrap();
    let admitted = ["notes", "listening.podcasts"]
        .iter()
        .map(|ns| {
            success(root.view(ns, NOW).unwrap())
                .admitted
                .iter()
                .filter(|o| o.author == agent.public().id())
                .count()
        })
        .sum::<usize>();
    assert_eq!(admitted, 1);
    write(
        &mut root,
        &owner,
        "notes",
        "createNotebook",
        json!({"id":"root","title":"Root"}),
        155,
    );
    let records: colophon_core::model::Records = root
        .records()
        .iter()
        .filter(|(p, _)| protocol::listing_includes(p, &["notes".into()]))
        .map(|(p, b)| (p.clone(), b.clone()))
        .collect();
    let mut scoped = opened(records.clone(), &owner);
    scoped.set_read_scope(vec!["notes".into()]);
    let view = success(scoped.view("notes", NOW).unwrap());
    assert_eq!(
        view.admitted.len(),
        1,
        "Unrelated owner content remains usable"
    );
    assert_eq!(view.admitted[0].author, owner.public().id());
    let mut engine = Engine::open(
        records.clone(),
        records.keys().cloned().collect(),
        owner.public(),
        EngineOptions {
            library_id: root.id().into(),
            checkpoint_key: [156; 32],
            content_cache_bytes: 0,
            namespaces: vec!["notes".into()],
        },
        None,
    )
    .unwrap();
    let shared = engine
        .begin_unlock()
        .iter()
        .map(|s| (s.namespace.clone(), s.epoch, owner.agree(&s.peer).unwrap()))
        .collect();
    engine.finish_unlock_many(shared).unwrap();
    assert_eq!(
        success(engine.view("notes", NOW).unwrap()).admitted.len(),
        1
    );
    let mut writer = opened(records, &agent);
    writer.set_read_scope(vec!["notes".into()]);
    assert!(matches!(
        writer
            .begin_write(
                "notes",
                "createNotebook",
                json!({"id":"no","title":"No"}),
                NOW,
                [157; 32]
            )
            .unwrap(),
        colophon_core::model::Outcome::Failure { .. }
    ));
}

#[test]
fn binary_private_checkpoint_roundtrip_and_tamper() {
    use colophon_core::checkpoint::{CheckpointOpening, PreparedCheckpointKey};
    let (library, owner, _) = create();
    let prepared = PreparedCheckpointKey::new(library.id(), owner.public(), [201; 32]).unwrap();
    let signature = owner.sign(prepared.signing_body());
    let key = prepared.finish(signature).unwrap();
    let bytes = key
        .protect_binary(b"private checkpoint", [202; 32])
        .unwrap();
    let opening = CheckpointOpening::begin(&bytes, library.id(), &owner.public()).unwrap();
    let shared = owner.agree(opening.agreement_peer()).unwrap();
    assert_eq!(opening.finish(&shared).unwrap().1, b"private checkpoint");
    let mut corrupt = bytes.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    let opening = CheckpointOpening::begin(&corrupt, library.id(), &owner.public()).unwrap();
    assert!(opening.finish(&shared).is_err());
    for length in [0, 8, 11, 24, bytes.len() - 20] {
        assert!(CheckpointOpening::begin(&bytes[..length], library.id(), &owner.public()).is_err());
    }
    corrupt = bytes;
    corrupt[12] ^= 1;
    assert!(CheckpointOpening::begin(&corrupt, library.id(), &owner.public()).is_err());
}

#[test]
fn review_long_playback_then_deliberate_write_survives_reopen() {
    let (mut lib, owner, _) = create();
    let mut reader = lib.clone();
    for n in 0u64..1030 {
        let mut seed = [0; 32];
        seed[..8].copy_from_slice(&n.to_le_bytes());
        let pending = success(
            lib.begin_write(
                "listening.podcasts",
                "position",
                json!({"id":"e","seconds":n}),
                NOW,
                seed,
            )
            .unwrap(),
        );
        apply(&mut lib, pending, &owner);
        if n == 0 {
            reader.merge(lib.records().clone()).unwrap();
        }
    }
    reader.merge(lib.records().clone()).unwrap();
    assert_eq!(episode_seconds(&reader, "e"), 1029.0);
    write(
        &mut lib,
        &owner,
        "listening.podcasts",
        "position",
        json!({"id":"e","seconds":3,"seek":true}),
        180,
    );
    let cold = opened(lib.records().clone(), &owner);
    assert_eq!(episode_seconds(&cold, "e"), 3.0);
    assert!(success(cold.view("listening.podcasts", NOW).unwrap())
        .refused
        .is_empty());
}

#[test]
fn review_malformed_and_locked_replacements_preserve_head() {
    let (mut lib, owner, _) = create();
    write(
        &mut lib,
        &owner,
        "listening.podcasts",
        "position",
        json!({"id":"e","seconds":1}),
        181,
    );
    let (path, old) = lib
        .records()
        .iter()
        .find(|(p, _)| p.starts_with("state/"))
        .map(|(p, b)| (p.clone(), b.clone()))
        .unwrap();
    write(
        &mut lib,
        &owner,
        "listening.podcasts",
        "position",
        json!({"id":"e","seconds":2}),
        182,
    );
    let current = lib.records()[&path].clone();
    lib.merge([(path.clone(), b"invalid JSON".to_vec())].into())
        .unwrap();
    assert_eq!(lib.records()[&path], current);
    let mut locked = Library::open(lib.records().clone(), owner.public()).unwrap();
    locked.merge([(path.clone(), old)].into()).unwrap();
    assert_eq!(locked.records()[&path], current);
}

#[test]
fn review_forward_exhaustion_is_refused() {
    use colophon_core::{
        model::{LiveStamp, Operation, OperationHeader},
        records::{canonical, SignedRecord},
    };
    let (mut lib, owner, _) = create();
    let raw = adversarial(
        &lib,
        &owner,
        &owner,
        "listening.podcasts",
        Operation {
            id: String::new(),
            kind: "position".into(),
            v: 1,
            clock: 9_007_199_254_740_991,
            authority: lib.authority().latest,
            created: NOW.into(),
            payload: json!({"id":"e","seconds":99}),
        },
        1,
        183,
    )
    .into_values()
    .next()
    .unwrap();
    let record: SignedRecord = serde_json::from_slice(&raw).unwrap();
    let mut header: OperationHeader = serde_json::from_slice(&record.body).unwrap();
    let slot = protocol::live_slot_name("e");
    header.live = Some(LiveStamp {
        library_id: lib.id().into(),
        slot: slot.clone(),
        generation: header.meta.clock,
        operation_id: header.meta.id.clone(),
    });
    let body = canonical(&header).unwrap();
    let raw = SignedRecord {
        signature: owner.sign(&body),
        body,
    }
    .encode()
    .unwrap();
    lib.merge(
        [(
            protocol::live_state_path(&owner.public().id(), "listening.podcasts", &slot),
            raw,
        )]
        .into(),
    )
    .unwrap();
    write(
        &mut lib,
        &owner,
        "listening.podcasts",
        "position",
        json!({"id":"good","seconds":1,"seek":true}),
        184,
    );
    assert_eq!(
        episode_seconds(&opened(lib.records().clone(), &owner), "good"),
        1.0
    );
    // A signed but inadmissible initial head must not pin this slot at the maximum either.
    write(
        &mut lib,
        &owner,
        "listening.podcasts",
        "position",
        json!({"id":"e","seconds":2}),
        185,
    );
    assert_eq!(episode_seconds(&lib, "e"), 2.0);
}

#[test]
fn review_unrelated_commands_do_not_retain_all_live_slots() {
    let (mut lib, owner, _) = create();
    write(
        &mut lib,
        &owner,
        "listening.podcasts",
        "position",
        json!({"id":"one","seconds":1}),
        190,
    );
    write(
        &mut lib,
        &owner,
        "listening.podcasts",
        "position",
        json!({"id":"two","seconds":1}),
        191,
    );
    let pending = success(
        lib.begin_write(
            "listening.podcasts",
            "follow",
            json!({"id":"show","url":"https://example.org/feed"}),
            NOW,
            [192; 32],
        )
        .unwrap(),
    );
    assert!(pending.copies.is_empty());
    let pending = success(
        lib.begin_write(
            "listening.podcasts",
            "position",
            json!({"id":"one","seconds":0,"seek":true}),
            NOW,
            [193; 32],
        )
        .unwrap(),
    );
    assert_eq!(pending.copies.len(), 1);
}

#[test]
fn review_locked_equivocation_is_explicit() {
    let (mut first, owner, _) = create();
    let mut second = first.clone();
    write(
        &mut first,
        &owner,
        "listening.podcasts",
        "position",
        json!({"id":"e","seconds":1}),
        200,
    );
    write(
        &mut second,
        &owner,
        "listening.podcasts",
        "position",
        json!({"id":"e","seconds":2}),
        201,
    );
    let mut locked = Library::open(first.records().clone(), owner.public()).unwrap();
    assert!(protocol::is_equivocation(
        &locked.merge(second.records().clone()).unwrap_err()
    ));
    unlock(&mut locked, &owner);
    assert_eq!(episode_seconds(&locked, "e"), 1.0);
}
