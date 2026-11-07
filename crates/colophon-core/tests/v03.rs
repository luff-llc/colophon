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
