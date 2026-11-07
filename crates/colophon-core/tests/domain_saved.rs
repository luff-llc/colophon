#![allow(clippy::unwrap_used)]
mod support;
use base64::{engine::general_purpose::STANDARD, Engine};
use colophon_core::{
    domain::{DomainModule, Reducer},
    domains::saved::{import::*, source_id, ReadingSaved, SavedState},
    model::OperationView,
};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
};
use support::*;
fn blob(n: u8, media: &str) -> Value {
    json!({"digest":format!("{n:064x}"),"size":128,"mediaType":media})
}
fn manifest(n: u8, browser: bool) -> Value {
    let mut m = json!({"id":"pending","metadata":blob(n,"application/json"),"mediaType":"text/plain","origin":{"kind":if browser{"browserExtraction"}else{"file"}},"capturedAt":"2026-11-06T00:00:00Z","extractionVersion":1,"coverage":"complete"});
    if !browser {
        m["original"] = blob(n + 1, "text/plain");
    }
    m["id"] = json!(source_id(&m).unwrap());
    m
}
fn annotation(id: &str, parents: Value, action: &str, s: &Value) -> Value {
    json!({"id":id,"thread":"thread","item":"item","source":s["id"],"parents":parents,"action":action,"anchor":{"kind":"text","passageID":"p","startUTF16":0,"lengthUTF16":4,"quote":"text"},"text":format!("note {id}")})
}
fn op(n: usize, kind: &str, payload: Value) -> OperationView {
    OperationView {
        id: format!("op{n}"),
        kind: kind.into(),
        author: "owner".into(),
        author_label: "Owner".into(),
        origin: "person".into(),
        clock: n as u64,
        created: "2026-11-06T00:00:00Z".into(),
        payload,
    }
}
fn q(s: &SavedState, name: &str, args: Value) -> Value {
    ReadingSaved.query(s, name, &args).unwrap()["value"].clone()
}
fn add(s: &mut SavedState, n: usize, kind: &str, p: Value) {
    ReadingSaved.apply(s, &op(n, kind, p));
}
fn populated() -> (SavedState, Value) {
    let mut s = SavedState::default();
    let m = manifest(1, false);
    add(
        &mut s,
        1,
        "capture",
        json!({"id":"item","title":"Document","extensions":{"x":1},"origin":"spoof"}),
    );
    add(
        &mut s,
        2,
        "retainSource",
        json!({"id":m["id"],"item":"item","manifest":m,"select":true,"expect":null}),
    );
    (s, m)
}

#[test]
fn independent_heads_conflicts_tombstones_and_extensions() {
    let (mut s, m) = populated();
    add(
        &mut s,
        3,
        "setState",
        json!({"id":"item","consumption":"inProgress","expect":"op1"}),
    );
    add(
        &mut s,
        4,
        "editMetadata",
        json!({"id":"item","title":"New","expect":"op1","tags":[" b ","a","a",""]}),
    );
    add(
        &mut s,
        5,
        "position",
        json!({"item":"item","source":m["id"],"position":{"kind":"passage","id":"p","offsetUTF16":30},"expect":null}),
    );
    add(
        &mut s,
        6,
        "position",
        json!({"item":"item","source":m["id"],"position":{"kind":"passage","id":"p","offsetUTF16":1},"expect":"op5"}),
    );
    add(
        &mut s,
        7,
        "setState",
        json!({"id":"item","retention":"released","expect":"op1","extra":4}),
    );
    let item = q(&s, "item", json!({"id":"item"}));
    assert_eq!(
        item["heads"],
        json!({"state":"op3","metadata":"op4","source":"op2","position":"op6","activity":"op6"})
    );
    assert_eq!(item["extensions"]["extensions"]["x"], 1);
    assert_eq!(item["item"]["origin"], "person");
    assert_eq!(item["item"]["tags"], json!(["a", "b"]));
    assert_eq!(
        q(&s, "position", json!({"item":"item"}))["position"]["offsetUTF16"],
        1
    );
    add(
        &mut s,
        8,
        "delete",
        json!({"id":"item","expectActivity":"op4"}),
    );
    assert!(q(&s, "item", json!({"id":"item"}))["outcome"].is_null());
    add(
        &mut s,
        9,
        "delete",
        json!({"id":"item","expectActivity":"op6"}),
    );
    add(
        &mut s,
        10,
        "editMetadata",
        json!({"id":"item","title":"Late"}),
    );
    add(
        &mut s,
        11,
        "capture",
        json!({"id":"item","title":"No resurrection"}),
    );
    assert_eq!(q(&s, "item", json!({"id":"item"}))["outcome"], "deleted");
    assert_eq!(
        q(&s, "item", json!({"id":"item","includeDeleted":true}))["item"]["title"],
        "New"
    );
    assert_eq!(q(&s, "conflicts", json!({"object":"item"}))["total"], 4);
    assert_eq!(q(&s, "items", json!({}))["total"], 0);
    assert_eq!(q(&s, "readingCounts", json!({}))["deleted"], 1);
}
#[test]
fn graph_branches_resolution_terminal_delete_and_missing_parents() {
    let (mut s, m) = populated();
    add(
        &mut s,
        3,
        "reviseAnnotation",
        annotation("a", json!([]), "create", &m),
    );
    add(
        &mut s,
        4,
        "reviseAnnotation",
        annotation("b", json!(["a"]), "edit", &m),
    );
    add(
        &mut s,
        5,
        "reviseAnnotation",
        annotation("c", json!(["a"]), "edit", &m),
    );
    assert_eq!(
        q(&s, "annotation", json!({"thread":"thread"}))["headCount"],
        2
    );
    assert!(q(&s, "annotation", json!({"thread":"thread"}))["current"].is_null());
    add(
        &mut s,
        6,
        "reviseAnnotation",
        annotation("stale", json!(["b"]), "resolve", &m),
    );
    assert_eq!(
        q(&s, "annotation", json!({"thread":"thread"}))["headCount"],
        2
    );
    add(
        &mut s,
        7,
        "reviseAnnotation",
        annotation("d", json!(["b", "c"]), "resolve", &m),
    );
    add(
        &mut s,
        8,
        "tagAnnotations",
        json!({"id":"tag","threads":["thread"],"tag":"insight","included":true,"expect":null}),
    );
    assert_eq!(q(&s, "annotations", json!({"tag":"insight"}))["total"], 1);
    add(
        &mut s,
        9,
        "reviseAnnotation",
        annotation("e", json!(["d"]), "delete", &m),
    );
    add(
        &mut s,
        10,
        "reviseAnnotation",
        annotation("f", json!(["d"]), "edit", &m),
    );
    assert_eq!(
        q(&s, "annotation", json!({"thread":"thread"}))["deleted"],
        true
    );
    assert_eq!(
        q(&s, "annotationHistory", json!({"thread":"thread"}))["total"],
        5
    );
    let (mut pending, m) = populated();
    add(
        &mut pending,
        3,
        "reviseAnnotation",
        annotation("child", json!(["parent"]), "edit", &m),
    );
    assert_eq!(
        q(&pending, "conflicts", json!({"object":"item"}))["rows"][0]["reason"],
        "missingParents"
    );
    add(
        &mut pending,
        4,
        "reviseAnnotation",
        annotation("parent", json!([]), "create", &m),
    );
    assert_eq!(
        q(&pending, "annotationHistory", json!({"thread":"thread"}))["total"],
        2
    );
}
#[test]
fn atomic_invalid_commands_sources_and_browser_checkpoints() {
    let (mut s, m) = populated();
    let before = q(&s, "item", json!({"id":"item"}));
    let b = manifest(3, true);
    add(
        &mut s,
        3,
        "captureReading",
        json!({"id":"bad","item":"item","source":b,"position":{"kind":"page","index":1},"notes":[],"expect":"op2"}),
    );
    assert_eq!(q(&s, "item", json!({"id":"item"})), before);
    assert_eq!(
        q(&s, "sources", json!({"item":"item","kind":"versions"}))["total"],
        1
    );
    add(
        &mut s,
        4,
        "captureReading",
        json!({"id":"checkpoint","item":"item","source":b,"position":{"kind":"passage","id":"p","offsetUTF16":0},"notes":[{"id":"seed","anchor":{"kind":"item"},"text":"hello"}],"expect":"op2"}),
    );
    add(
        &mut s,
        5,
        "selectSource",
        json!({"item":"item","source":m["id"],"expect":"op4"}),
    );
    add(
        &mut s,
        6,
        "selectReadingCheckpoint",
        json!({"item":"item","checkpoint":"checkpoint","expect":"op5"}),
    );
    assert_eq!(q(&s, "position", json!({"item":"item"}))["source"], b["id"]);
    let mut changed = m.clone();
    changed["coverage"] = json!("changed");
    add(
        &mut s,
        7,
        "retainSource",
        json!({"id":m["id"],"item":"item","manifest":changed}),
    );
    assert_eq!(q(&s, "invalid", json!({}))["total"], 2);
}
#[test]
fn feeds_review_answers_connections_views_and_subscriptions() {
    let (mut s, m) = populated();
    add(
        &mut s,
        3,
        "reviseAnnotation",
        annotation("a", json!([]), "create", &m),
    );
    add(
        &mut s,
        4,
        "followFeed",
        json!({"id":"feed","url":"https://example.org/feed","title":"Feed","folders":[["News"]],"expect":null}),
    );
    let entry = json!({"id":"entry","title":"Entry","author":"Writer","summary":"Summary","publisherIdentity":"publisher"});
    add(
        &mut s,
        5,
        "refreshFeed",
        json!({"id":"feed","response":blob(10,"application/xml"),"entries":[entry],"expect":"op4"}),
    );
    add(
        &mut s,
        6,
        "organizeFeed",
        json!({"id":"feed","folders":[],"expect":"op5"}),
    );
    add(
        &mut s,
        7,
        "unfollowFeed",
        json!({"id":"feed","expect":"op6"}),
    );
    add(
        &mut s,
        8,
        "followFeed",
        json!({"id":"feed","url":"https://example.org/feed","title":"Feed","folders":[],"expect":"op7"}),
    );
    assert_eq!(q(&s, "feedEntries", json!({"feed":"feed"}))["total"], 1);
    add(
        &mut s,
        9,
        "reviseView",
        json!({"id":"v1","view":"view","parents":[],"name":"Unread","query":{"consumption":"notStarted"},"deleted":false}),
    );
    for (n, action) in [
        (10, "enable"),
        (11, "revisited"),
        (12, "undo"),
        (13, "exclude"),
        (14, "include"),
        (15, "disable"),
    ] {
        let mut p = json!({"id":format!("r{n}"),"action":action});
        if !["enable", "disable"].contains(&action) {
            p["thread"] = json!("thread");
        }
        if action == "revisited" {
            p["annotation"] = json!("a");
        }
        if action == "undo" {
            p["undoing"] = json!("r11");
        }
        add(&mut s, n, "changeReview", p);
    }
    assert_eq!(q(&s, "reviewQueue", json!({}))["enabled"], false);
    assert_eq!(q(&s, "reviewHistory", json!({}))["total"], 6);
    let evidence = json!({"source":m["id"],"annotation":"a","anchor":{"kind":"unresolved","quote":"text","location":"source","reason":"historical"}});
    add(
        &mut s,
        16,
        "keepAnswer",
        json!({"id":"answer","question":"Why?","claims":[{"text":"Because","citations":[evidence]}],"evidence":[evidence],"engine":"test","runtime":"test","promptRevision":"1"}),
    );
    add(
        &mut s,
        17,
        "setAnswerVisibility",
        json!({"id":"hide","answer":"answer","parents":[],"hidden":true}),
    );
    add(
        &mut s,
        18,
        "setAnswerVisibility",
        json!({"id":"reveal","answer":"answer","parents":["hide"],"hidden":false}),
    );
    assert_eq!(q(&s, "answers", json!({}))["total"], 1);
    let endpoint = json!({"item":"item","source":m["id"],"annotation":"a"});
    add(
        &mut s,
        19,
        "reviseConnection",
        json!({"id":"c1","connection":"c","parents":[],"source":endpoint,"target":{"item":"item","source":m["id"]},"relation":"related","reason":"Context","retracted":false}),
    );
    assert_eq!(q(&s, "connections", json!({}))["total"], 1);
    add(
        &mut s,
        20,
        "setMagazineSubscription",
        json!({"id":"sub1","publication":"wired","status":"active","plan":"digital","expect":null}),
    );
    add(
        &mut s,
        21,
        "setMagazineSubscription",
        json!({"id":"sub2","publication":"wired","status":"expired","plan":"digital","expect":null}),
    );
    assert_eq!(
        q(&s, "subscriptions", json!({}))["rows"][0]["alternativeCount"],
        1
    );
    assert_eq!(q(&s, "invalid", json!({}))["total"], 0);
}
#[test]
fn source_only_attach_images_and_unknown_fields() {
    let mut s = SavedState::default();
    add(
        &mut s,
        1,
        "capture",
        json!({"id":"item","title":"Imported"}),
    );
    let raw = blob(20, "application/json");
    let value = json!({"version":1,"provenance":{"version":1,"documentID":"doc","sourceRecordDigest":"a".repeat(64),"rawExport":raw,"importedAt":"2026-11-06T00:00:00Z"},"values":{"title":"Imported","author":"Writer","summary":"","sourceName":"Reader","tags":[],"suppliedFraction":0.5}});
    add(
        &mut s,
        2,
        "retainSourceMetadata",
        json!({"id":"metadata","item":"item","kind":"readerMetadata","value":value,"raw":raw}),
    );
    assert_eq!(q(&s, "item", json!({"id":"item"}))["metadataOnly"], true);
    let mut m = manifest(21, false);
    m["origin"] = json!({"kind":"reader","documentID":"doc","sourceRecordDigest":"a".repeat(64),"rawDigest":raw["digest"]});
    add(
        &mut s,
        3,
        "attachOriginal",
        json!({"item":"item","metadata":"metadata","manifest":m,"expect":"op2","expectActivity":"op2"}),
    );
    let mut asset = json!({"candidate":{"id":"image","itemID":"item","source":m["id"],"index":0,"sourceURL":"https://example.org/image.png","alt":"image"},"blob":blob(22,"image/png"),"mime":"image/png","width":100,"height":100,"observedURLs":["https://example.org/image.png"],"capturedAt":"2026-11-06T00:00:00Z"});
    asset["candidate"]["id"] =
        json!(colophon_core::domains::saved::image_candidate_id(&asset["candidate"]).unwrap());
    let candidate_id = asset["candidate"]["id"].clone();
    add(
        &mut s,
        4,
        "retainImages",
        json!({"item":"item","source":m["id"],"assets":[asset],"coverage":{"results":[{"candidate":candidate_id,"outcome":"retained"}]},"expect":"op3"}),
    );
    assert_eq!(
        q(&s, "sources", json!({"item":"item","kind":"images"}))["total"],
        1
    );
    assert_eq!(q(&s, "invalid", json!({}))["total"], 0);
}
#[test]
fn query_paging_binding_bounds_and_tool_specs() {
    let mut s = SavedState::default();
    for n in 1..=120 {
        add(
            &mut s,
            n,
            "capture",
            json!({"id":format!("item{n:03}"),"title":"Same"}),
        );
    }
    let first = q(&s, "items", json!({"limit":50,"query":{"sort":"title"}}));
    assert_eq!(first["rows"].as_array().unwrap().len(), 50);
    assert_eq!(first["total"], 120);
    let second = q(
        &s,
        "items",
        json!({"cursor":first["next"],"query":{"sort":"title"},"limit":50}),
    );
    assert_eq!(second["rows"][0]["id"], "item051");
    assert_eq!(
        q(
            &s,
            "items",
            json!({"cursor":first["next"],"query":{"sort":"added"}})
        )["outcome"],
        "staleCursor"
    );
    add(&mut s, 121, "future.graph", json!({"id":"future"}));
    assert_eq!(
        q(
            &s,
            "items",
            json!({"cursor":first["next"],"query":{"sort":"title"}})
        )["outcome"],
        "staleCursor"
    );
    assert!(ReadingSaved
        .query(&s, "items", &json!({"limit":101}))
        .is_err());
    assert!(ReadingSaved
        .query(&s, "items", &json!({"query":{"unknown":true}}))
        .is_err());
    assert_eq!(ReadingSaved.operations().len(), 24);
    let names: Vec<_> = ReadingSaved
        .operations()
        .into_iter()
        .chain(ReadingSaved.queries())
        .map(|s| s.name)
        .collect();
    assert_eq!(names.len(), names.iter().collect::<BTreeSet<_>>().len());
}
#[test]
fn fixed_seed_replay_and_serialized_prefixes() {
    let mut seed = 0x3141592653589793u64;
    let mut operations = vec![];
    for n in 1..=180 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let id = format!("item{}", seed % 9);
        let (kind, p) = match seed % 6 {
            0 => ("capture", json!({"id":id,"title":"Item"})),
            1 => (
                "editMetadata",
                json!({"id":id,"title":format!("Title{n}"),"extensions":{"kept":n}}),
            ),
            2 => (
                "setState",
                json!({"id":id,"consumption":"completed","expect":"stale"}),
            ),
            3 => ("delete", json!({"id":id,"expectActivity":"stale"})),
            4 => ("capture", json!({"id":id,"title":7})),
            _ => ("future", json!({})),
        };
        operations.push(op(n, kind, p));
    }
    for _ in 0..8 {
        for i in (1..operations.len()).rev() {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            operations.swap(i, seed as usize % (i + 1));
        }
        // The engine sorts deliveries; reducers receive that admitted prefix.
        let mut admitted: Vec<OperationView> = vec![];
        for chunk in operations.chunks(19) {
            admitted.extend_from_slice(chunk);
            admitted.sort_by(|a, b| (a.clock, &a.author, &a.id).cmp(&(b.clock, &b.author, &b.id)));
            let mut state = SavedState::default();
            for o in &admitted {
                ReadingSaved.apply(&mut state, o);
            }
            assert_eq!(
                ReadingSaved.query(&state, "read", &json!({})).unwrap(),
                ReadingSaved.fold(&admitted)
            );
            let restored: SavedState =
                serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
            assert_eq!(
                q(&state, "items", json!({})),
                q(&restored, "items", json!({}))
            );
        }
    }
}
fn legacy(kind: &str) -> VerifiedLegacyOperation {
    VerifiedLegacyOperation {
        source_library: "source".into(),
        author_id: "old-writer".into(),
        author_label: "Historical writer".into(),
        operation_id: "legacy-op".into(),
        signed_body_digest: "a".repeat(64),
        kind: kind.into(),
        version: 1,
        payload: json!({}),
        admitted_order: 1,
        outcome: LegacyOutcome::Effective,
    }
}
#[test]
fn every_legacy_kind_retains_malformed_rejected_and_conflicting_history() {
    assert_eq!(LEGACY_KINDS.len(), 36);
    for kind in LEGACY_KINDS {
        let mut op = legacy(kind);
        op.payload = json!({"unknown":{"must":"survive"}});
        let result = translate(&op, &ImportContext::default());
        assert!(result.commands.is_empty(), "{kind}");
        assert_eq!(result.evidence[0].source.payload, op.payload);
        for disposition in [
            LegacyOutcome::Conflict,
            LegacyOutcome::Rejected,
            LegacyOutcome::Invalid,
            LegacyOutcome::Unresolved,
            LegacyOutcome::Historical,
        ] {
            op.outcome = disposition;
            let result = translate(&op, &ImportContext::default());
            assert!(result.commands.is_empty());
            assert_eq!(result.evidence.len(), 1);
        }
    }
    for kind in [
        "legacy.capture",
        "source.native/nativeSource.preserve",
        "future.unknown",
    ] {
        let op = legacy(kind);
        let result = translate(&op, &ImportContext::default());
        assert_eq!(result.evidence[0].disposition, "unresolved");
        assert!(result.commands.is_empty());
    }
}
#[test]
fn import_effects_head_rebase_and_no_presence_or_enablement() {
    let mut op = legacy("capture.link");
    op.payload = json!({"item":"old","url":"https://example.org/a","title":"Imported","author":"Writer","tags":["one"],"added":42,"unknown":true});
    let c = ImportContext {
        identities: BTreeMap::from([("item/old".into(), "new".into())]),
        ..Default::default()
    };
    let r = translate(&op, &c);
    assert_eq!(r.commands.len(), 2);
    assert!(r.publication_barrier);
    assert_eq!(r.commands[0].payload["id"], "new");
    assert_eq!(r.commands[1].payload["creator"], "Writer");
    assert_eq!(r.commands[1].expect_from_child, Some(0));
    assert_eq!(
        resolve_payload(&r.commands[1], &["signed-output".into()]).unwrap()["expect"],
        "signed-output"
    );
    assert!(resolve_payload(&r.commands[1], &[]).is_err());
    assert_eq!(r.evidence[0].source.payload, op.payload);
    let again = translate(&op, &c);
    assert_eq!(r.commands, again.commands);
    op.signed_body_digest = "b".repeat(64);
    assert_ne!(r.evidence[0].key, translate(&op, &c).evidence[0].key);
    op.kind = "item.setState".into();
    op.payload = json!({"item":"old","consumption":"completed","expect":"old-component"});
    let mut c = c;
    c.heads
        .insert("new/state".into(), json!("destination-component"));
    let r = translate(&op, &c);
    assert_eq!(r.commands[0].payload["expect"], "destination-component");
    op.outcome = LegacyOutcome::Conflict;
    assert!(translate(&op, &c).commands.is_empty());
    let mut activity = legacy("safari.activity");
    activity.payload = json!({"active":true});
    assert!(translate(&activity, &c).commands.is_empty());
    let review = legacy("review.change");
    c.decoded = Some(json!({"change":{"id":"enable","action":"enable"}}));
    assert!(translate(&review, &c).commands.is_empty());
    let mut malformed = legacy("capture.link");
    malformed.payload = json!({"item":"x","url":"file:///private/x"});
    assert_eq!(
        translate(&malformed, &c).evidence[0].disposition,
        "unresolved"
    );
}

#[test]
fn deterministic_saved_vector() {
    let (mut lib, owner, _) = create();
    let m = manifest(1, false);
    let commands = vec![
        (
            "capture",
            json!({"id":"item","title":"Synthetic retained document","future":{"preserved":true}}),
        ),
        (
            "retainSource",
            json!({"id":m["id"],"item":"item","manifest":m,"select":true,"expect":null}),
        ),
        (
            "position",
            json!({"item":"item","source":m["id"],"position":{"kind":"passage","id":"p","offsetUTF16":4},"expect":null}),
        ),
        ("reviseAnnotation", annotation("a", json!([]), "create", &m)),
        (
            "reviseAnnotation",
            annotation("b", json!(["a"]), "edit", &m),
        ),
        (
            "reviseAnnotation",
            annotation("c", json!(["a"]), "edit", &m),
        ),
        (
            "editMetadata",
            json!({"id":"item","title":"Stale title","expect":"missing"}),
        ),
        (
            "capture",
            json!({"id":"link","title":"Link","url":"https://example.org/a"}),
        ),
        (
            "followFeed",
            json!({"id":"feed","url":"https://example.org/feed","title":"Feed","folders":[],"expect":null}),
        ),
        (
            "reviseView",
            json!({"id":"view-root","view":"view","parents":[],"name":"Saved","query":{"retention":"saved"},"deleted":false}),
        ),
        (
            "setMagazineSubscription",
            json!({"id":"sub","publication":"wired","status":"active","plan":"digital","expect":null}),
        ),
    ];
    for (i, (kind, p)) in commands.into_iter().enumerate() {
        write(&mut lib, &owner, "reading.saved", kind, p, 100 + i as u8);
    }
    let activity = success(
        lib.query("reading.saved", "item", json!({"id":"link"}), NOW)
            .unwrap(),
    )["value"]["heads"]["activity"]
        .clone();
    write(
        &mut lib,
        &owner,
        "reading.saved",
        "delete",
        json!({"id":"link","expectActivity":activity}),
        120,
    );
    write(
        &mut lib,
        &owner,
        "reading.saved",
        "editMetadata",
        json!({"id":"link","title":"Late"}),
        121,
    );
    let cases = vec![
        ("items", json!({"limit":1})),
        ("item", json!({"id":"item"})),
        ("item", json!({"id":"link"})),
        ("readingCounts", json!({})),
        ("sources", json!({"item":"item","kind":"versions"})),
        ("position", json!({"item":"item"})),
        ("annotations", json!({})),
        ("annotation", json!({"thread":"thread"})),
        ("annotationHistory", json!({"thread":"thread","limit":2})),
        ("feeds", json!({})),
        ("feedEntries", json!({"feed":"feed"})),
        ("savedViews", json!({})),
        ("savedView", json!({"id":"view"})),
        ("reviewQueue", json!({})),
        ("reviewHistory", json!({})),
        ("answers", json!({})),
        ("answer", json!({"id":"absent"})),
        ("connections", json!({})),
        ("subscriptions", json!({})),
        ("conflicts", json!({"object":"item"})),
    ];
    let queries:Vec<_>=cases.into_iter().map(|(name,args)|json!({"name":name,"args":args,"expected":success(lib.query("reading.saved",name,args.clone(),NOW).unwrap())})).collect();
    let records: BTreeMap<_, _> = lib
        .records()
        .iter()
        .map(|(path, bytes)| (path.clone(), STANDARD.encode(bytes)))
        .collect();
    let vector = json!({"namespace":"reading.saved","queries":queries,"records":records});
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/0.3/reading.saved.json");
    if std::env::var_os("COLOPHON_UPDATE_VECTORS").is_some() {
        fs::write(&path, serde_json::to_vec_pretty(&vector).unwrap()).unwrap();
    }
    let stored: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert_eq!(stored,vector,"Regenerate with COLOPHON_UPDATE_VECTORS=1 cargo test --test domain_saved deterministic_saved_vector");
}

#[test]
fn every_legacy_kind_has_a_verified_effect_mapping() {
    let m = manifest(31, false);
    let browser = manifest(33, true);
    let note = annotation("a", json!([]), "create", &m);
    let view = json!({"id":"v1","view":"v","parents":[],"name":"View","query":{"shelf":"unread","sort":"newest"},"deleted":false});
    let evidence = json!({"source":m["id"],"annotation":"a"});
    let answer = json!({"id":"answer","question":"Why?","claims":[{"text":"Claim","citations":[evidence]}],"evidence":[evidence],"engine":"model","runtime":"runtime","promptRevision":"1"});
    let visibility = json!({"id":"vis","answer":"answer","parents":[],"hidden":true});
    let connection = json!({"id":"c1","connection":"c","parents":[],"source":{"item":"item","source":m["id"],"annotation":"a"},"target":{"item":"item","source":m["id"]},"relation":"related","reason":"Relation","retracted":false});
    let subscription =
        json!({"id":"sub","publication":"wired","status":"active","plan":"digital","expect":null});
    let raw_blob = blob(35, "application/json");
    let metadata = json!({"version":1,"provenance":{"version":1,"documentID":"doc","sourceRecordDigest":"c".repeat(64),"rawExport":raw_blob,"importedAt":"2026-11-06T00:00:00Z"},"values":{"title":"Imported","author":"Writer","summary":"","sourceName":"Reader","tags":[]}});
    let excerpt = json!({"version":1,"format":"readwiseCSV","workKey":"d".repeat(64),"sourceRecordDigest":"e".repeat(64),"title":"Excerpt","author":"Writer","rawExport":raw_blob,"importedAt":"2026-11-06T00:00:00Z"});
    let position = json!({"kind":"passage","id":"p","offsetUTF16":0});
    let change = json!({"id":"review","action":"passed","thread":"thread","annotation":"a"});
    let tags = json!({"id":"tag","threads":["thread"],"tag":"topic","included":true});
    let entry = json!({"id":"entry","title":"Entry","publisherIdentity":"publisher","author":"Writer","summary":"Summary"});
    for kind in LEGACY_KINDS {
        let mut legacy = legacy(kind);
        legacy.payload = json!({"item":"item","feed":"feed","version":m["id"],"checkpoint":"checkpoint","title":"Imported","url":"https://example.org/a","folders":[],"consumption":"inProgress","create":true});
        let mut c = ImportContext {
            closure_verified: true,
            advanced_reading: true,
            existing_items: BTreeSet::from(["item".into()]),
            ..Default::default()
        };
        for (object, component) in [
            ("item", "state"),
            ("item", "metadata"),
            ("item", "source"),
            ("item", "position"),
            ("item", "activity"),
            ("feed", "feed"),
            ("wired", "subscription"),
        ] {
            c.heads
                .insert(format!("{object}/{component}"), json!("destination-head"));
        }
        let decoded = match kind {
            "content.install" | "content.attachReaderOriginal" => {
                json!({"manifest":m,"metadataID":"metadata"})
            }
            "content.position" => json!({"position":position}),
            "content.note" => json!({"revision":note}),
            "content.removeNote" => {
                let mut n = note.clone();
                n["action"] = json!("delete");
                n["parents"] = json!(["previous"]);
                json!({"revision":n})
            }
            "content.images" => json!({"assets":[],"coverage":{"results":[]}}),
            "content.readerMetadata" => json!({"id":"metadata","value":metadata,"raw":raw_blob}),
            "content.externalExcerpt" => json!({"id":"excerpt","value":excerpt,"raw":raw_blob}),
            "content.restore" | "content.restoreDeleted" => {
                c.existing_items.clear();
                json!({"record":{"title":"Imported","selectedSource":m["id"],"position":{"source":m["id"],"position":position}},"manifests":[m],"annotations":[note],"metadata":[],"images":[]})
            }
            "safari.checkpoint" => {
                json!({"id":"checkpoint","title":"Browser","url":"https://example.org/a","source":browser,"position":position,"notes":[]})
            }
            "feed.follow" | "feed.organize" => legacy.payload.clone(),
            "feed.refresh" => json!({"response":blob(40,"application/xml"),"entries":[entry]}),
            "feed.restore" => {
                json!({"record":{"title":"Feed","url":"https://example.org/feed","folders":[],"followed":false},"responses":[{"response":blob(40,"application/xml"),"entries":[entry]}]})
            }
            "annotation.revision" => json!({"revision":note}),
            "annotation.tags" => json!({"change":tags}),
            "annotation.restore" => json!({"sources":[],"revisions":[note],"tags":[tags]}),
            "view.revision" => json!({"revision":view}),
            "view.restore" => json!({"revisions":[view]}),
            "review.change" => json!({"change":change}),
            "review.restore" => json!({"changes":[{"id":"old-enable","action":"enable"},change]}),
            "answer.keep" => json!({"answer":answer}),
            "answer.visibility" => json!({"revision":visibility}),
            "connection.change" => json!({"revision":connection}),
            "question.restore" => {
                json!({"sources":[],"answers":[answer],"visibility":[visibility],"connections":[connection]})
            }
            "magazine.subscription" => json!({"winner":subscription}),
            "magazine.subscriptionRestore" => json!({"winners":[subscription]}),
            _ => legacy.payload.clone(),
        };
        c.decoded = Some(decoded);
        let result = translate(&legacy, &c);
        if kind == "safari.activity" {
            assert!(result.commands.is_empty());
            continue;
        }
        assert!(
            !result.commands.is_empty(),
            "{kind}: {:?}",
            result.evidence[0].reason
        );
        assert_eq!(result.evidence[0].disposition, "mapped", "{kind}");
        assert!(result
            .commands
            .iter()
            .all(|c| c.payload["importSource"]["authorLabel"] == "Historical writer"));
    }
}

#[test]
fn every_command_rejects_missing_payload_without_partial_mutation() {
    for spec in ReadingSaved.operations() {
        let (mut s, _) = populated();
        let before = q(&s, "item", json!({"id":"item"}));
        add(
            &mut s,
            3,
            &spec.name,
            json!({"unknown":{"preserved":"in authenticated history"}}),
        );
        assert_eq!(q(&s, "invalid", json!({}))["total"], 1, "{}", spec.name);
        assert_eq!(q(&s, "item", json!({"id":"item"})), before, "{}", spec.name);
    }
    let (mut s, m) = populated();
    let mut operation = op(
        3,
        "position",
        json!({"item":"item","source":m["id"],"position":{"kind":"passage","id":"p","offsetUTF16":0}}),
    );
    operation.origin = "ai".into();
    ReadingSaved.apply(&mut s, &operation);
    assert_eq!(
        q(&s, "invalid", json!({}))["rows"][0]["reason"],
        "roleRequired"
    );
    for id in ["".to_owned(), "bad\nidentifier".into(), "a".repeat(1025)] {
        add(&mut s, 4, "capture", json!({"id":id,"title":"Invalid"}));
    }
    assert_eq!(q(&s, "items", json!({}))["total"], 1);
}

#[test]
fn preview_utf16_limits_host_search_and_missing_source_dependency() {
    let (mut s, m) = populated();
    let mut node = annotation("long", json!([]), "create", &m);
    node["text"] = json!("😀".repeat(400));
    add(&mut s, 3, "reviseAnnotation", node);
    let row = &q(&s, "annotations", json!({}))["rows"][0];
    assert_eq!(row["textPreview"]["truncated"], true);
    assert_eq!(
        row["textPreview"]["text"]
            .as_str()
            .unwrap()
            .encode_utf16()
            .count(),
        512
    );
    assert_eq!(
        q(&s, "items", json!({"query":{"availability":"savedText"}}))["outcome"],
        "unavailable"
    );
    assert!(ReadingSaved
        .query(
            &s,
            "items",
            &json!({"query":{"shelf":"readingNow","retention":"released"}})
        )
        .is_err());
    let mut delayed = SavedState::default();
    add(
        &mut delayed,
        1,
        "capture",
        json!({"id":"item","title":"Item"}),
    );
    add(
        &mut delayed,
        2,
        "reviseAnnotation",
        annotation("wait", json!([]), "create", &m),
    );
    assert_eq!(
        ReadingSaved.query(&delayed, "read", &json!({})).unwrap()["exportBlocked"],
        true
    );
    add(
        &mut delayed,
        3,
        "retainSource",
        json!({"id":m["id"],"item":"item","manifest":m}),
    );
    assert_eq!(
        q(&delayed, "annotation", json!({"thread":"thread"}))["current"]["id"],
        "wait"
    );
    assert_eq!(
        q(&delayed, "item", json!({"id":"item"}))["heads"]["activity"],
        "op3"
    );
}

#[test]
fn feed_browse_window_does_not_delete_kept_items() {
    let (mut s, _) = populated();
    add(
        &mut s,
        3,
        "followFeed",
        json!({"id":"feed","title":"Feed","url":"https://example.org/feed","folders":[],"expect":null}),
    );
    for n in 4..=104 {
        add(
            &mut s,
            n,
            "refreshFeed",
            json!({"id":"feed","response":blob(n as u8,"application/xml"),"entries":[{"id":format!("entry{n}"),"title":"Entry","publisherIdentity":"publisher","author":"Writer","summary":"Summary"}],"expect":format!("op{}",n-1)}),
        );
    }
    assert_eq!(q(&s, "feedEntries", json!({"feed":"feed"}))["total"], 100);
    assert_eq!(q(&s, "items", json!({}))["total"], 1);
    assert_eq!(q(&s, "invalid", json!({}))["total"], 0);
}

#[test]
fn saved_records_random_delivery_and_checkpoint_replay() {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/0.3/reading.saved.json");
    let vector: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let mut records: Vec<_> = vector["records"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(p, b)| (p.clone(), STANDARD.decode(b.as_str().unwrap()).unwrap()))
        .collect();
    let mut seed = 0x1234567u64;
    for i in (1..records.len()).rev() {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        records.swap(i, seed as usize % (i + 1));
    }
    let mut partial = BTreeMap::new();
    for chunk in records.chunks(5) {
        partial.extend(chunk.iter().cloned());
        let lib = colophon_core::library::Library::open(partial.clone(), keys(1).public());
        if let Ok(mut lib) = lib {
            unlock(&mut lib, &keys(1));
            if let Ok(checkpoint) = lib.checkpoint("reading.saved") {
                let before = success(lib.view("reading.saved", NOW).unwrap());
                assert!(lib
                    .restore_checkpoint("reading.saved", &checkpoint)
                    .unwrap());
                assert_eq!(before, success(lib.view("reading.saved", NOW).unwrap()));
            }
        }
    }
    let lib = opened(partial, &keys(1));
    for query in vector["queries"].as_array().unwrap() {
        assert_eq!(
            success(
                lib.query(
                    "reading.saved",
                    query["name"].as_str().unwrap(),
                    query["args"].clone(),
                    NOW
                )
                .unwrap()
            ),
            query["expected"]
        );
    }
}

#[test]
fn content_identity_can_be_shared_without_merging_occurrences() {
    let (mut s, m) = populated();
    add(
        &mut s,
        3,
        "capture",
        json!({"id":"copy","title":"Independent occurrence"}),
    );
    add(
        &mut s,
        4,
        "retainSource",
        json!({"id":m["id"],"item":"copy","manifest":m,"select":true,"expect":null}),
    );
    assert_eq!(
        q(&s, "sources", json!({"item":"copy","kind":"versions"}))["total"],
        1
    );
    assert_eq!(q(&s, "items", json!({}))["total"], 2);
    add(
        &mut s,
        5,
        "reviseAnnotation",
        annotation("a", json!([]), "create", &m),
    );
    let mut collision = annotation("a", json!([]), "create", &m);
    collision["thread"] = json!("different-thread");
    collision["item"] = json!("copy");
    add(&mut s, 6, "reviseAnnotation", collision);
    assert_eq!(
        q(&s, "annotation", json!({"thread":"different-thread"}))["outcome"],
        "notFound"
    );
    assert_eq!(
        q(&s, "conflicts", json!({"object":"different-thread"}))["total"],
        1
    );
    assert_eq!(q(&s, "invalid", json!({}))["total"], 0);
}

#[test]
fn shelf_ties_use_admitted_order_and_ignore_claimed_dates() {
    let mut s = SavedState::default();
    let mut a = op(1, "capture", json!({"id":"z","title":"A"}));
    a.author = "a".into();
    a.created = "2099-01-01T00:00:00Z".into();
    let mut b = op(1, "capture", json!({"id":"a","title":"B"}));
    b.author = "z".into();
    b.id = "other-operation".into();
    b.created = "2000-01-01T00:00:00Z".into();
    ReadingSaved.apply(&mut s, &a);
    ReadingSaved.apply(&mut s, &b);
    assert_eq!(q(&s, "items", json!({}))["rows"][0]["id"], "a");
    assert_eq!(
        q(&s, "items", json!({"query":{"sort":"oldest"}}))["rows"][0]["id"],
        "z"
    );
}

#[test]
fn generated_tools_validate_nested_shapes_and_enums_before_signing() {
    let (lib, _, _) = create();
    assert!(lib
        .begin_write(
            "reading.saved",
            "setState",
            json!({"id":"x","consumption":"invented"}),
            NOW,
            [201; 32]
        )
        .is_err());
    let m = manifest(44, false);
    assert!(lib
        .begin_write(
            "reading.saved",
            "retainSource",
            json!({"id":m["id"],"item":"x","manifest":m,"select":true}),
            NOW,
            [202; 32]
        )
        .is_err());
}
