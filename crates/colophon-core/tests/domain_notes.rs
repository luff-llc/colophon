#![allow(clippy::unwrap_used)]
use colophon_core::{
    domain::{DomainModule, Reducer},
    domains::notes::{import::*, validate_payload, Notes, NotesState},
    model::{MemberKind, OperationView},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
fn op(n: u64, kind: &str, payload: Value) -> OperationView {
    OperationView {
        id: format!("r{n}"),
        kind: kind.into(),
        author: "writer".into(),
        author_label: "Writer".into(),
        origin: "person".into(),
        clock: n,
        created: "2026-11-04T12:00:00Z".into(),
        payload,
    }
}
fn put(s: &mut NotesState, n: u64, kind: &str, payload: Value) {
    Notes.apply(s, &op(n, kind, payload));
}
fn q(s: &NotesState, name: &str, args: Value) -> Value {
    let result = Notes.query(s, name, &args).unwrap();
    result.get("value").cloned().unwrap_or(result)
}
fn read(s: &NotesState) -> Value {
    Notes.query(s, "read", &json!({})).unwrap()
}
fn base() -> NotesState {
    let mut s = NotesState::default();
    put(
        &mut s,
        1,
        "createNotebook",
        json!({"id":"b","title":"Book"}),
    );
    put(
        &mut s,
        2,
        "putEntry",
        json!({"id":"e","notebook":"b","title":"Entry","date":"2024-02-29","tags":["x"]}),
    );
    s
}
fn hash(text: &str) -> String {
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
#[test]
fn cells_conflicts_resolution_tombstones_and_outputs() {
    let mut s = base();
    put(
        &mut s,
        3,
        "putCell",
        json!({"id":"c","notebook":"b","entry":"e","kind":"code","language":"js","source":"one","extensions":{"nested":1},"author":"spoof"}),
    );
    put(
        &mut s,
        4,
        "recordOutput",
        json!({"id":"run","notebook":"b","cell":"c","sourceDigest":hash("one"),"runtime":"test","outputs":[{"mime":"text/plain","text":"ok","future":true}]}),
    );
    assert_eq!(
        q(&s, "cell", json!({"notebook":"b","id":"c"}))["outputIsCurrent"],
        true
    );
    put(
        &mut s,
        5,
        "putCell",
        json!({"id":"c","notebook":"b","kind":"latex","source":"stale","expect":"old","future":7}),
    );
    let conflict = q(
        &s,
        "contentDetail",
        json!({"notebook":"b","category":"cellConflict","id":"c"}),
    )["versions"]["rows"][0]
        .clone();
    assert_eq!(conflict["candidate"]["language"], "js");
    assert_eq!(conflict["candidate"]["entry"], "e");
    assert_eq!(conflict["candidate"]["author"], "writer");
    assert_eq!(conflict["candidate"]["extensions"]["future"], 7);
    put(
        &mut s,
        6,
        "resolveCell",
        json!({"id":"c","notebook":"b","source":"bad resolution","expect":"r3","resolves":[]}),
    );
    assert_eq!(
        q(&s, "cells", json!({"notebook":"b"}))["rows"][0]["alternativeCount"],
        2
    );
    put(
        &mut s,
        7,
        "resolveCell",
        json!({"id":"c","notebook":"b","source":"resolved","expect":"r3","resolves":["r6","r5"]}),
    );
    let cell = q(&s, "cell", json!({"notebook":"b","id":"c"}));
    assert_eq!(cell["source"], "resolved");
    assert_eq!(cell["kind"], "code");
    assert_eq!(cell["language"], "js");
    assert_eq!(cell["outputIsCurrent"], false);
    assert_eq!(cell["extensions"]["extensions"]["nested"], 1);
    put(
        &mut s,
        8,
        "putCell",
        json!({"id":"c","notebook":"b","kind":"code","source":"changed","entry":null,"language":null,"expect":"r7"}),
    );
    assert_eq!(
        q(&s, "cells", json!({"notebook":"b","entry":"e"}))["total"],
        0
    );
    assert_eq!(
        q(&s, "cells", json!({"notebook":"b","entry":null}))["total"],
        1
    );
    assert_eq!(
        q(&s, "entry", json!({"notebook":"b","id":"e"}))["cellCount"],
        0
    );
    put(
        &mut s,
        9,
        "deleteCell",
        json!({"id":"c","notebook":"b","expect":"r8"}),
    );
    put(
        &mut s,
        10,
        "putCell",
        json!({"id":"c","notebook":"b","kind":"markdown","source":"recover me"}),
    );
    assert_eq!(
        q(&s, "cell", json!({"notebook":"b","id":"c"}))["outcome"],
        "deleted"
    );
    let late = q(
        &s,
        "contentDetail",
        json!({"notebook":"b","category":"lateEdit","id":"c"}),
    );
    assert_eq!(
        late["versions"]["rows"][0]["candidate"]["source"],
        "recover me"
    );
    assert_eq!(q(&s, "noteCounts", json!({}))["cells"], 0);
    assert_eq!(q(&s, "noteCounts", json!({}))["lateEdits"], 1);
    assert_eq!(
        q(
            &s,
            "contentDetail",
            json!({"notebook":"b","category":"run","id":"run"})
        )["record"]["outputs"][0]["extensions"]["future"],
        true
    );
    put(
        &mut s,
        11,
        "deleteCell",
        json!({"id":"never","notebook":"b"}),
    );
    put(
        &mut s,
        12,
        "putCell",
        json!({"id":"never","notebook":"b","kind":"raw","source":"late"}),
    );
    assert_eq!(
        q(&s, "cell", json!({"notebook":"b","id":"never"}))["outcome"],
        "deleted"
    );
}
#[test]
fn entry_metadata_complete_cas_and_ownership() {
    let mut s = base();
    put(
        &mut s,
        3,
        "putEntry",
        json!({"id":"e","notebook":"b","title":"no CAS"}),
    );
    let detail = q(
        &s,
        "contentDetail",
        json!({"notebook":"b","category":"entryConflict","id":"e"}),
    );
    assert_eq!(
        detail["versions"]["rows"][0]["candidate"]["tags"],
        json!([])
    );
    assert!(detail["versions"]["rows"][0]["candidate"]["date"].is_null());
    put(
        &mut s,
        4,
        "putEntry",
        json!({"id":"e","notebook":"b","title":"new","expect":"r2"}),
    );
    assert_eq!(
        q(&s, "entry", json!({"notebook":"b","id":"e"}))["alternativeCount"],
        1
    );
    put(
        &mut s,
        5,
        "resolveEntry",
        json!({"id":"e","notebook":"b","tags":["settled"],"expect":"r4","resolves":["r3"]}),
    );
    assert_eq!(
        q(&s, "entry", json!({"notebook":"b","id":"e"}))["alternativeCount"],
        0
    );
    put(
        &mut s,
        6,
        "createNotebook",
        json!({"id":"other","title":"Other"}),
    );
    for (n, kind, payload) in [
        (
            7,
            "putEntry",
            json!({"id":"e","notebook":"other","expect":"r5"}),
        ),
        (
            8,
            "putCell",
            json!({"id":"bad","notebook":"other","entry":"e","kind":"raw","source":""}),
        ),
    ] {
        put(&mut s, n, kind, payload);
    }
    assert_eq!(read(&s)["invalid"], json!(["r7", "r8"]));
    assert_eq!(q(&s, "noteCounts", json!({}))["entries"], 1);
}
#[test]
fn order_head_is_separate_and_bad_mutations_are_atomic() {
    let mut s = base();
    for (n, id, after) in [
        (3, "a", Value::Null),
        (4, "b", json!("a")),
        (5, "c", json!("b")),
    ] {
        put(
            &mut s,
            n,
            "putCell",
            json!({"id":id,"notebook":"b","kind":"markdown","source":id,"after":after}),
        );
    }
    put(
        &mut s,
        6,
        "putCell",
        json!({"id":"a","notebook":"b","kind":"markdown","source":"edit","after":"c"}),
    );
    let ids = |s: &NotesState| {
        q(s, "cells", json!({"notebook":"b"}))["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["id"].clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(ids(&s), vec![json!("a"), json!("b"), json!("c")]);
    put(
        &mut s,
        7,
        "moveCell",
        json!({"id":"c","notebook":"b","after":"missing","expect":"r5"}),
    );
    assert_eq!(ids(&s), vec![json!("c"), json!("a"), json!("b")]);
    assert_eq!(
        q(&s, "cell", json!({"notebook":"b","id":"c"}))["cell"]["revision"],
        "r5"
    );
    put(
        &mut s,
        8,
        "moveCell",
        json!({"id":"a","notebook":"b","after":"b","expect":"r5"}),
    );
    assert_eq!(ids(&s), vec![json!("c"), json!("a"), json!("b")]);
    let before = q(&s, "notebook", json!({"id":"b"}));
    put(
        &mut s,
        9,
        "moveCell",
        json!({"id":"a","notebook":"b","after":"a"}),
    );
    put(
        &mut s,
        10,
        "putCell",
        json!({"id":"a","notebook":"b","kind":"future","source":"no","entry":"absent"}),
    );
    assert_eq!(before, q(&s, "notebook", json!({"id":"b"})));
    put(
        &mut s,
        11,
        "renameNotebook",
        json!({"id":"b","title":"Renamed","expect":"r1"}),
    );
    put(
        &mut s,
        12,
        "archiveNotebook",
        json!({"id":"b","archived":true,"expect":"r11"}),
    );
    assert_eq!(q(&s, "notebooks", json!({}))["total"], 0);
    assert_eq!(q(&s, "notebooks", json!({"archived":true}))["total"], 1);
    assert_eq!(ids(&s).len(), 3);
    put(
        &mut s,
        13,
        "archiveNotebook",
        json!({"id":"b","archived":false,"expect":"r12"}),
    );
    assert_eq!(q(&s, "noteCounts", json!({}))["archived"], 0);
}
#[test]
fn proposals_require_exact_inputs_verified_role_and_current_keep() {
    let mut s = base();
    put(
        &mut s,
        3,
        "putCell",
        json!({"id":"c","notebook":"b","entry":"e","kind":"markdown","source":"original"}),
    );
    put(
        &mut s,
        4,
        "proposeEntry",
        json!({"id":"bad","notebook":"b","entry":"e","markdown":"draft","inputs":{}}),
    );
    let proposal =
        json!({"id":"p","notebook":"b","entry":"e","markdown":"draft","inputs":{"c":"r3"}});
    put(&mut s, 5, "proposeEntry", proposal.clone());
    put(&mut s, 6, "proposeEntry", proposal);
    assert_eq!(
        q(&s, "proposals", json!({"notebook":"b","entry":"e"}))["total"],
        1
    );
    let review = op(
        7,
        "reviewProposal",
        json!({"id":"p","notebook":"b","keep":true,"authorKind":"device"}),
    );
    Notes.apply(&mut s, &review);
    Notes.apply_with_member_kind(&mut s, &review, Some(MemberKind::Agent));
    Notes.apply_with_member_kind(&mut s, &review, Some(MemberKind::Server));
    assert_eq!(
        q(&s, "proposals", json!({"notebook":"b","entry":"e"}))["rows"][0]["status"],
        "pending"
    );
    Notes.apply_with_member_kind(
        &mut s,
        &op(
            8,
            "reviewProposal",
            json!({"id":"p","notebook":"b","keep":true,"markdown":"reviewed","expect":"r5"}),
        ),
        Some(MemberKind::Device),
    );
    assert_eq!(
        q(
            &s,
            "proposals",
            json!({"notebook":"b","entry":"e","status":"kept"})
        )["total"],
        1
    );
    assert_eq!(q(&s, "noteCounts", json!({}))["pendingProposals"], 0);
    assert_eq!(
        q(&s, "cell", json!({"notebook":"b","id":"c"}))["source"],
        "original"
    );
    put(
        &mut s,
        9,
        "proposeEntry",
        json!({"id":"p2","notebook":"b","entry":"e","markdown":"new draft","inputs":{"c":"r3"}}),
    );
    put(
        &mut s,
        10,
        "putCell",
        json!({"id":"c","notebook":"b","kind":"markdown","source":"late draft","expect":"stale"}),
    );
    assert_eq!(
        q(
            &s,
            "proposals",
            json!({"notebook":"b","entry":"e","status":"pending"})
        )["rows"][0]["inputCurrent"],
        false
    );
    Notes.apply_with_member_kind(
        &mut s,
        &op(
            11,
            "reviewProposal",
            json!({"id":"p2","notebook":"b","keep":true}),
        ),
        Some(MemberKind::App),
    );
    assert_eq!(q(&s, "noteCounts", json!({}))["pendingProposals"], 1);
    Notes.apply_with_member_kind(
        &mut s,
        &op(
            12,
            "reviewProposal",
            json!({"id":"p2","notebook":"b","keep":false}),
        ),
        Some(MemberKind::App),
    );
    assert_eq!(q(&s, "noteCounts", json!({}))["pendingProposals"], 0);
}
#[test]
fn attachments_are_immutable_and_nested_extras_survive() {
    let mut s = base();
    let p = json!({"id":"a","notebook":"b","entry":"e","role":"link","name":"Reference","source":{"kind":"web","url":"https://example.org","future":1},"extensions":{"nested":2}});
    put(&mut s, 3, "addAttachment", p.clone());
    put(&mut s, 4, "addAttachment", p.clone());
    let mut changed = p;
    changed["name"] = json!("Different");
    put(&mut s, 5, "addAttachment", changed);
    assert_eq!(q(&s, "noteCounts", json!({}))["materials"], 1);
    assert_eq!(read(&s)["invalid"], json!(["r5"]));
    let a = q(&s, "attachments", json!({"notebook":"b","entry":"e"}));
    assert_eq!(a["rows"][0]["source"]["extensions"]["future"], 1);
    assert_eq!(
        q(&s, "attachments", json!({"notebook":"b","entry":null}))["total"],
        0
    );
}
#[test]
fn validation_boundaries_unknowns_and_specs() {
    let cases = [
        (
            "putEntry",
            json!({"id":"e","notebook":"b","date":"2023-02-29"}),
        ),
        (
            "putEntry",
            json!({"id":"e","notebook":"b","tags":["x","x"]}),
        ),
        (
            "putCell",
            json!({"id":"c\n","notebook":"b","kind":"raw","source":""}),
        ),
        (
            "putCell",
            json!({"id":"c","notebook":"b","kind":"raw","source":"x".repeat(256*1024+1)}),
        ),
        (
            "resolveCell",
            json!({"id":"c","notebook":"b","source":"","expect":null,"resolves":[]}),
        ),
        (
            "recordOutput",
            json!({"id":"r","cell":"c","notebook":"b","sourceDigest":hash(""),"runtime":"","outputs":[{"mime":"text/plain","text":"x","blob":{"digest":hash("x"),"size":1,"mediaType":"text/plain"}}]}),
        ),
        (
            "addAttachment",
            json!({"id":"a","notebook":"b","role":"link","name":"x","source":{"kind":"web","url":"https://user:password@example.org"}}),
        ),
        (
            "addAttachment",
            json!({"id":"a","notebook":"b","role":"link","name":"x","source":{"kind":"library","library":"l","namespace":"n","artifact":"a","revision":"r","seconds":1}}),
        ),
    ];
    for (kind, p) in cases {
        assert!(!validate_payload(kind, &p), "{kind}: {p}");
    }
    assert!(validate_payload(
        "putCell",
        &json!({"id":"legacy-opaque-id","notebook":"b","kind":"raw","source":"🦀".repeat(65536)})
    ));
    assert!(validate_payload(
        "putEntry",
        &json!({"id":"e","notebook":"b","date":"2000-02-29"})
    ));
    let mut s = base();
    let before = read(&s);
    put(&mut s, 8, "futureKind", json!({"notebook":"b"}));
    assert_eq!(read(&s), before);
    let names: BTreeSet<_> = Notes.operations().into_iter().map(|s| s.name).collect();
    assert_eq!(names.len(), 15);
    assert!(names.contains("recordOutput"));
    let queries: BTreeSet<_> = Notes.queries().into_iter().map(|s| s.name).collect();
    assert!(queries.contains("contentDetail"));
    assert!(names.is_disjoint(&queries));
}
#[test]
fn query_pages_bind_query_arguments_and_prefix_and_truncate_utf8() {
    let mut s = base();
    let mut after = Value::Null;
    for n in 0..123 {
        let id = format!("cell-{n:03}");
        put(
            &mut s,
            n + 3,
            "putCell",
            json!({"id":id,"notebook":"b","kind":"markdown","source":"🦀".repeat(300),"after":after}),
        );
        after = json!(id);
    }
    let first = q(&s, "cells", json!({"notebook":"b","limit":17}));
    assert_eq!(first["rows"].as_array().unwrap().len(), 17);
    assert_eq!(first["rows"][0]["truncated"], true);
    assert_eq!(
        first["rows"][0]["sourcePreview"]
            .as_str()
            .unwrap()
            .chars()
            .count(),
        240
    );
    let mut all = vec![];
    let mut cursor = Value::Null;
    loop {
        let mut args = json!({"notebook":"b","limit":17});
        if !cursor.is_null() {
            args["cursor"] = cursor.clone();
        }
        let p = q(&s, "cells", args);
        all.extend(
            p["rows"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v["id"].as_str().unwrap().to_owned()),
        );
        cursor = p["next"].clone();
        if cursor.is_null() {
            break;
        }
    }
    assert_eq!(
        all,
        (0..123).map(|n| format!("cell-{n:03}")).collect::<Vec<_>>()
    );
    assert_eq!(
        Notes
            .query(
                &s,
                "cells",
                &json!({"notebook":"b","entry":null,"cursor":first["next"]})
            )
            .unwrap()["outcome"],
        "invalidArgument"
    );
    put(&mut s, 200, "futureKind", json!({}));
    assert_eq!(
        Notes
            .query(&s, "cells", &json!({"notebook":"b","cursor":first["next"]}))
            .unwrap()["outcome"],
        "staleCursor"
    );
    assert_eq!(
        Notes
            .query(&s, "cells", &json!({"notebook":"b","limit":101}))
            .unwrap()["outcome"],
        "invalidArgument"
    );
    assert_eq!(
        q(&s, "cell", json!({"notebook":"b","id":"absent"}))["outcome"],
        "notFound"
    );
}
fn rng(seed: &mut u64) -> u64 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed
}
#[test]
fn incremental_randomized_orders_equal_full_and_serialized_replay() {
    let mut seed = 0x6e6f746573_u64;
    let mut operations = vec![
        op(1, "createNotebook", json!({"id":"b","title":"Book"})),
        op(2, "putEntry", json!({"id":"e","notebook":"b"})),
    ];
    for n in 3..140 {
        let id = format!("c{}", rng(&mut seed) % 12);
        let (kind, p) = match rng(&mut seed) % 7 {
            0 => ("deleteCell", json!({"id":id,"notebook":"b"})),
            1 => (
                "moveCell",
                json!({"id":id,"notebook":"b","after":format!("c{}",rng(&mut seed)%12)}),
            ),
            2 => (
                "putCell",
                json!({"id":id,"notebook":"b","kind":"raw","source":format!("stale {n}"),"expect":"old"}),
            ),
            3 => (
                "putEntry",
                json!({"id":"e","notebook":"b","title":format!("entry {n}")}),
            ),
            _ => (
                "putCell",
                json!({"id":id,"notebook":"b","entry":"e","kind":"markdown","source":format!("source {n}")}),
            ),
        };
        operations.push(op(n, kind, p));
    }
    for _ in 0..4 {
        for i in (2..operations.len()).rev() {
            let j = 2 + rng(&mut seed) as usize % (i - 1);
            operations.swap(i, j);
        }
        let mut s = NotesState::default();
        for (i, op) in operations.iter().enumerate() {
            Notes.apply(&mut s, op);
            assert_eq!(read(&s), Notes.fold(&operations[..=i]));
            if i % 17 == 0 {
                s = serde_json::from_value(json!(s)).unwrap();
            }
        }
        assert_eq!(
            q(&s, "noteCounts", json!({}))["cells"],
            q(&s, "cells", json!({"notebook":"b"}))["total"]
        );
    }
}
fn source(kind: &str, payload: Value) -> VerifiedOperation {
    VerifiedOperation {
        source_library: "old".into(),
        author_id: "old-author".into(),
        operation_id: format!("old-{kind}"),
        author_label: "Historical writer".into(),
        kind: kind.into(),
        version: 1,
        payload,
        signed_body_digest: hash(kind),
        admitted_order: 7,
        claimed_date: json!("old date representation"),
        admission: Admission::Admitted,
        outcome: SourceOutcome::Applied,
    }
}
fn context() -> ImportContext {
    let mut c = ImportContext::default();
    for (category, id) in [
        ("notebook", "b"),
        ("cell", "c"),
        ("entry", "e"),
        ("attachment", "a"),
        ("proposal", "p"),
    ] {
        c.identities
            .insert(identity_key("old", category, id), format!("new-{id}"));
    }
    for category in ["notebook", "cell", "entry", "order", "proposal"] {
        c.revisions.insert(
            revision_key(category, "old-head"),
            format!("new-{category}-head"),
        );
    }
    for (category, id) in [
        ("notebook", "b"),
        ("cell", "c"),
        ("entry", "e"),
        ("order", "b"),
        ("proposal", "p"),
    ] {
        c.heads
            .insert(head_key(category, id), Some("old-head".into()));
    }
    c.source_order = Some(vec!["c".into()]);
    c.alternatives = Some(vec![]);
    c.translated_inputs_current = Some(true);
    c.reviewer_kind = Some(MemberKind::Device);
    c
}
#[test]
fn import_every_kind_and_disposition_is_pure_and_never_reauthors_history() {
    let cases = [
        (
            "notebook.create",
            json!({"notebook":"b","title":"B","topic":"T"}),
            "createNotebook",
        ),
        (
            "notebook.rename",
            json!({"notebook":"b","title":"New"}),
            "renameNotebook",
        ),
        (
            "notebook.archive",
            json!({"notebook":"b"}),
            "archiveNotebook",
        ),
        (
            "cell.put",
            json!({"cell":"c","notebook":"b","kind":"code","source":"x","language":"js","entry":"e"}),
            "putCell",
        ),
        (
            "cell.resolve",
            json!({"cell":"c","notebook":"b","source":"resolved"}),
            "resolveCell",
        ),
        (
            "cell.move",
            json!({"cell":"c","notebook":"b","after":"c"}),
            "moveCell",
        ),
        (
            "cell.delete",
            json!({"cell":"c","notebook":"b"}),
            "deleteCell",
        ),
        (
            "cell.output",
            json!({"cell":"c","notebook":"b","sourceDigest":hash("x"),"outputs":[{"mime":"text/plain","data":"out"},{"malformed":true}]}),
            "recordOutput",
        ),
        (
            "entry.put",
            json!({"entry":"e","notebook":"b","title":"Title","tags":["x"]}),
            "putEntry",
        ),
        (
            "attachment.add",
            json!({"attachment":"a","notebook":"b","entry":"e","role":"link","name":"Reference","source":{"kind":"web","url":"https://example.org"}}),
            "addAttachment",
        ),
        (
            "entry.propose",
            json!({"proposal":"p","notebook":"b","entry":"e","markdown":"draft","inputs":{"c":"old-head"}}),
            "proposeEntry",
        ),
        (
            "proposal.review",
            json!({"proposal":"p","notebook":"b","keep":true}),
            "reviewProposal",
        ),
    ];
    for (kind, payload, new_kind) in cases {
        let mut c = context();
        c.effective_payload = Some(payload.clone());
        let o = source(kind, payload);
        let first = translate(&o, &c);
        assert_eq!(json!(first), json!(translate(&o, &c)));
        assert_eq!(first.commands.len(), 1, "{kind}: {:?}", first.evidence);
        assert_eq!(first.commands[0].kind, new_kind);
        assert_eq!(
            first.commands[0].payload["importSource"]["authorLabel"],
            "Historical writer"
        );
        assert!(first.commands[0].payload.get("author").is_none());
        assert_eq!(first.evidence[0].source.payload, o.payload);
        for outcome in [
            SourceOutcome::Conflict,
            SourceOutcome::LateEdit,
            SourceOutcome::Invalid,
            SourceOutcome::NoEffect,
        ] {
            let mut rejected = o.clone();
            rejected.outcome = outcome;
            let result = translate(&rejected, &c);
            assert!(result.commands.is_empty());
            assert_eq!(result.evidence.len(), 1);
        }
        let mut rejected = o.clone();
        rejected.admission = Admission::Unresolved("revoked".into());
        assert!(translate(&rejected, &c).commands.is_empty());
        let mut malformed = o.clone();
        malformed.payload = json!({});
        assert!(translate(&malformed, &c).commands.is_empty(), "{kind}");
    }
}
#[test]
fn import_missing_blobs_large_runs_legacy_kinds_and_historical_keeps() {
    let mut c = context();
    let o = source(
        "cell.output",
        json!({"cell":"c","notebook":"b","sourceDigest":hash("x"),"outputs":[{"mime":"text/plain","data":"x".repeat(300000)}]}),
    );
    let translated = translate(&o, &c);
    assert_eq!(translated.blobs.len(), 1);
    assert_eq!(
        translated.blobs[0].descriptor["digest"],
        hash(&"x".repeat(300000))
    );
    assert_eq!(translated.commands.len(), 1);
    let o = source(
        "attachment.add",
        json!({"attachment":"a","notebook":"b","role":"file","name":"File","blob":{"digest":hash("cipher"),"plain":hash("bytes"),"size":5,"epoch":1}}),
    );
    let missing = translate(&o, &c);
    assert!(missing.commands.is_empty());
    assert!(missing.evidence[0].reasons[0].contains("unavailable"));
    c.blobs.insert(
        hash("cipher"),
        json!({"digest":hash("bytes"),"size":5,"mediaType":"application/octet-stream"}),
    );
    assert_eq!(translate(&o, &c).commands.len(), 1);
    for kind in ["addNote", "editNote", "journal.page", "unknown"] {
        assert!(translate(&source(kind, json!({"notebook":"b"})), &c)
            .commands
            .is_empty());
    }
    assert!(translate(
        &source(
            "notebook.create",
            json!({"notebook":"b","title":"x","kind":"legacy-type"})
        ),
        &c
    )
    .commands
    .is_empty());
    c.translated_inputs_current = Some(false);
    let keep = translate(
        &source(
            "proposal.review",
            json!({"notebook":"b","proposal":"p","keep":true}),
        ),
        &c,
    );
    assert!(keep.commands.is_empty());
    assert!(keep.evidence[0].reasons[0].contains("pending repair"));
}

mod support;
fn signed_notes_vector() -> Value {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use support::*;
    let (mut lib, owner, _) = create();
    let commands = [
        (
            "createNotebook",
            json!({"id":"b","title":"Synthetic notebook","kind":"seminar","topic":"Conformance","future":{"kept":true}}),
        ),
        (
            "putEntry",
            json!({"id":"e","notebook":"b","title":"Entry","tags":["synthetic"]}),
        ),
        (
            "putCell",
            json!({"id":"c","notebook":"b","entry":"e","kind":"code","language":"js","source":"1 + 1"}),
        ),
        (
            "recordOutput",
            json!({"id":"run","cell":"c","notebook":"b","sourceDigest":hash("1 + 1"),"runtime":"fixture","outputs":[{"mime":"text/plain","text":"2"}]}),
        ),
        (
            "putCell",
            json!({"id":"d","notebook":"b","entry":"e","kind":"markdown","source":"Second cell","after":"c"}),
        ),
        (
            "putCell",
            json!({"id":"c","notebook":"b","kind":"code","source":"stale source","expect":"unobserved"}),
        ),
        (
            "putEntry",
            json!({"id":"e","notebook":"b","title":"stale entry","expect":"unobserved"}),
        ),
        (
            "addAttachment",
            json!({"id":"material","notebook":"b","entry":"e","role":"link","name":"Source","source":{"kind":"web","url":"https://example.org/synthetic","future":true}}),
        ),
    ];
    for (i, (kind, p)) in commands.into_iter().enumerate() {
        write(&mut lib, &owner, "notes", kind, p, 50 + i as u8);
    }
    let snapshot = success(lib.view("notes", NOW).unwrap());
    let cell_revision = snapshot.admitted[2].id.clone();
    let entry_revision = snapshot.admitted[1].id.clone();
    let cell_conflict = snapshot.admitted[5].id.clone();
    let entry_conflict = snapshot.admitted[6].id.clone();
    write(
        &mut lib,
        &owner,
        "notes",
        "resolveCell",
        json!({"id":"c","notebook":"b","source":"2 + 2","expect":cell_revision,"resolves":[cell_conflict]}),
        60,
    );
    write(
        &mut lib,
        &owner,
        "notes",
        "resolveEntry",
        json!({"id":"e","notebook":"b","title":"Resolved entry","tags":["reviewed"],"expect":entry_revision,"resolves":[entry_conflict]}),
        61,
    );
    let view = success(lib.view("notes", NOW).unwrap());
    let c = view.admitted[8].id.clone();
    let d = view.admitted[4].id.clone();
    write(
        &mut lib,
        &owner,
        "notes",
        "proposeEntry",
        json!({"id":"p","notebook":"b","entry":"e","markdown":"Proposed organization","inputs":{"c":c,"d":d}}),
        62,
    );
    // Until the engine supplies authenticated roles, the wire path records a diagnostic.
    write(
        &mut lib,
        &owner,
        "notes",
        "reviewProposal",
        json!({"id":"p","notebook":"b","keep":true}),
        63,
    );
    write(
        &mut lib,
        &owner,
        "notes",
        "moveCell",
        json!({"id":"d","notebook":"b"}),
        64,
    );
    write(
        &mut lib,
        &owner,
        "notes",
        "deleteCell",
        json!({"id":"c","notebook":"b","expect":c}),
        65,
    );
    write(
        &mut lib,
        &owner,
        "notes",
        "putCell",
        json!({"id":"c","notebook":"b","kind":"raw","source":"Recover under a new ID"}),
        66,
    );
    write(
        &mut lib,
        &owner,
        "notes",
        "renameNotebook",
        json!({"id":"b","title":"Notebook renamed"}),
        67,
    );
    write(
        &mut lib,
        &owner,
        "notes",
        "archiveNotebook",
        json!({"id":"b","archived":true}),
        68,
    );
    write(
        &mut lib,
        &owner,
        "notes",
        "putCell",
        json!({"id":"invalid","notebook":"b","kind":"unsupported","source":"invalid discriminant"}),
        69,
    );
    let requests = [
        ("notebooks", json!({})),
        ("notebooks", json!({"archived":true,"limit":1})),
        ("notebook", json!({"id":"b"})),
        ("entries", json!({"notebook":"b"})),
        ("entry", json!({"notebook":"b","id":"e"})),
        ("cells", json!({"notebook":"b","limit":1})),
        ("cell", json!({"notebook":"b","id":"d"})),
        ("cell", json!({"notebook":"b","id":"c"})),
        ("attachments", json!({"notebook":"b","entry":"e"})),
        ("proposals", json!({"notebook":"b","entry":"e"})),
        (
            "contentDetail",
            json!({"notebook":"b","category":"run","id":"run"}),
        ),
        (
            "contentDetail",
            json!({"notebook":"b","category":"proposal","id":"p"}),
        ),
        (
            "contentDetail",
            json!({"notebook":"b","category":"lateEdit","id":"c"}),
        ),
        (
            "contentDetail",
            json!({"notebook":"b","category":"cellConflict","id":"c"}),
        ),
        (
            "contentDetail",
            json!({"notebook":"b","category":"entryConflict","id":"e"}),
        ),
        ("noteCounts", json!({})),
        ("noteCounts", json!({"notebook":"b"})),
        ("invalid", json!({})),
        ("conflicts", json!({"limit":1})),
    ];
    let queries: Vec<_> = requests
        .into_iter()
        .map(|(name, args)| {
            let result = success(lib.query("notes", name, args.clone(), NOW).unwrap());
            json!({"name":name,"args":args,"result":result})
        })
        .collect();
    let records: std::collections::BTreeMap<_, _> = lib
        .records()
        .iter()
        .map(|(path, bytes)| (path.clone(), STANDARD.encode(bytes)))
        .collect();
    json!({"format":"colophon/notes-conformance/1","identitySeed":1,"records":records,"queries":queries})
}
#[test]
fn deterministic_notes_conformance_vector() {
    assert_eq!(signed_notes_vector(), signed_notes_vector());
}
#[test]
fn signed_reverse_arrival_and_checkpoint_suffix_match_fresh_replay() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use support::*;
    let vector = signed_notes_vector();
    let records: colophon_core::model::Records = vector["records"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(path, bytes)| {
            (
                path.clone(),
                STANDARD.decode(bytes.as_str().unwrap()).unwrap(),
            )
        })
        .collect();
    let mut replica = opened(
        records
            .iter()
            .filter(|(p, _)| !p.starts_with("ops/"))
            .map(|(p, b)| (p.clone(), b.clone()))
            .collect(),
        &keys(1),
    );
    for (path, bytes) in records.iter().filter(|(p, _)| p.starts_with("ops/")).rev() {
        replica
            .merge([(path.clone(), bytes.clone())].into())
            .unwrap();
        let fresh = opened(replica.records().clone(), &keys(1));
        assert_eq!(
            success(replica.view("notes", NOW).unwrap()),
            success(fresh.view("notes", NOW).unwrap())
        );
    }
    let checkpoint = replica.checkpoint("notes").unwrap();
    write(
        &mut replica,
        &keys(1),
        "notes",
        "archiveNotebook",
        json!({"id":"b","archived":false}),
        80,
    );
    assert!(replica.restore_checkpoint("notes", &checkpoint).unwrap());
    let fresh = opened(replica.records().clone(), &keys(1));
    assert_eq!(
        success(replica.view("notes", NOW).unwrap()),
        success(fresh.view("notes", NOW).unwrap())
    );
}

#[test]
fn import_nested_pointers_component_revisions_and_absent_tombstone() {
    let mut ctx = context();
    ctx.identities.insert(
        identity_key("source-lib", "library", "source-lib"),
        "destination-lib".into(),
    );
    ctx.identities.insert(
        identity_key("source-lib", "namespace", "reading.saved"),
        "reading.saved".into(),
    );
    ctx.identities.insert(
        source_identity_key("source-lib", "reading.saved", "article"),
        "new-article".into(),
    );
    ctx.revisions.insert(
        source_revision_key("source-lib", "reading.saved", "old-revision"),
        "pinned-revision".into(),
    );
    let pointer = source(
        "attachment.add",
        json!({"attachment":"a","notebook":"b","role":"reading","name":"Pinned source","source":{"kind":"library","library":"source-lib","namespace":"reading.saved","artifact":"article","revision":"old-revision","quote":"A quote","page":0}}),
    );
    let result = translate(&pointer, &ctx);
    assert_eq!(result.commands.len(), 1);
    let mapped = &result.commands[0].payload["source"];
    assert_eq!(mapped["library"], "destination-lib");
    assert_eq!(mapped["artifact"], "new-article");
    assert_eq!(mapped["revision"], "pinned-revision");
    assert_eq!(
        result.evidence[0].source.payload["source"]["artifact"],
        "article"
    );
    ctx.heads.insert(head_key("cell", "c"), None);
    let delete = translate(
        &source("cell.delete", json!({"notebook":"b","cell":"c"})),
        &ctx,
    );
    assert_eq!(delete.commands.len(), 1);
    assert!(delete.commands[0].payload["expect"].is_null());
    let rename = translate(
        &source("notebook.rename", json!({"notebook":"b","title":"Title"})),
        &ctx,
    );
    assert_eq!(rename.commands[0].payload["expect"], "new-notebook-head");
    let moving = translate(
        &source(
            "cell.move",
            json!({"notebook":"b","cell":"c","after":"missing"}),
        ),
        &ctx,
    );
    assert_eq!(moving.commands[0].payload["expect"], "new-order-head");
    assert!(moving.commands[0].payload["after"].is_null());
    assert!(!moving.evidence[0].reasons.is_empty());
    let mut s = NotesState::default();
    put(
        &mut s,
        1,
        "createNotebook",
        json!({"id":"new-b","title":"B"}),
    );
    put(
        &mut s,
        2,
        "renameNotebook",
        json!({"id":"new-b","title":"Native title"}),
    );
    Notes.apply(
        &mut s,
        &op(
            3,
            &rename.commands[0].kind,
            rename.commands[0].payload.clone(),
        ),
    );
    assert_eq!(
        q(&s, "notebook", json!({"id":"new-b"}))["title"],
        "Native title"
    );
    assert_eq!(read(&s)["conflicts"].as_array().unwrap().len(), 1);
}
#[test]
fn every_collection_pages_and_empty_or_oversize_queries_are_explicit() {
    let mut s = base();
    for n in 0..7 {
        put(
            &mut s,
            10 + n,
            "putEntry",
            json!({"id":format!("e{n}"),"notebook":"b","title":format!("Entry {n}")}),
        );
        put(
            &mut s,
            30 + n,
            "addAttachment",
            json!({"id":format!("a{n}"),"notebook":"b","role":"link","name":"Link","source":{"kind":"web","url":"https://example.org"}}),
        );
        put(
            &mut s,
            50 + n,
            "proposeEntry",
            json!({"id":format!("p{n}"),"notebook":"b","entry":"e","markdown":"Proposal","inputs":{}}),
        );
    }
    for (name, base, total) in [
        ("entries", json!({"notebook":"b"}), 8),
        ("attachments", json!({"notebook":"b","entry":null}), 7),
        (
            "proposals",
            json!({"notebook":"b","entry":"e","status":"pending"}),
            7,
        ),
    ] {
        let mut args = base;
        args["limit"] = json!(2);
        let mut seen = BTreeSet::new();
        loop {
            let page = q(&s, name, args.clone());
            assert_eq!(page["total"], total);
            for row in page["rows"].as_array().unwrap() {
                assert!(seen.insert(row["id"].as_str().unwrap().to_owned()));
            }
            if page["next"].is_null() {
                break;
            }
            args["cursor"] = page["next"].clone();
        }
        assert_eq!(seen.len(), total as usize);
    }
    assert_eq!(
        Notes
            .query(&s, "cell", &json!({"notebook":"missing","id":"c"}))
            .unwrap()["outcome"],
        "notFound"
    );
    put(
        &mut s,
        70,
        "putCell",
        json!({"id":"huge-extra","notebook":"b","kind":"raw","source":"small","future":"x".repeat(1024*1024)}),
    );
    assert_eq!(
        Notes
            .query(&s, "cell", &json!({"notebook":"b","id":"huge-extra"}))
            .unwrap()["outcome"],
        "contentTooLarge"
    );
    assert_eq!(
        q(&s, "cells", json!({"notebook":"b"}))["rows"][0]["sourcePreview"],
        "small"
    );
}
#[test]
#[ignore = "100k shape/performance gate; run explicitly to avoid repeated shared-worker load"]
fn indexed_hundred_thousand_cell_notebook() {
    let start = std::time::Instant::now();
    let mut s = base();
    let mut after = Value::Null;
    for n in 0..100_000 {
        let id = format!("c{n:06}");
        put(
            &mut s,
            n + 3,
            "putCell",
            json!({"id":id,"notebook":"b","entry":"e","kind":"markdown","source":"Synthetic source","after":after}),
        );
        after = json!(id);
    }
    let build = start.elapsed();
    let start = std::time::Instant::now();
    let page = q(&s, "cells", json!({"notebook":"b","entry":"e","limit":30}));
    assert_eq!(page["total"], 100000);
    assert_eq!(page["rows"].as_array().unwrap().len(), 30);
    let second = q(
        &s,
        "cells",
        json!({"notebook":"b","entry":"e","limit":30,"cursor":page["next"]}),
    );
    assert_eq!(second["rows"][0]["id"], "c000030");
    assert_eq!(q(&s, "noteCounts", json!({}))["cells"], 100000);
    eprintln!(
        "100k notes projection: {:?}; two indexed pages + counts: {:?}",
        build,
        start.elapsed()
    );
}

#[test]
fn logical_retries_noop_moves_and_preview_alias_collisions() {
    let mut s = base();
    put(
        &mut s,
        3,
        "addNote",
        json!({"id":"c","notebook":"b","text":"original","kind":"not-a-real-kind"}),
    );
    let before = q(&s, "notebook", json!({"id":"b"}));
    put(
        &mut s,
        4,
        "moveCell",
        json!({"id":"c","notebook":"b","after":"missing"}),
    );
    assert_eq!(q(&s, "notebook", json!({"id":"b"})), before);
    put(
        &mut s,
        5,
        "addNote",
        json!({"id":"c","notebook":"b","text":"losing create"}),
    );
    assert_eq!(
        q(&s, "cell", json!({"notebook":"b","id":"c"}))["source"],
        "original"
    );
    assert_eq!(
        q(
            &s,
            "contentDetail",
            json!({"notebook":"b","category":"cellConflict","id":"c"})
        )["versions"]["rows"][0]["candidate"]["source"],
        "losing create"
    );
    let proposal = json!({"id":"p","notebook":"b","entry":"e","markdown":"draft","inputs":{},"future":"original"});
    put(&mut s, 6, "proposeEntry", proposal.clone());
    Notes.apply_with_member_kind(
        &mut s,
        &op(
            7,
            "reviewProposal",
            json!({"id":"p","notebook":"b","keep":false,"future":"review"}),
        ),
        Some(MemberKind::App),
    );
    put(&mut s, 8, "proposeEntry", proposal);
    assert!(read(&s)["invalid"].as_array().unwrap().is_empty());
    assert_eq!(
        q(&s, "proposals", json!({"notebook":"b","entry":"e"}))["rows"][0]["status"],
        "dismissed"
    );
    let before_order = q(&s, "notebook", json!({"id":"b"}))["orderRevision"].clone();
    put(
        &mut s,
        9,
        "deleteCell",
        json!({"id":"absent","notebook":"b"}),
    );
    assert_eq!(
        q(&s, "notebook", json!({"id":"b"}))["orderRevision"],
        before_order
    );
}

#[test]
fn import_refuses_to_invent_source_order_or_resolve_unprojected_history() {
    let mut ctx = context();
    ctx.source_order = None;
    let moving = source(
        "cell.move",
        json!({"notebook":"b","cell":"c","after":"unknown"}),
    );
    assert!(translate(&moving, &ctx).commands.is_empty());
    ctx.alternatives = Some(vec!["old-conflict".into()]);
    ctx.revisions.insert(
        revision_key("cell", "old-conflict"),
        "imported-conflict".into(),
    );
    let resolve = source(
        "cell.resolve",
        json!({"notebook":"b","cell":"c","source":"settled"}),
    );
    let pending = translate(&resolve, &ctx);
    assert!(pending.commands.is_empty());
    assert!(pending.evidence[0].reasons[0].contains("conflict adapter"));
    ctx.projected_alternatives = Some(vec!["imported-conflict".into()]);
    assert_eq!(
        translate(&resolve, &ctx).commands[0].payload["resolves"],
        json!(["imported-conflict"])
    );
    ctx.effective_payload = Some(json!({"kind":"raw","source":"x".repeat(256*1024+1)}));
    let large = source(
        "cell.put",
        json!({"notebook":"b","cell":"c","kind":"raw","source":"x".repeat(256*1024+1)}),
    );
    let translated = translate(&large, &ctx);
    assert!(translated.commands.is_empty());
    assert_eq!(translated.evidence[0].source.payload, large.payload);
}
