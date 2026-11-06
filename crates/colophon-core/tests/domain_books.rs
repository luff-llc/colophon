#![allow(clippy::unwrap_used)]
use colophon_core::{
    domain::{DomainModule, Reducer},
    domains::books::{
        import::{transform, ImportState, SourceOperation},
        validate, BooksState, ReadingBooks,
    },
    model::{MemberKind, OperationView},
};
use serde_json::{json, Value};
fn op(n: u64, kind: &str, payload: Value) -> OperationView {
    OperationView {
        id: format!("op-{n:05}"),
        kind: kind.into(),
        author: "signer".into(),
        author_label: "Reader".into(),
        origin: "person".into(),
        clock: n,
        created: "2026-11-06T00:00:00Z".into(),
        payload,
    }
}
fn apply(s: &mut BooksState, n: u64, k: &str, p: Value) {
    ReadingBooks.apply(s, &op(n, k, p));
}
fn q(s: &BooksState, n: &str, a: Value) -> Value {
    ReadingBooks.query(s, n, &a).unwrap()
}
fn add(s: &mut BooksState) {
    apply(
        s,
        1,
        "addBook",
        json!({"id":"b","title":"Book","creator":"Writer","catalogKey":"OL1","extra":{"a":1},"author":"forged","extensions":{"a":2}}),
    );
}
#[test]
fn components_extensions_readings_and_ordered_backwards_progress() {
    let mut s = BooksState::default();
    add(&mut s);
    apply(
        &mut s,
        2,
        "editBook",
        json!({"id":"b","title":"Revised","expect":"op-00001","isbn":null}),
    );
    apply(
        &mut s,
        3,
        "setPlan",
        json!({"id":"b","status":"reading","expect":"op-00001","started":"2024-02-29"}),
    );
    apply(
        &mut s,
        4,
        "position",
        json!({"id":"b","fraction":0.7,"page":70}),
    );
    apply(&mut s, 5, "position", json!({"id":"b","fraction":0.2}));
    let b = q(&s, "book", json!({"id":"b"}))["value"].clone();
    assert_eq!(
        b["heads"],
        json!({"metadata":"op-00002","plan":"op-00003","progress":"op-00005","loan":null,"activity":"op-00005"})
    );
    assert_eq!(b["book"]["page"], 70);
    assert_eq!(b["book"]["fraction"], 0.2);
    assert_eq!(b["book"]["author"], "signer");
    assert_eq!(b["extensions"]["author"], "forged");
    assert_eq!(b["extensions"]["extensions"], json!({"a":2}));
    apply(
        &mut s,
        6,
        "setPlan",
        json!({"id":"b","status":"finished","finished":"2024-03-01"}),
    );
    assert_eq!(
        q(&s, "book", json!({"id":"b"}))["value"]["currentReading"]["started"],
        "2024-02-29"
    );
    assert_eq!(
        q(
            &s,
            "books",
            json!({"finishedYear":2024,"status":"finished"})
        )["value"]["total"],
        1
    );
    apply(
        &mut s,
        7,
        "setPlan",
        json!({"id":"b","status":"reading","reread":true}),
    );
    let readings = q(&s, "readings", json!({"book":"b"}));
    assert_eq!(readings["value"]["total"], 2);
    assert_eq!(readings["value"]["rows"][0]["started"], Value::Null);
    assert_eq!(readings["value"]["rows"][1]["finished"], "2024-03-01");
    apply(
        &mut s,
        8,
        "position",
        json!({"id":"b","fraction":0.1,"page":null}),
    );
    assert_eq!(
        q(&s, "books", json!({}))["value"]["rows"][0]["page"],
        Value::Null
    );
}
#[test]
fn conflicts_exact_resolution_tombstones_and_child_activity() {
    let mut s = BooksState::default();
    add(&mut s);
    apply(
        &mut s,
        2,
        "addNote",
        json!({"id":"n","book":"b","text":"first"}),
    );
    apply(
        &mut s,
        3,
        "editNote",
        json!({"id":"n","text":"loser","expect":null,"unknown":1}),
    );
    apply(
        &mut s,
        4,
        "resolveNote",
        json!({"id":"n","text":"wrong","expect":"op-00002","resolves":[]}),
    );
    assert_eq!(
        q(&s, "note", json!({"id":"n"}))["value"]["alternativeCount"],
        2
    );
    apply(
        &mut s,
        5,
        "resolveNote",
        json!({"id":"n","text":"reviewed","expect":"op-00002","resolves":["op-00003","op-00004"]}),
    );
    assert_eq!(
        q(&s, "note", json!({"id":"n"}))["value"]["alternativeCount"],
        0
    );
    assert_eq!(
        q(&s, "book", json!({"id":"b"}))["value"]["heads"]["activity"],
        "op-00005"
    );
    let c = q(&s, "conflicts", json!({"object":"n"}));
    assert_eq!(c["value"]["rows"][0]["candidate"]["unknown"], 1);
    assert_eq!(c["value"]["rows"][0]["authorLabel"], "Reader");
    assert_eq!(c["value"]["rows"][0]["historical"], false);
    apply(
        &mut s,
        6,
        "deleteBook",
        json!({"id":"b","expect":"op-00001"}),
    );
    assert!(q(&s, "book", json!({"id":"b"})).get("value").is_some());
    apply(
        &mut s,
        7,
        "deleteBook",
        json!({"id":"b","expect":"op-00005"}),
    );
    assert_eq!(q(&s, "book", json!({"id":"b"}))["reason"], "deleted");
    assert_eq!(q(&s, "note", json!({"id":"n"}))["reason"], "deleted");
    assert_eq!(q(&s, "bookNotes", json!({"book":"b"}))["reason"], "deleted");
    assert_eq!(q(&s, "books", json!({}))["value"]["total"], 0);
    apply(
        &mut s,
        8,
        "addBook",
        json!({"id":"b","title":"resurrect","creator":""}),
    );
    apply(&mut s, 9, "editNote", json!({"id":"n","text":"late"}));
    assert_eq!(q(&s, "book", json!({"id":"b"}))["reason"], "deleted");
    assert_eq!(
        q(&s, "conflicts", json!({"object":"n"}))["value"]["total"],
        3
    );
    let mut s = BooksState::default();
    add(&mut s);
    apply(
        &mut s,
        2,
        "addNote",
        json!({"id":"n","book":"b","text":"t"}),
    );
    apply(&mut s, 3, "deleteNote", json!({"id":"n"}));
    apply(
        &mut s,
        4,
        "addNote",
        json!({"id":"n","book":"b","text":"t"}),
    );
    assert_eq!(q(&s, "note", json!({"id":"n"}))["reason"], "deleted");
    assert_eq!(
        q(&s, "books", json!({}))["value"]["rows"][0]["noteCount"],
        0
    );
}
#[test]
fn exact_retries_and_signer_scoped_loan_receipts() {
    let mut s = BooksState::default();
    add(&mut s);
    let b = q(&s, "book", json!({"id":"b"}))["value"].clone();
    add(&mut s);
    assert_eq!(q(&s, "book", json!({"id":"b"}))["value"], b);
    let loan = op(
        2,
        "setCopyLoan",
        json!({"id":"b","status":"returned","requestID":"r","expect":null,"proposal":{"acceptedBy":"untrusted"}}),
    );
    ReadingBooks.apply(&mut s, &loan);
    assert_eq!(q(&s, "invalid", json!({}))["value"]["total"], 1);
    ReadingBooks.apply_with_member_kind(&mut s, &loan, Some(MemberKind::Server));
    assert_eq!(
        q(&s, "book", json!({"id":"b"}))["value"]["loan"],
        Value::Null
    );
    ReadingBooks.apply_with_member_kind(&mut s, &loan, Some(MemberKind::Device));
    assert_eq!(
        q(&s, "book", json!({"id":"b"}))["value"]["loan"]["author"],
        "signer"
    );
    let mut retry = loan.clone();
    retry.id = "retry".into();
    retry.clock = 3;
    ReadingBooks.apply_with_member_kind(&mut s, &retry, Some(MemberKind::App));
    assert_eq!(
        q(&s, "book", json!({"id":"b"}))["value"]["heads"]["loan"],
        "op-00002"
    );
    retry.payload["status"] = json!("needsReturn");
    ReadingBooks.apply_with_member_kind(&mut s, &retry, Some(MemberKind::Device));
    assert_eq!(
        q(&s, "conflicts", json!({"object":"b"}))["value"]["total"],
        1
    );
    retry.author = "another".into();
    retry.payload.as_object_mut().unwrap().remove("expect");
    ReadingBooks.apply_with_member_kind(&mut s, &retry, Some(MemberKind::Device));
    assert_eq!(
        q(&s, "book", json!({"id":"b"}))["value"]["loan"]["author"],
        "another"
    );
}
#[test]
fn validation_boundaries_and_generated_specs() {
    for (kind, payload) in [
        ("addBook", json!({"id":"","title":"T","creator":""})),
        ("addBook", json!({"id":"b","title":"  ","creator":""})),
        ("editBook", json!({"id":"b","pages":0})),
        ("position", json!({"id":"b","fraction":1.1})),
        ("position", json!({"id":"b","fraction":0,"page":-1})),
        ("setPlan", json!({"id":"b","status":"unknown"})),
        (
            "setPlan",
            json!({"id":"b","status":"reading","started":"1900-02-29"}),
        ),
        (
            "resolveNote",
            json!({"id":"n","text":"t","expect":null,"resolves":[]}),
        ),
        (
            "resolveNote",
            json!({"id":"n","text":"t","expect":"r","resolves":["z","a"]}),
        ),
        (
            "addNote",
            json!({"id":"n","book":"b","text":"é".repeat(131073)}),
        ),
        (
            "editBook",
            json!({"id":"b","publicationYear":9007199254740992u64}),
        ),
    ] {
        assert!(!validate(kind, &payload), "{kind}");
        let spec = ReadingBooks
            .operations()
            .into_iter()
            .find(|s| s.name == kind)
            .unwrap();
        assert!(!colophon_core::domain::validate_input(
            &spec.input_schema,
            &payload
        ));
    }
    assert!(validate(
        "setPlan",
        &json!({"id":"b","status":"reading","started":"2000-02-29"})
    ));
    assert!(validate(
        "editBook",
        &json!({"id":"legacy:b","pages":null,"publicationYear":-1})
    ));
    assert_eq!(ReadingBooks.operations().len(), 10);
    assert_eq!(ReadingBooks.queries().len(), 10);
    let mut s = BooksState::default();
    apply(&mut s, 1, "unknown", json!({}));
    assert_eq!(q(&s, "invalid", json!({}))["value"]["total"], 0);
    apply(&mut s, 2, "addBook", json!({}));
    assert_eq!(q(&s, "invalid", json!({}))["value"]["total"], 1);
}
#[test]
fn paging_filters_counts_membership_and_bounded_previews() {
    let mut s = BooksState::default();
    for i in 1..=123 {
        apply(
            &mut s,
            i,
            "addBook",
            json!({"id":format!("b{i}"),"title":format!("Book {i}"),"creator":"A","catalogKey":"OL1"}),
        );
    }
    let first = q(&s, "books", json!({"limit":50}));
    assert_eq!(first["value"]["rows"].as_array().unwrap().len(), 50);
    assert_eq!(first["value"]["rows"][0]["id"], "b123");
    let next = q(
        &s,
        "books",
        json!({"cursor":first["value"]["next"],"limit":50}),
    );
    assert_eq!(next["value"]["rows"][0]["id"], "b73");
    let end = q(&s, "books", json!({"cursor":next["value"]["next"]}));
    assert_eq!(end["value"]["rows"].as_array().unwrap().len(), 23);
    assert_eq!(end["value"]["next"], Value::Null);
    assert_eq!(
        q(
            &s,
            "books",
            json!({"cursor":first["value"]["next"],"status":"reading"})
        )["reason"],
        "invalidArgument"
    );
    apply(
        &mut s,
        124,
        "setPlan",
        json!({"id":"b1","status":"finished","finished":"2025-01-01"}),
    );
    assert_eq!(
        q(&s, "books", json!({"cursor":first["value"]["next"]}))["reason"],
        "staleCursor"
    );
    assert_eq!(
        q(&s, "books", json!({"finishedYear":null}))["value"]["total"],
        122
    );
    assert_eq!(
        q(&s, "books", json!({"finishedYear":2025}))["value"]["total"],
        1
    );
    assert_eq!(
        q(&s, "bookCounts", json!({}))["value"]["byStatus"]["finished"],
        1
    );
    let membership = q(&s, "catalogMembership", json!({"keys":["OL1","missing"]}));
    assert_eq!(membership["value"][0]["total"], 123);
    assert_eq!(
        membership["value"][0]["bookIDs"].as_array().unwrap().len(),
        100
    );
    for i in 125..128 {
        apply(
            &mut s,
            i,
            "addNote",
            json!({"id":format!("n{i}"),"book":"b1","text":"é".repeat(2000)}),
        );
    }
    let notes = q(
        &s,
        "bookNotes",
        json!({"book":"b1","order":"oldest","limit":1}),
    );
    assert_eq!(notes["value"]["rows"][0]["id"], "n125");
    assert_eq!(notes["value"]["rows"][0]["truncated"], true);
    assert!(
        notes["value"]["rows"][0]["textPreview"]
            .as_str()
            .unwrap()
            .len()
            <= 512
    );
    assert_eq!(
        q(
            &s,
            "bookNotes",
            json!({"book":"b1","order":"oldest","limit":1,"cursor":notes["value"]["next"]})
        )["value"]["rows"][0]["id"],
        "n126"
    );
    for args in [
        json!({"limit":0}),
        json!({"limit":101}),
        json!({"cursor":"garbage"}),
        json!({"status":"no"}),
        json!({"finishedYear":0}),
        json!({"offset":1}),
    ] {
        assert_eq!(q(&s, "books", args)["reason"], "invalidArgument");
    }
    assert_eq!(q(&s, "book", json!({"id":"missing"}))["reason"], "notFound");
    assert_eq!(
        q(&s, "catalogMembership", json!({"keys":vec!["key";101]}))["reason"],
        "invalidArgument"
    );
}
fn rng(seed: &mut u64) -> u64 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed
}
#[test]
fn randomized_incremental_and_checkpoint_replay_equal_full_fold() {
    let mut seed = 0x23abcdef_u64;
    let mut ops = vec![];
    for n in 1..150 {
        let id = format!("b{}", rng(&mut seed) % 8);
        let (kind, p) = match rng(&mut seed) % 9 {
            0 => ("addBook", json!({"id":id,"title":"Book","creator":"A"})),
            1 => (
                "editBook",
                json!({"id":id,"title":"Changed","expect":if n%2==0 {Value::Null}else{json!("old")}}),
            ),
            2 => ("setPlan", json!({"id":id,"status":"reading","reread":true})),
            3 => ("position", json!({"id":id,"fraction":0.25})),
            4 => ("deleteBook", json!({"id":id})),
            5 => (
                "addNote",
                json!({"id":format!("n{}",rng(&mut seed)%8),"book":id,"text":"note"}),
            ),
            6 => (
                "editNote",
                json!({"id":format!("n{}",rng(&mut seed)%8),"text":"changed"}),
            ),
            7 => ("deleteNote", json!({"id":format!("n{}",rng(&mut seed)%8)})),
            _ => (
                "resolveNote",
                json!({"id":"n0","text":"resolved","expect":"bad","resolves":[]}),
            ),
        };
        ops.push(op(n, kind, p));
    }
    for _ in 0..5 {
        for i in (1..ops.len()).rev() {
            let j = rng(&mut seed) as usize % (i + 1);
            ops.swap(i, j);
        }
        let mut state = BooksState::default();
        for (i, o) in ops.iter().enumerate() {
            ReadingBooks.apply(&mut state, o);
            assert_eq!(q(&state, "read", json!({})), ReadingBooks.fold(&ops[..=i]));
            if i % 19 == 0 {
                state = serde_json::from_value(serde_json::to_value(&state).unwrap()).unwrap();
            }
        }
    }
}
fn src(n: u64, k: &str, payload: Value) -> SourceOperation {
    SourceOperation {
        source_library: "old-library".into(),
        author_id: "old-author".into(),
        author_label: "Historical reader".into(),
        operation_id: format!("old-{n}"),
        signed_body_digest: format!("{n:064x}"),
        kind: k.into(),
        version: 1,
        payload,
        admitted_order: n,
        claimed_date: json!("original date"),
        admission: "admitted".into(),
    }
}
#[test]
fn every_import_kind_heads_alternatives_and_lifecycles() {
    let mut state = ImportState::default();
    let cases = [
        src(
            1,
            "book.add",
            json!({"book":"b","title":"Book","author":"Writer","year":2020,"openLibraryKey":"OL1","rawBooklist":{"x":1}}),
        ),
        src(
            2,
            "book.edit",
            json!({"book":"b","title":"Edited","isbn":"ignored"}),
        ),
        src(
            3,
            "book.setPlan",
            json!({"book":"b","status":"reading","expect":"old-1"}),
        ),
        src(4, "book.progress", json!({"book":"b","fraction":0.5})),
        src(
            5,
            "note.add",
            json!({"note":"n","book":"b","text":"original"}),
        ),
        src(
            6,
            "note.edit",
            json!({"note":"n","text":"loser","expect":"wrong"}),
        ),
        src(
            7,
            "note.edit",
            json!({"note":"n","text":"edited","expect":"old-5"}),
        ),
        src(
            8,
            "note.resolve",
            json!({"note":"n","text":"resolved","expect":"old-7"}),
        ),
        src(9, "note.delete", json!({"note":"n"})),
        src(10, "book.remove", json!({"book":"b"})),
        src(11, "book.add", json!({"book":"b","title":"Recreated"})),
        src(
            12,
            "note.add",
            json!({"note":"n","book":"b","text":"new occurrence"}),
        ),
    ];
    let mut kinds = vec![];
    let mut clean = BooksState::default();
    for source in cases {
        let result = transform(&state, &source);
        assert_eq!(result.evidence.len(), 1);
        assert_eq!(
            result.evidence[0].source["authorLabel"],
            "Historical reader"
        );
        if source.admitted_order == 2 {
            assert!(result.commands[0].payload.get("isbn").is_none());
        }
        if source.admitted_order == 3 {
            assert_eq!(result.commands[0].payload["expect"], "destination-1");
            assert_eq!(result.commands[0].payload["started"], Value::Null);
        }
        if source.admitted_order == 4 {
            assert_eq!(result.commands[0].payload["page"], Value::Null);
        }
        if source.admitted_order == 6 {
            assert!(result.commands.is_empty());
            assert_eq!(result.evidence[0].disposition["component"], "text");
        }
        if source.admitted_order == 8 {
            assert_eq!(
                result.evidence[0].disposition["resolvesEvidence"]
                    .as_array()
                    .unwrap()
                    .len(),
                1
            );
        }
        if source.admitted_order == 11 {
            assert_ne!(result.commands[0].payload["id"], "b");
        }
        state = result.state;
        for command in result.commands {
            kinds.push(command.kind.clone());
            let mut o = op(source.admitted_order, &command.kind, command.payload);
            o.id = format!("destination-{}", source.admitted_order);
            ReadingBooks.apply(&mut clean, &o);
            state.bind_output(&command.output_key, &o.id);
        }
    }
    for k in [
        "addBook",
        "editBook",
        "setPlan",
        "position",
        "addNote",
        "editNote",
        "resolveNote",
        "deleteNote",
        "deleteBook",
    ] {
        assert!(kinds.contains(&k.into()));
    }
    assert_eq!(q(&clean, "books", json!({}))["value"]["total"], 1);
    assert_eq!(
        q(&clean, "conflicts", json!({"object":"b"}))["value"]["total"],
        0
    );
}
#[test]
fn import_legacy_malformed_rejected_unknown_and_invalid_history() {
    let start = transform(
        &ImportState::default(),
        &src(1, "book.add", json!({"book":"b","title":"B"})),
    );
    let state = start.state;
    for source in [
        src(2, "book.add", json!({"book":"b","title":"Duplicate"})),
        src(
            3,
            "book.setPlan",
            json!({"book":"b","status":"historic-unknown"}),
        ),
        src(4, "book.progress", json!({"book":"b","fraction":2})),
        src(
            5,
            "book.progress",
            json!({"book":"b","fraction":0.2,"page":-1}),
        ),
        src(6, "legacy.plan", json!({"book":"b"})),
        src(
            7,
            "note.add",
            json!({"note":"orphan","book":"missing","text":"keep"}),
        ),
        src(8, "book.add", json!({"book":"bad"})),
        src(
            9,
            "book.setPlan",
            json!({"book":"b","status":"reading","expect":"stale"}),
        ),
    ] {
        let result = transform(&state, &source);
        assert!(result.commands.is_empty(), "{}", source.kind);
        assert_eq!(result.evidence[0].source["payload"], source.payload);
    }
    for admission in ["refused", "held", "invalidSignature", "unavailable"] {
        let mut source = src(10, "book.add", json!({"book":"x","title":"Never"}));
        source.admission = admission.into();
        let r = transform(&state, &source);
        assert!(r.commands.is_empty());
        assert_eq!(r.evidence[0].disposition["outcome"], "unresolved");
    }
    let repeated = transform(&state, &src(1, "book.add", json!({"book":"b","title":"B"})));
    assert!(repeated.commands.is_empty());
    assert!(repeated.evidence.is_empty());
    let mut legacy = src(
        11,
        "book.add",
        json!({"book":"legacy","title":"Version not tested by old fold"}),
    );
    legacy.version = 42;
    assert_eq!(transform(&state, &legacy).commands.len(), 1);
    let typed = src(
        12,
        "book.edit",
        json!({"book":"b","copyLoan":{"version":1,"status":"returned","requestID":"return-1","provenance":{"producerID":"p","acceptingUserID":"u","confirmedByUser":true}}}),
    );
    let r = transform(&state, &typed);
    assert_eq!(r.commands.len(), 2);
    assert_eq!(r.commands[1].kind, "setCopyLoan");
    assert_eq!(r.commands[1].child_index, 1);
    let bad = src(
        13,
        "book.edit",
        json!({"book":"b","copyLoan":{"version":1,"status":"returned","requestID":"r","provenance":{"confirmedByUser":false}}}),
    );
    let r = transform(&state, &bad);
    assert!(r.commands.iter().all(|c| c.kind != "setCopyLoan"));
}
mod support;
use support::books as books_vector;
#[test]
fn deterministic_books_vector() {
    books_vector::check(true);
}
#[test]
fn reverse_record_arrival_and_engine_checkpoint_match_fresh_replay() {
    use support::*;
    let (records, _) = books_vector::scenario();
    let owner = keys(5);
    let expected = success(
        opened(records.clone(), &owner)
            .view("reading.books", NOW)
            .unwrap(),
    );
    let authority = records
        .iter()
        .filter(|(p, _)| !p.starts_with("ops/"))
        .map(|(p, b)| (p.clone(), b.clone()))
        .collect();
    let mut lib = opened(authority, &owner);
    lib.set_checkpoint_policy(colophon_core::engine::CheckpointPolicy {
        every: 2,
        retain: 4,
    });
    for (p, b) in records.iter().rev().filter(|(p, _)| p.starts_with("ops/")) {
        lib.merge(std::collections::BTreeMap::from([(p.clone(), b.clone())]))
            .unwrap();
        let rebuilt = opened(lib.records().clone(), &owner);
        assert_eq!(
            success(lib.view("reading.books", NOW).unwrap()),
            success(rebuilt.view("reading.books", NOW).unwrap())
        );
    }
    assert_eq!(success(lib.view("reading.books", NOW).unwrap()), expected);
    let bytes = lib.checkpoint("reading.books").unwrap();
    assert!(lib.restore_checkpoint("reading.books", &bytes).unwrap());
    assert_eq!(success(lib.view("reading.books", NOW).unwrap()), expected);
}

#[test]
fn orphan_import_materialization_and_output_binding_preserve_attribution() {
    let first = src(
        1,
        "note.add",
        json!({"note":"n","book":"b","text":"orphan","quote":"quoted"}),
    );
    let pending = transform(&ImportState::default(), &first);
    assert_eq!(pending.evidence[0].disposition["outcome"], "pending");
    let edited = transform(
        &pending.state,
        &src(
            2,
            "note.edit",
            json!({"note":"n","text":"edited before parent","expect":"old-1"}),
        ),
    );
    let mut materialized = transform(
        &edited.state,
        &src(3, "book.add", json!({"book":"b","title":"Parent"})),
    );
    assert_eq!(
        materialized
            .commands
            .iter()
            .map(|c| c.kind.as_str())
            .collect::<Vec<_>>(),
        vec!["addBook", "addNote", "editNote"]
    );
    let mut state = BooksState::default();
    for i in 0..materialized.commands.len() {
        let command = materialized.commands[i].clone();
        let mut operation = op(i as u64 + 1, &command.kind, command.payload);
        operation.id = format!("dest-{i}");
        ReadingBooks.apply(&mut state, &operation);
        materialized.bind_output(&command.output_key, &operation.id);
    }
    assert_eq!(
        q(&state, "note", json!({"id":"n"}))["value"]["text"],
        "edited before parent"
    );
    assert_eq!(
        q(&state, "conflicts", json!({"object":"n"}))["value"]["total"],
        0
    );
    assert_eq!(materialized.evidence.len(), 3);
    assert!(materialized
        .evidence
        .iter()
        .all(|e| !e.output_operation_ids.is_empty()));
    assert_eq!(
        materialized.commands[1].payload["importSource"]["operationID"],
        "old-1"
    );
    let removed = transform(&pending.state, &src(4, "book.remove", json!({"book":"b"})));
    let later = transform(
        &removed.state,
        &src(5, "book.add", json!({"book":"b","title":"Parent"})),
    );
    assert_eq!(later.commands.len(), 1);
}

#[test]
fn unknown_import_fields_merge_without_clean_field_collisions() {
    let initial = transform(
        &ImportState::default(),
        &src(
            1,
            "book.add",
            json!({"book":"b","title":"Title","creator":"old extra","rawBooklist":{"raw":1},"other":2}),
        ),
    );
    let first = &initial.commands[0];
    assert_eq!(first.payload["creator"], "");
    assert_eq!(first.payload["legacyExtras"]["creator"], "old extra");
    assert_eq!(first.payload["rawBooklist"], json!({"raw":1}));
    let changed = transform(
        &initial.state,
        &src(
            2,
            "book.edit",
            json!({"book":"b","newExtra":3,"expect":"ignored by old edit"}),
        ),
    );
    assert_eq!(changed.commands[0].payload["rawBooklist"], json!({"raw":1}));
    assert_eq!(
        changed.commands[0].payload["legacyExtras"]["expect"],
        "ignored by old edit"
    );
    assert_ne!(changed.commands[0].payload["expect"], "ignored by old edit");
}

#[test]
fn response_budget_and_complete_note_editor_value() {
    let mut state = BooksState::default();
    add(&mut state);
    apply(
        &mut state,
        2,
        "addNote",
        json!({"id":"n","book":"b","text":"x".repeat(262144),"quote":"q".repeat(262144)}),
    );
    let note = q(&state, "note", json!({"id":"n"}));
    assert_eq!(note["value"]["text"].as_str().unwrap().len(), 262144);
    assert!(serde_json::to_vec(&note).unwrap().len() <= 1024 * 1024);
    apply(
        &mut state,
        3,
        "editBook",
        json!({"id":"b","huge":"x".repeat(1024*1024)}),
    );
    assert_eq!(
        q(&state, "book", json!({"id":"b"}))["reason"],
        "unavailable"
    );
    assert_eq!(q(&state, "books", json!({}))["value"]["total"], 1);
    apply(
        &mut state,
        4,
        "editBook",
        json!({"id":"b","expect":"stale","huge":"x".repeat(1024*1024)}),
    );
    let conflicts = q(&state, "conflicts", json!({"object":"b"}));
    assert_eq!(conflicts["value"]["rows"][0]["authorLabel"], "Reader");
    assert_eq!(
        conflicts["value"]["rows"][0]["candidate"]["truncated"],
        true
    );
}

#[test]
fn all_nine_source_kinds_retain_malformed_and_rejected_history() {
    for (i, kind) in [
        "book.add",
        "book.edit",
        "book.remove",
        "book.setPlan",
        "book.progress",
        "note.add",
        "note.edit",
        "note.resolve",
        "note.delete",
    ]
    .into_iter()
    .enumerate()
    {
        let source = src(i as u64 + 1, kind, json!({"unrecognized":"retain"}));
        let malformed = transform(&ImportState::default(), &source);
        assert!(malformed.commands.is_empty());
        assert_eq!(malformed.evidence[0].source["payload"], source.payload);
        let mut rejected = source.clone();
        rejected.admission = "refused".into();
        let result = transform(&ImportState::default(), &rejected);
        assert!(result.commands.is_empty());
        assert_eq!(result.evidence[0].disposition["outcome"], "unresolved");
    }
}

#[test]
fn stale_source_resolution_stays_historical_and_notes_count_toward_book_conflicts() {
    let initial = transform(
        &ImportState::default(),
        &src(1, "book.add", json!({"book":"b","title":"Book"})),
    );
    let note = transform(
        &initial.state,
        &src(
            2,
            "note.add",
            json!({"note":"n","book":"b","text":"original"}),
        ),
    );
    let stale = transform(
        &note.state,
        &src(
            3,
            "note.resolve",
            json!({"note":"n","text":"stale resolution","expect":"wrong"}),
        ),
    );
    assert!(stale.commands.is_empty());
    assert_eq!(stale.evidence[0].disposition["component"], "text");
    let mut state = BooksState::default();
    add(&mut state);
    apply(
        &mut state,
        2,
        "addNote",
        json!({"id":"b","book":"b","text":"Category-scoped ID"}),
    );
    apply(
        &mut state,
        3,
        "editNote",
        json!({"id":"b","text":"alternative","expect":null}),
    );
    assert_eq!(
        q(&state, "books", json!({}))["value"]["rows"][0]["conflictCount"],
        1
    );
    apply(
        &mut state,
        4,
        "resolveNote",
        json!({"id":"b","text":"reviewed","expect":"op-00002","resolves":["op-00003"]}),
    );
    assert_eq!(
        q(&state, "books", json!({}))["value"]["rows"][0]["conflictCount"],
        0
    );
    assert_eq!(
        q(&state, "conflicts", json!({"object":"b"}))["value"]["rows"][0]["resolved"],
        true
    );
}

#[test]
fn source_progress_does_not_read_metadata_extras_as_progress() {
    let initial = transform(
        &ImportState::default(),
        &src(
            1,
            "book.add",
            json!({"book":"b","title":"Book","fraction":0.8}),
        ),
    );
    let edited = transform(
        &initial.state,
        &src(2, "book.edit", json!({"book":"b","fraction":0.9,"page":90})),
    );
    let report = transform(&edited.state, &src(3, "book.progress", json!({"book":"b"})));
    assert_eq!(report.commands[0].payload["fraction"], 0);
    assert_eq!(report.commands[0].payload["page"], Value::Null);
    assert_eq!(edited.commands[0].payload["fraction"], 0.9);
    let mut state = BooksState::default();
    for command in &initial.commands {
        ReadingBooks.apply(&mut state, &op(1, &command.kind, command.payload.clone()));
    }
    assert_eq!(
        q(&state, "book", json!({"id":"b"}))["value"]["book"]["fraction"],
        0
    );
    assert_eq!(
        q(&state, "book", json!({"id":"b"}))["value"]["extensions"]["fraction"],
        0.8
    );
}

#[test]
fn hundred_thousand_reports_keep_hot_pages_bounded() {
    let mut state = BooksState::default();
    for i in 0..100 {
        apply(
            &mut state,
            i + 1,
            "addBook",
            json!({"id":format!("book-{i}"),"title":"Synthetic scale test","creator":"Example"}),
        );
    }
    for i in 100..100000 {
        apply(
            &mut state,
            i + 1,
            "position",
            json!({"id":format!("book-{}",i%100),"fraction":(i%100) as f64/100.0}),
        );
    }
    let page = q(&state, "books", json!({"limit":10}));
    assert_eq!(page["value"]["total"], 100);
    assert_eq!(page["value"]["rows"].as_array().unwrap().len(), 10);
    assert!(serde_json::to_vec(&page).unwrap().len() < 10000);
    assert!(serde_json::to_vec(&state).unwrap().len() < 300000);
    assert_eq!(q(&state, "bookCounts", json!({}))["value"]["total"], 100);
}

#[test]
fn stale_import_note_does_not_regress_parent_activity_head() {
    let mut state = ImportState::default();
    for source in [
        src(1, "book.add", json!({"book":"b","title":"B"})),
        src(2, "note.add", json!({"note":"n","book":"b","text":"N"})),
        src(3, "book.edit", json!({"book":"b","title":"Updated"})),
        src(
            4,
            "note.edit",
            json!({"note":"n","text":"stale","expect":"wrong"}),
        ),
    ] {
        let mut result = transform(&state, &source);
        for i in 0..result.commands.len() {
            let output = result.commands[i].output_key.clone();
            result.bind_output(&output, &format!("dest-{}", source.admitted_order));
        }
        state = result.state;
    }
    let delete = transform(&state, &src(5, "book.remove", json!({"book":"b"})));
    assert_eq!(delete.commands[0].payload["expect"], "dest-3");
}

#[test]
fn import_identity_collisions_use_framed_source_identity() {
    let mut initial = ImportState::default();
    initial.reserve_destination_ids(["b".into()], std::iter::empty());
    let source = src(1, "book.add", json!({"book":"b","title":"Source"}));
    let result = transform(&initial, &source);
    assert_ne!(result.commands[0].payload["id"], "b");
    assert_eq!(
        result.commands[0].payload,
        transform(&initial, &source).commands[0].payload
    );
    let mut other = source.clone();
    other.source_library = "another source".into();
    assert_ne!(
        transform(&initial, &other).commands[0].payload["id"],
        result.commands[0].payload["id"]
    );
}
