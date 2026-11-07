use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::json;
use std::{collections::BTreeMap, fs, path::PathBuf};
pub fn scenario() -> (Records, Value) {
    let owner = keys(5);
    let recovery = SoftwareKeys::recovery([99; 32]).unwrap();
    let create = Library::begin_create(
        CreateOptions {
            owner: owner.public(),
            recovery: recovery.public(),
            label: "Synthetic books fixture".into(),
            owner_label: "Books fixture owner".into(),
            namespaces: vec!["reading.books".into()],
        },
        NOW,
        [80; 32],
    )
    .unwrap();
    let mut lib = opened(finish(create, &owner), &owner);
    for (seed, kind, payload) in [
        (
            81,
            "addBook",
            json!({"id":"b","title":"A synthetic book","creator":"Example writer","catalogKey":"OL-example","pages":200,"extensions":{"fixture":true}}),
        ),
        (
            82,
            "editBook",
            json!({"id":"b","title":"Synthetic book revised","isbn":null}),
        ),
        (
            83,
            "setPlan",
            json!({"id":"b","status":"reading","started":"2024-02-29"}),
        ),
        (84, "position", json!({"id":"b","fraction":0.5,"page":100})),
        (
            85,
            "position",
            json!({"id":"b","fraction":0.25,"page":null}),
        ),
        (
            86,
            "addNote",
            json!({"id":"n","book":"b","text":"A synthetic note","quote":"Example quote"}),
        ),
        (87, "editNote", json!({"id":"n","text":"An applied edit"})),
        (
            88,
            "editNote",
            json!({"id":"n","text":"A stale alternative","expect":null}),
        ),
    ] {
        write(&mut lib, &owner, "reading.books", kind, payload, seed);
    }
    let view = success(lib.view("reading.books", NOW).unwrap());
    let head = &view.admitted[6].id;
    let alternative = &view.admitted[7].id;
    write(
        &mut lib,
        &owner,
        "reading.books",
        "resolveNote",
        json!({"id":"n","text":"Reviewed text","expect":head,"resolves":[alternative]}),
        89,
    );
    for (seed, kind, payload) in [
        (
            90,
            "setPlan",
            json!({"id":"b","status":"finished","finished":"2024-03-01"}),
        ),
        (
            91,
            "setPlan",
            json!({"id":"b","status":"reading","reread":true}),
        ),
        (
            92,
            "setCopyLoan",
            json!({"id":"b","status":"needsReturn","requestID":"fixture-request"}),
        ),
        (
            93,
            "addBook",
            json!({"id":"gone","title":"Deleted occurrence","creator":""}),
        ),
        (
            94,
            "addNote",
            json!({"id":"gone-note","book":"gone","text":"Retained history"}),
        ),
        (95, "deleteNote", json!({"id":"gone-note"})),
        (96, "deleteBook", json!({"id":"gone"})),
        (
            97,
            "addBook",
            json!({"id":"gone","title":"Cannot resurrect","creator":""}),
        ),
        (
            98,
            "addNote",
            json!({"id":"orphan","book":"missing","text":"No invented parent"}),
        ),
    ] {
        write(&mut lib, &owner, "reading.books", kind, payload, seed);
    }
    let invalid = adversarial(
        &lib,
        &owner,
        &owner,
        "reading.books",
        op(
            "position",
            19,
            lib.authority().latest,
            json!({"id":"b","fraction":2}),
        ),
        1,
        100,
    );
    lib.merge(invalid).unwrap();
    let queries = [
        ("books", json!({"limit":1})),
        ("book", json!({"id":"b"})),
        ("bookCounts", json!({})),
        ("bookNotes", json!({"book":"b"})),
        ("note", json!({"id":"n"})),
        ("readings", json!({"book":"b"})),
        (
            "catalogMembership",
            json!({"keys":["OL-example","missing"]}),
        ),
        ("conflicts", json!({"object":"n"})),
        ("conflicts", json!({"object":"gone"})),
        ("invalid", json!({})),
        ("book", json!({"id":"gone"})),
        ("note", json!({"id":"gone-note"})),
    ]
    .into_iter()
    .map(|(name, args)| {
        let value = success(lib.query("reading.books", name, args.clone(), NOW).unwrap());
        json!({"name":name,"args":args,"result":value})
    })
    .collect::<Vec<_>>();
    (
        lib.records().clone(),
        json!({"namespace":"reading.books","queries":queries}),
    )
}
pub fn check(update: bool) {
    let (records, expected) = scenario();
    let folder =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/0.3/reading.books");
    let encoded: BTreeMap<_, _> = records
        .iter()
        .map(|(p, b)| (p.clone(), STANDARD.encode(b)))
        .collect();
    if update && std::env::var_os("COLOPHON_UPDATE_VECTORS").is_some() {
        fs::create_dir_all(&folder).unwrap();
        fs::write(folder.join("records.json"), canonical(&encoded).unwrap()).unwrap();
        fs::write(
            folder.join("expected.json"),
            serde_json::to_vec_pretty(&expected).unwrap(),
        )
        .unwrap();
    }
    let stored: BTreeMap<String, String> =
        serde_json::from_slice(&fs::read(folder.join("records.json")).unwrap()).unwrap();
    let expected_stored: Value =
        serde_json::from_slice(&fs::read(folder.join("expected.json")).unwrap()).unwrap();
    assert_eq!(stored, encoded);
    assert_eq!(expected_stored, expected);
    let records: Records = stored
        .into_iter()
        .map(|(p, b)| (p, STANDARD.decode(b).unwrap()))
        .collect();
    let lib = opened(records, &keys(5));
    for query in expected_stored["queries"].as_array().unwrap() {
        assert_eq!(
            success(
                lib.query(
                    "reading.books",
                    query["name"].as_str().unwrap(),
                    query["args"].clone(),
                    NOW
                )
                .unwrap()
            ),
            query["result"]
        );
    }
}
