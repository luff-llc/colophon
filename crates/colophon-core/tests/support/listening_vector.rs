use super::support::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use colophon_core::{model::Records, records::canonical};
use serde_json::{json, Value};
use std::{collections::BTreeMap, fs, path::PathBuf};

pub fn check() {
    let (mut root, owner, _) = create();
    let commands = [
        (
            "follow",
            json!({"id":"show","url":"https://example.org/podcast.xml","title":"Synthetic show","future":{"retained":true}}),
        ),
        (
            "episode",
            json!({"id":"one","show":"show","title":"First episode","published":"2026-11-05T00:00:00Z"}),
        ),
        (
            "episode",
            json!({"id":"two","show":"show","title":"Second episode","published":"2026-11-06T00:00:00Z"}),
        ),
        (
            "position",
            json!({"id":"one","show":"show","seconds":60,"duration":120}),
        ),
        ("position", json!({"id":"one","show":"show","seconds":5})),
        (
            "setState",
            json!({"id":"one","show":"show","consumption":"inProgress"}),
        ),
        ("queue", json!({"episodes":["two","one"]})),
        (
            "setPreferences",
            json!({"id":"prefs","changes":[{"scope":"global","field":"speed","value":1.25,"expect":null}]}),
        ),
        (
            "addNote",
            json!({"id":"note","episode":"one","show":"show","text":"Synthetic thought","seconds":12}),
        ),
        (
            "editNote",
            json!({"id":"note","text":"Concurrent alternative","expect":"stale"}),
        ),
        (
            "addNote",
            json!({"id":"deleted","episode":"one","show":"show","text":"Retained tombstone"}),
        ),
        ("deleteNote", json!({"id":"deleted"})),
        ("editNote", json!({"id":"deleted","text":"Late edit"})),
        (
            "savePlaylist",
            json!({"id":"daily","name":"Daily","mode":"automatic","shows":["show"]}),
        ),
        (
            "setChapters",
            json!({"episode":"one","show":"show","recording":"a".repeat(64),"source":"publisher","origin":"id3","entries":[{"start":30,"title":"Second"},{"start":0,"title":"First"}]}),
        ),
        (
            "saveTranscript",
            json!({"id":"transcript","episode":"one","show":"show","blob":{"digest":"b".repeat(64),"size":10,"mediaType":"application/json"},"source":"publisher","timed":true,"recording":"a".repeat(64)}),
        ),
    ];
    for (i, (kind, payload)) in commands.into_iter().enumerate() {
        write(
            &mut root,
            &owner,
            "listening.podcasts",
            kind,
            payload,
            100 + i as u8,
        );
    }
    let queries = [
        ("shows", json!({})),
        ("show", json!({"id":"show"})),
        ("episodes", json!({"limit":1})),
        ("episode", json!({"id":"one"})),
        ("queue", json!({"limit":1})),
        (
            "playbackContext",
            json!({"episode":"one","recording":"a".repeat(64)}),
        ),
        ("playlists", json!({})),
        ("playlist", json!({"id":"daily"})),
        ("notes", json!({"episode":"one"})),
        ("note", json!({"id":"deleted"})),
        (
            "recordingContent",
            json!({"episode":"one","recording":"a".repeat(64),"kind":"chapters"}),
        ),
        ("transcripts", json!({"episode":"one"})),
        ("preferences", json!({"scope":"global"})),
        ("recordings", json!({"episode":"one"})),
        ("history", json!({"mode":"importedSession"})),
        ("history", json!({"mode":"latestEpisode"})),
        ("jobs", json!({"kind":"question"})),
        ("contributions", json!({"kind":"answer"})),
        ("listeningCounts", json!({})),
        ("conflicts", json!({"object":"one"})),
    ];
    let expected:Vec<_>=queries.iter().map(|(name,args)|json!({"query":name,"arguments":args,"result":success(root.query("listening.podcasts",name,args.clone(),NOW).unwrap())})).collect();
    let encoded: BTreeMap<_, _> = root
        .records()
        .iter()
        .map(|(p, b)| (p.clone(), STANDARD.encode(b)))
        .collect();
    let folder = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/0.2");
    if std::env::var_os("COLOPHON_UPDATE_VECTORS").is_some() {
        fs::write(
            folder.join("listening.podcasts.records.json"),
            canonical(&encoded).unwrap(),
        )
        .unwrap();
        fs::write(
            folder.join("listening.podcasts.expected.json"),
            serde_json::to_vec_pretty(&expected).unwrap(),
        )
        .unwrap();
    }
    let stored: BTreeMap<String, String> =
        serde_json::from_slice(&fs::read(folder.join("listening.podcasts.records.json")).unwrap())
            .unwrap();
    let results: Value =
        serde_json::from_slice(&fs::read(folder.join("listening.podcasts.expected.json")).unwrap())
            .unwrap();
    assert_eq!(stored, encoded);
    assert_eq!(results, json!(expected));
    let records: Records = stored
        .into_iter()
        .map(|(p, b)| (p, STANDARD.decode(b).unwrap()))
        .collect();
    let replay = opened(records, &owner);
    for test in results.as_array().unwrap() {
        assert_eq!(
            json!(success(
                replay
                    .query(
                        "listening.podcasts",
                        test["query"].as_str().unwrap(),
                        test["arguments"].clone(),
                        NOW
                    )
                    .unwrap()
            )),
            test["result"]
        );
    }
}
