use super::support::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use colophon_core::model::Records;
use serde_json::json;
use std::collections::BTreeMap;

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
    let encoded: BTreeMap<_, _> = root
        .records()
        .iter()
        .map(|(p, b)| (p.clone(), STANDARD.encode(b)))
        .collect();
    let records: Records = encoded
        .iter()
        .map(|(p, b)| (p.clone(), STANDARD.decode(b).unwrap()))
        .collect();
    let replayed = opened(records, &owner);
    let expected: Vec<_> = queries
        .iter()
        .map(|(name, args)| {
            json!({
                "query": name,
                "arguments": args,
                "result": success(replayed.query("listening.podcasts", name, args.clone(), NOW).unwrap())
            })
        })
        .collect();
    let results = json!(expected);
    let records = root.records().clone();
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
