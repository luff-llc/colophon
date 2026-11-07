#![allow(clippy::unwrap_used)]
#[path = "support/listening_vector.rs"]
mod listening_vector;
mod support;
use colophon_core::{
    domain::{DomainModule, Reducer},
    domains::listening::{import::*, ApplyContext, ListeningPodcasts, PodcastsState},
    model::{MemberKind, OperationView},
};
use serde_json::{json, Value};

fn op(n: u64, kind: &str, payload: Value) -> OperationView {
    OperationView {
        id: format!("op-{n:04}"),
        kind: kind.into(),
        author: "device".into(),
        author_label: "Listener".into(),
        origin: "person".into(),
        clock: n,
        created: "2026-11-06T12:00:00Z".into(),
        payload,
    }
}
fn apply(s: &mut PodcastsState, n: u64, kind: &str, payload: Value) {
    ListeningPodcasts.apply_with_context(
        s,
        &op(n, kind, payload),
        ApplyContext {
            member_kind: Some(MemberKind::Device),
            ..Default::default()
        },
    );
}
fn agent(s: &mut PodcastsState, n: u64, kind: &str, payload: Value) {
    let mut o = op(n, kind, payload);
    o.author = "agent".into();
    o.origin = "ai".into();
    ListeningPodcasts.apply_with_context(
        s,
        &o,
        ApplyContext {
            member_kind: Some(MemberKind::Agent),
            ..Default::default()
        },
    );
}
fn q(s: &PodcastsState, name: &str, args: Value) -> Value {
    ListeningPodcasts.query(s, name, &args).unwrap()["value"].clone()
}
fn full(s: &PodcastsState) -> Value {
    ListeningPodcasts.query(s, "read", &json!({})).unwrap()
}
fn blob() -> Value {
    json!({"digest":"a".repeat(64),"size":12,"mediaType":"application/json"})
}
fn anchor() -> Value {
    json!({"reference":{"transcript":"t","revision":"op-t","blob":blob(),"episode":"e"},"startUTF16":0,"lengthUTF16":5,"quote":"hello"})
}
fn claim() -> Value {
    json!([{"text":"A claim","citations":[anchor()]}])
}

#[test]
fn independent_heads_conflicts_tombstones_and_extensions() {
    let mut s = PodcastsState::default();
    apply(&mut s, 1, "unfollow", json!({"id":"show"}));
    apply(
        &mut s,
        2,
        "follow",
        json!({"id":"show","url":"https://example.org/feed","title":"Title"}),
    );
    apply(
        &mut s,
        3,
        "position",
        json!({"id":"e","show":"show","seconds":100,"future":{"kept":true}}),
    );
    apply(
        &mut s,
        4,
        "episode",
        json!({"id":"e","show":"show","title":"Episode","seconds":0,"positionRevision":"fake","origin":"ai","extensions":{"seconds":9}}),
    );
    apply(
        &mut s,
        5,
        "setState",
        json!({"id":"e","show":"show","consumption":"inProgress","expect":null}),
    );
    apply(
        &mut s,
        6,
        "position",
        json!({"id":"e","show":"show","seconds":10}),
    );
    apply(
        &mut s,
        7,
        "position",
        json!({"id":"e","show":"show","seconds":200,"expect":"wrong"}),
    );
    let e = q(&s, "episode", json!({"id":"e"}));
    assert_eq!(e["row"]["seconds"], 100.0);
    assert_eq!(
        e["heads"],
        json!({"metadata":"op-0004","position":"op-0003","state":"op-0005"})
    );
    assert_eq!(e["extensions"]["extensions"]["seconds"], 9);
    assert_eq!(e["extensions"]["seconds"], 0);
    assert_eq!(q(&s, "conflicts", json!({"object":"e"}))["total"], 2);
    apply(
        &mut s,
        8,
        "recoverPosition",
        json!({"id":"e","show":"show","seconds":12,"expectedPosition":"op-0003","expectedState":"op-0005","inProgress":true}),
    );
    assert_eq!(
        q(&s, "episode", json!({"id":"e"}))["heads"]["position"],
        "op-0008"
    );
    apply(
        &mut s,
        9,
        "recoverPosition",
        json!({"id":"e","show":"show","seconds":1,"expectedPosition":"op-0003","expectedState":"op-0005","inProgress":true}),
    );
    assert_eq!(q(&s, "episode", json!({"id":"e"}))["row"]["seconds"], 12.0);
    apply(
        &mut s,
        10,
        "addNote",
        json!({"id":"n","episode":"e","show":"show","text":"Original","future":2}),
    );
    agent(
        &mut s,
        11,
        "editNote",
        json!({"id":"n","text":"Alternative","expect":"stale"}),
    );
    let conflict = q(&s, "conflicts", json!({"object":"n"}));
    assert_eq!(conflict["rows"][0]["candidate"]["episode"], "e");
    assert_eq!(conflict["rows"][0]["candidate"]["origin"], "ai");
    apply(
        &mut s,
        12,
        "resolveNote",
        json!({"id":"n","text":"Resolved","expect":"op-0010","resolves":[]}),
    );
    assert_eq!(q(&s, "note", json!({"id":"n"}))["alternativeCount"], 2);
    apply(
        &mut s,
        13,
        "resolveNote",
        json!({"id":"n","text":"Resolved","expect":"op-0010","resolves":["op-0011","op-0012"]}),
    );
    assert_eq!(q(&s, "note", json!({"id":"n"}))["alternativeCount"], 0);
    apply(
        &mut s,
        14,
        "deleteNote",
        json!({"id":"n","expect":"op-0013"}),
    );
    apply(
        &mut s,
        15,
        "addNote",
        json!({"id":"n","episode":"e","show":"show","text":"Cannot resurrect"}),
    );
    apply(&mut s, 16, "editNote", json!({"id":"n","text":"Late edit"}));
    let note = q(&s, "note", json!({"id":"n"}));
    assert_eq!(note["outcome"], "deleted");
    assert_eq!(note["note"]["text"], "Resolved");
    assert_eq!(note["note"]["creationRevision"], "op-0010");
    assert_eq!(note["alternativeCount"], 2);
    assert_eq!(q(&s, "notes", json!({}))["total"], 0);
    assert_eq!(q(&s, "listeningCounts", json!({}))["notes"], 0);
}

#[test]
fn preferences_and_completion_are_atomic_and_receipted() {
    let mut s = PodcastsState::default();
    apply(
        &mut s,
        1,
        "setPreferences",
        json!({"id":"p","changes":[{"scope":"global","field":"speed","value":1.25,"expect":null},{"scope":"show","target":"show","field":"speed","value":2,"expect":null}]}),
    );
    apply(
        &mut s,
        2,
        "setPreferences",
        json!({"id":"bad","changes":[{"scope":"global","field":"speed","value":3,"expect":"op-0001"},{"scope":"show","target":"show","field":"speed","value":1,"expect":"stale"}]}),
    );
    apply(&mut s, 3, "episode", json!({"id":"e","show":"show"}));
    assert_eq!(
        q(&s, "playbackContext", json!({"episode":"e"}))["preferences"]["speed"],
        2
    );
    apply(
        &mut s,
        4,
        "setPreferences",
        json!({"id":"inherit","changes":[{"scope":"show","target":"show","field":"speed","value":null,"expect":"op-0001"}]}),
    );
    assert_eq!(
        q(&s, "playbackContext", json!({"episode":"e"}))["preferences"]["speed"],
        1.25
    );
    apply(&mut s, 5, "queue", json!({"episodes":["e","next"]}));
    let complete = json!({"id":"end","events":[{"eventID":"event","episode":"e","show":"show","audio":"https://audio/identity","endSeconds":42,"actualDuration":42,"expectedPosition":null,"expectedState":null}],"baseQueue":["e","next"],"expect":"op-0005"});
    apply(&mut s, 6, "completePlayback", complete.clone());
    assert_eq!(
        q(&s, "episode", json!({"id":"e"}))["row"]["consumption"],
        "completed"
    );
    assert_eq!(q(&s, "queue", json!({}))["page"]["rows"][0]["id"], "next");
    apply(&mut s, 7, "completePlayback", complete.clone());
    assert_eq!(q(&s, "queue", json!({}))["head"], "op-0006");
    let mut changed = complete;
    changed["events"][0]["endSeconds"] = json!(43);
    changed["events"][0]["actualDuration"] = json!(43);
    apply(&mut s, 8, "completePlayback", changed);
    assert_eq!(
        q(&s, "conflicts", json!({"object":"end"}))["rows"][0]["outcome"],
        "identityConflict"
    );
    apply(&mut s, 9, "queue", json!({"episodes":["x","x"]}));
    assert_eq!(full(&s)["invalid"], json!(["op-0009"]));
}

#[test]
fn recordings_transcripts_playlists_and_nested_extensions() {
    let mut s = PodcastsState::default();
    let recording = "b".repeat(64);
    apply(
        &mut s,
        1,
        "setSegments",
        json!({"episode":"e","show":"show","recording":recording,"source":"person","segments":[{"start":20,"end":25,"kind":"sponsor","future":7},{"start":0,"end":1,"kind":"intro"}]}),
    );
    agent(
        &mut s,
        2,
        "setSegments",
        json!({"episode":"e","show":"show","recording":recording,"source":"person","segments":[]}),
    );
    let page = q(
        &s,
        "recordingContent",
        json!({"episode":"e","recording":recording,"kind":"segments"}),
    );
    assert_eq!(page["page"]["total"], 2);
    assert_eq!(page["page"]["rows"][1]["extensions"]["future"], 7);
    assert_eq!(page["head"], "op-0001");
    apply(
        &mut s,
        3,
        "setChapters",
        json!({"episode":"e","show":"show","recording":recording,"source":"publisher","entries":[{"start":3,"title":"Later"},{"start":0,"title":"First"}]}),
    );
    assert_eq!(
        q(
            &s,
            "recordingContent",
            json!({"episode":"e","recording":recording,"kind":"chapters"})
        )["page"]["rows"][0]["title"],
        "First"
    );
    for (n, id, timed, source) in [
        (4, "t1", false, "person"),
        (5, "t2", true, "publisher"),
        (6, "t3", true, "detector"),
        (7, "t4", true, "publisher"),
    ] {
        apply(
            &mut s,
            n,
            "saveTranscript",
            json!({"id":id,"episode":"e","show":"show","blob":blob(),"source":source,"timed":timed}),
        );
    }
    let transcripts = q(&s, "transcripts", json!({"episode":"e"}));
    assert_eq!(transcripts["total"], 4);
    assert_eq!(
        transcripts["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["selected"] == true)
            .unwrap()["id"],
        "t4"
    );
    apply(
        &mut s,
        8,
        "savePlaylist",
        json!({"id":"p","name":"Daily","mode":"automatic","future":1}),
    );
    apply(
        &mut s,
        9,
        "savePlaylist",
        json!({"id":"p","name":"Other","mode":"manual","expect":"stale"}),
    );
    let rule = q(&s, "playlist", json!({"id":"p"}));
    assert_eq!(rule["rule"]["progress"], "any");
    assert_eq!(rule["alternativeCount"], 1);
    assert_eq!(rule["extensions"]["future"], 1);
}

#[test]
fn structural_services_enforce_roles_ownership_and_never_execute() {
    let mut s = PodcastsState::default();
    // The legacy engine origin cannot distinguish servers from apps. Fail closed.
    ListeningPodcasts.apply(&mut s,&op(1,"requestTranscript",json!({"id":"job","episode":"e","show":"show","worker":"agent","audio":blob(),"recording":"a".repeat(64),"language":"en"})));
    assert_eq!(q(&s, "jobs", json!({"kind":"transcript"}))["total"], 0);
    apply(
        &mut s,
        2,
        "requestTranscript",
        json!({"id":"job","episode":"e","show":"show","worker":"agent","audio":blob(),"recording":"a".repeat(64),"language":"en"}),
    );
    agent(
        &mut s,
        3,
        "supplyTranscript",
        json!({"id":"job","request":"op-0002","result":blob()}),
    );
    let mut other = blob();
    other["digest"] = json!("b".repeat(64));
    agent(
        &mut s,
        4,
        "supplyTranscript",
        json!({"id":"job","request":"op-0002","result":other}),
    );
    assert_eq!(
        q(&s, "jobs", json!({"kind":"transcript"}))["rows"][0]["status"],
        "conflict"
    );
    assert_eq!(q(&s, "transcripts", json!({}))["total"], 0);
    apply(
        &mut s,
        5,
        "cancelTranscript",
        json!({"id":"job","request":"op-0002"}),
    );
    assert_eq!(
        q(&s, "jobs", json!({"kind":"transcript"}))["rows"][0]["status"],
        "cancelled"
    );
    apply(
        &mut s,
        6,
        "askQuestion",
        json!({"id":"q","question":"Why?","scope":[anchor()],"worker":"agent","expires":"2026-11-07T12:00:00Z"}),
    );
    let scope_digest = colophon_core::records::digest(
        &colophon_core::records::canonical(&json!([anchor()])).unwrap(),
    );
    agent(
        &mut s,
        7,
        "answerQuestion",
        json!({"id":"q","request":"op-0006","scopeDigest":scope_digest,"claims":claim()}),
    );
    apply(
        &mut s,
        8,
        "acceptAnswer",
        json!({"id":"q","request":"op-0006","response":"op-0007"}),
    );
    let answer = q(&s, "contributions", json!({"kind":"answer","id":"q"}));
    assert_eq!(answer["sourceStatus"], "pendingSource");
    assert_eq!(answer["responseAttribution"]["origin"], "ai");
    assert_eq!(answer["acceptance"]["origin"], "person");
    apply(
        &mut s,
        9,
        "cancelQuestion",
        json!({"id":"q","request":"op-0006"}),
    );
    assert_eq!(
        q(&s, "jobs", json!({"kind":"question"}))["rows"][0]["status"],
        "cancelled"
    );
    apply(
        &mut s,
        10,
        "addNote",
        json!({"id":"n","episode":"e","show":"show","text":"Original","capture":{"requestID":"capture","originalText":"Original","surroundingText":"Around","targetAgentID":"agent"}}),
    );
    agent(
        &mut s,
        11,
        "respondCapture",
        json!({"id":"capture","request":"op-0010","text":"Response"}),
    );
    apply(
        &mut s,
        12,
        "cancelCapture",
        json!({"id":"capture","request":"op-0010"}),
    );
    assert_eq!(q(&s, "note", json!({"id":"n"}))["text"], "Original");
    agent(
        &mut s,
        13,
        "proposeContext",
        json!({"id":"proposal","contributionID":"c","reference":anchor()["reference"],"text":"Context","citation":"hello","expect":null}),
    );
    apply(
        &mut s,
        14,
        "acceptContext",
        json!({"id":"acceptance","contributionID":"c","reference":anchor()["reference"],"proposal":"op-0013","expect":"op-0013"}),
    );
    let context = q(&s, "contributions", json!({"kind":"context","id":"c"}));
    assert_eq!(context["origin"], "ai");
    assert_eq!(context["acceptance"]["origin"], "person");
    apply(
        &mut s,
        15,
        "saveAnswer",
        json!({"id":"answer","question":"Question?","claims":claim()}),
    );
    assert_eq!(q(&s, "contributions", json!({"kind":"answer"}))["total"], 2);
    assert!(full(&s)["invalid"].as_array().unwrap().is_empty());
}

#[test]
fn bounded_pages_cursors_filters_and_unknown_prefixes() {
    let mut s = PodcastsState::default();
    for i in 0..125 {
        apply(
            &mut s,
            i + 1,
            "episode",
            json!({"id":format!("e{i:03}"),"show":"show","title":"Title","published":"2026-11-06T00:00:00Z"}),
        );
    }
    let first = q(&s, "episodes", json!({"show":"show","limit":30}));
    assert_eq!(first["rows"].as_array().unwrap().len(), 30);
    assert_eq!(first["total"], 125);
    let next = q(
        &s,
        "episodes",
        json!({"show":"show","limit":30,"cursor":first["next"]}),
    );
    assert_eq!(next["rows"][0]["id"], "e030");
    assert!(ListeningPodcasts
        .query(
            &s,
            "episodes",
            &json!({"show":"other","cursor":first["next"]})
        )
        .is_err());
    ListeningPodcasts.apply(&mut s, &op(126, "futureKind", json!({"ignored":true})));
    assert_eq!(
        q(
            &s,
            "episodes",
            json!({"show":"show","cursor":first["next"]})
        )["outcome"],
        "staleCursor"
    );
    assert!(ListeningPodcasts
        .query(&s, "episodes", &json!({"limit":101}))
        .is_err());
    assert_eq!(
        q(&s, "episode", json!({"id":"missing"}))["outcome"],
        "notFound"
    );
    // Imported session history is a page of baseline-imported episodes (none here), not unavailable.
    assert_eq!(
        q(&s, "history", json!({"mode":"importedSession"}))["total"],
        0
    );
    assert_eq!(
        q(&s, "listeningCounts", json!({"show":"show"}))["episodes"],
        125
    );
}

#[test]
fn fixed_seed_incremental_replay_and_serialized_prefixes_agree() {
    let mut seed = 0xd1b54a32d192ed03u64;
    let mut random = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for _ in 0..12 {
        let mut ops = vec![];
        for i in 1..=100 {
            let id = format!("e{}", random() % 9);
            let (kind, payload) = match random() % 5 {
                0 => (
                    "episode",
                    json!({"id":id,"show":"show","title":format!("Episode {}",random()%10)}),
                ),
                1 => (
                    "setState",
                    json!({"id":id,"show":"show","consumption":"completed"}),
                ),
                2 => (
                    "position",
                    json!({"id":id,"seconds":random()%1000,"seek":random()%2==0}),
                ),
                3 => ("queue", json!({"episodes":[id]})),
                _ => ("position", json!({"id":id,"seconds":1,"expect":"stale"})),
            };
            ops.push(op(i, kind, payload));
        }
        // Random arrival then engine-equivalent admitted sorting.
        for i in (1..ops.len()).rev() {
            ops.swap(i, random() as usize % (i + 1));
        }
        ops.sort_by(|a, b| (&a.clock, &a.author, &a.id).cmp(&(&b.clock, &b.author, &b.id)));
        let mut state = PodcastsState::default();
        for (i, operation) in ops.iter().enumerate() {
            ListeningPodcasts.apply(&mut state, operation);
            if i % 17 == 0 {
                assert_eq!(full(&state), ListeningPodcasts.fold(&ops[..=i]));
                state = serde_json::from_value(serde_json::to_value(&state).unwrap()).unwrap();
            }
        }
        assert_eq!(full(&state), ListeningPodcasts.fold(&ops));
    }
}

#[test]
fn rejects_boundaries_unknown_enums_and_malformed_nested_models() {
    let mut s = PodcastsState::default();
    let invalid = [
        (
            "setState",
            json!({"id":"e","show":"s","consumption":"almost"}),
        ),
        ("position", json!({"id":"e","seconds":0,"duration":0})),
        (
            "follow",
            json!({"id":"s","url":"https://user:secret@example.org/feed"}),
        ),
        (
            "setPreferences",
            json!({"id":"p","changes":[{"scope":"global","field":"speed","value":1.23,"expect":null}]}),
        ),
        (
            "addNote",
            json!({"id":"n","episode":"e","show":"s","text":"a","anchor":{"reference":anchor()["reference"],"startUTF16":0,"lengthUTF16":1,"quote":"😀"}}),
        ),
        (
            "setSegments",
            json!({"episode":"e","show":"s","recording":"a".repeat(64),"source":"detected","segments":[{"start":1,"end":0,"kind":"x"}]}),
        ),
        (
            "saveTranscript",
            json!({"id":"t","episode":"e","show":"s","blob":{"digest":"A".repeat(64),"size":12,"mediaType":"application/json"},"source":"publisher","timed":true}),
        ),
        (
            "setChapters",
            json!({"episode":"e","show":"s","recording":"a".repeat(64),"source":"publisher","entries":[]}),
        ),
    ];
    for (i, (kind, payload)) in invalid.iter().enumerate() {
        apply(&mut s, i as u64, kind, payload.clone());
    }
    assert_eq!(full(&s)["invalid"].as_array().unwrap().len(), invalid.len());
    assert_eq!(ListeningPodcasts.operations().len(), 30);
    for spec in ListeningPodcasts.operations() {
        let mut state = PodcastsState::default();
        apply(&mut state, 1, &spec.name, json!({}));
        assert_eq!(
            full(&state)["invalid"],
            json!(["op-0001"]),
            "{} requires a payload",
            spec.name
        );
    }
    assert!(ListeningPodcasts
        .queries()
        .iter()
        .all(|query| ListeningPodcasts
            .operations()
            .iter()
            .all(|op| op.name != query.name)));
}

fn legacy(kind: &str, payload: Value) -> VerifiedOperation {
    VerifiedOperation {
        source_library: "old-library".into(),
        author_id: "old-author".into(),
        author_label: "Old listener".into(),
        operation_id: "old-op".into(),
        signed_body_digest: "d".repeat(64),
        kind: kind.into(),
        version: 1,
        payload,
        admitted_order: json!([1, "old-author", "old-op"]),
        claimed_date: json!(1234),
    }
}
fn applied() -> ImportContext {
    ImportContext {
        admission: "admitted".into(),
        disposition: Disposition::Applied,
        ..Default::default()
    }
}
#[test]
fn every_legacy_kind_has_a_durable_disposition_and_rejections_never_write() {
    let kinds = [
        "show.follow",
        "show.unfollow",
        "show.settings",
        "episode.setState",
        "episode.position",
        "position.recover",
        "queue.set",
        "queue.retain",
        "note.add",
        "note.edit",
        "note.resolve",
        "note.delete",
        "episode.segments",
        "episode.transcript",
        "episode.chapters",
        "playlist.save",
        "preferences.batch",
        "playback.naturalEnd.batch",
        "legacy.bridge.import",
        "legacy.podcastState.import",
        "podcast.source.publish",
        "answer.save",
        "transcript.prepare",
        "transcript.prepare.cancel",
        "transcript.prepare.result",
        "question.request",
        "question.response",
        "question.cancel",
        "question.admit",
        "capture.response",
        "capture.cancel",
        "context.propose",
        "context.accept",
    ];
    assert_eq!(kinds.len(), 33);
    for kind in kinds {
        for disposition in [
            Disposition::Rejected,
            Disposition::Malformed,
            Disposition::Unresolved,
            Disposition::Unknown,
        ] {
            let mut c = applied();
            c.disposition = disposition;
            let record = legacy(kind, json!({"future":true,"origin":"person"}));
            let plan = import_operation(&record, &c);
            assert!(plan.commands.is_empty(), "{kind}");
            assert_eq!(plan.evidence.len(), 1);
            assert_eq!(plan.evidence[0].manifest["originalPayload"], record.payload);
            assert_eq!(plan.evidence[0].manifest["authorLabel"], "Old listener");
        }
        let record = legacy(kind, json!({"malformed":true}));
        let plan = import_operation(&record, &applied());
        assert!(plan.commands.is_empty(), "{kind}");
    }
    let unknown = import_operation(&legacy("future.kind", json!({"opaque":1})), &applied());
    assert!(unknown.commands.is_empty());
    assert_eq!(unknown.evidence[0].manifest["originalPayload"]["opaque"], 1);
}

#[test]
fn import_effects_component_maps_baselines_and_archived_jobs() {
    let c = applied();
    let cases = [
        (
            "show.follow",
            json!({"show":"s","feed":"https://example.org/rss","title":"Show"}),
            "follow",
        ),
        ("show.unfollow", json!({"show":"s"}), "unfollow"),
        (
            "episode.setState",
            json!({"episode":"e","show":"s","consumption":"completed"}),
            "setState",
        ),
        (
            "episode.position",
            json!({"episode":"e","show":"s","seconds":12,"deliberate":true}),
            "position",
        ),
        (
            "note.add",
            json!({"note":"n","episode":"e","show":"s","text":"Original"}),
            "addNote",
        ),
        ("note.edit", json!({"note":"n","text":"New"}), "editNote"),
        ("note.delete", json!({"note":"n"}), "deleteNote"),
        (
            "episode.segments",
            json!({"episode":"e","show":"s","audio":"a".repeat(64),"source":"detected","segments":[{"start":0,"end":2}]}),
            "setSegments",
        ),
        (
            "episode.chapters",
            json!({"episode":"e","show":"s","audio":"a".repeat(64),"source":"publisher","entries":[{"start":0,"title":"  One  "},{"start":-1,"title":"Rejected"}]}),
            "setChapters",
        ),
        (
            "playlist.save",
            json!({"playlist":"p","name":" Name ","mode":"automatic","episodes":["e","e",null],"maxMinutes":9999}),
            "savePlaylist",
        ),
    ];
    for (old, payload, new) in cases {
        let mut evaluated = c.clone();
        evaluated.effective_payload = Some(payload.clone());
        let plan = import_operation(&legacy(old, payload), &evaluated);
        assert_eq!(plan.commands.len(), 1, "{old}: {:?}", plan.evidence);
        assert_eq!(plan.commands[0].kind, new);
        assert_eq!(
            plan.commands[0].payload["importSource"]["authorID"],
            "old-author"
        );
    }
    let queue = import_operation(
        &legacy(
            "queue.set",
            json!({"episodes":["e","e","other"],"metadata":[{"episode":"bad","feed":"bad"}]}),
        ),
        &c,
    );
    assert_eq!(queue.commands.len(), 1);
    assert_eq!(queue.commands[0].payload["episodes"], json!(["e", "other"]));
    assert_eq!(
        queue.evidence[0].manifest["originalPayload"]["episodes"],
        json!(["e", "e", "other"])
    );
    let mut settings_context = c.clone();
    settings_context.effective_payload = Some(json!({"show":"s","skipIntro":5,"speed":1.25}));
    let settings = import_operation(
        &legacy(
            "show.settings",
            json!({"show":"s","skipIntro":5,"speed":1.25}),
        ),
        &settings_context,
    );
    assert_eq!(settings.commands.len(), 2);
    settings_context.destination_heads.insert(
        map_key("preference", "show:s:speed"),
        json!("prior-imported-speed"),
    );
    let updated_settings = import_operation(&legacy("show.settings", json!({})), &settings_context);
    assert_eq!(
        updated_settings.commands[1].payload["changes"][0]["expect"],
        "prior-imported-speed"
    );
    let mut c = c;
    c.revisions
        .insert(map_key("position", "old-head"), "new-position-head".into());
    let recovered = import_operation(
        &legacy(
            "position.recover",
            json!({"episode":"e","show":"s","seconds":1,"duration":null,"expectedPosition":"old-head","expectedState":null,"inProgress":true}),
        ),
        &c,
    );
    assert_eq!(
        recovered.commands[0].payload["expectedPosition"],
        "new-position-head"
    );
    let stale = import_operation(
        &legacy(
            "episode.setState",
            json!({"episode":"e","show":"s","consumption":"completed","expect":"unmapped"}),
        ),
        &c,
    );
    assert!(stale.commands.is_empty());
    let prefs = import_operation(
        &legacy(
            "preferences.batch",
            json!({"changes":{"playback.show:a.b.speed":"1.25"},"expected":{"playback.show:a.b.speed":null}}),
        ),
        &c,
    );
    assert_eq!(prefs.commands[0].payload["changes"][0]["target"], "a.b");
    c.effective_payload = Some(
        json!({"records":[{"feed":"https://example.org/rss","guid":"g","seconds":100,"consumption":"inProgress"}]}),
    );
    let baseline = import_operation(
        &legacy("legacy.podcastState.import", json!({"original":"archive"})),
        &c,
    );
    assert_eq!(baseline.commands.len(), 2);
    assert!(baseline.commands.iter().all(|command| command.baseline));
    assert_eq!(baseline.commands[0].payload["expect"], Value::Null);
    c.effective_payload = None;
    for kind in [
        "transcript.prepare",
        "transcript.prepare.cancel",
        "transcript.prepare.result",
        "question.request",
        "question.cancel",
        "capture.response",
        "capture.cancel",
        "context.propose",
        "context.accept",
    ] {
        let plan = import_operation(
            &legacy(
                kind,
                json!({"request":"old-worker-job","blob":{"plain":"b".repeat(64)}}),
            ),
            &c,
        );
        assert!(plan.commands.is_empty(), "{kind}");
        assert_eq!(plan.evidence.len(), 1);
    }
    assert_ne!(
        occurrence_id("l", "note", "n", "a"),
        occurrence_id("l", "note", "n", "b")
    );
}

#[test]
fn imported_baseline_yields_to_native_progress_and_no_old_capture_job() {
    let mut s = PodcastsState::default();
    ListeningPodcasts.apply_with_context(
        &mut s,
        &op(1, "position", json!({"id":"e","seconds":100,"expect":null})),
        ApplyContext {
            imported_baseline: true,
            ..Default::default()
        },
    );
    apply(&mut s, 2, "position", json!({"id":"e","seconds":5}));
    assert_eq!(q(&s, "episode", json!({"id":"e"}))["row"]["seconds"], 5.0);
    let plan = import_operation(
        &legacy(
            "note.add",
            json!({"note":"n","episode":"e","show":"s","text":"Original","captureThought":{"requestID":"r","originalText":"Original","surroundingText":"Around","targetAgentID":"old-agent"}}),
        ),
        &applied(),
    );
    apply(
        &mut s,
        3,
        &plan.commands[0].kind,
        plan.commands[0].payload.clone(),
    );
    assert_eq!(q(&s, "jobs", json!({"kind":"capture"}))["total"], 0);
}

#[test]
fn deterministic_listening_vector() {
    listening_vector::check();
}

#[test]
fn remaining_import_mappings_and_durable_sidecar() {
    use colophon_core::{domains::listening::evidence::*, records::digest};
    let feed = "https://example.org/rss";
    let show = digest(feed.as_bytes())[..32].to_string();
    let episode = digest(format!("{feed}\nguid").as_bytes())[..32].to_string();
    let metadata = json!({"episode":episode,"show":show,"feed":feed,"guid":"guid","title":"Episode","showTitle":"Show","audio":"https://example.org/audio.mp3","published":"2026-11-06T00:00:00Z"});
    let mut c = applied();
    c.effective_payload = Some(json!({"metadata":[metadata]}));
    assert_eq!(
        import_operation(&legacy("queue.retain", json!({})), &c).commands[0].kind,
        "episode"
    );
    c.effective_payload = None;
    let natural = import_operation(
        &legacy(
            "playback.naturalEnd.batch",
            json!({"events":[{"eventID":"end","episode":"e","show":"s","audio":"recording","endSeconds":10,"actualDuration":10,"expectedPosition":null,"expectedState":null}],"baseQueue":["e"],"expectedQueueRevision":null,"seconds":10,"duration":10}),
        ),
        &c,
    );
    assert_eq!(natural.commands[0].kind, "completePlayback");
    assert!(natural.commands[0].payload.get("seconds").is_none());
    c.revisions
        .insert(map_key("text", "old-head"), "new-head".into());
    c.revisions
        .insert(map_key("text", "old-alternative"), "new-alternative".into());
    let resolved = import_operation(
        &legacy(
            "note.resolve",
            json!({"note":"n","text":"Reviewed","expect":"old-head","resolves":["old-alternative"]}),
        ),
        &c,
    );
    assert_eq!(
        resolved.commands[0].payload["resolves"],
        json!(["new-alternative"])
    );
    c.blobs.insert("a".repeat(64), blob());
    c.revisions
        .insert(map_key("transcript", "old-t"), "new-t".into());
    c.identities
        .insert(map_key("transcriptRevision", "old-t"), "t".into());
    let old_blob = json!({"digest":"c".repeat(64),"plain":"a".repeat(64),"epoch":1,"size":12});
    let transcript = import_operation(
        &legacy(
            "episode.transcript",
            json!({"episode":"e","show":"s","blob":old_blob,"source":"publisher","timed":true}),
        ),
        &c,
    );
    assert_eq!(transcript.commands[0].kind, "saveTranscript");
    assert_eq!(transcript.commands[0].payload["blob"], blob());
    let old_anchor = json!({"reference":{"revision":"old-t","episode":"e","show":"s","libraryID":"old","blob":old_blob},"startUTF16":0,"lengthUTF16":5,"quote":"hello"});
    let old_claims = json!([{"text":"Answer","citations":[old_anchor]}]);
    let answer = import_operation(
        &legacy(
            "answer.save",
            json!({"question":"Why?","claims":old_claims}),
        ),
        &c,
    );
    assert_eq!(answer.commands[0].kind, "saveAnswer");
    c.accepted_answer =
        Some(json!({"responseRevision":"accepted-response","question":"Why?","claims":old_claims}));
    for kind in ["question.response", "question.admit"] {
        assert_eq!(
            import_operation(&legacy(kind, json!({})), &c).commands[0].kind,
            "saveAnswer"
        );
    }
    c.emitted_answers.insert("accepted-response".into());
    assert!(import_operation(&legacy("question.admit", json!({})), &c)
        .commands
        .is_empty());
    c.effective_payload =
        Some(json!({"feeds":[{"targetShowID":"s","feedURL":feed,"title":"Show"}]}));
    assert_eq!(
        import_operation(
            &legacy("legacy.bridge.import", json!({"sourceRoot":"e".repeat(64)})),
            &c
        )
        .commands[0]
            .kind,
        "follow"
    );
    c.effective_payload = Some(
        json!({"actions":[{"kind":"position","mode":"baseline","payload":{"id":"e","show":"s","seconds":12}}]}),
    );
    let published = import_operation(
        &legacy(
            "podcast.source.publish",
            json!({"facts":[{"kind":"playbackEvidence","body":{"sessionID":"old-session"}}]}),
        ),
        &c,
    );
    assert_eq!(published.commands[0].kind, "position");
    assert_eq!(published.commands[0].payload["expect"], Value::Null);
    let bound = bind_outputs(published, &["new-operation".into()]).unwrap();
    assert_eq!(
        bound.evidence[0].manifest["children"][0]["outputOperationID"],
        "new-operation"
    );
    let mut index = EvidenceIndex::default();
    let evidence = bound.evidence[0].clone();
    index.insert(evidence.clone()).unwrap();
    index.insert(evidence.clone()).unwrap();
    let mut changed = evidence.clone();
    changed.manifest["reason"] = json!("changed");
    assert!(index.insert(changed).is_err());
    index.insert_historical(HistoricalRow {evidence_id:evidence.id.clone(),query:"importedSession".into(),id:"source-session".into(),object:"e".into(),order:"2026-11-01:source-session".into(),value:json!({"sourceID":"source-session","episode":"e","started":"2026-11-01T00:00:00Z","ended":"2026-11-01T00:01:00Z","elapsed":60,"hidden":false})}).unwrap();
    let rows = index
        .query("importedSession", &json!({"object":"e"}))
        .unwrap();
    assert_eq!(rows["value"]["total"], 1);
    assert_eq!(rows["value"]["rows"][0]["historical"], true);
    assert_eq!(
        index
            .query("importEvidence", &json!({"sourceLibrary":"old-library"}))
            .unwrap()["value"]["total"],
        1
    );
    assert_eq!(
        index.manifest(&evidence.id).unwrap().manifest["originalPayload"]["facts"][0]["kind"],
        "playbackEvidence"
    );
}

#[test]
fn catch_up_and_stale_event_identities_cannot_overwrite_native_heads() {
    let mut c = applied();
    c.catch_up = true;
    let old = legacy(
        "episode.position",
        json!({"episode":"e","show":"s","seconds":500}),
    );
    assert!(import_operation(&old, &c).commands.is_empty());
    c.destination_heads
        .insert(map_key("position", "e"), json!("imported-head"));
    let plan = import_operation(&old, &c);
    assert_eq!(plan.commands[0].payload["expect"], "imported-head");
    let mut s = PodcastsState::default();
    apply(
        &mut s,
        1,
        "position",
        json!({"id":"e","show":"s","seconds":5}),
    );
    apply(
        &mut s,
        2,
        &plan.commands[0].kind,
        plan.commands[0].payload.clone(),
    );
    assert_eq!(q(&s, "episode", json!({"id":"e"}))["row"]["seconds"], 5.0);
    let event = json!({"eventID":"stale-event","episode":"e","show":"s","audio":"audio","endSeconds":100,"actualDuration":100,"expectedPosition":null,"expectedState":null});
    apply(
        &mut s,
        3,
        "completePlayback",
        json!({"id":"first","events":[event],"baseQueue":[],"expect":null}),
    );
    let mut changed = event;
    changed["expectedPosition"] = json!("op-0001");
    apply(
        &mut s,
        4,
        "completePlayback",
        json!({"id":"second","events":[changed],"baseQueue":[],"expect":null}),
    );
    assert_eq!(q(&s, "episode", json!({"id":"e"}))["row"]["seconds"], 5.0);
    assert_eq!(
        q(&s, "conflicts", json!({"object":"second"}))["rows"][0]["outcome"],
        "eventAlreadyUsed"
    );
}

#[test]
fn late_sources_update_episode_filters_without_replaying_jobs() {
    let mut s = PodcastsState::default();
    let mut pinned = anchor();
    pinned["reference"]
        .as_object_mut()
        .unwrap()
        .remove("episode");
    apply(
        &mut s,
        1,
        "saveAnswer",
        json!({"id":"answer","question":"Why?","claims":[{"text":"Answer","citations":[pinned]}]}),
    );
    apply(
        &mut s,
        2,
        "askQuestion",
        json!({"id":"question","question":"Why?","scope":[pinned],"worker":"agent","expires":"2026-11-07T00:00:00Z"}),
    );
    assert_eq!(
        q(&s, "contributions", json!({"kind":"answer","episode":"e"}))["total"],
        0
    );
    assert_eq!(
        q(&s, "jobs", json!({"kind":"question","episode":"e"}))["total"],
        0
    );
    apply(
        &mut s,
        3,
        "saveTranscript",
        json!({"id":"t","episode":"e","show":"show","blob":blob(),"source":"publisher","timed":true}),
    );
    assert_eq!(
        q(&s, "contributions", json!({"kind":"answer","episode":"e"}))["total"],
        1
    );
    assert_eq!(
        q(&s, "jobs", json!({"kind":"question","episode":"e"}))["total"],
        1
    );
    assert_eq!(
        q(&s, "jobs", json!({"kind":"question"}))["rows"][0]["status"],
        "pendingSource"
    );
    apply(&mut s, 4, "episode", json!({"id":"e","show":"show"}));
    assert_eq!(
        q(&s, "history", json!({"mode":"latestEpisode"}))["total"],
        0
    );
    apply(
        &mut s,
        5,
        "setState",
        json!({"id":"e","show":"show","consumption":"completed"}),
    );
    assert_eq!(
        q(&s, "history", json!({"mode":"latestEpisode"}))["total"],
        1
    );
    apply(
        &mut s,
        6,
        "follow",
        json!({"id":"show","url":"https://example.org/feed"}),
    );
    apply(
        &mut s,
        7,
        "editShow",
        json!({"id":"show","skipIntro":15,"expect":"op-0006"}),
    );
    assert_eq!(q(&s, "show", json!({"id":"show"}))["skipIntro"], 15);
    let mut progress = op(8, "position", json!({"id":"e","seconds":5}));
    progress.created = "2026-11-06T13:00:00Z".into();
    ListeningPodcasts.apply(&mut s, &progress);
    assert_eq!(
        q(&s, "history", json!({"mode":"latestEpisode"}))["rows"][0]["updated"],
        "2026-11-06T12:00:00Z"
    );
    assert_eq!(
        q(&s, "episode", json!({"id":"e"}))["row"]["updated"],
        "2026-11-06T13:00:00Z"
    );
}

#[test]
fn inline_source_bytes_are_rejected_and_prefix_binding_invalidates_cursors() {
    let mut s = PodcastsState::default();
    for n in 1..=2 {
        apply(&mut s, n, "episode", json!({"id":format!("e{n}")}));
    }
    let page = q(&s, "episodes", json!({"limit":1}));
    ListeningPodcasts
        .bind_admitted_prefix(&mut s, &"f".repeat(64))
        .unwrap();
    assert_eq!(
        q(&s, "episodes", json!({"cursor":page["next"]}))["outcome"],
        "staleCursor"
    );
    assert!(ListeningPodcasts
        .bind_admitted_prefix(&mut s, "unverified")
        .is_err());
    apply(
        &mut s,
        3,
        "saveTranscript",
        json!({"id":"t","episode":"e","show":"s","source":"publisher","timed":false,"blob":blob(),"text":"Inline bytes"}),
    );
    let mut inline = blob();
    inline["bytes"] = json!([1, 2, 3]);
    apply(
        &mut s,
        4,
        "saveTranscript",
        json!({"id":"t","episode":"e","show":"s","source":"publisher","timed":false,"blob":inline}),
    );
    assert_eq!(full(&s)["invalid"], json!(["op-0003", "op-0004"]));
}
