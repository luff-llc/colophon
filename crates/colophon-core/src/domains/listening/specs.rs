use crate::domain::Spec;
use serde_json::{json, Value};

fn id() -> Value {
    json!({"type":"string","minLength":1,"maxLength":1024,"format":"colophon-id"})
}
fn text(max: usize) -> Value {
    json!({"type":"string","maxLength":max})
}
fn enumeration(values: &[&str]) -> Value {
    json!({"type":"string","enum":values})
}
fn number(min: f64) -> Value {
    json!({"type":"number","minimum":min})
}
fn boolean() -> Value {
    json!({"type":"boolean"})
}
fn array(items: Value, max: usize) -> Value {
    json!({"type":"array","items":items,"maxItems":max})
}
fn nullable(value: Value) -> Value {
    json!({"anyOf":[value,{"type":"null"}]})
}
fn rev() -> Value {
    nullable(id())
}
fn digest() -> Value {
    json!({"type":"string","format":"sha256"})
}
fn instant() -> Value {
    json!({"type":"string","format":"date-time"})
}
fn url() -> Value {
    json!({"type":"string","format":"http-url","maxLength":4096})
}
fn object(required: &[&str], fields: &[(&str, Value)]) -> Value {
    let properties: serde_json::Map<String, Value> = fields
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect();
    json!({"type":"object","required":required,"properties":properties,"additionalProperties":true})
}
pub(super) fn blob() -> Value {
    let mut schema = object(
        &["digest", "size", "mediaType"],
        &[
            ("digest", digest()),
            (
                "size",
                json!({"type":"integer","minimum":0,"maximum":9007199254740991u64}),
            ),
            ("mediaType", text(256)),
        ],
    );
    schema["not"] = json!({"anyOf":[{"required":["bytes"]},{"required":["data"]},{"required":["text"]},{"required":["words"]}]});
    schema
}
fn reference() -> Value {
    object(
        &["transcript", "revision", "blob"],
        &[
            ("transcript", id()),
            ("revision", id()),
            ("blob", blob()),
            ("episode", id()),
            ("show", id()),
            ("libraryID", id()),
        ],
    )
}
fn anchor() -> Value {
    object(
        &["reference", "startUTF16", "lengthUTF16", "quote"],
        &[
            ("reference", reference()),
            (
                "startUTF16",
                json!({"type":"integer","minimum":0,"maximum":9007199254740991u64}),
            ),
            (
                "lengthUTF16",
                json!({"type":"integer","minimum":1,"maximum":8000}),
            ),
            ("quote", text(32000)),
        ],
    )
}
fn claims() -> Value {
    let mut v = array(
        object(
            &["text", "citations"],
            &[("text", text(160000)), ("citations", array(anchor(), 200))],
        ),
        50,
    );
    v["minItems"] = json!(1);
    v
}
pub(super) fn descriptor() -> Value {
    object(
        &[
            "id",
            "show",
            "feed",
            "guid",
            "title",
            "showTitle",
            "audioURL",
        ],
        &episode_fields(),
    )
}
fn episode_fields() -> Vec<(&'static str, Value)> {
    vec![
        ("id", id()),
        ("show", id()),
        ("feed", url()),
        ("guid", text(4096)),
        ("title", text(2048)),
        ("showTitle", text(2048)),
        ("audioURL", url()),
        ("duration", json!({"type":"number","exclusiveMinimum":0})),
        ("published", instant()),
        ("transcriptExcerpt", text(4096)),
        ("expect", rev()),
    ]
}
fn spec(name: &str, description: &str, required: &[&str], fields: Vec<(&str, Value)>) -> Spec {
    Spec {
        name: name.into(),
        description: description.into(),
        input_schema: object(required, &fields),
    }
}
pub(super) fn operations() -> Vec<Spec> {
    let mut changes = array(
        object(
            &["scope", "field", "value", "expect"],
            &[
                ("scope", enumeration(&["global", "show", "episode"])),
                ("target", id()),
                ("field", text(64)),
                (
                    "value",
                    json!({"anyOf":[boolean(),number(0.0),text(128),{"type":"null"}]}),
                ),
                ("expect", rev()),
            ],
        ),
        15,
    );
    changes["minItems"] = json!(1);
    let event = object(
        &[
            "eventID",
            "episode",
            "show",
            "audio",
            "endSeconds",
            "actualDuration",
            "expectedPosition",
            "expectedState",
        ],
        &[
            ("eventID", text(128)),
            ("episode", id()),
            ("show", id()),
            ("audio", text(512)),
            ("endSeconds", number(0.0)),
            (
                "actualDuration",
                json!({"type":"number","exclusiveMinimum":0,"maximum":604800}),
            ),
            ("expectedPosition", rev()),
            ("expectedState", rev()),
        ],
    );
    let capture = object(
        &["requestID", "originalText", "surroundingText"],
        &[
            ("requestID", id()),
            ("originalText", nullable(text(40000))),
            ("surroundingText", text(8000)),
            ("voice", nullable(blob())),
            ("voiceMimeType", nullable(text(256))),
            ("targetAgentID", nullable(id())),
        ],
    );
    let mut specs = vec![
        spec(
            "follow",
            "Create or reactivate a podcast show",
            &["id", "url"],
            vec![
                ("id", id()),
                ("url", url()),
                ("title", text(2048)),
                ("expect", rev()),
            ],
        ),
        spec(
            "unfollow",
            "Unfollow, retaining an ordered head even before creation",
            &["id"],
            vec![("id", id()), ("expect", rev())],
        ),
        spec(
            "editShow",
            "Patch show title and skip settings against its head",
            &["id"],
            vec![
                ("id", id()),
                ("title", text(2048)),
                ("skipIntro", number(0.0)),
                ("skipOutro", number(0.0)),
                ("expect", rev()),
            ],
        ),
        spec(
            "setPreferences",
            "Atomically compare and change up to fifteen preference heads",
            &["id", "changes"],
            vec![("id", id()), ("changes", changes)],
        ),
        spec(
            "setState",
            "Set episode consumption against the independent state head",
            &["id", "show", "consumption"],
            vec![
                ("id", id()),
                ("show", id()),
                (
                    "consumption",
                    enumeration(&[
                        "notStarted",
                        "inProgress",
                        "doneEnough",
                        "completed",
                        "abandoned",
                    ]),
                ),
                ("expect", rev()),
            ],
        ),
        // Missing show remains accepted for the shipped preview callers; an existing parent is retained.
        spec(
            "position",
            "Record progress or a deliberate seek; never a listening session",
            &["id", "seconds"],
            vec![
                ("id", id()),
                ("show", id()),
                ("seconds", number(0.0)),
                ("duration", json!({"type":"number","exclusiveMinimum":0})),
                ("seek", boolean()),
                ("expect", rev()),
            ],
        ),
        spec(
            "recoverPosition",
            "Atomically recover position and optional in-progress state",
            &[
                "id",
                "show",
                "seconds",
                "expectedPosition",
                "expectedState",
                "inProgress",
            ],
            vec![
                ("id", id()),
                ("show", id()),
                ("seconds", number(0.0)),
                ("duration", json!({"type":"number","exclusiveMinimum":0})),
                ("expectedPosition", rev()),
                ("expectedState", rev()),
                ("inProgress", boolean()),
            ],
        ),
        spec(
            "queue",
            "Replace a unique ordered queue, retaining optional episode descriptors",
            &["episodes"],
            vec![
                ("episodes", array(id(), 1024)),
                ("metadata", array(descriptor(), 512)),
                ("expect", rev()),
            ],
        ),
        spec(
            "episode",
            "Patch retained episode metadata without changing playback heads",
            &["id"],
            episode_fields(),
        ),
        spec(
            "completePlayback",
            "Atomically complete up to sixteen episodes and remove them from the queue",
            &["id", "events", "baseQueue", "expect"],
            vec![
                ("id", id()),
                ("events", array(event, 16)),
                ("baseQueue", array(id(), 1024)),
                ("expect", rev()),
            ],
        ),
        spec(
            "addNote",
            "Create an immutable note occurrence and optional pinned capture",
            &["id", "episode", "show", "text"],
            vec![
                ("id", id()),
                ("episode", id()),
                ("show", id()),
                ("text", text(262144)),
                ("seconds", number(0.0)),
                ("quote", text(32000)),
                ("anchor", anchor()),
                ("capture", capture),
            ],
        ),
        spec(
            "editNote",
            "Edit note text; preserve stale edits as attributed alternatives",
            &["id", "text"],
            vec![("id", id()), ("text", text(262144)), ("expect", rev())],
        ),
        spec(
            "resolveNote",
            "Resolve precisely the current head and observed alternatives",
            &["id", "text", "expect", "resolves"],
            vec![
                ("id", id()),
                ("text", text(262144)),
                ("expect", id()),
                ("resolves", array(id(), 4096)),
            ],
        ),
        spec(
            "deleteNote",
            "Permanently tombstone this note occurrence",
            &["id"],
            vec![("id", id()), ("expect", rev())],
        ),
        spec(
            "setSegments",
            "Replace recording-specific skip segments with full validation",
            &["episode", "show", "recording", "source", "segments"],
            vec![
                ("episode", id()),
                ("show", id()),
                ("recording", digest()),
                ("source", enumeration(&["detected", "person"])),
                ("detector", text(1024)),
                (
                    "segments",
                    array(
                        object(
                            &["start", "end", "kind"],
                            &[
                                ("start", number(0.0)),
                                ("end", number(0.0)),
                                ("kind", text(128)),
                            ],
                        ),
                        2048,
                    ),
                ),
                ("expect", rev()),
            ],
        ),
        spec(
            "saveTranscript",
            "Retain an immutable transcript descriptor; select by rank and fold order",
            &["id", "episode", "show", "blob", "source", "timed"],
            vec![
                ("id", id()),
                ("episode", id()),
                ("show", id()),
                ("blob", blob()),
                ("source", text(1024)),
                ("timed", boolean()),
                ("language", text(128)),
                ("recording", digest()),
                ("receipt", json!({})),
            ],
        ),
        spec(
            "setChapters",
            "Replace recording-specific chapters, preserving person review",
            &["episode", "show", "recording", "source", "entries"],
            vec![
                ("episode", id()),
                ("show", id()),
                ("recording", digest()),
                ("source", text(1024)),
                (
                    "entries",
                    array(
                        object(
                            &["start", "title"],
                            &[("start", number(0.0)), ("title", text(640))],
                        ),
                        2048,
                    ),
                ),
                ("expect", rev()),
            ],
        ),
        spec(
            "savePlaylist",
            "Save a complete playlist rule; retain competing rules",
            &["id", "name", "mode"],
            vec![
                ("id", id()),
                ("name", text(480)),
                ("mode", enumeration(&["manual", "automatic"])),
                ("allShows", boolean()),
                ("includeFinished", boolean()),
                ("archived", boolean()),
                ("shows", array(id(), 1024)),
                ("episodes", array(id(), 1024)),
                ("excluded", array(id(), 1024)),
                ("pinned", array(id(), 1024)),
                ("included", array(id(), 1024)),
                ("order", enumeration(&["newest", "oldest", "byShow"])),
                ("progress", enumeration(&["any", "unplayed", "inProgress"])),
                (
                    "maxMinutes",
                    json!({"type":"integer","minimum":1,"maximum":1440}),
                ),
                ("titleContains", text(320)),
                ("expect", rev()),
            ],
        ),
        spec(
            "saveAnswer",
            "Retain an immutable cited answer with pending source verification",
            &["id", "question", "claims"],
            vec![
                ("id", id()),
                ("question", text(16000)),
                ("claims", claims()),
            ],
        ),
        spec(
            "requestTranscript",
            "Delegate an immutable transcript request to an enrolled worker",
            &[
                "id",
                "episode",
                "show",
                "worker",
                "audio",
                "recording",
                "language",
            ],
            vec![
                ("id", id()),
                ("episode", id()),
                ("show", id()),
                ("worker", id()),
                ("audio", blob()),
                ("recording", digest()),
                ("language", text(128)),
            ],
        ),
        spec(
            "cancelTranscript",
            "Original requester durably cancels a transcript job",
            &["id", "request"],
            vec![("id", id()), ("request", id())],
        ),
        spec(
            "supplyTranscript",
            "Selected agent supplies a result without installing it",
            &["id", "request", "result"],
            vec![("id", id()), ("request", id()), ("result", blob())],
        ),
        spec(
            "askQuestion",
            "Delegate a question over exact pinned passages; host checks deadline",
            &["id", "question", "scope", "worker", "expires"],
            vec![
                ("id", id()),
                ("question", text(16000)),
                ("scope", array(anchor(), 20)),
                ("worker", id()),
                ("expires", instant()),
            ],
        ),
        spec(
            "answerQuestion",
            "Selected agent supplies claims scoped to the original question",
            &["id", "request", "scopeDigest", "claims"],
            vec![
                ("id", id()),
                ("request", id()),
                ("scopeDigest", digest()),
                ("claims", claims()),
            ],
        ),
        spec(
            "cancelQuestion",
            "An app or device durably cancels a question",
            &["id", "request"],
            vec![("id", id()), ("request", id())],
        ),
        spec(
            "acceptAnswer",
            "Record technical admission separately from person endorsement",
            &["id", "request", "response"],
            vec![("id", id()), ("request", id()), ("response", id())],
        ),
        spec(
            "respondCapture",
            "Selected agent responds without overwriting the original thought",
            &["id", "request", "text"],
            vec![("id", id()), ("request", id()), ("text", text(40000))],
        ),
        spec(
            "cancelCapture",
            "Original requester cancels a capture; preserve its original text",
            &["id", "request"],
            vec![("id", id()), ("request", id())],
        ),
        spec(
            "proposeContext",
            "Agent proposes an owned contribution pinned to a transcript",
            &["id", "reference", "contributionID", "text", "citation"],
            vec![
                ("id", id()),
                ("reference", reference()),
                ("contributionID", id()),
                ("text", text(262144)),
                ("citation", text(32000)),
                ("expect", rev()),
            ],
        ),
        spec(
            "acceptContext",
            "Accept the exact current proposal, retaining both attributions",
            &["id", "reference", "contributionID", "proposal"],
            vec![
                ("id", id()),
                ("reference", reference()),
                ("contributionID", id()),
                ("proposal", id()),
                ("note", text(262144)),
                ("expect", rev()),
            ],
        ),
    ];
    if let Some(transcript) = specs.iter_mut().find(|spec| spec.name == "saveTranscript") {
        transcript.input_schema["not"] = json!({"anyOf":[{"required":["text"]},{"required":["words"]},{"required":["transcript"]},{"required":["bytes"]}]});
    }
    specs
}

pub(super) fn queries() -> Vec<Spec> {
    let definitions = [
        ("shows", vec![], vec![("following", boolean())]),
        ("show", vec!["id"], vec![("id", id())]),
        (
            "episodes",
            vec![],
            vec![
                ("show", id()),
                (
                    "state",
                    enumeration(&[
                        "notStarted",
                        "inProgress",
                        "doneEnough",
                        "completed",
                        "abandoned",
                    ]),
                ),
            ],
        ),
        ("getEpisode", vec!["id"], vec![("id", id())]),
        ("episodeDetail", vec!["id"], vec![("id", id())]),
        ("getQueue", vec![], vec![]),
        (
            "playbackContext",
            vec!["episode"],
            vec![("episode", id()), ("recording", digest())],
        ),
        ("playlists", vec![], vec![("archived", boolean())]),
        ("playlist", vec!["id"], vec![("id", id())]),
        ("notes", vec![], vec![("episode", id())]),
        ("note", vec!["id"], vec![("id", id())]),
        (
            "recordingContent",
            vec!["episode", "recording", "kind"],
            vec![
                ("episode", id()),
                ("recording", digest()),
                ("kind", enumeration(&["segments", "chapters"])),
            ],
        ),
        ("transcripts", vec![], vec![("episode", id())]),
        (
            "history",
            vec!["mode"],
            vec![
                ("mode", enumeration(&["latestEpisode", "importedSession"])),
                ("finishedOnly", boolean()),
            ],
        ),
        (
            "jobs",
            vec!["kind"],
            vec![
                ("kind", enumeration(&["transcript", "question", "capture"])),
                ("episode", id()),
                ("status", text(128)),
            ],
        ),
        (
            "contributions",
            vec!["kind"],
            vec![
                ("kind", enumeration(&["answer", "context"])),
                ("id", id()),
                ("episode", id()),
            ],
        ),
        ("listeningCounts", vec![], vec![("show", id())]),
        ("conflicts", vec!["object"], vec![("object", id())]),
        ("invalid", vec![], vec![]),
        ("read", vec![], vec![]),
    ];
    definitions.into_iter().map(|(name,required,mut fields)| {
        if !["show","getEpisode","episodeDetail","playbackContext","playlist","note","listeningCounts","read"].contains(&name) {
            fields.extend([("cursor",text(8192)),("limit",json!({"type":"integer","minimum":1,"maximum":100})),("offset",json!({"type":"integer","minimum":0}))]);
        }
        let mut s=spec(name,&format!("Read {name}; bounded pages default to 50 (queue/jobs/contributions 20), maximum 100; cursors bind the admitted prefix"),&required,fields);
        s.input_schema["additionalProperties"]=json!(false); s
    }).collect()
}
