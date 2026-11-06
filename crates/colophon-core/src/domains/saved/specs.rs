use crate::domain::Spec;
use serde_json::{json, Value};

fn schema(fields: &[(&str, Value)], required: &[&str]) -> Value {
    let props: serde_json::Map<String, Value> = fields
        .iter()
        .map(|(k, v)| ((*k).into(), v.clone()))
        .collect();
    json!({"type":"object","properties":props,"required":required,"additionalProperties":true})
}
fn text(max: usize) -> Value {
    json!({"type":"string","maxLength":max})
}
fn id() -> Value {
    json!({"type":"string","minLength":1,"maxLength":1024,"format":"saved-id"})
}
fn en(values: &[&str]) -> Value {
    json!({"type":"string","enum":values})
}
fn array(v: Value, max: usize) -> Value {
    json!({"type":"array","items":v,"maxItems":max})
}
fn integer(max: u64) -> Value {
    json!({"type":"integer","minimum":0,"maximum":max})
}
fn boolean() -> Value {
    json!({"type":"boolean"})
}
fn expect() -> Value {
    json!({"anyOf":[id(),{"type":"null"}]})
}
fn url() -> Value {
    json!({"type":"string","format":"saved-url","maxLength":8192})
}
fn instant() -> Value {
    json!({"type":"string","format":"date-time"})
}
pub(super) fn blob(max: u64) -> Value {
    schema(
        &[
            ("digest", json!({"type":"string","format":"sha256"})),
            ("size", json!({"type":"integer","minimum":1,"maximum":max})),
            ("mediaType", text(256)),
        ],
        &["digest", "size", "mediaType"],
    )
}
pub(super) fn manifest() -> Value {
    schema(
        &[
            ("id", id()),
            ("original", blob(128_000_000)),
            ("metadata", blob(16 * 1024 * 1024)),
            (
                "mediaType",
                en(&[
                    "application/pdf",
                    "text/plain",
                    "text/html",
                    "message/rfc822",
                    "application/xml",
                    "text/xml",
                ]),
            ),
            ("origin", json!({"type":"object"})),
            ("capturedAt", instant()),
            ("extractionVersion", json!({"const":1})),
            (
                "pageCount",
                json!({"type":"integer","minimum":1,"maximum":10000}),
            ),
            ("coverage", text(4096)),
        ],
        &[
            "id",
            "metadata",
            "mediaType",
            "origin",
            "capturedAt",
            "extractionVersion",
            "coverage",
        ],
    )
}
pub(super) fn anchor() -> Value {
    json!({"oneOf":[
     schema(&[("kind",json!({"const":"page"})),("index",integer(10000))], &["kind","index"]),
     schema(&[("kind",json!({"const":"text"})),("passageID",id()),("startUTF16",integer(9007199254740991)),("lengthUTF16",integer(9007199254740991)),("quote",text(262144))], &["kind","passageID","startUTF16","lengthUTF16","quote"]),
     schema(&[("kind",json!({"const":"item"}))], &["kind"]),
     schema(&[("kind",json!({"const":"unresolved"})),("quote",text(262144)),("location",text(4096)),("reason",text(4096))], &["kind","quote","location","reason"])
    ]})
}
fn position() -> Value {
    json!({"oneOf":[schema(&[("kind",json!({"const":"page"})),("index",integer(10000))], &["kind","index"]),schema(&[("kind",json!({"const":"passage"})),("id",id()),("offsetUTF16",integer(9007199254740991))], &["kind","id","offsetUTF16"])]})
}
fn evidence() -> Value {
    schema(
        &[("source", id()), ("annotation", id()), ("anchor", anchor())],
        &["source"],
    )
}
fn endpoint() -> Value {
    schema(
        &[("item", id()), ("source", id()), ("annotation", id())],
        &["item", "source"],
    )
}
fn folders() -> Value {
    array(array(text(120), 16), 100)
}
pub(super) fn view_query() -> Value {
    let mut v = schema(
        &[
            ("version", json!({"type":"integer","enum":[1,2]})),
            (
                "shelf",
                en(&["all", "readingNow", "unread", "finished", "archive"]),
            ),
            ("search", text(2000)),
            ("source", text(500)),
            ("availability", en(&["any", "savedText"])),
            (
                "consumption",
                en(&[
                    "notStarted",
                    "inProgress",
                    "doneEnough",
                    "completed",
                    "abandoned",
                ]),
            ),
            (
                "retention",
                en(&["captured", "saved", "chosen", "resurface", "released"]),
            ),
            ("tag", text(120)),
            ("collection", text(1024)),
            (
                "kind",
                en(&[
                    "all",
                    "web",
                    "pdf",
                    "text",
                    "htmlFile",
                    "email",
                    "feed",
                    "originalMissing",
                    "link",
                    "native",
                ]),
            ),
            ("sourceStatus", en(&["none", "sourceOnly", "retained"])),
            ("includeDeleted", boolean()),
            (
                "sort",
                en(&["newest", "oldest", "title", "author", "added", "touched"]),
            ),
            ("direction", en(&["ascending", "descending"])),
        ],
        &[],
    );
    v["additionalProperties"] = json!(false);
    v
}
fn operation(name: &str, desc: &str, fields: Vec<(&str, Value)>, required: &[&str]) -> Spec {
    Spec {
        name: name.into(),
        description: desc.into(),
        input_schema: {
            let mut s = schema(&fields, required);
            s["x-colophon-saved-command"] = json!(name);
            s
        },
    }
}
pub(super) fn operations() -> Vec<Spec> {
    let consumption = en(&[
        "notStarted",
        "inProgress",
        "doneEnough",
        "completed",
        "abandoned",
    ]);
    let retention = en(&["captured", "saved", "chosen", "resurface", "released"]);
    let parents = array(id(), 1024);
    vec![
        operation(
            "capture",
            "Create a saved occurrence, with or without a URL",
            vec![
                ("id", id()),
                ("title", text(16384)),
                ("url", url()),
                (
                    "consumption",
                    json!({"anyOf":[consumption.clone(),{"type":"null"}]}),
                ),
                (
                    "retention",
                    json!({"anyOf":[retention.clone(),{"type":"null"}]}),
                ),
            ],
            &["id"],
        ),
        operation(
            "setState",
            "Change reading state with an independent state precondition",
            vec![
                ("id", id()),
                ("consumption", consumption),
                ("retention", retention),
                ("expect", expect()),
                ("state", en(&["reading", "read", "done", "unread"])),
            ],
            &["id"],
        ),
        operation(
            "editMetadata",
            "Edit metadata; stale changes remain attributed alternatives",
            vec![
                ("id", id()),
                ("title", text(16384)),
                ("creator", text(1024)),
                ("summary", text(262144)),
                ("collection", text(1024)),
                ("tags", array(text(120), 100)),
                ("expect", expect()),
            ],
            &["id"],
        ),
        operation(
            "delete",
            "Permanently tombstone this occurrence at its exact current activity",
            vec![("id", id()), ("expectActivity", id())],
            &["id", "expectActivity"],
        ),
        operation(
            "retainSource",
            "Retain an immutable source descriptor; bytes are resolved by the host",
            vec![
                ("id", id()),
                ("item", id()),
                ("manifest", manifest()),
                ("select", boolean()),
                ("expect", expect()),
            ],
            &["id", "item", "manifest"],
        ),
        operation(
            "selectSource",
            "Select an existing source at the exact selection head",
            vec![("item", id()), ("source", id()), ("expect", expect())],
            &["item", "source", "expect"],
        ),
        operation(
            "position",
            "Replace reading position, including deliberate backward movement",
            vec![
                ("item", id()),
                ("source", id()),
                ("position", position()),
                ("expect", expect()),
            ],
            &["item", "source", "position"],
        ),
        operation(
            "reviseAnnotation",
            "Retain an annotation branch; resolve all observed heads or delete terminally",
            vec![
                ("id", id()),
                ("thread", id()),
                ("item", id()),
                ("source", id()),
                ("parents", parents.clone()),
                (
                    "action",
                    en(&["create", "edit", "relocate", "resolve", "delete"]),
                ),
                ("anchor", anchor()),
                ("text", text(262144)),
            ],
            &[
                "id", "thread", "item", "source", "parents", "action", "anchor", "text",
            ],
        ),
        operation(
            "tagAnnotations",
            "Atomically set tag membership for live threads",
            vec![
                ("id", id()),
                ("threads", array(id(), 1000)),
                ("tag", text(120)),
                ("included", boolean()),
                ("expect", expect()),
            ],
            &["id", "threads", "tag", "included"],
        ),
        operation(
            "followFeed",
            "Follow or conditionally refollow a feed",
            vec![
                ("id", id()),
                ("url", url()),
                ("title", text(1024)),
                ("folders", folders()),
                ("expect", expect()),
            ],
            &["id", "url", "title", "folders"],
        ),
        operation(
            "unfollowFeed",
            "Stop following a feed without deleting its history",
            vec![("id", id()), ("expect", id())],
            &["id", "expect"],
        ),
        operation(
            "organizeFeed",
            "Replace a followed feed's folder paths",
            vec![("id", id()), ("folders", folders()), ("expect", id())],
            &["id", "folders", "expect"],
        ),
        operation(
            "refreshFeed",
            "Merge a bounded feed response and retain response descriptors",
            vec![
                ("id", id()),
                ("response", blob(5 * 1024 * 1024)),
                (
                    "entries",
                    array(
                        schema(
                            &[
                                ("id", text(128)),
                                ("title", text(4096)),
                                ("url", url()),
                                ("publisherIdentity", text(8192)),
                                ("author", text(1024)),
                                ("summary", text(4096)),
                                ("published", instant()),
                            ],
                            &["id", "title", "publisherIdentity", "author", "summary"],
                        ),
                        500,
                    ),
                ),
                ("expect", id()),
                ("title", text(1024)),
                ("omitted", integer(9007199254740991)),
            ],
            &["id", "response", "entries", "expect"],
        ),
        operation(
            "reviseView",
            "Retain a saved-view revision and all concurrent definitions",
            vec![
                ("id", id()),
                ("view", id()),
                ("parents", parents.clone()),
                ("name", text(120)),
                ("query", view_query()),
                ("deleted", boolean()),
            ],
            &["id", "view", "parents", "name", "query", "deleted"],
        ),
        operation(
            "changeReview",
            "Record a review choice, exclusion, undo or explicit local opt-in",
            vec![
                ("id", id()),
                (
                    "action",
                    en(&[
                        "enable",
                        "disable",
                        "revisited",
                        "passed",
                        "exclude",
                        "include",
                        "undo",
                    ]),
                ),
                ("thread", id()),
                ("annotation", id()),
                ("undoing", id()),
            ],
            &["id", "action"],
        ),
        operation(
            "keepAnswer",
            "Keep an immutable answer with exact retained evidence references",
            vec![
                ("id", id()),
                ("question", text(500)),
                (
                    "claims",
                    array(
                        schema(
                            &[("text", text(262144)), ("citations", array(evidence(), 8))],
                            &["text", "citations"],
                        ),
                        6,
                    ),
                ),
                ("evidence", array(evidence(), 8)),
                ("engine", text(1024)),
                ("runtime", text(1024)),
                ("promptRevision", text(1024)),
            ],
            &[
                "id",
                "question",
                "claims",
                "evidence",
                "engine",
                "runtime",
                "promptRevision",
            ],
        ),
        operation(
            "setAnswerVisibility",
            "Retain reversible visibility branches for an answer",
            vec![
                ("id", id()),
                ("answer", id()),
                ("parents", parents.clone()),
                ("hidden", boolean()),
            ],
            &["id", "answer", "parents", "hidden"],
        ),
        operation(
            "reviseConnection",
            "Retain a relation revision with immutable exact endpoints",
            vec![
                ("id", id()),
                ("connection", id()),
                ("parents", parents),
                ("source", endpoint()),
                ("target", endpoint()),
                (
                    "relation",
                    en(&["related", "supports", "challenges", "expands"]),
                ),
                ("reason", text(262144)),
                ("retracted", boolean()),
            ],
            &[
                "id",
                "connection",
                "parents",
                "source",
                "target",
                "relation",
                "reason",
                "retracted",
            ],
        ),
        operation(
            "setMagazineSubscription",
            "Conditionally replace a publication subscription; credentials stay local",
            vec![
                ("id", id()),
                ("publication", id()),
                (
                    "status",
                    en(&["unknown", "active", "paused", "expired", "cancelled"]),
                ),
                (
                    "plan",
                    en(&["unknown", "digital", "print", "printAndDigital"]),
                ),
                ("accessUntil", instant()),
                ("expect", expect()),
            ],
            &["id", "publication", "status", "plan"],
        ),
        operation(
            "retainSourceMetadata",
            "Retain a typed source-only record and immutable raw provenance",
            vec![
                ("id", id()),
                ("item", id()),
                ("kind", en(&["readerMetadata", "externalExcerpt"])),
                ("value", metadata_value()),
                ("raw", blob(128_000_000)),
            ],
            &["id", "item", "kind", "value", "raw"],
        ),
        operation(
            "attachOriginal",
            "Attach a reviewed original at exact metadata and activity heads",
            vec![
                ("item", id()),
                ("metadata", id()),
                ("manifest", manifest()),
                ("expect", id()),
                ("expectActivity", id()),
            ],
            &["item", "metadata", "manifest", "expect", "expectActivity"],
        ),
        operation(
            "retainImages",
            "Retain immutable image evidence at an exact source head",
            vec![
                ("item", id()),
                ("source", id()),
                ("assets", array(image_asset(), 20)),
                ("coverage", image_coverage()),
                ("expect", id()),
            ],
            &["item", "source", "assets", "coverage", "expect"],
        ),
        operation(
            "captureReading",
            "Atomically retain a browser checkpoint, position and new annotations",
            vec![
                ("id", id()),
                ("item", id()),
                ("source", manifest()),
                ("position", position()),
                (
                    "notes",
                    array(
                        schema(
                            &[("id", id()), ("anchor", anchor()), ("text", text(65536))],
                            &["id", "anchor", "text"],
                        ),
                        256,
                    ),
                ),
                ("expect", expect()),
            ],
            &["id", "item", "source", "position", "notes", "expect"],
        ),
        operation(
            "selectReadingCheckpoint",
            "Select retained reading without activating browser presence",
            vec![("item", id()), ("checkpoint", id()), ("expect", expect())],
            &["item", "checkpoint", "expect"],
        ),
    ]
}
pub(super) fn queries() -> Vec<Spec> {
    type QueryDefinition<'a> = (&'a str, &'a [&'a str], Vec<(&'a str, Value)>);
    let definitions: &[QueryDefinition<'_>] = &[
        ("items", &[], vec![("query", view_query())]),
        (
            "item",
            &["id"],
            vec![("id", id()), ("includeDeleted", boolean())],
        ),
        ("readingCounts", &[], vec![("query", view_query())]),
        (
            "sources",
            &["item", "kind"],
            vec![
                ("item", id()),
                ("kind", en(&["versions", "images"])),
                ("source", id()),
            ],
        ),
        ("position", &["item"], vec![("item", id())]),
        ("getPosition", &["item"], vec![("item", id())]),
        (
            "annotations",
            &[],
            vec![
                ("item", id()),
                ("tag", text(120)),
                ("includeDeleted", boolean()),
            ],
        ),
        (
            "annotation",
            &["thread"],
            vec![("thread", id()), ("revision", id())],
        ),
        ("annotationHistory", &["thread"], vec![("thread", id())]),
        (
            "feeds",
            &[],
            vec![("followed", boolean()), ("folder", array(text(120), 16))],
        ),
        ("feedEntries", &["feed"], vec![("feed", id())]),
        ("savedViews", &[], vec![("includeDeleted", boolean())]),
        ("savedView", &["id"], vec![("id", id())]),
        ("reviewQueue", &[], vec![]),
        ("reviewHistory", &[], vec![("thread", id())]),
        ("answers", &[], vec![("hidden", boolean()), ("item", id())]),
        ("answer", &["id"], vec![("id", id())]),
        (
            "connections",
            &[],
            vec![("item", id()), ("includeRetracted", boolean())],
        ),
        ("subscriptions", &[], vec![("publication", id())]),
        (
            "conflicts",
            &["object"],
            vec![("object", id()), ("component", text(120))],
        ),
        ("invalid", &[], vec![]),
        ("read", &[], vec![]),
    ];
    definitions
        .iter()
        .map(|(name, required, fields)| {
            let mut fields = fields.clone();
            fields.extend([
                ("cursor", json!({"type":"string"})),
                ("limit", json!({"type":"integer","minimum":1,"maximum":100})),
                ("offset", integer(9007199254740991)),
            ]);
            let mut s = operation(
                name,
                "Read a bounded saved-reading projection; cursors bind the admitted prefix",
                fields,
                required,
            );
            if let Some(schema) = s.input_schema.as_object_mut() {
                schema.remove("x-colophon-saved-command");
            }
            s.input_schema["additionalProperties"] = json!(false);
            s
        })
        .collect()
}

pub(super) fn image_asset() -> Value {
    let candidate = schema(
        &[
            ("id", id()),
            ("itemID", id()),
            ("source", id()),
            ("index", integer(127)),
            ("baseURL", url()),
            ("sourceURL", url()),
            ("alt", text(4000)),
            ("afterPassageID", id()),
        ],
        &["id", "itemID", "source", "index", "sourceURL", "alt"],
    );
    schema(
        &[
            ("candidate", candidate),
            ("blob", blob(8_000_000)),
            (
                "mime",
                en(&["image/jpeg", "image/png", "image/gif", "image/webp"]),
            ),
            ("width", integer(10000)),
            ("height", integer(10000)),
            ("observedURLs", array(url(), 6)),
            ("capturedAt", instant()),
        ],
        &[
            "candidate",
            "blob",
            "mime",
            "width",
            "height",
            "observedURLs",
            "capturedAt",
        ],
    )
}
fn image_coverage() -> Value {
    schema(
        &[(
            "results",
            array(
                schema(
                    &[
                        ("candidate", id()),
                        ("outcome", en(&["retained", "failed", "skipped"])),
                        ("reason", text(4096)),
                    ],
                    &["candidate", "outcome"],
                ),
                128,
            ),
        )],
        &["results"],
    )
}
fn metadata_value() -> Value {
    let provenance = schema(
        &[
            ("version", json!({"const":1})),
            ("documentID", id()),
            (
                "sourceRecordDigest",
                json!({"type":"string","format":"sha256"}),
            ),
            ("rawExport", blob(128_000_000)),
            ("sourceSavedAt", instant()),
            ("importedAt", instant()),
        ],
        &[
            "version",
            "documentID",
            "sourceRecordDigest",
            "rawExport",
            "importedAt",
        ],
    );
    let values = schema(
        &[
            ("title", text(16384)),
            ("author", text(1024)),
            ("summary", text(262144)),
            ("sourceName", text(1024)),
            ("category", text(1024)),
            ("sourceLocation", text(8192)),
            ("url", url()),
            ("firstOpened", instant()),
            ("lastOpened", instant()),
            ("published", instant()),
            ("tags", array(text(120), 100)),
            (
                "suppliedFraction",
                json!({"type":"number","minimum":0,"maximum":1}),
            ),
        ],
        &["title", "author", "summary", "sourceName", "tags"],
    );
    json!({"oneOf":[schema(&[("version",json!({"const":1})),("provenance",provenance),("values",values)], &["version","provenance","values"]),schema(&[("version",json!({"const":1})),("format",json!({"const":"readwiseCSV"})),("workKey",text(64)),("sourceRecordDigest",text(64)),("title",text(16384)),("author",text(1024)),("amazonBookID",text(1024)),("rawExport",blob(128_000_000)),("importedAt",instant())], &["version","format","workKey","sourceRecordDigest","title","author","rawExport","importedAt"])]})
}
