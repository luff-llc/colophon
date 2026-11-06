use super::*;

pub(super) const SOURCE_LIMIT: usize = 256 * 1024;
pub(super) const DETAIL_LIMIT: usize = 1024 * 1024;
pub(super) fn id(v: &Value) -> bool {
    v.as_str()
        .is_some_and(|s| !s.is_empty() && s.len() <= 512 && !s.chars().any(char::is_control))
}
fn text(v: &Value, max: usize) -> bool {
    v.as_str().is_some_and(|s| s.len() <= max)
}
pub(super) fn digest(v: &Value) -> bool {
    v.as_str().is_some_and(|s| {
        s.len() == 64
            && s.bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    })
}
fn day(v: &Value) -> bool {
    let Some(s) = v.as_str() else { return false };
    if s.len() != 10 || !s.is_ascii() || &s[4..5] != "-" || &s[7..8] != "-" {
        return false;
    }
    let (Ok(y), Ok(m), Ok(d)) = (
        s[..4].parse::<u32>(),
        s[5..7].parse::<u32>(),
        s[8..].parse::<u32>(),
    ) else {
        return false;
    };
    let days = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) => 29,
        2 => 28,
        _ => 0,
    };
    y > 0 && d > 0 && d <= days
}
fn tags(v: &Value) -> bool {
    v.as_array().is_some_and(|a| {
        a.len() <= 64
            && a.iter().all(|v| text(v, 128) && v != "")
            && a.iter()
                .filter_map(Value::as_str)
                .collect::<BTreeSet<_>>()
                .len()
                == a.len()
    })
}
fn optional(p: &Value, key: &str, check: impl Fn(&Value) -> bool) -> bool {
    p.get(key).is_none_or(|v| v.is_null() || check(v))
}
pub(super) fn blob(v: &Value) -> bool {
    v.is_object()
        && digest(&v["digest"])
        && v["size"].as_u64().is_some_and(|n| n <= 512 * 1024 * 1024)
        && text(&v["mediaType"], 256)
}
fn web_url(v: &Value) -> bool {
    let Some(s) = v.as_str() else { return false };
    let Some((scheme, rest)) = s.split_once("://") else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return false;
    }
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    s.len() <= 4096
        && !host.is_empty()
        && !host.contains('@')
        && !host.starts_with(':')
        && !s
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == '\\')
}
fn source(v: &Value) -> bool {
    if !v.is_object() {
        return false;
    }
    match v["kind"].as_str() {
        Some("web") => {
            web_url(&v["url"])
                && [
                    "library",
                    "namespace",
                    "artifact",
                    "revision",
                    "quote",
                    "page",
                    "seconds",
                    "recording",
                ]
                .iter()
                .all(|k| v.get(k).is_none_or(Value::is_null))
        }
        Some("library") => {
            ["library", "namespace", "artifact", "revision"]
                .iter()
                .all(|k| id(&v[k]))
                && optional(v, "quote", |v| text(v, 16 * 1024))
                && optional(v, "page", |v| {
                    v.as_u64().is_some_and(|n| n <= 9_007_199_254_740_991)
                })
                && optional(v, "recording", digest)
                && optional(v, "seconds", |s| {
                    s.as_f64().is_some_and(|n| n.is_finite() && n >= 0.0) && digest(&v["recording"])
                })
                && v.get("url").is_none_or(Value::is_null)
        }
        _ => false,
    }
}
fn enum_value(v: &Value, choices: &[&str]) -> bool {
    v.as_str().is_some_and(|s| choices.contains(&s))
}

/// Validate a known notes payload, including byte bounds and nested descriptors.
/// Unknown kinds return false; the reducer skips them before validation.
pub fn validate_payload(kind: &str, p: &Value) -> bool {
    let Some(spec) = specs().iter().find(|s| s.name == kind) else {
        return false;
    };
    if !crate::domain::validate_input(&spec.input_schema, p) || !p.is_object() || !id(&p["id"]) {
        return false;
    }
    if spec.input_schema["required"]
        .as_array()
        .is_some_and(|a| a.iter().any(|v| v == "notebook"))
        && !id(&p["notebook"])
    {
        return false;
    }
    if !optional(p, "expect", id) {
        return false;
    }
    match kind {
        "createNotebook" => {
            text(&p["title"], 512)
                && p.get("kind")
                    .is_none_or(|v| enum_value(v, &["notebook", "lecture", "seminar", "document"]))
                && optional(p, "topic", Value::is_string)
        }
        "renameNotebook" => text(&p["title"], 512),
        "archiveNotebook" => p["archived"].is_boolean(),
        "addNote" | "editNote" => text(&p["text"], SOURCE_LIMIT),
        "putCell" => {
            enum_value(&p["kind"], &["markdown", "latex", "code", "raw"])
                && text(&p["source"], SOURCE_LIMIT)
                && optional(p, "language", Value::is_string)
                && optional(p, "entry", id)
                && optional(p, "after", id)
        }
        "resolveCell" => text(&p["source"], SOURCE_LIMIT) && resolution(p),
        "moveCell" => optional(p, "after", id) && p["after"] != p["id"],
        "deleteCell" => true,
        "recordOutput" => {
            id(&p["cell"])
                && digest(&p["sourceDigest"])
                && p["runtime"].is_string()
                && optional(p, "error", |v| text(v, SOURCE_LIMIT))
                && p["outputs"].as_array().is_some_and(|a| {
                    a.len() <= 100
                        && a.iter().all(|o| {
                            o.is_object()
                                && text(&o["mime"], 256)
                                && (o.get("text").is_some_and(|v| text(v, SOURCE_LIMIT))
                                    ^ o.get("blob").is_some_and(blob))
                                && optional(o, "text", |v| text(v, SOURCE_LIMIT))
                                && optional(o, "blob", blob)
                        })
                })
                && serde_json::to_vec(p).is_ok_and(|b| b.len() <= SOURCE_LIMIT)
        }
        "putEntry" | "resolveEntry" => {
            optional(p, "title", |v| text(v, 512))
                && optional(p, "date", day)
                && p.get("tags").is_none_or(tags)
                && (kind != "resolveEntry" || resolution(p))
        }
        "addAttachment" => {
            enum_value(
                &p["role"],
                &[
                    "reading", "slides", "handout", "image", "audio", "file", "link",
                ],
            ) && id(&p["name"])
                && optional(p, "entry", id)
                && optional(p, "mime", |v| text(v, 256))
                && (p.get("blob").is_some_and(blob) ^ p.get("source").is_some_and(source))
                && optional(p, "blob", blob)
                && optional(p, "source", source)
        }
        "proposeEntry" => {
            id(&p["entry"])
                && text(&p["markdown"], 16 * 1024)
                && optional(p, "title", |v| text(v, 512))
                && p.get("tags").is_none_or(tags)
                && p["inputs"].as_object().is_some_and(|o| {
                    o.len() <= 2048 && o.iter().all(|(k, v)| id(&json!(k)) && id(v))
                })
        }
        "reviewProposal" => {
            p["keep"].is_boolean() && optional(p, "markdown", |v| text(v, 16 * 1024))
        }
        _ => false,
    }
}
fn resolution(p: &Value) -> bool {
    id(&p["expect"])
        && p["resolves"].as_array().is_some_and(|a| {
            a.iter().all(id)
                && a.iter()
                    .filter_map(Value::as_str)
                    .collect::<BTreeSet<_>>()
                    .len()
                    == a.len()
        })
}
fn str_schema(max: usize) -> Value {
    json!({"type":"string","maxLength":max,"x-maxUtf8Bytes":max})
}
fn nullable(mut v: Value) -> Value {
    let t = v["type"].clone();
    v["type"] = json!([t, "null"]);
    v
}
fn id_schema() -> Value {
    json!({"type":"string","minLength":1,"maxLength":512,"pattern":"^[^\\u0000-\\u001f\\u007f-\\u009f]+$"})
}
fn enum_schema(values: &[&str]) -> Value {
    json!({"type":"string","enum":values})
}
fn blob_schema() -> Value {
    json!({"type":"object","required":["digest","size","mediaType"],"properties":{"digest":{"type":"string","pattern":"^[0-9a-f]{64}$"},"size":{"type":"integer","minimum":0,"maximum":536870912},"mediaType":str_schema(256)},"additionalProperties":true})
}
fn source_schema() -> Value {
    json!({"type":"object","required":["kind"],"oneOf":[{"required":["kind","url"],"properties":{"kind":{"const":"web"},"url":{"type":"string","format":"uri","maxLength":4096}}},{"required":["kind","library","namespace","artifact","revision"],"properties":{"kind":{"const":"library"},"library":id_schema(),"namespace":id_schema(),"artifact":id_schema(),"revision":id_schema(),"quote":nullable(str_schema(16384)),"page":{"type":["integer","null"],"minimum":0},"seconds":{"type":["number","null"],"minimum":0},"recording":{"type":["string","null"],"pattern":"^[0-9a-f]{64}$"}}}],"additionalProperties":true})
}
pub(super) fn specs() -> &'static [Spec] {
    static SPECS: OnceLock<Vec<Spec>> = OnceLock::new();
    SPECS.get_or_init(|| {
        let definitions = [
            ("createNotebook","Create an active notebook","id title","kind topic"),
            ("renameNotebook","Replace notebook title with optional metadata CAS","id title","expect"),
            ("archiveNotebook","Reversibly archive a notebook with optional metadata CAS","id archived","expect"),
            ("putCell","Create or edit a cell; retain full stale candidates","id notebook kind source","language entry after expect"),
            ("resolveCell","Resolve exactly the observed cell alternatives","id notebook source expect resolves",""),
            ("moveCell","Move a cell using the notebook order head","id notebook","after expect"),
            ("deleteCell","Permanently tombstone a cell; retain late edits","id notebook","expect"),
            ("recordOutput","Retain an immutable asserted run without executing code","id cell notebook sourceDigest runtime outputs","error"),
            ("putEntry","Replace complete entry metadata; edits require current revision","id notebook","title date tags expect"),
            ("resolveEntry","Resolve exactly the observed entry alternatives","id notebook tags expect resolves","title date"),
            ("addAttachment","Add an immutable blob descriptor or descriptive source pointer","id notebook role name","entry mime blob source"),
            ("proposeEntry","Propose organization against the exact conflict-free entry cells","id notebook entry markdown inputs","title tags"),
            ("reviewProposal","App/device review; engine must supply authenticated member kind","id notebook keep","markdown expect"),
            ("addNote","Compatibility alias: create one markdown cell in an explicit notebook","id notebook text",""),
            ("editNote","Compatibility alias: edit a markdown cell in an explicit notebook","id notebook text","expect"),
        ];
        definitions.into_iter().map(|(name,description,required,optional)| {
            let mut properties=Map::new();
            for key in required.split_whitespace().chain(optional.split_whitespace()) {
                let schema=match key {
                    "id"|"notebook"|"cell"|"name" => id_schema(),
                    "expect" if matches!(name,"resolveCell"|"resolveEntry") => id_schema(),
                    "entry" if name=="proposeEntry" => id_schema(),
                    "entry"|"after"|"expect" => nullable(id_schema()),
                    "topic"|"language" => json!({"type":["string","null"]}),
                    "title" => if key=="title" && matches!(name,"createNotebook"|"renameNotebook") {str_schema(512)}else{nullable(str_schema(512))},
                    "kind" => if name=="createNotebook" {enum_schema(&["notebook","lecture","seminar","document"])}else{enum_schema(&["markdown","latex","code","raw"])},
                    "source" if name=="addAttachment" => nullable(source_schema()),
                    "source"|"text" => str_schema(SOURCE_LIMIT),
                    "markdown" => if name=="reviewProposal"{nullable(str_schema(16384))}else{str_schema(16384)},
                    "tags"=>json!({"type":"array","maxItems":64,"uniqueItems":true,"items":{"type":"string","minLength":1,"maxLength":128}}),
                    "resolves"=>json!({"type":"array","uniqueItems":true,"items":id_schema()}),
                    "date"=>json!({"type":["string","null"],"format":"date"}),
                    "archived"|"keep"=>json!({"type":"boolean"}),
                    "sourceDigest"=>json!({"type":"string","pattern":"^[0-9a-f]{64}$"}),
                    "runtime"=>json!({"type":"string"}),
                    "error"=>nullable(str_schema(SOURCE_LIMIT)),
                    "role"=>enum_schema(&["reading","slides","handout","image","audio","file","link"]),
                    "mime"=>nullable(str_schema(256)),
                    "blob"=>nullable(blob_schema()),
                    "inputs"=>json!({"type":"object","maxProperties":2048,"additionalProperties":id_schema()}),
                    "outputs"=>json!({"type":"array","maxItems":100,"items":{"type":"object","required":["mime"],"properties":{"mime":str_schema(256),"text":nullable(str_schema(SOURCE_LIMIT)),"blob":nullable(blob_schema())},"oneOf":[{"required":["text"],"properties":{"text":str_schema(SOURCE_LIMIT),"blob":{"type":"null"}}},{"required":["blob"],"properties":{"blob":blob_schema(),"text":{"type":"null"}}}],"additionalProperties":true}}),
                    _=>json!({}),
                };
                properties.insert(key.into(),schema);
            }
            let mut schema=json!({"type":"object","required":required.split_whitespace().collect::<Vec<_>>(),"properties":properties,"additionalProperties":true});
            if name=="addAttachment" {schema["oneOf"]=json!([{"required":["blob"],"properties":{"blob":blob_schema(),"source":{"type":"null"}}},{"required":["source"],"properties":{"source":source_schema(),"blob":{"type":"null"}}}]);}
            Spec{name:name.into(),description:description.into(),input_schema:schema}
        }).collect()
    })
}

pub(super) fn normalize_nested(v: &mut Value, fields: &[&str]) {
    let Some(object) = v.as_object_mut() else {
        return;
    };
    let mut extras = Map::new();
    let keys: Vec<_> = object
        .keys()
        .filter(|k| !fields.contains(&k.as_str()))
        .cloned()
        .collect();
    for key in keys {
        if let Some(value) = object.remove(&key) {
            extras.insert(key, value);
        }
    }
    object.insert("extensions".into(), Value::Object(extras));
}
