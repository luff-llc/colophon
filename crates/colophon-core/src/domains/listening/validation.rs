use super::{specs, text};
use crate::{
    model::time_key,
    records::{canonical, digest},
};
use serde_json::{json, Value};
use std::collections::BTreeSet;

pub(super) fn valid(schema: &Value, value: &Value) -> bool {
    if let Some(options) = schema["anyOf"].as_array() {
        return options.iter().any(|s| valid(s, value));
    }
    let type_ok = match schema["type"].as_str() {
        Some("null") => value.is_null(),
        Some("object") => value.is_object(),
        Some("array") => value.is_array(),
        Some("string") => value.is_string(),
        Some("boolean") => value.is_boolean(),
        Some("number") => value.as_f64().is_some_and(f64::is_finite),
        Some("integer") => value.as_u64().is_some_and(|n| n <= 9_007_199_254_740_991),
        _ => true,
    };
    if !type_ok {
        return false;
    }
    if schema
        .get("not")
        .is_some_and(|forbidden| valid(forbidden, value))
    {
        return false;
    }
    if let Some(options) = schema["enum"].as_array() {
        if !options.contains(value) {
            return false;
        }
    }
    if let Some(s) = value.as_str() {
        if schema["minLength"]
            .as_u64()
            .is_some_and(|n| s.len() < n as usize)
            || schema["maxLength"]
                .as_u64()
                .is_some_and(|n| s.len() > n as usize)
        {
            return false;
        }
        if !match schema["format"].as_str() {
            Some("colophon-id") => {
                !s.trim().is_empty() && s.len() <= 1024 && !s.chars().any(char::is_control)
            }
            Some("sha256") => {
                s.len() == 64
                    && s.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            }
            Some("date-time") => time_key(s).is_ok(),
            Some("http-url") => http_url(s),
            _ => true,
        } {
            return false;
        }
    }
    if let Some(n) = value.as_f64() {
        if schema["minimum"].as_f64().is_some_and(|min| n < min)
            || schema["maximum"].as_f64().is_some_and(|max| n > max)
            || schema["exclusiveMinimum"]
                .as_f64()
                .is_some_and(|min| n <= min)
        {
            return false;
        }
    }
    if let Some(a) = value.as_array() {
        if schema["minItems"]
            .as_u64()
            .is_some_and(|n| a.len() < n as usize)
            || schema["maxItems"]
                .as_u64()
                .is_some_and(|n| a.len() > n as usize)
        {
            return false;
        }
        if let Some(items) = schema.get("items") {
            if !a.iter().all(|v| valid(items, v)) {
                return false;
            }
        }
    }
    if let Some(o) = value.as_object() {
        if schema["required"].as_array().is_some_and(|keys| {
            keys.iter()
                .any(|k| !o.contains_key(k.as_str().unwrap_or("")))
        }) {
            return false;
        }
        if let Some(props) = schema["properties"].as_object() {
            for (k, v) in o {
                match props.get(k) {
                    Some(s) if !valid(s, v) => return false,
                    None if schema["additionalProperties"] == false => return false,
                    _ => {}
                }
            }
        }
    }
    true
}
fn http_url(s: &str) -> bool {
    let Some((scheme, rest)) = s.split_once("://") else {
        return false;
    };
    if !["http", "https"]
        .iter()
        .any(|v| scheme.eq_ignore_ascii_case(v))
        || s.chars().any(|c| {
            c.is_whitespace()
                || c.is_control()
                || ['\\', '<', '>', '"', '`', '{', '}', '|', '^'].contains(&c)
        })
    {
        return false;
    }
    let bytes = s.as_bytes();
    if bytes.iter().enumerate().any(|(i, b)| {
        *b == b'%'
            && (i + 2 >= bytes.len()
                || !bytes[i + 1].is_ascii_hexdigit()
                || !bytes[i + 2].is_ascii_hexdigit())
    }) {
        return false;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') || authority.contains('%') {
        return false;
    }
    if let Some(ip) = authority.strip_prefix('[') {
        let Some((ip, suffix)) = ip.split_once(']') else {
            return false;
        };
        return ip.parse::<std::net::Ipv6Addr>().is_ok()
            && (suffix.is_empty()
                || suffix
                    .strip_prefix(':')
                    .is_some_and(|port| port.parse::<u16>().is_ok()));
    }
    let host = if let Some((host, port)) = authority.rsplit_once(':') {
        if port.parse::<u16>().is_err() {
            return false;
        }
        host
    } else {
        authority
    };
    !host.is_empty()
        && host.trim_end_matches('.').split('.').all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_alphanumeric() || c == '-')
        })
}
pub(super) fn unique(values: &Value) -> bool {
    values.as_array().is_some_and(|a| {
        a.iter()
            .map(Value::to_string)
            .collect::<BTreeSet<_>>()
            .len()
            == a.len()
    })
}
pub(super) fn preference_key(change: &Value) -> String {
    format!(
        "{}:{}:{}",
        text(change, "scope"),
        text(change, "target"),
        text(change, "field")
    )
}
pub(super) fn preference(change: &Value) -> bool {
    let scope = text(change, "scope");
    let field = text(change, "field");
    let value = &change["value"];
    if scope == "global" && change.get("target").is_some()
        || scope != "global" && change.get("target").is_none()
    {
        return false;
    }
    let playback = [
        "speed",
        "backward",
        "forward",
        "shortenSilence",
        "levelSpeech",
        "monoAudio",
        "skipSponsors",
        "skipDetectedSponsors",
        "skipAdChapters",
    ];
    let listening = [
        "doublePress",
        "triplePress",
        "carUsesChapters",
        "sentenceRewind",
        "smartResume",
        "markButton",
    ];
    if !(playback.contains(&field) || scope == "global" && listening.contains(&field)) {
        return false;
    }
    if value.is_null() {
        return scope != "global";
    }
    match field {
        "speed" => value.as_f64().is_some_and(|n| {
            [
                0.75, 0.8, 0.85, 0.9, 0.95, 1.0, 1.05, 1.1, 1.15, 1.2, 1.25, 1.3, 1.35, 1.4, 1.45,
                1.5, 1.6, 1.7, 1.75, 1.8, 1.9, 2.0, 2.1, 2.2, 2.3, 2.4, 2.5, 2.75, 3.0,
            ]
            .contains(&n)
        }),
        "backward" | "forward" => value
            .as_f64()
            .is_some_and(|n| [5.0, 10.0, 15.0, 30.0, 45.0, 60.0].contains(&n)),
        "doublePress" => {
            ["skipForward", "nextChapter", "mark"].contains(&value.as_str().unwrap_or(""))
        }
        "triplePress" => ["skipBack", "sentence", "undoSkipOrSentence", "comment"]
            .contains(&value.as_str().unwrap_or("")),
        _ => value.is_boolean(),
    }
}
fn anchor_valid(a: &Value) -> bool {
    let count = text(a, "quote").encode_utf16().count();
    count > 0
        && count <= 8000
        && a["lengthUTF16"].as_u64() == Some(count as u64)
        && a["startUTF16"]
            .as_u64()
            .and_then(|n| n.checked_add(count as u64))
            .is_some_and(|n| n <= 9_007_199_254_740_991)
}
fn claims_valid(claims: &Value) -> bool {
    let Some(a) = claims.as_array() else {
        return false;
    };
    let mut units = 0;
    let mut count = 0;
    for claim in a {
        units += text(claim, "text").encode_utf16().count();
        let Some(citations) = claim["citations"].as_array() else {
            return false;
        };
        if citations.is_empty() || !citations.iter().all(anchor_valid) {
            return false;
        }
        count += citations.len();
    }
    units <= 40000 && count <= 200
}
// Playback reports dominate long histories. This typed equivalent of the position schema
// avoids repeatedly interpreting its JSON constraints. Unknown fields still reach the shared
// size, anchor, claims and question checks below and remain preserved by normalization.
fn position_shape(p: &Value) -> bool {
    let id = |v: &Value| {
        v.as_str().is_some_and(|s| {
            !s.trim().is_empty() && s.len() <= 1024 && !s.chars().any(char::is_control)
        })
    };
    p.is_object()
        && id(&p["id"])
        && p["seconds"]
            .as_f64()
            .is_some_and(|n| n.is_finite() && n >= 0.0)
        && p.get("show").is_none_or(id)
        && p.get("duration")
            .is_none_or(|v| v.as_f64().is_some_and(|n| n.is_finite() && n > 0.0))
        && p.get("seek").is_none_or(Value::is_boolean)
        && p.get("expect").is_none_or(|v| v.is_null() || id(v))
}

pub(super) fn payload(kind: &str, p: &Value) -> bool {
    let Some(spec) = super::operation_specs().iter().find(|s| s.name == kind) else {
        return false;
    };
    let shape = if kind == "position" {
        position_shape(p)
    } else {
        valid(&spec.input_schema, p)
    };
    if !shape || !serde_json::to_vec(p).is_ok_and(|b| b.len() <= 1_048_576) {
        return false;
    }
    if p.get("anchor").is_some_and(|a| !anchor_valid(a)) {
        return false;
    }
    if p.get("claims").is_some_and(|a| !claims_valid(a)) {
        return false;
    }
    if p.get("question")
        .is_some_and(|q| q.as_str().unwrap_or("").encode_utf16().count() > 4000)
    {
        return false;
    }
    match kind {
        "setPreferences" => {
            let changes = p["changes"].as_array().map(Vec::as_slice).unwrap_or(&[]);
            changes.iter().all(preference)
                && changes
                    .iter()
                    .map(preference_key)
                    .collect::<BTreeSet<_>>()
                    .len()
                    == changes.len()
        }
        "queue" => {
            unique(&p["episodes"])
                && p["metadata"].as_array().is_none_or(|a| {
                    a.iter()
                        .map(|v| text(v, "id"))
                        .collect::<BTreeSet<_>>()
                        .len()
                        == a.len()
                        && a.iter().all(descriptor_valid)
                })
        }
        "completePlayback" => {
            let a = p["events"].as_array().map(Vec::as_slice).unwrap_or(&[]);
            !a.is_empty()
                && unique(&p["baseQueue"])
                && a.iter().all(|e| {
                    !text(e, "eventID").is_empty()
                        && !text(e, "audio").is_empty()
                        && e["endSeconds"].as_f64() == e["actualDuration"].as_f64()
                })
                && ["eventID", "episode"]
                    .iter()
                    .all(|k| a.iter().map(|e| text(e, k)).collect::<BTreeSet<_>>().len() == a.len())
        }
        "setSegments" => p["segments"]
            .as_array()
            .is_some_and(|a| a.iter().all(|e| e["end"].as_f64() > e["start"].as_f64())),
        "setChapters" => p["entries"].as_array().is_some_and(|a| {
            !a.is_empty()
                && a.iter().all(|e| {
                    !text(e, "title").trim().is_empty() && text(e, "title").chars().count() <= 160
                })
        }),
        "savePlaylist" => {
            !text(p, "name").trim().is_empty()
                && text(p, "name").chars().count() <= 120
                && text(p, "titleContains").chars().count() <= 80
                && ["shows", "episodes", "excluded", "pinned", "included"]
                    .iter()
                    .all(|k| p.get(k).is_none_or(unique))
        }
        "resolveNote" => {
            unique(&p["resolves"])
                && p["resolves"]
                    .as_array()
                    .is_some_and(|a| a.windows(2).all(|w| w[0].as_str() < w[1].as_str()))
        }
        "askQuestion" => p["scope"].as_array().is_some_and(|a| {
            !a.is_empty()
                && unique(&p["scope"])
                && a.iter().all(anchor_valid)
                && a.iter()
                    .map(|v| text(v, "quote").encode_utf16().count())
                    .sum::<usize>()
                    <= 20000
        }),
        "addNote" => p.get("capture").is_none_or(|c| {
            text(c, "surroundingText").encode_utf16().count() <= 2000
                && text(c, "originalText").encode_utf16().count() <= 10000
                && c["voice"]["size"]
                    .as_u64()
                    .is_none_or(|s| s <= 6 * 1024 * 1024)
        }),
        "respondCapture" => text(p, "text").encode_utf16().count() <= 10000,
        "requestTranscript" => {
            !text(p, "language").trim().is_empty()
                && p["audio"]["size"]
                    .as_u64()
                    .is_some_and(|s| s > 0 && s <= 2_000_000_000)
                && p["audio"]["digest"] == p["recording"]
        }
        _ => true,
    }
}
pub(super) fn descriptor_valid(p: &Value) -> bool {
    if !valid(&specs::descriptor(), p) {
        return false;
    }
    let show = digest(text(p, "feed").as_bytes());
    let episode = digest(format!("{}\n{}", text(p, "feed"), text(p, "guid")).as_bytes());
    text(p, "show") == &show[..32]
        && text(p, "id") == &episode[..32]
        && canonical(p).is_ok_and(|b| b.len() <= 16384)
}
/// Move unknown nested model properties into their own extension bags.
pub(super) fn normalize(schema: &Value, value: &Value) -> Value {
    if let Some(choices) = schema["anyOf"].as_array() {
        if let Some(choice) = choices.iter().find(|s| valid(s, value)) {
            return normalize(choice, value);
        }
    }
    if let (Some(props), Some(obj)) = (schema["properties"].as_object(), value.as_object()) {
        let mut result = json!({});
        let mut extensions = json!({});
        for (k, v) in obj {
            if let Some(s) = props.get(k) {
                result[k] = normalize(s, v);
            } else {
                extensions[k] = v.clone();
            }
        }
        if extensions.as_object().is_some_and(|m| !m.is_empty()) {
            result["extensions"] = extensions;
        }
        result
    } else if let (Some(items), Some(values)) = (schema.get("items"), value.as_array()) {
        Value::Array(values.iter().map(|v| normalize(items, v)).collect())
    } else {
        value.clone()
    }
}
/// Validate a plaintext blob descriptor without claiming byte availability.
pub(super) fn valid_blob(value: &Value) -> bool {
    valid(&specs::blob(), value)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn typed_playback_validation_matches_the_published_schema() {
        let specs = specs::operations();
        let schema = &specs
            .iter()
            .find(|spec| spec.name == "position")
            .expect("position spec")
            .input_schema;
        let values = [
            Value::Null,
            json!(false),
            json!(true),
            json!(0),
            json!(-1),
            json!(0.5),
            json!(u64::MAX),
            json!(f64::MAX),
            json!(""),
            json!(" "),
            json!("id"),
            json!("Ω"),
            json!("line\nbreak"),
            json!("x".repeat(1024)),
            json!("x".repeat(1025)),
            json!([]),
            json!({}),
        ];
        for field in [
            "id", "seconds", "show", "duration", "seek", "expect", "future",
        ] {
            let mut missing = json!({"id":"episode","seconds":1.5});
            missing.as_object_mut().expect("object").remove(field);
            assert_eq!(position_shape(&missing), valid(schema, &missing));
            for value in &values {
                let mut p = json!({"id":"episode","seconds":1.5});
                p[field] = value.clone();
                assert_eq!(position_shape(&p), valid(schema, &p), "{p}");
            }
        }
        for p in values {
            assert_eq!(position_shape(&p), valid(schema, &p));
        }
    }
}
