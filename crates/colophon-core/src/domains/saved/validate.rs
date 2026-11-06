use super::*;
use crate::model::time_key;

pub(super) fn id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 1024 && !s.chars().any(char::is_control)
}
pub(super) fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn url(s: &str) -> bool {
    let rest = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"));
    rest.is_some_and(|r| {
        !r.is_empty() && !r.starts_with('/') && !r.split('/').next().unwrap_or("").contains('@')
    }) && !s.chars().any(|c| c.is_control() || c.is_whitespace())
}
pub(super) fn matches(s: &Value, v: &Value) -> bool {
    if let Some(a) = s["anyOf"].as_array() {
        return a.iter().any(|s| matches(s, v));
    }
    if let Some(a) = s["oneOf"].as_array() {
        return a.iter().filter(|s| matches(s, v)).count() == 1;
    }
    if let Some(c) = s.get("const") {
        if c != v {
            return false;
        }
    }
    if let Some(e) = s["enum"].as_array() {
        if !e.contains(v) {
            return false;
        }
    }
    let ty = match s["type"].as_str() {
        Some("null") => v.is_null(),
        Some("object") => v.is_object(),
        Some("array") => v.is_array(),
        Some("string") => v.is_string(),
        Some("boolean") => v.is_boolean(),
        Some("integer") => v.as_u64().is_some(),
        Some("number") => v.is_number(),
        _ => true,
    };
    if !ty {
        return false;
    }
    if let Some(t) = v.as_str() {
        if s["maxLength"]
            .as_u64()
            .is_some_and(|max| t.len() as u64 > max)
            || s["minLength"]
                .as_u64()
                .is_some_and(|min| (t.len() as u64) < min)
        {
            return false;
        }
        if !match s["format"].as_str() {
            Some("saved-id") => id(t),
            Some("sha256") => digest(t),
            Some("saved-url") => url(t),
            Some("date-time") => time_key(t).is_ok(),
            _ => true,
        } {
            return false;
        }
    }
    if let Some(n) = v.as_f64() {
        if s["minimum"].as_f64().is_some_and(|m| n < m)
            || s["maximum"].as_f64().is_some_and(|m| n > m)
        {
            return false;
        }
    }
    if let Some(a) = v.as_array() {
        if s["maxItems"].as_u64().is_some_and(|m| a.len() as u64 > m)
            || s.get("items")
                .is_some_and(|s| a.iter().any(|v| !matches(s, v)))
        {
            return false;
        }
    }
    if let Some(o) = v.as_object() {
        if s["required"]
            .as_array()
            .is_some_and(|a| a.iter().any(|k| !o.contains_key(k.as_str().unwrap_or(""))))
        {
            return false;
        }
        if let Some(p) = s["properties"].as_object() {
            for (k, v) in o {
                match p.get(k) {
                    Some(s) if !matches(s, v) => return false,
                    None if s["additionalProperties"] == false => return false,
                    _ => {}
                }
            }
        }
    }
    true
}
pub(super) fn payload(op: &AdmittedOperation) -> Result<()> {
    let spec = operation_spec(&op.kind).ok_or_else(|| Error("unsupported".into()))?;
    ensure(matches(&spec.input_schema, &op.payload), "invalidPayload")?;
    ensure(
        serde_json::to_vec(&op.payload)?.len() <= 1024 * 1024,
        "commandTooLarge",
    )?;
    let p = &op.payload;
    if protected_kind(&op.kind) {
        ensure(op.origin != "ai", "roleRequired")?;
    }
    match op.kind.as_str() {
        "capture" => ensure(
            p.get("title").is_some() || p.get("url").is_some(),
            "titleRequired",
        )?,
        "setState" => ensure(
            ["consumption", "retention", "state"]
                .iter()
                .any(|k| p.get(k).is_some()),
            "emptyState",
        )?,
        "retainSource" => {
            ensure(
                p["select"] != true || p.get("expect").is_some(),
                "selectionRequiresHead",
            )?;
            manifest(&p["manifest"])?;
            ensure(p["id"] == p["manifest"]["id"], "sourceIdentity")?;
        }
        "attachOriginal" => manifest(&p["manifest"])?,
        "captureReading" => {
            manifest(&p["source"])?;
            ensure(
                p["source"]["origin"]["kind"] == "browserExtraction",
                "browserSourceRequired",
            )?;
            unique(&p["notes"], "id")?;
            ensure(
                p.get("active").is_none() && p.get("presence").is_none(),
                "presenceIsLocal",
            )?;
        }
        "tagAnnotations" => {
            unique(&p["threads"], "")?;
            ensure(
                !arr(&p["threads"]).is_empty() && !strv(p, "tag").trim().is_empty(),
                "emptyTagTargets",
            )?;
        }
        "followFeed" | "organizeFeed" => {
            for path in arr(&p["folders"]) {
                ensure(
                    !arr(path).is_empty()
                        && arr(path)
                            .iter()
                            .all(|v| !v.as_str().unwrap_or("").trim().is_empty()),
                    "invalidFolder",
                )?;
            }
        }
        "refreshFeed" => {
            unique(&p["entries"], "id")?;
            for e in arr(&p["entries"]) {
                ensure(id(strv(e, "id")), "entryIdentity")?;
            }
        }
        "reviseView" => {
            ensure(
                !arr(&p["parents"]).is_empty() || p["deleted"] == false,
                "deletedViewRoot",
            )?;
            ensure(!strv(p, "name").trim().is_empty(), "emptyViewName")?;
            view_query(&p["query"])?;
        }
        "reviseConnection" => {
            ensure(
                !arr(&p["parents"]).is_empty() || p["retracted"] == false,
                "retractedConnectionRoot",
            )?;
            ensure(
                strv(p, "reason").chars().count() <= 4000 && arr(&p["parents"]).len() <= 1000,
                "connectionBounds",
            )?;
        }
        "keepAnswer" => {
            let text_bytes: usize = arr(&p["claims"])
                .iter()
                .map(|c| strv(c, "text").len())
                .sum();
            ensure(text_bytes <= 262144, "answerTextTooLarge")?;
            let mut excerpt_chars = 0;
            for e in arr(&p["evidence"]) {
                if let Some(a) = e.get("anchor") {
                    ensure(
                        matches!(strv(a, "kind"), "text" | "unresolved"),
                        "answerExcerptAnchor",
                    )?;
                    excerpt_chars += strv(a, "quote").chars().count();
                }
            }
            ensure(excerpt_chars <= 3600, "answerExcerptBudget")?;
        }
        "reviseAnnotation" | "setAnswerVisibility" => {}
        "retainSourceMetadata" => metadata(strv(p, "kind"), &p["value"], &p["raw"])?,
        "retainImages" => images(p)?,
        _ => {}
    }
    if p.get("parents").is_some() {
        unique(&p["parents"], "")?;
        ensure(
            arr(&p["parents"])
                .windows(2)
                .all(|w| w[0].as_str() < w[1].as_str()),
            "parentsNotSorted",
        )?;
    }
    Ok(())
}
pub(super) fn unique(v: &Value, key: &str) -> Result<()> {
    let mut ids = BTreeSet::new();
    for v in arr(v) {
        let v = if key.is_empty() { v } else { &v[key] };
        ensure(ids.insert(v.to_string()), "duplicateIdentity")?;
    }
    Ok(())
}
pub(super) fn manifest(v: &Value) -> Result<()> {
    ensure(matches(&specs::manifest(), v), "invalidManifest")?;
    ensure(
        (v["mediaType"] == "application/pdf") == v.get("pageCount").is_some(),
        "pageCountMediaType",
    )?;
    ensure(
        v.get("original").is_some() || v["origin"]["kind"] == "browserExtraction",
        "originalRequired",
    )?;
    ensure(strv(v, "id") == source_id(v)?, "sourceDigestIdentity")?;
    Ok(())
}
pub(super) fn anchor(a: &Value, source: &Value, position: bool) -> Result<()> {
    let kind = strv(a, "kind");
    if source.get("mediaType").is_none() {
        ensure(matches!(kind, "item" | "unresolved"), "sourceOnlyAnchor")?;
    }
    match kind {
        "page" => ensure(
            a["index"]
                .as_u64()
                .zip(source["pageCount"].as_u64())
                .is_some_and(|(n, max)| n >= 1 && n <= max),
            "pageOutOfRange",
        ),
        "text" | "passage" => {
            ensure(source["mediaType"] != "application/pdf", "passageOnPDF")?;
            if !position {
                ensure(
                    a["startUTF16"]
                        .as_u64()
                        .zip(a["lengthUTF16"].as_u64())
                        .is_some_and(|(a, b)| {
                            a.checked_add(b).is_some_and(|n| n <= 9007199254740991)
                        }),
                    "rangeOverflow",
                )?;
            }
            Ok(())
        }
        "item" | "unresolved" if !position => Ok(()),
        _ => Err(Error("invalidAnchor".into())),
    }
}
fn metadata(kind: &str, v: &Value, raw: &Value) -> Result<()> {
    ensure(v["version"] == 1, "unsupportedMetadataVersion")?;
    if kind == "readerMetadata" {
        let p = &v["provenance"];
        ensure(
            p["version"] == 1
                && id(strv(p, "documentID"))
                && digest(strv(p, "sourceRecordDigest"))
                && p["rawExport"]["digest"] == raw["digest"],
            "readerProvenance",
        )?;
        ensure(time_key(strv(p, "importedAt")).is_ok(), "metadataDate")?;
        let values = &v["values"];
        ensure(values.is_object(), "metadataValues")?;
        for k in ["title", "author", "summary", "sourceName"] {
            ensure(values[k].is_string(), "metadataText")?;
        }
        if let Some(v) = values.get("suppliedFraction") {
            ensure(
                v.as_f64().is_some_and(|n| (0.0..=1.0).contains(&n)),
                "metadataFraction",
            )?;
        }
        for k in ["firstOpened", "lastOpened", "published"] {
            if let Some(v) = values.get(k) {
                ensure(
                    v.is_null() || v.as_str().is_some_and(|s| time_key(s).is_ok()),
                    "metadataDate",
                )?;
            }
        }
        ensure(
            arr(&values["tags"]).iter().all(Value::is_string) && values["tags"].is_array(),
            "metadataTags",
        )?;
    } else {
        ensure(
            v["format"] == "readwiseCSV"
                && digest(strv(v, "workKey"))
                && digest(strv(v, "sourceRecordDigest"))
                && v["title"].is_string()
                && v["author"].is_string()
                && v["rawExport"]["digest"] == raw["digest"]
                && time_key(strv(v, "importedAt")).is_ok(),
            "excerptProvenance",
        )?;
    }
    Ok(())
}
fn images(p: &Value) -> Result<()> {
    unique(&p["assets"], "candidate")?;
    let results = &p["coverage"]["results"];
    ensure(
        results.is_array() && arr(results).len() <= 128,
        "imageCoverage",
    )?;
    let mut total = 0u64;
    let mut candidates = BTreeSet::new();
    for a in arr(&p["assets"]) {
        let c = &a["candidate"];
        let u = strv(c, "sourceURL");
        ensure(
            strv(c, "id") == image_candidate_id(c)?
                && candidates.insert(strv(c, "id"))
                && c["itemID"] == p["item"]
                && c["source"] == p["source"]
                && c["index"].as_u64().is_some_and(|n| n < 128)
                && url(u)
                && strv(c, "alt").len() <= 4000,
            "imageCandidate",
        )?;
        ensure(matches(&specs::blob(8_000_000), &a["blob"]), "imageBlob")?;
        ensure(
            ["image/jpeg", "image/png", "image/gif", "image/webp"].contains(&strv(a, "mime")),
            "imageMime",
        )?;
        ensure(
            a["width"]
                .as_u64()
                .zip(a["height"].as_u64())
                .is_some_and(|(w, h)| {
                    w > 2 && h > 2 && w <= 10000 && h <= 10000 && w * h <= 25_000_000
                }),
            "imageDimensions",
        )?;
        let urls = arr(&a["observedURLs"]);
        ensure(
            (1..=6).contains(&urls.len())
                && urls[0] == u
                && urls.iter().all(|v| url(v.as_str().unwrap_or(""))),
            "imageRedirects",
        )?;
        unique(&a["observedURLs"], "")?;
        ensure(time_key(strv(a, "capturedAt")).is_ok(), "imageDate")?;
        total += a["blob"]["size"].as_u64().unwrap_or(0);
    }
    ensure(total <= 40_000_000, "imageBatchSize")?;
    unique(results, "candidate")?;
    for r in arr(results) {
        ensure(
            id(strv(r, "candidate"))
                && ["retained", "failed", "skipped"].contains(&strv(r, "outcome")),
            "imageOutcome",
        )?;
    }
    ensure(
        candidates.iter().all(|id| {
            arr(results)
                .iter()
                .any(|r| r["candidate"] == *id && r["outcome"] == "retained")
        }),
        "imageCoverageClosure",
    )
}

pub(super) fn view_query(q: &Value) -> Result<()> {
    ensure(matches(&specs::view_query(), q), "invalidViewQuery")?;
    let c = strv(q, "consumption");
    let r = strv(q, "retention");
    ensure(
        match strv(q, "shelf") {
            "readingNow" => (c.is_empty() || c == "inProgress") && r != "released",
            "unread" => {
                (c.is_empty() || ["notStarted", "abandoned"].contains(&c)) && r != "released"
            }
            "finished" => {
                (c.is_empty() || ["doneEnough", "completed"].contains(&c)) && r != "released"
            }
            "archive" => r.is_empty() || r == "released",
            _ => true,
        },
        "inconsistentShelfFilters",
    )?;
    for key in ["tag", "collection"] {
        if let Some(v) = q.get(key) {
            ensure(!v.as_str().unwrap_or("").trim().is_empty(), "emptyFilter")?;
        }
    }
    ensure(
        q["kind"] != "originalMissing" || q.get("version").is_none_or(|v| v == 2),
        "viewQueryVersion",
    )
}
