//! Pure 0.1 migration boundary. The source verifier supplies outcomes and component maps;
//! rejected, ambiguous or undecoded history is durable evidence, never an unconditional write.
use super::*;

/// Every advertised 0.1 saved-reading kind; legacy journal opcodes are a separate format.
pub const LEGACY_KINDS: [&str; 36] = [
    "capture.link",
    "item.setState",
    "item.editMetadata",
    "item.delete",
    "content.install",
    "content.select",
    "content.position",
    "content.note",
    "content.removeNote",
    "content.images",
    "content.readerMetadata",
    "content.externalExcerpt",
    "content.attachReaderOriginal",
    "content.restore",
    "content.restoreDeleted",
    "safari.checkpoint",
    "safari.activity",
    "archive.select",
    "feed.follow",
    "feed.unfollow",
    "feed.organize",
    "feed.refresh",
    "feed.restore",
    "annotation.revision",
    "annotation.tags",
    "annotation.restore",
    "view.revision",
    "view.restore",
    "review.change",
    "review.restore",
    "answer.keep",
    "answer.visibility",
    "connection.change",
    "question.restore",
    "magazine.subscription",
    "magazine.subscriptionRestore",
];
/// Verified old admission and fold disposition. A signature alone does not imply an effective write.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum LegacyOutcome {
    /// Old admission and actual typed projection accepted this effect.
    Effective,
    /// Old CAS or terminal deletion retained an alternative.
    Conflict,
    /// Known old payload failed validation.
    Invalid,
    /// Old authority refused this operation.
    Rejected,
    /// Missing authority/key/dependency prevented a verified outcome.
    Unresolved,
    /// Valid immutable history that did not become the selected value.
    Historical,
}
/// An operation read by the authenticated 0.1 reader. Exact envelopes remain in its source archive.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedLegacyOperation {
    /// Original library identity, part of the idempotency tuple.
    pub source_library: String,
    /// Original authenticated signer ID; never used as a destination signer.
    pub author_id: String,
    /// Original verified display label.
    pub author_label: String,
    /// Original operation ID.
    pub operation_id: String,
    /// SHA-256 of exact authenticated signed-body bytes, not canonical plaintext.
    pub signed_body_digest: String,
    /// Original kind, including unsupported kinds.
    pub kind: String,
    /// Original payload version.
    pub version: u64,
    /// Unmodified parsed payload, including all unknown nested fields.
    pub payload: Value,
    /// Position in the source reader's admitted order, not an author timestamp.
    pub admitted_order: u64,
    /// Actual source fold result. Refused/held/invalid history cannot produce commands.
    pub outcome: LegacyOutcome,
}
/// Domain-side interface to the original Swift codec and typed service projections.
/// It is pure data: no I/O, signing, mutation, source authority or guessed date/enum decoding.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportContext {
    /// Persisted category/original-ID -> destination occurrence identity map.
    pub identities: BTreeMap<String, String>,
    /// Last imported destination component heads, keyed `item/component` (including explicit null).
    /// Do not refresh these from native edits: those edits must make later import commands stale.
    pub heads: BTreeMap<String, Value>,
    /// Present destination occurrences, so imports do not accidentally create duplicates.
    pub existing_items: BTreeSet<String>,
    /// Lossless semantic value from the original Codable decoder. Raw JSON stays in evidence.
    /// This supplies ISO instants, typed anchors/manifests, normalized graphs and exact references.
    pub decoded: Option<Value>,
    /// Source service validated the entire snapshot/graph/custody closure and its legacy digest.
    pub closure_verified: bool,
    /// True only if the old Safari fold advanced selected reading; never starts a presence lease.
    pub advanced_reading: bool,
}
/// Unsigned clean command. The importing root signs it under its own identity.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ImportCommand {
    /// Stable transform child identity, distinct from the final signed destination operation ID.
    pub key: String,
    /// Clean 0.3 kind.
    pub kind: String,
    /// Clean payload, including labelled `importSource` provenance.
    pub payload: Value,
    /// Bind the earlier child's signed ID to `expectActivity` for delete, or `expect` otherwise.
    pub expect_from_child: Option<usize>,
}
/// One durable sidecar disposition, including unchanged source payload and historical attribution.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportEvidence {
    /// Full framed source tuple plus transform version, hashed for idempotent catch-up.
    pub key: String,
    /// Source metadata and original payload, never a live authenticated destination projection.
    pub source: VerifiedLegacyOperation,
    /// `mapped`, `historical`, `conflict`, `invalid`, `rejected`, or `unresolved`.
    pub disposition: String,
    /// Explicit reason for deferred or evidence-only data.
    pub reason: Option<String>,
    /// Stable child command keys; the publisher must durably bind these to actual signed output IDs.
    pub outputs: Vec<String>,
    /// Historical attribution cannot substitute for the importing root's signature.
    pub historical: bool,
}
/// Atomic migration unit. Host stages commands until all blobs, evidence and output-ID receipts exist.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportResult {
    /// Zero or more clean commands in dependency order.
    pub commands: Vec<ImportCommand>,
    /// Always one evidence disposition per source operation, even for malformed or refused data.
    pub evidence: Vec<ImportEvidence>,
    /// Multi-command and deleted-history imports must not become visible before this barrier commits.
    pub publication_barrier: bool,
}
fn mapped(c: &ImportContext, category: &str, id: &str) -> String {
    c.identities
        .get(&format!("{category}/{id}"))
        .cloned()
        .unwrap_or_else(|| id.into())
}
fn head(c: &ImportContext, item: &str, component: &str) -> Result<Value> {
    c.heads
        .get(&format!("{item}/{component}"))
        .cloned()
        .ok_or_else(|| Error(format!("missing component head: {item}/{component}")))
}
fn command(kind: &str, payload: Value) -> ImportCommand {
    ImportCommand {
        key: String::new(),
        kind: kind.into(),
        payload,
        expect_from_child: None,
    }
}
fn conditional(
    kind: &str,
    mut p: Value,
    c: &ImportContext,
    item: &str,
    component: &str,
) -> Result<ImportCommand> {
    p["expect"] = head(c, item, component)?;
    Ok(command(kind, p))
}
fn pick(v: &Value, fields: &[&str]) -> Value {
    let mut p = json!({});
    for key in fields {
        if let Some(v) = v.get(key) {
            p[key] = v.clone();
        }
    }
    p
}
fn source(c: &ImportContext, v: &Value) -> Result<Value> {
    let mut m = v.clone();
    validate::manifest(&m).or_else(|_| {
        m["id"] = json!(source_id(&m)?);
        validate::manifest(&m)
    })?;
    let _ = c;
    Ok(m)
}
fn require_decoded(c: &ImportContext) -> Result<&Value> {
    c.decoded
        .as_ref()
        .ok_or_else(|| Error("original Codable decoder and source fold context required".into()))
}
fn capture(item: &str, title: &Value, url: Option<&Value>) -> ImportCommand {
    let mut p = json!({"id":item,"title":title});
    if let Some(url) = url {
        if !url.is_null() {
            p["url"] = url.clone();
        }
    }
    command("capture", p)
}

/// Translate a verified source operation without reinterpreting stale, rejected or unknown history.
/// The context must come from the actual 0.1 typed fold and original codec, not a guessed JSON tag.
/// Missing context gives an explicit unresolved disposition and no partial commands.
pub fn translate(op: &VerifiedLegacyOperation, c: &ImportContext) -> ImportResult {
    let key = hash(
        &crate::records::canonical(&json!([
            "colophon/reading.saved/import/1",
            op.source_library,
            "reading.saved",
            op.author_id,
            op.operation_id,
            op.signed_body_digest
        ]))
        .unwrap_or_default(),
    );
    let mut evidence = ImportEvidence {
        key: key.clone(),
        source: op.clone(),
        disposition: "unresolved".into(),
        reason: None,
        outputs: vec![],
        historical: true,
    };
    let mapped = if !validate::digest(&op.signed_body_digest) {
        Err(Error("invalid signed-body digest".into()))
    } else if op.version != 1 || !LEGACY_KINDS.contains(&op.kind.as_str()) {
        Err(Error(
            "unsupported legacy kind/version; retain exact source archive".into(),
        ))
    } else if op.outcome != LegacyOutcome::Effective {
        evidence.disposition = match op.outcome {
            LegacyOutcome::Conflict => "conflict",
            LegacyOutcome::Invalid => "invalid",
            LegacyOutcome::Rejected => "rejected",
            LegacyOutcome::Historical => "historical",
            _ => "unresolved",
        }
        .into();
        Ok(vec![])
    } else {
        map_effect(op, c)
    };
    let mut commands = match mapped {
        Ok(commands) => commands,
        Err(e) => {
            evidence.reason = Some(e.0);
            vec![]
        }
    };
    // Validate the complete plan before exposing any child; preserve stricter-new failures as evidence.
    for (index, cmd) in commands.iter_mut().enumerate() {
        cmd.key = format!("{key}/{index}");
        cmd.payload["importSource"] = json!({"sourceLibrary":op.source_library,"namespace":"reading.saved","authorID":op.author_id,"authorLabel":op.author_label,"operationID":op.operation_id,"signedBodyDigest":op.signed_body_digest,"digestPurpose":"SHA-256/exact-authenticated-signed-body","admittedOrder":op.admitted_order,"transformVersion":1,"childIndex":index});
        let check = AdmittedOperation {
            id: cmd.key.clone(),
            kind: cmd.kind.clone(),
            author: "importer".into(),
            author_label: "Importer".into(),
            origin: "person".into(),
            clock: 1,
            created: "2026-11-06T00:00:00Z".into(),
            payload: cmd.payload.clone(),
        };
        if let Err(e) = validate::payload(&check) {
            evidence.reason = Some(format!("unprojectable {}: {}", cmd.kind, e.0));
            break;
        }
    }
    if evidence.reason.is_some() {
        commands.clear();
    } else if !commands.is_empty() {
        evidence.disposition = "mapped".into();
    } else if op.outcome == LegacyOutcome::Effective {
        evidence.disposition = "historical".into();
        evidence.reason = Some(
            "transient presence, completion receipt or imported preference; no live effect".into(),
        );
    }
    evidence.outputs = commands.iter().map(|c| c.key.clone()).collect();
    ImportResult {
        publication_barrier: commands.len() > 1 || op.kind == "content.restoreDeleted",
        commands,
        evidence: vec![evidence],
    }
}
fn map_effect(op: &VerifiedLegacyOperation, c: &ImportContext) -> Result<Vec<ImportCommand>> {
    let raw = &op.payload;
    ensure(raw.is_object(), "malformed payload")?;
    let d = c.decoded.as_ref().unwrap_or(raw);
    let item = mapped(c, "item", strv(raw, "item"));
    let mut out = Vec::new();
    match op.kind.as_str() {
        "capture.link" => {
            ensure(
                validate::id(&item) && raw["url"].is_string(),
                "capture fields",
            )?;
            let title = raw
                .get("title")
                .filter(|v| v.is_string())
                .unwrap_or(&raw["url"]);
            let mut cmd = capture(&item, title, raw.get("url"));
            for key in ["consumption", "retention"] {
                if let Some(v) = raw.get(key) {
                    cmd.payload[key] = v.clone();
                }
            }
            if let Some(o) = raw.as_object() {
                for (k, v) in o {
                    if !["item", "url", "title", "consumption", "retention"].contains(&k.as_str()) {
                        cmd.payload[k] = v.clone();
                    }
                }
            }
            out.push(cmd);
            if ["author", "summary", "collection", "tags"]
                .iter()
                .any(|k| raw.get(k).is_some())
            {
                let mut p = pick(raw, &["summary", "collection", "tags"]);
                p["id"] = json!(item);
                if let Some(a) = raw.get("author") {
                    p["creator"] = a.clone();
                }
                let mut cmd = command("editMetadata", p);
                cmd.expect_from_child = Some(0);
                out.push(cmd);
            }
        }
        "item.setState" => {
            let mut p = pick(raw, &["consumption", "retention"]);
            if p.as_object().is_some_and(|p| !p.is_empty()) {
                p["id"] = json!(item);
                out.push(conditional("setState", p, c, &item, "state")?);
            }
        }
        "item.editMetadata" => {
            let mut p = pick(raw, &["title", "summary", "collection", "tags"]);
            if let Some(v) = raw.get("author") {
                p["creator"] = v.clone();
            }
            p["id"] = json!(item);
            out.push(conditional("editMetadata", p, c, &item, "metadata")?);
        }
        "item.delete" => out.push(command(
            "delete",
            json!({"id":item,"expectActivity":head(c,&item,"activity")?}),
        )),
        "content.install" => {
            let d = require_decoded(c)?;
            let m = source(c, &d["manifest"])?;
            if !c.existing_items.contains(&item) {
                ensure(raw["create"] == true, "missing occurrence without create")?;
                out.push(capture(&item, &raw["title"], d.get("url")));
            }
            out.push(command(
                "retainSource",
                json!({"id":m["id"],"item":item,"manifest":m}),
            ));
            if raw["select"] != false {
                let h = if c.existing_items.contains(&item) {
                    head(c, &item, "source")?
                } else {
                    Value::Null
                };
                out.push(command(
                    "selectSource",
                    json!({"item":item,"source":m["id"],"expect":h}),
                ));
            }
        }
        "content.select" => out.push(conditional(
            "selectSource",
            json!({"item":item,"source":mapped(c,"source",strv(raw,"version"))}),
            c,
            &item,
            "source",
        )?),
        "content.position" => {
            let d = require_decoded(c)?;
            out.push(conditional("position",json!({"item":item,"source":mapped(c,"source",strv(raw,"version")),"position":d["position"]}),c,&item,"position")?);
        }
        "content.note" | "content.removeNote" => {
            let d = require_decoded(c)?;
            let mut p = d["revision"].clone();
            ensure(
                p.is_object(),
                "normalized native annotation revision required",
            )?;
            p["item"] = json!(item);
            if op.kind == "content.removeNote" {
                p["action"] = json!("delete");
            }
            out.push(command("reviseAnnotation", p));
        }
        "content.images" => {
            let d = require_decoded(c)?;
            out.push(conditional("retainImages",json!({"item":item,"source":mapped(c,"source",strv(raw,"version")),"assets":d["assets"],"coverage":d["coverage"]}),c,&item,"source")?);
        }
        "content.readerMetadata" | "content.externalExcerpt" => {
            let d = require_decoded(c)?;
            let kind = if op.kind == "content.readerMetadata" {
                "readerMetadata"
            } else {
                "externalExcerpt"
            };
            let value = &d["value"];
            let title = if kind == "readerMetadata" {
                &value["values"]["title"]
            } else {
                &value["title"]
            };
            if !c.existing_items.contains(&item) {
                out.push(capture(&item, title, None));
            }
            out.push(command(
                "retainSourceMetadata",
                json!({"id":d["id"],"item":item,"kind":kind,"value":value,"raw":d["raw"]}),
            ));
        }
        "content.attachReaderOriginal" => {
            let d = require_decoded(c)?;
            out.push(command("attachOriginal",json!({"item":item,"metadata":d["metadataID"],"manifest":source(c,&d["manifest"] )?,"expect":head(c,&item,"source")?,"expectActivity":head(c,&item,"activity")?})));
        }
        "content.restore" | "content.restoreDeleted" => {
            let d = require_decoded(c)?;
            ensure(
                c.closure_verified,
                "snapshot/deleted history closure not verified",
            )?;
            ensure(!c.existing_items.contains(&item),"snapshot replacement needs explicit new occurrence map; terminal notes cannot be overwritten")?;
            let record = &d["record"];
            ensure(record.is_object(), "decoded snapshot required")?;
            out.push(capture(&item, &record["title"], record.get("url")));
            for manifest in arr(&d["manifests"]) {
                let m = source(c, manifest)?;
                out.push(command(
                    "retainSource",
                    json!({"id":m["id"],"item":item,"manifest":m}),
                ));
            }
            if let Some(source) = record.get("selectedSource") {
                out.push(command("selectSource",json!({"item":item,"source":mapped(c,"source",source.as_str().unwrap_or("")),"expect":null})));
            }
            if let Some(position) = record.get("position") {
                out.push(command("position",json!({"item":item,"source":position["source"],"position":position["position"],"expect":null})));
            }
            for revision in arr(&d["annotations"]) {
                out.push(command("reviseAnnotation", revision.clone()));
            }
            for metadata in arr(&d["metadata"]) {
                out.push(command("retainSourceMetadata", metadata.clone()));
            }
            for images in arr(&d["images"]) {
                out.push(command("retainImages", images.clone()));
            }
            if op.kind == "content.restoreDeleted" {
                let last = out.len() - 1;
                let mut cmd = command(
                    "delete",
                    json!({"id":item,"expectActivity":"@previous-child"}),
                );
                cmd.expect_from_child = Some(last);
                out.push(cmd);
            }
        }
        "safari.checkpoint" => {
            let d = require_decoded(c)?;
            ensure(
                c.closure_verified,
                "Safari exact source/UTF-16 closure not verified",
            )?;
            if !c.existing_items.contains(&item) {
                out.push(capture(&item, &d["title"], d.get("url")));
            }
            if c.advanced_reading {
                let mut cmd = command(
                    "captureReading",
                    json!({"id":d["id"],"item":item,"source":source(c,&d["source"] )?,"position":d["position"],"notes":d["notes"],"expect":if c.existing_items.contains(&item){head(c,&item,"activity")?}else{Value::Null}}),
                );
                if !c.existing_items.contains(&item) {
                    cmd.expect_from_child = Some(0);
                }
                out.push(cmd);
            } else {
                let m = source(c, &d["source"])?;
                out.push(command(
                    "retainSource",
                    json!({"id":m["id"],"item":item,"manifest":m}),
                ));
                for node in arr(&d["annotations"]) {
                    out.push(command("reviseAnnotation", node.clone()));
                }
            }
        }
        "safari.activity" => {}
        "archive.select" => out.push(conditional(
            "selectReadingCheckpoint",
            json!({"item":item,"checkpoint":mapped(c,"checkpoint",strv(raw,"checkpoint"))}),
            c,
            &item,
            "source",
        )?),
        "feed.follow" | "feed.unfollow" | "feed.organize" | "feed.refresh" => {
            let id = mapped(c, "feed", strv(raw, "feed"));
            let kind = match op.kind.as_str() {
                "feed.follow" => "followFeed",
                "feed.unfollow" => "unfollowFeed",
                "feed.organize" => "organizeFeed",
                _ => "refreshFeed",
            };
            let mut p = pick(
                d,
                &["url", "title", "folders", "response", "entries", "omitted"],
            );
            p["id"] = json!(id);
            if kind == "refreshFeed" {
                require_decoded(c)?;
            }
            p["expect"] = head(c, &id, "feed")?;
            out.push(command(kind, p));
        }
        "feed.restore" => {
            let d = require_decoded(c)?;
            ensure(c.closure_verified, "feed archive closure not verified")?;
            let record = &d["record"];
            let id = mapped(c, "feed", strv(raw, "feed"));
            out.push(command("followFeed",json!({"id":id,"url":record["url"],"title":record["title"],"folders":record["folders"],"expect":null})));
            for response in arr(&d["responses"]) {
                let mut cmd = command(
                    "refreshFeed",
                    json!({"id":id,"response":response["response"],"entries":response["entries"],"expect":"@previous-child"}),
                );
                cmd.expect_from_child = Some(out.len() - 1);
                out.push(cmd);
            }
            if record["followed"] == false {
                let mut cmd = command("unfollowFeed", json!({"id":id,"expect":"@previous-child"}));
                cmd.expect_from_child = Some(out.len() - 1);
                out.push(cmd);
            }
        }
        "annotation.revision" | "view.revision" | "connection.change" | "answer.visibility" => {
            let d = require_decoded(c)?;
            ensure(c.closure_verified, "graph/custody closure not verified")?;
            let kind = match op.kind.as_str() {
                "annotation.revision" => "reviseAnnotation",
                "view.revision" => "reviseView",
                "connection.change" => "reviseConnection",
                _ => "setAnswerVisibility",
            };
            out.push(command(kind, d["revision"].clone()));
        }
        "annotation.tags" => {
            let d = require_decoded(c)?;
            out.push(command("tagAnnotations", d["change"].clone()));
        }
        "annotation.restore"
        | "view.restore"
        | "review.restore"
        | "question.restore"
        | "magazine.subscriptionRestore" => {
            let d = require_decoded(c)?;
            ensure(
                c.closure_verified,
                "restored graph/custody/provenance closure not verified",
            )?;
            let sections: &[(&str, &str)] = match op.kind.as_str() {
                "annotation.restore" => &[
                    ("sources", "retainSource"),
                    ("revisions", "reviseAnnotation"),
                    ("tags", "tagAnnotations"),
                ],
                "view.restore" => &[("revisions", "reviseView")],
                "review.restore" => &[("changes", "changeReview")],
                "question.restore" => &[
                    ("sources", "retainSource"),
                    ("answers", "keepAnswer"),
                    ("visibility", "setAnswerVisibility"),
                    ("connections", "reviseConnection"),
                ],
                _ => &[("winners", "setMagazineSubscription")],
            };
            for (field, kind) in sections {
                ensure(d[*field].is_array(), "missing normalized archive section")?;
                for p in arr(&d[*field]) {
                    if *kind == "changeReview" && matches!(strv(p, "action"), "enable" | "disable")
                    {
                        continue;
                    }
                    out.push(command(kind, p.clone()));
                }
            }
            topological(&mut out)?;
        }
        "review.change" => {
            let d = require_decoded(c)?;
            let p = &d["change"];
            if !matches!(strv(p, "action"), "enable" | "disable") {
                out.push(command("changeReview", p.clone()));
            }
        }
        "answer.keep" => {
            let d = require_decoded(c)?;
            ensure(c.closure_verified, "answer custody not verified")?;
            out.push(command("keepAnswer", d["answer"].clone()));
        }
        "magazine.subscription" => {
            let d = require_decoded(c)?;
            ensure(
                c.closure_verified,
                "subscription winner/provenance not verified",
            )?;
            let p = &d["winner"];
            if !p.is_null() {
                out.push(conditional(
                    "setMagazineSubscription",
                    p.clone(),
                    c,
                    strv(p, "publication"),
                    "subscription",
                )?);
            }
        }
        _ => return Err(Error("unsupported legacy kind".into())),
    }
    Ok(out)
}
fn topological(commands: &mut Vec<ImportCommand>) -> Result<()> {
    let ids: BTreeSet<_> = commands
        .iter()
        .filter_map(|c| c.payload["id"].as_str().map(str::to_owned))
        .collect();
    let mut emitted = BTreeSet::new();
    let mut remaining = std::mem::take(commands);
    while !remaining.is_empty() {
        let Some(i) = remaining.iter().position(|c| {
            arr(&c.payload["parents"]).iter().all(|p| {
                !ids.contains(p.as_str().unwrap_or(""))
                    || emitted.contains(p.as_str().unwrap_or(""))
            })
        }) else {
            return Err(Error("cyclic imported graph".into()));
        };
        let c = remaining.remove(i);
        if let Some(id) = c.payload["id"].as_str() {
            emitted.insert(id.to_owned());
        }
        commands.push(c);
    }
    Ok(())
}

/// Bind a dependent command to already signed child operation IDs. The publisher must persist
/// these IDs with the evidence receipt and commit the publication barrier only after every child.
pub fn resolve_payload(command: &ImportCommand, published_ids: &[String]) -> Result<Value> {
    let mut payload = command.payload.clone();
    if let Some(child) = command.expect_from_child {
        let id = published_ids
            .get(child)
            .ok_or_else(|| Error("import dependency has not been published".into()))?;
        ensure(validate::id(id), "invalid destination operation ID")?;
        payload[if command.kind == "delete" {
            "expectActivity"
        } else {
            "expect"
        }] = json!(id);
    }
    Ok(payload)
}
