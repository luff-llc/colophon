//! Pure import planning. The verified Swift reader owns old admission and service evaluation.
//! Missing historical outcomes or reference mappings produce evidence, never guessed effects.
use super::{items, key, text, validation};
use crate::records::{canonical, digest};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

/// Exact verified source tuple and decoded plaintext. Exact envelopes remain in the archive.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedOperation {
    /// Source library, required to disambiguate IDs across archives.
    pub source_library: String,
    /// Original authenticated signer, never used as the new signer.
    pub author_id: String,
    /// Historical author label.
    pub author_label: String,
    /// Old operation ID, which alone need not be unique.
    pub operation_id: String,
    /// SHA-256 of the exact authenticated signed body, not a plaintext digest.
    pub signed_body_digest: String,
    /// Old kind, including unknown and service-only kinds.
    pub kind: String,
    /// Old payload version.
    pub version: u64,
    /// Original decoded payload, preserved unchanged in evidence.
    pub payload: Value,
    /// Original admitted ordering key as supplied by the verified reader.
    pub admitted_order: Value,
    /// Original claimed date representation, without guessing its codec.
    pub claimed_date: Value,
}
/// Historical evaluation supplied by the verified 0.1 reader, not by payload fields.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Disposition {
    /// Verified and effective in the complete original fold/service projection.
    Applied,
    /// A valid candidate retained even when not selected, notably transcripts.
    Retained,
    /// Verified but stale, rejected, duplicate, conflicted or otherwise ineffective.
    Rejected,
    /// Domain malformed; preserve the verified source and diagnostic.
    Malformed,
    /// Held, refused, unreadable or not authenticated; cannot become a trusted effect.
    Unresolved,
    /// A projection outcome has not been provided.
    #[default]
    Unknown,
}
/// Small importer/engine boundary. All maps are keyed with `map_key`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportContext {
    /// Verified old admission status; only `admitted` allows commands.
    pub admission: String,
    /// Evaluated old domain/service outcome.
    pub disposition: Disposition,
    /// Human-readable old receipt or unresolved reason, retained in evidence.
    pub reason: String,
    /// Optional old effective payload: filtered entries, retained metadata, pending events or
    /// applied legacy records/actions only. Never includes effects that the old fold rejected.
    pub effective_payload: Option<Value>,
    /// Category and old ID to new occurrence ID. The host persists lifecycle/collision choices.
    pub identities: BTreeMap<String, String>,
    /// Component and old qualified revision to exact new operation revision.
    pub revisions: BTreeMap<String, String>,
    /// Old plaintext digest to verified/resealed descriptor; descriptor does not imply available bytes.
    pub blobs: BTreeMap<String, Value>,
    /// An old durably accepted answer, with old claims, supplied by the service evaluator.
    pub accepted_answer: Option<Value>,
    /// Accepted source response revisions already materialized as durable answers.
    pub emitted_answers: BTreeSet<String>,
    /// Catch-up imports must compare against persisted prior imported component heads.
    pub catch_up: bool,
    /// Component/new object ID to the last imported head, including explicit null.
    pub destination_heads: BTreeMap<String, Value>,
}
/// A new clean command for the importer to sign under its own identity.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Command {
    /// Clean 0.3 kind.
    pub kind: String,
    /// Validated payload with historical `importSource` extension.
    pub payload: Value,
    /// Stable child index for idempotent one-to-many import and output-ID binding.
    pub child_index: usize,
    /// Evaluated legacy baseline, to be bound to the signed output ID in the trusted sidecar.
    /// Never infer this privilege from an arbitrary destination payload extension.
    pub baseline: bool,
}
/// Immutable encrypted sidecar entry, not a new domain opcode.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    /// Digest of the framed source tuple and transform version; the idempotency key.
    pub id: String,
    /// Full manifest including the original payload, attribution and disposition.
    pub manifest: Value,
}
/// Proposed effects and an always-present evidence disposition.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ImportPlan {
    /// Zero or more commands; signing/output operation IDs are supplied later by the host.
    pub commands: Vec<Command>,
    /// Source manifest entries that must become durable before migration is complete.
    pub evidence: Vec<Evidence>,
}
/// Collision-free key for typed component/identity maps. IDs containing dots remain opaque.
pub fn map_key(category: &str, id: &str) -> String {
    key(&[category, id])
}
/// Deterministic occurrence identity for an old remove/recreate or colliding object.
pub fn occurrence_id(
    source_library: &str,
    category: &str,
    id: &str,
    creation_digest: &str,
) -> String {
    digest(
        &canonical(&json!([
            "colophon/listening-import-occurrence/1",
            source_library,
            category,
            id,
            creation_digest
        ]))
        .unwrap_or_default(),
    )[..32]
        .into()
}
fn identity(c: &ImportContext, category: &str, id: &str) -> String {
    c.identities
        .get(&map_key(category, id))
        .cloned()
        .unwrap_or_else(|| id.into())
}
fn reference(c: &ImportContext, component: &str, v: &Value) -> Option<Value> {
    if v.is_null() {
        Some(Value::Null)
    } else {
        c.revisions
            .get(&map_key(component, v.as_str()?))
            .map(|s| json!(s))
    }
}
fn blob(c: &ImportContext, old: &Value) -> Option<Value> {
    let b = c.blobs.get(text(old, "plain"))?.clone();
    validation::valid_blob(&b).then_some(b)
}
fn anchor(c: &ImportContext, a: &Value) -> Option<Value> {
    let old = &a["reference"];
    let revision = reference(c, "transcript", &old["revision"])?;
    let transcript = c
        .identities
        .get(&map_key("transcriptRevision", text(old, "revision")))?;
    let mut result = a.clone();
    result["reference"] =
        json!({"transcript":transcript,"revision":revision,"blob":blob(c,&old["blob"])?});
    for field in ["episode", "show"] {
        if let Some(v) = old[field].as_str() {
            result["reference"][field] = json!(identity(c, field, v));
        }
    }
    Some(result)
}
fn claims(c: &ImportContext, old: &Value) -> Option<Value> {
    let mut result = old.clone();
    for claim in result.as_array_mut()? {
        for citation in claim["citations"].as_array_mut()? {
            *citation = anchor(c, citation)?;
        }
    }
    Some(result)
}
fn rename(p: &Value, pairs: &[(&str, &str)]) -> Value {
    let mut v = p.clone();
    if let Some(o) = v.as_object_mut() {
        for (old, new) in pairs {
            if let Some(value) = o.remove(*old) {
                o.insert((*new).into(), value);
            }
        }
    }
    v
}
fn map_ids(c: &ImportContext, p: &mut Value) {
    for (field, category) in [("show", "show"), ("episode", "episode")] {
        if let Some(id) = p[field].as_str() {
            p[field] = json!(identity(c, category, id));
        }
    }
    for (field, category) in [
        ("shows", "show"),
        ("episodes", "episode"),
        ("excluded", "episode"),
        ("pinned", "episode"),
        ("included", "episode"),
        ("baseQueue", "episode"),
    ] {
        if let Some(a) = p[field].as_array_mut() {
            for id in a {
                if let Some(old) = id.as_str() {
                    *id = json!(identity(c, category, old));
                }
            }
        }
    }
}
fn expectation(c: &ImportContext, p: &mut Value, control: &str, component: &str) -> bool {
    if let Some(old) = p.get(control) {
        let Some(new) = reference(c, component, old) else {
            return false;
        };
        p[control] = new;
    }
    true
}
fn unique_strings(v: &Value) -> Value {
    let mut seen = std::collections::BTreeSet::new();
    json!(items(v)
        .iter()
        .filter_map(Value::as_str)
        .filter(|s| !s.is_empty() && seen.insert(*s))
        .collect::<Vec<_>>())
}
/// Convert one verified record using its evaluated historical outcome. Without the evaluator
/// context this intentionally emits only evidence: signatures cannot prove old effectiveness.
/// The caller atomically persists the sidecar and child-index/output-ID map after signing.
pub fn import_operation(op: &VerifiedOperation, c: &ImportContext) -> ImportPlan {
    let source = json!({"sourceLibrary":op.source_library,"namespace":"listening.podcasts","authorID":op.author_id,"operationID":op.operation_id,"signedBodyDigest":op.signed_body_digest,"transformVersion":1});
    let evidence_id = digest(&canonical(&source).unwrap_or_default());
    let mut commands = vec![];
    let mut issues = vec![];
    let mut notices = vec![];
    let p = c.effective_payload.as_ref().unwrap_or(&op.payload);
    let digest_valid = op.signed_body_digest.len() == 64
        && op
            .signed_body_digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    let needs_projection = matches!(
        op.kind.as_str(),
        "show.follow"
            | "show.settings"
            | "queue.retain"
            | "legacy.bridge.import"
            | "legacy.podcastState.import"
            | "podcast.source.publish"
    );
    let eligible = (!needs_projection || c.effective_payload.is_some())
        && c.admission == "admitted"
        && matches!(c.disposition, Disposition::Applied | Disposition::Retained)
        && digest_valid
        && op.version == 1;
    let mut emit = |kind: &str, mut payload: Value, category: &str, component: &str| {
        if !payload.is_object() {
            issues.push("malformedPayload".to_string());
            return;
        }
        if let Some(id) = payload["id"].as_str() {
            payload["id"] = json!(identity(c, category, id));
        }
        map_ids(c, &mut payload);
        let destination_expect = c.catch_up && payload.get("expect").is_none();
        if destination_expect
            && [
                "show", "position", "state", "metadata", "text", "playlist", "queue",
            ]
            .contains(&component)
        {
            let object = if kind == "queue" {
                "queue"
            } else {
                text(&payload, "id")
            };
            if let Some(head) = c.destination_heads.get(&map_key(component, object)) {
                payload["expect"] = head.clone();
            } else {
                issues.push(format!("missingCatchUpHead:{component}:{object}"));
                return;
            }
        }
        if !destination_expect && !expectation(c, &mut payload, "expect", component) {
            issues.push(format!("unmappedRevision:{component}"));
            return;
        }
        normalize_legacy(kind, &mut payload);
        payload["importSource"] = source.clone();
        payload["importSource"]["childIndex"] = json!(commands.len());
        if validation::payload(kind, &payload) {
            let baseline = matches!(
                op.kind.as_str(),
                "legacy.bridge.import" | "legacy.podcastState.import"
            ) || op.kind == "podcast.source.publish"
                && payload["importedBaseline"] == true;
            commands.push(Command {
                kind: kind.into(),
                payload,
                child_index: commands.len(),
                baseline,
            });
        } else {
            issues.push(format!("unprojectable:{kind}"));
        }
    };
    if eligible {
        match op.kind.as_str() {
            "show.follow" => emit(
                "follow",
                rename(p, &[("show", "id"), ("feed", "url")]),
                "show",
                "show",
            ),
            "show.unfollow" => emit("unfollow", rename(p, &[("show", "id")]), "show", "show"),
            "show.settings" => {
                if p.get("skipIntro").is_some() || p.get("skipOutro").is_some() {
                    let mut v = rename(p, &[("show", "id")]);
                    if let Some(o) = v.as_object_mut() {
                        o.remove("speed");
                    }
                    emit("editShow", v, "show", "show");
                }
                if let Some(speed) = p.get("speed") {
                    let target = identity(c, "show", text(p, "show"));
                    let head = c
                        .destination_heads
                        .get(&map_key("preference", &format!("show:{target}:speed")))
                        .cloned()
                        .unwrap_or(Value::Null);
                    let change = json!({"scope":"show","target":target,"field":"speed","value":speed,"expect":head});
                    emit(
                        "setPreferences",
                        json!({"id":evidence_id,"changes":[change]}),
                        "receipt",
                        "preference",
                    );
                }
            }
            "preferences.batch" => {
                if let Some(changes) = p["changes"].as_object() {
                    let mut result = vec![];
                    let mut okay = true;
                    for (k, v) in changes {
                        if let Some(mut change) = preference_change(k, v) {
                            if let Some(target) = change["target"].as_str() {
                                change["target"] =
                                    json!(identity(c, text(&change, "scope"), target));
                            }
                            if let Some(head) =
                                reference(c, &format!("preference:{k}"), &p["expected"][k])
                            {
                                change["expect"] = head;
                            } else {
                                okay = false;
                            }
                            result.push(change);
                        } else {
                            okay = false;
                        }
                    }
                    if okay {
                        emit(
                            "setPreferences",
                            json!({"id":evidence_id,"changes":result}),
                            "receipt",
                            "preferences",
                        );
                    }
                }
            }
            "episode.setState" => emit(
                "setState",
                rename(p, &[("episode", "id")]),
                "episode",
                "state",
            ),
            "episode.position" => emit(
                "position",
                rename(p, &[("episode", "id"), ("deliberate", "seek")]),
                "episode",
                "position",
            ),
            "position.recover" => {
                let mut v = rename(p, &[("episode", "id")]);
                if v["duration"].is_null() {
                    if let Some(o) = v.as_object_mut() {
                        o.remove("duration");
                    }
                }
                if expectation(c, &mut v, "expectedPosition", "position")
                    && expectation(c, &mut v, "expectedState", "state")
                {
                    emit("recoverPosition", v, "episode", "position");
                }
            }
            "queue.set" if p["episodes"].is_array() => {
                let mut v = json!({"episodes":unique_strings(&p["episodes"])});
                // Overflow remains explicitly visible in the original evidence.
                if items(&v["episodes"]).len() > 1024 {
                    notices.push(format!(
                        "queueOverflow:{}",
                        items(&v["episodes"]).len() - 1024
                    ));
                    v["episodes"] = json!(&items(&v["episodes"])[..1024]);
                }
                if p.get("expect").is_some() {
                    v["expect"] = p["expect"].clone();
                }
                emit("queue", v, "queue", "queue");
                for m in items(&p["metadata"]) {
                    let mut descriptor = rename(m, &[("episode", "id"), ("audio", "audioURL")]);
                    normalize_legacy("episode", &mut descriptor);
                    if validation::descriptor_valid(&descriptor) {
                        emit("episode", descriptor, "episode", "metadata");
                    } else {
                        notices.push("unprojectableQueueMetadata".into());
                    }
                }
            }
            "queue.retain" => {
                for m in items(&p["metadata"]) {
                    let mut descriptor = rename(m, &[("episode", "id"), ("audio", "audioURL")]);
                    normalize_legacy("episode", &mut descriptor);
                    if validation::descriptor_valid(&descriptor) {
                        emit("episode", descriptor, "episode", "metadata");
                    } else {
                        notices.push("unprojectableQueueMetadata".into());
                    }
                }
            }
            "playback.naturalEnd.batch" => {
                let mut v = json!({"id":evidence_id,"events":p["events"],"baseQueue":unique_strings(&p["baseQueue"]),"expect":p["expectedQueueRevision"]});
                let mut okay = true;
                if let Some(events) = v["events"].as_array_mut() {
                    for e in events {
                        map_ids(c, e);
                        okay &= expectation(c, e, "expectedPosition", "position")
                            && expectation(c, e, "expectedState", "state");
                    }
                }
                if okay {
                    emit("completePlayback", v, "receipt", "queue");
                }
            }
            "note.add" => {
                let mut v = rename(
                    p,
                    &[
                        ("note", "id"),
                        ("transcriptAnchor", "anchor"),
                        ("captureThought", "capture"),
                    ],
                );
                if let Some(a) = v.get("anchor") {
                    if let Some(mapped) = anchor(c, a) {
                        v["anchor"] = mapped;
                    } else {
                        if let Some(o) = v.as_object_mut() {
                            o.remove("anchor");
                        }
                        v["unverifiedAnchorClaim"] = json!(true);
                        notices.push("unverifiedAnchorClaim".into());
                    }
                }
                if let Some(capture) = v.get_mut("capture") {
                    // Keep historical capture as evidence; never transfer its agent capability.
                    capture["targetAgentID"] = Value::Null;
                    if !capture["voice"].is_null() {
                        if let Some(mapped) = blob(c, &capture["voice"]) {
                            capture["voice"] = mapped;
                        } else {
                            capture["voice"] = Value::Null;
                            notices.push("missingVoiceBlobDescriptor".into());
                        }
                    }
                }
                emit("addNote", v, "note", "text");
            }
            "note.edit" => emit("editNote", rename(p, &[("note", "id")]), "note", "text"),
            "note.resolve" => {
                let mut v = rename(p, &[("note", "id")]);
                // The old service must supply the exact observed alternatives in effective_payload.
                if let Some(resolves) = p["resolves"].as_array() {
                    let mapped: Option<Vec<_>> =
                        resolves.iter().map(|r| reference(c, "text", r)).collect();
                    if let Some(mut mapped) = mapped {
                        mapped.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
                        v["resolves"] = json!(mapped);
                        emit("resolveNote", v, "note", "text");
                    }
                }
            }
            "note.delete" => emit("deleteNote", rename(p, &[("note", "id")]), "note", "text"),
            "episode.segments" => {
                let mut v = rename(p, &[("audio", "recording")]);
                if let Some(a) = v["segments"].as_array_mut() {
                    a.retain(|e| e["start"].is_number() && e["end"].as_f64() > e["start"].as_f64());
                    for e in a {
                        if e.get("kind").is_none() {
                            e["kind"] = json!("sponsor");
                        }
                    }
                }
                emit("setSegments", v, "recording", "segments");
            }
            "episode.chapters" => {
                let mut v = rename(p, &[("audio", "recording")]);
                if let Some(a) = v["entries"].as_array_mut() {
                    a.retain(|e| {
                        e["start"]
                            .as_f64()
                            .is_some_and(|n| n.is_finite() && n >= 0.0)
                            && !text(e, "title").trim().is_empty()
                    });
                    for e in a {
                        e["title"] = json!(text(e, "title")
                            .trim()
                            .chars()
                            .take(160)
                            .collect::<String>());
                    }
                }
                emit("setChapters", v, "recording", "chapters");
            }
            "episode.transcript" => {
                if let Some(mapped) = blob(c, &p["blob"]) {
                    let mut v = rename(p, &[("audio", "recording"), ("sourceReceipt", "receipt")]);
                    if let Some(raw) = v["receipt"].get("raw") {
                        if let Some(mapped) = blob(c, raw) {
                            v["receipt"]["raw"] = mapped;
                        } else {
                            notices.push("missingReceiptBlobDescriptor".into());
                        }
                    }
                    v["id"] = json!(identity(c, "transcriptRevision", &op.operation_id));
                    v["blob"] = mapped;
                    if v.get("timed").is_none() {
                        v["timed"] = json!(false);
                    }
                    if let Some(recording) = v["recording"].as_str() {
                        if recording.len() == 64 && recording.bytes().all(|b| b.is_ascii_hexdigit())
                        {
                            v["recording"] = json!(recording.to_ascii_lowercase());
                        } else if let Some(o) = v.as_object_mut() {
                            o.remove("recording");
                        }
                    }
                    emit("saveTranscript", v, "transcript", "transcript");
                } else {
                    notices.push("missingTranscriptBlobDescriptor".into());
                }
            }
            "playlist.save" => {
                let mut v = rename(p, &[("playlist", "id")]);
                v["name"] = json!(text(p, "name").trim().chars().take(120).collect::<String>());
                for field in ["shows", "episodes", "excluded", "pinned", "included"] {
                    v[field] = unique_strings(&p[field]);
                }
                for field in ["allShows", "includeFinished", "archived"] {
                    v[field] = json!(p[field].as_bool().unwrap_or(false));
                }
                for (field, allowed, default) in [
                    ("order", &["newest", "oldest", "byShow"][..], "newest"),
                    ("progress", &["any", "unplayed", "inProgress"][..], "any"),
                ] {
                    v[field] = json!(if allowed.contains(&text(p, field)) {
                        text(p, field)
                    } else {
                        default
                    });
                }
                if let Some(minutes) = p["maxMinutes"]
                    .as_f64()
                    .filter(|n| n.is_finite() && *n >= 1.0)
                {
                    v["maxMinutes"] = json!(minutes.min(1440.0) as u64);
                } else if let Some(o) = v.as_object_mut() {
                    o.remove("maxMinutes");
                }
                if p.get("titleContains").is_some() {
                    v["titleContains"] = json!(text(p, "titleContains")
                        .trim()
                        .chars()
                        .take(80)
                        .collect::<String>());
                }
                emit("savePlaylist", v, "playlist", "playlist");
            }
            "legacy.bridge.import" => {
                // Only evaluated applied feeds are eligible, never the original proposed crosswalk.
                if c.effective_payload.is_some() {
                    for feed in items(&p["feeds"]) {
                        emit(
                            "follow",
                            json!({"id":feed["targetShowID"],"url":feed["feedURL"],"title":feed["title"],"expect":null,"importedBaseline":true}),
                            "show",
                            "show",
                        );
                    }
                }
            }
            "legacy.podcastState.import" => {
                if c.effective_payload.is_some() {
                    for record in items(&p["records"]) {
                        let show = digest(text(record, "feed").as_bytes())[..32].to_string();
                        let id = digest(
                            format!("{}\n{}", text(record, "feed"), text(record, "guid"))
                                .as_bytes(),
                        )[..32]
                            .to_string();
                        if let Some(seconds) = record.get("seconds") {
                            emit(
                                "position",
                                json!({"id":id,"show":show,"seconds":seconds,"expect":null,"importedBaseline":true}),
                                "episode",
                                "position",
                            );
                        }
                        if let Some(consumption) = record.get("consumption") {
                            emit(
                                "setState",
                                json!({"id":id,"show":show,"consumption":consumption,"expect":null,"importedBaseline":true}),
                                "episode",
                                "state",
                            );
                        }
                    }
                }
            }
            "podcast.source.publish" => {
                // Applied action records are supplied by the old typed service. Facts always stay evidence.
                if c.effective_payload.is_some() {
                    for action in items(&p["actions"]) {
                        let kind = text(action, "kind");
                        if ["follow", "unfollow", "position", "setState"].contains(&kind) {
                            let mut payload = action["payload"].clone();
                            if let Some(object) = payload.as_object_mut() {
                                object.remove("importedBaseline");
                            }
                            if action["mode"] == "baseline" {
                                payload["expect"] = Value::Null;
                                payload["importedBaseline"] = json!(true);
                            }
                            emit(
                                kind,
                                payload,
                                if ["follow", "unfollow"].contains(&kind) {
                                    "show"
                                } else {
                                    "episode"
                                },
                                match kind {
                                    "position" => "position",
                                    "setState" => "state",
                                    _ => "show",
                                },
                            );
                        }
                    }
                }
            }
            "answer.save" => {
                if let Some(mapped) = claims(c, &p["claims"]) {
                    emit(
                        "saveAnswer",
                        json!({"id":evidence_id,"question":p["question"],"claims":mapped}),
                        "answer",
                        "answer",
                    );
                }
            }
            "question.response" | "question.admit" => {
                if let Some(answer) = c
                    .accepted_answer
                    .as_ref()
                    .filter(|answer| !c.emitted_answers.contains(text(answer, "responseRevision")))
                {
                    if let Some(mapped) = claims(c, &answer["claims"]) {
                        emit(
                            "saveAnswer",
                            json!({"id":identity(c,"acceptedAnswer",text(answer,"responseRevision")),"question":answer["question"],"claims":mapped}),
                            "answer",
                            "answer",
                        );
                    }
                }
            }
            // No capability or original authorship is recreated by importing these service records.
            "transcript.prepare"
            | "transcript.prepare.cancel"
            | "transcript.prepare.result"
            | "question.request"
            | "question.cancel"
            | "capture.response"
            | "capture.cancel"
            | "context.propose"
            | "context.accept" => {}
            _ => {}
        }
    }
    issues.extend(notices);
    if commands.is_empty() {
        issues.push(
            if eligible {
                "evidenceOnly"
            } else {
                "unresolvedOrIneffective"
            }
            .into(),
        );
    }
    let objects: BTreeSet<_> = commands
        .iter()
        .flat_map(|command| {
            ["id", "episode", "show"]
                .iter()
                .filter_map(|field| command.payload[*field].as_str())
        })
        .collect();
    let manifest = json!({"objects":objects,"source":source,"authorLabel":op.author_label,"kind":op.kind,"version":op.version,"admittedOrder":op.admitted_order,"claimedDate":op.claimed_date,"admission":c.admission,"domainOutcome":c.disposition,"reason":c.reason,"digestAlgorithm":"SHA-256","digestPurpose":"exact-authenticated-signed-body","originalPayload":op.payload,"effectivePayload":c.effective_payload,"issues":issues,"children":commands.iter().map(|cmd|json!({"childIndex":cmd.child_index,"kind":cmd.kind,"baseline":cmd.baseline,"outputOperationID":null})).collect::<Vec<_>>(),"archiveRequired":true,"historical":true});
    ImportPlan {
        commands,
        evidence: vec![Evidence {
            id: evidence_id,
            manifest,
        }],
    }
}
fn preference_change(k: &str, v: &Value) -> Option<Value> {
    let value = v.as_str()?;
    let rest = k
        .strip_prefix("playback.")
        .or_else(|| k.strip_prefix("listening."))?;
    let fields = [
        "speed",
        "backward",
        "forward",
        "shortenSilence",
        "levelSpeech",
        "monoAudio",
        "skipSponsors",
        "skipDetectedSponsors",
        "skipAdChapters",
        "doublePress",
        "triplePress",
        "carUsesChapters",
        "sentenceRewind",
        "smartResume",
        "markButton",
    ];
    for field in fields {
        let (scope, target) = if rest == field {
            ("global", None)
        } else if let Some(prefix) = rest.strip_suffix(&format!(".{field}")) {
            if let Some(target) = prefix.strip_prefix("show:") {
                ("show", Some(target))
            } else if let Some(target) = prefix.strip_prefix("episode:") {
                ("episode", Some(target))
            } else {
                continue;
            }
        } else {
            continue;
        };
        let decoded = if value.is_empty() {
            Value::Null
        } else if value == "true" || value == "false" {
            json!(value == "true")
        } else if ["speed", "backward", "forward"].contains(&field) {
            json!(value.parse::<f64>().ok()?)
        } else {
            json!(value)
        };
        let mut change = json!({"scope":scope,"field":field,"value":decoded,"expect":null});
        if let Some(target) = target {
            change["target"] = json!(target);
        }
        return validation::preference(&change).then_some(change);
    }
    None
}

/// Shipping 0.1 payloads write explicit `null` for absent optional fields and Unix-second
/// `published` dates. Normalize both against the 0.3 schema here, so every host adapter need not:
/// a null is dropped only where the destination field does not accept null (heads such as
/// `expect: null` keep their meaning), and numeric `published` becomes an RFC 3339 UTC string.
/// The original payload stays unchanged in the import evidence.
pub(crate) fn normalize_legacy(kind: &str, payload: &mut Value) {
    let Some(spec) = super::operation_specs().iter().find(|s| s.name == kind) else {
        return;
    };
    normalize_value(&spec.input_schema, payload);
}
fn normalize_value(schema: &Value, value: &mut Value) {
    match value {
        Value::Object(fields) => {
            let properties = schema.get("properties");
            fields.retain(|key, v| {
                !(v.is_null()
                    && properties
                        .and_then(|p| p.get(key))
                        .is_some_and(|field| !validation::valid(field, &Value::Null)))
            });
            for (key, v) in fields.iter_mut() {
                if key == "published" {
                    if let Some(seconds) = v.as_f64() {
                        if let Some(date) = unix_seconds_rfc3339(seconds) {
                            *v = json!(date);
                        }
                    }
                }
                if let Some(field) = properties.and_then(|p| p.get(key)) {
                    normalize_value(field, v);
                }
            }
        }
        Value::Array(entries) => {
            if let Some(item) = schema.get("items") {
                for v in entries {
                    normalize_value(item, v);
                }
            }
        }
        _ => {}
    }
}
/// Civil-from-days (Howard Hinnant), UTC, second precision; None outside years 1970–9999.
fn unix_seconds_rfc3339(seconds: f64) -> Option<String> {
    if !seconds.is_finite() || !(0.0..253_402_300_800.0).contains(&seconds) {
        return None;
    }
    let total = seconds.floor() as i64;
    let (days, rem) = (total.div_euclid(86_400), total.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    ))
}

#[cfg(test)]
mod legacy_tests {
    use super::*;
    #[test]
    fn unix_seconds_and_nulls_normalize_against_the_schema() {
        assert_eq!(
            unix_seconds_rfc3339(0.0).as_deref(),
            Some("1970-01-01T00:00:00Z")
        );
        assert_eq!(
            unix_seconds_rfc3339(1_762_473_600.5).as_deref(),
            Some("2025-11-07T00:00:00Z")
        );
        assert_eq!(
            unix_seconds_rfc3339(951_782_400.0).as_deref(),
            Some("2000-02-29T00:00:00Z")
        );
        let mut note =
            json!({"id":"n","episode":"e","show":"s","text":"t","quote":null,"seconds":null});
        normalize_legacy("addNote", &mut note);
        assert_eq!(note, json!({"id":"n","episode":"e","show":"s","text":"t"}));
        assert!(validation::payload("addNote", &note));
        let mut episode =
            json!({"id":"e","show":"s","title":"T","published":1_762_473_600,"duration":null});
        normalize_legacy("episode", &mut episode);
        assert_eq!(episode["published"], "2025-11-07T00:00:00Z");
        assert!(episode.get("duration").is_none());
        let mut queue = json!({"episodes":["e"],"expect":null});
        normalize_legacy("queue", &mut queue);
        assert!(
            queue["expect"].is_null() && queue.get("expect").is_some(),
            "null heads keep their meaning"
        );
    }
}
