//! Pure 0.1 translation. A verified source reader supplies admission and actual fold outcome.
//! This module never verifies 0.1 signatures, guesses a historical outcome, signs as an old
//! author, reads blobs, or writes the evidence sidecar. Hosts must persist every disposition.
use super::*;

/// Source admission after verification by the 0.1 reader.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Admission {
    /// Authenticated and admitted to the source fold.
    Admitted,
    /// Not admitted (including refused, held, missing-key and invalid-signature records).
    Unresolved(String),
}
/// Actual result from the verified source fold, not inferred from new validation rules.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SourceOutcome {
    /// An effective source mutation.
    Applied,
    /// A complete losing candidate; never emit an unconditional new mutation.
    Conflict,
    /// An edit against a permanent tombstone.
    LateEdit,
    /// A source-invalid attempt.
    Invalid,
    /// Accepted retry, ignored target, or no effective content change.
    NoEffect,
}
/// Verified source metadata plus the exact parsed payload. Exact signed envelopes remain
/// in the source archive; `signed_body_digest` is SHA-256 of authenticated signed body bytes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifiedOperation {
    /// Source library identity.
    pub source_library: String,
    /// Original signer identity, never used as new authenticated authorship.
    pub author_id: String,
    /// Original operation ID.
    pub operation_id: String,
    /// Original author label.
    pub author_label: String,
    /// Original operation kind.
    pub kind: String,
    /// Original payload version.
    pub version: u64,
    /// Parsed payload; unknown and malformed fields remain in evidence.
    pub payload: Value,
    /// SHA-256 of the exact signed body.
    pub signed_body_digest: String,
    /// Verified source fold position, not claimed wall time.
    pub admitted_order: u64,
    /// Original claimed date representation, without conversion guesses.
    pub claimed_date: Value,
    /// Source admission disposition.
    pub admission: Admission,
    /// Actual 0.1 fold disposition.
    pub outcome: SourceOutcome,
}
/// Context is a value supplied by the verified source reader and persisted import map.
/// It makes translation pure while avoiding the impossible inference of a source fold from
/// one operation alone. Missing mappings yield visible evidence, never guessed references.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct ImportContext {
    /// Identity mappings keyed by `identity_key(source_library, category, old_id)`.
    pub identities: BTreeMap<String, String>,
    /// Component revision mappings keyed by `revision_key(category, old_revision)`.
    pub revisions: BTreeMap<String, String>,
    /// Actual pre-operation source heads keyed by `head_key(category, old_object_id)`.
    /// An absent object must have an explicit null entry, rather than a missing entry.
    pub heads: BTreeMap<String, Option<String>>,
    /// Complete source value for putCell/entry candidates, including old preserve semantics.
    /// Uses 0.1 payload field names. Must be supplied for edits and historical alternatives.
    pub effective_payload: Option<Value>,
    /// Actual observed source alternative revisions for a successful cell.resolve.
    pub alternatives: Option<Vec<String>>,
    /// Revisions actually materialized by the destination historical-conflict adapter.
    /// Nonempty historical resolutions remain evidence-only until this exact set is supplied.
    pub projected_alternatives: Option<Vec<String>>,
    /// Source notebook's live cell sequence, needed to reproduce old missing/self anchors.
    pub source_order: Option<Vec<String>>,
    /// Verified plaintext blob descriptors after accessible legacy bytes have been re-sealed.
    /// Key is old ciphertext digest; absent means unavailable, not empty bytes.
    pub blobs: BTreeMap<String, Value>,
    /// Source-author role established by the source authority reader.
    pub reviewer_kind: Option<MemberKind>,
    /// Whether translated proposal inputs still exactly match the destination entry.
    /// A historical keep needs explicit true, otherwise it stays evidence pending repair.
    pub translated_inputs_current: Option<bool>,
}
/// Stable framed identity key; use the persisted map for collisions and nested pointers.
pub fn identity_key(library: &str, category: &str, id: &str) -> String {
    json!([library, category, id]).to_string()
}
/// Stable component revision key; text, metadata and order maps are independent.
pub fn revision_key(category: &str, revision: &str) -> String {
    json!([category, revision]).to_string()
}
/// Namespace-qualified source artifact identity key, preventing cross-namespace collisions.
pub fn source_identity_key(library: &str, namespace: &str, artifact: &str) -> String {
    json!(["sourceArtifact", library, namespace, artifact]).to_string()
}
/// Namespace-qualified revision key for a pinned cross-library source pointer.
pub fn source_revision_key(library: &str, namespace: &str, revision: &str) -> String {
    json!(["sourceRevision", library, namespace, revision]).to_string()
}
/// Stable source component head key.
pub fn head_key(category: &str, id: &str) -> String {
    json!([category, id]).to_string()
}
/// A clean command for the destination importer identity to sign.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Command {
    /// Clean 0.2 kind.
    pub kind: String,
    /// Validated payload, including separately labelled importSource provenance.
    pub payload: Value,
    /// Stable child identity for idempotent signing/outbox lookup, not an operation ID.
    pub child_key: String,
}
/// Bytes the host must durably store, encrypt and verify before declaring import complete.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlobWrite {
    /// Plaintext digest/size/mediaType descriptor.
    pub descriptor: Value,
    /// Original UTF-8 output bytes encoded as text; no decoding or execution occurs.
    pub utf8: String,
}
/// Durable evidence record for the common encrypted import sidecar.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Evidence {
    /// Full immutable source metadata and payload.
    pub source: VerifiedOperation,
    /// Transform version and complete source tuple bind catch-up identity.
    pub key: String,
    /// `mapped`, `historicalAlternative`, `lateEdit`, `invalid`, `noEffect`, or `unresolved`.
    pub disposition: String,
    /// Visible migration gaps and normalization decisions.
    pub reasons: Vec<String>,
    /// Separately labelled full historical candidate; never authenticated as an old signer.
    pub historical_candidate: Option<Value>,
    /// Stable child keys; host must atomically bind these to newly signed operation IDs.
    pub children: Vec<String>,
}
/// Pure translation result. Every input gets exactly one manifest entry, including unknown,
/// legacy, malformed and rejected history. Blob writes and evidence are not disposable caches.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Translation {
    /// Zero or more commands, signed only by the destination importer.
    pub commands: Vec<Command>,
    /// Immutable evidence entries for sidecar persistence.
    pub evidence: Vec<Evidence>,
    /// Content-addressed output bytes requiring durable host storage.
    pub blobs: Vec<BlobWrite>,
}
fn mapped(
    ctx: &ImportContext,
    library: &str,
    category: &str,
    v: &Value,
) -> std::result::Result<Value, String> {
    let id = v
        .as_str()
        .ok_or_else(|| format!("malformed {category} identity"))?;
    ctx.identities
        .get(&identity_key(library, category, id))
        .map(|s| json!(s))
        .ok_or_else(|| format!("missing identity map: {category}/{id}"))
}
fn revision(ctx: &ImportContext, category: &str, v: &str) -> std::result::Result<Value, String> {
    ctx.revisions
        .get(&revision_key(category, v))
        .map(|s| json!(s))
        .ok_or_else(|| format!("missing {category} revision map: {v}"))
}
fn head(ctx: &ImportContext, category: &str, id: &str) -> std::result::Result<Value, String> {
    match ctx.heads.get(&head_key(category, id)) {
        Some(Some(old)) => revision(ctx, category, old),
        Some(None) => Ok(Value::Null),
        None => Err(format!("missing verified source {category} head")),
    }
}
fn rename(p: &mut Value, old: &str, new: &str) {
    if let Some(m) = p.as_object_mut() {
        if let Some(v) = m.remove(old) {
            m.insert(new.into(), v);
        }
    }
}
fn map_field(
    p: &mut Value,
    key: &str,
    ctx: &ImportContext,
    lib: &str,
    category: &str,
) -> std::result::Result<(), String> {
    if !p[key].is_null() {
        p[key] = mapped(ctx, lib, category, &p[key])?;
    }
    Ok(())
}

/// Translate one verified 0.1 operation using actual source-fold context. This function has
/// no I/O and cannot certify archive/blob/evidence durability. Formerly invalid or stale
/// records always yield evidence only. Preview and journal kinds are never treated as 0.1 cells.
pub fn translate(op: &VerifiedOperation, ctx: &ImportContext) -> Translation {
    let key = hash(
        json!([
            "colophon/notes-import/1",
            op.source_library,
            "notes",
            op.author_id,
            op.operation_id,
            op.signed_body_digest
        ])
        .to_string()
        .as_bytes(),
    );
    let mut evidence = Evidence {
        source: op.clone(),
        key: key.clone(),
        disposition: "unresolved".into(),
        reasons: vec![],
        historical_candidate: None,
        children: vec![],
    };
    let mut result = Translation {
        commands: vec![],
        evidence: vec![],
        blobs: vec![],
    };
    if op.admission != Admission::Admitted || !digest(&json!(op.signed_body_digest)) {
        evidence
            .reasons
            .push("source not verified/admitted or signed-body digest unavailable".into());
    } else if op.version != 1 {
        evidence
            .reasons
            .push("unsupported source payload version".into());
    } else if matches!(
        op.outcome,
        SourceOutcome::Conflict | SourceOutcome::LateEdit
    ) {
        evidence.disposition = if op.outcome == SourceOutcome::LateEdit {
            "lateEdit"
        } else {
            "historicalAlternative"
        }
        .into();
        evidence.historical_candidate = Some(
            json!({"historical":true,"candidate":ctx.effective_payload.as_ref().unwrap_or(&op.payload),"provenance":{"author":op.author_id,"authorLabel":op.author_label,"revision":op.operation_id,"signedBodyDigest":op.signed_body_digest,"admittedOrder":op.admitted_order},"complete":ctx.effective_payload.is_some()}),
        );
        if ctx.effective_payload.is_none() {
            evidence
                .reasons
                .push("full source candidate context required before migration completion".into());
        }
    } else if op.outcome == SourceOutcome::Invalid {
        evidence.disposition = "invalid".into();
        evidence
            .reasons
            .push("originally rejected by source domain".into());
    } else if op.outcome == SourceOutcome::NoEffect {
        evidence.disposition = "noEffect".into();
    } else {
        match clean(op, ctx, &mut evidence.reasons, &mut result.blobs) {
            Ok((kind, mut payload)) => {
                let child_key = hash(json!([key, 0]).to_string().as_bytes());
                payload["importSource"] = json!({"sourceLibrary":op.source_library,"namespace":"notes","authorID":op.author_id,"authorLabel":op.author_label,"operationID":op.operation_id,"signedBodyDigest":op.signed_body_digest,"digestAlgorithm":"SHA-256","digestPurpose":"exact authenticated signed body","admittedOrder":op.admitted_order,"transformVersion":1,"childIndex":0,"historical":true});
                if validate_payload(&kind, &payload) {
                    evidence.disposition = "mapped".into();
                    evidence.children.push(child_key.clone());
                    result.commands.push(Command {
                        kind,
                        payload,
                        child_key,
                    });
                } else {
                    evidence.reasons.push("stricter 0.2 validation or inline size limit: original retained without truncation".into());
                    result.blobs.clear();
                }
            }
            Err(reason) => {
                evidence.reasons.push(reason);
                result.blobs.clear();
            }
        }
    }
    result.evidence.push(evidence);
    result
}
fn clean(
    op: &VerifiedOperation,
    ctx: &ImportContext,
    reasons: &mut Vec<String>,
    blobs: &mut Vec<BlobWrite>,
) -> std::result::Result<(String, Value), String> {
    let old = &op.payload;
    let lib = &op.source_library;
    if !old.is_object() {
        return Err("malformed payload".into());
    }
    let kind=match op.kind.as_str(){"notebook.create"=>"createNotebook","notebook.rename"=>"renameNotebook","notebook.archive"=>"archiveNotebook","cell.put"=>"putCell","cell.resolve"=>"resolveCell","cell.move"=>"moveCell","cell.delete"=>"deleteCell","cell.output"=>"recordOutput","entry.put"=>"putEntry","attachment.add"=>"addAttachment","entry.propose"=>"proposeEntry","proposal.review"=>"reviewProposal",_=>return Err("unknown/legacy source kind; preview addNote/editNote and journal formats need separate adapters".into())};
    let mut p = old.clone();
    let old_book = old["notebook"].as_str().ok_or("missing notebook")?;
    let category = match kind {
        "createNotebook" | "renameNotebook" | "archiveNotebook" => "notebook",
        "putCell" | "resolveCell" | "moveCell" | "deleteCell" => "cell",
        "putEntry" => "entry",
        "addAttachment" => "attachment",
        "proposeEntry" | "reviewProposal" => "proposal",
        _ => "run",
    };
    if matches!(kind, "putCell" | "putEntry") {
        let object_id = old[category].as_str().ok_or("missing object ID")?;
        let component = if category == "cell" { "cell" } else { "entry" };
        if ctx
            .heads
            .get(&head_key(component, object_id))
            .is_some_and(Option::is_some)
        {
            let effective = ctx
                .effective_payload
                .as_ref()
                .ok_or("effective source value required for old omitted-field semantics")?;
            for field in if category == "cell" {
                &["kind", "source", "language", "entry"][..]
            } else {
                &["title", "date", "tags"][..]
            } {
                p[*field] = effective[*field].clone();
            }
        }
    }
    if category == "notebook" {
        rename(&mut p, "notebook", "id");
    } else if category != "run" {
        rename(&mut p, category, "id");
    }
    if category == "run" {
        p["id"] = json!(hash(
            json!([
                "colophon/notes-import-run/1",
                lib,
                op.author_id,
                op.operation_id,
                op.signed_body_digest
            ])
            .to_string()
            .as_bytes()
        ));
    } else {
        p["id"] = mapped(ctx, lib, category, &p["id"])?;
    }
    if category != "notebook" {
        p["notebook"] = mapped(ctx, lib, "notebook", &old["notebook"])?;
    }
    match kind {
        "createNotebook" => {
            if p.get("kind").is_none_or(Value::is_null) {
                p["kind"] = json!("notebook");
            }
            if !matches!(
                p["kind"].as_str(),
                Some("notebook" | "lecture" | "seminar" | "document")
            ) {
                return Err(
                    "unsupported historical notebook kind; no renamed type invented".into(),
                );
            }
        }
        "renameNotebook" | "archiveNotebook" => {
            p["expect"] = head(ctx, "notebook", old_book)?;
            if kind == "archiveNotebook" && p.get("archived").is_none_or(Value::is_null) {
                p["archived"] = json!(true);
            }
        }
        "putCell" | "resolveCell" | "deleteCell" | "moveCell" => {
            let cell = old["cell"].as_str().ok_or("missing cell")?;
            p["expect"] = head(
                ctx,
                if kind == "moveCell" { "order" } else { "cell" },
                if kind == "moveCell" { old_book } else { cell },
            )?;
            if kind == "resolveCell" {
                let source_alternatives = ctx
                    .alternatives
                    .as_ref()
                    .ok_or("verified source alternative set required")?;
                let mapped: Vec<Value> = source_alternatives
                    .iter()
                    .map(|r| revision(ctx, "cell", r))
                    .collect::<std::result::Result<_, _>>()?;
                if !mapped.is_empty() {
                    let expected: BTreeSet<_> = mapped.iter().filter_map(Value::as_str).collect();
                    let projected: BTreeSet<_> = ctx
                        .projected_alternatives
                        .as_ref()
                        .into_iter()
                        .flatten()
                        .map(String::as_str)
                        .collect();
                    if expected != projected {
                        return Err("historical alternatives require destination conflict adapter before resolution; retained pending repair".into());
                    }
                }
                p["resolves"] = Value::Array(mapped);
            }
            if kind == "putCell" {
                map_field(&mut p, "entry", ctx, lib, "entry")?;
            }
            if matches!(kind, "putCell" | "moveCell") {
                if let Some(after) = p["after"].as_str() {
                    let is_edit = kind == "putCell"
                        && ctx
                            .heads
                            .get(&head_key("cell", cell))
                            .is_some_and(Option::is_some);
                    if is_edit {
                        if let Some(object) = p.as_object_mut() {
                            object.remove("after");
                        }
                    } else if (kind == "moveCell" && after == cell)
                        || !ctx
                            .source_order
                            .as_ref()
                            .ok_or("verified source order required to translate anchor")?
                            .iter()
                            .any(|id| id == after)
                    {
                        reasons.push("old missing/self anchor translated to top; original anchor retained in source payload".into());
                        p["after"] = Value::Null;
                    } else {
                        p["after"] = mapped(ctx, lib, "cell", &p["after"])?;
                    }
                }
            }
        }
        "recordOutput" => {
            map_field(&mut p, "cell", ctx, lib, "cell")?;
            if !digest(&p["sourceDigest"]) {
                return Err(
                    "invalid sourceDigest: historical output cannot be certified current".into(),
                );
            }
            if !p["runtime"].is_string() {
                p["runtime"] = json!("");
            }
            let mut outputs = vec![];
            for v in old["outputs"].as_array().into_iter().flatten() {
                if let (Some(mime), Some(text)) = (v["mime"].as_str(), v["data"].as_str()) {
                    let mut output = v.clone();
                    rename(&mut output, "data", "text");
                    // Keep each imported run small; large originals are explicit durable blobs.
                    if text.len() > 1024 {
                        let descriptor = json!({"digest":hash(text.as_bytes()),"size":text.len(),"mediaType":mime});
                        if let Some(o) = output.as_object_mut() {
                            o.remove("text");
                        }
                        output["blob"] = descriptor.clone();
                        blobs.push(BlobWrite {
                            descriptor,
                            utf8: text.into(),
                        });
                    }
                    outputs.push(output);
                } else {
                    reasons.push(
                        "source-skipped malformed output element preserved in evidence".into(),
                    );
                }
            }
            p["outputs"] = json!(outputs);
            reasons.push("historical signed output assertion; no execution or safety claim".into());
        }
        "putEntry" => {
            let entry = old["entry"].as_str().ok_or("missing entry")?;
            p["expect"] = head(ctx, "entry", entry)?;
            if p.get("tags").is_none_or(Value::is_null) {
                p["tags"] = json!([]);
            }
        }
        "addAttachment" => {
            map_field(&mut p, "entry", ctx, lib, "entry")?;
            if p["blob"].is_object() {
                let key = string(&p["blob"], "digest");
                let descriptor=ctx.blobs.get(key).filter(|v|blob(v)).ok_or("legacy blob unavailable/unverified; retain missing reference, never empty bytes")?;
                p["blob"] = descriptor.clone();
            }
            if p["source"]["kind"] == "library" {
                let source_library = p["source"]["library"]
                    .as_str()
                    .ok_or("malformed pointer library")?
                    .to_owned();
                let namespace = p["source"]["namespace"]
                    .as_str()
                    .ok_or("malformed pointer namespace")?
                    .to_owned();
                let artifact = p["source"]["artifact"]
                    .as_str()
                    .ok_or("malformed pointer artifact")?
                    .to_owned();
                let old_revision = p["source"]["revision"]
                    .as_str()
                    .ok_or("malformed pointer revision")?
                    .to_owned();
                p["source"]["artifact"] = json!(ctx
                    .identities
                    .get(&source_identity_key(&source_library, &namespace, &artifact))
                    .ok_or("missing nested source artifact mapping")?);
                p["source"]["revision"] = json!(ctx
                    .revisions
                    .get(&source_revision_key(
                        &source_library,
                        &namespace,
                        &old_revision
                    ))
                    .ok_or("missing nested source revision mapping")?);
                for field in ["library", "namespace"] {
                    p["source"][field] = mapped(ctx, &source_library, field, &p["source"][field])?;
                }
            }
        }
        "proposeEntry" => {
            map_field(&mut p, "entry", ctx, lib, "entry")?;
            let inputs = old["inputs"]
                .as_object()
                .ok_or("malformed proposal inputs")?;
            let mut new = Map::new();
            for (cell, rev) in inputs {
                let id = mapped(ctx, lib, "cell", &json!(cell))?;
                let rev = revision(ctx, "cell", rev.as_str().ok_or("malformed input revision")?)?;
                new.insert(id.as_str().unwrap_or_default().into(), rev);
            }
            p["inputs"] = Value::Object(new);
            if p.get("tags").is_none_or(Value::is_null) {
                p["tags"] = json!([]);
            }
            if ctx.translated_inputs_current != Some(true) {
                return Err("translated proposal inputs not verified current; historical contribution pending repair".into());
            }
        }
        "reviewProposal" => {
            if !matches!(
                ctx.reviewer_kind,
                Some(MemberKind::App | MemberKind::Device)
            ) {
                return Err("source reviewer was not a verified app/device".into());
            }
            if p["keep"] == true && ctx.translated_inputs_current != Some(true) {
                return Err("historical keep cannot be reproduced; retained pending repair".into());
            }
            p["expect"] = head(
                ctx,
                "proposal",
                old["proposal"].as_str().ok_or("missing proposal")?,
            )?;
            reasons.push(
                "destination importer app must sign review; original reviewer is provenance only"
                    .into(),
            );
        }
        _ => {}
    }
    Ok((kind.into(), p))
}
