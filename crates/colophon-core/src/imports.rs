//! Encrypted import publication, immutable evidence and historical alternatives.
//! The enclosing ordinary operation supplies encryption, signature, admission and namespace scope.
use crate::{
    domain::{AuthorContext, ProjectionState},
    ensure,
    model::OperationView,
    records::{canonical, digest},
    Error, Result,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

/// Reserved engine operation. Only an authenticated root may publish it.
pub const BATCH_KIND: &str = "colophon.importBatch";
/// Maximum encoded publication size; large originals belong in blobs.
pub const MAX_BATCH_BYTES: usize = 1024 * 1024;

/// One effective clean output, authenticated by the enclosing batch signature.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportChild {
    /// Stable transform output key, unique within the source batch.
    pub key: String,
    /// Native domain kind, never another engine operation.
    pub kind: String,
    /// Clean domain payload; historical authorship belongs in evidence.
    pub payload: Value,
    /// Trusted importer receipt, never inferred from payload extensions.
    #[serde(default)]
    pub baseline: bool,
}
/// Reserved destination occurrence, scoped by namespace and object category.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityReservation {
    /// Domain object category (book, notebook, cell, entry, episode, etc.).
    pub category: String,
    /// Destination object identity.
    pub id: String,
}
impl IdentityReservation {
    fn key(&self) -> String {
        identity_key(&self.category, &self.id)
    }
}
fn identity_key(category: &str, id: &str) -> String {
    json!([category, id]).to_string()
}
/// A complete source-unit transaction. One signed record publishes all fields atomically.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportBatch {
    /// Full source tuple plus transform version (hosts must not use only a clock or old ID).
    pub key: String,
    /// Original attribution, losing candidates, date representation and evaluated receipts.
    pub evidence: Value,
    /// Ordered effective outputs. Rejected historical writes must not appear here.
    #[serde(default)]
    pub children: Vec<ImportChild>,
    /// Full historical alternatives, separate from domain effects.
    #[serde(default)]
    pub alternatives: Vec<Value>,
    /// Source occurrence key to destination object ID. Bound with effects and evidence.
    #[serde(default)]
    pub identities: BTreeMap<String, IdentityReservation>,
    /// Verified encrypted blob manifests, whose bytes the host persists before publication.
    #[serde(default)]
    pub blobs: Vec<crate::blobs::BlobManifest>,
}
/// Stable virtual output revision, scoped by destination library, namespace and source unit.
/// The enclosing signed operation authenticates this binding; it is not an old author's signature.
pub fn output_id(library: &str, namespace: &str, batch: &str, child: &str) -> Result<String> {
    Ok(digest(&canonical(&json!([
        "colophon/import-output/1",
        library,
        namespace,
        batch,
        child
    ]))?)[..32]
        .into())
}
/// Deterministic collision/lifecycle identity. Persist its binding in ImportBatch.identities.
pub fn occurrence_id(library: &str, namespace: &str, source: &Value) -> Result<String> {
    Ok(digest(&canonical(&json!([
        "colophon/import-occurrence/1",
        library,
        namespace,
        source
    ]))?)[..32]
        .into())
}
/// Additive earlier-prefix comparison. Changed outcomes always become explicit alternatives;
/// this function never emits an unconditional mutation or rewrites signed destination history.
pub fn reconcile_prefix(
    previous: &BTreeMap<String, Value>,
    current: &BTreeMap<String, Value>,
    imported_heads: &Value,
) -> Vec<Value> {
    previous.keys().chain(current.keys()).collect::<BTreeSet<_>>().into_iter()
        .filter(|key| previous.get(*key) != current.get(*key))
        .map(|key| json!({"key":key,"historical":true,"reason":"sourceOutcomeChanged","previous":previous.get(key),"candidate":current.get(key),"importedHeads":imported_heads}))
        .collect()
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct ImportState {
    namespace: String,
    revision: String,
    batches: BTreeMap<String, Value>,
    alternatives: BTreeMap<String, Value>,
    identities: BTreeMap<String, IdentityReservation>,
    occupied: BTreeSet<String>,
    reserved: BTreeSet<String>,
    blobs: BTreeMap<String, crate::blobs::BlobManifest>,
    references: BTreeMap<String, BTreeSet<String>>,
    invalid: BTreeSet<String>,
}
impl ImportState {
    pub fn new(namespace: &str) -> Self {
        Self {
            namespace: namespace.into(),
            revision: String::new(),
            batches: BTreeMap::new(),
            alternatives: BTreeMap::new(),
            identities: BTreeMap::new(),
            occupied: BTreeSet::new(),
            reserved: BTreeSet::new(),
            blobs: BTreeMap::new(),
            references: BTreeMap::new(),
            invalid: BTreeSet::new(),
        }
    }
    pub fn validate_batch(
        &self,
        payload: &Value,
        projection: &ProjectionState,
    ) -> Result<ImportBatch> {
        ensure(
            canonical(payload)?.len() <= MAX_BATCH_BYTES,
            "Import batch exceeds 1 MiB",
        )?;
        let batch: ImportBatch = serde_json::from_value(payload.clone())?;
        ensure(
            !batch.key.is_empty() && batch.key.len() <= 8192,
            "Invalid import identity",
        )?;
        ensure(
            batch.evidence.is_object(),
            "Import evidence must be an object",
        )?;
        ensure(
            batch.children.len() <= 1024
                && batch.alternatives.len() <= 1024
                && batch.blobs.len() <= 1024,
            "Import batch count exceeded",
        )?;
        if let Some(old) = self.batches.get(&batch.key) {
            ensure(
                old["digest"] == digest(&canonical(payload)?),
                "Import identity already bound to different content",
            )?;
            return Ok(batch);
        }
        let mut outputs = BTreeSet::new();
        for child in &batch.children {
            ensure(
                !child.key.is_empty() && outputs.insert(&child.key),
                "Duplicate import output key",
            )?;
            ensure(
                !child.kind.starts_with("colophon."),
                "Nested engine command",
            )?;
            ensure(child.payload.is_object(), "Invalid import child payload")?;
            let spec = crate::domain::module(&self.namespace)
                .and_then(|m| m.operations().into_iter().find(|s| s.name == child.kind))
                .ok_or_else(|| Error("Unknown import child kind".into()))?;
            ensure(
                crate::domain::validate_input(&spec.input_schema, &child.payload),
                "Invalid import child schema",
            )?;
            if self.namespace == "notes" {
                ensure(
                    crate::domains::notes::validate_payload(&child.kind, &child.payload),
                    "Invalid notes import child",
                )?;
            }
            if creates_identity(&self.namespace, &child.kind, &child.payload) {
                if let Some(id) = child.payload["id"].as_str() {
                    ensure(
                        !projection
                            .identity_exists(identity_category(&self.namespace, &child.kind), id)
                            && !self.occupied.contains(&identity_key(
                                identity_category(&self.namespace, &child.kind),
                                id,
                            )),
                        "Destination identity occupied; use occurrence_id",
                    )?;
                }
            }
        }
        let mut reserved = BTreeSet::new();
        for (source, destination) in &batch.identities {
            ensure(
                !source.is_empty()
                    && !destination.id.is_empty()
                    && destination.id.len() <= 1024
                    && !destination.category.is_empty()
                    && destination.category.len() <= 128,
                "Invalid identity reservation",
            )?;
            if let Some(old) = self.identities.get(source) {
                ensure(old == destination, "Source identity already reserved")?;
            } else {
                ensure(
                    !projection.identity_exists(&destination.category, &destination.id)
                        && !self.occupied.contains(&destination.key())
                        && reserved.insert(destination.key()),
                    "Destination identity occupied; use occurrence_id",
                )?;
            }
        }
        for blob in &batch.blobs {
            blob.validate()?;
        }
        Ok(batch)
    }
    pub fn apply(
        &mut self,
        projection: &mut ProjectionState,
        op: &OperationView,
        context: &AuthorContext,
    ) {
        // Every admitted attempt invalidates overlay cursors, including refused engine commands.
        let previous_revision = self.revision.clone();
        self.revision = digest(format!("{}{}", self.revision, op.id).as_bytes());
        if op.kind == BATCH_KIND {
            if !context.root {
                self.invalid.insert(op.id.clone());
                return;
            }
            let Ok(batch) = self.validate_batch(&op.payload, projection) else {
                self.invalid.insert(op.id.clone());
                return;
            };
            if self.batches.contains_key(&batch.key) {
                return;
            }
            // All structural and reservation checks precede every mutation. Domain CAS failures
            // are retained normal alternatives, not a partially published transaction.
            let library = &context.library;
            let mut outputs = BTreeMap::new();
            for child in &batch.children {
                let id = output_id(library, &self.namespace, &batch.key, &child.key)
                    .expect("serializable keys");
                let mut child_op = op.clone();
                child_op.id = id.clone();
                child_op.kind = child.kind.clone();
                child_op.payload = child.payload.clone();
                if let Some(id) = child.payload["id"].as_str() {
                    self.occupied.insert(identity_key(
                        identity_category(&self.namespace, &child.kind),
                        id,
                    ));
                }
                projection.apply_with_context(&child_op, context, child.baseline);
                outputs.insert(child.key.clone(), id);
            }
            for (index, candidate) in batch.alternatives.iter().enumerate() {
                let id = digest(
                    &canonical(&json!([batch.key, index, candidate]))
                        .expect("serializable candidate"),
                );
                self.alternatives.insert(id.clone(), json!({"id":id,"batch":batch.key,"historical":true,"candidate":candidate,"importer":op.author,"publication":op.id,"sourceLibrary":batch.evidence["sourceLibrary"],"object":candidate.get("object").unwrap_or(&batch.evidence["object"]),"component":candidate.get("component").unwrap_or(&batch.evidence["component"])}));
            }
            for blob in batch.blobs {
                self.references
                    .entry(blob.descriptor.digest.clone())
                    .or_default()
                    .insert(batch.key.clone());
                self.blobs
                    .entry(blob.descriptor.digest.clone())
                    .or_insert(blob);
            }
            self.occupied
                .extend(batch.identities.values().map(IdentityReservation::key));
            self.reserved
                .extend(batch.identities.values().map(IdentityReservation::key));
            self.identities.extend(batch.identities.clone());
            self.batches.insert(batch.key.clone(), json!({"key":batch.key,"digest":digest(&canonical(&op.payload).expect("serializable batch")),"publication":op.id,"importer":op.author,"evidence":batch.evidence,"outputOperationIDs":outputs,"identities":batch.identities,"alternatives":batch.alternatives,"baselineOutputs":batch.children.iter().filter(|c|c.baseline).map(|c|(&c.key,&outputs[&c.key])).collect::<BTreeMap<_,_>>() }));
        } else if op.kind == "colophon.resolveHistorical" {
            // Resolving only acknowledges reviewed evidence; a separately authored clean command
            // is required to change native state. No rejected old command is replayed implicitly.
            let supplied = op.payload["alternatives"].as_array().and_then(|a| {
                a.iter()
                    .map(|v| v.as_str().map(String::from))
                    .collect::<Option<BTreeSet<_>>>()
            });
            let actual: BTreeSet<_> = self
                .alternatives
                .iter()
                .filter(|(_, row)| {
                    op.payload.get("object").is_none_or(|v| v == &row["object"])
                        && op
                            .payload
                            .get("component")
                            .is_none_or(|v| v == &row["component"])
                })
                .map(|(key, _)| key.clone())
                .collect();
            if !matches!(
                context.kind,
                crate::model::MemberKind::App | crate::model::MemberKind::Device
            ) || supplied.as_ref() != Some(&actual)
                || op.payload["expectedRevision"] != previous_revision
            {
                self.invalid.insert(op.id.clone());
                return;
            }
            self.alternatives.retain(|key, _| !actual.contains(key));
        } else if op.kind == "colophon.blobPublish" {
            let manifest = serde_json::from_value::<crate::blobs::BlobManifest>(
                op.payload["manifest"].clone(),
            );
            let Some(reference) = op.payload["reference"].as_str().filter(|v| !v.is_empty()) else {
                self.invalid.insert(op.id.clone());
                return;
            };
            let Ok(manifest) =
                manifest.and_then(|m| m.validate().map(|_| m).map_err(serde::de::Error::custom))
            else {
                self.invalid.insert(op.id.clone());
                return;
            };
            if self
                .blobs
                .get(&manifest.descriptor.digest)
                .is_some_and(|old| old.descriptor != manifest.descriptor)
            {
                self.invalid.insert(op.id.clone());
                return;
            }
            self.references
                .entry(manifest.descriptor.digest.clone())
                .or_default()
                .insert(reference.into());
            self.blobs
                .entry(manifest.descriptor.digest.clone())
                .or_insert(manifest);
        } else if op.kind == "colophon.blobReference" {
            let Some(blob) = op.payload["digest"].as_str() else {
                self.invalid.insert(op.id.clone());
                return;
            };
            let Some(reference) = op.payload["reference"].as_str() else {
                self.invalid.insert(op.id.clone());
                return;
            };
            if !self.blobs.contains_key(blob) {
                self.invalid.insert(op.id.clone());
                return;
            }
            let refs = self.references.entry(blob.into()).or_default();
            if op.payload["retain"] == true {
                refs.insert(reference.into());
            } else if op.payload["retain"] == false {
                refs.remove(reference);
            }
        } else {
            if creates_identity(&self.namespace, &op.kind, &op.payload)
                && op.payload["id"].as_str().is_some_and(|id| {
                    self.reserved.contains(&identity_key(
                        identity_category(&self.namespace, &op.kind),
                        id,
                    ))
                })
            {
                self.invalid.insert(op.id.clone());
                return;
            }
            if self.namespace == "reading.saved"
                && !crate::domain::role_allows(&self.namespace, &op.kind, context.kind)
            {
                self.invalid.insert(op.id.clone());
                return;
            }
            if let Some(id) = op.payload["id"].as_str() {
                self.occupied.insert(identity_key(
                    identity_category(&self.namespace, &op.kind),
                    id,
                ));
            }
            projection.apply_with_context(op, context, false);
        }
    }
    pub fn query(
        &self,
        name: &str,
        args: &Value,
        projection: &ProjectionState,
    ) -> Result<Option<Value>> {
        match name {
            "importEvidence" | "historicalAlternatives" => {
                let limit =
                    args.get("limit")
                        .map_or(Some(50), Value::as_u64)
                        .ok_or_else(|| Error("Invalid limit".into()))? as usize;
                ensure((1..=100).contains(&limit), "Invalid limit")?;
                let filter = json!([
                    args.get("sourceLibrary"),
                    args.get("object"),
                    args.get("component")
                ]);
                let mut after = String::new();
                if let Some(cursor) = args.get("cursor").filter(|v| !v.is_null()) {
                    ensure(
                        cursor["revision"] == self.revision
                            && cursor["query"] == name
                            && cursor["namespace"] == self.namespace
                            && cursor["filter"] == filter,
                        "staleCursor",
                    )?;
                    after = cursor["after"]
                        .as_str()
                        .ok_or_else(|| Error("Invalid cursor".into()))?
                        .into();
                }
                let source = if name == "importEvidence" {
                    &self.batches
                } else {
                    &self.alternatives
                };
                let mut rows = Vec::new();
                let mut bytes = 0;
                let mut last = after.clone();
                let mut more = false;
                for (key, row) in
                    source.range((std::ops::Bound::Excluded(after), std::ops::Bound::Unbounded))
                {
                    let evidence = if name == "importEvidence" {
                        &row["evidence"]
                    } else {
                        row
                    };
                    if args
                        .get("component")
                        .is_some_and(|v| v != &evidence["component"])
                        || args
                            .get("sourceLibrary")
                            .is_some_and(|v| v != &evidence["sourceLibrary"])
                        || args.get("object").is_some_and(|v| v != &evidence["object"])
                    {
                        continue;
                    }
                    let size = canonical(row)?.len();
                    ensure(size <= MAX_BATCH_BYTES - 4096, "contentTooLarge")?;
                    if rows.len() == limit || bytes + size > MAX_BATCH_BYTES - 4096 {
                        more = true;
                        break;
                    }
                    rows.push(row);
                    bytes += size;
                    last = key.clone();
                }
                let next = more.then(|| json!({"revision":self.revision,"query":name,"namespace":self.namespace,"filter":filter,"after":last}));
                Ok(Some(
                    json!({"revision":self.revision,"value":{"rows":rows,"next":next,"total":source.values().filter(|row| { let evidence = if name == "importEvidence" { &row["evidence"] } else { row }; !args.get("component").is_some_and(|v| v != &evidence["component"]) && !args.get("sourceLibrary").is_some_and(|v| v != &evidence["sourceLibrary"]) && !args.get("object").is_some_and(|v| v != &evidence["object"]) }).count()}}),
                ))
            }
            "importReceipt" => Ok(Some(
                self.batches
                    .get(
                        args["key"]
                            .as_str()
                            .ok_or_else(|| Error("Missing key".into()))?,
                    )
                    .cloned()
                    .unwrap_or(Value::Null),
            )),
            "importIdentity" => {
                let key = args["key"]
                    .as_str()
                    .ok_or_else(|| Error("Missing key".into()))?;
                let preferred = args["preferred"]
                    .as_str()
                    .ok_or_else(|| Error("Missing preferred identity".into()))?;
                Ok(Some(
                    json!({"reserved":self.identities.get(key).map(|r| &r.id),"occupied":projection.identity_exists(args["category"].as_str().ok_or_else(|| Error("Missing category".into()))?,preferred) || self.occupied.contains(&identity_key(args["category"].as_str().ok_or_else(|| Error("Missing category".into()))?,preferred))}),
                ))
            }
            "blob" => {
                let key = args["digest"]
                    .as_str()
                    .ok_or_else(|| Error("Missing digest".into()))?;
                Ok(Some(
                    json!({"manifest":self.blobs.get(key),"references":self.references.get(key).map_or(0,BTreeSet::len)}),
                ))
            }
            "importInvalid" => Ok(Some(json!(self
                .invalid
                .iter()
                .take(100)
                .collect::<Vec<_>>()))),
            _ => Ok(None),
        }
    }
}

/// Common grant-checked engine queries available in every namespace.
pub fn query_names() -> &'static [&'static str] {
    &[
        "importEvidence",
        "historicalAlternatives",
        "importReceipt",
        "importIdentity",
        "blob",
        "importInvalid",
    ]
}
pub(crate) fn query_specs() -> Vec<crate::domain::Spec> {
    query_names()
        .iter()
        .map(|name| crate::domain::Spec {
            name: (*name).into(),
            description: "Read encrypted namespace import metadata".into(),
            input_schema: json!({"type":"object"}),
        })
        .collect()
}

pub(crate) fn creates_identity(namespace: &str, kind: &str, payload: &Value) -> bool {
    matches!(
        (namespace, kind),
        ("reading.books", "addBook" | "addNote")
            | ("reading.saved", "capture")
            | ("notes", "createNotebook" | "addNote")
            | ("listening.podcasts", "addNote")
    ) || matches!(
        (namespace, kind),
        ("notes", "putCell" | "putEntry") | ("listening.podcasts", "follow")
    ) && payload.get("expect").is_some_and(Value::is_null)
}

/// Category used by the common identity reservation index. The namespace supplies the outer scope.
pub fn identity_category(namespace: &str, kind: &str) -> &'static str {
    match namespace {
        "reading.books" => {
            if kind.contains("Note") {
                "note"
            } else {
                "book"
            }
        }
        "notes" => match kind {
            "createNotebook" | "renameNotebook" | "archiveNotebook" => "notebook",
            "putEntry" | "resolveEntry" => "entry",
            "proposeEntry" | "reviewProposal" => "proposal",
            "addAttachment" => "attachment",
            "recordOutput" => "run",
            _ => "cell",
        },
        "listening.podcasts" => match kind {
            "follow" | "unfollow" | "editShow" => "show",
            "addNote" | "editNote" | "resolveNote" | "deleteNote" => "note",
            "putPlaylist" | "deletePlaylist" => "playlist",
            "queue" => "queue",
            _ => "episode",
        },
        "reading.saved" => match kind {
            "followFeed" | "unfollowFeed" | "organizeFeed" | "refreshFeed" => "feed",
            "retainSource" | "selectSource" => "source",
            "retainSourceMetadata" | "attachOriginal" => "sourceMetadata",
            "retainImages" => "image",
            "keepAnswer" | "setAnswerVisibility" => "answer",
            "setMagazineSubscription" => "subscription",
            "captureReading" | "selectReadingCheckpoint" => "checkpoint",
            "reviseAnnotation" | "tagAnnotations" => "annotation",
            "reviseView" => "view",
            "reviseConnection" => "connection",
            _ => "item",
        },
        _ => "object",
    }
}
