//! Saved reading: immutable sources, component CAS, terminal tombstones and retained DAGs.
//! Blob bytes, authenticated app/device fences and historical migration overlays are host interfaces.
pub mod import;
mod item_index;
mod order_index;
mod queries;
mod specs;
mod validate;

use crate::{
    domain::{AdmittedOperation, DomainModule, Reducer, Spec},
    ensure, Error, Result,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    sync::OnceLock,
};

/// Saved-reading domain module. Apply only in the engine's admitted order.
pub struct ReadingSaved;
// One field list keeps the serialized projection and restore-only helper in sync.
macro_rules! saved_state {
    ($($(#[$attr:meta])* $field:ident: $ty:ty,)*) => {
        /// Serializable saved-reading projection. Not a portable authority or source archive.
        #[derive(Clone, Default, Serialize)]
        pub struct SavedState { $($(#[$attr])* $field: $ty,)* }
        impl<'de> Deserialize<'de> for SavedState {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
                #[derive(Deserialize)]
                struct Stored { $($(#[$attr])* $field: $ty,)* }
                let Stored { $($field,)* } = Stored::deserialize(deserializer)?;
                let mut state = Self { $($field,)* };
                // Shelf rows contain only values derived from the retained projection and indexes.
                // Rebuild during restore, never by fetching or replaying historical operations.
                let ids: Vec<_> = state.items.keys().collect();
                let rows = crate::verification::parallel_map(&ids, |id| {
                    ((*id).clone(), state.row(id).expect("retained item"))
                });
                state.rows = rows.into_iter().collect();
                Ok(state)
            }
        }
    };
}
saved_state! {
    #[serde(with = "item_index")]
    items: BTreeMap<String, Item>,
    sources: BTreeMap<String, Value>,
    metadata: BTreeMap<String, Value>,
    metadata_items: BTreeSet<String>,
    item_metadata: BTreeMap<String, BTreeSet<String>>,
    images: BTreeMap<String, Value>,
    checkpoints: BTreeMap<String, Value>,
    annotations: BTreeMap<String, Graph>,
    node_roots: BTreeMap<String, BTreeMap<String, String>>,
    views: BTreeMap<String, Graph>,
    visibility: BTreeMap<String, Graph>,
    connections: BTreeMap<String, Graph>,
    feeds: BTreeMap<String, Feed>,
    answers: BTreeMap<String, Value>,
    subscriptions: BTreeMap<String, Value>,
    receipts: BTreeMap<String, Value>,
    review: Vec<Value>,
    review_enabled: bool,
    review_revision: Option<String>,
    review_excluded: BTreeSet<String>,
    review_choices: BTreeMap<String, String>,
    conflicts: Vec<Value>,
    conflict_index: BTreeMap<String, Vec<usize>>,
    invalid: Vec<String>,
    diagnostics: Vec<Value>,
    unsupported: BTreeSet<String>,
    pending: BTreeMap<String, AdmittedOperation>,
    dependencies: BTreeMap<String, BTreeSet<String>>,
    revision: String,
    // Maintained source/parent/summary indexes. No operation scan on UI reads.
    item_sources: BTreeMap<String, BTreeSet<String>>,
    item_annotations: BTreeMap<String, BTreeSet<String>>,
    note_counts: BTreeMap<String, usize>,
    #[serde(skip)]
    rows: BTreeMap<String, Value>,
    #[serde(with = "order_index")]
    item_order: order_index::Index,
    counts: BTreeMap<String, i64>,
    bucket_counts: BTreeMap<String, BTreeMap<String, i64>>,
}
#[derive(Clone, Default, Serialize, Deserialize)]
struct Item {
    value: Value,
    heads: Value,
    position: Option<Value>,
    selected: Option<String>,
    checkpoint: Option<String>,
    added: u64,
    creation_order: (u64, String, String),
}
#[derive(Clone, Default, Serialize, Deserialize)]
struct Graph {
    touched: (u64, String, String),
    history_order: BTreeSet<(u64, String, String, String)>,
    nodes: BTreeMap<String, Value>,
    heads: BTreeSet<String>,
    deleted: bool,
    tags: BTreeMap<String, Value>,
    item: String,
    source: String,
}
#[derive(Clone, Default, Serialize, Deserialize)]
struct Feed {
    value: Value,
    entries: BTreeMap<String, Value>,
    responses: Vec<Value>,
}

fn strv<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or("")
}
fn arr(v: &Value) -> &[Value] {
    v.as_array().map(Vec::as_slice).unwrap_or(&[])
}
fn operation_spec(kind: &str) -> Option<&'static Spec> {
    static SPECS: OnceLock<Vec<Spec>> = OnceLock::new();
    SPECS
        .get_or_init(specs::operations)
        .iter()
        .find(|s| s.name == kind)
}
fn hash(bytes: &[u8]) -> String {
    crate::records::digest(bytes)
}
/// Content identity for a new source, framed by a versioned purpose and plaintext blob digests.
/// Imported source IDs must be rebased through the import identity map to this identity.
pub fn source_id(manifest: &Value) -> Result<String> {
    Ok(hash(&crate::records::canonical(&json!([
        "colophon/reading.saved/source/1",
        manifest["original"]["digest"],
        manifest["metadata"]["digest"]
    ]))?))
}
/// Content-derived image candidate identity, binding occurrence, source, index and exact URL.
pub fn image_candidate_id(candidate: &Value) -> Result<String> {
    Ok(hash(&crate::records::canonical(&json!([
        "colophon/reading.saved/image/1",
        candidate["itemID"],
        candidate["source"],
        candidate["index"],
        candidate["sourceURL"]
    ]))?))
}
/// Host must authorize these commands for authenticated `app` or `device` members.
/// `OperationView` exposes only person/AI, so the reducer can reject agents but cannot distinguish servers.
pub fn protected_kind(kind: &str) -> bool {
    !matches!(
        kind,
        "capture"
            | "setState"
            | "editMetadata"
            | "followFeed"
            | "unfollowFeed"
            | "organizeFeed"
            | "refreshFeed"
    )
}
/// Byte validation hook for host adapters; a descriptor alone never establishes anchor validity.
pub trait SourceVerifier {
    /// Verify all plaintext descriptors, source format and extraction metadata against bytes.
    fn verify_source(&self, source: &Value) -> Result<()>;
    /// Verify plaintext digest/size, UTF-16 boundaries and any exact quotation.
    /// Return unavailable/missing/invalid as distinct errors; never substitute blank content.
    fn verify_anchor(&self, source: &Value, anchor: &Value) -> Result<()>;
    /// Verify Reader/Readwise provenance against the retained raw export.
    fn verify_source_metadata(&self, record: &Value) -> Result<()>;
    /// Verify image bytes and candidate evidence against the exact source.
    fn verify_image(&self, source: &Value, asset: &Value) -> Result<()>;
}
/// Host authorization/byte-validation boundary for preparing local writes. The engine must also
/// supply authenticated member kinds for equivalent replay-time role fencing.
pub fn validate_for_member(
    state: &SavedState,
    operation: &AdmittedOperation,
    member: &crate::model::MemberKind,
    host: &dyn SourceVerifier,
) -> Result<()> {
    ensure(
        !protected_kind(&operation.kind)
            || matches!(
                member,
                crate::model::MemberKind::App | crate::model::MemberKind::Device
            ),
        "roleRequired",
    )?;
    validate_with_sources(state, operation, host)
}
/// Validate structural input and all referenced host-resolved source bytes before a local write.
pub fn validate_with_sources(
    state: &SavedState,
    operation: &AdmittedOperation,
    host: &dyn SourceVerifier,
) -> Result<()> {
    validate::payload(operation)?;
    let p = &operation.payload;
    match operation.kind.as_str() {
        "retainSource" | "attachOriginal" => host.verify_source(&p["manifest"])?,
        "retainSourceMetadata" => host.verify_source_metadata(p)?,
        "position" | "reviseAnnotation" => {
            let source = state.source(strv(p, "source"), strv(p, "item"))?;
            host.verify_anchor(
                source,
                if operation.kind == "position" {
                    &p["position"]
                } else {
                    &p["anchor"]
                },
            )?;
        }
        "captureReading" => {
            host.verify_source(&p["source"])?;
            host.verify_anchor(&p["source"], &p["position"])?;
            for note in arr(&p["notes"]) {
                host.verify_anchor(&p["source"], &note["anchor"])?;
            }
        }
        "retainImages" => {
            let source = state.source(strv(p, "source"), strv(p, "item"))?;
            for asset in arr(&p["assets"]) {
                host.verify_image(source, asset)?;
            }
        }
        "keepAnswer" => {
            for evidence in arr(&p["evidence"]) {
                state.evidence(evidence)?;
                let source = state
                    .sources
                    .get(strv(evidence, "source"))
                    .or_else(|| state.metadata.get(strv(evidence, "source")))
                    .ok_or_else(|| Error("unavailable".into()))?;
                if let Some(anchor) = evidence.get("anchor") {
                    host.verify_anchor(source.get("manifest").unwrap_or(&source["value"]), anchor)?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}
impl DomainModule for ReadingSaved {
    fn namespace(&self) -> &'static str {
        "reading.saved"
    }
    fn display_name(&self) -> &'static str {
        "reading"
    }
    fn contribution_names(&self, _: &str) -> (&'static str, &'static str) {
        ("link", "links")
    }
    fn write_phrase(&self, k: &str) -> Option<&'static str> {
        match k {
            "capture" => Some("saved a link"),
            "setState" => Some("updated reading progress"),
            "editMetadata" => Some("edited a link"),
            "delete" => Some("removed a link"),
            _ => operation_spec(k).map(|_| "updated saved reading"),
        }
    }
    fn operations(&self) -> Vec<Spec> {
        specs::operations()
    }
    fn queries(&self) -> Vec<Spec> {
        specs::queries()
            .into_iter()
            .filter(|s| s.name != "position")
            .collect()
    }
    fn fold(&self, ops: &[AdmittedOperation]) -> Value {
        let mut s = SavedState::default();
        for o in ops {
            self.apply(&mut s, o);
        }
        s.projection()
    }
}
impl Reducer for ReadingSaved {
    type State = SavedState;
    fn apply(&self, s: &mut SavedState, o: &AdmittedOperation) {
        s.revision = hash(&crate::records::canonical(&json!([s.revision, o])).unwrap_or_default());
        if operation_spec(&o.kind).is_none() {
            s.unsupported.insert(o.kind.clone());
            return;
        }
        if let Err(e) = validate::payload(o) {
            s.invalid.push(o.id.clone());
            s.diagnostics.push(json!({"operation":o.id,"reason":e.0}));
            return;
        }
        match s.execute(o) {
            Ok(()) => {
                for key in dependency_keys(o) {
                    s.wake(&key);
                }
            }
            Err(e) if e.0 == "deferred" => {}
            Err(e) => {
                s.invalid.push(o.id.clone());
                s.diagnostics.push(json!({"operation":o.id,"reason":e.0}));
            }
        }
    }
    fn query(&self, s: &SavedState, name: &str, args: &Value) -> Result<Value> {
        queries::query(s, name, args)
    }
}
fn stamp(v: &mut Value, o: &AdmittedOperation) {
    v["revision"] = json!(o.id);
    v["author"] = json!(o.author);
    v["authorLabel"] = json!(o.author_label);
    v["origin"] = json!(o.origin);
    v["clock"] = json!(o.clock);
}
fn nested(v: &Value, s: &Value) -> Value {
    let s = if let Some(choices) = s["oneOf"].as_array().or_else(|| s["anyOf"].as_array()) {
        choices
            .iter()
            .find(|s| validate::matches(s, v))
            .unwrap_or(s)
    } else {
        s
    };
    if let (Some(v), Some(props)) = (v.as_object(), s["properties"].as_object()) {
        let mut out = json!({});
        for (k, v) in v {
            if let Some(s) = props.get(k) {
                out[k] = nested(v, s);
            } else {
                if !out["extensions"].is_object() {
                    out["extensions"] = json!({});
                }
                out["extensions"][k] = v.clone();
            }
        }
        out
    } else if let (Some(a), Some(s)) = (v.as_array(), s.get("items")) {
        Value::Array(a.iter().map(|v| nested(v, s)).collect())
    } else {
        v.clone()
    }
}
fn merge(v: &mut Value, o: &AdmittedOperation) {
    if !v.is_object() {
        *v = json!({});
    }
    if let (Some(spec), Some(p)) = (operation_spec(&o.kind), o.payload.as_object()) {
        for (k, field) in p {
            if matches!(k.as_str(), "expect" | "expectActivity" | "select") {
                continue;
            }
            if let Some(schema) = spec.input_schema["properties"].get(k) {
                v[k] = nested(field, schema);
            } else {
                if !v["extensions"].is_object() {
                    v["extensions"] = json!({});
                }
                v["extensions"][k] = field.clone();
            }
        }
    }
    stamp(v, o);
}
fn attributed(o: &AdmittedOperation) -> Value {
    let mut v = json!({});
    merge(&mut v, o);
    v
}
fn cas(p: &Value, key: &str, head: &Value) -> bool {
    p.get(key).is_none_or(|v| v == head)
}
impl SavedState {
    fn projection(&self) -> Value {
        let mut items: Vec<_> = self.items.values().map(|i| i.value.clone()).collect();
        items.sort_by(|a, b| order(a).cmp(&order(b)));
        json!({"items":items,"conflicts":self.conflicts,"invalid":self.invalid,"diagnostics":self.diagnostics,"unsupported":self.unsupported,"exportBlocked":!self.pending.is_empty() || !self.unsupported.is_empty(),"pendingCount":self.pending.len(),"sources":self.sources,"sourceMetadata":self.metadata,"images":self.images,"checkpoints":self.checkpoints,"annotations":self.annotations,"feeds":self.feeds,"savedViews":self.views,"reviewHistory":self.review,"answers":self.answers,"visibility":self.visibility,"connections":self.connections,"subscriptions":self.subscriptions,"receipts":self.receipts})
    }
    fn alternative(
        &mut self,
        o: &AdmittedOperation,
        object: &str,
        component: &str,
        reason: &str,
        expected: Value,
        found: Value,
    ) {
        let v = json!({"operation":o.id,"reason":reason,"object":object,"component":component,"expected":expected,"found":found,"candidate":attributed(o),"attribution":{"author":o.author,"authorLabel":o.author_label,"origin":o.origin,"clock":o.clock},"historical":false});
        self.conflict_index
            .entry(object.into())
            .or_default()
            .push(self.conflicts.len());
        self.conflicts.push(v);
        self.refresh_row(object);
    }
    fn pre_item(
        &mut self,
        o: &AdmittedOperation,
        id: &str,
        component: &str,
        control: &str,
    ) -> Result<bool> {
        let i = self
            .items
            .get(id)
            .ok_or_else(|| Error("itemNotFound".into()))?;
        let found = i.heads[component].clone();
        let deleted = i.value["deleted"] == true;
        if deleted || !cas(&o.payload, control, &found) {
            self.alternative(
                o,
                id,
                component,
                if deleted { "deleted" } else { "stale" },
                o.payload[control].clone(),
                found,
            );
            return Ok(false);
        }
        Ok(true)
    }
    fn touch(&mut self, id: &str, component: Option<&str>, o: &AdmittedOperation) {
        if let Some(i) = self.items.get_mut(id) {
            if (o.clock, o.author.as_str(), o.id.as_str()) < order(&i.value) {
                self.refresh_row(id);
                return;
            }
            i.heads["activity"] = json!(o.id);
            if let Some(c) = component {
                i.heads[c] = json!(o.id);
            }
            stamp(&mut i.value, o);
        }
        self.refresh_row(id);
    }
    fn source(&self, id: &str, item: &str) -> Result<&Value> {
        let s = self
            .sources
            .get(id)
            .or_else(|| self.metadata.get(id))
            .ok_or_else(|| Error("sourceNotFound".into()))?;
        ensure(
            self.item_sources
                .get(item)
                .is_some_and(|ids| ids.contains(id))
                || s["item"] == item,
            "sourceItemMismatch",
        )?;
        Ok(s.get("manifest").unwrap_or(&s["value"]))
    }
    fn retain_pre(&self, id: &str, _item: &str, m: &Value) -> Result<()> {
        if let Some(old) = self.sources.get(id) {
            ensure(
                old["manifest"] == nested(m, &specs::manifest()),
                "immutableSourceCollision",
            )?;
        }
        Ok(())
    }
    fn retain(&mut self, id: &str, item: &str, m: &Value, o: &AdmittedOperation) {
        if !self.sources.contains_key(id) {
            let mut v = json!({"id":id,"item":item,"manifest":nested(m,&specs::manifest())});
            stamp(&mut v, o);
            merge_extensions(&mut v, o);
            self.sources.insert(id.into(), v);
        }
        self.item_sources
            .entry(item.into())
            .or_default()
            .insert(id.into());
    }
    fn execute(&mut self, o: &AdmittedOperation) -> Result<()> {
        let p = &o.payload;
        let id = strv(p, "id");
        let item = strv(p, "item");
        match o.kind.as_str() {
            "capture" => {
                if self.items.contains_key(id) {
                    self.alternative(
                        o,
                        id,
                        "item",
                        "duplicate",
                        Value::Null,
                        self.items[id].value["revision"].clone(),
                    );
                    return Ok(());
                }
                let mut v = attributed(o);
                v["added"] = json!(o.created);
                if v.get("title").is_none() {
                    v["title"] = p["url"].clone();
                }
                if v.get("retention").is_none() {
                    v["retention"] = json!("saved");
                }
                self.items.insert(id.into(),Item{value:v,heads:json!({"state":o.id,"metadata":o.id,"activity":o.id,"source":null,"position":null}),added:o.clock,creation_order:(o.clock,o.author.clone(),o.id.clone()),..Default::default()});
                self.refresh_row(id);
            }
            "setState" | "editMetadata" | "delete" => {
                let c = match o.kind.as_str() {
                    "setState" => "state",
                    "editMetadata" => "metadata",
                    _ => "activity",
                };
                let control = if o.kind == "delete" {
                    "expectActivity"
                } else {
                    "expect"
                };
                if !self.pre_item(o, id, c, control)? {
                    return Ok(());
                }
                if let Some(i) = self.items.get_mut(id) {
                    merge(&mut i.value, o);
                    if o.kind == "delete" {
                        i.value["deleted"] = json!(true);
                    }
                    if o.kind == "setState" && p.get("state").is_some() {
                        i.value["consumption"] = json!(match strv(p, "state") {
                            "reading" => "inProgress",
                            "unread" => "notStarted",
                            _ => "completed",
                        });
                    }
                    if let Some(tags) = p["tags"].as_array() {
                        let tags: BTreeSet<_> = tags
                            .iter()
                            .filter_map(Value::as_str)
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .collect();
                        i.value["tags"] = json!(tags);
                    }
                }
                self.touch(id, Some(c), o);
            }
            "retainSource" => {
                if !self.pre_item(
                    o,
                    item,
                    "source",
                    if p["select"] == true {
                        "expect"
                    } else {
                        "__none"
                    },
                )? {
                    return Ok(());
                }
                self.retain_pre(id, item, &p["manifest"])?;
                self.retain(id, item, &p["manifest"], o);
                if p["select"] == true {
                    if let Some(i) = self.items.get_mut(item) {
                        i.selected = Some(id.into());
                    }
                    self.touch(item, Some("source"), o);
                } else {
                    self.touch(item, None, o);
                }
            }
            "selectSource" | "position" => {
                let c = if o.kind == "position" {
                    "position"
                } else {
                    "source"
                };
                if !self.pre_item(o, item, c, "expect")? {
                    return Ok(());
                }
                let source = self.source(strv(p, "source"), item)?;
                if o.kind == "position" {
                    validate::anchor(&p["position"], source, true)?;
                }
                if let Some(i) = self.items.get_mut(item) {
                    if o.kind == "position" {
                        i.position = Some(
                            json!({"source":p["source"],"position":p["position"],"revision":o.id,"updated":o.created}),
                        );
                    } else {
                        i.selected = Some(strv(p, "source").into());
                    }
                    merge_extensions(&mut i.value, o);
                }
                self.touch(item, Some(c), o);
            }
            "retainSourceMetadata" => {
                if !self.pre_item(o, item, "source", "__none")? {
                    return Ok(());
                }
                if self.metadata.contains_key(id) {
                    self.alternative(
                        o,
                        item,
                        "source",
                        "immutableMetadata",
                        Value::Null,
                        json!(id),
                    );
                    return Ok(());
                }
                self.metadata.insert(id.into(), attributed(o));
                self.metadata_items.insert(item.into());
                self.item_metadata
                    .entry(item.into())
                    .or_default()
                    .insert(id.into());
                self.touch(item, Some("source"), o);
            }
            "attachOriginal" => {
                if !self.pre_item(o, item, "source", "expect")?
                    || !self.pre_item(o, item, "activity", "expectActivity")?
                {
                    return Ok(());
                }
                let metadata = self
                    .metadata
                    .get(strv(p, "metadata"))
                    .ok_or_else(|| Error("metadataNotFound".into()))?;
                ensure(
                    metadata["item"] == item && metadata["kind"] == "readerMetadata",
                    "metadataItemMismatch",
                )?;
                ensure(
                    p["manifest"]["origin"]["documentID"]
                        == metadata["value"]["provenance"]["documentID"]
                        && p["manifest"]["origin"]["kind"] == "reader"
                        && p["manifest"]["origin"]["sourceRecordDigest"]
                            == metadata["value"]["provenance"]["sourceRecordDigest"]
                        && p["manifest"]["origin"]["rawDigest"] == metadata["raw"]["digest"],
                    "originalProvenanceMismatch",
                )?;
                ensure(
                    self.items[item].selected.is_none(),
                    "originalAlreadyAttached",
                )?;
                let sid = strv(&p["manifest"], "id");
                self.retain_pre(sid, item, &p["manifest"])?;
                self.retain(sid, item, &p["manifest"], o);
                if let Some(i) = self.items.get_mut(item) {
                    i.selected = Some(sid.into());
                }
                self.touch(item, Some("source"), o);
            }
            "retainImages" => {
                if !self.pre_item(o, item, "source", "expect")? {
                    return Ok(());
                }
                self.source(strv(p, "source"), item)?;
                for a in arr(&p["assets"]) {
                    let aid = strv(&a["candidate"], "id");
                    if let Some(old) = self.images.get(aid) {
                        ensure(
                            old["asset"] == nested(a, &specs::image_asset()),
                            "immutableImageCollision",
                        )?;
                    }
                }
                for a in arr(&p["assets"]) {
                    self.images
                        .entry(strv(&a["candidate"], "id").into())
                        .or_insert_with(
                            || json!({"item":item,"source":p["source"],"asset":nested(a,&specs::image_asset()),"revision":o.id,"clock":o.clock}),
                        );
                }
                self.receipts.insert(o.id.clone(), attributed(o));
                self.touch(item, None, o);
            }
            "captureReading" => self.capture_reading(o)?,
            "selectReadingCheckpoint" => {
                if !self.pre_item(o, item, "source", "expect")? {
                    return Ok(());
                }
                let checkpoint = self
                    .checkpoints
                    .get(strv(p, "checkpoint"))
                    .ok_or_else(|| Error("checkpointNotFound".into()))?;
                ensure(checkpoint["item"] == item, "checkpointItemMismatch")?;
                if let Some(i) = self.items.get_mut(item) {
                    i.selected = Some(strv(&checkpoint["source"], "id").into());
                    i.checkpoint = Some(strv(p, "checkpoint").into());
                    i.position = Some(
                        json!({"source":i.selected,"position":checkpoint["position"],"revision":o.id,"updated":o.created}),
                    );
                    i.heads["position"] = json!(o.id);
                }
                self.touch(item, Some("source"), o);
            }
            "reviseAnnotation" | "reviseView" | "setAnswerVisibility" | "reviseConnection" => {
                self.graph(o)?
            }
            "tagAnnotations" => self.tag(o)?,
            "followFeed" | "unfollowFeed" | "organizeFeed" | "refreshFeed" => self.feed(o)?,
            "changeReview" => self.review(o)?,
            "keepAnswer" => {
                if self.answers.contains_key(id) {
                    self.alternative(
                        o,
                        id,
                        "answer",
                        "immutableAnswer",
                        Value::Null,
                        self.answers[id]["revision"].clone(),
                    );
                    return Ok(());
                }
                ensure(
                    !strv(p, "question").trim().is_empty()
                        && !arr(&p["claims"]).is_empty()
                        && !arr(&p["evidence"]).is_empty(),
                    "emptyAnswer",
                )?;
                for e in arr(&p["evidence"]) {
                    self.evidence(e)?;
                }
                for c in arr(&p["claims"]) {
                    ensure(!arr(&c["citations"]).is_empty(), "uncitedClaim")?;
                    for e in arr(&c["citations"]) {
                        ensure(arr(&p["evidence"]).contains(e), "citationClosure")?;
                    }
                }
                self.answers.insert(id.into(), attributed(o));
            }
            "setMagazineSubscription" => {
                let publication = strv(p, "publication");
                let old = self
                    .subscriptions
                    .get(publication)
                    .map(|v| v["revision"].clone())
                    .unwrap_or(Value::Null);
                if !cas(p, "expect", &old) {
                    self.alternative(
                        o,
                        publication,
                        "subscription",
                        "stale",
                        p["expect"].clone(),
                        old,
                    );
                    return Ok(());
                }
                let v = self
                    .subscriptions
                    .entry(publication.into())
                    .or_insert_with(|| json!({}));
                merge(v, o);
            }
            _ => {}
        }
        Ok(())
    }
    fn capture_reading(&mut self, o: &AdmittedOperation) -> Result<()> {
        let p = &o.payload;
        let item = strv(p, "item");
        let id = strv(p, "id");
        let sid = strv(&p["source"], "id");
        if !self.pre_item(o, item, "activity", "expect")? {
            return Ok(());
        }
        ensure(!self.checkpoints.contains_key(id), "checkpointCollision")?;
        self.retain_pre(sid, item, &p["source"])?;
        validate::anchor(&p["position"], &p["source"], true)?;
        for n in arr(&p["notes"]) {
            ensure(
                !self.annotations.contains_key(strv(n, "id")),
                "annotationSeedCollision",
            )?;
            validate::anchor(&n["anchor"], &p["source"], false)?;
        }
        self.retain(sid, item, &p["source"], o);
        self.checkpoints.insert(id.into(), attributed(o));
        for n in arr(&p["notes"]) {
            let tid = strv(n, "id");
            let mut node = json!({"id":tid,"thread":tid,"item":item,"source":sid,"parents":[],"action":"create","anchor":n["anchor"],"text":n["text"]});
            stamp(&mut node, o);
            *self.note_counts.entry(item.into()).or_default() += 1;
            self.node_roots
                .entry("reviseAnnotation".into())
                .or_default()
                .insert(tid.into(), tid.into());
            self.annotations.insert(
                tid.into(),
                Graph {
                    touched: (o.clock, o.author.clone(), o.id.clone()),
                    history_order: BTreeSet::from([(
                        o.clock,
                        o.author.clone(),
                        o.id.clone(),
                        tid.into(),
                    )]),
                    nodes: BTreeMap::from([(tid.into(), node)]),
                    heads: BTreeSet::from([tid.into()]),
                    item: item.into(),
                    source: sid.into(),
                    ..Default::default()
                },
            );
            self.item_annotations
                .entry(item.into())
                .or_default()
                .insert(tid.into());
        }
        if let Some(i) = self.items.get_mut(item) {
            i.selected = Some(sid.into());
            i.checkpoint = Some(id.into());
            i.position = Some(
                json!({"source":sid,"position":p["position"],"revision":o.id,"updated":o.created}),
            );
            i.value["consumption"] = json!("inProgress");
            i.heads["state"] = json!(o.id);
            i.heads["position"] = json!(o.id);
        }
        self.touch(item, Some("source"), o);
        Ok(())
    }
    fn evidence(&self, e: &Value) -> Result<()> {
        let s = self
            .sources
            .get(strv(e, "source"))
            .or_else(|| self.metadata.get(strv(e, "source")))
            .ok_or_else(|| Error("evidenceSourceMissing".into()))?;
        if let Some(a) = e.get("anchor") {
            validate::anchor(a, s.get("manifest").unwrap_or(&s["value"]), false)?;
        }
        if let Some(a) = e.get("annotation") {
            let id = a.as_str().unwrap_or("");
            let node = self
                .node_roots
                .get("reviseAnnotation")
                .and_then(|ids| ids.get(id))
                .and_then(|root| self.annotations.get(root))
                .and_then(|g| {
                    g.nodes
                        .get(id)
                        .or_else(|| g.nodes.values().find(|n| n["revision"] == id))
                });
            ensure(
                node.is_some_and(|n| n["source"] == e["source"]),
                "evidenceAnnotationMissing",
            )?;
        }
        Ok(())
    }
    fn endpoint(&self, e: &Value) -> Result<()> {
        self.source(strv(e, "source"), strv(e, "item"))?;
        self.evidence(e)
    }
}
fn order(v: &Value) -> (u64, &str, &str) {
    (
        v["clock"].as_u64().unwrap_or(0),
        strv(v, "author"),
        strv(v, "revision"),
    )
}
fn merge_extensions(v: &mut Value, o: &AdmittedOperation) {
    let candidate = attributed(o);
    if let Some(ext) = candidate["extensions"].as_object() {
        if !v["extensions"].is_object() {
            v["extensions"] = json!({});
        }
        for (k, x) in ext {
            v["extensions"][k] = x.clone();
        }
    }
}
impl SavedState {
    fn graph_map(&self, kind: &str) -> &BTreeMap<String, Graph> {
        match kind {
            "reviseAnnotation" => &self.annotations,
            "reviseView" => &self.views,
            "setAnswerVisibility" => &self.visibility,
            _ => &self.connections,
        }
    }
    fn graph_map_mut(&mut self, kind: &str) -> &mut BTreeMap<String, Graph> {
        match kind {
            "reviseAnnotation" => &mut self.annotations,
            "reviseView" => &mut self.views,
            "setAnswerVisibility" => &mut self.visibility,
            _ => &mut self.connections,
        }
    }
    fn graph(&mut self, o: &AdmittedOperation) -> Result<()> {
        let p = &o.payload;
        let id = strv(p, "id");
        let key = match o.kind.as_str() {
            "reviseAnnotation" => "thread",
            "reviseView" => "view",
            "setAnswerVisibility" => "answer",
            _ => "connection",
        };
        let root = strv(p, key);
        let item = strv(p, "item");
        ensure(
            !arr(&p["parents"]).iter().any(|v| v == id || v == &o.id),
            "graphCycle",
        )?;
        if self
            .node_roots
            .get(&o.kind)
            .is_some_and(|ids| ids.contains_key(id))
        {
            self.alternative(o, root, key, "revisionCollision", Value::Null, json!(id));
            return Ok(());
        }
        for parent in arr(&p["parents"]) {
            if let Some(parent_root) = self
                .node_roots
                .get(&o.kind)
                .and_then(|ids| ids.get(parent.as_str().unwrap_or("")))
            {
                ensure(parent_root == root, "parentRootMismatch")?;
            }
        }
        let old = self.graph_map(&o.kind).get(root);
        if old.is_some_and(|g| g.nodes.contains_key(id)) {
            self.alternative(o, root, key, "revisionCollision", Value::Null, json!(id));
            return Ok(());
        }
        let mut missing = Vec::new();
        let mut parents = BTreeSet::new();
        for parent in arr(&p["parents"]) {
            let parent = parent.as_str().unwrap_or("");
            if let Some((id, _)) = old.and_then(|g| {
                g.nodes
                    .iter()
                    .find(|(id, n)| id.as_str() == parent || n["revision"] == parent)
            }) {
                parents.insert(id.clone());
            } else {
                missing.push(parent.to_owned());
            }
        }
        if !missing.is_empty() {
            for parent in missing {
                self.dependencies
                    .entry(parent)
                    .or_default()
                    .insert(o.id.clone());
            }
            self.pending.insert(o.id.clone(), o.clone());
            return Err(Error("deferred".into()));
        }
        if o.kind == "reviseAnnotation" {
            if !self.items.contains_key(item) {
                return self.defer(o, &dependency("item", item));
            }
            if !self.sources.contains_key(strv(p, "source"))
                && !self.metadata.contains_key(strv(p, "source"))
            {
                return self.defer(o, &dependency("source", strv(p, "source")));
            }
            if !self.pre_item(o, item, "activity", "__none")? {
                return Ok(());
            }
            let source = self.source(strv(p, "source"), item)?;
            validate::anchor(&p["anchor"], source, false)?;
            if let Some(g) = self.annotations.get(root) {
                ensure(g.item == item, "immutableAnnotationItem")?;
                if strv(p, "action") != "relocate" {
                    ensure(g.source == strv(p, "source"), "immutableAnnotationSource")?;
                }
            }
            ensure(
                (strv(p, "action") == "create") == parents.is_empty(),
                "annotationParents",
            )?;
        } else if o.kind == "setAnswerVisibility" {
            if !self.answers.contains_key(root) {
                return self.defer(o, &dependency("answer", root));
            }
        } else if o.kind == "reviseConnection" {
            ensure(p["source"] != p["target"], "identicalEndpoints")?;
            for e in [&p["source"], &p["target"]] {
                if !self.sources.contains_key(strv(e, "source")) {
                    return self.defer(o, &dependency("source", strv(e, "source")));
                }
            }
            self.endpoint(&p["source"])?;
            self.endpoint(&p["target"])?;
            if let Some(g) = self.connections.get(root) {
                if let Some(n) = g.nodes.values().next() {
                    ensure(
                        n["source"] == p["source"] && n["target"] == p["target"],
                        "immutableEndpoints",
                    )?;
                }
            }
        }
        let old = self.graph_map(&o.kind).get(root);
        if old.is_some_and(|g| g.deleted) {
            self.alternative(
                o,
                if item.is_empty() { root } else { item },
                key,
                "deleted",
                p["parents"].clone(),
                json!(old.map(|g| &g.heads)),
            );
            return Ok(());
        }
        if strv(p, "action") == "resolve" && old.is_some_and(|g| g.heads != parents) {
            self.alternative(
                o,
                item,
                key,
                "staleResolution",
                p["parents"].clone(),
                json!(old.map(|g| &g.heads)),
            );
            return Ok(());
        }
        let mut node = attributed(o);
        node["parents"] = json!(parents);
        node["historical"] = json!(false);
        let deleted = p["action"] == "delete" || (o.kind == "reviseView" && p["deleted"] == true);
        if o.kind == "reviseAnnotation" {
            if !self.annotations.contains_key(root) {
                *self.note_counts.entry(item.into()).or_default() += 1;
            }
            if deleted {
                let count = self.note_counts.entry(item.into()).or_default();
                *count = count.saturating_sub(1);
            }
        }
        let graph = self.graph_map_mut(&o.kind).entry(root.into()).or_default();
        graph.item = item.into();
        graph.source = strv(p, "source").into();
        for parent in &parents {
            graph.heads.remove(parent);
        }
        graph.heads.insert(id.into());
        graph.nodes.insert(id.into(), node);
        graph
            .history_order
            .insert((o.clock, o.author.clone(), o.id.clone(), id.into()));
        graph.touched = graph
            .touched
            .clone()
            .max((o.clock, o.author.clone(), o.id.clone()));
        graph.deleted |= deleted;
        let conflicted = graph.heads.len() > 1;
        let heads = json!(graph.heads);
        self.node_roots
            .entry(o.kind.clone())
            .or_default()
            .insert(id.into(), root.into());
        self.node_roots
            .entry(o.kind.clone())
            .or_default()
            .insert(o.id.clone(), root.into());
        if conflicted {
            self.alternative(
                o,
                if item.is_empty() { root } else { item },
                key,
                "concurrentHeads",
                p["parents"].clone(),
                heads,
            );
        }
        if o.kind == "reviseAnnotation" {
            self.item_annotations
                .entry(item.into())
                .or_default()
                .insert(root.into());
            self.touch(item, None, o);
        }
        Ok(())
    }
    fn defer(&mut self, o: &AdmittedOperation, key: &str) -> Result<()> {
        self.dependencies
            .entry(key.into())
            .or_default()
            .insert(o.id.clone());
        self.pending.insert(o.id.clone(), o.clone());
        Err(Error("deferred".into()))
    }
    fn wake(&mut self, id: &str) {
        let mut ready = self.dependencies.remove(id).unwrap_or_default();
        while let Some(opid) = ready.pop_first() {
            if let Some(op) = self.pending.remove(&opid) {
                match self.execute(&op) {
                    Ok(()) => {
                        for key in dependency_keys(&op) {
                            if let Some(next) = self.dependencies.remove(&key) {
                                ready.extend(next);
                            }
                        }
                    }
                    Err(e) if e.0 == "deferred" => {}
                    Err(e) => {
                        self.invalid.push(op.id.clone());
                        self.diagnostics
                            .push(json!({"operation":op.id,"reason":e.0}));
                    }
                }
            }
        }
    }
    fn tag(&mut self, o: &AdmittedOperation) -> Result<()> {
        let p = &o.payload;
        let tag = strv(p, "tag");
        let id = strv(p, "id");
        if self.receipts.contains_key(id) {
            self.alternative(o, id, "tag", "receiptCollision", Value::Null, json!(id));
            return Ok(());
        }
        for thread in arr(&p["threads"]) {
            let thread = thread.as_str().unwrap_or("");
            let g = self
                .annotations
                .get(thread)
                .ok_or_else(|| Error("threadNotFound".into()))?;
            let head = g
                .tags
                .get(tag)
                .map(|v| v["revision"].clone())
                .unwrap_or(Value::Null);
            if g.deleted || self.items[&g.item].value["deleted"] == true || !cas(p, "expect", &head)
            {
                let item = g.item.clone();
                self.alternative(
                    o,
                    &item,
                    "tags",
                    "staleOrDeleted",
                    p["expect"].clone(),
                    head,
                );
                return Ok(());
            }
        }
        let mut items = BTreeSet::new();
        for thread in arr(&p["threads"]) {
            if let Some(g) = self.annotations.get_mut(thread.as_str().unwrap_or("")) {
                g.touched = g
                    .touched
                    .clone()
                    .max((o.clock, o.author.clone(), o.id.clone()));
                g.tags.insert(
                    tag.into(),
                    json!({"included":p["included"],"revision":o.id}),
                );
                items.insert(g.item.clone());
            }
        }
        self.receipts.insert(id.into(), attributed(o));
        for item in items {
            self.touch(&item, None, o);
        }
        Ok(())
    }
    fn feed(&mut self, o: &AdmittedOperation) -> Result<()> {
        let p = &o.payload;
        let id = strv(p, "id");
        let old = self.feeds.get(id);
        let head = old
            .map(|f| f.value["revision"].clone())
            .unwrap_or(Value::Null);
        if !cas(p, "expect", &head)
            || (o.kind == "followFeed" && old.is_some_and(|f| f.value["followed"] == true))
        {
            self.alternative(o, id, "feed", "stale", p["expect"].clone(), head);
            return Ok(());
        }
        if o.kind != "followFeed" {
            ensure(
                old.is_some_and(|f| f.value["followed"] == true),
                "feedNotFollowed",
            )?;
        } else if let Some(old) = old {
            ensure(old.value["url"] == p["url"], "immutableFeedURL")?;
            ensure(p.get("expect").is_some(), "refollowRequiresHead")?;
        }
        let f = self.feeds.entry(id.into()).or_default();
        merge(&mut f.value, o);
        // Entries and response bytes never belong in feed summary values.
        if let Some(v) = f.value.as_object_mut() {
            v.remove("entries");
            v.remove("response");
        }
        match o.kind.as_str() {
            "followFeed" => f.value["followed"] = json!(true),
            "unfollowFeed" => f.value["followed"] = json!(false),
            "refreshFeed" => {
                f.responses.push(p["response"].clone());
                if f.responses.len() > 100 {
                    f.responses.remove(0);
                }
                for e in arr(&p["entries"]) {
                    let mut e = e.clone();
                    e["response"] = p["response"].clone();
                    e["arrival"] = json!(o.clock);
                    f.entries.insert(strv(&e, "id").into(), e);
                }
                let digests: BTreeSet<_> = f.responses.iter().map(|v| strv(v, "digest")).collect();
                f.entries
                    .retain(|_, v| digests.contains(strv(&v["response"], "digest")));
                if f.entries.len() > 5000 {
                    let mut order: Vec<_> = f
                        .entries
                        .iter()
                        .map(|(id, e)| (e["arrival"].as_u64().unwrap_or(0), id.clone()))
                        .collect();
                    order.sort();
                    for (_, id) in order.into_iter().take(f.entries.len() - 5000) {
                        f.entries.remove(&id);
                    }
                }
                f.value["refreshed"] = json!(o.created);
            }
            _ => {}
        }
        Ok(())
    }
    fn review(&mut self, o: &AdmittedOperation) -> Result<()> {
        let p = &o.payload;
        let id = strv(p, "id");
        let action = strv(p, "action");
        let thread = strv(p, "thread");
        ensure(
            !self.review.iter().any(|v| v["id"] == id),
            "reviewIdentityCollision",
        )?;
        if matches!(action, "enable" | "disable") {
            ensure(
                p.get("thread").is_none()
                    && p.get("annotation").is_none()
                    && p.get("undoing").is_none(),
                "reviewSettingsTargets",
            )?;
            self.review_enabled = action == "enable";
        } else {
            let g = self
                .annotations
                .get(thread)
                .ok_or_else(|| Error("threadNotFound".into()))?;
            ensure(
                !g.deleted && self.items[&g.item].value["deleted"] != true,
                "threadDeleted",
            )?;
            match action {
                "revisited" | "passed" => {
                    ensure(
                        g.nodes.contains_key(strv(p, "annotation"))
                            || g.nodes.values().any(|v| v["revision"] == p["annotation"]),
                        "reviewAnnotationMissing",
                    )?;
                    ensure(p.get("undoing").is_none(), "unexpectedUndo")?;
                    self.review_choices.insert(thread.into(), id.into());
                }
                "exclude" | "include" => {
                    ensure(
                        p.get("annotation").is_none() && p.get("undoing").is_none(),
                        "reviewExclusionTargets",
                    )?;
                    if action == "exclude" {
                        self.review_excluded.insert(thread.into());
                    } else {
                        self.review_excluded.remove(thread);
                    }
                }
                "undo" => {
                    let undoing = strv(p, "undoing");
                    let old = self
                        .review
                        .iter()
                        .find(|v| v["id"] == undoing || v["revision"] == undoing)
                        .ok_or_else(|| Error("undoTargetMissing".into()))?;
                    ensure(
                        old["thread"] == thread
                            && ["revisited", "passed"].contains(&strv(old, "action")),
                        "undoTargetMismatch",
                    )?;
                    ensure(
                        self.review_choices
                            .get(thread)
                            .is_some_and(|id| id == strv(old, "id")),
                        "undoNotCurrent",
                    )?;
                    self.review_choices.remove(thread);
                }
                _ => {}
            }
        }
        self.review.push(attributed(o));
        self.review_revision = Some(o.id.clone());
        Ok(())
    }
    fn item_kind(&self, id: &str) -> &'static str {
        if self.source_status(id) == "sourceOnly" {
            return "originalMissing";
        }
        let item = &self.items[id];
        if item.value.get("url").is_some() {
            return "web";
        }
        let source = item
            .selected
            .as_ref()
            .and_then(|id| self.sources.get(id))
            .map(|v| &v["manifest"]);
        match source {
            Some(s) => match strv(s, "mediaType") {
                "application/pdf" => "pdf",
                "message/rfc822" => "email",
                _ => match strv(&s["origin"], "kind") {
                    "web" | "browserExtraction" => "web",
                    "feed" => "feed",
                    _ => match strv(s, "mediaType") {
                        "text/plain" => "text",
                        "text/html" => "htmlFile",
                        _ => "native",
                    },
                },
            },
            None => "native",
        }
    }
    fn source_status(&self, id: &str) -> &'static str {
        if self.item_sources.get(id).is_some_and(|v| !v.is_empty()) {
            "retained"
        } else if self.metadata_items.contains(id) {
            "sourceOnly"
        } else {
            "none"
        }
    }
    fn row(&self, id: &str) -> Option<Value> {
        let i = self.items.get(id)?;
        let v = &i.value;
        let notes = self.note_counts.get(id).copied().unwrap_or(0);
        Some(
            json!({"id":id,"title":v["title"],"creator":v["creator"],"url":v["url"],"kind":self.item_kind(id),"occurrenceKind":if v.get("url").is_some(){"link"}else{"native"},"consumption":v["consumption"],"retention":v["retention"],"added":v["added"],"sequence":i.added,"sortAdded":fold_sort(&i.creation_order),"sortTouched":fold_sort(&(v["clock"].as_u64().unwrap_or(0),strv(v,"author").into(),strv(v,"revision").into())),"sourceStatus":self.source_status(id),"noteCount":notes,"conflictCount":self.conflict_index.get(id).map(Vec::len).unwrap_or(0),"revision":v["revision"],"deleted":v["deleted"]==true,"touched":v["clock"],"tags":v["tags"],"collection":v["collection"]}),
        )
    }
    fn refresh_row(&mut self, id: &str) {
        if let Some(old) = self.rows.remove(id) {
            self.index_row(id, &old, false);
        }
        if let Some(row) = self.row(id) {
            self.index_row(id, &row, true);
            self.rows.insert(id.into(), row);
        }
    }
    fn index_row(&mut self, id: &str, row: &Value, add: bool) {
        let delta = if add { 1 } else { -1 };
        let keys = [
            ("title", "title"),
            ("creator", "creator"),
            ("added", "sortAdded"),
            ("touched", "sortTouched"),
        ]
        .map(|(index, field)| {
            (
                index,
                Arc::new((strv(row, field).to_owned(), id.to_owned())),
            )
        });
        let row_counts = count_row(row);
        for bucket in row_buckets(row) {
            let indexes = self.item_order.entry(bucket.clone()).or_default();
            for (name, key) in &keys {
                if !indexes.contains_key(*name) {
                    indexes.insert((*name).into(), BTreeSet::new());
                }
                let set = indexes.get_mut(*name).expect("initialized sort index");
                if add {
                    set.insert(key.clone());
                } else {
                    set.remove(key);
                }
            }
            let counts = self.bucket_counts.entry(bucket).or_default();
            for (key, n) in &row_counts {
                if let Some(count) = counts.get_mut(*key) {
                    *count += delta * n;
                } else {
                    counts.insert((*key).into(), delta * n);
                }
            }
        }
        let delta = if add { 1 } else { -1 };
        for (key, n) in count_row(row) {
            *self.counts.entry(key.into()).or_default() += delta * n;
        }
    }
}
fn count_row(v: &Value) -> Vec<(&'static str, i64)> {
    let live = v["deleted"] != true;
    let b = |x: bool| i64::from(x);
    vec![
        ("total", b(live)),
        ("readingNow", b(live && shelf_matches(v, "readingNow"))),
        ("unread", b(live && shelf_matches(v, "unread"))),
        ("finished", b(live && shelf_matches(v, "finished"))),
        ("archived", b(live && v["retention"] == "released")),
        ("deleted", b(!live)),
        ("sourceOnly", b(live && v["sourceStatus"] == "sourceOnly")),
        (
            "notes",
            if live {
                v["noteCount"].as_i64().unwrap_or(0)
            } else {
                0
            },
        ),
        ("conflicts", v["conflictCount"].as_i64().unwrap_or(0)),
    ]
}

fn index_key(bucket: &str, sort: &str) -> String {
    format!("{}:{bucket}{sort}", bucket.len())
}
fn row_buckets(row: &Value) -> Vec<String> {
    let mut filters = vec![json!([]).to_string()];
    for key in [
        "consumption",
        "retention",
        "collection",
        "kind",
        "sourceStatus",
    ] {
        let value = if row[key].is_null() && key == "consumption" {
            json!("notStarted")
        } else if row[key].is_null() && key == "retention" {
            json!("saved")
        } else {
            row[key].clone()
        };
        filters.push(json!([key, value]).to_string());
    }
    filters.push(json!(["kind", row["occurrenceKind"]]).to_string());
    for shelf in ["readingNow", "unread", "finished", "archive"] {
        if shelf_matches(row, shelf) {
            filters.push(json!(["shelf", shelf]).to_string());
        }
    }
    for tag in arr(&row["tags"]) {
        filters.push(json!(["tag", tag]).to_string());
    }
    let mut buckets = Vec::new();
    for filter in filters {
        buckets.push(index_key("all", &filter));
        if row["deleted"] != true {
            buckets.push(index_key("live", &filter));
        }
    }
    buckets
}

fn shelf_matches(row: &Value, shelf: &str) -> bool {
    let archived = row["retention"] == "released";
    let finished = row["consumption"] == "completed" || row["consumption"] == "doneEnough";
    match shelf {
        "readingNow" => !archived && row["consumption"] == "inProgress",
        "unread" => !archived && !finished && row["consumption"] != "inProgress",
        "finished" => !archived && finished,
        "archive" => archived,
        _ => true,
    }
}

fn dependency(category: &str, id: &str) -> String {
    json!(["savedDependency", category, id]).to_string()
}
fn dependency_keys(o: &AdmittedOperation) -> Vec<String> {
    let id = strv(&o.payload, "id");
    let mut keys = vec![id.into(), o.id.clone()];
    match o.kind.as_str() {
        "capture" => keys.push(dependency("item", id)),
        "retainSource" | "retainSourceMetadata" => keys.push(dependency("source", id)),
        "keepAnswer" => keys.push(dependency("answer", id)),
        "captureReading" => keys.push(dependency("source", strv(&o.payload["source"], "id"))),
        "attachOriginal" => keys.push(dependency("source", strv(&o.payload["manifest"], "id"))),
        _ => {}
    }
    keys
}

fn fold_sort(order: &(u64, String, String)) -> String {
    format!("{:020}\0{}\0{}", order.0, order.1, order.2)
}

// Adapter for the shared tool validator's intentionally small JSON Schema subset.
// Keep saved-specific semantic validation here, outside the engine and other domains.
pub(crate) fn validate_command_input(kind: &str, input: &Value) -> bool {
    validate::payload(&AdmittedOperation {
        id: String::new(),
        kind: kind.into(),
        author: String::new(),
        author_label: String::new(),
        origin: "person".into(),
        clock: 0,
        created: String::new(),
        payload: input.clone(),
    })
    .is_ok()
}

impl SavedState {
    pub(crate) fn identity_exists(&self, category: &str, id: &str) -> bool {
        match category {
            "item" => self.items.contains_key(id),
            "source" => self.sources.contains_key(id),
            "sourceMetadata" => self.metadata.contains_key(id),
            "image" => self.images.contains_key(id),
            "checkpoint" => self.checkpoints.contains_key(id),
            "annotation" => self.annotations.contains_key(id),
            "view" => self.views.contains_key(id),
            "visibility" => self.visibility.contains_key(id),
            "connection" => self.connections.contains_key(id),
            "feed" => self.feeds.contains_key(id),
            "answer" => self.answers.contains_key(id),
            "subscription" => self.subscriptions.contains_key(id),
            "receipt" => self.receipts.contains_key(id),
            _ => false,
        }
    }
}
