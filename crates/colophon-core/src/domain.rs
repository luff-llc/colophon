//! Deterministic domain folds and generated operation/query specifications.
use crate::model::OperationView;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// A portable tool/operation/query description using JSON Schema.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Spec {
    /// Local operation/query name, or fully qualified tool name.
    pub name: String,
    /// Human-readable help.
    pub description: String,
    /// JSON Schema for the input object; unknown fields are retained.
    pub input_schema: Value,
}
/// A domain is pure: fold already-admitted operations in their supplied deterministic order.
pub trait DomainModule {
    /// Stable namespace name.
    fn namespace(&self) -> &'static str;
    /// Human-facing module name used in the library ledger.
    fn display_name(&self) -> &'static str;
    /// Past-tense phrase for a known operation kind.
    fn write_phrase(&self, kind: &str) -> Option<&'static str>;
    /// Singular and plural names for a preserved contribution, grouped by payload ID.
    fn contribution_names(&self, kind: &str) -> (&'static str, &'static str);
    /// Supported operations and their input contracts.
    fn operations(&self) -> Vec<Spec>;
    /// Read-only queries. Every built-in domain exposes `read`.
    fn queries(&self) -> Vec<Spec> {
        vec![Spec {
            name: "read".into(),
            description: format!("Read {}", self.namespace()),
            input_schema: json!({"type":"object","properties":{},"additionalProperties":false}),
        }]
    }
    /// Fold known kinds, retaining unknown payload fields and ignoring unknown kinds.
    fn fold(&self, operations: &[OperationView]) -> Value;
}
/// Saved reading shelf.
pub struct ReadingSaved;
/// Followed podcasts, episodes, positions and queue.
pub struct ListeningPodcasts;
/// Notebooks and attributed notes.
pub struct Notes;
fn spec(name: &str, description: &str, required: &[&str], properties: Value) -> Spec {
    Spec {
        name: name.into(),
        description: description.into(),
        input_schema: json!({"type":"object","required":required,"properties":properties,"additionalProperties":true}),
    }
}
impl DomainModule for ReadingSaved {
    fn display_name(&self) -> &'static str {
        "reading"
    }
    fn write_phrase(&self, kind: &str) -> Option<&'static str> {
        match kind {
            "capture" => Some("saved a link"),
            "setState" => Some("updated reading progress"),
            "editMetadata" => Some("edited a link"),
            "delete" => Some("removed a link"),
            _ => None,
        }
    }
    fn contribution_names(&self, _kind: &str) -> (&'static str, &'static str) {
        ("link", "links")
    }
    fn namespace(&self) -> &'static str {
        "reading.saved"
    }
    fn operations(&self) -> Vec<Spec> {
        vec![
            spec(
                "capture",
                "Save a link to the reading shelf",
                &["id", "url"],
                json!({"id":{"type":"string"},"url":{"type":"string"},"title":{"type":"string"}}),
            ),
            spec(
                "setState",
                "Set a saved item's reading state",
                &["id", "state"],
                json!({"id":{"type":"string"},"state":{"type":"string"},"expect":{"type":"string"}}),
            ),
            spec(
                "editMetadata",
                "Edit a saved item's metadata",
                &["id"],
                json!({"id":{"type":"string"},"title":{"type":"string"},"expect":{"type":"string"}}),
            ),
            spec(
                "delete",
                "Delete a saved item",
                &["id"],
                json!({"id":{"type":"string"},"expect":{"type":"string"}}),
            ),
        ]
    }
    fn fold(&self, ops: &[OperationView]) -> Value {
        let mut items = BTreeMap::new();
        let mut conflicts = Vec::new();
        let mut invalid = Vec::new();
        for op in ops {
            if !known_valid(self, op, &mut invalid) {
                continue;
            }
            let id = string(&op.payload, "id");
            if op.kind == "capture" {
                create(self, &mut items, id, op, &mut conflicts);
            } else if let Some(item) = items.get_mut(id) {
                if conflict(item, op) || item["deleted"] == true {
                    conflicts.push(json!(op));
                    continue;
                }
                merge(self, item, op);
                if op.kind == "delete" {
                    item["deleted"] = json!(true);
                }
            } else {
                invalid.push(op.id.clone());
            }
        }
        json!({"items":ordered(items),"conflicts":conflicts,"invalid":invalid})
    }
}
impl DomainModule for ListeningPodcasts {
    fn display_name(&self) -> &'static str {
        "listening"
    }
    fn write_phrase(&self, kind: &str) -> Option<&'static str> {
        match kind {
            "follow" => Some("followed a show"),
            "unfollow" => Some("unfollowed a show"),
            "episode" => Some("added an episode"),
            "position" => Some("updated playback"),
            "queue" => Some("updated the listening queue"),
            _ => None,
        }
    }
    fn contribution_names(&self, kind: &str) -> (&'static str, &'static str) {
        match kind {
            "follow" | "unfollow" => ("show", "shows"),
            "episode" | "position" => ("episode", "episodes"),
            _ => ("queue update", "queue updates"),
        }
    }
    fn namespace(&self) -> &'static str {
        "listening.podcasts"
    }
    fn operations(&self) -> Vec<Spec> {
        vec![
            spec(
                "follow",
                "Follow a podcast",
                &["id", "url"],
                json!({"id":{"type":"string"},"url":{"type":"string"},"title":{"type":"string"}}),
            ),
            spec(
                "unfollow",
                "Unfollow a podcast",
                &["id"],
                json!({"id":{"type":"string"}}),
            ),
            spec(
                "position",
                "Record episode progress or a deliberate seek",
                &["id", "seconds"],
                json!({"id":{"type":"string"},"seconds":{"type":"number","minimum":0},"seek":{"type":"boolean"},"expect":{"type":"string"}}),
            ),
            spec(
                "queue",
                "Replace the ordered listening queue",
                &["episodes"],
                json!({"episodes":{"type":"array","items":{"type":"string"}},"expect":{"type":"string"}}),
            ),
            spec(
                "episode",
                "Save episode metadata and optional transcript excerpt text",
                &["id"],
                json!({"id":{"type":"string"},"show":{"type":"string"},"title":{"type":"string"},"transcriptExcerpt":{"type":"string"}}),
            ),
        ]
    }
    fn fold(&self, ops: &[OperationView]) -> Value {
        let mut shows = BTreeMap::new();
        let mut episodes: BTreeMap<String, Value> = BTreeMap::new();
        let mut queue = json!({"episodes":[]});
        let mut conflicts = Vec::new();
        let mut invalid = Vec::new();
        for op in ops {
            if !known_valid(self, op, &mut invalid) {
                continue;
            }
            let id = string(&op.payload, "id");
            match op.kind.as_str() {
                "follow" | "unfollow" => {
                    let show = shows.entry(id.to_owned()).or_insert_with(|| json!({}));
                    merge(self, show, op);
                    show["followed"] = json!(op.kind == "follow");
                }
                "episode" => {
                    let episode = episodes.entry(id.to_owned()).or_insert_with(|| json!({}));
                    merge(self, episode, op);
                }
                "position" => {
                    let episode = episodes
                        .entry(id.to_owned())
                        .or_insert_with(|| json!({"id":id}));
                    let ahead = op.payload["seconds"].as_f64().unwrap_or(0.0)
                        >= episode["seconds"].as_f64().unwrap_or(0.0);
                    let saw_position = op.payload["expect"]
                        .as_str()
                        .is_some_and(|s| Some(s) == episode["positionRevision"].as_str());
                    if ahead || op.payload["seek"] == true || saw_position {
                        merge(self, episode, op);
                        episode["positionRevision"] = json!(op.id);
                    }
                }
                "queue" => {
                    if conflict(&queue, op) {
                        conflicts.push(json!(op));
                    } else {
                        merge(self, &mut queue, op);
                    }
                }
                _ => {}
            }
        }
        json!({"shows":ordered(shows),"episodes":ordered(episodes),"queue":queue,"conflicts":conflicts,"invalid":invalid})
    }
}
impl DomainModule for Notes {
    fn display_name(&self) -> &'static str {
        "notes"
    }
    fn write_phrase(&self, kind: &str) -> Option<&'static str> {
        match kind {
            "createNotebook" => Some("started a notebook"),
            "addNote" => Some("added a note"),
            "editNote" => Some("edited a note"),
            _ => None,
        }
    }
    fn contribution_names(&self, kind: &str) -> (&'static str, &'static str) {
        match kind {
            "createNotebook" => ("notebook", "notebooks"),
            _ => ("note", "notes"),
        }
    }
    fn namespace(&self) -> &'static str {
        "notes"
    }
    fn operations(&self) -> Vec<Spec> {
        vec![
            spec(
                "createNotebook",
                "Create a notebook",
                &["id", "title"],
                json!({"id":{"type":"string"},"title":{"type":"string"}}),
            ),
            spec(
                "addNote",
                "Add an attributed note to a notebook",
                &["id", "notebook", "text"],
                json!({"id":{"type":"string"},"notebook":{"type":"string"},"text":{"type":"string"}}),
            ),
            spec(
                "editNote",
                "Edit a note, retaining stale edits as conflicts",
                &["id", "notebook", "text"],
                json!({"id":{"type":"string"},"notebook":{"type":"string"},"text":{"type":"string"},"expect":{"type":"string"}}),
            ),
        ]
    }
    fn fold(&self, ops: &[OperationView]) -> Value {
        let mut notebooks = BTreeMap::new();
        let mut notes: BTreeMap<String, Value> = BTreeMap::new();
        let mut conflicts = Vec::new();
        let mut invalid = Vec::new();
        for op in ops {
            if !known_valid(self, op, &mut invalid) {
                continue;
            }
            let id = string(&op.payload, "id");
            match op.kind.as_str() {
                "createNotebook" => create(self, &mut notebooks, id, op, &mut conflicts),
                "addNote" if notebooks.contains_key(string(&op.payload, "notebook")) => {
                    create(self, &mut notes, id, op, &mut conflicts)
                }
                "editNote" => {
                    if let Some(note) = notes.get_mut(id) {
                        if note["notebook"] != op.payload["notebook"] {
                            invalid.push(op.id.clone());
                        } else if conflict(note, op) {
                            conflicts.push(json!(op));
                        } else {
                            merge(self, note, op);
                        }
                    } else {
                        invalid.push(op.id.clone());
                    }
                }
                _ => invalid.push(op.id.clone()),
            }
        }
        json!({"notebooks":ordered(notebooks),"notes":ordered(notes),"conflicts":conflicts,"invalid":invalid})
    }
}
fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().unwrap_or("")
}
fn conflict(value: &Value, op: &OperationView) -> bool {
    op.payload
        .get("expect")
        .is_some_and(|e| e != &value["revision"])
}
fn create(
    module: &dyn DomainModule,
    items: &mut BTreeMap<String, Value>,
    id: &str,
    op: &OperationView,
    conflicts: &mut Vec<Value>,
) {
    if items.contains_key(id) {
        conflicts.push(json!(op));
    } else {
        let mut value = json!({});
        merge(module, &mut value, op);
        items.insert(id.into(), value);
    }
}
fn merge(module: &dyn DomainModule, value: &mut Value, op: &OperationView) {
    if let (Some(target), Some(payload)) = (value.as_object_mut(), op.payload.as_object()) {
        let specs = module.operations();
        let Some(spec) = specs.iter().find(|spec| spec.name == op.kind) else {
            return;
        };
        for (key, field) in payload {
            if spec.input_schema["properties"].get(key).is_some() {
                // Preconditions and command flags influence the fold, not the stored object.
                if key != "expect" && key != "seek" {
                    target.insert(key.clone(), field.clone());
                }
            } else {
                let extensions = target.entry("extensions").or_insert_with(|| json!({}));
                extensions[key] = field.clone();
            }
        }
        // Reserved projection fields always come from authenticated metadata.
        target.insert("revision".into(), json!(op.id));
        target.insert("author".into(), json!(op.author));
        target.insert("authorLabel".into(), json!(op.author_label));
        target.insert("origin".into(), json!(op.origin));
        target.insert("clock".into(), json!(op.clock));
    }
}
fn known_valid(module: &dyn DomainModule, op: &OperationView, invalid: &mut Vec<String>) -> bool {
    let specs = module.operations();
    let Some(spec) = specs.iter().find(|s| s.name == op.kind) else {
        return false;
    };
    if validate_input(&spec.input_schema, &op.payload) {
        true
    } else {
        invalid.push(op.id.clone());
        false
    }
}
/// Validate the JSON Schema subset used by the built-in tool specs, including nested arrays.
pub fn validate_input(schema: &Value, input: &Value) -> bool {
    let valid_type = match schema["type"].as_str() {
        Some("object") => input.is_object(),
        Some("string") => input.is_string(),
        Some("number") => input.is_number(),
        Some("boolean") => input.is_boolean(),
        Some("array") => input.is_array(),
        _ => true,
    };
    if !valid_type {
        return false;
    }
    if let Some(required) = schema["required"].as_array() {
        for key in required {
            if key.as_str().is_none_or(|k| input.get(k).is_none()) {
                return false;
            }
        }
    }
    if let Some(properties) = schema["properties"].as_object() {
        for (key, s) in properties {
            if let Some(value) = input.get(key) {
                if !validate_input(s, value) {
                    return false;
                }
            }
        }
        if schema["additionalProperties"] == false
            && input
                .as_object()
                .is_some_and(|o| o.keys().any(|k| !properties.contains_key(k)))
        {
            return false;
        }
    }
    if let (Some(min), Some(value)) = (schema["minimum"].as_f64(), input.as_f64()) {
        if value < min {
            return false;
        }
    }
    if let (Some(items), Some(values)) = (schema.get("items"), input.as_array()) {
        if !values.iter().all(|v| validate_input(items, v)) {
            return false;
        }
    }
    true
}
/// Built-in module lookup; unknown namespaces may still store operations but have an empty fold.
pub fn module(namespace: &str) -> Option<Box<dyn DomainModule>> {
    match namespace {
        "reading.saved" => Some(Box::new(ReadingSaved)),
        "listening.podcasts" => Some(Box::new(ListeningPodcasts)),
        "notes" => Some(Box::new(Notes)),
        _ => None,
    }
}
/// All built-in module namespaces.
pub const NAMESPACES: [&str; 3] = ["reading.saved", "listening.podcasts", "notes"];

// Display collection items in the agreed order of their most recent applied operation.
fn ordered(items: BTreeMap<String, Value>) -> Vec<Value> {
    let mut values: Vec<_> = items.into_values().collect();
    values.sort_by(|a, b| {
        (
            a["clock"].as_u64(),
            a["author"].as_str(),
            a["revision"].as_str(),
        )
            .cmp(&(
                b["clock"].as_u64(),
                b["author"].as_str(),
                b["revision"].as_str(),
            ))
    });
    values
}
