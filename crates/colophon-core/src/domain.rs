//! Deterministic domain reducers and generated operation/query specifications.
use crate::model::OperationView;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::BTreeMap, sync::OnceLock};

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
        let mut specs = vec![Spec {
            name: "read".into(),
            description: format!("Read {} (compatibility full view)", self.namespace()),
            input_schema: json!({"type":"object","properties":{},"additionalProperties":false}),
        }];
        let (single, pages): (&[&str], &[&str]) = match self.namespace() {
            "reading.saved" => (&["item"], &["items", "conflicts", "invalid"]),
            // Avoid names already used by write tools (episode and queue).
            "listening.podcasts" => (
                &["show", "getEpisode"],
                &["shows", "episodes", "getQueue", "conflicts", "invalid"],
            ),
            "notes" => (
                &["notebook", "note"],
                &["notebooks", "notes", "conflicts", "invalid"],
            ),
            _ => (&[], &[]),
        };
        for name in single {
            specs.push(spec(
                name,
                "Get one projected object by ID, or null",
                &["id"],
                json!({"id":{"type":"string"}}),
            ));
        }
        for name in pages {
            specs.push(spec(name, "Read a page (default 50, maximum 200); nextOffset is null at the end", &[], json!({"offset":{"type":"integer","minimum":0},"limit":{"type":"integer","minimum":1,"maximum":200}})));
        }
        specs
    }

    /// Fold known kinds, retaining unknown payload fields and ignoring unknown kinds.
    fn fold(&self, operations: &[OperationView]) -> Value;
}
/// Authenticated operation delivered in deterministic admitted order.
pub type AdmittedOperation = OperationView;

/// Incremental domain contract. State contains projections, never an operation journal.
pub trait Reducer: DomainModule {
    /// Serializable, device-local projection state.
    type State: Default + Clone + Serialize + for<'de> Deserialize<'de>;
    /// Apply one admitted operation after the existing prefix.
    fn apply(&self, state: &mut Self::State, operation: &AdmittedOperation);
    /// Read a named projection. Collection queries use offset/limit (default 50, maximum 200).
    fn query(&self, state: &Self::State, name: &str, args: &Value) -> crate::Result<Value>;
}

/// Saved links and their attributed conflicts.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct SavedState {
    items: BTreeMap<String, Value>,
    conflicts: Vec<Value>,
    invalid: Vec<String>,
}
/// Followed shows, episode metadata, progress and the queue.
#[derive(Clone, Serialize, Deserialize)]
pub struct PodcastsState {
    shows: BTreeMap<String, Value>,
    episodes: BTreeMap<String, Value>,
    queue: Value,
    conflicts: Vec<Value>,
    invalid: Vec<String>,
}
impl Default for PodcastsState {
    fn default() -> Self {
        Self {
            shows: BTreeMap::new(),
            episodes: BTreeMap::new(),
            queue: json!({"episodes":[]}),
            conflicts: Vec::new(),
            invalid: Vec::new(),
        }
    }
}
/// Notebook, cell and entry domain types.
pub use crate::domains::notes::{Notes, NotesState};

/// Saved reading shelf.
pub struct ReadingSaved;
/// Followed podcasts, episodes, positions and queue.
pub struct ListeningPodcasts;
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
        let mut state = SavedState::default();
        for op in ops {
            self.apply(&mut state, op);
        }
        state.projection()
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
        let mut state = PodcastsState::default();
        for op in ops {
            self.apply(&mut state, op);
        }
        state.projection()
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
        let specs = operation_specs(module);
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
    let specs = operation_specs(module);
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
        Some("integer") => input.as_u64().is_some(),
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
    if let (Some(max), Some(value)) = (schema["maximum"].as_f64(), input.as_f64()) {
        if value > max {
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
fn ordered(items: &BTreeMap<String, Value>) -> Vec<Value> {
    let mut values: Vec<_> = items.values().cloned().collect();
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

impl SavedState {
    fn projection(&self) -> Value {
        let state = self;
        json!({"items":ordered(&state.items),"conflicts":state.conflicts,"invalid":state.invalid})
    }
}
impl Reducer for ReadingSaved {
    type State = SavedState;
    fn apply(&self, state: &mut Self::State, op: &AdmittedOperation) {
        let SavedState {
            items,
            conflicts,
            invalid,
        } = state;

        if !known_valid(self, op, invalid) {
            return;
        }
        let id = string(&op.payload, "id");
        if op.kind == "capture" {
            create(self, items, id, op, conflicts);
        } else if let Some(item) = items.get_mut(id) {
            if conflict(item, op) || item["deleted"] == true {
                conflicts.push(json!(op));
                return;
            }
            merge(self, item, op);
            if op.kind == "delete" {
                item["deleted"] = json!(true);
            }
        } else {
            invalid.push(op.id.clone());
        }
    }
    fn query(&self, state: &Self::State, name: &str, args: &Value) -> crate::Result<Value> {
        match name {
            "read" => Ok(state.projection()),
            "items" => page_map(&state.items, args),
            "item" => Ok(state
                .items
                .get(required_id(args)?)
                .cloned()
                .unwrap_or(Value::Null)),
            "conflicts" => page_slice(&state.conflicts, args),
            "invalid" => page_slice(&state.invalid, args),
            _ => Err(crate::Error("Unknown query".into())),
        }
    }
}

impl PodcastsState {
    fn projection(&self) -> Value {
        let state = self;
        json!({"shows":ordered(&state.shows),"episodes":ordered(&state.episodes),"queue":state.queue,"conflicts":state.conflicts,"invalid":state.invalid})
    }
}
impl Reducer for ListeningPodcasts {
    type State = PodcastsState;
    fn apply(&self, state: &mut Self::State, op: &AdmittedOperation) {
        let PodcastsState {
            shows,
            episodes,
            queue,
            conflicts,
            invalid,
        } = state;

        if !known_valid(self, op, invalid) {
            return;
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
                if conflict(queue, op) {
                    conflicts.push(json!(op));
                } else {
                    merge(self, queue, op);
                }
            }
            _ => {}
        }
    }
    fn query(&self, state: &Self::State, name: &str, args: &Value) -> crate::Result<Value> {
        match name {
            "read" => Ok(state.projection()),
            "shows" => page_map(&state.shows, args),
            "show" => Ok(state
                .shows
                .get(required_id(args)?)
                .cloned()
                .unwrap_or(Value::Null)),
            "episodes" => page_map(&state.episodes, args),
            "getEpisode" => Ok(state
                .episodes
                .get(required_id(args)?)
                .cloned()
                .unwrap_or(Value::Null)),
            "getQueue" => page_slice(
                state.queue["episodes"]
                    .as_array()
                    .map(Vec::as_slice)
                    .unwrap_or(&[]),
                args,
            ),
            "conflicts" => page_slice(&state.conflicts, args),
            "invalid" => page_slice(&state.invalid, args),
            _ => Err(crate::Error("Unknown query".into())),
        }
    }
}

fn operation_specs(module: &dyn DomainModule) -> &'static [Spec] {
    static SAVED: OnceLock<Vec<Spec>> = OnceLock::new();
    static PODCASTS: OnceLock<Vec<Spec>> = OnceLock::new();
    static NOTES: OnceLock<Vec<Spec>> = OnceLock::new();
    match module.namespace() {
        "reading.saved" => SAVED.get_or_init(|| ReadingSaved.operations()),
        "listening.podcasts" => PODCASTS.get_or_init(|| ListeningPodcasts.operations()),
        "notes" => NOTES.get_or_init(|| Notes.operations()),
        _ => &[],
    }
}
fn required_id(args: &Value) -> crate::Result<&str> {
    args.get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| crate::Error("Query requires string id".into()))
}
fn paging(args: &Value) -> crate::Result<(usize, usize)> {
    let number = |key: &str, default: u64| -> crate::Result<usize> {
        let n = match args.get(key) {
            Some(v) => v
                .as_u64()
                .ok_or_else(|| crate::Error(format!("{key} must be a nonnegative integer")))?,
            None => default,
        };
        usize::try_from(n).map_err(|_| crate::Error("Paging integer too large".into()))
    };
    let offset = number("offset", 0)?;
    let limit = number("limit", 50)?;
    crate::ensure(
        (1..=200).contains(&limit),
        "limit must be between 1 and 200",
    )?;
    Ok((offset, limit))
}
fn page_slice<T: Serialize>(values: &[T], args: &Value) -> crate::Result<Value> {
    let (offset, limit) = paging(args)?;
    let end = offset.saturating_add(limit).min(values.len());
    Ok(
        json!({"items":&values[offset.min(values.len())..end],"nextOffset":(end < values.len()).then_some(end)}),
    )
}
fn page_map(values: &BTreeMap<String, Value>, args: &Value) -> crate::Result<Value> {
    // Only references are sorted; only the requested page is cloned/serialized.
    let mut ordered: Vec<_> = values.values().collect();
    ordered.sort_by_key(|v| {
        (
            v["clock"].as_u64(),
            v["author"].as_str(),
            v["revision"].as_str(),
        )
    });
    page_slice(&ordered, args)
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) enum State {
    Saved(SavedState),
    Podcasts(PodcastsState),
    Notes(NotesState),
    Unknown,
}
impl State {
    pub fn new(namespace: &str) -> Self {
        match namespace {
            "reading.saved" => Self::Saved(SavedState::default()),
            "listening.podcasts" => Self::Podcasts(PodcastsState::default()),
            "notes" => Self::Notes(NotesState::default()),
            _ => Self::Unknown,
        }
    }
    pub fn apply(&mut self, op: &AdmittedOperation) {
        match self {
            Self::Saved(s) => ReadingSaved.apply(s, op),
            Self::Podcasts(s) => ListeningPodcasts.apply(s, op),
            Self::Notes(s) => Notes.apply(s, op),
            Self::Unknown => {}
        }
    }
    pub fn query(&self, name: &str, args: &Value) -> crate::Result<Value> {
        match self {
            Self::Saved(s) => ReadingSaved.query(s, name, args),
            Self::Podcasts(s) => ListeningPodcasts.query(s, name, args),
            Self::Notes(s) => Notes.query(s, name, args),
            Self::Unknown => Ok(json!({})),
        }
    }
}
