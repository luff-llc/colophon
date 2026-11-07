//! Deterministic domain reducers and generated operation/query specifications.
use crate::domains::books::{BooksState, ReadingBooks};
use crate::model::OperationView;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

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

/// Followed podcasts, episodes, positions and queue.
pub use crate::domains::listening::{ListeningPodcasts, PodcastsState};
/// Notebook, cell and entry domain types.
pub use crate::domains::notes::{Notes, NotesState};
/// Saved reading shelf and its attributed state.
pub use crate::domains::saved::{ReadingSaved, SavedState};

fn spec(name: &str, description: &str, required: &[&str], properties: Value) -> Spec {
    Spec {
        name: name.into(),
        description: description.into(),
        input_schema: json!({"type":"object","required":required,"properties":properties,"additionalProperties":true}),
    }
}
/// Validate the JSON Schema subset used by the built-in tool specs, including nested arrays.
pub fn validate_input(schema: &Value, input: &Value) -> bool {
    if let Some(kind) = schema["x-colophon-books-kind"].as_str() {
        return crate::domains::books::validate(kind, input);
    }
    if let Some(kind) = schema["x-colophon-saved-command"].as_str() {
        return crate::domains::saved::validate_command_input(kind, input);
    }
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
        "reading.books" => Some(Box::new(ReadingBooks)),
        "reading.saved" => Some(Box::new(ReadingSaved)),
        "listening.podcasts" => Some(Box::new(ListeningPodcasts)),
        "notes" => Some(Box::new(Notes)),
        _ => None,
    }
}
/// All built-in module namespaces.
pub const NAMESPACES: [&str; 4] = [
    "reading.saved",
    "listening.podcasts",
    "notes",
    "reading.books",
];

// Authenticated local-cache generation for the complete built-in reducer registry.
// Increment on any projection schema or reducer semantic change, even if serde can decode it.
pub(crate) const REDUCER_SCHEMA: u32 = 5;

#[derive(Clone, Serialize, Deserialize)]
pub(crate) enum ProjectionState {
    Books(Box<BooksState>),
    Saved(Box<SavedState>),
    Podcasts(Box<PodcastsState>),
    Notes(NotesState),
    Unknown,
}
impl ProjectionState {
    pub fn new(namespace: &str) -> Self {
        match namespace {
            "reading.books" => Self::Books(Box::default()),
            "reading.saved" => Self::Saved(Box::default()),
            "listening.podcasts" => Self::Podcasts(Box::default()),
            "notes" => Self::Notes(NotesState::default()),
            _ => Self::Unknown,
        }
    }
    pub(crate) fn identity_exists(&self, category: &str, id: &str) -> bool {
        match self {
            Self::Books(s) => s.identity_exists(category, id),
            Self::Saved(s) => s.identity_exists(category, id),
            Self::Podcasts(s) => s.identity_exists(category, id),
            Self::Notes(s) => s.identity_exists(category, id),
            Self::Unknown => false,
        }
    }
    /// Authenticated role context comes only from the verified authority chain.
    pub fn apply_with_context(
        &mut self,
        op: &AdmittedOperation,
        context: &AuthorContext,
        baseline: bool,
    ) {
        let kind = Some(context.kind);
        match self {
            Self::Books(s) => ReadingBooks.apply_with_member_kind(s, op, kind),
            Self::Saved(s) => ReadingSaved.apply(s, op),
            Self::Podcasts(s) => ListeningPodcasts.apply_with_context(
                s,
                op,
                crate::domains::listening::ApplyContext {
                    member_kind: kind,
                    imported_baseline: baseline,
                },
            ),
            Self::Notes(s) => Notes.apply_with_member_kind(s, op, kind),
            Self::Unknown => {}
        }
    }
    pub fn query(&self, name: &str, args: &Value) -> crate::Result<Value> {
        match self {
            Self::Books(s) => ReadingBooks.query(s, name, args),
            Self::Saved(s) => ReadingSaved.query(s, name, args),
            Self::Podcasts(s) => ListeningPodcasts.query(s, name, args),
            Self::Notes(s) => Notes.query(s, name, args),
            Self::Unknown => Ok(json!({})),
        }
    }
}

/// Authority-derived reducer identity. Never constructed from operation payload fields.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthorContext {
    /// Authenticated member kind.
    pub kind: crate::model::MemberKind,
    /// Destination library authenticated by the operation header.
    pub library: String,
    /// Immutable approved grant; absent only for an admitted root identity.
    pub grant: Option<crate::model::Grant>,
    /// Whether this identity was enrolled as a root (admission separately checks its tenure).
    pub root: bool,
}
impl AuthorContext {
    pub(crate) fn from_member(member: &crate::model::Member, library: &str) -> Self {
        Self {
            library: library.into(),
            kind: member.kind,
            grant: member.grant.clone(),
            root: member.grant.is_none(),
        }
    }
}
/// Role fence used before signing, in tool filtering and during authenticated replay.
pub fn role_allows(namespace: &str, kind: &str, member: crate::model::MemberKind) -> bool {
    if matches!(
        member,
        crate::model::MemberKind::App | crate::model::MemberKind::Device
    ) {
        return true;
    }
    if matches!(kind, "colophon.blobPublish" | "colophon.blobReference") {
        return true;
    }
    if kind == "colophon.resolveHistorical" {
        return matches!(
            member,
            crate::model::MemberKind::App | crate::model::MemberKind::Device
        );
    }
    let protected = match namespace {
        "reading.books" => kind == "setCopyLoan",
        "notes" => kind == "reviewProposal",
        "reading.saved" => {
            crate::domains::saved::protected_kind(kind)
                && module(namespace).is_some_and(|m| m.operations().iter().any(|s| s.name == kind))
        }
        _ => false,
    };
    !protected
        || matches!(
            member,
            crate::model::MemberKind::App | crate::model::MemberKind::Device
        )
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct State {
    pub(crate) projection: ProjectionState,
    sidecar: crate::imports::ImportState,
}
impl State {
    pub fn new(namespace: &str) -> Self {
        Self {
            projection: ProjectionState::new(namespace),
            sidecar: crate::imports::ImportState::new(namespace),
        }
    }
    pub fn apply_with_context(&mut self, op: &AdmittedOperation, context: Option<&AuthorContext>) {
        let Some(context) = context else { return };
        self.sidecar.apply(&mut self.projection, op, context);
    }
    pub fn query(&self, name: &str, args: &Value) -> crate::Result<Value> {
        if let Some(value) = self.sidecar.query(name, args, &self.projection)? {
            return Ok(value);
        }
        self.projection.query(name, args)
    }
    pub(crate) fn validate_import(&self, payload: &Value) -> crate::Result<()> {
        self.sidecar
            .validate_batch(payload, &self.projection)
            .map(|_| ())
    }
}
