//! Notebook, cell, entry, material and proposal reducers. No I/O or code execution.
//! `apply_with_member_kind` is the explicit engine seam for the review role fence.
use crate::{
    domain::{AdmittedOperation, DomainModule, Reducer, Spec},
    model::MemberKind,
    Error, Result,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::{
    cmp::Reverse,
    collections::{BTreeMap, BTreeSet},
    sync::OnceLock,
};

/// Pure translation of verified 0.1 history and immutable migration evidence.
pub mod import;
mod query;
mod validation;
pub use validation::validate_payload;
use validation::*;

type Order = (u64, String, String);
type TouchedIndex = BTreeSet<(Reverse<Order>, String)>;
type Position = Vec<u32>;
type Sequence = BTreeSet<(Position, String)>;

#[derive(Clone, Default, Serialize, Deserialize)]
struct Item {
    value: Value,
    alternatives: Vec<Value>,
    late: Vec<Value>,
    position: Position,
    latest_run: Option<String>,
    source_hash: String,
}
#[derive(Clone, Default, Serialize, Deserialize)]
struct Counts {
    notebooks: usize,
    archived: usize,
    entries: usize,
    cells: usize,
    materials: usize,
    #[serde(rename = "pendingProposals")]
    pending: usize,
    conflicts: usize,
    #[serde(rename = "lateEdits")]
    late: usize,
}
/// Serializable projection and maintained parent, sequence, touched and count indexes.
/// The required format marker deliberately rejects old flat-note checkpoint states.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NotesState(Box<NotesData>);

impl std::ops::Deref for NotesState {
    type Target = NotesData;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
/// Internal projection layout, exposed only as the dereference target of `NotesState`.
#[doc(hidden)]
#[derive(Clone, Serialize, Deserialize)]
pub struct NotesData {
    format: String,
    prefix: String,
    books: BTreeMap<String, Value>,
    cells: BTreeMap<String, Item>,
    entries: BTreeMap<String, Item>,
    runs: BTreeMap<String, Value>,
    attachments: BTreeMap<String, Value>,
    proposals: BTreeMap<String, Value>,
    book_index: BTreeMap<bool, TouchedIndex>,
    entry_index: BTreeMap<String, TouchedIndex>,
    order: BTreeMap<String, Sequence>,
    entry_cells: BTreeMap<String, Sequence>,
    material_index: BTreeMap<String, BTreeSet<String>>,
    proposal_index: BTreeMap<String, BTreeSet<String>>,
    proposal_status_index: BTreeMap<String, BTreeSet<String>>,
    proposal_creation_extensions: BTreeMap<String, Value>,
    unassigned_material_index: BTreeMap<String, BTreeSet<String>>,
    counts: Counts,
    book_counts: BTreeMap<String, Counts>,
    entry_counts: BTreeMap<String, Counts>,
    conflicts: Vec<Value>,
    invalid: Vec<String>,
    diagnostics: Vec<Value>,
}
impl Default for NotesData {
    fn default() -> Self {
        Self {
            format: "notes/cells/1".into(),
            prefix: hash(b"colophon/notes-prefix/1"),
            books: BTreeMap::new(),
            cells: BTreeMap::new(),
            entries: BTreeMap::new(),
            runs: BTreeMap::new(),
            attachments: BTreeMap::new(),
            proposals: BTreeMap::new(),
            book_index: BTreeMap::new(),
            entry_index: BTreeMap::new(),
            order: BTreeMap::new(),
            entry_cells: BTreeMap::new(),
            material_index: BTreeMap::new(),
            proposal_index: BTreeMap::new(),
            proposal_status_index: BTreeMap::new(),
            proposal_creation_extensions: BTreeMap::new(),
            unassigned_material_index: BTreeMap::new(),
            counts: Counts::default(),
            book_counts: BTreeMap::new(),
            entry_counts: BTreeMap::new(),
            conflicts: vec![],
            invalid: vec![],
            diagnostics: vec![],
        }
    }
}
/// The `notes` domain; preview names remain explicit markdown-cell aliases.
pub struct Notes;
fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn string<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or("")
}
fn order(op: &AdmittedOperation) -> Order {
    (op.clock, op.author.clone(), op.id.clone())
}
fn value_order(v: &Value) -> Order {
    (
        v["clock"].as_u64().unwrap_or(0),
        string(v, "author").into(),
        string(v, "revision").into(),
    )
}
fn parent(book: &str, entry: Option<&str>) -> String {
    json!([book, entry]).to_string()
}
fn entry_key(v: &Value) -> String {
    parent(string(v, "notebook"), v["entry"].as_str())
}
fn is_deleted(v: &Value) -> bool {
    v["deleted"] == true
}
fn stale(v: &Value, p: &Value, required: bool) -> bool {
    match p.get("expect") {
        Some(expect) => expect != &v["revision"],
        None => required && !v.is_null(),
    }
}
fn attribute(v: &mut Value, op: &AdmittedOperation) {
    v["revision"] = json!(op.id);
    v["author"] = json!(op.author);
    v["authorLabel"] = json!(op.author_label);
    v["origin"] = json!(op.origin);
    v["clock"] = json!(op.clock);
}
fn data(v: &Value) -> Value {
    let mut result = v.clone();
    if let Some(m) = result.as_object_mut() {
        for k in ["revision", "author", "authorLabel", "origin", "clock"] {
            m.remove(k);
        }
    }
    result
}
fn project(base: &Value, op: &AdmittedOperation) -> Value {
    let mut result = if base.is_object() {
        base.clone()
    } else {
        json!({"extensions":{}})
    };
    let Some(spec) = specs().iter().find(|s| s.name == op.kind) else {
        return result;
    };
    if let Some(p) = op.payload.as_object() {
        for (key, value) in p {
            if spec.input_schema["properties"].get(key).is_some() {
                if !["expect", "resolves", "after"].contains(&key.as_str()) {
                    result[key] = value.clone();
                }
            } else {
                result["extensions"][key] = value.clone();
            }
        }
    }
    if matches!(op.kind.as_str(), "putEntry" | "resolveEntry") {
        for key in ["title", "date"] {
            result[key] = op.payload[key].clone();
        }
        result["tags"] = op.payload.get("tags").cloned().unwrap_or(json!([]));
    }
    for key in ["blob", "source"] {
        if result[key].is_object() {
            let fields: &[&str] = if key == "blob" {
                &["digest", "size", "mediaType"]
            } else {
                &[
                    "kind",
                    "url",
                    "library",
                    "namespace",
                    "artifact",
                    "revision",
                    "quote",
                    "page",
                    "seconds",
                    "recording",
                ]
            };
            // Only normalize fresh descriptors; avoid repeatedly nesting an existing bag.
            if op.payload.get(key).is_some() {
                normalize_nested(&mut result[key], fields);
            }
        }
    }
    if op.kind == "recordOutput" {
        if let Some(outputs) = result["outputs"].as_array_mut() {
            for output in outputs {
                normalize_nested(output, &["mime", "text", "blob"]);
                if output["blob"].is_object() {
                    normalize_nested(&mut output["blob"], &["digest", "size", "mediaType"]);
                }
            }
        }
    }
    attribute(&mut result, op);
    result
}
fn candidate(base: &Value, op: &AdmittedOperation, component: &str, found: Value) -> Value {
    let mut value = project(base, op);
    if op.kind == "deleteCell" {
        value["deleted"] = json!(true);
    }
    let mut result = json!({"id":op.payload["id"],"component":component,"candidate":value,"expected":op.payload["expect"],"found":found,"historical":false,"kind":op.kind,"payload":op.payload});
    attribute(&mut result, op);
    result
}
fn exact_alternatives(item: &Item, p: &Value) -> bool {
    let wanted: BTreeSet<_> = item
        .alternatives
        .iter()
        .map(|v| string(v, "revision"))
        .collect();
    let supplied: BTreeSet<_> = p["resolves"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    wanted == supplied
}
fn between(left: Option<&Position>, right: Option<&Position>) -> Position {
    // Leave billions of slots at the ends: common append/prepend must not grow keys.
    match (left, right) {
        (None, None) => return vec![u32::MAX / 2],
        (Some(a), None) if a[0] < u32::MAX - 1 => return vec![a[0] + 1],
        (None, Some(b)) if b[0] > 1 => return vec![b[0] - 1],
        _ => {}
    }
    let mut result = vec![];
    let mut i = 0;
    let mut upper_open = false;
    loop {
        let a = left.and_then(|p| p.get(i)).copied().unwrap_or(0);
        let b = if upper_open {
            u32::MAX
        } else {
            right.and_then(|p| p.get(i)).copied().unwrap_or(u32::MAX)
        };
        if b > a + 1 {
            result.push(b - 1);
            return result;
        }
        result.push(a);
        if b > a {
            upper_open = true;
        }
        i += 1;
    }
}
impl NotesData {
    fn invalid(&mut self, op: &AdmittedOperation, reason: &str) {
        self.invalid.push(op.id.clone());
        self.diagnostics.push(json!({"id":op.id,"reason":reason}));
    }
    fn touch(&mut self, book: &str, op: &AdmittedOperation) {
        if let Some(v) = self.books.get_mut(book) {
            let archived = v["archived"] == true;
            let old: Order = serde_json::from_value(v["touched"].clone()).unwrap_or_default();
            self.book_index
                .entry(archived)
                .or_default()
                .remove(&(Reverse(old), book.into()));
            v["touched"] = json!(order(op));
            self.book_index
                .entry(archived)
                .or_default()
                .insert((Reverse(order(op)), book.into()));
        }
    }
    fn count(&mut self, book: &str, entry: Option<&str>, f: impl Fn(&mut Counts)) {
        f(&mut self.counts);
        f(self.book_counts.entry(book.into()).or_default());
        if let Some(entry) = entry {
            f(self.entry_counts.entry(entry.into()).or_default());
        }
    }
    fn conflict(&mut self, book: &str, v: Value) {
        self.conflicts.push(v);
        self.count(book, None, |c| c.conflicts += 1);
    }
    fn position(&self, book: &str, after: Option<&str>) -> Position {
        let sequence = self.order.get(book);
        let left = after
            .and_then(|id| self.cells.get(id))
            .filter(|c| !is_deleted(&c.value) && c.value["notebook"] == book)
            .map(|c| &c.position);
        let right = sequence
            .and_then(|s| match left {
                Some(p) => s
                    .range((
                        std::ops::Bound::Excluded((p.clone(), after.unwrap_or("").into())),
                        std::ops::Bound::Unbounded,
                    ))
                    .next(),
                None => s.first(),
            })
            .map(|(p, _)| p);
        between(left, right)
    }
    fn remove_position(&mut self, id: &str, item: &Item) {
        if let Some(s) = self.order.get_mut(string(&item.value, "notebook")) {
            s.remove(&(item.position.clone(), id.into()));
        }
        if let Some(s) = self.entry_cells.get_mut(&entry_key(&item.value)) {
            s.remove(&(item.position.clone(), id.into()));
        }
    }
    fn insert_position(&mut self, id: &str, item: &Item) {
        self.order
            .entry(string(&item.value, "notebook").into())
            .or_default()
            .insert((item.position.clone(), id.into()));
        self.entry_cells
            .entry(entry_key(&item.value))
            .or_default()
            .insert((item.position.clone(), id.into()));
    }
    fn inputs(&self, book: &str, entry: &str) -> Option<Value> {
        let mut inputs = Map::new();
        if let Some(cells) = self.entry_cells.get(&parent(book, Some(entry))) {
            for (_, id) in cells {
                let cell = self.cells.get(id)?;
                if !cell.alternatives.is_empty() {
                    return None;
                }
                inputs.insert(id.clone(), cell.value["revision"].clone());
            }
        }
        Some(Value::Object(inputs))
    }
    fn refresh_proposals(&mut self, book: &str, entry: Option<&str>) {
        let Some(entry) = entry else { return };
        let key = parent(book, Some(entry));
        if self.proposal_index.get(&key).is_none_or(BTreeSet::is_empty) {
            return;
        }
        let inputs = self.inputs(book, entry);
        if let Some(ids) = self.proposal_index.get(&key) {
            for id in ids {
                if let Some(v) = self.proposals.get_mut(id) {
                    v["inputCurrent"] = json!(inputs.as_ref() == Some(&v["inputs"]));
                }
            }
        }
    }
    fn projection(&self) -> Value {
        let mut notes: Vec<_> = self
            .cells
            .values()
            .filter(|c| !is_deleted(&c.value))
            .map(|c| {
                let mut v = c.value.clone();
                v["text"] = v["source"].clone();
                v
            })
            .collect();
        notes.sort_by_key(value_order);
        let mut books: Vec<_> = self.books.values().cloned().collect();
        books.sort_by_key(value_order);
        json!({"notebooks":books,"notes":notes,"cells":self.cells.values().map(|c|&c.value).collect::<Vec<_>>(),"entries":self.entries.values().map(|c|&c.value).collect::<Vec<_>>(),"attachments":self.attachments.values().collect::<Vec<_>>(),"runs":self.runs.values().collect::<Vec<_>>(),"proposals":self.proposals.values().collect::<Vec<_>>(),"conflicts":self.conflicts,"invalid":self.invalid})
    }
}
impl DomainModule for Notes {
    fn namespace(&self) -> &'static str {
        "notes"
    }
    fn display_name(&self) -> &'static str {
        "notes"
    }
    fn write_phrase(&self, kind: &str) -> Option<&'static str> {
        match kind {
            "createNotebook" => Some("started a notebook"),
            "addNote" => Some("added a note"),
            "editNote" => Some("edited a note"),
            "renameNotebook" => Some("renamed a notebook"),
            "archiveNotebook" => Some("changed notebook archival"),
            "putCell" => Some("saved a cell"),
            "resolveCell" => Some("resolved a cell"),
            "moveCell" => Some("moved a cell"),
            "deleteCell" => Some("deleted a cell"),
            "recordOutput" => Some("recorded cell output"),
            "putEntry" => Some("saved an entry"),
            "resolveEntry" => Some("resolved an entry"),
            "addAttachment" => Some("added material"),
            "proposeEntry" => Some("proposed entry organization"),
            "reviewProposal" => Some("reviewed a proposal"),
            _ => None,
        }
    }
    fn contribution_names(&self, kind: &str) -> (&'static str, &'static str) {
        match kind {
            "createNotebook" | "renameNotebook" | "archiveNotebook" => ("notebook", "notebooks"),
            "putEntry" | "resolveEntry" => ("entry", "entries"),
            "addAttachment" => ("attachment", "attachments"),
            "recordOutput" => ("run", "runs"),
            "proposeEntry" | "reviewProposal" => ("proposal", "proposals"),
            _ => ("note", "notes"),
        }
    }
    fn operations(&self) -> Vec<Spec> {
        specs().to_vec()
    }
    fn queries(&self) -> Vec<Spec> {
        query::specs()
    }
    fn fold(&self, ops: &[AdmittedOperation]) -> Value {
        let mut s = NotesState::default();
        for op in ops {
            self.apply(&mut s, op);
        }
        s.projection()
    }
}
impl Reducer for Notes {
    type State = NotesState;
    fn apply(&self, s: &mut NotesState, op: &AdmittedOperation) {
        self.apply_with_member_kind(s, op, None);
    }
    fn query(&self, s: &NotesState, name: &str, args: &Value) -> Result<Value> {
        query::query(s, name, args)
    }
}
impl Notes {
    /// Apply with a member kind obtained from verified authority, never from payload claims.
    /// The current engine calls `Reducer::apply`, so reviews fail closed until it supplies this.
    pub fn apply_with_member_kind(
        &self,
        s: &mut NotesState,
        original: &AdmittedOperation,
        member_kind: Option<MemberKind>,
    ) {
        let s = s.0.as_mut();
        s.prefix = hash(format!("{}{}", s.prefix, json!(original)).as_bytes());
        if !specs().iter().any(|v| v.name == original.kind) {
            return;
        }
        if !validate_payload(&original.kind, &original.payload) {
            s.invalid(original, "invalidPayload");
            return;
        }
        let mut normalized;
        let op = if matches!(original.kind.as_str(), "addNote" | "editNote") {
            let old = s.cells.get(string(&original.payload, "id"));
            if original.kind == "editNote" && old.is_none() {
                s.invalid(original, "notFound");
                return;
            }
            normalized = original.clone();
            normalized.kind = "putCell".into();
            // Build from the alias schema so extras cannot become canonical cell fields.
            normalized.payload = json!({"id":original.payload["id"],"notebook":original.payload["notebook"],"kind":"markdown","source":original.payload["text"]});
            if original.kind == "addNote" {
                normalized.payload["expect"] = Value::Null;
            } else if let Some(expect) = original.payload.get("expect") {
                normalized.payload["expect"] = expect.clone();
            }
            &normalized
        } else {
            original
        };
        let p = &op.payload;
        let id = string(p, "id");
        let book = if matches!(
            op.kind.as_str(),
            "createNotebook" | "renameNotebook" | "archiveNotebook"
        ) {
            id
        } else {
            string(p, "notebook")
        };
        if op.kind == "createNotebook" {
            if let Some(old) = s.books.get(id) {
                s.conflict(
                    book,
                    candidate(old, op, "notebook", old["revision"].clone()),
                );
                return;
            }
            let mut v = project(&Value::Null, op);
            v["kind"] = p.get("kind").cloned().unwrap_or(json!("notebook"));
            v["archived"] = json!(false);
            v["orderRevision"] = Value::Null;
            v["touched"] = json!(order(op));
            s.books.insert(id.into(), v);
            s.book_index
                .entry(false)
                .or_default()
                .insert((Reverse(order(op)), id.into()));
            s.count(book, None, |c| c.notebooks += 1);
            return;
        }
        if !s.books.contains_key(book) {
            s.invalid(op, "notebookNotFound");
            return;
        }
        if matches!(op.kind.as_str(), "renameNotebook" | "archiveNotebook") {
            let old = &s.books[book];
            if stale(old, p, false) {
                s.conflict(
                    book,
                    candidate(old, op, "notebook", old["revision"].clone()),
                );
                return;
            }
            let v = project(old, op);
            if data(&v) == data(old) {
                return;
            }
            let was = old["archived"] == true;
            let now = v["archived"] == true;
            if was != now {
                let touched = serde_json::from_value(old["touched"].clone()).unwrap_or_default();
                s.book_index
                    .entry(was)
                    .or_default()
                    .remove(&(Reverse(touched), book.into()));
                s.count(book, None, |c| {
                    if now {
                        c.archived += 1
                    } else {
                        c.archived -= 1
                    }
                });
            }
            s.books.insert(book.into(), v);
            s.touch(book, op);
            return;
        }
        // Validate all parent ownership before touching any index.
        let target = match op.kind.as_str() {
            "putCell" | "resolveCell" | "moveCell" | "deleteCell" => {
                s.cells.get(id).map(|i| &i.value)
            }
            "putEntry" | "resolveEntry" => s.entries.get(id).map(|i| &i.value),
            "recordOutput" => s.cells.get(string(p, "cell")).map(|i| &i.value),
            "reviewProposal" => s.proposals.get(id),
            _ => None,
        };
        if target.is_some_and(|v| v["notebook"] != book) {
            s.invalid(op, "immutableNotebook");
            return;
        }
        if let Some(entry) = p["entry"].as_str() {
            if s.entries
                .get(entry)
                .is_none_or(|e| e.value["notebook"] != book)
            {
                s.invalid(op, "entryNotFound");
                return;
            }
        }
        match op.kind.as_str() {
            "putCell" | "resolveCell" | "deleteCell" | "moveCell" => {
                let existing = s.cells.get(id);
                if existing.is_none() && matches!(op.kind.as_str(), "resolveCell" | "moveCell") {
                    s.invalid(op, "cellNotFound");
                    return;
                }
                let mut item = existing.cloned().unwrap_or_default();
                let head = if op.kind == "moveCell" {
                    s.books[book]["orderRevision"].clone()
                } else {
                    item.value["revision"].clone()
                };
                let resolution_bad = op.kind == "resolveCell" && !exact_alternatives(&item, p);
                let stale = p.get("expect").is_some_and(|e| e != &head);
                if is_deleted(&item.value) || stale || resolution_bad {
                    let component = if is_deleted(&item.value) {
                        "lateEdit"
                    } else if op.kind == "moveCell" {
                        "order"
                    } else {
                        "cell"
                    };
                    let mut v = candidate(&item.value, op, component, head);
                    if original.kind != op.kind {
                        merge_alias_extras(&mut v["candidate"], original);
                    }
                    if is_deleted(&item.value) {
                        item.late.push(v.clone());
                        s.count(book, None, |c| c.late += 1);
                    } else if op.kind != "moveCell" {
                        item.alternatives.push(v.clone());
                    }
                    s.conflict(book, v);
                    if item.value.is_null() {
                        return;
                    }
                    let entry = item.value["entry"].as_str().map(str::to_owned);
                    s.cells.insert(id.into(), item);
                    s.refresh_proposals(book, entry.as_deref());
                    return;
                }
                let before = item.value.clone();
                let old_entry = before["entry"].as_str().map(str::to_owned);
                if op.kind == "moveCell" {
                    let previous = s
                        .order
                        .get(book)
                        .and_then(|seq| {
                            seq.range(..(item.position.clone(), id.to_owned()))
                                .next_back()
                        })
                        .map(|(_, id)| id.as_str());
                    let anchor = p["after"].as_str().filter(|id| {
                        s.cells
                            .get(*id)
                            .is_some_and(|c| !is_deleted(&c.value) && c.value["notebook"] == book)
                    });
                    if previous == anchor {
                        let before = item.value.clone();
                        merge_extensions_only(&mut item.value, op);
                        if item.value != before {
                            s.cells.insert(id.into(), item);
                            s.touch(book, op);
                        }
                        return;
                    }
                    // Remove before anchor lookup. Self anchors have already been rejected.
                    s.remove_position(id, &item);
                    let position = s.position(book, p["after"].as_str());
                    if position == item.position {
                        s.insert_position(id, &item);
                        return;
                    }
                    item.position = position;
                    merge_extensions_only(&mut item.value, op);
                    s.insert_position(id, &item);
                    s.cells.insert(id.into(), item);
                    if let Some(v) = s.books.get_mut(book) {
                        v["orderRevision"] = json!(op.id);
                    }
                    s.touch(book, op);
                    return;
                }
                if op.kind == "deleteCell" {
                    if !before.is_null() {
                        s.remove_position(id, &item);
                        s.count(book, old_entry.as_deref(), |c| c.cells -= 1);
                    }
                    item.value = project(&before, op);
                    item.value["deleted"] = json!(true);
                    if !before.is_null() {
                        if let Some(v) = s.books.get_mut(book) {
                            v["orderRevision"] = json!(op.id);
                        }
                    }
                } else {
                    item.value = project(&before, op);
                    if original.kind != op.kind {
                        merge_alias_extras(&mut item.value, original);
                    }
                    if data(&before) == data(&item.value)
                        && (op.kind != "resolveCell" || item.alternatives.is_empty())
                    {
                        return;
                    }
                    if op.kind == "resolveCell" {
                        let cleared = item.alternatives.len();
                        item.alternatives.clear();
                        s.count(book, None, |c| c.conflicts -= cleared);
                    }
                    item.source_hash = hash(string(&item.value, "source").as_bytes());
                    let new_entry = item.value["entry"].as_str();
                    if before.is_null() {
                        item.position = s.position(book, p["after"].as_str());
                        s.count(book, new_entry, |c| c.cells += 1);
                        if let Some(v) = s.books.get_mut(book) {
                            v["orderRevision"] = json!(op.id);
                        }
                    } else {
                        s.remove_position(id, &item);
                        if old_entry.as_deref() != new_entry {
                            if let Some(old) = old_entry.as_deref() {
                                s.entry_counts.entry(old.into()).or_default().cells -= 1;
                            }
                            if let Some(new) = new_entry {
                                s.entry_counts.entry(new.into()).or_default().cells += 1;
                            }
                        }
                    }
                    // remove_position must use old membership when it changed.
                    if let Some(seq) = s.entry_cells.get_mut(&entry_key(&before)) {
                        seq.remove(&(item.position.clone(), id.into()));
                    }
                    s.insert_position(id, &item);
                }
                let new_entry = item.value["entry"].as_str().map(str::to_owned);
                s.cells.insert(id.into(), item);
                s.touch(book, op);
                s.refresh_proposals(book, old_entry.as_deref());
                s.refresh_proposals(book, new_entry.as_deref());
            }
            "putEntry" | "resolveEntry" => {
                let old = s.entries.get(id);
                if old.is_none() && op.kind == "resolveEntry" {
                    s.invalid(op, "entryNotFound");
                    return;
                }
                let mut item = old.cloned().unwrap_or_default();
                if stale(&item.value, p, true)
                    || (op.kind == "resolveEntry" && !exact_alternatives(&item, p))
                {
                    let v = candidate(&item.value, op, "entry", item.value["revision"].clone());
                    item.alternatives.push(v.clone());
                    s.conflict(book, v);
                    if !item.value.is_null() {
                        s.entries.insert(id.into(), item);
                    }
                    return;
                }
                let before = item.value.clone();
                let v = project(&before, op);
                if data(&v) == data(&before)
                    && (op.kind != "resolveEntry" || item.alternatives.is_empty())
                {
                    return;
                }
                if !before.is_null() {
                    let previous =
                        serde_json::from_value(before["touched"].clone()).unwrap_or_default();
                    s.entry_index
                        .entry(book.into())
                        .or_default()
                        .remove(&(Reverse(previous), id.into()));
                } else {
                    s.count(book, None, |c| c.entries += 1);
                }
                item.value = v;
                item.value["touched"] = json!(order(op));
                if op.kind == "resolveEntry" {
                    let cleared = item.alternatives.len();
                    item.alternatives.clear();
                    s.count(book, None, |c| c.conflicts -= cleared);
                }
                s.entry_index
                    .entry(book.into())
                    .or_default()
                    .insert((Reverse(order(op)), id.into()));
                s.entries.insert(id.into(), item);
                s.touch(book, op);
            }
            "recordOutput" | "addAttachment" | "proposeEntry" => {
                let mut v = project(&Value::Null, op);
                if op.kind == "proposeEntry" {
                    v["tags"] = p.get("tags").cloned().unwrap_or(json!([]));
                }
                let old = match op.kind.as_str() {
                    "recordOutput" => s.runs.get(id),
                    "addAttachment" => s.attachments.get(id),
                    _ => s.proposals.get(id),
                };
                if let Some(old) = old {
                    let mut logical = data(old);
                    if let Some(o) = logical.as_object_mut() {
                        for key in [
                            "status",
                            "inputCurrent",
                            "reviewRevision",
                            "reviewedMarkdown",
                            "reviewer",
                            "reviewerLabel",
                            "reviewKeep",
                            "reviewExtensions",
                        ] {
                            o.remove(key);
                        }
                    }
                    if op.kind == "proposeEntry" {
                        logical["extensions"] = s
                            .proposal_creation_extensions
                            .get(id)
                            .cloned()
                            .unwrap_or(json!({}));
                    }
                    if logical == data(&v) && old["author"] == op.author {
                        return;
                    }
                    s.invalid(op, "immutableIDReuse");
                    return;
                }
                if op.kind == "recordOutput" {
                    let Some(cell) = s.cells.get_mut(string(p, "cell")) else {
                        s.invalid(op, "cellNotFound");
                        return;
                    };
                    cell.latest_run = Some(id.into());
                    s.runs.insert(id.into(), v);
                } else if op.kind == "addAttachment" {
                    s.material_index
                        .entry(parent(book, None))
                        .or_default()
                        .insert(id.into());
                    if let Some(entry) = p["entry"].as_str() {
                        s.material_index
                            .entry(parent(book, Some(entry)))
                            .or_default()
                            .insert(id.into());
                    }
                    if p["entry"].is_null() {
                        s.unassigned_material_index
                            .entry(book.into())
                            .or_default()
                            .insert(id.into());
                    }
                    s.count(book, p["entry"].as_str(), |c| c.materials += 1);
                    s.attachments.insert(id.into(), v);
                } else {
                    if s.inputs(book, string(p, "entry")).as_ref() != Some(&p["inputs"]) {
                        s.invalid(op, "inputsNotCurrent");
                        return;
                    }
                    v["status"] = json!("pending");
                    v["inputCurrent"] = json!(true);
                    s.proposal_index
                        .entry(parent(book, p["entry"].as_str()))
                        .or_default()
                        .insert(id.into());
                    s.proposal_status_index
                        .entry(json!([book, p["entry"], "pending"]).to_string())
                        .or_default()
                        .insert(id.into());
                    s.count(book, p["entry"].as_str(), |c| c.pending += 1);
                    s.proposal_creation_extensions
                        .insert(id.into(), v["extensions"].clone());
                    s.proposals.insert(id.into(), v);
                }
                s.touch(book, op);
            }
            "reviewProposal" => {
                if !matches!(member_kind, Some(MemberKind::App | MemberKind::Device)) {
                    s.invalid(op, "authenticatedAppOrDeviceRequired");
                    return;
                }
                let Some(old) = s.proposals.get(id) else {
                    s.invalid(op, "proposalNotFound");
                    return;
                };
                if old["status"] != "pending" {
                    if old["reviewer"] == op.author
                        && old["reviewKeep"] == p["keep"]
                        && old["reviewedMarkdown"] == p["markdown"]
                    {
                        return;
                    }
                    s.conflict(
                        book,
                        candidate(old, op, "proposal", old["reviewRevision"].clone()),
                    );
                    return;
                }
                if stale(old, p, false) || (p["keep"] == true && old["inputCurrent"] != true) {
                    s.conflict(
                        book,
                        candidate(old, op, "proposal", old["revision"].clone()),
                    );
                    return;
                }
                let mut v = old.clone();
                v["status"] = json!(if p["keep"] == true {
                    "kept"
                } else {
                    "dismissed"
                });
                v["reviewRevision"] = json!(op.id);
                v["reviewer"] = json!(op.author);
                v["reviewerLabel"] = json!(op.author_label);
                v["reviewKeep"] = p["keep"].clone();
                v["reviewedMarkdown"] = p["markdown"].clone();
                merge_extensions_only(&mut v, op);
                s.proposal_status_index
                    .entry(json!([book, v["entry"], "pending"]).to_string())
                    .or_default()
                    .remove(id);
                s.proposal_status_index
                    .entry(json!([book, v["entry"], v["status"]]).to_string())
                    .or_default()
                    .insert(id.into());
                s.count(book, v["entry"].as_str(), |c| c.pending -= 1);
                s.proposals.insert(id.into(), v);
                s.touch(book, op);
            }
            _ => {}
        }
    }
}
fn merge_extensions_only(value: &mut Value, op: &AdmittedOperation) {
    let extras = project(&Value::Null, op)["extensions"].clone();
    if let Some(o) = extras.as_object() {
        for (k, v) in o {
            value["extensions"][k] = v.clone();
        }
    }
}
fn merge_alias_extras(value: &mut Value, op: &AdmittedOperation) {
    merge_extensions_only(value, op);
}
