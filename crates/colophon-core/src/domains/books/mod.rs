//! Shelf books, readings, notes, permanent tombstones and attributed alternatives.
//!
//! `apply_with_member_kind` is the deliberately small engine integration seam for loan
//! authorization: the current `OperationView` erases member kind. Ordinary `apply`
//! fails closed for loans rather than trusting a payload or treating servers as devices.
pub mod import;
mod query;
mod specs;
use crate::{
    domain::{AdmittedOperation, DomainModule, Reducer, Spec},
    model::MemberKind,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
pub use specs::validate;
use std::{
    cmp::Reverse,
    collections::{BTreeMap, BTreeSet},
};

type Order = (Reverse<u64>, Reverse<String>, Reverse<String>, String);
fn order(op: &AdmittedOperation, id: &str) -> Order {
    (
        Reverse(op.clock),
        Reverse(op.author.clone()),
        Reverse(op.id.clone()),
        id.into(),
    )
}
fn hash(value: &impl Serialize) -> String {
    // All values here are finite JSON / serializable domain structs.
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or("")
}
fn stamp(v: &mut Value, op: &AdmittedOperation) {
    for (k, x) in [
        ("revision", json!(op.id)),
        ("author", json!(op.author)),
        ("authorLabel", json!(op.author_label)),
        ("origin", json!(op.origin)),
        ("clock", json!(op.clock)),
    ] {
        v[k] = x;
    }
}
fn extensions(v: &mut Value, op: &AdmittedOperation) {
    if !v["extensions"].is_object() {
        v["extensions"] = json!({});
    }
    if let (Some(p), Some((_, defined))) = (op.payload.as_object(), specs::fields(&op.kind)) {
        for (k, x) in p {
            if !defined.contains(&k.as_str()) {
                v["extensions"][k] = x.clone();
            }
        }
    }
}
fn patch(v: &mut Value, p: &Value, keys: &[&str]) {
    for k in keys {
        if let Some(x) = p.get(k) {
            v[*k] = x.clone();
        }
    }
}
fn stale(op: &AdmittedOperation, head: &Value) -> bool {
    op.payload.get("expect").is_some_and(|e| e != head)
}

#[derive(Clone, Serialize, Deserialize)]
struct Book {
    value: Value,
    heads: Value,
    readings: Vec<Value>,
    loan: Option<Value>,
    deleted: bool,
    added: Order,
    creation: Value,
    note_count: usize,
}
impl Book {
    fn current(&self) -> &Value {
        self.readings.last().unwrap_or(&Value::Null)
    }
    fn index_keys(&self) -> Vec<String> {
        let status = s(self.current(), "status");
        let year = year(self.current());
        vec![
            "all".into(),
            format!("status:{status}"),
            format!("year:{year:?}"),
            format!("status:{status}/year:{year:?}"),
        ]
    }
}
fn year(reading: &Value) -> Option<i64> {
    reading["finished"]
        .as_str()
        .and_then(|s| s.get(..4))
        .and_then(|s| s.parse().ok())
}
#[derive(Clone, Serialize, Deserialize)]
struct Note {
    value: Value,
    deleted: bool,
    added: Order,
    creation: Value,
    alternatives: BTreeSet<String>,
}
#[derive(Clone, Serialize, Deserialize)]
struct Conflict {
    book: Option<String>,
    row: Value,
    active: bool,
}
/// Serializable books projection and incrementally maintained collection/count indexes.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct BooksState {
    books: BTreeMap<String, Book>,
    notes: BTreeMap<String, Note>,
    indexes: BTreeMap<String, BTreeSet<Order>>,
    note_index: BTreeMap<String, BTreeSet<Order>>,
    catalog: BTreeMap<String, BTreeSet<String>>,
    by_status: BTreeMap<String, usize>,
    years: BTreeMap<String, usize>,
    conflicts: BTreeMap<String, Vec<Conflict>>,
    conflict_counts: BTreeMap<String, usize>,
    book_conflicts: BTreeMap<String, usize>,
    active_conflicts: usize,
    receipts: BTreeMap<String, Value>,
    invalid: Vec<Value>,
    prefix: String,
}
/// The `reading.books` domain module.
pub struct ReadingBooks;
impl DomainModule for ReadingBooks {
    fn namespace(&self) -> &'static str {
        "reading.books"
    }
    fn display_name(&self) -> &'static str {
        "books"
    }
    fn write_phrase(&self, kind: &str) -> Option<&'static str> {
        Some(match kind {
            "addBook" => "added a book",
            "editBook" => "edited a book",
            "deleteBook" => "removed a book",
            "setPlan" => "updated a reading plan",
            "position" => "updated reading progress",
            "addNote" => "added a book note",
            "editNote" => "edited a book note",
            "resolveNote" => "resolved a book note",
            "deleteNote" => "removed a book note",
            "setCopyLoan" => "updated a copy loan",
            _ => return None,
        })
    }
    fn contribution_names(&self, kind: &str) -> (&'static str, &'static str) {
        if kind.ends_with("Note") {
            ("note", "notes")
        } else {
            ("book", "books")
        }
    }
    fn operations(&self) -> Vec<Spec> {
        specs::operations()
    }
    fn queries(&self) -> Vec<Spec> {
        query::specs()
    }
    fn fold(&self, ops: &[AdmittedOperation]) -> Value {
        let mut state = BooksState::default();
        for op in ops {
            self.apply(&mut state, op);
        }
        state.projection()
    }
}
impl BooksState {
    fn projection(&self) -> Value {
        json!({"books":self.books.iter().map(|(id,b)|(id,json!({"book":b.value,"heads":b.heads,"readings":b.readings,"loan":b.loan,"deleted":b.deleted}))).collect::<BTreeMap<_,_>>(),"notes":self.notes.iter().map(|(id,n)|(id,json!({"note":n.value,"deleted":n.deleted,"alternatives":n.alternatives}))).collect::<BTreeMap<_,_>>(),"conflicts":self.conflicts.iter().map(|(id,c)|(id,c.iter().map(|c|&c.row).collect::<Vec<_>>())).collect::<BTreeMap<_,_>>(),"invalid":self.invalid})
    }
    fn invalid(&mut self, op: &AdmittedOperation, reason: &str) {
        self.invalid
            .push(json!({"operation":op.id,"reason":reason}));
    }
    fn conflict(&mut self, op: &AdmittedOperation, component: &str, found: Value) {
        let id = s(&op.payload, "id");
        let row = json!({"operation":op.id,"component":component,"expected":op.payload.get("expect"),"found":found,"candidate":op.payload,"author":op.author,"authorLabel":op.author_label,"origin":op.origin,"clock":op.clock,"historical":false,"resolved":false});
        let book = if op.kind.ends_with("Note") {
            self.notes
                .get(id)
                .map(|n| s(&n.value, "book").to_owned())
                .or_else(|| op.payload["book"].as_str().map(str::to_owned))
        } else {
            Some(id.to_owned())
        };
        if let Some(parent) = &book {
            *self.book_conflicts.entry(parent.clone()).or_default() += 1;
        }
        self.conflicts.entry(id.into()).or_default().push(Conflict {
            row,
            book,
            active: true,
        });
        *self.conflict_counts.entry(id.into()).or_default() += 1;
        self.active_conflicts += 1;
        if component == "text" {
            if let Some(n) = self.notes.get_mut(id) {
                n.alternatives.insert(op.id.clone());
            }
        }
    }
    fn index(&mut self, id: &str, insert: bool) {
        let Some(b) = self.books.get(id).filter(|b| !b.deleted) else {
            return;
        };
        for k in b.index_keys() {
            let set = self.indexes.entry(k).or_default();
            if insert {
                set.insert(b.added.clone());
            } else {
                set.remove(&b.added);
            }
        }
        let status = s(b.current(), "status").to_owned();
        let count = self.by_status.entry(status.clone()).or_default();
        if insert {
            *count += 1
        } else {
            *count -= 1
        }
        if status == "finished" {
            let count = self
                .years
                .entry(year(b.current()).map_or_else(|| "undated".into(), |y| format!("{y:04}")))
                .or_default();
            if insert {
                *count += 1
            } else {
                *count -= 1
            }
        }
        if let Some(key) = b.value["catalogKey"].as_str() {
            let set = self.catalog.entry(key.into()).or_default();
            if insert {
                set.insert(id.into());
            } else {
                set.remove(id);
            }
        }
    }
    fn activity(&mut self, book: &str, op: &AdmittedOperation) {
        if let Some(b) = self.books.get_mut(book) {
            b.heads["activity"] = json!(op.id);
            stamp(&mut b.value, op);
        }
    }
}
impl ReadingBooks {
    /// Apply with the signer's authenticated grant kind, supplied by the engine, never payload JSON.
    /// Pass `None` if unavailable; `setCopyLoan` then records an invalid diagnostic and has no effect.
    pub fn apply_with_member_kind(
        &self,
        state: &mut BooksState,
        op: &AdmittedOperation,
        kind: Option<MemberKind>,
    ) {
        state.prefix = hash(&(state.prefix.as_str(), op));
        if specs::fields(&op.kind).is_none() {
            return;
        }
        if !validate(&op.kind, &op.payload) {
            state.invalid(op, "invalidPayload");
            return;
        }
        if op.kind == "setCopyLoan" && !matches!(kind, Some(MemberKind::App | MemberKind::Device)) {
            state.invalid(op, "authenticatedAppOrDeviceRequired");
            return;
        }
        let id = s(&op.payload, "id");
        if op.kind.ends_with("Note") {
            self.note(state, op);
            return;
        }
        if op.kind == "addBook" {
            if let Some(b) = state.books.get(id) {
                if !b.deleted && b.creation == op.payload {
                    return;
                }
                state.conflict(op, "metadata", b.heads["metadata"].clone());
                return;
            }
            let mut value = json!({"id":id,"fraction":0,"page":null});
            patch(
                &mut value,
                &op.payload,
                &[
                    "title",
                    "creator",
                    "isbn",
                    "pages",
                    "coverID",
                    "publicationYear",
                    "catalogKey",
                ],
            );
            extensions(&mut value, op);
            stamp(&mut value, op);
            state.books.insert(id.into(),Book{value,heads:json!({"metadata":op.id,"plan":op.id,"progress":null,"loan":null,"activity":op.id}),readings:vec![json!({"id":op.id,"status":"unplanned","started":null,"finished":null,"revision":op.id,"extensions":{}})],loan:None,deleted:false,added:order(op,id),creation:op.payload.clone(),note_count:0});
            state.index(id, true);
            return;
        }
        let component = match op.kind.as_str() {
            "editBook" => "metadata",
            "setPlan" => "plan",
            "position" => "progress",
            "setCopyLoan" => "loan",
            _ => "activity",
        };
        let Some(book) = state.books.get(id) else {
            state.conflict(op, component, Value::Null);
            return;
        };
        if op.kind == "setCopyLoan" && !book.deleted {
            let receipt = hash(&(op.author.as_str(), s(&op.payload, "requestID")));
            if let Some(prior) = state.receipts.get(&receipt) {
                if prior == &logical_loan(&op.payload) {
                    return;
                }
                state.conflict(op, "loan", book.heads["loan"].clone());
                return;
            }
        }
        if book.deleted || stale(op, &book.heads[component]) {
            let head = book.heads[component].clone();
            state.conflict(op, component, head);
            return;
        }
        state.index(id, false);
        if let Some(book) = state.books.get_mut(id) {
            match op.kind.as_str() {
                "editBook" => patch(
                    &mut book.value,
                    &op.payload,
                    &[
                        "title",
                        "creator",
                        "isbn",
                        "pages",
                        "coverID",
                        "publicationYear",
                        "catalogKey",
                    ],
                ),
                "deleteBook" => book.deleted = true,
                "setPlan" => {
                    if op.payload["reread"] == true {
                        book.readings.push(
                            json!({"id":op.id,"started":null,"finished":null,"extensions":{}}),
                        );
                    }
                    if let Some(r) = book.readings.last_mut() {
                        patch(r, &op.payload, &["status", "started", "finished"]);
                        r["revision"] = json!(op.id);
                        extensions(r, op);
                    }
                }
                "position" => {
                    patch(&mut book.value, &op.payload, &["fraction", "page"]);
                }
                "setCopyLoan" => {
                    let mut loan = json!({});
                    patch(
                        &mut loan,
                        &op.payload,
                        &["status", "requestID", "reflection", "proposal"],
                    );
                    extensions(&mut loan, op);
                    stamp(&mut loan, op);
                    book.loan = Some(loan);
                    state.receipts.insert(
                        hash(&(op.author.as_str(), s(&op.payload, "requestID"))),
                        logical_loan(&op.payload),
                    );
                }
                _ => {}
            }
            extensions(&mut book.value, op);
            book.heads[component] = json!(op.id);
        }
        state.activity(id, op);
        state.index(id, true);
    }
    fn note(&self, state: &mut BooksState, op: &AdmittedOperation) {
        let id = s(&op.payload, "id");
        if op.kind == "addNote" {
            if let Some(n) = state.notes.get(id) {
                if !n.deleted
                    && n.creation == op.payload
                    && state
                        .books
                        .get(s(&n.value, "book"))
                        .is_some_and(|b| !b.deleted)
                {
                    return;
                }
                state.conflict(op, "text", n.value["revision"].clone());
                return;
            }
            let parent = s(&op.payload, "book");
            if state.books.get(parent).is_none_or(|b| b.deleted) {
                state.conflict(op, "parent", Value::Null);
                return;
            }
            let mut value = json!({});
            patch(
                &mut value,
                &op.payload,
                &["id", "book", "text", "quote", "location"],
            );
            extensions(&mut value, op);
            stamp(&mut value, op);
            let added = order(op, id);
            state.notes.insert(
                id.into(),
                Note {
                    value,
                    deleted: false,
                    added: added.clone(),
                    creation: op.payload.clone(),
                    alternatives: BTreeSet::new(),
                },
            );
            state
                .note_index
                .entry(parent.into())
                .or_default()
                .insert(added);
            if let Some(b) = state.books.get_mut(parent) {
                b.note_count += 1;
            }
            state.activity(parent, op);
            return;
        }
        let Some(n) = state.notes.get(id) else {
            state.conflict(op, "text", Value::Null);
            return;
        };
        let parent = s(&n.value, "book").to_owned();
        let wrong_set = op.kind == "resolveNote" && op.payload["resolves"] != json!(n.alternatives);
        if n.deleted
            || state.books.get(&parent).is_none_or(|b| b.deleted)
            || stale(op, &n.value["revision"])
            || wrong_set
        {
            state.conflict(op, "text", n.value["revision"].clone());
            return;
        }
        if let Some(n) = state.notes.get_mut(id) {
            if op.kind == "deleteNote" {
                n.deleted = true;
                if let Some(set) = state.note_index.get_mut(&parent) {
                    set.remove(&n.added);
                }
                if let Some(b) = state.books.get_mut(&parent) {
                    b.note_count -= 1;
                }
            } else {
                n.value["text"] = op.payload["text"].clone();
            }
            if op.kind == "resolveNote" {
                if let Some(conflicts) = state.conflicts.get_mut(id) {
                    for c in conflicts {
                        if c.active && n.alternatives.contains(s(&c.row, "operation")) {
                            c.active = false;
                            c.row["resolved"] = json!(true);
                            if let Some(book) = &c.book {
                                if let Some(count) = state.book_conflicts.get_mut(book) {
                                    *count -= 1;
                                }
                            }
                            state.active_conflicts -= 1;
                            if let Some(count) = state.conflict_counts.get_mut(id) {
                                *count -= 1;
                            }
                        }
                    }
                }
                n.alternatives.clear();
            }
            extensions(&mut n.value, op);
            stamp(&mut n.value, op);
        }
        state.activity(&parent, op);
    }
}
fn logical_loan(p: &Value) -> Value {
    let mut p = p.clone();
    if let Some(o) = p.as_object_mut() {
        o.remove("expect");
    }
    p
}
impl Reducer for ReadingBooks {
    type State = BooksState;
    fn apply(&self, state: &mut BooksState, op: &AdmittedOperation) {
        self.apply_with_member_kind(state, op, None)
    }
    fn query(&self, state: &BooksState, name: &str, args: &Value) -> crate::Result<Value> {
        query::query(state, name, args)
    }
}
