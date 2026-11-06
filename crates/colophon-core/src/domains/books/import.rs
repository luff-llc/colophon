//! Pure, ordered 0.1 migration adapter. No legacy kinds enter the 0.2 reducer.
//!
//! The verifier supplies exact signed-body digests and admission outcomes; the host
//! archives source envelopes and persists every evidence entry. Apply returned commands
//! in order as the importer, then call `bind_output` with actual signed destination IDs
//! before importing the next source operation. Planned output keys are NOT operation IDs.
//! Re-evaluating changed source admission requires a fresh source-prefix replay and host
//! reconciliation against native 0.2 edits, never rewriting destination history.
use super::*;

/// A source record authenticated by the 0.1 reader, or an explicitly unresolved entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceOperation {
    /// Original library identifier.
    pub source_library: String,
    /// Original signer (historical claim in the new library).
    pub author_id: String,
    /// Verified source author label.
    pub author_label: String,
    /// Original operation identifier.
    pub operation_id: String,
    /// SHA-256 of exact authenticated signed body, never a plaintext digest.
    pub signed_body_digest: String,
    /// Source kind, including unknown or legacy-journal kinds.
    pub kind: String,
    /// Source version; the old books fold did not inspect it.
    pub version: u64,
    /// Original JSON, retained in evidence even when malformed.
    pub payload: Value,
    /// Deterministic source admitted-order position.
    pub admitted_order: u64,
    /// Original date representation; no guessed Swift Date codec.
    pub claimed_date: Value,
    /// `admitted` only after verification; all other dispositions are evidence-only.
    pub admission: String,
}
/// One proposed 0.2 write; host signs as importer, not the historical author.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportCommand {
    /// Stable transform output key; bind to the actual destination operation ID.
    pub output_key: String,
    /// Stable zero-based child index within the source operation.
    pub child_index: usize,
    /// Clean 0.2 kind.
    pub kind: String,
    /// Clean payload including explicitly historical `importSource` provenance.
    pub payload: Value,
}
/// Immutable sidecar entry. Persist encrypted with the source archive before migration completes.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportEvidence {
    /// Full source tuple and original fields, including signed-body digest purpose.
    pub source: Value,
    /// Disposition, diagnostics, and reviewed historical alternative keys.
    pub disposition: Value,
    /// Stable output keys, later linked to actual output operation IDs by the host.
    pub outputs: Vec<String>,
    /// Destination signed operation IDs indexed by stable output key, filled before persistence.
    pub output_operation_ids: BTreeMap<String, String>,
}
#[derive(Clone, Default, Serialize, Deserialize)]
struct OldBook {
    fraction: Value,
    target: String,
    value: Value,
    revision: String,
    live: bool,
    heads: BTreeMap<String, String>,
}
#[derive(Clone, Default, Serialize, Deserialize)]
struct OldNote {
    target: String,
    parent: String,
    value: Value,
    revision: String,
    live: bool,
    head: Option<String>,
    alternatives: Vec<String>,
    pending: Vec<SourceOperation>,
}
/// Persisted source identity/component maps and idempotency receipts, scoped to source libraries.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct ImportState {
    books: BTreeMap<String, OldBook>,
    notes: BTreeMap<String, OldNote>,
    used_books: BTreeSet<String>,
    used_notes: BTreeSet<String>,
    seen: BTreeSet<String>,
}
impl ImportState {
    /// Reserve existing destination identities before importing, including native objects
    /// and tombstones, so source IDs cannot collide with an existing occurrence.
    pub fn reserve_destination_ids(
        &mut self,
        books: impl IntoIterator<Item = String>,
        notes: impl IntoIterator<Item = String>,
    ) {
        self.used_books.extend(books);
        self.used_notes.extend(notes);
    }

    /// Replace a planned output key with the operation ID returned by the destination signer.
    /// Call after each emitted write; native destination conflicts require host reconciliation.
    pub fn bind_output(&mut self, output_key: &str, operation_id: &str) {
        for b in self.books.values_mut() {
            for h in b.heads.values_mut() {
                if h == output_key {
                    *h = operation_id.into();
                }
            }
        }
        for n in self.notes.values_mut() {
            if n.head.as_deref() == Some(output_key) {
                n.head = Some(operation_id.into());
            }
        }
    }
}
/// Result of one pure import step, including the next persisted context.
#[derive(Clone, Serialize, Deserialize)]
pub struct ImportResult {
    /// Source fold and identity state after this record.
    pub state: ImportState,
    /// Zero or more proposed destination writes in child-index order.
    pub commands: Vec<ImportCommand>,
    /// Every first-seen source entry has one durable disposition, including rejected history.
    pub evidence: Vec<ImportEvidence>,
}
impl ImportResult {
    /// Bind an actual destination ID in pending command expectations, component maps,
    /// and evidence receipts. Invoke after each signed write, before the next command.
    pub fn bind_output(&mut self, output_key: &str, operation_id: &str) {
        self.state.bind_output(output_key, operation_id);
        for command in &mut self.commands {
            if command.payload["expect"] == output_key {
                command.payload["expect"] = json!(operation_id);
            }
            if let Some(revisions) = command.payload["resolves"].as_array_mut() {
                for revision in revisions {
                    if revision == output_key {
                        *revision = json!(operation_id);
                    }
                }
            }
        }
        for evidence in &mut self.evidence {
            if evidence.outputs.iter().any(|key| key == output_key) {
                evidence
                    .output_operation_ids
                    .insert(output_key.into(), operation_id.into());
            }
        }
    }
}

fn identity(library: &str, category: &str, id: &str) -> String {
    hash(&(library, category, id))
}
fn source_key(op: &SourceOperation) -> String {
    hash(&(
        "books-import-v1",
        &op.source_library,
        "reading.books",
        &op.author_id,
        &op.operation_id,
        &op.signed_body_digest,
    ))
}
fn source(op: &SourceOperation) -> Value {
    json!({"sourceLibrary":op.source_library,"namespace":"reading.books","authorID":op.author_id,"authorLabel":op.author_label,"operationID":op.operation_id,"signedBodyDigest":op.signed_body_digest,"digestAlgorithm":"SHA-256","digestPurpose":"exact authenticated signed operation body","kind":op.kind,"version":op.version,"admittedOrder":op.admitted_order,"claimedDate":op.claimed_date,"admission":op.admission,"payload":op.payload,"transformVersion":1,"historical":true})
}
fn lifecycle(
    used: &mut BTreeSet<String>,
    op: &SourceOperation,
    category: &str,
    id: &str,
) -> String {
    let mut target = if specs::valid_id(id) && !used.contains(id) {
        id.into()
    } else {
        format!(
            "import-{}",
            hash(&(&op.source_library, category, id, &op.signed_body_digest))
        )
    };
    let mut collision = 0_u64;
    while used.contains(&target) {
        collision += 1;
        target = format!(
            "import-{}",
            hash(&(
                &op.source_library,
                category,
                id,
                &op.signed_body_digest,
                collision
            ))
        );
    }
    used.insert(target.clone());
    target
}
fn extras(p: &Value, exclude: &[&str]) -> Value {
    Value::Object(
        p.as_object()
            .into_iter()
            .flatten()
            .filter(|(k, _)| !exclude.contains(&k.as_str()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
    )
}
fn emit(
    result: &mut ImportResult,
    op: &SourceOperation,
    kind: &str,
    mut payload: Value,
) -> Option<String> {
    if !validate(kind, &payload) {
        return None;
    }
    let index = result
        .commands
        .iter()
        .filter(|c| {
            c.payload["importSource"]["signedBodyDigest"] == op.signed_body_digest
                && c.payload["importSource"]["operationID"] == op.operation_id
        })
        .count();
    let key = hash(&(source_key(op), index));
    payload["importSource"] = json!({"sourceLibrary":op.source_library,"namespace":"reading.books","authorID":op.author_id,"authorLabel":op.author_label,"operationID":op.operation_id,"signedBodyDigest":op.signed_body_digest,"admittedOrder":op.admitted_order,"childIndex":index,"transformVersion":1,"historical":true});
    result.commands.push(ImportCommand {
        output_key: key.clone(),
        child_index: index,
        kind: kind.into(),
        payload,
    });
    Some(key)
}
fn expect(p: &mut Value, heads: &BTreeMap<String, String>, component: &str) {
    p["expect"] = json!(heads.get(component));
}
fn loan(p: &Value) -> bool {
    p["version"] == 1
        && ["needsReturn", "returned"]
            .iter()
            .any(|s| p["status"] == *s)
        && p.get("reflection")
            .is_none_or(|v| v.is_null() || v.is_string())
        && p.get("requestID")
            .is_none_or(|v| v.is_null() || v.is_string())
        && p.get("provenance").is_none_or(|v| {
            v.is_null()
                || (v.is_object()
                    && v["producerID"].is_string()
                    && v["acceptingUserID"].is_string()
                    && v["confirmedByUser"].is_boolean()
                    && ["sourceQuote", "sourceContext"]
                        .iter()
                        .all(|k| v.get(k).is_none_or(|v| v.is_null() || v.is_string())))
        })
        && (p["status"] != "returned"
            || (p["requestID"].as_str().is_some_and(|s| !s.is_empty())
                && p["provenance"]["confirmedByUser"] == true))
}
/// Transform one verified source operation against its prior source fold, without I/O.
/// Non-admitted records are unresolved evidence and can never produce trusted effects.
/// The source verifier must replay ordered history; catch-up is idempotent by the full tuple.
pub fn transform(prior: &ImportState, op: &SourceOperation) -> ImportResult {
    let mut result = ImportResult {
        state: prior.clone(),
        commands: vec![],
        evidence: vec![],
    };
    let key = source_key(op);
    if !result.state.seen.insert(key) {
        return result;
    }
    let mut disposition = json!({"outcome":"evidenceOnly","diagnostics":[],"historical":true});
    let digest_ok = op.signed_body_digest.len() == 64
        && op
            .signed_body_digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if op.admission != "admitted" || !digest_ok {
        disposition["outcome"] = json!("unresolved");
        disposition["diagnostics"] = json!([
            "Source is not verified admitted history with an exact signed-body SHA-256 digest"
        ]);
    } else {
        map(&mut result, op, &mut disposition);
    }
    if !result.commands.is_empty() {
        disposition["outcome"] = json!("translated");
    }
    result.evidence.push(ImportEvidence {
        source: source(op),
        disposition,
        output_operation_ids: BTreeMap::new(),
        outputs: result
            .commands
            .iter()
            .filter(|c| {
                c.payload["importSource"]["signedBodyDigest"] == op.signed_body_digest
                    && c.payload["importSource"]["operationID"] == op.operation_id
            })
            .map(|c| c.output_key.clone())
            .collect(),
    });
    result
}
fn diagnostic(d: &mut Value, message: &str) {
    if let Some(a) = d["diagnostics"].as_array_mut() {
        a.push(json!(message));
    }
}
fn map(r: &mut ImportResult, op: &SourceOperation, d: &mut Value) {
    let p = &op.payload;
    let is_note = op.kind.starts_with("note.");
    let old_id = if is_note {
        p["note"].as_str()
    } else {
        p["book"].as_str()
    };
    let Some(old_id) = old_id else {
        diagnostic(d, "Malformed or unknown source operation: missing typed ID");
        return;
    };
    let ik = identity(
        &op.source_library,
        if is_note { "note" } else { "book" },
        old_id,
    );
    match op.kind.as_str() {
        "book.add" => {
            if r.state.books.get(&ik).is_some_and(|b| b.live) {
                diagnostic(d, "Ineffective duplicate add");
                return;
            }
            let Some(title) = p["title"].as_str() else {
                diagnostic(d, "Malformed add without title");
                return;
            };
            let target = lifecycle(&mut r.state.used_books, op, "book", old_id);
            let mut clean = extras(
                p,
                &[
                    "book",
                    "title",
                    "author",
                    "isbn",
                    "year",
                    "openLibraryKey",
                    "pages",
                    "coverID",
                ],
            );
            // Unrecognized/legacy extra keys may coincide with clean reserved field names.
            // Preserve them in historical evidence and a nested, unflattened import bag.
            let legacy = clean.clone();
            clean = preserved_extras(&legacy, "addBook");
            clean["id"] = json!(target);
            clean["title"] = json!(title);
            clean["creator"] = json!(p["author"].as_str().unwrap_or(""));
            for (old, new) in [
                ("isbn", "isbn"),
                ("pages", "pages"),
                ("coverID", "coverID"),
                ("year", "publicationYear"),
                ("openLibraryKey", "catalogKey"),
            ] {
                if let Some(v) = p.get(old) {
                    clean[new] = v.clone();
                }
            }
            let mut book = OldBook {
                fraction: json!(0),
                target,
                value: p.clone(),
                revision: op.operation_id.clone(),
                live: true,
                heads: BTreeMap::new(),
            };
            if let Some(h) = emit(r, op, "addBook", clean) {
                for c in ["metadata", "plan", "activity"] {
                    book.heads.insert(c.into(), h.clone());
                }
            } else {
                diagnostic(
                    d,
                    "Old book exists but fails clean validation; retained as unprojectable history",
                );
            }
            r.state.books.insert(ik.clone(), book);
            materialize_pending(r, &ik);
        }
        "book.edit" | "book.remove" | "book.setPlan" | "book.progress" => {
            let Some(mut b) = r.state.books.get(&ik).filter(|b| b.live).cloned() else {
                if op.kind == "book.remove" {
                    for n in r.state.notes.values_mut() {
                        if n.parent == ik {
                            n.live = false;
                        }
                    }
                }
                diagnostic(d, "Ineffective operation on missing source book");
                return;
            };
            let projected = b.heads.contains_key("metadata");
            match op.kind.as_str() {
                "book.edit" => {
                    let mut clean = json!({"id":b.target});
                    let mut changed = false;
                    for (old, new, typed) in [
                        ("title", "title", p["title"].is_string()),
                        ("author", "creator", p["author"].is_string()),
                        ("pages", "pages", p["pages"].as_i64().is_some()),
                    ] {
                        if typed && b.value.get(old) != p.get(old) {
                            clean[new] = p[old].clone();
                            b.value[old] = p[old].clone();
                            changed = true;
                        }
                    }
                    let extra = extras(p, &["book", "title", "author", "isbn", "pages"]);
                    let mut changed_extra = Map::new();
                    for (k, v) in extra.as_object().into_iter().flatten() {
                        if b.value.get(k) != Some(v) {
                            b.value[k] = v.clone();
                            changed_extra.insert(k.clone(), v.clone());
                            changed = true;
                        }
                    }
                    if !changed_extra.is_empty() {
                        let all = extras(&b.value, &["book", "title", "author", "isbn", "pages"]);
                        let preserved = preserved_extras(&all, "editBook");
                        for (k, v) in preserved.as_object().into_iter().flatten() {
                            clean[k] = v.clone();
                        }
                    }
                    // Known metadata extras were merged by the old fold, unlike ignored ISBN.
                    for (old, new) in [
                        ("year", "publicationYear"),
                        ("openLibraryKey", "catalogKey"),
                        ("coverID", "coverID"),
                    ] {
                        if let Some(v) = changed_extra.get(old) {
                            clean[new] = v.clone();
                        }
                    }
                    if changed && projected {
                        expect(&mut clean, &b.heads, "metadata");
                        if let Some(h) = emit(r, op, "editBook", clean) {
                            b.heads.insert("metadata".into(), h.clone());
                            b.heads.insert("activity".into(), h);
                        } else {
                            diagnostic(d, "Metadata changes fail clean validation");
                        }
                    }
                    if let Some(copy) = p.get("copyLoan") {
                        if loan(copy) && projected && changed_extra.contains_key("copyLoan") {
                            let request = copy["requestID"]
                                .as_str()
                                .map(str::to_owned)
                                .unwrap_or_else(|| format!("import-{}", source_key(op)));
                            let mut command = json!({"id":b.target,"status":copy["status"],"requestID":request,"proposal":{"historicalCopyLoan":copy}});
                            patch(&mut command, copy, &["reflection"]);
                            expect(&mut command, &b.heads, "loan");
                            if let Some(h) = emit(r, op, "setCopyLoan", command) {
                                b.heads.insert("loan".into(), h.clone());
                                b.heads.insert("activity".into(), h);
                                diagnostic(d,"Loan requires importer app/device authority; provenance is historical, not another person's confirmation");
                            }
                        } else {
                            diagnostic(d,"Unrecognized or unprojectable copyLoan retained in extensions/evidence");
                        }
                    }
                    if p.get("isbn").is_some() {
                        diagnostic(d, "Ignored source ISBN edit retained only in evidence");
                    }
                }
                "book.remove" => {
                    b.live = false;
                    if projected {
                        let mut command = json!({"id":b.target});
                        expect(&mut command, &b.heads, "activity");
                        if let Some(h) = emit(r, op, "deleteBook", command) {
                            b.heads.insert("activity".into(), h);
                        }
                    }
                    // Swift removes all notes having this source parent, including prior orphans.
                    for n in r.state.notes.values_mut() {
                        if n.parent == identity(&op.source_library, "book", old_id) {
                            n.live = false;
                        }
                    }
                }
                "book.setPlan" => {
                    if !p["status"].is_string() {
                        diagnostic(d, "Malformed plan without string status");
                        return;
                    }
                    if p.get("expect")
                        .is_some_and(|e| !e.is_null() && e != &json!(b.revision))
                    {
                        diagnostic(d, "Stale historical plan alternative");
                        d["component"] = json!("plan");
                        return;
                    }
                    b.revision = op.operation_id.clone();
                    if projected {
                        let mut command = json!({"id":b.target,"status":p["status"],"started":p["started"].as_str(),"finished":p["finished"].as_str(),"reread":p["reread"]==true});
                        expect(&mut command, &b.heads, "plan");
                        if let Some(h) = emit(r, op, "setPlan", command) {
                            b.heads.insert("plan".into(), h.clone());
                            b.heads.insert("activity".into(), h);
                        } else {
                            diagnostic(d,"Unknown status or invalid historical day retained without coercion");
                        }
                    }
                    if p.get("intent").is_some() {
                        diagnostic(d, "Ignored intent is historical provenance only");
                    }
                }
                _ => {
                    if p["fraction"].is_number() {
                        b.fraction = p["fraction"].clone();
                    }
                    let page = if p["page"].as_i64().is_some() {
                        p["page"].clone()
                    } else {
                        Value::Null
                    };
                    let command = json!({"id":b.target,"fraction":b.fraction,"page":page});
                    if projected {
                        if let Some(h) = emit(r, op, "position", command) {
                            b.heads.insert("progress".into(), h.clone());
                            b.heads.insert("activity".into(), h);
                        } else {
                            diagnostic(
                                d,
                                "Historical progress fails clean numeric bounds; never clamped",
                            );
                        }
                    }
                }
            }
            if !projected {
                diagnostic(d, "Source parent has no projected clean occurrence");
            }
            r.state.books.insert(ik, b);
        }
        "note.add" => {
            if r.state.notes.get(&ik).is_some_and(|n| n.live) {
                diagnostic(d, "Ineffective duplicate note");
                return;
            }
            let (Some(parent), Some(_)) = (p["book"].as_str(), p["text"].as_str()) else {
                diagnostic(d, "Malformed note add");
                return;
            };
            let parent = identity(&op.source_library, "book", parent);
            let target = lifecycle(&mut r.state.used_notes, op, "note", old_id);
            let mut n = OldNote {
                target,
                value: p.clone(),
                parent: parent.clone(),
                revision: op.operation_id.clone(),
                live: true,
                head: None,
                alternatives: vec![],
                pending: vec![op.clone()],
            };
            if let Some(b) = r
                .state
                .books
                .get(&parent)
                .filter(|b| b.live && b.heads.contains_key("metadata"))
            {
                let mut command = json!({"id":n.target,"book":b.target,"text":p["text"]});
                for k in ["quote", "location"] {
                    if p[k].is_string() {
                        command[k] = p[k].clone();
                    }
                }
                n.head = emit(r, op, "addNote", command);
                if n.head.is_some() {
                    n.pending.clear();
                } else {
                    diagnostic(
                        d,
                        "Historical note fails clean validation; original retained in evidence",
                    );
                }
                if let Some(h) = &n.head {
                    if let Some(b) = r.state.books.get_mut(&parent) {
                        b.heads.insert("activity".into(), h.clone());
                    }
                }
            } else {
                d["outcome"] = json!("pending");
                diagnostic(d,"Orphan note pending source parent; replay/reconcile this evidence when parent is available");
            }
            r.state.notes.insert(ik, n);
        }
        "note.edit" | "note.resolve" | "note.delete" => {
            let Some(mut n) = r.state.notes.get(&ik).filter(|n| n.live).cloned() else {
                diagnostic(d, "Ineffective operation on missing source note");
                return;
            };
            let previous_head = n.head.clone();
            if op.kind == "note.delete" {
                n.live = false;
                if let Some(head) = &n.head {
                    let command = json!({"id":n.target,"expect":head});
                    if let Some(h) = emit(r, op, "deleteNote", command) {
                        n.head = Some(h);
                    }
                }
            } else {
                if !p["text"].is_string() {
                    diagnostic(d, "Malformed text mutation");
                    return;
                }
                if p["expect"].as_str().is_some_and(|e| e != n.revision) {
                    n.alternatives.push(source_key(op));
                    d["component"] = json!("text");
                    d["candidate"] = p.clone();
                    d["expected"] = p["expect"].clone();
                    d["found"] = json!(n.revision);
                    diagnostic(
                        d,
                        "Stale historical text alternative with full source attribution",
                    );
                } else {
                    n.value["text"] = p["text"].clone();
                    n.revision = op.operation_id.clone();
                    let resolve = op.kind == "note.resolve";
                    if resolve {
                        d["resolvesEvidence"] = json!(n.alternatives);
                        n.alternatives.clear();
                    }
                    if let Some(head) = &n.head {
                        let mut command = json!({"id":n.target,"text":p["text"],"expect":head});
                        if resolve {
                            command["resolves"] = json!([]);
                            command["importReviewedAlternatives"] = d["resolvesEvidence"].clone();
                        }
                        if let Some(h) = emit(
                            r,
                            op,
                            if resolve { "resolveNote" } else { "editNote" },
                            command,
                        ) {
                            n.head = Some(h);
                        } else {
                            diagnostic(d, "Historical note text exceeds clean validation limits");
                        }
                    } else {
                        n.pending.push(op.clone());
                        diagnostic(
                            d,
                            "Pending or unprojectable source note; text retained in evidence",
                        );
                    }
                }
            }
            if n.head != previous_head {
                if let Some(h) = &n.head {
                    if let Some(b) = r.state.books.get_mut(&n.parent) {
                        b.heads.insert("activity".into(), h.clone());
                    }
                }
            }
            r.state.notes.insert(ik, n);
        }
        _ => diagnostic(
            d,
            "Unknown kind or legacy journal opcode requires a separate adapter",
        ),
    }
}

// Keep unknown fields at their original extension keys. A legacy field that would
// accidentally become a new command property is retained in an unflattened bag.
fn preserved_extras(extras: &Value, kind: &str) -> Value {
    let mut value = json!({});
    let mut collisions = Map::new();
    let defined = specs::fields(kind).map(|(_, d)| d).unwrap_or(&[]);
    for (k, v) in extras.as_object().into_iter().flatten() {
        if defined.contains(&k.as_str()) || k == "importSource" || k == "legacyExtras" {
            collisions.insert(k.clone(), v.clone());
        } else {
            value[k] = v.clone();
        }
    }
    if !collisions.is_empty() {
        value["legacyExtras"] = Value::Object(collisions);
    }
    value
}
// Pending orphan records become clean writes only once their real source parent
// has a projected live occurrence. Earlier stale edits remain sidecar alternatives.
fn materialize_pending(r: &mut ImportResult, parent: &str) {
    let Some(b) = r
        .state
        .books
        .get(parent)
        .filter(|b| b.live && b.heads.contains_key("metadata"))
    else {
        return;
    };
    let book = b.target.clone();
    let mut pending = r
        .state
        .notes
        .iter()
        .filter(|(_, n)| n.live && n.parent == parent && n.head.is_none())
        .map(|(k, _)| k.clone())
        .collect::<Vec<_>>();
    pending.sort_by_key(|key| {
        r.state.notes[key].pending.first().map(|op| {
            (
                op.admitted_order,
                op.author_id.clone(),
                op.operation_id.clone(),
            )
        })
    });
    for key in pending {
        let Some(mut n) = r.state.notes.get(&key).cloned() else {
            continue;
        };
        let mut remaining = vec![];
        for source_op in &n.pending {
            let mut payload = json!({"id":n.target,"text":source_op.payload["text"]});
            let kind = if source_op.kind == "note.add" {
                payload["book"] = json!(book);
                for k in ["quote", "location"] {
                    if source_op.payload[k].is_string() {
                        payload[k] = source_op.payload[k].clone();
                    }
                }
                "addNote"
            } else if let Some(head) = &n.head {
                payload["expect"] = json!(head);
                if source_op.kind == "note.resolve" {
                    payload["resolves"] = json!([]);
                    "resolveNote"
                } else {
                    "editNote"
                }
            } else {
                remaining.push(source_op.clone());
                continue;
            };
            if let Some(h) = emit(r, source_op, kind, payload) {
                r.evidence.push(ImportEvidence{source:source(source_op),disposition:json!({"outcome":"pendingMaterialized","historical":true,"diagnostics":[]}),outputs:vec![h.clone()],output_operation_ids:BTreeMap::new()});
                n.head = Some(h.clone());
                if let Some(b) = r.state.books.get_mut(parent) {
                    b.heads.insert("activity".into(), h);
                }
            } else {
                remaining.push(source_op.clone());
            }
        }
        n.pending = remaining;
        r.state.notes.insert(key, n);
    }
}
