use super::*;
use std::ops::Bound::{Excluded, Unbounded};

fn select(v: &Value, keys: &[&str]) -> Value {
    let mut m = Map::new();
    for k in keys {
        if let Some(v) = v.get(k) {
            m.insert((*k).into(), v.clone());
        }
    }
    Value::Object(m)
}
fn preview(text: &str) -> (String, bool) {
    let end = text.char_indices().nth(240).map_or(text.len(), |(i, _)| i);
    (text[..end].into(), end < text.len())
}
fn outcome(reason: &str) -> Value {
    json!({"outcome":reason})
}
fn id_arg<'a>(a: &'a Value, key: &str) -> Result<&'a str> {
    a[key]
        .as_str()
        .filter(|_| id(&a[key]))
        .ok_or_else(|| Error(format!("invalidArgument: {key}")))
}
#[derive(Serialize, Deserialize)]
struct Cursor {
    namespace: String,
    revision: String,
    query: String,
    args: Value,
    last: Value,
}
struct Paging {
    limit: usize,
    last: Option<Value>,
    args: Value,
}
fn paging(s: &NotesState, name: &str, args: &Value) -> Result<Paging> {
    let default = match name {
        "cells" => 30,
        "proposals" | "contentDetail" => 20,
        _ => 50,
    };
    let limit = match args.get("limit") {
        None => default,
        Some(v) => v
            .as_u64()
            .filter(|n| (1..=100).contains(n))
            .ok_or_else(|| Error("invalidArgument: limit must be 1...100".into()))?
            as usize,
    };
    let mut normalized = args.clone();
    if let Some(o) = normalized.as_object_mut() {
        o.remove("cursor");
        o.remove("limit");
    }
    if name == "notebooks" {
        normalized["archived"] = args.get("archived").cloned().unwrap_or(json!(false));
    }
    let last = if let Some(cursor) = args.get("cursor") {
        let raw = cursor
            .as_str()
            .filter(|s| s.len() <= 16384)
            .ok_or_else(|| Error("invalidArgument: cursor".into()))?;
        let c: Cursor =
            serde_json::from_str(raw).map_err(|_| Error("invalidArgument: cursor".into()))?;
        if c.namespace != "notes" || c.query != name || c.args != normalized {
            return Err(Error("invalidArgument: cursor binding".into()));
        }
        if c.revision != s.prefix {
            return Err(Error("staleCursor".into()));
        }
        Some(c.last)
    } else {
        None
    };
    Ok(Paging {
        limit,
        last,
        args: normalized,
    })
}
fn page<I: Iterator<Item = (Value, Value)>>(
    s: &NotesState,
    name: &str,
    p: &Paging,
    mut values: I,
    total: usize,
) -> Result<Value> {
    let mut rows = vec![];
    let mut size = 0;
    let mut last = Value::Null;
    let mut more = false;
    for (key, value) in values.by_ref() {
        let bytes = serde_json::to_vec(&value)?.len();
        if size + bytes > DETAIL_LIMIT - 32768 || rows.len() == p.limit {
            if rows.is_empty() {
                return Err(Error("contentTooLarge: use a blob/detail adapter".into()));
            }
            more = true;
            break;
        }
        size += bytes;
        last = key;
        rows.push(value);
    }
    let next = if more {
        Some(serde_json::to_string(&Cursor {
            namespace: "notes".into(),
            revision: s.prefix.clone(),
            query: name.into(),
            args: p.args.clone(),
            last,
        })?)
    } else {
        None
    };
    Ok(json!({"rows":rows,"next":next,"total":total}))
}
fn indexed<T, F>(
    s: &NotesState,
    name: &str,
    p: &Paging,
    set: Option<&BTreeSet<T>>,
    f: F,
) -> Result<Value>
where
    T: Ord + Serialize + for<'de> Deserialize<'de>,
    F: Fn(&T) -> Value,
{
    let empty = BTreeSet::new();
    let set = set.unwrap_or(&empty);
    let last: Option<T> = p
        .last
        .clone()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|_| Error("invalidArgument: cursor key".into()))?;
    let range = set.range((last.as_ref().map_or(Unbounded, Excluded), Unbounded));
    page(s, name, p, range.map(|k| (json!(k), f(k))), set.len())
}
fn versions(s: &NotesState, name: &str, p: &Paging, values: &[Value]) -> Result<Value> {
    let start = match &p.last {
        None => 0,
        Some(v) => v
            .as_u64()
            .and_then(|n| usize::try_from(n).ok())
            .and_then(|n| n.checked_add(1))
            .ok_or_else(|| Error("invalidArgument: cursor key".into()))?,
    };
    page(
        s,
        name,
        p,
        values
            .iter()
            .enumerate()
            .skip(start)
            .map(|(i, v)| (json!(i), v.clone())),
        values.len(),
    )
}
fn cell_row(s: &NotesState, id: &str) -> Value {
    let c = &s.cells[id];
    let mut v = select(&c.value, &["id", "kind", "language", "entry", "revision"]);
    let (text, truncated) = preview(string(&c.value, "source"));
    v["sourcePreview"] = json!(text);
    v["truncated"] = json!(truncated);
    v["alternativeCount"] = json!(c.alternatives.len());
    v["outputIsCurrent"] = json!(output_current(s, c));
    if let Some(run) = &c.latest_run {
        v["latestRun"] = json!(run);
    }
    v
}
fn output_current(s: &NotesState, c: &Item) -> bool {
    c.latest_run
        .as_ref()
        .and_then(|id| s.runs.get(id))
        .is_some_and(|r| r["sourceDigest"] == c.source_hash)
}
fn book_row(s: &NotesState, id: &str) -> Value {
    let v = &s.books[id];
    let mut row = select(v, &["id", "title", "kind", "topic", "touched", "revision"]);
    let c = s.book_counts.get(id).cloned().unwrap_or_default();
    row["entryCount"] = json!(c.entries);
    row["cellCount"] = json!(c.cells);
    row
}
fn entry_row(s: &NotesState, id: &str) -> Value {
    let e = &s.entries[id];
    let mut v = select(
        &e.value,
        &["id", "title", "date", "tags", "touched", "revision"],
    );
    v["cellCount"] = json!(s.entry_counts.get(id).map_or(0, |c| c.cells));
    v["alternativeCount"] = json!(e.alternatives.len());
    v
}
fn validate_args(name: &str, args: &Value) -> Result<()> {
    let spec = specs()
        .into_iter()
        .find(|v| v.name == name)
        .ok_or_else(|| Error("invalidArgument: unknown notes query".into()))?;
    if !args.is_object() || !crate::domain::validate_input(&spec.input_schema, args) {
        return Err(Error("invalidArgument: query arguments".into()));
    }
    if args.get("entry").is_some_and(|v| !v.is_null() && !id(v))
        || args
            .get("status")
            .is_some_and(|v| !matches!(v.as_str(), Some("pending" | "kept" | "dismissed")))
    {
        return Err(Error("invalidArgument: query filter".into()));
    }
    if args
        .get("search")
        .is_some_and(|v| v.as_str().is_none_or(|s| s.len() > 512))
    {
        return Err(Error("invalidArgument: search".into()));
    }
    Ok(())
}
pub(super) fn query(s: &NotesState, name: &str, args: &Value) -> Result<Value> {
    if let Err(Error(reason)) = validate_args(name, args) {
        return Ok(json!({"outcome":"invalidArgument","reason":reason}));
    }
    // Compatibility APIs retain their original unwrapped, offset-paged shape.
    if name == "read" {
        return Ok(s.projection());
    }
    if matches!(name, "note" | "notes") {
        if name == "note" {
            let id = id_arg(args, "id")?;
            return Ok(s
                .cells
                .get(id)
                .filter(|c| !is_deleted(&c.value))
                .map(|c| {
                    let mut v = c.value.clone();
                    v["text"] = v["source"].clone();
                    v
                })
                .unwrap_or(Value::Null));
        }
        let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize;
        let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(50) as usize;
        if !(1..=200).contains(&limit) {
            return Err(Error("invalidArgument: limit".into()));
        }
        let mut refs: Vec<_> = s.cells.values().filter(|c| !is_deleted(&c.value)).collect();
        refs.sort_by_key(|c| value_order(&c.value));
        let end = offset.saturating_add(limit).min(refs.len());
        return Ok(
            json!({"items":refs.iter().skip(offset).take(limit).map(|c|{let mut v=c.value.clone();v["text"]=v["source"].clone();v}).collect::<Vec<_>>(),"nextOffset":(end<refs.len()).then_some(end)}),
        );
    }
    let result = inner(s, name, args);
    match result {
        Ok(v) => {
            if v.get("outcome").is_some() {
                return Ok(v);
            }
            let wrapped = json!({"revision":s.prefix,"value":v});
            if serde_json::to_vec(&wrapped)?.len() > DETAIL_LIMIT {
                return Ok(outcome("contentTooLarge"));
            }
            Ok(wrapped)
        }
        Err(Error(reason)) if reason == "staleCursor" => Ok(outcome("staleCursor")),
        Err(Error(reason)) if reason.starts_with("contentTooLarge") => {
            Ok(outcome("contentTooLarge"))
        }
        Err(Error(reason)) => Ok(json!({"outcome":"invalidArgument","reason":reason})),
    }
}
fn inner(s: &NotesState, name: &str, args: &Value) -> Result<Value> {
    let p = paging(s, name, args)?;
    if name == "notebooks" {
        let archived = args["archived"] == true;
        if let Some(search) = args["search"].as_str() {
            // Explicit content search is the only scan; normal sidebar pages use the index.
            let search = search.to_lowercase();
            let set: TouchedIndex = s
                .book_index
                .get(&archived)
                .into_iter()
                .flatten()
                .filter(|(_, id)| {
                    string(&s.books[id], "title")
                        .to_lowercase()
                        .contains(&search)
                })
                .cloned()
                .collect();
            return indexed(s, name, &p, Some(&set), |(_, id)| book_row(s, id));
        }
        return indexed(s, name, &p, s.book_index.get(&archived), |(_, id)| {
            book_row(s, id)
        });
    }
    if name == "noteCounts" {
        return if let Some(book) = args.get("notebook") {
            let book = book
                .as_str()
                .filter(|_| id(book))
                .ok_or_else(|| Error("invalidArgument: notebook".into()))?;
            if !s.books.contains_key(book) {
                Ok(outcome("notFound"))
            } else {
                Ok(json!(s.book_counts.get(book).cloned().unwrap_or_default()))
            }
        } else {
            Ok(json!(s.counts))
        };
    }
    if name == "conflicts" {
        return versions(s, name, &p, &s.conflicts);
    }
    if name == "invalid" {
        return versions(s, name, &p, &s.diagnostics);
    }
    let book = if name == "notebook" {
        id_arg(args, "id")?
    } else {
        id_arg(args, "notebook")?
    };
    let Some(notebook) = s.books.get(book) else {
        return Ok(outcome("notFound"));
    };
    if name == "notebook" {
        let mut v = select(
            notebook,
            &[
                "id",
                "title",
                "kind",
                "topic",
                "archived",
                "revision",
                "orderRevision",
                "extensions",
            ],
        );
        let c = s.book_counts.get(book).cloned().unwrap_or_default();
        v["entryCount"] = json!(c.entries);
        v["cellCount"] = json!(c.cells);
        v["materialCount"] = json!(c.materials);
        return Ok(v);
    }
    match name {
        "entries" => indexed(s, name, &p, s.entry_index.get(book), |(_, id)| {
            entry_row(s, id)
        }),
        "entry" => {
            let id = id_arg(args, "id")?;
            let Some(e) = s.entries.get(id).filter(|e| e.value["notebook"] == book) else {
                return Ok(outcome("notFound"));
            };
            let c = s.entry_counts.get(id).cloned().unwrap_or_default();
            Ok(
                json!({"id":id,"current":select(&e.value,&["title","date","tags","revision","author","authorLabel"]),"cellCount":c.cells,"attachmentCount":c.materials,"proposalCount":s.proposal_index.get(&parent(book,Some(id))).map_or(0,BTreeSet::len),"alternativeCount":e.alternatives.len()}),
            )
        }
        "cells" => {
            let set = if args.get("entry").is_some() {
                s.entry_cells.get(&parent(book, args["entry"].as_str()))
            } else {
                s.order.get(book)
            };
            indexed(s, name, &p, set, |(_, id)| cell_row(s, id))
        }
        "cell" => {
            let id = id_arg(args, "id")?;
            let Some(c) = s.cells.get(id).filter(|c| c.value["notebook"] == book) else {
                return Ok(outcome("notFound"));
            };
            if is_deleted(&c.value) {
                return Ok(json!({"outcome":"deleted","id":id,"revision":c.value["revision"]}));
            }
            let mut v = select(
                &c.value,
                &["kind", "source", "language", "entry", "extensions"],
            );
            v["cell"] = select(
                &c.value,
                &[
                    "id",
                    "notebook",
                    "revision",
                    "author",
                    "authorLabel",
                    "origin",
                    "clock",
                ],
            );
            v["outputIsCurrent"] = json!(output_current(s, c));
            if let Some(run) = &c.latest_run {
                v["latestRun"] = json!(run);
            }
            Ok(v)
        }
        "attachments" => {
            let key = parent(book, args["entry"].as_str());
            // Null means unassigned; the all-parent index includes assigned materials too.
            if args.get("entry") == Some(&Value::Null) {
                return indexed(s, name, &p, s.unassigned_material_index.get(book), |id| {
                    select(
                        &s.attachments[id],
                        &[
                            "id",
                            "role",
                            "name",
                            "mime",
                            "blob",
                            "source",
                            "revision",
                            "authorLabel",
                        ],
                    )
                });
            }
            indexed(s, name, &p, s.material_index.get(&key), |id| {
                select(
                    &s.attachments[id],
                    &[
                        "id",
                        "role",
                        "name",
                        "mime",
                        "blob",
                        "source",
                        "revision",
                        "authorLabel",
                    ],
                )
            })
        }
        "proposals" => {
            let entry = id_arg(args, "entry")?;
            let set = if let Some(status) = args.get("status") {
                s.proposal_status_index
                    .get(&json!([book, entry, status]).to_string())
            } else {
                s.proposal_index.get(&parent(book, Some(entry)))
            };
            indexed(s, name, &p, set, |id| {
                let v = &s.proposals[id];
                let mut r = select(
                    v,
                    &[
                        "id",
                        "title",
                        "revision",
                        "status",
                        "inputCurrent",
                        "reviewRevision",
                        "authorLabel",
                    ],
                );
                let (text, truncated) = preview(string(v, "markdown"));
                r["markdownPreview"] = json!(text);
                r["truncated"] = json!(truncated);
                r
            })
        }
        "contentDetail" => {
            let id = id_arg(args, "id")?;
            let category = string(args, "category");
            let (record, values) = match category {
                "run" | "proposal" => {
                    let map = if category == "run" {
                        &s.runs
                    } else {
                        &s.proposals
                    };
                    let Some(v) = map.get(id).filter(|v| v["notebook"] == book) else {
                        return Ok(outcome("notFound"));
                    };
                    (v.clone(), &[][..])
                }
                "cellConflict" | "entryConflict" | "lateEdit" => {
                    let map = if category == "entryConflict" {
                        &s.entries
                    } else {
                        &s.cells
                    };
                    let Some(i) = map.get(id).filter(|i| i.value["notebook"] == book) else {
                        return Ok(outcome("notFound"));
                    };
                    (
                        Value::Null,
                        if category == "lateEdit" {
                            i.late.as_slice()
                        } else {
                            i.alternatives.as_slice()
                        },
                    )
                }
                _ => return Err(Error("invalidArgument: category".into())),
            };
            Ok(json!({"record":record,"versions":versions(s,name,&p,values)?}))
        }
        _ => Err(Error("invalidArgument: unknown query".into())),
    }
}
pub(super) fn specs() -> Vec<Spec> {
    let definitions = [
        (
            "notebooks",
            "List active or archived notebooks by last effective touch",
            "",
            "archived search cursor limit",
        ),
        ("notebook", "Read one workspace header", "id", ""),
        (
            "entries",
            "List notebook entries by last metadata touch",
            "notebook",
            "cursor limit",
        ),
        ("entry", "Read entry metadata and counts", "notebook id", ""),
        (
            "cells",
            "Read virtual document rows in notebook order; null entry means unassigned",
            "notebook",
            "entry cursor limit",
        ),
        ("cell", "Read one full editor input", "notebook id", ""),
        (
            "attachments",
            "List immutable material descriptors by ID",
            "notebook",
            "entry cursor limit",
        ),
        (
            "proposals",
            "List proposal summaries by ID",
            "notebook entry",
            "status cursor limit",
        ),
        (
            "contentDetail",
            "Read one run/proposal or paged conflict candidates, capped at 1 MiB",
            "notebook category id",
            "cursor limit",
        ),
        (
            "noteCounts",
            "Read maintained badge counters",
            "",
            "notebook",
        ),
        (
            "conflicts",
            "Read the attributed conflict audit",
            "",
            "cursor limit",
        ),
        (
            "invalid",
            "Read invalid operation diagnostics",
            "",
            "cursor limit",
        ),
        (
            "read",
            "Compatibility full projection; use bounded queries for UI",
            "",
            "",
        ),
        ("note", "Compatibility markdown cell lookup", "id", ""),
        (
            "notes",
            "Compatibility flat markdown-cell page",
            "",
            "offset limit",
        ),
    ];
    definitions.into_iter().map(|(name,description,required,optional)|{
        let mut properties=Map::new();for k in required.split_whitespace().chain(optional.split_whitespace()){
            let schema=match k {"limit"=>json!({"type":"integer","minimum":1,"maximum":if name=="notes"{200}else{100}}),"offset"=>json!({"type":"integer","minimum":0}),"archived"=>json!({"type":"boolean","default":false}),"entry" if name!="proposals"=>json!({"type":["string","null"]}),"status"=>json!({"type":"string","enum":["pending","kept","dismissed"]}),"category"=>json!({"type":"string","enum":["run","proposal","cellConflict","entryConflict","lateEdit"]}),_=>json!({"type":"string"})};properties.insert(k.into(),schema);
        }
        Spec{name:name.into(),description:description.into(),input_schema:json!({"type":"object","required":required.split_whitespace().collect::<Vec<_>>(),"properties":properties,"additionalProperties":false})}
    }).collect()
}
