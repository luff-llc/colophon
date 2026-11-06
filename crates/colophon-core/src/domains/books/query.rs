use super::*;
use std::ops::Bound::{Excluded, Unbounded};
const CAP: usize = 1024 * 1024;
const PREVIEW: usize = 512;
pub(super) fn specs() -> Vec<Spec> {
    ["read","books","book","bookCounts","bookNotes","note","readings","catalogMembership","conflicts","invalid"].into_iter().map(|name|{
        let mut props=json!({});let mut required=vec![];
        if ["books","bookNotes","readings","conflicts","invalid"].contains(&name){props=json!({"cursor":{"type":"string"},"limit":{"type":"integer","minimum":1,"maximum":100,"default":50}});}
        match name {
            "books"=>{props["status"]=json!({"type":"string","enum":specs::STATUSES});props["finishedYear"]=json!({"type":["integer","null"],"minimum":1,"maximum":9999});props["search"]=json!({"type":"string","maxLength":4096});},
            "book"|"note"=>{props["id"]=json!({"type":"string","minLength":1,"maxLength":1024});required.push("id");},
            "bookNotes"|"readings"=>{props["book"]=json!({"type":"string","minLength":1,"maxLength":1024});required.push("book");if name=="bookNotes"{props["order"]=json!({"type":"string","enum":["oldest","newest"],"default":"newest"});}},
            "conflicts"=>{props["object"]=json!({"type":"string","minLength":1,"maxLength":1024});required.push("object");},
            "catalogMembership"=>{props["keys"]=json!({"type":"array","maxItems":100,"items":{"type":"string","maxLength":4096}});required.push("keys");},
            _=>{},
        }
        Spec{name:name.into(),description:match name{"books"=>"Page books by immutable addition order, newest first; explicit null year selects undated","book"=>"Book detail and component heads without notes or reading history","bookCounts"=>"Maintained shelf status, finished-year and conflict counts","bookNotes"=>"Bounded note previews for one book","note"=>"Full note editor value without alternatives","readings"=>"Reading history, newest first","catalogMembership"=>"Batch catalog membership, at most 100 keys and IDs per key","conflicts"=>"Attributed alternatives and retained conflict history for one object","invalid"=>"Page invalid operation diagnostics",_=>"Compatibility full projection; use bounded queries for UI"}.into(),input_schema:json!({"type":"object","properties":props,"required":required,"additionalProperties":false})}
    }).collect()
}
fn failure(reason: &str) -> Value {
    json!({"ok":false,"reason":reason})
}
fn normalize(name: &str, args: &Value) -> Option<Value> {
    let spec = specs().into_iter().find(|s| s.name == name)?;
    let obj = args.as_object()?;
    if obj
        .keys()
        .any(|k| spec.input_schema["properties"].get(k).is_none())
    {
        return None;
    }
    for k in spec.input_schema["required"].as_array()? {
        args.get(k.as_str()?)?;
    }
    let mut a = args.clone();
    for (k, v) in obj {
        let valid = match k.as_str() {
            "id" | "book" | "object" => v.as_str().is_some_and(specs::valid_id),
            "limit" => v.as_u64().is_some_and(|n| (1..=100).contains(&n)),
            "cursor" => v.as_str().is_some_and(|s| s.len() <= 65536),
            "status" => v.as_str().is_some_and(|s| specs::STATUSES.contains(&s)),
            "finishedYear" => v.is_null() || v.as_u64().is_some_and(|n| (1..=9999).contains(&n)),
            "search" => v.as_str().is_some_and(|s| s.len() <= 4096),
            "order" => v == "oldest" || v == "newest",
            "keys" => v.as_array().is_some_and(|a| {
                a.len() <= 100
                    && a.iter()
                        .all(|v| v.as_str().is_some_and(|s| s.len() <= 4096))
            }),
            _ => false,
        };
        if !valid {
            return None;
        }
    }
    a.as_object_mut()?.remove("cursor");
    if spec.input_schema["properties"].get("limit").is_some() && a.get("limit").is_none() {
        a["limit"] = json!(50);
    }
    if name == "bookNotes" && a.get("order").is_none() {
        a["order"] = json!("newest");
    }
    if name == "books" && a.get("search").is_none() {
        a["search"] = json!("");
    }
    Some(a)
}
struct Page<'a> {
    state: &'a BooksState,
    name: &'a str,
    args: Value,
    after: Option<Value>,
    limit: usize,
}
impl Page<'_> {
    fn collect(&self, iter: impl Iterator<Item = (Value, Value)>, total: usize) -> Value {
        let mut rows = vec![];
        let mut last = Value::Null;
        let mut more = false;
        let mut size = 256;
        for (key, mut row) in iter {
            let mut bytes = serde_json::to_vec(&row).map_or(CAP, |v| v.len());
            if bytes > CAP / 2 {
                row["candidate"] =
                    json!({"truncated":true,"retrieval":{"operation":row["operation"]}});
                row["truncated"] = json!(true);
                bytes = serde_json::to_vec(&row).map_or(CAP, |v| v.len());
            }
            if rows.len() >= self.limit || size + bytes > CAP - 32768 {
                more = true;
                break;
            }
            size += bytes;
            last = key;
            rows.push(row);
        }
        let next=more.then(||json!({"namespace":"reading.books","query":self.name,"args":self.args,"revision":self.state.prefix,"after":last}).to_string());
        json!({"rows":rows,"total":total,"next":next})
    }
    fn set(
        &self,
        set: Option<&BTreeSet<Order>>,
        oldest: bool,
        make: impl Fn(&Order) -> Value,
    ) -> Value {
        let empty = BTreeSet::new();
        let set = set.unwrap_or(&empty);
        let after = self
            .after
            .as_ref()
            .and_then(|v| serde_json::from_value::<Order>(v.clone()).ok());
        let iter: Box<dyn Iterator<Item = &Order>> = match (oldest, after.as_ref()) {
            (false, Some(k)) => Box::new(set.range((Excluded(k), Unbounded))),
            (true, Some(k)) => Box::new(set.range((Unbounded, Excluded(k))).rev()),
            (false, None) => Box::new(set.iter()),
            (true, None) => Box::new(set.iter().rev()),
        };
        self.collect(iter.map(|k| (json!(k), make(k))), set.len())
    }
    fn slice<'a, T>(&self, items: &'a [T], make: impl Fn(&'a T) -> Value, reverse: bool) -> Value {
        let start = self
            .after
            .as_ref()
            .and_then(Value::as_u64)
            .map_or(0, |n| n.saturating_add(1) as usize);
        self.collect(
            (start.min(items.len())..items.len()).map(|i| {
                (
                    json!(i),
                    make(&items[if reverse { items.len() - 1 - i } else { i }]),
                )
            }),
            items.len(),
        )
    }
}
fn preview(v: &Value) -> (Value, bool) {
    if let Some(s) = v.as_str() {
        let end = s
            .char_indices()
            .map(|(i, _)| i)
            .take_while(|i| *i <= PREVIEW)
            .last()
            .unwrap_or(0);
        if s.len() > PREVIEW {
            return (json!(&s[..end]), true);
        }
    }
    (v.clone(), false)
}
fn book_row(state: &BooksState, b: &Book) -> Value {
    let mut row = json!({"id":b.value["id"],"title":b.value["title"],"creator":b.value["creator"],"status":b.current()["status"],"fraction":b.value.get("fraction").cloned().unwrap_or(json!(0)),"noteCount":b.note_count,"conflictCount":state.book_conflicts.get(s(&b.value,"id")).copied().unwrap_or(0),"revision":b.value["revision"]});
    patch(&mut row, &b.value, &["isbn", "coverID", "page", "pages"]);
    patch(&mut row, b.current(), &["started", "finished"]);
    row
}
fn note_row(n: &Note) -> Value {
    let (text, t) = preview(&n.value["text"]);
    let (quote, q) = preview(&n.value["quote"]);
    json!({"id":n.value["id"],"textPreview":text,"quotePreview":quote,"location":n.value["location"],"revision":n.value["revision"],"alternativeCount":n.alternatives.len(),"authorLabel":n.value["authorLabel"],"truncated":t||q})
}
pub(super) fn query(state: &BooksState, name: &str, args: &Value) -> crate::Result<Value> {
    let Some(normal) = normalize(name, args) else {
        return Ok(failure("invalidArgument"));
    };
    if name == "read" {
        return Ok(state.projection());
    }
    let mut page = Page {
        state,
        name,
        limit: normal["limit"].as_u64().unwrap_or(50) as usize,
        args: normal,
        after: None,
    };
    if let Some(raw) = args["cursor"].as_str() {
        let Ok(cursor) = serde_json::from_str::<Value>(raw) else {
            return Ok(failure("invalidArgument"));
        };
        if cursor["namespace"] != "reading.books"
            || cursor["query"] != name
            || cursor["args"] != page.args
        {
            return Ok(failure("invalidArgument"));
        }
        if cursor["revision"] != state.prefix {
            return Ok(failure("staleCursor"));
        }
        let after = cursor["after"].clone();
        if if ["books", "bookNotes"].contains(&name) {
            serde_json::from_value::<Order>(after.clone()).is_err()
        } else {
            after.as_u64().is_none()
        } {
            return Ok(failure("invalidArgument"));
        }
        page.after = Some(after);
    }
    let value = match name {
        "book" => {
            let Some(b) = state.books.get(s(args, "id")) else {
                return Ok(failure("notFound"));
            };
            if b.deleted {
                return Ok(failure("deleted"));
            }
            let mut book = b.value.clone();
            if let Some(o) = book.as_object_mut() {
                o.remove("extensions");
            }
            json!({"book":book,"heads":b.heads,"currentReading":b.current(),"loan":b.loan,"extensions":b.value["extensions"]})
        }
        "note" => {
            let Some(n) = state.notes.get(s(args, "id")) else {
                return Ok(failure("notFound"));
            };
            if n.deleted
                || state
                    .books
                    .get(s(&n.value, "book"))
                    .is_none_or(|b| b.deleted)
            {
                return Ok(failure("deleted"));
            }
            let mut note = json!({});
            patch(
                &mut note,
                &n.value,
                &["id", "revision", "author", "authorLabel", "origin", "clock"],
            );
            json!({"note":note,"text":n.value["text"],"quote":n.value["quote"],"location":n.value["location"],"book":n.value["book"],"alternativeCount":n.alternatives.len(),"extensions":n.value["extensions"]})
        }
        "books" => {
            let status = args["status"].as_str();
            let year = args.get("finishedYear").map(Value::as_i64);
            let key = match (status, year) {
                (Some(s), Some(y)) => format!("status:{s}/year:{y:?}"),
                (Some(s), None) => format!("status:{s}"),
                (None, Some(y)) => format!("year:{y:?}"),
                _ => "all".into(),
            };
            let set = state.indexes.get(&key);
            let search = s(args, "search").to_lowercase();
            if search.is_empty() {
                page.set(set, false, |k| book_row(state, &state.books[&k.3]))
            } else {
                let filtered = set
                    .into_iter()
                    .flatten()
                    .filter(|k| {
                        let b = &state.books[&k.3];
                        ["title", "creator", "isbn"]
                            .iter()
                            .any(|f| s(&b.value, f).to_lowercase().contains(&search))
                    })
                    .cloned()
                    .collect();
                page.set(Some(&filtered), false, |k| {
                    book_row(state, &state.books[&k.3])
                })
            }
        }
        "bookCounts" => {
            json!({"total":state.indexes.get("all").map_or(0,BTreeSet::len),"byStatus":state.by_status.iter().filter(|(_,n)|**n>0).collect::<BTreeMap<_,_>>(),"finishedYears":state.years.iter().rev().filter(|(_,n)|**n>0).map(|(y,n)|json!({"year":y.parse::<i64>().ok(),"count":n})).collect::<Vec<_>>(),"conflicts":state.active_conflicts})
        }
        "bookNotes" | "readings" => {
            let Some(b) = state.books.get(s(args, "book")) else {
                return Ok(failure("notFound"));
            };
            if b.deleted {
                return Ok(failure("deleted"));
            }
            if name == "bookNotes" {
                page.set(
                    state.note_index.get(s(args, "book")),
                    page.args["order"] == "oldest",
                    |k| note_row(&state.notes[&k.3]),
                )
            } else {
                page.slice(
                    &b.readings,
                    |r| {
                        let mut r = r.clone();
                        if let Some(o) = r.as_object_mut() {
                            o.remove("extensions");
                        }
                        r
                    },
                    true,
                )
            }
        }
        "catalogMembership" => {
            let keys = args["keys"].as_array().map(Vec::as_slice).unwrap_or(&[]);
            let key_bytes = serde_json::to_vec(keys)?.len();
            let budget = (CAP.saturating_sub(key_bytes + 32768)) / keys.len().max(1);
            json!(keys.iter().map(|key|{
                let ids=state.catalog.get(key.as_str().unwrap_or(""));
                let total=ids.map_or(0,BTreeSet::len);
                let mut bytes=0;let mut selected=vec![];
                for id in ids.into_iter().flatten().take(100){
                    let size=serde_json::to_vec(id).map_or(CAP,|v|v.len()+1);
                    if bytes+size>budget{break;}bytes+=size;selected.push(id);
                }
                json!({"key":key,"bookIDs":selected,"total":total,"truncated":selected.len()<total})
            }).collect::<Vec<_>>())
        }
        "conflicts" => page.slice(
            state
                .conflicts
                .get(s(args, "object"))
                .map(Vec::as_slice)
                .unwrap_or(&[]),
            |c| c.row.clone(),
            false,
        ),
        "invalid" => page.slice(&state.invalid, Clone::clone, false),
        _ => return Ok(failure("invalidArgument")),
    };
    let result = json!({"revision":state.prefix,"value":value});
    if serde_json::to_vec(&result)?.len() > CAP {
        return Ok(
            json!({"ok":false,"reason":"unavailable","detail":"responseTooLarge","retrieval":"host content/blob adapter required"}),
        );
    }
    Ok(result)
}
