use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

fn preview(s: &str) -> Value {
    let mut units = 0;
    let mut end = s.len();
    for (i, c) in s.char_indices() {
        units += c.len_utf16();
        if units > 512 {
            end = i;
            break;
        }
    }
    json!({"text":&s[..end],"truncated":end<s.len()})
}
fn missing(deleted: bool) -> Value {
    json!({"outcome":if deleted{"deleted"}else{"notFound"}})
}
fn page<I>(s: &SavedState, name: &str, args: &Value, rows: I) -> Result<Value>
where
    I: Iterator<Item = Value> + Clone,
{
    let mut normalized = args.clone();
    if let Some(o) = normalized.as_object_mut() {
        o.remove("cursor");
        o.remove("offset");
        o.remove("limit");
    }
    let binding = hash(&crate::records::canonical(&json!([
        "reading.saved",
        name,
        normalized
    ]))?);
    let mut offset = args["offset"].as_u64().unwrap_or(0) as usize;
    if let Some(cursor) = args["cursor"].as_str() {
        let c: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(cursor)
                .map_err(|_| Error("invalidArgument: cursor".into()))?,
        )?;
        if c["revision"] != s.revision || c["binding"] != binding {
            return Ok(json!({"outcome":"staleCursor"}));
        }
        offset = c["offset"]
            .as_u64()
            .ok_or_else(|| Error("invalidArgument: cursor offset".into()))?
            as usize;
    }
    let limit = args["limit"].as_u64().unwrap_or(50) as usize;
    let total = rows.clone().count();
    let mut out = Vec::new();
    let mut bytes = 256;
    let mut end = offset;
    for v in rows.skip(offset).take(limit) {
        let size = serde_json::to_vec(&v)?.len();
        if bytes + size > 1000 * 1024 {
            if out.is_empty() {
                return Ok(
                    json!({"outcome":"unavailable","reason":"rowTooLarge","retrieval":"singleRecordOrEvidenceBlob"}),
                );
            }
            break;
        }
        bytes += size;
        out.push(v);
        end += 1;
    }
    let cursor = if end < total {
        Some(URL_SAFE_NO_PAD.encode(crate::records::canonical(
            &json!({"revision":s.revision,"binding":binding,"offset":end}),
        )?))
    } else {
        None
    };
    Ok(json!({"rows":out,"next":cursor,"total":total}))
}
fn filtered(row: &Value, q: &Value) -> bool {
    (q["includeDeleted"] == true || row["deleted"] != true)
        && shelf_matches(row, strv(q, "shelf"))
        && ["consumption", "retention", "collection", "sourceStatus"]
            .iter()
            .all(|k| {
                q.get(k).is_none_or(|v| {
                    v == &row[k]
                        || (row[k].is_null()
                            && ((*k == "consumption" && v == "notStarted")
                                || (*k == "retention" && v == "saved")))
                })
            })
        && q.get("kind").is_none_or(|kind| {
            kind == "all" || kind == &row["kind"] || kind == &row["occurrenceKind"]
        })
        && q.get("tag")
            .is_none_or(|tag| arr(&row["tags"]).contains(tag))
}
fn heads(g: &Graph) -> Vec<Value> {
    g.heads
        .iter()
        .take(100)
        .filter_map(|id| g.nodes.get(id).cloned())
        .collect()
}
fn annotation_row(s: &SavedState, id: &str, g: &Graph) -> Value {
    let current = if g.heads.len() == 1 {
        g.heads.first().and_then(|id| g.nodes.get(id))
    } else {
        None
    };
    let tags: Vec<_> = g
        .tags
        .iter()
        .filter(|(_, v)| v["included"] == true)
        .map(|(tag, _)| tag)
        .collect();
    json!({"id":id,"thread":id,"item":g.item,"source":g.source,"anchorPreview":current.map(|n|preview(&n["anchor"].to_string())),"textPreview":current.map(|n|preview(strv(n,"text"))),"heads":g.heads.iter().take(100).collect::<Vec<_>>(),"headCount":g.heads.len(),"headsTruncated":g.heads.len()>100,"deleted":g.deleted || s.items.get(&g.item).is_some_and(|i|i.value["deleted"]==true),"conflicted":g.heads.len()>1,"authorLabel":current.map(|n|&n["authorLabel"]),"tags":tags})
}
fn graph_order(g: &Graph) -> (u64, &str, &str) {
    (g.touched.0, g.touched.1.as_str(), g.touched.2.as_str())
}
fn source_status(s: &SavedState, evidence: &Value) -> &'static str {
    if arr(evidence)
        .iter()
        .all(|e| s.sources.contains_key(strv(e, "source")))
    {
        "retained"
    } else {
        "sourceOnly"
    }
}

pub(super) fn query(s: &SavedState, name: &str, args: &Value) -> Result<Value> {
    let specs = specs::queries();
    let spec = specs
        .iter()
        .find(|q| q.name == name)
        .ok_or_else(|| Error("Unknown query".into()))?;
    ensure(
        validate::matches(&spec.input_schema, args),
        "invalidArgument",
    )?;
    if let Some(q) = args.get("query") {
        validate::view_query(q)?;
        if q["availability"] == "savedText"
            || !strv(q, "search").is_empty()
            || !strv(q, "source").is_empty()
        {
            return Ok(
                json!({"revision":s.revision,"value":{"outcome":"unavailable","reason":"hostSearchIndexRequired"}}),
            );
        }
    }
    if name == "read" {
        return Ok(s.projection());
    }
    let id = strv(args, "id");
    let item = strv(args, "item");
    let value = match name {
        "items" => item_page(s, args)?,
        "item" => match s.items.get(id) {
            None => missing(false),
            Some(i) if i.value["deleted"] == true && args["includeDeleted"] != true => {
                missing(true)
            }
            Some(i) => {
                json!({"item":i.value,"heads":i.heads,"selectedSource":i.selected,"metadataOnly":s.source_status(id)=="sourceOnly","extensions":i.value["extensions"]})
            }
        },
        "readingCounts" => {
            if args.get("query").is_none() {
                let mut counts = BTreeMap::new();
                for (k, _) in count_row(&json!({})) {
                    counts.insert(k, *s.counts.get(k).unwrap_or(&0));
                }
                json!(counts)
            } else {
                let q = &args["query"];
                let (bucket, filters) = item_bucket(s, q, "added");
                let mut counts: BTreeMap<String, i64> = count_row(&json!({}))
                    .into_iter()
                    .map(|(k, _)| (k.into(), 0))
                    .collect();
                if filters <= 1 {
                    if let Some(c) = s.bucket_counts.get(&bucket) {
                        counts.extend(c.clone());
                    }
                } else {
                    for (_, id) in s
                        .item_order
                        .get(&index_key(&bucket, "added"))
                        .into_iter()
                        .flatten()
                    {
                        let row = &s.rows[id];
                        if filtered(row, q) {
                            for (k, n) in count_row(row) {
                                *counts.entry(k.into()).or_default() += n;
                            }
                        }
                    }
                }
                json!(counts)
            }
        }
        "sources" => {
            if !s.items.contains_key(item) {
                missing(false)
            } else if args["kind"] == "versions" {
                let mut versions: Vec<_> = s
                    .item_sources
                    .get(item)
                    .into_iter()
                    .flatten()
                    .filter_map(|id| s.sources.get(id))
                    .chain(
                        s.item_metadata
                            .get(item)
                            .into_iter()
                            .flatten()
                            .filter_map(|id| s.metadata.get(id)),
                    )
                    .filter(|v| args.get("source").is_none_or(|id| id == &v["id"]))
                    .collect();
                versions.sort_by_key(|v| order(v));
                page(
                    s,
                    name,
                    args,
                    versions
                        .into_iter()
                        .map(|v| v.get("manifest").unwrap_or(v).clone()),
                )?
            } else {
                let mut images: Vec<_> = s
                    .images
                    .values()
                    .filter(|v| {
                        v["item"] == item
                            && args
                                .get("source")
                                .is_none_or(|source| source == &v["source"])
                    })
                    .collect();
                images.sort_by_key(|v| (v["clock"].as_u64(), strv(&v["asset"]["candidate"], "id")));
                page(
                    s,
                    name,
                    args,
                    images.into_iter().map(|v| v["asset"].clone()),
                )?
            }
        }
        "position" | "getPosition" => match s.items.get(item) {
            None => missing(false),
            Some(i) if i.value["deleted"] == true => missing(true),
            Some(i) => i.position.clone().unwrap_or(Value::Null),
        },
        "annotations" => {
            let mut graphs: Vec<_> = s
                .annotations
                .iter()
                .filter(|(_, g)| {
                    (item.is_empty() || item == g.item)
                        && (args["includeDeleted"] == true
                            || (!g.deleted
                                && s.items
                                    .get(&g.item)
                                    .is_some_and(|i| i.value["deleted"] != true)))
                        && args.get("tag").is_none_or(|t| {
                            g.tags
                                .get(t.as_str().unwrap_or(""))
                                .is_some_and(|v| v["included"] == true)
                        })
                })
                .collect();
            graphs.sort_by(|(aid, a), (bid, b)| {
                graph_order(b)
                    .cmp(&graph_order(a))
                    .then_with(|| aid.cmp(bid))
            });
            page(
                s,
                name,
                args,
                graphs.into_iter().map(|(id, g)| annotation_row(s, id, g)),
            )?
        }
        "annotation" => match s.annotations.get(strv(args, "thread")) {
            None => missing(false),
            Some(g) => {
                let node = if let Some(rev) = args["revision"].as_str() {
                    g.nodes
                        .get(rev)
                        .or_else(|| g.nodes.values().find(|v| v["revision"] == rev))
                } else if g.heads.len() == 1 {
                    g.heads.first().and_then(|id| g.nodes.get(id))
                } else {
                    None
                };
                if args.get("revision").is_some() && node.is_none() {
                    missing(false)
                } else {
                    json!({"current":node,"heads":g.heads.iter().take(100).collect::<Vec<_>>(),"headCount":g.heads.len(),"deleted":g.deleted || s.items.get(&g.item).is_some_and(|i|i.value["deleted"]==true),"sourceStatus":s.source_status(&g.item),"extensions":node.map(|v|&v["extensions"])})
                }
            }
        },
        "annotationHistory" => match s.annotations.get(strv(args, "thread")) {
            None => missing(false),
            Some(g) => page(
                s,
                name,
                args,
                g.history_order
                    .iter()
                    .filter_map(|(_, _, _, id)| g.nodes.get(id))
                    .cloned(),
            )?,
        },
        "feeds" => {
            let mut rows: Vec<_> = s
                .feeds
                .values()
                .filter(|f| {
                    f.value["followed"] == args.get("followed").cloned().unwrap_or(json!(true))
                        && args
                            .get("folder")
                            .is_none_or(|p| arr(&f.value["folders"]).contains(p))
                })
                .map(|f| {
                    let mut v = f.value.clone();
                    v["entryCount"] = json!(f.entries.len());
                    v
                })
                .collect();
            rows.sort_by(|a, b| {
                (strv(a, "title"), strv(a, "id")).cmp(&(strv(b, "title"), strv(b, "id")))
            });
            page(s, name, args, rows.into_iter())?
        }
        "feedEntries" => match s.feeds.get(strv(args, "feed")) {
            None => missing(false),
            Some(f) => {
                let mut rows: Vec<_> = f.entries.values().cloned().collect();
                rows.sort_by(|a, b| {
                    b["arrival"]
                        .as_u64()
                        .cmp(&a["arrival"].as_u64())
                        .then_with(|| strv(a, "id").cmp(strv(b, "id")))
                });
                for e in &mut rows {
                    e["summaryPreview"] = preview(strv(e, "summary"));
                    if let Some(o) = e.as_object_mut() {
                        o.remove("summary");
                        o.remove("arrival");
                    }
                }
                page(s, name, args, rows.into_iter())?
            }
        },
        "savedViews" => {
            let mut rows:Vec<_>=s.views.iter().filter(|(_,g)|args["includeDeleted"]==true||!g.deleted).map(|(id,g)|{let n=if g.heads.len()==1{g.heads.first().and_then(|id|g.nodes.get(id))}else{None};json!({"id":id,"name":n.map(|n|&n["name"]),"headCount":g.heads.len(),"deleted":g.deleted,"conflicted":g.heads.len()>1,"revision":n.map(|n|&n["revision"])})}).collect();
            rows.sort_by(|a, b| {
                (strv(a, "name"), strv(a, "id")).cmp(&(strv(b, "name"), strv(b, "id")))
            });
            page(s, name, args, rows.into_iter())?
        }
        "savedView" => match s.views.get(id) {
            None => missing(false),
            Some(g) => {
                json!({"heads":heads(g),"headCount":g.heads.len(),"deleted":g.deleted,"conflicted":g.heads.len()>1})
            }
        },
        "reviewQueue" => {
            let mut eligible: Vec<_> = s
                .annotations
                .iter()
                .filter(|(id, g)| {
                    !g.deleted
                        && g.heads.len() == 1
                        && !s.review_excluded.contains(*id)
                        && s.items
                            .get(&g.item)
                            .is_some_and(|i| i.value["deleted"] != true)
                })
                .collect();
            eligible.sort_by_key(|(id, _)| {
                (
                    s.review_choices
                        .get(*id)
                        .and_then(|choice| s.review.iter().find(|v| v["id"] == *choice))
                        .map(|v| v["clock"].as_u64().unwrap_or(0))
                        .unwrap_or(0),
                    *id,
                )
            });
            let count = eligible.len();
            let rows: Vec<_> = if s.review_enabled {
                eligible
                    .into_iter()
                    .take(args["limit"].as_u64().unwrap_or(20) as usize)
                    .map(|(id, g)| annotation_row(s, id, g))
                    .collect()
            } else {
                vec![]
            };
            json!({"enabled":s.review_enabled,"rows":rows,"eligibleCount":count,"decisionRevision":s.review_revision})
        }
        "reviewHistory" => page(
            s,
            name,
            args,
            s.review
                .iter()
                .filter(|v| args.get("thread").is_none_or(|id| id == &v["thread"]))
                .cloned(),
        )?,
        "answers" => {
            let mut rows: Vec<_> = s
                .answers
                .values()
                .filter(|v| {
                    let hidden = s
                        .visibility
                        .get(strv(v, "id"))
                        .and_then(|g| {
                            if g.heads.len() == 1 {
                                g.heads.first().and_then(|h| g.nodes.get(h))
                            } else {
                                None
                            }
                        })
                        .is_some_and(|n| n["hidden"] == true);
                    hidden == (args["hidden"] == true)
                        && (item.is_empty()
                            || arr(&v["evidence"]).iter().any(|e| {
                                s.sources
                                    .get(strv(e, "source"))
                                    .is_some_and(|v| v["item"] == item)
                            }))
                })
                .collect();
            rows.sort_by_key(|v| order(v));
            let rows:Vec<_>=rows.into_iter().map(|v|{let g=s.visibility.get(strv(v,"id"));json!({"id":v["id"],"question":v["question"],"claimCount":arr(&v["claims"]).len(),"evidenceCount":arr(&v["evidence"]).len(),"sourceStatus":source_status(s,&v["evidence"]),"visibilityHeads":g.map(|g|g.heads.iter().take(100).collect::<Vec<_>>()),"visibilityHeadCount":g.map(|g|g.heads.len()).unwrap_or(0),"conflicted":g.is_some_and(|g|g.heads.len()>1),"revision":v["revision"]})}).collect();
            page(s, name, args, rows.into_iter())?
        }
        "answer" => match s.answers.get(id) {
            None => missing(false),
            Some(v) => {
                let mut attributed = v.clone();
                if let Some(o) = attributed.as_object_mut() {
                    o.remove("claims");
                    o.remove("evidence");
                }
                json!({"answer":attributed,"question":v["question"],"claims":v["claims"],"evidence":v["evidence"],"engine":v["engine"],"runtime":v["runtime"],"promptRevision":v["promptRevision"],"sourceStatus":source_status(s,&v["evidence"])})
            }
        },
        "connections" => {
            let mut graphs: Vec<_> = s.connections.iter().collect();
            graphs.sort_by(|(aid, a), (bid, b)| {
                graph_order(b)
                    .cmp(&graph_order(a))
                    .then_with(|| aid.cmp(bid))
            });
            let rows:Vec<_>=graphs.into_iter().filter_map(|(id,g)|{let n=g.heads.first().and_then(|h|g.nodes.get(h))?;if (!item.is_empty() && n["source"]["item"]!=item && n["target"]["item"]!=item) || (args["includeRetracted"]!=true && g.heads.len()==1 && n["retracted"]==true){return None;}Some(json!({"id":id,"source":n["source"],"target":n["target"],"relation":if g.heads.len()==1{n["relation"].clone()}else{Value::Null},"reasonPreview":if g.heads.len()==1{preview(strv(n,"reason"))}else{Value::Null},"retracted":if g.heads.len()==1{n["retracted"].clone()}else{Value::Null},"heads":g.heads.iter().take(100).collect::<Vec<_>>(),"headCount":g.heads.len(),"conflicted":g.heads.len()>1}))}).collect();
            page(s, name, args, rows.into_iter())?
        }
        "subscriptions" => page(
            s,
            name,
            args,
            s.subscriptions
                .iter()
                .filter(|(id, _)| args.get("publication").is_none_or(|p| p == *id))
                .map(|(id, v)| {
                    let mut v = v.clone();
                    v["alternativeCount"] =
                        json!(s.conflict_index.get(id).map(Vec::len).unwrap_or(0));
                    v
                }),
        )?,
        "conflicts" => {
            let object = strv(args, "object");
            let mut rows: Vec<_> = s
                .conflict_index
                .get(object)
                .into_iter()
                .flatten()
                .map(|i| &s.conflicts[*i])
                .filter(|v| args.get("component").is_none_or(|c| c == &v["component"]))
                .cloned()
                .collect();
            for op in s.pending.values().filter(|o| {
                ["item", "thread", "view", "answer", "connection"]
                    .iter()
                    .any(|k| o.payload[k] == object)
            }) {
                rows.push(json!({"operation":op.id,"reason":"missingParents","candidate":attributed(op),"historical":false}));
            }
            page(s, name, args, rows.into_iter())?
        }
        "invalid" => page(s, name, args, s.diagnostics.iter().cloned())?,
        _ => return Err(Error("Unknown query".into())),
    };
    let result = json!({"revision":s.revision,"value":value});
    if serde_json::to_vec(&result)?.len() > 1024 * 1024 {
        return Ok(
            json!({"revision":s.revision,"value":{"outcome":"unavailable","reason":"responseTooLarge","retrieval":"evidenceBlob"}}),
        );
    }
    Ok(result)
}

// Keyset paging reads the selected maintained order index. Common unfiltered and single-filter
// shelf pages are O(log n + page); compound filters scan only their smallest indexed bucket.
fn item_bucket(s: &SavedState, q: &Value, sort: &str) -> (String, usize) {
    let visibility = if q["includeDeleted"] == true {
        "all"
    } else {
        "live"
    };
    let mut filters = vec![json!([]).to_string()];
    for key in [
        "consumption",
        "retention",
        "collection",
        "kind",
        "sourceStatus",
        "tag",
        "shelf",
    ] {
        if let Some(v) = q.get(key) {
            if (key == "kind" || key == "shelf") && v == "all" {
                continue;
            }
            filters.push(json!([key, v]).to_string());
        }
    }
    let count = filters.len() - 1;
    let bucket = filters
        .into_iter()
        .map(|f| index_key(visibility, &f))
        .min_by_key(|b| {
            s.item_order
                .get(&index_key(b, sort))
                .map(BTreeSet::len)
                .unwrap_or(0)
        })
        .unwrap_or_default();
    (bucket, count)
}
fn item_page(s: &SavedState, args: &Value) -> Result<Value> {
    use std::ops::Bound::{Excluded, Unbounded};
    let mut q = args.get("query").cloned().unwrap_or_else(|| json!({}));
    let requested_sort = q["sort"].as_str().unwrap_or("newest");
    let sort = match requested_sort {
        "newest" | "oldest" => "added",
        "author" => "creator",
        other => other,
    }
    .to_owned();
    if requested_sort == "oldest" {
        q["direction"] = json!("ascending");
    }
    let descending = q["direction"] != "ascending"
        && (!["title", "creator"].contains(&sort.as_str()) || q["direction"] == "descending");
    q["sort"] = json!(sort);
    q["direction"] = json!(if descending {
        "descending"
    } else {
        "ascending"
    });
    if q.get("includeDeleted").is_none() {
        q["includeDeleted"] = json!(false);
    }
    let binding = hash(&crate::records::canonical(&json!([
        "reading.saved",
        "items",
        q
    ]))?);
    let mut after = None;
    if let Some(c) = args["cursor"].as_str() {
        let c: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(c)
                .map_err(|_| Error("invalidArgument: cursor".into()))?,
        )?;
        if c["revision"] != s.revision || c["binding"] != binding {
            return Ok(json!({"outcome":"staleCursor"}));
        }
        after = Some(serde_json::from_value::<(String, String)>(
            c["after"].clone(),
        )?);
    }
    let (bucket, filters) = item_bucket(s, &q, &sort);
    let empty = BTreeSet::new();
    let index = s
        .item_order
        .get(&index_key(&bucket, &sort))
        .unwrap_or(&empty);
    let total = if filters <= 1 {
        index.len()
    } else {
        index
            .iter()
            .filter(|(_, id)| s.rows.get(id).is_some_and(|r| filtered(r, &q)))
            .count()
    };
    let range = if descending {
        index.range((Unbounded, after.map(Excluded).unwrap_or(Unbounded)))
    } else {
        index.range((after.map(Excluded).unwrap_or(Unbounded), Unbounded))
    };
    let iter: Box<dyn Iterator<Item = &(String, String)>> = if descending {
        Box::new(range.rev())
    } else {
        Box::new(range)
    };
    let limit = args["limit"].as_u64().unwrap_or(50) as usize;
    let mut rows = Vec::new();
    let mut bytes = 256;
    let mut last = None;
    let mut more = false;
    for key in iter
        .filter(|(_, id)| s.rows.get(id).is_some_and(|r| filtered(r, &q)))
        .skip(args["offset"].as_u64().unwrap_or(0) as usize)
    {
        if rows.len() == limit {
            more = true;
            break;
        }
        let mut row = s.rows[&key.1].clone();
        if let Some(o) = row.as_object_mut() {
            o.remove("tags");
            o.remove("collection");
            o.remove("occurrenceKind");
            o.remove("sequence");
            o.remove("sortAdded");
            o.remove("sortTouched");
        }
        let size = serde_json::to_vec(&row)?.len();
        if bytes + size > 1000 * 1024 {
            more = true;
            break;
        }
        bytes += size;
        rows.push(row);
        last = Some(key);
    }
    let next = if more {
        last.map(|key| {
            URL_SAFE_NO_PAD
                .encode(json!({"revision":s.revision,"binding":binding,"after":key}).to_string())
        })
    } else {
        None
    };
    Ok(json!({"rows":rows,"total":total,"next":next}))
}
