use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use std::ops::Bound::{Excluded, Unbounded};

fn index(parts: &[&str]) -> String {
    key(parts)
}
fn order(v: &Value) -> String {
    format!(
        "{:016x}:{}:{}",
        v["clock"].as_u64().unwrap_or(0),
        text(v, "author"),
        text(v, "revision")
    )
}
fn reverse_order(v: &Value) -> String {
    format!(
        "{:016x}:{}:{}",
        u64::MAX - v["clock"].as_u64().unwrap_or(0),
        text(v, "author"),
        text(v, "revision")
    )
}
fn number(v: &Value) -> String {
    format!("{:016x}", v.as_f64().unwrap_or(f64::MAX).to_bits())
}
fn date(v: &Value) -> String {
    let d = crate::model::time_key(v.as_str().unwrap_or("")).unwrap_or([0; 7]);
    format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}{:03}",
        d[0], d[1], d[2], d[3], d[4], d[5], d[6]
    )
}
fn reverse_date(v: &Value) -> String {
    date(v)
        .bytes()
        .map(|b| char::from(b'9' - (b - b'0')))
        .collect()
}
impl PodcastsState {
    fn reindex(&mut self, table: &str, id: &str, entries: Vec<(String, String)>) {
        let membership = key(&[table, id]);
        if let Some(old) = self.memberships.remove(&membership) {
            for (name, sort) in old {
                if let Some(set) = self.indexes.get_mut(&name) {
                    set.remove(&(sort, id.into()));
                }
            }
        }
        for (name, sort) in &entries {
            self.indexes
                .entry(name.clone())
                .or_default()
                .insert((sort.clone(), id.into()));
        }
        self.memberships.insert(membership, entries);
    }
    pub(super) fn index_show(&mut self, id: &str) {
        let v = &self.shows[id];
        self.reindex(
            "show",
            id,
            vec![(
                index(&[
                    "shows",
                    if v["following"] == true {
                        "true"
                    } else {
                        "false"
                    },
                ]),
                text(v, "title").into(),
            )],
        );
    }
    pub(super) fn index_episode(&mut self, id: &str) {
        let v = &self.episodes[id];
        let show = text(v, "show");
        let state = text(v, "consumption");
        let sort = format!("{}:{}", date(&v["published"]), id);
        let mut entries = vec![];
        for parent in ["", show] {
            for status in ["", state] {
                entries.push((index(&["episodes", parent, status]), sort.clone()));
            }
        }
        if v.get("stateRevision").is_some() {
            entries.push((
                index(&["history", "all"]),
                format!("{}:{}", reverse_date(&v["stateUpdated"]), id),
            ));
        }
        if finished(v) {
            entries.push((
                index(&["history", "finished"]),
                format!("{}:{}", reverse_date(&v["stateUpdated"]), id),
            ));
        }
        self.reindex("episode", id, entries);
    }
    pub(super) fn index_note(&mut self, id: &str) {
        let v = &self.notes[id];
        let mut entries = vec![];
        if v["deleted"] != true {
            entries.push((index(&["notes", ""]), reverse_order(&v["creation"])));
            entries.push((
                index(&["notes", text(v, "episode")]),
                format!("{}:{}", number(&v["seconds"]), order(&v["creation"])),
            ));
            entries.push((index(&["showNotes", text(v, "show")]), id.into()));
        }
        self.reindex("note", id, entries);
    }
    pub(super) fn index_playlist(&mut self, id: &str) {
        let v = &self.playlists[id];
        self.reindex(
            "playlist",
            id,
            vec![(
                index(&[
                    "playlists",
                    if v["archived"] == true {
                        "true"
                    } else {
                        "false"
                    },
                ]),
                format!("{}:{}", text(v, "name"), id),
            )],
        );
    }
    pub(super) fn index_transcript(&mut self, id: &str) {
        let v = &self.transcripts[id];
        let sort = order(v);
        self.reindex(
            "transcript",
            id,
            vec![
                (index(&["transcripts", ""]), sort.clone()),
                (index(&["transcripts", text(v, "episode")]), sort),
                (index(&["showTranscripts", text(v, "show")]), id.into()),
            ],
        );
    }
    fn source_memberships(
        &self,
        v: &Value,
    ) -> (BTreeSet<String>, BTreeSet<String>, BTreeSet<String>) {
        let mut episodes = BTreeSet::from([String::new()]);
        let mut shows = BTreeSet::from([String::new()]);
        let mut transcripts = BTreeSet::new();
        if let Some(e) = v["episode"].as_str() {
            episodes.insert(e.into());
        }
        if let Some(show) = v["show"].as_str() {
            shows.insert(show.into());
        }
        let mut references = vec![&v["reference"]];
        for field in ["scope", "sourceRefs"] {
            for anchor in items(&v[field]) {
                references.push(&anchor["reference"]);
            }
        }
        for claim in items(&v["claims"]) {
            for anchor in items(&claim["citations"]) {
                references.push(&anchor["reference"]);
            }
        }
        for reference in references {
            for source in [
                reference,
                self.transcripts
                    .get(text(reference, "transcript"))
                    .unwrap_or(&Value::Null),
            ] {
                if let Some(e) = source["episode"].as_str() {
                    episodes.insert(e.into());
                }
                if let Some(show) = source["show"].as_str() {
                    shows.insert(show.into());
                }
            }
            if let Some(id) = reference["transcript"].as_str() {
                transcripts.insert(id.into());
            }
        }
        (episodes, shows, transcripts)
    }
    pub(super) fn index_job(&mut self, id: &str) {
        let v = &self.jobs[id];
        let mut entries = vec![];
        let (episodes, shows, transcripts) = self.source_memberships(v);
        for episode in &episodes {
            for status in ["", text(v, "status")] {
                entries.push((index(&["jobs", text(v, "kind"), episode, status]), order(v)));
            }
        }
        if !["cancelled", "acceptedPendingVerification"].contains(&text(v, "status")) {
            for show in &shows {
                entries.push((index(&["pendingJobs", show]), id.into()));
            }
        }
        for transcript in &transcripts {
            entries.push((index(&["sourceJobs", transcript]), id.into()));
        }
        self.reindex("job", id, entries);
    }
    pub(super) fn index_contribution(&mut self, id: &str) {
        let v = &self.contributions[id];
        let (episodes, _, transcripts) = self.source_memberships(v);
        let mut entries = vec![];
        for episode in &episodes {
            entries.push((
                index(&["contributions", text(v, "kind"), episode]),
                order(v),
            ));
        }
        for transcript in &transcripts {
            entries.push((index(&["sourceContributions", transcript]), id.into()));
        }
        self.reindex("contribution", id, entries);
    }
    pub(super) fn refresh_source_dependents(&mut self, transcript: &str) {
        for table in ["sourceJobs", "sourceContributions"] {
            let ids: Vec<_> = self
                .indexes
                .get(&index(&[table, transcript]))
                .into_iter()
                .flatten()
                .map(|(_, id)| id.clone())
                .collect();
            for id in ids {
                if table == "sourceJobs" {
                    self.index_job(&id);
                } else {
                    self.index_contribution(&id);
                }
            }
        }
    }
    fn count(&self, parts: &[&str]) -> usize {
        self.indexes.get(&index(parts)).map_or(0, BTreeSet::len)
    }
    fn row(&self, id: &str) -> Value {
        let e = self.episodes.get(id).unwrap_or(&Value::Null);
        let mut row = json!({"id":id,"show":e["show"],"seconds":e["seconds"].as_f64().unwrap_or(0.0),"metadataAvailable":e["metadataAvailable"]==true,"transcriptAvailable":self.selected.contains_key(id),"noteCount":self.count(&["notes",id])});
        for field in [
            "title",
            "showTitle",
            "duration",
            "consumption",
            "updated",
            "positionRevision",
            "stateRevision",
        ] {
            if let Some(v) = e.get(field) {
                row[field] = v.clone();
            }
        }
        row
    }
    fn detail(&self, id: &str) -> Value {
        let Some(e) = self.episodes.get(id) else {
            return outcome("notFound");
        };
        let mut metadata = json!({});
        for field in [
            "id",
            "show",
            "feed",
            "guid",
            "title",
            "showTitle",
            "audioURL",
            "duration",
            "published",
            "transcriptExcerpt",
        ] {
            if let Some(v) = e.get(field) {
                metadata[field] = v.clone();
            }
        }
        json!({"row":self.row(id),"metadata":if e["metadataAvailable"]==true {metadata} else {Value::Null},"heads":{"metadata":e["metadataRevision"],"position":e["positionRevision"],"state":e["stateRevision"]},"extensions":e.get("extensions").cloned().unwrap_or_else(||json!({}))})
    }
}
fn finished(v: &Value) -> bool {
    matches!(
        text(v, "consumption"),
        "doneEnough" | "completed" | "abandoned"
    )
}
fn outcome(reason: &str) -> Value {
    json!({"outcome":reason})
}
fn preview(s: &str) -> (String, bool) {
    let short: String = s.chars().take(240).collect();
    let truncated = short.len() < s.len();
    (short, truncated)
}
fn fields(v: &Value, names: &[&str]) -> Value {
    let mut o = json!({});
    for k in names {
        if let Some(value) = v.get(k) {
            o[k] = value.clone();
        }
    }
    o
}
#[derive(Serialize, Deserialize)]
struct Cursor {
    namespace: String,
    query: String,
    args: String,
    revision: String,
    last: (String, String),
}
fn arguments(name: &str, args: &Value) -> String {
    let mut a = args.clone();
    if let Some(o) = a.as_object_mut() {
        o.remove("cursor");
        o.remove("offset");
        o.remove("limit");
    }
    for (query, field, default) in [
        ("shows", "following", true),
        ("playlists", "archived", false),
        ("history", "finishedOnly", false),
    ] {
        if name == query && a.get(field).is_none() {
            a[field] = json!(default);
        }
    }
    digest(&canonical(&a).unwrap_or_default())
}
struct Paging {
    limit: usize,
    offset: usize,
    after: Option<(String, String)>,
}
fn paging(s: &PodcastsState, name: &str, args: &Value) -> crate::Result<Paging> {
    let default = if ["queue", "getQueue", "jobs", "contributions"].contains(&name) {
        20
    } else {
        50
    };
    let limit = args["limit"].as_u64().unwrap_or(default) as usize;
    crate::ensure(
        (1..=100).contains(&limit),
        "invalidArgument: limit must be 1..100",
    )?;
    crate::ensure(
        args.get("cursor").is_none() || args.get("offset").is_none(),
        "invalidArgument: cursor with offset",
    )?;
    let mut after = None;
    if let Some(encoded) = args["cursor"].as_str() {
        let cursor = URL_SAFE_NO_PAD
            .decode(encoded)
            .ok()
            .and_then(|b| serde_json::from_slice::<Cursor>(&b).ok())
            .ok_or_else(|| crate::Error("invalidArgument: cursor".into()))?;
        crate::ensure(
            cursor.namespace == "listening.podcasts"
                && cursor.query == name
                && cursor.args == arguments(name, args),
            "invalidArgument: cursor arguments",
        )?;
        crate::ensure(cursor.revision == s.prefix, "staleCursor")?;
        after = Some(cursor.last);
    }
    Ok(Paging {
        limit,
        offset: args["offset"].as_u64().unwrap_or(0) as usize,
        after,
    })
}
fn page<'a>(
    s: &PodcastsState,
    name: &str,
    args: &Value,
    total: usize,
    iter: impl Iterator<Item = (String, String, Value)> + 'a,
) -> crate::Result<Value> {
    let p = paging(s, name, args)?;
    let mut rows = vec![];
    let mut last = None;
    let mut bytes = 0;
    let mut has_more = false;
    for (sort, id, row) in iter
        .filter(|(sort, id, _)| {
            p.after
                .as_ref()
                .is_none_or(|after| (sort, id) > (&after.0, &after.1))
        })
        .skip(p.offset)
    {
        let size = canonical(&row)?.len();
        if size > 900_000 {
            return Ok(outcome("unavailable"));
        }
        if rows.len() == p.limit || bytes + size > 900_000 {
            has_more = true;
            break;
        }
        bytes += size;
        last = Some((sort, id));
        rows.push(row);
    }
    let next = if has_more {
        last.map(|last| {
            URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(&Cursor {
                    namespace: "listening.podcasts".into(),
                    query: name.into(),
                    args: arguments(name, args),
                    revision: s.prefix.clone(),
                    last,
                })
                .unwrap_or_default(),
            )
        })
    } else {
        None
    };
    let mut value = json!({"rows":rows,"next":next,"total":total});
    if args.get("offset").is_some() {
        value["items"] = value["rows"].clone();
        value["nextOffset"] = if has_more {
            json!(p.offset + rows.len())
        } else {
            Value::Null
        };
    }
    Ok(value)
}
fn indexed(
    s: &PodcastsState,
    name: &str,
    args: &Value,
    parts: &[&str],
    row: impl Fn(&str) -> Value,
) -> crate::Result<Value> {
    let empty = BTreeSet::new();
    let set = s.indexes.get(&index(parts)).unwrap_or(&empty);
    let p = paging(s, name, args)?;
    let iter: Box<dyn Iterator<Item = &(String, String)>> = if let Some(after) = p.after {
        Box::new(set.range((Excluded(after), Unbounded)))
    } else {
        Box::new(set.iter())
    };
    page(
        s,
        name,
        args,
        set.len(),
        iter.map(|(sort, id)| (sort.clone(), id.clone(), row(id))),
    )
}
pub(super) fn query(s: &PodcastsState, name: &str, args: &Value) -> crate::Result<Value> {
    let lookup = match name {
        "episode" => "getEpisode",
        "queue" => "getQueue",
        _ => name,
    };
    let specs = specs::queries();
    let spec = specs
        .iter()
        .find(|spec| spec.name == lookup)
        .ok_or_else(|| crate::Error("Unknown query".into()))?;
    crate::ensure(
        validation::valid(&spec.input_schema, args),
        "invalidArgument: query arguments",
    )?;
    if name == "read" {
        return Ok(s.projection());
    }
    let result = query_value(s, name, args);
    let value = match result {
        Err(e) if e.0 == "staleCursor" => outcome("staleCursor"),
        other => other?,
    };
    if canonical(&value)?.len() > 1_048_000 {
        return Ok(
            json!({"revision":s.prefix,"value":{"outcome":"unavailable","reason":"responseTooLarge"}}),
        );
    }
    // Preview read aliases and explicit offset paging preserve their original shape.
    if name == "getEpisode" || args.get("offset").is_some() {
        Ok(value)
    } else {
        Ok(json!({"revision":s.prefix,"value":value}))
    }
}
fn query_value(s: &PodcastsState, name: &str, a: &Value) -> crate::Result<Value> {
    let id = text(a, "id");
    let episode = text(a, "episode");
    match name {
        "shows"=>indexed(s,name,a,&["shows",if a["following"].as_bool().unwrap_or(true) {"true"} else {"false"}],|id|fields(&s.shows[id],&["id","title","url","following","revision"])),
        "show"=>Ok(s.shows.get(id).map(|v|json!({"show":v,"skipIntro":v["skipIntro"],"skipOutro":v["skipOutro"],"episodeCount":s.count(&["episodes",id,""])})).unwrap_or_else(||outcome("notFound"))),
        "episodes"=>indexed(s,name,a,&["episodes",text(a,"show"),text(a,"state")],|id|s.row(id)),
        "episode"|"episodeDetail"=>Ok(s.detail(id)),
        "getEpisode"=>Ok(s.episodes.get(id).cloned().unwrap_or(Value::Null)),
        "queue"|"getQueue"=>{
            let ids=items(&s.queue["episodes"]);Ok(json!({"head":s.queue["revision"],"page":page(s,name,a,ids.len(),ids.iter().enumerate().map(|(i,id)|(format!("{i:08}"),id.as_str().unwrap_or("").into(),s.row(id.as_str().unwrap_or("")))))?}))
        },
        "playbackContext"=>{
            let Some(e)=s.episodes.get(episode) else {return Ok(outcome("notFound"));};let mut preferences=json!({});let mut heads=json!({});
            for (scope,target) in [("global",""),("show",text(e,"show")),("episode",episode)] {
                for field in ["speed","backward","forward","shortenSilence","levelSpeech","monoAudio","skipSponsors","skipDetectedSponsors","skipAdChapters","doublePress","triplePress","carUsesChapters","sentenceRewind","smartResume","markButton"] {
                    if let Some(pref)=s.preferences.get(&format!("{scope}:{target}:{field}")) {heads[&format!("{scope}:{target}:{field}")]=pref["revision"].clone();if !pref["value"].is_null() {preferences[field]=pref["value"].clone();}}
                }
            }
            let ids=items(&s.queue["episodes"]);let next=ids.iter().position(|v|v==episode).and_then(|i|ids.get(i+1)).and_then(Value::as_str).map(|id|s.row(id));
            let segment=s.recordings.get(&recording_key(episode,text(a,"recording"),"segments")).unwrap_or(&Value::Null);
            let chapter=s.recordings.get(&recording_key(episode,text(a,"recording"),"chapters")).unwrap_or(&Value::Null);
            Ok(json!({"episode":s.row(episode),"queueHead":s.queue["revision"],"next":next,"preferences":preferences,"preferenceHeads":heads,"segmentHead":segment["revision"],"chapterHead":chapter["revision"],"transcriptID":s.selected.get(episode)}))
        },
        "playlists"=>indexed(s,name,a,&["playlists",if a["archived"]==true {"true"} else {"false"}],|id|{let mut row=fields(&s.playlists[id],&["id","name","mode","revision"]);row["alternativeCount"]=json!(s.conflicts.get(id).map_or(0,Vec::len));row}),
        "playlist"=>Ok(s.playlists.get(id).map(|v|json!({"rule":fields(v,&["id","name","mode","allShows","includeFinished","archived","shows","episodes","excluded","pinned","included","order","progress","maxMinutes","titleContains"]),"revision":v["revision"],"alternativeCount":s.conflicts.get(id).map_or(0,Vec::len),"extensions":v["extensions"]})).unwrap_or_else(||outcome("notFound"))),
        "notes"=>indexed(s,name,a,&["notes",episode],|id|{let v=&s.notes[id];let (short,truncated)=preview(text(v,"text"));let (quote,quote_truncated)=preview(text(v,"quote"));let mut row=fields(v,&["id","episode","seconds","revision","creationRevision","created","anchorClaimed"]);row["authorLabel"]=v["creation"]["authorLabel"].clone();row["origin"]=v["creation"]["origin"].clone();row["textPreview"]=json!(short);if v.get("quote").is_some() {row["quotePreview"]=json!(quote);}row["truncated"]=json!(truncated || quote_truncated);row["alternativeCount"]=json!(s.conflicts.get(id).map_or(0,Vec::len));row}),
        "note"=>Ok(s.notes.get(id).map(|v|if v["deleted"]==true {json!({"outcome":"deleted","note":v,"alternativeCount":s.conflicts.get(id).map_or(0,Vec::len)})} else {json!({"note":fields(v,&["id","episode","show","seconds","revision","author","authorLabel","origin","clock","created","extensions","sourceStatus"]),"text":v["text"],"quote":v["quote"],"anchor":v["anchor"],"capture":v["capture"],"creationRevision":v["creationRevision"],"creation":v["creation"],"lastTextEditor":v["lastTextEditor"],"alternativeCount":s.conflicts.get(id).map_or(0,Vec::len)})}).unwrap_or_else(||outcome("notFound"))),
        "recordingContent"=>{
            let Some(v)=s.recordings.get(&recording_key(episode,text(a,"recording"),text(a,"kind"))) else {return Ok(outcome("notFound"));};let list=items(&v[if a["kind"]=="segments" {"segments"} else {"entries"}]);
            Ok(json!({"head":v["revision"],"source":v["source"],"contentOrigin":v["contentOrigin"],"page":page(s,name,a,list.len(),list.iter().map(|v|(format!("{}:{}",number(&v["start"]),text(v,"id")),text(v,"id").into(),v.clone())))?}))
        },
        "transcripts"=>indexed(s,name,a,&["transcripts",episode],|id|{let v=&s.transcripts[id];let mut row=fields(v,&["id","episode","blob","source","timed","recording","language","revision","sourceStatus"]);row["selected"]=json!(s.selected.get(text(v,"episode")).is_some_and(|selected|selected==id));row}),
        "preferences"=>{
            // Shared preference heads, so a writer can supply `expect` for setPreferences.
            let scope=text(a,"scope");let target=a.get("target").and_then(Value::as_str);
            let rows:Vec<_>=s.preferences.iter().filter(|(_,v)|(scope.is_empty()||v["scope"]==scope)&&target.is_none_or(|t|v["target"].as_str().unwrap_or("")==t)).collect();
            page(s,name,a,rows.len(),rows.into_iter().map(|(k,v)|{let mut row=fields(v,&["scope","target","field","value","revision","author","authorLabel","origin"]);row["key"]=json!(k);(k.clone(),k.clone(),row)}))
        },
        "recordings"=>{
            // Which recordings carry chapters or segments, without reading their entries.
            let kind=text(a,"kind");
            let rows:Vec<_>=s.recordings.iter().filter(|(_,v)|(episode.is_empty()||v["episode"]==episode)&&(kind.is_empty()||v.get(if kind=="segments" {"segments"} else {"entries"}).is_some())).collect();
            page(s,name,a,rows.len(),rows.into_iter().map(|(k,v)|{let kind=if v.get("segments").is_some() {"segments"} else {"chapters"};let count=items(&v[if kind=="segments" {"segments"} else {"entries"}]).len();(k.clone(),k.clone(),json!({"episode":v["episode"],"show":v["show"],"recording":v["recording"],"kind":kind,"head":v["revision"],"source":v["source"],"contentOrigin":v["contentOrigin"],"personReviewed":v["personReviewed"],"count":count}))}))
        },
        "history"=>if a["mode"]=="importedSession" {
            // Episodes whose position or state came from an authenticated imported baseline.
            let empty=BTreeSet::new();let set=s.indexes.get(&index(&["history","all"])).unwrap_or(&empty);
            let rows:Vec<_>=set.iter().filter(|(_,id)|s.episodes.get(id).is_some_and(|e|e["positionBaseline"]==true||e["stateBaseline"]==true)).collect();
            page(s,name,a,rows.len(),rows.into_iter().map(|(sort,id)|{let mut row=s.row(id);let e=&s.episodes[id];if let Some(date)=e.get("stateUpdated") {row["updated"]=date.clone();}row["positionBaseline"]=json!(e["positionBaseline"]==true);row["stateBaseline"]=json!(e["stateBaseline"]==true);(sort.clone(),id.clone(),row)}))
        } else {indexed(s,name,a,&["history",if a["finishedOnly"]==true {"finished"} else {"all"}],|id|{let mut row=s.row(id);if let Some(date)=s.episodes[id].get("stateUpdated") {row["updated"]=date.clone();}row})},
        "jobs"=>indexed(s,name,a,&["jobs",text(a,"kind"),episode,text(a,"status")],|id|fields(&s.jobs[id],&["id","kind","requestRevision","worker","status","responseRevision","sourceRefs","deadline"])),
        "contributions"=>if !id.is_empty() {Ok(s.contributions.get(&key(&[text(a,"kind"),id])).cloned().unwrap_or_else(||outcome("notFound")))} else {indexed(s,name,a,&["contributions",text(a,"kind"),episode],|id|{let v=&s.contributions[id];let mut row=fields(v,&["id","question","reference","proposalRevision","acceptanceRevision","author","origin","sourceStatus"]);if let Some(claims)=v["claims"].as_array() {row["claimCount"]=json!(claims.len());row["truncated"]=json!(true);}
            if let Some(t)=v["text"].as_str() {let (short,truncated)=preview(t);row["textPreview"]=json!(short);row["truncated"]=json!(truncated);}row})},
        "listeningCounts"=>{
            let show=text(a,"show");let queued=items(&s.queue["episodes"]).iter().filter(|id|show.is_empty() || s.episodes.get(id.as_str().unwrap_or("")).is_some_and(|e|e["show"]==show)).count();
            Ok(json!({"followed":if show.is_empty() {s.count(&["shows","true"])} else {usize::from(s.shows.get(show).is_some_and(|s|s["following"]==true))},"episodes":s.count(&["episodes",show,""]),"inProgress":s.count(&["episodes",show,"inProgress"]),"finished":(["doneEnough","completed","abandoned"].iter().map(|state|s.count(&["episodes",show,state])).sum::<usize>()),"queued":queued,"notes":if show.is_empty() {s.count(&["notes",""])} else {s.count(&["showNotes",show])},"transcripts":if show.is_empty() {s.count(&["transcripts",""])} else {s.count(&["showTranscripts",show])},"pendingJobs":s.count(&["pendingJobs",show]),"conflicts":s.conflict_counts.get(show).copied().unwrap_or(0)}))
        },
        "conflicts"=>{let c=s.conflicts.get(text(a,"object")).map(Vec::as_slice).unwrap_or(&[]);page(s,name,a,c.len(),c.iter().map(|v|(order(v),text(v,"revision").into(),v.clone())))},
        "invalid"=>page(s,name,a,s.invalid.len(),s.invalid.iter().enumerate().map(|(i,id)|(format!("{i:016x}"),id.clone(),json!(id)))),
        _=>Err(crate::Error("Unknown query".into())),
    }
}
