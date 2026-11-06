//! Podcast projections, bounded queries and pure 0.1 import planning.
//! No I/O, wall clock, source-byte verification or worker execution occurs here.
pub mod evidence;
pub mod import;
mod query;
mod specs;
mod validation;

use crate::{
    domain::{AdmittedOperation, DomainModule, Reducer, Spec},
    model::MemberKind,
    records::{canonical, digest},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::OnceLock,
};

/// Podcast domain module. `episode` and `queue` write tools keep their preview names.
pub struct ListeningPodcasts;
/// Authenticated context missing from the current engine's `OperationView`.
/// Hosts must obtain member kind from verified authority, never operation payloads.
#[derive(Clone, Copy, Default)]
pub struct ApplyContext {
    /// Granted kind for this operation's signer. None fails closed for role-sensitive actions.
    pub member_kind: Option<MemberKind>,
    /// True only for evaluated legacy baseline effects supplied by the import adapter.
    pub imported_baseline: bool,
}
/// Serializable podcast projections. This schema deliberately rejects preview checkpoints.
#[derive(Clone, Serialize, Deserialize)]
pub struct PodcastsState {
    schema: u32,
    prefix: String,
    shows: BTreeMap<String, Value>,
    episodes: BTreeMap<String, Value>,
    queue: Value,
    preferences: BTreeMap<String, Value>,
    notes: BTreeMap<String, Value>,
    recordings: BTreeMap<String, Value>,
    transcripts: BTreeMap<String, Value>,
    selected: BTreeMap<String, String>,
    playlists: BTreeMap<String, Value>,
    jobs: BTreeMap<String, Value>,
    requests: BTreeMap<String, String>,
    contributions: BTreeMap<String, Value>,
    receipts: BTreeMap<String, Value>,
    conflicts: BTreeMap<String, Vec<Value>>,
    invalid: Vec<String>,
    conflict_counts: BTreeMap<String, usize>,
    // Query indexes contain sort keys and IDs, not copies of payloads.
    indexes: BTreeMap<String, BTreeSet<(String, String)>>,
    memberships: BTreeMap<String, Vec<(String, String)>>,
}
impl Default for PodcastsState {
    fn default() -> Self {
        Self {
            schema: 2,
            prefix: String::new(),
            shows: BTreeMap::new(),
            episodes: BTreeMap::new(),
            queue: json!({"episodes":[]}),
            preferences: BTreeMap::new(),
            notes: BTreeMap::new(),
            recordings: BTreeMap::new(),
            transcripts: BTreeMap::new(),
            selected: BTreeMap::new(),
            playlists: BTreeMap::new(),
            jobs: BTreeMap::new(),
            requests: BTreeMap::new(),
            contributions: BTreeMap::new(),
            receipts: BTreeMap::new(),
            conflicts: BTreeMap::new(),
            invalid: vec![],
            conflict_counts: BTreeMap::new(),
            indexes: BTreeMap::new(),
            memberships: BTreeMap::new(),
        }
    }
}
fn operation_specs() -> &'static [Spec] {
    static SPECS: OnceLock<Vec<Spec>> = OnceLock::new();
    SPECS.get_or_init(specs::operations)
}
fn text<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or("")
}
fn items(v: &Value) -> &[Value] {
    v.as_array().map(Vec::as_slice).unwrap_or(&[])
}
fn key(parts: &[&str]) -> String {
    serde_json::to_string(parts).unwrap_or_default()
}
fn matches_head(p: &Value, control: &str, head: &Value) -> bool {
    p.get(control).is_none_or(|expect| expect == head)
}
fn editor(op: &AdmittedOperation) -> Value {
    json!({"revision":op.id,"author":op.author,"authorLabel":op.author_label,"origin":op.origin,"clock":op.clock})
}
fn attributed(mut value: Value, op: &AdmittedOperation) -> Value {
    if let Some(fields) = value.as_object_mut() {
        for (key, text) in [
            ("revision", &op.id),
            ("author", &op.author),
            ("authorLabel", &op.author_label),
            ("origin", &op.origin),
        ] {
            match fields.get_mut(key) {
                Some(Value::String(old)) => old.clone_from(text),
                Some(old) => *old = Value::String(text.clone()),
                None => {
                    fields.insert(key.into(), Value::String(text.clone()));
                }
            }
        }
        if let Some(clock) = fields.get_mut("clock") {
            *clock = json!(op.clock);
        } else {
            fields.insert("clock".into(), json!(op.clock));
        }
    }
    value
}
fn merged(old: &Value, op: &AdmittedOperation) -> Value {
    let mut result = if old.is_object() {
        old.clone()
    } else {
        json!({})
    };
    merge_into(&mut result, op);
    result
}
fn merge_into(result: &mut Value, op: &AdmittedOperation) {
    let Some(spec) = operation_specs().iter().find(|s| s.name == op.kind) else {
        return;
    };
    if let Some(fields) = op.payload.as_object() {
        for (k, v) in fields {
            if let Some(schema) = spec.input_schema["properties"].get(k) {
                if [
                    "expect",
                    "seek",
                    "expectedPosition",
                    "expectedState",
                    "resolves",
                    "baseQueue",
                    "events",
                    "changes",
                    "metadata",
                    "inProgress",
                ]
                .contains(&k.as_str())
                {
                    continue;
                }
                if v.is_object() || v.is_array() {
                    result[k] = validation::normalize(schema, v);
                } else if result.get(k) != Some(v) {
                    result[k] = v.clone();
                }
            } else {
                if !result["extensions"].is_object() {
                    result["extensions"] = json!({});
                }
                result["extensions"][k] = v.clone();
            }
        }
    }
    *result = attributed(std::mem::take(result), op);
}
// Field order matches canonical OperationView JSON. Borrow metadata rather than cloning it
// into an intermediate JSON object for every playback report; nested payload keys still sort.
fn operation_prefix(previous: &str, op: &AdmittedOperation) -> String {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Ordered<'a> {
        author: &'a str,
        author_label: &'a str,
        clock: u64,
        created: &'a str,
        id: &'a str,
        kind: &'a str,
        origin: &'a str,
        payload: Value,
    }
    let mut payload = op.payload.clone();
    payload.sort_all_objects();
    let ordered = Ordered {
        author: &op.author,
        author_label: &op.author_label,
        clock: op.clock,
        created: &op.created,
        id: &op.id,
        kind: &op.kind,
        origin: &op.origin,
        payload,
    };
    digest(&serde_json::to_vec(&(previous, ordered)).unwrap_or_default())
}
// Keep in sync with index_episode's membership and ordering dependencies.
const EPISODE_INDEX_FIELDS: [&str; 5] = [
    "show",
    "consumption",
    "published",
    "stateRevision",
    "stateUpdated",
];

fn recording_key(episode: &str, recording: &str, kind: &str) -> String {
    key(&[episode, recording, kind])
}
impl DomainModule for ListeningPodcasts {
    fn namespace(&self) -> &'static str {
        "listening.podcasts"
    }
    fn display_name(&self) -> &'static str {
        "listening"
    }
    fn write_phrase(&self, kind: &str) -> Option<&'static str> {
        Some(match kind {
            "follow" => "followed a show",
            "unfollow" => "unfollowed a show",
            "episode" => "added an episode",
            "position" => "updated playback",
            "queue" => "updated the listening queue",
            k if operation_specs().iter().any(|s| s.name == k) => "updated listening",
            _ => return None,
        })
    }
    fn contribution_names(&self, kind: &str) -> (&'static str, &'static str) {
        match kind {
            "follow" | "unfollow" | "editShow" => ("show", "shows"),
            "episode" | "position" | "setState" => ("episode", "episodes"),
            "queue" => ("queue update", "queue updates"),
            _ => ("contribution", "contributions"),
        }
    }
    fn operations(&self) -> Vec<Spec> {
        operation_specs().to_vec()
    }
    fn queries(&self) -> Vec<Spec> {
        specs::queries()
    }
    fn fold(&self, ops: &[AdmittedOperation]) -> Value {
        let mut state = PodcastsState::default();
        for op in ops {
            self.apply(&mut state, op);
        }
        state.projection()
    }
}
impl Reducer for ListeningPodcasts {
    type State = PodcastsState;
    fn apply(&self, state: &mut PodcastsState, op: &AdmittedOperation) {
        self.apply_with_context(state, op, ApplyContext::default());
    }
    fn query(&self, state: &PodcastsState, name: &str, args: &Value) -> crate::Result<Value> {
        query::query(state, name, args)
    }
}
impl PodcastsState {
    fn projection(&self) -> Value {
        fn ordered(map: &BTreeMap<String, Value>) -> Vec<&Value> {
            let mut v: Vec<_> = map.values().collect();
            v.sort_by_key(|v| (v["clock"].as_u64(), text(v, "author"), text(v, "revision")));
            v
        }
        json!({"shows":ordered(&self.shows),"episodes":ordered(&self.episodes),"queue":self.queue,"notes":ordered(&self.notes),"playlists":ordered(&self.playlists),"transcripts":ordered(&self.transcripts),"jobs":ordered(&self.jobs),"contributions":ordered(&self.contributions),"preferences":self.preferences,"recordings":self.recordings,"receipts":self.receipts,"conflicts":self.conflicts.values().flatten().collect::<Vec<_>>(),"invalid":self.invalid})
    }
    fn conflict(
        &mut self,
        object: &str,
        component: &str,
        found: Value,
        op: &AdmittedOperation,
        outcome: &str,
    ) {
        let previous = match component {
            "show" => self.shows.get(object),
            "positionRevision" | "stateRevision" | "metadataRevision" | "parent" => {
                self.episodes.get(object)
            }
            "note" | "text" => self.notes.get(object),
            "playlist" => self.playlists.get(object),
            "queue" => Some(&self.queue),
            _ => None,
        };
        let mut candidate = merged(previous.unwrap_or(&Value::Null), op);
        if ["positionRevision", "stateRevision", "metadataRevision"].contains(&component) {
            candidate[component] = json!(op.id);
            candidate["updated"] = json!(op.created);
        }
        if matches!(op.kind.as_str(), "editNote" | "resolveNote") {
            candidate["lastTextEditor"] = editor(op);
        }
        if op.kind == "savePlaylist" {
            candidate = playlist_value(previous.unwrap_or(&Value::Null), op);
        }
        let show = op
            .payload
            .get("show")
            .and_then(Value::as_str)
            .or_else(|| previous.and_then(|v| v.get("show")).and_then(Value::as_str))
            .unwrap_or(if component == "show" { object } else { "" })
            .to_owned();
        *self.conflict_counts.entry(String::new()).or_default() += 1;
        if !show.is_empty() {
            *self.conflict_counts.entry(show.clone()).or_default() += 1;
        }
        // Command controls and the exact complete attempt remain available for reconciliation.
        candidate["command"] = op.payload.clone();
        self.conflicts.entry(object.into()).or_default().push(attributed(json!({"object":object,"show":show,"component":component,"expected":op.payload.get("expect").cloned().unwrap_or(Value::Null),"found":found,"outcome":outcome,"candidate":candidate,"historical":false}),op));
    }
    fn alternatives(&self, id: &str) -> Vec<String> {
        let mut ids: Vec<_> = self
            .conflicts
            .get(id)
            .into_iter()
            .flatten()
            .filter(|c| matches!(text(c, "component"), "note" | "text"))
            .map(|c| text(c, "revision").to_owned())
            .collect();
        ids.sort();
        ids
    }
    fn episode_parent(&mut self, id: &str, op: &AdmittedOperation) -> bool {
        if let Some(existing) = self.episodes.get(id) {
            if op.payload.get("show").is_some()
                && existing.get("show").is_some()
                && existing["show"] != op.payload["show"]
            {
                self.conflict(id, "parent", existing["show"].clone(), op, "parentMismatch");
                return false;
            }
        }
        true
    }
    fn save_episode(&mut self, id: &str, value: Value) {
        // Playback progress usually changes no collection membership or sort key.
        let reindex = self.episodes.get(id).is_none_or(|old| {
            EPISODE_INDEX_FIELDS
                .iter()
                .any(|field| old.get(*field) != value.get(*field))
        });
        self.episodes.insert(id.into(), value);
        if reindex {
            self.index_episode(id);
        }
    }
    fn receipt(&mut self, op: &AdmittedOperation, outcome: &str) {
        let mut receipt = merged(&json!({}), op);
        receipt["outcome"] = json!(outcome);
        receipt["payload"] = op.payload.clone();
        receipt["bodyDigest"] = json!(digest(&canonical(&op.payload).unwrap_or_default()));
        self.receipts.insert(
            key(&[&op.author, &op.kind, text(&op.payload, "id")]),
            receipt,
        );
    }
    fn retry(&mut self, op: &AdmittedOperation) -> bool {
        let k = key(&[&op.author, &op.kind, text(&op.payload, "id")]);
        if let Some(previous) = self.receipts.get(&k) {
            if previous["bodyDigest"] != digest(&canonical(&op.payload).unwrap_or_default()) {
                self.conflict(
                    text(&op.payload, "id"),
                    "receipt",
                    previous["revision"].clone(),
                    op,
                    "identityConflict",
                );
            }
            true
        } else {
            false
        }
    }
}
impl ListeningPodcasts {
    /// Engine integration hook: bind cursors to the verified admitted-prefix digest after an
    /// admission pass, including prefixes containing versions not delivered to this reducer.
    /// Until wired, the reducer uses a deterministic hash of every delivered OperationView.
    pub fn bind_admitted_prefix(
        &self,
        state: &mut PodcastsState,
        prefix: &str,
    ) -> crate::Result<()> {
        crate::ensure(
            prefix.len() == 64
                && prefix
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalidAdmittedPrefix",
        )?;
        state.prefix = prefix.to_owned();
        Ok(())
    }
    /// Apply with authority-derived role context. The ordinary engine path fails closed when
    /// it cannot distinguish app/device from server. `origin` alone authenticates agent status.
    pub fn apply_with_context(
        &self,
        s: &mut PodcastsState,
        op: &AdmittedOperation,
        context: ApplyContext,
    ) {
        s.prefix = operation_prefix(&s.prefix, op);
        if !operation_specs().iter().any(|spec| spec.name == op.kind) {
            return;
        }
        if !validation::payload(&op.kind, &op.payload) {
            s.invalid.push(op.id.clone());
            return;
        }
        let p = &op.payload;
        let id = text(p, "id");
        if context
            .member_kind
            .is_some_and(|kind| (kind == MemberKind::Agent) != (op.origin == "ai"))
        {
            s.invalid.push(op.id.clone());
            return;
        }
        let device = matches!(
            context.member_kind,
            Some(MemberKind::Device | MemberKind::App)
        );
        let agent = op.origin == "ai"
            && context
                .member_kind
                .is_none_or(|kind| kind == MemberKind::Agent);
        let needs_device = matches!(
            op.kind.as_str(),
            "requestTranscript"
                | "cancelTranscript"
                | "askQuestion"
                | "cancelQuestion"
                | "acceptAnswer"
                | "cancelCapture"
                | "acceptContext"
        );
        let needs_agent = matches!(
            op.kind.as_str(),
            "supplyTranscript" | "answerQuestion" | "respondCapture" | "proposeContext"
        );
        if needs_device && !device || needs_agent && !agent {
            s.conflict(
                id,
                "role",
                Value::Null,
                op,
                if context.member_kind.is_none() && op.origin != "ai" {
                    "unavailableRole"
                } else {
                    "roleDenied"
                },
            );
            return;
        }
        match op.kind.as_str() {
            "follow" | "unfollow" | "editShow" => {
                let old = s.shows.get(id).cloned().unwrap_or_else(|| json!({"id":id}));
                if !matches_head(p, "expect", &old["revision"])
                    || context.imported_baseline && !old["revision"].is_null()
                {
                    s.conflict(id, "show", old["revision"].clone(), op, "stale");
                    return;
                }
                if op.kind == "editShow" && !s.shows.contains_key(id) {
                    s.invalid.push(op.id.clone());
                    return;
                }
                let mut show = merged(&old, op);
                if op.kind == "follow" && show.get("title").is_none() {
                    show["title"] = p["url"].clone();
                }
                if op.kind != "editShow" {
                    show["following"] = json!(op.kind == "follow");
                    show["followed"] = show["following"].clone();
                }
                s.shows.insert(id.into(), show);
                s.index_show(id);
            }
            "episode" | "position" | "setState" | "recoverPosition" => {
                if !s.episode_parent(id, op) {
                    return;
                }
                let empty = json!({"id":id});
                let old = s.episodes.get(id).unwrap_or(&empty);
                let component = if op.kind == "episode" {
                    "metadataRevision"
                } else if op.kind == "setState" {
                    "stateRevision"
                } else {
                    "positionRevision"
                };
                let good = match op.kind.as_str() {
                    "episode" => matches_head(p, "expect", &old["metadataRevision"]),
                    "position" => {
                        let stale = p.get("expect").is_some()
                            && !matches_head(p, "expect", &old[component]);
                        !stale
                            && (p["seek"] == true
                                || p.get("expect").is_some()
                                || old["positionBaseline"] == true
                                || p["seconds"].as_f64() >= old["seconds"].as_f64())
                    }
                    "recoverPosition" => {
                        p["expectedPosition"] == old["positionRevision"]
                            && p["expectedState"] == old["stateRevision"]
                            && s.shows.contains_key(text(p, "show"))
                    }
                    _ => matches_head(p, "expect", &old[component]),
                };
                if !good || context.imported_baseline && !old[component].is_null() {
                    s.conflict(
                        id,
                        component,
                        old[component].clone(),
                        op,
                        if op.kind == "position" && p.get("expect").is_none() {
                            "passiveRegression"
                        } else {
                            "stale"
                        },
                    );
                    return;
                }
                let previous_index = s
                    .episodes
                    .get(id)
                    .map(|v| EPISODE_INDEX_FIELDS.map(|field| v.get(field).cloned()));
                // Validation, parent and CAS checks have all passed. Update the projection in
                // place; no complete episode clone is needed for each playback report.
                let value = s.episodes.entry(id.into()).or_insert(empty);
                merge_into(value, op);
                match op.kind.as_str() {
                    "episode" => {
                        value["metadataRevision"] = json!(op.id);
                        value["metadataAvailable"] = json!(true);
                    }
                    "recoverPosition" => {
                        value["positionRevision"] = json!(op.id);
                        if p["inProgress"] == true {
                            value["consumption"] = json!("inProgress");
                            value["stateRevision"] = json!(op.id);
                        }
                    }
                    _ => {
                        value[component] = json!(op.id);
                    }
                }
                if op.kind != "episode" {
                    value["updated"] = json!(op.created);
                }
                if op.kind == "position" || op.kind == "recoverPosition" {
                    value["positionBaseline"] = json!(context.imported_baseline);
                }
                if op.kind == "setState" || op.kind == "recoverPosition" && p["inProgress"] == true
                {
                    value["stateBaseline"] = json!(context.imported_baseline);
                    value["stateUpdated"] = json!(op.created);
                }
                let reindex = previous_index.is_none_or(|previous| {
                    EPISODE_INDEX_FIELDS
                        .iter()
                        .zip(previous)
                        .any(|(field, old)| value.get(*field) != old.as_ref())
                });
                if reindex {
                    s.index_episode(id);
                }
            }
            "queue" => {
                if !matches_head(p, "expect", &s.queue["revision"]) {
                    s.conflict("queue", "queue", s.queue["revision"].clone(), op, "stale");
                    return;
                }
                // Validate parent consistency for the entire metadata batch before any effect.
                if items(&p["metadata"]).iter().any(|m| {
                    s.episodes
                        .get(text(m, "id"))
                        .is_some_and(|e| e.get("show").is_some() && e["show"] != m["show"])
                }) {
                    s.conflict("queue", "metadata", Value::Null, op, "parentMismatch");
                    return;
                }
                s.queue = merged(&s.queue, op);
                for metadata in items(&p["metadata"]) {
                    let mut command = op.clone();
                    command.kind = "episode".into();
                    command.payload = metadata.clone();
                    let eid = text(metadata, "id");
                    let mut value = merged(s.episodes.get(eid).unwrap_or(&Value::Null), &command);
                    value["metadataRevision"] = json!(op.id);
                    value["metadataAvailable"] = json!(true);
                    s.save_episode(eid, value);
                }
            }
            "setPreferences" => {
                if s.retry(op) {
                    return;
                }
                let stale = items(&p["changes"]).iter().any(|c| {
                    c["expect"]
                        != s.preferences
                            .get(&validation::preference_key(c))
                            .unwrap_or(&Value::Null)["revision"]
                });
                if stale {
                    s.conflict(
                        id,
                        "preferences",
                        json!(items(&p["changes"])
                            .iter()
                            .map(|c| s
                                .preferences
                                .get(&validation::preference_key(c))
                                .cloned()
                                .unwrap_or(Value::Null))
                            .collect::<Vec<_>>()),
                        op,
                        "stale",
                    );
                    s.receipt(op, "stale");
                    return;
                }
                let spec = operation_specs()
                    .iter()
                    .find(|spec| spec.name == "setPreferences");
                let normalized = spec
                    .map(|spec| validation::normalize(&spec.input_schema, p))
                    .unwrap_or_else(|| p.clone());
                for c in items(&normalized["changes"]) {
                    let mut value = c.clone();
                    if let Some(o) = value.as_object_mut() {
                        o.remove("expect");
                    }
                    s.preferences
                        .insert(validation::preference_key(c), attributed(value, op));
                }
                s.receipt(op, "applied");
            }
            "completePlayback" => self.complete(s, op),
            "addNote" | "editNote" | "resolveNote" | "deleteNote" => self.note(s, op, device),
            "setSegments" | "setChapters" => {
                let kind = if op.kind == "setSegments" {
                    "segments"
                } else {
                    "chapters"
                };
                let rid = recording_key(text(p, "episode"), text(p, "recording"), kind);
                let old = s.recordings.get(&rid).cloned().unwrap_or(Value::Null);
                let reviewed = old["personReviewed"] == true;
                let person = text(p, "source") == "person" && device;
                if !matches_head(p, "expect", &old["revision"]) || reviewed && !person {
                    s.conflict(
                        text(p, "episode"),
                        kind,
                        old["revision"].clone(),
                        op,
                        if reviewed && !person {
                            "personProtected"
                        } else {
                            "stale"
                        },
                    );
                    return;
                }
                let mut value = merged(&old, op);
                value["personReviewed"] = json!(person);
                let field = if kind == "segments" {
                    "segments"
                } else {
                    "entries"
                };
                if let Some(a) = value[field].as_array_mut() {
                    for (i, v) in a.iter_mut().enumerate() {
                        v["id"] = json!(format!("{}:{i}", op.id));
                    }
                    a.sort_by(|a, b| {
                        a["start"]
                            .as_f64()
                            .unwrap_or(0.0)
                            .total_cmp(&b["start"].as_f64().unwrap_or(0.0))
                            .then_with(|| text(a, "id").cmp(text(b, "id")))
                    });
                }
                s.recordings.insert(rid, value);
            }
            "saveTranscript" => {
                if let Some(old) = s.transcripts.get(id) {
                    s.conflict(id, "transcript", old["revision"].clone(), op, "immutable");
                    return;
                }
                let mut value = merged(&json!({}), op);
                value["sourceStatus"] = json!("pendingSource");
                let episode = text(p, "episode");
                let selected = s.selected.get(episode).and_then(|id| s.transcripts.get(id));
                if selected.is_none_or(|old| transcript_rank(&value) >= transcript_rank(old)) {
                    s.selected.insert(episode.into(), id.into());
                }
                value["personReviewed"] = json!(text(p, "source") == "person" && device);
                s.transcripts.insert(id.into(), value);
                s.index_transcript(id);
                s.refresh_source_dependents(id);
            }
            "savePlaylist" => {
                let old = s.playlists.get(id).cloned().unwrap_or(Value::Null);
                if !matches_head(p, "expect", &old["revision"]) {
                    s.conflict(id, "playlist", old["revision"].clone(), op, "stale");
                    return;
                }
                let value = playlist_value(&old, op);
                s.playlists.insert(id.into(), value);
                s.index_playlist(id);
            }
            "saveAnswer" => {
                let cid = key(&["answer", id]);
                if let Some(old) = s.contributions.get(&cid) {
                    s.conflict(id, "answer", old["revision"].clone(), op, "immutable");
                    return;
                }
                let mut value = merged(&json!({}), op);
                value["kind"] = json!("answer");
                value["sourceStatus"] = json!("pendingSource");
                s.contributions.insert(cid.clone(), value);
                s.index_contribution(&cid);
            }
            "requestTranscript" | "askQuestion" | "cancelTranscript" | "supplyTranscript"
            | "answerQuestion" | "cancelQuestion" | "acceptAnswer" | "respondCapture"
            | "cancelCapture" => self.job(s, op),
            "proposeContext" | "acceptContext" => self.context(s, op),
            _ => {}
        }
    }
}
fn playlist_value(old: &Value, op: &AdmittedOperation) -> Value {
    let mut value = merged(&json!({"extensions":old["extensions"]}), op);
    for field in ["allShows", "includeFinished", "archived"] {
        if value.get(field).is_none() {
            value[field] = json!(false);
        }
    }
    for field in ["shows", "episodes", "excluded", "pinned", "included"] {
        if value.get(field).is_none() {
            value[field] = json!([]);
        }
    }
    for (field, default) in [("order", "newest"), ("progress", "any")] {
        if value.get(field).is_none() {
            value[field] = json!(default);
        }
    }
    value
}
fn transcript_rank(v: &Value) -> (bool, u8) {
    (
        v["timed"] == true,
        match text(v, "source") {
            "person" => 3,
            "publisher" => 2,
            _ => 1,
        },
    )
}
impl ListeningPodcasts {
    fn complete(&self, s: &mut PodcastsState, op: &AdmittedOperation) {
        if s.retry(op) {
            return;
        }
        let p = &op.payload;
        let id = text(p, "id");
        let mut mismatch =
            p["expect"] != s.queue["revision"] || p["baseQueue"] != s.queue["episodes"];
        let mut duplicate = false;
        for event in items(&p["events"]) {
            let previous = s
                .receipts
                .get(&key(&[&op.author, "endEvent", text(event, "eventID")]));
            if let Some(previous) = previous {
                if previous["event"] != *event {
                    mismatch = true;
                }
                duplicate = true;
            }
            let episode = s
                .episodes
                .get(text(event, "episode"))
                .unwrap_or(&Value::Null);
            mismatch |= event["expectedPosition"] != episode["positionRevision"]
                || event["expectedState"] != episode["stateRevision"]
                || episode
                    .get("show")
                    .is_some_and(|show| *show != event["show"]);
        }
        // Bind every event identity, including stale attempts, before returning its receipt.
        // Reusing a stale event under a fresh batch ID cannot change its meaning.
        for event in items(&p["events"]) {
            s.receipts
                .entry(key(&[&op.author, "endEvent", text(event, "eventID")]))
                .or_insert_with(|| attributed(json!({"event":event,"outcome":"stale"}), op));
        }
        if mismatch || duplicate {
            s.conflict(
                id,
                "playback",
                s.queue["revision"].clone(),
                op,
                if duplicate {
                    "eventAlreadyUsed"
                } else {
                    "stale"
                },
            );
            s.receipt(op, "stale");
            return;
        }
        let ended: BTreeSet<_> = items(&p["events"])
            .iter()
            .map(|e| text(e, "episode"))
            .collect();
        for event in items(&p["events"]) {
            let eid = text(event, "episode");
            let mut value = s
                .episodes
                .get(eid)
                .cloned()
                .unwrap_or_else(|| json!({"id":eid}));
            value["show"] = event["show"].clone();
            value["seconds"] = event["endSeconds"].clone();
            value["duration"] = event["actualDuration"].clone();
            value["consumption"] = json!("completed");
            value["positionBaseline"] = json!(false);
            value["stateBaseline"] = json!(false);
            value["stateUpdated"] = json!(op.created);
            value["positionRevision"] = json!(op.id);
            value["stateRevision"] = json!(op.id);
            value["updated"] = json!(op.created);
            s.save_episode(eid, attributed(value, op));
            s.receipts.insert(
                key(&[&op.author, "endEvent", text(event, "eventID")]),
                attributed(json!({"event":event,"outcome":"applied"}), op),
            );
        }
        let remaining: Vec<_> = items(&s.queue["episodes"])
            .iter()
            .filter(|id| !ended.contains(id.as_str().unwrap_or("")))
            .cloned()
            .collect();
        s.queue["episodes"] = json!(remaining);
        s.queue = attributed(s.queue.clone(), op);
        s.receipt(op, "applied");
    }
    fn note(&self, s: &mut PodcastsState, op: &AdmittedOperation, device: bool) {
        let p = &op.payload;
        let id = text(p, "id");
        let old = s.notes.get(id).cloned().unwrap_or(Value::Null);
        if op.kind == "addNote" && !old.is_null() || old["deleted"] == true {
            s.conflict(
                id,
                "note",
                old["revision"].clone(),
                op,
                if old["deleted"] == true {
                    "deleted"
                } else {
                    "immutable"
                },
            );
            return;
        }
        if op.kind != "addNote" && old.is_null() {
            s.invalid.push(op.id.clone());
            return;
        }
        if !matches_head(p, "expect", &old["revision"])
            || op.kind == "resolveNote" && p["resolves"] != json!(s.alternatives(id))
        {
            s.conflict(id, "text", old["revision"].clone(), op, "stale");
            return;
        }
        let mut value = merged(&old, op);
        if op.kind == "addNote" {
            value["creationRevision"] = json!(op.id);
            value["creation"] = editor(op);
            value["creationOrder"] = json!(op.clock);
            value["anchorClaimed"] = json!(p.get("anchor").is_some());
            if p.get("anchor").is_some() {
                value["sourceStatus"] = json!("pendingSource");
                value["quote"] = p["anchor"]["quote"].clone();
            }
            if let Some(capture) = p.get("capture").filter(|c| c["targetAgentID"].is_string()) {
                let cid = text(capture, "requestID");
                let jid = key(&["capture", cid]);
                if !device {
                    s.conflict(cid, "capture", Value::Null, op, "unavailableRole");
                } else if s.jobs.contains_key(&jid) {
                    s.conflict(
                        cid,
                        "capture",
                        s.jobs[&jid]["requestRevision"].clone(),
                        op,
                        "immutable",
                    );
                } else {
                    let job = attributed(
                        json!({"id":cid,"kind":"capture","episode":p["episode"],"show":p["show"],"requestRevision":op.id,"requester":op.author,"worker":capture["targetAgentID"],"status":"pendingSource","sourceRefs":value.get("anchor").map(|a|json!([a])).unwrap_or_else(||json!([])),"capture":value["capture"]}),
                        op,
                    );
                    s.jobs.insert(jid.clone(), job);
                    s.requests.insert(op.id.clone(), jid.clone());
                    s.index_job(&jid);
                }
            }
        }
        if op.kind == "deleteNote" {
            value["deleted"] = json!(true);
        } else {
            value["lastTextEditor"] = editor(op);
        }
        if op.kind == "resolveNote" {
            let all = s.conflicts.remove(id).unwrap_or_default();
            let (resolved, other): (Vec<_>, Vec<_>) = all
                .into_iter()
                .partition(|c| matches!(text(c, "component"), "note" | "text"));
            if !other.is_empty() {
                s.conflicts.insert(id.into(), other);
            }
            for conflict in &resolved {
                if let Some(count) = s.conflict_counts.get_mut("") {
                    *count = count.saturating_sub(1);
                }
                let show = text(conflict, "show");
                if !show.is_empty() {
                    if let Some(count) = s.conflict_counts.get_mut(show) {
                        *count = count.saturating_sub(1);
                    }
                }
            }
            s.receipts.insert(
                key(&[&op.author, "resolvedNote", &op.id]),
                attributed(
                    json!({"object":id,"outcome":"resolved","alternatives":resolved}),
                    op,
                ),
            );
        }
        s.notes.insert(id.into(), value);
        s.index_note(id);
    }
    fn job(&self, s: &mut PodcastsState, op: &AdmittedOperation) {
        let p = &op.payload;
        let id = text(p, "id");
        if matches!(op.kind.as_str(), "requestTranscript" | "askQuestion") {
            let kind = if op.kind == "requestTranscript" {
                "transcript"
            } else {
                "question"
            };
            let jid = key(&[kind, id]);
            if let Some(old) = s.jobs.get(&jid) {
                s.conflict(id, "job", old["requestRevision"].clone(), op, "immutable");
                return;
            }
            let mut value = merged(&json!({}), op);
            value["kind"] = json!(kind);
            value["requestRevision"] = json!(op.id);
            value["requester"] = json!(op.author);
            value["status"] = json!("pendingSource");
            value["sourceRefs"] = p
                .get("scope")
                .cloned()
                .unwrap_or_else(|| json!([p["audio"]]));
            if kind == "question" {
                value["scopeDigest"] = json!(digest(&canonical(&p["scope"]).unwrap_or_default()));
                value["deadline"] = p["expires"].clone();
            }
            s.requests.insert(op.id.clone(), jid.clone());
            s.jobs.insert(jid.clone(), value);
            s.index_job(&jid);
            return;
        }
        let Some(jid) = s.requests.get(text(p, "request")).cloned() else {
            s.conflict(id, "job", Value::Null, op, "missingRequest");
            return;
        };
        let old = s.jobs[&jid].clone();
        let kind = text(&old, "kind");
        let expected_kind = match op.kind.as_str() {
            "cancelTranscript" | "supplyTranscript" => "transcript",
            "respondCapture" | "cancelCapture" => "capture",
            _ => "question",
        };
        if kind != expected_kind || old["id"] != p["id"] {
            s.conflict(
                id,
                "job",
                old["requestRevision"].clone(),
                op,
                "requestMismatch",
            );
            return;
        }
        let cancel = op.kind.starts_with("cancel");
        if cancel && op.kind != "cancelQuestion" && old["requester"] != op.author {
            s.conflict(
                id,
                "job",
                old["requestRevision"].clone(),
                op,
                "requesterOnly",
            );
            return;
        }
        let mut value = old.clone();
        if cancel {
            value["status"] = json!("cancelled");
            value["cancellation"] = editor(op);
        } else if text(&old, "status") == "cancelled" {
            s.conflict(id, "job", old["revision"].clone(), op, "cancelled");
            return;
        } else if op.kind == "acceptAnswer" {
            if old["responseRevision"] != p["response"]
                || old["responseRevision"].is_null()
                || old["status"] == "conflict"
                || old.get("acceptance").is_some()
            {
                s.conflict(
                    id,
                    "acceptance",
                    old["responseRevision"].clone(),
                    op,
                    "responseMismatch",
                );
                return;
            }
            value["acceptance"] = editor(op);
            value["status"] = json!("acceptedPendingVerification");
            let cid = key(&["answer", id]);
            if s.contributions.contains_key(&cid) {
                s.conflict(
                    id,
                    "answer",
                    s.contributions[&cid]["revision"].clone(),
                    op,
                    "immutable",
                );
                return;
            }
            let answer = attributed(
                json!({"id":id,"kind":"answer","question":old["question"],"claims":old["response"]["claims"],"responseAttribution":old["responseAttribution"],"acceptance":editor(op),"sourceStatus":"pendingSource"}),
                op,
            );
            s.contributions.insert(cid.clone(), answer);
            s.index_contribution(&cid);
        } else {
            if old["worker"] != op.author {
                s.conflict(
                    id,
                    "response",
                    old["requestRevision"].clone(),
                    op,
                    "workerOnly",
                );
                return;
            }
            if op.kind == "answerQuestion" {
                let scope = items(&old["scope"]);
                let normalized = merged(&json!({}), op);
                if p["scopeDigest"] != old["scopeDigest"]
                    || items(&normalized["claims"])
                        .iter()
                        .flat_map(|c| items(&c["citations"]))
                        .any(|citation| !scope.contains(citation))
                {
                    s.conflict(
                        id,
                        "response",
                        old["scopeDigest"].clone(),
                        op,
                        "invalidScope",
                    );
                    return;
                }
            }
            if old.get("responseRevision").is_some() {
                if op.kind == "supplyTranscript"
                    && old["response"]["result"]["digest"] == p["result"]["digest"]
                {
                    s.receipt(op, "reused");
                    return;
                }
                s.conflict(
                    id,
                    "response",
                    old["responseRevision"].clone(),
                    op,
                    "multipleResponses",
                );
                value["status"] = json!("conflict");
            } else {
                value["responseRevision"] = json!(op.id);
                value["response"] = merged(&json!({}), op);
                value["responseAttribution"] = editor(op);
                value["status"] = json!("respondedPendingVerification");
            }
        }
        value = attributed(value, op);
        s.receipt(op, "applied");
        s.jobs.insert(jid.clone(), value);
        s.index_job(&jid);
    }
    fn context(&self, s: &mut PodcastsState, op: &AdmittedOperation) {
        let p = &op.payload;
        let id = text(p, "contributionID");
        let cid = key(&["context", id]);
        let old = s.contributions.get(&cid).cloned().unwrap_or(Value::Null);
        let head = &old["proposalRevision"];
        if !matches_head(p, "expect", head) || !old.is_null() && old["reference"] != p["reference"]
        {
            s.conflict(id, "context", head.clone(), op, "stale");
            return;
        }
        if op.kind == "proposeContext" {
            if !old.is_null() && old["proposer"] != op.author {
                s.conflict(id, "context", head.clone(), op, "ownerOnly");
                return;
            }
            if !old.is_null() {
                s.receipts.insert(
                    key(&["contextVersion", id, text(&old, "proposalRevision")]),
                    old.clone(),
                );
            }
            let mut value = merged(&old, op);
            // A new proposal remains pending even after a previous proposal was accepted.
            if let Some(o) = value.as_object_mut() {
                o.remove("acceptanceRevision");
                o.remove("acceptance");
            }
            value["id"] = json!(id);
            value["kind"] = json!("context");
            value["proposer"] = json!(op.author);
            value["proposalRevision"] = json!(op.id);
            value["proposalAttribution"] = editor(op);
            value["sourceStatus"] = json!("pendingSource");
            s.contributions.insert(cid.clone(), value);
        } else {
            if old.is_null()
                || p["proposal"] != old["proposalRevision"]
                || old.get("acceptanceRevision").is_some()
            {
                s.conflict(id, "context", head.clone(), op, "proposalMismatch");
                return;
            }
            let mut value = old;
            value["acceptanceRevision"] = json!(op.id);
            value["acceptance"] = merged(&json!({}), op);
            s.contributions.insert(cid.clone(), value);
        }
        s.index_contribution(&cid);
    }
}

#[cfg(test)]
mod prefix_tests {
    use super::*;
    #[test]
    fn borrowed_prefix_matches_canonical_operation_bytes() {
        for payload in [
            json!({}),
            json!({"z":[{"z":1,"a":"\nΩ"}],"a":1.25,"null":null}),
        ] {
            let op = AdmittedOperation {
                id: "id".into(),
                kind: "futureKind".into(),
                author: "author".into(),
                author_label: "Writer".into(),
                clock: u64::MAX,
                created: "time".into(),
                origin: "person".into(),
                payload,
            };
            let expected =
                digest(&canonical(&json!(["prefix", op])).expect("serializable operation"));
            assert_eq!(operation_prefix("prefix", &op), expected);
        }
    }
}
