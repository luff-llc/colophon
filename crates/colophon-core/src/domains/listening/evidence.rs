//! Domain half of the encrypted import-evidence sidecar contract.
//! The engine/SDK must persist this separately, authorize every read with namespace access,
//! and combine its historical pages with structural domain pages without making live jobs.
use super::{
    import::{Evidence, ImportPlan},
    text,
};
use crate::{
    ensure,
    records::{canonical, digest},
    Result,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Bound::{Excluded, Unbounded},
};

/// A normalized historical row supplied by the verified old service projector.
/// Source dates and visibility must already have been decoded/evaluated by that projector;
/// legacy playback visibility is ordered by source clock/actor/operation, not arrival here.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HistoricalRow {
    /// Immutable evidence entry that proves this historical claim.
    pub evidence_id: String,
    /// `importedSession`, `jobs`, `contributions` or `conflicts`.
    pub query: String,
    /// Stable category-scoped source identity, not a new authenticated operation ID.
    pub id: String,
    /// Mapped object/episode for bounded filtering.
    pub object: String,
    /// Normalized deterministic display key including a source-ID tie breaker.
    pub order: String,
    /// Bounded historical projection. It never confers worker or source authority.
    pub value: Value,
}
/// Serializable immutable sidecar index. It has no effect on the native reducer or authority.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct EvidenceIndex {
    entries: BTreeMap<String, Evidence>,
    rows: BTreeMap<String, HistoricalRow>,
    indexes: BTreeMap<String, BTreeSet<(String, String)>>,
    revision: String,
}
fn key(parts: &[&str]) -> String {
    serde_json::to_string(parts).unwrap_or_default()
}
impl EvidenceIndex {
    /// Insert an immutable manifest and update its read indexes. Repeated identical insertion
    /// is idempotent; changed source outcomes require a separate reconciliation entry.
    pub fn insert(&mut self, evidence: Evidence) -> Result<()> {
        if let Some(existing) = self.entries.get(&evidence.id) {
            return ensure(existing == &evidence, "importEvidenceConflict");
        }
        let library = text(&evidence.manifest["source"], "sourceLibrary");
        let namespace = text(&evidence.manifest["source"], "namespace");
        ensure(
            namespace == "listening.podcasts" && !library.is_empty(),
            "invalidEvidenceSource",
        )?;
        let id = evidence.id.clone();
        let mut objects = BTreeSet::from([String::new()]);
        for payload in [
            &evidence.manifest["originalPayload"],
            &evidence.manifest["effectivePayload"],
        ] {
            for field in [
                "id",
                "show",
                "episode",
                "note",
                "playlist",
                "contributionID",
                "requestID",
            ] {
                if let Some(object) = payload[field].as_str() {
                    objects.insert(object.to_owned());
                }
            }
        }
        for object in super::items(&evidence.manifest["objects"]) {
            if let Some(object) = object.as_str() {
                objects.insert(object.to_owned());
            }
        }
        for source in ["", library] {
            for object in &objects {
                self.indexes
                    .entry(key(&["importEvidence", source, object]))
                    .or_default()
                    .insert((id.clone(), id.clone()));
            }
        }
        self.entries.insert(id, evidence);
        self.refresh();
        Ok(())
    }
    /// Insert a verified normalized historical result. The old evaluator decides effectiveness,
    /// source visibility and dates. Rows are forcibly labelled historical and cannot start jobs.
    pub fn insert_historical(&mut self, mut row: HistoricalRow) -> Result<()> {
        ensure(
            ["importedSession", "jobs", "contributions", "conflicts"].contains(&row.query.as_str()),
            "invalidHistoricalQuery",
        )?;
        let evidence = self
            .entries
            .get(&row.evidence_id)
            .ok_or_else(|| crate::Error("missingImportEvidence".into()))?;
        ensure(
            row.value.is_object() && canonical(&row.value)?.len() <= 512 * 1024,
            "historicalRowTooLarge",
        )?;
        let mut attribution = json!({"authorID":evidence.manifest["source"]["authorID"],"authorLabel":evidence.manifest["authorLabel"]});
        for field in ["author", "authorLabel", "origin", "clock", "revision"] {
            if let Some(value) = row
                .value
                .as_object_mut()
                .and_then(|object| object.remove(field))
            {
                attribution[field] = value;
            }
        }
        row.value["historicalAttribution"] = attribution;
        row.value["historical"] = json!(true);
        row.value["provenance"] = evidence.manifest["source"].clone();
        if row.query == "jobs" {
            row.value["executionEligible"] = json!(false);
        }
        let id = key(&[&row.query, &row.id]);
        if let Some(existing) = self.rows.get(&id) {
            return ensure(existing == &row, "historicalProjectionConflict");
        }
        for source in ["", text(&evidence.manifest["source"], "sourceLibrary")] {
            for object in ["", &row.object] {
                self.indexes
                    .entry(key(&[&row.query, source, object]))
                    .or_default()
                    .insert((row.order.clone(), id.clone()));
            }
        }
        self.rows.insert(id, row);
        self.refresh();
        Ok(())
    }
    fn refresh(&mut self) {
        // Background import cost, independent of hot UI reads. Insertion arrival order is irrelevant.
        self.revision = digest(&canonical(&json!([self.entries, self.rows])).unwrap_or_default());
    }
    /// Read a bounded sidecar page (`rows`, `next`, `total`) wrapped in its content revision.
    /// Arguments: sourceLibrary (manifest pages), object (historical pages), cursor, limit 1..100.
    /// SDK must reject inaccessible namespaces before calling; this index carries no grant keys.
    pub fn query(&self, name: &str, args: &Value) -> Result<Value> {
        ensure(args.is_object(), "invalidArgument")?;
        for field in ["sourceLibrary", "object", "namespace", "cursor"] {
            ensure(
                args.get(field).is_none_or(Value::is_string),
                "invalidArgument",
            )?;
        }
        ensure(
            args.get("namespace")
                .is_none_or(|v| v == "listening.podcasts"),
            "invalidArgument",
        )?;
        ensure(
            [
                "importEvidence",
                "importedSession",
                "jobs",
                "contributions",
                "conflicts",
            ]
            .contains(&name),
            "invalidArgument",
        )?;
        let limit = match args.get("limit") {
            Some(v) => v
                .as_u64()
                .ok_or_else(|| crate::Error("invalidArgument".into()))?,
            None => 50,
        };
        ensure((1..=100).contains(&limit), "invalidArgument")?;
        let source = text(args, "sourceLibrary");
        let object = text(args, "object");
        let index = key(&[name, source, object]);
        let empty = BTreeSet::new();
        let entries = self.indexes.get(&index).unwrap_or(&empty);
        let after = if let Some(cursor) = args.get("cursor") {
            let cursor = cursor
                .as_str()
                .ok_or_else(|| crate::Error("invalidArgument".into()))?;
            let decoded = URL_SAFE_NO_PAD
                .decode(cursor)
                .map_err(|_| crate::Error("invalidArgument".into()))?;
            let (revision, query, last): (String, String, (String, String)) =
                serde_json::from_slice(&decoded)?;
            if revision != self.revision {
                return Ok(json!({"revision":self.revision,"value":{"outcome":"staleCursor"}}));
            }
            ensure(query == index, "invalidArgument")?;
            Some(last)
        } else {
            None
        };
        let mut iter: Box<dyn Iterator<Item = &(String, String)>> = match after {
            Some(after) => Box::new(entries.range((Excluded(after), Unbounded))),
            None => Box::new(entries.iter()),
        };
        let mut rows = vec![];
        let mut last = None;
        let mut size = 0;
        let mut more = false;
        for (order, id) in iter.by_ref() {
            let row = if name == "importEvidence" {
                let e = &self.entries[id];
                // Raw historical bodies may exceed a UI page; the SDK retrieves the encrypted
                // manifest separately by this ID. Do not copy a two-MiB source publication here.
                json!({"id":e.id,"source":e.manifest["source"],"kind":e.manifest["kind"],"authorLabel":e.manifest["authorLabel"],"admission":e.manifest["admission"],"domainOutcome":e.manifest["domainOutcome"],"issues":e.manifest["issues"],"historical":true,"truncated":true})
            } else {
                self.rows[id].value.clone()
            };
            let bytes = canonical(&row)?.len();
            if rows.len() == limit as usize || size + bytes > 900_000 {
                more = true;
                break;
            }
            size += bytes;
            rows.push(row);
            last = Some((order.clone(), id.clone()));
        }
        let next = if more {
            last.map(|last| {
                URL_SAFE_NO_PAD
                    .encode(canonical(&json!([self.revision, index, last])).unwrap_or_default())
            })
        } else {
            None
        };
        Ok(
            json!({"revision":self.revision,"value":{"rows":rows,"total":entries.len(),"next":next}}),
        )
    }
    /// Retrieve a manifest for background archival export. The SDK provides byte streaming and
    /// access control; this intentionally is not a UI query or generated tool.
    pub fn manifest(&self, id: &str) -> Option<&Evidence> {
        self.entries.get(id)
    }
}
/// Bind output operation IDs after the importer signs all children. Persist the returned
/// manifest and the resulting records atomically; an unsigned plan is not migration completion.
pub fn bind_outputs(mut plan: ImportPlan, operation_ids: &[String]) -> Result<ImportPlan> {
    ensure(
        operation_ids.len() == plan.commands.len(),
        "importOutputCountMismatch",
    )?;
    ensure(
        operation_ids.iter().all(|id| !id.is_empty())
            && operation_ids.iter().collect::<BTreeSet<_>>().len() == operation_ids.len(),
        "invalidImportOutputIDs",
    )?;
    for evidence in &mut plan.evidence {
        if let Some(children) = evidence.manifest["children"].as_array_mut() {
            for (child, id) in children.iter_mut().zip(operation_ids) {
                child["outputOperationID"] = json!(id);
            }
        }
    }
    Ok(plan)
}
