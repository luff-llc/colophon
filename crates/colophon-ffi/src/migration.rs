//! Pure transport for the four 0.1 adapters. Verification and old fold evaluation belong
//! to the Swift reference reader; this API never treats a signature as proof of effectiveness.
use crate::{invalid, Result};
use colophon_core::domains::{books, listening, notes, saved};
use serde_json::{json, Value};
use std::collections::HashMap;

#[derive(Clone, Debug, uniffi::Record)]
pub struct LegacyImportOperation {
    pub source_library: String,
    pub author_id: String,
    pub author_label: String,
    pub operation_id: String,
    pub signed_body_digest: String,
    pub kind: String,
    pub version: u64,
    pub payload_json: Vec<u8>,
    pub admitted_order: u64,
    pub claimed_date_json: Vec<u8>,
    /// admitted, held, refused, unreadable, etc. Only admitted can produce effects.
    pub admission: String,
    /// applied, conflict, invalid, noEffect, retained, lateEdit, or unresolved.
    pub outcome: String,
    /// Domain-specific context serialized from the verified old fold. Omit with {}.
    pub context_json: Vec<u8>,
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct LegacyImportCommand {
    pub source_index: u64,
    pub output_key: String,
    pub kind: String,
    pub payload_json: Vec<u8>,
    pub expect_from_child: Option<u64>,
    pub baseline: bool,
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct LegacyImportBatch {
    pub commands: Vec<LegacyImportCommand>,
    /// Array of domain evidence records, preserving their full original fields.
    pub evidence_json: Vec<u8>,
    /// Opaque source fold/identity state. Persist along with receipts, never as authority.
    pub state_json: Vec<u8>,
    pub blobs_json: Vec<u8>,
    pub publication_barrier: bool,
}
fn context<T: serde::de::DeserializeOwned + serde::Serialize + Default>(bytes: &[u8]) -> Result<T> {
    let mut defaults = serde_json::to_value(T::default())?;
    let supplied: Value = serde_json::from_slice(bytes)?;
    let object = supplied
        .as_object()
        .ok_or_else(|| invalid("Expected context object"))?;
    for (key, value) in object {
        defaults[key] = value.clone();
    }
    Ok(serde_json::from_value(defaults)?)
}
/// Inputs must be in complete verified source order. Contexts describe each old prefix,
/// not the final snapshot. Return values are unsigned proposals, signed by the importer.
#[uniffi::export]
pub fn import_legacy_batch(
    namespace: String,
    operations: Vec<LegacyImportOperation>,
    state_json: Vec<u8>,
) -> Result<LegacyImportBatch> {
    if ![
        "reading.books",
        "listening.podcasts",
        "reading.saved",
        "notes",
    ]
    .contains(&namespace.as_str())
    {
        return Err(invalid("Unsupported migration namespace"));
    }
    if operations.windows(2).any(|pair| {
        pair[0].source_library == pair[1].source_library
            && pair[0].admitted_order >= pair[1].admitted_order
    }) {
        return Err(invalid(
            "Import batch must be in strictly increasing source order",
        ));
    }
    if operations.len() > 1024 {
        return Err(invalid("Import batch exceeds 1024 operations"));
    }
    let mut result = LegacyImportBatch {
        commands: vec![],
        evidence_json: vec![],
        state_json: state_json.clone(),
        blobs_json: b"[]".to_vec(),
        publication_barrier: false,
    };
    let mut evidence = vec![];
    let mut blobs = vec![];
    let mut book_state: books::import::ImportState =
        if namespace == "reading.books" && state_json != b"{}" {
            serde_json::from_slice(&state_json)?
        } else {
            Default::default()
        };
    for (index, op) in operations.iter().enumerate() {
        let mut source = json!({"sourceLibrary":op.source_library,"authorId":op.author_id,"authorLabel":op.author_label,"operationId":op.operation_id,"signedBodyDigest":op.signed_body_digest,"kind":op.kind,"version":op.version,"payload":serde_json::from_slice::<Value>(&op.payload_json)?,"admittedOrder":op.admitted_order,"claimedDate":serde_json::from_slice::<Value>(&op.claimed_date_json)?,"admission":op.admission});
        let (commands, entries): (Vec<Value>, Vec<Value>) = match namespace.as_str() {
            "reading.books" => {
                let plan = books::import::transform(&book_state, &serde_json::from_value(source)?);
                book_state = plan.state;
                (
                    plan.commands
                        .into_iter()
                        .map(serde_json::to_value)
                        .collect::<std::result::Result<_, _>>()?,
                    plan.evidence
                        .into_iter()
                        .map(serde_json::to_value)
                        .collect::<std::result::Result<_, _>>()?,
                )
            }
            "listening.podcasts" => {
                let mut ctx: listening::import::ImportContext = context(&op.context_json)?;
                ctx.admission = op.admission.clone();
                ctx.disposition = match op.outcome.as_str() {
                    "applied" => listening::import::Disposition::Applied,
                    "retained" => listening::import::Disposition::Retained,
                    "conflict" | "noEffect" => listening::import::Disposition::Rejected,
                    "invalid" => listening::import::Disposition::Malformed,
                    _ => listening::import::Disposition::Unresolved,
                };
                let plan =
                    listening::import::import_operation(&serde_json::from_value(source)?, &ctx);
                let key = plan.evidence[0].id.clone();
                (plan.commands.into_iter().enumerate().map(|(i,c)| json!({"outputKey":format!("{key}/{i}"),"kind":c.kind,"payload":c.payload,"baseline":c.baseline})).collect(), plan.evidence.into_iter().map(serde_json::to_value).collect::<std::result::Result<_,_>>()?)
            }
            "reading.saved" => {
                source["outcome"] = json!(if op.admission != "admitted" {
                    "unresolved"
                } else {
                    match op.outcome.as_str() {
                        "applied" => "effective",
                        "conflict" => "conflict",
                        "invalid" => "invalid",
                        "retained" | "noEffect" => "historical",
                        _ => "unresolved",
                    }
                });
                let plan = saved::import::translate(
                    &serde_json::from_value(source)?,
                    &context(&op.context_json)?,
                );
                result.publication_barrier |= plan.publication_barrier;
                (
                    plan.commands
                        .into_iter()
                        .map(serde_json::to_value)
                        .collect::<std::result::Result<_, _>>()?,
                    plan.evidence
                        .into_iter()
                        .map(serde_json::to_value)
                        .collect::<std::result::Result<_, _>>()?,
                )
            }
            "notes" => {
                source = json!({"source_library":op.source_library,"author_id":op.author_id,"author_label":op.author_label,"operation_id":op.operation_id,"signed_body_digest":op.signed_body_digest,"kind":op.kind,"version":op.version,"payload":source["payload"],"admitted_order":op.admitted_order,"claimed_date":source["claimedDate"]});
                source["admission"] = if op.admission == "admitted"
                    && ["applied", "conflict", "lateEdit", "invalid", "noEffect"]
                        .contains(&op.outcome.as_str())
                {
                    json!("Admitted")
                } else {
                    json!({"Unresolved":format!("admission={}, source outcome={}", op.admission, op.outcome)})
                };
                source["outcome"] = json!(match op.outcome.as_str() {
                    "applied" => "Applied",
                    "conflict" => "Conflict",
                    "lateEdit" => "LateEdit",
                    "invalid" => "Invalid",
                    _ => "NoEffect",
                });
                let plan = notes::import::translate(
                    &serde_json::from_value(source)?,
                    &context(&op.context_json)?,
                );
                blobs.extend(
                    plan.blobs
                        .into_iter()
                        .map(serde_json::to_value)
                        .collect::<std::result::Result<Vec<_>, _>>()?,
                );
                (
                    plan.commands
                        .into_iter()
                        .map(serde_json::to_value)
                        .collect::<std::result::Result<_, _>>()?,
                    plan.evidence
                        .into_iter()
                        .map(serde_json::to_value)
                        .collect::<std::result::Result<_, _>>()?,
                )
            }
            _ => return Err(invalid("Unsupported migration namespace")),
        };
        for command in commands {
            let key = command
                .get("outputKey")
                .or_else(|| command.get("key"))
                .or_else(|| command.get("child_key"))
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("Missing transform output key"))?;
            result.commands.push(LegacyImportCommand {
                source_index: index as u64,
                output_key: key.into(),
                kind: command["kind"]
                    .as_str()
                    .ok_or_else(|| invalid("Missing kind"))?
                    .into(),
                payload_json: serde_json::to_vec(&command["payload"])?,
                expect_from_child: command["expectFromChild"].as_u64(),
                baseline: command["baseline"].as_bool().unwrap_or(false),
            });
        }
        evidence.extend(entries);
    }
    if namespace == "reading.books" {
        result.state_json = serde_json::to_vec(&book_state)?;
    }
    result.evidence_json = serde_json::to_vec(&evidence)?;
    result.blobs_json = serde_json::to_vec(&blobs)?;
    Ok(result)
}
/// Bind planned book component heads to actual signed destination IDs before the next batch.
#[uniffi::export]
pub fn bind_legacy_import_state(
    namespace: String,
    state_json: Vec<u8>,
    outputs: HashMap<String, String>,
) -> Result<Vec<u8>> {
    if namespace != "reading.books" {
        return Ok(state_json);
    }
    let mut state: books::import::ImportState = serde_json::from_slice(&state_json)?;
    for (key, id) in outputs {
        state.bind_output(&key, &id);
    }
    Ok(serde_json::to_vec(&state)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn operation(kind: &str, payload: Value) -> LegacyImportOperation {
        LegacyImportOperation {
            source_library: "old-library".into(),
            author_id: "old-author".into(),
            author_label: "Phone".into(),
            operation_id: "old-op".into(),
            signed_body_digest: "a".repeat(64),
            kind: kind.into(),
            version: 1,
            payload_json: serde_json::to_vec(&payload).expect("valid synthetic import fixture"),
            admitted_order: 0,
            claimed_date_json: b"null".to_vec(),
            admission: "admitted".into(),
            outcome: "applied".into(),
            context_json: b"{}".to_vec(),
        }
    }
    #[test]
    fn all_namespaces_and_unresolved_are_lossless() {
        for (ns, kind, payload, expected) in [
            (
                "reading.books",
                "book.add",
                json!({"book":"b","title":"Book","author":"Writer"}),
                "addBook",
            ),
            (
                "reading.saved",
                "capture.link",
                json!({"item":"i","url":"https://example.com","title":"Link"}),
                "capture",
            ),
            (
                "listening.podcasts",
                "show.follow",
                json!({"show":"s","feed":"https://example.com/rss","title":"Show"}),
                "follow",
            ),
            (
                "notes",
                "notebook.create",
                json!({"notebook":"n","title":"Notes","kind":"notebook"}),
                "createNotebook",
            ),
        ] {
            let mut op = operation(kind, payload.clone());
            if ns == "listening.podcasts" {
                op.context_json = serde_json::to_vec(&json!({"effectivePayload":payload}))
                    .expect("valid synthetic import fixture");
            }
            if ns == "notes" {
                op.context_json = serde_json::to_vec(&json!({"identities": {notes::import::identity_key("old-library", "notebook", "n"):"n"}})).expect("valid synthetic import fixture");
            }
            let result = import_legacy_batch(ns.into(), vec![op.clone()], b"{}".to_vec())
                .expect("valid synthetic import fixture");
            assert_eq!(
                result.commands.first().map(|c| c.kind.as_str()),
                Some(expected),
                "{}: {}",
                ns,
                String::from_utf8_lossy(&result.evidence_json)
            );
            op.admission = "held".into();
            let held = import_legacy_batch(ns.into(), vec![op], b"{}".to_vec())
                .expect("valid synthetic import fixture");
            assert!(held.commands.is_empty());
            assert!(!serde_json::from_slice::<Vec<Value>>(&held.evidence_json)
                .expect("valid synthetic import fixture")
                .is_empty());
        }
    }
    #[test]
    fn ordered_batch_and_output_binding_preserve_component_expectations() {
        let first = operation(
            "book.add",
            json!({"book":"b","title":"Book","author":"Writer"}),
        );
        let mut second = operation("book.edit", json!({"book":"b","title":"Edited"}));
        second.operation_id = "second".into();
        second.signed_body_digest = "b".repeat(64);
        second.admitted_order = 1;
        let batch = import_legacy_batch(
            "reading.books".into(),
            vec![first.clone(), second.clone()],
            b"{}".to_vec(),
        )
        .expect("batch");
        assert_eq!(batch.commands.len(), 2);
        let payload: Value =
            serde_json::from_slice(&batch.commands[1].payload_json).expect("payload");
        assert_eq!(payload["expect"], batch.commands[0].output_key);
        let state = bind_legacy_import_state(
            "reading.books".into(),
            batch.state_json,
            HashMap::from([(batch.commands[1].output_key.clone(), "signed-second".into())]),
        )
        .expect("bound state");
        let mut third = operation("book.edit", json!({"book":"b","title":"Again"}));
        third.operation_id = "third".into();
        third.admitted_order = 2;
        let next =
            import_legacy_batch("reading.books".into(), vec![third], state).expect("next batch");
        let payload: Value =
            serde_json::from_slice(&next.commands[0].payload_json).expect("payload");
        assert_eq!(payload["expect"], "signed-second");
        assert!(
            import_legacy_batch("reading.books".into(), vec![second, first], b"{}".to_vec())
                .is_err()
        );
        assert!(import_legacy_batch("unknown".into(), vec![], b"{}".to_vec()).is_err());
    }
}
