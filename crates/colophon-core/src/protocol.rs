//! Wire constants, storage paths and the current storage layout.
use crate::{ensure, model::OperationMeta, Error, Result};
use sha2::{Digest, Sha256};

/// Authority record protocol marker.
pub const AUTHORITY: &str = "colophon/authority/3";
/// Signed operation header protocol marker.
pub const OPERATION: &str = "colophon/operation/3";
/// Access-request protocol marker.
pub const REQUEST: &str = "colophon/request/3";
/// HTTP relay protocol marker.
pub const RELAY: &str = "colophon/relay/3";
/// Operation-ID digest purpose.
pub const OPERATION_ID: &str = "colophon/operation-id/3";
/// HKDF salt for host-supplied action entropy.
pub const ENTROPY: &[u8] = b"colophon/entropy/3";
/// HKDF salt for a software recovery kit.
pub const RECOVERY: &[u8] = b"colophon/recovery/3";
/// HPKE info / AEAD AD prefix for epoch seals.
pub const EPOCH: &str = "colophon/epoch/3";
/// Device-local checkpoint authentication label.
pub const CHECKPOINT: &[u8] = b"colophon/device-checkpoint/3";
/// Current storage layout. Readers reject an authenticated higher value.
pub const LAYOUT: u32 = 2;
/// Implicit layout when no `layout` authority entry has been applied.
pub const DEFAULT_LAYOUT: u32 = 1;

/// Stable error prefix for an authenticated unsupported layout or newer authority kind.
pub const UNSUPPORTED_LAYOUT: &str = "Unsupported storage layout";
/// Stable error prefix for changed bytes at a previously verified immutable path.
pub const EQUIVOCATION: &str = "Equivocation";

/// True when `error` is an authenticated layout/authority the client cannot evaluate.
pub fn is_unsupported_layout(error: &Error) -> bool {
    error.0.starts_with(UNSUPPORTED_LAYOUT)
}

/// True when `error` reports changed bytes at an immutable path.
pub fn is_equivocation(error: &Error) -> bool {
    error.0.contains(EQUIVOCATION)
}

/// Namespace named by a storage path, if the path is namespace-scoped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathScope<'a> {
    /// Authority and access requests: every client lists these.
    Always,
    /// Legacy 0.2-style `ops/<author>/<clock>-<id>.json`; namespace is unknown until verified.
    Unknown,
    /// `ops|state|history/<author>/<namespace>/...`
    Namespace(&'a str),
}

/// Classify a well-formed library path. `None` is not a library record path.
pub fn path_scope(path: &str) -> Option<PathScope<'_>> {
    let parts: Vec<&str> = path.split('/').collect();
    match parts.as_slice() {
        ["authority", file] | ["requests", file] if file.ends_with(".json") => {
            Some(PathScope::Always)
        }
        ["ops", _, file] if file.ends_with(".json") => Some(PathScope::Unknown),
        ["ops" | "state" | "history", _, namespace, file] if file.ends_with(".json") => {
            Some(PathScope::Namespace(namespace))
        }
        _ => None,
    }
}

/// Whether a host listing of `namespaces` should include `path`.
/// An empty `namespaces` slice means every namespace.
pub fn listing_includes(path: &str, namespaces: &[String]) -> bool {
    match path_scope(path) {
        Some(PathScope::Always | PathScope::Unknown) => true,
        Some(PathScope::Namespace(ns)) => {
            namespaces.is_empty() || namespaces.iter().any(|n| n == ns)
        }
        None => false,
    }
}

/// Immutable operation path: `ops/<author>/<namespace>/<clock 12 digits>-<id>.json`.
pub fn operation_path(meta: &OperationMeta) -> String {
    format!(
        "ops/{}/{}/{:012}-{}.json",
        meta.author, meta.namespace, meta.clock, meta.id
    )
}

/// Legacy 0.2-style path whose namespace is unknown until the header is verified.
pub fn legacy_operation_path(meta: &OperationMeta) -> String {
    format!("ops/{}/{:012}-{}.json", meta.author, meta.clock, meta.id)
}

/// Replaceable live-state slot: `state/<author>/<namespace>/<slot>.json`.
pub fn live_state_path(author: &str, namespace: &str, slot: &str) -> String {
    format!("state/{author}/{namespace}/{slot}.json")
}

/// Append-only engagement evidence for a live write.
pub fn history_path(author: &str, namespace: &str, clock: u64, id: &str) -> String {
    format!("history/{author}/{namespace}/{clock:012}-{id}.json")
}

/// SHA-256 hex of an episode ID, used as the live-state slot name.
pub fn live_slot_name(episode_id: &str) -> String {
    hex32(&Sha256::digest(episode_id.as_bytes()))
}

/// Passive `listening.podcasts` `position` samples may use replaceable live state.
pub fn live_slot(namespace: &str, kind: &str, payload: &serde_json::Value) -> Option<String> {
    if namespace != "listening.podcasts" || kind != "position" {
        return None;
    }
    if payload.get("seek") == Some(&serde_json::Value::Bool(true)) {
        return None;
    }
    let id = payload.get("id")?.as_str()?;
    if id.is_empty() || id.len() > 256 {
        return None;
    }
    Some(live_slot_name(id))
}

/// Whether this path may be replaced (live slot) rather than only appended.
pub fn is_replaceable(path: &str) -> bool {
    path.starts_with("state/")
}

/// Whether this path is engagement evidence that does not participate in opening.
pub fn is_history(path: &str) -> bool {
    path.starts_with("history/")
}

/// Whether this path is a content operation (immutable, live, or history).
pub fn is_operation_record(path: &str) -> bool {
    path.starts_with("ops/") || path.starts_with("state/")
}

/// Author and file name (`<clock>-<id>.json`) for an ops or history path.
pub fn operation_file(path: &str) -> Option<(&str, &str)> {
    let rest = path
        .strip_prefix("ops/")
        .or_else(|| path.strip_prefix("history/"))?;
    let parts: Vec<&str> = rest.split('/').collect();
    match parts.as_slice() {
        [author, file] => Some((author, file)),
        [author, _namespace, file] => Some((author, file)),
        _ => None,
    }
}

/// Require that a verified header belongs at `path`.
pub fn match_header_path(
    path: &str,
    meta: &OperationMeta,
    live: Option<&crate::model::LiveStamp>,
) -> Result<()> {
    let author_ok = path.split('/').nth(1) == Some(meta.author.as_str());
    ensure(author_ok, "Operation path mismatch")?;
    if let Some(stamp) = live {
        ensure(
            stamp.library_id == meta.library
                && stamp.generation == meta.clock
                && stamp.operation_id == meta.id,
            "Live stamp mismatch",
        )?;
        let state = live_state_path(&meta.author, &meta.namespace, &stamp.slot);
        let history = history_path(&meta.author, &meta.namespace, meta.clock, &meta.id);
        let retained = operation_path(meta);
        ensure(
            path == state || path == history || path == retained,
            "Operation path mismatch",
        )?;
        if path.starts_with("ops/") || path.starts_with("history/") || path.starts_with("state/") {
            if let Some(PathScope::Namespace(ns)) = path_scope(path) {
                ensure(ns == meta.namespace, "Operation path mismatch")?;
            }
        }
        return Ok(());
    }
    ensure(
        path == operation_path(meta) || path == legacy_operation_path(meta),
        "Operation path mismatch",
    )?;
    if let Some(PathScope::Namespace(ns)) = path_scope(path) {
        ensure(ns == meta.namespace, "Operation path mismatch")?;
    }
    Ok(())
}

fn hex32(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::model::OperationMeta;

    fn meta(ns: &str) -> OperationMeta {
        OperationMeta {
            protocol: OPERATION.into(),
            library: "lib".into(),
            namespace: ns.into(),
            author: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            epoch: 1,
            id: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            clock: 7,
            authority: 3,
            created: "2026-11-07T00:00:00Z".into(),
        }
    }

    #[test]
    fn namespaced_and_legacy_paths_parse() {
        let meta = meta("listening.podcasts");
        let path = operation_path(&meta);
        assert_eq!(
            path,
            "ops/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/listening.podcasts/000000000007-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.json"
        );
        assert_eq!(
            path_scope(&path),
            Some(PathScope::Namespace("listening.podcasts"))
        );
        assert_eq!(
            path_scope("ops/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/000000000007-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.json"),
            Some(PathScope::Unknown)
        );
        match_header_path(&path, &meta, None).unwrap();
        match_header_path(&legacy_operation_path(&meta), &meta, None).unwrap();
        assert!(!listing_includes(&path, &["notes".into()]));
        assert!(listing_includes(&path, &["listening.podcasts".into()]));
        assert!(listing_includes(
            "authority/00000001.json",
            &["notes".into()]
        ));
        assert!(listing_includes(
            "ops/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/000000000007-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.json",
            &["notes".into()]
        ));
    }

    #[test]
    fn live_slot_is_episode_digest() {
        let payload = serde_json::json!({"id":"episode","seconds":12.0});
        let slot = live_slot("listening.podcasts", "position", &payload).unwrap();
        assert_eq!(slot.len(), 64);
        assert!(live_slot(
            "listening.podcasts",
            "position",
            &serde_json::json!({"id":"episode","seconds":1,"seek":true})
        )
        .is_none());
        assert!(live_slot("notes", "position", &payload).is_none());
    }
}
