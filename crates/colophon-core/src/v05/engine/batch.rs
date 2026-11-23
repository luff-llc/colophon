//! Batch record reads (proposed for Colophon 0.6, `docs/colophon-0.6-w1-batch.md`): the request
//! body, how a list of wanted records is split into batches, and the strict reading of a home's
//! answer. The exchange ([`super::exchange`]) decides when to batch and what to do with what is
//! read; nothing here trusts the home.
//!
//! A batch answer is read as a whole first: anything that is not exactly the documented shape
//! (an item for a path that was not asked for, out of order, repeated or extra, a missing item
//! without `truncated`, an `etag` that is not the SHA-256 of its `bytes`, an unknown status,
//! an oversized body) fails the batch, and none of its items is used as data. Only a well-formed
//! answer is split into items, and each found item is then judged exactly as a single
//! `GET {base}/records/<path>` answer is.
use crate::v05::encoding::{decode_base64, digest, is_lower_hex, strict_parse};
use serde_json::Value;

/// The batch read route, relative to a home's base.
pub const BATCH_PATH: &str = "/records/batch";
/// The most paths one batch names.
pub const MAX_BATCH_PATHS: usize = 256;
/// The largest batch request body.
pub const MAX_BATCH_BODY: usize = 64 * 1024;
/// The largest batch answer a home may send (the whole encoded JSON).
pub const MAX_BATCH_RESPONSE: usize = 4 * 1024 * 1024;

/// The request body for `paths`: `{"paths":[…]}`, compact JSON.
pub(crate) fn body(paths: &[String]) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        paths
            .iter()
            .fold(16_usize, |n, p| n.saturating_add(p.len()).saturating_add(3)),
    );
    out.extend_from_slice(b"{\"paths\":[");
    for (i, p) in paths.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        out.extend_from_slice(&json_string(p));
    }
    out.extend_from_slice(b"]}");
    out
}

fn json_string(s: &str) -> Vec<u8> {
    serde_json::to_vec(&Value::String(s.to_string())).unwrap_or_default()
}

/// Split `wanted` (path, listed SHA-256) into batches of at most [`MAX_BATCH_PATHS`] paths and
/// [`MAX_BATCH_BODY`] body bytes, in order. Paths are unique within a batch because the input
/// is (a map's keys).
pub(crate) fn split(wanted: Vec<(String, String)>) -> Vec<Vec<(String, String)>> {
    const FRAME: usize = b"{\"paths\":[]}".len();
    let mut out: Vec<Vec<(String, String)>> = Vec::new();
    let mut cur: Vec<(String, String)> = Vec::new();
    let mut bytes = FRAME;
    for item in wanted {
        let add = json_string(&item.0)
            .len()
            .saturating_add(usize::from(!cur.is_empty()));
        if !cur.is_empty()
            && (cur.len() >= MAX_BATCH_PATHS || bytes.saturating_add(add) > MAX_BATCH_BODY)
        {
            out.push(std::mem::take(&mut cur));
            bytes = FRAME;
        }
        bytes = bytes
            .saturating_add(json_string(&item.0).len())
            .saturating_add(usize::from(!cur.is_empty()));
        cur.push(item);
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// One item of a well-formed batch answer, in the request's order.
#[derive(Debug)]
pub(crate) enum Item {
    /// 200: the bytes, which hash to the item's own `etag`.
    Found { bytes: Vec<u8> },
    /// 404: the record is absent.
    Absent,
    /// 413: the record alone exceeds the answer's budget: fetch it with a single GET.
    TooLarge,
    /// 503: the home's own head is due (never asked for by the exchange).
    Unavailable,
}

/// A well-formed batch answer: one item per returned path (a prefix of the request), and
/// whether the rest was left out.
#[derive(Debug)]
pub(crate) struct Answer {
    pub items: Vec<Item>,
    pub truncated: bool,
}

fn etag_sha(v: &Value) -> Option<String> {
    let s = v.as_str()?;
    let inner = s.strip_prefix('"')?.strip_suffix('"')?;
    is_lower_hex(inner, 64).then(|| inner.to_string())
}

/// Read a 200 answer to a batch of `requested` paths. `Err` names why the whole batch fails.
pub(crate) fn parse(requested: &[String], body: &[u8]) -> std::result::Result<Answer, String> {
    if body.len() > MAX_BATCH_RESPONSE {
        return Err("a batch answer over 4 MiB".into());
    }
    let v = strict_parse(body).map_err(|e| e.code())?;
    let obj = v
        .as_object()
        .ok_or("a batch answer that is not an object")?;
    let records = obj
        .get("records")
        .and_then(Value::as_array)
        .ok_or("a batch answer without records")?;
    let truncated = obj
        .get("truncated")
        .and_then(Value::as_bool)
        .ok_or("a batch answer without truncated")?;
    if records.len() > requested.len() {
        return Err("a batch answer with more items than paths asked for".into());
    }
    if truncated && records.is_empty() {
        return Err("a truncated batch answer with no item".into());
    }
    if !truncated && records.len() < requested.len() {
        return Err("a batch answer missing items without truncated".into());
    }
    let mut items = Vec::with_capacity(records.len());
    for (item, want) in records.iter().zip(requested) {
        let o = item
            .as_object()
            .ok_or("a batch item that is not an object")?;
        if o.get("path").and_then(Value::as_str) != Some(want.as_str()) {
            return Err("a batch item for another path than asked, or out of order".into());
        }
        let status = o
            .get("status")
            .and_then(Value::as_u64)
            .ok_or("a batch item without a numeric status")?;
        items.push(match status {
            200 => {
                let sha = o
                    .get("etag")
                    .and_then(etag_sha)
                    .ok_or("a found batch item without a valid etag")?;
                let text = o
                    .get("bytes")
                    .and_then(Value::as_str)
                    .ok_or("a found batch item without bytes")?;
                let bytes = decode_base64(text, MAX_BATCH_RESPONSE)
                    .map_err(|_| "a batch item whose bytes are not base64")?;
                if digest(&bytes) != sha {
                    return Err("a batch item whose bytes do not hash to its etag".into());
                }
                Item::Found { bytes }
            }
            404 => Item::Absent,
            413 => {
                if o.get("etag").and_then(etag_sha).is_none()
                    || o.get("size").and_then(Value::as_u64).is_none()
                {
                    return Err("a 413 batch item without etag and size".into());
                }
                Item::TooLarge
            }
            503 => Item::Unavailable,
            _ => return Err("a batch item with an unknown status".into()),
        });
    }
    Ok(Answer { items, truncated })
}
