//! The record store's path grammar (0.3 §4 and §8.1 with 0.5 §13–§14): what kind of object a
//! path names, and nothing else. A path that does not parse here is ignored by the engine and
//! never read.
use crate::v05::encoding::is_lower_hex;

// The store layout §14 adopts (the spec owner writes it into §14). One place for the names.
/// Directory of pending transitions: `transitions/<digest>.json`.
pub const TRANSITIONS: &str = "transitions";
/// Directory of vetoes: `vetoes/<digest>.json`.
pub const VETOES: &str = "vetoes";
/// Directory of receipts: `receipts/<object digest>/<home id>.receipt.json`.
pub const RECEIPTS: &str = "receipts";
/// Directory of heads: `heads/<home id>.json`.
pub const HEADS: &str = "heads";

/// What a path names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    /// `authority/<seq, 8 digits>.json`.
    Authority(u64),
    /// `predecessor/authority/<seq, 8 digits>.json` (§15.1).
    Predecessor(u64),
    /// `transitions/<digest>.json` or `vetoes/<digest>.json`.
    Pending,
    /// `<dir>/<object digest>/<home member ID>.receipt.json` under `transitions`, `vetoes` or
    /// `receipts` (the spec names the file, not its directory; see the engine's report).
    Receipt,
    /// `heads/<home member ID>.json`.
    Head,
    /// `ops/<author>/<namespace>/<clock, 12 digits>-<id>.json`.
    Op {
        /// The author's member ID.
        author: String,
        /// The namespace.
        namespace: String,
        /// The clock.
        clock: u64,
        /// The operation ID.
        id: String,
    },
    /// `state/<author>/<namespace>/<slot>.json`.
    Live {
        /// The author's member ID.
        author: String,
        /// The namespace.
        namespace: String,
        /// The slot.
        slot: String,
    },
    /// `history/<author>/<namespace>/<clock>-<id>.json`: engagement evidence, never read to
    /// open an account (0.3 §4).
    History,
    /// `blobs/<64 lowercase hex>`.
    Blob(String),
    /// `requests/<name>.json`: not part of 0.5's records.
    Request,
}

/// Whether `path` obeys the component rules of 0.3 §8.1: shorter than 512 bytes, no empty,
/// `.`, `..` or dot-leading component, no `\` or NUL.
pub fn well_formed(path: &str) -> bool {
    path.len() < 512
        && !path.is_empty()
        && path
            .split('/')
            .all(|c| !c.is_empty() && !c.starts_with('.') && !c.contains(['\\', '\0']))
}

fn seq8(name: &str) -> Option<u64> {
    let n = name.strip_suffix(".json")?;
    (n.len() == 8 && n.bytes().all(|b| b.is_ascii_digit()))
        .then(|| n.parse().ok())
        .flatten()
        .filter(|s| *s >= 1)
}
fn key_id(s: &str) -> bool {
    is_lower_hex(s, 32)
}
fn ns_ok(s: &str) -> bool {
    crate::v05::terms::valid_namespace(s)
}

/// Classify `path`, or `None` when it is not a path of the store.
pub fn classify(path: &str) -> Option<Kind> {
    if !well_formed(path) {
        return None;
    }
    let parts: Vec<&str> = path.split('/').collect();
    match parts.as_slice() {
        ["authority", f] => seq8(f).map(Kind::Authority),
        ["predecessor", "authority", f] => seq8(f).map(Kind::Predecessor),
        ["transitions" | "vetoes", f] => {
            let d = f.strip_suffix(".json")?;
            is_lower_hex(d, 64).then_some(Kind::Pending)
        }
        ["receipts", obj, f] => {
            let by = f.strip_suffix(".receipt.json")?;
            (is_lower_hex(obj, 64) && key_id(by)).then_some(Kind::Receipt)
        }
        ["heads", f] => {
            let by = f.strip_suffix(".json")?;
            key_id(by).then_some(Kind::Head)
        }
        ["ops", author, ns, f] => {
            let (clock, id) = f.strip_suffix(".json")?.split_once('-')?;
            if !(key_id(author) && ns_ok(ns) && clock.len() == 12 && key_id(id)) {
                return None;
            }
            if !clock.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            Some(Kind::Op {
                author: (*author).into(),
                namespace: (*ns).into(),
                clock: clock.parse().ok()?,
                id: id.into(),
            })
        }
        ["state", author, ns, f] => {
            let slot = f.strip_suffix(".json")?;
            (key_id(author)
                && ns_ok(ns)
                && !slot.is_empty()
                && slot
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()))
            .then(|| Kind::Live {
                author: (*author).into(),
                namespace: (*ns).into(),
                slot: slot.into(),
            })
        }
        ["history", author, ns, f] => {
            let ok = f.strip_suffix(".json").is_some_and(|n| {
                n.split_once('-')
                    .is_some_and(|(c, i)| c.len() == 12 && key_id(i))
            });
            (key_id(author) && ns_ok(ns) && ok).then_some(Kind::History)
        }
        ["blobs", d] => is_lower_hex(d, 64).then(|| Kind::Blob((*d).into())),
        ["requests", f] => f.ends_with(".json").then_some(Kind::Request),
        _ => None,
    }
}

/// The storage path of a pending object.
pub fn pending_path(protocol_is_veto: bool, digest: &str) -> String {
    format!(
        "{}/{digest}.json",
        if protocol_is_veto {
            VETOES
        } else {
            TRANSITIONS
        }
    )
}
/// Where the engine keeps a home's receipt of an object it fetched.
pub fn receipt_path(object: &str, by: &str) -> String {
    format!("{RECEIPTS}/{object}/{by}.receipt.json")
}
