//! The engine's own checkpoint (0.3 §7.1, 0.5 §17.2): a sealed, device-local cache of what the
//! verifier would otherwise recompute. It holds no state the verifier takes on trust:
//!
//! * the **record memo**: for each record read, the digest of its exact bytes and, if its
//!   signature verified and its payload opened, the facts that cost cryptography to find. A
//!   restart uses a memo entry only for the exact bytes and the exact author key it was made
//!   for, so it can skip the work but never change a verdict;
//! * the **index**: each path read, its provider version token and the digest of its bytes,
//!   so a changed token drops that path's memo and a path that vanished is reported;
//! * the **live witnesses** (0.3 §7.1): per live slot the highest generation seen and its
//!   body digest, so a rolled-back slot is recognised after a restart;
//! * the namespace revisions at the time, which a resumed open compares with the revisions it
//!   derives, as evidence that a resume and a cold open agree.
//!
//! The whole blob is sealed ([`super::seal`]) under the host's device-held key and bound to
//! the account, the identity and the namespace scope. Anything else means a cold open.
use crate::v05::records::RecordMemo;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The checkpoint format.
pub const FORMAT: u32 = 1;

/// One path the engine had read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexEntry {
    /// The path.
    pub path: String,
    /// The provider's content version, when it has one.
    pub version: Option<String>,
    /// SHA-256 of the exact bytes, hex.
    pub sha256: String,
}

/// The checkpoint body, before sealing.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Body {
    /// [`FORMAT`].
    pub format: u32,
    /// The verified head `(seq, digest)` when it was made.
    pub head: (u64, String),
    /// Every immutable path read.
    pub index: Vec<IndexEntry>,
    /// The crypto memo of the records.
    pub memo: Vec<RecordMemo>,
    /// The namespace revisions at the time.
    pub revisions: BTreeMap<String, u64>,
    /// Per live path `(generation, body digest)`.
    pub live_witness: BTreeMap<String, (u64, String)>,
    /// Per home, its cursors and remembered remote set.
    #[serde(default)]
    pub exchange: BTreeMap<String, super::exchange::SavedHome>,
}
