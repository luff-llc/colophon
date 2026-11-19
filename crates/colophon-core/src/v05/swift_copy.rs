//! Copying a Swift library's records into a 0.5 account (§15.3 steps 3 and 5, §15.4, §16.2):
//! reading the predecessor's operations, judging them as the Swift reader does, and preparing
//! the successor's `colophon.importBatch` writes with the counts and view digests that
//! `write::succession::prepare_migration` takes as input, so the two agree by construction.
//!
//! **Who writes, and what survives.** The text decides this far: the copying member is the
//! member holding the `import` term (§15.3 step 3, §9.3), and 0.3 §7.2 (incorporated by §11.8)
//! says an import's children are the importer's operations, with "original attribution ...
//! labelled historical evidence, never replacement authenticated authorship". So each source
//! record becomes **one** `colophon.importBatch` operation by the copying member, whose `evidence`
//! holds the original author, label, operation ID, clock, `created`, epoch, cited authority, kind,
//! module version, path and source body digest, and whose single child is the original kind and
//! payload (`docs/engine.md`, "Engine3"). The destination record's own author, clock, `created`
//! and ID are the importer's. One destination record per copied source record is what makes
//! `copied` equal the number of view digests.
//!
//! **What is copied.** A record is copied when it authenticates (the author is a member by the
//! Swift fold, the signature is the member's), decrypts under a namespace key the host opened,
//! decodes as a `ColophonOperation`, passes the Swift admission rule (`Admission.swift`: authority
//! seen, grant in force at the cited authority, write access, the epoch current at that
//! authority, expiry, revocation and `kept`, caveats) in the Swift fold order `(clock, author,
//! id)`, and is a clean child (`imports::ImportState::validate_batch` accepts it). Anything else
//! is **omitted**, by source body digest, with a reason: the record is evidence the person can
//! see, not a silent loss (§15.4). Records under `state/` or `history/` (replaceable live state)
//! are counted and omitted `liveState`: they are not copied. Blobs (`blobs/`) are listed in
//! [`CopyResult::blobs_not_copied`] and not copied (the account has no blob writer yet).
//!
//! **What the core guarantees, and what the host is trusted with.** No secret is read here: the
//! namespace keys arrive as [`SwiftEpochKey`] handles, which open operation headers of their own
//! library, namespace and epoch and nothing else. [`CopyPlan::finish`] refuses unless every source
//! record was written or omitted exactly once, and [`CopyPlan::record_written`] refuses a source
//! record written twice, a destination record used twice and a destination record of another
//! namespace. The host is trusted to write each item it was given, unchanged, with the copying
//! member's key.
use super::encoding::{decode_base64, digest, parse_date, strict_parse};
use super::records::OperationHeader;
use super::signature::verify_raw;
use super::swift_slots::{SwiftEpochKey, SwiftLibrary};
use super::write::succession::MigratedNamespace;
use super::{malformed, require, Result};
use crate::domain::{AuthorContext, ProjectionState};
use crate::imports::ImportState;
use crate::model::OperationView;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

/// The format string of a Swift predecessor (§16.3).
pub const SOURCE_FORMAT: &str = "colophon/swift-keyring/2";
/// The version of this transform, part of every batch key.
pub const TRANSFORM: &str = "colophon/swift-copy/1";
/// Most files a plan reads, and the largest single file: bounds before any allocation.
pub const MAX_FILES: usize = 262_144;
/// The largest source file read.
pub const MAX_FILE_BYTES: usize = 4 * 1_048_576;
/// The most items a [`CopyPlan::next_batch`] returns.
pub const MAX_BATCH: usize = 256;
/// The most omitted records a migration carries (§15.4).
pub const MAX_OMITTED: usize = 4_096;

/// A Swift operation as the source reader judged it: the fields of the domain translators'
/// `VerifiedLegacyOperation` (`domains/*/import.rs`), so a host can bridge to them.
#[derive(Clone, Debug)]
pub struct SwiftOp<'a> {
    /// The predecessor library's ID.
    pub source_library: &'a str,
    /// The original signer's member ID (never the destination signer).
    pub author_id: &'a str,
    /// The original author's label.
    pub author_label: &'a str,
    /// The original operation ID.
    pub operation_id: &'a str,
    /// SHA-256 of the exact signed body bytes.
    pub signed_body_digest: &'a str,
    /// The original kind.
    pub kind: &'a str,
    /// The original module version.
    pub version: u64,
    /// The original payload, unmodified.
    pub payload: &'a Value,
    /// The position in the namespace's Swift fold order `(clock, author, id)`, counting every
    /// record the plan judged.
    pub admitted_order: u64,
}
/// A child of an import batch: a destination module's operation and payload, as
/// `imports::ImportChild` takes it.
#[derive(Clone, Debug)]
pub struct Child {
    /// A key unique within the batch.
    pub key: String,
    /// The destination module's operation name.
    pub kind: String,
    /// The clean payload.
    pub payload: Value,
    /// A trusted importer receipt for the child (`baseline`), never inferred from a payload.
    pub baseline: bool,
}
/// What a host translator says about one admitted Swift operation: everything an import batch
/// can carry (`docs/engine.md`, Engine3). The core adds the batch's `key` and the evidence
/// fields that bind it to its source (library, author, label, operation ID, clock, `created`,
/// epoch, authority, kind, version, path, source body digest); a translator can change the
/// representation, never add a record, drop one silently or attribute one to another author.
#[derive(Clone, Debug)]
pub struct Batch {
    /// The effective outputs, in order (may be empty for evidence-only records).
    pub children: Vec<Child>,
    /// Historical alternatives (`imports::ImportBatch::alternatives`).
    pub alternatives: Vec<Value>,
    /// Source occurrence key to `(category, destination id)` reservations.
    pub identities: BTreeMap<String, (String, String)>,
    /// Encrypted blob manifests (`blobs::BlobManifest` JSON) the host has staged.
    pub blobs: Vec<Value>,
    /// The domain outcome the source reader evaluated: `applied`, `noEffect`, `conflict`, ...
    pub outcome: String,
    /// Extra evidence, kept under `evidence.translation` (it cannot overwrite a core field).
    pub evidence: Value,
}
impl Batch {
    /// A batch of children only, outcome `applied`.
    pub fn of(children: Vec<Child>) -> Self {
        Self {
            children,
            alternatives: Vec::new(),
            identities: BTreeMap::new(),
            blobs: Vec::new(),
            outcome: "applied".into(),
            evidence: Value::Null,
        }
    }
}
/// Maps an admitted Swift operation to its batch. The shipped apps hold the Swift codecs, so
/// translating Swift wire kinds into the Rust domain modules' operations is the host's job
/// (as the 0.4 `colophon-clean-copy` tool does), not the core's. With no translator the batch is
/// one child with the original kind and payload verbatim, which the destination accepts only
/// where the two coincide. The core validates every result against the destination's cumulative
/// projection with `imports::ImportState::validate_batch`; a translation it refuses, or an error,
/// omits the record with the reason.
pub type Translator<'a> = dyn Fn(&SwiftOp<'_>) -> Result<Batch> + 'a;

/// One file of the predecessor's record store: its path and exact bytes.
#[derive(Clone, Debug)]
pub struct SourceFile {
    /// `ops/<author>/<namespace>/<clock>-<id>.json`, the layout 1 form without the namespace,
    /// `state/…`, `history/…` or `blobs/<digest>`.
    pub path: String,
    /// The file's bytes.
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
struct Grant {
    seq: u64,
    namespaces: Vec<String>,
    write: bool,
    expires: Option<i64>,
    caveats: Vec<Value>,
}
#[derive(Clone, Debug)]
struct Member {
    signing: Vec<u8>,
    label: String,
    role: Option<String>,
    grants: Vec<Grant>,
    revoked_at: Option<u64>,
    kept: BTreeSet<String>,
}

/// A predecessor member as the Swift fold has it at the head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwiftMember {
    /// The member ID.
    pub id: String,
    /// The label of its first grant (`"Member"` when none).
    pub label: String,
    /// The role of its first grant (`device`, `app`, `web`, `agent`, `service`), when it has one.
    pub role: Option<String>,
    /// Revoked.
    pub revoked: bool,
    /// Some grant carries a `budget` caveat (which has no 0.5 form, §16.2).
    pub budget: bool,
}

/// The Swift authority fold the admission rule reads (`AuthorityState.swift:281-327`), up to the
/// head: the entry before a freezing `layout`.
struct Fold {
    latest: u64,
    members: BTreeMap<String, Member>,
}
fn fold(lib: &SwiftLibrary) -> Result<Fold> {
    let entries = &lib.history().entries;
    let mut latest = entries.len();
    // F (and any later freezing entry) is not an entry the Swift reader could read.
    while latest > 0 && entries[latest - 1].value.get("successor").is_some() {
        latest -= 1;
    }
    let mut members: BTreeMap<String, Member> = BTreeMap::new();
    for (i, e) in entries.iter().take(latest).enumerate() {
        let seq = i as u64 + 1;
        let v = &e.value;
        match v["kind"].as_str() {
            Some("grant") => {
                let Some(signing) = v["member"]
                    .get("signing")
                    .and_then(Value::as_str)
                    .and_then(|s| decode_base64(s, 65).ok())
                else {
                    continue;
                };
                let id = super::ids::key_id(&signing);
                let expires = match v.get("expires").and_then(Value::as_str) {
                    Some(s) => Some(swift_date(s)?),
                    None => None,
                };
                let grant = Grant {
                    seq,
                    namespaces: v["namespaces"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|n| n.as_str().map(str::to_string))
                        .collect(),
                    write: v["write"].as_bool().unwrap_or(false),
                    expires,
                    caveats: v["caveats"].as_array().cloned().unwrap_or_default(),
                };
                match members.get_mut(&id) {
                    Some(m) if m.revoked_at.is_none() => m.grants.push(grant),
                    Some(_) => {} // Swift ignores a grant to a revoked member (`:292-300`).
                    None => {
                        members.insert(
                            id,
                            Member {
                                signing,
                                label: v["label"].as_str().unwrap_or("Member").to_string(),
                                role: v["role"].as_str().map(str::to_string),
                                grants: vec![grant],
                                revoked_at: None,
                                kept: BTreeSet::new(),
                            },
                        );
                    }
                }
            }
            Some("revoke") => {
                if let Some(m) = v["memberID"]
                    .as_str()
                    .and_then(|id| members.get_mut(id))
                    .filter(|m| m.revoked_at.is_none())
                {
                    m.revoked_at = Some(seq);
                    m.kept = v["kept"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|k| k.as_str().map(str::to_string))
                        .collect();
                }
            }
            _ => {}
        }
    }
    Ok(Fold {
        latest: latest as u64,
        members,
    })
}

/// A Swift date: `yyyy-MM-ddTHH:mm:ssZ`, no fraction (`Canonical.swift:11`).
fn swift_date(s: &str) -> Result<i64> {
    require(!s.contains('.'), "a Swift date has no fractional seconds")?;
    parse_date(s).ok_or_else(|| malformed("Swift date"))
}

/// The predecessor's current members at its head: the Swift verifier's own fold
/// (`history::swift`), which ignores a grant to a revoked key as the shipped reader does. The
/// label and role are those of the member's first grant (`AuthorityState.swift:297-299`).
pub fn swift_members(lib: &SwiftLibrary) -> Result<Vec<SwiftMember>> {
    let f = fold(lib)?;
    let snap = lib
        .history()
        .states
        .get((f.latest as usize).saturating_sub(1))
        .ok_or_else(|| malformed("Swift predecessor has no state"))?;
    Ok(snap
        .members
        .keys()
        .filter_map(|id| f.members.get(id).map(|m| (id, m)))
        .map(|(id, m)| SwiftMember {
            budget: m.grants.iter().any(|g| {
                g.caveats
                    .iter()
                    .any(|c| c["kind"] == "budget" || c.get("budget").is_some())
            }),
            revoked: false,
            label: m.label.clone(),
            role: m.role.clone(),
            id: id.clone(),
        })
        .collect())
}

/// Every namespace the predecessor names up to its head: by a grant or by a `shareKey`
/// (§15.4 "every predecessor namespace"; the rule `prepare_migration` applies). A namespace that
/// was granted and never given an epoch is one, with no records.
pub fn predecessor_namespaces(lib: &SwiftLibrary) -> Result<BTreeSet<String>> {
    let f = fold(lib)?;
    let mut out = BTreeSet::new();
    for e in lib.history().entries.iter().take(f.latest as usize) {
        match e.value["kind"].as_str() {
            Some("grant") => {
                for n in e.value["namespaces"].as_array().into_iter().flatten() {
                    if let Some(n) = n.as_str() {
                        out.insert(n.to_string());
                    }
                }
            }
            Some("shareKey") => {
                if let Some(n) = e.value["namespace"].as_str() {
                    out.insert(n.to_string());
                }
            }
            _ => {}
        }
    }
    Ok(out)
}

/// What the Swift admission rule says (`Admission.swift:23-49`).
enum Judged {
    Admitted,
    Held(String),
    Refused(String),
}

fn amount(v: Option<&Value>) -> Option<i64> {
    let n = v?.as_number()?;
    if let Some(i) = n.as_i64() {
        return (i.unsigned_abs() < 1_000_000_000_000_000).then_some(i);
    }
    let f = n.as_f64()?;
    (f.fract() == 0.0 && f.abs() < 1e15).then_some(f as i64)
}

struct Operation {
    id: String,
    kind: String,
    v: u64,
    clock: u64,
    authority: u64,
    created: String,
    created_ms: i64,
    payload: Value,
}
fn operation_of(plain: &[u8]) -> Result<Operation> {
    let v = strict_parse(plain)?;
    let text = |f: &str| {
        v.get(f)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| malformed("operation field"))
    };
    let num = |f: &str| {
        v.get(f)
            .and_then(Value::as_u64)
            .filter(|n| *n < 1 << 53)
            .ok_or_else(|| malformed("operation number"))
    };
    let created = text("created")?;
    let payload = v
        .get("payload")
        .filter(|p| p.is_object())
        .cloned()
        .ok_or_else(|| malformed("operation payload"))?;
    Ok(Operation {
        id: text("id")?,
        kind: text("kind")?,
        v: num("v")?,
        clock: num("clock")?,
        authority: num("authority")?,
        created_ms: swift_date(&created)?,
        created,
        payload,
    })
}

struct Judge<'a> {
    fold: &'a Fold,
    lib: &'a SwiftLibrary,
    namespace: &'a str,
    spent: BTreeMap<String, BTreeMap<String, i64>>,
}
impl Judge<'_> {
    fn judge(&mut self, op: &Operation, epoch: u64, author: &str) -> Judged {
        if op.authority > self.fold.latest {
            return Judged::Held("cites authority this copy has not received".into());
        }
        let Some(member) = self.fold.members.get(author) else {
            return Judged::Refused("not a member".into());
        };
        let Some(grant) = member.grants.iter().rev().find(|g| g.seq <= op.authority) else {
            return Judged::Refused("written before the grant".into());
        };
        if !(grant.write && grant.namespaces.iter().any(|n| n == self.namespace)) {
            return Judged::Refused(format!("no write grant for {}", self.namespace));
        }
        let at = self
            .lib
            .epochs(self.namespace)
            .iter()
            .rev()
            .find(|(_, seq)| *seq <= op.authority)
            .map(|(e, _)| *e);
        if at != Some(epoch) {
            return Judged::Refused("sealed with the wrong key epoch".into());
        }
        if grant.expires.is_some_and(|x| op.created_ms > x) {
            return Judged::Refused("written after the grant expired".into());
        }
        if let Some(revoked) = member.revoked_at {
            if !member.kept.contains(&op.id) {
                return if op.authority >= revoked {
                    Judged::Refused("written after access was revoked".into())
                } else {
                    Judged::Held("written by a member whose access was later revoked".into())
                };
            }
        }
        if let Some(why) = self.caveats(&grant.caveats, op, author) {
            return Judged::Refused(why);
        }
        Judged::Admitted
    }

    /// Caveats fail closed (`Admission.swift:52-89`).
    fn caveats(&mut self, caveats: &[Value], op: &Operation, author: &str) -> Option<String> {
        if self.namespace == "listening.podcasts" && op.kind == "playback.naturalEnd.batch" {
            let ok = amount(op.payload.get("seconds")).is_some_and(|n| n > 0)
                && amount(op.payload.get("duration")).is_some_and(|n| n > 0);
            if !ok {
                return Some("invalid natural-end costs".into());
            }
        }
        let mut pending: Vec<(String, i64)> = Vec::new();
        for c in caveats {
            let ns = c.get("namespace").and_then(Value::as_str);
            if ns.is_some() && ns != Some(self.namespace) {
                continue;
            }
            let field = c.get("field").and_then(Value::as_str);
            let max = c.get("max").and_then(Value::as_i64);
            match c["kind"].as_str() {
                Some("kinds") => {
                    let allowed = c["kinds"]
                        .as_array()
                        .is_some_and(|k| k.iter().any(|x| x == &Value::String(op.kind.clone())));
                    if !allowed {
                        return Some(format!("the grant does not allow {}", op.kind));
                    }
                }
                Some("ceiling") => {
                    let (Some(field), Some(max)) = (field, max) else {
                        return Some("malformed ceiling caveat".into());
                    };
                    if amount(op.payload.get(field)).is_some_and(|a| a > max) {
                        return Some(format!("{field} exceeds the grant's ceiling"));
                    }
                }
                Some("budget") => {
                    let (Some(field), Some(max)) = (field, max) else {
                        return Some("malformed budget caveat".into());
                    };
                    if let Some(a) = amount(op.payload.get(field)) {
                        let so_far = self
                            .spent
                            .get(author)
                            .and_then(|m| m.get(field))
                            .copied()
                            .unwrap_or(0);
                        if so_far.checked_add(a).is_none_or(|t| t > max) {
                            return Some(format!("{field} would exceed the grant's budget"));
                        }
                        pending.push((field.to_string(), a));
                    }
                }
                _ => {
                    return Some("the grant has a condition this reader does not understand".into())
                }
            }
        }
        for (field, a) in pending {
            let e = self
                .spent
                .entry(author.to_string())
                .or_default()
                .entry(field)
                .or_insert(0);
            *e = e.saturating_add(a);
        }
        None
    }
}

#[derive(Clone, Debug)]
enum State {
    Pending(Value),
    Written(String),
    Omitted(String),
}
#[derive(Clone, Debug)]
struct Item {
    source_digest: String,
    /// The batch key (empty for a record that never reached a batch).
    key: String,
    /// `(clock, author, id)`: the Swift fold order.
    order: (u64, String, String),
    state: State,
}

/// An import write the host makes with the copying member's key.
#[derive(Clone)]
pub struct CopyItem {
    /// The destination namespace (the source's).
    pub namespace: String,
    /// The body digest of the source record this write carries.
    pub source_digest: String,
    /// The batch's key.
    pub key: String,
    /// The payload of the `colophon.importBatch` operation.
    pub payload: Value,
}
impl std::fmt::Debug for CopyItem {
    // The payload is a decrypted record: it is never printed.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CopyItem({}, {}, ..)",
            self.namespace, self.source_digest
        )
    }
}

/// An import batch the destination already holds, as an account reports it
/// (`Account::swift_copy_destination`). Fields are private: only the account makes one.
#[derive(Clone)]
pub struct DestinationBatch {
    namespace: String,
    key: String,
    source_digest: String,
    source_library: String,
    destination_digest: String,
    valid: bool,
    payload: Value,
}
impl DestinationBatch {
    pub(crate) fn new(
        namespace: String,
        destination_digest: String,
        valid: bool,
        payload: Value,
    ) -> Option<Self> {
        Some(Self {
            namespace,
            key: payload.get("key")?.as_str()?.to_string(),
            source_digest: payload["evidence"]["bodyDigest"].as_str()?.to_string(),
            source_library: payload["evidence"]["sourceLibrary"].as_str()?.to_string(),
            destination_digest,
            valid,
            payload,
        })
    }
}
/// What the destination holds, in its fold order.
#[derive(Clone, Default)]
pub struct Destination {
    batches: Vec<DestinationBatch>,
}
impl Destination {
    /// The destination digest of the batch the destination took under `key`, if any.
    pub(crate) fn taken(&self, namespace: &str, key: &str) -> Option<&str> {
        self.batches
            .iter()
            .find(|b| b.valid && b.namespace == namespace && b.key == key)
            .map(|b| b.destination_digest.as_str())
    }
    /// A destination that holds nothing yet.
    pub fn empty() -> Self {
        Self::default()
    }
    pub(crate) fn from_batches(batches: Vec<DestinationBatch>) -> Self {
        Self { batches }
    }
}
impl std::fmt::Debug for Destination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Destination({} batches)", self.batches.len())
    }
}

/// What a finished copy reports, to feed the `migration` entry. Its fields are private and only
/// [`CopyPlan::finish`] makes one, after reconciling with what the destination holds.
///
/// ```compile_fail
/// let _ = colophon_core::v05::swift_copy::CopyResult {
///     namespaces: vec![],
///     omitted: vec![],
///     blobs_not_copied: vec![],
/// };
/// ```
#[derive(Clone, Debug)]
pub struct CopyResult {
    namespaces: Vec<MigratedNamespace>,
    omitted: Vec<(String, String)>,
    blobs_not_copied: Vec<String>,
}
impl CopyResult {
    /// One entry per predecessor namespace: `source`, the destination digests copied, the
    /// omitted count.
    pub fn namespaces(&self) -> &[MigratedNamespace] {
        &self.namespaces
    }
    /// Every source record not copied: `(body digest, reason)`, sorted.
    pub fn omitted(&self) -> &[(String, String)] {
        &self.omitted
    }
    /// The blob paths the host listed, which are not copied.
    pub fn blobs_not_copied(&self) -> &[String] {
        &self.blobs_not_copied
    }
}

/// The destination's fold as the copy has built it so far: what the next batch is judged against
/// (`imports::ImportState` and the domain projection, cumulative, in the determined order).
struct Scratch {
    import: ImportState,
    projection: ProjectionState,
    ctx: AuthorContext,
    n: u64,
}
impl Scratch {
    fn new(namespace: &str) -> Self {
        Self {
            import: ImportState::new(namespace),
            projection: ProjectionState::new(namespace),
            ctx: AuthorContext {
                kind: crate::model::MemberKind::Device,
                library: "0".repeat(32),
                grant: Some(crate::model::Grant {
                    namespaces: vec![namespace.to_string()],
                    access: vec![crate::model::Access::Read, crate::model::Access::Write],
                    expires: None,
                    write_budget: None,
                    import: Some(true),
                }),
            },
            n: 0,
        }
    }
    /// The destination's own validator against the cumulative state.
    fn check(&self, payload: &Value) -> Result<()> {
        self.import
            .validate_batch(payload, &self.projection)
            .map(|_| ())
            .map_err(|e| malformed(e.to_string()))
    }
    fn apply(&mut self, payload: &Value) {
        self.n += 1;
        let op = OperationView {
            id: format!("scratch-{}", self.n),
            kind: crate::imports::BATCH_KIND.into(),
            author: "0".repeat(32),
            author_label: "Copier".into(),
            origin: "person".into(),
            clock: self.n,
            created: "2026-01-01T00:00:00Z".into(),
            payload: payload.clone(),
        };
        self.import.apply(&mut self.projection, &op, &self.ctx);
    }
}

/// A copy in progress. See the module header.
pub struct CopyPlan {
    library: String,
    namespaces: BTreeMap<String, Vec<Item>>,
    /// Source records that belong to no predecessor namespace: in `omitted` only.
    unassigned: Vec<(String, String)>,
    destinations: BTreeSet<String>,
    blobs: Vec<String>,
}
impl std::fmt::Debug for CopyPlan {
    // Never the decrypted payloads.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CopyPlan({}, {} namespaces, {} pending, ..)",
            self.library,
            self.namespaces.len(),
            self.pending()
        )
    }
}

struct PathParts<'a> {
    author: &'a str,
    namespace: Option<&'a str>,
    id: &'a str,
}
/// `LibraryPath.operation` (`RecordStore.swift:92-103`) and `isOperationFileName` (`:86-90`).
fn parse_path(path: &str) -> Option<PathParts<'_>> {
    let rest = path.strip_prefix("ops/")?;
    let parts: Vec<&str> = rest.split('/').collect();
    let (author, namespace, name) = match parts.as_slice() {
        [a, n] => (*a, None, *n),
        [a, ns, n] => (*a, Some(*ns), *n),
        _ => return None,
    };
    let b = name.as_bytes();
    let ok = b.len() > 18
        && b[12] == b'-'
        && b[..12].iter().all(u8::is_ascii_digit)
        && name.ends_with(".json");
    ok.then(|| PathParts {
        author,
        namespace,
        id: &name[13..name.len() - 5],
    })
}

struct Candidate {
    namespace: String,
    source_digest: String,
    author: String,
    epoch: u64,
    path: String,
    op: Operation,
}

fn omit_into(
    namespaces: &mut BTreeMap<String, Vec<Item>>,
    unassigned: &mut Vec<(String, String)>,
    namespace: Option<&str>,
    digest: String,
    reason: &str,
) {
    match namespace.filter(|n| namespaces.contains_key(*n)) {
        Some(ns) => namespaces.entry(ns.to_string()).or_default().push(Item {
            source_digest: digest,
            key: String::new(),
            order: (0, String::new(), String::new()),
            state: State::Omitted(reason.to_string()),
        }),
        None => unassigned.push((digest, reason.to_string())),
    }
}

impl CopyPlan {
    /// Read the predecessor's files and plan the copy. `keys` are the namespace keys the host
    /// opened (a key of another library, namespace or epoch never opens a record that is not its
    /// own); `files` are every file of the predecessor's record store the host holds (a file it
    /// does not pass is neither copied nor counted); `destination` is what the destination already
    /// holds, so a copy interrupted half way is rebuilt and continues: a batch of the destination
    /// is recognised by its key and evidence (library and source body digest) and is neither
    /// written again nor lost.
    ///
    /// The namespaces are exactly those `prepare_migration` requires (a grant or a `shareKey` up to
    /// the head), a granted namespace with no epoch included with no records. A file under any
    /// other namespace is omitted, with a reason, and belongs to none.
    pub fn read(
        lib: &SwiftLibrary,
        files: &[SourceFile],
        keys: &[SwiftEpochKey],
        translate: Option<&Translator<'_>>,
        destination: &Destination,
    ) -> Result<Self> {
        require(files.len() <= MAX_FILES, "too many source files")?;
        let fold = fold(lib)?;
        let library = lib.library().to_string();
        let known = predecessor_namespaces(lib)?;
        let mut namespaces: BTreeMap<String, Vec<Item>> =
            known.iter().map(|n| (n.clone(), Vec::new())).collect();
        let mut unassigned = Vec::new();
        let mut blobs = Vec::new();
        let mut candidates: Vec<Candidate> = Vec::new();
        for f in files {
            if f.path.starts_with("blobs/") {
                blobs.push(f.path.clone());
                continue;
            }
            let live = f.path.starts_with("state/") || f.path.starts_with("history/");
            if !live && !f.path.starts_with("ops/") {
                continue; // authority, requests: not records.
            }
            let whole = digest(&f.bytes);
            let segs: Vec<&str> = f.path.split('/').collect();
            let ns_of_path = segs.get(2).copied().filter(|_| segs.len() == 4);
            if live {
                let ns = segs.get(2).copied();
                omit_into(&mut namespaces, &mut unassigned, ns, whole, "liveState");
                continue;
            }
            if f.bytes.len() > MAX_FILE_BYTES {
                omit_into(
                    &mut namespaces,
                    &mut unassigned,
                    ns_of_path,
                    whole,
                    "tooLarge",
                );
                continue;
            }
            let parsed = (|| -> Result<(Vec<u8>, Value, Vec<u8>)> {
                let env = strict_parse(&f.bytes)?;
                let body = decode_base64(
                    env.get("body")
                        .and_then(Value::as_str)
                        .ok_or_else(|| malformed("record body"))?,
                    MAX_FILE_BYTES,
                )?;
                let sig = decode_base64(
                    env.get("signature")
                        .and_then(Value::as_str)
                        .ok_or_else(|| malformed("record signature"))?,
                    64,
                )?;
                Ok((body.clone(), strict_parse(&body)?, sig))
            })();
            let Ok((body, header, sig)) = parsed else {
                omit_into(
                    &mut namespaces,
                    &mut unassigned,
                    ns_of_path,
                    whole,
                    "invalidPayload",
                );
                continue;
            };
            let source_digest = digest(&body);
            let (Some(path), Some(author), Some(ns), Some(epoch), Some(sealed)) = (
                parse_path(&f.path),
                header.get("author").and_then(Value::as_str),
                header.get("namespace").and_then(Value::as_str),
                header
                    .get("epoch")
                    .and_then(Value::as_u64)
                    .filter(|n| *n < 1 << 53),
                header
                    .get("sealed")
                    .and_then(Value::as_str)
                    .and_then(|s| decode_base64(s, MAX_FILE_BYTES).ok()),
            ) else {
                omit_into(
                    &mut namespaces,
                    &mut unassigned,
                    ns_of_path,
                    source_digest,
                    "invalidPayload",
                );
                continue;
            };
            let mut fail = |reason: &str| {
                omit_into(
                    &mut namespaces,
                    &mut unassigned,
                    Some(ns),
                    source_digest.clone(),
                    reason,
                )
            };
            if !known.contains(ns) {
                fail("notAPredecessorNamespace");
                continue;
            }
            if path.author != author || path.namespace.is_some_and(|p| p != ns) {
                fail("pathMismatch");
                continue;
            }
            let Some(member) = fold.members.get(author) else {
                fail("notAMember");
                continue;
            };
            if verify_raw(&member.signing, &body, &sig).is_err() {
                fail("badSignature");
                continue;
            }
            let plain = keys
                .iter()
                .find(|k| k.namespace() == ns && k.epoch() == epoch && k.library() == library)
                .and_then(|k| k.open_operation(&library, ns, epoch, &sealed));
            let Some(plain) = plain else {
                fail("unreadable");
                continue;
            };
            let Ok(op) = operation_of(&plain) else {
                fail("invalidPayload");
                continue;
            };
            if op.id != path.id {
                fail("pathMismatch");
                continue;
            }
            candidates.push(Candidate {
                namespace: ns.to_string(),
                source_digest,
                author: author.to_string(),
                epoch,
                path: f.path.clone(),
                op,
            });
        }
        // A duplicate `(author, id)` is decided by the body digest, never by the order the host
        // listed the files in: the authentic record with the lowest digest is the one.
        candidates.sort_by(|a, b| {
            (&a.author, &a.op.id, &a.source_digest).cmp(&(&b.author, &b.op.id, &b.source_digest))
        });
        let mut by_ns: BTreeMap<String, Vec<Candidate>> = BTreeMap::new();
        let mut last: Option<(String, String)> = None;
        for c in candidates {
            let id = (c.author.clone(), c.op.id.clone());
            if last.as_ref() == Some(&id) {
                omit_into(
                    &mut namespaces,
                    &mut unassigned,
                    Some(&c.namespace),
                    c.source_digest,
                    "duplicate",
                );
                continue;
            }
            last = Some(id);
            by_ns.entry(c.namespace.clone()).or_default().push(c);
        }
        // Several batches can sit under one key (the same item written twice): the one the
        // destination took, if any, is the copy; the others are no-op duplicates (§15.3 step 5).
        let mut held: BTreeMap<(String, String), &DestinationBatch> = BTreeMap::new();
        for b in destination
            .batches
            .iter()
            .filter(|b| b.source_library == library)
        {
            let slot = held
                .entry((b.namespace.clone(), b.key.clone()))
                .or_insert(b);
            if b.valid && !slot.valid {
                *slot = b;
            }
        }
        for (ns, mut list) in by_ns {
            list.sort_by(|a, b| {
                (a.op.clock, &a.author, &a.op.id).cmp(&(b.op.clock, &b.author, &b.op.id))
            });
            let mut scratch = Scratch::new(&ns);
            // What the destination already holds, in its own order, is the state the next
            // batch is judged against.
            for b in destination
                .batches
                .iter()
                .filter(|b| b.namespace == ns && b.valid)
            {
                scratch.apply(&b.payload);
            }
            let mut judge = Judge {
                fold: &fold,
                lib,
                namespace: &ns,
                spent: BTreeMap::new(),
            };
            for (position, c) in list.into_iter().enumerate() {
                let order = (c.op.clock, c.author.clone(), c.op.id.clone());
                let key = batch_key(&library, &c);
                let state = match judge.judge(&c.op, c.epoch, &c.author) {
                    Judged::Held(w) => State::Omitted(format!("held: {w}")),
                    Judged::Refused(w) => State::Omitted(format!("refused: {w}")),
                    Judged::Admitted => match held.get(&(ns.clone(), key.clone())) {
                        Some(b) if b.source_digest == c.source_digest => {
                            if b.valid {
                                State::Written(b.destination_digest.clone())
                            } else {
                                State::Omitted(
                                    "importInvalid: the destination marked it invalid".into(),
                                )
                            }
                        }
                        _ => match batch_of(&library, &fold, &c, &key, position as u64, translate)
                            .and_then(|p| scratch.check(&p).map(|_| p))
                        {
                            Ok(p) => {
                                scratch.apply(&p);
                                State::Pending(p)
                            }
                            Err(e) => State::Omitted(format!("notCleanChild: {}", e.detail())),
                        },
                    },
                };
                namespaces.entry(ns.clone()).or_default().push(Item {
                    source_digest: c.source_digest,
                    key,
                    order,
                    state,
                });
            }
        }
        for items in namespaces.values_mut() {
            items.sort_by(|a, b| {
                a.order
                    .cmp(&b.order)
                    .then(a.source_digest.cmp(&b.source_digest))
            });
        }
        let destinations = destination
            .batches
            .iter()
            .filter(|b| b.source_library == library)
            .map(|b| b.destination_digest.clone())
            .collect();
        let plan = Self {
            library,
            namespaces,
            unassigned,
            destinations,
            blobs,
        };
        require(
            plan.omitted_total() <= MAX_OMITTED,
            "more than 4,096 source records are not copied: stop (§15.4)",
        )?;
        Ok(plan)
    }

    fn omitted_total(&self) -> usize {
        self.unassigned.len()
            + self
                .namespaces
                .values()
                .flatten()
                .filter(|i| matches!(i.state, State::Omitted(_)))
                .count()
    }

    /// The predecessor library's ID.
    pub fn library(&self) -> &str {
        &self.library
    }
    /// How many items are still to be written or omitted.
    pub fn pending(&self) -> usize {
        self.namespaces
            .values()
            .flatten()
            .filter(|i| matches!(i.state, State::Pending(_)))
            .count()
    }
    /// The source records already omitted, with their reasons: `(namespace or empty, source body
    /// digest, reason)`.
    pub fn omissions(&self) -> Vec<(String, String, String)> {
        let mut out: Vec<(String, String, String)> = self
            .unassigned
            .iter()
            .map(|(d, r)| (String::new(), d.clone(), r.clone()))
            .collect();
        for (ns, items) in &self.namespaces {
            for it in items {
                if let State::Omitted(r) = &it.state {
                    out.push((ns.clone(), it.source_digest.clone(), r.clone()));
                }
            }
        }
        out
    }
    /// How many source records the plan holds per namespace.
    pub fn source_counts(&self) -> BTreeMap<String, u64> {
        self.namespaces
            .iter()
            .map(|(n, v)| (n.clone(), v.len() as u64))
            .collect()
    }

    /// The next bounded batch of writes (at most `max`, never more than [`MAX_BATCH`]): the
    /// pending items in namespace order, each in the Swift fold order.
    pub fn next_batch(&self, max: usize) -> Vec<CopyItem> {
        let mut out = Vec::new();
        for (ns, items) in &self.namespaces {
            for it in items {
                if out.len() >= max.min(MAX_BATCH) {
                    return out;
                }
                if let State::Pending(p) = &it.state {
                    out.push(CopyItem {
                        namespace: ns.clone(),
                        source_digest: it.source_digest.clone(),
                        key: it.key.clone(),
                        payload: p.clone(),
                    });
                }
            }
        }
        out
    }

    /// True when `item` is exactly one of the plan's pending writes.
    pub fn is_pending(&self, item: &CopyItem) -> bool {
        self.namespaces.get(&item.namespace).is_some_and(|v| {
            v.iter().any(|i| {
                i.source_digest == item.source_digest
                    && i.key == item.key
                    && matches!(&i.state, State::Pending(p) if *p == item.payload)
            })
        })
    }

    fn item_mut(&mut self, ns: &str, source_digest: &str) -> Result<&mut Item> {
        self.namespaces
            .get_mut(ns)
            .and_then(|v| {
                v.iter_mut().find(|i| {
                    i.source_digest == source_digest && matches!(i.state, State::Pending(_))
                })
            })
            .ok_or_else(|| {
                malformed("no such pending source record (written already, omitted, or unknown)")
            })
    }

    /// Record that the host wrote the item as `header` (the parsed `/5` header of the finished
    /// operation). Refused: a source record that is not pending, a header of another namespace,
    /// and a destination record already used.
    pub fn record_written(&mut self, source_digest: &str, header: &OperationHeader) -> Result<()> {
        let dest = header.digest();
        require(
            !self.destinations.contains(&dest),
            "a destination record is copied once: this one is already recorded",
        )?;
        let ns = header.namespace.clone();
        let item = self.item_mut(&ns, source_digest)?;
        item.state = State::Written(dest.clone());
        self.destinations.insert(dest);
        Ok(())
    }

    /// Record that the copy of a pending item is a batch the destination already holds and took
    /// (`destination_digest`), because the same item was written again and the later write was a
    /// no-op. The digest comes from the account's own view of the destination, and the final
    /// reconciliation checks it again; refused when another item already claims it.
    pub(crate) fn record_existing(
        &mut self,
        namespace: &str,
        source_digest: &str,
        destination_digest: &str,
    ) -> Result<()> {
        require(
            !self
                .namespaces
                .values()
                .flatten()
                .any(|i| matches!(&i.state, State::Written(d) if d == destination_digest)),
            "a destination record is copied once: this one is already recorded",
        )?;
        let item = self.item_mut(namespace, source_digest)?;
        item.state = State::Written(destination_digest.to_string());
        self.destinations.insert(destination_digest.to_string());
        Ok(())
    }

    /// Record that a pending item is not copied, with a reason (the destination marked it
    /// invalid, or the person chose to leave it).
    pub fn record_omitted(
        &mut self,
        namespace: &str,
        source_digest: &str,
        reason: &str,
    ) -> Result<()> {
        require(!reason.is_empty(), "an omission needs a reason")?;
        let item = self.item_mut(namespace, source_digest)?;
        item.state = State::Omitted(reason.to_string());
        Ok(())
    }

    /// Finish: refused while any item is neither written nor omitted, and unless the destination
    /// holds exactly what the plan says it copied: every written record is a valid batch of the
    /// destination with the plan's key and source evidence, and the destination holds no valid
    /// batch of this library that the plan does not list. `destination` comes from
    /// `Account::swift_copy_destination`.
    pub fn finish(self, destination: &Destination) -> Result<CopyResult> {
        let pending = self.pending();
        if pending > 0 {
            return Err(malformed(format!(
                "{pending} source records are neither written nor omitted"
            )));
        }
        let held: BTreeMap<&str, &DestinationBatch> = destination
            .batches
            .iter()
            .filter(|b| b.source_library == self.library)
            .map(|b| (b.destination_digest.as_str(), b))
            .collect();
        let mut claimed = BTreeSet::new();
        for (ns, items) in &self.namespaces {
            for it in items {
                if let State::Written(d) = &it.state {
                    let b = held.get(d.as_str()).ok_or_else(|| {
                        malformed(format!("the destination does not hold the record {d}"))
                    })?;
                    require(
                        b.valid && b.namespace == *ns && b.key == it.key && b.source_digest == it.source_digest,
                        "the destination holds a record that is invalid or is not the copy of its source",
                    )?;
                    claimed.insert(d.clone());
                }
            }
        }
        for b in held.values().filter(|b| b.valid) {
            require(
                claimed.contains(&b.destination_digest),
                "the destination holds a copied record the plan does not list",
            )?;
        }
        let mut namespaces = Vec::new();
        let mut omitted: Vec<(String, String)> = self.unassigned.clone();
        for (ns, items) in &self.namespaces {
            let mut copied = Vec::new();
            let mut n_omitted = 0u64;
            for it in items {
                match &it.state {
                    State::Written(d) => copied.push(d.clone()),
                    State::Omitted(r) => {
                        n_omitted += 1;
                        omitted.push((it.source_digest.clone(), r.clone()));
                    }
                    State::Pending(_) => return Err(malformed("a record is still pending")),
                }
            }
            namespaces.push(MigratedNamespace {
                namespace: ns.clone(),
                source: items.len() as u64,
                copied,
                omitted: n_omitted,
            });
        }
        omitted.sort();
        omitted.dedup();
        require(
            omitted.len() <= MAX_OMITTED,
            "more than 4,096 source records are not copied: stop (§15.4)",
        )?;
        Ok(CopyResult {
            namespaces,
            omitted,
            blobs_not_copied: self.blobs,
        })
    }
}

fn batch_key(library: &str, c: &Candidate) -> String {
    format!(
        "{TRANSFORM}:{library}:{}:{}:{}",
        c.namespace, c.author, c.op.id
    )
}

/// The `colophon.importBatch` payload of one admitted source record. The core writes the key and
/// the evidence that binds the batch to its source; the translator's batch supplies the rest.
fn batch_of(
    library: &str,
    fold: &Fold,
    c: &Candidate,
    key: &str,
    position: u64,
    translate: Option<&Translator<'_>>,
) -> Result<Value> {
    let label = fold
        .members
        .get(&c.author)
        .map_or("Member", |m| m.label.as_str());
    let batch = match translate {
        Some(t) => t(&SwiftOp {
            source_library: library,
            author_id: &c.author,
            author_label: label,
            operation_id: &c.op.id,
            signed_body_digest: &c.source_digest,
            kind: &c.op.kind,
            version: c.op.v,
            payload: &c.op.payload,
            admitted_order: position,
        })?,
        None => {
            let mut b = Batch::of(vec![Child {
                key: "op".into(),
                kind: c.op.kind.clone(),
                payload: c.op.payload.clone(),
                baseline: false,
            }]);
            b.outcome = "admitted".into();
            b
        }
    };
    require(
        (1..=128).contains(&batch.outcome.len()),
        "a translation names its domain outcome",
    )?;
    // A batch with no child writes nothing: it is not a copy of the record but its absence.
    require(
        !batch.children.is_empty(),
        "the translation produced no child record",
    )?;
    let mut evidence = json!({
        "sourceLibrary": library,
        "sourceFormat": SOURCE_FORMAT,
        "transform": TRANSFORM,
        "authorID": c.author,
        "authorLabel": label,
        "operationID": c.op.id,
        "clock": c.op.clock,
        "created": c.op.created,
        "authority": c.op.authority,
        "epoch": c.epoch,
        "kind": c.op.kind,
        "v": c.op.v,
        "path": c.path,
        "bodyDigest": c.source_digest,
        "domainOutcome": batch.outcome,
    });
    if !batch.evidence.is_null() {
        evidence["translation"] = batch.evidence.clone();
    }
    let children: Vec<Value> = batch
        .children
        .iter()
        .map(
            |k| json!({"key": k.key, "kind": k.kind, "payload": k.payload, "baseline": k.baseline}),
        )
        .collect();
    let identities: serde_json::Map<String, Value> = batch
        .identities
        .iter()
        .map(|(s, (cat, id))| (s.clone(), json!({"category": cat, "id": id})))
        .collect();
    Ok(json!({
        "key": key,
        "evidence": evidence,
        "children": children,
        "alternatives": batch.alternatives,
        "identities": identities,
        "blobs": batch.blobs,
    }))
}

#[cfg(test)]
mod tests {
    use super::amount;
    use serde_json::json;

    /// Swift counts an amount only below 1e15 (`Admission.swift:93`).
    #[test]
    fn an_amount_is_counted_below_1e15_exactly_as_swift_counts_it() {
        assert_eq!(
            amount(Some(&json!(999_999_999_999_999i64))),
            Some(999_999_999_999_999)
        );
        assert_eq!(
            amount(Some(&json!(-999_999_999_999_999i64))),
            Some(-999_999_999_999_999)
        );
        assert_eq!(amount(Some(&json!(1_000_000_000_000_000i64))), None);
        assert_eq!(amount(Some(&json!(1_000_000_000_000_001i64))), None);
        assert_eq!(amount(Some(&json!(1.0e15))), None);
        assert_eq!(
            amount(Some(&json!(999_999_999_999_999.0))),
            Some(999_999_999_999_999)
        );
        assert_eq!(amount(Some(&json!(1.5))), None);
        assert_eq!(amount(None), None);
    }
}
