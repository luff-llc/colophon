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
/// A clean child of an import batch: a destination module's operation name and payload.
#[derive(Clone, Debug)]
pub struct Child {
    /// A key unique within the batch.
    pub key: String,
    /// The destination module's operation name.
    pub kind: String,
    /// The clean payload.
    pub payload: Value,
}
/// Maps an admitted Swift operation to the clean children of its batch. The default (no
/// translator) is one child with the original kind and payload verbatim, which the destination
/// accepts only where the Swift kind is the module's operation name. A domain translator
/// (`domains::*::import::translate`) needs the original Swift codec's decoded context, which the
/// core cannot produce, so a host supplies it here.
pub type Translator<'a> = dyn Fn(&SwiftOp<'_>) -> Result<Vec<Child>> + 'a;

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

/// The predecessor's members at its head, by the Swift fold.
pub fn swift_members(lib: &SwiftLibrary) -> Result<Vec<SwiftMember>> {
    Ok(fold(lib)?
        .members
        .into_iter()
        .map(|(id, m)| SwiftMember {
            budget: m.grants.iter().any(|g| {
                g.caveats
                    .iter()
                    .any(|c| c["kind"] == "budget" || c.get("budget").is_some())
            }),
            revoked: m.revoked_at.is_some(),
            label: m.label,
            role: m.role,
            id,
        })
        .collect())
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
    /// `(clock, author, id)`: the Swift fold order.
    order: (u64, String, String),
    state: State,
}

/// An import write the host makes with the copying member's key.
#[derive(Clone, Debug)]
pub struct CopyItem {
    /// The destination namespace (the source's).
    pub namespace: String,
    /// The body digest of the source record this write carries.
    pub source_digest: String,
    /// The payload of the `colophon.importBatch` operation.
    pub payload: Value,
}

/// What a finished copy reports, to feed the `migration` entry.
#[derive(Clone, Debug)]
pub struct CopyResult {
    /// One entry per predecessor namespace: `source`, the destination digests copied, the
    /// omitted count.
    pub namespaces: Vec<MigratedNamespace>,
    /// Every source record not copied: `(body digest, reason)`, sorted by digest.
    pub omitted: Vec<(String, String)>,
    /// The blob paths the host listed, which are not copied.
    pub blobs_not_copied: Vec<String>,
}

/// A copy in progress. See the module header.
#[derive(Debug)]
pub struct CopyPlan {
    library: String,
    namespaces: BTreeMap<String, Vec<Item>>,
    /// Source records that belong to no namespace (an unreadable header and no namespace in the
    /// path): in `omitted` only.
    unassigned: Vec<(String, String)>,
    destinations: BTreeSet<String>,
    blobs: Vec<String>,
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

impl CopyPlan {
    /// Read the predecessor's files and plan the copy. `keys` are the namespace keys the host
    /// opened (any number, any library: a key of another library or namespace never opens a
    /// record that is not its own). `files` are every file of the predecessor's record store
    /// the host holds.
    pub fn read(
        lib: &SwiftLibrary,
        files: &[SourceFile],
        keys: &[SwiftEpochKey],
        translate: Option<&Translator<'_>>,
    ) -> Result<Self> {
        require(files.len() <= MAX_FILES, "too many source files")?;
        let fold = fold(lib)?;
        let library = lib.library().to_string();
        let mut namespaces: BTreeMap<String, Vec<Item>> = lib
            .namespaces()
            .into_iter()
            .map(|n| (n, Vec::new()))
            .collect();
        let mut unassigned = Vec::new();
        let mut blobs = Vec::new();
        let mut candidates: BTreeMap<String, Vec<Candidate>> = BTreeMap::new();
        let mut seen_ids: BTreeSet<(String, String)> = BTreeSet::new();
        let omit = |namespaces: &mut BTreeMap<String, Vec<Item>>,
                    unassigned: &mut Vec<(String, String)>,
                    namespace: Option<&str>,
                    d: String,
                    reason: String| {
            match namespace {
                Some(ns) => namespaces.entry(ns.to_string()).or_default().push(Item {
                    source_digest: d,
                    order: (0, String::new(), String::new()),
                    state: State::Omitted(reason),
                }),
                None => unassigned.push((d, reason)),
            }
        };
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
            let ns_of_path = f
                .path
                .split('/')
                .nth(2)
                .filter(|_| f.path.split('/').count() == 4);
            let ns_of_state = f.path.split('/').nth(2);
            if live {
                omit(
                    &mut namespaces,
                    &mut unassigned,
                    ns_of_state,
                    whole,
                    "liveState".into(),
                );
                continue;
            }
            if f.bytes.len() > MAX_FILE_BYTES {
                omit(
                    &mut namespaces,
                    &mut unassigned,
                    ns_of_path,
                    whole,
                    "tooLarge".into(),
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
                omit(
                    &mut namespaces,
                    &mut unassigned,
                    ns_of_path,
                    whole,
                    "invalidPayload".into(),
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
                omit(
                    &mut namespaces,
                    &mut unassigned,
                    ns_of_path,
                    source_digest,
                    "invalidPayload".into(),
                );
                continue;
            };
            let mut omit_here = |reason: &str| {
                omit(
                    &mut namespaces,
                    &mut unassigned,
                    Some(ns),
                    source_digest.clone(),
                    reason.into(),
                )
            };
            if path.author != author || path.namespace.is_some_and(|p| p != ns) {
                omit_here("pathMismatch");
                continue;
            }
            let Some(member) = fold.members.get(author) else {
                omit_here("notAMember");
                continue;
            };
            if verify_raw(&member.signing, &body, &sig).is_err() {
                omit_here("badSignature");
                continue;
            }
            let plain = keys
                .iter()
                .find(|k| k.namespace() == ns && k.epoch() == epoch && k.library() == library)
                .and_then(|k| k.open_operation(&library, ns, epoch, &sealed));
            let Some(plain) = plain else {
                omit_here("unreadable");
                continue;
            };
            let Ok(op) = operation_of(&plain) else {
                omit_here("invalidPayload");
                continue;
            };
            if op.id != path.id {
                omit_here("pathMismatch");
                continue;
            }
            if !seen_ids.insert((author.to_string(), op.id.clone())) {
                omit_here("duplicate");
                continue;
            }
            candidates
                .entry(ns.to_string())
                .or_default()
                .push(Candidate {
                    namespace: ns.to_string(),
                    source_digest,
                    author: author.to_string(),
                    epoch,
                    path: f.path.clone(),
                    op,
                });
        }
        for (ns, mut list) in candidates {
            list.sort_by(|a, b| {
                (a.op.clock, &a.author, &a.op.id).cmp(&(b.op.clock, &b.author, &b.op.id))
            });
            let mut judge = Judge {
                fold: &fold,
                lib,
                namespace: &ns,
                spent: BTreeMap::new(),
            };
            for (position, c) in list.into_iter().enumerate() {
                let order = (c.op.clock, c.author.clone(), c.op.id.clone());
                let state = match judge.judge(&c.op, c.epoch, &c.author) {
                    Judged::Held(w) => State::Omitted(format!("held: {w}")),
                    Judged::Refused(w) => State::Omitted(format!("refused: {w}")),
                    Judged::Admitted => {
                        match batch_of(&library, &fold, &c, position as u64, translate) {
                            Ok(p) => State::Pending(p),
                            Err(e) => State::Omitted(format!("notCleanChild: {}", e.detail())),
                        }
                    }
                };
                namespaces.entry(ns.clone()).or_default().push(Item {
                    source_digest: c.source_digest,
                    order,
                    state,
                });
            }
        }
        // Duplicate source bodies (the same record at two paths) are two source records, but a
        // destination record is made for one: the second is omitted, never copied twice.
        for items in namespaces.values_mut() {
            let mut seen = BTreeSet::new();
            for it in items.iter_mut() {
                if matches!(it.state, State::Pending(_)) && !seen.insert(it.source_digest.clone()) {
                    it.state = State::Omitted("duplicate".into());
                }
            }
            items.sort_by(|a, b| {
                a.order
                    .cmp(&b.order)
                    .then(a.source_digest.cmp(&b.source_digest))
            });
        }
        let plan = Self {
            library,
            namespaces,
            unassigned,
            destinations: BTreeSet::new(),
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
    /// digest, reason)`. Records written later with [`Self::record_omitted`] are included.
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
    /// pending items in namespace order, each in the Swift fold order. Reading it changes
    /// nothing; an item stays pending until [`Self::record_written`] or [`Self::record_omitted`].
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
                        payload: p.clone(),
                    });
                }
            }
        }
        out
    }

    /// True when `item` is exactly one of the plan's pending writes (same namespace, source record
    /// and payload).
    pub fn is_pending(&self, item: &CopyItem) -> bool {
        self.namespaces.get(&item.namespace).is_some_and(|v| {
            v.iter().any(|i| {
                i.source_digest == item.source_digest
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
    /// operation). Refused: a source record that is not pending (written twice, omitted, or not
    /// in the plan), a header of another namespace, and a destination record already used.
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

    /// Record that a pending item is not copied, with a reason (the destination refused it, or
    /// the person chose to leave it).
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

    /// Finish: refused while any item is neither written nor omitted. The result is exactly what
    /// `write::succession::prepare_migration` takes.
    pub fn finish(self) -> Result<CopyResult> {
        let pending = self.pending();
        if pending > 0 {
            return Err(malformed(format!(
                "{pending} source records are neither written nor omitted"
            )));
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

/// The `colophon.importBatch` payload of one admitted source record, checked by the destination
/// fold's own validator (`imports::ImportState::validate_batch`) before it is offered.
fn batch_of(
    library: &str,
    fold: &Fold,
    c: &Candidate,
    position: u64,
    translate: Option<&Translator<'_>>,
) -> Result<Value> {
    let label = fold
        .members
        .get(&c.author)
        .map_or("Member", |m| m.label.as_str());
    let children = match translate {
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
        None => vec![Child {
            key: "op".into(),
            kind: c.op.kind.clone(),
            payload: c.op.payload.clone(),
        }],
    };
    require(!children.is_empty(), "a translator returned no child")?;
    let children: Vec<Value> = children
        .into_iter()
        .map(|k| json!({"key": k.key, "kind": k.kind, "payload": k.payload, "baseline": false}))
        .collect();
    let payload = json!({
        "key": format!("{TRANSFORM}:{library}:{}:{}:{}", c.namespace, c.author, c.op.id),
        "evidence": {
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
            "domainOutcome": "admitted",
        },
        "children": children,
        "alternatives": [],
        "identities": {},
        "blobs": [],
    });
    crate::imports::ImportState::new(&c.namespace)
        .validate_batch(&payload, &crate::domain::ProjectionState::new(&c.namespace))
        .map_err(|e| malformed(e.to_string()))?;
    Ok(payload)
}
