//! The 0.5 account engine: the counterpart of the 0.4 storage engine
//! (`storage::Engine<S: RecordSource>`). It is what an app's session runs. It reads objects from
//! a host-supplied record source, hands them to the [`Account`] (which verifies them), keeps
//! checkpoints so a restart is cheap, answers views and queries, writes, and exchanges with a
//! home. Sans-IO: the source, the clock, the entropy and the network are the host's.
//!
//! # What the engine is, and is not
//!
//! The engine **holds an [`Account`] and nothing else that is verified**. Every verdict, every
//! folded namespace, every key and every member comes from the account; no function here takes
//! a state, a keyring, terms or a session number from a caller. The engine adds: the path
//! grammar ([`paths`]), reading from the source in bounded, ordered batches, a sealed
//! checkpoint ([`checkpoint`], [`seal`]), the live-state, blob, import and exchange mechanics,
//! and the integrity audit.
//!
//! **Memory.** The account holds the record envelopes it was given and its folds, so the
//! engine reads a record once, in batches of [`EngineOptions::batch`], and does not read a
//! path it holds again; it does not keep every record *out of memory*. An index-only account
//! (envelopes dropped once judged, re-read by path when needed) is not built. What a
//! checkpoint saves on a restart is the cryptography: signature checks and payload
//! decryptions of records whose exact bytes and author key it remembers.
//!
//! **Incremental judgement.** A merge of records that sort after everything held resumes the
//! account's walk from its last state, and a merge of earlier records walks again without
//! repeating any signature check or decryption (`v05::records::JudgeCache`). The result equals
//! a full judgement; `tests/v05_account_engine.rs` shows it over shuffled arrival orders.
pub use crate::engine::RecordSource;
use crate::model::{Denial, LedgerEntry, OperationView, Outcome};
use crate::v05::account::{Account, Changes, Identity, Incoming, Status};
use crate::v05::history::Objects;
use crate::v05::records::{HeldRecord, OperationHeader};
use crate::v05::write::SignatureResult;
use crate::v05::{malformed, require, Failure, Reason, Result};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub mod blobs;
pub mod checkpoint;
pub mod exchange;
pub mod live;
pub mod paths;
pub mod seal;

use paths::Kind;

/// Largest authority-side object (an entry, a transition, a receipt, a head) read from a source.
pub const MAX_OBJECT: usize = crate::v05::account::MAX_OBJECT_BYTES;
/// Largest record read from a source.
pub const MAX_RECORD: usize = crate::v05::account::MAX_RECORD_BYTES;
/// Most paths a listing may name.
pub const MAX_LISTING: usize = crate::v05::account::MAX_OBJECTS * 2;

/// Device-local configuration, never protocol metadata.
#[derive(Clone)]
pub struct EngineOptions {
    /// The account this engine is for: its 64-hex ID, taken from enrollment or creation. A
    /// source whose genesis is another's is refused.
    pub account: String,
    /// The host's device-held 32-byte key for sealed state. It never leaves the engine:
    /// `Debug` redacts it and no accessor returns it.
    checkpoint_key: [u8; 32],
    /// Namespaces this replica reads. Empty means every namespace.
    pub namespaces: Vec<String>,
    /// Records read and merged per batch (1..=65,536): one judgement per batch.
    pub batch: usize,
}
impl EngineOptions {
    /// Options for `account` with the device-held `checkpoint_key`.
    pub fn new(account: &str, checkpoint_key: [u8; 32]) -> Self {
        Self {
            account: account.to_string(),
            checkpoint_key,
            namespaces: Vec::new(),
            batch: 16_384,
        }
    }
}
impl std::fmt::Debug for EngineOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "EngineOptions({}, {} namespaces, batch {}, ..)",
            self.account,
            self.namespaces.len(),
            self.batch
        )
    }
}

/// Why this open used or ignored the checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpenMode {
    /// No checkpoint was given: everything is verified.
    Cold,
    /// The sealed checkpoint verified and its memo is in use.
    Resumed,
    /// A checkpoint was given and ignored, or a resume disagreed with what it derived;
    /// everything was verified. The reason.
    Invalidated(String),
}

/// Observable engine work.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EngineStats {
    /// Objects read from the source.
    pub records_read: u64,
    /// Signatures verified by the account's judgement (cumulative).
    pub signatures_verified: u64,
    /// Payloads decrypted by the account's judgement (cumulative).
    pub payloads_decrypted: u64,
    /// Candidates the latest walk judged.
    pub walked_last: u64,
    /// Operations applied to a namespace fold by the latest build.
    pub folds_applied_last: u64,
    /// Listed paths that were not a path of the store, and were ignored.
    pub ignored_paths: u64,
    /// Immutable paths read and held.
    pub held_paths: usize,
    /// Listed paths not yet read.
    pub unread_paths: usize,
}

/// Bounded history result in protocol order. Reset offsets when the revision changes.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryPage {
    /// Authenticated admitted operations with their payloads.
    pub items: Vec<OperationView>,
    /// Offset for the next page, or none at the end.
    pub next_offset: Option<usize>,
}
/// Progress of the background integrity audit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationProgress {
    /// Paths checked in this call (never more than the limit).
    pub checked: usize,
    /// Paths left in this pass; after zero the next call starts a new pass.
    pub remaining: usize,
}

/// What the host stores after a write: exact bytes at paths, in order. The account's `finish`
/// ran the verifier over exactly these bytes before the engine returned them.
#[derive(Clone, Debug)]
pub struct Written {
    /// `(path, bytes)` to store, in this order.
    pub stores: Vec<(String, Vec<u8>)>,
    /// What the write changed.
    pub changes: Changes,
}

/// The sealed state a host stores between sessions: the account's verifier state and the
/// engine's checkpoint. Both are caches sealed under the device-held key.
#[derive(Clone, Debug)]
pub struct Saved {
    /// The account's persisted verifier state (§17.2).
    pub verifier: Vec<u8>,
    /// The engine's checkpoint.
    pub checkpoint: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(crate) struct Have {
    pub sha: [u8; 32],
    pub version: Option<String>,
}

/// What the engine has read and what the host has listed.
#[derive(Default)]
pub(crate) struct Index {
    /// Immutable paths read and held.
    pub have: BTreeMap<String, Have>,
    /// Live paths read: the latest bytes seen for each.
    pub live_have: BTreeMap<String, Have>,
    /// Paths listed and not yet read.
    pub unread: BTreeSet<String>,
    /// Every path the host listed.
    pub listing: BTreeSet<String>,
}

pub(crate) fn sha(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
/// Whether a verdict code (§1 failure codes against §11.5 admission spellings) says the
/// header never became a record: it did not parse, or its signature, account or path is wrong.
pub(crate) fn is_not_a_record(code: &str) -> bool {
    !(code == "admitted"
        || code.starts_with("refused:")
        || code.starts_with("held:")
        || code == "newerFormat")
}
fn unavailable(path: &str, why: impl std::fmt::Display) -> Failure {
    Failure::Unavailable(format!("{path}: {why}"))
}

/// Add `c` to `into`: the engine returns one summary for the batches of one call.
pub(crate) fn absorb(into: &mut Changes, c: Changes) {
    if into.status.is_none() {
        into.authority.seq = c.authority.seq;
    } else {
        into.authority.seq.1 = c.authority.seq.1;
    }
    into.authority.entries.extend(c.authority.entries);
    for (dst, src) in [
        (&mut into.authority.members_added, c.authority.members_added),
        (
            &mut into.authority.members_revoked,
            c.authority.members_revoked,
        ),
        (
            &mut into.authority.controllers_added,
            c.authority.controllers_added,
        ),
        (
            &mut into.authority.controllers_removed,
            c.authority.controllers_removed,
        ),
        (&mut into.pending.added, c.pending.added),
    ] {
        for x in src {
            if !dst.contains(&x) {
                dst.push(x);
            }
        }
    }
    into.authority.vault_changed |= c.authority.vault_changed;
    into.authority.policy_changed |= c.authority.policy_changed;
    into.authority.reorganized |= c.authority.reorganized;
    into.namespaces.extend(c.namespaces);
    into.pending.gone.extend(c.pending.gone);
    into.pending.now = c.pending.now;
    into.heads.accepted.extend(c.heads.accepted);
    into.heads.refused.extend(c.heads.refused);
    into.foreign += c.foreign;
    if c.status.is_some() {
        into.status = c.status;
    }
}

fn read_source<S: RecordSource>(
    source: &S,
    stats: &mut EngineStats,
    path: &str,
    cap: usize,
) -> Result<Vec<u8>> {
    stats.records_read += 1;
    let bytes = source.read(path).map_err(|e| unavailable(path, &e.0))?;
    require(bytes.len() <= cap, "an object exceeds its bound")?;
    Ok(bytes)
}

fn in_scope(options: &EngineOptions, ns: &str) -> bool {
    options.namespaces.is_empty() || options.namespaces.iter().any(|n| n == ns)
}

/// Validate and classify a listing; remember it and queue the records and live slots in scope
/// for reading. Returns every listed path's kind.
fn classify_listing(
    options: &EngineOptions,
    ix: &mut Index,
    ignored: &mut u64,
    listing: Vec<String>,
) -> Result<BTreeMap<String, Kind>> {
    require(listing.len() <= MAX_LISTING, "the listing is too long")?;
    let mut kinds = BTreeMap::new();
    let mut set = BTreeSet::new();
    for p in listing {
        match paths::classify(&p) {
            Some(k) => {
                set.insert(p.clone());
                kinds.insert(p, k);
            }
            None => *ignored += 1,
        }
    }
    for (p, k) in &kinds {
        match k {
            Kind::Op { namespace, .. }
                if in_scope(options, namespace) && !ix.have.contains_key(p) =>
            {
                ix.unread.insert(p.clone());
            }
            Kind::Live { namespace, .. }
                if in_scope(options, namespace) && !ix.live_have.contains_key(p) =>
            {
                ix.unread.insert(p.clone());
            }
            _ => {}
        }
    }
    ix.listing = set;
    Ok(kinds)
}

fn is_authority_side(k: &Kind) -> bool {
    matches!(
        k,
        Kind::Authority(_) | Kind::Predecessor(_) | Kind::Pending | Kind::Receipt | Kind::Head
    )
}

fn hold_object(
    ix: &mut Index,
    objects: &mut Objects,
    kind: &Kind,
    path: &str,
    bytes: Vec<u8>,
    version: Option<String>,
) {
    ix.have.insert(
        path.to_string(),
        Have {
            sha: sha(&bytes),
            version,
        },
    );
    match kind {
        Kind::Authority(_) => objects.entries.push(bytes),
        Kind::Predecessor(_) => objects.predecessor.push(bytes),
        Kind::Pending | Kind::Receipt => objects.pending.push(bytes),
        Kind::Head => objects.heads.push(bytes),
        _ => {}
    }
}

/// The account engine over a record source `S`.
pub struct Engine<S: RecordSource> {
    pub(crate) source: S,
    pub(crate) account: Account,
    pub(crate) options: EngineOptions,
    me: Identity,
    mode: OpenMode,
    pub(crate) ix: Index,
    /// Paths a checkpoint covered that the listing no longer names.
    missing: BTreeSet<String>,
    /// The restored checkpoint's index, until the records it covers are read.
    restored: BTreeMap<String, checkpoint::IndexEntry>,
    restored_revisions: Option<BTreeMap<String, u64>>,
    /// Per live path `(generation, body digest)`: the highest seen.
    pub(crate) live_witness: BTreeMap<String, (u64, String)>,
    /// Live candidates refused for being below their witness: `(path, generation)`.
    pub(crate) stale_live: Vec<(String, u64)>,
    pub(crate) stats: EngineStats,
    /// Covered paths the open judged again because their bytes changed.
    rejudged: Vec<String>,
    ready: bool,
    failure: Option<Failure>,
    verify_cursor: usize,
    pub(crate) exchange: exchange::State,
}

impl<S: RecordSource> std::fmt::Debug for Engine<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Engine({:?}, {} paths held, ready {})",
            self.account,
            self.ix.have.len(),
            self.ready
        )
    }
}

impl<S: RecordSource> Engine<S> {
    /// Open an engine over a coherent host `listing` of the source's paths.
    ///
    /// It reads the authority-side objects first (entries, transitions, vetoes, receipts,
    /// heads, the predecessor), opens the account over them, and checks the account is
    /// `options.account`. It reads **no record** yet: records are read after the host has
    /// unlocked ([`Engine::finish_unlock_slot`], [`Engine::finish_unlock_epochs`], or
    /// [`Engine::load`]), so a session never judges its history once before unlock and again
    /// after (0.3 §7.1).
    ///
    /// `saved` is what [`Engine::save`] returned. A sealed state that fails its tag, is of an
    /// unknown format, or names another account or identity is ignored and the engine opens
    /// cold: a checkpoint is a cache and never state taken on bare bytes.
    pub fn open(
        source: S,
        listing: Vec<String>,
        me: Identity,
        options: EngineOptions,
        saved: Option<&Saved>,
        now_ms: i64,
    ) -> Result<Self> {
        require(
            crate::v05::encoding::is_lower_hex(&options.account, 64),
            "the account ID is 64 lowercase hex",
        )?;
        require(
            (1..=65_536).contains(&options.batch),
            "batch is 1 to 65536",
        )?;
        for n in &options.namespaces {
            require(
                crate::v05::terms::valid_namespace(n),
                "invalid namespace in the read scope",
            )?;
        }
        let mut ix = Index::default();
        let mut stats = EngineStats::default();
        let kinds = classify_listing(&options, &mut ix, &mut stats.ignored_paths, listing)?;
        let mut objects = Objects::default();
        for (p, k) in kinds.iter().filter(|(_, k)| is_authority_side(k)) {
            let Ok(bytes) = read_source(&source, &mut stats, p, MAX_OBJECT) else {
                // Unreadable now; `refresh` tries again.
                continue;
            };
            let version = source.content_version(p).unwrap_or(None);
            hold_object(&mut ix, &mut objects, k, p, bytes, version);
        }
        let key = options.checkpoint_key;
        let mut scope = options.namespaces.clone();
        scope.sort();
        scope.dedup();
        let mut mode = OpenMode::Cold;
        let mut body = None;
        if let Some(s) = saved {
            match seal::open(&s.checkpoint, &options.account, &me, &scope, &key)
                .and_then(|plain| serde_json::from_slice::<checkpoint::Body>(&plain).ok())
            {
                Some(b) if b.format == checkpoint::FORMAT => {
                    mode = OpenMode::Resumed;
                    body = Some(b);
                }
                Some(_) => {
                    mode = OpenMode::Invalidated("the checkpoint is of an unknown format".into());
                }
                None => {
                    mode = OpenMode::Invalidated(
                        "the checkpoint failed its seal or names another account or identity"
                            .into(),
                    );
                }
            }
        }
        let mut account = Account::open(
            objects,
            Vec::new(),
            saved.map(|s| (s.verifier.as_slice(), &key)),
            me.clone(),
            now_ms,
        )?;
        require(
            account.id().as_str() == options.account,
            "the source holds another account",
        )?;
        if !options.namespaces.is_empty() {
            account.set_read_scope(options.namespaces.clone())?;
        }
        let mut restored = BTreeMap::new();
        let mut restored_revisions = None;
        let mut live_witness = BTreeMap::new();
        let mut saved_exchange = BTreeMap::new();
        if let Some(b) = body {
            // A changed provider token drops that path's memo (0.3 §7.1): the work is done
            // again even for identical bytes.
            let mut memo = b.memo;
            let tokens: BTreeMap<&str, &Option<String>> = b
                .index
                .iter()
                .map(|i| (i.path.as_str(), &i.version))
                .collect();
            memo.retain(|m| match tokens.get(m.path.as_str()) {
                None => false,
                Some(was) => {
                    ix.listing.contains(&m.path)
                        && **was == source.content_version(&m.path).unwrap_or(None)
                }
            });
            account.import_judge_memo(memo);
            restored = b.index.into_iter().map(|i| (i.path.clone(), i)).collect();
            restored_revisions = Some(b.revisions);
            live_witness = b.live_witness;
            saved_exchange = b.exchange;
        }
        // What the checkpoint covered and the listing no longer names is unavailable, not
        // gone (0.3 §7.1).
        let missing: BTreeSet<String> = restored
            .keys()
            .filter(|p| !ix.listing.contains(*p))
            .cloned()
            .collect();
        let mut e = Self {
            source,
            account,
            options,
            me,
            mode,
            ix,
            missing,
            restored,
            restored_revisions,
            live_witness,
            stale_live: Vec::new(),
            stats,
            rejudged: Vec::new(),
            ready: false,
            failure: None,
            verify_cursor: 0,
            exchange: exchange::State::default(),
        };
        let verified = e.account.head().0;
        e.exchange.import(saved_exchange, verified);
        e.refresh_stats();
        Ok(e)
    }

    fn scope(&self) -> Vec<String> {
        let mut s = self.options.namespaces.clone();
        s.sort();
        s.dedup();
        s
    }

    fn refresh_stats(&mut self) {
        let w = self.account.work();
        self.stats.signatures_verified = w.total.signatures;
        self.stats.payloads_decrypted = w.total.opened;
        self.stats.walked_last = w.last.walked;
        self.stats.folds_applied_last = w.fold_applied;
        self.stats.held_paths = self.ix.have.len();
        self.stats.unread_paths = self.ix.unread.len();
    }

    pub(crate) fn check_usable(&self) -> Result<()> {
        match &self.failure {
            Some(f) => Err(f.clone()),
            None => Ok(()),
        }
    }
    pub(crate) fn check_ready(&self) -> Result<()> {
        self.check_usable()?;
        require(
            self.ready,
            "the engine has not loaded its records: unlock, then call load",
        )
    }
    pub(crate) fn poison(&mut self, f: Failure) -> Failure {
        self.failure = Some(f.clone());
        f
    }

    // -----------------------------------------------------------------------------------------
    // Reading from the source.

    /// Read every listed record and live slot in scope, in batches, and merge them. The
    /// `finish_unlock_*` methods call it; a host with nothing to unlock calls it directly.
    /// Idempotent.
    pub fn load(&mut self) -> Result<Changes> {
        self.check_usable()?;
        let paths: Vec<String> = self.ix.unread.iter().cloned().collect();
        let c = self.ingest(paths)?;
        self.ready = true;
        if let Some(was) = self.restored_revisions.take() {
            // A resume must agree with a cold open: when the records read are exactly the
            // ones the checkpoint covered, the revisions it recorded are the ones derived now.
            let ops =
                |m: &mut dyn Iterator<Item = (&String, [u8; 32])>| -> BTreeMap<String, [u8; 32]> {
                    m.filter(|(p, _)| matches!(paths::classify(p), Some(Kind::Op { .. })))
                        .map(|(p, h)| (p.clone(), h))
                        .collect()
                };
            let then = ops(&mut self.restored.iter().map(|(p, e)| (p, sha_of(e))));
            let now = ops(&mut self.ix.have.iter().map(|(p, h)| (p, h.sha)));
            if then == now {
                for (ns, rev) in was {
                    if self.account.is_namespace_open(&ns) && self.account.revision(&ns) != rev {
                        self.mode = OpenMode::Invalidated(format!(
                            "namespace {ns} derived revision {} but the checkpoint recorded {rev}",
                            self.account.revision(&ns)
                        ));
                    }
                }
            }
        }
        // A checkpoint covers a path only for the exact bytes it saw. Where the bytes now at a
        // covered path are other bytes, the memo did not apply (it is keyed by the exact
        // bytes), the path was judged again, and the open says so instead of claiming a clean
        // resume (0.3 §7.1).
        let mut changed: Vec<String> = self
            .restored
            .iter()
            .filter(|(p, e)| self.ix.have.get(*p).is_some_and(|h| h.sha != sha_of(e)))
            .map(|(p, _)| p.clone())
            .collect();
        changed.sort();
        if !changed.is_empty() {
            self.mode = OpenMode::Invalidated(format!(
                "{} covered path(s) hold other bytes than the checkpoint saw and were judged again: {}",
                changed.len(),
                changed.iter().take(3).cloned().collect::<Vec<_>>().join(", ")
            ));
            self.rejudged = changed;
        }
        self.restored.clear();
        self.account.checkpoint_verifier();
        Ok(c)
    }

    /// Take what is new from the source after the host's coherent `listing`: read the paths
    /// not read yet, merge them through the account and return what changed. A path read before
    /// whose provider version changed is read again; different bytes at an immutable path are
    /// equivocation and the engine fails closed (sticky: open a fresh engine after the host
    /// has looked).
    pub fn refresh(&mut self, listing: Vec<String>) -> Result<Changes> {
        self.check_usable()?;
        let kinds = classify_listing(
            &self.options,
            &mut self.ix,
            &mut self.stats.ignored_paths,
            listing,
        )?;
        let mut todo: Vec<String> = Vec::new();
        for (p, k) in &kinds {
            let now = || self.source.content_version(p).unwrap_or(None);
            match k {
                Kind::Live { namespace, .. } if in_scope(&self.options, namespace) => {
                    let was = self.ix.live_have.get(p);
                    if self.ix.unread.contains(p)
                        || was.is_none_or(|h| h.version != now() || h.version.is_none())
                    {
                        todo.push(p.clone());
                    }
                }
                Kind::Live { .. } | Kind::Blob(_) | Kind::History | Kind::Request => {}
                Kind::Op { namespace, .. } => {
                    if in_scope(&self.options, namespace) {
                        if self.ix.unread.contains(p) {
                            todo.push(p.clone());
                        } else if let Some(h) = self.ix.have.get(p) {
                            let n = now();
                            if n.is_some() && n != h.version {
                                todo.push(p.clone());
                            }
                        }
                    }
                }
                _ => {
                    let new = !self.ix.have.contains_key(p);
                    let changed = self.ix.have.get(p).is_some_and(|h| {
                        let n = now();
                        n.is_some() && n != h.version
                    });
                    if new || changed || self.ix.unread.contains(p) {
                        todo.push(p.clone());
                    }
                }
            }
        }
        self.missing = self
            .ix
            .have
            .keys()
            .filter(|p| !self.ix.listing.contains(*p))
            .cloned()
            .collect();
        self.ingest(todo)
    }

    /// Read exactly `paths` (the host says they changed) and merge them. The paths join the
    /// listing.
    pub fn apply_paths(&mut self, paths: Vec<String>) -> Result<Changes> {
        self.check_usable()?;
        require(paths.len() <= MAX_LISTING, "too many paths")?;
        for p in &paths {
            if paths::classify(p).is_some() {
                self.ix.listing.insert(p.clone());
            }
        }
        self.ingest(paths)
    }

    /// The common path of `load`, `refresh` and `apply_paths`.
    fn ingest(&mut self, wanted: Vec<String>) -> Result<Changes> {
        let mut objects = Objects::default();
        let mut records: Vec<((u64, String, String), String)> = Vec::new();
        let mut live: Vec<String> = Vec::new();
        let mut seen = BTreeSet::new();
        for p in wanted {
            if !seen.insert(p.clone()) {
                continue;
            }
            let Some(kind) = paths::classify(&p) else {
                self.stats.ignored_paths += 1;
                continue;
            };
            match kind {
                Kind::Authority(_)
                | Kind::Predecessor(_)
                | Kind::Pending
                | Kind::Receipt
                | Kind::Head => {
                    let Ok(bytes) = read_source(&self.source, &mut self.stats, &p, MAX_OBJECT)
                    else {
                        continue;
                    };
                    let version = self.source.content_version(&p).unwrap_or(None);
                    hold_object(&mut self.ix, &mut objects, &kind, &p, bytes, version);
                    self.ix.unread.remove(&p);
                }
                Kind::Op {
                    namespace,
                    author,
                    clock,
                    id,
                } => {
                    if in_scope(&self.options, &namespace) {
                        records.push(((clock, author, id), p));
                    }
                }
                Kind::Live { namespace, .. } => {
                    if in_scope(&self.options, &namespace) {
                        live.push(p);
                    }
                }
                Kind::History | Kind::Blob(_) | Kind::Request => {
                    self.ix.unread.remove(&p);
                }
            }
        }
        records.sort();
        let now = self.account.now_ms();
        let mut total = Changes::default();
        let mut first = Some(objects);
        let mut chunks = records.chunks(self.options.batch.max(1));
        loop {
            let mut incoming = Incoming {
                objects: first.take().unwrap_or_default(),
                records: Vec::new(),
            };
            let chunk = chunks.next();
            if let Some(chunk) = chunk {
                for (_, p) in chunk {
                    let Ok(bytes) = read_source(&self.source, &mut self.stats, p, MAX_RECORD)
                    else {
                        continue;
                    };
                    let version = self.source.content_version(p).unwrap_or(None);
                    let digest = sha(&bytes);
                    if self.ix.have.get(p).is_some_and(|h| h.sha != digest) {
                        // Different bytes where a record was verified are equivocation
                        // (0.3 §7.1). Bytes that were never a record (garbage planted in
                        // front of the real one) verified nothing, and are replaced.
                        let was_record = self
                            .account
                            .record_verdict(p)
                            .is_some_and(|c| !is_not_a_record(&c));
                        if was_record {
                            return Err(self.poison(Failure::Refused(Reason::Fork)));
                        }
                    }
                    self.ix.have.insert(
                        p.clone(),
                        Have {
                            sha: digest,
                            version,
                        },
                    );
                    self.ix.unread.remove(p);
                    incoming.records.push(HeldRecord {
                        path: p.clone(),
                        bytes,
                    });
                }
            }
            let empty = incoming.objects.entries.is_empty()
                && incoming.objects.pending.is_empty()
                && incoming.objects.heads.is_empty()
                && incoming.objects.predecessor.is_empty()
                && incoming.records.is_empty();
            if !empty {
                let c = self.account.merge(incoming, now)?;
                absorb(&mut total, c);
            }
            if chunk.is_none() {
                break;
            }
        }
        if !live.is_empty() {
            let c = self.ingest_live(live)?;
            absorb(&mut total, c);
        }
        self.refresh_stats();
        Ok(total)
    }

    /// Advance the account's clock (the host passes the time).
    pub fn advance(&mut self, now_ms: i64) -> Result<Changes> {
        self.check_usable()?;
        self.account.advance(now_ms)
    }

    // -----------------------------------------------------------------------------------------
    // Unlock: forwarded to the account, then the records are read once.

    /// See [`Account::slots`].
    pub fn slots(&self) -> Result<Vec<crate::v05::account::SlotOption>> {
        self.account.slots()
    }
    /// See [`Account::begin_unlock_slot`].
    pub fn begin_unlock_slot(&self, index: usize) -> Result<Vec<crate::v05::slots::OpeningInput>> {
        self.account.begin_unlock_slot(index)
    }
    /// Open a slot, then read the records once (the account opens every epoch the seed
    /// reaches first, so the history is judged once, with its keys).
    pub fn finish_unlock_slot(
        &mut self,
        index: usize,
        secrets: &[crate::v05::slots::OpeningSecret],
    ) -> Result<Changes> {
        self.check_usable()?;
        let mut c = self.account.finish_unlock_slot(index, secrets)?;
        let l = self.load()?;
        absorb(&mut c, l);
        Ok(c)
    }
    /// See [`Account::begin_unlock_epochs`].
    pub fn begin_unlock_epochs(&self) -> Vec<crate::v05::account::EpochAgreement> {
        self.account.begin_unlock_epochs()
    }
    /// A member opens its shares, then the records are read once.
    pub fn finish_unlock_epochs(
        &mut self,
        results: Vec<crate::v05::account::EpochSecret>,
    ) -> Result<Changes> {
        self.check_usable()?;
        let mut c = self.account.finish_unlock_epochs(results)?;
        let l = self.load()?;
        absorb(&mut c, l);
        Ok(c)
    }

    // -----------------------------------------------------------------------------------------
    // Reads.

    /// The account, read-only. It holds the verified state; nothing reached through this
    /// reference gives the engine a state.
    pub fn account(&self) -> &Account {
        &self.account
    }
    /// The account ID.
    pub fn id(&self) -> &crate::v05::ids::AccountId {
        self.account.id()
    }
    /// How this open used the checkpoint.
    pub fn open_mode(&self) -> &OpenMode {
        &self.mode
    }
    /// The record source.
    pub fn source(&self) -> &S {
        &self.source
    }
    /// Engine work counters.
    pub fn stats(&self) -> EngineStats {
        let mut s = self.stats.clone();
        let w = self.account.work();
        s.signatures_verified = w.total.signatures;
        s.payloads_decrypted = w.total.opened;
        s.walked_last = w.last.walked;
        s.folds_applied_last = w.fold_applied;
        s.held_paths = self.ix.have.len();
        s.unread_paths = self.ix.unread.len();
        s
    }
    /// Where the verifier stands.
    pub fn status(&self) -> Status {
        self.account.status()
    }
    /// Members whose `writes` budget spans namespaces this replica does not read (0.3 §4,
    /// `budgetScopeUnavailable`): a budget is counted across all of a member's namespaces, so
    /// a partial replica cannot tell how much of it is spent. This replica refuses local
    /// writes under such a grant; the host should show these members' contributions as
    /// unevaluated. (The fold here still counts what it reads: the engine does not yet refuse
    /// the contributions themselves, which the report lists as not done.)
    pub fn budget_scope_unavailable(&self) -> Vec<String> {
        if self.options.namespaces.is_empty() {
            return Vec::new();
        }
        self.account
            .record_authority()
            .state()
            .members()
            .iter()
            .filter(|m| {
                m.revoked_seq.is_none()
                    && m.terms.writes().is_some()
                    && m.terms
                        .records()
                        .is_some_and(|r| r.iter().any(|e| !in_scope(&self.options, &e.namespace)))
            })
            .map(|m| m.request.member_id())
            .collect()
    }
    fn partial_budget_denial(&self) -> Option<Denial> {
        let crate::v05::account::Standing::Member(me) = self.account.me() else {
            return None;
        };
        self.budget_scope_unavailable()
            .contains(&me.member.id)
            .then(|| Denial {
                reason: "budgetScopeUnavailable".into(),
                detail: "this replica reads only part of the grant a write budget spans".into(),
            })
    }
    /// Paths a checkpoint covered that the latest listing does not name: unavailable, never
    /// permission to rebuild an empty namespace.
    pub fn missing_covered(&self) -> Vec<String> {
        self.missing.iter().cloned().collect()
    }
    /// Covered paths whose bytes changed since the checkpoint, which the resumed open judged
    /// again.
    pub fn rejudged(&self) -> &[String] {
        &self.rejudged
    }
    /// Why `namespace` is not readable, or `None` when it is.
    pub fn access(&self, namespace: &str) -> Result<Option<Denial>> {
        self.check_usable()?;
        Ok(self.account.access(namespace))
    }
    /// The namespace's local revision token.
    pub fn revision(&self, namespace: &str) -> u64 {
        self.account.revision(namespace)
    }
    /// Every declared namespace's revision.
    pub fn revisions(&self) -> BTreeMap<String, u64> {
        self.account
            .record_authority()
            .namespaces()
            .iter()
            .map(|n| (n.clone(), self.account.revision(n)))
            .collect()
    }
    /// What this session is in the verified history.
    pub fn me(&self) -> crate::v05::account::Standing {
        self.account.me()
    }
    /// The members.
    pub fn members(&self) -> Vec<crate::v05::account::MemberInfo> {
        self.account.members()
    }
    /// The plain-language ledger.
    pub fn ledger(&self) -> Vec<LedgerEntry> {
        self.account.ledger()
    }
    /// The folded namespace with its held and refused evidence.
    pub fn view(&self, namespace: &str) -> Result<Outcome<crate::model::NamespaceView>> {
        self.check_ready()?;
        self.account.view(namespace)
    }
    /// A domain query.
    pub fn query(&self, namespace: &str, name: &str, args: Value) -> Result<Outcome<Value>> {
        self.check_ready()?;
        self.account.query(namespace, name, args)
    }
    /// One bounded page of admitted operations in fold order.
    pub fn history(
        &self,
        namespace: &str,
        offset: usize,
        limit: usize,
    ) -> Result<Outcome<HistoryPage>> {
        self.check_ready()?;
        require((1..=200).contains(&limit), "history limit must be 1..200")?;
        match self.account.view(namespace)? {
            Outcome::Failure { reason, detail, .. } => {
                Ok(Outcome::failure(Denial { reason, detail }))
            }
            Outcome::Success { value, .. } => {
                let end = offset.saturating_add(limit).min(value.admitted.len());
                let start = offset.min(end);
                Ok(Outcome::success(HistoryPage {
                    items: value.admitted[start..end].to_vec(),
                    next_offset: (end < value.admitted.len()).then_some(end),
                }))
            }
        }
    }
    /// One admitted operation by the path it is stored at (`ops/…`, or its live slot), for
    /// write receipts and publication reconciliation.
    pub fn operation_at(&self, namespace: &str, path: &str) -> Result<Outcome<OperationView>> {
        self.check_ready()?;
        let gone = |why: &str| {
            Ok(Outcome::failure(Denial {
                reason: "unavailable".into(),
                detail: why.into(),
            }))
        };
        let (author, id) = match paths::classify(path) {
            Some(Kind::Op {
                author,
                namespace: ns,
                id,
                ..
            }) if ns == namespace => (author, id),
            Some(Kind::Live {
                author,
                namespace: ns,
                slot,
            }) if ns == namespace => {
                let head = self
                    .account
                    .live_heads()
                    .iter()
                    .find(|h| h.author == author && h.namespace == ns && h.slot == slot);
                match head {
                    Some(h) => (h.author.clone(), h.id.clone()),
                    None => return gone("no verified live head at this path"),
                }
            }
            _ => return Err(malformed("not an operation path of this namespace")),
        };
        match self.account.view(namespace)? {
            Outcome::Failure { reason, detail, .. } => {
                Ok(Outcome::failure(Denial { reason, detail }))
            }
            Outcome::Success { value, .. } => {
                match value
                    .admitted
                    .into_iter()
                    .find(|o| o.author == author && o.id == id)
                {
                    Some(o) => Ok(Outcome::success(o)),
                    None => gone("the operation is not admitted here"),
                }
            }
        }
    }

    // -----------------------------------------------------------------------------------------
    // Writes.

    /// Begin a `/5` write through the account: the host signs the action's steps and calls
    /// [`Engine::finish_write`].
    pub fn begin_write(
        &self,
        namespace: &str,
        kind: &str,
        payload: Value,
        level: crate::v05::records::Level,
        seed: [u8; 32],
    ) -> Result<std::result::Result<crate::v05::account::PendingAction, Denial>> {
        self.check_ready()?;
        if let Some(d) = self.partial_budget_denial() {
            return Ok(Err(d));
        }
        self.account
            .begin_write(namespace, kind, payload, level, seed)
    }

    /// Finish a prepared action. The account verifies the exact bytes it returns before it
    /// changes; the engine then records them as held (they are not read again) and returns them
    /// with their paths for the host to store.
    pub fn finish_write(
        &mut self,
        action: crate::v05::account::PendingAction,
        signatures: Vec<SignatureResult>,
    ) -> Result<Written> {
        self.check_ready()?;
        let f = self.account.finish(action, signatures)?;
        let paths = f.record_paths();
        let mut bytes: Vec<Vec<u8>> = Vec::new();
        bytes.extend(f.entries.iter().map(|(_, b)| b.clone()));
        bytes.extend(f.pending.iter().cloned());
        bytes.extend(f.records.iter().map(|r| r.bytes.clone()));
        let stores: Vec<(String, Vec<u8>)> = if paths.len() == bytes.len() {
            paths.into_iter().zip(bytes).collect()
        } else {
            Vec::new()
        };
        for (p, b) in &stores {
            self.ix.have.insert(
                p.clone(),
                Have {
                    sha: sha(b),
                    version: None,
                },
            );
            self.ix.listing.insert(p.clone());
            self.ix.unread.remove(p);
        }
        self.refresh_stats();
        Ok(Written {
            stores,
            changes: f.changes,
        })
    }

    // -----------------------------------------------------------------------------------------
    // Imports (§9.3, §10.1).

    /// Begin an import batch under a grant whose terms carry `import`. The batch is an
    /// ordinary `colophon.importBatch` record: every admission rule applies (0.3 §7.2).
    pub fn begin_import(
        &self,
        namespace: &str,
        batch: &crate::imports::ImportBatch,
        seed: [u8; 32],
    ) -> Result<std::result::Result<crate::v05::account::PendingAction, Denial>> {
        self.check_ready()?;
        let crate::v05::account::Standing::Member(me) = self.account.me() else {
            return Err(Failure::Refused(Reason::NotGranted));
        };
        let may = self
            .account
            .record_authority()
            .member(&me.member.id)
            .is_some_and(|m| m.terms.import() && m.revoked_seq.is_none());
        if !may {
            return Err(Failure::Refused(Reason::NotGranted));
        }
        let payload = serde_json::to_value(batch).map_err(|e| malformed(e.to_string()))?;
        require(
            crate::v05::encoding::canonical(&payload)?.len() <= 1 << 20,
            "an import batch is at most 1 MiB",
        )?;
        self.account.begin_write(
            namespace,
            crate::imports::BATCH_KIND,
            payload,
            crate::v05::records::Level::Write,
            seed,
        )
    }

    // -----------------------------------------------------------------------------------------
    // Saving and the integrity audit.

    /// The sealed state to store atomically: the account's verifier state and the engine's
    /// checkpoint, both caches under the device-held key. `nonce_seed` is fresh host entropy.
    pub fn save(&mut self, nonce_seed: [u8; 32]) -> Result<Saved> {
        self.check_ready()?;
        // Never persist over a replacement that waits for an epoch key this member can open
        // (0.3 §5.1).
        if self
            .account
            .live_verdicts()
            .iter()
            .any(|(_, v)| *v == crate::v05::live::LiveVerdict::Quarantined("unavailable"))
            && !self.account.begin_unlock_epochs().is_empty()
        {
            return Err(Failure::Unavailable(
                "a live replacement waits for an epoch key this member can unlock: unlock first"
                    .into(),
            ));
        }
        let key = self.options.checkpoint_key;
        let verifier = self.account.export_persisted(&key, nonce_seed)?;
        let mut index: Vec<checkpoint::IndexEntry> = self
            .ix
            .have
            .iter()
            .map(|(p, h)| checkpoint::IndexEntry {
                path: p.clone(),
                version: h.version.clone(),
                sha256: hex(&h.sha),
            })
            .collect();
        index.sort_by(|a, b| a.path.cmp(&b.path));
        let body = checkpoint::Body {
            format: checkpoint::FORMAT,
            head: self.account.head(),
            index,
            memo: self.account.export_judge_memo(),
            revisions: self.revisions(),
            live_witness: self.live_witness.clone(),
            exchange: self.exchange.export(),
        };
        let plain = serde_json::to_vec(&body).map_err(|e| malformed(e.to_string()))?;
        let mut h = Sha256::new();
        h.update(nonce_seed);
        h.update(b"colophon/engine-checkpoint-nonce");
        let seed2: [u8; 32] = h.finalize().into();
        let scope = self.scope();
        let checkpoint = seal::seal(&plain, &self.options.account, &self.me, &scope, &key, seed2)?;
        Ok(Saved {
            verifier,
            checkpoint,
        })
    }

    /// Recheck up to `limit` held paths from where the last call stopped: the source still
    /// returns the exact bytes (digest) and, for a record, its signature still verifies under
    /// its author's key as the verified state has it. A change or a missing path is a sticky
    /// integrity error (0.3 §7.1): queries and writes fail until the host opens a fresh engine.
    pub fn verify_batch(&mut self, limit: usize) -> Result<VerificationProgress> {
        self.check_ready()?;
        let all: Vec<String> = self.ix.have.keys().cloned().collect();
        if self.verify_cursor >= all.len() {
            self.verify_cursor = 0;
        }
        let start = self.verify_cursor;
        let end = start.saturating_add(limit).min(all.len());
        for p in &all[start..end] {
            let want = self.ix.have[p].sha;
            let bytes = match self.source.read(p) {
                Ok(b) => b,
                Err(e) => {
                    return Err(self.poison(Failure::Unavailable(format!(
                        "integrity: {p} is no longer readable: {}",
                        e.0
                    ))))
                }
            };
            self.stats.records_read += 1;
            if sha(&bytes) != want {
                return Err(self.poison(Failure::Refused(Reason::Fork)));
            }
            if matches!(paths::classify(p), Some(Kind::Op { .. })) {
                self.audit_signature(p, &bytes)?;
            }
        }
        self.verify_cursor = end;
        Ok(VerificationProgress {
            checked: end - start,
            remaining: all.len() - end,
        })
    }

    fn audit_signature(&mut self, path: &str, bytes: &[u8]) -> Result<()> {
        let Ok((header, _)) = OperationHeader::parse(bytes) else {
            // Bytes that are no header where a record was covered: an integrity error, not a
            // pass.
            if self.rejudged.iter().any(|p| p == path) {
                return Err(self.poison(Failure::Refused(Reason::Fork)));
            }
            return Ok(());
        };
        let Some(member) = self.account.record_authority().member(&header.author) else {
            return Ok(());
        };
        let signing = member.request.signing.clone();
        let checked = crate::v05::signature::RawEnvelope::parse(
            bytes,
            crate::v05::encoding::bounds::OPERATION_HEADER_BODY,
            false,
        )
        .and_then(|e| OperationHeader::verify(&e, &signing));
        if checked.is_err() {
            return Err(self.poison(Failure::BadSignature(format!(
                "integrity: {path} no longer verifies"
            ))));
        }
        Ok(())
    }
}

fn sha_of(e: &checkpoint::IndexEntry) -> [u8; 32] {
    let mut out = [0u8; 32];
    if e.sha256.len() == 64 {
        for (i, c) in e.sha256.as_bytes().chunks(2).enumerate() {
            out[i] = std::str::from_utf8(c)
                .ok()
                .and_then(|s| u8::from_str_radix(s, 16).ok())
                .unwrap_or(0);
        }
    }
    out
}
