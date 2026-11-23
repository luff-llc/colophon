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
use zeroize::Zeroize;

pub mod batch;
pub mod blobs;
pub mod checkpoint;
pub mod exchange;
pub mod live;
pub mod paths;
pub mod seal;
pub mod stream;

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
/// A copy of the device key held on the stack for the length of one call, wiped when it goes
/// out of scope (on every return, errors included).
struct KeyCopy([u8; 32]);
impl Drop for KeyCopy {
    fn drop(&mut self) {
        crate::v05::hpke_wiped::wipe(&mut self.0);
    }
}

impl EngineOptions {
    /// Erase the device key held here.
    fn wipe_key(&mut self) {
        self.checkpoint_key.zeroize();
    }
}
impl Drop for EngineOptions {
    fn drop(&mut self) {
        self.wipe_key();
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

/// A fault of the record source the host must show: a source gave other bytes at an immutable
/// path whose bytes a checkpoint had verified. A source never changes those bytes
/// (0.3 §7.1: changing bytes at a previously verified immutable path is equivocation).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceFault {
    /// The immutable path.
    pub path: String,
    /// What happened, in a sentence the host can show.
    pub what: String,
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
    /// The envelope of a link or a call (§12), which is not stored: for the host to use.
    pub artifact: Option<Vec<u8>>,
}

/// The sealed state a host stores between sessions: the account's verifier state, the engine's
/// checkpoint and one sealed part per namespace (its record memo and its fold). All are caches
/// sealed under the device-held key; a part that fails its seal makes that namespace open cold
/// and the open says so.
#[derive(Clone, Debug)]
pub struct Saved {
    /// The account's persisted verifier state (§17.2).
    pub verifier: Vec<u8>,
    /// The engine's checkpoint.
    pub checkpoint: Vec<u8>,
    /// One sealed part per namespace.
    pub parts: BTreeMap<String, Vec<u8>>,
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
    /// True during [`Engine::load`], the first read of what the device already holds: a stopped
    /// account takes those records (what the saved state covered, or everything on a cold open with
    /// no saved state); later arrivals are ignored (§1 "A stop").
    loading: bool,
    restored_revisions: Option<BTreeMap<String, u64>>,
    /// Per live path `(generation, body digest)`: the highest seen.
    pub(crate) live_witness: BTreeMap<String, (u64, String)>,
    /// Live candidates refused for being below their witness: `(path, generation)`.
    pub(crate) stale_live: Vec<(String, u64)>,
    pub(crate) stats: EngineStats,
    /// Covered paths the open judged again because their bytes changed.
    rejudged: Vec<String>,
    /// Faults of the source the host must show (see [`SourceFault`]).
    source_faults: Vec<SourceFault>,
    /// Paths whose bytes a home should be asked for again: a source changed their bytes. A
    /// pass pulls such a path from any home that lists it, even when the home's digest is the
    /// one we last held.
    pub(crate) repull: BTreeSet<String>,
    ready: bool,
    locked: bool,
    /// Source versions the host gave for this refresh in one batch.
    version_hint: BTreeMap<String, Option<String>>,
    failure: Option<Failure>,
    verify_cursor: usize,
    pub(crate) exchange: exchange::State,
    /// Live heads the next immutable write retains (0.3 §5.1), found by `begin_write`.
    retain: std::sync::Mutex<Vec<(String, Vec<u8>)>>,
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
        require((1..=65_536).contains(&options.batch), "batch is 1 to 65536")?;
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
        let key = KeyCopy(options.checkpoint_key);
        let mut scope = options.namespaces.clone();
        scope.sort();
        scope.dedup();
        let mut mode = OpenMode::Cold;
        let mut body = None;
        if let Some(s) = saved {
            match seal::open(&s.checkpoint, &options.account, &me, &scope, &key.0)
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
            saved.map(|s| (s.verifier.as_slice(), &key.0)),
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
        let mut bad_parts: Vec<String> = Vec::new();
        if let Some(b) = body {
            // A changed provider token drops that path's memo (0.3 §7.1): the work is done
            // again even for identical bytes.
            let tokens: BTreeMap<&str, &Option<String>> = b
                .index
                .iter()
                .map(|i| (i.path.as_str(), &i.version))
                .collect();
            let mut folds = Vec::new();
            if let Some(sv) = saved {
                for (ns, bytes) in &sv.parts {
                    let mut ps = scope.clone();
                    ps.push(format!("ns:{ns}"));
                    let part = seal::open(bytes, &options.account, &me, &ps, &key.0)
                        .and_then(|p| serde_json::from_slice::<checkpoint::NsPart>(&p).ok())
                        .filter(|p| p.namespace == *ns);
                    let Some(part) = part else {
                        bad_parts.push(ns.clone());
                        continue;
                    };
                    let mut memo = part.memo;
                    memo.retain(|m| match tokens.get(m.path.as_str()) {
                        None => false,
                        Some(was) => {
                            ix.listing.contains(&m.path)
                                && **was == source.content_version(&m.path).unwrap_or(None)
                        }
                    });
                    account.import_judge_memo(memo);
                    folds.extend(part.fold);
                }
            }
            account.import_folds(folds);
            restored = b.index.into_iter().map(|i| (i.path.clone(), i)).collect();
            restored_revisions = Some(b.revisions);
            live_witness = b.live_witness;
            saved_exchange = b.exchange;
        }
        if !bad_parts.is_empty() {
            mode = OpenMode::Invalidated(format!(
                "namespace part(s) failed their seal and open cold: {}",
                bad_parts.join(", ")
            ));
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
            loading: false,
            live_witness,
            stale_live: Vec::new(),
            stats,
            rejudged: Vec::new(),
            source_faults: Vec::new(),
            repull: BTreeSet::new(),
            ready: false,
            locked: false,
            version_hint: BTreeMap::new(),
            failure: None,
            verify_cursor: 0,
            exchange: exchange::State::default(),
            retain: std::sync::Mutex::new(Vec::new()),
        };
        let verified = e.account.head().0;
        e.exchange.import(saved_exchange, verified);
        e.refresh_stats();
        Ok(e)
    }

    /// Open an engine over the stores a creation returned, keeping the created account's
    /// unlocked state (its seed and epoch keys), so the session that created the account is
    /// unlocked at once and a passkey owner is asked once at first run. The host has stored
    /// [`Account`]'s objects and records first and lists them: the engine opens over that listing
    /// as [`Engine::open`] does (cold), checks that what it read is exactly what the creation
    /// made (the same identity, account, verified head and object set; else `malformed` and
    /// nothing is kept), then takes the created account in place of the one it opened and loads
    /// the records. A creation is not a sealed state, so there is nothing to resume.
    pub fn open_created(
        source: S,
        listing: Vec<String>,
        created: Account,
        options: EngineOptions,
        now_ms: i64,
    ) -> Result<Self> {
        let me = created.identity().clone();
        let mut e = Self::open(source, listing, me, options, None, now_ms)?;
        let same_set = |a: &Objects, b: &Objects| {
            let sorted = |v: &[Vec<u8>]| {
                let mut v = v.to_vec();
                v.sort();
                v.dedup();
                v
            };
            sorted(&a.entries) == sorted(&b.entries)
                && sorted(&a.pending) == sorted(&b.pending)
                && sorted(&a.predecessor) == sorted(&b.predecessor)
        };
        require(
            created.id() == e.account.id()
                && created.head() == e.account.head()
                && same_set(created.objects(), e.account.objects()),
            "the source does not hold exactly what the creation made",
        )?;
        let mut created = created;
        created.advance(now_ms)?;
        if !e.options.namespaces.is_empty() {
            created.set_read_scope(e.options.namespaces.clone())?;
        }
        e.account = created;
        e.load()?;
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
        require(!self.locked, "the engine is locked: open a new one")?;
        let paths: Vec<String> = self.ix.unread.iter().cloned().collect();
        let c = {
            self.loading = true;
            let c = self.ingest(paths);
            self.loading = false;
            c?
        };
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
            // Show it, and fetch the verified bytes again from a home: a source must never
            // change them.
            self.source_faults = changed
                .iter()
                .map(|p| SourceFault {
                    path: p.clone(),
                    what: "a source changed the bytes of a path it had given and a checkpoint had verified"
                        .into(),
                })
                .collect();
            self.repull.extend(changed.iter().cloned());
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
            let now = || self.version_of(p);
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

    /// The paths whose provider versions a [`Engine::refresh_batched`] wants: every path held or
    /// listed that a refresh compares. The host asks its provider for all of them in one call.
    pub fn version_paths(&self, listing: &[String]) -> Vec<String> {
        self.ix
            .have
            .keys()
            .chain(self.ix.live_have.keys())
            .chain(listing.iter())
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// [`Engine::refresh`] with the provider versions of the paths the host asked for in one
    /// batch ([`Engine::version_paths`]), not one source call per record. A path missing from
    /// `versions` is asked of the source as before.
    pub fn refresh_batched(
        &mut self,
        listing: Vec<String>,
        versions: BTreeMap<String, Option<String>>,
    ) -> Result<Changes> {
        self.version_hint = versions;
        let r = self.refresh(listing);
        self.version_hint = BTreeMap::new();
        r
    }

    fn version_of(&self, path: &str) -> Option<String> {
        match self.version_hint.get(path) {
            Some(v) => v.clone(),
            None => self.source.content_version(path).unwrap_or(None),
        }
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
                    let version = self.version_of(&p);
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
                    let version = self.version_of(p);
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
                let c = self.merge_read(incoming, now)?;
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

    /// Merge what was read from the source. A stopped account ignores records that arrive after the
    /// stop (§1 "A stop"); during [`Engine::load`] it takes what the device already held: the
    /// records its saved state covered (exact bytes), or, with no saved state, what is on disk.
    fn merge_read(&mut self, mut incoming: Incoming, now: i64) -> Result<Changes> {
        if self.loading && self.account.stop_seq().is_some() {
            if !self.restored.is_empty() {
                let restored = &self.restored;
                incoming.records.retain(|r| {
                    restored
                        .get(&r.path)
                        .is_some_and(|e| sha_of(e) == sha(&r.bytes))
                });
            }
            return self.account.merge_held(incoming, now);
        }
        self.account.merge(incoming, now)
    }
    /// [`Engine::merge_read`] for live candidates.
    pub(crate) fn merge_live_read(
        &mut self,
        mut cands: Vec<HeldRecord>,
        now: i64,
    ) -> Result<Changes> {
        if self.loading && self.account.stop_seq().is_some() {
            if !self.restored.is_empty() {
                let restored = &self.restored;
                cands.retain(|r| {
                    restored
                        .get(&r.path)
                        .is_some_and(|e| sha_of(e) == sha(&r.bytes))
                });
            }
            return self.account.merge_live_held(cands, now);
        }
        self.account.merge_live(cands, now)
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
        require(!self.locked, "the engine is locked: open a new one")?;
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
        require(!self.locked, "the engine is locked: open a new one")?;
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
    /// Where this reader stopped, if it is stopped for the account (§1 "A stop"; see
    /// [`crate::v05::account::Account::stopped`]).
    pub fn stopped(&self) -> Option<crate::v05::account::Stopped> {
        self.account.stopped()
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
    /// Faults of the record source the host must show: a source changed bytes it must never
    /// change. Each path is also fetched again from a home that lists it.
    pub fn source_faults(&self) -> &[SourceFault] {
        &self.source_faults
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
        self.begin_write_claimed(namespace, kind, payload, level, None, seed)
    }

    /// [`Engine::begin_write`] with an optional claimed date for the operation's `created`
    /// ([`crate::v05::account::Account::begin_write_claimed`]): an import keeps each item's
    /// original date. Later than the engine's clock is refused; everything else is unchanged.
    pub fn begin_write_claimed(
        &self,
        namespace: &str,
        kind: &str,
        payload: Value,
        level: crate::v05::records::Level,
        claimed_ms: Option<i64>,
        seed: [u8; 32],
    ) -> Result<std::result::Result<crate::v05::account::PendingAction, Denial>> {
        self.check_ready()?;
        self.account.refuse_if_stopped()?;
        if let Some(d) = self.partial_budget_denial() {
            return Ok(Err(d));
        }
        // An immutable action on an episode that has a live head retains the exact signed head
        // under `ops/` before it relies on it (0.3 §5.1; also the 1,024-bound anchor).
        let retain = self.heads_to_retain(namespace, &payload)?;
        let r = self
            .account
            .begin_write_claimed(namespace, kind, payload, level, claimed_ms, seed)?;
        if r.is_ok() {
            *self
                .retain
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = retain;
        }
        Ok(r)
    }

    /// The live heads of the target episode that are not retained yet: `(ops path, exact bytes)`,
    /// each fetched from the store and matched to the verified bytes first.
    fn heads_to_retain(&self, namespace: &str, payload: &Value) -> Result<Vec<(String, Vec<u8>)>> {
        let Some(id) = payload.get("id").and_then(Value::as_str) else {
            return Ok(Vec::new());
        };
        if namespace != "listening.podcasts" {
            return Ok(Vec::new());
        }
        let slot = crate::protocol::live_slot_name(id);
        let mut out = Vec::new();
        for h in self.account.live_heads() {
            if h.namespace != namespace || h.slot != slot {
                continue;
            }
            let ops =
                crate::v05::records::operation_path(&h.author, &h.namespace, h.generation, &h.id);
            if self.ix.have.contains_key(&ops) || self.account.holds_path(&ops) {
                continue;
            }
            let fetched = self
                .source
                .read(&h.path)
                .map_err(|e| Failure::Unavailable(format!("{}: {}", h.path, e.0)))?;
            require(
                sha(&fetched) == sha(&h.bytes),
                "the live head's stored bytes are not the verified ones: fail the write",
            )?;
            out.push((ops, fetched));
        }
        Ok(out)
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
        let retained = std::mem::take(
            &mut *self
                .retain
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        let f = self.account.finish(action, signatures)?;
        let mut retained_stores: Vec<(String, Vec<u8>)> = Vec::new();
        if !retained.is_empty() {
            let now = self.account.now_ms();
            self.account.merge(
                Incoming {
                    objects: Objects::default(),
                    records: retained
                        .iter()
                        .map(|(p, b)| HeldRecord {
                            path: p.clone(),
                            bytes: b.clone(),
                        })
                        .collect(),
                },
                now,
            )?;
            for (p, b) in retained {
                self.ix.have.insert(
                    p.clone(),
                    Have {
                        sha: sha(&b),
                        version: None,
                    },
                );
                retained_stores.push((p, b));
            }
        }
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
        let stores: Vec<(String, Vec<u8>)> = retained_stores.into_iter().chain(stores).collect();
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
            artifact: f.artifact,
        })
    }

    /// The stores of a finished action, held as read (they are not read again), and the
    /// result in the shape a write returns.
    fn written_of(&mut self, f: crate::v05::account::Finished) -> Written {
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
        Written {
            stores,
            changes: f.changes,
            artifact: f.artifact,
        }
    }

    // -----------------------------------------------------------------------------------------
    // Forwards to the account the engine owns: a session needs no second object over the same
    // stores. Each applies its result to the engine's own state (what it stores is held as read,
    // the counters move), so nothing is fed back through `apply_paths`.

    /// Record every transition that is due (§8.7, §17.5), in the account's order: all or none.
    /// Each recording is returned as a write: its bytes and paths for the host to store.
    pub fn record_due(&mut self) -> Result<Vec<Written>> {
        self.check_ready()?;
        let done = self.account.record_due()?;
        Ok(done.into_iter().map(|f| self.written_of(f)).collect())
    }

    /// Restrict the namespaces this engine reads (as [`Account::set_read_scope`]); the records
    /// of a namespace newly in scope are read from the source now. An empty list reads every
    /// namespace.
    pub fn set_read_scope(&mut self, namespaces: Vec<String>) -> Result<Changes> {
        self.check_usable()?;
        let all = self.account.record_authority().namespaces().to_vec();
        let wanted = if namespaces.is_empty() {
            all
        } else {
            namespaces.clone()
        };
        let mut c = self.account.set_read_scope(wanted)?;
        self.options.namespaces = namespaces;
        // The account dropped what is out of scope: those paths are unread again.
        let options = &self.options;
        self.ix.have.retain(|p, _| {
            !matches!(paths::classify(p), Some(Kind::Op { namespace, .. }) if !in_scope(options, &namespace))
        });
        self.ix.live_have.retain(|p, _| {
            !matches!(paths::classify(p), Some(Kind::Live { namespace, .. }) if !in_scope(options, &namespace))
        });
        let listing: Vec<String> = self.ix.listing.iter().cloned().collect();
        classify_listing(
            &self.options,
            &mut self.ix,
            &mut self.stats.ignored_paths,
            listing,
        )?;
        if self.ready {
            let todo: Vec<String> = self.ix.unread.iter().cloned().collect();
            let more = self.ingest(todo)?;
            absorb(&mut c, more);
        }
        self.refresh_stats();
        Ok(c)
    }

    /// See [`Account::transfer_seed`].
    pub fn transfer_seed(
        &self,
        pairing: &crate::v05::pairing::ConfirmedPairing,
        entropy_seed: [u8; 32],
    ) -> Result<crate::v05::vault::SealedBox> {
        self.check_usable()?;
        self.account.transfer_seed(pairing, entropy_seed)
    }

    /// See [`Account::accept_seed_transfer`]. The seed is held by the engine's account only.
    pub fn accept_seed_transfer(
        &mut self,
        key: &crate::v05::pairing::TransferKey,
        sealed: &crate::v05::vault::SealedBox,
        pairing: &crate::v05::pairing::ConfirmedPairing,
    ) -> Result<Changes> {
        self.check_usable()?;
        require(!self.locked, "the engine is locked: open a new one")?;
        let mut c = self.account.accept_seed_transfer(key, sealed, pairing)?;
        if self.ready {
            let more = self.load()?;
            absorb(&mut c, more);
        }
        self.refresh_stats();
        Ok(c)
    }

    /// Take a predecessor entry the host holds (F, or any) into the account (§15.1), and hold
    /// it as read.
    pub fn accept_predecessor_entry(&mut self, entry: Vec<u8>, now_ms: i64) -> Result<Changes> {
        self.check_usable()?;
        let c = self
            .account
            .accept_predecessor_entry(entry.clone(), now_ms)?;
        self.hold_predecessor(&entry);
        self.refresh_stats();
        Ok(c)
    }
    fn hold_predecessor(&mut self, entry: &[u8]) {
        let seq = serde_json::from_slice::<Value>(entry).ok().and_then(|v| {
            let b = crate::v05::encoding::decode_base64(
                v.get("body")?.as_str()?,
                crate::v05::encoding::bounds::AUTHORITY_BODY,
            )
            .ok()?;
            serde_json::from_slice::<Value>(&b)
                .ok()?
                .get("seq")?
                .as_u64()
        });
        if let Some(seq) = seq {
            let path = format!("predecessor/authority/{seq:08}.json");
            self.ix.have.insert(
                path.clone(),
                Have {
                    sha: sha(entry),
                    version: None,
                },
            );
            self.ix.listing.insert(path);
        }
    }

    /// §16.1: prepare the in-place upgrade of a 0.4 account (no engine state is involved).
    pub fn begin_upgrade(
        history: &crate::model::Records,
        params: &crate::v05::write::upgrade::UpgradeParams,
        now_ms: i64,
    ) -> Result<crate::v05::write::upgrade::PendingUpgrade> {
        Account::begin_upgrade(history, params, now_ms)
    }
    /// See [`Account::swift_succession`].
    pub fn swift_succession(&self) -> Result<crate::v05::account::SwiftSuccession> {
        self.check_usable()?;
        self.account.swift_succession()
    }
    /// See [`Account::begin_swift_veto`].
    pub fn begin_swift_veto(
        &self,
        params: &crate::v05::write::swift_veto::SwiftVetoParams,
    ) -> Result<crate::v05::write::swift_veto::PendingSwiftVeto> {
        self.check_usable()?;
        self.account.begin_swift_veto(params)
    }
    /// See [`Account::begin_swift_freeze`].
    pub fn begin_swift_freeze(
        &self,
        earlier_attempts: Vec<Objects>,
        signers: Vec<String>,
        issued_ms: i64,
    ) -> Result<crate::v05::account::PendingMove> {
        self.check_usable()?;
        self.account
            .begin_swift_freeze(earlier_attempts, signers, issued_ms)
    }
    /// See [`Account::begin_swift_copy_write`].
    pub fn begin_swift_copy_write(
        &self,
        plan: &crate::v05::swift_copy::CopyPlan,
        item: &crate::v05::swift_copy::CopyItem,
        seed: [u8; 32],
    ) -> Result<crate::v05::account::CopyWrite> {
        self.check_ready()?;
        self.account.begin_swift_copy_write(plan, item, seed)
    }
    /// Finish an import write of a copy plan (see [`Account::finish_swift_copy_write`]); what it
    /// wrote is returned for the host to store and held as read.
    pub fn finish_swift_copy_write(
        &mut self,
        plan: &mut crate::v05::swift_copy::CopyPlan,
        write: crate::v05::account::CopyWrite,
        signatures: Vec<SignatureResult>,
    ) -> Result<Written> {
        self.check_ready()?;
        let f = self
            .account
            .finish_swift_copy_write(plan, write, signatures)?;
        Ok(self.written_of(f))
    }
    /// See [`Account::swift_copy_destination`].
    pub fn swift_copy_destination(
        &self,
        library: &str,
    ) -> Result<crate::v05::swift_copy::Destination> {
        self.check_ready()?;
        self.account.swift_copy_destination(library)
    }
    /// See [`Account::finish_swift_copy`].
    pub fn finish_swift_copy(
        &self,
        plan: crate::v05::swift_copy::CopyPlan,
    ) -> Result<crate::v05::swift_copy::CopyResult> {
        self.check_ready()?;
        self.account.finish_swift_copy(plan)
    }
    /// See [`Account::begin_swift_copier_shares`].
    pub fn begin_swift_copier_shares(
        &self,
        member: &str,
        signers: &[String],
        seed: [u8; 32],
    ) -> Result<crate::v05::account::PendingMove> {
        self.check_ready()?;
        self.account
            .begin_swift_copier_shares(member, signers, seed)
    }
    /// See [`Account::begin_swift_migration`].
    #[allow(clippy::too_many_arguments)]
    pub fn begin_swift_migration(
        &self,
        copy: &crate::v05::swift_copy::CopyResult,
        members: Vec<crate::v05::write::succession::MigratedMember>,
        drain_from_ms: i64,
        drain_until_ms: i64,
        issued_ms: i64,
        signers: Vec<String>,
    ) -> Result<crate::v05::account::PendingMove> {
        self.check_ready()?;
        self.account.begin_swift_migration(
            copy,
            members,
            drain_from_ms,
            drain_until_ms,
            issued_ms,
            signers,
        )
    }
    /// Finish a step of the move (see [`Account::finish_move`]). F is held as read.
    pub fn finish_move(
        &mut self,
        pending: crate::v05::account::PendingMove,
        signatures: Vec<SignatureResult>,
    ) -> Result<crate::v05::account::Moved> {
        self.check_usable()?;
        let m = self.account.finish_move(pending, signatures)?;
        if let crate::v05::account::Moved::Frozen(f) = &m {
            let entry = f.entry.clone();
            self.hold_predecessor(&entry);
        }
        self.refresh_stats();
        Ok(m)
    }

    /// The current live heads (0.3 §5.1): verified, current, folded.
    pub fn live_heads(&self) -> &[crate::v05::live::LiveHead] {
        self.account.live_heads()
    }

    /// The verdict on the record the host stored at `path`: `admitted`, `held:<why>` or
    /// `refused:<reason>` (§11.5), or `None` when the engine holds no record there.
    pub fn record_verdict(&self, path: &str) -> Option<String> {
        self.account.record_verdict(path)
    }

    /// Forget the vault seed, every epoch key and the device key (all erased as they are
    /// dropped), overwrite with zeros the opened plaintext the account keeps (its judgement,
    /// its operation views and the memo of opened payloads), and rebuild what needs no key.
    ///
    /// **What cannot be guaranteed:** copies the allocator or the stack may still hold (a buffer
    /// that grew leaves its old block; a value moved by the compiler leaves its old place), the
    /// folded domain state of each namespace (a typed value, freed but not overwritten), and
    /// secrets the host keeps. After `lock` the engine refuses to unlock, load or save again. The engine stays open for the verified history,
    /// its members and pending objects; every namespace is unreadable, and it can no longer
    /// [`Engine::save`], until the host opens a new engine with its device key.
    pub fn lock(&mut self) -> Result<Changes> {
        self.check_usable()?;
        let c = self.account.forget_keys()?;
        self.options.wipe_key();
        self.locked = true;
        self.retain
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        self.refresh_stats();
        Ok(c)
    }
    /// Whether [`Engine::lock`] was called.
    pub fn is_locked(&self) -> bool {
        self.locked
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
        self.account.refuse_if_stopped()?;
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
        require(
            !self.locked,
            "the engine is locked: its device key was forgotten",
        )?;
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
        let key = KeyCopy(self.options.checkpoint_key);
        let verifier = self.account.export_persisted(&key.0, nonce_seed)?;
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
        let checkpoint = seal::seal(
            &plain,
            &self.options.account,
            &self.me,
            &scope,
            &key.0,
            seed2,
        )?;
        // One sealed part per namespace: the memo of its records and its fold.
        let mut memos: BTreeMap<String, Vec<crate::v05::records::RecordMemo>> = BTreeMap::new();
        for m in self.account.export_judge_memo() {
            if let Some(Kind::Op { namespace, .. }) = paths::classify(&m.path) {
                memos.entry(namespace).or_default().push(m);
            }
        }
        let mut folds: BTreeMap<String, crate::v05::account::FoldSnapshot> = self
            .account
            .export_folds()
            .into_iter()
            .map(|f| (f.namespace.clone(), f))
            .collect();
        let names: BTreeSet<String> = memos.keys().chain(folds.keys()).cloned().collect();
        let mut parts = BTreeMap::new();
        for ns in names {
            let part = checkpoint::NsPart {
                namespace: ns.clone(),
                memo: memos.remove(&ns).unwrap_or_default(),
                fold: folds.remove(&ns),
            };
            let plain = serde_json::to_vec(&part).map_err(|e| malformed(e.to_string()))?;
            let mut hh = Sha256::new();
            hh.update(seed2);
            hh.update(ns.as_bytes());
            let mut ps = scope.clone();
            ps.push(format!("ns:{ns}"));
            parts.insert(
                ns,
                seal::seal(
                    &plain,
                    &self.options.account,
                    &self.me,
                    &ps,
                    &key.0,
                    hh.finalize().into(),
                )?,
            );
        }
        Ok(Saved {
            verifier,
            checkpoint,
            parts,
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
