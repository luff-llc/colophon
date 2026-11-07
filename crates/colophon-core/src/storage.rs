//! Storage-backed engine. This child module shares the Library admission implementation.
use super::*;
use crate::verification::{BatchVerifier, Verifiers};
use sha2::{Digest, Sha256};
use std::{
    collections::{hash_map::DefaultHasher, BTreeSet, HashSet, VecDeque},
    hash::BuildHasherDefault,
    sync::Arc,
};

/// Host-owned immutable storage. Reads must return one coherent record or an error.
/// A listing is supplied separately at open/refresh; the core never enumerates storage itself.
pub trait RecordSource {
    /// Fetch the exact stored envelope, including its original body bytes.
    fn read(&self, path: &str) -> Result<Vec<u8>>;
    /// Provider content-version token (etag, inode/mtime version, etc.). A changed token
    /// invalidates cached verification even when bytes happen to be identical. None means
    /// the provider has no version contract; hosts must audit immutable records explicitly.
    fn content_version(&self, _path: &str) -> Result<Option<String>> {
        Ok(None)
    }
    /// Lazy blob fetch. Override to distinguish missing hydration from inaccessible storage.
    fn read_blob(&self, path: &str) -> Result<crate::blobs::BlobRead> {
        self.read(path).map(crate::blobs::BlobRead::Available)
    }
}
impl RecordSource for Records {
    fn read_blob(&self, path: &str) -> Result<crate::blobs::BlobRead> {
        Ok(self.get(path).cloned().map_or(
            crate::blobs::BlobRead::Missing,
            crate::blobs::BlobRead::Available,
        ))
    }
    fn read(&self, path: &str) -> Result<Vec<u8>> {
        self.get(path)
            .cloned()
            .ok_or_else(|| Error(format!("Missing record: {path}")))
    }
}
impl<T: RecordSource + ?Sized> RecordSource for Arc<T> {
    fn content_version(&self, path: &str) -> Result<Option<String>> {
        (**self).content_version(path)
    }
    fn read_blob(&self, path: &str) -> Result<crate::blobs::BlobRead> {
        (**self).read_blob(path)
    }
    fn read(&self, path: &str) -> Result<Vec<u8>> {
        (**self).read(path)
    }
}
/// Device-local configuration, never protocol metadata.
#[derive(Clone)]
pub struct EngineOptions {
    /// Expected genesis-body library ID, taken from enrollment or library creation.
    pub library_id: String,
    /// Host-generated random device-local secret; protect it separately from shared records.
    pub checkpoint_key: [u8; 32],
    /// Maximum encoded plaintext bytes in the history cache; zero disables caching.
    pub content_cache_bytes: usize,
    /// Namespaces this replica lists. Empty means every namespace.
    pub namespaces: Vec<String>,
}
/// Why this open used or invalidated a verified-prefix checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpenMode {
    /// No usable cache; all records will be verified during finish_unlock_many.
    FullVerification,
    /// Authenticated cache and unchanged authority listing; only the suffix is processed.
    VerifiedPrefix,
    /// A cache or prefix was invalidated. Full verification is required.
    Invalidated(String),
}
/// Observable engine work and retained content; excludes memory owned by the host source.
#[derive(Clone, Debug, Default)]
pub struct EngineStats {
    /// Record envelopes fetched since opening this engine.
    pub records_read: u64,
    /// Successfully verified operation headers since opening (including audited signatures).
    pub signatures_verified: u64,
    /// Operation payloads decrypted since opening.
    pub payloads_decrypted: u64,
    /// Number of retained record index entries.
    pub indexed_records: usize,
    /// Encoded operation bytes retained in the bounded history cache.
    pub cached_content_bytes: usize,
    /// Reducer applications since opening.
    pub applied_operations: u64,
}
/// Bounded history result in protocol order. Reset offsets when revision changes.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryPage {
    /// Authenticated admitted operations with original payloads.
    pub items: Vec<OperationView>,
    /// Offset for the next page, or none at the end.
    pub next_offset: Option<usize>,
}
/// Progress for a single pass over the current trusted index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationProgress {
    /// Records checked in this call (never more than the requested limit).
    pub checked: usize,
    /// Records left in this pass. Calling again after zero starts a new pass.
    pub remaining: usize,
}

const VERIFIED: u8 = 1;
const SPENT: u8 = 2;
const AUTHENTICATED: u8 = 4;
const PROJECTED: u8 = 8;
const NO_NAMESPACE: u16 = u16::MAX;
const MAGIC: &[u8; 8] = b"COLOENG3";
const CACHE_VERSION: u32 = 3;
const STORAGE_VERSION: u32 = 3;
const BATCH: usize = 8192;

#[derive(Clone)]
struct Entry {
    path: String,
    digest: [u8; 32],
    namespace: u16,
    flags: u8,
    /// SHA-256 of the author's uncompressed signing key; zero until the header verifies.
    author_key: [u8; 32],
    /// Namespace epoch from the verified header; zero until the header verifies.
    epoch: u64,
    version: Option<String>,
}
#[derive(Serialize, Deserialize)]
struct Projection {
    state: domain::State,
    clock: u64,
    revision: u64,
    digest: [u8; 32],
    count: u64,
}
#[derive(Serialize, Deserialize)]
struct CacheMeta {
    version: u32,
    storage_version: u32,
    layout: u32,
    namespaces: Vec<String>,
    reducer_schema: u32,
    identity: PublicIdentity,
    authority: Authority,
    projections: BTreeMap<String, Projection>,
    clocks: BTreeMap<String, u64>,
    namespace_tails: BTreeMap<String, (u64, String, String)>,
    author_tails: BTreeMap<String, (u64, String, String)>,
    spent: BTreeMap<String, BTreeSet<String>>,
    unlocked: BTreeSet<(String, u64)>,
    rejections: BTreeMap<String, (String, Rejection, bool)>,
}
// DefaultHasher::new uses fixed keys. RandomState would pull OS entropy into the pure core.
// Keys here are authenticated SHA-derived identities, not arbitrary untrusted strings;
// iteration order is never used for protocol decisions or checkpoint serialization.
type AuthenticatedIds = HashSet<[u8; 32], BuildHasherDefault<DefaultHasher>>;

/// Pure storage-backed replica with authenticated prefix trust and lazy history content.
/// Call finish_unlock_many (even with an empty vector) before queries/checkpoint/write.
/// All I/O happens through the explicitly supplied RecordSource. See docs/engine.md.
pub struct Engine<S: RecordSource> {
    source: S,
    library: Library,
    options: EngineOptions,
    verifier: Option<Arc<dyn BatchVerifier>>,
    entries: Vec<Entry>,
    integrity_baseline: Vec<Entry>,
    pending: Vec<String>,
    listing: Vec<String>,
    authenticated: AuthenticatedIds,
    counts: BTreeMap<String, u64>,
    rejections: BTreeMap<String, (String, Rejection, bool)>,
    cached_unlocked: BTreeSet<(String, u64)>,
    cache: VecDeque<(String, Vec<u8>)>,
    stats: EngineStats,
    mode: OpenMode,
    ready: bool,
    failure: Option<Error>,
    verify_cursor: usize,
    generation: u64,
    history_order: BTreeMap<String, Vec<usize>>,
}
impl<S: RecordSource> Engine<S> {
    /// Open a coherent host listing. Missing/invalid caches fall back to full verification.
    /// No historical operation bytes are fetched on the verified-prefix path.
    pub fn open(
        source: S,
        listing: Vec<String>,
        me: PublicIdentity,
        options: EngineOptions,
        checkpoint: Option<&[u8]>,
    ) -> Result<Self> {
        Self::open_with_verifier(source, listing, me, options, checkpoint, None)
    }
    /// Open with an optional trusted host cryptographic backend. Admission remains in the core.
    pub fn open_with_verifier(
        source: S,
        mut listing: Vec<String>,
        me: PublicIdentity,
        options: EngineOptions,
        checkpoint: Option<&[u8]>,
        verifier: Option<Arc<dyn BatchVerifier>>,
    ) -> Result<Self> {
        me.validate()?;
        listing.retain(|p| {
            crate::protocol::listing_includes(p, &options.namespaces)
                && !crate::protocol::is_history(p)
        });
        validate_listing(&mut listing)?;
        let restored =
            checkpoint.map(|bytes| decode_cache(bytes, &options, &me, &listing, &source));
        let mut integrity_baseline = Vec::new();
        let (mut library, entries, pending, counts, rejections, unlocked, mode, reads) =
            match restored {
                Some(Ok(DecodedCache {
                    meta,
                    entries,
                    pending: Ok(pending),
                })) => {
                    let counts = meta
                        .projections
                        .iter()
                        .map(|(ns, p)| (ns.clone(), p.count))
                        .collect();
                    let mut library = empty_library(meta.authority, me);
                    library.admission.clocks = meta.clocks;
                    library.admission.namespace_tails = meta.namespace_tails;
                    library.admission.author_tails = meta.author_tails;
                    library.admission.spent = meta.spent;
                    for (ns, p) in meta.projections {
                        let mut state = Namespace::new(&ns);
                        state.state = p.state;
                        state.clock = p.clock;
                        state.revision = p.revision;
                        state.hashes = vec![p.digest];
                        library.namespaces.insert(ns, state);
                    }
                    (
                        library,
                        entries,
                        pending,
                        counts,
                        meta.rejections,
                        meta.unlocked,
                        OpenMode::VerifiedPrefix,
                        0,
                    )
                }
                invalid => {
                    let mode = match invalid {
                        Some(Ok(DecodedCache {
                            entries,
                            pending: Err(e),
                            ..
                        })) => {
                            if e.0 == "Checkpoint record missing from listing" {
                                return Err(e);
                            }
                            integrity_baseline = entries;
                            OpenMode::Invalidated(e.0)
                        }
                        Some(Err(e)) => OpenMode::Invalidated(e.0),
                        _ => OpenMode::FullVerification,
                    };
                    let (library, reads) = read_authority(
                        &source,
                        &listing,
                        me,
                        &options.library_id,
                        &integrity_baseline,
                    )?;
                    (
                        library,
                        Vec::new(),
                        listing.clone(),
                        BTreeMap::new(),
                        BTreeMap::new(),
                        BTreeSet::new(),
                        mode,
                        reads,
                    )
                }
            };
        library.read_scope = options.namespaces.clone();
        let mut authenticated =
            AuthenticatedIds::with_capacity_and_hasher(entries.len(), Default::default());
        for entry in &entries {
            if entry.flags & AUTHENTICATED != 0 && !crate::protocol::is_replaceable(&entry.path) {
                authenticated.insert(path_identity(&entry.path)?);
            }
        }
        Ok(Self {
            source,
            library,
            options,
            verifier,
            entries,
            integrity_baseline,
            pending,
            listing,
            authenticated,
            counts,
            rejections,
            cached_unlocked: unlocked,
            cache: VecDeque::new(),
            stats: EngineStats {
                records_read: reads,
                ..EngineStats::default()
            },
            mode,
            ready: false,
            failure: None,
            verify_cursor: 0,
            generation: 0,
            history_order: BTreeMap::new(),
        })
    }
    /// Source owned by this engine. Hosts may use interior mutability for snapshot-safe storage.
    pub fn source(&self) -> &S {
        &self.source
    }
    /// Reason the current replica used or invalidated a checkpoint.
    pub fn open_mode(&self) -> &OpenMode {
        &self.mode
    }
    /// Diagnostic counters; includes no record bytes or history views retained outside the cache.
    pub fn stats(&self) -> EngineStats {
        EngineStats {
            indexed_records: self.entries.len(),
            ..self.stats.clone()
        }
    }
    /// Verified authority for host inspection and key-unlock tasks.
    pub fn authority(&self) -> &Authority {
        self.library.authority()
    }
    /// ECDH tasks; the host supplies the corresponding shared secrets to finish_unlock_many.
    pub fn begin_unlock(&self) -> Vec<AgreementStep> {
        self.library.begin_unlock()
    }
    /// Authenticate epoch keys atomically, then admit/apply pending records.
    /// Additional historical keys explicitly invalidate the projection and replay from storage.
    pub fn finish_unlock_many(&mut self, results: Vec<(String, u64, Vec<u8>)>) -> Result<()> {
        self.check_failure()?;
        let result = self.unlock_inner(results);
        if let Err(error) = &result {
            self.failure = Some(error.clone());
        }
        result
    }
    fn unlock_inner(&mut self, results: Vec<(String, u64, Vec<u8>)>) -> Result<()> {
        let old: BTreeMap<_, _> = self
            .library
            .namespaces
            .iter()
            .map(|(ns, n)| (ns.clone(), n.revision))
            .collect();
        let generation = self.generation;
        let keys = results
            .iter()
            .map(|(ns, epoch, shared)| {
                self.library
                    .unseal_key(ns, *epoch, shared)
                    .map(|keys| ((ns.clone(), *epoch), keys))
            })
            .collect::<Result<Vec<_>>>()?;
        for (location, (key, checkpoint_key)) in keys {
            self.library.keys.insert(location.clone(), key);
            self.library
                .checkpoint_keys
                .insert(location, checkpoint_key);
        }
        let unlocked: BTreeSet<_> = self.library.keys.keys().cloned().collect();
        if self.mode == OpenMode::VerifiedPrefix && unlocked != self.cached_unlocked {
            self.reset("Unlocked epochs changed")?;
        } else if self.ready && unlocked != self.cached_unlocked {
            self.reset("Additional epoch unlocked")?;
        }
        let result = self.process_pending();
        if let Err(error) = &result {
            self.failure = Some(error.clone());
        }
        result?;
        if self.generation != generation {
            for (ns, state) in &mut self.library.namespaces {
                state.revision = old.get(ns).copied().unwrap_or(0) + 1;
            }
        }
        self.cached_unlocked = self.library.keys.keys().cloned().collect();
        self.ready = true;
        Ok(())
    }
    /// Read reducer state without fetching or decrypting historical records.
    pub fn query(
        &self,
        namespace: &str,
        name: &str,
        args: Value,
        now: &str,
    ) -> Result<Outcome<Value>> {
        self.check_ready()?;
        self.library.query(namespace, name, args, now)
    }
    /// Local revision token; changes after a successful refresh or rebuild.
    pub fn revision(&self, namespace: &str) -> u64 {
        self.library.revision(namespace)
    }
    /// Prepare a write using cached clocks/grants/state. Finish signatures with PendingBatch::finish,
    /// persist its records atomically in the host, then call refresh with the new listing.
    pub fn begin_write(
        &self,
        namespace: &str,
        kind: &str,
        payload: Value,
        now: &str,
        seed: [u8; 32],
    ) -> Result<Outcome<PendingBatch>> {
        self.check_ready()?;
        self.library
            .begin_write(namespace, kind, payload, now, seed)
    }
    /// Refresh after the host persists immutable records. Authority/removal/order changes rebuild.
    /// An I/O/backend/integrity error poisons this instance; reopen after the host resolves it.
    pub fn refresh(&mut self, mut listing: Vec<String>) -> Result<ChangeSummary> {
        self.check_ready()?;
        listing.retain(|p| {
            crate::protocol::listing_includes(p, &self.options.namespaces)
                && !crate::protocol::is_history(p)
        });
        validate_listing(&mut listing)?;
        let result = self.refresh_inner(listing);
        if let Err(error) = &result {
            self.failure = Some(error.clone());
        }
        result
    }
    /// Apply an explicit host delta of persisted immutable paths without rescanning the listing.
    /// Use refresh for removals/full listings. Replayed paths are checked for byte equality.
    pub fn apply_paths(&mut self, mut paths: Vec<String>) -> Result<ChangeSummary> {
        paths.retain(|p| {
            crate::protocol::listing_includes(p, &self.options.namespaces)
                && !crate::protocol::is_history(p)
        });
        self.check_ready()?;
        validate_listing(&mut paths)?;
        let result = self.apply_paths_inner(paths);
        if let Err(error) = &result {
            self.failure = Some(error.clone());
        }
        result
    }
    fn apply_paths_inner(&mut self, paths: Vec<String>) -> Result<ChangeSummary> {
        let generation = self.generation;
        let mut authority_changed = false;
        for path in paths {
            if crate::protocol::is_replaceable(&path) {
                if let Err(at) = self.listing.binary_search(&path) {
                    self.listing.insert(at, path.clone());
                }
                self.pending.push(path);
                continue;
            }
            match self.entries.binary_search_by(|e| e.path.cmp(&path)) {
                Ok(at) => {
                    let raw = self.source.read(&path)?;
                    self.stats.records_read += 1;
                    ensure(
                        <[u8; 32]>::from(Sha256::digest(raw)) == self.entries[at].digest,
                        &format!(
                            "Integrity error: {} at {path}: immutable record bytes changed",
                            crate::protocol::EQUIVOCATION
                        ),
                    )?;
                }
                Err(_) => {
                    authority_changed |= path.starts_with("authority/");
                    let at = self
                        .listing
                        .binary_search(&path)
                        .expect_err("new listing path");
                    self.listing.insert(at, path.clone());
                    self.pending.push(path);
                }
            }
        }
        let old: BTreeMap<_, _> = self
            .library
            .namespaces
            .iter()
            .map(|(ns, n)| (ns.clone(), n.revision))
            .collect();
        if authority_changed {
            self.reset("Authority listing changed")?;
        }
        self.process_pending()?;
        self.cached_unlocked = self.library.keys.keys().cloned().collect();
        let mut changes = ChangeSummary::default();
        for (ns, state) in &mut self.library.namespaces {
            let previous = old.get(ns).copied().unwrap_or(0);
            if self.generation != generation || state.revision != previous {
                state.revision = previous + 1;
                changes.namespaces.insert(ns.clone(), state.revision);
            }
        }
        Ok(changes)
    }
    fn refresh_inner(&mut self, listing: Vec<String>) -> Result<ChangeSummary> {
        let generation = self.generation;
        let old_revisions: BTreeMap<_, _> = self
            .library
            .namespaces
            .iter()
            .map(|(ns, n)| (ns.clone(), n.revision))
            .collect();
        let difference = compare_listing(&self.entries, &listing).and_then(|pending| {
            for entry in &self.entries {
                if !crate::protocol::is_replaceable(&entry.path)
                    && self.source.content_version(&entry.path)? != entry.version
                {
                    return Err(Error("Provider content version changed".into()));
                }
            }
            Ok(pending)
        });
        if let Err(error) = &difference {
            if error.0 == "Checkpoint record missing from listing" {
                return Err(error.clone());
            }
        }
        self.listing = listing;
        match difference {
            Ok(pending) => self.pending = pending,
            Err(reason) => self.reset(&reason.0)?,
        }
        self.process_pending()?;
        self.cached_unlocked = self.library.keys.keys().cloned().collect();
        // Rebuilds get fresh local revisions even if reducer counts happen to match the old state.
        let rebuilt = generation != self.generation;
        let mut changes = ChangeSummary::default();
        for (ns, state) in &mut self.library.namespaces {
            let old = old_revisions.get(ns).copied().unwrap_or(0);
            if rebuilt || state.revision != old {
                state.revision = old + 1;
                changes.namespaces.insert(ns.clone(), state.revision);
            }
        }
        Ok(changes)
    }
    fn reset(&mut self, reason: &str) -> Result<()> {
        let (mut library, reads) = read_authority(
            &self.source,
            &self.listing,
            self.library.me.clone(),
            &self.options.library_id,
            if self.entries.is_empty() {
                &self.integrity_baseline
            } else {
                &self.entries
            },
        )?;
        self.stats.records_read += reads;
        // Existing epoch keys are valid only while the corresponding authenticated seal is identical.
        for (location, key) in &self.library.keys {
            let seal = |lib: &Library| {
                lib.authority
                    .epochs
                    .get(&location.0)
                    .and_then(|e| e.get(&location.1))
                    .map(|(_, e)| serde_json::to_vec(e))
            };
            if matches!((seal(&self.library),seal(&library)),(Some(Ok(a)),Some(Ok(b))) if a == b) {
                library.keys.insert(location.clone(), key.clone());
                if let Some(cache_key) = self.library.checkpoint_keys.get(location) {
                    library
                        .checkpoint_keys
                        .insert(location.clone(), cache_key.clone());
                }
            }
        }
        self.library = library;
        self.library.read_scope = self.options.namespaces.clone();
        self.generation += 1;
        self.mode = OpenMode::Invalidated(reason.into());
        self.library.admission = Admission::default();
        self.library.namespaces.clear();
        if !self.entries.is_empty() {
            self.integrity_baseline = std::mem::take(&mut self.entries);
        }
        self.authenticated.clear();
        self.counts.clear();
        self.rejections.clear();
        self.cache.clear();
        self.history_order.clear();
        self.stats.cached_content_bytes = 0;
        self.pending = self.listing.clone();
        self.verify_cursor = 0;
        Ok(())
    }
    fn process_pending(&mut self) -> Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        self.history_order.clear();
        // Keep a running audit moving forward when appends shift the sorted index.
        let audit_after = self
            .verify_cursor
            .checked_sub(1)
            .and_then(|i| self.entries.get(i))
            .map(|e| e.path.clone());
        // Paths carry (author, clock, ID). Malformed paths can only become rejected records.
        // Sorting before streaming makes the shared admission rule deterministic without full views.
        // Parse numeric clocks once rather than on every sorting comparison.
        let mut paths: Vec<_> = std::mem::take(&mut self.pending)
            .into_iter()
            .map(|path| {
                (
                    if crate::protocol::is_replaceable(&path) {
                        u64::MAX
                    } else {
                        path_order(&path).0
                    },
                    path,
                )
            })
            .collect();
        paths.sort_unstable_by(|(a, p), (b, q)| {
            a.cmp(b).then_with(|| path_order(p).cmp(&path_order(q)))
        });
        let mut new_entries = Vec::with_capacity(paths.len());
        let contexts: BTreeMap<_, _> = self
            .library
            .authority
            .members
            .iter()
            .map(|(id, member)| {
                (
                    id.clone(),
                    domain::AuthorContext::from_member(&member.member, &self.library.authority.id),
                )
            })
            .collect();
        let mut invalidates = false;
        for chunk in paths.chunks(BATCH) {
            let records = chunk
                .iter()
                .map(|(_, path)| {
                    self.source
                        .read(path)
                        .map(|raw| (path.as_str(), raw))
                        .map_err(|e| read_failure(&self.integrity_baseline, path, e))
                })
                .collect::<Result<Vec<_>>>()?;
            self.stats.records_read += records.len() as u64;
            let ops: Vec<_> = records
                .iter()
                .filter(|(p, _)| p.starts_with("ops/") || p.starts_with("state/"))
                .map(|(p, r)| (*p, r.as_slice()))
                .collect();
            let parsed = self.library.verifiers.operations(
                &self.library.authority,
                &ops,
                self.verifier.as_deref(),
            )?;
            let mut results = parsed.into_iter();
            let mut candidates = Vec::new();
            for (path, raw) in &records {
                let mut entry = Entry {
                    path: (*path).into(),
                    digest: Sha256::digest(raw).into(),
                    namespace: NO_NAMESPACE,
                    flags: 0,
                    author_key: [0; 32],
                    epoch: 0,
                    version: self.source.content_version(path)?,
                };
                check_expected(&self.integrity_baseline, path, &entry.digest)?;
                if path.starts_with("history/") {
                    continue;
                }
                if path.starts_with("authority/") {
                    ensure(
                        self.library.records.get(*path) == Some(raw),
                        "Integrity error: authority changed during read",
                    )?;
                }
                if path.starts_with("ops/") || path.starts_with("state/") {
                    match results.next().expect("one result per operation") {
                        Ok((header, digest)) => {
                            self.stats.signatures_verified += 1;
                            entry.flags |= VERIFIED;
                            entry.epoch = header.meta.epoch;
                            if let Some(member) =
                                self.library.authority.members.get(&header.meta.author)
                            {
                                entry.author_key = Sha256::digest(&member.public.signing).into();
                            }
                            entry.namespace = self
                                .library
                                .authority
                                .namespaces
                                .iter()
                                .position(|ns| ns == &header.meta.namespace)
                                .and_then(|i| u16::try_from(i).ok())
                                .unwrap_or(NO_NAMESPACE);
                            if !self.entries.is_empty()
                                && !path.starts_with("state/")
                                && self.needs_replay(&header.meta)
                            {
                                invalidates = true;
                            }
                            if path.starts_with("state/") {
                                if let Ok(at) =
                                    self.entries.binary_search_by(|e| e.path.as_str().cmp(path))
                                {
                                    if self.entries[at].digest == entry.digest
                                        && self
                                            .library
                                            .live
                                            .values()
                                            .any(|j| j.header.meta.id == header.meta.id)
                                    {
                                        continue;
                                    }
                                }
                            }
                            candidates.push((
                                entry,
                                Judged {
                                    header,
                                    digest,
                                    operation: None,
                                    opened: false,
                                    status: Status::Admitted,
                                    from_live_slot: path.starts_with("state/"),
                                },
                            ));
                            continue;
                        }
                        Err(error) => {
                            let header =
                                serde_json::from_slice::<SignedRecord>(raw)
                                    .ok()
                                    .and_then(|r| {
                                        serde_json::from_slice::<OperationHeader>(&r.body).ok()
                                    });
                            let (ns, id, author) = header
                                .map(|h| (h.meta.namespace, h.meta.id, h.meta.author))
                                .unwrap_or_else(|| (String::new(), (*path).into(), String::new()));
                            if self.library.authority.namespaces.contains(&ns) {
                                self.library
                                    .namespaces
                                    .entry(ns.clone())
                                    .or_insert_with(|| Namespace::new(&ns))
                                    .revision += 1;
                            }
                            self.rejections.insert(
                                (*path).into(),
                                (
                                    ns,
                                    Rejection {
                                        id,
                                        author,
                                        reason: format!("invalidRecord: {error}"),
                                    },
                                    false,
                                ),
                            );
                        }
                    }
                }
                new_entries.push(entry);
            }
            if invalidates {
                break;
            }
            // Payload authentication and ID validation are independent; order only matters to admission.
            crate::verification::parallel_for_each(&mut candidates, |(_, j)| {
                if self
                    .library
                    .keys
                    .contains_key(&(j.header.meta.namespace.clone(), j.header.meta.epoch))
                {
                    Library::open_operation(&self.library.authority, &self.library.keys, j);
                }
            });
            type Reduction<'a> = (OperationView, Option<&'a domain::AuthorContext>);
            let mut reductions: BTreeMap<String, Vec<Reduction>> = BTreeMap::new();
            candidates.sort_by(|(_, a), (_, b)| order(&a.header.meta).cmp(&order(&b.header.meta)));
            for (mut entry, mut j) in candidates {
                if j.opened {
                    self.stats.payloads_decrypted += 1;
                }
                let meta = &j.header.meta;
                let mut status = if !Library::budget_scope_complete(
                    &self.library.authority,
                    &self.options.namespaces,
                    &meta.author,
                ) {
                    Status::Refused("budgetScopeUnavailable".into())
                } else {
                    Library::judge(
                        &self.library.authority,
                        meta,
                        &j.digest,
                        &mut self.library.admission.spent,
                        self.library
                            .admission
                            .clocks
                            .get(&meta.namespace)
                            .copied()
                            .unwrap_or(0),
                        j.from_live_slot,
                    )
                };
                if j.from_live_slot
                    && status == Status::Admitted
                    && self
                        .library
                        .authority
                        .members
                        .get(&meta.author)
                        .is_some_and(|m| m.member.revoked_at.is_some())
                {
                    status = Status::Refused("revoked".into());
                }
                if status == Status::Admitted {
                    entry.flags |= SPENT;
                    self.library
                        .admission
                        .clocks
                        .insert(meta.namespace.clone(), meta.clock);
                }
                j.status = status;
                if j.status == Status::Admitted && j.operation.is_some() {
                    entry.flags |= AUTHENTICATED;
                    if !j.from_live_slot && !self.authenticated.insert(path_identity(&entry.path)?)
                    {
                        j.status = Status::Refused("duplicateID".into());
                    }
                }
                // Uncapped writers need no retained spend set. Identity deduplication has its own compact index.
                if self
                    .library
                    .authority
                    .members
                    .get(&meta.author)
                    .and_then(|m| m.member.grant.as_ref())
                    .and_then(|g| g.write_budget)
                    .is_none()
                {
                    self.library.admission.spent.remove(&meta.author);
                }
                let tail = (meta.clock, meta.author.clone(), meta.id.clone());
                update_tail(
                    &mut self.library.admission.namespace_tails,
                    &meta.namespace,
                    &tail,
                );
                update_tail(
                    &mut self.library.admission.author_tails,
                    &meta.author,
                    &tail,
                );
                if j.from_live_slot {
                    if j.status == Status::Admitted && j.operation.is_some() {
                        let stamp = j.header.live.as_ref().expect("verified live stamp");
                        let key = (
                            meta.author.clone(),
                            meta.namespace.clone(),
                            stamp.slot.clone(),
                        );
                        if self
                            .library
                            .live
                            .get(&key)
                            .is_none_or(|old| old.header.meta.clock <= meta.clock)
                        {
                            self.library
                                .namespaces
                                .entry(meta.namespace.clone())
                                .or_insert_with(|| Namespace::new(&meta.namespace))
                                .revision += 1;
                            self.library.live.insert(key, j);
                        }
                    }
                    new_entries.push(entry);
                    continue;
                }
                let state = self
                    .library
                    .namespaces
                    .entry(meta.namespace.clone())
                    .or_insert_with(|| Namespace::new(&meta.namespace));
                state.revision += 1;
                if j.status == Status::Admitted {
                    if let Some(op) = j.operation.take() {
                        state.clock = op.clock;
                        let kind = contexts.get(&op.author);
                        reductions
                            .entry(meta.namespace.clone())
                            .or_default()
                            .push((op, kind));
                        state.hashes[0] = engine::roll(state.hashes[0], &j.digest);
                        *self.counts.entry(meta.namespace.clone()).or_default() += 1;
                        entry.flags |= PROJECTED;
                        self.stats.applied_operations += 1;
                    } else {
                        let reason = if j.opened {
                            "invalidPayload"
                        } else {
                            "unavailable"
                        };
                        self.rejections.insert(
                            entry.path.clone(),
                            (
                                meta.namespace.clone(),
                                Rejection {
                                    id: meta.id.clone(),
                                    author: meta.author.clone(),
                                    reason: reason.into(),
                                },
                                !j.opened,
                            ),
                        );
                    }
                } else {
                    let (reason, held) = match &j.status {
                        Status::Held(s) => (s, true),
                        Status::Refused(s) => (s, false),
                        Status::Admitted => unreachable!(),
                    };
                    self.rejections.insert(
                        entry.path.clone(),
                        (
                            meta.namespace.clone(),
                            Rejection {
                                id: meta.id.clone(),
                                author: meta.author.clone(),
                                reason: reason.clone(),
                            },
                            held,
                        ),
                    );
                }
                new_entries.push(entry);
            }
            // Admission (including global budgets/duplicates) is complete and ordered. Reducers
            // own disjoint namespace states; retain each namespace's operation order within the
            // bounded batch. Only the verified member kind accompanies each operation; no source,
            // keys, authority state or admission decisions enter these tasks.
            let mut jobs: Vec<_> = self
                .library
                .namespaces
                .iter_mut()
                .filter_map(|(ns, state)| reductions.remove(ns).map(|ops| (&mut state.state, ops)))
                .collect();
            let apply = |(state, ops): &mut (&mut domain::State, Vec<Reduction>)| {
                for (op, kind) in ops {
                    state.apply_with_context(op, *kind);
                }
            };
            if chunk.len() >= 512 {
                crate::verification::parallel_tasks(&mut jobs, 1, apply);
            } else {
                jobs.iter_mut().for_each(apply);
            }
        }
        if invalidates {
            self.reset("Earlier arrival or duplicate changes admission order")?;
            return self.process_pending();
        }
        for ns in &self.library.authority.namespaces {
            self.library
                .namespaces
                .entry(ns.clone())
                .or_insert_with(|| Namespace::new(ns));
        }
        if new_entries.len() <= 32 {
            for entry in new_entries {
                match self.entries.binary_search_by(|e| e.path.cmp(&entry.path)) {
                    Ok(at) => self.entries[at] = entry,
                    Err(at) => self.entries.insert(at, entry),
                }
            }
        } else {
            self.entries.extend(new_entries);
            self.entries.sort_unstable_by(|a, b| a.path.cmp(&b.path));
            self.entries.dedup_by(|a, b| {
                if a.path == b.path {
                    *b = a.clone();
                    true
                } else {
                    false
                }
            });
        }
        self.verify_cursor = audit_after.as_ref().map_or(0, |path| {
            self.entries.partition_point(|entry| entry.path <= *path)
        });
        self.integrity_baseline = Vec::new();
        // Authority bytes were retained only to check the initial read against this batch.
        // Parsed authority and exact digest indexes suffice between host reads.
        self.library.records.clear();
        Ok(())
    }
    fn needs_replay(&self, meta: &OperationMeta) -> bool {
        let before = |tail: &(u64, String, String)| {
            order(meta) <= (tail.0, tail.1.as_str(), tail.2.as_str())
        };
        self.library
            .admission
            .namespace_tails
            .get(&meta.namespace)
            .is_some_and(before)
            || (self
                .library
                .authority
                .members
                .get(&meta.author)
                .and_then(|m| m.member.grant.as_ref())
                .and_then(|g| g.write_budget)
                .is_some()
                && self
                    .library
                    .admission
                    .author_tails
                    .get(&meta.author)
                    .is_some_and(before))
    }
    /// Persist an authenticated index and reducer state. Contains no epoch keys or operation payloads
    /// except values retained by reducers. Protect this local cache; never sync it as protocol authority.
    pub fn checkpoint(&self) -> Result<Vec<u8>> {
        self.check_ready()?;
        let projections = self
            .library
            .namespaces
            .iter()
            .map(|(ns, n)| {
                (
                    ns.clone(),
                    Projection {
                        state: n.state.clone(),
                        clock: n.clock,
                        revision: n.revision,
                        digest: n.hashes[0],
                        count: self.counts.get(ns).copied().unwrap_or(0),
                    },
                )
            })
            .collect();
        let meta = CacheMeta {
            version: CACHE_VERSION,
            storage_version: STORAGE_VERSION,
            layout: self.library.authority.layout,
            namespaces: self.options.namespaces.clone(),
            reducer_schema: domain::REDUCER_SCHEMA,
            identity: self.library.me.clone(),
            authority: self.library.authority.clone(),
            projections,
            clocks: self.library.admission.clocks.clone(),
            namespace_tails: self.library.admission.namespace_tails.clone(),
            author_tails: self.library.admission.author_tails.clone(),
            spent: self.library.admission.spent.clone(),
            unlocked: self.cached_unlocked.clone(),
            rejections: self.rejections.clone(),
        };
        let json = serde_json::to_vec(&meta)?;
        let mut output = Vec::new();
        output.extend_from_slice(MAGIC);
        put_length(&mut output, json.len())?;
        output.extend(json);
        put_length(&mut output, self.entries.len())?;
        for entry in &self.entries {
            put_length(&mut output, entry.path.len())?;
            output.extend_from_slice(entry.path.as_bytes());
            output.extend(entry.digest);
            output.extend(entry.namespace.to_le_bytes());
            output.push(entry.flags);
            output.extend(entry.author_key);
            output.extend(entry.epoch.to_le_bytes());
            if let Some(version) = &entry.version {
                put_length(&mut output, version.len() + 1)?;
                output.extend_from_slice(version.as_bytes());
            } else {
                put_length(&mut output, 0)?;
            }
        }
        output.extend(cache_tag(&self.options.checkpoint_key, &output)?);
        Ok(output)
    }
    /// Load one bounded page of original operation payloads. Access is checked on every call.
    /// Every cache miss checks the fetched envelope digest before decrypting; mismatches poison the engine.
    pub fn history(
        &mut self,
        namespace: &str,
        offset: usize,
        limit: usize,
        now: &str,
    ) -> Result<Outcome<HistoryPage>> {
        self.check_ready()?;
        ensure((1..=200).contains(&limit), "History limit must be 1..200")?;
        if let Some(denial) = self.library.authorize(namespace, Access::Read, now)? {
            return Ok(Outcome::failure(denial));
        }
        let epoch = self
            .library
            .authority
            .epoch_at(namespace, self.library.authority.latest)
            .ok_or_else(|| missing("epoch"))?;
        if !self.library.keys.contains_key(&(namespace.into(), epoch)) {
            return Ok(Outcome::failure(Denial::new(
                "notReadable",
                "The namespace key has not been unlocked",
            )));
        }
        let index = self
            .library
            .authority
            .namespaces
            .iter()
            .position(|ns| ns == namespace)
            .ok_or_else(|| missing("namespace"))? as u16;
        let selected = self
            .history_order
            .entry(namespace.into())
            .or_insert_with(|| {
                let mut selected: Vec<_> = self
                    .entries
                    .iter()
                    .enumerate()
                    .filter(|(_, e)| {
                        e.namespace == index
                            && e.flags & PROJECTED != 0
                            && !crate::protocol::is_replaceable(&e.path)
                    })
                    .map(|(i, e)| (path_order(&e.path).0, i))
                    .collect();
                selected.sort_unstable_by(|(a, i), (b, j)| {
                    a.cmp(b).then_with(|| {
                        path_order(&self.entries[*i].path).cmp(&path_order(&self.entries[*j].path))
                    })
                });
                selected.into_iter().map(|(_, i)| i).collect()
            });
        let end = offset.saturating_add(limit).min(selected.len());
        let next_offset = (end < selected.len()).then_some(end);
        let paths: Vec<_> = selected
            .iter()
            .skip(offset)
            .take(limit)
            .map(|i| {
                let e = &self.entries[*i];
                (e.path.clone(), e.digest)
            })
            .collect();
        let mut items = Vec::with_capacity(paths.len());
        for (path, digest) in paths {
            match self.load_operation(&path, digest) {
                Ok(op) => items.push(op),
                Err(e) => {
                    let error = Error(format!("Integrity error at {path}: {e}"));
                    self.failure = Some(error.clone());
                    return Err(error);
                }
            }
        }
        Ok(Outcome::success(HistoryPage { items, next_offset }))
    }
    fn load_operation(&mut self, path: &str, digest: [u8; 32]) -> Result<OperationView> {
        if let Some(index) = self.cache.iter().position(|(p, _)| p == path) {
            let entry = self.cache.remove(index).expect("cache index exists");
            let result = serde_json::from_slice(&entry.1)?;
            self.cache.push_back(entry);
            return Ok(result);
        }
        let raw = self.source.read(path)?;
        self.stats.records_read += 1;
        ensure(
            <[u8; 32]>::from(Sha256::digest(&raw)) == digest,
            "Record digest mismatch",
        )?;
        let record: SignedRecord = serde_json::from_slice(&raw)?;
        let header: OperationHeader = serde_json::from_slice(&record.body)?;
        let mut j = Judged {
            header,
            digest: records::digest(&record.body),
            operation: None,
            opened: false,
            status: Status::Admitted,
            from_live_slot: false,
        };
        Library::open_operation(&self.library.authority, &self.library.keys, &mut j);
        self.stats.payloads_decrypted += 1;
        let operation = j
            .operation
            .ok_or_else(|| Error("Trusted operation payload failed validation".into()))?;
        let encoded = serde_json::to_vec(&operation)?;
        if encoded.len() <= self.options.content_cache_bytes {
            while self.stats.cached_content_bytes + encoded.len() > self.options.content_cache_bytes
            {
                if let Some((_, bytes)) = self.cache.pop_front() {
                    self.stats.cached_content_bytes -= bytes.len();
                }
            }
            self.stats.cached_content_bytes += encoded.len();
            self.cache.push_back((path.into(), encoded));
        }
        Ok(operation)
    }
    /// Assemble the legacy full view on demand. The returned allocation belongs to the caller.
    /// Rendering apps should use query/history instead of retaining a full history view.
    pub fn view(&mut self, namespace: &str, now: &str) -> Result<Outcome<NamespaceView>> {
        self.check_ready()?;
        let state = match self.library.query(namespace, "read", json!({}), now)? {
            Outcome::Success { value, .. } => value,
            Outcome::Failure { reason, detail, .. } => {
                return Ok(Outcome::Failure {
                    ok: false,
                    reason,
                    detail,
                })
            }
        };
        let mut view = NamespaceView {
            namespace: namespace.into(),
            admitted: Vec::new(),
            held: Vec::new(),
            refused: Vec::new(),
            state,
        };
        let mut offset = 0;
        loop {
            let Outcome::Success { value: page, .. } = self.history(namespace, offset, 200, now)?
            else {
                unreachable!()
            };
            view.admitted.extend(page.items);
            if let Some(next) = page.next_offset {
                offset = next;
            } else {
                break;
            }
        }
        for j in self
            .library
            .live
            .values()
            .filter(|j| j.header.meta.namespace == namespace)
        {
            if let Some(op) = &j.operation {
                if !view
                    .admitted
                    .iter()
                    .any(|old| old.id == op.id && old.author == op.author)
                {
                    view.admitted.push(op.clone());
                }
            }
        }
        view.admitted
            .sort_by(|a, b| (a.clock, &a.author, &a.id).cmp(&(b.clock, &b.author, &b.id)));
        let mut rejections: Vec<_> = self
            .rejections
            .iter()
            .filter(|(_, (ns, _, _))| ns == namespace)
            .collect();
        // Match Library: verified-header rejections in operation order, followed by
        // invalid envelopes in storage-path order. Untrusted header clocks never order them.
        rejections.sort_unstable_by(|a, b| {
            let invalid_a = a.1 .1.reason.starts_with("invalidRecord: ");
            let invalid_b = b.1 .1.reason.starts_with("invalidRecord: ");
            invalid_a.cmp(&invalid_b).then_with(|| {
                if invalid_a {
                    a.0.cmp(b.0)
                } else {
                    path_order(a.0).cmp(&path_order(b.0))
                }
            })
        });
        for (_, (_, rejection, held)) in rejections {
            if *held {
                view.held.push(rejection.clone());
            } else {
                view.refused.push(rejection.clone());
            }
        }
        Ok(Outcome::success(view))
    }
    /// Materialize a caller-owned compatibility Library for ledger or administrative actions.
    /// This explicitly fetches and verifies all records and allocates full history; the Engine
    /// does not retain that allocation. Persist resulting actions through the host and apply_paths.
    pub fn materialize_library(&mut self) -> Result<Library> {
        self.check_ready()?;
        let result = (|| -> Result<Library> {
            let mut records = Records::new();
            for entry in &self.entries {
                let raw = self
                    .source
                    .read(&entry.path)
                    .map_err(|e| Error(format!("Integrity error at {}: {e}", entry.path)))?;
                self.stats.records_read += 1;
                if !crate::protocol::is_replaceable(&entry.path) {
                    ensure(
                        <[u8; 32]>::from(Sha256::digest(&raw)) == entry.digest,
                        &format!(
                            "Integrity error at {}: {}: record digest mismatch",
                            entry.path,
                            crate::protocol::EQUIVOCATION
                        ),
                    )?;
                }
                records.insert(entry.path.clone(), raw);
            }
            let mut library = Library::open(records, self.library.me.clone())?;
            for entry in &self.entries {
                ensure(
                    entry.flags & VERIFIED == 0 || !library.invalid.contains_key(&entry.path),
                    &format!(
                        "Integrity error at {}: trusted verification failed",
                        entry.path
                    ),
                )?;
            }
            library.keys = self.library.keys.clone();
            library.checkpoint_keys = self.library.checkpoint_keys.clone();
            library.ingest(&[], true, &[]);
            Ok(library)
        })();
        if let Err(error) = &result {
            self.failure = Some(error.clone());
        }
        result
    }

    /// Recheck up to limit indexed records, including signatures on verified operation records.
    /// Any changed/missing bytes or failed signature is a sticky integrity error. Queries/writes then fail.
    /// Rejected records and requests are checked for byte equality, not promoted to verified authority.
    pub fn verify_batch(&mut self, limit: usize) -> Result<VerificationProgress> {
        self.check_ready()?;
        if self.verify_cursor == self.entries.len() {
            self.verify_cursor = 0;
        }
        let end = self
            .verify_cursor
            .saturating_add(limit)
            .min(self.entries.len());
        let start = self.verify_cursor;
        for i in start..end {
            let entry = &self.entries[i];
            let result = (|| -> Result<()> {
                let raw = self.source.read(&entry.path)?;
                self.stats.records_read += 1;
                if !crate::protocol::is_replaceable(&entry.path) {
                    ensure(
                        <[u8; 32]>::from(Sha256::digest(&raw)) == entry.digest,
                        &format!("{}: record digest mismatch", crate::protocol::EQUIVOCATION),
                    )?;
                }
                if entry.flags & VERIFIED != 0 {
                    let record: SignedRecord = serde_json::from_slice(&raw)?;
                    let header: OperationHeader = serde_json::from_slice(&record.body)?;
                    let member = self
                        .library
                        .authority
                        .members
                        .get(&header.meta.author)
                        .ok_or_else(|| missing("author"))?;
                    // Deliberately use the independent standard RustCrypto path for background audits.
                    record.verify(&member.public.signing)?;
                    self.stats.signatures_verified += 1;
                } else if entry.path.starts_with("authority/") {
                    let record: SignedRecord = serde_json::from_slice(&raw)?;
                    let body: AuthorityEntry = serde_json::from_slice(&record.body)?;
                    let key = if body.by == "recovery" {
                        &self.library.authority.recovery.signing
                    } else {
                        let root = self
                            .library
                            .authority
                            .root_at(body.seq.saturating_sub(1).max(1))
                            .ok_or_else(|| missing("root"))?;
                        &self.library.authority.members[root].public.signing
                    };
                    record.verify(key)?;
                }
                Ok(())
            })();
            if let Err(e) = result {
                let error = Error(format!("Integrity error at {}: {e}", entry.path));
                self.failure = Some(error.clone());
                self.cache.clear();
                self.stats.cached_content_bytes = 0;
                return Err(error);
            }
            self.verify_cursor = i + 1;
        }
        Ok(VerificationProgress {
            checked: end - start,
            remaining: self.entries.len() - end,
        })
    }
    fn check_failure(&self) -> Result<()> {
        self.failure.clone().map_or(Ok(()), Err)
    }
    fn check_ready(&self) -> Result<()> {
        self.check_failure()?;
        ensure(self.ready, "Engine requires finish_unlock_many before use")
    }
}

fn empty_library(authority: Authority, me: PublicIdentity) -> Library {
    let verifiers = Arc::new(Verifiers::new(&authority));
    Library {
        records: Records::new(),
        read_scope: Vec::new(),
        authority,
        me,
        keys: BTreeMap::new(),
        checkpoint_keys: BTreeMap::new(),
        judged: Vec::new(),
        invalid: BTreeMap::new(),
        admission: Admission::default(),
        namespaces: BTreeMap::new(),
        checkpoint_policy: CheckpointPolicy {
            every: 0,
            retain: 0,
        },
        changes: ChangeSummary::default(),
        pending_checkpoints: BTreeMap::new(),
        verifiers,
        live: BTreeMap::new(),
    }
}
fn read_authority(
    source: &impl RecordSource,
    listing: &[String],
    me: PublicIdentity,
    expected: &str,
    baseline: &[Entry],
) -> Result<(Library, u64)> {
    let records: Records = listing
        .iter()
        .filter(|p| p.starts_with("authority/"))
        .map(|p| {
            source
                .read(p)
                .map(|raw| (p.clone(), raw))
                .map_err(|e| read_failure(baseline, p, e))
        })
        .collect::<Result<_>>()?;
    let reads = records.len() as u64;
    for (path, raw) in &records {
        check_expected(baseline, path, &Sha256::digest(raw).into())?;
    }
    let library = Library::open(records, me)?;
    ensure(
        library.authority.namespaces.len() < usize::from(NO_NAMESPACE),
        "Engine namespace index capacity exceeded",
    )?;
    ensure(library.id() == expected, "Different library")?;
    Ok((library, reads))
}
fn read_failure(entries: &[Entry], path: &str, error: Error) -> Error {
    if entries
        .binary_search_by(|e| e.path.as_str().cmp(path))
        .is_ok()
    {
        Error(format!("Integrity error at {path}: {error}"))
    } else {
        error
    }
}
fn check_expected(entries: &[Entry], path: &str, digest: &[u8; 32]) -> Result<()> {
    if crate::protocol::is_replaceable(path) {
        return Ok(());
    }
    if let Ok(index) = entries.binary_search_by(|e| e.path.as_str().cmp(path)) {
        ensure(
            entries[index].digest == *digest,
            &format!(
                "Integrity error: {} at {path}: immutable record bytes changed",
                crate::protocol::EQUIVOCATION
            ),
        )?;
    }
    Ok(())
}
fn validate_listing(listing: &mut [String]) -> Result<()> {
    listing.sort_unstable();
    ensure(
        listing.windows(2).all(|p| p[0] != p[1]),
        "Duplicate listing path",
    )?;
    ensure(
        listing.iter().all(|p| {
            p.starts_with("authority/")
                || p.starts_with("ops/")
                || p.starts_with("requests/")
                || p.starts_with("state/")
                || p.starts_with("history/")
        }),
        "Unknown storage path",
    )
}
fn compare_listing(entries: &[Entry], listing: &[String]) -> Result<Vec<String>> {
    // Both inputs are sorted. A merge walk keeps unchanged opens linear in index size,
    // while checking every missing immutable path before allowing authority invalidation.
    let mut pending = Vec::new();
    let mut previous = entries.iter().peekable();
    let mut authority_changed = false;
    for path in listing {
        while previous.peek().is_some_and(|entry| entry.path < *path) {
            let entry = previous.next().expect("peeked entry");
            ensure(
                crate::protocol::is_replaceable(&entry.path),
                "Checkpoint record missing from listing",
            )?;
        }
        if previous.peek().is_some_and(|entry| entry.path == *path) {
            previous.next();
            if crate::protocol::is_replaceable(path) {
                pending.push(path.clone());
            }
        } else {
            authority_changed |= path.starts_with("authority/");
            pending.push(path.clone());
        }
    }
    for entry in previous {
        ensure(
            crate::protocol::is_replaceable(&entry.path),
            "Checkpoint record missing from listing",
        )?;
    }
    ensure(!authority_changed, "Authority listing changed")?;
    Ok(pending)
}

fn update_tail(
    map: &mut BTreeMap<String, (u64, String, String)>,
    name: &str,
    tail: &(u64, String, String),
) {
    map.entry(name.into())
        .and_modify(|old| {
            if *old < *tail {
                *old = tail.clone();
            }
        })
        .or_insert_with(|| tail.clone());
}
fn path_order(path: &str) -> (u64, &str, &str) {
    let Some((author, file)) = crate::protocol::operation_file(path) else {
        return (0, "", path);
    };
    let Some((clock, id)) = file.split_once('-') else {
        return (0, author, file);
    };
    (clock.parse().unwrap_or(0), author, id)
}
fn path_identity(path: &str) -> Result<[u8; 32]> {
    let (_, author, id) = path_order(path);
    let id = id
        .strip_suffix(".json")
        .ok_or_else(|| Error("Invalid indexed operation path".into()))?;
    path_identity_parts(author, id)
}
fn path_identity_parts(author: &str, id: &str) -> Result<[u8; 32]> {
    let mut result = [0; 32];
    ensure(
        author.len() == 32 && id.len() == 32,
        "Invalid indexed operation identity",
    )?;
    for (i, part) in [author, id].iter().enumerate() {
        for j in 0..16 {
            result[i * 16 + j] = u8::from_str_radix(&part[j * 2..j * 2 + 2], 16)
                .map_err(|_| Error("Invalid indexed operation identity".into()))?;
        }
    }
    Ok(result)
}
fn cache_tag(key: &[u8], body: &[u8]) -> Result<[u8; 32]> {
    let mut tag = [0; 32];
    hkdf::Hkdf::<Sha256>::new(Some(key), body)
        .expand(b"colophon/verified-prefix/3", &mut tag)
        .map_err(|_| Error("Cache authentication failed".into()))?;
    Ok(tag)
}
fn put_length(output: &mut Vec<u8>, length: usize) -> Result<()> {
    output.extend(
        u32::try_from(length)
            .map_err(|_| Error("Checkpoint field too large".into()))?
            .to_le_bytes(),
    );
    Ok(())
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        ensure(n <= self.0.len(), "Truncated checkpoint")?;
        let (part, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(part)
    }
    fn length(&mut self) -> Result<usize> {
        let mut bytes = [0; 4];
        bytes.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(bytes) as usize)
    }
}
struct DecodedCache {
    meta: CacheMeta,
    entries: Vec<Entry>,
    pending: Result<Vec<String>>,
}
fn decode_cache<S: RecordSource>(
    bytes: &[u8],
    options: &EngineOptions,
    identity: &PublicIdentity,
    listing: &[String],
    source: &S,
) -> Result<DecodedCache> {
    ensure(bytes.len() >= 40, "Truncated checkpoint")?;
    let (body, tag) = bytes.split_at(bytes.len() - 32);
    let expected = cache_tag(&options.checkpoint_key, body)?;
    ensure(
        expected.iter().zip(tag).fold(0u8, |d, (a, b)| d | (a ^ b)) == 0,
        "Checkpoint authentication failed",
    )?;
    let mut reader = Reader(body);
    ensure(reader.take(8)? == MAGIC, "Checkpoint version mismatch")?;
    let length = reader.length()?;
    let meta: CacheMeta = serde_json::from_slice(reader.take(length)?)?;
    ensure(
        meta.version == CACHE_VERSION
            && meta.storage_version == STORAGE_VERSION
            && meta.layout == meta.authority.layout
            && meta.layout <= crate::protocol::LAYOUT
            && meta.namespaces == options.namespaces
            && meta.reducer_schema == domain::REDUCER_SCHEMA
            && meta.identity == *identity
            && meta.authority.id == options.library_id,
        "Checkpoint version/library/identity mismatch",
    )?;
    ensure(
        meta.authority.namespaces.len() < usize::from(NO_NAMESPACE),
        "Engine namespace index capacity exceeded",
    )?;
    let length = reader.length()?;
    ensure(
        length <= reader.0.len() / 79,
        "Invalid checkpoint index length",
    )?;
    let mut entries = Vec::with_capacity(length);
    for _ in 0..length {
        let len = reader.length()?;
        let path = std::str::from_utf8(reader.take(len)?)
            .map_err(|_| Error("Invalid checkpoint path".into()))?
            .to_owned();
        let mut digest = [0; 32];
        digest.copy_from_slice(reader.take(32)?);
        let mut ns = [0; 2];
        ns.copy_from_slice(reader.take(2)?);
        let flags = reader.take(1)?[0];
        let mut author_key = [0; 32];
        author_key.copy_from_slice(reader.take(32)?);
        let mut epoch = [0; 8];
        epoch.copy_from_slice(reader.take(8)?);
        entries.push(Entry {
            path,
            digest,
            namespace: u16::from_le_bytes(ns),
            flags,
            author_key,
            epoch: u64::from_le_bytes(epoch),
            version: {
                let length = reader.length()?;
                if length == 0 {
                    None
                } else {
                    Some(
                        std::str::from_utf8(reader.take(length - 1)?)
                            .map_err(|_| Error("Invalid provider version".into()))?
                            .to_owned(),
                    )
                }
            },
        });
    }
    ensure(reader.0.is_empty(), "Trailing checkpoint bytes")?;
    ensure(
        entries.windows(2).all(|p| p[0].path < p[1].path),
        "Unsorted checkpoint index",
    )?;
    let pending = compare_listing(&entries, listing).and_then(|pending| {
        for entry in &entries {
            if !crate::protocol::is_replaceable(&entry.path)
                && source.content_version(&entry.path)? != entry.version
            {
                return Err(Error("Provider content version changed".into()));
            }
        }
        Ok(pending)
    });
    Ok(DecodedCache {
        meta,
        entries,
        pending,
    })
}

impl<S: RecordSource> Engine<S> {
    /// Read and authenticate at most one 64 KiB blob chunk through host storage.
    /// Blob paths are not operation-listing entries and are fetched only on demand.
    pub fn read_blob_chunk(
        &self,
        namespace: &str,
        digest: &str,
        index: usize,
        now: &str,
    ) -> Result<Outcome<Vec<u8>>> {
        self.check_ready()?;
        match self.library.blob_manifest(namespace, digest, now)? {
            Outcome::Success {
                value: manifest, ..
            } => {
                let chunk = manifest
                    .chunks
                    .get(index)
                    .ok_or_else(|| Error("Invalid blob chunk index".into()))?;
                let bytes = self.source.read(&chunk.path)?;
                self.library
                    .open_blob_chunk(namespace, digest, index, &bytes, now)
            }
            Outcome::Failure { reason, detail, .. } => {
                Ok(Outcome::failure(Denial::new(&reason, &detail)))
            }
        }
    }
    /// Start a grant-checked streaming blob upload. The host owns the returned immutable bytes.
    pub fn begin_blob(
        &self,
        namespace: &str,
        media_type: String,
        now: &str,
        seed: [u8; 32],
    ) -> Result<Outcome<crate::blobs::BlobWriter>> {
        self.check_ready()?;
        self.library.begin_blob(namespace, media_type, now, seed)
    }
}

impl<S: RecordSource> Engine<S> {
    /// Bounded blob retrieval with explicit availability; authenticates bytes before success.
    pub fn blob_chunk(
        &self,
        namespace: &str,
        digest: &str,
        index: usize,
        now: &str,
    ) -> Result<crate::blobs::BlobRead> {
        use crate::blobs::BlobRead;
        self.check_ready()?;
        let manifest = match self.library.blob_manifest(namespace, digest, now)? {
            Outcome::Success { value, .. } => value,
            Outcome::Failure { reason, detail, .. } => {
                return Ok(if reason == "unavailable" {
                    BlobRead::Missing
                } else {
                    BlobRead::Inaccessible(detail)
                })
            }
        };
        let chunk = manifest
            .chunks
            .get(index)
            .ok_or_else(|| Error("Invalid blob chunk index".into()))?;
        match self.source.read_blob(&chunk.path)? {
            BlobRead::Available(bytes) => match self
                .library
                .open_blob_chunk(namespace, digest, index, &bytes, now)
            {
                Ok(Outcome::Success { value, .. }) => Ok(BlobRead::Available(value)),
                Ok(Outcome::Failure { detail, .. }) => Ok(BlobRead::Inaccessible(detail)),
                Err(error) => Ok(BlobRead::Invalid(error.to_string())),
            },
            other => Ok(other),
        }
    }
}
