//! Storage engine transport. Keys stay in the host. Record callbacks are synchronous,
//! read-only, and must not reenter this engine; a thread-local guard rejects reentry.
use super::*;
use colophon_core::{
    checkpoint,
    engine::{Engine, EngineOptions, RecordSource},
};
use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
};
use zeroize::Zeroizing;

#[uniffi::export(callback_interface)]
pub trait EngineRecordSource: Send + Sync {
    fn read(&self, path: String) -> Result<Vec<u8>>;
}
struct Source {
    host: RefCell<Box<dyn EngineRecordSource>>,
    records: RefCell<model::Records>,
    versions: RefCell<HashMap<String, String>>,
}
impl RecordSource for Source {
    fn read(&self, path: &str) -> colophon_core::Result<Vec<u8>> {
        if let Some(bytes) = self.records.borrow().get(path) {
            return Ok(bytes.clone());
        }
        self.host
            .borrow()
            .read(path.into())
            .map_err(|e| colophon_core::Error(e.to_string()))
    }
    fn content_version(&self, path: &str) -> colophon_core::Result<Option<String>> {
        Ok(self.versions.borrow().get(path).cloned())
    }
}
struct EngineSession {
    engine: Engine<Source>,
    revision: u64,
    listing: Vec<String>,
    key: Arc<checkpoint::CheckpointKey>,
}
#[derive(uniffi::Object)]
pub struct NativeEngine {
    session: Mutex<EngineSession>,
    id: u64,
}
thread_local! {
    static ACTIVE_ENGINES: RefCell<std::collections::HashSet<u64>> = RefCell::default();
}

struct EngineEntry(u64);
impl Drop for EngineEntry {
    fn drop(&mut self) {
        ACTIVE_ENGINES.with(|active| active.borrow_mut().remove(&self.0));
    }
}

// Drop the mutex guard before clearing the thread-local entry, including during unwinding.
struct SessionGuard<'a, T> {
    guard: MutexGuard<'a, T>,
    _entry: EngineEntry,
}
impl<T> std::ops::Deref for SessionGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.guard
    }
}
impl<T> std::ops::DerefMut for SessionGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.guard
    }
}
fn lock_session<T>(session: &Mutex<T>, id: u64) -> Result<SessionGuard<'_, T>> {
    let (reentry, nested) = ACTIVE_ENGINES.with(|active| {
        let mut active = active.borrow_mut();
        let nested = !active.is_empty();
        (!active.insert(id), nested)
    });
    if reentry {
        return Err(invalid(
            "Record source callback must not reenter this engine",
        ));
    }
    let entry = EngineEntry(id);
    let guard = if nested {
        session.try_lock().map_err(|error| match error {
            std::sync::TryLockError::Poisoned(_) => BindingError::Poisoned,
            std::sync::TryLockError::WouldBlock => {
                invalid("Record source callback cannot wait for another engine")
            }
        })?
    } else {
        session.lock().map_err(|_| BindingError::Poisoned)?
    };
    Ok(SessionGuard {
        guard,
        _entry: entry,
    })
}

impl NativeEngine {
    fn lock(&self) -> Result<SessionGuard<'_, EngineSession>> {
        lock_session(&self.session, self.id)
    }
    fn prepared(&self, s: &EngineSession, result: Outcome<PendingBatch>) -> Result<PreparedAction> {
        match result {
            Outcome::Success { value, .. } => Ok(PreparedAction::Ready {
                action: Arc::new(HostAction {
                    pending: value,
                    session: Some((self.id, s.revision)),
                }),
            }),
            Outcome::Failure { reason, detail, .. } => Ok(PreparedAction::Failure {
                denial: denial(reason, detail)?,
            }),
        }
    }
    fn merge_locked(s: &mut EngineSession, records: Records) -> Result<ChangeSummary> {
        let mut paths = Vec::new();
        for (path, bytes) in records {
            if let Some(old) = s.engine.source().records.borrow().get(&path) {
                if old == &bytes {
                    continue;
                }
                if !path.starts_with("state/") {
                    return Err(invalid("Immutable record conflict"));
                }
            }
            s.engine
                .source()
                .records
                .borrow_mut()
                .insert(path.clone(), bytes);
            paths.push(path);
        }
        if paths.is_empty() {
            return Ok(ChangeSummary {
                revision: s.revision,
                namespaces: vec![],
                records_added: 0,
            });
        }
        let added = paths
            .iter()
            .filter(|p| s.listing.binary_search(p).is_err())
            .count() as u64;
        let changes = s.engine.apply_paths(paths.clone())?;
        for path in paths {
            if let Err(at) = s.listing.binary_search(&path) {
                s.listing.insert(at, path);
            }
        }
        if added != 0 || !changes.namespaces.is_empty() {
            s.revision += 1;
        }
        Ok(ChangeSummary {
            revision: s.revision,
            namespaces: changes.namespaces.into_keys().collect(),
            records_added: added,
        })
    }
}
#[derive(uniffi::Record)]
pub struct EngineWork {
    pub records_read: u64,
    pub signatures_verified: u64,
    pub payloads_decrypted: u64,
    pub applied_operations: u64,
    pub open_mode: String,
}
#[derive(uniffi::Record)]
pub struct UnlockResult {
    pub step: AgreementStep,
    pub shared: Vec<u8>,
}
#[uniffi::export]
impl NativeEngine {
    #[uniffi::constructor]
    pub fn open(
        source: Box<dyn EngineRecordSource>,
        listing: Vec<String>,
        versions: HashMap<String, String>,
        me: PublicKeys,
        library_id: String,
        namespaces: Vec<String>,
        key: Arc<NativeCheckpointKey>,
    ) -> Result<Arc<Self>> {
        let options = EngineOptions {
            library_id,
            namespaces,
            checkpoint_key: key.key.authentication_key(),
            content_cache_bytes: 256 * 1024,
        };
        let source = Source {
            host: RefCell::new(source),
            records: RefCell::new(BTreeMap::new()),
            versions: RefCell::new(versions),
        };
        let mut listing = listing;
        listing.sort();
        listing.dedup();
        let engine = Engine::open(
            source,
            listing.clone(),
            me.into(),
            options,
            key.checkpoint.as_deref(),
        )?;
        Ok(Arc::new(Self {
            session: Mutex::new(EngineSession {
                engine,
                revision: 0,
                listing,
                key: key.key.clone(),
            }),
            id: NEXT_SESSION.fetch_add(1, Ordering::Relaxed),
        }))
    }
    /// Batched inventory: little-endian u32 path length, UTF-8 path, u32 version length,
    /// UTF-8 version; zero version length means no provider token. No per-record callbacks.
    #[uniffi::constructor]
    pub fn open_inventory(
        source: Box<dyn EngineRecordSource>,
        inventory: Vec<u8>,
        me: PublicKeys,
        library_id: String,
        namespaces: Vec<String>,
        key: Arc<NativeCheckpointKey>,
    ) -> Result<Arc<Self>> {
        fn part<'a>(input: &mut &'a [u8]) -> Result<&'a str> {
            if input.len() < 4 {
                return Err(invalid("Truncated inventory"));
            }
            let n = u32::from_le_bytes(
                input[..4]
                    .try_into()
                    .map_err(|_| invalid("Inventory length"))?,
            ) as usize;
            *input = &input[4..];
            if n > input.len() {
                return Err(invalid("Truncated inventory entry"));
            }
            let text =
                std::str::from_utf8(&input[..n]).map_err(|_| invalid("Invalid inventory UTF-8"))?;
            *input = &input[n..];
            Ok(text)
        }
        let mut input = inventory.as_slice();
        let mut listing = Vec::new();
        let mut versions = HashMap::new();
        while !input.is_empty() {
            let path = part(&mut input)?.to_owned();
            let version = part(&mut input)?;
            if !version.is_empty() {
                versions.insert(path.clone(), version.to_owned());
            }
            listing.push(path);
        }
        Self::open(source, listing, versions, me, library_id, namespaces, key)
    }
    pub fn id(&self) -> Result<String> {
        Ok(self.lock()?.engine.authority().id.clone())
    }
    pub fn revision(&self) -> Result<u64> {
        Ok(self.lock()?.revision)
    }
    pub fn revisions(&self) -> Result<HashMap<String, u64>> {
        let s = self.lock()?;
        Ok(s.engine
            .authority()
            .namespaces
            .iter()
            .map(|ns| (ns.clone(), s.engine.revision(ns)))
            .collect())
    }
    pub fn work(&self) -> Result<EngineWork> {
        let s = self.lock()?;
        let stats = s.engine.stats();
        Ok(EngineWork {
            records_read: stats.records_read,
            signatures_verified: stats.signatures_verified,
            payloads_decrypted: stats.payloads_decrypted,
            applied_operations: stats.applied_operations,
            open_mode: format!("{:?}", s.engine.open_mode()),
        })
    }
    pub fn access(&self, namespace: String, now: String) -> Result<Option<Denial>> {
        self.lock()?
            .engine
            .access(&namespace, &now)?
            .map(|d| denial(d.reason, d.detail))
            .transpose()
    }
    pub fn me(&self) -> Result<Member> {
        types::convert(self.lock()?.engine.me())
    }
    pub fn members(&self) -> Result<Vec<Member>> {
        types::convert(self.lock()?.engine.members())
    }
    /// Explicit compatibility history materialization, never needed by named queries or writes.
    pub fn ledger(&self) -> Result<Vec<LedgerEntry>> {
        types::convert(self.lock()?.engine.materialize_library()?.ledger())
    }
    pub fn begin_unlock(&self) -> Result<Vec<AgreementStep>> {
        Ok(self
            .lock()?
            .engine
            .begin_unlock()
            .into_iter()
            .map(|s| AgreementStep {
                namespace: s.namespace,
                epoch: s.epoch,
                peer: s.peer,
            })
            .collect())
    }
    pub fn finish_unlock_many(&self, results: Vec<UnlockResult>) -> Result<()> {
        let results: Vec<_> = results
            .into_iter()
            .map(|r| (r.step, Zeroizing::new(r.shared)))
            .collect();
        let mut s = self.lock()?;
        let pending = s.engine.begin_unlock();
        for (step, _) in &results {
            if !pending.iter().any(|p| {
                p.namespace == step.namespace && p.epoch == step.epoch && p.peer == step.peer
            }) {
                return Err(BindingError::StaleAction);
            }
        }
        let before: Vec<_> = s
            .engine
            .authority()
            .namespaces
            .iter()
            .map(|ns| s.engine.revision(ns))
            .collect();
        s.engine.finish_unlock_many(
            results
                .iter()
                .map(|(step, shared)| (step.namespace.clone(), step.epoch, shared.to_vec()))
                .collect(),
        )?;
        let after: Vec<_> = s
            .engine
            .authority()
            .namespaces
            .iter()
            .map(|ns| s.engine.revision(ns))
            .collect();
        if before != after {
            s.revision += 1;
        }
        Ok(())
    }
    pub fn checkpoint(&self, entropy: Vec<u8>) -> Result<Vec<u8>> {
        let s = self.lock()?;
        Ok(s.key
            .protect_binary(&s.engine.checkpoint()?, seed(entropy)?)?)
    }
    pub fn merge(&self, records: Records) -> Result<ChangeSummary> {
        Self::merge_locked(&mut *self.lock()?, records)
    }
    /// A provider version change requires fresh verification even if its bytes are identical.
    pub fn merge_observed(
        &self,
        records: Records,
        versions: HashMap<String, String>,
    ) -> Result<ChangeSummary> {
        let mut s = self.lock()?;
        let changed_version = records.keys().any(|path| {
            !path.starts_with("state/")
                && s.listing.binary_search(path).is_ok()
                && s.engine.source().versions.borrow().get(path) != versions.get(path)
        });
        for path in records.keys() {
            if let Some(version) = versions.get(path) {
                s.engine
                    .source()
                    .versions
                    .borrow_mut()
                    .insert(path.clone(), version.clone());
            } else {
                s.engine.source().versions.borrow_mut().remove(path);
            }
        }
        let observed: Vec<_> = records.keys().cloned().collect();
        let result = Self::merge_locked(&mut s, records);
        // Observed bytes are already durable. Only unpublished local/journal writes need staging.
        for path in observed {
            s.engine.source().records.borrow_mut().remove(&path);
        }
        let mut summary = result?;
        // An authority reset already queued the updated listing for replay after host unlock.
        if changed_version && s.engine.begin_unlock().is_empty() {
            let listing = s.listing.clone();
            let changes = s.engine.refresh(listing)?;
            s.revision += 1;
            summary.revision = s.revision;
            summary.namespaces.extend(changes.namespaces.into_keys());
            summary.namespaces.sort();
            summary.namespaces.dedup();
        }
        Ok(summary)
    }
    /// Bounded independent integrity audit. Failure is sticky until the host repairs and reopens.
    pub fn verify_batch(&self, limit: u32) -> Result<u64> {
        Ok(self.lock()?.engine.verify_batch(limit as usize)?.remaining as u64)
    }
    /// Replace the coherent host snapshot after successful publication/refresh.
    pub fn set_source(&self, source: Box<dyn EngineRecordSource>) -> Result<()> {
        *self.lock()?.engine.source().host.borrow_mut() = source;
        Ok(())
    }
    pub fn update_versions(&self, versions: HashMap<String, String>) -> Result<()> {
        let mut s = self.lock()?;
        let paths = versions.keys().cloned().collect::<Vec<_>>();
        s.engine.source().versions.borrow_mut().extend(versions);
        s.engine.acknowledge_versions(&paths)?;
        for path in &paths {
            s.engine.source().records.borrow_mut().remove(path);
        }
        Ok(())
    }
    pub fn records_at(&self, paths: Vec<String>) -> Result<Records> {
        let s = self.lock()?;
        paths
            .into_iter()
            .map(|p| {
                s.engine
                    .source()
                    .read(&p)
                    .map(|b| (p, b))
                    .map_err(Into::into)
            })
            .collect()
    }
    pub fn records(&self) -> Result<Records> {
        let paths = self.lock()?.listing.clone();
        self.records_at(paths)
    }
    pub fn begin_write(
        &self,
        namespace: String,
        kind: String,
        payload: Vec<u8>,
        now: String,
        entropy: Vec<u8>,
    ) -> Result<PreparedAction> {
        let s = self.lock()?;
        self.prepared(
            &s,
            s.engine.begin_write(
                &namespace,
                &kind,
                serde_json::from_slice(&payload)?,
                &now,
                seed(entropy)?,
            )?,
        )
    }
    pub fn commit(
        &self,
        action: Arc<HostAction>,
        signatures: Vec<Vec<u8>>,
    ) -> Result<ChangeSummary> {
        let records = action.pending.clone().finish(signatures)?;
        let mut s = self.lock()?;
        let Some((id, revision)) = action.session else {
            return Err(BindingError::WrongSession);
        };
        if id != self.id {
            return Err(BindingError::WrongSession);
        }
        if revision != s.revision {
            return Err(BindingError::StaleAction);
        }
        Self::merge_locked(&mut s, records.into_iter().collect())
    }
    pub fn query(
        &self,
        namespace: String,
        name: String,
        arguments: Vec<u8>,
        now: String,
    ) -> Result<JsonOutcome> {
        match self.lock()?.engine.query(
            &namespace,
            &name,
            serde_json::from_slice(&arguments)?,
            &now,
        )? {
            Outcome::Success { value, .. } => Ok(JsonOutcome::Success {
                value: serde_json::to_vec(&value)?,
            }),
            Outcome::Failure { reason, detail, .. } => Ok(JsonOutcome::Failure {
                denial: denial(reason, detail)?,
            }),
        }
    }
    pub fn operation_at(
        &self,
        path: String,
        namespace: String,
        now: String,
    ) -> Result<OperationOutcome> {
        match self.lock()?.engine.operation_at(&path, &namespace, &now)? {
            Outcome::Success { value, .. } => Ok(OperationOutcome::Success {
                value: value.try_into()?,
            }),
            Outcome::Failure { reason, detail, .. } => Ok(OperationOutcome::Failure {
                denial: denial(reason, detail)?,
            }),
        }
    }
    pub fn live_generation(&self, path: String, bytes: Vec<u8>, now: String) -> Result<u64> {
        Ok(self.lock()?.engine.live_generation(&path, &bytes, &now)?)
    }
    pub fn begin_approve(
        &self,
        request: Vec<u8>,
        grant: Option<GrantOptions>,
        now: String,
        entropy: Vec<u8>,
    ) -> Result<PreparedAction> {
        let mut s = self.lock()?;
        let library = s.engine.materialize_library()?;
        let info = Library::finish_request(request.clone(), library.id())?;
        let grant = grant
            .map(|g| -> Result<_> {
                Ok(model::Grant {
                    namespaces: g.namespaces.unwrap_or(info.namespaces),
                    access: g
                        .access
                        .map(types::convert)
                        .transpose()?
                        .unwrap_or(info.access),
                    expires: g.expires,
                    write_budget: g.write_budget,
                    import: None,
                })
            })
            .transpose()?;
        self.prepared(
            &s,
            library.begin_approve(request, grant, &now, seed(entropy)?)?,
        )
    }
    pub fn begin_revoke(
        &self,
        member_id: String,
        now: String,
        entropy: Vec<u8>,
    ) -> Result<PreparedAction> {
        let mut s = self.lock()?;
        let library = s.engine.materialize_library()?;
        self.prepared(&s, library.begin_revoke(&member_id, &now, seed(entropy)?)?)
    }
    pub fn begin_blob(
        &self,
        namespace: String,
        media_type: String,
        now: String,
        entropy: Vec<u8>,
    ) -> Result<BlobWriteOutcome> {
        match self
            .lock()?
            .engine
            .begin_blob(&namespace, media_type, &now, seed(entropy)?)?
        {
            Outcome::Success { value, .. } => Ok(BlobWriteOutcome::Ready {
                writer: Arc::new(NativeBlobWriter::new(value)),
            }),
            Outcome::Failure { reason, detail, .. } => Ok(BlobWriteOutcome::Failure {
                denial: denial(reason, detail)?,
            }),
        }
    }
    pub fn open_blob_chunk(
        &self,
        namespace: String,
        digest: String,
        index: u32,
        ciphertext: Vec<u8>,
        now: String,
    ) -> Result<BlobReadOutcome> {
        match self.lock()?.engine.open_blob_chunk(
            &namespace,
            &digest,
            index as usize,
            &ciphertext,
            &now,
        ) {
            Ok(Outcome::Success { value, .. }) => Ok(BlobReadOutcome::Available { bytes: value }),
            Ok(Outcome::Failure { reason, detail, .. }) => Ok(if reason == "unavailable" {
                BlobReadOutcome::Missing
            } else {
                BlobReadOutcome::Inaccessible { detail }
            }),
            Err(error) => Ok(BlobReadOutcome::Invalid {
                detail: error.to_string(),
            }),
        }
    }
}

#[derive(uniffi::Object)]
pub struct NativeCheckpointKey {
    key: Arc<checkpoint::CheckpointKey>,
    checkpoint: Option<Vec<u8>>,
}
#[derive(uniffi::Object)]
pub struct NativeCheckpointPreparation {
    prepared: Mutex<Option<checkpoint::PreparedCheckpointKey>>,
}
#[uniffi::export]
impl NativeCheckpointPreparation {
    #[uniffi::constructor]
    pub fn new(library_id: String, member: PublicKeys, entropy: Vec<u8>) -> Result<Arc<Self>> {
        Ok(Arc::new(Self {
            prepared: Mutex::new(Some(checkpoint::PreparedCheckpointKey::new(
                &library_id,
                member.into(),
                seed(entropy)?,
            )?)),
        }))
    }
    pub fn signing_body(&self) -> Result<Vec<u8>> {
        Ok(self
            .prepared
            .lock()
            .map_err(|_| BindingError::Poisoned)?
            .as_ref()
            .ok_or_else(|| invalid("Checkpoint preparation consumed"))?
            .signing_body()
            .to_vec())
    }
    pub fn finish(&self, signature: Vec<u8>) -> Result<Arc<NativeCheckpointKey>> {
        let key = self
            .prepared
            .lock()
            .map_err(|_| BindingError::Poisoned)?
            .take()
            .ok_or_else(|| invalid("Checkpoint preparation consumed"))?
            .finish(signature)?;
        Ok(Arc::new(NativeCheckpointKey {
            key: Arc::new(key),
            checkpoint: None,
        }))
    }
}
#[derive(uniffi::Object)]
pub struct NativeCheckpointOpening {
    opening: Mutex<Option<checkpoint::CheckpointOpening>>,
}
#[uniffi::export]
impl NativeCheckpointOpening {
    #[uniffi::constructor]
    pub fn new(bytes: Vec<u8>, library_id: String, member: PublicKeys) -> Result<Arc<Self>> {
        Ok(Arc::new(Self {
            opening: Mutex::new(Some(checkpoint::CheckpointOpening::begin(
                &bytes,
                &library_id,
                &member.into(),
            )?)),
        }))
    }
    pub fn agreement_peer(&self) -> Result<Vec<u8>> {
        Ok(self
            .opening
            .lock()
            .map_err(|_| BindingError::Poisoned)?
            .as_ref()
            .ok_or_else(|| invalid("Checkpoint opening consumed"))?
            .agreement_peer()
            .to_vec())
    }
    pub fn finish(&self, shared: Vec<u8>) -> Result<Arc<NativeCheckpointKey>> {
        let shared = Zeroizing::new(shared);
        let opening = self
            .opening
            .lock()
            .map_err(|_| BindingError::Poisoned)?
            .take()
            .ok_or_else(|| invalid("Checkpoint opening consumed"))?;
        let (key, checkpoint) = opening.finish(&shared)?;
        Ok(Arc::new(NativeCheckpointKey {
            key: Arc::new(key),
            checkpoint: Some(checkpoint),
        }))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod lock_tests {
    use super::*;
    use std::{sync::mpsc, time::Duration};

    #[test]
    fn concurrent_calls_wait_and_callback_reentry_fails() {
        let session = Mutex::new(0);
        let id = NEXT_SESSION.fetch_add(1, Ordering::Relaxed);
        let first = lock_session(&session, id).unwrap();
        // This is the same acquisition used by an engine call from a synchronous callback.
        let callback = || {
            assert!(matches!(
                lock_session(&session, id),
                Err(BindingError::InvalidData { detail }) if detail.contains("reenter")
            ));
        };
        callback();
        std::thread::scope(|scope| {
            let (started_tx, started_rx) = mpsc::channel();
            let (finished_tx, finished_rx) = mpsc::channel();
            let session = &session;
            let caller = scope.spawn(move || {
                started_tx.send(()).unwrap();
                let mut guard = lock_session(session, id).unwrap();
                *guard += 1;
                finished_tx.send(()).unwrap();
            });
            started_rx.recv().unwrap();
            assert!(matches!(
                finished_rx.recv_timeout(Duration::from_millis(50)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ));
            drop(first);
            finished_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            caller.join().unwrap();
        });
        assert_eq!(*lock_session(&session, id).unwrap(), 1);
    }

    #[test]
    fn cross_engine_callbacks_never_wait_for_contended_locks() {
        let a = Arc::new(Mutex::new(()));
        let b = Arc::new(Mutex::new(()));
        let a_id = NEXT_SESSION.fetch_add(1, Ordering::Relaxed);
        let b_id = NEXT_SESSION.fetch_add(1, Ordering::Relaxed);
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let (done_tx, done_rx) = mpsc::channel();
        let mut callers = Vec::new();
        for (held, held_id, target, target_id) in [
            (a.clone(), a_id, b.clone(), b_id),
            (b.clone(), b_id, a.clone(), a_id),
        ] {
            let barrier = barrier.clone();
            let done = done_tx.clone();
            callers.push(std::thread::spawn(move || {
                let _guard = lock_session(&held, held_id).unwrap();
                barrier.wait();
                assert!(matches!(lock_session(&target, target_id), Err(BindingError::InvalidData { detail }) if detail.contains("cannot wait")));
                ACTIVE_ENGINES.with(|active| {
                    assert!(!active.borrow().contains(&target_id));
                });
                // Keep both locks held until both callback attempts have completed.
                done.send(()).unwrap();
                barrier.wait();
            }));
        }
        // Detached threads on failure let a deadlock regression fail within the timeout.
        for _ in 0..2 {
            done_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        }
        for caller in callers {
            caller.join().unwrap();
        }
        // Uncontended cross-engine callbacks still work.
        let _a = lock_session(&a, a_id).unwrap();
        let _b = lock_session(&b, b_id).unwrap();
    }

    #[test]
    fn poisoning_is_reported_and_thread_entry_is_cleared() {
        let session = Mutex::new(());
        let id = NEXT_SESSION.fetch_add(1, Ordering::Relaxed);
        let _ = std::panic::catch_unwind(|| {
            let _guard = lock_session(&session, id).unwrap();
            panic!("poison the mutex");
        });
        for _ in 0..2 {
            assert!(matches!(
                lock_session(&session, id),
                Err(BindingError::Poisoned)
            ));
        }
    }
}
