package org.luff.colophon

import com.luff.colophon.AccessException
import com.luff.colophon.AccessRequest
import com.luff.colophon.BindingException
import com.luff.colophon.DenialReason
import com.luff.colophon.GrantOptions
import com.luff.colophon.KeyProvider
import com.luff.colophon.LedgerEntry
import com.luff.colophon.Member
import com.luff.colophon.NamespaceView
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.cancel
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.isActive
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.time.Instant
import java.util.UUID
import java.util.concurrent.CancellationException
import java.util.concurrent.Executors

/**
 * Own exactly one instance at the process entry point and share it with screens.
 * Configuration in; [phase] out. Await [restore] before dependent work.
 */
class ColophonSession internal constructor(
    configuration: SessionConfiguration,
    core: SessionCore,
    store: RecordStore?,
    dispatcher: CoroutineDispatcher,
) {
    constructor(configuration: SessionConfiguration) : this(
        configuration,
        BindingSessionCore(),
        configuration.store,
        sessionDispatcher,
    )

    private val worker = SessionWorker(configuration, core, store ?: configuration.store)
    private val dispatcher = dispatcher
    private val restoreMutex = Mutex()
    private var restoreDeferred: Deferred<Unit>? = null
    @Volatile private var context: UUID = UUID.randomUUID()
    private val caches = mutableMapOf<UUID, (Set<String>, Boolean) -> Unit>()
    private val cacheLock = Any()
    @Volatile private var activeEngine: com.luff.colophon.NativeEngine? = null
    @Volatile private var views: Map<String, NamespaceView> = emptyMap()
    private var watchHandle: AutoCloseable? = null
    private var expiryJob: Job? = null
    private val scope = CoroutineScope(SupervisorJob() + dispatcher)

    private val _phase = MutableStateFlow<SessionPhase>(SessionPhase.Opening)
    val phase: StateFlow<SessionPhase> = _phase.asStateFlow()
    private val _revision = MutableStateFlow(0uL)
    val revision: StateFlow<ULong> = _revision.asStateFlow()
    private val _namespaceRevisions = MutableStateFlow<Map<String, ULong>>(emptyMap())
    val namespaceRevisions: StateFlow<Map<String, ULong>> = _namespaceRevisions.asStateFlow()
    private val _libraryID = MutableStateFlow<String?>(null)
    val libraryID: StateFlow<String?> = _libraryID.asStateFlow()
    private val _memberID = MutableStateFlow<String?>(null)
    val memberID: StateFlow<String?> = _memberID.asStateFlow()
    private val _members = MutableStateFlow<List<Member>>(emptyList())
    val members: StateFlow<List<Member>> = _members.asStateFlow()
    private val _ledger = LedgerFlow()
    val ledger: StateFlow<List<LedgerEntry>> = _ledger
    private val _requests = MutableStateFlow<List<AccessRequest>>(emptyList())
    val requests: StateFlow<List<AccessRequest>> = _requests.asStateFlow()
    private val _lastError = MutableStateFlow<String?>(null)
    val lastError: StateFlow<String?> = _lastError.asStateFlow()

    private val relay = configuration.relay
    private val _syncState = MutableStateFlow<SyncState>(if (relay == null) SyncState.Disabled else SyncState.Idle)
    /** Relay synchronization (spec §8). [SyncState.Disabled] without a configured relay. */
    val syncState: StateFlow<SyncState> = _syncState.asStateFlow()
    private val _lastSynced = MutableStateFlow<Instant?>(null)
    val lastSynced: StateFlow<Instant?> = _lastSynced.asStateFlow()
    private val _syncConflicts = MutableStateFlow<List<String>>(emptyList())
    /** Paths whose relay bytes differ from this device's records, from the latest pass. */
    val syncConflicts: StateFlow<List<String>> = _syncConflicts.asStateFlow()
    private val syncKick = Channel<Unit>(Channel.CONFLATED)
    private var syncJob: Job? = null
    private val _blobDownloads = MutableStateFlow<Map<String, BlobAvailability>>(emptyMap())
    /** In-progress blob downloads by digest; absent when nothing is downloading. */
    val blobDownloads: StateFlow<Map<String, BlobAvailability>> = _blobDownloads.asStateFlow()
    @Volatile private var requiredBlobsChecked = false

    val observedRevision: ObservedRevision get() = ObservedRevision(context, _revision.value)

    /** Shared completion barrier. Dependent startup work awaits this before using the session. */
    suspend fun restore() {
        val deferred = restoreMutex.withLock {
            restoreDeferred ?: scope.async {
                val lease = context
                startWatching()
                try {
                    val snapshot = worker.restore()
                    if (lease == context) apply(snapshot)
                } catch (error: Exception) {
                    if (error is CancellationException || error is SessionException.NotReady) throw error
                    if (lease == context) fail(error)
                }
                startSyncLoop()
            }.also { restoreDeferred = it }
        }
        deferred.await()
    }

    suspend fun refresh() {
        restore()
        val lease = context
        withContext(dispatcher) {
            if (_phase.value == SessionPhase.Ready) _phase.value = SessionPhase.Refreshing
            try {
                val snapshot = worker.refresh()
                if (lease == context) {
                    apply(snapshot)
                    startWatching()
                }
            } catch (error: Exception) {
                if (error is CancellationException || error is SessionException.NotReady) throw error
                if (lease == context) fail(error)
            }
        }
    }

    /** Retry the selected connection; never reset its identity or manufacture an empty library. */
    suspend fun retry() { refresh() }

    suspend fun create() {
        restore()
        withContext(dispatcher) {
            if (_phase.value != SessionPhase.NoLibrary) return@withContext
            _phase.value = SessionPhase.Creating
            try {
                apply(worker.create())
                startWatching()
            } catch (error: Exception) {
                if (error is CancellationException || error is SessionException.NotReady) {
                    if (_phase.value == SessionPhase.Creating) _phase.value = SessionPhase.NoLibrary
                    throw error
                }
                fail(error)
            }
        }
    }

    /** Restore/discover an existing library and submit this identity's pairing request if ungranted. */
    suspend fun join() {
        restore()
        if (_phase.value == SessionPhase.NoLibrary) return
        refresh()
    }

    suspend fun perform(command: DomainCommand, observed: ObservedRevision): WriteReceipt {
        restore()
        if (observed.context != context) throw SessionException.DestinationChanged
        return withContext(dispatcher) {
            try {
                val (receipt, snapshot) = worker.write(command, observed.revision)
                if (observed.context != context) throw SessionException.DestinationChanged
                apply(snapshot)
                receipt
            } catch (refusal: SessionRefusal) {
                if (observed.context == context) {
                    apply(refusal.snapshot)
                    _lastError.value = refusal.error.message
                }
                throw refusal.error
            } catch (error: Exception) {
                if (error is CancellationException || error is SessionException.NotReady) throw error
                if (observed.context == context) handleCommandError(error)
                throw error
            }
        }
    }

    suspend fun approve(request: AccessRequest, grant: GrantOptions? = null) {
        restore()
        val lease = context
        withContext(dispatcher) {
            try {
                val snapshot = worker.approve(request.record, grant)
                if (lease == context) apply(snapshot)
            } catch (error: Exception) {
                if (error is CancellationException || error is SessionException.NotReady) throw error
                if (lease == context) handleCommandError(error)
                throw error
            }
        }
    }

    suspend fun revoke(memberID: String) {
        restore()
        val lease = context
        withContext(dispatcher) {
            try {
                val snapshot = worker.revoke(memberID)
                if (lease == context) apply(snapshot)
            } catch (error: Exception) {
                if (error is CancellationException || error is SessionException.NotReady) throw error
                if (lease == context) handleCommandError(error)
                throw error
            }
        }
    }

    /** Leaves locally; does not revoke the member or delete the person's records. */
    suspend fun leave() {
        restore()
        withContext(dispatcher) {
            try {
                worker.leave()
                stopSync()
                invalidateContext()
                _phase.value = SessionPhase.NoLibrary
            } catch (error: Exception) {
                if (error is CancellationException || error is SessionException.NotReady) throw error
                handleCommandError(error)
                throw error
            }
        }
    }

    /**
     * Revoked identities need fresh, independently persisted keys; unchanged requests are immutable.
     * Context is invalidated only after [SessionWorker.rejoin] accepts the new provider.
     */
    suspend fun rejoin(keys: KeyProvider) {
        restore()
        withContext(dispatcher) {
            val generation = worker.connectionGeneration
            val snapshot = try {
                worker.rejoin(keys)
            } catch (error: Exception) {
                if (error is CancellationException || error is SessionException.NotReady) throw error
                if (worker.connectionGeneration != generation) invalidateContext()
                // PendingPublication is an internal publication signal. Callers see storage failure.
                val publicError: Exception = if (error is PendingPublication) {
                    StorageException.Unavailable(error.reason)
                } else {
                    error
                }
                handleCommandError(publicError)
                throw publicError
            }
            invalidateContext()
            apply(snapshot)
            startWatching()
            startSyncLoop()
        }
    }

    /** Imports an external member's signed pairing request into this library. */
    suspend fun importRequest(data: ByteArray) {
        restore()
        val lease = context
        withContext(dispatcher) {
            try {
                val snapshot = worker.importRequest(data)
                if (lease == context) apply(snapshot)
            } catch (error: Exception) {
                if (error is CancellationException || error is SessionException.NotReady) throw error
                if (lease == context) handleCommandError(error)
                throw error
            }
        }
    }

    suspend fun recoveryKeys(): KeyProvider? = withContext(dispatcher) { worker.recovery() }

    /**
     * Runs one relay pass now (list, pull, push) and refreshes when records arrived. A barrier
     * for tests and for hosts that sync on foreground entry. Returns false when the pass failed.
     */
    suspend fun syncNow(): Boolean {
        if (relay == null) return false
        restore()
        _syncState.value = SyncState.Syncing
        return try {
            val report = withContext(Dispatchers.IO) { worker.syncRelay() }
            _syncConflicts.value = report?.conflicts ?: emptyList()
            _lastSynced.value = Instant.now()
            val conflict = report?.conflicts?.firstOrNull()
            _syncState.value = if (conflict != null) SyncState.Error("The relay holds different bytes for $conflict") else SyncState.Idle
            // Pulled records reach the core exactly like another process's folder writes.
            if ((report?.pulled ?: 0) > 0 || _phase.value != SessionPhase.Ready) refresh()
            if ((report?.pulled ?: 0) > 0 || !requiredBlobsChecked) {
                requiredBlobsChecked = true
                downloadRequiredBlobs()
            }
            true
        } catch (error: CancellationException) {
            throw error
        } catch (error: RelayException) {
            _syncState.value = when (error) {
                is RelayException.Offline -> SyncState.Offline(error.reason)
                is RelayException.Unauthorized -> SyncState.Unauthorized
                is RelayException.Busy -> SyncState.Offline(error.message ?: "busy")
                else -> SyncState.Error(error.message ?: error.toString())
            }
            false
        } catch (error: SessionException.NotReady) {
            throw error
        } catch (error: Exception) {
            _syncState.value = SyncState.Error(error.message ?: error.toString())
            if (error is SessionLayoutException) withContext(dispatcher) { fail(error) }
            false
        }
    }

    /**
     * Encrypts [data] in 64 KiB content-addressed chunks under the namespace epoch key, stores
     * them, then publishes a signed `colophon.blobPublish` manifest with one live reference.
     * Identical content already published only gains a reference. [required] asks every device to
     * download it eagerly (offline reading, transcripts).
     */
    suspend fun putBlob(data: ByteArray, namespace: String, mediaType: String, reference: String, required: Boolean = false): ColophonBlob =
        putBlob(BlobInput.Bytes(data), namespace, mediaType, reference, required)

    /** Streams [file] without loading it into memory. It is read twice and must not change. */
    suspend fun putBlob(file: java.io.File, namespace: String, mediaType: String, reference: String, required: Boolean = false): ColophonBlob =
        putBlob(BlobInput.FromFile(file), namespace, mediaType, reference, required)

    private suspend fun putBlob(input: BlobInput, namespace: String, mediaType: String, reference: String, required: Boolean): ColophonBlob {
        restore()
        if (_phase.value != SessionPhase.Ready && _phase.value != SessionPhase.Refreshing) throw SessionException.NotReady()
        val lease = context
        val staged = withContext(dispatcher) { worker.blobs.stage(namespace, mediaType, input) }
        if (lease != context) throw SessionException.DestinationChanged
        val fields = mutableListOf(
            "reference" to jsonString(reference).toByteArray(),
            "required" to required.toString().toByteArray(),
        )
        val kind = if (staged.manifest != null) {
            fields += "manifest" to staged.manifest
            BLOB_PUBLISH
        } else {
            fields += "digest" to jsonString(staged.digest).toByteArray()
            fields += "retain" to "true".toByteArray()
            BLOB_REFERENCE
        }
        val receipt = perform(DomainCommand(namespace, kind, rawJsonObject(fields)), observedRevision)
        if (relay != null) requestSync()
        return ColophonBlob(namespace, staged.digest, staged.size, staged.mediaType, receipt)
    }

    /** Adds or removes a live reference. Zero references lets local garbage collection reclaim it. */
    suspend fun setBlobReference(blob: ColophonBlob, reference: String, retain: Boolean, required: Boolean? = null): WriteReceipt {
        val fields = mutableListOf(
            "digest" to jsonString(blob.digest).toByteArray(),
            "reference" to jsonString(reference).toByteArray(),
            "retain" to retain.toString().toByteArray(),
        )
        if (required != null) fields += "required" to required.toString().toByteArray()
        return perform(DomainCommand(blob.namespace, BLOB_REFERENCE, rawJsonObject(fields)), observedRevision)
    }

    /** Local presence without downloading or decrypting anything. */
    suspend fun blobAvailability(namespace: String, digest: String): BlobAvailability {
        restore()
        _blobDownloads.value[digest]?.let { return it }
        if (_phase.value != SessionPhase.Ready && _phase.value != SessionPhase.Refreshing) return BlobAvailability.Inaccessible("The library is not ready")
        return withContext(dispatcher) {
            try {
                worker.blobs.availability(namespace, digest)
            } catch (error: BlobException) {
                BlobAvailability.Inaccessible(error.message ?: "inaccessible")
            } catch (error: StorageException) {
                BlobAvailability.Inaccessible(error.message ?: "inaccessible")
            }
        }
    }

    /**
     * Verified plaintext, chunk by chunk, in order. Missing chunks are fetched from the relay on
     * demand. Each chunk is authenticated before [consumer] sees it; the call throws
     * [BlobException.DigestMismatch] at the end if the whole content does not match, so do not
     * certify content until it returns.
     */
    suspend fun readBlob(namespace: String, digest: String, maximumBytes: Long = Long.MAX_VALUE, consumer: suspend (ByteArray) -> Unit) {
        restore()
        if (_phase.value != SessionPhase.Ready && _phase.value != SessionPhase.Refreshing) throw SessionException.NotReady()
        val lease = context
        val manifest = withContext(dispatcher) { worker.blobs.manifest(namespace, digest) }
        if (manifest.size > maximumBytes) throw BlobException.TooLarge()
        val hash = BlobHash()
        for (index in manifest.chunks.indices) {
            withContext(Dispatchers.IO) { worker.blobs.ensureChunk(manifest.chunks[index]) }
            val plaintext = withContext(dispatcher) { worker.blobs.openChunk(namespace, manifest, index) }
            if (lease != context) throw SessionException.DestinationChanged
            hash.update(plaintext)
            consumer(plaintext)
        }
        if (hash.finish() != manifest.digest || hash.size != manifest.size) throw BlobException.DigestMismatch()
    }

    /** Complete verified plaintext; use [blobFile] or [readBlob] for anything larger. */
    suspend fun blobBytes(namespace: String, digest: String, maximumBytes: Long = 16L * 1024 * 1024): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        readBlob(namespace, digest, maximumBytes) { out.write(it) }
        return out.toByteArray()
    }

    /**
     * Writes verified plaintext to a new private file under [directory] (default: the session's
     * private home). It appears only after the whole digest verified. The caller removes it.
     */
    suspend fun blobFile(namespace: String, digest: String, directory: java.io.File? = null): java.io.File {
        val folder = directory ?: java.io.File(worker.configuration.privateHome, "blob-files")
        if (!folder.exists() && !folder.mkdirs()) throw StorageException.Unavailable("Cannot create ${folder.path}")
        val partial = java.io.File(folder, ".partial-${UUID.randomUUID()}")
        val target = java.io.File(folder, "$digest-${UUID.randomUUID()}")
        try {
            java.io.FileOutputStream(partial).use { stream ->
                readBlob(namespace, digest) { withContext(Dispatchers.IO) { stream.write(it) } }
                stream.fd.sync()
            }
            if (!partial.renameTo(target)) throw StorageException.Unavailable("Cannot publish ${target.path}")
            return target
        } finally {
            if (partial.exists()) partial.delete()
        }
    }

    /** Downloads every missing chunk (ciphertext only), publishing progress in [blobDownloads]. */
    suspend fun prefetchBlob(namespace: String, digest: String) {
        restore()
        if (_phase.value != SessionPhase.Ready && _phase.value != SessionPhase.Refreshing) throw SessionException.NotReady()
        download(withContext(dispatcher) { worker.blobs.manifest(namespace, digest) })
    }

    /** Fetches every incomplete blob marked required in the configured namespaces. */
    suspend fun downloadRequiredBlobs() {
        restore()
        if (_phase.value != SessionPhase.Ready || relay == null) return
        for (namespace in worker.configuration.namespaces) {
            val manifests = try {
                withContext(dispatcher) { worker.blobs.incompleteRequired(namespace) }
            } catch (error: Exception) {
                if (error is CancellationException) throw error
                continue
            }
            for (manifest in manifests) {
                try {
                    download(manifest)
                } catch (error: Exception) {
                    if (error is CancellationException) throw error
                }
            }
        }
    }

    /**
     * Removes local chunks this session wrote or downloaded that no live reference needs: blobs
     * with zero references, and failed uploads older than [graceMillis]. With [evictReplicated],
     * chunks the relay already holds are evicted too unless required; they are fetched again on
     * demand. Never touches chunks other writers stored; deletes nothing if a namespace is unreadable.
     */
    suspend fun collectBlobGarbage(graceMillis: Long = 24L * 60 * 60 * 1000, evictReplicated: Boolean = false, discardSoleCopy: Boolean = false): BlobCollection {
        restore()
        if (_phase.value != SessionPhase.Ready && _phase.value != SessionPhase.Refreshing) throw SessionException.NotReady()
        return withContext(dispatcher) { worker.blobs.collect(graceMillis, evictReplicated, discardSoleCopy) }
    }

    private suspend fun download(manifest: BlobManifestInfo) {
        val total = manifest.chunks.size
        _blobDownloads.value = _blobDownloads.value + (manifest.digest to BlobAvailability.Downloading(0, total))
        try {
            manifest.chunks.forEachIndexed { index, path ->
                withContext(Dispatchers.IO) { worker.blobs.ensureChunk(path) }
                _blobDownloads.value = _blobDownloads.value + (manifest.digest to BlobAvailability.Downloading(index + 1, total))
            }
        } finally {
            _blobDownloads.value = _blobDownloads.value - manifest.digest
        }
    }

    /** Wakes the background sync loop, for example when connectivity returns. */
    fun requestSync() {
        syncKick.trySend(Unit)
    }

    /** Stops background relay sync. Local storage and the session keep working. */
    fun stopSync() {
        syncJob?.cancel()
        syncJob = null
    }

    private fun startSyncLoop() {
        val relay = relay ?: return
        if (!relay.automatic || syncJob != null) return
        syncJob = scope.launch {
            var failures = 0
            while (isActive) {
                val ok = try {
                    syncNow()
                } catch (_: SessionException.NotReady) {
                    return@launch
                }
                failures = if (ok) 0 else failures + 1
                val backoffMs = if (_syncState.value == SyncState.Unauthorized) {
                    300_000L
                } else {
                    (minOf(60_000.0, 1000.0 * Math.pow(2.0, (failures - 1).coerceAtLeast(0).toDouble())) *
                        (0.5 + Math.random() * 0.5)).toLong()
                }
                // Success: long-poll the relay or wait for a local change. Failure: capped,
                // jittered backoff that a local change or requestSync() cuts short. A blocking
                // long-poll is not joined, so a kick never waits for it.
                val wake = scope.async(Dispatchers.IO) {
                    if (ok) {
                        val started = System.nanoTime()
                        val changed = try {
                            worker.waitForRemoteChanges(25)
                        } catch (_: Exception) {
                            false
                        }
                        // A relay that answers at once without long-polling is polled instead.
                        if (!changed && System.nanoTime() - started < 2_000_000_000L) delay(15_000)
                    } else {
                        delay(backoffMs)
                    }
                }
                select<Unit> {
                    wake.onAwait {}
                    syncKick.onReceive {}
                }
                if (wake.isActive) wake.cancel()
            }
        }
    }

    fun close() {
        stopSync()
        watchHandle?.close()
        watchHandle = null
        expiryJob?.cancel()
        expiryJob = null
        scope.cancel()
        // The session dispatcher is one thread. runBlocking onto it deadlocks when close()
        // runs on that thread, and it stalls the caller behind whatever that thread is doing.
        worker.markClosed()
        if (Thread.currentThread().name.startsWith("colophon-session")) {
            worker.closeCoreNow()
        } else {
            CoroutineScope(SupervisorJob() + dispatcher).launch {
                worker.closeCoreSuspended()
            }
        }
    }

    private fun startWatching() {
        if (watchHandle != null) return
        try {
            watchHandle = worker.watch {
                launchRefresh()
            }
        } catch (error: Exception) {
            if (error is CancellationException || error is SessionException.NotReady) throw error
            _lastError.value = error.message
        }
    }

    val hasUsableContent: Boolean get() = views.isNotEmpty() && _phase.value in listOf(SessionPhase.Ready, SessionPhase.Refreshing, SessionPhase.WaitingForDownload, SessionPhase.Retry)
    private fun apply(snapshot: SessionSnapshot) {
        if (snapshot.revision < _revision.value) return
        if (relay != null && (snapshot.revision != _revision.value || snapshot.phase != _phase.value)) syncKick.trySend(Unit)
        val changed = snapshot.namespaceRevisions.keys.filter { _namespaceRevisions.value[it] != snapshot.namespaceRevisions[it] }.toSet()
        val lost = snapshot.phase !in listOf(SessionPhase.Ready, SessionPhase.Refreshing, SessionPhase.WaitingForDownload, SessionPhase.Retry)
        _phase.value = snapshot.phase
        _revision.value = snapshot.revision
        _namespaceRevisions.value = snapshot.namespaceRevisions
        _libraryID.value = snapshot.core?.libraryID ?: _libraryID.value
        _memberID.value = snapshot.core?.me?.id ?: _memberID.value
        _members.value = snapshot.core?.members ?: emptyList()
        _ledger.value = snapshot.core?.ledger ?: emptyList()
        _requests.value = snapshot.core?.requests ?: emptyList()
        views = if (lost) emptyMap() else snapshot.core?.views ?: emptyMap()
        activeEngine = if (lost) null else snapshot.core?.engine
        if (!lost) scheduleCheckpoint()
        synchronized(cacheLock) {
            for (invalidate in caches.values) invalidate(changed, lost)
        }
        scheduleExpiry(snapshot)
        _lastError.value = null
    }

    private fun scheduleExpiry(snapshot: SessionSnapshot) {
        expiryJob?.cancel()
        expiryJob = null
        if (snapshot.phase != SessionPhase.Ready) return
        val expires = snapshot.core?.me?.grant?.expires ?: return
        val expiryMs = try {
            Instant.parse(expires).toEpochMilli()
        } catch (_: Exception) {
            return
        }
        // The engine keeps a grant through its expiry instant (`now > expires`).
        // Waking on that exact millisecond would refresh too early and then not reschedule.
        val delayMs = expiryMs + 1 - System.currentTimeMillis()
        if (delayMs <= 0L) return
        expiryJob = scope.launch {
            delay(delayMs)
            try {
                refresh()
            } catch (_: SessionException.NotReady) {
                // close() won the race with the expiry wake-up.
            }
        }
    }

    /** File and expiry wakes are session jobs. A closed session is not a crash. */
    private fun launchRefresh() {
        scope.launch {
            try {
                refresh()
            } catch (_: SessionException.NotReady) {
            }
        }
    }

    private fun invalidateContext() {
        expiryJob?.cancel()
        expiryJob = null
        context = UUID.randomUUID()
        views = emptyMap()
        activeEngine = null
        _members.value = emptyList()
        _ledger.value = emptyList()
        _requests.value = emptyList()
        _libraryID.value = null
        _memberID.value = null
        synchronized(cacheLock) {
            for (invalidate in caches.values) invalidate(emptySet(), true)
        }
    }

    private fun handleCommandError(error: Exception) {
        if (error is AccessException || error is StorageException || error is PendingPublication || error is BindingException) {
            fail(error)
        } else {
            _lastError.value = error.message ?: error.toString()
        }
    }

    private fun fail(error: Exception) {
        val next = when (error) {
            is SessionLayoutException -> SessionPhase.UpdateRequired
            is BindingException.InvalidData ->
                if (error.detail.startsWith("Unsupported storage layout")) SessionPhase.UpdateRequired
                else SessionPhase.Failed(error.detail)
            is PendingPublication -> SessionPhase.Retry
            is StorageException.Unavailable -> {
                val reason = error.message ?: "unavailable"
                if (reason.contains("Waiting for the relay") || reason.contains("download pending")) SessionPhase.WaitingForDownload
                else SessionPhase.Retry
            }
            is AccessException -> if (error.denial.reason == DenialReason.NOT_READABLE || error.denial.reason == DenialReason.UNAVAILABLE) {
                SessionPhase.Unavailable(error.denial.detail)
            } else {
                SessionPhase.Denied
            }
            is BindingException.KeyProvider -> SessionPhase.Failed(error.detail)
            else -> SessionPhase.Failed(error.message ?: error.toString())
        }
        _lastError.value = error.message ?: error.toString()
        _phase.value = next
        if (next == SessionPhase.UpdateRequired || next == SessionPhase.WaitingForDownload || next == SessionPhase.Retry) return
        views = emptyMap()
        activeEngine = null
        _ledger.value = emptyList()
        _members.value = emptyList()
        _requests.value = emptyList()
        synchronized(cacheLock) {
            for (invalidate in caches.values) invalidate(emptySet(), true)
        }
    }

    internal fun registerCache(callback: (Set<String>, Boolean) -> Unit): UUID {
        val id = UUID.randomUUID()
        synchronized(cacheLock) { caches[id] = callback }
        return id
    }

    internal fun unregisterCache(id: UUID) {
        synchronized(cacheLock) { caches.remove(id) }
    }

    suspend fun query(namespace: String, name: String, arguments: ByteArray): ByteArray {
        restore()
        if (!hasUsableContent) throw SessionException.NotReady()
        val lease = context
        val observed = namespaceRevisions.value[namespace]
        val result = withContext(dispatcher) { worker.mutex.withLock {
            val engine = activeEngine
            if (engine == null) worker.core.query(namespace, name, arguments)
            else when (val result = engine.query(namespace, name, arguments, EngineLibrary.now())) {
                is com.luff.colophon.JsonOutcome.Success -> result.value
                is com.luff.colophon.JsonOutcome.Failure -> throw AccessException(result.denial)
            }
        } }
        if (lease != context || observed != namespaceRevisions.value[namespace] || !hasUsableContent) throw SessionException.StaleRevision
        return result
    }
    internal suspend fun projection(namespace: String): ByteArray = query(namespace, "read", "{}".toByteArray())

    suspend fun flushCheckpoint() = withContext(dispatcher) { checkpointJob?.cancel(); checkpointJob = null; worker.saveCheckpoint() }
    private var checkpointJob: Job? = null
    private fun scheduleCheckpoint() {
        checkpointJob?.cancel()
        checkpointJob = scope.launch { delay(1000); try { worker.saveCheckpoint() } catch (error: Exception) { if (error is CancellationException) throw error; fail(error) } }
    }

    companion object {
        internal val sessionDispatcher: CoroutineDispatcher =
            Executors.newSingleThreadExecutor { runnable ->
                Thread(runnable, "colophon-session").apply { isDaemon = true }
            }.asCoroutineDispatcher()
    }
}
