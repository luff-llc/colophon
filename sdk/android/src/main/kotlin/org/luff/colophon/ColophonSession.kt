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
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
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
    private val _ledger = MutableStateFlow<List<LedgerEntry>>(emptyList())
    val ledger: StateFlow<List<LedgerEntry>> = _ledger.asStateFlow()
    private val _requests = MutableStateFlow<List<AccessRequest>>(emptyList())
    val requests: StateFlow<List<AccessRequest>> = _requests.asStateFlow()
    private val _lastError = MutableStateFlow<String?>(null)
    val lastError: StateFlow<String?> = _lastError.asStateFlow()

    val observedRevision: ObservedRevision get() = ObservedRevision(context, _revision.value)

    /** Shared completion barrier. Dependent startup work awaits this before using the session. */
    suspend fun restore() {
        val deferred = restoreMutex.withLock {
            restoreDeferred ?: scope.async {
                startWatching()
                try {
                    apply(worker.restore())
                } catch (error: Exception) {
                    if (error is CancellationException) throw error
                    fail(error)
                }
            }.also { restoreDeferred = it }
        }
        deferred.await()
    }

    suspend fun refresh() {
        restore()
        val lease = context
        withContext(dispatcher) {
            try {
                val snapshot = worker.refresh()
                if (lease == context) {
                    apply(snapshot)
                    startWatching()
                }
            } catch (error: Exception) {
                if (error is CancellationException) throw error
                if (lease == context) fail(error)
            }
        }
    }

    suspend fun create() {
        restore()
        withContext(dispatcher) {
            if (_phase.value != SessionPhase.NoLibrary) return@withContext
            _phase.value = SessionPhase.Creating
            try {
                apply(worker.create())
                startWatching()
            } catch (error: Exception) {
                if (error is CancellationException) {
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
                if (error is CancellationException) throw error
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
                if (error is CancellationException) throw error
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
                if (error is CancellationException) throw error
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
                invalidateContext()
                _phase.value = SessionPhase.NoLibrary
            } catch (error: Exception) {
                if (error is CancellationException) throw error
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
            val snapshot = try {
                worker.rejoin(keys)
            } catch (error: Exception) {
                if (error is CancellationException) throw error
                throw error
            }
            invalidateContext()
            apply(snapshot)
            startWatching()
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
                if (error is CancellationException) throw error
                if (lease == context) handleCommandError(error)
                throw error
            }
        }
    }

    suspend fun recoveryKeys(): KeyProvider? = withContext(dispatcher) { worker.recovery() }

    fun close() {
        watchHandle?.close()
        watchHandle = null
        expiryJob?.cancel()
        expiryJob = null
        scope.cancel()
        runBlocking(dispatcher) { worker.close() }
    }

    private fun startWatching() {
        if (watchHandle != null) return
        try {
            watchHandle = worker.watch {
                scope.launch { refresh() }
            }
        } catch (error: Exception) {
            if (error is CancellationException) throw error
            _lastError.value = error.message
        }
    }

    private fun apply(snapshot: SessionSnapshot) {
        val changed = snapshot.namespaceRevisions.keys.filter { _namespaceRevisions.value[it] != snapshot.namespaceRevisions[it] }.toSet()
        val lost = snapshot.phase != SessionPhase.Ready
        _phase.value = snapshot.phase
        _revision.value = snapshot.revision
        _namespaceRevisions.value = snapshot.namespaceRevisions
        _libraryID.value = snapshot.core?.libraryID ?: _libraryID.value
        _memberID.value = snapshot.core?.me?.id ?: _memberID.value
        _members.value = snapshot.core?.members ?: emptyList()
        _ledger.value = snapshot.core?.ledger ?: emptyList()
        _requests.value = snapshot.core?.requests ?: emptyList()
        views = if (lost) emptyMap() else snapshot.core?.views ?: emptyMap()
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
            refresh()
        }
    }

    private fun invalidateContext() {
        expiryJob?.cancel()
        expiryJob = null
        context = UUID.randomUUID()
        views = emptyMap()
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
        views = emptyMap()
        _ledger.value = emptyList()
        _members.value = emptyList()
        _requests.value = emptyList()
        synchronized(cacheLock) {
            for (invalidate in caches.values) invalidate(emptySet(), true)
        }
        _lastError.value = error.message ?: error.toString()
        _phase.value = when (error) {
            is PendingPublication -> SessionPhase.Unavailable(error.reason)
            is StorageException.Unavailable -> SessionPhase.Unavailable(error.message ?: "unavailable")
            is AccessException -> if (error.denial.reason == DenialReason.NOT_READABLE || error.denial.reason == DenialReason.UNAVAILABLE) {
                SessionPhase.Unavailable(error.denial.detail)
            } else {
                SessionPhase.Denied
            }
            is BindingException.KeyProvider -> SessionPhase.Failed(error.detail)
            else -> SessionPhase.Failed(error.message ?: error.toString())
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

    internal fun projection(namespace: String): ByteArray {
        val view = views[namespace]
        if (_phase.value != SessionPhase.Ready || view == null) throw SessionException.NotReady
        return view.state
    }

    companion object {
        internal val sessionDispatcher: CoroutineDispatcher =
            Executors.newSingleThreadExecutor { runnable ->
                Thread(runnable, "colophon-session").apply { isDaemon = true }
            }.asCoroutineDispatcher()
    }
}
