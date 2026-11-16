package com.luff.colophon.session

import com.luff.colophon.AccountException
import com.luff.colophon.AccountDenialReason
import com.luff.colophon.AccountPairing
import com.luff.colophon.AddMode
import com.luff.colophon.ControllerRole
import com.luff.colophon.ControllerSpec
import com.luff.colophon.PairingTransferKey
import com.luff.colophon.SealedSeed
import com.luff.colophon.SignForm
import kotlinx.coroutines.async
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.util.UUID
import kotlin.coroutines.cancellation.CancellationException
import kotlin.random.Random

/**
 * The one object an app holds over one Colophon 0.5 account: it opens the account's records, unlocks this device's
 * member, keeps the engine fresh as the store and the homes change, performs writes with observed revisions, and
 * surfaces what a person must see (pending changes, unseen activations, "this account has no home", update required).
 * Own exactly one per process and account.
 *
 * Threads: every public call is a `suspend` function that returns to its caller's dispatcher (the main thread is
 * fine to call from); the session's own state changes on one serial lane, and every engine call, key ceremony, file
 * operation and HTTP request runs off the main thread in the worker. Published state is [state], a `StateFlow`.
 * The Kotlin twin of the Swift SDK's `ColophonSession`, with the same names where Kotlin allows.
 */
class ColophonSession(configuration: SessionConfiguration) : AutoCloseable {
    internal val worker = SessionWorker(configuration)
    @Suppress("OPT_IN_USAGE")
    private val lane = Dispatchers.Default.limitedParallelism(1, "colophon-session-facade")
    private val scope = CoroutineScope(SupervisorJob() + lane)
    internal val homesConfigured = configuration.homes.isNotEmpty()
    private val _state = MutableStateFlow(SessionState(context = UUID.randomUUID().toString(),
        syncState = if (configuration.homes.isNotEmpty()) HomeSyncState.Idle else HomeSyncState.Disabled))
    /** Everything the session publishes. */
    val state: StateFlow<SessionState> = _state.asStateFlow()

    val phase: SessionPhase get() = _state.value.phase
    val revision: Long get() = _state.value.revision
    val libraryId: String? get() = _state.value.libraryId
    val memberId: String? get() = _state.value.memberId
    val requests: List<AccessRequest> get() = _state.value.requests
    val notices: SessionNotices get() = _state.value.notices
    val homes get() = _state.value.homes
    val duties: HostDuties get() = _state.value.duties
    val homeFaults: List<HomeFault> get() = _state.value.homeFaults
    val homeIssues: List<HomeIssue> get() = _state.value.homeIssues
    val lastError: String? get() = _state.value.lastError
    val observedRevision: ObservedRevision get() = _state.value.let { ObservedRevision(it.context, it.revision) }

    private var restoreJob: Deferred<Unit>? = null
    private var syncJob: Job? = null
    private var dueJob: Job? = null
    private var watchJob: Job? = null
    private var batchJob: Job? = null
    private var checkpointJob: Job? = null
    private var usable = false
    private var commandFailureRevision = 0L
    private var retryCreate = false
    private val submissions = LinkedHashMap<String, Submission>()
    private val syncSignal = Channel<Unit>(Channel.CONFLATED)
    private val syncMutex = Mutex()
    /** In-progress blob downloads by digest. */
    internal val blobDownloads = HashMap<String, BlobAvailabilityState>()

    internal val context: String get() = _state.value.context
    private inline fun set(change: SessionState.() -> SessionState) = _state.update(change)

    internal suspend fun <T> facade(body: suspend () -> T): T = withContext(lane) { body() }

    /** Stops the background loops and locks the engine, waiting for the lock. The session is unusable afterwards. */
    suspend fun shutdown() {
        scope.cancel()
        try { worker.lock() } catch (e: CancellationException) { throw e } catch (_: Exception) {}
    }
    /** [shutdown] without waiting (never blocks the calling thread): the engine is locked on a background thread. */
    override fun close() {
        scope.cancel()
        CoroutineScope(Dispatchers.IO).launch { try { worker.lock() } catch (_: Exception) {} }
    }

    private fun scheduleCheckpoint() {
        checkpointJob?.cancel()
        checkpointJob = scope.launch {
            try { delay(1000); worker.saveCheckpoint() } catch (e: CancellationException) { throw e } catch (e: Exception) { set { copy(lastError = e.message) } }
        }
    }

    /** A shared completion barrier: dependent startup work awaits this before using the session. */
    suspend fun restore() {
        // The first call starts the restore in the session's own scope (as a Swift Task): a caller that is cancelled
        // stops waiting, the restore itself completes.
        facade { restoreJob ?: scope.async { runRestore() }.also { restoreJob = it } }.await()
    }
    private suspend fun runRestore() {
        val lease = context
        startWatching()
        try {
            val snapshot = worker.restore()
            if (lease == context) apply(snapshot)
        } catch (e: CancellationException) { throw e
        } catch (e: Exception) { if (lease == context) fail(e) }
        startSyncLoop(); startDueLoop()
    }

    suspend fun refresh() = refresh(false)
    private suspend fun refresh(preservingCommandFailure: Boolean): Unit = facade {
        restore()
        val lease = context
        val failureRevision = commandFailureRevision
        if (phase == SessionPhase.Ready) set { copy(phase = SessionPhase.Refreshing) }
        try {
            val snapshot = worker.refresh()
            if (lease != context) return@facade
            // A command that failed while this refresh was in flight keeps its phase (Swift's rule).
            if (snapshot.phase == SessionPhase.Ready && failureRevision != commandFailureRevision) return@facade
            apply(snapshot)
            startWatching()
        } catch (e: CancellationException) { throw e
        } catch (e: Exception) { if (lease == context && failureRevision == commandFailureRevision) fail(e) }
    }

    /**
     * Creates the account for this device: the owner controller, this device's member, and (spec §18) the configured
     * homes appointed at once, with the creation's own engine (a passkey owner is asked once).
     */
    suspend fun create(): Unit = facade {
        restore()
        if (phase != SessionPhase.NoLibrary) return@facade
        retryCreate = true
        set { copy(phase = SessionPhase.Creating) }
        val lease = context
        try {
            val snapshot = worker.create()
            if (lease != context) return@facade
            apply(snapshot); retryCreate = false; startWatching(); startSyncLoop(); startDueLoop()
            if (homesConfigured) try { apply(worker.registerRoutes()) } catch (e: CancellationException) { throw e } catch (_: Exception) {}
        } catch (e: CancellationException) { throw e
        } catch (e: Exception) {
            if (lease == context) {
                if (e is SessionError.NoHome) { retryCreate = false; set { copy(lastError = e.message, phase = SessionPhase.NoLibrary) } } else fail(e)
            }
        }
    }
    /** Retries the lifecycle action that failed, an interrupted create included. */
    suspend fun retry() = facade {
        refresh()
        if (retryCreate && phase == SessionPhase.NoLibrary) create()
    }

    /** One write, bound to the revision observed when the person began the action. */
    suspend fun perform(command: DomainCommand, observed: ObservedRevision): WriteReceipt = facade {
        restore()
        if (observed.context != context) throw SessionError.DestinationChanged()
        try {
            val (receipt, snapshot) = worker.write(command, observed.revision)
            if (observed.context != context) throw SessionError.DestinationChanged()
            apply(snapshot)
            if (homesConfigured) requestSync()
            receipt
        } catch (r: SessionRefusal) {
            if (observed.context == context) { apply(r.snapshot); set { copy(lastError = r.error.message) } }
            throw r.error
        } catch (e: CancellationException) { throw e
        } catch (e: Exception) {
            if (observed.context == context) handleCommandError(e)
            throw e
        }
    }

    /** Approves a member's request with the owner controller. `terms` overrides the requested terms. */
    suspend fun approve(request: AccessRequest, termsJson: String? = null) = owner { worker.approve(request, termsJson) }
    suspend fun revoke(memberId: String) = owner { worker.revoke(memberId) }
    /** Leaves locally; does not revoke the member or delete the person's records. */
    suspend fun leave() = facade {
        restore(); worker.leave(); stopSync(); invalidateContext(); set { copy(phase = SessionPhase.NoLibrary) }
    }
    /** A revoked identity needs fresh keys. */
    suspend fun rejoin(keys: AsyncKeyProvider) = facade {
        restore(); invalidateContext(); set { copy(phase = SessionPhase.Opening) }
        val lease = context
        try { val s = worker.rejoin(keys); if (lease == context) { apply(s); startWatching(); startSyncLoop() } }
        catch (e: CancellationException) { throw e } catch (e: Exception) { if (lease == context) fail(e) }
    }
    /** Takes a request that arrived out of band (a file, a code) and shows it for approval. */
    suspend fun importRequest(data: ByteArray) = owner { worker.importRequest(data) }
    /** This device's own signed membership request, to hand to an approver. */
    suspend fun exportRequest(): ByteArray = facade { restore(); worker.exportRequest() }

    /** A bounded core query (`query_json`), fenced against namespace and identity changes. Returns the value's JSON. */
    suspend fun query(namespace: String, name: String, argumentsJson: String = "{}"): String = facade {
        restore()
        if (!hasUsableContent) throw SessionError.NotReady()
        val lease = context
        val observed = _state.value.namespaceRevisions[namespace] ?: 0u
        try {
            val result = worker.query(namespace, name, argumentsJson)
            if (context != lease || !hasUsableContent || (_state.value.namespaceRevisions[namespace] ?: 0u) != observed) throw SessionError.StaleRevision()
            result
        } catch (e: CancellationException) { throw e
        } catch (e: Exception) { if (context == lease) handleCommandError(e); throw e }
    }
    /** The namespace's fold as the engine reports it (`view_json`, `{"ok":...,"value":...}`), for screens and tests. */
    suspend fun view(namespace: String): String = facade {
        restore()
        if (!hasUsableContent) throw SessionError.NotReady()
        // Fenced as `query` is: a fold that returns after the session locked, lost access or changed account is stale.
        val lease = context
        val observed = _state.value.namespaceRevisions[namespace] ?: 0u
        try {
            val result = worker.view(namespace)
            afterViewForTests?.invoke()
            if (context != lease || !hasUsableContent || (_state.value.namespaceRevisions[namespace] ?: 0u) != observed) throw SessionError.StaleRevision()
            result
        } catch (e: CancellationException) { throw e
        } catch (e: Exception) { if (context == lease) handleCommandError(e); throw e }
    }
    /** Tests only: runs between the worker's answer to `view` and the fence. */
    @Volatile internal var afterViewForTests: (suspend () -> Unit)? = null
    /** The verified history as the engine reports it (JSON). */
    suspend fun ledger(): String = facade { restore(); worker.ledger() }

    // Adding a device, pending changes

    /** Adds a controller key (a second device's owner key, a passkey, a security key). The owner confirms. */
    suspend fun addController(key: AsyncKeyProvider, label: String, roles: List<ControllerRole> = listOf(ControllerRole.APPROVE), immediate: Boolean = true) = owner {
        val d = key.keyDescriptor()
        worker.addController(ControllerSpec(d, label, roles, d.form == SignForm.WEBAUTHN, null, listOf()), if (immediate) AddMode.IMMEDIATE else AddMode.TRANSITION, key)
    }
    /** The existing device's half of "add a device": seals the vault seed to the new device. */
    suspend fun transferSeed(pairing: AccountPairing): SealedSeed = facade { restore(); worker.transferSeed(pairing) }
    /** The new device's half: takes the sealed seed and builds this controller's own slot. */
    suspend fun acceptSeedTransfer(key: PairingTransferKey, pairing: AccountPairing, sealed: SealedSeed, label: String) =
        owner { worker.acceptSeedTransfer(key, pairing, sealed, label) }
    /** The removal follow-up (§17.5, `duties.removals`): revokes and removes in one action what a removed key admitted. */
    suspend fun removeFollowUp(seq: ULong) = owner { worker.removeFollowUp(seq) }
    /** The person keeps what a removed key admitted; the card is not shown again. */
    suspend fun keepFollowUp(seq: ULong) = owner { worker.keepFollowUp(seq) }
    /** One call to veto a pending transition (§17.5): signs, stores, and submits to every home until each receipted it or 300 s passed. */
    suspend fun veto(transition: String) = facade {
        owner { worker.veto(transition) }
        submitUntilReceipted(transition, Submission.Kind.VETO)
    }
    /** Proposes a change to the account (spec §8.7: homes, keyring, policy) signed with the owner's keys, and submits it. Returns its digest. */
    suspend fun proposeTransition(changeJson: String): String = facade {
        restore()
        val digest = try { val (d, s) = worker.submitTransition(changeJson); apply(s); d }
        catch (e: CancellationException) { throw e } catch (e: Exception) { handleCommandError(e); throw e }
        submitUntilReceipted(digest, Submission.Kind.TRANSITION)
        digest
    }
    /** Signs a dead transition this device signed again and submits the new one. */
    suspend fun resign(transition: String): String = facade {
        restore()
        val digest = try { val (d, s) = worker.resign(transition); apply(s); d }
        catch (e: CancellationException) { throw e } catch (e: Exception) { handleCommandError(e); throw e }
        submitUntilReceipted(digest, Submission.Kind.TRANSITION)
        digest
    }
    /** Suspends `key` while `transition` is pending (§8.7), and submits it like a veto. */
    suspend fun suspendKey(key: String, transition: String) = facade {
        restore()
        val digest = try { val (d, s) = worker.suspend(key, transition); apply(s); d }
        catch (e: CancellationException) { throw e } catch (e: Exception) { handleCommandError(e); throw e }
        submitUntilReceipted(digest, Submission.Kind.SUSPEND)
    }
    /** Records that the person saw one activation. A pending transition stays until it is vetoed, activates or is dead. */
    suspend fun acknowledgeActivation(seq: ULong) = facade {
        try { apply(worker.acknowledgeActivation(seq)) } catch (e: CancellationException) { throw e } catch (e: Exception) { set { copy(lastError = e.message) } }
    }
    /** How many homes hold a verified receipt for a transition, out of how many the account names. */
    suspend fun receipts(obj: String): Pair<Int, Int> = worker.receipts(obj)

    private suspend fun owner(body: suspend () -> SessionSnapshot) = facade {
        restore()
        val lease = context
        try { val s = body(); if (lease == context) apply(s) }
        catch (e: CancellationException) { throw e } catch (e: Exception) { if (lease == context) handleCommandError(e); throw e }
    }

    /** §17.5 submission: exchanges with every home, repeated until each receipted `obj` or `deadlineMs` passed. */
    internal suspend fun submitUntilReceipted(obj: String, kind: Submission.Kind, deadlineMs: Long = 300_000) {
        if (!homesConfigured || obj.isEmpty()) return
        val end = System.nanoTime() + deadlineMs * 1_000_000
        var wait = 500L
        var last = Submission(obj, kind, 0, homes.size, false)
        record(last)
        while (System.nanoTime() < end && currentCoroutineContextActive()) {
            syncNow()
            val counts = try { worker.receipts(obj) } catch (e: CancellationException) { throw e } catch (_: Exception) { null }
            if (counts != null) {
                last = Submission(obj, kind, counts.first, counts.second, false)
                record(last)
                if (counts.second == 0 || counts.first >= counts.second) break
            }
            delay(wait); wait = minOf(wait * 2, 15_000)
        }
        record(last.copy(finished = true))
    }
    private suspend fun currentCoroutineContextActive() = kotlinx.coroutines.currentCoroutineContext().isActive
    private fun record(s: Submission) {
        submissions[s.obj] = s
        set { copy(duties = duties.copy(submissions = submissions.values.sortedBy { it.obj })) }
    }

    // Lock

    /** Hides the content and drops every secret the engine holds: call it when the app goes to the background. */
    suspend fun lock() = facade {
        val s = try { worker.lock() } catch (e: CancellationException) { throw e } catch (_: Exception) { return@facade }
        usable = false; apply(s)
    }
    suspend fun unlock() = facade {
        val lease = context
        try { val s = worker.unlock(); if (lease == context) { apply(s); startWatching() } }
        catch (e: CancellationException) { throw e } catch (e: Exception) { if (lease == context) fail(e) }
    }

    // Exchange with the homes

    /** Runs one exchange with every home now and refreshes when something arrived. False when it failed. Passes never overlap. */
    suspend fun syncNow(): Boolean {
        if (!homesConfigured) return false
        return syncMutex.withLock { facade { runSync() } }
    }
    private suspend fun runSync(): Boolean {
        restore()
        set { copy(syncState = HomeSyncState.Syncing) }
        return try {
            val result = worker.exchange()
            set { copy(homeFaults = result.faults.toList(), homeIssues = result.issues.toList(), lastSyncedMs = System.currentTimeMillis(),
                syncState = if (result.unauthorized) HomeSyncState.Unauthorized
                    else if (result.failed) HomeSyncState.Error("a pass could not finish: the engine was still waiting") else HomeSyncState.Idle) }
            if (result.changed || phase != SessionPhase.Ready) refresh(true)
            else try { apply(worker.currentSnapshot()) } catch (e: CancellationException) { throw e } catch (_: Exception) {}
            !result.unauthorized && !result.failed
        } catch (e: CancellationException) { throw e
        } catch (e: HomeTransportException.Offline) { set { copy(syncState = HomeSyncState.Offline(e.reason)) }; false
        } catch (e: AccountException) {
            set { copy(syncState = HomeSyncState.Error(e.message ?: e.code)) }
            if (e is AccountException.NewerFormat) fail(e)
            false
        } catch (e: Exception) { set { copy(syncState = HomeSyncState.Error(e.message ?: e.javaClass.simpleName)) }; false }
    }

    /** Wakes the background exchange loop (a local change, the network came back). */
    fun requestSync() { syncSignal.trySend(Unit) }
    /** Stops the background exchange. Local storage and the session keep working. */
    fun stopSync() { syncJob?.cancel(); syncJob = null; dueJob?.cancel(); dueJob = null }

    private fun startSyncLoop() {
        if (!homesConfigured || syncJob != null) return
        syncJob = scope.launch {
            var failures = 0
            while (isActive) {
                val ok = syncNow()
                failures = if (ok) 0 else failures + 1
                // Success: poll after duties.pollIntervalMs or when a local change arrives. Failure: capped, jittered backoff.
                val wait = if (ok) duties.pollIntervalMs else (minOf(60.0, Math.pow(2.0, maxOf(0, failures - 1).toDouble())) * Random.nextDouble(0.5, 1.0) * 1000).toLong()
                withTimeoutOrNull(wait) { syncSignal.receive() }
            }
        }
    }
    /** `record_due` on a schedule: transitions that came due are recorded without waiting for a pass. */
    private fun startDueLoop() {
        if (dueJob != null) return
        dueJob = scope.launch {
            while (isActive) {
                delay(60_000)
                if (phase == SessionPhase.Ready) try { apply(worker.recordDue()) } catch (e: CancellationException) { throw e } catch (_: Exception) {}
            }
        }
    }

    private fun startWatching() {
        if (watchJob != null) return
        watchJob = scope.launch {
            try { worker.storage().changes().collect { externalChange() } } catch (e: CancellationException) { throw e } catch (e: Exception) { set { copy(lastError = e.message) } }
        }
    }
    /** One trailing batch coalesces bursts of store changes. */
    private fun externalChange() {
        if (batchJob != null) return
        batchJob = scope.launch {
            delay(75)
            batchJob = null
            refresh(true)
        }
    }
    /** A deterministic barrier for hosts and tests. */
    suspend fun flushExternalChanges() = facade { batchJob?.cancel(); batchJob = null; refresh(true) }

    val hasUsableContent: Boolean get() = usable && phase.usable

    private fun apply(s: SessionSnapshot) {
        val current = _state.value
        if (s.revision < current.revision) return
        if (homesConfigured && (s.revision != current.revision || s.phase != current.phase)) syncSignal.trySend(Unit)
        val lost = !s.usable
        set {
            copy(phase = s.phase, revision = s.revision, namespaceRevisions = s.namespaceRevisions,
                libraryId = s.libraryId ?: libraryId, memberId = s.memberId ?: memberId, members = s.members, requests = s.requests,
                notices = s.notices, homes = s.homes, duties = s.duties.copy(submissions = submissions.values.sortedBy { it.obj }), lastError = null)
        }
        usable = !lost
        if (!lost) scheduleCheckpoint()
    }
    private fun invalidateContext() {
        usable = false
        set { copy(context = UUID.randomUUID().toString(), members = listOf(), requests = listOf(), libraryId = null, memberId = null, notices = SessionNotices.empty) }
    }
    private fun handleCommandError(e: Exception) {
        when (e) {
            // A refused command does not decide the phase: the engine's access check does, on the next refresh.
            is AccountException.Denied -> { set { copy(lastError = e.message) }; scope.launch { refresh(false) } }
            is AccountException, is StorageException, is SessionKeyFailure, is KeyCustodyException -> { commandFailureRevision++; fail(e) }
            else -> set { copy(lastError = e.message) }
        }
    }
    private fun fail(e: Exception) {
        set { copy(lastError = e.message ?: e.javaClass.simpleName) }
        when (e) {
            is AccountException.NewerFormat -> { set { copy(phase = SessionPhase.UpdateRequired) }; usable = false; return }
            is AccountException.Denied -> set { copy(phase = if (e.reason == AccountDenialReason.NOT_READABLE || e.reason == AccountDenialReason.UNAVAILABLE) SessionPhase.Unavailable(e.detail) else SessionPhase.Denied) }
            is AccountException.Host, is AccountException.Unavailable, is AccountException.Reentered, is AccountException.Integrity -> { set { copy(phase = SessionPhase.Retry) }; return }
            is AccountException.Locked -> set { copy(phase = SessionPhase.Locked) }
            is AccountException -> set { copy(phase = SessionPhase.Failed(SessionFailure.Other(e.message ?: e.code))) }
            is SessionKeyFailure -> set { copy(phase = SessionPhase.Failed(SessionFailure.KeysUnavailable(e.detail))) }
            is KeyCustodyException -> set { copy(phase = SessionPhase.Failed(SessionFailure.KeysUnavailable(e.message ?: ""))) }
            is StorageException.Unavailable -> { set { copy(phase = if ("download pending" in e.reason) SessionPhase.WaitingForDownload else SessionPhase.Retry) }; return }
            is StorageException -> { set { copy(phase = SessionPhase.Retry) }; return }
            else -> set { copy(phase = SessionPhase.Failed(SessionFailure.Other(e.message ?: e.javaClass.simpleName))) }
        }
        usable = false
    }

    /** Persist the sealed saved state now (it is otherwise saved one second after the last change). */
    suspend fun flushCheckpoint() = facade { checkpointJob?.cancel(); checkpointJob = null; worker.saveCheckpoint() }
}
