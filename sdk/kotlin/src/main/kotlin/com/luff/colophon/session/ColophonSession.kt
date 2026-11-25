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
    @Volatile internal var homesConfigured = configuration.homes.isNotEmpty()
        private set
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
    /** Counts the refreshes that moved `Ready` to `Refreshing`; only the latest such refresh puts `Ready` back. */
    private var refreshMark = 0L
    /** The refresh a refused command started ([handleCommandError]), for hosts and tests that must see its outcome. */
    internal var refusalRefresh: Job? = null
        private set
    /** A test seam: awaited by every refresh after the worker answered and before its outcome is published. Null outside tests. */
    internal var refreshWillFinish: (suspend () -> Unit)? = null
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
        val marked = phase == SessionPhase.Ready
        if (marked) { set { copy(phase = SessionPhase.Refreshing) }; refreshMark++ }
        // This refresh's generation. A refresh that a newer one has since re-marked is stale: its outcome (snapshot or
        // error) is dropped and the phase follows the newer one (Swift's rule).
        val generation = refreshMark
        fun current() = generation == refreshMark && lease == context
        // A command that failed while this refresh was in flight keeps the phase its failure set; a failure that set none
        // leaves the refresh's own outcome to decide.
        fun failureHoldsPhase() = failureRevision != commandFailureRevision && phase != SessionPhase.Refreshing
        try {
            val snapshot = worker.refresh()
            refreshWillFinish?.invoke()
            if (!current()) return@facade
            if (snapshot.phase == SessionPhase.Ready && failureHoldsPhase()) return@facade
            apply(snapshot)
            startWatching()
        } catch (e: CancellationException) { throw e
        } catch (e: Exception) { if (current() && !failureHoldsPhase()) fail(e)
        } finally {
            // A finished refresh never leaves the phase at `Refreshing`: whatever path ends it (cancelled, a snapshot apply()
            // ignored, a command failure that set no phase), the phase this refresh replaced comes back.
            if (marked && current() && phase == SessionPhase.Refreshing) set { copy(phase = SessionPhase.Ready) }
        }
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

    /**
     * One write, bound to the revision observed when the person began the action. [claimedMs], when given (ms since
     * the Unix epoch), is the operation's signed `created` instead of now: an app importing old data keeps each
     * item's original date, which rows such as a note's `created` show. Order stays logical; only that date changes.
     * A claimed date later than now is [SessionError.InvalidCommand].
     */
    suspend fun perform(command: DomainCommand, observed: ObservedRevision, claimedMs: Long? = null): WriteReceipt = facade {
        restore()
        if (observed.context != context) throw SessionError.DestinationChanged()
        try {
            val (receipt, snapshot) = worker.write(command, observed.revision, claimedMs)
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

    /**
     * Approves a member's request with the owner controller, spending `pairing`: confirmed on this device for exactly this
     * request's key (spec §9.1), by the six-digit code (`beginApproval`, `approvalCode`, then `pairing.confirm()` once the
     * person saw the same digits on both devices) or by `scanRequest`. Any other pairing is refused; a pairing is spent
     * whatever the answer. `termsJson` overrides the requested terms.
     */
    suspend fun approve(request: AccessRequest, pairing: AccountPairing, termsJson: String? = null) = owner { worker.approve(request, pairing, termsJson) }
    /**
     * Approves a request that asks for services (spec §10.1), narrowed by `grant`: the services granted, an expiry,
     * conditions. A grant wider than the request is `SessionError.InvalidCommand`, and the pairing is not spent.
     */
    suspend fun approve(request: AccessRequest, pairing: AccountPairing, grant: ServiceGrant) {
        val terms = SessionWorker.narrowed(request.termsJson, grant)
        owner { worker.approve(request, pairing, terms) }
    }

    // Calls for services (§12)

    /**
     * Signs a call (spec §12.2) for `audience` and `purpose` with `argsJson` (a JSON object) by this device's member key
     * and returns its bytes base64url-encoded, ready for `Authorization: Colophon <call>`. Refused locally, with nothing
     * sent: a service this session did not ask for (`refused:outOfScope`, before the key is asked), and any call the
     * core's own §12.3 check refuses over what this device holds (its grant's services, expiry or conditions, a
     * revocation it holds). Sign a fresh call for each request: a home refuses a replay.
     */
    suspend fun signCall(audience: String, purpose: String, argsJson: String): String = facade {
        restore()
        java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(worker.signCall(audience, purpose, argsJson))
    }

    /**
     * Provisions a slot at a home's door by this member's grant (the reference home's gate `"grant"`, relay/README.md):
     * signs a fresh call for `audience` with purpose `home.provision` and args exactly the body
     * `{"account","base","slot"}`, POSTs the body to `door` with `Content-Type: application/json`, its `Content-Length`
     * and `Authorization: Colophon <call>`, and returns the home's signed member request (§9.1). So it plugs into
     * `HomeConfiguration.request`: `request = { account -> rig.provisionRequest(door, audience, slot, base, account) }`.
     * A refusal is a `ProvisionRefusal` with the door's status and code; the signer's own refusal is the engine's
     * `AccountException` and sends nothing. `transport` defaults to `HttpHomeTransport` (`allowsLoopbackHttp` for a test
     * door on loopback).
     */
    suspend fun provisionRequest(door: String, audience: String, slot: String, base: String, account: String,
                                 transport: HomeTransport? = null, allowsLoopbackHttp: Boolean = false): ByteArray {
        val body = Json.write(mapOf("account" to account, "base" to base, "slot" to slot))
        val call = signCall(audience, "home.provision", body)
        val bytes = body.toByteArray(Charsets.UTF_8)
        val sender = transport ?: HttpHomeTransport(allowingLoopbackHttp = allowsLoopbackHttp)
        val answer = sender.send(com.luff.colophon.HttpRequest(0uL, "", com.luff.colophon.HttpMethod.POST, door, listOf(
            com.luff.colophon.Header("Content-Type", "application/json"), com.luff.colophon.Header("Content-Length", bytes.size.toString()),
            com.luff.colophon.Header("Authorization", "Colophon $call"),
        ), bytes))
        if (answer.status.toInt() == 200) return answer.body
        val refusal = HomeRefusal.of(answer.status.toInt(), answer.headers, answer.body)
        throw ProvisionRefusal(answer.status.toInt(), refusal?.code, refusal?.retryAfterSeconds)
    }

    // Pairing before approval (§7.3)

    /**
     * The joining device, code path: a pairing for this device's member key. Send `pairing.commitment()` to the approving
     * device; when its nonce arrives, `pairing.receiveNonce(na)` gives the reveal to send back and `pairing.digits()` the
     * six digits to show. On a match `pairing.confirm()`, otherwise `rejectPairing(pairing)`.
     */
    suspend fun beginJoinPairing(): AccountPairing = facade { restore(); worker.beginJoinPairing() }
    /** The approving device's person starts a ceremony for one incoming commitment: send `nonce` back. Call it only when the person asked (an incoming commitment is never started by itself). One ceremony at a time; every start counts toward five an hour until it confirms (§7.3). */
    suspend fun beginApproval(commitment: ByteArray): ApprovalStart = facade { restore(); worker.beginApproval(commitment) }
    /** The approving device received the reveal: the six digits to show. A reveal that does not open the commitment aborts and counts as a failure. */
    suspend fun approvalCode(pairing: AccountPairing, e: ByteArray, nb: ByteArray): String = facade { worker.approvalCode(pairing, e, nb) }
    /** The codes differed or the person stopped: the session ends on this device and counts as a failure. */
    suspend fun rejectPairing(pairing: AccountPairing) = facade { worker.rejectPairing(pairing) }
    /** Ends a ceremony this device started (the person cancelled, the other device went away). It stays counted. */
    suspend fun abandonApproval(pairing: AccountPairing) = facade { worker.abandonApproval(pairing) }
    /** The approving device scanned a request from the joining device's screen (its canonical envelope, §9.1). Nothing is stored. */
    suspend fun scanRequest(data: ByteArray): ScannedRequest = facade { restore(); worker.scanRequest(data) }
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
    /** This device's own signed membership request (its canonical envelope), to show as a QR code for the approving device to scan (`scanRequest`). */
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
    /**
     * With `immediate = false` it is a transition: [cosigners] (other control keys the person holds here) sign it beside the
     * owner, so that with every control key signing it is a full set (spec §8.7) and takes effect without the delay.
     */
    suspend fun addController(key: AsyncKeyProvider, label: String, roles: List<ControllerRole> = listOf(ControllerRole.APPROVE), immediate: Boolean = true,
                              cosigners: List<AsyncKeyProvider> = listOf()) = owner {
        val d = key.keyDescriptor()
        worker.addController(ControllerSpec(d, label, roles, d.form == SignForm.WEBAUTHN, null, listOf()), if (immediate) AddMode.IMMEDIATE else AddMode.TRANSITION, key, cosigners)
    }
    /**
     * Appoints `homes` to an account that has none yet (one created with `createWithoutHome`), and with `adding` adds that
     * controller (a passkey, say, with roles CONTROL and RECOVER), in ONE transition (spec §8.7) the owner signs with the new
     * key's possession proof. With no home before it, it is recorded at once and final (§13.1): the new controller then builds
     * its own slot, so it unlocks alone, and this session starts syncing with the homes at once (no relaunch; pass the same
     * homes in `SessionConfiguration.homes` on the next launch). With a home already current the transition waits out its
     * delay: the call submits each transition it waits on like [proposeTransition] and answers [HomesAppointment.Pending].
     *
     * Idempotent: called again after a crash or a `Pending`, it finishes what the account shows is not done, and never adds
     * the controller or appoints a home twice. A home's `request` is called only while no current or pending appointment
     * names its endpoint; a request that names another account or not that endpoint, or a key already present with another
     * label or roles, is `InvalidCommand` before anything is signed.
     */
    suspend fun appointHomes(homes: List<HomeConfiguration>, adding: AdditionalController? = null,
                             cosigners: List<AsyncKeyProvider> = listOf()): HomesAppointment = facade {
        restore()
        val added = adding?.let { a ->
            val d = a.provider.keyDescriptor()
            ControllerSpec(d, a.label, a.roles, d.form == SignForm.WEBAUTHN, null, listOf()) to a.provider
        }
        val outcome = try { val (o, s) = worker.appointHomes(homes, added, cosigners); apply(s); o }
        catch (e: CancellationException) { throw e } catch (e: Exception) { handleCommandError(e); throw e }
        if (homes.isNotEmpty() && !homesConfigured) { homesConfigured = true; set { copy(syncState = HomeSyncState.Idle) } }
        startSyncLoop()
        if (outcome is HomesAppointment.Pending) for (digest in outcome.transitions) submitUntilReceipted(digest, Submission.Kind.TRANSITION)
        if (homesConfigured) try { apply(worker.registerRoutes()) } catch (e: CancellationException) { throw e } catch (_: Exception) {}
        outcome
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
    /**
     * Proposes a change to the account (spec §8.7: homes, keyring, policy) signed with the owner's keys and [cosigners] (other
     * control or recover keys the person holds here: with every control key signing, and at least two units, it is a full set,
     * final without the delay), and submits it. Returns its digest. To remove or replace a controller use [removeController] or
     * [replaceController], which also rotate the vault (a bare `keyring.remove` here leaves it retiring, spec §8.3).
     */
    suspend fun proposeTransition(changeJson: String, cosigners: List<AsyncKeyProvider> = listOf()): String = facade {
        restore()
        val digest = try { val (d, s) = worker.submitTransition(changeJson, cosigners = cosigners); apply(s); d }
        catch (e: CancellationException) { throw e } catch (e: Exception) { handleCommandError(e); throw e }
        submitUntilReceipted(digest, Submission.Kind.TRANSITION)
        digest
    }
    // Removing and replacing keys (§8.3)

    /**
     * What removing controller `id` would do, before anything is signed: a refusal ([removeController] throws `InvalidCommand`
     * for it), whether the vault rotates at once, and the spec §6.4 warnings a host MUST show first. With [replacingWith], what
     * [replaceController] would do. Nothing is asked of any key.
     */
    suspend fun checkRemoval(id: String, replacingWith: AsyncKeyProvider? = null,
                             roles: List<ControllerRole> = listOf(ControllerRole.CONTROL, ControllerRole.RECOVER),
                             cosigners: List<AsyncKeyProvider> = listOf()): RemovalCheck = facade {
        restore()
        worker.checkRemoval(id, replacingWith, roles, cosigners)
    }
    /**
     * Removes controller `id` (a lost passkey, say) by ONE transition (spec §8.7) signed by the owner and [cosigners], and
     * submits it to every home like [proposeTransition]. It lists the `approve` or `sign` keys the removed key added (§8.4).
     * When the removed key had a slot and every remaining passkey's credential is held here, the transition rotates the vault
     * at once (§8.3); otherwise the vault retires when it activates and this call, made again then, writes the `vault` entry.
     * After the rotation it appends the `rekey` of every namespace. [KeyringChange.Pending] while the transition waits out its
     * delay (a full set does not wait) or a duty is left; call it again with the same arguments: it never signs twice.
     */
    suspend fun removeController(id: String, cosigners: List<AsyncKeyProvider> = listOf()): KeyringChange = facade {
        restore()
        val outcome = try { val (o, s) = worker.removeController(id, cosigners); apply(s); o }
        catch (e: CancellationException) { throw e } catch (e: Exception) { handleCommandError(e); throw e }
        if (outcome is KeyringChange.Pending) for (digest in outcome.transitions) submitUntilReceipted(digest, Submission.Kind.TRANSITION)
        outcome
    }
    /**
     * Replaces controller `id` (the first passkey, say) with [key]: the new key signs its possession proof with PRF in the same
     * assertion (spec §7.2), so there is never a moment with fewer ways in. When this device keeps another key that can rotate
     * the vault it is ONE transition adding the new key and removing the old one; otherwise (spec §8.3) it is staged: the new
     * key is added, builds its own slot, then the old key is removed with a rotation signed by both. Answers like
     * [removeController]. When `id` is this device's owner key, configure [key] as the owner controller afterwards.
     */
    suspend fun replaceController(id: String, key: AsyncKeyProvider, label: String,
                                  roles: List<ControllerRole> = listOf(ControllerRole.CONTROL, ControllerRole.RECOVER),
                                  cosigners: List<AsyncKeyProvider> = listOf()): KeyringChange = facade {
        restore()
        val d = key.keyDescriptor()
        val spec = ControllerSpec(d, label, roles, d.form == SignForm.WEBAUTHN, null, listOf())
        val outcome = try { val (o, s) = worker.replaceController(id, spec, key, cosigners); apply(s); o }
        catch (e: CancellationException) { throw e } catch (e: Exception) { handleCommandError(e); throw e }
        if (outcome is KeyringChange.Pending) for (digest in outcome.transitions) submitUntilReceipted(digest, Submission.Kind.TRANSITION)
        outcome
    }
    /**
     * Does what a removal left this host (`duties.vaultRotationOwed`, `duties.rekeyOwed`): the `vault` entry while the vault is
     * retiring, then the `rekey`. A passkey owner is asked to unlock, so call it when the duties show something.
     */
    suspend fun completeKeyChanges(cosigners: List<AsyncKeyProvider> = listOf()): KeyringChange = facade {
        restore()
        try { val (o, s) = worker.completeKeyChanges(cosigners); apply(s); o }
        catch (e: CancellationException) { throw e } catch (e: Exception) { handleCommandError(e); throw e }
    }
    /** "Use this key once more" (`duties.keysWithoutSlot`): gives [key], a current controller without a slot, its own slot. */
    suspend fun restoreSlot(key: AsyncKeyProvider, label: String) = owner { worker.restoreSlot(key, label) }

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
        // With no library there is nothing to exchange. A pass here would refresh to `NoLibrary` and erase what a failed
        // `create()` just published (its `Failed` phase and error), which an app would see as a missing error.
        if (_state.value.libraryId == null) return false
        // A stopped account runs no exchange (spec §1 "A stop"): not a failure, and nothing to retry.
        if (phase.isStopped) { set { copy(syncState = HomeSyncState.Disabled) }; return true }
        set { copy(syncState = HomeSyncState.Syncing) }
        return try {
            val result = worker.exchange()
            if (result.stopped) { set { copy(syncState = HomeSyncState.Disabled) }; refresh(true); return true }
            // A home that answered `503 {"result":"unavailable"}` is not available: shown so, retried with backoff (never as this
            // device being stopped, which only its own verified history decides).
            if (result.homeUnavailable && !result.changed) {
                set { copy(homeFaults = result.faults.toList(), homeIssues = result.issues.toList(), syncState = HomeSyncState.Offline(HomeWords.UNAVAILABLE)) }
                return false
            }
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
                // Stopped: no timer and no backoff. Only an event wakes the loop, and each pass returns at once without
                // contacting a home.
                if (phase.isStopped) { syncSignal.receive(); continue }
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
            is AccountException.Denied -> { set { copy(lastError = e.message) }; refusalRefresh = scope.launch { refresh(false) } }
            is AccountException, is StorageException, is SessionKeyFailure, is KeyCustodyException -> { commandFailureRevision++; fail(e) }
            else -> set { copy(lastError = e.message) }
        }
    }
    private fun fail(e: Exception) {
        // A stopped account refuses every write (`newerFormat`) and every call (`unavailable`): that is the stopped phase the
        // person already sees, not a new fault, so the phase and the readable content stay.
        if (phase.isStopped && (e is AccountException.NewerFormat || e is AccountException.Unavailable)) return
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
