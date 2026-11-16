package com.luff.colophon.session

import com.luff.colophon.AccessKind
import com.luff.colophon.AccountException
import com.luff.colophon.AccountIdentity
import com.luff.colophon.AccountIdentityKind
import com.luff.colophon.AccountMember
import com.luff.colophon.AccountRequest
import com.luff.colophon.AccountDenialReason
import com.luff.colophon.AccountCreation
import com.luff.colophon.AccountPairing
import com.luff.colophon.AddMode
import com.luff.colophon.AuthorityObjects
import com.luff.colophon.ByteString
import com.luff.colophon.CallNeed
import com.luff.colophon.ControllerRole
import com.luff.colophon.ControllerSpec
import com.luff.colophon.CreateParams
import com.luff.colophon.CreateStage
import com.luff.colophon.Created
import com.luff.colophon.ExchangeFaultKind
import com.luff.colophon.ExchangeStepKind
import com.luff.colophon.Home
import com.luff.colophon.HttpAnswer
import com.luff.colophon.HttpMethod
import com.luff.colophon.KeepMode
import com.luff.colophon.ListedPath
import com.luff.colophon.Notices
import com.luff.colophon.PairingTransferKey
import com.luff.colophon.Report
import com.luff.colophon.RequestSpec
import com.luff.colophon.RevokeKeep
import com.luff.colophon.RuleKind
import com.luff.colophon.SealedSeed
import com.luff.colophon.SeenActivation
import com.luff.colophon.SignForm
import com.luff.colophon.Signature
import com.luff.colophon.SignerNeed
import com.luff.colophon.SlotPlan
import com.luff.colophon.StandingKind
import com.luff.colophon.StatusKind
import com.luff.colophon.Store
import com.luff.colophon.Written
import com.luff.colophon.accountDefaultPolicy
import com.luff.colophon.accountFormatDate
import com.luff.colophon.accountKeyId
import com.luff.colophon.accountRequestInfo
import com.luff.colophon.accountVerifyHistory
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.io.File
import java.util.Base64
import kotlin.coroutines.cancellation.CancellationException

internal data class SessionSnapshot(
    val phase: SessionPhase,
    val revision: Long,
    val namespaceRevisions: Map<String, ULong>,
    val libraryId: String?,
    val memberId: String?,
    val members: List<AccountMember> = listOf(),
    val requests: List<AccessRequest> = listOf(),
    val notices: SessionNotices = SessionNotices.empty,
    val homes: List<Home> = listOf(),
    val duties: HostDuties = HostDuties(),
) {
    val usable: Boolean get() = phase.usable
}

/** A refusal that carries the fresh snapshot so the facade shows what the person must now see. */
internal class SessionRefusal(val snapshot: SessionSnapshot, val error: SessionError) : Exception(error.message)

/**
 * Every engine call, key ceremony, file operation and HTTP request runs here, off the main thread. The gate (a
 * mutex) serialises complete operations across suspensions, including a passkey prompt and the persistence of the
 * stores a finish returned: the engine is never ahead of the disk when another operation reads it. A port of the
 * Swift SDK's `SessionWorker`, with the same names.
 */
internal class SessionWorker(val configuration: SessionConfiguration) {
    @Suppress("OPT_IN_USAGE")
    private val lane: CoroutineDispatcher = Dispatchers.IO.limitedParallelism(1, "colophon-session")
    private val gate = Mutex()
    private var memberKeys: AsyncKeyProvider = SessionKeys(configuration.keys)
    @Volatile private var engine: ColophonEngine? = null
        set(value) { field = value; if (value == null) memberOpened = false }
    @Volatile private var memberCustody: KeyCustody? = null
    var accountId: String? = null; private set
    var memberId: String? = null; private set
    private var journal = SessionJournal()
    private var journalLoaded = false
    private var locked = false
    private var revision = 0L
    private var lastRevisions: Map<String, ULong> = mapOf()
    private var lastPhase: SessionPhase = SessionPhase.Opening
    private var memberOpened = false
    private val journalFile = File(configuration.privateDirectory, "session.json")
    private val cache = SavedStateCache(configuration.privateDirectory)

    // Gate

    /**
     * One complete operation under the gate (a mutex). It stays cancellable, as a Swift task is: waiting on a person (a
     * passkey prompt, a key that never answers) ends when the caller is cancelled. What must not be cut in half is made
     * uncancellable where it happens: a finish and the persistence of its stores (`ColophonEngine.execute` with
     * `persistOn`), an exchange answer and its stores, `record_due` and its stores, and the abort of a pass.
     */
    private suspend fun <T> gated(body: suspend () -> T): T = withContext(lane) {
        gate.withLock {
            currentCoroutineContext().ensureActive()
            body()
        }
    }
    suspend fun <T> onLane(body: suspend () -> T): T = withContext(lane) { body() }

    // Storage

    fun storage(): RecordMedium = configuration.medium
    private fun loadJournal() {
        if (journalLoaded) return
        journal = AtomicFile.read(journalFile, 8 * 1024 * 1024)?.let { SessionJournal.decode(it) } ?: SessionJournal()
        journalLoaded = true
    }
    private fun saveJournal() = AtomicFile.write(journalFile, journal.encode())
    private val nowMs: Long get() = configuration.now()

    /** Persists the stores of one finished step, all or none. If the disk refuses, the engine is ahead of the disk: discard it. */
    private suspend fun persist(stores: List<Store>, on: ColophonEngine? = null) {
        if (stores.isEmpty()) return
        try {
            storage().write(stores.map { MediumWrite(it.path, it.bytes) })
        } catch (e: Exception) {
            if (on != null && on !== engine) on.discard() else { engine?.discard(); engine = null }
            throw e
        }
    }
    private suspend fun persist(written: Written, on: ColophonEngine? = null) = persist(written.stores, on)
    /** Persists a finish's stores in the same uncancellable step as the finish (`ColophonEngine.execute`). */
    private fun persistOn(on: ColophonEngine?): suspend (Written) -> Unit = { persist(it, on) }

    // Opening

    suspend fun restore(): SessionSnapshot = gated { reconcile() }
    suspend fun refresh(): SessionSnapshot = gated { reconcile() }

    /**
     * Locks at once, whatever holds the gate: the member engine and every open owner engine are locked (their keys and
     * opened plaintext overwritten) without waiting for the operation in flight, which then fails as `Locked`. The
     * gate is taken only briefly, if it frees soon, so the snapshot is ordered; a prompt that never returns is not
     * waited for. Never cancelled half way.
     */
    suspend fun lock(): SessionSnapshot = withContext(lane + NonCancellable) {
        locked = true
        val e = engine
        engine = null; memberOpened = false
        e?.lock()
        synchronized(openOwners) { openOwners.toList() }.forEach { it.lock() }
        val held = withTimeoutOrNull(2_000) { gate.lock(); true } ?: false
        try { snapshot(SessionPhase.Locked) } finally { if (held) gate.unlock() }
    }
    /** Owner engines open right now (each lives for one owner operation), so `lock` can lock them too. */
    private val openOwners = HashSet<ColophonEngine>()
    private fun <T : ColophonEngine?> tracked(owner: T): T { if (owner != null) synchronized(openOwners) { openOwners.add(owner) }; return owner }
    private suspend fun release(owner: ColophonEngine) { owner.lock(); synchronized(openOwners) { openOwners.remove(owner) } }
    suspend fun unlock(): SessionSnapshot = gated { locked = false; reconcile() }

    private fun listed(entries: List<MediumEntry>) = entries.map { ListedPath(it.path, it.version) }

    private suspend fun reconcile(): SessionSnapshot {
        loadJournal()
        if (journal.left) return snapshot(SessionPhase.NoLibrary)
        if (locked) return snapshot(SessionPhase.Locked)
        val entries = storage().listing()
        if (entries.none { it.path.startsWith("authority/") }) {
            if (journal.account != null) throw StorageException.Unavailable("Selected library is unavailable")
            return snapshot(SessionPhase.NoLibrary)
        }
        try {
            if (engine == null) openEngine(entries) else refreshEngine(entries)
        } catch (e: AccountException.NewerFormat) {
            engine?.discard(); engine = null
            return snapshot(SessionPhase.UpdateRequired)
        } catch (e: AccountException.Integrity) {
            engine?.discard(); engine = null
            throw e
        }
        return build()
    }

    private fun discoverAccount(entries: List<MediumEntry>): String {
        val medium = storage()
        fun objects(prefix: String) = entries.filter { it.path.startsWith(prefix) }.map { ByteString(medium.read(it.path)) }
        val pending = objects("transitions/") + objects("vetoes/") + objects("receipts/")
        val report = accountVerifyHistory(AuthorityObjects(objects("authority/"), pending, objects("heads/"), objects("predecessor/")), nowMs)
        if (report.kind == StatusKind.NEWER_FORMAT) throw AccountException.NewerFormat(report.code, report.detail ?: "")
        return report.account ?: throw AccountException.Malformed(report.code, report.detail ?: "the library's history does not verify")
    }

    private suspend fun openEngine(entries: List<MediumEntry>) {
        val account = journal.account ?: discoverAccount(entries)
        val keyId = KeyCustody.keyId(memberKeys)
        memberId = keyId
        memberCustody = KeyCustody.of(listOf(memberKeys))
        val saved = cache.load(account)
        val opened = configuration.deviceSecrets.key(account).use { key ->
            ColophonEngine.open(source = MediumSource(storage()), listing = listed(entries),
                identity = AccountIdentity(AccountIdentityKind.MEMBER, keyId), account = account,
                namespaces = configuration.libraryNamespaces, saved = saved, deviceKey = key, nowMs = nowMs)
        }
        if (locked) { opened.lock(); throw AccountException.Locked("locked", "the session was locked while it opened") }
        engine = opened; accountId = account
        // A member that is not approved yet holds no keys; the records can still be read and the exchange can still
        // bring the approval in. A member opens its epoch shares in `unlockIfPossible`.
        if (opened.run { it.me() }.kind != StandingKind.MEMBER) opened.run { it.load() }
        if (journal.account == null) { journal.account = account; saveJournal() }
        unlockIfPossible()
    }

    private suspend fun refreshEngine(entries: List<MediumEntry>) {
        val engine = engine ?: return
        val list = listed(entries)
        val at = nowMs
        engine.run { it.advance(at) }
        engine.run { it.refresh(list) }
        withContext(NonCancellable) { for (written in engine.run { it.recordDue() }) persist(written) }
        unlockIfPossible()
    }

    /** A member opens its epoch shares with its own agreement key: at first, and whenever new epochs were sealed to it. */
    private suspend fun unlockIfPossible() {
        val engine = engine ?: return
        val custody = memberCustody ?: return
        if (engine.run { it.me() }.kind != StandingKind.MEMBER) return
        val agreements = engine.run { it.beginUnlockEpochs() }
        if (agreements.isEmpty()) {
            // Revoked/no-readable-namespace members have no finish-unlock step to load records.
            // The core still requires load before notices/exchange, even when every read is denied.
            if (!memberOpened) { engine.run { it.load() }; memberOpened = true }
            return
        }
        engine.finishUnlockEpochs(custody.answerEpochs(agreements))
        memberOpened = true
    }

    suspend fun saveCheckpoint() = gated {
        val engine = engine ?: return@gated
        val account = accountId ?: return@gated
        if (lastPhase != SessionPhase.Ready) return@gated
        engine.run { it.verifyBatch(128u) }
        val state = engine.run { e -> withEntropy(32) { e.save(it) } }
        cache.save(account, state)
    }

    // Snapshot

    private fun snapshot(phase: SessionPhase, members: List<AccountMember> = listOf(), requests: List<AccessRequest> = listOf(),
                         notices: SessionNotices = SessionNotices.empty, revisions: Map<String, ULong> = mapOf(), homes: List<Home> = listOf(),
                         duties: HostDuties = HostDuties()): SessionSnapshot {
        if (phase != lastPhase || revisions != lastRevisions) revision++
        lastPhase = phase; lastRevisions = revisions
        return SessionSnapshot(phase, revision, revisions, accountId, memberId, members, requests, notices, homes, duties)
    }

    private suspend fun build(): SessionSnapshot {
        val engine = engine ?: return snapshot(SessionPhase.NoLibrary)
        val standing = engine.run { it.me() }
        val status = engine.run { it.status() }
        if (status.kind == StatusKind.NEWER_FORMAT) return snapshot(SessionPhase.UpdateRequired)
        val members = engine.run { it.members() }
        val pending = pendingRequests(members)
        val homes = engine.run { it.homes() }
        var phase: SessionPhase
        when (standing.kind) {
            StandingKind.UNKNOWN -> {
                ensureOwnRequest()
                return snapshot(SessionPhase.WaitingForApproval(AccessRequest.code(memberId ?: "")), members, pending, homes = homes)
            }
            StandingKind.CONTROLLER -> phase = SessionPhase.Failed(SessionFailure.Other("this identity is a controller, not a member"))
            StandingKind.MEMBER -> {
                if (standing.member?.revokedAt != null) phase = SessionPhase.Denied
                else {
                    phase = SessionPhase.Ready
                    for (namespace in configuration.libraryNamespaces) {
                        val denial = engine.run { it.access(namespace) } ?: continue
                        phase = if (denial.reason == AccountDenialReason.NOT_READABLE || denial.reason == AccountDenialReason.UNAVAILABLE)
                            SessionPhase.Unavailable(denial.detail) else SessionPhase.Denied
                        break
                    }
                }
            }
        }
        val revisions = HashMap<String, ULong>()
        if (phase == SessionPhase.Ready) for (r in engine.run { it.revisions() }) if (r.namespace in configuration.libraryNamespaces) revisions[r.namespace] = r.revision
        val notices = currentNotices()
        val head = engine.run { it.headSeq() }
        if (phase == SessionPhase.Ready) revisions["colophon.authority"] = head
        val duties = hostDuties(notices, homes)
        return snapshot(phase, members, pending, notices, if (phase == SessionPhase.Ready) revisions else mapOf(), homes, duties)
    }

    private suspend fun ownerId(): String? = try { KeyCustody.keyId(configuration.ownerController) } catch (e: CancellationException) { throw e } catch (_: Exception) { null }

    private suspend fun localKeyIds(): List<String> {
        val ids = ArrayList<String>()
        memberId?.let { ids.add(it) }
        ownerId()?.let { ids.add(it) }
        configuration.recoveryKeys?.let { kit -> try { ids.add(KeyCustody.keyId(kit)) } catch (e: CancellationException) { throw e } catch (_: Exception) {} }
        return ids
    }

    private suspend fun currentNotices(): SessionNotices {
        val engine = engine ?: return SessionNotices.empty
        val keys = localKeyIds()
        val seq = journal.shownSeq; val shown = journal.shownTransitions
        val raw = engine.run { it.notices(seq, shown, keys) }
        // The member engine that reads the account is not a controller, so the engine reports nothing as vetoable to
        // it. The one-tap veto is the owner controller's: offered when the owner key is a controller with `control` or
        // `recover` and the deadline the engine computed has not passed.
        val controllers = engine.run { it.controllers() }
        val owner = ownerId()
        val ownerMayVeto = controllers.firstOrNull { it.id == owner }?.let { ControllerRole.CONTROL in it.roles || ControllerRole.RECOVER in it.roles } ?: false
        val now = nowMs
        val pending = raw.pending.map { p -> p.copy(vetoable = ownerMayVeto && p.fullSet != true && (p.vetoDeadlineMs?.let { now <= it } ?: false)) }
        val activations = raw.activations.filter { it.seq !in journal.seenActivations }
        return SessionNotices(Notices(pending, activations, raw.owed, raw.controllersWithoutSlot, raw.vaultRetiring, raw.noHome))
    }

    /** Marks one activation seen, and nothing else (a pending transition is never dismissed by it). */
    suspend fun acknowledgeActivation(seq: ULong): SessionSnapshot = gated {
        if (engine == null) return@gated snapshot(lastPhase)
        loadJournal()
        journal.seenActivations = journal.seenActivations + seq
        var floor = journal.shownSeq
        for (activation in rawActivations().sortedBy { it.seq }) {
            if (activation.seq !in journal.seenActivations) break
            floor = maxOf(floor, activation.seq)
        }
        journal.shownSeq = floor
        journal.seenActivations = journal.seenActivations.filter { it > floor }.toSet()
        saveJournal()
        build()
    }
    private suspend fun rawActivations(): List<SeenActivation> {
        val engine = engine ?: return listOf()
        val keys = localKeyIds()
        val seq = journal.shownSeq; val shown = journal.shownTransitions
        return engine.run { it.notices(seq, shown, keys) }.activations
    }

    // Host duties (§17.5)

    private suspend fun hostDuties(notices: SessionNotices, homes: List<Home>): HostDuties {
        val engine = engine ?: return HostDuties()
        val controllers = engine.run { it.controllers() }
        val policy = engine.run { it.policy() }
        val quorum = maxOf(1, policy.headQuorum.toInt())
        val now = nowMs
        val dead = ArrayList<DeadTransition>()
        if (homes.isNotEmpty()) {
            for (pending in notices.pending) {
                if (now <= pending.issuedMs + 300_000) continue
                val receipted = engine.run { it.receiptedBy(pending.digest) }.size
                if (receipted < quorum) dead.add(DeadTransition(pending.digest, receipted, quorum, journal.signedChanges[pending.digest] != null))
            }
        }
        val routes = homes.map { home ->
            val configured = transportFor(home)
            val list = configured?.deliveryRoutes ?: listOf()
            val label = home.label
            when {
                list.map { it.reaches }.toSet().size < 2 -> RouteState(home.id, label, false,
                    "This app has fewer than two ways to reach you about changes to your account (on different devices or services). Add a second one.")
                journal.routes[home.id] == true -> RouteState(home.id, label, true, "")
                else -> RouteState(home.id, label, false,
                    if (journal.routes[home.id] == false || configured?.registerRoutes == null)
                        "$label does not offer notices yet, so it cannot tell you about a pending change. This app checks for them itself."
                    else "Your ways to be reached are not registered with $label yet.")
            }
        }
        val follow = engine.run { it.removalFollowUp() }.filter { it.seq !in journal.answeredRemovals }
        var removals = listOf<RemovalCard>()
        if (follow.isNotEmpty()) {
            val memberLabels = engine.run { it.members() }.associate { it.id to it.label }
            val labels = controllers.associate { it.id to it.label }
            removals = follow.map { r ->
                RemovalCard(r.seq, r.removed, r.members.map { RemovalCard.Item(it, memberLabels[it] ?: it.take(8)) },
                    r.controllers.map { RemovalCard.Item(it, labels[it] ?: it.take(8)) })
            }
        }
        val delay = policy.recoveryDelay.toLong() / 6
        return HostDuties(
            soleDevice = controllers.count { ControllerRole.CONTROL in it.roles && !it.suspended } <= 1,
            routes = routes, deadTransitions = dead, removals = removals,
            homeLabels = homes.associate { it.id to it.label },
            pollIntervalMs = if (notices.pending.isEmpty()) maxOf(60L, delay) * 1000 else 15_000,
        )
    }

    /** Registers this host's delivery routes with every home that offers it and has not got them (§17.5). */
    suspend fun registerRoutes(): SessionSnapshot = gated {
        val engine = engine ?: return@gated snapshot(lastPhase)
        val account = accountId ?: return@gated snapshot(lastPhase)
        loadJournal()
        for (home in engine.run { it.homes() }) {
            if (journal.routes[home.id] == true) continue
            val configured = transportFor(home) ?: continue
            if (configured.deliveryRoutes.map { it.reaches }.toSet().size < 2) continue
            val register = configured.registerRoutes
            journal.routes = journal.routes + (home.id to (register?.invoke(account, configured.deliveryRoutes) ?: false))
        }
        saveJournal()
        build()
    }

    /** Signs a transition with the owner's keys, stores it, and keeps its change so a dead one can be signed again. */
    suspend fun submitTransition(changeJson: String, rule: RuleKind = RuleKind.CONTROL): Pair<String, SessionSnapshot> = gated {
        if (engine == null) reconcile()
        val digest = withOwner { owner, custody, ownerId ->
            val signers = signers(owner, ownerId, SignerNeed.CONTROL)
            val written = owner.execute(custody, persistOn(owner)) { it.beginTransition(changeJson, signers, rule, ByteArray(0)) }
            objectDigest(written.stores, "transitions/") ?: ""
        }
        loadJournal()
        if (digest.isNotEmpty()) { journal.signedChanges = journal.signedChanges + (digest to changeJson); saveJournal() }
        digest to reconcile()
    }
    /** Signs the same change again (a dead transition this device signed). */
    suspend fun resign(digest: String): Pair<String, SessionSnapshot> {
        val change = onLane { loadJournal(); journal.signedChanges[digest] } ?: throw SessionError.InvalidCommand()
        return submitTransition(change)
    }
    /** Suspends `key` while `transition` is pending (§8.7), signed by the owner key. */
    suspend fun suspend(key: String, transition: String): Pair<String, SessionSnapshot> = gated {
        if (engine == null) reconcile()
        val digest = withOwner { owner, custody, ownerId ->
            val written = owner.execute(custody, persistOn(owner)) { e -> withEntropy(32) { e.beginSuspend(key, transition, ownerId, it) } }
            objectDigest(written.stores, "") ?: ""
        }
        digest to reconcile()
    }

    // Requests

    private fun requestPath(id: String) = "requests/$id.json"
    private suspend fun ownRequestBytes(): ByteArray {
        val account = accountId ?: throw SessionError.NotReady()
        if (memberId == null) throw SessionError.NotReady()
        val keys = memberKeys.publicKeys()
        val spec = RequestSpec(account, keys.signing, keys.agreement, configuration.memberLabel, configuration.memberKind,
            terms(configuration.namespaces, configuration.access, null, null), accountFormatDate(nowMs - 1000), null, null, listOf())
        return AccountRequest.prepare(spec).use { request ->
            val signature = memberKeys.sign(request.step().body)
            request.finish(Signature(signature, null, null)).raw
        }
    }
    private suspend fun ensureOwnRequest() {
        val id = memberId ?: return
        val path = requestPath(id)
        try { storage().read(path); return } catch (_: StorageException) {}
        storage().write(listOf(MediumWrite(path, ownRequestBytes())))
    }
    suspend fun exportRequest(): ByteArray = gated {
        loadJournal()
        if (engine == null) reconcile()
        val id = memberId ?: throw SessionError.NotReady()
        ensureOwnRequest()
        storage().read(requestPath(id))
    }
    suspend fun importRequest(data: ByteArray): SessionSnapshot = gated {
        val info = accountRequestInfo(data)
        storage().write(listOf(MediumWrite(requestPath(info.member), info.raw)))
        reconcile()
    }
    private fun pendingRequests(members: List<AccountMember>): List<AccessRequest> {
        val known = members.map { it.id }.toSet()
        val out = ArrayList<AccessRequest>()
        for (entry in storage().listing()) {
            if (!entry.path.startsWith("requests/")) continue
            val info = try { accountRequestInfo(storage().read(entry.path)) } catch (_: Exception) { continue }
            if (info.member in known || info.member == memberId) continue
            out.add(AccessRequest(info.member, info.label, info.kind, info.termsJson, AccessRequest.code(info.member), info.raw))
        }
        return out
    }

    // Owner operations

    /** Opens a controller engine for the owner, unlocks it by the owner's slot, runs `body`, locks it. */
    private suspend fun <T> withOwner(body: suspend (ColophonEngine, KeyCustody, String) -> T): T {
        val account = accountId ?: throw SessionError.NotReady()
        val custody = ownerCustody()
        val ownerId = KeyCustody.keyId(configuration.ownerController)
        val entries = storage().listing()
        val owner = tracked(configuration.deviceSecrets.key(account).use { key ->
            ColophonEngine.open(label = "colophon-owner", source = MediumSource(storage()), listing = listed(entries),
                identity = AccountIdentity(AccountIdentityKind.CONTROLLER, ownerId), account = account,
                namespaces = configuration.libraryNamespaces, saved = null, deviceKey = key, nowMs = nowMs)
        })
        try {
            if (owner.run { it.controllers() }.none { it.id == ownerId }) throw SessionError.OwnerRequired()
            unlockOwner(owner, custody, ownerId)
            return body(owner, custody, ownerId)
        } finally {
            release(owner)
        }
    }
    private suspend fun ownerCustody(): KeyCustody =
        KeyCustody.of(listOfNotNull(SessionKeys(configuration.ownerController), configuration.recoveryKeys?.let { SessionKeys(it) }))

    /** Opens the controller's own slot with the owner's key (a PRF ceremony for a passkey, a silent ECDH for a device key). */
    private suspend fun unlockOwner(owner: ColophonEngine, custody: KeyCustody, ownerId: String) {
        val slots = owner.run { it.slots() }
        val slot = slots.firstOrNull { it.controllers.size == 1 && it.controllers[0].id == ownerId }
            ?: slots.firstOrNull { s -> s.controllers.any { it.id == ownerId } } ?: throw SessionError.OwnerRequired()
        val inputs = owner.run { it.beginUnlockSlot(slot.index) }
        owner.finishUnlockSlot(slot.index, custody.answerUnlock(inputs))
    }
    private suspend fun signers(owner: ColophonEngine, ownerId: String, need: SignerNeed): List<String> {
        val chosen = owner.run { it.suggestSigners(listOf(ownerId), need) }
        return chosen.ifEmpty { listOf(ownerId) }
    }

    suspend fun approve(request: AccessRequest, terms: String?): SessionSnapshot = gated {
        if (engine == null) reconcile()
        withOwner { owner, custody, ownerId ->
            val signers = signers(owner, ownerId, SignerNeed.MEMBER)
            val t = terms ?: request.termsJson
            owner.execute(custody, persistOn(owner)) { e -> withEntropy(32) { e.beginApprove(request.record, t, signers, it) } }
        }
        reconcile()
    }
    suspend fun revoke(member: String): SessionSnapshot = gated {
        if (engine == null) reconcile()
        withOwner { owner, custody, ownerId ->
            val signers = signers(owner, ownerId, SignerNeed.CONTROL)
            owner.execute(custody, persistOn(owner)) { e -> withEntropy(32) { e.beginRevoke(member, RevokeKeep(KeepMode.EVERYTHING, listOf(), listOf()), signers, it) } }
        }
        reconcile()
    }
    /** The removal follow-up's one action (§17.5): revokes the members and removes the controllers a removed key admitted. */
    suspend fun removeFollowUp(seq: ULong): SessionSnapshot = gated {
        if (engine == null) reconcile()
        withOwner { owner, custody, ownerId ->
            val follow = owner.run { it.removalFollowUp() }.firstOrNull { it.seq == seq } ?: return@withOwner
            for (member in follow.members) {
                val signers = signers(owner, ownerId, SignerNeed.CONTROL)
                owner.execute(custody, persistOn(owner)) { e -> withEntropy(32) { e.beginRevoke(member, RevokeKeep(KeepMode.EVERYTHING, listOf(), listOf()), signers, it) } }
            }
            if (follow.controllers.isNotEmpty()) {
                val signers = signers(owner, ownerId, SignerNeed.CONTROL)
                owner.execute(custody, persistOn(owner)) { e -> withEntropy(32) { e.beginRemoveController(follow.controllers, listOf(), signers, RuleKind.CONTROL, false, it) } }
            }
        }
        loadJournal()
        journal.answeredRemovals = journal.answeredRemovals + seq; saveJournal()
        reconcile()
    }
    suspend fun keepFollowUp(seq: ULong): SessionSnapshot = gated {
        loadJournal()
        journal.answeredRemovals = journal.answeredRemovals + seq; saveJournal()
        reconcile()
    }
    /** Signs a veto of the pending transition with the keys this device holds and stores it; the next exchange submits it. */
    suspend fun veto(transition: String): SessionSnapshot = gated {
        if (engine == null) reconcile()
        withOwner { owner, custody, ownerId ->
            val signers = signers(owner, ownerId, SignerNeed.VETO)
            owner.execute(custody, persistOn(owner)) { it.beginVeto(transition, signers, ByteArray(0)) }
        }
        reconcile()
    }
    /** Adds a controller key (a second device, a passkey, a security key); the new key signs its own possession proof. */
    suspend fun addController(spec: ControllerSpec, mode: AddMode, possession: AsyncKeyProvider): SessionSnapshot = gated {
        if (engine == null) reconcile()
        withOwner { owner, ownerCustody, ownerId ->
            val custody = ownerCustody.merging(accountKeyId(spec.key.signing), SessionKeys(possession))
            val signers = signers(owner, ownerId, SignerNeed.CONTROL)
            owner.execute(custody, persistOn(owner)) { it.beginAddController(spec, mode, signers, RuleKind.CONTROL, ByteArray(0)) }
        }
        reconcile()
    }
    /** The existing device's half of seed transfer: seals the vault seed to the device that confirmed `pairing`. */
    suspend fun transferSeed(pairing: AccountPairing): SealedSeed = gated {
        if (engine == null) reconcile()
        withOwner { owner, _, _ -> owner.run { e -> withEntropy(32) { e.transferSeed(pairing, it) } } }
    }
    /** The new device's half: takes the seed and builds this controller's own slot so it unlocks alone from now on. */
    suspend fun acceptSeedTransfer(key: PairingTransferKey, pairing: AccountPairing, sealed: SealedSeed, label: String): SessionSnapshot = gated {
        loadJournal()
        val account = accountId ?: journal.account ?: try { discoverAccount(storage().listing()) } catch (_: Exception) { null } ?: throw SessionError.NotReady()
        accountId = account
        val custody = ownerCustody()
        val ownerId = KeyCustody.keyId(configuration.ownerController)
        val owner = tracked(configuration.deviceSecrets.key(account).use { secret ->
            ColophonEngine.open(label = "colophon-owner", source = MediumSource(storage()), listing = listed(storage().listing()),
                identity = AccountIdentity(AccountIdentityKind.CONTROLLER, ownerId), account = account,
                namespaces = configuration.libraryNamespaces, saved = null, deviceKey = secret, nowMs = nowMs)
        })
        try {
            owner.run { it.acceptSeedTransfer(key, pairing, sealed) }
            owner.run { it.load() }
            val written = owner.execute(custody, persistOn(owner)) { e -> withEntropy(32) { e.beginAddSlot(ownerId, SlotPlan(listOf(ownerId), label), it) } }
        } finally {
            release(owner)
        }
        reconcile()
    }

    // Create

    suspend fun create(): SessionSnapshot = gated {
        loadJournal()
        if (engine != null || journal.account != null || storage().listing().any { it.path.startsWith("authority/") }) throw SessionError.DestinationChanged()
        if (configuration.homes.isEmpty() && !configuration.createWithoutHome) throw SessionError.NoHome()
        if (!configuration.homes.all { it.isAllowed }) throw SessionError.InsecureHome()
        journal.left = false
        var custody = ownerCustody()
        val ownerKey = configuration.ownerController.keyDescriptor()
        val ownerId = accountKeyId(ownerKey.signing)
        val controllers = mutableListOf(ControllerSpec(ownerKey, "Owner", listOf(ControllerRole.APPROVE, ControllerRole.CONTROL, ControllerRole.RECOVER),
            ownerKey.form == SignForm.WEBAUTHN, null, listOf()))
        val slots = mutableListOf(SlotPlan(listOf(ownerId), "Owner"))
        configuration.recoveryKeys?.let { kit ->
            val d = kit.keyDescriptor(); val kitId = accountKeyId(d.signing)
            controllers.add(ControllerSpec(d, "Recovery kit", listOf(ControllerRole.RECOVER), d.form == SignForm.WEBAUTHN, null, listOf()))
            slots.add(SlotPlan(listOf(kitId), "Recovery kit"))
        }
        for (extra in configuration.additionalControllers) {
            val d = extra.provider.keyDescriptor(); val id = accountKeyId(d.signing)
            controllers.add(ControllerSpec(d, extra.label, extra.roles, d.form == SignForm.WEBAUTHN, null, listOf()))
            slots.add(SlotPlan(listOf(id), extra.label))
            custody = custody.merging(id, SessionKeys(extra.provider))
        }
        @Suppress("UNCHECKED_CAST")
        val policy = (Json.obj(accountDefaultPolicy()) ?: mapOf()).toMutableMap()
        configuration.recoveryDelay?.let { policy["recoveryDelay"] = it }
        configuration.history?.let { policy["history"] = it.wire }
        configuration.headQuorum?.let { policy["headQuorum"] = it }
        val params = CreateParams(configuration.memberLabel, configuration.libraryNamespaces.sorted(), controllers, slots, null, null, null, false,
            Json.write(policy), listOf(ownerId), listOf(ownerId))
        val (creation, created) = AccountCreator.create(params, AccountIdentity(AccountIdentityKind.CONTROLLER, ownerId), custody, nowMs)
        creation.use {
            storage().write(created.stores.map { MediumWrite(it.path, it.bytes) })
            journal.account = created.account; accountId = created.account
            saveJournal()
            // The creation's own engine: unlocked as the creation left it, so the owner is asked once at first run.
            val owner = tracked(configuration.deviceSecrets.key(created.account).use { key ->
                ColophonEngine.openCreated(creation, label = "colophon-owner", source = MediumSource(storage()), listing = listed(storage().listing()),
                    account = created.account, identity = AccountIdentity(AccountIdentityKind.CONTROLLER, ownerId),
                    namespaces = configuration.libraryNamespaces, deviceKey = key, nowMs = nowMs)
            })
            setUpFirstDevice(owner, created.account, ownerId, custody)
        }
        reconcile()
    }

    /** Appoints the homes in one transition recorded at once, and approves this device's member, with the creation's own engine. */
    private suspend fun setUpFirstDevice(owner: ColophonEngine, account: String, ownerId: String, custody: KeyCustody) {
        try {
            val appoint = ArrayList<Map<String, Any?>>()
            for (home in configuration.homes) {
                val makeRequest = home.request ?: continue
                val raw = makeRequest(account)
                val info = accountRequestInfo(raw)
                appoint.add(mapOf("request" to Base64.getEncoder().encodeToString(raw), "terms" to Json.parse(info.termsJson)))
            }
            if (appoint.isNotEmpty()) {
                val change = Json.write(mapOf("homes" to mapOf("appoint" to appoint)))
                val signers = signers(owner, ownerId, SignerNeed.CONTROL)
                owner.execute(custody, persistOn(owner)) { it.beginTransition(change, signers, RuleKind.CONTROL, ByteArray(0)) }
                withContext(NonCancellable) { for (due in owner.run { it.recordDue() }) persist(due, owner) }
            }
            memberId = KeyCustody.keyId(memberKeys)
            accountId = account
            val memberRaw = ownRequestBytes()
            val terms = terms(configuration.namespaces, configuration.access, null, null)
            val signers = signers(owner, ownerId, SignerNeed.MEMBER)
            owner.execute(custody, persistOn(owner)) { e -> withEntropy(32) { e.beginApprove(memberRaw, terms, signers, it) } }
        } finally {
            release(owner)
        }
    }

    // Leave and rejoin

    suspend fun leave() = gated {
        loadJournal()
        engine?.lock(); engine = null
        journal.left = true; saveJournal()
    }
    suspend fun rejoin(keys: AsyncKeyProvider): SessionSnapshot = gated {
        loadJournal()
        engine?.lock(); engine = null; memberOpened = false
        memberKeys = SessionKeys(keys); memberCustody = null
        journal.left = false; saveJournal()
        reconcile()
    }

    // Writes and queries

    suspend fun write(command: DomainCommand, observed: Long): Pair<WriteReceipt, SessionSnapshot> = gated {
        val fresh = reconcile()
        val engine = engine; val custody = memberCustody
        if (fresh.phase != SessionPhase.Ready || engine == null || custody == null) throw SessionRefusal(fresh, SessionError.NotReady())
        if (observed != revision) throw SessionRefusal(fresh, SessionError.StaleRevision())
        if (command.namespace !in configuration.namespaces || AccessKind.WRITE !in configuration.access) throw SessionError.InvalidCommand()
        val ceiling = if (command.kind == "colophon.blobPublish") 1024 * 1024 else 256 * 1024
        if (command.payloadJson.toByteArray(Charsets.UTF_8).size > ceiling) throw SessionError.InvalidCommand()
        val written = engine.execute(custody, persistOn(null)) { e -> withEntropy(32) { e.beginWrite(command.namespace, command.kind, command.payloadJson, it) } }
        WriteReceipt.Saved(operationId(written.stores) ?: "") to build()
    }

    suspend fun query(namespace: String, name: String, argumentsJson: String): String = onLane {
        val engine = engine ?: throw SessionError.NotReady()
        queryResult(engine.run { it.queryJson(namespace, name, argumentsJson) })
    }
    /** The namespace's whole fold as the engine reports it (`view_json`), unchanged. */
    suspend fun view(namespace: String): String = onLane {
        val engine = engine ?: throw SessionError.NotReady()
        engine.run { it.viewJson(namespace) }
    }
    suspend fun ledger(): String = onLane { (engine ?: throw SessionError.NotReady()).run { it.ledgerJson() } }

    // Exchange

    private fun transportFor(home: Home): HomeConfiguration? =
        configuration.homes.firstOrNull { configured -> home.endpoints.any { it.trim('/') == configured.endpoint.trim('/') } }

    class ExchangeResult(var passes: Int = 0, val faults: MutableList<HomeFault> = ArrayList(), val issues: MutableList<HomeIssue> = ArrayList(),
                         var changed: Boolean = false, var unauthorized: Boolean = false)

    /**
     * One exchange with every home. The network calls run outside the gate; each engine step and the persistence of
     * its stores run inside it, so an unpersisted answer is never visible to a refresh. A home is held to [HomeLimits].
     */
    suspend fun exchange(): ExchangeResult = onLane {
        gated { if (engine == null) reconcile() }
        val result = ExchangeResult()
        val engine = engine ?: return@onLane result
        val homes = engine.run { it.exchangeHomes() }
        for (home in homes) {
            val configured = transportFor(home) ?: continue
            if (!configured.isAllowed) { result.issues.add(HomeIssue(home.id, HomeProblem.InsecureEndpoint(configured.endpoint))); continue }
            configured.bearerToken?.let { token -> engine.run { it.exchangeSetBearer(home.id, token) } }
            // The pass starts from fresh local state.
            gated {
                val list = listed(storage().listing()); val at = nowMs
                engine.run { it.advance(at) }
                engine.run { it.refresh(list) }
                unlockIfPossible()
            }
            val started = System.nanoTime()
            var progress = true
            var passIndex = 0
            var stopped: HomeProblem? = null
            var recovered = false
            try {
            // A pass can end before everything moved (the engine plans the next stage from what the home just said):
            // run passes until one moves nothing, at most HomeLimits.PASSES.
            homeLoop@ while (progress && passIndex < HomeLimits.PASSES) {
                progress = false; passIndex++
                var steps = 0
                while (true) {
                    steps++
                    currentCoroutineContext().ensureActive()
                    if (steps > HomeLimits.STEPS_PER_PASS) { stopped = HomeProblem.TooManySteps(HomeLimits.STEPS_PER_PASS); break@homeLoop }
                    if ((System.nanoTime() - started) / 1_000_000 > exchangeTimeMs) { stopped = HomeProblem.TooSlow((exchangeTimeMs / 1000).toInt()); break@homeLoop }
                    val step = gated { engine.run { it.exchangeNext(home.id) } }
                    when (step.kind) {
                        ExchangeStepKind.DONE -> break
                        // This loop answers every request it is given, so an outstanding one belongs to a pass that was
                        // interrupted (a cancelled caller): abandon it and run the pass again, once.
                        ExchangeStepKind.WAITING -> { abortPass(engine, home.id); if (!recovered) { recovered = true; progress = true }; break }
                        ExchangeStepKind.NEED_CALL -> {
                            val need = step.need ?: break
                            try { provideCall(need, home, configured) } catch (e: HomeProblemException) { stopped = e.problem; break@homeLoop }
                        }
                        ExchangeStepKind.REQUEST -> {
                            val request = step.request ?: break
                            // A request is for this home, except another home's public head (headQuorum above 1), which
                            // goes to the transport configured for the home its URL names, with no credential.
                            val target: HomeConfiguration = if (request.url.startsWith(base(configured.endpoint) + "/")) configured else {
                                val other = configuration.homes.firstOrNull { request.url == base(it.endpoint) + "/head" }
                                if (request.method == HttpMethod.GET && request.url.endsWith("/head") &&
                                    request.headers.none { it.name.equals("authorization", ignoreCase = true) } && other != null && other.isAllowed) other
                                else { stopped = HomeProblem.CallNotBound("a request for another host than the configured home"); break@homeLoop }
                            }
                            if (request.method != HttpMethod.GET) progress = true
                            // The exchange deadline covers the transport: a home that does not answer in the time left ends the pass.
                            val left = exchangeTimeMs - (System.nanoTime() - started) / 1_000_000
                            val sent: HttpAnswer? = try {
                                withTimeoutOrNull(maxOf(1L, left)) { target.transport.send(request) }
                            } catch (e: HomeTransportException.ResponseTooLarge) { stopped = HomeProblem.ResponseTooLarge(e.limit); break@homeLoop
                            } catch (e: HomeTransportException.InsecureEndpoint) { stopped = HomeProblem.InsecureEndpoint(e.url); break@homeLoop }
                            val answer: HttpAnswer = sent ?: run { stopped = HomeProblem.TooSlow((exchangeTimeMs / 1000).toInt()); break@homeLoop }
                            val limit = HomeLimits.responseBytes(request.url)
                            if (answer.body.size > limit) { stopped = HomeProblem.ResponseTooLarge(limit); break@homeLoop }
                            // The answer and the persistence of its stores are one step: never abandoned half way.
                            val report: Report = gated {
                                withContext(NonCancellable) {
                                    val report = engine.run { it.exchangeAnswer(home.id, request.ticket, answer) }
                                    persist(report.store)
                                    report
                                }
                            }
                            for (fault in report.faults) {
                                result.faults.add(HomeFault(home.id, fault))
                                if (fault.kind == ExchangeFaultKind.UNAUTHORIZED) result.unauthorized = true
                            }
                            if (report.store.isNotEmpty() || report.changes.authorityToSeq != report.changes.authorityFromSeq || report.changes.namespaces.isNotEmpty()) {
                                result.changed = true; progress = true
                            }
                            // The core's Unauthorized fault discards the result code. A home's claim about our
                            // signed call is shown, but only verified records can deny local access or alter keys.
                            if (answer.status == 403u && request.home == home.id &&
                                request.headers.any { it.name.equals("authorization", ignoreCase = true) && it.value.startsWith("Colophon ") } &&
                                Json.obj(answer.body.toString(Charsets.UTF_8))?.string("result") == "refused:revoked") {
                                stopped = HomeProblem.RemoteCallRefused("refused:revoked")
                                result.unauthorized = true
                                break@homeLoop
                            }
                        }
                    }
                }
                result.passes++
            }
            } catch (e: Throwable) {
                // A transport failure, an engine error or a cancelled caller: the request in flight is forgotten, what was
                // pulled and verified is kept, and the next pass starts clean. This runs even when the caller was cancelled.
                abortPass(engine, home.id)
                throw e
            }
            stopped?.let { problem ->
                result.issues.add(HomeIssue(home.id, problem))
                abortPass(engine, home.id)
            }
        }
        result
    }

    private suspend fun abortPass(engine: ColophonEngine, home: String) = withContext(NonCancellable) {
        gated { persist(engine.run { it.exchangeAbort(home) }.store) }
    }

    private fun base(text: String) = if (text.endsWith("/")) text.dropLast(1) else text

    /**
     * The call a `NeedCall` asked for, built by the engine for exactly the request it will send, signed by this
     * device's member key and judged by the core with the home's own rule before it is returned. A need for another
     * home or audience is not signed (`CallNotBound`); a call the core's own check refuses is `CallRefused`.
     */
    private suspend fun provideCall(need: CallNeed, home: Home, configured: HomeConfiguration) {
        val engine = engine; val custody = memberCustody; val id = memberId
        if (engine == null || custody == null || id == null) throw SessionError.NotReady()
        if (need.home != home.id || base(need.audience) != base(configured.endpoint) || need.url != base(need.audience) + need.path) {
            throw HomeProblemException(HomeProblem.CallNotBound("the engine asked a call for another home than the configured one"))
        }
        val signing = custody.provider(id).publicKeys().signing
        val written = try {
            gated { engine.execute(custody) { e -> withEntropy(32) { e.exchangeBeginCall(need.home, need.ticket, signing, it) } } }
        } catch (e: AccountException) {
            when (e) {
                is AccountException.Refused, is AccountException.Unavailable, is AccountException.Denied -> throw HomeProblemException(HomeProblem.CallRefused(e.code))
                else -> throw e
            }
        }
        val artifact = written.artifact ?: throw AccountException.Internal("internal", "a call returned no envelope")
        gated { engine.run { it.exchangeProvideCall(need.home, need.ticket, artifact) } }
    }

    /** Records transitions that came due (§8.7). A schedule calls it; refresh calls it too. */
    suspend fun recordDue(): SessionSnapshot = gated {
        val engine = engine ?: return@gated reconcile()
        val at = nowMs
        engine.run { it.advance(at) }
        withContext(NonCancellable) { for (written in engine.run { it.recordDue() }) persist(written) }
        build()
    }
    /** How many homes hold a verified receipt for `object`, and how many the account names. */
    suspend fun receipts(obj: String): Pair<Int, Int> = onLane {
        val engine = engine ?: throw SessionError.NotReady()
        engine.run { it.receiptedBy(obj) }.size to engine.run { it.exchangeHomes() }.size
    }

    // Test hooks
    internal fun engineForTests(): ColophonEngine? = engine
    /** The longest one exchange with one home may take (tests shorten it). */
    internal var exchangeTimeMs: Long = HomeLimits.EXCHANGE_TIME_MS

    // Engine access for blobs

    fun requireEngine(): ColophonEngine = engine ?: throw SessionError.NotReady()
    fun requireCustody(): KeyCustody = memberCustody ?: throw SessionError.NotReady()
    suspend fun persistStores(stores: List<Store>) = persist(stores)
    suspend fun <T> inGate(body: suspend () -> T): T = gated(body)
    suspend fun currentSnapshot(): SessionSnapshot = gated { build() }

    companion object {
        fun terms(namespaces: List<String>, access: Set<AccessKind>, expires: String?, budget: ULong?): String {
            val terms = LinkedHashMap<String, Any?>()
            terms["records"] = namespaces.sorted().map { mapOf("namespace" to it, "access" to if (AccessKind.WRITE in access) "write" else "read") }
            expires?.let { terms["expires"] = it }
            budget?.let { terms["writes"] = it }
            return Json.write(terms)
        }
        /** The digest an object's store path names (`transitions/<digest>.json`). */
        fun objectDigest(stores: List<Store>, prefix: String): String? {
            for (s in stores) {
                if (prefix.isNotEmpty() && !s.path.startsWith(prefix)) continue
                val name = s.path.substringAfterLast('/').removeSuffix(".json")
                if (name.length == 64 && name.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) return name
            }
            return null
        }
        /** `ops/<author>/<namespace>/<clock>-<id>.json`: the operation ID is the part after the clock. */
        fun operationId(stores: List<Store>): String? {
            for (s in stores) {
                if (!s.path.startsWith("ops/")) continue
                val name = s.path.substringAfterLast('/').removeSuffix(".json")
                val dash = name.indexOf('-')
                if (dash >= 0) return name.substring(dash + 1)
            }
            return null
        }
        /** The engine's `{"ok":true,"value":X}` outcome as the value's JSON, or `{"ok":false,"reason":...}`. */
        fun queryResult(text: String): String {
            val obj = Json.obj(text) ?: return text
            if (obj["ok"] == true && obj.containsKey("value")) return Json.write(obj["value"])
            val reason = obj.string("reason") ?: "unavailable"
            val known = setOf("notFound", "deleted", "notGranted", "unavailable", "invalidArgument", "staleCursor", "contentTooLarge")
            return Json.write(mapOf("ok" to false, "reason" to if (reason in known) reason else "unavailable"))
        }
    }
}

/** Drives `AccountCreation` through its stages with the host's key custody. */
internal object AccountCreator {
    suspend fun create(params: CreateParams, identity: AccountIdentity, custody: KeyCustody, nowMs: Long): Pair<AccountCreation, Created> {
        val creation = withEntropy(96) { AccountCreation.begin(params, identity, nowMs, it) }
        try {
            val requests = creation.prfRequests()
            if (requests.isNotEmpty()) {
                val answers = custody.answer(requests)
                answers.withRecords { creation.providePrf(it) }
            }
            repeat(8) {
                if (creation.provideSignatures(custody.sign(creation.steps())) == CreateStage.DONE) return creation to creation.takeResult()
            }
            throw AccountException.Internal("internal", "the creation did not finish")
        } catch (e: Throwable) {
            creation.close()
            throw e
        }
    }
}
