package org.luff.colophon

import com.luff.colophon.Access
import com.luff.colophon.BindingException
import com.luff.colophon.DenialReason
import com.luff.colophon.GrantOptions
import com.luff.colophon.KeyProvider
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.File
import java.util.concurrent.CancellationException

/**
 * All filesystem, FFI, projections and signing run off the main thread. The mutex serializes
 * complete operations, including signing and durable publication.
 */
internal class SessionWorker(
    val configuration: SessionConfiguration,
    private val core: SessionCore = BindingSessionCore(),
    store: RecordStore? = configuration.store,
) {
    @Volatile private var keys: KeyProvider = configuration.keys
    private var store: RecordStore? = store
    private var journal = SessionJournal()
    private var loaded = false
    private var opened = false
    private var last: CoreSnapshot? = null
    private var revision: ULong = 0u
    private var namespaceRevisions: MutableMap<String, ULong> = mutableMapOf()
    private val mutex = Mutex()
    private val journalFile: File = File(configuration.privateHome, "session.json")
    private var acceptNewIdentity = false
    @Volatile private var closed = false
    @Volatile private var relaySync: RelaySync? = null

    private fun storage(): RecordStore {
        store?.let { return it }
        val folder = File(configuration.privateHome, "library")
        val created = FileRecordStore(folder)
        store = created
        return created
    }

    fun watch(onChange: () -> Unit): AutoCloseable = storage().watch(onChange)

    @Synchronized private fun relay(): RelaySync? {
        relaySync?.let { return it }
        val relay = configuration.relay ?: return null
        return RelaySync(storage(), relay.endpoint, relay.transport, File(configuration.privateHome, "relay.json"))
            .also { relaySync = it }
    }

    /**
     * One relay pass outside the session mutex (blocking; call on an IO thread). The relay only
     * appends digest-verified records to local storage; the session then refreshes them through
     * the normal merge, exactly like another writer's files.
     */
    fun syncRelay(): RelaySync.Report? = relay()?.sync()

    fun waitForRemoteChanges(seconds: Int): Boolean = relay()?.waitForRemoteChanges(seconds) ?: false

    /** An empty local store is not an empty library while a configured relay has not been listed. */
    private fun pullBeforeTrustingEmpty() {
        val relay = relay() ?: return
        try {
            relay.sync()
        } catch (error: RelayException) {
            throw StorageException.Unavailable("Waiting for the relay before opening this library. ${error.message}")
        }
    }

    private fun loadJournal() {
        if (!loaded) {
            journal = SessionJournal.load(journalFile)
            loaded = true
        }
    }

    suspend fun restore(): SessionSnapshot = mutex.withLock {
        ensureUsable()
        loadJournal()
        if (journal.left) return empty(SessionPhase.NoLibrary)
        refreshLocked()
    }

    suspend fun refresh(): SessionSnapshot = mutex.withLock {
        ensureUsable()
        loadJournal()
        if (journal.left) return empty(SessionPhase.NoLibrary)
        refreshLocked()
    }

    private fun refreshLocked(): SessionSnapshot {
        var records = storage().read()
        if (records.isEmpty() && journal.pending.isEmpty() && configuration.relay != null) {
            pullBeforeTrustingEmpty()
            records = storage().read()
        }
        val available = records.keys + journal.pending.keys
        if (!journal.knownPaths.all { it in available }) {
            throw StorageException.Unavailable("Previously observed library records are unavailable")
        }
        if (records.isEmpty() && journal.pending.isEmpty()) {
            if (journal.libraryID != null) throw StorageException.Unavailable("Selected library is unavailable")
            return empty(SessionPhase.NoLibrary)
        }
        ensureIdentity()
        val combined = records.toMutableMap()
        for ((path, data) in journal.pending) {
            val old = combined[path]
            if (old != null && !old.contentEquals(data)) throw StorageException.Conflict(path)
            combined[path] = data
        }
        if (opened) core.merge(combined) else {
            core.open(combined, keys)
            opened = true
        }
        var snapshot = core.snapshot(configuration.namespaces)
        if (journal.libraryID != null && journal.libraryID != snapshot.libraryID) {
            throw SessionException.DestinationChanged
        }
        if (!acceptNewIdentity && journal.memberID != null && journal.memberID != snapshot.me.id) {
            opened = false
            core.close()
            throw BindingException.KeyProvider("Key provider does not match the selected member")
        }
        journal.libraryID = snapshot.libraryID
        if (journal.pending.isNotEmpty()) publish()
        if (snapshot.me.since == 0uL) {
            val existing = snapshot.requests.firstOrNull { it.id == snapshot.me.id }
            val request = existing ?: run {
                val created = core.request(configuration, keys)
                core.merge(mapOf("requests/${created.id}.json" to created.record))
                snapshot = core.snapshot(configuration.namespaces)
                // Identity is part of the journal write that queues the request. persistDelta
                // saves before publish; recording it afterwards leaves session.json anonymous
                // when publication throws.
                recordIdentity(snapshot)
                persistDelta()
                snapshot = core.snapshot(configuration.namespaces)
                created
            }
            remember(snapshot)
            return makeSnapshot(snapshot, SessionPhase.WaitingForApproval(request.pairingCode))
        }
        remember(snapshot)
        val phase = when {
            snapshot.me.revokedAt != null -> SessionPhase.Denied
            snapshot.denials.values.any { it.reason == DenialReason.UNAVAILABLE || it.reason == DenialReason.NOT_READABLE } ->
                SessionPhase.Unavailable("Namespace keys or records are not available")
            snapshot.denials.isNotEmpty() -> SessionPhase.Denied
            else -> SessionPhase.Ready
        }
        return makeSnapshot(snapshot, phase)
    }

    private fun ensureIdentity() {
        if (acceptNewIdentity) return
        val expectedSigning = journal.signingPublicKey ?: return
        val expectedAgreement = journal.agreementPublicKey
        val signing = keys.signingPublicKey()
        val agreement = keys.agreementPublicKey()
        if (expectedAgreement == null || !expectedSigning.contentEquals(signing) || !expectedAgreement.contentEquals(agreement)) {
            throw BindingException.KeyProvider("Key provider does not match the selected library identity")
        }
    }

    /** Public keys and member id only. Does not mark records known or touch disk. */
    private fun recordIdentity(snapshot: CoreSnapshot) {
        if (acceptNewIdentity || journal.signingPublicKey == null) {
            journal.signingPublicKey = keys.signingPublicKey().copyOf()
            journal.agreementPublicKey = keys.agreementPublicKey().copyOf()
            journal.memberID = snapshot.me.id
        } else if (journal.memberID == null) {
            journal.memberID = snapshot.me.id
        }
    }

    private fun remember(snapshot: CoreSnapshot) {
        journal.knownPaths.addAll(snapshot.records.keys)
        recordIdentity(snapshot)
        journal.save(journalFile)
    }

    suspend fun create(): SessionSnapshot = mutex.withLock {
        ensureUsable()
        loadJournal()
        if (configuration.relay != null && !opened && journal.libraryID == null && storage().read().isEmpty()) {
            pullBeforeTrustingEmpty()
            // The relay already holds a library for this slot: join it instead of forking it.
            if (storage().read().isNotEmpty()) return refreshLocked()
        }
        if (opened || journal.libraryID != null || storage().read().isNotEmpty()) {
            throw SessionException.DestinationChanged
        }
        core.create(configuration)
        opened = true
        journal.left = false
        val created = core.snapshot(configuration.namespaces)
        journal.libraryID = created.libraryID
        // persistDelta writes session.json before publication. The identity has to be in
        // that write, or a lost key file on the next open looks like a brand-new member.
        recordIdentity(created)
        persistDelta()
        refreshLocked()
    }

    suspend fun write(command: DomainCommand, observed: ULong): Pair<WriteReceipt, SessionSnapshot> = mutex.withLock {
        ensureUsable()
        val fresh = refreshLocked()
        if (fresh.phase != SessionPhase.Ready) throw SessionRefusal(fresh, SessionException.NotReady())
        if (observed != revision) throw SessionRefusal(fresh, SessionException.StaleRevision)
        if (command.namespace !in configuration.namespaces || Access.WRITE !in configuration.access) {
            throw SessionException.InvalidCommand
        }
        if (command.payload.size > 256 * 1024) throw SessionException.InvalidCommand
        val operation = try {
            core.write(command)
        } catch (error: Exception) {
            if (error is CancellationException || error is SessionException.NotReady) throw error
            val after = core.records()
            val added = after.keys.filter { it.startsWith("ops/") && fresh.core?.records?.get(it) == null }
            if (added.isNotEmpty()) {
                try {
                    persistDelta()
                } catch (_: PendingPublication) {
                }
                return WriteReceipt.Queued to empty(
                    SessionPhase.Unavailable("Committed write awaits confirmation; refresh to retry publication"),
                )
            }
            persistDelta()
            throw error
        }
        try {
            persistDelta()
        } catch (_: PendingPublication) {
            return WriteReceipt.Queued to empty(SessionPhase.Unavailable("Write queued for durable publication"))
        }
        WriteReceipt.Saved(operation.id) to refreshLocked()
    }

    private fun persistDelta() {
        val records = core.records()
        for ((path, bytes) in records) {
            if (path !in journal.knownPaths) journal.pending[path] = bytes
        }
        journal.save(journalFile)
        try {
            publish()
        } catch (error: StorageException.Unavailable) {
            throw PendingPublication(error.message ?: "Publication unavailable")
        }
    }

    private fun publish() {
        if (journal.pending.isEmpty()) return
        storage().append(journal.pending)
        val readback = storage().read()
        val published = journal.pending.all { (path, bytes) -> readback[path]?.contentEquals(bytes) == true }
        if (!published) throw StorageException.Unavailable("Publication readback incomplete")
        journal.knownPaths.addAll(journal.pending.keys)
        journal.pending.clear()
        journal.save(journalFile)
    }

    suspend fun approve(request: ByteArray, grant: GrantOptions?): SessionSnapshot = mutex.withLock {
        ensureUsable()
        refreshLocked()
        try {
            core.approve(request, grant)
        } catch (error: Exception) {
            if (error is CancellationException || error is SessionException.NotReady) throw error
            persistDelta()
            throw error
        }
        persistDelta()
        refreshLocked()
    }

    suspend fun revoke(memberID: String): SessionSnapshot = mutex.withLock {
        ensureUsable()
        refreshLocked()
        try {
            core.revoke(memberID)
        } catch (error: Exception) {
            if (error is CancellationException || error is SessionException.NotReady) throw error
            persistDelta()
            throw error
        }
        persistDelta()
        refreshLocked()
    }

    suspend fun leave() = mutex.withLock {
        ensureUsable()
        loadJournal()
        if (journal.pending.isNotEmpty()) {
            throw StorageException.Unavailable("Retry pending publication before leaving")
        }
        journal.left = true
        journal.save(journalFile)
        opened = false
        last = null
        core.close()
    }

    suspend fun rejoin(keys: KeyProvider): SessionSnapshot = mutex.withLock {
        ensureUsable()
        loadJournal()
        if (journal.pending.isNotEmpty()) {
            throw StorageException.Unavailable("Retry pending publication before rejoining")
        }
        // A provider failure must surface before the live core is closed or the identity switches.
        val signing = keys.signingPublicKey()
        val agreement = keys.agreementPublicKey()
        if (signing.isEmpty() || agreement.isEmpty()) {
            throw BindingException.KeyProvider("Key provider returned no public key")
        }
        val previousKeys = this.keys
        val previousLeft = journal.left
        val previousSigning = journal.signingPublicKey?.copyOf()
        val previousAgreement = journal.agreementPublicKey?.copyOf()
        val previousMember = journal.memberID
        this.keys = keys
        opened = false
        last = null
        journal.left = false
        acceptNewIdentity = true
        core.close()
        try {
            refreshLocked()
        } catch (error: Exception) {
            // The new request is already in the journal. Reverting the provider would
            // leave session.json between the old identity and the queued request.
            if (journal.pending.isEmpty()) {
                this.keys = previousKeys
                journal.left = previousLeft
                journal.signingPublicKey = previousSigning
                journal.agreementPublicKey = previousAgreement
                journal.memberID = previousMember
            }
            opened = false
            last = null
            core.close()
            throw error
        } finally {
            acceptNewIdentity = false
        }
    }

    suspend fun importRequest(data: ByteArray): SessionSnapshot = mutex.withLock {
        ensureUsable()
        refreshLocked()
        core.importRequest(data)
        persistDelta()
        refreshLocked()
    }

    fun markClosed() {
        closed = true
    }

    /** Already on the session thread. Taking the mutex here deadlocks if this stack holds it. */
    fun closeCoreNow() {
        closed = true
        core.close()
        opened = false
        last = null
    }

    suspend fun closeCoreSuspended() {
        mutex.withLock {
            closed = true
            core.close()
            opened = false
            last = null
        }
    }

    private fun ensureUsable() {
        if (closed) throw SessionException.NotReady()
    }

    fun recovery(): KeyProvider? = core.recovery()

    private fun empty(phase: SessionPhase) = SessionSnapshot(phase, null, revision, namespaceRevisions.toMap())

    private fun makeSnapshot(snapshot: CoreSnapshot, phase: SessionPhase): SessionSnapshot {
        val previous = last
        val changed = previous == null ||
            !mapsEqual(previous.records, snapshot.records) ||
            !denialsEqual(previous.denials, snapshot.denials) ||
            configuration.namespaces.any { !viewsEqual(previous.views[it], snapshot.views[it]) }
        if (changed) {
            revision += 1u
            for (namespace in configuration.namespaces) {
                if (!viewsEqual(previous?.views?.get(namespace), snapshot.views[namespace]) ||
                    previous?.denials?.get(namespace) != snapshot.denials[namespace]
                ) {
                    namespaceRevisions[namespace] = (namespaceRevisions[namespace] ?: 0u) + 1u
                }
            }
        }
        last = snapshot
        return SessionSnapshot(phase, snapshot, revision, namespaceRevisions.toMap())
    }
}
