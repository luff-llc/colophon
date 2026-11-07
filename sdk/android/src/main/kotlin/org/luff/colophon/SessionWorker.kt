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
    internal val core: SessionCore = BindingSessionCore(),
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
    internal val mutex = Mutex()
    /** Every record path merged into the open core; storage reads skip these. */
    private val merged = HashSet<String>()
    private val requestPaths = sortedSetOf<String>()
    internal val blobs = SessionBlobEngine(this)
    private val journalFile: File = File(configuration.privateHome, "session.json")
    private var acceptNewIdentity = false
    @Volatile private var closed = false
    @Volatile private var relaySync: RelaySync? = null

    internal fun storage(): RecordStore {
        store?.let { return it }
        val folder = File(configuration.privateHome, "library")
        val created = FileRecordStore(folder)
        store = created
        return created
    }

    fun watch(onChange: () -> Unit): AutoCloseable = storage().watch(onChange)

    @Synchronized internal fun relay(): RelaySync? {
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

    internal fun refreshLocked(): SessionSnapshot {
        val marker = configuration.migrationMarker
        if (!configuration.migrationWriter && marker != null && MigrationMarker.isActive(marker)) {
            return empty(SessionPhase.Migrating)
        }
        var stored = storage().paths()
        if (stored.isEmpty() && journal.pending.isEmpty() && configuration.relay != null) {
            pullBeforeTrustingEmpty()
            stored = storage().paths()
        }
        if (!journal.knownPaths.all { it in stored || it in journal.pending }) {
            throw StorageException.Unavailable("Previously observed library records are unavailable")
        }
        if (stored.isEmpty() && journal.pending.isEmpty()) {
            if (journal.libraryID != null) throw StorageException.Unavailable("Selected library is unavailable")
            return empty(SessionPhase.NoLibrary)
        }
        ensureIdentity()
        // Only records the open core has not seen are read: proportional to the change.
        val fresh = if (opened) stored.filter { it !in merged } else stored.toList()
        val incoming = storage().read(fresh).toMutableMap()
        for ((path, data) in journal.pending) {
            val old = incoming[path]
            if (old != null && !old.contentEquals(data)) throw StorageException.Conflict(path)
            if (!opened || path !in merged) incoming[path] = data
        }
        if (opened) {
            if (incoming.isNotEmpty()) core.merge(incoming)
        } else {
            core.open(incoming, keys)
            opened = true
            merged.clear()
            requestPaths.clear()
        }
        track(incoming.keys)
        var snapshot = snapshot()
        if (journal.libraryID != null && journal.libraryID != snapshot.libraryID) {
            throw SessionException.DestinationChanged
        }
        if (!acceptNewIdentity && journal.memberID != null && journal.memberID != snapshot.me.id) {
            opened = false
            merged.clear()
            core.close()
            throw BindingException.KeyProvider("Key provider does not match the selected member")
        }
        journal.libraryID = snapshot.libraryID
        if (journal.pending.isNotEmpty()) publish()
        if (snapshot.me.since == 0uL) {
            val existing = snapshot.requests.firstOrNull { it.id == snapshot.me.id }
            val request = existing ?: run {
                val created = core.request(configuration, keys)
                val path = "requests/${created.id}.json"
                core.merge(mapOf(path to created.record))
                track(listOf(path))
                snapshot = snapshot()
                // Identity is part of the journal write that queues the request. persistDelta
                // saves before publish; recording it afterwards leaves session.json anonymous
                // when publication throws.
                recordIdentity(snapshot)
                persistDelta(listOf(path))
                snapshot = snapshot()
                created
            }
            remember(snapshot, incoming.keys)
            return makeSnapshot(snapshot, SessionPhase.WaitingForApproval(request.pairingCode))
        }
        remember(snapshot, incoming.keys)
        val phase = when {
            snapshot.me.revokedAt != null -> SessionPhase.Denied
            snapshot.denials.values.any { it.reason == DenialReason.UNAVAILABLE || it.reason == DenialReason.NOT_READABLE } ->
                SessionPhase.Unavailable("Namespace keys or records are not available")
            snapshot.denials.isNotEmpty() -> SessionPhase.Denied
            else -> SessionPhase.Ready
        }
        return makeSnapshot(snapshot, phase)
    }

    private fun track(paths: Collection<String>) {
        merged.addAll(paths)
        for (path in paths) if (path.startsWith("requests/")) requestPaths.add(path)
    }

    /** Copies only `requests/` records out of the core; everything else is tracked by path. */
    private fun snapshot(): CoreSnapshot = core.snapshot(configuration.namespaces, core.recordsAt(requestPaths))

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

    private fun remember(snapshot: CoreSnapshot, observed: Collection<String>) {
        journal.knownPaths.addAll(observed)
        recordIdentity(snapshot)
        journal.save(journalFile)
    }

    suspend fun create(): SessionSnapshot = mutex.withLock {
        ensureUsable()
        loadJournal()
        val marker = configuration.migrationMarker
        if (!configuration.migrationWriter && marker != null && MigrationMarker.isActive(marker)) {
            return empty(SessionPhase.Migrating)
        }
        if (configuration.relay != null && !opened && journal.libraryID == null && storage().paths().isEmpty()) {
            pullBeforeTrustingEmpty()
            // The relay already holds a library for this slot: join it instead of forking it.
            if (storage().paths().isNotEmpty()) return refreshLocked()
        }
        if (opened || journal.libraryID != null || storage().paths().isNotEmpty()) {
            throw SessionException.DestinationChanged
        }
        core.create(configuration)
        opened = true
        merged.clear()
        requestPaths.clear()
        journal.left = false
        val created = core.snapshot(configuration.namespaces, emptyMap())
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
        if (command.kind == IMPORT_BATCH && !configuration.migrationWriter) throw SessionException.InvalidCommand
        val ceiling = if (command.kind == IMPORT_BATCH || command.kind == BLOB_PUBLISH) 1024 * 1024 else 256 * 1024
        if (command.payload.size > ceiling) throw SessionException.InvalidCommand
        val written = mutableListOf<String>()
        val operation = try {
            core.write(command, written)
        } catch (error: Exception) {
            if (error is CancellationException || error is SessionException.NotReady) throw error
            val after = core.records()
            val added = after.keys.filter { it.startsWith("ops/") && it !in merged }
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
            // Only the signed records of this write are copied and persisted.
            persistDelta(written.ifEmpty { null })
        } catch (_: PendingPublication) {
            return WriteReceipt.Queued to empty(SessionPhase.Unavailable("Write queued for durable publication"))
        }
        WriteReceipt.Saved(operation.id) to refreshLocked()
    }

    /**
     * Journals new core records, then publishes them. With [paths], only those records are copied
     * out of the core (ordinary writes); without, the whole map is diffed (rare authority actions).
     */
    private fun persistDelta(paths: Collection<String>? = null) {
        val records = if (paths != null) core.recordsAt(paths.filter { it !in journal.knownPaths }) else core.records()
        for ((path, bytes) in records) {
            if (path !in journal.knownPaths) journal.pending[path] = bytes
        }
        track(journal.pending.keys)
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
        val readback = storage().read(journal.pending.keys)
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
            previous.libraryID != snapshot.libraryID || previous.revision != snapshot.revision ||
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
