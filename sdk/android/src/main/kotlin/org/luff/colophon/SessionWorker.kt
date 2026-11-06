package org.luff.colophon

import com.luff.colophon.Access
import com.luff.colophon.DenialReason
import com.luff.colophon.GrantOptions
import com.luff.colophon.KeyProvider
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.File

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

    private fun storage(): RecordStore {
        store?.let { return it }
        val folder = File(configuration.privateHome, "library")
        val created = FileRecordStore(folder)
        store = created
        return created
    }

    fun watch(onChange: () -> Unit): AutoCloseable = storage().watch(onChange)

    private fun loadJournal() {
        if (!loaded) {
            journal = SessionJournal.load(journalFile)
            loaded = true
        }
    }

    suspend fun restore(): SessionSnapshot = mutex.withLock {
        loadJournal()
        if (journal.left) return empty(SessionPhase.NoLibrary)
        refreshLocked()
    }

    suspend fun refresh(): SessionSnapshot = mutex.withLock {
        loadJournal()
        if (journal.left) return empty(SessionPhase.NoLibrary)
        refreshLocked()
    }

    private fun refreshLocked(): SessionSnapshot {
        val records = storage().read()
        val available = records.keys + journal.pending.keys
        if (!journal.knownPaths.all { it in available }) {
            throw StorageException.Unavailable("Previously observed library records are unavailable")
        }
        if (records.isEmpty() && journal.pending.isEmpty()) {
            if (journal.libraryID != null) throw StorageException.Unavailable("Selected library is unavailable")
            return empty(SessionPhase.NoLibrary)
        }
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
        journal.libraryID = snapshot.libraryID
        if (journal.pending.isNotEmpty()) publish()
        if (snapshot.me.since == 0uL) {
            val existing = snapshot.requests.firstOrNull { it.id == snapshot.me.id }
            val request = existing ?: run {
                val created = core.request(configuration, keys)
                core.merge(mapOf("requests/${created.id}.json" to created.record))
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

    private fun remember(snapshot: CoreSnapshot) {
        journal.knownPaths.addAll(snapshot.records.keys)
        journal.save(journalFile)
    }

    suspend fun create(): SessionSnapshot = mutex.withLock {
        loadJournal()
        if (opened || journal.libraryID != null || storage().read().isNotEmpty()) {
            throw SessionException.DestinationChanged
        }
        core.create(configuration)
        opened = true
        journal.left = false
        journal.libraryID = core.snapshot(configuration.namespaces).libraryID
        persistDelta()
        refreshLocked()
    }

    suspend fun write(command: DomainCommand, observed: ULong): Pair<WriteReceipt, SessionSnapshot> = mutex.withLock {
        val fresh = refreshLocked()
        if (fresh.phase != SessionPhase.Ready) throw SessionRefusal(fresh, SessionException.NotReady)
        if (observed != revision) throw SessionRefusal(fresh, SessionException.StaleRevision)
        if (command.namespace !in configuration.namespaces || Access.WRITE !in configuration.access) {
            throw SessionException.InvalidCommand
        }
        if (command.payload.size > 256 * 1024) throw SessionException.InvalidCommand
        val operation = try {
            core.write(command)
        } catch (error: Exception) {
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
        refreshLocked()
        try {
            core.approve(request, grant)
        } catch (error: Exception) {
            persistDelta()
            throw error
        }
        persistDelta()
        refreshLocked()
    }

    suspend fun revoke(memberID: String): SessionSnapshot = mutex.withLock {
        refreshLocked()
        try {
            core.revoke(memberID)
        } catch (error: Exception) {
            persistDelta()
            throw error
        }
        persistDelta()
        refreshLocked()
    }

    suspend fun leave() = mutex.withLock {
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
        loadJournal()
        if (journal.pending.isNotEmpty()) {
            throw StorageException.Unavailable("Retry pending publication before rejoining")
        }
        this.keys = keys
        opened = false
        last = null
        journal.left = false
        journal.save(journalFile)
        core.close()
        refreshLocked()
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
