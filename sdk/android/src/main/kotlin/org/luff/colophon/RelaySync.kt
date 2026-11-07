package org.luff.colophon

import java.io.File
import java.util.concurrent.Callable
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

sealed class SyncState {
    /** No relay is configured. */
    data object Disabled : SyncState()
    data object Idle : SyncState()
    data object Syncing : SyncState()
    /** The relay is unreachable. Local reads and writes continue; nothing is assumed missing. */
    data class Offline(val reason: String) : SyncState()
    /** The relay refused the storage token. Replace it; sync stops retrying quickly. */
    data object Unauthorized : SyncState()
    data class Error(val reason: String) : SyncState()
}

/**
 * Synchronizes a local record store with one relay slot (spec §8.4). The local store stays the
 * source of truth: the relay only ever adds records to it, and absence on the relay is never
 * deletion. Records are immutable, so listing both sides is enough to reconcile them.
 * Blocking: call it off the main thread.
 */
class RelaySync(
    private val local: RecordStore,
    val endpoint: RelayEndpoint,
    transport: RelayTransport = HttpUrlConnectionTransport(),
    /** Private container, never the shared library. Without it each process relists the slot. */
    private val stateFile: File? = null,
) {
    data class Report(val pulled: Int = 0, val pushed: Int = 0, val conflicts: List<String> = emptyList())

    private val client = RelayClient(endpoint, transport)
    private val lock = ReentrantLock()
    private var loaded = false
    @Volatile private var cursor: String? = null
    private var remote = mutableMapOf<String, String>()
    private val localDigests = mutableMapOf<String, String>()
    @Volatile var hasListed = false
        private set

    /** One complete pass: list, pull what the local store lacks, push what the relay lacks. */
    fun sync(): Report = lock.withLock {
        loadState()
        list()
        val localRecords = local.read().toMutableMap()
        val genesis = "authority/00000001.json"
        val mine = localRecords[genesis]
        val theirs = remote[genesis]
        if (mine != null && theirs != null && digest(genesis, mine) != theirs) throw RelayException.DifferentLibrary()
        var pulled = 0
        var pushed = 0
        val conflicts = mutableListOf<String>()
        val missing = remote.keys.filter { path -> localRecords[path] == null && validRecord(path) }.sortedWith(PULL_ORDER)
        for (batch in missing.chunked(256)) {
            val fetched = parallel(batch) { path -> path to client.get(path) }
                .mapNotNull { (path, bytes) ->
                    // Listed but gone (a withdrawn request, or a racing relay rebuild): skip it.
                    bytes ?: return@mapNotNull null
                    if (sha256Hex(bytes) != remote[path]) {
                        throw RelayException.ProtocolViolation("Record bytes do not match the listed digest: $path")
                    }
                    path to bytes
                }.toMap()
            if (fetched.isNotEmpty()) {
                local.append(fetched)
                localRecords.putAll(fetched)
                pulled += fetched.size
            }
        }
        for ((path, bytes) in localRecords) {
            val listed = remote[path]
            if (listed != null && digest(path, bytes) != listed) conflicts += path
        }
        val unpushed = localRecords.keys.filter { remote[it] == null }.sortedWith(PULL_ORDER)
        for (batch in unpushed.chunked(PARALLELISM)) {
            for ((path, result) in parallel(batch) { path -> path to client.putIfAbsent(path, localRecords.getValue(path)) }) {
                when (result) {
                    RelayClient.PutResult.CREATED -> {
                        pushed += 1
                        remote[path] = digest(path, localRecords.getValue(path))
                    }
                    RelayClient.PutResult.PRESENT -> remote[path] = digest(path, localRecords.getValue(path))
                    RelayClient.PutResult.CONFLICT -> conflicts += path
                }
            }
        }
        saveState()
        Report(pulled, pushed, conflicts.sorted())
    }

    /** Long-polls the change feed after the saved cursor, outside the pass lock. */
    fun waitForRemoteChanges(seconds: Int): Boolean {
        lock.withLock { loadState() }
        val page = client.changes(cursor, limit = 1, wait = seconds.coerceIn(0, 30))
        return page.entries.isNotEmpty()
    }

    private fun list() {
        var restarted = false
        while (true) {
            val page = try {
                client.changes(cursor, limit = 1000)
            } catch (reset: RelayException.CursorReset) {
                if (restarted) throw reset
                // The relay lost or rebuilt its log. Forget what it held and relist from the start.
                restarted = true
                cursor = null
                remote.clear()
                continue
            }
            for (entry in page.entries) {
                if (!validRecord(entry.path) && !validBlob(entry.path)) {
                    throw RelayException.ProtocolViolation("Invalid path in change feed: ${entry.path}")
                }
                if (entry.deleted) {
                    remote.remove(entry.path)
                    continue
                }
                val sha = entry.sha256
                if (sha == null || sha.length != 64) throw RelayException.ProtocolViolation("Entry without digest: ${entry.path}")
                remote[entry.path] = sha
            }
            if (page.cursor == cursor && page.entries.isNotEmpty()) throw RelayException.ProtocolViolation("Cursor did not advance")
            cursor = page.cursor
            if (!page.more) break
        }
        hasListed = true
    }

    private fun <T> parallel(items: List<String>, work: (String) -> T): List<T> {
        if (items.size <= 1) return items.map(work)
        val futures = items.map { item -> pool.submit(Callable { work(item) }) }
        return futures.map { future ->
            try {
                future.get()
            } catch (error: ExecutionException) {
                futures.forEach { it.cancel(true) }
                throw error.cause ?: error
            }
        }
    }

    private fun digest(path: String, bytes: ByteArray): String = localDigests.getOrPut(path) { sha256Hex(bytes) }

    private fun loadState() {
        if (loaded) return
        loaded = true
        val file = stateFile ?: return
        if (!file.exists()) return
        // A corrupt or foreign state file only costs a full relisting.
        try {
            val root = JsonParser(AtomicFile.read(file, AtomicFile.MAX_JOURNAL_BYTES).decodeToString()).parseValue() as Json.Obj
            if (root.string("relay") != endpoint.url) return
            cursor = root.string("cursor")
            remote = root.stringMap("remote").toMutableMap()
        } catch (_: Exception) {
            cursor = null
            remote = mutableMapOf()
        }
    }

    private fun saveState() {
        val file = stateFile ?: return
        val text = buildString {
            append("{\"relay\":").append(jsonString(endpoint.url))
            append(",\"cursor\":").append(cursor?.let { jsonString(it) } ?: "null")
            append(",\"remote\":{")
            remote.keys.sorted().forEachIndexed { index, path ->
                if (index > 0) append(',')
                append(jsonString(path)).append(':').append(jsonString(remote.getValue(path)))
            }
            append("}}")
        }
        AtomicFile.write(text.toByteArray(Charsets.UTF_8), file)
    }

    private companion object {
        const val PARALLELISM = 8
        val pool = Executors.newFixedThreadPool(PARALLELISM) { runnable ->
            Thread(runnable, "colophon-relay").apply { isDaemon = true }
        }
        /** Authority first, then requests, then operations, so a partial pull is most useful. */
        val PULL_ORDER = compareBy<String>({ if (it.startsWith("authority/")) 0 else if (it.startsWith("requests/")) 1 else 2 }, { it })
        fun validRecord(path: String) = try {
            RecordPath.validate(path)
            true
        } catch (_: StorageException) {
            false
        }
        fun validBlob(path: String) = path.length == 70 && path.startsWith("blobs/") &&
            path.substring(6).all { it in '0'..'9' || it in 'a'..'f' }
    }
}
