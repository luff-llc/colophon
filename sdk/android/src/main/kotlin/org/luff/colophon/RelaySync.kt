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
 *
 * Work is proportional to the change: the feed is read from a persisted cursor, the relay's known
 * paths live in an append-only private log, local records are enumerated by path, and only records
 * that must be pushed or compared are read. Blob chunks are pushed before records, so a manifest
 * never reaches a peer ahead of its ciphertext, and are pulled lazily with [fetchBlob].
 * Blocking: call it off the main thread.
 */
class RelaySync(
    private val local: RecordStore,
    val endpoint: RelayEndpoint,
    transport: RelayTransport = HttpUrlConnectionTransport(),
    /** Private container, never the shared library. Without it each process relists the slot. */
    private val stateFile: File? = null,
    private val namespaces: List<String> = emptyList(),
    private val verifyLive: ((String, ByteArray) -> ULong)? = null,
    private val validateAuthority: ((Map<String, ByteArray>) -> Unit)? = null,
) {
    data class Report(
        val pulled: Int = 0,
        val pushed: Int = 0,
        val conflicts: List<String> = emptyList(),
        /** Encrypted blob chunks uploaded in this pass. */
        val pushedBlobs: Int = 0,
        /** Local record bodies read (pushes, conflict checks, the genesis check). */
        val localRecordReads: Int = 0,
        /** Change-feed entries that were new to this device. */
        val listed: Int = 0,
    )

    private val client = RelayClient(endpoint, transport)
    private val lock = ReentrantLock()
    private var loaded = false
    @Volatile private var cursor: String? = null
    private var remote = HashMap<String, String>()
    private val conflicts = sortedSetOf<String>()
    private val unsaved = mutableListOf<Pair<String, String?>>()
    private var genesisChecked = false
    private var stateDirty = false
    @Volatile var hasListed = false
        private set

    private val stateScope get() = endpoint.url + "|colophon/relay/3|" + namespaces.sorted().joinToString(",")
    private val remoteLog: File? get() = stateFile?.let { File(it.parentFile, it.nameWithoutExtension + "-remote.log") }

    /** True when the relay's listing, as last seen, holds [path] (a record or blob chunk). */
    fun relayHolds(path: String): Boolean = lock.withLock {
        loadState()
        remote.containsKey(path)
    }

    /** One complete pass: list, pull what the local store lacks, push what the relay lacks. */
    fun sync(): Report = lock.withLock {
        loadState()
        val listed = list()
        var reads = 0
        val localPaths = local.syncPaths(namespaces)
        val genesis = "authority/00000001.json"
        val theirs = remote[genesis]
        if (genesis in localPaths && theirs != null && (!genesisChecked || genesis in listed)) {
            val mine = local.read(listOf(genesis))[genesis]
            reads += 1
            if (mine != null && sha256Hex(mine) != theirs) throw RelayException.DifferentLibrary()
            genesisChecked = true
        }
        var pulled = 0
        var pushed = 0
        var pushedBlobs = 0
        val pulledPaths = mutableSetOf<String>()
        var missing = remote.keys.filter { path -> path !in localPaths && validRecord(path) && !RecordPath.isReplaceable(path) }.sortedWith(PULL_ORDER)
        validateAuthority?.let { validate ->
            val authorityMissing = missing.filter { it.startsWith("authority/") }
            val fetched = authorityMissing.associateWith { path ->
                val bytes = client.get(path) ?: throw RelayException.ProtocolViolation("Authority download pending")
                if (sha256Hex(bytes) != remote[path]) throw RelayException.ProtocolViolation("Authority digest mismatch")
                bytes
            }
            if (fetched.isNotEmpty()) { local.append(fetched); pulledPaths.addAll(fetched.keys); pulled += fetched.size }
            val authority = local.read(localPaths.filter { it.startsWith("authority/") } + authorityMissing)
            reads += authority.size
            if (authority.isNotEmpty()) validate(authority)
            missing = missing.filterNot { it.startsWith("authority/") }
        }
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
                pulledPaths.addAll(fetched.keys)
                pulled += fetched.size
            }
        }
        // Conflicts: only immutable entries new in this pass that this store already held.
        val compare = listed.filter { it in localPaths && it !in pulledPaths && validRecord(it) && !RecordPath.isReplaceable(it) }
        if (compare.isNotEmpty()) {
            val bytes = local.read(compare)
            reads += bytes.size
            for ((path, data) in bytes) {
                if (sha256Hex(data) != remote[path]) conflicts += path else conflicts -= path
            }
        }
        // Blob chunks first: a peer that sees a manifest must be able to fetch its ciphertext.
        val blobs = local as? BlobStore
        if (blobs != null) {
            val unpushedBlobs = blobs.blobPaths().keys.filter { it !in remote }.sorted()
            for (batch in unpushedBlobs.chunked(PARALLELISM)) {
                val chunks = batch.mapNotNull { path ->
                    val bytes = blobs.readBlob(path)
                    val sha = sha256Hex(bytes)
                    // A local chunk that fails its content address is never uploaded.
                    if ("blobs/$sha" == path) Triple(path, sha, bytes) else null
                }
                for ((triple, result) in parallel(chunks) { it to client.putIfAbsent(it.first, it.third) }) {
                    when (result) {
                        RelayClient.PutResult.CREATED -> {
                            pushedBlobs += 1
                            remember(triple.first, triple.second)
                        }
                        RelayClient.PutResult.PRESENT -> remember(triple.first, triple.second)
                        RelayClient.PutResult.CONFLICT -> conflicts += triple.first
                    }
                }
            }
        }
        val unpushed = localPaths.filter { it !in remote && !RecordPath.isReplaceable(it) }.sortedWith(PULL_ORDER)
        for (group in unpushed.chunked(64)) {
            val records = local.read(group)
            reads += records.size
            // A reader must never observe a successor before its authority predecessor.
            val batches = group.filter { it.startsWith("authority/") }.map { listOf(it) } +
                group.filterNot { it.startsWith("authority/") }.chunked(PARALLELISM)
            for (batch in batches) {
                val present = batch.mapNotNull { path -> records[path]?.let { Triple(path, sha256Hex(it), it) } }
                for ((triple, result) in parallel(present) { it to client.putIfAbsent(it.first, it.third) }) {
                    when (result) {
                        RelayClient.PutResult.CREATED -> {
                            pushed += 1
                            remember(triple.first, triple.second)
                        }
                        RelayClient.PutResult.PRESENT -> remember(triple.first, triple.second)
                        RelayClient.PutResult.CONFLICT -> conflicts += triple.first
                    }
                }
            }
        }
        verifyLive?.let { verify ->
            val slots = (localPaths + remote.keys).filter { RecordPath.isReplaceable(it) }.sorted()
            for (path in slots) {
                val mine = local.read(listOf(path))[path]
                if (mine != null) reads += 1
                if (mine != null && sha256Hex(mine) == remote[path]) continue
                val theirs = client.get(path)
                if (theirs != null && sha256Hex(theirs) != remote[path]) continue
                val mineGeneration = mine?.let { runCatching { verify(path, it) }.getOrNull() }
                val theirGeneration = theirs?.let { runCatching { verify(path, it) }.getOrNull() }
                if (theirs != null && theirGeneration != null && (mineGeneration == null || theirGeneration > mineGeneration)) {
                    if (local.replaceLive(path, mine, theirs)) pulled += 1
                } else if (mine != null && mineGeneration != null && (theirGeneration == null || mineGeneration > theirGeneration)) {
                    val result = client.putIfAbsent(path, mine, theirs?.let(::sha256Hex))
                    if (result != RelayClient.PutResult.CONFLICT) { remember(path, sha256Hex(mine)); pushed += 1 }
                } else if (mineGeneration != null && theirs != null && !mine!!.contentEquals(theirs)) conflicts += path
            }
        }
        saveState()
        Report(pulled, pushed, conflicts.toList(), pushedBlobs, reads, listed.size)
    }

    /**
     * Lazily fetches one encrypted chunk the local store lacks, verifies that its bytes hash to its
     * name and appends it to the local blob store. Returns null when the relay lacks it too.
     * Resumable: every verified chunk is durable before the next is requested.
     */
    fun fetchBlob(path: String): ByteArray? {
        BlobPath.validate(path)
        val blobs = local as? BlobStore ?: throw StorageException.Unavailable("The local store keeps no blobs")
        val bytes = client.get(path) ?: return null
        if (bytes.size > MAX_BLOB_CHUNK_BYTES || "blobs/${sha256Hex(bytes)}" != path) {
            throw RelayException.ProtocolViolation("Blob chunk does not match its content address: $path")
        }
        blobs.appendBlob(path, bytes)
        lock.withLock {
            loadState()
            if (path !in remote) {
                remember(path, path.substring(6))
                saveState()
            }
        }
        return bytes
    }

    /** Long-polls the change feed after the saved cursor, outside the pass lock. */
    fun waitForRemoteChanges(seconds: Int): Boolean {
        lock.withLock { loadState() }
        val page = client.changes(cursor, limit = 1, wait = seconds.coerceIn(0, 30), namespaces = namespaces)
        return page.entries.isNotEmpty()
    }

    /** Lists from the saved cursor; returns the paths new to this device in this pass. */
    private fun list(): Set<String> {
        var restarted = false
        val listed = mutableSetOf<String>()
        while (true) {
            val page = try {
                client.changes(cursor, limit = 1000, namespaces = namespaces)
            } catch (reset: RelayException.CursorReset) {
                if (restarted) throw reset
                // The relay lost or rebuilt its log. Forget what it held and relist from the start.
                restarted = true
                cursor = null
                remote.clear()
                listed.clear()
                unsaved.clear()
                genesisChecked = false
                resetRemoteLog()
                continue
            }
            for (entry in page.entries) {
                if (!validRecord(entry.path) && !validBlob(entry.path)) {
                    throw RelayException.ProtocolViolation("Invalid path in change feed: ${entry.path}")
                }
                if (entry.deleted) {
                    if (remote.remove(entry.path) != null) unsaved += entry.path to null
                    listed -= entry.path
                    continue
                }
                val sha = entry.sha256
                if (sha == null || sha.length != 64) throw RelayException.ProtocolViolation("Entry without digest: ${entry.path}")
                // Entries this device already knew (its own pushes, relistings) are not changes.
                if (remote[entry.path] != sha) {
                    remember(entry.path, sha)
                    listed += entry.path
                }
            }
            if (page.cursor == cursor && page.entries.isNotEmpty()) throw RelayException.ProtocolViolation("Cursor did not advance")
            if (page.cursor != cursor) {
                cursor = page.cursor
                stateDirty = true
            }
            if (!page.more) break
        }
        hasListed = true
        return listed
    }

    private fun remember(path: String, sha: String) {
        remote[path] = sha
        unsaved += path to sha
    }

    private fun <I, T> parallel(items: List<I>, work: (I) -> T): List<T> {
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

    private fun loadState() {
        if (loaded) return
        loaded = true
        val file = stateFile ?: return
        if (!file.exists()) return
        // A corrupt or foreign state file only costs a full relisting.
        try {
            val root = JsonParser(AtomicFile.read(file, AtomicFile.MAX_JOURNAL_BYTES).decodeToString()).parseValue() as Json.Obj
            if (root.string("relay") != stateScope) return
            cursor = root.string("cursor")
            conflicts.addAll(root.stringList("conflicts"))
            val legacy = root.fields["remote"]
            if (legacy is Json.Obj) {
                // Migrate the whole-map format once into the append-only log.
                remote = HashMap(root.stringMap("remote"))
                resetRemoteLog()
                unsaved.addAll(remote.entries.map { it.key to it.value })
                saveState()
                return
            }
            val log = remoteLog
            if (log == null || !log.exists()) {
                // A cursor without its known paths would skip records: relist instead.
                cursor = null
                return
            }
            val text = AtomicFile.read(log, 256 * 1024 * 1024).decodeToString()
            val complete = text.lastIndexOf('\n')
            if (complete < 0) return
            var start = 0
            while (start <= complete) {
                val end = text.indexOf('\n', start)
                // "<sha256> <path>" adds, "- <path>" removes; a torn final line is ignored.
                if (end > start + 2) {
                    if (text[start] == '-' && text[start + 1] == ' ') {
                        remote.remove(text.substring(start + 2, end))
                    } else if (end > start + 65 && text[start + 64] == ' ') {
                        remote[text.substring(start + 65, end)] = text.substring(start, start + 64)
                    }
                }
                start = end + 1
            }
        } catch (_: Exception) {
            cursor = null
            remote = HashMap()
        }
    }

    private fun resetRemoteLog() {
        val log = remoteLog ?: return
        AtomicFile.write(ByteArray(0), log)
        stateDirty = true
    }

    private fun saveState() {
        val file = stateFile
        if (file == null) {
            unsaved.clear()
            return
        }
        val log = remoteLog
        if (unsaved.isNotEmpty() && log != null) {
            val text = buildString { for ((path, sha) in unsaved) append(sha ?: "-").append(' ').append(path).append('\n') }
            AtomicFile.append(text.toByteArray(Charsets.UTF_8), log)
            unsaved.clear()
        }
        val text = buildString {
            append("{\"relay\":").append(jsonString(stateScope))
            append(",\"cursor\":").append(cursor?.let { jsonString(it) } ?: "null")
            append(",\"conflicts\":[").append(conflicts.joinToString(",") { jsonString(it) }).append("]}")
        }
        val bytes = text.toByteArray(Charsets.UTF_8)
        val old = if (!stateDirty && file.exists()) runCatching { AtomicFile.read(file, AtomicFile.MAX_JOURNAL_BYTES) }.getOrNull() else null
        if (stateDirty || old == null || !old.contentEquals(bytes)) AtomicFile.write(bytes, file)
        stateDirty = false
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
