package org.luff.colophon

import com.luff.colophon.AccessException
import com.luff.colophon.Access
import com.luff.colophon.BlobReadOutcome
import kotlinx.coroutines.sync.withLock
import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest

/**
 * A published, encrypted, content-addressed blob in one namespace. [digest], [size] and
 * [mediaType] form the plaintext descriptor domains reference (`{digest,size,mediaType}`).
 */
data class ColophonBlob(
    val namespace: String,
    /** SHA-256 of the complete plaintext, lowercase hex. */
    val digest: String,
    val size: Long,
    val mediaType: String,
    /** Saved when durable in the local store; Queued when it awaits publication. */
    val receipt: WriteReceipt? = null,
) {
    /** The domain descriptor object as JSON, ready for a command payload. */
    val descriptorJson: String get() = "{\"digest\":${jsonString(digest)},\"size\":$size,\"mediaType\":${jsonString(mediaType)}}"
}

/** Never treat anything other than [Available] as empty content. */
sealed class BlobAvailability {
    /** No readable manifest: not published, not synced here yet, or not readable. */
    data object Unpublished : BlobAvailability()
    /** The manifest is known and some encrypted chunks are not on this device. */
    data class Missing(val presentChunks: Int, val totalChunks: Int) : BlobAvailability()
    /** Chunks are being fetched from the relay. */
    data class Downloading(val completedChunks: Int, val totalChunks: Int) : BlobAvailability()
    /** Every chunk is local; reads verify them again. */
    data object Available : BlobAvailability()
    /** Current grants, keys or storage prevent reading. */
    data class Inaccessible(val reason: String) : BlobAvailability()
}

sealed class BlobException(message: String) : Exception(message) {
    class Unpublished : BlobException("This content has not reached this device yet.")
    /** A chunk is neither local nor fetchable (no relay, relay unreachable, or it lacks it). */
    class Missing(detail: String) : BlobException("This content is not downloaded yet. $detail")
    class Inaccessible(detail: String) : BlobException("This content is not readable with the current access. $detail")
    /** Bytes failed their content address, AEAD tag or chunk digest. */
    class Invalid(detail: String) : BlobException("Stored content failed verification. $detail")
    class DigestMismatch : BlobException("Stored content does not match its descriptor.")
    class TooLarge : BlobException("This content is too large for one blob. Split it into parts.")
}

data class BlobCollection(val removedChunks: Int = 0, val removedBytes: Long = 0, val keptChunks: Int = 0)

internal data class BlobManifestInfo(val digest: String, val size: Long, val mediaType: String, val chunks: List<String>)

internal data class StagedBlob(val manifest: ByteArray?, val digest: String, val size: Long, val mediaType: String)

/** Upload input, streamed in 64 KiB reads. */
internal sealed class BlobInput {
    class Bytes(val data: ByteArray) : BlobInput()
    class FromFile(val file: File) : BlobInput()

    fun forEachChunk(body: (ByteArray) -> Unit) {
        when (this) {
            is Bytes -> {
                var offset = 0
                while (offset < data.size) {
                    body(data.copyOfRange(offset, minOf(data.size, offset + CHUNK)))
                    offset += CHUNK
                }
            }
            is FromFile -> FileInputStream(file).use { stream ->
                val buffer = ByteArray(CHUNK)
                while (true) {
                    var filled = 0
                    while (filled < CHUNK) {
                        val read = stream.read(buffer, filled, CHUNK - filled)
                        if (read < 0) break
                        filled += read
                    }
                    if (filled == 0) break
                    body(buffer.copyOf(filled))
                    if (filled < CHUNK) break
                }
            }
        }
    }

    companion object {
        const val CHUNK = 65536
    }
}

/** One manifest travels in one ordinary command (at most 1 MiB): 4,000 chunks, 250 MiB. */
internal const val MAXIMUM_BLOB_CHUNKS = 4000

internal class BlobHash {
    private val digest = MessageDigest.getInstance("SHA-256")
    var size = 0L
        private set
    fun update(bytes: ByteArray) {
        digest.update(bytes)
        size += bytes.size
    }
    fun finish(): String = digest.digest().joinToString("") { "%02x".format(it) }
}

/**
 * Blob work for one session. Core calls run on the session dispatcher; relay fetches are blocking
 * and run on an IO dispatcher. Garbage collection only considers chunks listed in this session's
 * private index, so another app's chunks in a shared store are never removed.
 */
internal class SessionBlobEngine(private val worker: SessionWorker) {
    private var index: MutableSet<String>? = null
    private val completeRequired = mutableSetOf<String>()
    private val indexFile get() = File(worker.configuration.privateHome, "blob-index.log")

    fun store(): BlobStore = worker.storage() as? BlobStore
        ?: throw BlobException.Inaccessible("This storage location keeps no blobs")

    suspend fun stage(namespace: String, mediaType: String, input: BlobInput): StagedBlob = worker.mutex.withLock {
        val fresh = worker.refreshLocked()
        if (fresh.phase != SessionPhase.Ready) throw SessionException.NotReady()
        val configuration = worker.configuration
        if (namespace !in configuration.namespaces || Access.WRITE !in configuration.access) throw SessionException.InvalidCommand
        val blobs = store()
        // Pass 1 addresses the content, so identical bytes are never stored twice.
        val addressing = BlobHash()
        input.forEachChunk { addressing.update(it) }
        val digest = addressing.finish()
        val size = addressing.size
        if (size > MAXIMUM_BLOB_CHUNKS.toLong() * BlobInput.CHUNK) throw BlobException.TooLarge()
        val existing = query(namespace, digest).first
        if (existing != null && existing.size == size) return StagedBlob(null, digest, size, existing.mediaType)
        val writer = try {
            worker.core.beginBlob(namespace, mediaType)
        } catch (error: AccessException) {
            throw BlobException.Inaccessible(error.denial.detail)
        }
        // Pass 2 seals and persists; each chunk is durable and read back before the next is read.
        val sealing = BlobHash()
        val written = mutableListOf<String>()
        writer.use {
            input.forEachChunk { plaintext ->
                sealing.update(plaintext)
                val sealed = writer.push(plaintext)
                blobs.appendBlob(sealed.path, sealed.bytes)
                if (!blobs.readBlob(sealed.path).contentEquals(sealed.bytes)) throw SessionException.PublicationUncertain
                written += sealed.path
            }
            indexBlobs(written)
            if (sealing.finish() != digest || sealing.size != size) throw BlobException.DigestMismatch()
            val manifest = writer.finish()
            if (manifest.size > 1024 * 1024 - 4096) throw BlobException.TooLarge()
            StagedBlob(manifest, digest, size, mediaType)
        }
    }

    /** (manifest or null, references, required) from the grant-checked `blob` query. */
    private fun query(namespace: String, digest: String): Triple<BlobManifestInfo?, Int, Boolean> {
        val bytes = try {
            worker.core.query(namespace, "blob", "{\"digest\":${jsonString(digest)}}".toByteArray())
        } catch (error: AccessException) {
            throw BlobException.Inaccessible(error.denial.detail)
        }
        val root = JsonParser(bytes.decodeToString()).parseValue() as? Json.Obj ?: throw BlobException.Invalid("Unreadable blob manifest")
        val references = (root.fields["references"] as? Json.Number)?.raw?.toIntOrNull() ?: 0
        val required = root.bool("required") ?: false
        val manifest = root.fields["manifest"] as? Json.Obj ?: return Triple(null, references, required)
        val descriptor = manifest.fields["descriptor"] as? Json.Obj ?: throw BlobException.Invalid("Unreadable blob manifest")
        val chunks = manifest.array("chunks").map { (it as Json.Obj).string("path") ?: throw BlobException.Invalid("Unreadable chunk") }
        return Triple(
            BlobManifestInfo(
                descriptor.string("digest") ?: digest,
                (descriptor.fields["size"] as? Json.Number)?.raw?.toLongOrNull() ?: throw BlobException.Invalid("Unreadable size"),
                descriptor.string("mediaType") ?: "",
                chunks,
            ),
            references,
            required,
        )
    }

    fun manifest(namespace: String, digest: String): BlobManifestInfo {
        if (namespace !in worker.configuration.namespaces) throw SessionException.InvalidCommand
        return query(namespace, digest).first ?: throw BlobException.Unpublished()
    }

    fun availability(namespace: String, digest: String): BlobAvailability {
        val manifest = try {
            manifest(namespace, digest)
        } catch (_: BlobException.Unpublished) {
            return BlobAvailability.Unpublished
        }
        val blobs = store()
        val present = manifest.chunks.count { blobs.hasBlob(it) }
        return if (present == manifest.chunks.size) BlobAvailability.Available else BlobAvailability.Missing(present, manifest.chunks.size)
    }

    /** Blocking: makes one chunk local, fetching it lazily from the relay. Run on an IO thread. */
    fun ensureChunk(path: String) {
        val blobs = store()
        if (blobs.hasBlob(path)) return
        val relay = worker.relay() ?: throw BlobException.Missing("No relay is configured to fetch it.")
        val fetched = try {
            relay.fetchBlob(path)
        } catch (error: RelayException) {
            throw BlobException.Missing(error.message ?: "The relay is unreachable.")
        }
        if (fetched == null) throw BlobException.Missing("The relay does not hold it yet.")
        synchronized(this) { indexBlobs(listOf(path)) }
    }

    fun openChunk(namespace: String, manifest: BlobManifestInfo, index: Int): ByteArray {
        val ciphertext = store().readBlob(manifest.chunks[index])
        return when (val outcome = worker.core.openBlobChunk(namespace, manifest.digest, index, ciphertext)) {
            is BlobReadOutcome.Available -> outcome.bytes
            is BlobReadOutcome.Missing -> throw BlobException.Unpublished()
            is BlobReadOutcome.Inaccessible -> throw BlobException.Inaccessible(outcome.detail)
            is BlobReadOutcome.Invalid -> throw BlobException.Invalid(outcome.detail)
        }
    }

    private data class Row(val digest: String, val references: Int, val required: Boolean)

    private fun page(namespace: String, requiredOnly: Boolean): List<Row> {
        val rows = mutableListOf<Row>()
        var after: String? = null
        do {
            val args = buildString {
                append("{\"limit\":500")
                if (requiredOnly) append(",\"required\":true")
                after?.let { append(",\"after\":").append(jsonString(it)) }
                append('}')
            }
            val bytes = try {
                worker.core.query(namespace, "blobs", args.toByteArray())
            } catch (error: AccessException) {
                throw BlobException.Inaccessible(error.denial.detail)
            }
            val root = JsonParser(bytes.decodeToString()).parseValue() as Json.Obj
            for (item in root.array("blobs")) {
                val row = item as Json.Obj
                rows += Row(
                    row.string("digest") ?: continue,
                    (row.fields["references"] as? Json.Number)?.raw?.toIntOrNull() ?: 0,
                    row.bool("required") ?: false,
                )
            }
            after = root.string("next")
        } while (after != null)
        return rows
    }

    /** Required blobs not yet complete here; completed digests are remembered for the process. */
    fun incompleteRequired(namespace: String): List<BlobManifestInfo> {
        val blobs = store()
        return page(namespace, true).filter { it.digest !in completeRequired }.mapNotNull { row ->
            val manifest = query(namespace, row.digest).first ?: return@mapNotNull null
            if (manifest.chunks.all { blobs.hasBlob(it) }) {
                completeRequired += row.digest
                null
            } else {
                manifest
            }
        }
    }

    suspend fun collect(graceMillis: Long, evictReplicated: Boolean, discardSoleCopy: Boolean = false): BlobCollection = worker.mutex.withLock {
        val blobs = store()
        val live = mutableSetOf<String>()
        val dead = mutableSetOf<String>()
        val pinned = mutableSetOf<String>()
        for (namespace in worker.configuration.namespaces) {
            // An unreadable namespace throws here, so nothing is deleted without complete evidence.
            for (row in page(namespace, false)) {
                val manifest = query(namespace, row.digest).first ?: continue
                if (row.references > 0 || row.required) live += manifest.chunks else dead += manifest.chunks
                if (row.required) pinned += manifest.chunks
            }
        }
        val indexed = loadIndex()
        val relay = worker.relay()
        val now = System.currentTimeMillis()
        var removed = 0
        var bytes = 0L
        var kept = 0
        val gone = mutableSetOf<String>()
        for ((path, modified) in blobs.blobPaths()) {
            if (path !in indexed) continue
            val remove = when {
                path in live -> evictReplicated && path !in pinned && relay?.relayHolds(path) == true
                path in dead -> discardSoleCopy || relay?.relayHolds(path) == true
                // A chunk no manifest names: an upload that never published.
                else -> modified + graceMillis < now
            }
            if (remove) {
                bytes += runCatching { blobs.readBlob(path).size.toLong() }.getOrDefault(0L)
                blobs.removeBlob(path)
                gone += path
                removed += 1
            } else {
                kept += 1
            }
        }
        if (gone.isNotEmpty()) {
            val remaining = indexed - gone
            AtomicFile.write(remaining.sorted().joinToString("") { it + "\n" }.toByteArray(Charsets.UTF_8), indexFile)
            index = remaining.toMutableSet()
        }
        completeRequired.clear()
        BlobCollection(removed, bytes, kept)
    }

    private fun loadIndex(): Set<String> {
        index?.let { return it }
        val paths = mutableSetOf<String>()
        if (indexFile.exists()) {
            val text = AtomicFile.read(indexFile, 64 * 1024 * 1024).decodeToString()
            for (line in text.split('\n')) if (runCatching { BlobPath.validate(line) }.isSuccess) paths += line
        }
        index = paths
        return paths
    }

    private fun indexBlobs(paths: List<String>) {
        val current = loadIndex().toMutableSet()
        val fresh = paths.filter { it !in current }
        if (fresh.isEmpty()) return
        AtomicFile.append(fresh.joinToString("") { it + "\n" }.toByteArray(Charsets.UTF_8), indexFile)
        current += fresh
        index = current
    }
}

/** Joins already-encoded JSON values, keeping their exact bytes (a signed manifest is not re-encoded). */
internal fun rawJsonObject(fields: List<Pair<String, ByteArray>>): ByteArray {
    val out = java.io.ByteArrayOutputStream()
    out.write('{'.code)
    fields.forEachIndexed { index, (key, value) ->
        if (index > 0) out.write(','.code)
        out.write(jsonString(key).toByteArray(Charsets.UTF_8))
        out.write(':'.code)
        out.write(value)
    }
    out.write('}'.code)
    return out.toByteArray()
}
