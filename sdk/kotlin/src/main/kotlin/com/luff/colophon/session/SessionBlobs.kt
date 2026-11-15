package com.luff.colophon.session

import com.luff.colophon.AccountException
import com.luff.colophon.BlobState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.InputStream
import java.security.MessageDigest

/** A published blob. */
data class ColophonBlob(val namespace: String, val digest: String, val size: Long, val mediaType: String, val receipt: WriteReceipt)

/** How much of a blob this device holds. */
sealed class BlobAvailabilityState {
    object Available : BlobAvailabilityState() { override fun toString() = "Available" }
    data class Missing(val presentChunks: Int, val totalChunks: Int) : BlobAvailabilityState()
    data class Downloading(val completedChunks: Int, val totalChunks: Int) : BlobAvailabilityState()
    data class Inaccessible(val reason: String) : BlobAvailabilityState()
    /** No manifest for this digest is published in the namespace. */
    object Unpublished : BlobAvailabilityState() { override fun toString() = "Unpublished" }
}

sealed class BlobException(message: String) : Exception(message) {
    class Unpublished : BlobException("No blob with this digest is published.")
    class Missing(detail: String) : BlobException(detail)
    class Inaccessible(detail: String) : BlobException(detail)
    class Invalid(detail: String) : BlobException(detail)
    class TooLarge : BlobException("The blob is larger than the caller allows.")
    class DigestMismatch : BlobException("The blob's content does not match its digest.")
}

internal data class BlobManifestInfo(val digest: String, val size: Long, val mediaType: String, val chunks: Int)

private const val CHUNK = 64 * 1024

internal fun parseManifest(text: String): BlobManifestInfo? {
    val obj = Json.obj(text) ?: return null
    if (obj["ok"] != true) return null
    var value = obj.obj("value") ?: return null
    value.obj("manifest")?.let { value = it }
    val descriptor = value.obj("descriptor") ?: value
    val digest = descriptor.string("digest") ?: return null
    val size = descriptor.long("size") ?: return null
    val chunks = value.list("chunks") ?: return null
    return BlobManifestInfo(digest, size, descriptor.string("mediaType") ?: "application/octet-stream", chunks.size)
}

private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it) }

/** Reads `input` in 64 KiB pieces. */
private inline fun forEachChunk(input: () -> InputStream, body: (ByteArray) -> Unit) {
    input().use { stream ->
        val buffer = ByteArray(CHUNK)
        while (true) {
            var n = 0
            while (n < CHUNK) { val r = stream.read(buffer, n, CHUNK - n); if (r < 0) break; n += r }
            if (n == 0) break
            body(buffer.copyOf(n))
            if (n < CHUNK) break
        }
    }
}

/**
 * Encrypts and stores `data` in 64 KiB chunks under the namespace epoch key, then publishes a signed
 * `colophon.blobPublish` manifest with one reference. Identical content already published is not stored again; a
 * reference is added instead. `required` asks every device to download it. Hashing, encryption and chunk writes run
 * on `Dispatchers.IO`, outside the session's gate (only `begin_blob` and the publish take it).
 */
suspend fun ColophonSession.putBlob(data: ByteArray, namespace: String, mediaType: String, reference: String, required: Boolean = false): ColophonBlob =
    putBlob({ data.inputStream() }, namespace, mediaType, reference, required)

/** The same from a file, streamed (read twice: once to address it, once to encrypt it). The file must not change in between. */
suspend fun ColophonSession.putBlob(file: File, namespace: String, mediaType: String, reference: String, required: Boolean = false): ColophonBlob =
    putBlob({ file.inputStream() }, namespace, mediaType, reference, required)

private suspend fun ColophonSession.putBlob(input: () -> InputStream, namespace: String, mediaType: String, reference: String, required: Boolean): ColophonBlob {
    restore()
    if (phase != SessionPhase.Ready && phase != SessionPhase.Refreshing) throw SessionError.NotReady()
    val lease = context
    val (digest, size) = withContext(Dispatchers.IO) {
        val sha = MessageDigest.getInstance("SHA-256"); var size = 0L
        forEachChunk(input) { sha.update(it); size += it.size }
        hex(sha.digest()) to size
    }
    if (lease != context) throw SessionError.DestinationChanged()
    // The engine half, inside the gate and quick: the published manifest, or a writer.
    val existing = worker.inGate {
        val engine = worker.requireEngine()
        try { parseManifest(engine.run { it.blobManifestJson(namespace, digest) }) } catch (_: AccountException) { null }
    }
    val manifestText: String?
    val storedSize: Long
    val storedType: String
    if (existing != null) {
        manifestText = null; storedSize = existing.size; storedType = existing.mediaType
    } else {
        val writer = worker.inGate { worker.requireEngine().run { e -> withEntropy(32) { e.beginBlob(namespace, mediaType, it) } } }
        manifestText = writer.use { w ->
            withContext(Dispatchers.IO) {
                val sha = MessageDigest.getInstance("SHA-256"); var count = 0L
                forEachChunk(input) { chunk ->
                    sha.update(chunk); count += chunk.size
                    val sealed = w.push(chunk)
                    worker.storage().write(listOf(MediumWrite(sealed.path, sealed.bytes)))
                }
                if (hex(sha.digest()) != digest || count != size) throw BlobException.DigestMismatch()
                w.finish()
            }
        }
        storedSize = size; storedType = mediaType
    }
    if (lease != context) throw SessionError.DestinationChanged()
    // The signed manifest is embedded byte for byte: no numeric re-encoding.
    val fields = LinkedHashMap<String, Any?>()
    fields["reference"] = reference
    fields["required"] = required
    val kind: String
    if (manifestText != null) { kind = "colophon.blobPublish"; fields["manifest"] = RawJson(manifestText) }
    else { kind = "colophon.blobReference"; fields["digest"] = digest; fields["retain"] = true }
    val receipt = perform(DomainCommand(namespace, kind, Json.write(fields, sorted = false)), observedRevision)
    return ColophonBlob(namespace, digest, storedSize, storedType, receipt)
}

/** Adds (`retain`) or removes a live reference. */
suspend fun ColophonSession.setBlobReference(blob: ColophonBlob, reference: String, retain: Boolean, required: Boolean? = null): WriteReceipt {
    val payload = LinkedHashMap<String, Any?>()
    payload["digest"] = blob.digest; payload["reference"] = reference; payload["retain"] = retain
    required?.let { payload["required"] = it }
    return perform(DomainCommand(blob.namespace, "colophon.blobReference", Json.write(payload)), observedRevision)
}

/** Checks local presence without downloading or decrypting anything. */
suspend fun ColophonSession.blobAvailability(namespace: String, digest: String): BlobAvailabilityState {
    restore()
    facade { blobDownloads[digest] }?.let { return it }
    if (phase != SessionPhase.Ready && phase != SessionPhase.Refreshing) return BlobAvailabilityState.Inaccessible("The library is not ready")
    return try { workerAvailability(namespace, digest) } catch (e: Exception) { BlobAvailabilityState.Inaccessible(e.message ?: "not readable") }
}

private suspend fun ColophonSession.manifest(namespace: String, digest: String): BlobManifestInfo {
    val engine = worker.requireEngine()
    return parseManifest(engine.run { it.blobManifestJson(namespace, digest) }) ?: throw BlobException.Unpublished()
}

private suspend fun ColophonSession.workerAvailability(namespace: String, digest: String): BlobAvailabilityState {
    val engine = worker.requireEngine()
    val manifest = try { manifest(namespace, digest) } catch (_: Exception) { return BlobAvailabilityState.Unpublished }
    val a = engine.run { it.blobAvailability(namespace, digest) }
    return when (a.state) {
        BlobState.COMPLETE -> BlobAvailabilityState.Available
        BlobState.PARTIAL -> BlobAvailabilityState.Missing(a.present.toInt(), a.total.toInt())
        BlobState.MISSING -> BlobAvailabilityState.Missing(0, manifest.chunks)
        BlobState.INACCESSIBLE -> BlobAvailabilityState.Inaccessible(a.detail ?: "not readable")
    }
}

/**
 * Complete verified plaintext; missing chunks are fetched from the homes first. Each chunk is authenticated by the
 * engine and the whole content is checked against its digest before it is returned.
 */
suspend fun ColophonSession.blobData(namespace: String, digest: String, maximumBytes: Long = 16L * 1024 * 1024): ByteArray {
    restore()
    if (phase != SessionPhase.Ready && phase != SessionPhase.Refreshing) throw SessionError.NotReady()
    val lease = context
    val manifest = manifest(namespace, digest)
    if (manifest.size > maximumBytes) throw BlobException.TooLarge()
    if (workerAvailability(namespace, digest) is BlobAvailabilityState.Missing) fetch(namespace, digest)
    val engine = worker.requireEngine()
    val out = java.io.ByteArrayOutputStream(manifest.size.toInt())
    val sha = MessageDigest.getInstance("SHA-256")
    for (index in 0 until manifest.chunks) {
        val plaintext = try {
            engine.run { it.blobChunk(namespace, digest, index.toULong()) }
        } catch (e: AccountException.Unavailable) { throw BlobException.Missing(e.detail)
        } catch (e: AccountException.Denied) { throw BlobException.Inaccessible(e.detail)
        } catch (e: AccountException.Malformed) { throw BlobException.Invalid(e.detail)
        } catch (e: AccountException.BadSignature) { throw BlobException.Invalid(e.detail) }
        if (lease != context) throw SessionError.DestinationChanged()
        sha.update(plaintext); out.write(plaintext)
    }
    if (out.size().toLong() != manifest.size || hex(sha.digest()) != manifest.digest) throw BlobException.DigestMismatch()
    return out.toByteArray()
}

/** Downloads every missing chunk (ciphertext only) from the homes so later reads work offline. */
suspend fun ColophonSession.prefetchBlob(namespace: String, digest: String) {
    restore()
    if (phase != SessionPhase.Ready && phase != SessionPhase.Refreshing) throw SessionError.NotReady()
    fetch(namespace, digest)
}

/** Fetches every blob marked `required` that is not complete here (one exchange pulls them). */
suspend fun ColophonSession.downloadRequiredBlobs() {
    restore()
    if (phase != SessionPhase.Ready || !homesConfigured) return
    for (namespace in worker.configuration.namespaces) {
        val missing = try { worker.requireEngine().run { it.requiredBlobFetches(namespace) } } catch (_: Exception) { listOf() }
        if (missing.isNotEmpty()) { syncNow(); return }
    }
}

private suspend fun ColophonSession.fetch(namespace: String, digest: String) {
    val manifest = manifest(namespace, digest)
    facade { blobDownloads[digest] = BlobAvailabilityState.Downloading(0, manifest.chunks) }
    try {
        if (!homesConfigured) throw BlobException.Missing("No home is configured to fetch it from.")
        val engine = worker.requireEngine()
        for (home in engine.run { it.exchangeHomes() }) engine.run { it.exchangeWantBlob(home.id, namespace, digest) }
        syncNow()
        if (workerAvailability(namespace, digest) == BlobAvailabilityState.Available) return
        throw BlobException.Missing("No home holds every chunk yet.")
    } finally {
        facade { blobDownloads.remove(digest) }
    }
}
