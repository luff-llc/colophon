package com.luff.colophon.session

import com.luff.colophon.SavedPart
import com.luff.colophon.SavedState
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileOutputStream
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption

/**
 * Where the 32-byte device-held key that seals saved state lives (spec §17.2). A cache key, not an identity: losing
 * it makes the engine replay the history. It must never leave this device. On Android: `KeystoreDeviceSecrets`.
 */
interface DeviceSecretStore {
    /** The key for `account`, created on first use. The caller closes the returned copy. */
    fun key(account: String): SecretBytes
    fun remove(account: String)
}

/** A process-lifetime store for tests and previews. */
class MemoryDeviceSecrets : DeviceSecretStore {
    private val keys = HashMap<String, ByteArray>()
    @Synchronized override fun key(account: String): SecretBytes =
        SecretBytes.adopt(keys.getOrPut(account) { ByteArray(32).also(java.security.SecureRandom()::nextBytes) }.copyOf())
    @Synchronized override fun remove(account: String) { keys.remove(account)?.fill(0) }
}

/** Replaces a small private file atomically (write a sibling, sync, rename). */
internal object AtomicFile {
    fun write(file: File, bytes: ByteArray) {
        file.parentFile?.mkdirs()
        val tmp = File(file.parentFile, ".${file.name}.${System.nanoTime()}.tmp")
        FileOutputStream(tmp).use { it.write(bytes); it.fd.sync() }
        try {
            Files.move(tmp.toPath(), file.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
        } catch (_: AtomicMoveNotSupportedException) {
            Files.move(tmp.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING)
        }
    }
    fun read(file: File, maximumBytes: Int): ByteArray? {
        if (!file.isFile) return null
        if (file.length() > maximumBytes) throw StorageException.LimitExceeded()
        return file.readBytes()
    }
}

/** Small durable state in the private directory: which account, whether the person left, what was shown. */
internal class SessionJournal(
    var account: String? = null,
    var left: Boolean = false,
    var shownSeq: ULong = 0u,
    var shownTransitions: List<String> = listOf(),
    /** Activations above `shownSeq` the person marked seen one by one. */
    var seenActivations: Set<ULong> = setOf(),
    /** Homes that hold this host's delivery routes (true), or said they offer no registration (false). */
    var routes: Map<String, Boolean> = mapOf(),
    /** The change of each transition this device signed, by digest, so a dead one can be signed again. */
    var signedChanges: Map<String, String> = mapOf(),
    /** Removal follow-ups the person answered, by activation seq. */
    var answeredRemovals: Set<ULong> = setOf(),
) {
    fun encode(): ByteArray = Json.write(mapOf(
        "account" to account, "left" to left, "shownSeq" to shownSeq.toString(), "shownTransitions" to shownTransitions,
        "seenActivations" to seenActivations.map { it.toString() }, "routes" to routes, "signedChanges" to signedChanges,
        "answeredRemovals" to answeredRemovals.map { it.toString() },
    )).toByteArray(Charsets.UTF_8)

    companion object {
        @Suppress("UNCHECKED_CAST")
        fun decode(bytes: ByteArray): SessionJournal {
            val m = Json.obj(bytes.toString(Charsets.UTF_8)) ?: throw StorageException.Unavailable("the session journal is not readable")
            return SessionJournal(
                account = m.string("account"),
                left = m["left"] as? Boolean ?: false,
                shownSeq = m.string("shownSeq")?.toULongOrNull() ?: 0u,
                shownTransitions = (m.list("shownTransitions") ?: listOf()).filterIsInstance<String>(),
                seenActivations = (m.list("seenActivations") ?: listOf()).mapNotNull { (it as? String)?.toULongOrNull() }.toSet(),
                routes = (m.obj("routes") ?: mapOf()).mapNotNull { (k, v) -> (v as? Boolean)?.let { k to it } }.toMap(),
                signedChanges = (m.obj("signedChanges") ?: mapOf()).mapNotNull { (k, v) -> (v as? String)?.let { k to it } }.toMap(),
                answeredRemovals = (m.list("answeredRemovals") ?: listOf()).mapNotNull { (it as? String)?.toULongOrNull() }.toSet(),
            )
        }
    }
}

/**
 * The engine's sealed saved state per account, in the private directory. It is sealed under the device key by the
 * core; a file that fails its seal is ignored by the engine (the history replays), and a file this code cannot parse
 * is ignored here.
 */
internal class SavedStateCache(private val directory: File) {
    private fun file(account: String): File {
        require(account.length == 64 && account.all { it in '0'..'9' || it in 'a'..'f' }) { "an account ID is 64 hex" }
        return File(directory, "saved-$account.bin")
    }
    fun load(account: String): SavedState? = try {
        AtomicFile.read(file(account), 64 * 1024 * 1024)?.let { decode(it) }
    } catch (_: Exception) {
        null
    }
    fun save(account: String, state: SavedState) = AtomicFile.write(file(account), encode(state))

    private fun encode(s: SavedState): ByteArray {
        val out = ByteArrayOutputStream()
        DataOutputStream(out).use { d ->
            d.writeInt(1)
            d.writeInt(s.verifier.size); d.write(s.verifier)
            d.writeInt(s.checkpoint.size); d.write(s.checkpoint)
            d.writeInt(s.parts.size)
            for (p in s.parts) {
                val ns = p.namespace.toByteArray(Charsets.UTF_8)
                d.writeInt(ns.size); d.write(ns); d.writeInt(p.bytes.size); d.write(p.bytes)
            }
        }
        return out.toByteArray()
    }
    private fun decode(bytes: ByteArray): SavedState? {
        val d = DataInputStream(bytes.inputStream())
        if (d.readInt() != 1) return null
        fun field(): ByteArray { val n = d.readInt(); require(n in 0..bytes.size); return ByteArray(n).also { d.readFully(it) } }
        val verifier = field(); val checkpoint = field()
        val count = d.readInt(); require(count in 0..4096)
        val parts = (0 until count).map { SavedPart(field().toString(Charsets.UTF_8), field()) }
        return SavedState(verifier, checkpoint, parts)
    }
}
