package com.luff.colophon.session

import com.luff.colophon.HostSource
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.StandardCopyOption
import java.util.UUID

/** A path the medium holds and the provider's content-version token for it (null: no cheap version). */
data class MediumEntry(val path: String, val version: String?)

/** Exact bytes to store at a path. */
class MediumWrite(val path: String, val bytes: ByteArray)

sealed class StorageException(message: String) : IOException(message) {
    /** The medium cannot answer now. Never read as "empty". */
    class Unavailable(val reason: String) : StorageException(reason)
    class InvalidPath(val path: String) : StorageException("Invalid record path: $path")
    /** Immutable bytes already exist at the path and differ. */
    class Conflict(val path: String) : StorageException("Immutable record conflict: $path")
    class LimitExceeded : StorageException("Storage limit exceeded")
}

/**
 * Where an account's records live: the host's record store of docs/bindings-05.md. Every call is synchronous (the
 * engine's `HostSource` callbacks run on the engine's lane and need the bytes at once) and thread-safe. A medium must
 * not call into the engine.
 */
interface RecordMedium {
    /** Every path held, with versions, in one batch. A listing that cannot be completed throws: an error is never an empty store. */
    fun listing(): List<MediumEntry>
    /** The exact bytes at `path`. Missing or unreadable throws [StorageException.Unavailable]. */
    fun read(path: String): ByteArray
    /** A blob chunk's ciphertext; empty means "not held here" (the engine fetches it from a home). */
    fun readBlob(path: String): ByteArray
    /**
     * Stores every write, in order, or none. Exact duplicates are idempotent; different bytes at an existing path are
     * [StorageException.Conflict] except at a replaceable path (`state/`, `heads/`).
     */
    fun write(writes: List<MediumWrite>)
    /** Wake-up hints when something changes (this process's own writes included). A hint carries nothing: list again. */
    fun changes(): Flow<Unit>
}

object RecordPaths {
    /** The largest stored object (docs/bindings-05.md §5: a request or entry blob is 40 MiB). */
    const val MAXIMUM_BYTES = 40 * 1024 * 1024

    /** A relative path of at most 512 bytes, in components that are neither empty nor hidden. */
    fun validate(path: String) {
        val bytes = path.toByteArray(Charsets.UTF_8)
        if (bytes.isEmpty() || bytes.size > 512 || bytes.contains(0) || bytes.contains(92) || bytes.first() == 47.toByte() || bytes.last() == 47.toByte()) {
            throw StorageException.InvalidPath(path)
        }
        for (part in path.split('/')) {
            if (part.isEmpty() || part.toByteArray(Charsets.UTF_8).size > 255 || part.startsWith(".")) throw StorageException.InvalidPath(path)
        }
    }
    /** Live slots and head marks are replaced by newer bytes; everything else is immutable. */
    fun isReplaceable(path: String) = path.startsWith("state/") || path.startsWith("heads/")
    fun isBlob(path: String) = path.startsWith("blobs/")
}

/** The record source the engine reads through: the medium, nothing else. It never calls the engine. */
class MediumSource(private val medium: RecordMedium) : HostSource {
    override fun read(path: String): ByteArray = medium.read(path)
    override fun readBlob(path: String): ByteArray = medium.readBlob(path)
}

/** An in-memory medium for tests and previews, with the folder's all-or-none contract. */
class MemoryMedium(files: Map<String, ByteArray> = mapOf()) : RecordMedium {
    private val lock = Any()
    private val files = HashMap(files)
    private val versions = HashMap<String, Long>().also { v -> files.keys.forEach { v[it] = 0 } }
    private var generation = 0L
    private val hints = MutableSharedFlow<Unit>(extraBufferCapacity = 1, onBufferOverflow = BufferOverflow.DROP_OLDEST)

    fun snapshot(): Map<String, ByteArray> = synchronized(lock) { HashMap(files) }
    fun copy(): MemoryMedium = MemoryMedium(snapshot())
    /** Puts bytes without the immutability check (a test of an outside change). */
    fun put(path: String, bytes: ByteArray) {
        synchronized(lock) { files[path] = bytes; generation++; versions[path] = generation }
        hints.tryEmit(Unit)
    }

    override fun listing(): List<MediumEntry> = synchronized(lock) { files.keys.sorted().map { MediumEntry(it, (versions[it] ?: 0).toString()) } }
    override fun read(path: String): ByteArray = synchronized(lock) { files[path] ?: throw StorageException.Unavailable("Missing record: $path") }
    override fun readBlob(path: String): ByteArray = synchronized(lock) { files[path] ?: ByteArray(0) }
    override fun write(writes: List<MediumWrite>) {
        synchronized(lock) {
            for (w in writes) {
                RecordPaths.validate(w.path)
                if (w.bytes.size > RecordPaths.MAXIMUM_BYTES) throw StorageException.LimitExceeded()
            }
            val undo = ArrayList<Pair<String, ByteArray?>>()
            try {
                for (w in writes) {
                    val old = files[w.path]
                    if (old != null && old.contentEquals(w.bytes)) continue
                    if (old != null && !RecordPaths.isReplaceable(w.path)) throw StorageException.Conflict(w.path)
                    undo.add(w.path to old)
                    files[w.path] = w.bytes
                }
            } catch (e: Exception) {
                for ((p, old) in undo.asReversed()) if (old == null) files.remove(p) else files[p] = old
                throw e
            }
            generation++
            for (w in writes) versions[w.path] = generation
        }
        hints.tryEmit(Unit)
    }
    override fun changes(): Flow<Unit> = hints.asSharedFlow()
}

/**
 * A folder of record files (an app's private directory on Android, a temporary directory in tests). Each [write] is
 * all or none, across a kill at any step: the batch is staged under `.colophon/staging/<id>/`, a commit record naming
 * its paths is published by an atomic rename (the commit point), the files are moved into place, and the record is
 * removed. The next call in any process finishes a committed batch and discards an uncommitted one. Paths are
 * validated, never followed through a symbolic link, and hidden files are not listed. Thread-safe within one process;
 * one process per folder (Android app-private storage).
 */
class FolderMedium(val root: File) : RecordMedium {
    private val lock = Any()
    private val control = File(root, ".colophon")
    private val staging = File(control, "staging")
    private val hints = MutableSharedFlow<Unit>(extraBufferCapacity = 1, onBufferOverflow = BufferOverflow.DROP_OLDEST)
    @Volatile private var recovered = false

    private fun file(path: String): File {
        RecordPaths.validate(path)
        val f = File(root, path)
        // No component may be a symbolic link (a link in an app's private folder is never ours).
        var p: File? = f
        while (p != null && p != root) {
            if (Files.isSymbolicLink(p.toPath())) throw StorageException.InvalidPath(path)
            p = p.parentFile
        }
        return f
    }

    private fun recover() {
        if (recovered) return
        synchronized(lock) {
            if (recovered) return
            if (!root.isDirectory && !root.mkdirs()) throw StorageException.Unavailable("cannot create ${root.path}")
            control.listFiles()?.filter { it.name.startsWith("commit-") }?.forEach { commit -> applyCommit(commit) }
            staging.listFiles()?.forEach { it.deleteRecursively() }
            recovered = true
        }
    }

    /** Moves a committed batch's staged files into place (idempotent), then removes the commit record. */
    private fun applyCommit(commit: File) {
        val id = commit.name.removePrefix("commit-")
        val dir = File(staging, id)
        for (line in commit.readLines(Charsets.UTF_8)) {
            if (line.isEmpty()) continue
            val n = line.substringBefore(' ')
            val path = line.substringAfter(' ')
            val staged = File(dir, n)
            if (!staged.exists()) continue
            val target = file(path)
            target.parentFile.mkdirs()
            move(staged, target)
        }
        dir.deleteRecursively()
        commit.delete()
        fsyncDir(control)
    }

    override fun listing(): List<MediumEntry> {
        recover()
        synchronized(lock) {
            val out = ArrayList<MediumEntry>()
            fun walk(dir: File, prefix: String) {
                val children = dir.listFiles() ?: throw StorageException.Unavailable("cannot list ${dir.path}")
                for (c in children) {
                    if (c.name.startsWith(".")) continue
                    if (Files.isSymbolicLink(c.toPath())) continue
                    val rel = if (prefix.isEmpty()) c.name else "$prefix/${c.name}"
                    if (c.isDirectory) walk(c, rel)
                    else if (c.isFile) {
                        val attrs = Files.readAttributes(c.toPath(), java.nio.file.attribute.BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
                        out.add(MediumEntry(rel, "${attrs.size()}-${attrs.lastModifiedTime().toMillis()}-${attrs.fileKey() ?: ""}"))
                    }
                }
            }
            walk(root, "")
            out.sortBy { it.path }
            return out
        }
    }

    override fun read(path: String): ByteArray {
        recover()
        val f = file(path)
        try {
            if (Files.size(f.toPath()) > RecordPaths.MAXIMUM_BYTES) throw StorageException.LimitExceeded()
            return Files.readAllBytes(f.toPath())
        } catch (e: StorageException) {
            throw e
        } catch (e: java.nio.file.NoSuchFileException) {
            throw StorageException.Unavailable("Missing record: $path")
        } catch (e: IOException) {
            throw StorageException.Unavailable("Cannot read $path: ${e.message}")
        }
    }

    override fun readBlob(path: String): ByteArray {
        recover()
        val f = file(path)
        if (!f.exists()) return ByteArray(0)
        return try { Files.readAllBytes(f.toPath()) } catch (e: IOException) { throw StorageException.Unavailable("Cannot read $path: ${e.message}") }
    }

    override fun write(writes: List<MediumWrite>) {
        recover()
        if (writes.isEmpty()) return
        synchronized(lock) {
            for (w in writes) {
                file(w.path)
                if (w.bytes.size > RecordPaths.MAXIMUM_BYTES) throw StorageException.LimitExceeded()
            }
            // Decide what changes, refusing a conflict before anything is staged.
            val changes = LinkedHashMap<String, ByteArray>()
            for (w in writes) {
                val target = file(w.path)
                val existing = if (target.isFile) Files.readAllBytes(target.toPath()) else null
                if (existing != null && existing.contentEquals(w.bytes)) continue
                if (existing != null && !RecordPaths.isReplaceable(w.path)) throw StorageException.Conflict(w.path)
                val earlier = changes[w.path]
                if (earlier != null && !earlier.contentEquals(w.bytes) && !RecordPaths.isReplaceable(w.path)) throw StorageException.Conflict(w.path)
                changes[w.path] = w.bytes
            }
            if (changes.isEmpty()) return
            val id = UUID.randomUUID().toString()
            val dir = File(staging, id)
            try {
                if (!dir.mkdirs()) throw StorageException.Unavailable("cannot stage a write in ${dir.path}")
                val lines = StringBuilder()
                changes.entries.forEachIndexed { n, (path, bytes) ->
                    FileOutputStream(File(dir, n.toString())).use { out -> out.write(bytes); out.fd.sync() }
                    lines.append(n).append(' ').append(path).append('\n')
                }
                fsyncDir(dir)
                val pending = File(control, ".commit-$id")
                FileOutputStream(pending).use { out -> out.write(lines.toString().toByteArray(Charsets.UTF_8)); out.fd.sync() }
                val commit = File(control, "commit-$id")
                move(pending, commit)
                fsyncDir(control)
                applyCommit(commit)
            } catch (e: StorageException) {
                dir.deleteRecursively(); throw e
            } catch (e: IOException) {
                dir.deleteRecursively(); throw StorageException.Unavailable("Cannot write: ${e.message}")
            }
        }
        hints.tryEmit(Unit)
    }

    override fun changes(): Flow<Unit> = hints.asSharedFlow()

    private fun move(from: File, to: File) {
        try {
            Files.move(from.toPath(), to.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
        } catch (_: AtomicMoveNotSupportedException) {
            Files.move(from.toPath(), to.toPath(), StandardCopyOption.REPLACE_EXISTING)
        }
    }
    private fun fsyncDir(dir: File) {
        // A directory fsync is not possible through every JVM; where it is not, the rename is still atomic.
        try { java.nio.channels.FileChannel.open(dir.toPath(), java.nio.file.StandardOpenOption.READ).use { it.force(true) } } catch (_: Exception) {}
    }
}
