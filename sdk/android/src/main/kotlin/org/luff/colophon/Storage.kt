package org.luff.colophon

import java.io.File
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.util.UUID
import java.util.concurrent.CopyOnWriteArrayList

sealed class StorageException(message: String) : Exception(message) {
    class Unavailable(reason: String) : StorageException(reason)
    class InvalidPath(path: String) : StorageException("Invalid record path: $path")
    class Conflict(path: String) : StorageException("Immutable record conflict: $path")
    class Corrupt(reason: String) : StorageException(reason)
    data object LimitExceeded : StorageException("Storage limit exceeded")
}

object RecordPath {
    fun validate(path: String) {
        val parts = path.split("/", limit = 0)
        val valid = { part: String ->
            part.isNotEmpty() && part != "." && part != ".." && !part.startsWith(".") &&
                '\\' !in part && '\u0000' !in part
        }
        val ok = parts.all(valid) && path.toByteArray().size < 512 && path.endsWith(".json") &&
            when (parts.size) {
                2 -> parts[0] in setOf("authority", "requests")
                3 -> parts[0] == "ops"
                4 -> parts[0] in setOf("ops", "state", "history")
                else -> false
            }
        if (!ok) throw StorageException.InvalidPath(path)
    }
    fun isReplaceable(path: String) = path.startsWith("state/")
    fun listingIncludes(path: String, namespaces: List<String>): Boolean {
        val parts = path.split("/", limit = 0)
        if (parts.size == 2 && parts[0] in setOf("authority", "requests")) return true
        if (parts.size == 3 && parts[0] == "ops") return true
        if (parts.size == 4 && parts[0] in setOf("ops", "state", "history")) {
            return namespaces.isEmpty() || parts[2] in namespaces
        }
        return false
    }
    fun missingBlocks(path: String): Boolean {
        val parts = path.split("/", limit = 0)
        return parts.size == 2 || parts[0] == "ops"
    }
}

/**
 * A complete readable snapshot, or an explicit error. Partial maps never escape this boundary.
 */
interface RecordStore {
    fun changeToken(): String? = null
    fun changes(since: String): RecordDelta? = null
    fun read(): Map<String, ByteArray>
    /** Exact duplicates are idempotent. Existing different bytes are never overwritten. */
    fun append(records: Map<String, ByteArray>)
    fun replaceLive(path: String, expected: ByteArray?, bytes: ByteArray): Boolean =
        throw StorageException.Unavailable("This provider does not support conditional live publication")
    fun watch(onChange: () -> Unit): AutoCloseable
    /** Every record path, without reading bytes. Errors are never an empty set. */
    fun paths(): Set<String> = read().keys
    fun paths(namespaces: List<String>): Set<String> = paths().filter { !it.startsWith("history/") && RecordPath.listingIncludes(it, namespaces) }.toSet()
    /** Scoped synchronization inventory, including append-only engagement evidence. */
    fun syncPaths(namespaces: List<String>): Set<String> = paths().filter { RecordPath.listingIncludes(it, namespaces) }.toSet()
    fun versions(paths: Set<String>): Map<String, String> = emptyMap()
    /** Exact bytes of the requested records that exist; absent paths are omitted. */
    fun read(paths: Collection<String>): Map<String, ByteArray> {
        val all = read()
        return paths.mapNotNull { path -> all[path]?.let { path to it } }.toMap()
    }
}

object BlobPath {
    fun validate(path: String) {
        val ok = path.length == 70 && path.startsWith("blobs/") &&
            path.substring(6).all { it in '0'..'9' || it in 'a'..'f' }
        if (!ok) throw StorageException.InvalidPath(path)
    }
}

/** Immutable encrypted blob chunks (`blobs/<sha256>`), never part of record snapshots. */
interface BlobStore {
    /** Ciphertext; a missing chunk throws [StorageException.Unavailable]. */
    fun readBlob(path: String): ByteArray
    fun appendBlob(path: String, bytes: ByteArray)
    /** Presence without reading bytes. */
    fun hasBlob(path: String): Boolean
    /** Local cache eviction; the session's garbage collector decides when it is safe. */
    fun removeBlob(path: String)
    /** Every local chunk with its modification time in epoch milliseconds. */
    fun blobPaths(): Map<String, Long>
}

internal const val MAX_BLOB_CHUNK_BYTES = 65536 + 16

class MemoryRecordStore(initial: Map<String, ByteArray> = emptyMap()) : RecordStore, BlobStore {
    private val lock = Any()
    private val records = initial.mapValues { it.value.copyOf() }.toMutableMap()
    private val versionsByPath = initial.mapValues { java.util.Base64.getEncoder().encodeToString(java.security.MessageDigest.getInstance("SHA-256").digest(it.value)) }.toMutableMap()
    private val recentChanges = java.util.ArrayDeque<Pair<Long, String>>()
    private var changeFloor = 0L
    private var generation = 0L
    private val blobs = mutableMapOf<String, ByteArray>()
    private val blobTimes = mutableMapOf<String, Long>()
    private val observers = CopyOnWriteArrayList<() -> Unit>()
    @Volatile private var unavailable: String? = null
    /** Complete snapshots served, so tests can prove incremental access. */
    @Volatile var fullReads = 0
        private set
    /** Record bodies served by [read] with paths. */
    @Volatile var recordReads = 0
        private set

    override fun changeToken(): String? = synchronized(lock) {
        unavailable?.let { throw StorageException.Unavailable(it) }; generation.toString()
    }
    override fun changes(since: String): RecordDelta? = synchronized(lock) {
        unavailable?.let { throw StorageException.Unavailable(it) }
        val previous = since.toLongOrNull() ?: return@synchronized null
        if (previous < changeFloor || previous > generation) return@synchronized null
        RecordDelta(generation.toString(), recentChanges.filter { it.first > previous }.map { it.second }.toSet())
    }
    override fun paths(): Set<String> = synchronized(lock) {
        unavailable?.let { throw StorageException.Unavailable(it) }
        records.keys.toSet()
    }

    override fun versions(paths: Set<String>): Map<String, String> = synchronized(lock) {
        unavailable?.let { throw StorageException.Unavailable(it) }
        paths.filter { it in records }.associateWith { versionsByPath[it] ?: "" }
    }
    override fun read(paths: Collection<String>): Map<String, ByteArray> = synchronized(lock) {
        unavailable?.let { throw StorageException.Unavailable(it) }
        val result = paths.mapNotNull { path -> records[path]?.let { path to it.copyOf() } }.toMap()
        recordReads += result.size
        result
    }

    override fun readBlob(path: String): ByteArray = synchronized(lock) {
        BlobPath.validate(path)
        unavailable?.let { throw StorageException.Unavailable(it) }
        blobs[path]?.copyOf() ?: throw StorageException.Unavailable("Blob chunk is missing: $path")
    }

    override fun appendBlob(path: String, bytes: ByteArray) = synchronized(lock) {
        BlobPath.validate(path)
        unavailable?.let { throw StorageException.Unavailable(it) }
        if (bytes.size > MAX_BLOB_CHUNK_BYTES) throw StorageException.LimitExceeded
        val old = blobs[path]
        if (old != null && !old.contentEquals(bytes)) throw StorageException.Conflict(path)
        if (old == null) {
            blobs[path] = bytes.copyOf()
            blobTimes[path] = System.currentTimeMillis()
        }
    }

    override fun hasBlob(path: String): Boolean = synchronized(lock) {
        BlobPath.validate(path)
        unavailable?.let { throw StorageException.Unavailable(it) }
        path in blobs
    }

    override fun removeBlob(path: String) {
        synchronized(lock) {
            BlobPath.validate(path)
            blobs.remove(path)
            blobTimes.remove(path)
        }
    }

    override fun blobPaths(): Map<String, Long> = synchronized(lock) {
        unavailable?.let { throw StorageException.Unavailable(it) }
        blobTimes.toMap()
    }

    /** Test seam: age a chunk past a garbage-collection grace period. */
    fun setBlobTime(path: String, millis: Long) = synchronized(lock) {
        if (path in blobs) blobTimes[path] = millis
    }

    fun setUnavailable(reason: String?) {
        synchronized(lock) { unavailable = reason }
        notifyObservers()
    }

    override fun read(): Map<String, ByteArray> = synchronized(lock) {
        unavailable?.let { throw StorageException.Unavailable(it) }
        fullReads += 1
        records.mapValues { it.value.copyOf() }
    }

    override fun append(incoming: Map<String, ByteArray>) {
        val changed = synchronized(lock) {
            unavailable?.let { throw StorageException.Unavailable(it) }
            for ((path, bytes) in incoming) {
                RecordPath.validate(path)
                val old = records[path]
                if (old != null && !old.contentEquals(bytes) && !RecordPath.isReplaceable(path)) {
                    throw StorageException.Conflict(path)
                }
            }
            var added = false
            for ((path, bytes) in incoming) {
                val old = records[path]
                if (old == null || RecordPath.isReplaceable(path) && !old.contentEquals(bytes)) {
                    generation += 1
                    versionsByPath[path] = java.util.Base64.getEncoder().encodeToString(java.security.MessageDigest.getInstance("SHA-256").digest(bytes))
                    recentChanges.addLast(generation to path)
                    if (recentChanges.size > 4096) repeat(2048) { changeFloor = recentChanges.removeFirst().first }
                    records[path] = bytes.copyOf()
                    added = true
                }
            }
            added
        }
        if (changed) notifyObservers()
    }

    override fun replaceLive(path: String, expected: ByteArray?, bytes: ByteArray): Boolean = synchronized(lock) {
        RecordPath.validate(path)
        if (!RecordPath.isReplaceable(path)) throw StorageException.InvalidPath(path)
        unavailable?.let { throw StorageException.Unavailable(it) }
        val old = records[path]
        if (old?.contentEquals(bytes) == true) return@synchronized true
        if (!(old == null && expected == null || old != null && expected != null && old.contentEquals(expected))) return@synchronized false
        append(mapOf(path to bytes)); true
    }
    override fun watch(onChange: () -> Unit): AutoCloseable {
        observers.add(onChange)
        return AutoCloseable { observers.remove(onChange) }
    }

    private fun notifyObservers() {
        for (observer in observers) observer()
    }
}

/**
 * Immutable library records under [folder]. Lives in the app's private files directory.
 */
class FileRecordStore(val folder: File) : RecordStore, BlobStore {
    private val lock = Any()
    private val knownPaths = mutableSetOf<String>()
    private val observers = CopyOnWriteArrayList<() -> Unit>()
    /**
     * Path index: built by one directory walk, then maintained by [append]. The folder is
     * app-private, so this store is its only writer in the process; use one instance per folder.
     */
    private var index: MutableSet<String>? = null

    override fun versions(paths: Set<String>): Map<String, String> = synchronized(lock) {
        paths.associateWith { path ->
            RecordPath.validate(path); rejectSymlinkPath(path)
            val attrs = Files.readAttributes(File(folder, path).toPath(), java.nio.file.attribute.BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
            "${attrs.fileKey()}:${attrs.size()}:${attrs.lastModifiedTime()}"
        }
    }
    override fun paths(namespaces: List<String>): Set<String> = scopedPaths(namespaces, false)
    override fun syncPaths(namespaces: List<String>): Set<String> = scopedPaths(namespaces, true)
    private fun scopedPaths(namespaces: List<String>, includeHistory: Boolean): Set<String> = synchronized(lock) {
        ensureFolderAccessible()
        val found = mutableSetOf<String>()
        for (directory in listOf("authority", "requests", "ops", "state") + if (includeHistory) listOf("history") else emptyList()) {
            val root = folder.toPath().resolve(directory)
            if (Files.isSymbolicLink(root)) throw StorageException.InvalidPath(root.toString())
            if (Files.exists(root, LinkOption.NOFOLLOW_LINKS)) collect(root, null, found, namespaces)
            else if (!Files.notExists(root, LinkOption.NOFOLLOW_LINKS)) throw StorageException.Unavailable("Cannot access $root")
        }
        if (!knownPaths.filter { RecordPath.missingBlocks(it) && RecordPath.listingIncludes(it, namespaces) }.all { it in found }) {
            throw StorageException.Unavailable("Previously observed records are missing")
        }
        knownPaths.addAll(found)
        found.toSet()
    }
    override fun paths(): Set<String> = synchronized(lock) {
        index?.let { return it.toSet() }
        try {
            ensureFolderAccessible()
            val found = mutableSetOf<String>()
            for (directory in listOf("authority", "requests", "ops", "state", "history")) {
                val root = folder.toPath().resolve(directory)
                if (Files.isSymbolicLink(root)) throw StorageException.InvalidPath(root.toString())
                if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) {
                    if (!Files.notExists(root, LinkOption.NOFOLLOW_LINKS)) throw StorageException.Unavailable("Cannot access $root")
                    continue
                }
                collect(root, null, found)
            }
            if (!knownPaths.filter { RecordPath.missingBlocks(it) }.all { it in found }) {
                throw StorageException.Unavailable("Previously observed records are missing")
            }
            knownPaths.addAll(found)
            index = found
            found.toSet()
        } catch (error: StorageException) {
            throw error
        } catch (error: Exception) {
            throw StorageException.Unavailable(error.message ?: error.toString())
        }
    }

    override fun read(paths: Collection<String>): Map<String, ByteArray> = synchronized(lock) {
        try {
            ensureFolderAccessible()
            val result = mutableMapOf<String, ByteArray>()
            for (path in paths) {
                RecordPath.validate(path)
                rejectSymlinkPath(path)
                val file = File(folder, path.replace('/', File.separatorChar))
                if (!Files.exists(file.toPath(), LinkOption.NOFOLLOW_LINKS)) {
                    if (path in knownPaths) throw StorageException.Unavailable("Previously observed record is missing: $path")
                    continue
                }
                result[path] = AtomicFile.read(file, AtomicFile.MAX_RECORD_BYTES)
            }
            result
        } catch (error: StorageException) {
            throw error
        } catch (error: Exception) {
            throw StorageException.Unavailable(error.message ?: error.toString())
        }
    }

    private fun blobFile(path: String): File {
        BlobPath.validate(path)
        rejectSymlinkPath(path)
        return File(File(folder, "blobs"), path.substring(6))
    }

    override fun readBlob(path: String): ByteArray {
        val file = blobFile(path)
        if (!file.exists()) throw StorageException.Unavailable("Blob chunk is missing: $path")
        return AtomicFile.read(file, MAX_BLOB_CHUNK_BYTES)
    }

    override fun appendBlob(path: String, bytes: ByteArray) {
        if (bytes.size > MAX_BLOB_CHUNK_BYTES) throw StorageException.LimitExceeded
        val file = blobFile(path)
        AtomicFile.write(bytes, file, immutable = true)
    }

    override fun hasBlob(path: String): Boolean = blobFile(path).exists()

    override fun removeBlob(path: String) {
        val file = blobFile(path)
        if (file.exists() && !file.delete()) throw StorageException.Unavailable("Cannot remove $path")
    }

    override fun blobPaths(): Map<String, Long> {
        val root = File(folder, "blobs")
        if (Files.isSymbolicLink(root.toPath())) throw StorageException.InvalidPath(root.path)
        val names = root.list() ?: return if (root.exists()) throw StorageException.Unavailable("Cannot list blobs") else emptyMap()
        return names.filter { !it.startsWith(".") && it.length == 64 }
            .associate { "blobs/$it" to File(root, it).lastModified() }
    }

    override fun read(): Map<String, ByteArray> = synchronized(lock) {
        try {
            ensureFolderAccessible()
            val result = mutableMapOf<String, ByteArray>()
            for (directory in listOf("authority", "requests", "ops", "state", "history")) {
                val root = folder.toPath().resolve(directory)
                if (Files.isSymbolicLink(root)) throw StorageException.InvalidPath(root.toString())
                if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) {
                    if (!Files.notExists(root, LinkOption.NOFOLLOW_LINKS)) {
                        throw StorageException.Unavailable("Cannot access $root")
                    }
                    continue
                }
                if (!Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) {
                    throw StorageException.Unavailable("Cannot enumerate $directory")
                }
                if (!Files.isReadable(root)) throw StorageException.Unavailable("Cannot read $root")
                collect(root, result, null)
            }
            if (!knownPaths.all { it in result.keys }) {
                throw StorageException.Unavailable("Previously observed records are missing")
            }
            knownPaths.addAll(result.keys)
            index = result.keys.toMutableSet()
            result
        } catch (error: StorageException) {
            throw error
        } catch (error: Exception) {
            throw StorageException.Unavailable(error.message ?: error.toString())
        }
    }

    override fun append(records: Map<String, ByteArray>) {
        synchronized(lock) {
            try {
                for ((path, bytes) in records) {
                    if (bytes.size > AtomicFile.MAX_RECORD_BYTES) throw StorageException.LimitExceeded
                    RecordPath.validate(path)
                }
                if (!folder.exists() && !folder.mkdirs()) {
                    throw StorageException.Unavailable("Cannot create ${folder.path}")
                }
                for (path in records.keys.sorted()) {
                    val bytes = records[path] ?: continue
                    rejectSymlinkPath(path)
                    val target = File(folder, path.replace('/', File.separatorChar))
                    AtomicFile.write(bytes, target, immutable = !RecordPath.isReplaceable(path))
                    index?.add(path)
                }
            } catch (error: StorageException) {
                throw error
            } catch (error: Exception) {
                throw StorageException.Unavailable(error.message ?: error.toString())
            }
        }
        notifyObservers()
    }

    override fun replaceLive(path: String, expected: ByteArray?, bytes: ByteArray): Boolean = synchronized(lock) {
        RecordPath.validate(path); rejectSymlinkPath(path)
        if (!RecordPath.isReplaceable(path)) throw StorageException.InvalidPath(path)
        folder.mkdirs()
        java.io.RandomAccessFile(File(folder, ".live.lock"), "rw").use { lockFile ->
            lockFile.channel.lock().use {
                val file = File(folder, path)
                val old = if (file.exists()) AtomicFile.read(file, AtomicFile.MAX_RECORD_BYTES) else null
                if (old?.contentEquals(bytes) == true) return@synchronized true
                if (!(old == null && expected == null || old != null && expected != null && old.contentEquals(expected))) return@synchronized false
                append(mapOf(path to bytes)); true
            }
        }
    }
    override fun watch(onChange: () -> Unit): AutoCloseable {
        observers.add(onChange)
        return AutoCloseable { observers.remove(onChange) }
    }

    private fun notifyObservers() {
        for (observer in observers) observer()
    }

    /** Absence is an empty library. An unreadable or indeterminate path is not absence. */
    private fun ensureFolderAccessible() {
        val path = folder.toPath()
        if (Files.isSymbolicLink(path)) throw StorageException.InvalidPath(folder.path)
        val exists = Files.exists(path, LinkOption.NOFOLLOW_LINKS)
        val missing = Files.notExists(path, LinkOption.NOFOLLOW_LINKS)
        if (!exists && !missing) throw StorageException.Unavailable("Cannot access ${folder.path}")
        if (!exists) return
        if (!Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS) || !Files.isReadable(path)) {
            throw StorageException.Unavailable("Cannot read ${folder.path}")
        }
    }

    private fun collect(root: Path, result: MutableMap<String, ByteArray>?, found: MutableSet<String>?, namespaces: List<String>? = null) {
        val entries = try {
            Files.newDirectoryStream(root)
        } catch (error: Exception) {
            throw StorageException.Unavailable("Cannot enumerate $root: ${error.message ?: error}")
        }
        entries.use { stream ->
            for (entry in stream) {
                val relative = folder.toPath().relativize(entry).map { it.toString() }
                if (namespaces != null && namespaces.isNotEmpty() && relative.size >= 3 && relative[0] in listOf("ops", "state", "history") && !relative[2].endsWith(".json") && relative[2] !in namespaces) continue
                if (Files.isSymbolicLink(entry)) throw StorageException.InvalidPath(entry.toString())
                val name = entry.fileName.toString()
                if (name.startsWith(".")) continue
                if (Files.isDirectory(entry, LinkOption.NOFOLLOW_LINKS)) {
                    if (!Files.isReadable(entry)) throw StorageException.Unavailable("Cannot read $entry")
                    collect(entry, result, found, namespaces)
                } else if (Files.isRegularFile(entry, LinkOption.NOFOLLOW_LINKS)) {
                    val file = entry.toFile()
                    val prefix = folder.canonicalFile.path + File.separator
                    val canonical = file.canonicalFile
                    if (!canonical.path.startsWith(prefix)) throw StorageException.InvalidPath(file.path)
                    val path = canonical.path.removePrefix(prefix).replace(File.separatorChar, '/')
                    RecordPath.validate(path)
                    found?.add(path)
                    result?.put(path, AtomicFile.read(file, AtomicFile.MAX_RECORD_BYTES))
                }
            }
        }
    }

    private fun rejectSymlinkPath(relative: String) {
        var current = folder.toPath()
        if (Files.isSymbolicLink(current)) throw StorageException.InvalidPath(folder.path)
        for (part in relative.split('/')) {
            current = current.resolve(part)
            if (Files.isSymbolicLink(current)) throw StorageException.InvalidPath(relative)
        }
    }
}

/**
 * Opaque engine-owned cache bytes. Only the engine may validate a verified prefix.
 * This folder belongs in the app's private container, never a shared library directory.
 */
class CheckpointCache(private val folder: File) {
    fun load(libraryID: String): ByteArray? {
        val file = location(libraryID)
        if (!file.exists()) return null
        return AtomicFile.read(file, AtomicFile.MAX_CHECKPOINT_BYTES)
    }

    fun save(bytes: ByteArray, libraryID: String) {
        if (bytes.size > AtomicFile.MAX_CHECKPOINT_BYTES) throw StorageException.LimitExceeded
        AtomicFile.write(bytes, location(libraryID))
    }

    fun remove(libraryID: String) {
        val file = location(libraryID)
        if (file.exists() && !file.delete()) {
            throw StorageException.Unavailable("Cannot remove checkpoint for $libraryID")
        }
    }

    private fun location(id: String): File {
        if (id.length != 32 || !id.all { it in '0'..'9' || it in 'a'..'f' }) {
            throw StorageException.InvalidPath(id)
        }
        if (!folder.exists()) folder.mkdirs()
        return File(folder, "$id.checkpoint")
    }
}

internal fun newId(): UUID = UUID.randomUUID()

data class RecordDelta(val token: String, val paths: Set<String>)
