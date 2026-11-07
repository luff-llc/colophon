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
            ((parts.size == 2 && parts[0] in setOf("authority", "requests")) ||
                (parts.size == 3 && parts[0] == "ops"))
        if (!ok) throw StorageException.InvalidPath(path)
    }
}

/**
 * A complete readable snapshot, or an explicit error. Partial maps never escape this boundary.
 */
interface RecordStore {
    fun read(): Map<String, ByteArray>
    /** Exact duplicates are idempotent. Existing different bytes are never overwritten. */
    fun append(records: Map<String, ByteArray>)
    fun watch(onChange: () -> Unit): AutoCloseable
}

class MemoryRecordStore(initial: Map<String, ByteArray> = emptyMap()) : RecordStore {
    private val lock = Any()
    private val records = initial.mapValues { it.value.copyOf() }.toMutableMap()
    private val observers = CopyOnWriteArrayList<() -> Unit>()
    @Volatile private var unavailable: String? = null

    fun setUnavailable(reason: String?) {
        synchronized(lock) { unavailable = reason }
        notifyObservers()
    }

    override fun read(): Map<String, ByteArray> = synchronized(lock) {
        unavailable?.let { throw StorageException.Unavailable(it) }
        records.mapValues { it.value.copyOf() }
    }

    override fun append(incoming: Map<String, ByteArray>) {
        val changed = synchronized(lock) {
            unavailable?.let { throw StorageException.Unavailable(it) }
            for ((path, bytes) in incoming) {
                RecordPath.validate(path)
                val old = records[path]
                if (old != null && !old.contentEquals(bytes)) throw StorageException.Conflict(path)
            }
            var added = false
            for ((path, bytes) in incoming) {
                if (records[path] == null) {
                    records[path] = bytes.copyOf()
                    added = true
                }
            }
            added
        }
        if (changed) notifyObservers()
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
class FileRecordStore(val folder: File) : RecordStore {
    private val lock = Any()
    private val knownPaths = mutableSetOf<String>()
    private val observers = CopyOnWriteArrayList<() -> Unit>()

    override fun read(): Map<String, ByteArray> = synchronized(lock) {
        try {
            ensureFolderAccessible()
            val result = mutableMapOf<String, ByteArray>()
            for (directory in listOf("authority", "requests", "ops")) {
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
                collect(root, result)
            }
            if (!knownPaths.all { it in result.keys }) {
                throw StorageException.Unavailable("Previously observed records are missing")
            }
            knownPaths.addAll(result.keys)
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
                    AtomicFile.write(bytes, target, immutable = true)
                }
            } catch (error: StorageException) {
                throw error
            } catch (error: Exception) {
                throw StorageException.Unavailable(error.message ?: error.toString())
            }
        }
        notifyObservers()
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

    private fun collect(root: Path, result: MutableMap<String, ByteArray>) {
        val entries = try {
            Files.newDirectoryStream(root)
        } catch (error: Exception) {
            throw StorageException.Unavailable("Cannot enumerate $root: ${error.message ?: error}")
        }
        entries.use { stream ->
            for (entry in stream) {
                if (Files.isSymbolicLink(entry)) throw StorageException.InvalidPath(entry.toString())
                val name = entry.fileName.toString()
                if (name.startsWith(".")) continue
                if (Files.isDirectory(entry, LinkOption.NOFOLLOW_LINKS)) {
                    if (!Files.isReadable(entry)) throw StorageException.Unavailable("Cannot read $entry")
                    collect(entry, result)
                } else if (Files.isRegularFile(entry, LinkOption.NOFOLLOW_LINKS)) {
                    val file = entry.toFile()
                    val prefix = folder.canonicalFile.path + File.separator
                    val canonical = file.canonicalFile
                    if (!canonical.path.startsWith(prefix)) throw StorageException.InvalidPath(file.path)
                    val path = canonical.path.removePrefix(prefix).replace(File.separatorChar, '/')
                    RecordPath.validate(path)
                    result[path] = AtomicFile.read(file, AtomicFile.MAX_RECORD_BYTES)
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
