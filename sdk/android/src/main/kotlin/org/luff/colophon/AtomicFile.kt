package org.luff.colophon

import com.sun.jna.Function
import com.sun.jna.LastErrorException
import com.sun.jna.Native
import com.sun.jna.NativeLibrary
import java.io.File
import java.io.FileOutputStream
import java.io.RandomAccessFile
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.FileAlreadyExistsException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermission
import java.util.UUID

/**
 * Stage, fsync, then publish. Immutable records are published exclusively: a hard link
 * where the platform allows it, otherwise `renameat2(RENAME_NOREPLACE)`. Android denies
 * `link(2)` in private app storage, and a plain rename would replace an existing record.
 * When `renameat2` is missing, publication copies with `O_CREAT|O_EXCL` and never renames
 * over an existing file. Mutable files (the session journal, checkpoints) use an atomic
 * rename that replaces an existing file. Android's [File.renameTo] does not.
 */
internal object AtomicFile {
    const val MAX_RECORD_BYTES = 16 * 1024 * 1024
    const val MAX_JOURNAL_BYTES = 64 * 1024 * 1024
    const val MAX_CHECKPOINT_BYTES = 64 * 1024 * 1024

    private const val AT_FDCWD = -100
    private const val RENAME_NOREPLACE = 1
    private const val EEXIST = 17
    private const val EINVAL = 22
    private const val ENOSYS = 38

    /**
     * Resolved once. `THROW_LAST_ERROR` captures `errno` in the native call so a failed
     * `renameat2` is not reported as `-1` after `errno` has been clobbered.
     */
    private val renameAt2: Function? by lazy { resolveRenameAt2() }

    fun write(bytes: ByteArray, to: File, immutable: Boolean = false) {
        if (bytes.size > MAX_JOURNAL_BYTES) throw StorageException.LimitExceeded
        val parent = to.parentFile ?: throw StorageException.Unavailable("Missing parent for ${to.path}")
        if (!parent.exists() && !parent.mkdirs()) {
            throw StorageException.Unavailable("Cannot create ${parent.path}")
        }
        val staged = File(parent, ".stage-${UUID.randomUUID()}")
        try {
            FileOutputStream(staged).use { stream ->
                stream.write(bytes)
                stream.flush()
                stream.fd.sync()
            }
            try {
                Files.setPosixFilePermissions(
                    staged.toPath(),
                    setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE),
                )
            } catch (_: Exception) {
                // Private app storage is already owner-only when POSIX permissions are unavailable.
            }
            if (immutable) publishImmutable(staged, to, bytes) else publishReplace(staged, to)
            syncDirectory(parent)
        } catch (error: StorageException) {
            throw error
        } catch (error: Exception) {
            val detail = listOfNotNull(error.javaClass.simpleName, error.message).joinToString(": ")
            throw StorageException.Unavailable(detail.ifEmpty { "Cannot publish ${to.path}" })
        } finally {
            if (staged.exists()) staged.delete()
        }
    }

    private fun publishImmutable(staged: File, to: File, bytes: ByteArray) {
        try {
            Files.createLink(to.toPath(), staged.toPath())
        } catch (_: FileAlreadyExistsException) {
            ensureSame(to, bytes)
        } catch (_: Exception) {
            // Untrusted Android apps get EACCES from link(2) on their own files.
            publishExclusiveRename(staged, to, bytes)
        }
    }

    private fun publishExclusiveRename(staged: File, to: File, bytes: ByteArray) {
        when (val errno = renameNoReplace(staged.path, to.path)) {
            0 -> Unit
            EEXIST -> ensureSame(to, bytes)
            null, ENOSYS, EINVAL -> moveIfAbsent(staged, to, bytes)
            else -> throw StorageException.Unavailable("Cannot publish ${to.path} (errno $errno)")
        }
    }

    /**
     * Linux `rename(2)` replaces the destination. `RENAME_NOREPLACE` keeps the conflict
     * check atomic. Returns null when this process has no `renameat2`.
     * `0` is success. A positive value is `errno`.
     */
    internal fun renameNoReplace(from: String, to: String): Int? {
        val renameat2 = renameAt2 ?: return null
        return try {
            val args = arrayOf<Any>(AT_FDCWD, from, AT_FDCWD, to, RENAME_NOREPLACE)
            val rc = renameat2.invokeInt(args)
            if (rc == 0) 0 else {
                val errno = Native.getLastError()
                if (errno != 0) errno else rc
            }
        } catch (error: LastErrorException) {
            val errno = error.errorCode
            if (errno != 0) errno else -1
        } catch (_: UnsatisfiedLinkError) {
            null
        }
    }

    /**
     * Desktop libc (glibc 2.28+) also exports `renameat2`. Probing it makes host JVM
     * tests observe `ENOENT` instead of the POSIX `Files.copy` fallback. Android is
     * the only runtime that needs this call: `link(2)` is denied in private app storage.
     */
    internal fun isAndroidRuntime(
        buildPropExists: Boolean = File("/system/build.prop").isFile,
        vmName: String = System.getProperty("java.vm.name") ?: "",
        runtimeName: String = System.getProperty("java.runtime.name") ?: "",
    ): Boolean {
        if (buildPropExists) return true
        if (vmName.contains("Dalvik", ignoreCase = true)) return true
        if (runtimeName.contains("Android", ignoreCase = true)) return true
        return false
    }

    private fun resolveRenameAt2(): Function? {
        if (!isAndroidRuntime()) return null
        val names = listOf("c", "libc.so", "/system/lib64/libc.so", "/system/lib/libc.so")
        for (name in names) {
            if (name.startsWith("/") && !File(name).isFile) continue
            try {
                return NativeLibrary.getInstance(name).getFunction("renameat2", Function.THROW_LAST_ERROR)
            } catch (_: Throwable) {
                // Try the next libc name. Hosts without Android bionic return null.
            }
        }
        return null
    }

    /**
     * Last-resort exclusive publish. `Files.copy` uses `O_CREAT|O_EXCL` on POSIX and
     * throws [FileAlreadyExistsException] instead of replacing the destination.
     * `Files.move(ATOMIC_MOVE)` is `rename(2)`, which would clobber an existing record.
     */
    internal fun moveIfAbsent(staged: File, to: File, bytes: ByteArray) {
        try {
            Files.copy(staged.toPath(), to.toPath())
            FileOutputStream(to, true).use { it.fd.sync() }
        } catch (_: FileAlreadyExistsException) {
            ensureSame(to, bytes)
        }
    }

    private fun publishReplace(staged: File, to: File) {
        try {
            Files.move(
                staged.toPath(),
                to.toPath(),
                StandardCopyOption.REPLACE_EXISTING,
                StandardCopyOption.ATOMIC_MOVE,
            )
        } catch (_: AtomicMoveNotSupportedException) {
            Files.move(staged.toPath(), to.toPath(), StandardCopyOption.REPLACE_EXISTING)
        }
    }

    private fun ensureSame(to: File, bytes: ByteArray) {
        if (to.length() != bytes.size.toLong()) throw StorageException.Conflict(to.path)
        val existing = read(to, bytes.size.coerceAtLeast(1))
        if (!existing.contentEquals(bytes)) throw StorageException.Conflict(to.path)
    }

    fun read(file: File, maximumBytes: Int): ByteArray {
        if (!file.isFile) throw StorageException.Unavailable("Not a regular file: ${file.path}")
        if (file.length() > maximumBytes) throw StorageException.LimitExceeded
        val bytes = file.readBytes()
        if (bytes.size > maximumBytes) throw StorageException.LimitExceeded
        return bytes
    }

    private fun syncDirectory(directory: File) {
        try {
            RandomAccessFile(directory, "r").use { file ->
                file.channel.force(true)
            }
        } catch (_: Exception) {
            try {
                FileOutputStream(directory).use { it.fd.sync() }
            } catch (_: Exception) {
                // Directory fsync is best-effort on filesystems that refuse a directory fd.
            }
        }
    }
}

internal fun mapsEqual(left: Map<String, ByteArray>?, right: Map<String, ByteArray>?): Boolean {
    if (left === right) return true
    if (left == null || right == null || left.size != right.size) return false
    return left.all { (path, bytes) -> right[path]?.contentEquals(bytes) == true }
}
