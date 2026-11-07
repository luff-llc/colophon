package org.luff.colophon

import java.io.File

/**
 * Shared upgrade status, outside the immutable record tree: no payloads, keys or grants.
 * While a marker is active, ordinary sessions report [SessionPhase.Migrating] instead of an empty
 * library, and only the session configured with `migrationWriter = true` writes.
 */
data class MigrationMarker(val sourceLibraryID: String, val active: Boolean) {
    fun save(file: File) {
        val text = "{\"sourceLibraryID\":${jsonString(sourceLibraryID)},\"active\":$active}"
        AtomicFile.write(text.toByteArray(Charsets.UTF_8), file)
    }

    companion object {
        /** A missing marker is inactive. An unreadable or malformed one fails closed (throws). */
        fun isActive(file: File): Boolean {
            if (!file.exists()) return false
            val root = JsonParser(AtomicFile.read(file, 4096).decodeToString()).parseValue() as? Json.Obj
                ?: throw StorageException.Corrupt("Malformed migration marker")
            return root.bool("active") ?: throw StorageException.Corrupt("Malformed migration marker")
        }
    }
}

internal const val IMPORT_BATCH = "colophon.importBatch"
internal const val BLOB_PUBLISH = "colophon.blobPublish"
internal const val BLOB_REFERENCE = "colophon.blobReference"
