package org.luff.colophon

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.nio.file.Files

class StorageTest {
    private fun temp(): java.io.File = Files.createTempDirectory("colophon-store-").toFile().also { it.deleteOnExit() }

    @Test
    fun atomicWriteIsDurableAndImmutable() {
        val root = temp()
        val file = java.io.File(root, "private.json")
        AtomicFile.write("old".toByteArray(), file)
        assertEquals("old", file.readText())
        try {
            AtomicFile.write("new".toByteArray(), file, immutable = true)
            fail("expected conflict")
        } catch (_: StorageException.Conflict) {
        }
        assertEquals("old", file.readText())
        AtomicFile.write("old".toByteArray(), file, immutable = true)
        AtomicFile.write("replaced".toByteArray(), file, immutable = false)
        assertEquals("replaced", file.readText())
    }

    @Test
    fun fileStoreRejectsConflictsAndInvalidPaths() {
        val store = FileRecordStore(java.io.File(temp(), "library"))
        val record = mapOf("authority/00000001.json" to "one".toByteArray())
        store.append(record)
        store.append(record)
        try {
            store.append(mapOf("authority/00000001.json" to "two".toByteArray()))
            fail("expected conflict")
        } catch (_: StorageException.Conflict) {
        }
        try {
            store.append(mapOf("authority/../secret.json" to ByteArray(0)))
            fail("expected invalid path")
        } catch (_: StorageException.InvalidPath) {
        }
        val read = store.read()
        assertArrayEquals("one".toByteArray(), read["authority/00000001.json"])
    }

    @Test
    fun missingObservedRecordsAreUnavailable() {
        val folder = java.io.File(temp(), "library")
        val store = FileRecordStore(folder)
        store.append(mapOf("authority/00000001.json" to "one".toByteArray()))
        store.read()
        java.io.File(folder, "authority/00000001.json").delete()
        try {
            store.read()
            fail("expected unavailable")
        } catch (error: StorageException.Unavailable) {
            assertTrue(error.message!!.contains("missing"))
        }
    }

    @Test
    fun checkpointCacheRoundTrip() {
        val cache = CheckpointCache(java.io.File(temp(), "checkpoints"))
        val id = "0123456789abcdef0123456789abcdef"
        assertNull(cache.load(id))
        cache.save("state".toByteArray(), id)
        assertArrayEquals("state".toByteArray(), cache.load(id))
        cache.remove(id)
        assertNull(cache.load(id))
        try {
            cache.save(ByteArray(1), "not-a-library-id")
            fail("expected invalid id")
        } catch (_: StorageException.InvalidPath) {
        }
    }

    @Test
    fun journalRoundTripAndCorruptDecode() {
        val file = java.io.File(temp(), "session.json")
        val journal = SessionJournal(
            libraryID = "0123456789abcdef0123456789abcdef",
            left = false,
            knownPaths = mutableSetOf("authority/00000001.json"),
            pending = mutableMapOf("ops/notes/abc.json" to "bytes".toByteArray()),
        )
        journal.save(file)
        val loaded = SessionJournal.load(file)
        assertEquals(journal.libraryID, loaded.libraryID)
        assertEquals(journal.knownPaths, loaded.knownPaths)
        assertArrayEquals("bytes".toByteArray(), loaded.pending["ops/notes/abc.json"])
        AtomicFile.write("not-json".toByteArray(), file)
        try {
            SessionJournal.load(file)
            fail("corrupt journal must fail closed")
        } catch (_: StorageException) {
        }
    }
}
