package org.luff.colophon

import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File
import java.nio.file.Files

class SessionBlobTest {
    private val homes = mutableListOf<File>()
    private val sessions = mutableListOf<ColophonSession>()
    private var relay: ReferenceRelay? = null

    @After
    fun cleanUp() {
        sessions.forEach { it.close() }
        relay?.close()
        homes.forEach { it.deleteRecursively() }
    }

    private fun home(): File = Files.createTempDirectory("colophon-blob-session-").toFile().also { homes += it }

    private fun session(
        store: RecordStore,
        home: File = home(),
        relay: ReferenceRelay? = null,
        marker: File? = null,
        writer: Boolean = false,
    ) = ColophonSession(
        SessionConfiguration(
            memberLabel = "Device",
            namespaces = listOf("notes", "reading.saved"),
            privateHome = home,
            keys = SoftwareKeys.ephemeral(),
            store = store,
            relay = relay?.let { RelayConfiguration(it.slotURL, it.token, automatic = false) },
            migrationMarker = marker,
            migrationWriter = writer,
        ),
    ).also { sessions += it }

    private fun content(count: Int, seed: Int = 7) = ByteArray(count) { (it * 31 + seed).toByte() }

    @Test
    fun putReadDeduplicateStreamAndRefuseMissingContent() = runBlocking {
        val store = MemoryRecordStore()
        val session = session(store)
        session.create()
        assertEquals(SessionPhase.Ready, session.phase.value)
        val bytes = content(200_000)
        val blob = session.putBlob(bytes, "notes", "application/octet-stream", "attachment-1")
        assertTrue(blob.receipt is WriteReceipt.Saved)
        assertEquals(BlobAvailability.Available, session.blobAvailability("notes", blob.digest))
        assertArrayEquals(bytes, session.blobBytes("notes", blob.digest))
        assertEquals(4, store.blobPaths().size)
        val again = session.putBlob(bytes, "notes", "application/octet-stream", "attachment-2")
        assertEquals(blob.digest, again.digest)
        assertEquals("Identical content only gains a reference", 4, store.blobPaths().size)

        val source = File(home(), "source.bin").apply { writeBytes(content(150_001, 3)) }
        val fileBlob = session.putBlob(source, "notes", "audio/mpeg", "recording")
        val out = session.blobFile("notes", fileBlob.digest)
        assertArrayEquals(source.readBytes(), out.readBytes())
        var largest = 0
        session.readBlob("notes", fileBlob.digest) { largest = maxOf(largest, it.size) }
        assertTrue(largest <= 65536)
        try {
            session.blobBytes("notes", fileBlob.digest, maximumBytes = 1000)
            fail("bounded reads refuse instead of truncating")
        } catch (_: BlobException.TooLarge) {
        }
        val unknown = "c".repeat(64)
        assertEquals(BlobAvailability.Unpublished, session.blobAvailability("notes", unknown))
        try {
            session.blobBytes("notes", unknown)
            fail("an unpublished blob is never empty content")
        } catch (_: BlobException.Unpublished) {
        }
        val first = store.blobPaths().keys.sorted().first()
        store.removeBlob(first)
        try {
            session.blobBytes("notes", blob.digest)
            session.blobBytes("notes", fileBlob.digest)
            fail("a missing chunk without a relay is missing, not empty")
        } catch (_: BlobException.Missing) {
        }
    }

    @Test
    fun garbageCollectionRemovesOnlyUnreferencedAndStaleOrphans() = runBlocking {
        val store = MemoryRecordStore()
        val session = session(store)
        session.create()
        val kept = session.putBlob(content(70_000, 1), "notes", "text/plain", "kept")
        val released = session.putBlob(content(70_000, 2), "notes", "text/plain", "released")
        val foreign = "blobs/" + "d".repeat(64)
        store.appendBlob(foreign, "other app".toByteArray())
        session.setBlobReference(released, "released", retain = false)
        assertEquals("Sole copy stays without another holder", 0, session.collectBlobGarbage().removedChunks)
        assertEquals("Owner may discard the sole copy", 2, session.collectBlobGarbage(discardSoleCopy = true).removedChunks)
        for (path in store.blobPaths().keys) store.setBlobTime(path, 0)
        assertEquals("Live chunks stay however old", 0, session.collectBlobGarbage(graceMillis = 0).removedChunks)
        assertTrue("Chunks this session never wrote are never collected", foreign in store.blobPaths())
        assertEquals(3, store.blobPaths().size)
        assertArrayEquals(content(70_000, 1), session.blobBytes("notes", kept.digest))
    }

    @Test
    fun blobsCrossDevicesLazilyAndRequiredOnesEagerlyThroughTheReferenceRelay() = runBlocking {
        val server = ReferenceRelay.start().also { relay = it }
        val owner = session(MemoryRecordStore(), relay = server)
        owner.create()
        assertTrue(owner.syncNow())
        val member = session(MemoryRecordStore(), relay = server)
        member.restore()
        assertTrue(member.syncNow())
        assertTrue(owner.syncNow())
        owner.approve(owner.requests.value.first())
        assertTrue(owner.syncNow())
        assertTrue(member.syncNow())
        assertEquals(SessionPhase.Ready, member.phase.value)

        val lazy = content(140_000, 4)
        val blob = owner.putBlob(lazy, "notes", "text/html", "article-1")
        assertTrue(owner.syncNow())
        assertTrue(member.syncNow())
        assertEquals(BlobAvailability.Missing(0, 3), member.blobAvailability("notes", blob.digest))
        assertArrayEquals(lazy, member.blobBytes("notes", blob.digest))
        assertEquals(BlobAvailability.Available, member.blobAvailability("notes", blob.digest))

        val eager = content(90_000, 5)
        val required = member.putBlob(eager, "notes", "application/json", "transcript", required = true)
        assertTrue(member.syncNow())
        assertTrue(owner.syncNow())
        assertEquals(BlobAvailability.Available, owner.blobAvailability("notes", required.digest))
        assertArrayEquals(eager, owner.blobBytes("notes", required.digest))

        owner.revoke(member.memberID.value!!)
        assertTrue(owner.syncNow())
        assertTrue(member.syncNow())
        assertEquals(SessionPhase.Denied, member.phase.value)
        try {
            member.blobBytes("notes", required.digest)
            fail("a revoked member cannot open content it still holds")
        } catch (_: Exception) {
        }
    }

    @Test
    fun migratingMarkerGatesOrdinarySessionsAndImportBatchesNeedTheWriter() = runBlocking {
        val store = MemoryRecordStore()
        val marker = File(home(), "migration.json")
        MigrationMarker("0123456789abcdef0123456789abcdef", active = true).save(marker)
        val waiting = session(store, marker = marker)
        waiting.restore()
        assertEquals(SessionPhase.Migrating, waiting.phase.value)
        waiting.create()
        assertEquals("An active upgrade never creates an empty library", SessionPhase.Migrating, waiting.phase.value)
        val writer = session(store, marker = marker, writer = true)
        writer.create()
        assertEquals(SessionPhase.Ready, writer.phase.value)
        MigrationMarker("0123456789abcdef0123456789abcdef", active = false).save(marker)
        val ordinary = session(store, home(), marker = marker)
        ordinary.restore()
        assertTrue(ordinary.phase.value is SessionPhase.WaitingForApproval)
        try {
            val batch = """{"key":"unit","evidence":{},"children":[],"alternatives":[],"identities":{},"blobs":[]}"""
            writer.perform(DomainCommand("notes", IMPORT_BATCH, batch.toByteArray()), writer.observedRevision)
        } catch (error: Exception) {
            assertTrue("the writer reaches the core, which validates the batch: $error", error !is SessionException.InvalidCommand)
        }
        val plain = session(MemoryRecordStore())
        plain.create()
        try {
            plain.perform(DomainCommand("notes", IMPORT_BATCH, "{}".toByteArray()), plain.observedRevision)
            fail("only the migration writer may publish import batches")
        } catch (_: SessionException.InvalidCommand) {
        }
    }

    @Test
    fun writesAndRefreshesReadOnlyNewRecords() = runBlocking {
        val store = MemoryRecordStore()
        val session = session(store)
        session.create()
        repeat(20) { session.perform(DomainCommand.saveLink("seed-$it", "https://example.com/$it", "Seed"), session.observedRevision) }
        val full = store.fullReads
        val reads = store.recordReads
        session.perform(DomainCommand.saveLink("one-more", "https://example.com/x", "One"), session.observedRevision)
        assertEquals("A write never reads the whole store", full, store.fullReads)
        assertTrue("A write reads back only its own records, read ${store.recordReads - reads}", store.recordReads - reads <= 2)
        val journal = File(homes.last(), "session.json").readText()
        assertTrue("Known paths live in the append-only log, not session.json", !journal.contains("knownPaths"))
        assertNotNull(File(homes.last(), "session-known.log").takeIf { it.exists() })
    }

    /** One new record costs one read and one upload. COLOPHON_SYNC_BENCH=1 runs 100k records. */
    @Test
    fun incrementalSyncPassIsProportionalToTheChange() {
        val server = ReferenceRelay.start().also { relay = it }
        val count = if (System.getenv("COLOPHON_SYNC_BENCH") == "1") 100_000 else 2_000
        val records = HashMap<String, ByteArray>()
        records["authority/00000001.json"] = "genesis".toByteArray()
        for (i in 0 until count) records["ops/author/%012d-op%06d.json".format(i, i)] = "record $i".toByteArray()
        val store = MemoryRecordStore(records)
        val state = File(home(), "relay.json")
        val endpoint = RelayEndpoint(server.slotURL, server.token)
        assertEquals(count + 1, RelaySync(store, endpoint, stateFile = state).sync().pushed)
        val resumed = RelaySync(store, endpoint, stateFile = state)
        store.append(mapOf("ops/author/999999999999-new.json" to "new".toByteArray()))
        val full = store.fullReads
        var started = System.nanoTime()
        val pass = resumed.sync()
        val cold = (System.nanoTime() - started) / 1e6
        assertEquals(1, pass.pushed)
        assertTrue(pass.localRecordReads <= 2)
        store.append(mapOf("ops/author/999999999999-newer.json" to "newer".toByteArray()))
        started = System.nanoTime()
        val warm = resumed.sync()
        val warmMs = (System.nanoTime() - started) / 1e6
        assertEquals(1, warm.pushed)
        assertEquals(1, warm.localRecordReads)
        assertEquals("A pass never reads the whole local store", full, store.fullReads)
        println("sync-benchmark records=${count + 3} newProcessPassMs=$cold warmPassMs=$warmMs")
    }
}

internal object MessageDigests {
    fun sha256Hex(bytes: ByteArray): String =
        java.security.MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
}
