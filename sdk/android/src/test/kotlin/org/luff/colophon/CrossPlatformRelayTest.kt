package org.luff.colophon

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/**
 * One step of scripts/test-relay-cross.sh: an Android session and an Apple session share one
 * library through one reference relay. Skipped unless the script sets COLOPHON_CROSS_STEP.
 */
class CrossPlatformRelayTest {
    @Test
    fun crossPlatformStep() = runBlocking {
        val step = System.getenv("COLOPHON_CROSS_STEP")
        assumeTrue("Run through scripts/test-relay-cross.sh", step != null)
        val dir = File(System.getenv("COLOPHON_CROSS_DIR"))
        val session = ColophonSession(
            SessionConfiguration(
                memberLabel = "Android",
                namespaces = listOf("reading.saved", "notes"),
                privateHome = File(dir, "android-home"),
                keys = SoftwareKeys.stored(File(dir, "android-keys.bin")),
                store = FileRecordStore(File(dir, "android-library")),
                relay = RelayConfiguration(System.getenv("COLOPHON_CROSS_URL"), System.getenv("COLOPHON_CROSS_TOKEN"), automatic = false),
            ),
        )
        session.restore()
        when (step) {
            "join" -> assertTrue(
                "The Apple library should arrive through the relay, got ${session.phase.value}",
                session.phase.value is SessionPhase.WaitingForApproval,
            )
            "write" -> {
                assertTrue(session.syncNow())
                assertEquals(SessionPhase.Ready, session.phase.value)
                session.perform(DomainCommand.saveLink("from-android", "https://example.com/android", "Android"), session.observedRevision)
                // Apple's blob arrives lazily: the manifest synced, the chunks are fetched on read.
                val appleDigest = File(dir, "apple-blob.txt").readText()
                assertTrue(session.blobAvailability("notes", appleDigest) is BlobAvailability.Missing)
                assertArrayEquals("Apple's blob reached Android intact", crossBlob(1), session.blobBytes("notes", appleDigest))
                // Android's blob is required, so Apple downloads it eagerly.
                val blob = session.putBlob(crossBlob(2), "notes", "application/octet-stream", "android-transcript", required = true)
                File(dir, "android-blob.txt").writeText(blob.digest)
            }
            "verify" -> {
                assertTrue(session.syncNow())
                val store = NamespaceStore.savedLinks(session)
                assertEquals(listOf("from-android", "from-apple"), store.load(SavedLinksQuery()).map { it.id }.sorted())
                store.close()
                assertEquals(BlobAvailability.Available, session.blobAvailability("notes", File(dir, "apple-blob.txt").readText()))
            }
            else -> error("Unknown step $step")
        }
        assertTrue(session.syncNow())
        assertEquals(SyncState.Idle, session.syncState.value)
        session.close()
    }
}

/** Deterministic blob content both platforms compute: three 64 KiB chunks plus a tail. */
internal fun crossBlob(seed: Int) = ByteArray(150_000) { (it * 31 + seed).toByte() }
