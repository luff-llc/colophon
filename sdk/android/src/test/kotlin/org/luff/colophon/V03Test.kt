package org.luff.colophon

import com.luff.colophon.ColophonLibrary
import com.luff.colophon.BindingException
import com.luff.colophon.ControllerProvider
import java.util.Base64
import com.luff.colophon.PreparedAction
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import java.nio.file.Files

class V03Test {
    // Model a newer writer. The old core must refuse finishing an unsupported layout itself;
    // replay still needs a correctly signed future-format fixture to test UpdateRequired.
    private fun futureLayout(lib: ColophonLibrary, controller: ControllerProvider): Map<String, ByteArray> =
        ((lib.native.beginLayout(99u, "2026-11-07T12:00:00Z") as PreparedAction.Ready).action).use { action ->
            val signatures = action.signControllerWith(controller)
            val refusal = assertThrows(BindingException.InvalidData::class.java) { action.finishAuthority(signatures) }
            assertEquals("newerFormat: storage layout", refusal.detail)
            val step = action.signingSteps().single()
            val body = Base64.getEncoder().encodeToString(step.body)
            val signature = Base64.getEncoder().encodeToString(signatures.single().signature)
            mapOf(step.path to """{"body":"$body","signature":"$signature"}""".toByteArray())
        }

    private fun config(store: RecordStore, home: java.io.File, keys: SoftwareKeys) =
        SessionConfiguration("Playback", namespaces = listOf("listening.podcasts"), store = store, privateHome = home, keys = keys, ownerController = com.luff.colophon.RawControllerProvider(SoftwareKeys.ephemeral()))

    @Test fun coldOpenDoesNotMergeAuthorityTwiceAndTranslatesLayoutError() = runBlocking {
        val keys = SoftwareKeys.ephemeral()
        val home = Files.createTempDirectory("colophon-review-open").toFile()
        try {
            val controller = com.luff.colophon.RawControllerProvider(SoftwareKeys.ephemeral())
            ColophonLibrary.create(keys, "Review", "Owner", listOf("listening.podcasts"), controller).use { lib ->
                val base = BindingSessionCore()
                var authorityMerges = 0
                val core = object : SessionCore by base {
                    override fun merge(records: Map<String, ByteArray>) {
                        authorityMerges += records.keys.count { it.startsWith("authority/") }
                        base.merge(records)
                    }
                    override fun mergeObserved(records: Map<String, ByteArray>, versions: Map<String, String>) {
                        authorityMerges += records.keys.count { it.startsWith("authority/") }
                        base.mergeObserved(records, versions)
                    }
                }
                val worker = SessionWorker(config(MemoryRecordStore(lib.records), home, keys), core)
                worker.refresh()
                assertEquals(0, authorityMerges)
                lib.unlockVault()
                val future = lib.records + futureLayout(lib, controller)
                val futureWorker = SessionWorker(config(MemoryRecordStore(future), java.io.File(home, "future"), keys))
                try { futureWorker.refresh(); fail("Future layout opened") }
                catch (error: Exception) { assertSame(SessionLayoutException, error) }
            }
        } finally { home.deleteRecursively() }
    }

    @Test fun livePlaybackReceiptsAndIncrementalRefresh() = runBlocking {
        val store = MemoryRecordStore()
        val keys = SoftwareKeys.ephemeral()
        val home = Files.createTempDirectory("colophon-v03").toFile()
        try {
            val worker = SessionWorker(config(store, home, keys))
            var snapshot = worker.create()
            for (seconds in listOf(10, 20, 30)) {
                val command = DomainCommand("listening.podcasts", "position", "{\"id\":\"e\",\"seconds\":$seconds}".toByteArray())
                val (receipt, next) = worker.write(command, snapshot.revision)
                assertTrue(receipt is WriteReceipt.Saved)
                snapshot = next
            }
            assertEquals(1, store.paths().count { it.startsWith("state/") })
            assertEquals(3, store.paths().count { it.startsWith("history/") })
            assertEquals(0, store.paths().count { it.startsWith("ops/") })
            val before = store.recordReads
            worker.refresh()
            assertEquals(before, store.recordReads)
            assertEquals(0, store.fullReads)
            ColophonLibrary.open(store.read(), keys).use { external ->
                val written = mutableListOf<String>()
                external.write("listening.podcasts", "position", "{\"id\":\"e\",\"seconds\":40}".toByteArray(), written).get()
                store.append(external.recordsAt(written))
            }
            worker.refresh()
            val state = JsonParser(String(worker.core.query("listening.podcasts", "read", "{}".toByteArray()))).parseValue() as Json.Obj
            val episode = state.array("episodes").first() as Json.Obj
            assertEquals(40.0, (episode.fields["seconds"] as Json.Number).raw.toDouble(), 0.0)
            val livePath = store.paths().single { it.startsWith("state/") }
            val predecessor = store.read(listOf(livePath)).getValue(livePath)
            snapshot = worker.refresh()
            val revision = (episode.fields["positionRevision"] as Json.Text).value
            val seek = DomainCommand("listening.podcasts", "position", """{"id":"e","seconds":3,"seek":true,"expect":"$revision"}""".toByteArray())
            val (receipt, _) = worker.write(seek, snapshot.revision)
            assertTrue(receipt is WriteReceipt.Saved)
            val immutable = store.read(store.paths().filter { it.startsWith("ops/") })
            assertEquals(2, immutable.size)
            assertTrue(immutable.values.any { it.contentEquals(predecessor) })
            worker.saveCheckpoint()
            val reopened = SessionWorker(config(store, home, keys))
            reopened.refresh()
            val restored = JsonParser(String(reopened.core.query("listening.podcasts", "getEpisode", """{"id":"e"}""".toByteArray()))).parseValue() as Json.Obj
            assertEquals(3.0, (restored.fields["seconds"] as Json.Number).raw.toDouble(), 0.0)
        } finally { home.deleteRecursively() }
    }

    @Test fun futureLayoutStopsBeforeContentAndPreservesIdentity() = runBlocking {
        val keys = SoftwareKeys.ephemeral()
        val home = Files.createTempDirectory("colophon-v03-future").toFile()
        try {
            val controller = com.luff.colophon.RawControllerProvider(SoftwareKeys.ephemeral())
            ColophonLibrary.create(keys, "Future", "Owner", listOf("listening.podcasts"), controller).use { lib ->
                lib.write("listening.podcasts", "position", "{\"id\":\"e\",\"seconds\":10,\"seek\":true}".toByteArray()).get()
                lib.unlockVault()
                val records = lib.records + futureLayout(lib, controller)
                val store = MemoryRecordStore(records)
                val identity = keys.signingPublicKey()
                val session = ColophonSession(config(store, home, keys))
                session.restore()
                assertEquals(SessionPhase.UpdateRequired, session.phase.value)
                assertEquals(records.keys.count { it.startsWith("authority/") }, store.recordReads)
                assertArrayEquals(identity, keys.signingPublicKey())
                assertEquals(records.keys, store.paths())
                session.retry()
                assertEquals(SessionPhase.UpdateRequired, session.phase.value)
                session.close()
                ReferenceRelay.start().use { relay ->
                    RelaySync(MemoryRecordStore(records), RelayEndpoint(relay.slotURL, relay.token)).sync()
                    val empty = MemoryRecordStore()
                    val remote = ColophonSession(SessionConfiguration("Reader", namespaces = listOf("listening.podcasts"), store = empty, privateHome = java.io.File(home, "remote"), keys = keys,
                        relay = RelayConfiguration(relay.slotURL, relay.token, automatic = false), ownerController = com.luff.colophon.RawControllerProvider(SoftwareKeys.ephemeral())))
                    remote.restore()
                    assertEquals(SessionPhase.UpdateRequired, remote.phase.value)
                    assertTrue("Future layouts stop before relay content downloads", empty.paths().all { it.startsWith("authority/") })
                    remote.close()
                }
            }
        } finally { home.deleteRecursively() }
    }

    @Test fun forgedFutureLayoutFailsInsteadOfRequestingAnUpdate() = runBlocking {
        val home = Files.createTempDirectory("colophon-future-forgery").toFile()
        try {
            val keys = SoftwareKeys.ephemeral()
            val controller = com.luff.colophon.RawControllerProvider(SoftwareKeys.ephemeral())
            ColophonLibrary.create(keys, "Future", "Owner", listOf("listening.podcasts"), controller).use { lib ->
                lib.unlockVault()
                val future = futureLayout(lib, controller).entries.single()
                val envelope = JsonParser(future.value.decodeToString()).parseValue() as Json.Obj
                val signature = Base64.getDecoder().decode(envelope.string("signature"))
                signature[0] = (signature[0].toInt() xor 1).toByte()
                val forged = """{"body":"${envelope.string("body")}","signature":"${Base64.getEncoder().encodeToString(signature)}"}""".toByteArray()
                val session = ColophonSession(config(MemoryRecordStore(lib.records + (future.key to forged)), home, keys))
                try {
                    session.restore()
                    val phase = session.phase.value
                    assertTrue("Forged future authority must fail authentication: $phase", phase is SessionPhase.Failed && phase.reason.contains("badSignature"))
                } finally { session.close() }
            }
        } finally { home.deleteRecursively() }
    }

    @Test fun conditionalLivePublicationRejectsStaleExpectedBytes() {
        val store = MemoryRecordStore()
        val path = "state/a/listening.podcasts/slot.json"
        val old = "old".toByteArray(); val newer = "newer".toByteArray()
        assertTrue(store.replaceLive(path, null, old))
        assertTrue(store.replaceLive(path, old, newer))
        assertFalse(store.replaceLive(path, old, "racing".toByteArray()))
        assertArrayEquals(newer, store.read(listOf(path))[path])
    }
    @Test fun scopedFolderListingIgnoresMissingSiblingNamespace() {
        val home = Files.createTempDirectory("colophon-v03-scoped").toFile()
        try {
            val store = FileRecordStore(home)
            val note = "ops/a/notes/000000000001-n.json"
            val sibling = "ops/a/listening.podcasts/000000000001-p.json"
            val history = "history/a/notes/000000000001-h.json"
            val legacy = "ops/a/000000000002-u.json"
            store.append(listOf(note, sibling, history, legacy).associateWith { "record".toByteArray() })
            store.paths()
            java.io.File(home, sibling).delete()
            assertEquals(setOf(note, legacy), store.paths(listOf("notes")))
            assertEquals(setOf(note, legacy, history), store.syncPaths(listOf("notes")))
            java.io.File(home, note).delete()
            assertThrows(StorageException.Unavailable::class.java) { store.paths(listOf("notes")) }
        } finally { home.deleteRecursively() }
    }

}

/** A file-watch refresh may begin immediately after an awaited operation returns. */
internal fun assertReadyContent(session: ColophonSession) {
    val phase = session.phase.value
    assertTrue("Expected ready usable content, got $phase", phase == SessionPhase.Ready || phase == SessionPhase.Refreshing)
    assertTrue("A refresh must retain the usable snapshot", session.hasUsableContent)
}
