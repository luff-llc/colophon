package org.luff.colophon

import com.luff.colophon.ColophonLibrary
import com.luff.colophon.PreparedAction
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import java.nio.file.Files

class V03Test {
    private fun config(store: RecordStore, home: java.io.File, keys: SoftwareKeys) =
        SessionConfiguration("Playback", namespaces = listOf("listening.podcasts"), store = store, privateHome = home, keys = keys)

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
        } finally { home.deleteRecursively() }
    }

    @Test fun futureLayoutStopsBeforeContentAndPreservesIdentity() = runBlocking {
        val keys = SoftwareKeys.ephemeral()
        val home = Files.createTempDirectory("colophon-v03-future").toFile()
        try {
            ColophonLibrary.create(keys, "Future", "Owner", listOf("listening.podcasts")).use { lib ->
                lib.write("listening.podcasts", "position", "{\"id\":\"e\",\"seconds\":10,\"seek\":true}".toByteArray()).get()
                val action = (lib.native.beginLayout(99u, "2026-11-07T12:00:00Z") as PreparedAction.Ready).action
                val records = lib.records + action.finish(action.signWith(keys))
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
                        relay = RelayConfiguration(relay.slotURL, relay.token, automatic = false)))
                    remote.restore()
                    assertEquals(SessionPhase.UpdateRequired, remote.phase.value)
                    assertTrue("Future layouts stop before relay content downloads", empty.paths().all { it.startsWith("authority/") })
                    remote.close()
                }
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
