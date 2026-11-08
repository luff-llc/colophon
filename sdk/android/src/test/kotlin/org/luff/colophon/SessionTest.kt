package org.luff.colophon

import com.luff.colophon.MemberKind
import com.luff.colophon.Origin
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.nio.file.Files
import java.util.UUID

class SessionTest {
    private fun home(): java.io.File = Files.createTempDirectory("colophon-session-").toFile()

    private fun configuration(
        home: java.io.File,
        store: RecordStore,
        keys: SoftwareKeys = SoftwareKeys.ephemeral(),
        kind: MemberKind = MemberKind.APP,
    ) = SessionConfiguration(
        memberLabel = "Test",
        memberKind = kind,
        namespaces = listOf("reading.saved", "notes"),
        privateHome = home,
        keys = keys,
        store = store,
        ownerController = com.luff.colophon.RawControllerProvider(SoftwareKeys.ephemeral()),
    )

    private fun link(id: String = UUID.randomUUID().toString()) =
        DomainCommand.saveLink(id, "https://example.com/", "Saved")

    @Test
    fun restoreCreateWriteQueryLeaveAndRejoin() = runBlocking {
        val store = MemoryRecordStore()
        val home = home()
        val keys = SoftwareKeys.stored(java.io.File(home, "keys.bin"))
        val session = ColophonSession(configuration(home, store, keys))
        assertEquals(SessionPhase.Opening, session.phase.value)
        session.restore()
        assertEquals(SessionPhase.NoLibrary, session.phase.value)
        session.create()
        assertReadyContent(session)
        val id = session.libraryID.value!!
        session.perform(link(), session.observedRevision)
        val reading = NamespaceStore.savedLinks(session)
        val links = reading.load(SavedLinksQuery())
        assertEquals(1, links.size)
        assertEquals("https://example.com/", links[0].url)
        store.setUnavailable("offline")
        session.refresh()
        assertEquals(SessionPhase.Retry, session.phase.value)
        assertEquals(id, session.libraryID.value)
        store.setUnavailable(null)
        session.refresh()
        assertReadyContent(session)
        session.leave()
        assertEquals(SessionPhase.NoLibrary, session.phase.value)
        val reopened = ColophonSession(configuration(home, store, keys))
        reopened.restore()
        assertEquals(SessionPhase.NoLibrary, reopened.phase.value)
        reopened.rejoin(keys)
        assertReadyContent(reopened)
        val restored = NamespaceStore.savedLinks(reopened).load(SavedLinksQuery())
        assertEquals(1, restored.size)
        reading.close()
    }

    @Test
    fun pairingRevocationAndFreshRejoin() = runBlocking {
        val store = MemoryRecordStore()
        val owner = ColophonSession(configuration(home(), store))
        owner.create()
        val otherKeys = SoftwareKeys.ephemeral()
        val other = ColophonSession(configuration(home(), store, otherKeys, MemberKind.AGENT))
        other.restore()
        val waiting = other.phase.value
        assertTrue(waiting is SessionPhase.WaitingForApproval)
        assertEquals(6, (waiting as SessionPhase.WaitingForApproval).code.length)
        owner.refresh()
        val request = owner.requests.value.first()
        assertEquals(waiting.code, request.pairingCode)
        owner.approve(request)
        other.refresh()
        assertReadyContent(other)
        other.perform(link(), other.observedRevision)
        owner.refresh()
        assertTrue(owner.ledger.value.any { it.origin == Origin.AI })
        val observedBeforeRevocation = other.observedRevision
        owner.revoke(request.id)
        try {
            other.perform(link(), observedBeforeRevocation)
            fail("revoked member must not write")
        } catch (_: SessionException.NotReady) {
        }
        assertEquals(SessionPhase.Denied, other.phase.value)
        other.rejoin(SoftwareKeys.ephemeral())
        assertTrue(other.phase.value is SessionPhase.WaitingForApproval)
    }

    @Test
    fun namespaceCachesAndStaleActions() = runBlocking {
        val store = MemoryRecordStore()
        val session = ColophonSession(configuration(home(), store))
        session.create()
        val reading = NamespaceStore.savedLinks(session)
        val notes = NamespaceStore(session, "notes") { _: Int, bytes: ByteArray -> bytes }
        val query = SavedLinksQuery()
        reading.load(query)
        notes.load(0)
        assertEquals(NamespaceStore.State.Ready, reading.state.value)
        val noteValue = notes.cached(0)
        val old = session.observedRevision
        session.perform(link(), old)
        assertEquals(null, reading.cached(query))
        assertTrue(notes.cached(0)?.contentEquals(noteValue) == true)
        assertEquals(NamespaceStore.State.Ready, notes.state.value)
        assertEquals(1, reading.load(query).size)
        try {
            session.perform(link(), old)
            fail("stale revision")
        } catch (_: SessionException.StaleRevision) {
        }
        store.setUnavailable("gone")
        session.refresh()
        assertEquals(1, reading.cached(query)?.size)
        assertTrue(notes.cached(0)?.contentEquals(noteValue) == true)
        assertTrue(session.hasUsableContent)
        reading.close()
        notes.close()
    }

    @Test
    fun missingKnownRecordsAreNotEmpty() = runBlocking {
        val store = MemoryRecordStore()
        val home = home()
        val keys = SoftwareKeys.ephemeral()
        val session = ColophonSession(configuration(home, store, keys))
        session.create()
        val missing = ColophonSession(configuration(home, MemoryRecordStore(), keys))
        missing.restore()
        assertTrue("Selected library must not become empty", missing.phase.value == SessionPhase.Retry)
        AtomicFile.write("invalid".toByteArray(), java.io.File(home, "session.json"))
        val corrupt = ColophonSession(configuration(home, store, keys))
        corrupt.restore()
        assertTrue("Corrupt selection must fail closed", corrupt.phase.value is SessionPhase.Failed)
        corrupt.refresh()
        assertTrue("Retry must not bypass corrupt selection", corrupt.phase.value is SessionPhase.Failed)
    }

    @Test
    fun fileBackedColdReopen() = runBlocking {
        val root = home()
        val store = FileRecordStore(java.io.File(root, "library"))
        val home = java.io.File(root, "home")
        val keys = SoftwareKeys.stored(java.io.File(home, "keys.bin"))
        val session = ColophonSession(configuration(home, store, keys))
        session.create()
        session.perform(link("one"), session.observedRevision)
        val reopened = ColophonSession(configuration(home, FileRecordStore(java.io.File(root, "library")), keys))
        reopened.restore()
        assertReadyContent(reopened)
        assertEquals(1, NamespaceStore.savedLinks(reopened).load(SavedLinksQuery()).size)
    }
}
