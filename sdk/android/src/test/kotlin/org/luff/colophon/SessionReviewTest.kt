package org.luff.colophon

import com.luff.colophon.AccessException
import com.luff.colophon.BindingException
import com.luff.colophon.GrantOptions
import com.luff.colophon.KeyProvider
import com.luff.colophon.MemberKind
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.concurrent.CancellationException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class SessionReviewTest {
    private fun home(): java.io.File = Files.createTempDirectory("colophon-review-").toFile()

    private fun configuration(
        home: java.io.File,
        store: RecordStore,
        keys: KeyProvider = SoftwareKeys.ephemeral(),
        label: String = "Test",
        kind: MemberKind = MemberKind.APP,
    ) = SessionConfiguration(
        memberLabel = label,
        memberKind = kind,
        namespaces = listOf("reading.saved", "notes"),
        privateHome = home,
        keys = keys,
        store = store,
    )

    private fun link(id: String = java.util.UUID.randomUUID().toString()) =
        DomainCommand.saveLink(id, "https://example.com/", "Saved")

    private fun session(
        home: java.io.File,
        store: RecordStore,
        keys: KeyProvider = SoftwareKeys.ephemeral(),
        label: String = "Test",
        core: SessionCore = BindingSessionCore(),
    ) = ColophonSession(configuration(home, store, keys, label), core, store, ColophonSession.sessionDispatcher)

    @Test
    fun cancelledRestoreDoesNotFailTheSession() = runBlocking {
        val entered = CountDownLatch(1)
        val gate = CountDownLatch(1)
        val memory = MemoryRecordStore()
        val store = object : RecordStore {
            override fun read(): Map<String, ByteArray> {
                entered.countDown()
                check(gate.await(10, TimeUnit.SECONDS))
                return memory.read()
            }
            override fun append(records: Map<String, ByteArray>) = memory.append(records)
            override fun watch(onChange: () -> Unit): AutoCloseable = memory.watch(onChange)
        }
        val session = session(home(), store)
        val job = launch(Dispatchers.Default) { session.restore() }
        assertTrue(entered.await(10, TimeUnit.SECONDS))
        job.cancel()
        gate.countDown()
        job.join()
        assertFalse(session.phase.value is SessionPhase.Failed)
        session.restore()
        assertEquals(SessionPhase.NoLibrary, session.phase.value)
    }

    @Test
    fun cancelledLoadDoesNotPoisonTheNamespaceOrSession() = runBlocking {
        val session = session(home(), MemoryRecordStore())
        session.create()
        val entered = CountDownLatch(1)
        val gate = CountDownLatch(1)
        val notes = NamespaceStore(session, "notes") { _: Int, _: ByteArray ->
            entered.countDown()
            check(gate.await(10, TimeUnit.SECONDS))
            "ok"
        }
        val job = launch(Dispatchers.Default) { notes.load(0) }
        assertTrue(entered.await(10, TimeUnit.SECONDS))
        job.cancel()
        gate.countDown()
        job.join()
        assertFalse(session.phase.value is SessionPhase.Failed)
        assertTrue(notes.state.value != NamespaceStore.State.Unavailable)
        assertEquals("ok", notes.load(0))
        notes.close()
    }

    @Test
    fun keyFailureDuringRestoreAndCommandIsFailed() = runBlocking {
        val store = MemoryRecordStore()
        val home = home()
        val broken = object : KeyProvider {
            var thread: String? = null
            override fun signingPublicKey(): ByteArray {
                thread = Thread.currentThread().name
                throw BindingException.KeyProvider("unreadable identity")
            }
            override fun agreementPublicKey(): ByteArray = throw BindingException.KeyProvider("unreadable identity")
            override fun sign(body: ByteArray): ByteArray = throw BindingException.KeyProvider("unreadable identity")
            override fun agree(peer: ByteArray): ByteArray = throw BindingException.KeyProvider("unreadable identity")
        }
        val created = session(home, store)
        created.create()
        val reopened = session(home, store, broken)
        reopened.restore()
        assertTrue(reopened.phase.value is SessionPhase.Failed)
        assertTrue(
            "key use must stay on the session thread, was ${broken.thread}",
            broken.thread?.startsWith("colophon-session") == true,
        )
    }

    @Test
    fun commandKeyFailureBecomesFailed() = runBlocking {
        val keys = SoftwareKeys.ephemeral()
        val flaky = object : KeyProvider by keys {
            var failSign = false
            override fun sign(body: ByteArray): ByteArray {
                if (failSign) throw BindingException.KeyProvider("sign failed")
                return keys.sign(body)
            }
        }
        val session = session(home(), MemoryRecordStore(), flaky)
        session.create()
        flaky.failSign = true
        try {
            session.perform(link(), session.observedRevision)
            fail("sign failure must surface")
        } catch (_: BindingException.KeyProvider) {
        }
        assertTrue(session.phase.value is SessionPhase.Failed)
    }

    @Test
    fun replacedIdentityFailsClosedWithoutANewRequest() = runBlocking {
        val store = MemoryRecordStore()
        val home = home()
        val session = session(home, store, SoftwareKeys.ephemeral(), "Owner")
        session.create()
        val before = store.read().keys
        val replaced = session(home, store, SoftwareKeys.ephemeral(), "Stranger")
        replaced.restore()
        assertTrue(replaced.phase.value is SessionPhase.Failed)
        assertFalse(replaced.phase.value is SessionPhase.WaitingForApproval)
        assertEquals(before, store.read().keys)
    }

    @Test
    fun softwareKeyFileIsDeferredAndCorruptMaterialIsKept() = runBlocking {
        val home = home()
        val file = java.io.File(home, "keys.bin")
        val keys = SoftwareKeys.stored(file)
        val store = MemoryRecordStore()
        val session = session(home, store, keys)
        assertFalse(file.exists())
        session.restore()
        assertFalse("empty restore must not mint a key file", file.exists())
        session.create()
        assertTrue(file.exists())
        val garbage = "not-a-key".toByteArray()
        file.writeBytes(garbage)
        val broken = SoftwareKeys.stored(file)
        try {
            broken.signingPublicKey()
            fail("corrupt software keys must fail")
        } catch (_: BindingException.KeyProvider) {
        }
        assertArrayEquals(garbage, file.readBytes())
        val reopened = session(home, store, SoftwareKeys.stored(file))
        reopened.restore()
        assertTrue(reopened.phase.value is SessionPhase.Failed)
        assertArrayEquals(garbage, file.readBytes())
    }

    @Test
    fun unreadableLibraryRestoreIsUnavailable() = runBlocking {
        val root = home()
        val folder = java.io.File(root, "library")
        assertTrue(folder.mkdirs())
        java.io.File(folder, "authority").mkdirs()
        Files.setPosixFilePermissions(folder.toPath(), emptySet())
        try {
            val session = session(home(), FileRecordStore(folder))
            session.restore()
            assertTrue(
                "unreadable library must not look empty: ${session.phase.value}",
                session.phase.value is SessionPhase.Unavailable,
            )
            assertFalse(session.phase.value is SessionPhase.NoLibrary)
        } finally {
            Files.setPosixFilePermissions(
                folder.toPath(),
                setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE),
            )
        }
    }

    @Test
    fun narrowedExpiredAndBudgetedGrantsFailClosed() = runBlocking {
        val store = MemoryRecordStore()
        val owner = session(home(), store, label = "Owner")
        owner.create()
        val narrowedKeys = SoftwareKeys.ephemeral()
        val narrowed = session(home(), store, narrowedKeys, "Narrowed")
        narrowed.restore()
        owner.refresh()
        owner.approve(owner.requests.value.first(), GrantOptions(listOf("notes"), null, null, null))
        narrowed.refresh()
        assertEquals(SessionPhase.Denied, narrowed.phase.value)

        val expiredKeys = SoftwareKeys.ephemeral()
        val expired = session(home(), store, expiredKeys, "Expired")
        expired.restore()
        owner.refresh()
        owner.approve(owner.requests.value.first(), GrantOptions(null, null, "2000-01-01T00:00:00Z", null))
        expired.refresh()
        assertEquals(SessionPhase.Denied, expired.phase.value)

        val budgetKeys = SoftwareKeys.ephemeral()
        val budget = session(home(), store, budgetKeys, "Budget")
        budget.restore()
        owner.refresh()
        owner.approve(owner.requests.value.first(), GrantOptions(null, null, null, 0uL))
        budget.refresh()
        assertEquals(SessionPhase.Ready, budget.phase.value)
        try {
            budget.perform(link(), budget.observedRevision)
            fail("spent budget must not write")
        } catch (_: AccessException) {
        }
        assertEquals(SessionPhase.Denied, budget.phase.value)
    }

    @Test
    fun futureGrantExpiryRefreshesWithoutAnotherCall() = runBlocking {
        val store = MemoryRecordStore()
        val owner = session(home(), store, label = "Owner")
        owner.create()
        owner.perform(link("owned"), owner.observedRevision)
        val member = session(home(), store, SoftwareKeys.ephemeral(), "Member")
        member.restore()
        owner.refresh()
        val expires = java.time.format.DateTimeFormatter.ISO_INSTANT.format(
            Instant.now().plusSeconds(2).truncatedTo(ChronoUnit.SECONDS),
        )
        owner.approve(owner.requests.value.first(), GrantOptions(null, null, expires, null))
        member.refresh()
        assertEquals(SessionPhase.Ready, member.phase.value)
        val reading = NamespaceStore.savedLinks(member)
        val query = SavedLinksQuery()
        try {
            assertEquals(1, reading.load(query).size)
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(8)
            while (member.phase.value == SessionPhase.Ready && System.nanoTime() < deadline) {
                delay(100)
            }
            assertEquals(SessionPhase.Denied, member.phase.value)
            assertNull(reading.cached(query))
        } finally {
            reading.close()
            member.close()
            owner.close()
        }
    }

    @Test
    fun queuedPublicationRetriesOnRefresh() = runBlocking {
        val store = GatedStore()
        val session = session(home(), store)
        session.create()
        store.failAppend = true
        val receipt = session.perform(link(), session.observedRevision)
        assertTrue(receipt is WriteReceipt.Queued)
        assertTrue(session.phase.value is SessionPhase.Unavailable)
        store.failAppend = false
        session.refresh()
        assertEquals(SessionPhase.Ready, session.phase.value)
        assertEquals(1, NamespaceStore.savedLinks(session).load(SavedLinksQuery()).size)
    }

    @Test
    fun postCommitFailureIsQueuedAndRefreshKeepsTheWrite() = runBlocking {
        val store = MemoryRecordStore()
        val core = object : DelegatingCore() {
            var failAfterWrite = false
            override fun write(command: DomainCommand): com.luff.colophon.OperationView {
                val operation = super.write(command)
                if (failAfterWrite) throw BindingException.KeyProvider("post-commit")
                return operation
            }
        }
        val session = session(home(), store, core = core)
        session.create()
        core.failAfterWrite = true
        val receipt = session.perform(link(), session.observedRevision)
        assertTrue(receipt is WriteReceipt.Queued)
        assertTrue(session.phase.value is SessionPhase.Unavailable)
        core.failAfterWrite = false
        session.refresh()
        assertEquals(SessionPhase.Ready, session.phase.value)
        assertEquals(1, NamespaceStore.savedLinks(session).load(SavedLinksQuery()).size)
    }

    @Test
    fun leaveAndRejoinWithPendingPublicationDoNotWipeTheLibrary() = runBlocking {
        val store = GatedStore()
        val home = home()
        val session = session(home, store)
        session.create()
        val libraryId = session.libraryID.value
        store.failAppend = true
        assertTrue(session.perform(link(), session.observedRevision) is WriteReceipt.Queued)
        assertNull(session.lastError.value)
        try {
            session.leave()
            fail("pending publication must block leave")
        } catch (_: StorageException.Unavailable) {
        }
        assertNotNull(session.lastError.value)
        assertEquals(libraryId, session.libraryID.value)
        assertTrue(session.phase.value is SessionPhase.Unavailable)
        val phase = session.phase.value
        try {
            session.rejoin(SoftwareKeys.ephemeral())
            fail("pending publication must block rejoin")
        } catch (_: StorageException.Unavailable) {
        }
        assertEquals(libraryId, session.libraryID.value)
        assertEquals(phase, session.phase.value)
    }

    @Test
    fun rejoinDoesNotInvalidateWhileAWriteIsInFlight() = runBlocking {
        val entered = CountDownLatch(1)
        val gate = CountDownLatch(1)
        val core = object : DelegatingCore() {
            override fun write(command: DomainCommand): com.luff.colophon.OperationView {
                entered.countDown()
                check(gate.await(10, TimeUnit.SECONDS))
                return super.write(command)
            }
        }
        val session = session(home(), MemoryRecordStore(), core = core)
        session.create()
        val libraryId = session.libraryID.value
        val observed = session.observedRevision
        val writing = launch(Dispatchers.Default) { session.perform(link(), observed) }
        assertTrue(entered.await(10, TimeUnit.SECONDS))
        val rejoining = launch(Dispatchers.Default) { session.rejoin(SoftwareKeys.ephemeral()) }
        delay(300)
        assertEquals(libraryId, session.libraryID.value)
        assertEquals(SessionPhase.Ready, session.phase.value)
        gate.countDown()
        writing.join()
        rejoining.join()
        assertTrue(session.phase.value is SessionPhase.WaitingForApproval)
    }

    @Test
    fun importRequestApprovesAnExternalMember() = runBlocking {
        val ownerStore = MemoryRecordStore()
        val owner = session(home(), ownerStore, label = "Owner")
        owner.create()
        val memberStore = MemoryRecordStore(ownerStore.read())
        val member = session(home(), memberStore, SoftwareKeys.ephemeral(), "Member")
        member.restore()
        assertTrue(member.phase.value is SessionPhase.WaitingForApproval)
        val request = memberStore.read().entries.first { it.key.startsWith("requests/") }.value
        assertTrue(owner.requests.value.isEmpty())
        owner.importRequest(request)
        assertEquals(1, owner.requests.value.size)
        owner.approve(owner.requests.value.first())
        assertTrue(owner.members.value.any { it.label == "Member" })
    }

    @Test
    fun joinRecoveryKeysAndClose() = runBlocking {
        val store = MemoryRecordStore()
        val core = object : DelegatingCore() {
            var closed = false
            override fun close() {
                closed = true
                super.close()
            }
        }
        val session = session(home(), store, core = core)
        session.join()
        assertEquals(SessionPhase.NoLibrary, session.phase.value)
        session.create()
        assertNotNull(session.recoveryKeys())
        val member = session(home(), store, SoftwareKeys.ephemeral(), "Joiner")
        member.restore()
        assertTrue(member.phase.value is SessionPhase.WaitingForApproval)
        member.join()
        assertTrue(member.phase.value is SessionPhase.WaitingForApproval)
        session.join()
        assertEquals(SessionPhase.Ready, session.phase.value)
        session.close()
        assertTrue(core.closed)
        try {
            core.records()
            fail("closed core must not answer")
        } catch (_: SessionException.NotReady) {
        }
        try {
            session.refresh()
            fail("closed session must not refresh")
        } catch (_: CancellationException) {
        }
    }

    @Test
    fun failedCreateDoesNotStayCreating() = runBlocking {
        val store = GatedStore()
        store.failAppend = true
        val session = session(home(), store)
        session.restore()
        assertEquals(SessionPhase.NoLibrary, session.phase.value)
        session.create()
        assertFalse(session.phase.value is SessionPhase.Creating)
        assertTrue(session.phase.value is SessionPhase.Unavailable)
    }

    @Test
    fun publishedViewsAreVisibleToOtherThreads() {
        val field = ColophonSession::class.java.getDeclaredField("views")
        assertTrue(
            "Namespace views are read off the session thread",
            java.lang.reflect.Modifier.isVolatile(field.modifiers),
        )
    }
}

private open class DelegatingCore(private val base: SessionCore = BindingSessionCore()) : SessionCore {
    override fun open(records: Map<String, ByteArray>, keys: KeyProvider) = base.open(records, keys)
    override fun create(configuration: SessionConfiguration) = base.create(configuration)
    override fun merge(records: Map<String, ByteArray>) = base.merge(records)
    override fun records(): Map<String, ByteArray> = base.records()
    override fun snapshot(namespaces: List<String>): CoreSnapshot = base.snapshot(namespaces)
    override fun request(configuration: SessionConfiguration, keys: KeyProvider) = base.request(configuration, keys)
    override fun write(command: DomainCommand) = base.write(command)
    override fun approve(request: ByteArray, grant: GrantOptions?) = base.approve(request, grant)
    override fun revoke(id: String) = base.revoke(id)
    override fun importRequest(data: ByteArray) = base.importRequest(data)
    override fun recovery(): KeyProvider? = base.recovery()
    override fun close() = base.close()
}

private class GatedStore : RecordStore {
    private val memory = MemoryRecordStore()

    @Volatile var failAppend: Boolean = false

    override fun read(): Map<String, ByteArray> = memory.read()

    override fun append(records: Map<String, ByteArray>) {
        if (failAppend) throw StorageException.Unavailable("Publication offline")
        memory.append(records)
    }

    override fun watch(onChange: () -> Unit): AutoCloseable = memory.watch(onChange)
}
