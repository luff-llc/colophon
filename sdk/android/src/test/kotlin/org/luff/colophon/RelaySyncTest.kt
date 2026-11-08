package org.luff.colophon

import com.luff.colophon.ColophonLibrary
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.net.ServerSocket
import java.nio.file.Files

/** Starts relay/server.js on a free loopback port with a fresh data directory. */
internal class ReferenceRelay private constructor(private val process: Process, private val data: File, port: Int) : AutoCloseable {
    val slotURL = "http://127.0.0.1:$port/v1/libraries/home"
    val token = TOKEN

    override fun close() {
        process.destroy()
        process.waitFor()
        data.deleteRecursively()
    }

    companion object {
        const val TOKEN = "kotlin-relay-token-0123456789"
        val node: String? = (System.getenv("PATH") ?: "").split(File.pathSeparator).map { File(it, "node") }
            .plus(listOf(File("/opt/homebrew/bin/node"), File("/usr/local/bin/node")))
            .firstOrNull { it.canExecute() }?.path
        private val script: String? = System.getProperty("colophon.relayScript")

        fun start(): ReferenceRelay {
            assumeTrue("node and relay/server.js are required", node != null && script != null && File(script).exists())
            val data = Files.createTempDirectory("colophon-relay-data-").toFile()
            val builder = ProcessBuilder(node, script).redirectErrorStream(false)
            builder.environment().apply {
                put("COLOPHON_RELAY_PORT", "0")
                put("COLOPHON_RELAY_DATA", data.path)
                put("COLOPHON_RELAY_TOKENS", "home=$TOKEN")
            }
            builder.redirectError(ProcessBuilder.Redirect.INHERIT)
            val process = builder.start()
            val line = BufferedReader(InputStreamReader(process.inputStream)).readLine()
                ?: error("Relay exited before listening")
            val port = Regex("\"port\":(\\d+)").find(line)?.groupValues?.get(1)?.toInt() ?: error("No port in $line")
            return ReferenceRelay(process, data, port)
        }
    }
}

class RelaySyncTest {
    private lateinit var relay: ReferenceRelay
    private val homes = mutableListOf<File>()

    private fun home(): File = Files.createTempDirectory("colophon-relay-session-").toFile().also { homes += it }

    @Before
    fun startRelay() {
        relay = ReferenceRelay.start()
    }

    @After
    fun stopRelay() {
        if (::relay.isInitialized) relay.close()
        homes.forEach { it.deleteRecursively() }
    }

    private fun configuration(
        home: File,
        store: RecordStore,
        keys: SoftwareKeys = SoftwareKeys.ephemeral(),
        url: String = relay.slotURL,
        token: String = relay.token,
        automatic: Boolean = false,
    ) = SessionConfiguration(
        memberLabel = "Device",
        namespaces = listOf("reading.saved", "notes"),
        privateHome = home,
        keys = keys,
        store = store,
        relay = RelayConfiguration(url, token, automatic = automatic),
        ownerController = com.luff.colophon.RawControllerProvider(SoftwareKeys.ephemeral()),
    )

    private fun link(id: String) = DomainCommand.saveLink(id, "https://example.com/$id", id)

    private suspend fun links(session: ColophonSession): List<String> {
        val store = NamespaceStore.savedLinks(session)
        try {
            return store.load(SavedLinksQuery()).map { it.id }.sorted()
        } finally {
            store.close()
        }
    }

    @Test
    fun authorityUploadsWaitForPredecessorAcknowledgement() {
        val active = java.util.concurrent.atomic.AtomicInteger()
        val overlapped = java.util.concurrent.atomic.AtomicBoolean()
        val base = HttpUrlConnectionTransport()
        val transport = RelayTransport { request ->
            val authority = request.method == "PUT" && request.url.contains("authority")
            if (authority) {
                if (active.incrementAndGet() > 1) overlapped.set(true)
                // Model an upload still awaiting acknowledgement.
                Thread.sleep(10)
            }
            try { base.send(request) } finally { if (authority) active.decrementAndGet() }
        }
        val records = (1..3).associate { "authority/%08d.json".format(it) to "record$it".toByteArray() }
        assertEquals(3, RelaySync(MemoryRecordStore(records), RelayEndpoint(relay.slotURL, relay.token), transport=transport).sync().pushed)
        assertFalse(overlapped.get())
    }

    @Test
    fun reconcilesBothWaysAndKeepsLocalRecords() {
        val endpoint = RelayEndpoint(relay.slotURL, relay.token)
        val a = MemoryRecordStore(mapOf("authority/00000001.json" to "g".toByteArray(), "ops/m/000000000001-a.json" to "a".toByteArray()))
        val b = MemoryRecordStore()
        val stateFile = File(home(), "relay.json")
        val syncA = RelaySync(a, endpoint, stateFile = stateFile)
        assertEquals(2, syncA.sync().pushed)
        assertEquals(2, RelaySync(b, endpoint).sync().pulled)
        assertEquals(a.read().keys, b.read().keys)
        b.append(mapOf("ops/n/000000000001-b.json" to "b".toByteArray()))
        assertEquals(1, RelaySync(b, endpoint).sync().pushed)
        assertEquals(1, syncA.sync().pulled)
        // A new process resumes from the persisted cursor and remote log: nothing to pull or push,
        // and the only local read is its one-time genesis check.
        val resumed = RelaySync(a, endpoint, stateFile = stateFile)
        assertEquals(RelaySync.Report(localRecordReads = 1), resumed.sync())
        assertEquals(RelaySync.Report(), resumed.sync())

        val foreign = MemoryRecordStore(mapOf("authority/00000001.json" to "other".toByteArray()))
        try {
            RelaySync(foreign, endpoint).sync()
            fail("A different library must stop synchronization")
        } catch (_: RelayException.DifferentLibrary) {
        }
        assertEquals(1, foreign.read().size)

        a.append(mapOf("requests/x.json" to "local".toByteArray()))
        val other = MemoryRecordStore(a.read() - "requests/x.json" + ("requests/x.json" to "relay".toByteArray()))
        assertEquals(1, RelaySync(other, endpoint).sync().pushed)
        assertEquals(listOf("requests/x.json"), syncA.sync().conflicts)
        assertArrayEquals("local".toByteArray(), a.read()["requests/x.json"])
    }

    @Test
    fun unreachableOrUnauthorizedRelayIsNeverAnEmptyLibrary() = runBlocking {
        val closedPort = ServerSocket(0).use { it.localPort }
        val offline = ColophonSession(configuration(home(), MemoryRecordStore(), url = "http://127.0.0.1:$closedPort/v1/libraries/home"))
        offline.restore()
        assertTrue("Expected unavailable, got ${offline.phase.value}", offline.phase.value == SessionPhase.WaitingForDownload)
        offline.create()
        assertTrue("Create must not fork an unknown library", offline.phase.value == SessionPhase.WaitingForDownload)
        assertFalse(offline.syncNow())
        assertTrue(offline.syncState.value is SyncState.Offline)
        offline.close()

        val wrong = ColophonSession(configuration(home(), MemoryRecordStore(), token = "wrong-token-000000000000"))
        wrong.restore()
        assertTrue(wrong.phase.value == SessionPhase.WaitingForDownload)
        assertFalse(wrong.syncNow())
        assertEquals(SyncState.Unauthorized, wrong.syncState.value)
        wrong.close()

        val empty = ColophonSession(configuration(home(), MemoryRecordStore()))
        empty.restore()
        assertEquals("A listed, empty relay slot is an empty library", SessionPhase.NoLibrary, empty.phase.value)
        assertEquals(SyncState.Idle, empty.syncState.value)
        empty.close()
    }

    /**
     * Two members on different local stores converge through one relay. After revocation the
     * member's offline write is held on the owner and its session refuses further writes.
     */
    @Test
    fun twoMembersConvergeAndRevocationHolds() = runBlocking {
        val ownerKeys = SoftwareKeys.ephemeral()
        val ownerStore = MemoryRecordStore()
        val memberStore = MemoryRecordStore()
        val owner = ColophonSession(configuration(home(), ownerStore, ownerKeys))
        owner.restore()
        assertEquals(SessionPhase.NoLibrary, owner.phase.value)
        owner.create()
        assertReadyContent(owner)
        owner.perform(link("from-owner"), owner.observedRevision)
        assertTrue(owner.syncNow())

        val member = ColophonSession(configuration(home(), memberStore))
        member.restore()
        val waiting = member.phase.value as? SessionPhase.WaitingForApproval ?: error("Expected pairing, got ${member.phase.value}")
        assertEquals(owner.libraryID.value, member.libraryID.value)
        assertTrue(member.syncNow())

        assertTrue(owner.syncNow())
        val request = owner.requests.value.single()
        assertEquals(waiting.code, request.pairingCode)
        owner.approve(request)
        assertTrue(owner.syncNow())

        assertTrue(member.syncNow())
        assertReadyContent(member)
        member.perform(link("from-member"), member.observedRevision)
        assertTrue(member.syncNow())
        assertTrue(owner.syncNow())
        assertEquals(listOf("from-member", "from-owner"), links(owner))
        assertEquals("Both devices converge on the same query result", links(owner), links(member))

        val memberID = member.memberID.value!!
        owner.revoke(memberID)
        assertTrue(owner.syncNow())
        member.perform(link("after-revocation"), member.observedRevision)
        assertTrue(member.syncNow())
        assertEquals("Pulling the revocation ends the member's access", SessionPhase.Denied, member.phase.value)
        try {
            member.perform(link("refused"), member.observedRevision)
            fail("A revoked member's session must refuse writes")
        } catch (_: SessionException.NotReady) {
        }
        assertTrue(owner.syncNow())
        assertEquals("A revoked member's later write never folds", listOf("from-member", "from-owner"), links(owner))
        val view = ColophonLibrary.open(ownerStore.read(), ownerKeys).use { it.view("reading.saved").get() }
        assertTrue((view.held + view.refused).any { it.author == memberID && it.reason.contains("revoked", ignoreCase = true) })
        owner.close()
        member.close()
    }

    @Test
    fun automaticSyncDeliversWithoutBarriers() = runBlocking {
        val owner = ColophonSession(configuration(home(), MemoryRecordStore(), automatic = true))
        owner.create()
        assertReadyContent(owner)
        val member = ColophonSession(configuration(home(), MemoryRecordStore(), automatic = true))
        member.restore()
        eventually { owner.requests.value.isNotEmpty() }
        owner.approve(owner.requests.value.first())
        try { eventually { member.phase.value == SessionPhase.Ready } }
        catch (error: Throwable) { throw AssertionError("Member phase=${member.phase.value} sync=${member.syncState.value}; owner phase=${owner.phase.value} sync=${owner.syncState.value}", error) }
        member.perform(link("pushed-automatically"), member.observedRevision)
        eventually { links(owner) == listOf("pushed-automatically") }
        owner.close()
        member.close()
    }

    private suspend fun eventually(condition: suspend () -> Boolean) {
        withTimeout(20_000) {
            while (!condition()) delay(50)
        }
    }
}
