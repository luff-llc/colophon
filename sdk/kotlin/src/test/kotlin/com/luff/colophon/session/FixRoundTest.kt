package com.luff.colophon.session

import com.luff.colophon.AccountException
import com.luff.colophon.AccountMemberKind
import com.luff.colophon.AccountRequest
import com.luff.colophon.EpochAgreement
import com.luff.colophon.HttpMethod
import com.luff.colophon.PublicKeys
import com.luff.colophon.RequestSpec
import com.luff.colophon.Signature
import com.luff.colophon.UnlockInput
import com.luff.colophon.UnlockKind
import com.luff.colophon.accountFormatDate
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.util.Collections
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** The findings of the independent check of K1, each as a test that failed before its fix. */
class FixRoundTest {
    /** A key that answers with 32 bytes of 7 and remembers the array it handed over. */
    private class Remembering(val keys: SoftwareKeys = SoftwareKeys()) : AsyncKeyProvider by keys {
        val handed = Collections.synchronizedList(ArrayList<ByteArray>())
        override suspend fun sharedSecret(peer: ByteArray): SecretBytes = ByteArray(32) { 7 }.also { handed.add(it) }.let { SecretBytes.adopt(it) }
        override suspend fun prf(salt: ByteArray): SecretBytes? = ByteArray(32) { 7 }.also { handed.add(it) }.let { SecretBytes.adopt(it) }
    }
    private class Failing(val keys: SoftwareKeys = SoftwareKeys()) : AsyncKeyProvider by keys {
        override suspend fun sharedSecret(peer: ByteArray): SecretBytes = throw IllegalStateException("second route failed")
        override suspend fun prf(salt: ByteArray): SecretBytes? = throw IllegalStateException("second route failed")
    }

    // 1. A later provider failing leaves no earlier secret live.
    @Test fun aFailingSecondKeyWipesTheFirstSecret() = runBlocking<Unit> {
        val first = Remembering(); val second = Failing()
        val custody = KeyCustody.of(listOf(first, second))
        val peer = first.keys.publicKeys().agreement
        val agreements = listOf(EpochAgreement("notes", 1u, first.keys.id, peer, peer), EpochAgreement("notes", 1u, second.keys.id, peer, peer))
        assertFailsWith<IllegalStateException> { custody.answerEpochs(agreements) }
        val inputs = listOf(UnlockInput(UnlockKind.ECDH, first.keys.id, peer, ByteArray(0)), UnlockInput(UnlockKind.PRF, second.keys.id, ByteArray(0), ByteArray(32)))
        assertFailsWith<IllegalStateException> { custody.answerUnlock(inputs) }
        assertEquals(2, first.handed.size)
        assertTrue(first.handed.all { a -> a.all { it == 0.toByte() } }, "every secret built before the failure is wiped")
    }

    // 1. A locked engine refuses the answers, and they are wiped all the same.
    @Test fun answersGivenToALockedEngineAreWiped() = runBlocking<Unit> {
        val d = Device()
        try {
            d.session.create()
            val engine = d.session.worker.requireEngine()
            engine.lock()
            val bytes = ByteArray(32) { 7 }
            assertFailsWith<AccountException.Locked> { engine.finishUnlockEpochs(listOf(HostEpochAnswer("notes", 1u, SecretBytes.adopt(bytes)))) }
            assertTrue(bytes.all { it == 0.toByte() }, "a refused answer is wiped")
        } finally { d.close() }
    }

    // 2. A failure after the commit point rolls forward; it is never half applied.
    @Test fun aFolderBatchThatFailsAfterItsCommitRollsForward() {
        val root = Files.createTempDirectory("colophon-kotlin-rollforward-").toFile()
        try {
            val m = FolderMedium(root)
            val batch = listOf(MediumWrite("ops/a.json", byteArrayOf(1)), MediumWrite("ops/b.json", byteArrayOf(2)), MediumWrite("ops/c.json", byteArrayOf(3)))
            m.fault = { if (it == "move:ops/b.json") throw java.io.IOException("injected") }
            assertFailsWith<StorageException.Unavailable> { m.write(batch) }
            // While it cannot be completed, no caller sees half of it.
            assertFailsWith<StorageException.Unavailable> { m.listing() }
            assertFailsWith<StorageException.Unavailable> { m.read("ops/a.json") }
            // A crash now, then a reopen: the batch is completed.
            val reopened = FolderMedium(root)
            assertEquals(listOf("ops/a.json", "ops/b.json", "ops/c.json"), reopened.listing().map { it.path })
            assertTrue(File(root, ".colophon").listFiles()!!.none { it.name.startsWith("commit-") }, "the record is removed once complete")
            // And the same process completes it too once the fault is gone.
            m.fault = { if (it == "move:ops/e.json") throw java.io.IOException("injected") }
            assertFailsWith<StorageException.Unavailable> { m.write(listOf(MediumWrite("ops/d.json", byteArrayOf(4)), MediumWrite("ops/e.json", byteArrayOf(5)))) }
            m.fault = null
            assertEquals(listOf("ops/a.json", "ops/b.json", "ops/c.json", "ops/d.json", "ops/e.json"), m.listing().map { it.path })
        } finally { root.deleteRecursively() }
    }

    // 2. A failure at each target, then a crash and a reopen: every batch is whole, each time.
    @Test fun aFolderBatchIsWholeAfterAFailureAtEveryStep() {
        val paths = listOf("ops/a.json", "ops/b.json", "state/s.json")
        for (step in paths.map { "stage:$it" } + "commit" + paths.map { "move:$it" }) {
            val root = Files.createTempDirectory("colophon-kotlin-steps-").toFile()
            try {
                val m = FolderMedium(root)
                m.write(listOf(MediumWrite("state/s.json", byteArrayOf(0))))
                m.fault = { if (it == step) throw java.io.IOException("injected at $it") }
                assertFailsWith<StorageException> { m.write(paths.mapIndexed { n, p -> MediumWrite(p, byteArrayOf((n + 1).toByte())) }) }
                val after = FolderMedium(root).listing().map { it.path }
                if (step.startsWith("move:")) {
                    assertEquals(paths.sorted(), after, "after the commit point the batch is completed ($step)")
                    assertEquals(3, FolderMedium(root).read("state/s.json")[0].toInt(), "the replaced slot has its new bytes ($step)")
                } else {
                    assertEquals(listOf("state/s.json"), after, "before the commit point nothing is published ($step)")
                    assertEquals(0, FolderMedium(root).read("state/s.json")[0].toInt())
                }
                assertTrue(File(root, ".colophon/staging").listFiles().orEmpty().isEmpty(), "no staging is left ($step)")
            } finally { root.deleteRecursively() }
        }
    }

    // 6. Loopback means a literal loopback address or `localhost`, never a name that starts with 127.
    @Test fun loopbackIsALiteralAddress() {
        for (bad in listOf("http://127.attacker.example/", "http://127.0.0.1.attacker.example/", "http://localhost.attacker.example/",
                           "http://evil.localhost/", "http://127.1/", "http://0x7f000001/")) {
            assertTrue(!HomeLimits.isAllowed(bad, true), bad)
        }
        for (good in listOf("http://127.0.0.1:8080/", "http://127.255.0.9/", "http://[::1]:9000/", "http://localhost/", "http://LOCALHOST:1/")) {
            assertTrue(HomeLimits.isAllowed(good, true), good)
        }
    }

    // 9. A lone surrogate escape is not JSON text (spec §2.3).
    @Test fun loneSurrogatesAreRefused() {
        for (bad in listOf("""{"x":"\ud800"}""", """{"x":"\udc00"}""", """{"x":"\ud800x"}""", """{"x":"\ud800A"}""")) {
            assertFailsWith<Json.ParseException>(bad) { Json.parse(bad) }
        }
        assertEquals(mapOf("x" to "😀"), Json.parse("""{"x":"😀"}"""))
        assertFailsWith<SessionError.InvalidCommand> { DomainCommand("notes", "note.put", """{"x":"\ud800"}""") }
    }

    // 5. A key prompt that never returns: cancelling the owner operation ends it, and lock() completes and clears the keys.
    @Test(timeout = 60_000) fun aHungKeyPromptDoesNotHoldTheSessionOrBlockLock() = runBlocking<Unit> {
        val shared = MemoryMedium()
        val first = Device(medium = shared)
        val second = Device(medium = shared)
        try {
            first.session.create()
            second.session.restore()
            first.session.refresh()
            val prompting = CompletableDeferred<Unit>()
            val hung = object : AsyncKeyProvider by first.owner {
                override suspend fun sharedSecret(peer: ByteArray): SecretBytes { prompting.complete(Unit); awaitCancellation() }
            }
            val third = ColophonSession(SessionConfiguration(memberLabel = "Test device", namespaces = listOf("notes"), medium = shared,
                privateDirectory = Files.createTempDirectory("colophon-kotlin-hung-").toFile(), keys = first.member, ownerController = hung,
                createWithoutHome = true, deviceSecrets = MemoryDeviceSecrets()))
            third.restore()
            val request = third.requests.single()
            val job = async { third.approve(request) }
            withTimeout(10_000) { prompting.await() }
            job.cancel()
            val locked = withTimeoutOrNull(5_000) { third.lock(); true }
            assertNotNull(locked, "lock() completed while the cancelled prompt was outstanding")
            assertEquals(SessionPhase.Locked, third.phase)
            assertTrue(third.worker.engineForTests() == null, "the engine is dropped")
            third.unlock()
            assertEquals(SessionPhase.Ready, third.phase, "the session opens again")
            third.shutdown()
        } finally { first.close(); second.close() }
    }

    // 7. The exchange deadline covers the transport: a home that never answers ends the pass.
    @Test(timeout = 60_000) fun theExchangeDeadlineCoversTheTransport() = runBlocking<Unit> {
        val endpoint = "https://silent-home.test/v1/accounts/k/"
        val homeKeys = SoftwareKeys()
        val seen = Collections.synchronizedList(ArrayList<String>())
        val home = HomeConfiguration(endpoint, request = { account -> homeRequest(homeKeys, account, endpoint) },
            transport = HomeTransport { r -> seen.add("${r.method} ${r.url}"); awaitCancellation() })
        val d = Device(homes = listOf(home), createWithoutHome = false)
        try {
            d.session.create()
            d.session.stopSync()
            d.session.worker.exchangeTimeMs = 1_000
            val ok = withTimeout(20_000) { d.session.syncNow() }
            assertTrue(d.session.homeIssues.any { it.problem is HomeProblem.TooSlow }, "the pass is stopped as too slow: ${d.describe()} $ok")
            seen.clear()
            withTimeout(20_000) { d.session.syncNow() }
            assertEquals("${HttpMethod.GET} ${endpoint}head", seen.firstOrNull(), "the next pass starts from the head (the slow one was aborted)")
        } finally { d.close() }
    }

    private suspend fun homeRequest(keys: SoftwareKeys, account: String, endpoint: String): ByteArray {
        val p: PublicKeys = keys.publicKeys()
        val spec = RequestSpec(account, p.signing, p.agreement, "Home", AccountMemberKind.SERVER, "{\"serves\":[\"home\"]}",
            accountFormatDate(System.currentTimeMillis() - 5_000), null, null, listOf(endpoint))
        return AccountRequest.prepare(spec).use { r -> r.finish(Signature(keys.sign(r.step().body), null, null)).raw }
    }
}
