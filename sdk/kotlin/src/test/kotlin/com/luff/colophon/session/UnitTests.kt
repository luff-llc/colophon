package com.luff.colophon.session

import com.luff.colophon.AccountSigningStep
import com.luff.colophon.EpochAnswer
import com.luff.colophon.HttpMethod
import com.luff.colophon.HttpRequest
import com.luff.colophon.SignForm
import com.luff.colophon.StepRole
import com.sun.net.httpserver.HttpServer
import kotlinx.coroutines.runBlocking
import org.junit.Test
import java.io.File
import java.net.InetSocketAddress
import java.nio.file.Files
import java.security.Signature
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class JsonTest {
    @Test fun roundTripsAndRefusesWhatIsNotJson() {
        val v = Json.parse("""{"b":[1,-2,3.5,true,null,"x\né"],"a":{"n":12345678901234567890}}""")
        @Suppress("UNCHECKED_CAST") val m = v as Map<String, Any?>
        assertEquals(listOf(1L, -2L, 3.5, true, null, "x\né"), m["b"])
        assertEquals("12345678901234567890", (m["a"] as Map<*, *>)["n"].toString())
        assertEquals("""{"a":{"n":12345678901234567890},"b":[1,-2,3.5,true,null,"x\né"]}""", Json.write(v))
        assertEquals("""{"z":1,"a":2}""", Json.write(linkedMapOf("z" to 1, "a" to 2), sorted = false))
        assertEquals("""{"m":{"k":1}}""", Json.write(mapOf("m" to RawJson("""{"k":1}"""))))
        for (bad in listOf("""{"a":1,"a":2}""", "[1,]", "01", "\"\u0001\"", "{} x", "[" .repeat(300) + "]".repeat(300))) {
            assertFailsWith<Json.ParseException>(bad) { Json.parse(bad) }
        }
        assertNull(Json.obj("[1]"))
    }
}

class KeysTest {
    @Test fun softwareKeysSignRawAndAgree() = runBlocking<Unit> {
        val a = SoftwareKeys(); val b = SoftwareKeys()
        val body = "body".toByteArray()
        val raw = a.sign(body)
        assertEquals(64, raw.size)
        val ok = Signature.getInstance("SHA256withECDSAinP1363Format").run {
            initVerify(P256.publicKey(a.publicKeys().signing)); update(body); verify(raw)
        }
        assertTrue(ok, "a raw r||s signature verifies")
        val ab = a.sharedSecret(b.publicKeys().agreement).lend { it.copyOf() }
        val ba = b.sharedSecret(a.publicKeys().agreement).lend { it.copyOf() }
        assertContentEquals(ab, ba); assertEquals(32, ab.size)
        assertEquals(SignForm.RAW, a.keyDescriptor().form)
        assertEquals(a.id, KeyCustody.keyId(a))
    }

    @Test fun derToRawPadsAndRefuses() {
        // r with a leading zero byte (33 bytes in DER) and a short s.
        val r = ByteArray(32) { 0x80.toByte() }; val s = ByteArray(31) { 1 }
        val der = byteArrayOf(0x30, (2 + 33 + 2 + 31).toByte(), 2, 33, 0) + r + byteArrayOf(2, 31) + s
        assertContentEquals(r + (byteArrayOf(0) + s), P256.derToRaw(der))
        assertFailsWith<IllegalArgumentException> { P256.derToRaw(der.copyOf(der.size - 1)) }
        assertFailsWith<IllegalArgumentException> { P256.derToRaw(byteArrayOf(0x31) + der.copyOfRange(1, der.size)) }
    }

    @Test fun secretsAreWipedAfterTheirCall() = runBlocking<Unit> {
        val secret = SecretBytes.adopt(byteArrayOf(1, 2, 3))
        var lent: ByteArray? = null
        secret.lend { lent = it }
        secret.close()
        assertContentEquals(byteArrayOf(0, 0, 0), lent)
        assertFailsWith<IllegalStateException> { secret.lend { it } }
        assertEquals("SecretBytes(redacted)", secret.toString())
        val answer = HostEpochAnswer("notes", 1u, SecretBytes.adopt(ByteArray(32) { 7 }))
        var seen: List<EpochAnswer> = listOf()
        listOf(answer).withRecords { seen = it }
        assertTrue(seen.single().shared.all { it == 0.toByte() }, "the record's bytes are wiped after the call")
        var entropy: ByteArray? = null
        withEntropy(32) { entropy = it; assertTrue(it.any { b -> b != 0.toByte() }) }
        assertTrue(entropy!!.all { it == 0.toByte() })
    }

    @Test fun custodyRefusesAKeyItDoesNotHoldAndAnUnknownForm() = runBlocking<Unit> {
        val a = SoftwareKeys()
        val custody = KeyCustody.of(listOf(a))
        val step = AccountSigningStep("p", byteArrayOf(1), "0".repeat(32), StepRole.PRIMARY, SignForm.RAW, null, byteArrayOf(), null, false)
        assertFailsWith<KeyCustodyException.NoKey> { custody.sign(listOf(step)) }
        assertFailsWith<KeyCustodyException.Unsupported> { custody.sign(listOf(step.copy(signer = a.id, form = SignForm.UNKNOWN))) }
        assertFailsWith<KeyCustodyException.MissingChallenge> { custody.sign(listOf(step.copy(signer = a.id, form = SignForm.WEBAUTHN))) }
        // A raw key has no assertion: a WebAuthn step is unsupported, never a fallback.
        assertFailsWith<KeyCustodyException.Unsupported> { custody.sign(listOf(step.copy(signer = a.id, form = SignForm.WEBAUTHN, challenge = "c"))) }
        assertEquals(1, custody.sign(listOf(step.copy(signer = a.id))).size)
    }
}

class MediumTest {
    private fun both(): List<RecordMedium> = listOf(MemoryMedium(), FolderMedium(Files.createTempDirectory("colophon-kotlin-medium-").toFile()))

    @Test fun writesAreAllOrNoneAndImmutable() {
        for (m in both()) {
            m.write(listOf(MediumWrite("authority/00000001.json", byteArrayOf(1)), MediumWrite("state/x.json", byteArrayOf(1))))
            m.write(listOf(MediumWrite("authority/00000001.json", byteArrayOf(1)))) // an exact duplicate is idempotent
            assertFailsWith<StorageException.Conflict> {
                m.write(listOf(MediumWrite("ops/a.json", byteArrayOf(2)), MediumWrite("authority/00000001.json", byteArrayOf(9))))
            }
            assertEquals(listOf("authority/00000001.json", "state/x.json"), m.listing().map { it.path }, "nothing of a refused batch is stored: $m")
            m.write(listOf(MediumWrite("state/x.json", byteArrayOf(2))))
            assertContentEquals(byteArrayOf(2), m.read("state/x.json"), "a live slot is replaceable")
            assertContentEquals(byteArrayOf(), m.readBlob("blobs/none"), "a blob not held is empty")
            assertFailsWith<StorageException.Unavailable> { m.read("ops/missing.json") }
            for (bad in listOf("", "/a", "a/", "a//b", ".hidden/x", "a/../b", "a\\b")) {
                assertFailsWith<StorageException.InvalidPath>(bad) { m.write(listOf(MediumWrite(bad, byteArrayOf(1)))) }
            }
            if (m is FolderMedium) m.root.deleteRecursively()
        }
    }

    @Test fun folderFinishesACommittedBatchAndDiscardsAnUncommittedOne() {
        val root = Files.createTempDirectory("colophon-kotlin-folder-").toFile()
        try {
            // A kill after the commit point: the staged files and the commit record exist, nothing moved yet.
            val committed = File(root, ".colophon/staging/a").apply { mkdirs() }
            File(committed, "0").writeBytes(byteArrayOf(5))
            val digest = java.security.MessageDigest.getInstance("SHA-256").digest(byteArrayOf(5)).joinToString("") { "%02x".format(it) }
            File(root, ".colophon/commit-a").writeText("0 $digest ops/n/x.json\n")
            // A kill before it: staged, no commit record.
            val loose = File(root, ".colophon/staging/b").apply { mkdirs() }
            File(loose, "0").writeBytes(byteArrayOf(6))
            val m = FolderMedium(root)
            assertEquals(listOf("ops/n/x.json"), m.listing().map { it.path })
            assertContentEquals(byteArrayOf(5), m.read("ops/n/x.json"))
            assertFalse(File(root, ".colophon/commit-a").exists())
            assertFalse(loose.exists(), "an uncommitted batch is discarded")
            // A symbolic link inside the folder is never followed.
            val outside = Files.createTempFile("colophon-kotlin-outside", ".json").toFile().apply { writeBytes(byteArrayOf(7)) }
            Files.createSymbolicLink(File(root, "ops/link.json").toPath(), outside.toPath())
            assertFailsWith<StorageException.InvalidPath> { m.read("ops/link.json") }
            assertFalse(m.listing().any { it.path == "ops/link.json" })
            outside.delete()
        } finally {
            root.deleteRecursively()
        }
    }
}

class TransportTest {
    @Test fun onlyHttpsOrLoopbackWithTheTestingOption() {
        assertTrue(HomeLimits.isAllowed("https://home.example/v1/", false))
        assertFalse(HomeLimits.isAllowed("http://home.example/v1/", true))
        assertFalse(HomeLimits.isAllowed("http://127.0.0.1:8080/", false))
        assertTrue(HomeLimits.isAllowed("http://127.0.0.1:8080/", true))
        assertTrue(HomeLimits.isAllowed("http://localhost/", true))
        assertFalse(HomeLimits.isAllowed("ftp://home.example/", true))
        assertEquals(64 * 1024, HomeLimits.responseBytes("https://h/v1/accounts/a/head"))
        assertEquals(1024 * 1024, HomeLimits.responseBytes("https://h/v1/accounts/a/records/blobs/x"))
        assertEquals(41 * 1024 * 1024, HomeLimits.responseBytes("https://h/v1/accounts/a/records/ops/x"))
        assertEquals(32 * 1024 * 1024, HomeLimits.responseBytes("https://h/v1/accounts/a/authority?after=1"))
    }

    @Test fun boundsRedirectsAndInsecureEndpoints() = runBlocking<Unit> {
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.createContext("/big/head") { ex -> val b = ByteArray(70 * 1024); ex.sendResponseHeaders(200, b.size.toLong()); ex.responseBody.use { it.write(b) } }
        server.createContext("/moved") { ex -> ex.responseHeaders.add("Location", "https://elsewhere.example/"); ex.sendResponseHeaders(302, -1); ex.close() }
        server.createContext("/echo") { ex ->
            val body = ex.requestBody.readBytes(); val auth = ex.requestHeaders.getFirst("Authorization") ?: ""
            val out = (auth + ":" + body.size).toByteArray(); ex.sendResponseHeaders(201, out.size.toLong()); ex.responseBody.use { it.write(out) }
        }
        server.start()
        try {
            val base = "http://127.0.0.1:${server.address.port}"
            val t = HttpHomeTransport(allowingLoopbackHttp = true)
            fun req(method: HttpMethod, path: String, body: ByteArray = byteArrayOf()) =
                HttpRequest(1u, "h", method, base + path, listOf(com.luff.colophon.Header("Authorization", "Colophon x")), body)
            assertFailsWith<HomeTransportException.ResponseTooLarge> { t.send(req(HttpMethod.GET, "/big/head")) }
            assertEquals(302u, t.send(req(HttpMethod.GET, "/moved")).status, "a redirect is returned to the engine, not followed")
            val echo = t.send(req(HttpMethod.POST, "/echo", ByteArray(10)))
            assertEquals(201u, echo.status); assertEquals("Colophon x:10", echo.body.toString(Charsets.UTF_8))
            assertFailsWith<HomeTransportException.InsecureEndpoint> { HttpHomeTransport().send(req(HttpMethod.GET, "/echo")) }
        } finally {
            server.stop(0)
        }
    }
}

/** The session without a home: creation, writes, reads, lock, a second device approved over a shared store, revocation. */
class SessionTest {
    @Test fun createWriteReadLockAndUnlock() = runBlocking<Unit> {
        val d = Device()
        try {
            d.session.create()
            assertEquals(SessionPhase.Ready, d.session.phase, d.describe())
            assertTrue(d.session.notices.noHome, "an account without a home says so")
            assertTrue(d.session.duties.soleDevice)
            val stale = d.session.observedRevision
            note(d.session, "a")
            assertEquals(1, admitted(d.session))
            assertFailsWith<SessionError.StaleRevision> {
                d.session.perform(DomainCommand("notes", "note.put", """{"id":"b","text":"b"}"""), stale)
            }
            assertEquals(1, admitted(d.session), "a stale write signs nothing")
            assertFailsWith<SessionError.InvalidCommand> { DomainCommand("notes", "note.put", "[1]") }
            val blob = d.session.putBlob(ByteArray(150_000) { it.toByte() }, "notes", "application/octet-stream", "r")
            assertEquals(BlobAvailabilityState.Available, d.session.blobAvailability("notes", blob.digest))
            assertContentEquals(ByteArray(150_000) { it.toByte() }, d.session.blobData("notes", blob.digest))
            assertFailsWith<BlobException.TooLarge> { d.session.blobData("notes", blob.digest, maximumBytes = 10) }
            d.session.lock()
            assertEquals(SessionPhase.Locked, d.session.phase)
            assertFailsWith<SessionError.NotReady> { d.session.view("notes") }
            d.session.refresh()
            assertEquals(SessionPhase.Locked, d.session.phase, "a refresh leaves a locked session locked")
            d.session.unlock()
            assertEquals(SessionPhase.Ready, d.session.phase, d.describe())
            assertEquals(2, admitted(d.session))
        } finally { d.close() }
    }

    @Test fun creationNeedsAHomeOrAnOptOutAndHttps() = runBlocking<Unit> {
        val d = Device(createWithoutHome = false)
        try {
            d.session.create()
            assertEquals(SessionPhase.NoLibrary, d.session.phase)
            assertEquals(SessionError.NoHome().message, d.session.lastError)
        } finally { d.close() }
        val e = Device(homes = listOf(HomeConfiguration("http://home.example/v1/")), createWithoutHome = false)
        try {
            e.session.create()
            assertTrue(e.session.phase is SessionPhase.Failed, e.describe())
            assertTrue(e.medium.listing().isEmpty(), "nothing is created for an insecure home")
        } finally { e.close() }
    }

    /** A failed `create()` stays published: a background sync pass with no library does not refresh it away (the race seen as "phase NoLibrary error -" after an `http://` home). Deterministic: the pass is run explicitly after the failure. */
    @Test fun aFailedCreationIsNotErasedByASyncPass() = runBlocking<Unit> {
        val e = Device(homes = listOf(HomeConfiguration("http://home.example/v1/")), createWithoutHome = false)
        try {
            e.session.create()
            val failed = e.session.phase
            assertTrue(failed is SessionPhase.Failed, e.describe())
            val error = e.session.lastError
            assertNotNull(error, e.describe())
            assertEquals(false, e.session.syncNow(), "with no library there is nothing to exchange")
            assertEquals(failed, e.session.phase, e.describe())
            assertEquals(error, e.session.lastError, e.describe())
        } finally { e.close() }
    }

    @Test fun aFolderStoreReopensWithTheSavedState() = runBlocking<Unit> {
        val root = Files.createTempDirectory("colophon-kotlin-reopen-").toFile()
        val dir = Files.createTempDirectory("colophon-kotlin-private-").toFile()
        val secrets = MemoryDeviceSecrets(); val member = SoftwareKeys(); val owner = SoftwareKeys()
        try {
            val first = Device(member = member, owner = owner, secrets = secrets, dir = dir, storage = FolderMedium(root))
            first.session.create()
            note(first.session, "a")
            first.session.flushCheckpoint()
            first.session.shutdown()
            assertTrue(dir.listFiles()!!.any { it.name.startsWith("saved-") }, "the sealed saved state is in the private directory")
            val again = Device(member = member, owner = owner, secrets = secrets, dir = dir, storage = FolderMedium(root))
            again.session.restore()
            assertEquals(SessionPhase.Ready, again.session.phase, again.describe())
            assertEquals(1, admitted(again.session))
            note(again.session, "b")
            assertEquals(2, admitted(again.session))
            again.session.shutdown()
        } finally { root.deleteRecursively(); dir.deleteRecursively() }
    }

    @Test fun aSecondDeviceAsksOverASharedStoreIsApprovedAndRevoked() = runBlocking<Unit> {
        val shared = MemoryMedium()
        val first = Device(medium = shared)
        val second = Device(medium = shared)
        try {
            first.session.create()
            note(first.session, "a")
            second.session.restore()
            val waiting = second.session.phase
            assertTrue(waiting is SessionPhase.WaitingForApproval, second.describe())
            first.session.refresh()
            val request = first.session.requests.single()
            assertEquals(second.session.memberId, request.id)
            approveByCode(second.session, first.session)
            second.session.refresh()
            assertEquals(SessionPhase.Ready, second.session.phase, second.describe())
            assertEquals(1, admitted(second.session))
            note(second.session, "b")
            first.session.refresh()
            assertEquals(2, admitted(first.session))
            first.session.revoke(second.session.memberId!!)
            second.session.refresh()
            assertEquals(SessionPhase.Denied, second.session.phase, second.describe())
            assertFailsWith<SessionError.NotReady> { note(second.session, "c") }
        } finally { first.close(); second.close() }
    }

    @Test fun aFailingOwnerKeyIsAKeyFailureNotAnEmptyLibrary() = runBlocking<Unit> {
        val shared = MemoryMedium()
        val first = Device(medium = shared)
        val second = Device(medium = shared)
        try {
            first.session.create()
            second.session.restore()
            first.session.refresh()
            // The same account, with an owner key that fails (a cancelled prompt, a missing hardware key).
            val broken = object : AsyncKeyProvider by first.owner {
                override suspend fun sharedSecret(peer: ByteArray): SecretBytes = throw IllegalStateException("the key is not available")
            }
            val third = ColophonSession(SessionConfiguration(memberLabel = "Test device", namespaces = listOf("notes"), medium = shared,
                privateDirectory = Files.createTempDirectory("colophon-kotlin-broken-").toFile(), keys = first.member, ownerController = broken,
                createWithoutHome = true, deviceSecrets = MemoryDeviceSecrets()))
            third.restore()
            assertEquals(SessionPhase.Ready, third.phase)
            val scanned = third.scanRequest(second.session.exportRequest())
            assertFailsWith<SessionKeyFailure> { third.approve(scanned.request, scanned.pairing) }
            assertEquals(SessionPhase.Failed(SessionFailure.KeysUnavailable("the key is not available")), third.phase)
            third.shutdown()
        } finally { first.close(); second.close() }
    }

}
