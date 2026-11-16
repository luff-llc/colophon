package com.luff.colophon.session

import com.luff.colophon.Header
import com.luff.colophon.HttpAnswer
import com.luff.colophon.HttpMethod
import com.luff.colophon.accountFormatDate
import com.luff.colophon.accountKeyId
import kotlinx.coroutines.runBlocking
import org.junit.Test
import java.security.MessageDigest
import java.util.Base64
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.*

private fun sha256Hex(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

/**
 * **Test-only, below the 0.5 builders**: a transition raising the account's layout to [layout] (spec §20 "The upgrade
 * door"), signed by the owner controller and written to the device's store. 0.5's write side deliberately builds no
 * `layout` component, so this helper writes the canonical body itself (every value is plain ASCII, keys in order): the
 * account, the anchor (the verified head), the owner as `by` and only signer, the change, the clock. The session's own
 * refresh then records the `activate` (`record_due`), final at once in an account with no home: the device is stopped.
 */
suspend fun raiseLayout(device: Device, layout: Int = 3, nowMs: Long = System.currentTimeMillis()) {
    val account = assertNotNull(device.session.libraryId)
    val last = device.medium.listing().map { it.path }.filter { it.startsWith("authority/") }.sorted().last()
    val envelope = assertNotNull(Json.obj(device.medium.read(last).toString(Charsets.UTF_8)))
    val headBody = Base64.getDecoder().decode(assertNotNull(envelope.string("body")))
    val seq = last.removePrefix("authority/").take(8).toInt()
    val owner = accountKeyId(device.owner.publicKeys().signing)
    val issued = accountFormatDate(nowMs)
    val body = ("{\"account\":\"$account\",\"anchor\":{\"digest\":\"${sha256Hex(headBody)}\",\"seq\":$seq},\"by\":\"$owner\"," +
        "\"change\":{\"layout\":$layout},\"issued\":\"$issued\",\"protocol\":\"colophon/transition/5\",\"signers\":[\"$owner\"]}").toByteArray()
    val signature = device.owner.sign(body)
    val b64 = Base64.getEncoder()
    val transition = "{\"body\":\"${b64.encodeToString(body)}\",\"signature\":\"${b64.encodeToString(signature)}\"}".toByteArray()
    device.medium.write(listOf(MediumWrite("transitions/${sha256Hex(body)}.json", transition)))
}

/** A home's error body: the result, and bytes a session must never echo. */
fun refusalBody(result: String): ByteArray = "{\"result\":\"$result\",\"detail\":\"SECRET-BODY-BYTES\"}".toByteArray()

class StoppedAccountTest {
    private suspend fun items(session: ColophonSession): Int = admitted(session)

    /**
     * A final layout raise this device verified stops the account (spec §1 "A stop"): the phase says to update the app,
     * what the device holds stays readable, nothing is written, no exchange runs, and it persists across relaunch; lock
     * and sign-out still work.
     */
    @Test fun aFinalRaiseStopsTheAccountReadablyAndForGood() = runBlocking<Unit> {
        // A home is configured (so a sync loop exists) but not appointed: the raise is final at once. Any request fails.
        val sent = AtomicInteger()
        val home = HomeConfiguration("https://home.example/", transport = HomeTransport { sent.incrementAndGet(); HttpAnswer(500u, listOf(), ByteArray(0)) })
        val device = Device(homes = listOf(home))
        var relaunched: ColophonSession? = null
        try {
            device.session.create()
            assertEquals(SessionPhase.Ready, device.session.phase, device.describe())
            note(device.session, "before")
            assertEquals(1, items(device.session))
            val head = device.medium.listing().count { it.path.startsWith("authority/") }

            raiseLayout(device)
            device.session.flushExternalChanges()
            val phase = device.session.phase
            assertTrue(phase is SessionPhase.Stopped, device.describe())
            assertEquals(SessionPhase.Stopped(head + 1L, 3L), phase)
            assertNull(device.session.lastError, "no fault is shown")
            // Reads go on, as of the stop.
            assertTrue(device.session.hasUsableContent)
            assertEquals(1, items(device.session))
            // A write is refused, and the phase stays.
            assertFails { note(device.session, "after") }
            assertTrue(device.session.phase.isStopped, device.describe())
            assertEquals(1, device.medium.listing().count { it.path.startsWith("ops/") }, "nothing new was written")
            // No exchange runs: not a failure, and no home is contacted.
            assertTrue(device.session.syncNow())
            assertEquals(HomeSyncState.Disabled, device.session.state.value.syncState)
            assertEquals(0, sent.get())
            // Lock and unlock: back to stopped.
            device.session.lock()
            assertEquals(SessionPhase.Locked, device.session.phase)
            device.session.unlock()
            assertTrue(device.session.phase.isStopped, device.describe())
            device.session.shutdown()
            // Relaunch: still stopped, still readable.
            relaunched = ColophonSession(SessionConfiguration(memberLabel = "Test device", namespaces = listOf("notes"), medium = device.medium,
                privateDirectory = device.dir, keys = device.member, ownerController = device.owner, homes = listOf(home), deviceSecrets = device.secrets))
            relaunched.restore()
            relaunched.stopSync()
            assertEquals(SessionPhase.Stopped(head + 1L, 3L), relaunched.phase)
            assertEquals(1, items(relaunched))
            // Sign-out works.
            relaunched.leave()
            assertEquals(SessionPhase.NoLibrary, relaunched.phase)
        } finally { relaunched?.shutdown(); device.close() }
    }

    /** A raise that is only held (not yet due) changes nothing. */
    @Test fun aRaiseThatIsNotYetRecordedStopsNothing() = runBlocking<Unit> {
        val device = Device()
        try {
            device.session.create()
            raiseLayout(device, nowMs = System.currentTimeMillis() + 3_600_000)
            device.session.flushExternalChanges()
            assertFalse(device.session.phase.isStopped, device.describe())
        } finally { device.close() }
    }
}

/**
 * A home's refusals, shown raw (spec §14, §19): an unknown `refused:` name, and the four reserved ones, refuse only that
 * request and are surfaced with their name as given, validated and bounded, never echoing the body; `Retry-After` is
 * honoured; `503 {"result":"unavailable"}` is the home being unavailable; none of them is a verified state of the account.
 */
class HomeRefusalTest {
    @Test fun theResultGrammarIsBoundedAndNothingElseIsRead() {
        for (good in listOf("refused:overQuota", "refused:noEntitlement", "refused:closed", "refused:notProvisioned", "refused:somethingNew2", "unavailable")) {
            assertTrue(HomeRefusal.isValid(good), good)
        }
        for (bad in listOf("refused:", "refused:Upper", "refused:a-b", "refused:<script>", "refused:" + "a".repeat(49), "nope", "refused:é")) {
            assertFalse(HomeRefusal.isValid(bad), bad)
        }
        val r = assertNotNull(HomeRefusal.of(410, listOf(Header("Retry-After", "30")), refusalBody("refused:closed")))
        assertEquals("refused:closed", r.code); assertEquals(30, r.retryAfterSeconds)
        assertNull(HomeRefusal.of(410, listOf(), refusalBody("refused:<x>")), "an invalid result is not read")
        assertNull(HomeRefusal.of(200, listOf(), refusalBody("refused:closed")))
        assertNull(HomeRefusal.of(429, listOf(Header("retry-after", "Tue, 1 Dec")), ByteArray(0)))
    }

    /** One relay-backed device whose transport the test can make answer instead of the home. */
    private class World {
        val relay = RelayHome("https://refusal.test/v1/accounts/kotlin")
        @Volatile var answer: ((com.luff.colophon.HttpRequest) -> HttpAnswer?)? = null
        val sent = AtomicInteger()
        private val inner = relay.transport()
        val transport = HomeTransport { request -> sent.incrementAndGet(); answer?.invoke(request) ?: inner.send(request) }
        val creatorHome = HomeConfiguration("${relay.base}/", request = { account -> relay.start(account); relay.memberRequest(account) }, transport = transport)
        val home = HomeConfiguration("${relay.base}/", transport = transport)
    }

    @Test fun unknownAndReservedRefusalsRetryAfterAndAnUnavailableHome() = runBlocking<Unit> {
        val w = World()
        val device = Device(homes = listOf(w.creatorHome), createWithoutHome = false, history = HistoryAccess.EVERYONE)
        try {
            device.session.create()
            device.session.stopSync()
            assertTrue(device.session.syncNow(), device.describe())
            // Each reserved name, and one no version defines, refuses one request (a record write); the account stays ready.
            for ((code, status) in listOf("refused:overQuota" to 507, "refused:noEntitlement" to 402, "refused:closed" to 410, "refused:somethingNew" to 409)) {
                w.answer = { r -> if (r.method == HttpMethod.PUT && "/records/ops/" in r.url) HttpAnswer(status.toUInt(), listOf(), refusalBody(code)) else null }
                note(device.session, "n-$status")
                device.session.syncNow()
                assertTrue(device.session.homeIssues.any { it.problem == HomeProblem.RemoteCallRefused(code) }, "$code: ${device.describe()}")
                assertFalse("SECRET" in device.session.homeIssues.toString(), "the body is never echoed")
                assertEquals(SessionPhase.Ready, device.session.phase, "$code is not a state of the account")
            }
            // `refused:notProvisioned` (403) ends the pass, as a refused call does, and is still only the home's word.
            w.answer = { r -> if (r.url.endsWith("/head")) null else HttpAnswer(403u, listOf(), refusalBody("refused:notProvisioned")) }
            device.session.syncNow()
            assertTrue(device.session.homeIssues.any { it.problem == HomeProblem.RemoteCallRefused("refused:notProvisioned") }, device.describe())
            assertEquals(SessionPhase.Ready, device.session.phase)
            // `503 {"result":"unavailable"}`: the home is not available, retried with backoff; never the device being stopped.
            w.answer = { HttpAnswer(503u, listOf(), refusalBody("unavailable")) }
            assertFalse(device.session.syncNow(), "a failure, so the loop backs off")
            assertEquals(HomeSyncState.Offline(HomeWords.UNAVAILABLE), device.session.state.value.syncState)
            assertTrue(device.session.homeIssues.any { it.problem == HomeProblem.HomeUnavailable(null) }, device.describe())
            assertFalse(device.session.phase.isStopped)
            assertTrue(device.session.hasUsableContent)
            // `Retry-After` is honoured: not contacted again before then.
            w.answer = { HttpAnswer(429u, listOf(Header("Retry-After", "120")), refusalBody("refused:window")) }
            device.session.syncNow()
            assertTrue(device.session.homeIssues.any { it.problem == HomeProblem.RemoteCallRefused("refused:window", 120) }, device.describe())
            val count = w.sent.get()
            device.session.syncNow(); device.session.syncNow()
            assertEquals(count, w.sent.get(), "not contacted again before the time it asked for")
        } finally { device.close(); w.relay.stop() }
    }

    /**
     * A device that asked to join and holds no grant for itself is waiting for approval, not revoked, when a home answers
     * `refused:revoked` (the 0.5 result for a member no grant names). A member the account does name is shown the home's
     * refusal as received.
     */
    @Test fun aJoiningDeviceIsWaitingForApprovalNotRevoked() = runBlocking<Unit> {
        val w = World()
        val first = Device(homes = listOf(w.creatorHome), createWithoutHome = false, history = HistoryAccess.EVERYONE)
        val joining = Device(medium = first.medium, homes = listOf(w.home), createWithoutHome = false)
        try {
            first.session.create()
            first.session.stopSync()
            joining.session.restore()
            joining.session.stopSync()
            assertEquals(SessionPhase.WaitingForApproval, joining.session.phase, joining.describe())
            w.answer = { r -> if (r.url.endsWith("/head")) null else HttpAnswer(403u, listOf(), refusalBody("refused:revoked")) }
            joining.session.syncNow()
            assertTrue(joining.session.homeIssues.any { it.problem == HomeProblem.WaitingForApproval }, joining.describe())
            assertFalse(joining.session.homeIssues.any { it.problem == HomeProblem.RemoteCallRefused("refused:revoked") })
            assertEquals(SessionPhase.WaitingForApproval, joining.session.phase)
            first.session.syncNow()
            assertTrue(first.session.homeIssues.any { it.problem == HomeProblem.RemoteCallRefused("refused:revoked") }, first.describe())
            assertEquals(SessionPhase.Ready, first.session.phase)
        } finally { joining.close(); first.close(); w.relay.stop() }
    }
}
