package com.luff.colophon.session

import com.luff.colophon.AuthorityObjects
import com.luff.colophon.ByteString
import com.luff.colophon.HttpAnswer
import com.luff.colophon.HttpRequest
import com.luff.colophon.accountVerifyHistory
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Joining at an invite's head (0.5.2) against the REAL relay as the home (`relay/server.js` with the Rust home module,
 * history for members only): the joiner holds only the account ID, the home's base, the invite's head and its own keys.
 * It waits before approval, gets the history after, and the session opened from that history reuses the same request
 * and member. Refused: an invite head the home does not hold (another digest at the seq, a seq beyond), another account,
 * a history truncated at the invite's head or before the grant (the tip is not the signed head), a grant made from
 * another request, a signed head behind the history. A revoked member gets the home's same `refused:revoked`: waiting.
 * The same journey runs in Swift (`ColophonJoinTests.swift`).
 */
class ColophonJoinTest {
    private val base = "https://home-join.test/v1/accounts/kotlin"

    /** A home transport that lets a test rewrite what the home answers. */
    private class Tamper(private val inner: HomeTransport) : HomeTransport {
        @Volatile var answer: ((HttpRequest, HttpAnswer) -> HttpAnswer)? = null
        override suspend fun send(request: HttpRequest): HttpAnswer {
            val a = inner.send(request)
            return answer?.invoke(request, a) ?: a
        }
    }

    private fun invite(medium: MemoryMedium): Pair<Long, String> {
        val files = medium.snapshot()
        val entries = files.filterKeys { it.startsWith("authority/") }.toSortedMap().values.map { ByteString(it) }
        val report = accountVerifyHistory(AuthorityObjects(entries, listOf(), listOf(), listOf()), System.currentTimeMillis())
        assertEquals("ok", report.code)
        return report.branch.size.toLong() to report.branch.last()
    }

    /** A history page as the relay writes it, from stored entry envelopes. */
    private fun page(entries: List<ByteArray>): ByteArray =
        Json.write(mapOf("entries" to entries.map { Json.parse(it.toString(Charsets.UTF_8)) }, "receipts" to listOf<Any>(), "more" to false)).toByteArray()
    private fun entriesOf(body: ByteArray): List<ByteArray> =
        (Json.obj(body.toString(Charsets.UTF_8))!!["entries"] as List<*>).map { Json.write(it).toByteArray() }
    /** A head envelope for `(seq, digest)` signed by `keys` as `by` (canonical: keys sorted). */
    private suspend fun forgedHead(account: String, seq: Long, digest: String, by: String, keys: AsyncKeyProvider): ByteArray {
        val issued = com.luff.colophon.accountFormatDate(System.currentTimeMillis() - 1000)
        val body = "{\"account\":\"$account\",\"authority\":{\"digest\":\"$digest\",\"seq\":$seq},\"by\":\"$by\",\"issued\":\"$issued\",\"protocol\":\"colophon/head/5\"}".toByteArray()
        val b64 = java.util.Base64.getEncoder()
        return "{\"body\":\"${b64.encodeToString(body)}\",\"signature\":\"${b64.encodeToString(keys.sign(body))}\"}".toByteArray()
    }
    private fun isAuthority(r: HttpRequest) = r.url.contains("/authority")
    private fun ok(body: ByteArray) = HttpAnswer(200u, listOf(), body)

    private suspend fun until(join: ColophonJoin, tries: Int = 60): JoinHistory.Admitted {
        repeat(tries) {
            when (val h = join.fetchHistory()) { is JoinHistory.Admitted -> return h; JoinHistory.NotAdmitted -> delay(150) }
        }
        fail("the joiner was not admitted")
    }
    private suspend fun rejected(code: String, block: suspend () -> Unit) {
        try { block(); fail("expected $code") } catch (e: JoinError.Rejected) { assertTrue(e.code == code || e.code.startsWith("$code:"), "expected $code, got ${e.message}") }
    }
    private suspend fun refusedByHome(code: String, block: suspend () -> Unit) {
        try { block(); fail("expected the home to refuse with $code") } catch (e: JoinError.Refused) { assertEquals(403, e.status); assertEquals(code, e.code) }
    }
    private suspend fun settle(device: Device) {
        repeat(40) { if (device.session.syncNow() && device.session.homeIssues.isEmpty() && device.session.homeFaults.isEmpty()) return; delay(150) }
        fail("the owner did not settle: ${device.describe()}")
    }

    /** The paging bound, through the pure helper paging calls with its fixed limits: a home that pages forever fails. */
    @Test fun pagingStopsAtTheBound() {
        val page = List(16) { ByteString(ByteArray(100_000)) }
        var bytes = 0L
        var count = 0
        val limit = 4L * 1024 * 1024
        val error = kotlin.runCatching {
            while (true) { bytes = ColophonJoin.bounded(bytes, count, page, limit, 1 shl 18); count += page.size }
        }.exceptionOrNull()
        assertIs<JoinError.Rejected>(error); assertEquals("unavailable", error.code)
        assertTrue(bytes <= limit, "nothing past the bound was kept")
        assertEquals(1_600_000L, ColophonJoin.bounded(0, 0, page, ColophonJoin.MAX_HISTORY_BYTES, ColophonJoin.MAX_ENTRIES))
        assertIs<JoinError.Rejected>(kotlin.runCatching { ColophonJoin.bounded(0, ColophonJoin.MAX_ENTRIES, page.take(1), ColophonJoin.MAX_HISTORY_BYTES, ColophonJoin.MAX_ENTRIES) }.exceptionOrNull())
    }

    /** An accepted history and an owner passkey cannot be made outside the SDK, from Kotlin or Java. */
    @Test fun acceptanceValuesHaveNoPublicConstructor() {
        for (type in listOf(JoinHistory.Admitted::class.java, OwnerPasskey::class.java)) {
            val open = type.declaredConstructors.filter { !it.isSynthetic && !java.lang.reflect.Modifier.isPrivate(it.modifiers) }
            assertTrue(open.isEmpty(), "$type has a constructor Java can call: $open")
            val factories = (type.declaredClasses.flatMap { it.declaredMethods.toList() } + type.declaredMethods)
                .filter { it.returnType == type && !it.isSynthetic && java.lang.reflect.Modifier.isPublic(it.modifiers) }
            assertTrue(factories.isEmpty(), "$type has a factory Java can call: $factories")
        }
    }

    @Test(timeout = 600_000)
    fun joinAtTheInviteHead() = runBlocking<Unit> {
        val relay = RelayHome(base)
        val other = RelayHome("https://home-other.test/v1/accounts/kotlin")
        val devices = ArrayList<Device>()
        try {
            val passkey = TestPasskey()
            val owner = Device(homes = listOf(HomeConfiguration("$base/", request = { a -> relay.start(a); relay.memberRequest(a) }, transport = relay.transport())),
                createWithoutHome = false, history = HistoryAccess.MEMBERS, additional = listOf(AdditionalController(passkey, "Passkey"))).also { devices.add(it) }
            owner.session.create(); owner.session.stopSync()
            note(owner.session, "a")
            settle(owner)
            val account = owner.session.libraryId!!
            val (seq, head) = invite(owner.medium)
            val headAtInvite = relay.transport().send(HttpRequest(0uL, "", com.luff.colophon.HttpMethod.GET, "$base/head", listOf(), ByteArray(0))).body

            val refusals = RelayHome.Refusals()
            val tamper = Tamper(relay.transport(refusals))
            val joiner = Device(homes = listOf(HomeConfiguration("$base/", transport = tamper)), createWithoutHome = false).also { devices.add(it) }
            val join = ColophonJoin(joiner.configuration, account, "$base/", seq, head)

            // Before approval: the home refuses the member's read as from a non-member.
            val request = join.request()
            assertContentEquals(request, join.request(), "the request is made once and reused")
            assertContentEquals(request, joiner.medium.read("requests/${join.memberId()}.json"), "stored where the session looks")
            assertEquals(JoinHistory.NotAdmitted, join.fetchHistory())
            assertEquals(listOf("refused:revoked"), refusals.all, "a key no grant names is refused:revoked")

            // An invite head the home does not hold: the home refuses (before and after approval alike).
            refusedByHome("refused:fork") { ColophonJoin(joiner.configuration, account, base, seq, "ab".repeat(32)).fetchHistory() }
            refusedByHome("unavailable") { ColophonJoin(joiner.configuration, account, base, seq + 10, head).fetchHistory() }
            // Another account at this home: the home holds no history for it.
            val stranger = Device(homes = listOf(HomeConfiguration("$base/", transport = relay.transport())), createWithoutHome = false).also { devices.add(it) }
            refusedByHome("unavailable") { ColophonJoin(stranger.configuration, "cd".repeat(32), base, seq, head).fetchHistory() }

            // The owner scans the request and approves it; the joiner is then admitted through the home.
            val scanned = owner.session.scanRequest(request)
            owner.session.approve(scanned.request, scanned.pairing)
            settle(owner)
            val admitted = until(join)
            assertTrue(admitted.files.keys.all { it.startsWith("authority/") } && admitted.files.size > seq)
            // The owner's passkey, read only from the accepted history (an Admitted value, which only fetchHistory makes).
            assertNull(admitted.ownerDescriptor("00".repeat(16)), "no controller with this ID")
            assertNull(admitted.ownerDescriptor(KeyCustody.keyId(owner.owner)), "a raw controller has no WebAuthn descriptor")
            val ownerPasskey = admitted.ownerDescriptor(KeyCustody.keyId(passkey)) ?: fail("the passkey controller's descriptor")
            val descriptor = ownerPasskey.view
            assertEquals(passkey.rp, descriptor.rp)
            assertContentEquals(passkey.credential, descriptor.credential)
            assertContentEquals(passkey.publicKeys().signing, descriptor.signing)
            val restored = Json.obj(ownerPasskey.registrationDescriptor().toString(Charsets.UTF_8))!!
            assertEquals("webauthn", restored["form"]); assertEquals(passkey.rp, restored["rp"])
            assertEquals(java.util.Base64.getEncoder().encodeToString(passkey.credential), restored["credential"])

            // A home that serves a history truncated at the invite's head, or before the grant: the tip is not its head.
            val full = admitted.files.toSortedMap().values.toList()
            for (cut in listOf(seq.toInt(), full.size - 1)) {
                tamper.answer = { r, a -> if (isAuthority(r) && a.status.toInt() == 200) ok(page(full.take(cut))) else a }
                rejected("refused:rollback") { join.fetchHistory() }
            }
            // A head that moved past what was served once (the home recorded meanwhile): read again, then accepted.
            var once = true
            tamper.answer = { r, a -> if (once && isAuthority(r) && a.status.toInt() == 200) { once = false; ok(page(full.take(full.size - 1))) } else a }
            assertIs<JoinHistory.Admitted>(join.fetchHistory())
            // A head signed by a key the verified history names, but not as a current home (this member's own key).
            val tip = invite(MemoryMedium(admitted.files.toMutableMap()))
            val forged = forgedHead(account, tip.first, tip.second, join.memberId(), joiner.member)
            tamper.answer = { r, a -> if (r.url.endsWith("/head")) ok(forged) else a }
            rejected("badSignature") { join.fetchHistory() }
            // One entry over the authority envelope bound: malformed.
            val huge = Json.write(mapOf("entries" to listOf(mapOf("pad" to "a".repeat(2_200_000))), "more" to false)).toByteArray()
            tamper.answer = { r, a -> if (isAuthority(r) && a.status.toInt() == 200) ok(huge) else a }
            rejected("malformed") { join.fetchHistory() }
            // A page that says more follows but brings nothing.
            tamper.answer = { r, a -> if (isAuthority(r) && a.status.toInt() == 200) ok("{\"entries\":[],\"more\":true}".toByteArray()) else a }
            rejected("malformed") { join.fetchHistory() }
            // A signed head behind the history served (the head from the time of the invite).
            tamper.answer = { r, a -> if (r.url.endsWith("/head")) ok(headAtInvite) else a }
            rejected("unavailable") { join.fetchHistory() }
            // Another account's history and head, served for this one.
            val otherOwner = Device(homes = listOf(HomeConfiguration("https://home-other.test/v1/accounts/kotlin/", request = { a -> other.start(a); other.memberRequest(a) }, transport = other.transport())),
                createWithoutHome = false, history = HistoryAccess.MEMBERS).also { devices.add(it) }
            otherOwner.session.create(); otherOwner.session.stopSync(); settle(otherOwner)
            val otherEntries = otherOwner.medium.snapshot().filterKeys { it.startsWith("authority/") }.toSortedMap().values.toList()
            val otherHead = other.transport().send(HttpRequest(0uL, "", com.luff.colophon.HttpMethod.GET, "https://home-other.test/v1/accounts/kotlin/head", listOf(), ByteArray(0))).body
            tamper.answer = { r, a -> when { isAuthority(r) && a.status.toInt() == 200 -> ok(page(otherEntries)); r.url.endsWith("/head") -> ok(otherHead); else -> a } }
            rejected("refused:fork") { join.fetchHistory() }
            tamper.answer = null
            assertEquals(entriesOf(page(full)).size, full.size)

            // The session opened from the history reuses the request and the member.
            joiner.medium.write(admitted.files.map { MediumWrite(it.key, it.value) })
            joiner.session.restore()
            joiner.session.stopSync()
            assertEquals(join.memberId(), joiner.session.memberId)
            assertContentEquals(request, joiner.session.exportRequest(), "the session reuses the request the owner approved")
            assertTrue(joiner.session.phase == SessionPhase.Ready || joiner.session.phase is SessionPhase.WaitingForApproval, joiner.describe())
            repeat(20) { if (joiner.session.phase != SessionPhase.Ready) { joiner.session.syncNow(); joiner.session.refresh(); delay(100) } }
            assertEquals(SessionPhase.Ready, joiner.session.phase, joiner.describe())

            // A grant made from another request for the same key: refused:conflict.
            val keys = SoftwareKeys()
            val second = Device(member = keys, homes = listOf(HomeConfiguration("$base/", transport = relay.transport())), createWithoutHome = false).also { devices.add(it) }
            val decoy = Device(member = keys, services = listOf(ServiceTerms("https://service.test", listOf("decoy.read"))), homes = listOf(HomeConfiguration("$base/", transport = relay.transport())), createWithoutHome = false).also { devices.add(it) }
            val (seq2, head2) = invite(owner.medium)
            val mine = ColophonJoin(second.configuration, account, base, seq2, head2)
            val theirs = ColophonJoin(decoy.configuration, account, base, seq2, head2)
            assertEquals(mine.memberId(), theirs.memberId())
            mine.request()
            val decoyScan = owner.session.scanRequest(theirs.request())
            owner.session.approve(decoyScan.request, decoyScan.pairing)
            settle(owner)
            assertTrue(until(theirs).files.isNotEmpty())
            rejected("refused:conflict") { mine.fetchHistory() }
            // This member's key reading with another current member's request on its medium: refused:conflict.
            val swapped = Device(member = joiner.member, medium = MemoryMedium(mapOf(OwnRequest.path(join.memberId()) to theirs.request())),
                homes = listOf(HomeConfiguration("$base/", transport = relay.transport())), createWithoutHome = false).also { devices.add(it) }
            rejected("refused:conflict") { ColophonJoin(swapped.configuration, account, base, seq2, head2).fetchHistory() }

            // A revoked member: the home's answer is the same refused:revoked as before approval: not admitted (no longer).
            owner.session.revoke(join.memberId())
            settle(owner)
            var waiting = false
            repeat(40) { if (!waiting) { waiting = join.fetchHistory() == JoinHistory.NotAdmitted; if (!waiting) delay(150) } }
            assertTrue(waiting, "a revoked member is not admitted")
            assertEquals("refused:revoked", refusals.all.last())
            println("join: waiting code ${ColophonJoin.WAITING_CODE}; revoked gives ${refusals.all.last()}")
        } finally {
            devices.forEach { it.close() }
            relay.stop(); other.stop()
        }
    }
}
