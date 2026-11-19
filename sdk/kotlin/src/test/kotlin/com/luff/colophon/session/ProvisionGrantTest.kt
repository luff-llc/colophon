package com.luff.colophon.session

import com.luff.colophon.AccessKind
import com.luff.colophon.AccountException
import com.luff.colophon.Header
import com.luff.colophon.HttpMethod
import com.luff.colophon.HttpRequest
import kotlinx.coroutines.runBlocking
import org.junit.Test
import java.time.Instant
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.test.fail

/** A member key that counts the signatures it is asked for. */
private class CountingKeys(private val inner: AsyncKeyProvider = SoftwareKeys()) : AsyncKeyProvider {
    val signs = AtomicInteger()
    override val form get() = inner.form
    override suspend fun publicKeys() = inner.publicKeys()
    override suspend fun sign(body: ByteArray): ByteArray { signs.incrementAndGet(); return inner.sign(body) }
    override suspend fun sharedSecret(peer: ByteArray) = inner.sharedSecret(peer)
    override suspend fun keyDescriptor() = inner.keyDescriptor()
}

/**
 * Provisioning a home slot by a grant (the reference home's gate "grant", relay/README.md "Provisioning by a grant"),
 * through the Kotlin session against the REAL relay: an operator account on the relay's own slot, a test rig that asks
 * for `services` and is approved with an expiry and a slot condition, and the rig's `provisionRequest` plugged into a
 * fresh account's `HomeConfiguration.request`. Every session and the relay run on one fixed clock the test moves, and
 * the relay has no scheduler timer: heads are published by its test hook ([RelayHome.tick]), never by waiting.
 */
class ProvisionGrantTest {
    private val prefix = "https://door.test/v1/libraries/"
    private val audience = "https://door.test/v1/provision"
    private val purpose = "home.provision"
    private val release = "home.release"
    private val t0 = Instant.parse("2026-11-20T09:00:00Z").toEpochMilli()
    /** "The slot starts with `ci-`, or the call names no slot": conditions bind every call of the member (§12.3 step 7),
     *  its reads of the operator account's history at the home included, whose args name no slot (§10.4). */
    private val slotPrefix = """[{"any":[{"prefix":["args.slot","ci-"]},{"not":{"prefix":["args.slot",""]}}]}]"""
    private val now = AtomicLong(t0)

    /** Exchanges until clean, one relay pass after each exchange (the pass publishes the head covering what was uploaded). */
    private suspend fun settle(device: Device, relay: RelayHome) {
        repeat(6) {
            now.addAndGet(1000)
            val ok = device.session.syncNow()
            relay.tick()
            if (ok && device.session.homeIssues.isEmpty() && device.session.homeFaults.isEmpty()) return
        }
        fail("did not settle: ${device.describe()}")
    }
    /** A device that asked learns its approval through the home, once the relay's pass covered it. */
    private suspend fun untilApproved(device: Device, relay: RelayHome) {
        repeat(6) {
            now.addAndGet(1000)
            device.session.syncNow()
            device.session.refresh()
            if (device.session.phase == SessionPhase.Ready) return
            relay.tick()
        }
        fail("not approved: ${device.describe()}")
    }
    private fun authorityOnly(medium: MemoryMedium) = MemoryMedium(medium.snapshot().filterKeys { it.startsWith("authority/") })
    private fun iso(ms: Long) = Instant.ofEpochMilli(ms).toString()

    @Test fun servicesInRequestTermsAndAGrantThatNarrowsThem() {
        val services = listOf(ServiceTerms(audience, listOf(purpose, "home.read")))
        val asked = SessionWorker.terms(listOf(), setOf(AccessKind.READ), null, null, services)
        assertEquals("""{"services":[{"audience":"$audience","purposes":["home.provision","home.read"]}]}""", asked)
        assertEquals("""{"records":[{"access":"write","namespace":"notes"}]}""", SessionWorker.terms(listOf("notes"), setOf(AccessKind.READ, AccessKind.WRITE), null, null))
        assertEquals(
            """{"conditions":[{"prefix":["args.slot","ci-"]}],"expires":"2026-12-01T00:00:00Z","services":[{"audience":"$audience","purposes":["home.provision"]}]}""",
            SessionWorker.narrowed(asked, ServiceGrant(listOf(ServiceTerms(audience, listOf(purpose))), "2026-12-01T00:00:00Z", """[{"prefix":["args.slot","ci-"]}]""")))
        for (wider in listOf(ServiceGrant(listOf(ServiceTerms("https://other.test/x", listOf(purpose)))), ServiceGrant(listOf(ServiceTerms(audience, listOf(release)))),
                             ServiceGrant(listOf(ServiceTerms(audience, listOf("*")))), ServiceGrant(listOf()))) {
            assertFailsWith<SessionError.InvalidCommand> { SessionWorker.narrowed(asked, wider) }
        }
        // Finite requested bounds: an expiry later than requested is refused; the requested write budget is kept as asked.
        val bounded = """{"expires":"2026-11-01T00:00:00Z","services":[{"audience":"urn:x","purposes":["a"]}],"writes":5}"""
        assertFailsWith<SessionError.InvalidCommand> { SessionWorker.narrowed(bounded, ServiceGrant(expires = "2026-12-01T00:00:00Z")) }
        assertEquals("""{"expires":"2026-10-01T00:00:00Z","services":[{"audience":"urn:x","purposes":["a"]}],"writes":5}""",
            SessionWorker.narrowed(bounded, ServiceGrant(expires = "2026-10-01T00:00:00Z")))
    }

    @Test fun aRigGrantedByTheOperatorProvisionsAFreshAccount() = runBlocking<Unit> {
        val clock = { now.get() }
        val relay = RelayHome("https://door.test/v1/accounts/operator-kotlin", clockSource = clock)
        val devices = ArrayList<Device>()
        try {
            val provision = { account: String ->
                """{"enabled":true,"prefix":"$prefix","gate":["grant"],"operator":{"account":"$account","slot":"home"},"audience":"$audience"}"""
            }
            // The operator account lives on the relay's own slot `home`, which the door names as its operator slot.
            val op = Device(homes = listOf(HomeConfiguration("${relay.base}/", request = { account ->
                relay.start(account, provision = provision(account)); relay.memberRequest(account)
            }, transport = relay.transport())), createWithoutHome = false, now = clock).also { devices.add(it) }
            op.session.create()
            op.session.stopSync()
            assertEquals(SessionPhase.Ready, op.session.phase, op.describe())
            settle(op, relay)

            // The rig joins the operator account asking for two of the door's purposes, and no namespace.
            val keys = CountingKeys()
            val rig = Device(medium = authorityOnly(op.medium), homes = listOf(HomeConfiguration("${relay.base}/", transport = relay.transport())),
                createWithoutHome = false, namespaces = listOf(), services = listOf(ServiceTerms(audience, listOf(purpose, release))), now = clock, keys = keys)
                .also { devices.add(it) }
            rig.session.restore()
            rig.session.stopSync()
            assertEquals(SessionPhase.WaitingForApproval, rig.session.phase, rig.describe())
            val scanned = op.session.scanRequest(rig.session.exportRequest())
            assertEquals(listOf(ServiceTerms(audience, listOf(purpose, release))), scanned.request.services)
            assertTrue(scanned.request.namespaces.isEmpty())
            assertFailsWith<SessionError.InvalidCommand> {
                op.session.approve(scanned.request, scanned.pairing, ServiceGrant(listOf(ServiceTerms("https://other.test/v1/provision", listOf(purpose)))))
            }
            // The grant: provisioning only (release is withheld), until t0 + 240 s, and ci- slots.
            val expires = t0 + 240_000
            val again = op.session.scanRequest(rig.session.exportRequest())
            op.session.approve(again.request, again.pairing, ServiceGrant(listOf(ServiceTerms(audience, listOf(purpose))), iso(expires), slotPrefix))
            val rigId = assertNotNull(rig.session.memberId)
            assertEquals(expires, op.session.state.value.members.firstOrNull { it.id == rigId }?.expiresMs, "the grant carries its expiry")
            settle(op, relay)
            untilApproved(rig, relay)

            // The signer's own check. A purpose never asked for, or another audience: refused before the key is asked.
            val args = """{"account":"${"ab".repeat(32)}","base":"${prefix}ci-kotlin-x","slot":"ci-kotlin-x"}"""
            val signs = keys.signs.get()
            assertEquals("refused:outOfScope", assertFailsWith<AccountException.Refused> { rig.session.signCall(audience, "home.other", args) }.code)
            assertEquals("refused:outOfScope", assertFailsWith<AccountException.Refused> { rig.session.signCall("https://other.test/v1/provision", purpose, args) }.code)
            assertEquals(signs, keys.signs.get(), "the key was not asked")
            // A purpose asked for but withheld by the grant: the key signs, the core's check refuses, and no call is returned.
            assertEquals("refused:outOfScope", assertFailsWith<AccountException.Refused> { rig.session.signCall(audience, release, args) }.code)
            assertEquals(signs + 1, keys.signs.get(), "the key was asked once, and its call was refused")

            // A fresh account whose home request is the rig's provisionRequest: provisioned, written, read on a second device.
            val slot = "ci-kotlin-${java.util.UUID.randomUUID().toString().take(8)}"
            val base = prefix + slot
            val app = Device(homes = listOf(HomeConfiguration("$base/", request = { account ->
                rig.session.provisionRequest(relay.door, audience, slot, base, account, transport = relay.doorTransport())
            }, transport = relay.slotTransport(base, slot))), createWithoutHome = false, now = clock).also { devices.add(it) }
            app.session.create()
            app.session.stopSync()
            assertEquals(SessionPhase.Ready, app.session.phase, app.describe())
            assertEquals(1, app.session.homes.size, "the provisioned home is appointed")
            note(app.session, "a")
            settle(app, relay)
            val second = Device(medium = authorityOnly(app.medium), homes = listOf(HomeConfiguration("$base/", transport = relay.slotTransport(base, slot))),
                createWithoutHome = false, now = clock).also { devices.add(it) }
            second.session.restore()
            second.session.stopSync()
            approveByScan(second.session, app.session)
            settle(app, relay)
            untilApproved(second, relay)
            settle(second, relay)
            assertEquals(1, admitted(second.session), "the second device reads what the first wrote")

            // A slot outside the grant's prefix: the rig's own check refuses it (the condition is false); nothing is sent.
            val outside = assertFailsWith<AccountException.Refused> {
                rig.session.provisionRequest(relay.door, audience, "other-kotlin", prefix + "other-kotlin", "cd".repeat(32), transport = relay.doorTransport())
            }
            assertEquals("refused:outOfScope", outside.code)
            // The door's own refusal is final: a call for one slot carried with another slot's body is 403, nothing made.
            val call = rig.session.signCall(audience, purpose, """{"account":"${"cd".repeat(32)}","base":"${prefix}ci-kotlin-y","slot":"ci-kotlin-y"}""")
            val body = """{"account":"${"cd".repeat(32)}","base":"${prefix}other-kotlin","slot":"other-kotlin"}""".toByteArray()
            val refused = relay.doorTransport().send(HttpRequest(0uL, "", HttpMethod.POST, relay.door, listOf(
                Header("Content-Type", "application/json"), Header("Content-Length", body.size.toString()), Header("Authorization", "Colophon $call")), body))
            assertEquals(403u, refused.status)
            assertEquals("refused:outOfScope", HomeRefusal.of(refused.status.toInt(), refused.headers, refused.body)?.code)

            // The operator revokes the rig: the rig, which has not synced the revocation, signs; the door refuses it.
            op.session.revoke(rigId)
            settle(op, relay)
            try {
                rig.session.provisionRequest(relay.door, audience, "ci-kotlin-z", prefix + "ci-kotlin-z", "ef".repeat(32), transport = relay.doorTransport())
                fail("a revoked rig provisioned")
            } catch (refusal: ProvisionRefusal) {
                assertEquals(403, refusal.status)
                assertEquals("refused:revoked", refusal.code)
            }

            // The clock passes the grant's expiry (the heads the rig holds are still fresh): its own check refuses as expired.
            assertTrue(now.get() < expires, "the journey ran inside the grant")
            now.set(expires + 10_000)
            assertEquals("refused:expired", assertFailsWith<AccountException.Refused> { rig.session.signCall(audience, purpose, args) }.code)
        } finally {
            devices.forEach { it.close() }
            relay.stop()
        }
    }
}
