package com.luff.colophon.session

import com.luff.colophon.AccessKind
import com.luff.colophon.AccountException
import com.luff.colophon.Header
import com.luff.colophon.HttpMethod
import com.luff.colophon.HttpRequest
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.Test
import java.time.Instant
import java.time.temporal.ChronoUnit
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Provisioning a home slot by a grant (the reference home's gate "grant", relay/README.md "Provisioning by a grant"),
 * through the Kotlin session against the REAL relay: an operator account on the relay's own slot, a test rig that asks
 * for `services` and is approved with an expiry and a slot prefix, and the rig's `provisionRequest` plugged into a fresh
 * account's `HomeConfiguration.request`. The relay's clock is set to now before each request; nothing waits on elapsed
 * time beyond the home's own head tick, which `settle` polls for.
 */
class ProvisionGrantTest {
    private val prefix = "https://door.test/v1/libraries/"
    private val audience = "https://door.test/v1/provision"
    private val purpose = "home.provision"
    /** "The slot starts with `ci-`, or the call names no slot": conditions bind every call of the member (§12.3 step 7),
     *  its reads of the operator account's history at the home included, whose args name no slot (§10.4). */
    private val slotPrefix = """[{"any":[{"prefix":["args.slot","ci-"]},{"not":{"prefix":["args.slot",""]}}]}]"""

    private suspend fun settle(device: Device, tries: Int = 40): Boolean {
        repeat(tries) {
            val ok = device.session.syncNow()
            if (ok && device.session.homeIssues.isEmpty() && device.session.homeFaults.isEmpty()) return true
            delay(150)
        }
        return false
    }
    private suspend fun untilApproved(device: Device, tries: Int = 20): Boolean {
        repeat(tries) {
            device.session.syncNow()
            device.session.refresh()
            if (device.session.phase == SessionPhase.Ready) return true
            delay(100)
        }
        return false
    }
    private fun authorityOnly(medium: MemoryMedium) = MemoryMedium(medium.snapshot().filterKeys { it.startsWith("authority/") })

    @Test fun servicesInRequestTermsAndAGrantThatNarrowsThem() {
        val services = listOf(ServiceTerms(audience, listOf(purpose, "home.read")))
        val asked = SessionWorker.terms(listOf(), setOf(AccessKind.READ), null, null, services)
        assertEquals("""{"services":[{"audience":"$audience","purposes":["home.provision","home.read"]}]}""", asked)
        assertEquals("""{"records":[{"access":"write","namespace":"notes"}]}""", SessionWorker.terms(listOf("notes"), setOf(AccessKind.READ, AccessKind.WRITE), null, null))
        assertEquals(
            """{"conditions":[{"prefix":["args.slot","ci-"]}],"expires":"2026-12-01T00:00:00Z","services":[{"audience":"$audience","purposes":["home.provision"]}]}""",
            SessionWorker.narrowed(asked, ServiceGrant(listOf(ServiceTerms(audience, listOf(purpose))), "2026-12-01T00:00:00Z", """[{"prefix":["args.slot","ci-"]}]""")))
        for (wider in listOf(ServiceGrant(listOf(ServiceTerms("https://other.test/x", listOf(purpose)))), ServiceGrant(listOf(ServiceTerms(audience, listOf("home.release")))),
                             ServiceGrant(listOf(ServiceTerms(audience, listOf("*")))), ServiceGrant(listOf()))) {
            assertFailsWith<SessionError.InvalidCommand> { SessionWorker.narrowed(asked, wider) }
        }
        assertFailsWith<SessionError.InvalidCommand> {
            SessionWorker.narrowed("""{"expires":"2026-11-01T00:00:00Z","services":[{"audience":"urn:x","purposes":["a"]}]}""", ServiceGrant(expires = "2026-12-01T00:00:00Z"))
        }
    }

    @Test fun aRigGrantedByTheOperatorProvisionsAFreshAccount() = runBlocking<Unit> {
        val relay = RelayHome("https://door.test/v1/accounts/operator-kotlin")
        val devices = ArrayList<Device>()
        try {
            val provision = { account: String ->
                """{"enabled":true,"prefix":"$prefix","gate":["grant"],"operator":{"account":"$account","slot":"home"},"audience":"$audience"}"""
            }
            // The operator account lives on the relay's own slot `home`, which the door names as its operator slot.
            val op = Device(homes = listOf(HomeConfiguration("${relay.base}/", request = { account ->
                relay.start(account, provision = provision(account)); relay.memberRequest(account)
            }, transport = relay.transport())), createWithoutHome = false).also { devices.add(it) }
            op.session.create()
            op.session.stopSync()
            assertEquals(SessionPhase.Ready, op.session.phase, op.describe())
            assertTrue(settle(op), op.describe())

            // The rig joins the operator account asking only for the door's service.
            val rig = Device(medium = authorityOnly(op.medium), homes = listOf(HomeConfiguration("${relay.base}/", transport = relay.transport())),
                createWithoutHome = false, namespaces = listOf(), services = listOf(ServiceTerms(audience, listOf(purpose)))).also { devices.add(it) }
            rig.session.restore()
            rig.session.stopSync()
            assertEquals(SessionPhase.WaitingForApproval, rig.session.phase, rig.describe())
            val scanned = op.session.scanRequest(rig.session.exportRequest())
            assertEquals(listOf(ServiceTerms(audience, listOf(purpose))), scanned.request.services)
            assertTrue(scanned.request.namespaces.isEmpty())
            assertFailsWith<SessionError.InvalidCommand> {
                op.session.approve(scanned.request, scanned.pairing, ServiceGrant(listOf(ServiceTerms("https://other.test/v1/provision", listOf(purpose)))))
            }
            val again = op.session.scanRequest(rig.session.exportRequest())
            val expires = Instant.now().plus(1, ChronoUnit.DAYS).truncatedTo(ChronoUnit.SECONDS).toString()
            op.session.approve(again.request, again.pairing, ServiceGrant(expires = expires, conditionsJson = slotPrefix))
            val rigId = assertNotNull(rig.session.memberId)
            assertNotNull(op.session.state.value.members.firstOrNull { it.id == rigId }?.expiresMs, "the grant carries its expiry")
            assertTrue(settle(op), op.describe())
            assertTrue(untilApproved(rig), "the rig learns its approval: ${rig.describe()}")

            // The signer's own check: a purpose or an audience the rig was not granted is refused here; nothing is sent.
            val args = """{"account":"${"ab".repeat(32)}","base":"${prefix}ci-kotlin-x","slot":"ci-kotlin-x"}"""
            assertEquals("refused:outOfScope", assertFailsWith<AccountException.Refused> { rig.session.signCall(audience, "home.release", args) }.code)
            assertEquals("refused:outOfScope", assertFailsWith<AccountException.Refused> { rig.session.signCall("https://other.test/v1/provision", purpose, args) }.code)

            // A fresh account whose home request is the rig's provisionRequest: provisioned, written, read on a second device.
            val slot = "ci-kotlin-${java.util.UUID.randomUUID().toString().take(8)}"
            val base = prefix + slot
            val app = Device(homes = listOf(HomeConfiguration("$base/", request = { account ->
                rig.session.provisionRequest(relay.door, audience, slot, base, account, transport = relay.doorTransport())
            }, transport = relay.slotTransport(base, slot))), createWithoutHome = false).also { devices.add(it) }
            app.session.create()
            app.session.stopSync()
            assertEquals(SessionPhase.Ready, app.session.phase, app.describe())
            assertEquals(1, app.session.homes.size, "the provisioned home is appointed")
            note(app.session, "a")
            assertTrue(settle(app), app.describe())
            val second = Device(medium = authorityOnly(app.medium), homes = listOf(HomeConfiguration("$base/", transport = relay.slotTransport(base, slot))),
                createWithoutHome = false).also { devices.add(it) }
            second.session.restore()
            second.session.stopSync()
            approveByScan(second.session, app.session)
            assertTrue(settle(app), app.describe())
            assertTrue(untilApproved(second), second.describe())
            assertTrue(settle(second), second.describe())
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
            assertTrue(settle(op), op.describe())
            try {
                rig.session.provisionRequest(relay.door, audience, "ci-kotlin-z", prefix + "ci-kotlin-z", "ef".repeat(32), transport = relay.doorTransport())
                fail("a revoked rig provisioned")
            } catch (refusal: ProvisionRefusal) {
                assertEquals(403, refusal.status)
                assertEquals("refused:revoked", refusal.code)
            }
        } finally {
            devices.forEach { it.close() }
            relay.stop()
        }
    }
}
