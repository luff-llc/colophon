package com.luff.colophon.session

import com.luff.colophon.ControllerRole
import com.luff.colophon.HttpRequest
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * A history read with a passkey before admission, and recovery and self-approval built on it (0.5.7), against the REAL
 * relay as the home (`relay/server.js` with the Rust home module, history for members only). A device that holds only
 * the account ID, the home's base and the person's passkey reads and verifies the history, then enrols itself with the
 * passkey and opens a session the owner's other device sees through the home. Refused: a passkey that is no controller
 * (the home's `refused:revoked`), a passkey of another relying party, an assertion from an origin that is no authority
 * origin of the descriptor (the home's `refused:origin`), a `recover`-only passkey asked to approve. The same journeys
 * run in Swift (`PasskeyRecoveryTests.swift`).
 */
class PasskeyRecoveryTest {
    private val base = "https://home-passkey.test/v1/accounts/kotlin"

    private suspend fun settle(device: Device) {
        repeat(40) { if (device.session.syncNow() && device.session.homeIssues.isEmpty() && device.session.homeFaults.isEmpty()) return; delay(150) }
        fail("the device did not settle: ${device.describe()}")
    }
    private suspend fun refusedByHome(code: String, block: suspend () -> Unit) {
        try { block(); fail("expected the home to refuse with $code") } catch (e: JoinError.Refused) { assertEquals(403, e.status); assertEquals(code, e.code) }
    }
    private suspend fun rejected(code: String, block: suspend () -> Unit) {
        try { block(); fail("expected $code") } catch (e: JoinError.Rejected) { assertEquals(code, e.code, e.message) }
    }
    private fun owner(relay: RelayHome, passkey: TestPasskey, roles: List<ControllerRole>) =
        Device(homes = listOf(HomeConfiguration("$base/", request = { a -> relay.start(a); relay.memberRequest(a) }, transport = relay.transport())),
            createWithoutHome = false, history = HistoryAccess.MEMBERS, additional = listOf(AdditionalController(passkey, "Passkey", roles)))

    @Test(timeout = 600_000)
    fun recoverFromTheHomeWithAPasskey() = runBlocking<Unit> {
        val relay = RelayHome(base)
        val devices = ArrayList<Device>()
        try {
            val passkey = TestPasskey()
            val owner = owner(relay, passkey, listOf(ControllerRole.APPROVE, ControllerRole.CONTROL)).also { devices.add(it) }
            owner.session.create(); owner.session.stopSync()
            note(owner.session, "before")
            settle(owner)
            val account = owner.session.libraryId!!
            val passkeyId = KeyCustody.keyId(passkey)

            // A new device: the account ID, the home's base and the passkey. Nothing else.
            val fresh = Device(homes = listOf(HomeConfiguration("$base/", transport = relay.transport())), createWithoutHome = false).also { devices.add(it) }
            val recovery = ColophonJoin.recovery(fresh.configuration, account, "$base/")

            // Without the key ID: one get to identify the passkey, then one per page (and one more when the first
            // candidate point was the other one).
            var before = passkey.assertCount
            val read = recovery.readHistoryWithPasskey(passkey.authenticator())
            assertTrue(passkey.assertCount - before in 2..3, "gets: ${passkey.assertCount - before}")
            assertEquals(passkeyId, read.signerController.id)
            assertTrue(read.signerController.ownSlot)
            assertContentEquals(passkey.publicKeys().signing, read.signer.view.signing)
            assertEquals(listOf(passkeyId), read.controllers.map { it.id }, "the one current passkey controller")
            assertTrue(read.files.isNotEmpty() && read.files.keys.all { it.startsWith("authority/") })
            assertEquals(owner.medium.snapshot().filterKeys { it.startsWith("authority/") }.keys, read.files.keys)
            // With the key ID (an invite names it): exactly two gets.
            before = passkey.assertCount
            recovery.readHistoryWithPasskey(passkey.authenticator(), passkeyId)
            assertEquals(2, passkey.assertCount - before)
            assertTrue(fresh.medium.snapshot().keys.none { it.startsWith("authority/") }, "a read stores nothing")

            // Refused: a passkey that is no controller of this account, by the home, with the answer a key no grant names gets.
            refusedByHome("refused:revoked") { recovery.readHistoryWithPasskey(TestPasskey().authenticator()) }
            // An assertion for another relying party than the one asked for: no point is recovered from it.
            rejected("badSignature") { recovery.readHistoryWithPasskey(TestPasskey(rp = "other.example").authenticator(claimedRp = passkey.rp)) }
            // An origin the descriptor does not allow for authority signatures (a subdomain of the rp): the home refuses.
            refusedByHome("refused:origin") { recovery.readHistoryWithPasskey(passkey.authenticator(origin = "https://keys.${passkey.rp}"), passkeyId) }
            // The invite's key ID of another passkey.
            rejected("badSignature") { recovery.readHistoryWithPasskey(passkey.authenticator(), "00".repeat(16)) }

            // Recover: the history stored, this device's member approved by the passkey, the session opened.
            var restoredOwner: OwnerPasskey? = null
            val session = ColophonJoin.recoverWithPasskey(fresh.configuration, account, "$base/", passkey.authenticator()) { ownerPasskey ->
                restoredOwner = ownerPasskey
                Device(member = fresh.member, medium = fresh.medium, ownerKey = passkey,
                    homes = listOf(HomeConfiguration("$base/", transport = relay.transport())), createWithoutHome = false).also { devices.add(it) }.session
            }
            session.stopSync()
            assertContentEquals(passkey.publicKeys().signing, restoredOwner?.view?.signing)
            repeat(20) { if (session.phase != SessionPhase.Ready) { session.syncNow(); session.refresh(); delay(100) } }
            assertEquals(SessionPhase.Ready, session.phase)
            assertEquals(KeyCustody.keyId(fresh.member), session.memberId)
            assertEquals(1, admitted(session), "the recovered device reads what was written before")
            note(session, "after")
            assertTrue(session.syncNow())

            // The owner's device learns the new member and its write through the home.
            var seen = false
            repeat(40) { if (!seen) { owner.session.syncNow(); owner.session.refresh(); seen = admitted(owner.session) == 2; if (!seen) delay(150) } }
            assertTrue(seen, "the owner reads the recovered device's write: ${owner.describe()}")
            // The member is now admitted: its own key reads the history as any member does.
            val admittedHistory = ColophonJoin.recovery(fresh.configuration, account, "$base/").fetchHistory()
            assertTrue(admittedHistory is JoinHistory.Admitted, "the recovered member is admitted")
        } finally {
            devices.forEach { it.close() }
            relay.stop()
        }
    }

    @Test(timeout = 600_000)
    fun approveOwnJoinWithAPasskey() = runBlocking<Unit> {
        val relay = RelayHome(base)
        val devices = ArrayList<Device>()
        try {
            val passkey = TestPasskey()
            val owner = owner(relay, passkey, listOf(ControllerRole.APPROVE, ControllerRole.CONTROL)).also { devices.add(it) }
            owner.session.create(); owner.session.stopSync()
            settle(owner)
            val account = owner.session.libraryId!!
            val files = owner.medium.snapshot().filterKeys { it.startsWith("authority/") }.toSortedMap()
            val seq = files.size.toLong()
            val head = com.luff.colophon.accountVerifyHistory(com.luff.colophon.AuthorityObjects(files.values.map { com.luff.colophon.ByteString(it) }, listOf(), listOf(), listOf()), System.currentTimeMillis()).branch.last()

            // A short invite's join: the joiner waits, then approves itself with the owner's passkey (named by key ID).
            val joiner = Device(homes = listOf(HomeConfiguration("$base/", transport = relay.transport())), createWithoutHome = false).also { devices.add(it) }
            val join = ColophonJoin(joiner.configuration, account, "$base/", seq, head)
            join.request()
            assertEquals(JoinHistory.NotAdmitted, join.fetchHistory())
            // The wrong session: one whose owner is not the passkey that read the history.
            rejected("refused:conflict") {
                join.approveOwnJoinWithPasskey(passkey.authenticator(), KeyCustody.keyId(passkey)) { _ ->
                    Device(member = joiner.member, medium = joiner.medium, homes = listOf(HomeConfiguration("$base/", transport = relay.transport())),
                        createWithoutHome = false).also { devices.add(it) }.session
                }
            }
            val session = join.approveOwnJoinWithPasskey(passkey.authenticator(), KeyCustody.keyId(passkey)) { _ ->
                Device(member = joiner.member, medium = joiner.medium, ownerKey = passkey,
                    homes = listOf(HomeConfiguration("$base/", transport = relay.transport())), createWithoutHome = false).also { devices.add(it) }.session
            }
            session.stopSync()
            repeat(20) { if (session.phase != SessionPhase.Ready) { session.syncNow(); session.refresh(); delay(100) } }
            assertEquals(SessionPhase.Ready, session.phase)
            assertTrue(join.fetchHistory() is JoinHistory.Admitted, "the home holds the grant")
        } finally {
            devices.forEach { it.close() }
            relay.stop()
        }
    }

    @Test(timeout = 600_000)
    fun aRecoverOnlyPasskeyReadsButDoesNotApprove() = runBlocking<Unit> {
        val relay = RelayHome(base)
        val devices = ArrayList<Device>()
        try {
            val passkey = TestPasskey()
            val owner = owner(relay, passkey, listOf(ControllerRole.RECOVER)).also { devices.add(it) }
            owner.session.create(); owner.session.stopSync()
            settle(owner)
            val account = owner.session.libraryId!!
            val fresh = Device(homes = listOf(HomeConfiguration("$base/", transport = relay.transport())), createWithoutHome = false).also { devices.add(it) }
            val recovery = ColophonJoin.recovery(fresh.configuration, account, "$base/")
            // §13.4: a recover controller reads the history.
            val read = recovery.readHistoryWithPasskey(passkey.authenticator(), KeyCustody.keyId(passkey))
            assertEquals(listOf(ControllerRole.RECOVER), read.signerController.roles)
            // It cannot grant at once: refused before anything is stored or signed.
            val gets = passkey.assertCount
            rejected("refused:outOfScope") {
                recovery.approveOwnJoinWithPasskey(passkey.authenticator(), KeyCustody.keyId(passkey)) { fail("no session is opened") }
            }
            assertEquals(2, passkey.assertCount - gets, "only the read's gets")
            assertTrue(fresh.medium.snapshot().keys.none { it.startsWith("authority/") }, "nothing stored")
        } finally {
            devices.forEach { it.close() }
            relay.stop()
        }
    }
}
