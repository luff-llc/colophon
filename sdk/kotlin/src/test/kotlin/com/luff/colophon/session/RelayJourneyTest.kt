package com.luff.colophon.session

import com.luff.colophon.ExchangeFaultKind
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Two devices of one person, each running a Kotlin `ColophonSession`, syncing through the REAL relay as their home
 * (`relay/server.js` on Bun with the Rust home module, started by [RelayHome]), which requires a signed call for
 * everything spec §13.4 and §14 say needs one. No simulated home. The same journey runs through the Rust exports in
 * `crates/colophon-ffi/tests/v05_relay_journey.rs` and through the Swift session in `RelayJourneyTests.swift`.
 *
 * The journey: an owner creates an account with the home (the relay is started for the new account ID when the
 * session asks the home for its request); a second device holding a copy of the history from before its approval
 * asks, is approved, learns its approval through the home and syncs; both write and read, with a required and an
 * optional blob; a third device is approved then revoked, reads nothing new and is refused with exactly
 * `refused:revoked`; a pending change proposed on the first device is shown on the second (which holds a control key)
 * and vetoed there. Under `members` and `public`, and with two homes at `headQuorum` 2.
 */
class RelayJourneyTest {
    private fun base(n: Int) = "https://home-$n.test/v1/accounts/kotlin"

    private fun homes(count: Int): Pair<List<RelayHome>, List<HomeConfiguration>> {
        val relays = (0 until count).map { RelayHome(base(it)) }
        val configs = relays.map { relay ->
            HomeConfiguration("${relay.base}/", label = "Relay ${relay.base.take(14)}", request = { account ->
                relay.start(account, relays.filter { it !== relay })
                relay.memberRequest(account)
            }, transport = relay.transport())
        }
        return relays to configs
    }
    private fun joining(relays: List<RelayHome>, refusals: RelayHome.Refusals? = null) =
        relays.map { HomeConfiguration("${it.base}/", transport = it.transport(refusals)) }

    /** Sync until the session says nothing is wrong (a home records entries and forwards heads on its own schedule). */
    private suspend fun settle(device: Device, tries: Int = 40): Boolean {
        repeat(tries) {
            val ok = device.session.syncNow()
            if (ok && device.session.homeIssues.isEmpty() && device.session.homeFaults.isEmpty()) return true
            delay(150)
        }
        return false
    }

    /**
     * A device that asked learns its approval through the home. The home signs a new head on its own tick (50 ms
     * here), so a pass that runs before it may find the approval not yet covered: then the device's own check of the
     * call it would need says `refused:revoked` (it is not a member at what it holds) and nothing is sent. Any other
     * issue or fault fails. Returns the number of passes it took.
     */
    private suspend fun untilApproved(device: Device, tries: Int = 20): Int {
        for (n in 1..tries) {
            device.session.syncNow()
            device.session.refresh()
            if (device.session.phase == SessionPhase.Ready) return n
            assertTrue(device.session.homeFaults.isEmpty() && device.session.homeIssues.all { it.problem == HomeProblem.CallRefused("refused:revoked") },
                "only the device's own check may hold it back: ${device.describe()}")
            delay(100)
        }
        fail("the device did not learn its approval through the home: ${device.describe()}")
    }

    private fun journey(history: HistoryAccess, homeCount: Int) = runBlocking<Unit> {
        val (relays, configs) = homes(homeCount)
        val devices = ArrayList<Device>()
        try {
            val phoneOwner = SoftwareKeys()
            val first = Device(homes = configs, createWithoutHome = false, additional = listOf(AdditionalController(phoneOwner, "Phone owner key")),
                history = history, headQuorum = homeCount).also { devices.add(it) }
            first.session.create()
            first.session.stopSync()
            assertEquals(SessionPhase.Ready, first.session.phase, first.describe())
            assertEquals(homeCount, first.session.homes.size, "the homes are appointed at creation")
            note(first.session, "a")
            val required = ByteArray(90_000) { (it * 7).toByte() }
            val optional = ByteArray(20_000) { (it * 13).toByte() }
            val a = first.session.putBlob(required, "notes", "text/plain", "a", required = true)
            val b = first.session.putBlob(optional, "notes", "text/plain", "b", required = false)
            assertTrue(settle(first), "the first upload and the records reach the home: ${first.describe()}")

            // The second device: a copy of the history from before its approval; it asks and is approved.
            val second = Device(medium = MemoryMedium(first.medium.snapshot().filterKeys { it.startsWith("authority/") }), owner = phoneOwner,
                homes = joining(relays), createWithoutHome = false).also { devices.add(it) }
            second.session.restore()
            second.session.stopSync()
            assertTrue(second.session.phase is SessionPhase.WaitingForApproval, "expected waiting, got ${second.describe()}")
            first.session.importRequest(second.session.exportRequest())
            first.session.approve(first.session.requests.first())
            assertTrue(settle(first), first.describe())
            val secondPasses = untilApproved(second)
            assertEquals(SessionPhase.Ready, second.session.phase, "the phone learnt its approval through the home: ${second.describe()}")
            assertTrue(settle(second), second.describe())
            assertEquals(3, admitted(second.session), "the second device reads the note and the two blob publications")
            assertEquals(BlobAvailabilityState.Available, second.session.blobAvailability("notes", a.digest), "a required blob comes with the sync")
            assertContentEquals(required, second.session.blobData("notes", a.digest))
            assertTrue(second.session.blobAvailability("notes", b.digest) is BlobAvailabilityState.Missing, "an optional blob is not downloaded before it is asked for")
            second.session.prefetchBlob("notes", b.digest)
            assertEquals(BlobAvailabilityState.Available, second.session.blobAvailability("notes", b.digest), "fetched when asked")
            assertContentEquals(optional, second.session.blobData("notes", b.digest))
            note(second.session, "b")
            assertTrue(settle(second), second.describe())
            assertTrue(settle(first), first.describe())
            assertEquals(4, admitted(first.session), "the first device reads what the second wrote")

            // A third device is approved, then revoked: it reads nothing new and the home refuses it.
            val thirdRefusals = RelayHome.Refusals()
            val third = Device(medium = MemoryMedium(first.medium.snapshot().filterKeys { it.startsWith("authority/") }),
                homes = joining(relays, thirdRefusals), createWithoutHome = false).also { devices.add(it) }
            third.session.restore()
            third.session.stopSync()
            first.session.importRequest(third.session.exportRequest())
            first.session.approve(first.session.requests.first())
            assertTrue(settle(first), first.describe())
            val thirdPasses = untilApproved(third)
            assertEquals(SessionPhase.Ready, third.session.phase, third.describe())
            assertTrue(settle(third), third.describe())
            assertEquals(4, admitted(third.session))
            first.session.revoke(third.session.memberId ?: fail("the third device has a member ID"))
            note(first.session, "c")
            assertTrue(settle(first), first.describe())
            thirdRefusals.clear()
            third.session.syncNow()
            // Under `members` the home refuses its call with `refused:revoked` (the home holds the revocation, the
            // device cannot fetch it); under `public` it may fetch the revocation without a call, and then its own
            // check refuses with the same code and sends nothing. Any other refusal fails the test.
            val byHome = third.session.homeFaults.any { it.fault.kind == ExchangeFaultKind.UNAUTHORIZED }
            val byItself = third.session.homeIssues.any { it.problem == HomeProblem.CallRefused("refused:revoked") }
            assertTrue(byHome || byItself, "the revoked device is refused: ${third.describe()} home said ${thirdRefusals.all}")
            if (byHome) {
                assertTrue(thirdRefusals.all.isNotEmpty() && thirdRefusals.all.all { it == "refused:revoked" }, "the home refuses it as revoked: ${thirdRefusals.all}")
            }
            if (history == HistoryAccess.MEMBERS) assertTrue(byHome, "the home refuses the revoked device: ${third.describe()}")
            assertTrue(third.session.homeIssues.all { (it.problem as? HomeProblem.CallRefused)?.code?.let { c -> c == "refused:revoked" } ?: true }, third.describe())
            println("journey ${history.wire}/$homeCount: approvals learnt in $secondPasses and $thirdPasses passes; revoked device refused by home=$byHome by itself=$byItself, home results ${thirdRefusals.all}")
            third.session.refresh()
            // A device that holds its own revocation is `Denied` and serves no read; one the home refused before it
            // could fetch the revocation still reads only what it had.
            if (byItself) assertEquals(SessionPhase.Denied, third.session.phase, third.describe())
            if (third.session.phase == SessionPhase.Denied) {
                try { admitted(third.session); fail("a denied session served a read") } catch (_: SessionError.NotReady) {}
            } else {
                assertTrue(admitted(third.session) <= 4, "the revoked device reads nothing new: ${third.describe()}")
            }

            // A pending change proposed on the first device is shown on the second and vetoed there: a policy change
            // (a longer recovery delay), a transition with a veto window, signed by the first device's owner.
            val digest = first.session.proposeTransition("{\"policy\":{\"recoveryDelay\":7200}}")
            assertTrue(settle(first), first.describe())
            assertTrue(settle(second), second.describe())
            val shown = second.session.notices.pending.firstOrNull { it.digest == digest } ?: fail("the second device shows the pending change: ${second.describe()}")
            assertTrue(shown.vetoable, "the phone's owner key may veto it")
            second.session.veto(digest)
            assertTrue(settle(second), second.describe())
            var gone = false
            for (n in 0 until 60) {
                first.session.syncNow()
                gone = first.session.notices.pending.none { it.digest == digest }
                if (gone) break
                delay(150)
            }
            assertTrue(gone, "the home recorded the veto and the first device no longer shows the change: ${first.describe()}")
        } finally {
            devices.forEach { it.close() }
            relays.forEach { it.stop() }
        }
    }

    @Test(timeout = 600_000) fun twoDevicesAndARealHomeWithTheHistoryForMembers() = journey(HistoryAccess.MEMBERS, 1)
    @Test(timeout = 600_000) fun twoDevicesAndARealHomeWithAPublicHistory() = journey(HistoryAccess.EVERYONE, 1)
    @Test(timeout = 600_000) fun twoDevicesAndTwoRealHomesAtQuorumTwo() = journey(HistoryAccess.MEMBERS, 2)
}
