package com.luff.colophon.session

import com.luff.colophon.PairingStage
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import com.luff.colophon.AccountException
import java.io.File
import org.junit.Test
import kotlin.test.*

/**
 * Approval spends a confirmed pairing for exactly the request's key (spec §7.3, §9.1). There is no code made from a member
 * ID: a request cannot be approved from the list, from its bytes alone, with a pairing the person did not confirm, with a
 * pairing for another device, or twice with one pairing. The same cases as the Swift and JS sessions.
 */
class ApprovalPairingTest {
    private suspend fun world(): Pair<Device, Device> {
        val shared = MemoryMedium()
        val first = Device(medium = shared)
        first.session.create()
        val second = Device(medium = shared)
        second.session.restore()
        return first to second
    }
    private fun requestView(raw: ByteArray): AccessRequest {
        val info = com.luff.colophon.accountRequestInfo(raw)
        return AccessRequest(info.member, info.label, info.kind, info.termsJson, info.raw)
    }
    private suspend fun isMember(device: Device, owner: Device): Boolean {
        owner.session.refresh()
        return owner.session.state.value.members.any { it.id == device.session.memberId }
    }

    @Test fun aListedRequestCarriesNoCodeAndTheJoiningDeviceShowsNone() = runBlocking<Unit> {
        val (first, second) = world()
        try {
            assertEquals(SessionPhase.WaitingForApproval, second.session.phase)
            first.session.refresh()
            assertEquals(second.session.memberId, first.session.requests.single().id)
        } finally { first.close(); second.close() }
    }

    @Test fun aCodeThePersonDidNotConfirmApprovesNothing() = runBlocking<Unit> {
        val (first, second) = world()
        try {
            val raw = second.session.exportRequest()
            val j = second.session.beginJoinPairing()
            val start = first.session.beginApproval(j.commitment())
            val reveal = assertNotNull(j.receiveNonce(start.nonce))
            first.session.approvalCode(start.pairing, reveal.e, reveal.nb)
            // The request travels with the commitment; a scan now would be refused (one ceremony at a time).
            val request = requestView(raw)
            assertFails { first.session.approve(request, start.pairing) }
            assertFalse(isMember(second, first))
        } finally { first.close(); second.close() }
    }

    /** The attack of the prefix code: a relay substitutes another key's request. The refusal spends the pairing. */
    @Test fun aPairingForOneDeviceDoesNotApproveAnother() = runBlocking<Unit> {
        val (first, second) = world()
        val attacker = Device(medium = first.medium)
        try {
            attacker.session.restore()
            val (_, pairing) = pairByCode(second.session, first.session)
            val substituted = first.session.scanRequest(attacker.session.exportRequest()).request
            assertFails { first.session.approve(substituted, pairing) }
            assertFalse(isMember(attacker, first))
            val real = first.session.scanRequest(second.session.exportRequest()).request
            assertFails { first.session.approve(real, pairing) }
        } finally { first.close(); second.close(); attacker.close() }
    }

    @Test fun onePairingApprovesOnce() = runBlocking<Unit> {
        val (first, second) = world()
        try {
            val scanned = first.session.scanRequest(second.session.exportRequest())
            first.session.approve(scanned.request, scanned.pairing)
            assertTrue(isMember(second, first))
            assertEquals(PairingStage.SPENT, scanned.pairing.stage())
            assertFails { first.session.approve(scanned.request, scanned.pairing) }
        } finally { first.close(); second.close() }
    }

    @Test fun theJoiningDevicesOwnPairingDoesNotApprove() = runBlocking<Unit> {
        val (first, second) = world()
        try {
            val j = second.session.beginJoinPairing()
            val start = first.session.beginApproval(j.commitment())
            assertNotNull(j.receiveNonce(start.nonce))
            j.confirm()
            val request = requestView(second.session.exportRequest())
            assertFails { first.session.approve(request, j) }
            assertFalse(isMember(second, first))
        } finally { first.close(); second.close() }
    }

    @Test fun scanningARequestStoresNothing() = runBlocking<Unit> {
        val (first, second) = world()
        try {
            val raw = second.session.exportRequest()
            val before = first.medium.snapshot().keys
            val scanned = first.session.scanRequest(raw)
            assertEquals(second.session.memberId, scanned.request.id)
            assertEquals(before, first.medium.snapshot().keys, "a scan writes nothing")
        } finally { first.close(); second.close() }
    }

    /** A mismatch aborts on both devices, and the approving device allows five failed sessions an hour (§7.3). */
    @Test fun mismatchesAbortAndAreBoundedFivePerHour() = runBlocking<Unit> {
        val (first, second) = world()
        try {
            for (attempt in 0 until 5) {
                val j = second.session.beginJoinPairing()
                val start = first.session.beginApproval(j.commitment())
                val reveal = assertNotNull(j.receiveNonce(start.nonce))
                if (attempt % 2 == 0) {
                    assertFails { first.session.approvalCode(start.pairing, reveal.e, ByteArray(32)) }
                } else {
                    first.session.approvalCode(start.pairing, reveal.e, reveal.nb)
                    first.session.rejectPairing(start.pairing)
                }
                second.session.rejectPairing(j)
                assertEquals(PairingStage.SPENT, j.stage())
                assertEquals(PairingStage.SPENT, start.pairing.stage())
            }
            val j = second.session.beginJoinPairing()
            assertFails { first.session.beginApproval(j.commitment()) }
        } finally { first.close(); second.close() }
    }

    // The approving device's ledger: one ceremony at a time, every start counted (§7.3).

    private suspend fun commitment(joining: ColophonSession) = joining.beginJoinPairing().commitment()

    /** A second commitment while one ceremony is live is refused and yields no nonce. */
    @Test fun aSecondCommitmentWhileOneIsLiveIsRefused() = runBlocking<Unit> {
        val (first, second) = world()
        try {
            val live = first.session.beginApproval(commitment(second.session))
            val e = assertFailsWith<AccountException.Refused> { first.session.beginApproval(commitment(second.session)) }
            assertEquals("pairing:busy", e.code)
            first.session.abandonApproval(live.pairing)
            first.session.beginApproval(commitment(second.session))
        } finally { first.close(); second.close() }
    }

    /** Many starts through one session (its worker serializes them; the core lets one live) get one nonce. */
    @Test fun manyStartsThroughOneSessionYieldOneNonce() = runBlocking<Unit> {
        val (first, second) = world()
        try {
            val commitments = (0 until 40).map { commitment(second.session) }
            // The handles are kept, as a host keeps a ceremony it runs: dropping one ends it (counted).
            val started = commitments.map { c -> async { runCatching { first.session.beginApproval(c) }.getOrNull() } }.awaitAll().filterNotNull()
            val nonces = started.size
            assertEquals(1, nonces, "one live ceremony, one nonce")
        } finally { first.close(); second.close() }
    }

    /** Abandoned ceremonies stay counted: five close the hour. */
    @Test fun abandonedCeremoniesCount() = runBlocking<Unit> {
        val (first, second) = world()
        try {
            repeat(5) { first.session.abandonApproval(first.session.beginApproval(commitment(second.session)).pairing) }
            val e = assertFailsWith<AccountException.Refused> { first.session.beginApproval(commitment(second.session)) }
            assertEquals("pairing:limit", e.code)
        } finally { first.close(); second.close() }
    }

    /** When the ledger cannot be persisted, no nonce is produced. */
    @Test fun withoutAPersistedLedgerThereIsNoNonce() = runBlocking<Unit> {
        val (first, second) = world()
        try {
            File(first.dir, "pairing-ledger.bin/blocked").mkdirs()
            assertFails { first.session.beginApproval(commitment(second.session)) }
        } finally { first.close(); second.close() }
    }

    /** The ledger alone rolled back to an earlier copy (its recorded generation kept), or deleted, does not restore the budget after a relaunch. */
    @Test fun aRolledBackLedgerAloneDoesNotRestoreTheBudget() = runBlocking<Unit> {
        val (first, second) = world()
        val ledger = File(first.dir, "pairing-ledger.bin")
        try {
            first.session.abandonApproval(first.session.beginApproval(commitment(second.session)).pairing)
            val early = ledger.readBytes()
            repeat(4) { first.session.abandonApproval(first.session.beginApproval(commitment(second.session)).pairing) }
            ledger.writeBytes(early)
            val relaunched = Device(medium = first.medium, member = first.member, owner = first.owner, secrets = first.secrets, dir = first.dir)
            relaunched.session.restore()
            assertFails { relaunched.session.beginApproval(commitment(second.session)) }
            relaunched.session.shutdown()
            ledger.delete()
            val again = Device(medium = first.medium, member = first.member, owner = first.owner, secrets = first.secrets, dir = first.dir)
            again.session.restore()
            assertFails { again.session.beginApproval(commitment(second.session)) }
            again.session.shutdown()
        } finally { first.close(); second.close() }
    }

    /** The attack across instances: two sessions over one private directory start ceremonies at the same time, on two threads. The ledger lock and the reload under it let exactly one succeed. */
    @Test fun twoSessionsOverOneStoreYieldExactlyOneNonce() = runBlocking<Unit> {
        val (first, second) = world()
        val other = Device(medium = first.medium, member = first.member, owner = first.owner, secrets = first.secrets, dir = first.dir)
        try {
            other.session.restore()
            val commitments = (0 until 20).map { commitment(second.session) }
            val sessions = listOf(first.session, other.session)
            // The handles are kept, as a host keeps a ceremony it runs: dropping one ends it (counted).
            val started = commitments.mapIndexed { i, c ->
                async(kotlinx.coroutines.Dispatchers.Default) { runCatching { sessions[i % 2].beginApproval(c) }.getOrNull() }
            }.awaitAll().filterNotNull()
            val nonces = started.size
            assertEquals(1, nonces, "one ceremony live across both sessions")
        } finally { other.session.shutdown(); first.close(); second.close() }
    }

    /** The residual limit, as a test: restoring the sealed ledger and its recorded generation together (a wholesale restore of the private directory) restores the budget. Nothing on the device can tell; the docs say so. */
    @Test fun aWholesaleRestoreOfLedgerAndGenerationRestoresTheBudget() = runBlocking<Unit> {
        val (first, second) = world()
        val ledger = File(first.dir, "pairing-ledger.bin")
        val floor = File(first.dir, "pairing-ledger.generation")
        try {
            first.session.abandonApproval(first.session.beginApproval(commitment(second.session)).pairing)
            val early = ledger.readBytes() to floor.readBytes()
            repeat(4) { first.session.abandonApproval(first.session.beginApproval(commitment(second.session)).pairing) }
            ledger.writeBytes(early.first); floor.writeBytes(early.second)
            val relaunched = Device(medium = first.medium, member = first.member, owner = first.owner, secrets = first.secrets, dir = first.dir)
            relaunched.session.restore()
            relaunched.session.beginApproval(commitment(second.session))
            relaunched.session.shutdown()
        } finally { first.close(); second.close() }
    }
}
