package com.luff.colophon.session

import com.luff.colophon.PairingStage
import kotlinx.coroutines.runBlocking
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
            val request = first.session.scanRequest(raw).request
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
            val request = first.session.scanRequest(second.session.exportRequest()).request
            assertFails { first.session.approve(request, j) }
            assertFalse(isMember(second, first))
        } finally { first.close(); second.close() }
    }

    @Test fun scanningARequestStoresNothing() = runBlocking<Unit> {
        val (first, second) = world()
        try {
            val before = first.medium.snapshot().keys
            val scanned = first.session.scanRequest(second.session.exportRequest())
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
}
