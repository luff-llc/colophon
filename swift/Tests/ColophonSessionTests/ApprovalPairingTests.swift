import Foundation
import Testing
import ColophonKeys
import ColophonSession

/// Approval spends a confirmed pairing for exactly the request's key (spec §7.3, §9.1). There is no code made from a
/// member ID: a request cannot be approved from the list, from its bytes alone, with a pairing the person did not
/// confirm, with a pairing for another device, or twice with one pairing.
@MainActor struct ApprovalPairingTests {
    private func world() async -> (Device, Device) {
        let first = Device()
        await first.session.create()
        let second = Device(medium: first.medium)
        await second.session.restore()
        return (first, second)
    }
    private func isMember(_ device: Device, of owner: Device) async -> Bool {
        await owner.session.refresh()
        return owner.session.members.contains { $0.id == device.session.memberID }
    }

    @Test func aRequestIsListedWithoutAnyCodeAndTheJoiningDeviceShowsNone() async throws {
        let (first, second) = await world()
        guard case .waitingForApproval = second.session.phase else { Issue.record("expected waiting, got \(second.session.phase)"); return }
        await first.session.refresh()
        let listed = try #require(first.session.requests.first)
        #expect(listed.id == second.session.memberID)
        // A listed request is not approvable by itself: `approve` takes a pairing, and there is no code to compare.
    }

    @Test func aCodeThePersonDidNotConfirmApprovesNothing() async throws {
        let (first, second) = await world()
        let raw = try await second.session.exportRequest()
        let j = try await second.session.beginJoinPairing()
        let start = try await first.session.beginApproval(commitment: try j.commitment())
        let reveal = try #require(try j.receiveNonce(na: start.nonce))
        _ = try await first.session.approvalCode(pairing: start.pairing, e: reveal.e, nb: reveal.nb)
        let request = try await first.session.scanRequest(raw).request
        await #expect(throws: (any Error).self) { try await first.session.approve(request, pairing: start.pairing) }
        #expect(await isMember(second, of: first) == false)
    }

    /// The attack of the prefix code: a relay substitutes another key's request. The person paired the real device;
    /// the substituted request is refused, and the pairing is spent.
    @Test func aPairingForOneDeviceDoesNotApproveAnother() async throws {
        let (first, second) = await world()
        let attacker = Device(medium: first.medium)
        await attacker.session.restore()
        let (_, pairing) = try await pairByCode(joining: second.session, approving: first.session)
        let substituted = AccessRequest(id: try #require(attacker.session.memberID), label: "Test device", kind: .device, termsJSON: "{}",
                                        record: try await attacker.session.exportRequest())
        await #expect(throws: (any Error).self) { try await first.session.approve(substituted, pairing: pairing) }
        #expect(await isMember(attacker, of: first) == false)
        // The pairing was spent by the refused approval: it does not approve the real request either.
        let real = try await first.session.scanRequest(try await second.session.exportRequest()).request
        await #expect(throws: (any Error).self) { try await first.session.approve(real, pairing: pairing) }
    }

    @Test func onePairingApprovesOnce() async throws {
        let (first, second) = await world()
        let scanned = try await first.session.scanRequest(try await second.session.exportRequest())
        try await first.session.approve(scanned.request, pairing: scanned.pairing)
        #expect(await isMember(second, of: first))
        #expect(try scanned.pairing.stage() == .spent)
        await #expect(throws: (any Error).self) { try await first.session.approve(scanned.request, pairing: scanned.pairing) }
    }

    @Test func theJoiningDevicesOwnPairingDoesNotApprove() async throws {
        let (first, second) = await world()
        let j = try await second.session.beginJoinPairing()
        let start = try await first.session.beginApproval(commitment: try j.commitment())
        _ = try #require(try j.receiveNonce(na: start.nonce))
        try j.confirm()
        let request = try await first.session.scanRequest(try await second.session.exportRequest()).request
        await #expect(throws: (any Error).self) { try await first.session.approve(request, pairing: j) }
        #expect(await isMember(second, of: first) == false)
    }

    @Test func scanningARequestStoresNothing() async throws {
        let (first, second) = await world()
        let other = Device()
        await other.session.create()
        let before = first.medium.snapshot()
        let scanned = try await first.session.scanRequest(try await second.session.exportRequest())
        #expect(scanned.request.id == second.session.memberID)
        #expect(first.medium.snapshot() == before, "a scan writes nothing")
        // A request for another account is refused, and nothing is stored either.
        let stranger = Device(medium: other.medium)
        await stranger.session.restore()
        await #expect(throws: (any Error).self) { _ = try await first.session.scanRequest(try await stranger.session.exportRequest()) }
        #expect(first.medium.snapshot() == before)
    }

    /// A mismatch aborts on both devices, and the approving device allows five failed sessions an hour (§7.3).
    @Test func mismatchesAbortAndAreBoundedFivePerHour() async throws {
        let (first, second) = await world()
        for attempt in 0..<5 {
            let j = try await second.session.beginJoinPairing()
            let start = try await first.session.beginApproval(commitment: try j.commitment())
            let reveal = try #require(try j.receiveNonce(na: start.nonce))
            if attempt.isMultiple(of: 2) {
                // A reveal that does not open the commitment: the approving device aborts.
                await #expect(throws: (any Error).self) {
                    _ = try await first.session.approvalCode(pairing: start.pairing, e: reveal.e, nb: Data(repeating: 0, count: 32))
                }
            } else {
                _ = try await first.session.approvalCode(pairing: start.pairing, e: reveal.e, nb: reveal.nb)
                try await first.session.rejectPairing(start.pairing)
            }
            try await second.session.rejectPairing(j)
            #expect(try j.stage() == .spent && start.pairing.stage() == .spent, "both devices end the session")
        }
        let j = try await second.session.beginJoinPairing()
        await #expect(throws: (any Error).self) { _ = try await first.session.beginApproval(commitment: try j.commitment()) }
    }
}
