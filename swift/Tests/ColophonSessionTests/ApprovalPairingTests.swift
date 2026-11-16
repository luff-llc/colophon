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
    private func requestView(_ raw: Data) throws -> AccessRequest {
        let info = try accountRequestInfo(raw: raw)
        return AccessRequest(id: info.member, label: info.label, kind: info.kind, termsJSON: info.termsJson, record: info.raw)
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
        // The request travels with the commitment; a scan now would be refused (one ceremony at a time).
        let request = try requestView(raw)
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
        let request = try requestView(try await second.session.exportRequest())
        await #expect(throws: (any Error).self) { try await first.session.approve(request, pairing: j) }
        #expect(await isMember(second, of: first) == false)
    }

    @Test func scanningARequestStoresNothing() async throws {
        let (first, second) = await world()
        let other = Device()
        await other.session.create()
        let raw = try await second.session.exportRequest()
        let before = first.medium.snapshot()
        let scanned = try await first.session.scanRequest(raw)
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

    // MARK: The approving device's ledger: one ceremony at a time, every start counted (§7.3)

    private func commitment(_ joining: ColophonSession) async throws -> Data { try await joining.beginJoinPairing().commitment() }

    /// A second commitment while one ceremony is live is refused and yields no nonce.
    @Test func aSecondCommitmentWhileOneIsLiveIsRefused() async throws {
        let (first, second) = await world()
        let live = try await first.session.beginApproval(commitment: try await commitment(second.session))
        do {
            _ = try await first.session.beginApproval(commitment: try await commitment(second.session))
            Issue.record("a second ceremony started while one is live")
        } catch AccountError.Refused(let code, _, _) { #expect(code == "pairing:busy") }
        try await first.session.abandonApproval(live.pairing)
        _ = try await first.session.beginApproval(commitment: try await commitment(second.session))
    }

    /// Many starts through one session (its worker serializes them; the core lets one live) get one nonce.
    @Test func manyStartsThroughOneSessionYieldOneNonce() async throws {
        let (first, second) = await world()
        var commitments: [Data] = []
        for _ in 0..<40 { commitments.append(try await commitment(second.session)) }
        let session = first.session
        // All started at once; the worker serializes them, the core lets one live.
        // The handles are kept, as a host keeps a ceremony it runs: dropping one ends it (counted).
        let tasks = commitments.map { c in Task { @MainActor in try? await session.beginApproval(commitment: c) } }
        var started: [ApprovalStart] = []
        for task in tasks {
            if let s = await task.value { started.append(s) }
        }
        let nonces = started.count
        #expect(nonces == 1, "one live ceremony, one nonce")
    }

    /// Abandoned ceremonies stay counted: five close the hour.
    @Test func abandonedCeremoniesCount() async throws {
        let (first, second) = await world()
        for _ in 0..<5 {
            let start = try await first.session.beginApproval(commitment: try await commitment(second.session))
            try await first.session.abandonApproval(start.pairing)
        }
        do {
            _ = try await first.session.beginApproval(commitment: try await commitment(second.session))
            Issue.record("a sixth ceremony started")
        } catch AccountError.Refused(let code, _, _) { #expect(code == "pairing:limit") }
    }

    /// When the ledger cannot be persisted, no nonce is produced.
    @Test func withoutAPersistedLedgerThereIsNoNonce() async throws {
        let (first, second) = await world()
        // A directory where the ledger file goes: every write of it fails.
        try FileManager.default.createDirectory(at: first.home.appendingPathComponent("pairing-ledger.bin/blocked"), withIntermediateDirectories: true)
        await #expect(throws: (any Error).self) { _ = try await first.session.beginApproval(commitment: try await commitment(second.session)) }
    }

    /// The ledger alone rolled back to an earlier copy (its recorded generation kept), or deleted, does not restore the
    /// budget after a relaunch.
    @Test func aRolledBackLedgerAloneDoesNotRestoreTheBudget() async throws {
        let (first, second) = await world()
        let ledger = first.home.appendingPathComponent("pairing-ledger.bin")
        let start = try await first.session.beginApproval(commitment: try await commitment(second.session))
        try await first.session.abandonApproval(start.pairing)
        let early = try Data(contentsOf: ledger)
        for _ in 0..<4 {
            let s = try await first.session.beginApproval(commitment: try await commitment(second.session))
            try await first.session.abandonApproval(s.pairing)
        }
        try early.write(to: ledger)
        let relaunched = first.relaunch()
        await relaunched.restore()
        await #expect(throws: (any Error).self) { _ = try await relaunched.beginApproval(commitment: try await commitment(second.session)) }
        try FileManager.default.removeItem(at: ledger)
        let again = first.relaunch()
        await again.restore()
        await #expect(throws: (any Error).self) { _ = try await again.beginApproval(commitment: try await commitment(second.session)) }
    }

    /// The attack across instances: two sessions over one private container (two processes, an app and its extension)
    /// start ceremonies at the same time. The ledger lock and the reload under it let exactly one succeed.
    @Test func twoSessionsOverOneStoreYieldExactlyOneNonce() async throws {
        let (first, second) = await world()
        let other = first.relaunch()
        await other.restore()
        var commitments: [Data] = []
        for _ in 0..<20 { commitments.append(try await commitment(second.session)) }
        let sessions = [first.session, other]
        let tasks = commitments.enumerated().map { i, c in
            Task { @MainActor in try? await sessions[i % 2].beginApproval(commitment: c) }
        }
        // The handles are kept, as a host keeps a ceremony it runs: dropping one ends it (counted).
        var started: [ApprovalStart] = []
        for task in tasks {
            if let s = await task.value { started.append(s) }
        }
        let nonces = started.count
        #expect(nonces == 1, "one ceremony live across both sessions")
    }

    /// The residual limit, as a test: restoring the sealed ledger and its recorded generation together (a wholesale
    /// restore of the private container) restores the budget. Nothing on the device can tell; the docs say so.
    @Test func aWholesaleRestoreOfLedgerAndGenerationRestoresTheBudget() async throws {
        let (first, second) = await world()
        let ledger = first.home.appendingPathComponent("pairing-ledger.bin")
        let floor = first.home.appendingPathComponent("pairing-ledger.generation")
        let start = try await first.session.beginApproval(commitment: try await commitment(second.session))
        try await first.session.abandonApproval(start.pairing)
        let (early, earlyFloor) = (try Data(contentsOf: ledger), try Data(contentsOf: floor))
        for _ in 0..<4 {
            let s = try await first.session.beginApproval(commitment: try await commitment(second.session))
            try await first.session.abandonApproval(s.pairing)
        }
        try early.write(to: ledger); try earlyFloor.write(to: floor)
        let relaunched = first.relaunch()
        await relaunched.restore()
        _ = try await relaunched.beginApproval(commitment: try await commitment(second.session))
    }
}
