import ColophonSession
import ColophonSessionUI
import Foundation
import Testing

@MainActor struct SessionUIIntegrationTests {
    @Test func realMemorySessionsPairNarrowRevokeLeaveAndRejoin() async throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("SessionUI-" + UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: home) }
        let storage = MemoryRecordStore()
        let ownerKeys = SoftwareKeys()
        let owner = ColophonSession(configuration: .init(memberLabel: "Owner", namespaces: ["notes"],
            location: .memory(storage), privateContainer: home.appendingPathComponent("owner"),
            keys: ownerKeys, recoveryKeys: SoftwareKeys()))
        await owner.restore()
        #expect(owner.phase == .noLibrary)
        await owner.create()
        #expect(owner.phase == .ready)
        let guest = ColophonSession(configuration: .init(memberLabel: "Guest", memberKind: .agent, namespaces: ["notes"],
            location: .memory(storage), privateContainer: home.appendingPathComponent("guest"), keys: SoftwareKeys()))
        await guest.restore()
        guard case .waitingForApproval(let code) = guest.phase else {
            Issue.record("Expected a real signed pairing request"); return
        }
        await owner.refresh()
        let request = try #require(owner.requests.first)
        #expect(request.pairingCode == code)
        let approval = ApprovalModel(request: request, session: owner)
        approval.codeMatches = true; approval.readOnly = true
        #expect(await approval.approve(session: owner))
        await guest.refresh()
        #expect(guest.phase == .ready)
        let member = try #require(owner.members.first { $0.id == request.id })
        #expect(member.grant?.access == [.read])
        let access = MemberAccessModel(member: member, session: owner)
        #expect(await access.revoke(session: owner))
        await guest.refresh()
        #expect(guest.phase == .denied)
        #expect(owner.ledger.contains { $0.event == .revoked })
        try await owner.leave()
        #expect(owner.phase == .noLibrary)
        let action = LibraryActionModel()
        #expect(await action.rejoin(session: owner, host: .init(rejoinKeys: { ownerKeys })))
        #expect(owner.phase == .ready)
    }
}
