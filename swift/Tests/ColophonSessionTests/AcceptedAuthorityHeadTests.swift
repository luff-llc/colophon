import Foundation
import ColophonSession
import Testing

@MainActor struct AcceptedAuthorityHeadTests {
    @Test func thePendingDeviceReadsTheSameExactHeadAndALockRefusesIt() async throws {
        let first = Device()
        await first.session.create()
        let source = try await first.session.acceptedAuthorityHead()
        let pending = Device(medium: first.medium)
        let joining = try await pending.session.acceptedAuthorityHead()
        #expect(pending.session.phase == .waitingForApproval)
        #expect(joining.account == source.account)
        #expect(joining.sequence == source.sequence)
        #expect(joining.digest == source.digest)
        #expect(joining.digest.count == 64)

        try await approveByScan(joining: pending.session, approving: first.session)
        await pending.session.flushExternalChanges()
        let approved = try await pending.session.acceptedAuthorityHead()
        #expect(approved.sequence > joining.sequence)
        #expect(approved.digest != joining.digest)
        await pending.session.lock()
        await #expect(throws: SessionError.notReady) { try await pending.session.acceptedAuthorityHead() }
    }

    @Test func anAlreadyOpenHeadDoesNotReadStorageAndACanceledCallDoesNotOpen() async throws {
        let source = Device()
        await source.session.create()
        let accepted = try await source.session.acceptedAuthorityHead()
        source.medium.setFault(.throwOnListing("this test forbids listing after the initial open"))
        let reread = try await source.session.acceptedAuthorityHead()
        #expect(accepted.digest == reread.digest)
        #expect(accepted.sequence == reread.sequence)

        let unopened = Device()
        let canceled = Task { @MainActor in try await unopened.session.acceptedAuthorityHead() }
        canceled.cancel()
        await #expect(throws: CancellationError.self) { try await canceled.value }
        #expect(unopened.session.phase == .opening)
    }

}
