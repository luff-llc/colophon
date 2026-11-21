import Foundation
import ColophonKeys
@testable import ColophonSession
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

    enum ForkDelivery: CaseIterable, Sendable { case folder, home }

    @Test(arguments: ForkDelivery.allCases)
    func anExchangeReorganizationRemainsIneligibleAfterCancellationAndReopen(delivery: ForkDelivery) async throws {
        let endpoint = try #require(URL(string: "https://authority-home.test"))
        let home = SimHome(base: endpoint.absoluteString)
        let request: @Sendable (String) async throws -> Data = { account in
            try home.memberRequest(account: account, createdMs: Int64(Date().timeIntervalSince1970 * 1000) - 5_000)
        }
        let configured = HomeConfiguration(endpoint: endpoint, request: request, transport: ForkHome(entries: nil))
        let source = Device(homes: [configured], createWithoutHome: false)
        _ = try await source.session.worker.create()
        let other = Device(medium: source.medium.copy(), member: source.member, owner: source.owner)
        try await source.session.addController(SoftwareKeys(), label: "First signed branch")
        try await other.session.addController(SoftwareKeys(), label: "Second signed branch")

        // Drive the worker directly so a facade watcher or refresh cannot consume the change.
        let authority = try #require(source.medium.snapshot().keys.filter { $0.hasPrefix("authority/") }.max())
        let alternate = try other.medium.read(authority)
        let original = try source.medium.read(authority)
        #expect(alternate != original)
        let envelope = try JSONSerialization.jsonObject(with: alternate)
        let answer = try JSONSerialization.data(withJSONObject: ["entries": [envelope], "receipts": [], "more": false])
        let transport = ForkHome(entries: delivery == .home ? answer : nil)
        let joiningHome = HomeConfiguration(endpoint: endpoint, request: request, transport: transport)
        let joining = Device(medium: source.medium.copy(), homes: [joiningHome])
        let worker = joining.session.worker
        let waiting = try await worker.restore()
        #expect(waiting.phase == .waitingForApproval)
        let before = try await worker.acceptedAuthorityHead()
        #expect(authority == String(format: "authority/%08llu.json", before.sequence))
        let alternatePath = "authority/99999999.json"
        if delivery == .folder { joining.medium.put(alternatePath, alternate) }

        await #expect(throws: CancellationError.self) { _ = try await worker.exchange() }
        let engine = try await worker.requireEngine()
        let fork = try await engine.run { try $0.status() }
        #expect(fork.code == "refused:fork")
        #expect(fork.seq < before.sequence)

        // Reopening over the original branch makes the verifier healthy again. The fork from
        // the home was never persisted. The folder case explicitly removes its second branch.
        // The worker must still remember that this selection observed a reorganization.
        _ = try await worker.lock()
        if delivery == .folder { joining.medium.remove(alternatePath) }
        _ = try await worker.unlock()
        let reopened = try await worker.requireEngine()
        let healthy = try await reopened.run { try $0.status() }
        #expect(healthy.kind == .ok)
        #expect(!healthy.rollback)
        #expect(healthy.seq == before.sequence)
        await #expect(throws: SessionError.staleRevision) { try await worker.acceptedAuthorityHead() }
    }

    private struct ForkHome: HomeTransport {
        let entries: Data?

        func send(_ request: HttpRequest) async throws -> HttpAnswer {
            if let entries {
                if request.url.hasSuffix("/head") { return HttpAnswer(status: 404, headers: [], body: Data()) }
                if request.url.contains("/authority?") { return HttpAnswer(status: 200, headers: [], body: entries) }
            }
            throw CancellationError()
        }
    }
}
