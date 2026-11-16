import Foundation
import Testing
@testable import ColophonSession

/// A pass cancelled while a request is in flight must not leave the engine with an outstanding request: the next pass
/// starts again from the head. Before the fix the cancelled pass skipped `exchange_abort` (its gate checked
/// cancellation first), every later `exchange_next` returned `Waiting`, which the loop took as done, and the session
/// reported clean exchanges that moved nothing. The Kotlin SDK's `ExchangeCancelTest` is the same test.
@MainActor @Suite(.serialized) struct ExchangeCancelTests {
    /// Once armed, the next request waits until it is cancelled; every other one is answered 503. Every URL is recorded.
    final class HangingTransport: HomeTransport, @unchecked Sendable {
        private let lock = NSLock()
        private var urls: [String] = []
        private var armed = false
        private(set) var hung = false
        func arm() { lock.withLock { armed = true } }
        var hanging: Bool { lock.withLock { hung } }
        var seen: [String] { lock.withLock { urls } }
        func send(_ request: HttpRequest) async throws -> HttpAnswer {
            let hang = lock.withLock { () -> Bool in
                urls.append("\(request.method) \(request.url)")
                if armed { armed = false; hung = true; return true }
                return false
            }
            if hang { try await Task.sleep(for: .seconds(3600)) }
            return HttpAnswer(status: 503, headers: [], body: Data())
        }
    }

    @Test func aCancelledPassIsAbandonedAndTheNextOneStartsClean() async throws {
        let base = "https://hanging-home.test/v1/accounts/k"
        let home = SimHome(base: base)
        let transport = HangingTransport()
        let make: @Sendable (String) async throws -> Data = { account in
            home.setAccount(account)
            return try home.memberRequest(account: account, createdMs: Int64(Date().timeIntervalSince1970 * 1000) - 5000)
        }
        let device = Device(homes: [HomeConfiguration(endpoint: URL(string: base + "/")!, request: make, transport: transport)], createWithoutHome: false)
        await device.session.create()
        device.session.stopSync()
        try #require(device.session.phase == .ready, "\(device.session.phase)")
        _ = await device.session.syncNow() // any pass the loop began has finished
        let worker = device.session.worker
        transport.arm()
        let start = transport.seen.count
        let pass = Task { try await worker.exchange() }
        for _ in 0..<250 where !transport.hanging { try await Task.sleep(for: .milliseconds(20)) }
        try #require(transport.hanging, "the pass reached the home")
        pass.cancel()
        _ = try? await pass.value
        _ = try await worker.exchange()
        let after = transport.seen.dropFirst(start + 1)
        #expect(!after.isEmpty, "the next pass sent nothing: the engine still held the cancelled request")
        #expect(after.first == "get \(base)/head", "the next pass starts again from the head: \(Array(after))")
    }

    /// An engine that answers `Waiting` again after the one recovery: the pass cannot finish. Before the fix the loop ended
    /// on the second `Waiting` with no fault, `syncNow()` returned true and an app called it a complete sync.
    @Test func aPassThatStillWaitsAfterItsRecoveryFails() async throws {
        let base = "https://waiting-home.test/v1/accounts/w"
        let home = SimHome(base: base)
        let make: @Sendable (String) async throws -> Data = { account in
            home.setAccount(account)
            return try home.memberRequest(account: account, createdMs: Int64(Date().timeIntervalSince1970 * 1000) - 5000)
        }
        let device = Device(homes: [HomeConfiguration(endpoint: URL(string: base + "/")!, request: make, transport: home)], createWithoutHome: false)
        await device.session.create()
        device.session.stopSync()
        try #require(device.session.phase == .ready, "\(device.session.phase)")
        let worker = device.session.worker
        await worker.setNextStepOverride { _ in ExchangeStep(kind: .waiting, request: nil, need: nil) }
        let ok = await device.session.syncNow()
        #expect(!ok, "a pass that still waits is a failed sync")
        #expect(device.session.homeIssues.contains { $0.problem == .stillWaiting }, "named: \(device.session.homeIssues)")
        if case .error = device.session.syncState {} else { Issue.record("sync state \(device.session.syncState)") }
        await worker.setNextStepOverride(nil)
        #expect(await device.session.syncNow(), "the next real pass succeeds")
    }
}
