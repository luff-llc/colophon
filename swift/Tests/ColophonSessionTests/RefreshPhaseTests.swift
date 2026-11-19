import Foundation
import Testing
@testable import ColophonSession

/// A refresh moves `ready` to `refreshing` while it runs, and a finished refresh never leaves it there. Before the fix a
/// refresh that ended without applying a snapshot (its caller cancelled, as a SwiftUI `.task` is when its view goes away)
/// left the session `refreshing` until some later refresh. The Kotlin SDK's `RefreshPhaseTest` is the same test. No
/// time passes: the worker's gate is held by the test, so the refresh is in flight exactly as long as the test says.
@MainActor struct RefreshPhaseTests {
    @Test func aCancelledRefreshPutsReadyBack() async throws {
        let device = Device()
        await device.session.create()
        await device.session.flushExternalChanges() // no batch refresh of the creation's own writes is left to run
        try #require(device.session.phase == .ready, "\(device.session.phase) \(device.session.lastError ?? "")")
        let worker = device.session.worker
        await worker.enter()
        let refresh = Task { await device.session.refresh() }
        for _ in 0..<10_000 where device.session.phase != .refreshing { await Task.yield() }
        try #require(device.session.phase == .refreshing, "the refresh began: \(device.session.phase)")
        refresh.cancel()
        await worker.exit()
        await refresh.value
        #expect(device.session.phase == .ready, "a cancelled refresh left \(device.session.phase)")
        await device.session.refresh()
        #expect(device.session.phase == .ready, "\(device.session.phase) \(device.session.lastError ?? "")")
    }

    /// The refreshes held at `ColophonSession.refreshWillFinish`, numbered in the order they reach it: a held one waits there
    /// (its worker has answered, its outcome is not published) until the test releases it, with or without an error.
    @MainActor final class RefreshHolds {
        private var count = 0
        private let holding: Set<Int>
        private var held: [Int: CheckedContinuation<Void, any Error>] = [:]
        init(holding: Set<Int>) { self.holding = holding }
        func reached() async throws {
            count += 1
            let n = count
            guard holding.contains(n) else { return }
            try await withCheckedThrowingContinuation { held[n] = $0 }
        }
        func waiting(_ n: Int) async -> Bool {
            for _ in 0..<10_000 where held[n] == nil { await Task.yield() }
            return held[n] != nil
        }
        func release(_ n: Int, throwing error: (any Error)? = nil) {
            guard let continuation = held.removeValue(forKey: n) else { return }
            if let error { continuation.resume(throwing: error) } else { continuation.resume() }
        }
    }

    /// R1 is held after its worker answered; another refresh publishes `ready`; R2 marks `refreshing` and is held. R1, now
    /// stale, finishes or fails afterwards. Returns the device and both refresh tasks, with R2 still held.
    private func staleRefresh(_ holds: RefreshHolds) async throws -> (Device, Task<Void, Never>, Task<Void, Never>) {
        let device = Device()
        await device.session.create()
        await device.session.flushExternalChanges()
        try #require(device.session.phase == .ready, "\(device.session.phase) \(device.session.lastError ?? "")")
        device.session.refreshWillFinish = { try await holds.reached() }
        let r1 = Task { await device.session.refresh() }
        try #require(await holds.waiting(1), "R1 reached the hold")
        #expect(device.session.phase == .refreshing)
        await device.session.refresh() // the second to reach the hold, not held: it publishes `ready`
        try #require(device.session.phase == .ready, "\(device.session.phase) \(device.session.lastError ?? "")")
        let r2 = Task { await device.session.refresh() }
        try #require(await holds.waiting(3), "R2 reached the hold")
        try #require(device.session.phase == .refreshing)
        return (device, r1, r2)
    }

    @Test func aStaleRefreshThatFinishesIsDroppedAndThePhaseFollowsTheNewerOne() async throws {
        let holds = RefreshHolds(holding: [1, 3])
        let (device, r1, r2) = try await staleRefresh(holds)
        holds.release(1)
        await r1.value
        #expect(device.session.phase == .refreshing, "a stale refresh published \(device.session.phase) while a newer one runs")
        holds.release(3)
        await r2.value
        #expect(device.session.phase == .ready, "\(device.session.phase) \(device.session.lastError ?? "")")
    }

    @Test func aStaleRefreshThatFailsIsDroppedAndACancelledNewerOnePutsReadyBack() async throws {
        let holds = RefreshHolds(holding: [1, 3])
        let (device, r1, r2) = try await staleRefresh(holds)
        holds.release(1, throwing: StorageError.unavailable("the disk is gone"))
        await r1.value
        #expect(device.session.phase == .refreshing, "a stale refresh's failure published \(device.session.phase)")
        r2.cancel()
        holds.release(3)
        await r2.value
        #expect(device.session.phase == .ready, "a cancelled refresh left \(device.session.phase)")
    }

    /// A command that fails while a refresh is in flight, with a failure that sets a phase, keeps that phase: the refresh's
    /// ready snapshot, older than the failure, does not hide it.
    @Test func aCommandFailureDuringARefreshKeepsThePhaseItSet() async throws {
        let device = Device()
        await device.session.create()
        await device.session.flushExternalChanges()
        try #require(device.session.phase == .ready, "\(device.session.phase) \(device.session.lastError ?? "")")
        let holds = RefreshHolds(holding: [1])
        device.session.refreshWillFinish = { try await holds.reached() }
        let refresh = Task { await device.session.refresh() }
        try #require(await holds.waiting(1), "the refresh reached the hold")
        device.medium.setFault(.failWrite(after: 0))
        await #expect(throws: StorageError.self) {
            try await device.session.perform(try .saveLink(id: "b", url: URL(string: "https://example.org/b")!, title: "B"), observed: device.session.observedRevision)
        }
        device.medium.setFault(.none)
        #expect(device.session.phase == .retry, "\(device.session.phase)")
        holds.release(1)
        await refresh.value
        #expect(device.session.phase == .retry, "the refresh replaced the failure's phase with \(device.session.phase)")
        #expect(device.session.lastError != nil)
    }
}
