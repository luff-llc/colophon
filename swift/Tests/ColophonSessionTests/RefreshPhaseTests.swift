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
}
