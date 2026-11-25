import Foundation
import Testing
@testable import ColophonSession

/// The two status updates that are built without a refresh (the due loop's `recordDue`, and the snapshot after a sync
/// pass that changed nothing) settle the engine first: a locked library is `.locked`, never `.noLibrary` (which an app
/// shows as "library not available"), and an open one is `.ready`.
@MainActor struct StatusUnlockTests {
    @Test func theDueLoopAndAnUnchangedPassNeverReportNoLibraryForALockedOne() async throws {
        let device = Device()
        await device.session.create()
        try #require(device.session.phase == .ready)
        _ = try await device.session.worker.lock()
        #expect(try await device.session.worker.currentSnapshot().phase == .locked)
        #expect(try await device.session.worker.recordDue().phase == .locked)
        _ = try await device.session.worker.unlock()
        #expect(try await device.session.worker.currentSnapshot().phase == .ready)
        #expect(try await device.session.worker.recordDue().phase == .ready)
    }
}
