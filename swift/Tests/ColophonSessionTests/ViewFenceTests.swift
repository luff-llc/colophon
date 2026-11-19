import Foundation
import Testing
@testable import ColophonSession

/// `view(namespace:)` is fenced as `query` is: a fold that comes back after the session locked is refused, never handed
/// to a screen that no longer may show it. Before the fence `view` returned the old fold. The Kotlin session's
/// `ViewFenceTest` is the same test.
@MainActor @Suite(.serialized) struct ViewFenceTests {
    @Test func aViewThatReturnsAfterLockIsStale() async throws {
        let device = Device(namespaces: ["notes"])
        await device.session.create()
        try #require(device.session.phase == .ready, "\(device.session.phase)")
        let session = device.session
        _ = try await session.view(namespace: "notes")
        session.afterViewForTests = { await session.lock() }
        await #expect(throws: SessionError.staleRevision) { try await session.view(namespace: "notes") }
        session.afterViewForTests = nil
        #expect(session.phase == .locked)
        await #expect(throws: SessionError.notReady) { try await session.view(namespace: "notes") }
    }
}
