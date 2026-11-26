import Foundation
import Testing
import ColophonKit
import ColophonSavedKit
@testable import ColophonSession

/// A device that syncs with its home for days (0.5.7), against the REAL relay on a clock the test moves. Each sync fetches
/// a newer head from the home, a new envelope over the same history. Before 0.5.7 the account held every one, and after 64
/// every exchange failed `malformed: too many head envelopes`; now it keeps the heads a reader needs (spec §13.3) and keeps
/// syncing, writing, and reopening from its saved state. The account's own heal of an old saved state is
/// `v05_relay_heads.rs` (Rust). The same journey runs in Kotlin (`ManyHeadsTest.kt`).
@MainActor @Suite(.serialized) struct ManyHeadsTests {
    nonisolated private static let t0: Int64 = 1_795_165_200_000 // 2026-11-20T09:00:00Z

    private func describe(_ device: Device) -> String {
        "phase \(device.session.phase) error \(device.session.lastError ?? "-") issues \(device.session.homeIssues) faults \(device.session.homeFaults.map { "\($0.fault.kind) \($0.fault.status.map(String.init) ?? "")" })"
    }
    private func save(_ session: ColophonSession, _ id: String) async throws {
        try await session.perform(try .saveLink(id: id, url: URL(string: "https://example.org/\(id)")!, title: id), observed: session.observedRevision)
    }

    @Test(.timeLimit(.minutes(10))) func aDeviceThatSyncedForDaysKeepsSyncing() async throws {
        let clock = TestClock(Self.t0)
        let relay = RelayHome(base: "https://heads.test/v1/accounts/swift", port: RelayHome.freePort(), clock: { clock.now })
        defer { relay.stop() }
        let home = URL(string: relay.base + "/")!
        let first = Device(homes: [HomeConfiguration(endpoint: home, request: { account in
            try relay.start(account: account)
            return try relay.memberRequest(account: account)
        }, transport: relay.transport())], createWithoutHome: false, history: .members, clock: { clock.date })
        await first.session.create()
        first.session.stopSync()
        try #require(first.session.phase == .ready, "\(describe(first))")
        try await save(first.session, "a")
        for i in 0..<80 {
            clock.advance(150_000)
            try await relay.tick()
            let ok = await first.session.syncNow()
            #expect(ok && first.session.homeFaults.isEmpty && first.session.homeIssues.isEmpty, "sync \(i): \(describe(first))")
            if !ok { return }
        }
        try await save(first.session, "b")
        clock.advance(1_000); try await relay.tick()
        #expect(await first.session.syncNow(), "\(describe(first))")
        try await first.session.flushCheckpoint()

        // A relaunch from the saved state keeps syncing.
        await first.session.lock()
        let again = first.relaunch()
        await again.restore()
        again.stopSync()
        clock.advance(150_000); try await relay.tick()
        #expect(await again.syncNow())
        #expect(again.homeFaults.isEmpty)
        let total = try await SavedStore(session: again).load(ItemsQuery(limit: 50)).get().total
        #expect(total == 2)
    }
}
