import Foundation
import Testing
import ColophonSavedKit
@testable import ColophonSession

/// An exchange lists the folder once for all its homes, and a folder hint that arrives during a pass is reconciled once
/// with the refresh that follows the pass, not a second time.
@MainActor struct SyncCoalescingTests {
    /// A medium that counts its listings. With `hints` off it sends no change hints, so no watcher refresh lists it.
    final class CountingMedium: RecordMedium, @unchecked Sendable {
        let inner = MemoryMedium()
        private let lock = NSLock()
        private var count = 0
        private let hints: Bool
        init(hints: Bool) { self.hints = hints }
        var listings: Int { lock.withLock { count } }
        func listing() throws -> [MediumEntry] { lock.withLock { count += 1 }; return try inner.listing() }
        func read(_ path: String) throws -> Data { try inner.read(path) }
        func readBlob(_ path: String) throws -> Data { try inner.readBlob(path) }
        func write(_ writes: [MediumWrite]) throws { try inner.write(writes) }
        func changes() -> AsyncStream<Void> { hints ? inner.changes() : AsyncStream { $0.finish() } }
    }

    /// Holds the first request it is armed for until released.
    actor PausingTransport: HomeTransport {
        let home: SimHome
        nonisolated let started: AsyncStream<Void>
        nonisolated let release: AsyncStream<Void>.Continuation
        private let signal: AsyncStream<Void>.Continuation
        private let resume: AsyncStream<Void>
        private var armed = false
        init(home: SimHome) {
            self.home = home
            (started, signal) = AsyncStream<Void>.makeStream()
            (resume, release) = AsyncStream<Void>.makeStream()
        }
        func arm() { armed = true }
        func send(_ request: HttpRequest) async throws -> HttpAnswer {
            if armed {
                armed = false
                signal.yield(())
                for await _ in resume {}
            }
            return try await home.send(request)
        }
    }

    private func appointing(_ home: SimHome, transport: (any HomeTransport)? = nil) throws -> HomeConfiguration {
        HomeConfiguration(endpoint: try #require(URL(string: home.base + "/")), request: { account in
            home.setAccount(account)
            return try home.memberRequest(account: account, createdMs: Int64(Date().timeIntervalSince1970 * 1000) - 5000)
        }, transport: transport ?? home)
    }

    private func session(_ medium: CountingMedium, homes: [HomeConfiguration], root: URL) -> ColophonSession {
        ColophonSession(configuration: .init(memberLabel: "Device", namespaces: ["reading.saved"], location: .medium(medium),
            privateContainer: root, keys: SoftwareKeys(), ownerController: SoftwareKeys(), homes: homes, createWithoutHome: false,
            deviceSecrets: MemoryDeviceSecrets()))
    }

    @Test(.timeLimit(.minutes(1)))
    func twoHomesInOnePassListTheFolderOnce() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let first = SimHome(base: "https://first.example"), second = SimHome(base: "https://second.example")
        let medium = CountingMedium(hints: false)
        let session = session(medium, homes: [try appointing(first), try appointing(second)], root: root)
        defer { session.stopSync() }
        await session.create()
        session.stopSync()
        await session.drainSync()
        try #require(session.phase == .ready, "\(session.phase) \(session.lastError ?? "")")
        try #require(session.homes.count == 2)

        try await session.perform(try .saveLink(id: "a", url: URL(string: "https://example.org/a")!, title: "A"), observed: session.observedRevision)
        let local = medium.inner.snapshot().keys.filter { $0.hasPrefix("ops/") }.sorted()
        try #require(!local.isEmpty)
        let before = medium.listings
        let sentFirst = first.requestLog.count, sentSecond = second.requestLog.count
        let result = try await session.worker.exchange()
        let listings = medium.listings - before
        #expect(listings == 1, "one folder listing for the exchange with both homes, not one per home")
        #expect(result.issues.isEmpty && result.faults.isEmpty, "\(result.issues) \(result.faults)")
        #expect(first.requestLog.count > sentFirst && second.requestLog.count > sentSecond, "both homes were exchanged with")
        // The sync result is unchanged: both homes hold the record written before the pass.
        let atFirst = first.holds(prefix: "ops/"), atSecond = second.holds(prefix: "ops/")
        #expect(local.allSatisfy { atFirst.contains($0) && atSecond.contains($0) }, "first \(atFirst) second \(atSecond)")
    }

    @Test(.timeLimit(.minutes(1)))
    func aFolderHintDuringAPassIsReconciledOnce() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let home = SimHome()
        let transport = PausingTransport(home: home)
        let medium = CountingMedium(hints: true)
        let session = session(medium, homes: [try appointing(home, transport: transport)], root: root)
        defer { transport.release.finish(); session.stopSync(); session.refreshWillFinish = nil }
        await session.create()
        session.stopSync()
        await session.drainSync()
        try #require(session.phase == .ready, "\(session.phase) \(session.lastError ?? "")")
        try await session.perform(try .saveLink(id: "a", url: URL(string: "https://example.org/a")!, title: "A"), observed: session.observedRevision)
        await session.drainSync()
        let worker = session.worker
        let reconciles = await worker.markedReconciles, coalesced = await worker.coalescedRefreshes

        let (refreshed, finished) = AsyncStream<Void>.makeStream()
        session.refreshWillFinish = { finished.yield(()) }
        await transport.arm()
        let pass = Task { await session.syncNow() }
        var held = transport.started.makeAsyncIterator()
        try #require(await held.next() != nil)
        // The pass is held at its first request; the folder watcher reports a change.
        session.externalChange()
        var refreshes = refreshed.makeAsyncIterator()
        try #require(await refreshes.next() != nil)
        #expect(await worker.markedReconciles == reconciles, "the hint during the pass reconciled nothing")
        #expect(await worker.coalescedRefreshes == coalesced + 1)

        transport.release.finish()
        #expect(await pass.value)
        await session.drainSync()
        let after = await worker.markedReconciles
        // Before, the hint reconciled during the pass and the pass's own refresh reconciled again. Now the hint is
        // answered from the folder mark and at most the refresh after the pass reconciles.
        #expect(after - reconciles <= 1, "at most one full reconcile for the pass and the hint together, got \(after - reconciles)")
        #expect(session.phase == .ready && session.syncState == .idle, "\(session.phase) \(session.syncState)")
        let pushed = medium.inner.snapshot().keys.filter { $0.hasPrefix("ops/") }
        #expect(!pushed.isEmpty && pushed.allSatisfy { home.holds(prefix: "ops/").contains($0) }, "the pass still pushed the record")
        #expect(try await SavedStore(session: session).load(ItemsQuery(limit: 10)).get().total == 1)
    }
}
