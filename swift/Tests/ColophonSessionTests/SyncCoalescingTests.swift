import Foundation
import Testing
import ColophonSavedKit
@testable import ColophonSession

/// An exchange refreshes the engine from the folder before its first home, and before a later home only when something
/// besides its own writes arrived; a folder hint that arrives during a pass is reconciled once with the refresh that
/// follows the pass, not a second time.
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
    func aLaterHomeOfAPassRefreshesOnlyForAFolderChange() async throws {
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
        let worker = session.worker
        let reconciles = await worker.markedReconciles, later = await worker.laterHomeRefreshes
        let sentFirst = first.requestLog.count, sentSecond = second.requestLog.count
        let result = try await worker.exchange()
        let listings = medium.listings - before
        #expect(listings == 2, "the folder is listed before each home")
        #expect(await worker.laterHomeRefreshes == later, "nothing external changed: the second home did not refresh the engine")
        #expect(await worker.markedReconciles == reconciles, "the exchange itself ran no full reconcile")
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
        await session.drainSync()
        let worker = session.worker
        let reconciles = await worker.markedReconciles, coalesced = await worker.coalescedRefreshes

        let (refreshed, finished) = AsyncStream<Void>.makeStream()
        session.refreshWillFinish = { finished.yield(()) }
        await transport.arm()
        let pass = Task { await session.syncNow() }
        var held = transport.started.makeAsyncIterator()
        try #require(await held.next() != nil)
        // The pass is held at its first request. A local write lands (its snapshot is shown, but the engine now holds
        // a write no marked reconcile has seen) and the folder watcher reports the change.
        try await session.perform(try .saveLink(id: "a", url: URL(string: "https://example.org/a")!, title: "A"), observed: session.observedRevision)
        session.externalChange()
        var refreshes = refreshed.makeAsyncIterator()
        try #require(await refreshes.next() != nil)
        #expect(await worker.markedReconciles == reconciles, "the hint during the pass reconciled nothing")
        #expect(await worker.coalescedRefreshes > coalesced)
        #expect(await worker.owesRefresh, "the hint left its refresh to the one after the pass")

        transport.release.finish()
        #expect(await pass.value)
        await session.drainSync()
        let after = await worker.markedReconciles
        // Before, the hint reconciled during the pass and the pass's own refresh reconciled again. Now the hint is
        // answered from the folder mark and the owed refresh after the pass reconciles once.
        #expect(after - reconciles == 1, "one full reconcile for the pass and the hint together, got \(after - reconciles)")
        #expect(await worker.owesRefresh == false)
        #expect(session.phase == .ready && session.syncState == .idle, "\(session.phase) \(session.syncState)")
        let pushed = medium.inner.snapshot().keys.filter { $0.hasPrefix("ops/") }
        #expect(!pushed.isEmpty, "the write is in the folder")
        #expect(try await SavedStore(session: session).load(ItemsQuery(limit: 10)).get().total == 1)
    }

    /// Holds the first request of either home until released, and names the home it held.
    actor FirstRequest {
        nonisolated let started: AsyncStream<String>
        nonisolated let release: AsyncStream<Void>.Continuation
        private let signal: AsyncStream<String>.Continuation
        private let resume: AsyncStream<Void>
        private var armed = false
        init() { (started, signal) = AsyncStream<String>.makeStream(); (resume, release) = AsyncStream<Void>.makeStream() }
        func arm() { armed = true }
        func hold(_ base: String) async {
            guard armed else { return }
            armed = false
            signal.yield(base)
            for await _ in resume {}
        }
    }
    struct HeldTransport: HomeTransport {
        let home: SimHome
        let gate: FirstRequest
        func send(_ request: HttpRequest) async throws -> HttpAnswer {
            await gate.hold(home.base)
            return try await home.send(request)
        }
    }

    /// A record another session puts in the folder while the first home of a pass is in flight reaches the engine before
    /// the second home, which then receives it in the same pass.
    @Test(.timeLimit(.minutes(1)))
    func aRecordWrittenElsewhereDuringTheFirstHomeReachesTheSecond() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let first = SimHome(base: "https://first.example"), second = SimHome(base: "https://second.example")
        let gate = FirstRequest()
        let medium = CountingMedium(hints: false)
        let member = SoftwareKeys(), owner = SoftwareKeys()
        let session = ColophonSession(configuration: .init(memberLabel: "Device", namespaces: ["reading.saved"], location: .medium(medium),
            privateContainer: root.appendingPathComponent("a"), keys: member, ownerController: owner,
            homes: [try appointing(first, transport: HeldTransport(home: first, gate: gate)), try appointing(second, transport: HeldTransport(home: second, gate: gate))],
            createWithoutHome: false, deviceSecrets: MemoryDeviceSecrets()))
        defer { gate.release.finish(); session.stopSync() }
        await session.create()
        session.stopSync()
        await session.drainSync()
        try #require(session.phase == .ready, "\(session.phase) \(session.lastError ?? "")")
        _ = try await session.worker.exchange()
        // The same member on another process over the same folder, with no homes: its write is not this worker's.
        let other = ColophonSession(configuration: .init(memberLabel: "Device", namespaces: ["reading.saved"], location: .medium(medium),
            privateContainer: root.appendingPathComponent("b"), keys: member, ownerController: owner, createWithoutHome: true,
            deviceSecrets: MemoryDeviceSecrets()))
        defer { other.stopSync() }
        await other.restore()
        try #require(other.phase == .ready, "\(other.phase) \(other.lastError ?? "")")

        let worker = session.worker
        let later = await worker.laterHomeRefreshes
        let before = Set(medium.inner.snapshot().keys.filter { $0.hasPrefix("ops/") })
        await gate.arm()
        let pass = Task { try await worker.exchange() }
        var held = gate.started.makeAsyncIterator()
        let heldBase = try #require(await held.next())
        try await other.perform(try .saveLink(id: "elsewhere", url: URL(string: "https://example.org/e")!, title: "E"), observed: other.observedRevision)
        let injected = Set(medium.inner.snapshot().keys.filter { $0.hasPrefix("ops/") }).subtracting(before)
        try #require(!injected.isEmpty)
        gate.release.finish()
        let result = try await pass.value
        #expect(result.issues.isEmpty && result.faults.isEmpty, "\(result.issues) \(result.faults)")
        #expect(await worker.laterHomeRefreshes == later + 1, "the engine was refreshed before the second home")
        let secondHome = heldBase == first.base ? second : first
        let atSecond = Set(secondHome.holds(prefix: "ops/"))
        #expect(injected.isSubset(of: atSecond), "the second home received the record written during the first: \(atSecond)")
    }
}
