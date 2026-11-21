import Darwin
import Foundation
import Testing
@testable import ColophonSession

@MainActor struct SyncLifecycleTests {
    @Test(.timeLimit(.minutes(1)))
    func stopAndDrainWaitForBothAnExchangeAndAFileRefresh() async throws {
        let home = SimHome()
        let transport = PausingTransport(home: home)
        let configuration = HomeConfiguration(endpoint: try #require(URL(string: home.base + "/")), request: { account in
            home.setAccount(account)
            return try home.memberRequest(account: account, createdMs: Int64(Date().timeIntervalSince1970 * 1000) - 5000)
        }, transport: transport)
        let device = Device(homes: [configuration], createWithoutHome: false)
        let session = device.session
        await session.create()
        session.stopSync()
        await session.drainSync()
        await session.flushExternalChanges()
        try #require(session.phase == .ready)

        let (refreshStarted, started) = AsyncStream<Void>.makeStream()
        let (refreshRelease, release) = AsyncStream<Void>.makeStream()
        defer { release.finish(); transport.release.finish(); session.stopSync() }
        var reachedRefresh = false
        session.refreshWillFinish = {
            guard !reachedRefresh else { return }
            reachedRefresh = true
            started.yield(())
            for await _ in refreshRelease {}
        }

        await transport.arm()
        session.startSync()
        let loop = try #require(session.syncTask)
        let due = try #require(session.dueTask)
        session.startSync()
        #expect(session.syncTask == loop && session.dueTask == due)
        var exchange = transport.started.makeAsyncIterator()
        try #require(await exchange.next() != nil)

        session.externalChange()
        var refresh = refreshStarted.makeAsyncIterator()
        try #require(await refresh.next() != nil)
        session.stopSync()
        #expect(loop.isCancelled && due.isCancelled)
        #expect(session.syncTask == nil && session.dueTask == nil)

        var drained = false
        let drain = Task { await session.drainSync(); drained = true }
        await Task.yield()
        #expect(!drained)
        transport.release.finish()
        await loop.value
        #expect(!drained, "the refresh is still running after the exchange finishes")
        release.finish()
        await drain.value
        #expect(drained)
        #expect(session.batchTask == nil)
        let requestCount = home.requestLog.count
        await session.drainSync()
        #expect(home.requestLog.count == requestCount, "draining an idle session sends no requests")
    }

    @Test func lockingCancelsFileWorkAndUnlockingRegistersThePresenterAgain() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let medium = FolderMedium(folder: root.appendingPathComponent("library"), coordinated: false)
        let session = ColophonSession(configuration: .init(
            memberLabel: "Device", namespaces: ["reading.saved"], location: .medium(medium),
            privateContainer: root.appendingPathComponent("private"), keys: SoftwareKeys(), ownerController: SoftwareKeys(),
            createWithoutHome: true, deviceSecrets: MemoryDeviceSecrets()
        ))
        func presenterCount() -> Int {
            NSFileCoordinator.filePresenters.count { $0.presentedItemURL == medium.folder }
        }

        await session.create()
        session.stopSync()
        await session.drainSync()
        try #require(session.phase == .ready)
        let watch = try #require(session.watchTask)
        #expect(presenterCount() == 1)

        var refreshed = false
        session.refreshWillFinish = { refreshed = true }
        session.externalChange()
        let batch = try #require(session.batchTask)
        await session.lock()
        #expect(watch.isCancelled && batch.isCancelled)
        #expect(session.watchTask == nil && session.batchTask == nil && session.checkpointTask == nil)
        #expect(session.syncTask == nil && session.dueTask == nil)
        #expect(presenterCount() == 0)
        #expect(session.phase == .locked)
        session.externalChange()
        session.startSync()
        await session.refresh()
        #expect(session.batchTask == nil && session.dueTask == nil)
        #expect(!refreshed)

        let fd = open(medium.folder.appendingPathComponent(".colophon.nosync/lock").path, O_RDWR)
        try #require(fd >= 0)
        do {
            defer { close(fd) }
            #expect(flock(fd, LOCK_EX | LOCK_NB) == 0)
        }

        await session.unlock()
        #expect(session.phase == .ready)
        #expect(session.watchTask != nil && session.watchTask != watch)
        #expect(presenterCount() == 1)
        #expect(session.dueTask == nil, "an explicit stop survives an unlock")
        session.startSync()
        #expect(session.dueTask != nil)
        session.externalChange()
        await session.drainSync()
        #expect(refreshed)
        await session.lock()
    }

    private actor PausingTransport: HomeTransport {
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
}
