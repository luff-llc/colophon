import Foundation
import Synchronization
import Testing
@testable import ColophonSession

/// Holds a refresh open without timers, including when release precedes the waiter.
private actor RefreshLatch {
    private var entered = false
    private var released = false
    private var observer: CheckedContinuation<Void, Never>?
    private var refresh: CheckedContinuation<Void, Never>?

    func pause() async {
        entered = true
        observer?.resume(); observer = nil
        if !released { await withCheckedContinuation { refresh = $0 } }
    }
    func waitUntilEntered() async {
        if !entered { await withCheckedContinuation { observer = $0 } }
    }
    func release() {
        released = true
        refresh?.resume(); refresh = nil
    }
}

/// Models the native engine's refusal of overlapping queries and source refreshes. The real
/// core still supplies every snapshot, query result, signature and access decision.
@available(macOS 26.0, iOS 26.0, *)
private final class RefreshProbeCore: SessionCore, Sendable {
    let base = BindingSessionCore()
    let latch = RefreshLatch()
    private struct Probe {
        var armed = false
        var onSnapshot = false
        var refreshing = false
        var overlappingQueries = 0
    }
    private let probe = Mutex(Probe())

    func arm(onSnapshot: Bool) { probe.withLock { $0.armed = true; $0.onSnapshot = onSnapshot } }
    var overlappingQueries: Int { probe.withLock { $0.overlappingQueries } }
    func setOwnerController(_ provider: any AsyncKeyProvider) async { await base.setOwnerController(provider) }
    func openStorage(store: any RecordStore, paths: Set<String>, versions: [String: String], pending: [String: Data], keys: any AsyncKeyProvider, namespaces: [String], cache: CheckpointCache, libraryID: String?) async throws {
        try await base.openStorage(store: store, paths: paths, versions: versions, pending: pending, keys: keys, namespaces: namespaces, cache: cache, libraryID: libraryID)
    }
    func open(records: [String: Data], keys: any AsyncKeyProvider) async throws { try await base.open(records: records, keys: keys) }
    func create(configuration: SessionConfiguration) async throws { try await base.create(configuration: configuration) }
    func updateVersions(_ versions: [String: String], reader: RecordReader) async throws { try await base.updateVersions(versions, reader: reader) }
    private func pauseIfArmed(onSnapshot: Bool) async {
        let pause = probe.withLock { state in
            guard state.armed, state.onSnapshot == onSnapshot else { return false }
            state.armed = false; state.refreshing = true
            return true
        }
        if pause { await latch.pause() }
        if pause { probe.withLock { $0.refreshing = false } }
    }
    func refreshSource(reader: RecordReader, pending: [String: Data]) async throws {
        await pauseIfArmed(onSnapshot: false)
        try await base.refreshSource(reader: reader, pending: pending)
    }
    func merge(_ records: [String: Data]) async throws { try await base.merge(records) }
    func mergeObserved(_ records: [String: Data], versions: [String: String]) async throws { try await base.mergeObserved(records, versions: versions) }
    func records() async throws -> [String: Data] { try await base.records() }
    func records(at paths: [String]) async throws -> [String: Data] { try await base.records(at: paths) }
    func lastWrittenPaths() async throws -> [String] { try await base.lastWrittenPaths() }
    func snapshot(namespaces: [String]) async throws -> CoreSnapshot { try await base.snapshot(namespaces: namespaces) }
    func snapshot(namespaces: [String], requestPaths: [String]) async throws -> CoreSnapshot {
        await pauseIfArmed(onSnapshot: true)
        return try await base.snapshot(namespaces: namespaces, requestPaths: requestPaths)
    }
    func request(configuration: SessionConfiguration, keys: any AsyncKeyProvider) async throws -> AccessRequest { try await base.request(configuration: configuration, keys: keys) }
    // Stay on the worker until the probe runs. Task.immediate can then establish, without a
    // scheduler race, whether a blob read crossed the occupied worker gate.
    nonisolated(nonsending) func query(namespace: String, name: String, arguments: Data) async throws -> Data {
        let overlaps = probe.withLock { state in
            if state.refreshing { state.overlappingQueries += 1; return true }
            return false
        }
        if overlaps { throw BindingError.Poisoned }
        return try await base.query(namespace: namespace, name: name, arguments: arguments)
    }
    func write(_ command: DomainCommand) async throws -> OperationView { try await base.write(command) }
    func approve(_ request: Data, grant: GrantOptions?) async throws { try await base.approve(request, grant: grant) }
    func revoke(_ id: String) async throws { try await base.revoke(id) }
    func importRequest(_ data: Data) async throws -> AccessRequest { try await base.importRequest(data) }
    func approveWithController(_ request: Data, keys: any AsyncKeyProvider) async throws { try await base.approveWithController(request, keys: keys) }
}

@available(macOS 26.0, iOS 26.0, *)
private extension SessionWorker {
    /// Start on the worker executor and run to the first suspension before returning.
    func startRequiredBlobScan() -> Task<[BlobManifestInfo], any Error> {
        Task.immediate { try await self.incompleteRequiredBlobs(namespace: "reading.saved") }
    }
}

private actor SuspendedController: AsyncKeyProvider {
    let base = SoftwareKeys()
    let latch = RefreshLatch()
    private var failAgreement = false
    func arm() { failAgreement = true }
    func publicKeys() async throws -> PublicKeys { try await base.publicKeys() }
    func sign(body: Data) async throws -> Data { try base.sign(body: body) }
    func agree(peer: Data) async throws -> Data {
        if failAgreement {
            await latch.pause()
            throw BindingError.KeyProvider(detail: "Controller locked")
        }
        return try base.agree(peer: peer)
    }
}

@MainActor struct RefreshReadinessTests {
    @available(macOS 26.0, *)
    @available(iOS 26.0, *)
    @Test(.timeLimit(.minutes(1))) func olderRefreshDoesNotEraseControllerFailure() async throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: home) }
        let store = MemoryRecordStore(), owner = SuspendedController()
        let session = ColophonSession(configuration: .init(memberLabel: "Owner", namespaces: ["notes"], location: .memory(store),
            privateContainer: home, keys: SoftwareKeys(), ownerController: owner))
        await session.create()
        try #require(session.phase == .ready)
        let request = try await Library.requestAccess(libraryID: #require(session.libraryID), keys: SoftwareKeys(), label: "Reader",
            kind: .app, namespaces: ["notes"], access: [.read])
        try await store.append(["requests/\(request.id).json": request.record])
        await session.flushExternalChanges()
        let before = try await store.read()
        await owner.arm()
        let approval = Task { try await session.approve(request) }
        await owner.latch.waitUntilEntered()
        // Begin a refresh while approval owns the worker gate and is awaiting its controller.
        let refresh = Task.immediate { await session.refresh() }
        #expect(session.phase == .refreshing)
        await owner.latch.release()
        await #expect(throws: (any Error).self) { try await approval.value }
        await refresh.value
        #expect(try await store.read() == before)
        guard case .failed(.keysUnavailable) = session.phase else {
            Issue.record("An older refresh erased the controller failure: \(session.phase)")
            return
        }
        // A late watcher may begin after the error is already visible; member reads do
        // not exercise the controller that failed, so that refresh must retain the error.
        await session.flushExternalChanges()
        guard case .failed(.keysUnavailable) = session.phase else {
            Issue.record("A later watcher erased the controller failure: \(session.phase)")
            return
        }
        // A fresh, explicit refresh can still recover the member's readable session.
        await session.refresh()
        #expect(session.phase == .ready)
    }

    @available(macOS 26.0, *)
    @available(iOS 26.0, *)
    @Test(.timeLimit(.minutes(1)), arguments: [false, true])
    func blobScanWaitsForRefreshAndVerifiedContentStaysUsable(sourceChanged: Bool) async throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: home) }
        let store = MemoryRecordStore(), core = RefreshProbeCore()
        let configuration = SessionConfiguration(memberLabel: "Owner", namespaces: ["reading.saved"], location: .memory(store),
            privateContainer: home, keys: SoftwareKeys(), ownerController: SoftwareKeys())
        let session = ColophonSession(configuration: configuration, store: store, core: core)
        await session.create()
        try #require(session.phase == .ready)
        let command = try DomainCommand.saveLink(id: "verified", url: #require(URL(string: "https://example.com")), title: "Verified")
        try await session.perform(command, observed: session.observedRevision)
        let links = NamespaceStore<SavedLinksQuery, [SavedLink]>(savedLinksIn: session)
        defer { links.close() }
        #expect(try await links.load(.init()).map(\.id) == ["verified"])
        let observed = session.observedRevision

        // Cover both an unchanged snapshot and a source refresh, as after relay delivery.
        core.arm(onSnapshot: !sourceChanged)
        if sourceChanged {
            let request = try await Library.requestAccess(libraryID: #require(session.libraryID), keys: SoftwareKeys(), label: "Reader",
                kind: .app, namespaces: ["reading.saved"], access: [.read])
            try await store.append(["requests/\(request.id).json": request.record])
        }
        let refresh = Task { await session.flushExternalChanges() }
        await core.latch.waitUntilEntered()
        #expect(session.phase == .refreshing)
        #expect(session.hasUsableContent)
        #expect(links.cached(.init())?.map(\.id) == ["verified"])

        // syncNow does this scan even when the library has no blobs. Before the fix it
        // enters the core during refresh, where the native try_lock refuses the overlap.
        let scan = await session.worker.startRequiredBlobScan()
        let overlaps = core.overlappingQueries
        // A benign no-change refresh must also let an already-observed action complete.
        let action: Task<WriteReceipt, any Error>? = sourceChanged ? nil : Task {
            let bytes = try await session.query(namespace: "reading.saved", name: "read", arguments: Data("{}".utf8))
            #expect(String(decoding: bytes, as: UTF8.self).contains("verified"))
            return try await session.perform(DomainCommand.saveLink(id: "during", url: #require(URL(string: "https://example.com/during")), title: "During"), observed: observed)
        }
        await core.latch.release()
        await refresh.value
        #expect(overlaps == 0)
        #expect(try await scan.value.isEmpty)
        if let action {
            guard case .saved = try await action.value else { Issue.record("In-flight action did not publish"); return }
        }
        #expect(session.hasUsableContent)
        #expect(try await session.query(namespace: "reading.saved", name: "read", arguments: Data("{}".utf8)).isEmpty == false)
        #expect(session.observedRevision.context == observed.context)
        try await session.perform(DomainCommand.saveLink(id: "after", url: #require(URL(string: "https://example.com/after")), title: "After"), observed: session.observedRevision)
        #expect(try await links.load(.init()).map(\.id).sorted() == (sourceChanged ? ["after", "verified"] : ["after", "during", "verified"]))
    }
}
