import Foundation
import Observation
import ColophonKit
import ColophonKitStorage

/// Own exactly one instance at the app/process entry point; share it with windows and intents.
@Observable @MainActor public final class ColophonSession {
    public private(set) var phase: SessionPhase = .opening
    public private(set) var revision: UInt64 = 0
    public private(set) var namespaceRevisions: [String: UInt64] = [:]
    public private(set) var libraryID: String?
    public private(set) var memberID: String?
    public private(set) var members: [Member] = []
    private var ledgerValue: [LedgerEntry] = []
    @ObservationIgnored private var ledgerEngine: NativeEngine?
    @ObservationIgnored private var ledgerRevision: UInt64?
    public var ledger: [LedgerEntry] {
        // Legacy whole-history access is explicit; normal session readiness never requests it.
        if let engine = ledgerEngine, ledgerRevision != revision {
            do { ledgerValue = try engine.ledger(); ledgerRevision = revision }
            catch { fail(error) }
        }
        return ledgerValue
    }
    public private(set) var requests: [AccessRequest] = []
    public private(set) var lastError: String?
    public private(set) var context = UUID()
    /// Relay synchronization (spec §8). `.disabled` without a configured relay.
    public private(set) var syncState: RelaySyncState = .disabled
    public private(set) var lastSynced: Date?
    /// Paths whose relay bytes differ from this device's records, from the latest pass.
    public private(set) var syncConflicts: [String] = []
    /// In-progress blob downloads by digest; absent when nothing is downloading.
    public internal(set) var blobDownloads: [String: BlobAvailability] = [:]
    @ObservationIgnored let worker: SessionWorker
    @ObservationIgnored private var retryCreate = false
    @ObservationIgnored private var restoreTask: Task<Void, Never>?
    @ObservationIgnored private var watchTask: Task<Void, Never>?
    @ObservationIgnored private var batchTask: Task<Void, Never>?
    @ObservationIgnored private var expiryTask: Task<Void, Never>?
    @ObservationIgnored private var views: [String: NamespaceView] = [:]
    @ObservationIgnored private var caches: [UUID: @MainActor (Set<String>, Bool) -> Void] = [:]
    @ObservationIgnored private let relay: RelayConfiguration?
    var relayConfigured: Bool { relay != nil }
    @ObservationIgnored private var syncTask: Task<Void, Never>?
    @ObservationIgnored private var requiredBlobsChecked = false
    @ObservationIgnored private let syncSignal = SyncSignal()

    public init(configuration: SessionConfiguration) {
        worker = SessionWorker(configuration: configuration); relay = configuration.relay
        if relay != nil { syncState = .idle }
    }
    init(configuration: SessionConfiguration, store: any RecordStore, core: any SessionCore = BindingSessionCore()) {
        worker = SessionWorker(configuration: configuration, core: core, store: store); relay = configuration.relay
        if relay != nil { syncState = .idle }
    }
    @ObservationIgnored private var checkpointTask: Task<Void, Never>?
    private func scheduleCheckpoint() {
        checkpointTask?.cancel()
        checkpointTask = Task { [weak self] in
            do { try await Task.sleep(for: .seconds(1)); try await self?.worker.saveCheckpoint() }
            catch is CancellationError {}
            catch { self?.fail(error) }
        }
    }
    deinit { checkpointTask?.cancel(); restoreTask?.cancel(); watchTask?.cancel(); batchTask?.cancel(); expiryTask?.cancel(); syncTask?.cancel() }

    /// A shared completion barrier. Dependent startup work awaits this before using the session.
    public func restore() async {
        if let restoreTask { await restoreTask.value; return }
        let task = Task { [weak self] in
            guard let self else { return }
            let lease = context
            await startWatching()
            do {
                let snapshot = try await worker.restore()
                guard lease == context, !Task.isCancelled else { return }
                apply(snapshot)
                scheduleCheckpoint()
            } catch { if lease == context { fail(error) } }
            startSyncLoop()
        }
        restoreTask = task
        await task.value
    }
    public func refresh() async {
        await restore()
        let lease = context
        if phase == .ready { phase = .refreshing }
        do {
            let snapshot = try await worker.refresh()
            guard lease == context, !Task.isCancelled else { return }
            apply(snapshot)
            await startWatching()
        } catch { if lease == context { fail(error) } }
    }
    public func create() async {
        await restore()
        guard phase == .noLibrary else { return }
        retryCreate = true
        phase = .creating
        let lease = context
        do { let snapshot = try await worker.create(); guard lease == context else { return }; apply(snapshot); retryCreate = false; await startWatching() }
        catch { if lease == context { fail(error) } }
    }
    /// Retries the lifecycle action that failed, including an interrupted create.
    public func retry() async {
        await refresh()
        if retryCreate, phase == .noLibrary { await create() }
    }
    /// Durable, non-expiring source-output receipt. Used only by the root migration session.
    public func performMigration(_ command: DomainCommand, outputKey: String) async throws -> WriteReceipt {
        await refresh()
        let lease = context
        do {
            let (receipt, snapshot) = try await worker.write(command, observed: revision, migrationKey: outputKey)
            guard lease == context else { throw SessionError.destinationChanged }
            apply(snapshot); return receipt
        } catch let refusal as SessionRefusal {
            if lease == context { apply(refusal.snapshot); lastError = refusal.error.localizedDescription }
            throw refusal.error
        } catch { if lease == context { handleCommandError(error) }; throw error }
    }
    public var observedRevision: ObservedRevision { .init(context: context, revision: revision) }

    @discardableResult public func perform(_ command: DomainCommand, observed: ObservedRevision) async throws -> WriteReceipt {
        await restore()
        guard observed.context == context else { throw SessionError.destinationChanged }
        do {
            let (receipt, snapshot) = try await worker.write(command, observed: observed.revision)
            guard observed.context == context else { throw SessionError.destinationChanged }
            apply(snapshot); return receipt
        } catch let refusal as SessionRefusal {
            if observed.context == context { apply(refusal.snapshot); lastError = refusal.error.localizedDescription }
            throw refusal.error
        } catch {
            if observed.context == context { handleCommandError(error) }
            throw error
        }
    }
    /// Persist encrypted chunks before the migration publishes their signed manifest.
    public func migrationBlob(namespace: String, mediaType: String, bytes: Data) async throws -> Data {
        await restore()
        let lease = context
        let manifest = try await worker.migrationBlob(namespace: namespace, mediaType: mediaType, bytes: bytes)
        guard lease == context else { throw SessionError.destinationChanged }
        return manifest
    }
    public func approve(_ request: AccessRequest, grant: GrantOptions? = nil) async throws {
        await restore()
        let lease = context
        do { let snapshot = try await worker.approve(request.record, grant: grant); if lease == context { apply(snapshot) } }
        catch { if lease == context { handleCommandError(error) }; throw error }
    }
    public func revoke(memberID: String) async throws {
        await restore()
        let lease = context
        do { let snapshot = try await worker.revoke(memberID); if lease == context { apply(snapshot) } }
        catch { if lease == context { handleCommandError(error) }; throw error }
    }
    /// Leaves locally; does not revoke the member or delete the person's records.
    public func leave() async throws {
        await restore()
        try await worker.leave()
        stopSync()
        invalidateContext(); phase = .noLibrary
    }
    /// Revoked identities need fresh, independently persisted keys; unchanged requests are immutable.
    public func rejoin(keys: any AsyncKeyProvider) async {
        await restore()
        invalidateContext(); phase = .opening
        let lease = context
        do { let snapshot = try await worker.rejoin(keys: keys); guard lease == context else { return }; apply(snapshot); await startWatching(); startSyncLoop() }
        catch { if lease == context { fail(error) } }
    }
    public func importRequest(from url: URL) async throws {
        await restore()
        let lease = context
        do { let snapshot = try await worker.importRequest(from: url); if lease == context { apply(snapshot) } }
        catch { if lease == context { handleCommandError(error) }; throw error }
    }
    /// Reads a bounded core query. Results are fenced against namespace and identity changes.
    public func query(namespace: String, name: String, arguments: Data) async throws -> Data {
        await restore()
        guard phase == .ready || phase == .refreshing else { throw SessionError.notReady }
        let lease = context
        let observed = namespaceRevisions[namespace, default: 0]
        do {
            let bytes = try await worker.query(namespace: namespace, name: name, arguments: arguments)
            guard context == lease, (phase == .ready || phase == .refreshing),
                  namespaceRevisions[namespace, default: 0] == observed else { throw SessionError.staleRevision }
            return bytes
        } catch {
            if context == lease { handleCommandError(error) }
            throw error
        }
    }

    public func recoveryKeys() async -> (any AsyncKeyProvider)? { await worker.recovery() }

    /// Runs one relay pass now (list, pull, push) and refreshes when records arrived. A barrier
    /// for tests and for hosts that sync on foreground entry. Returns false when the pass failed.
    @discardableResult public func syncNow() async -> Bool {
        guard relay != nil else { return false }
        await restore()
        if syncState != .syncing { syncState = .syncing }
        do {
            let report = try await worker.syncRelay()
            syncConflicts = report?.conflicts ?? []
            lastSynced = .now
            if let first = report?.conflicts.first {
                syncState = .error(reason: "The relay holds different bytes for \(first)")
            } else { syncState = .idle }
            // Pulled records reach the core exactly like another process's folder writes.
            if (report?.pulled ?? 0) > 0 || phase != .ready { await refresh() }
            if (report?.pulled ?? 0) > 0 || !requiredBlobsChecked {
                requiredBlobsChecked = true
                await downloadRequiredBlobs()
            }
            return true
        } catch is CancellationError {
            return false
        } catch let error as RelayError {
            switch error {
            case .offline(let reason): syncState = .offline(reason: reason)
            case .unauthorized: syncState = .unauthorized
            case .busy: syncState = .offline(reason: error.localizedDescription)
            default: syncState = .error(reason: error.localizedDescription)
            }
            return false
        } catch {
            syncState = .error(reason: error.localizedDescription)
            if error is SessionLayoutError { fail(error) }
            return false
        }
    }

    /// Wakes the background sync loop, for example after a host learns the network returned.
    public func requestSync() { Task { await syncSignal.fire() } }

    /// Stops background relay sync. Local storage and the session keep working.
    public func stopSync() { syncTask?.cancel(); syncTask = nil }

    private func startSyncLoop() {
        guard let relay, relay.automatic, syncTask == nil else { return }
        syncTask = Task { [weak self] in
            var failures = 0
            while !Task.isCancelled {
                guard let self else { return }
                let ok = await self.syncNow()
                let unauthorized = self.syncState == .unauthorized
                failures = ok ? 0 : failures + 1
                let signal = self.syncSignal, worker = self.worker
                // Success: long-poll the relay or wait for a local change. Failure: capped,
                // jittered exponential backoff that a local change or requestSync() cuts short.
                let backoff = unauthorized ? 300.0 : min(60.0, pow(2.0, Double(max(0, failures - 1)))) * Double.random(in: 0.5...1.0)
                await withTaskGroup(of: Void.self) { group in
                    group.addTask { await signal.wait() }
                    group.addTask {
                        if ok {
                            let started = ContinuousClock.now
                            let changed = (try? await worker.waitForRemoteChanges(seconds: 25)) ?? false
                            // A relay that answers at once without long-polling is polled instead.
                            if !changed, ContinuousClock.now - started < .seconds(2) { try? await Task.sleep(for: .seconds(15)) }
                        } else { try? await Task.sleep(for: .seconds(backoff)) }
                    }
                    await group.next(); group.cancelAll()
                }
            }
        }
    }

    /// Returns per-envelope outcomes; invalid items stay queued for user review, never acknowledged.
    public func drain(_ inbox: IngressInbox) async throws -> [UUID: WriteReceipt] {
        await refresh()
        guard phase == .ready else { throw SessionError.notReady }
        let lease = context
        var results: [UUID: WriteReceipt] = [:]
        for envelope in try await inbox.pending() {
            guard lease == context else { throw SessionError.destinationChanged }
            do {
                let (receipt, snapshot) = try await worker.write(envelope.command, observed: revision, ingress: envelope)
                guard lease == context else { throw SessionError.destinationChanged }
                apply(snapshot)
                if case .saved = receipt { try await inbox.acknowledge(envelope) }
                results[envelope.id] = receipt
            } catch let refusal as SessionRefusal {
                apply(refusal.snapshot); lastError = refusal.error.localizedDescription; results[envelope.id] = .queued
            } catch { handleCommandError(error); results[envelope.id] = .queued }
        }
        return results
    }
    private func startWatching() async {
        guard watchTask == nil else { return }
        do {
            let stream = try await worker.changes()
            watchTask = Task { [weak self] in
                for await _ in stream {
                    guard !Task.isCancelled else { break }
                    self?.externalChange()
                }
            }
        } catch { lastError = error.localizedDescription }
    }
    /// A bounded notification stream plus one trailing batch task coalesces file bursts.
    func externalChange() {
        guard batchTask == nil else { return }
        batchTask = Task { [weak self] in
            do { try await Task.sleep(for: .milliseconds(75)) } catch { return }
            guard let self else { return }
            batchTask = nil
            await refresh()
        }
    }
    /// Deterministic batch barrier for hosts/tests; no timing-based polling is required.
    public func flushExternalChanges() async {
        batchTask?.cancel(); batchTask = nil
        await refresh()
    }
    public var hasUsableContent: Bool { !views.isEmpty && [.ready, .refreshing, .waitingForDownload, .retry].contains(phase) }
    private func apply(_ snapshot: SessionSnapshot) {
        guard snapshot.revision >= revision else { return }
        if relay != nil, snapshot.revision != revision || snapshot.phase != phase { Task { [syncSignal] in await syncSignal.fire() } }
        let changed = Set(snapshot.namespaceRevisions.keys.filter { namespaceRevisions[$0] != snapshot.namespaceRevisions[$0] })
        let lost = ![SessionPhase.ready, .refreshing, .waitingForDownload, .retry].contains(snapshot.phase)
        phase = snapshot.phase; revision = snapshot.revision; namespaceRevisions = snapshot.namespaceRevisions
        libraryID = snapshot.core?.libraryID ?? libraryID; memberID = snapshot.core?.me.id ?? memberID
        members = snapshot.core?.members ?? []; ledgerValue = snapshot.core?.ledger ?? []; ledgerEngine = lost ? nil : snapshot.core?.engine; ledgerRevision = nil; requests = snapshot.core?.requests ?? []
        views = lost ? [:] : snapshot.core?.views ?? [:]
        if !lost { scheduleCheckpoint() }
        for invalidate in caches.values { invalidate(changed, lost) }
        expiryTask?.cancel(); expiryTask = nil
        if let expires = snapshot.core?.me.grant?.expires,
           let date = try? Date(expires, strategy: .iso8601), date > .now {
            expiryTask = Task { [weak self] in
                do { try await Task.sleep(for: .seconds(max(0, date.timeIntervalSinceNow))) } catch { return }
                await self?.refresh()
            }
        }
        lastError = nil
    }
    private func invalidateContext() {
        context = UUID(); views = [:]; members = []; ledgerValue = []; ledgerEngine = nil; requests = []; libraryID = nil; memberID = nil
        for invalidate in caches.values { invalidate([], true) }
    }
    private func handleCommandError(_ error: any Error) {
        if error is AccessError || error is StorageError || error is PendingPublication || error is SessionKeyFailure || error is SessionLayoutError { fail(error) }
        else { lastError = error.localizedDescription }
    }
    private func fail(_ error: any Error) {
        if error is CancellationError { return }
        lastError = error.localizedDescription
        switch error {
        case SessionLayoutError.updateRequired:
            phase = .updateRequired
            return
        case let keys as SessionKeyFailure: phase = .failed(error: .keysUnavailable(detail: keys.detail))
        case is PendingPublication:
            phase = .retry
            return
        case StorageError.unavailable(let reason):
            if reason.contains("download pending") || reason.contains("Waiting for the relay") {
                phase = .waitingForDownload
                return
            }
            phase = .retry
            return
        case let access as AccessError:
            phase = [.notReadable, .unavailable].contains(access.denial.reason) ? .unavailable(reason: access.denial.detail) : .denied
        default: phase = .failed(error: .other(detail: error.localizedDescription))
        }
        views = [:]; ledgerValue = []; ledgerEngine = nil; members = []; requests = []
        for invalidate in caches.values { invalidate([], true) }
    }
    func registerCache(_ callback: @escaping @MainActor (Set<String>, Bool) -> Void) -> UUID {
        let id = UUID(); caches[id] = callback; return id
    }
    func unregisterCache(_ id: UUID) { caches[id] = nil }
    func projection(namespace: String) async throws -> Data {
        try await query(namespace: namespace, name: "read", arguments: Data("{}".utf8))
    }
    /// Persist acceleration state in the private cache, after durable publication.
    public func flushCheckpoint() async throws { checkpointTask?.cancel(); checkpointTask = nil; try await worker.saveCheckpoint() }

}

/// A one-shot wake-up for the sync loop. Firing while nobody waits is remembered once.
actor SyncSignal {
    private var pending = false
    private var waiter: CheckedContinuation<Void, Never>?
    func fire() {
        if let waiter { self.waiter = nil; waiter.resume() } else { pending = true }
    }
    func wait() async {
        if pending { pending = false; return }
        await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                if Task.isCancelled || pending { pending = false; continuation.resume() } else {
                    waiter?.resume(); waiter = continuation
                }
            }
        } onCancel: { Task { await self.cancelWait() } }
    }
    private func cancelWait() { waiter?.resume(); waiter = nil }
}
