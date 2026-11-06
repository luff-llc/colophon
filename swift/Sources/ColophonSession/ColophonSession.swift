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
    public private(set) var ledger: [LedgerEntry] = []
    public private(set) var requests: [AccessRequest] = []
    public private(set) var lastError: String?
    public private(set) var context = UUID()
    @ObservationIgnored private let worker: SessionWorker
    @ObservationIgnored private var retryCreate = false
    @ObservationIgnored private var restoreTask: Task<Void, Never>?
    @ObservationIgnored private var watchTask: Task<Void, Never>?
    @ObservationIgnored private var batchTask: Task<Void, Never>?
    @ObservationIgnored private var expiryTask: Task<Void, Never>?
    @ObservationIgnored private var views: [String: NamespaceView] = [:]
    @ObservationIgnored private var caches: [UUID: @MainActor (Set<String>, Bool) -> Void] = [:]

    public init(configuration: SessionConfiguration) { worker = SessionWorker(configuration: configuration) }
    init(configuration: SessionConfiguration, store: any RecordStore, core: any SessionCore = BindingSessionCore()) {
        worker = SessionWorker(configuration: configuration, core: core, store: store)
    }
    deinit { restoreTask?.cancel(); watchTask?.cancel(); batchTask?.cancel(); expiryTask?.cancel() }

    /// A shared completion barrier. Dependent startup work awaits this before using the session.
    public func restore() async {
        if let restoreTask { await restoreTask.value; return }
        let task = Task { [weak self] in
            guard let self else { return }
            await startWatching()
            do { apply(try await worker.restore()) }
            catch { fail(error) }
        }
        restoreTask = task
        await task.value
    }
    public func refresh() async {
        await restore()
        let lease = context
        do {
            let snapshot = try await worker.refresh()
            guard lease == context else { return }
            apply(snapshot)
            await startWatching()
        } catch { if lease == context { fail(error) } }
    }
    public func create() async {
        await restore()
        guard phase == .noLibrary else { return }
        retryCreate = true
        phase = .creating
        do { apply(try await worker.create()); retryCreate = false; await startWatching() }
        catch { fail(error) }
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
        invalidateContext(); phase = .noLibrary
    }
    /// Revoked identities need fresh, independently persisted keys; unchanged requests are immutable.
    public func rejoin(keys: any AsyncKeyProvider) async {
        await restore()
        invalidateContext(); phase = .opening
        do { apply(try await worker.rejoin(keys: keys)); await startWatching() }
        catch { fail(error) }
    }
    public func importRequest(from url: URL) async throws {
        await restore()
        let lease = context
        do { let snapshot = try await worker.importRequest(from: url); if lease == context { apply(snapshot) } }
        catch { if lease == context { handleCommandError(error) }; throw error }
    }
    public func recoveryKeys() async -> (any AsyncKeyProvider)? { await worker.recovery() }

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
    private func apply(_ snapshot: SessionSnapshot) {
        let changed = Set(snapshot.namespaceRevisions.keys.filter { namespaceRevisions[$0] != snapshot.namespaceRevisions[$0] })
        let lost = snapshot.phase != .ready
        phase = snapshot.phase; revision = snapshot.revision; namespaceRevisions = snapshot.namespaceRevisions
        libraryID = snapshot.core?.libraryID ?? libraryID; memberID = snapshot.core?.me.id ?? memberID
        members = snapshot.core?.members ?? []; ledger = snapshot.core?.ledger ?? []; requests = snapshot.core?.requests ?? []
        views = lost ? [:] : snapshot.core?.views ?? [:]
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
        context = UUID(); views = [:]; members = []; ledger = []; requests = []; libraryID = nil; memberID = nil
        for invalidate in caches.values { invalidate([], true) }
    }
    private func handleCommandError(_ error: any Error) {
        if error is AccessError || error is StorageError || error is PendingPublication || error is SessionKeyFailure { fail(error) }
        else { lastError = error.localizedDescription }
    }
    private func fail(_ error: any Error) {
        views = [:]; ledger = []; members = []; requests = []
        for invalidate in caches.values { invalidate([], true) }
        lastError = error.localizedDescription
        switch error {
        case let keys as SessionKeyFailure: phase = .failed(error: .keysUnavailable(detail: keys.detail))
        case let pending as PendingPublication: phase = .unavailable(reason: pending.reason)
        case StorageError.unavailable(let reason): phase = .unavailable(reason: reason)
        case let access as AccessError:
            phase = [.notReadable, .unavailable].contains(access.denial.reason) ? .unavailable(reason: access.denial.detail) : .denied
        default: phase = .failed(error: .other(detail: error.localizedDescription))
        }
    }
    func registerCache(_ callback: @escaping @MainActor (Set<String>, Bool) -> Void) -> UUID {
        let id = UUID(); caches[id] = callback; return id
    }
    func unregisterCache(_ id: UUID) { caches[id] = nil }
    func projection(namespace: String) throws -> Data {
        guard phase == .ready, let view = views[namespace] else { throw SessionError.notReady }
        return view.state
    }
}
