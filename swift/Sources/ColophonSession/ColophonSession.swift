import Foundation
import Observation

/// Own exactly one instance at the app/process entry point; share it with windows and intents.
///
/// The session is the actor an app holds over one Colophon 0.5 account: it opens the account's records,
/// unlocks this device's member, keeps the engine fresh as the folder and the homes change, performs
/// writes with observed revisions, and surfaces what a person must see (pending changes, unseen
/// activations, "this account has no home", update required). Every engine call, key ceremony and file
/// operation runs off the main actor in `SessionWorker`; this type only holds published state.
@Observable @MainActor public final class ColophonSession {
    public private(set) var phase: SessionPhase = .opening
    public private(set) var revision: UInt64 = 0
    public private(set) var namespaceRevisions: [String: UInt64] = [:]
    public private(set) var libraryID: String?
    public private(set) var memberID: String?
    /// New in 0.5: `AccountMember` (the 0.4 `Member` record is the old export's).
    public private(set) var members: [AccountMember] = []
    public private(set) var requests: [AccessRequest] = []
    public private(set) var lastError: String?
    public private(set) var context = UUID()
    /// What a person must be shown (§17.5, §18). `notices.noHome` is the "this account has no home" warning.
    public private(set) var notices: SessionNotices = .empty
    /// Homes the account names.
    public private(set) var homes: [Home] = []
    /// What the host must do and say beyond `notices` (§17.5): the sole-device warning, delivery routes per home, the
    /// outcome of each submission, dead transitions, the poll interval.
    public private(set) var duties: HostDuties = .none
    @ObservationIgnored private var submissions: [String: Submission] = [:]
    /// Home exchange state. `.disabled` without a configured home.
    public private(set) var syncState: HomeSyncState = .disabled
    public private(set) var lastSynced: Date?
    /// Faults of the latest exchange: what a home did that the engine did not follow.
    public private(set) var homeFaults: [HomeFault] = []
    /// What this host refused about a home in the latest exchange (an endpoint that is not `https`, a response over its
    /// bound, a pass over its step or time budget, a call it could not bind to its request).
    public private(set) var homeIssues: [HomeIssue] = []
    /// In-progress blob downloads by digest; absent when nothing is downloading.
    public internal(set) var blobDownloads: [String: BlobAvailability] = [:]
    @ObservationIgnored let worker: SessionWorker
    @ObservationIgnored private var restoreTask: Task<Void, Never>?
    @ObservationIgnored private var watchTask: Task<Void, Never>?
    @ObservationIgnored private var batchTask: Task<Void, Never>?
    @ObservationIgnored private var syncTask: Task<Void, Never>?
    @ObservationIgnored private var dueTask: Task<Void, Never>?
    @ObservationIgnored private(set) var checkpointTask: Task<Void, Never>?
    @ObservationIgnored private var usable = false
    @ObservationIgnored private var caches: [UUID: @MainActor (Set<String>, Bool) -> Void] = [:]
    @ObservationIgnored private let homesConfigured: Bool
    @ObservationIgnored private let syncSignal = SyncSignal()
    @ObservationIgnored private var commandFailureRevision: UInt64 = 0
    @ObservationIgnored private var retryCreate = false

    public init(configuration: SessionConfiguration) {
        worker = SessionWorker(configuration: configuration); homesConfigured = !configuration.homes.isEmpty
        if homesConfigured { syncState = .idle }
    }
    deinit { checkpointTask?.cancel(); restoreTask?.cancel(); watchTask?.cancel(); batchTask?.cancel(); syncTask?.cancel(); dueTask?.cancel() }
    var relayConfigured: Bool { homesConfigured }

    private func scheduleCheckpoint() {
        checkpointTask?.cancel()
        checkpointTask = Task { [weak self] in
            do { try await Task.sleep(for: .seconds(1)); try await self?.worker.saveCheckpoint() }
            catch is CancellationError {}
            catch { self?.lastError = error.localizedDescription }
        }
    }

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
            } catch { if lease == context { fail(error) } }
            startSyncLoop(); startDueLoop()
        }
        restoreTask = task
        await task.value
    }
    public func refresh() async { await refresh(preservingCommandFailure: false) }
    private func refresh(preservingCommandFailure: Bool) async {
        await restore()
        let lease = context
        let failureRevision = commandFailureRevision
        if phase == .ready { phase = .refreshing }
        do {
            let snapshot = try await worker.refresh()
            guard lease == context, !Task.isCancelled else { return }
            if snapshot.phase == .ready, failureRevision != commandFailureRevision { return }
            apply(snapshot)
            await startWatching()
        } catch { if lease == context, failureRevision == commandFailureRevision { fail(error) } }
    }
    /// Creates the account for this device: the owner controller, this device's member, and (spec §18) the
    /// configured homes appointed at once. A passkey owner is asked more than once at first run (see
    /// `docs/session.md`); the second unlock is one function and goes away with the engine constructor
    /// over a created account.
    public func create() async {
        await restore()
        guard phase == .noLibrary else { return }
        retryCreate = true
        phase = .creating
        let lease = context
        do {
            let snapshot = try await worker.create()
            guard lease == context else { return }
            apply(snapshot); retryCreate = false; await startWatching(); startSyncLoop(); startDueLoop()
            if homesConfigured, let registered = try? await worker.registerRoutes() { apply(registered) }
        } catch {
            if lease == context {
                if case SessionError.noHome = error { retryCreate = false; lastError = error.localizedDescription; phase = .noLibrary }
                else { fail(error) }
            }
        }
    }
    /// Retries the lifecycle action that failed, including an interrupted create.
    public func retry() async {
        await refresh()
        if retryCreate, phase == .noLibrary { await create() }
    }
    public var observedRevision: ObservedRevision { .init(context: context, revision: revision) }

    @discardableResult public func perform(_ command: DomainCommand, observed: ObservedRevision) async throws -> WriteReceipt {
        await restore()
        guard observed.context == context else { throw SessionError.destinationChanged }
        do {
            let (receipt, snapshot) = try await worker.write(command, observed: observed.revision)
            guard observed.context == context else { throw SessionError.destinationChanged }
            apply(snapshot)
            if homesConfigured { requestSync() }
            return receipt
        } catch let refusal as SessionRefusal {
            if observed.context == context { apply(refusal.snapshot); lastError = refusal.error.localizedDescription }
            throw refusal.error
        } catch {
            if observed.context == context { handleCommandError(error) }
            throw error
        }
    }
    /// Approves a member's request with the owner controller (a passkey owner is asked to confirm).
    public func approve(_ request: AccessRequest, grant: GrantOptions? = nil) async throws {
        await restore()
        let lease = context
        do {
            let terms = grant.map { options in
                SessionWorker.terms(namespaces: options.namespaces ?? worker.configuration.namespaces,
                                    access: options.access ?? [.read, .write], expires: options.expires, budget: options.writeBudget)
            }
            let snapshot = try await worker.approve(request, terms: terms)
            if lease == context { apply(snapshot) }
        } catch { if lease == context { handleCommandError(error) }; throw error }
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
    /// Takes a request that arrived out of band (a file, AirDrop, a code) and shows it for approval. The file is read
    /// on a background executor, never on the main actor.
    public func importRequest(from url: URL) async throws { try await importRequest(try await BlobIO.readRequest(url)) }
    public func importRequest(_ data: Data) async throws {
        await restore()
        let lease = context
        do { let snapshot = try await worker.importRequest(data); if lease == context { apply(snapshot) } }
        catch { if lease == context { handleCommandError(error) }; throw error }
    }
    /// This device's own signed membership request, to hand to an approver (a QR code, a file).
    public func exportRequest() async throws -> Data { await restore(); return try await worker.exportRequest() }

    /// Reads a bounded core query. Results are fenced against namespace and identity changes.
    public func query(namespace: String, name: String, arguments: Data) async throws -> Data {
        await restore()
        guard hasUsableContent else { throw SessionError.notReady }
        let lease = context
        let observed = namespaceRevisions[namespace, default: 0]
        do {
            let bytes = try await worker.query(namespace: namespace, name: name, arguments: arguments)
            guard context == lease, hasUsableContent, namespaceRevisions[namespace, default: 0] == observed else { throw SessionError.staleRevision }
            return bytes
        } catch {
            if context == lease { handleCommandError(error) }
            throw error
        }
    }
    /// The verified history as the engine reports it (JSON). Explicit: normal screens use named queries.
    public func ledger() async throws -> Data { await restore(); return try await worker.ledger() }

    // MARK: Adding a device, pending changes

    /// Adds a controller key (a second device's owner key, a passkey, a security key). The owner confirms.
    public func addController(_ key: any AsyncKeyProvider, label: String, roles: [ControllerRole] = [.approve], immediate: Bool = true) async throws {
        await restore()
        let descriptor = try await key.keyDescriptor()
        let spec = ControllerSpec(key: descriptor, label: label, roles: roles, verification: descriptor.form == .webauthn, holder: nil, audiences: [])
        do { apply(try await worker.addController(spec, mode: immediate ? .immediate : .transition, possession: key)) } catch { handleCommandError(error); throw error }
    }
    /// The existing device's half of "add a device": after both screens showed the same digits, seals the
    /// vault seed to the new device. See `AccountPairing`.
    public func transferSeed(pairing: AccountPairing) async throws -> SealedSeed { await restore(); return try await worker.transferSeed(pairing: pairing) }
    /// The new device's half: takes the sealed seed and builds this controller's own slot.
    public func acceptSeedTransfer(key: PairingTransferKey, pairing: AccountPairing, sealed: SealedSeed, label: String) async throws {
        await restore()
        do { apply(try await worker.acceptSeedTransfer(key: key, pairing: pairing, sealed: sealed, label: label)) }
        catch { handleCommandError(error); throw error }
    }
    /// One call to veto a pending transition (§17.5): signs with the keys this device holds, stores the
    /// veto, and submits it to every home, retrying until each has receipted it or 300 s have passed.
    public func veto(_ transition: String) async throws {
        await restore()
        do { apply(try await worker.veto(transition)) } catch { handleCommandError(error); throw error }
        await submitUntilReceipted(transition, kind: .veto)
    }
    /// Proposes a change to the account (spec §8.7: homes, keyring, policy), signed with the owner's keys, and submits it
    /// to every current home, retrying until each has receipted it or 300 s have passed (`duties.submissions`).
    @discardableResult public func proposeTransition(_ changeJSON: String) async throws -> String {
        await restore()
        let digest: String
        do { let (d, snapshot) = try await worker.submitTransition(changeJSON); digest = d; apply(snapshot) } catch { handleCommandError(error); throw error }
        await submitUntilReceipted(digest, kind: .transition)
        return digest
    }
    /// Signs a dead transition this device signed again (§17.5 quorum rule) and submits the new one.
    @discardableResult public func resign(_ transition: String) async throws -> String {
        await restore()
        let digest: String
        do { let (d, snapshot) = try await worker.resign(transition); digest = d; apply(snapshot) } catch { handleCommandError(error); throw error }
        await submitUntilReceipted(digest, kind: .transition)
        return digest
    }
    /// Suspends `key` while `transition` is pending (§8.7), and submits it to every home like a veto.
    public func suspend(key: String, while transition: String) async throws {
        await restore()
        let digest: String
        do { let (d, snapshot) = try await worker.suspend(key: key, transition: transition); digest = d; apply(snapshot) } catch { handleCommandError(error); throw error }
        await submitUntilReceipted(digest, kind: .suspend)
    }
    /// Records that the person has seen one activation (`notices.unseenActivations`). It marks that activation only:
    /// a pending transition stays in `notices.pending` until it is vetoed, activates or is dead.
    public func acknowledgeActivation(seq: UInt64) async {
        do { apply(try await worker.acknowledgeActivation(seq: seq)) } catch { lastError = error.localizedDescription }
    }
    /// How many homes hold a verified receipt for a transition, out of how many the account names.
    public func receipts(for object: String) async throws -> (receipted: Int, homes: Int) { try await worker.receipts(for: object) }

    /// §17.5 submission: an exchange with every home (which submits pending objects to each directly), repeated until
    /// each home has receipted the object or `deadline` has passed. The outcome is published in `duties.submissions`.
    func submitUntilReceipted(_ object: String, kind: Submission.Kind, deadline: Duration = .seconds(300)) async {
        guard homesConfigured, !object.isEmpty else { return }
        let end = ContinuousClock.now + deadline
        var delay = 0.5
        var last = Submission(object: object, kind: kind, receipted: 0, homes: homes.count, finished: false)
        record(last)
        while ContinuousClock.now < end, !Task.isCancelled {
            _ = await syncNow()
            if let counts = try? await worker.receipts(for: object) {
                last = Submission(object: object, kind: kind, receipted: counts.receipted, homes: counts.homes, finished: false)
                record(last)
                if counts.homes == 0 || counts.receipted >= counts.homes { break }
            }
            try? await Task.sleep(for: .seconds(delay)); delay = min(delay * 2, 15)
        }
        record(Submission(object: object, kind: kind, receipted: last.receipted, homes: last.homes, finished: true))
    }
    private func record(_ submission: Submission) {
        submissions[submission.object] = submission
        duties.submissions = submissions.values.sorted { $0.object < $1.object }
    }

    // MARK: Lock

    /// Hides the content and drops every secret the engine holds: call it when the app enters the background.
    /// `unlock()` opens it again (`LibraryGate` calls it on foreground entry); `restore()` and `refresh()` leave a locked session locked.
    public func lock() async {
        guard let snapshot = try? await worker.lock() else { return }
        usable = false; apply(snapshot)
    }
    public func unlock() async {
        let lease = context
        do { let snapshot = try await worker.unlock(); guard lease == context else { return }; apply(snapshot); await startWatching() }
        catch { if lease == context { fail(error) } }
    }

    // MARK: Exchange with the homes

    /// Runs one exchange pass with every home now and refreshes when something arrived. Returns false when it failed.
    @discardableResult public func syncNow() async -> Bool {
        guard homesConfigured else { return false }
        // Passes never overlap: a caller waits for the pass in flight, then runs its own.
        let previous = syncChain
        let task = Task { [weak self] () -> Bool in
            _ = await previous?.value
            return await self?.runSync() ?? false
        }
        syncChain = task
        return await task.value
    }
    @ObservationIgnored private var syncChain: Task<Bool, Never>?
    private func runSync() async -> Bool {
        await restore()
        if syncState != .syncing { syncState = .syncing }
        do {
            let result = try await worker.exchange()
            homeFaults = result.faults; homeIssues = result.issues
            lastSynced = .now
            syncState = result.unauthorized ? .unauthorized : .idle
            if result.changed || phase != .ready { await refresh(preservingCommandFailure: true) }
            else if let snapshot = try? await worker.currentSnapshot() { apply(snapshot) }
            return !result.unauthorized
        } catch is CancellationError {
            return false
        } catch let error as HomeTransportError {
            if case .offline(let reason) = error { syncState = .offline(reason: reason) } else { syncState = .error(reason: error.localizedDescription) }
            return false
        } catch let error as ColophonError {
            syncState = .error(reason: error.localizedDescription)
            if error.isNewerFormat { fail(error) }
            return false
        } catch {
            syncState = .error(reason: error.localizedDescription)
            return false
        }
    }

    /// Wakes the background exchange loop, for example after a host learns the network returned.
    public func requestSync() { Task { await syncSignal.fire() } }
    /// Stops the background exchange. Local storage and the session keep working.
    public func stopSync() { syncTask?.cancel(); syncTask = nil; dueTask?.cancel(); dueTask = nil }

    private func startSyncLoop() {
        guard homesConfigured, syncTask == nil else { return }
        syncTask = Task { [weak self] in
            var failures = 0
            while !Task.isCancelled {
                guard let self else { return }
                let ok = await self.syncNow()
                failures = ok ? 0 : failures + 1
                let signal = self.syncSignal
                // Success: poll again after `duties.pollInterval` (recoveryDelay / 6, as §17.5 asks at least; 15 s while a
                // change is pending) or when a local change arrives. Failure: capped, jittered exponential backoff.
                let interval = self.duties.pollInterval.components
                let poll = Double(interval.seconds) + Double(interval.attoseconds) / 1e18
                let wait = ok ? poll : min(60.0, pow(2.0, Double(max(0, failures - 1)))) * Double.random(in: 0.5...1.0)
                await withTaskGroup(of: Void.self) { group in
                    group.addTask { await signal.wait() }
                    group.addTask { try? await Task.sleep(for: .seconds(wait)) }
                    await group.next(); group.cancelAll()
                }
            }
        }
    }
    /// `record_due` on a schedule: transitions that came due are recorded without waiting for a pass.
    private func startDueLoop() {
        guard dueTask == nil else { return }
        dueTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(60))
                guard let self, !Task.isCancelled else { return }
                if self.phase == .ready, let snapshot = try? await self.worker.recordDue() { self.apply(snapshot) }
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
                for await _ in stream { guard !Task.isCancelled else { break }; self?.externalChange() }
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
            await refresh(preservingCommandFailure: true)
        }
    }
    /// Deterministic batch barrier for hosts/tests; no timing-based polling is required.
    public func flushExternalChanges() async {
        batchTask?.cancel(); batchTask = nil
        await refresh(preservingCommandFailure: true)
    }
    public var hasUsableContent: Bool { usable && [.ready, .refreshing, .waitingForDownload, .retry].contains(phase) }

    private func apply(_ snapshot: SessionSnapshot) {
        guard snapshot.revision >= revision else { return }
        if homesConfigured, snapshot.revision != revision || snapshot.phase != phase { Task { [syncSignal] in await syncSignal.fire() } }
        let changed = Set(snapshot.namespaceRevisions.keys.filter { namespaceRevisions[$0] != snapshot.namespaceRevisions[$0] })
        let lost = !snapshot.usable
        phase = snapshot.phase; revision = snapshot.revision; namespaceRevisions = snapshot.namespaceRevisions
        libraryID = snapshot.libraryID ?? libraryID; memberID = snapshot.memberID ?? memberID
        members = snapshot.members; requests = snapshot.requests; notices = snapshot.notices; homes = snapshot.homes
        var duties = snapshot.duties; duties.submissions = submissions.values.sorted { $0.object < $1.object }; self.duties = duties
        usable = !lost
        if !lost { scheduleCheckpoint() }
        for invalidate in caches.values { invalidate(changed, lost) }
        lastError = nil
    }
    private func invalidateContext() {
        context = UUID(); usable = false; members = []; requests = []; libraryID = nil; memberID = nil; notices = .empty
        for invalidate in caches.values { invalidate([], true) }
    }
    private func handleCommandError(_ error: any Error) {
        switch error {
        case ColophonError.denied:
            // A refused command does not decide the phase: the engine's access check does, on the next refresh (a read-only
            // member keeps reading; a revoked one becomes `denied` there).
            lastError = error.localizedDescription
            Task { await refresh(preservingCommandFailure: false) }
        case is ColophonError, is StorageError, is SessionKeyFailure, is KeyCustodyError:
            commandFailureRevision &+= 1
            fail(error)
        default: lastError = error.localizedDescription
        }
    }
    private func fail(_ error: any Error) {
        if error is CancellationError { return }
        lastError = error.localizedDescription
        switch error {
        case let colophon as ColophonError:
            switch colophon {
            case .newerFormat: phase = .updateRequired; usable = false; return
            case .denied(_, let reason, _, let detail):
                phase = [.notReadable, .unavailable].contains(reason) ? .unavailable(reason: detail) : .denied
            case .host, .unavailable, .reentered, .integrity: phase = .retry; return
            case .locked: phase = .locked
            default: phase = .failed(error: .other(detail: colophon.localizedDescription))
            }
        case let keys as SessionKeyFailure: phase = .failed(error: .keysUnavailable(detail: keys.detail))
        case is KeyCustodyError: phase = .failed(error: .keysUnavailable(detail: error.localizedDescription))
        case StorageError.unavailable(let reason):
            phase = reason.contains("download pending") ? .waitingForDownload : .retry
            return
        case is StorageError: phase = .retry; return
        default: phase = .failed(error: .other(detail: error.localizedDescription))
        }
        usable = false
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
    func fire() { if let waiter { self.waiter = nil; waiter.resume() } else { pending = true } }
    func wait() async {
        if pending { pending = false; return }
        await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                if Task.isCancelled || pending { pending = false; continuation.resume() } else { waiter?.resume(); waiter = continuation }
            }
        } onCancel: { Task { await self.cancelWait() } }
    }
    private func cancelWait() { waiter?.resume(); waiter = nil }
}
