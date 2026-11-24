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
    /// Whether this session has any home transports configured.
    public var hasConfiguredHomes: Bool { homesConfigured }
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
    @ObservationIgnored private(set) var watchTask: Task<Void, Never>?
    @ObservationIgnored private(set) var batchTask: Task<Void, Never>?
    @ObservationIgnored private(set) var syncTask: Task<Void, Never>?
    @ObservationIgnored private(set) var dueTask: Task<Void, Never>?
    @ObservationIgnored private var stoppedSyncTask: Task<Void, Never>?
    @ObservationIgnored private var stoppedDueTask: Task<Void, Never>?
    @ObservationIgnored private var dueWork: Task<Void, Never>?
    @ObservationIgnored private var refreshWaiters: [UUID: [CheckedContinuation<Void, Never>]] = [:]
    @ObservationIgnored private var batchNeedsRefresh = false
    @ObservationIgnored private var syncPaused = false
    private var suspended = false
    @ObservationIgnored private var lockTask: Task<Void, Never>?
    @ObservationIgnored private var lockGeneration: UInt64 = 0
    @ObservationIgnored private(set) var checkpointTask: Task<Void, Never>?
    @ObservationIgnored private var usable = false
    @ObservationIgnored private var caches: [UUID: @MainActor (Set<String>, Bool) -> Void] = [:]
    @ObservationIgnored private var homesConfigured: Bool
    @ObservationIgnored private let syncSignal = SyncSignal()
    @ObservationIgnored private var commandFailureRevision: UInt64 = 0
    /// Counts the refreshes that moved `ready` to `refreshing`; only the latest such refresh puts `ready` back.
    @ObservationIgnored private var refreshMark: UInt64 = 0
    /// The refresh a refused command started (`handleCommandError`), for hosts and tests that must see its outcome.
    @ObservationIgnored private(set) var refusalRefresh: Task<Void, Never>?
    /// A test seam: awaited by every refresh after the worker answered and before its outcome is published. Nil outside tests.
    @ObservationIgnored var refreshWillFinish: (@MainActor () async throws -> Void)?
    @ObservationIgnored private var retryCreate = false

    public init(configuration: SessionConfiguration) {
        worker = SessionWorker(configuration: configuration); homesConfigured = !configuration.homes.isEmpty
        if homesConfigured { syncState = .idle }
    }
    deinit { checkpointTask?.cancel(); restoreTask?.cancel(); watchTask?.cancel(); batchTask?.cancel(); syncTask?.cancel(); dueTask?.cancel() }
    var relayConfigured: Bool { homesConfigured }

    private func scheduleCheckpoint() {
        guard !suspended else { return }
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
        guard !suspended else { return }
        let lease = context, generation = lockGeneration
        let task = Task { [weak self] in
            guard let self else { return }
            await startWatching()
            guard canPublish(lease, generation) else { return }
            do {
                let snapshot = try await worker.restore()
                guard canPublish(lease, generation), !Task.isCancelled else { return }
                apply(snapshot)
            } catch { if canPublish(lease, generation) { fail(error) } }
            startSyncLoop(); startDueLoop()
        }
        restoreTask = task
        await task.value
    }
    public func refresh() async { await refresh(coalescing: false) }
    /// `coalescing`: a refresh for a hint (the folder watcher, the end of an exchange) while the session is ready lists
    /// the folder once and reconciles only when it holds something the engine has not read, or the engine holds
    /// something not yet shown (`SessionWorker.refreshIfStale`). Any other phase takes the full refresh.
    private func refresh(coalescing: Bool) async {
        guard !suspended, !Task.isCancelled else { return }
        let id = UUID(), lease = context, lockEpoch = lockGeneration
        refreshWaiters[id] = []
        defer {
            if let waiters = refreshWaiters.removeValue(forKey: id) {
                for waiter in waiters { waiter.resume() }
            }
        }
        await restore()
        guard canPublish(lease, lockEpoch), !Task.isCancelled else { return }
        let failureRevision = commandFailureRevision
        let marked = phase == .ready
        if marked { phase = .refreshing; refreshMark &+= 1 }
        // This refresh's generation. A refresh that a newer one has since re-marked is stale: its outcome (snapshot or
        // error) is dropped and the phase follows the newer one.
        let generation = refreshMark
        var current: Bool { generation == refreshMark && canPublish(lease, lockEpoch) }
        // A finished refresh never leaves the phase at `refreshing`: whatever path ends it (cancelled, a snapshot apply()
        // ignored, a command failure that set no phase), the phase this refresh replaced comes back.
        defer { if marked, current, phase == .refreshing { phase = .ready } }
        // A command that failed while this refresh was in flight keeps the phase its failure set; a failure that set none
        // leaves the refresh's own outcome to decide.
        var failureHoldsPhase: Bool { failureRevision != commandFailureRevision && phase != .refreshing }
        do {
            // Only a refresh with no other in flight answers from the folder mark: one that re-marks over an unmarked
            // refresh makes that one stale, so it must bring a snapshot of its own.
            let coalesce = coalescing && marked && refreshWaiters.count == 1
            let fresh = coalesce ? try await worker.refreshIfStale() : try await worker.refresh()
            try await refreshWillFinish?()
            guard current, !Task.isCancelled else { return }
            // Nothing new: what is shown is current.
            guard let snapshot = fresh else { return }
            if snapshot.phase == .ready, failureHoldsPhase { return }
            apply(snapshot)
            await startWatching()
        } catch { if current, !Task.isCancelled, !failureHoldsPhase { fail(error) } }
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

    /// `claimed`, when given, is the operation's signed `created` instead of now: an app importing old data (a
    /// note written years ago) keeps each item's original date, which rows such as a note's `created` show.
    /// Order stays logical; only that date changes. A claimed date later than now is `SessionError.invalidCommand`.
    @discardableResult public func perform(_ command: DomainCommand, observed: ObservedRevision, claimed: Date? = nil) async throws -> WriteReceipt {
        await restore()
        guard observed.context == context else { throw SessionError.destinationChanged }
        do {
            let (receipt, snapshot) = try await worker.write(command, observed: observed.revision, claimed: claimed)
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
    /// Writes `commands` in order as one batch: for an import, a backfill or any run of many writes. Each command is
    /// signed and admitted on its own, as `perform(_:observed:claimed:)` admits it, and its records are stored before the
    /// next command is signed. The batch reconciles once, publishes one snapshot and asks for one sync. Returns a receipt
    /// per command, in order.
    ///
    /// The whole batch is refused, with nothing written, by the errors a single write gives before it signs:
    /// `SessionError.destinationChanged`, `.notReady` and `.staleRevision`, and `.invalidCommand` for more than
    /// `maximumBatchCount` commands. After that the batch stops at the first command that fails: one this session does not
    /// write (its namespace, a payload over its ceiling), one the engine refuses (a spent write budget, an expired grant;
    /// the engine's clock advances before each command, as between separate writes), a failure of the keys, or a store
    /// that refuses its records. The error is then a `BatchInterruption`: `index` names that command, `error` is what the
    /// single write would have thrown for it, and `receipts` are those of the commands before it, which are durable and
    /// visible. That command and every one after it are not written, except when the store failed in a way that cannot
    /// be read back: then `error` is `StorageError.unavailable` saying the command may have been recorded, and the next
    /// refresh shows whether it was. Once a command is durable its receipt is returned, or carried by the
    /// `BatchInterruption`, whatever happens next: a snapshot that cannot be built afterwards is reported in `lastError`
    /// and followed by a refresh, and a session that moved to another library meanwhile still returns the receipts of the
    /// one it wrote to. An empty batch writes nothing and returns no receipts. Claimed dates are not taken here; write
    /// those with `perform(_:observed:claimed:)`.
    @discardableResult public func perform(_ commands: [DomainCommand], observed: ObservedRevision) async throws -> [WriteReceipt] {
        await restore()
        guard observed.context == context else { throw SessionError.destinationChanged }
        guard commands.count <= Self.maximumBatchCount else { throw SessionError.invalidCommand }
        guard !commands.isEmpty else { return [] }
        do {
            let written = try await worker.write(commands, observed: observed.revision)
            publishAfterBatch(written.snapshot, lease: observed.context)
            return written.receipts
        } catch let refusal as SessionRefusal {
            if observed.context == context { apply(refusal.snapshot); lastError = refusal.error.localizedDescription }
            throw refusal.error
        } catch let stop as BatchStop {
            if let snapshot = stop.snapshot { publishAfterBatch(snapshot, lease: observed.context) }
            if observed.context == context { handleCommandError(stop.error) }
            throw BatchInterruption(receipts: stop.receipts, index: stop.index, error: stop.error)
        } catch {
            if observed.context == context { handleCommandError(error) }
            throw error
        }
    }
    /// After a durable batch: publishes its snapshot and asks for a sync. A snapshot that could not be built is reported
    /// in `lastError` and a refresh publishes the next one; it never turns the durable batch into a failure. A session that
    /// moved to another library meanwhile publishes nothing.
    private func publishAfterBatch(_ snapshot: Result<SessionSnapshot, any Error>, lease: UUID) {
        guard lease == context else { return }
        switch snapshot {
        case .success(let snapshot): apply(snapshot)
        case .failure(let error):
            lastError = error.localizedDescription
            let generation = lockGeneration
            refusalRefresh = Task { [weak self] in
                guard let self, canPublish(lease, generation) else { return }
                await refresh()
            }
        }
        if homesConfigured { requestSync() }
    }
    /// Approves a member's request with the owner controller (a passkey owner is asked to confirm), spending
    /// `pairing`: confirmed on this device for exactly this request's key (spec §9.1), by the six-digit code
    /// (`beginApproval`, `approvalCode`, then `pairing.confirm()` once the person saw the same digits on both
    /// devices) or by `scanRequest`. Any other pairing is refused; a pairing is spent whatever the answer.
    /// In `grant`, a field left nil inherits the request; a field given must narrow it: an expiry later than a requested
    /// one or a write budget larger than a requested one is `SessionError.invalidCommand`, and the pairing is not spent.
    public func approve(_ request: AccessRequest, pairing: AccountPairing, grant: GrantOptions? = nil) async throws {
        try await approve(request, pairing: pairing, terms: {
            guard let grant else { return nil }
            try SessionWorker.checkBounds(requestTerms: request.termsJSON, options: grant)
            return SessionWorker.narrowed(requestTerms: request.termsJSON, options: grant)
        })
    }
    /// Approves a request that asks for services (spec §10.1), narrowed by `services` (the services granted, an expiry,
    /// conditions) and, for its records, by `grant`. A grant wider than the request is `SessionError.invalidCommand`, and
    /// the pairing is not spent.
    public func approve(_ request: AccessRequest, pairing: AccountPairing, services: ServiceGrant, grant: GrantOptions? = nil) async throws {
        try await approve(request, pairing: pairing, terms: {
            // Both are judged against the request as signed: `grant` first (its expiry and write budget), then `services`.
            if let grant { try SessionWorker.checkBounds(requestTerms: request.termsJSON, options: grant) }
            let records = grant.map { SessionWorker.narrowed(requestTerms: request.termsJSON, options: $0) } ?? request.termsJSON
            return try SessionWorker.narrowed(requestTerms: records, grant: services)
        })
    }
    private func approve(_ request: AccessRequest, pairing: AccountPairing, terms: () throws -> String?) async throws {
        await restore()
        let lease = context
        do {
            let snapshot = try await worker.approve(request, pairing: pairing, terms: try terms())
            if lease == context { apply(snapshot) }
        } catch { if lease == context { handleCommandError(error) }; throw error }
    }

    // MARK: Calls for services (§12)

    /// Signs a call (spec §12.2) for `audience` and `purpose` with `argsJSON` (a JSON object) by this device's member key
    /// and returns its bytes base64url-encoded, ready for `Authorization: Colophon <call>`. Refused locally, with nothing
    /// sent: a service this session did not ask for (`refused:outOfScope`, before the key is asked), and any call the
    /// core's own §12.3 check refuses over what this device holds (its grant's services, expiry or conditions, a
    /// revocation it holds). Sign a fresh call for each request: a home refuses a replay.
    public func signCall(audience: String, purpose: String, argsJSON: String) async throws -> String {
        await restore()
        return SessionWorker.base64url(try await worker.signCall(audience: audience, purpose: purpose, argsJSON: argsJSON))
    }

    /// Provisions a slot at a home's door by this member's grant (the reference home's gate `"grant"`, relay/README.md):
    /// signs a fresh call for `audience` with purpose `home.provision` and args exactly the body
    /// `{"account","base","slot"}`, POSTs the body to `door` with `Content-Type: application/json`, its `Content-Length`
    /// and `Authorization: Colophon <call>`, and returns the home's signed member request (§9.1). So it plugs into
    /// `HomeConfiguration.request`: `request: { account in try await rig.provisionRequest(door: door, audience: audience,
    /// slot: slot, base: base, account: account) }`. A refusal is a `ProvisionRefusal` with the door's status and code;
    /// the signer's own refusal is the engine's error and sends nothing. `transport` defaults to
    /// `URLSessionHomeTransport` (`allowsLoopbackHTTP` for a test door on loopback).
    public func provisionRequest(door: URL, audience: String, slot: String, base: String, account: String,
                                 transport: (any HomeTransport)? = nil, allowsLoopbackHTTP: Bool = false) async throws -> Data {
        let body = SessionWorker.canonicalJSON(["account": account, "base": base, "slot": slot]) ?? "{}"
        let call = try await signCall(audience: audience, purpose: "home.provision", argsJSON: body)
        let bytes = Data(body.utf8)
        let sender = transport ?? URLSessionHomeTransport(allowingLoopbackHTTP: allowsLoopbackHTTP)
        let answer = try await sender.send(HttpRequest(ticket: 0, home: "", method: .post, url: door.absoluteString, headers: [
            Header(name: "Content-Type", value: "application/json"), Header(name: "Content-Length", value: String(bytes.count)),
            Header(name: "Authorization", value: "Colophon \(call)"),
        ], body: bytes))
        if answer.status == 200 { return answer.body }
        let refusal = HomeRefusal(status: answer.status, headers: answer.headers, body: answer.body)
        throw ProvisionRefusal(status: Int(answer.status), code: refusal?.code, retryAfterSeconds: refusal?.retryAfterSeconds)
    }

    // MARK: Pairing before approval (§7.3)

    /// The joining device, code path: a pairing for this device's member key. Send `pairing.commitment()` to the
    /// approving device; when its nonce arrives, `pairing.receiveNonce(na:)` gives the reveal to send back and
    /// `pairing.digits()` the six digits to show. The person compares them with the approving device's: on a
    /// match `pairing.confirm()`, otherwise `rejectPairing(_:)` (and the approving device aborts too).
    public func beginJoinPairing() async throws -> AccountPairing { await restore(); return try await worker.beginJoinPairing() }
    /// The approving device's person starts a ceremony for one incoming commitment: send `nonce` back. Call it only
    /// when the person asked (an incoming commitment is never started by itself). One ceremony at a time: while one is
    /// live (not confirmed, rejected or abandoned, and younger than ten minutes) another is refused; every start counts
    /// toward five an hour until it confirms (§7.3).
    public func beginApproval(commitment: Data) async throws -> ApprovalStart {
        await restore(); return try await worker.beginApproval(commitment: commitment)
    }
    /// The approving device received the joining device's reveal: the six digits to show. A reveal that does not
    /// open the commitment aborts (`pairing:commitmentMismatch`) and counts as a failure.
    public func approvalCode(pairing: AccountPairing, e: Data, nb: Data) async throws -> String {
        try await worker.approvalCode(pairing: pairing, e: e, nb: nb)
    }
    /// The codes differed or the person stopped: the session ends on this device and counts as a failure.
    public func rejectPairing(_ pairing: AccountPairing) async throws { try await worker.rejectPairing(pairing) }
    /// Ends a ceremony this device started (the person cancelled, the other device went away). It stays counted.
    public func abandonApproval(_ pairing: AccountPairing) async throws { try await worker.abandonApproval(pairing) }
    /// The approving device scanned a request from the joining device's screen (its canonical envelope, §9.1).
    /// Nothing is stored; approve the result's request with its pairing.
    public func scanRequest(_ data: Data) async throws -> ScannedRequest {
        await restore(); return try await worker.scanRequest(data)
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
        do { let snapshot = try await worker.rejoin(keys: keys); guard lease == context else { return }; apply(snapshot); await startWatching(); startSync() }
        catch { if lease == context { fail(error) } }
    }
    /// This device's own signed membership request (its canonical envelope), to show as a QR code for the approving
    /// device to scan (`scanRequest`).
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
    /// The namespace's fold as the engine reports it (`view_json`: `{"ok":…,"value":{"admitted":[…],…}}`), unchanged, for
    /// screens and tests that read a kind no domain kit folds. The Kotlin session's `view(namespace)`.
    /// Fenced as `query` is: a fold that returns after the session locked, lost access or changed account is `staleRevision`.
    public func view(namespace: String) async throws -> Data {
        await restore()
        guard hasUsableContent else { throw SessionError.notReady }
        let lease = context
        let observed = namespaceRevisions[namespace, default: 0]
        do {
            let bytes = try await worker.view(namespace: namespace)
            if let afterViewForTests { await afterViewForTests() }
            guard context == lease, hasUsableContent, namespaceRevisions[namespace, default: 0] == observed else { throw SessionError.staleRevision }
            return bytes
        } catch {
            if context == lease { handleCommandError(error) }
            throw error
        }
    }
    /// Tests only: runs between the worker's answer to `view` and the fence.
    @ObservationIgnored var afterViewForTests: (@MainActor () async -> Void)?
    /// The exact authority head this session's verifier has accepted, including while this member waits
    /// for approval. The read waits for initial restoration and does not refresh the record store.
    /// Throws if this verifier is stopped, has seen an authority reorganization, or cannot vouch
    /// for the current branch.
    public func acceptedAuthorityHead() async throws -> (account: String, sequence: UInt64, digest: String) {
        try Task.checkCancellation()
        let lease = context
        await restore()
        try Task.checkCancellation()
        guard lease == context else { throw SessionError.destinationChanged }
        let head = try await worker.acceptedAuthorityHead()
        try Task.checkCancellation()
        guard lease == context, libraryID == head.account else { throw SessionError.destinationChanged }
        guard phase != .locked else { throw SessionError.notReady }
        return head
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
    /// Appoints `homes` to an account that has none yet (one created with `createWithoutHome`), and with `adding` adds that
    /// controller (a passkey, say, with roles `[.control, .recover]`), in ONE transition (spec §8.7) the owner signs with the
    /// new key's possession proof. With no home before it, it is recorded at once and final (§13.1): the new controller then
    /// builds its own slot, so it unlocks alone, and this session starts syncing with the homes at once (no relaunch; pass
    /// the same homes in `SessionConfiguration.homes` on the next launch). With a home already current the transition waits
    /// out its delay: the call submits each transition it waits on like `proposeTransition` and answers `.pending(transitions:)`.
    ///
    /// Idempotent: called again after a crash or a `.pending`, it finishes what the account shows is not done, and never
    /// adds the controller or appoints a home twice. A home's `request` is called only while no current or pending
    /// appointment names its endpoint; a request that names another account or not that endpoint, or a key already present
    /// with another label or roles, is `invalidCommand` before anything is signed.
    @discardableResult
    public func appointHomes(_ homes: [HomeConfiguration], adding: (key: any AsyncKeyProvider, label: String, roles: [ControllerRole])? = nil) async throws -> HomesAppointment {
        await restore()
        var added: (spec: ControllerSpec, key: any AsyncKeyProvider)?
        if let adding {
            let d = try await adding.key.keyDescriptor()
            added = (ControllerSpec(key: d, label: adding.label, roles: adding.roles, verification: d.form == .webauthn, holder: nil, audiences: []), adding.key)
        }
        let outcome: HomesAppointment
        do { let (o, snapshot) = try await worker.appointHomes(homes, adding: added); outcome = o; apply(snapshot) }
        catch { handleCommandError(error); throw error }
        if !homes.isEmpty, !homesConfigured { homesConfigured = true; syncState = .idle }
        startSyncLoop()
        if case .pending(let digests) = outcome { for digest in digests { await submitUntilReceipted(digest, kind: .transition) } }
        if homesConfigured, let registered = try? await worker.registerRoutes() { apply(registered) }
        return outcome
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
    /// The removal follow-up (§17.5, `duties.removals`): in one action, revokes the members and removes the controllers a
    /// removed key admitted since its removal's anchor.
    public func removeFollowUp(seq: UInt64) async throws {
        await restore()
        do { apply(try await worker.removeFollowUp(seq: seq)) } catch { handleCommandError(error); throw error }
    }
    /// The person keeps what a removed key admitted; the follow-up is not shown again.
    public func keepFollowUp(seq: UInt64) async throws {
        await restore()
        do { apply(try await worker.keepFollowUp(seq: seq)) } catch { handleCommandError(error); throw error }
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
        lockGeneration &+= 1
        if let lockTask { await lockTask.value; return }
        suspended = true
        if syncState == .syncing { syncState = .idle }
        let watch = watchTask, checkpoint = checkpointTask
        stopSyncLoops()
        watch?.cancel(); watchTask = nil
        batchTask?.cancel(); batchNeedsRefresh = false
        checkpoint?.cancel(); checkpointTask = nil
        let task = Task {
            await watch?.value
            await checkpoint?.value
            await restoreTask?.value
            await drainSync()
            batchTask = nil
            if let snapshot = try? await worker.lock() {
                usable = false; apply(snapshot, whileSuspended: true)
            }
            lockTask = nil
        }
        lockTask = task
        await task.value
    }
    public func unlock() async {
        lockGeneration &+= 1
        let generation = lockGeneration
        await lockTask?.value
        guard generation == lockGeneration else { return }
        let lease = context
        do {
            let snapshot = try await worker.unlock()
            guard lease == context, generation == lockGeneration else { return }
            suspended = false; apply(snapshot); await startWatching()
            startSyncLoop(); startDueLoop()
        } catch {
            if lease == context, generation == lockGeneration { suspended = false; fail(error) }
        }
    }

    private func canPublish(_ lease: UUID, _ generation: UInt64) -> Bool {
        lease == context && generation == lockGeneration && !suspended
    }

    // MARK: Exchange with the homes

    /// Attaches transports to this live session for homes the account names.
    public func configureHomes(_ homes: [HomeConfiguration]) async {
        guard !homes.isEmpty else { return }
        await worker.configureHomes(homes)
        homesConfigured = true
        if syncState == .disabled, !phase.isStopped { syncState = .idle }
        if !suspended, !syncPaused, !phase.isStopped {
            startSyncLoop()
            Task { [syncSignal] in await syncSignal.fire() }
        }
    }

    /// Runs one exchange pass with every home now and refreshes when something arrived. Returns false when it failed.
    @discardableResult public func syncNow() async -> Bool {
        guard homesConfigured, !suspended else { return false }
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
        let lease = context, generation = lockGeneration
        await restore()
        guard canPublish(lease, generation) else { return false }
        // With no library there is nothing to exchange. A pass here would refresh to `noLibrary` and erase what a failed
        // `create()` just published (its `failed` phase and error), which an app would see as a missing error.
        guard libraryID != nil else { return false }
        // A stopped account runs no exchange (spec §1 "A stop"): not a failure, and nothing to retry.
        if phase.isStopped { syncState = .disabled; return true }
        if syncState != .syncing { syncState = .syncing }
        do {
            let result = try await worker.exchange()
            guard canPublish(lease, generation) else { return false }
            homeFaults = result.faults; homeIssues = result.issues
            lastSynced = .now
            if result.stopped { syncState = .disabled; await refresh(); return true }
            // A home that answered `503 {"result":"unavailable"}` is not available: shown so, retried with backoff (never as
            // this device being stopped, which only its own verified history decides).
            if result.homeUnavailable, !result.changed {
                syncState = .offline(reason: HomeWords.unavailable)
                if result.owesRefresh { await refresh(coalescing: true) }
                return false
            }
            syncState = result.unauthorized ? .unauthorized : result.failed ? .error(reason: "a pass could not finish: the engine was still waiting") : .idle
            // A folder hint answered during the pass left its refresh to this one, so a change is reconciled once.
            if phase != .ready { await refresh() }
            else if result.changed || result.owesRefresh { await refresh(coalescing: true) }
            else if let snapshot = try? await worker.currentSnapshot(), canPublish(lease, generation) { apply(snapshot) }
            return !result.unauthorized && !result.failed
        } catch is CancellationError {
            return false
        } catch let error as HomeTransportError {
            guard canPublish(lease, generation) else { return false }
            if case .offline(let reason) = error { syncState = .offline(reason: reason) } else { syncState = .error(reason: error.localizedDescription) }
            await refreshOwed()
            return false
        } catch let error as ColophonError {
            guard canPublish(lease, generation) else { return false }
            syncState = .error(reason: error.localizedDescription)
            if error.isNewerFormat { fail(error) } else { await refreshOwed() }
            return false
        } catch {
            guard canPublish(lease, generation) else { return false }
            syncState = .error(reason: error.localizedDescription)
            await refreshOwed()
            return false
        }
    }
    /// An exchange that failed after a folder hint was answered during it: the refresh that hint skipped runs now.
    private func refreshOwed() async {
        if await worker.owesRefresh { await refresh(coalescing: true) }
    }

    /// Wakes the background exchange loop, for example after a host learns the network returned.
    public func requestSync() { Task { await syncSignal.fire() } }
    /// Stops the background exchange. Local storage and the session keep working.
    public func stopSync() {
        syncPaused = true
        stopSyncLoops()
    }

    private func stopSyncLoops() {
        if let syncTask { stoppedSyncTask = syncTask }
        if let dueTask { stoppedDueTask = dueTask }
        syncTask?.cancel(); syncTask = nil
        dueTask?.cancel(); dueTask = nil
        dueWork?.cancel()
    }

    /// Restarts periodic exchange and due work for an active session.
    public func startSync() {
        guard !suspended, homesConfigured || libraryID != nil else { return }
        syncPaused = false
        startSyncLoop(); startDueLoop()
    }

    /// Waits for the current exchanges, refreshes and due work. A running loop's next timer is outside this barrier.
    public func drainSync() async {
        let sync = syncChain, batch = batchTask
        let refreshes = Array(refreshWaiters.keys), due = dueWork
        let refusal = refusalRefresh
        let stoppedSync = stoppedSyncTask, stoppedDue = stoppedDueTask
        _ = await sync?.value
        await batch?.value
        for id in refreshes {
            await withCheckedContinuation { waiter in
                if refreshWaiters[id] != nil { refreshWaiters[id]?.append(waiter) }
                else { waiter.resume() }
            }
        }
        await refusal?.value
        await due?.value
        await stoppedSync?.value
        await stoppedDue?.value
    }

    private func startSyncLoop() {
        guard homesConfigured, !syncPaused, !suspended, syncTask == nil else { return }
        syncTask = Task { [weak self, previous = stoppedSyncTask] in
            await previous?.value
            var failures = 0
            while !Task.isCancelled {
                guard let self else { return }
                let ok = await self.syncNow()
                guard !Task.isCancelled else { return }
                // Stopped: no timer and no backoff. Only an event (a refresh, lock, unlock, an explicit `requestSync`) wakes the
                // loop, and each pass returns at once without contacting a home.
                if self.phase.isStopped { await self.syncSignal.wait(); continue }
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
        guard !syncPaused, !suspended, dueTask == nil else { return }
        dueTask = Task { [weak self, previous = stoppedDueTask] in
            await previous?.value
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(60))
                guard let self, !Task.isCancelled else { return }
                guard phase == .ready, !suspended else { continue }
                let lease = context, generation = lockGeneration
                let work = Task {
                    if let snapshot = try? await worker.recordDue(), canPublish(lease, generation), !Task.isCancelled {
                        apply(snapshot)
                    }
                }
                dueWork = work
                await work.value
                dueWork = nil
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
        guard !suspended, watchTask == nil else { return }
        await withCheckedContinuation { started in
            watchTask = Task { [weak self, worker] in
                guard !Task.isCancelled else { started.resume(); return }
                do {
                    let stream = try await worker.changes()
                    started.resume()
                    for await _ in stream {
                        guard !Task.isCancelled else { return }
                        self?.externalChange()
                    }
                } catch {
                    started.resume()
                    if !Task.isCancelled { self?.lastError = error.localizedDescription }
                }
                if !Task.isCancelled { self?.watchTask = nil }
            }
        }
    }
    /// A bounded notification stream plus one trailing batch task coalesces file bursts.
    func externalChange() {
        guard !suspended else { return }
        batchNeedsRefresh = true
        guard batchTask == nil else { return }
        batchTask = Task { [weak self] in
            while !Task.isCancelled {
                do { try await Task.sleep(for: .milliseconds(75)) } catch { return }
                guard let self, !Task.isCancelled else { return }
                batchNeedsRefresh = false
                await refresh(coalescing: true)
                guard !Task.isCancelled else { return }
                if !batchNeedsRefresh { batchTask = nil; return }
            }
        }
    }
    /// Deterministic batch barrier for hosts/tests; no timing-based polling is required.
    public func flushExternalChanges() async {
        guard !suspended else { return }
        let lease = context, generation = lockGeneration
        let batch = batchTask
        batch?.cancel(); batchTask = nil; batchNeedsRefresh = false
        await batch?.value
        guard canPublish(lease, generation) else { return }
        await refresh()
    }
    public var hasUsableContent: Bool {
        !suspended && usable && ([.ready, .refreshing, .waitingForDownload, .retry].contains(phase) || phase.isStopped)
    }

    private func apply(_ snapshot: SessionSnapshot, whileSuspended: Bool = false) {
        guard !suspended || whileSuspended, snapshot.revision >= revision else { return }
        if homesConfigured, snapshot.revision != revision || snapshot.phase != phase { Task { [syncSignal] in await syncSignal.fire() } }
        let changed = Set(snapshot.namespaceRevisions.keys.filter { namespaceRevisions[$0] != snapshot.namespaceRevisions[$0] })
        let lost = !snapshot.usable
        phase = snapshot.phase; revision = snapshot.revision; namespaceRevisions = snapshot.namespaceRevisions
        if snapshot.phase.isStopped { syncState = .disabled }
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
            let lease = context, generation = lockGeneration
            refusalRefresh = Task { [weak self] in
                guard let self, canPublish(lease, generation) else { return }
                await refresh()
            }
        case is ColophonError, is StorageError, is SessionKeyFailure, is KeyCustodyError:
            commandFailureRevision &+= 1
            fail(error)
        default: lastError = error.localizedDescription
        }
    }
    private func fail(_ error: any Error) {
        if suspended || error is CancellationError { return }
        // A stopped account refuses every write (`newerFormat`) and every call (`unavailable`): that is the stopped phase
        // the person already sees, not a new fault, so the phase and the readable content stay.
        if phase.isStopped, let colophon = error as? ColophonError, colophon.isNewerFormat || colophon.code.hasPrefix("unavailable") { return }
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
