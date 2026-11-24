import CryptoKit
import Foundation

/// The record source the engine reads through: the medium, nothing else. It never calls the engine.
final class MediumSource: HostSource, @unchecked Sendable {
    let medium: any RecordMedium
    /// Protects `unconfirmed`, the only mutable property.
    private let lock = NSLock()
    private var unconfirmed: UInt64 = 0
    init(_ medium: any RecordMedium) { self.medium = medium }
    /// Record reads the engine may have dropped without holding the path: a read that threw (the engine skips the path
    /// and goes on), or one larger than the smallest bound the engine reads records under (it refuses those bytes).
    var unconfirmedReads: UInt64 { lock.withLock { unconfirmed } }
    /// The engine's object bound (`MAX_OBJECT_BYTES`), the smaller of the two it reads records under.
    static let smallestReadBound = 2_097_152 + 4_096
    // Each callback in its own autorelease pool: Foundation's file reads autorelease, and the engine's queue runs a
    // whole engine call (many callbacks) as one job.
    func read(path: String) throws -> Data {
        do {
            let bytes = try autoreleasepool { try medium.read(path) }
            if bytes.count > Self.smallestReadBound { lock.withLock { unconfirmed &+= 1 } }
            return bytes
        } catch {
            lock.withLock { unconfirmed &+= 1 }
            throw error
        }
    }
    func readBlob(path: String) throws -> Data { try autoreleasepool { try medium.readBlob(path) } }
}

struct SessionSnapshot: Sendable {
    var phase: SessionPhase
    var revision: UInt64
    var namespaceRevisions: [String: UInt64]
    var libraryID: String?
    var memberID: String?
    var members: [AccountMember] = []
    var requests: [AccessRequest] = []
    var notices: SessionNotices = .empty
    var homes: [Home] = []
    var duties: HostDuties = .none
    var usable: Bool { [.ready, .refreshing, .waitingForDownload, .retry].contains(phase) || phase.isStopped }
}

/// A refusal that carries the fresh snapshot so the facade shows what the person must now see.
struct SessionRefusal: Error { let snapshot: SessionSnapshot; let error: SessionError }

/// Small durable state in the private container: which account, whether the person left, what was shown.
struct SessionJournalFile: Codable, Sendable {
    var account: String?
    var left = false
    var shownSeq: UInt64 = 0
    var shownTransitions: [String] = []
    /// Activations above `shownSeq` the person marked seen one by one (an activation is marked alone, never with others).
    var seenActivations: Set<UInt64> = []
    /// Homes that hold this host's delivery routes (home ID to true), or said they offer no registration (false).
    var routes: [String: Bool] = [:]
    /// The change of each transition this device signed, by digest, so a dead one can be signed again.
    var signedChanges: [String: String] = [:]
    /// Removal follow-ups the person answered (removed or kept), by activation seq.
    var answeredRemovals: Set<UInt64> = []
    /// Ingress envelopes already written, by ID, with their operation (an envelope is never signed twice).
    var ingress: [UUID: String] = [:]
}

/// All filesystem, FFI, signing and key ceremonies run off the main actor. The gate serialises complete
/// operations across suspensions, including a passkey prompt and the persistence of the stores a
/// finish returned: the engine is never ahead of the disk when another operation reads it.
actor SessionWorker {
    /// The worker's own serial queue is its executor (as `ColophonEngine` has one): the medium's synchronous record I/O
    /// and the checkpoint cache run here, never on the main actor and never on a cooperative-pool thread.
    private let queue = DispatchSerialQueue(label: "org.luff.colophon.session", qos: .userInitiated, autoreleaseFrequency: .workItem)
    nonisolated var unownedExecutor: UnownedSerialExecutor { queue.asUnownedSerialExecutor() }
    let configuration: SessionConfiguration
    private var memberKeys: any AsyncKeyProvider
    private var medium: (any RecordMedium)?
    private var engine: ColophonEngine? { didSet { if engine == nil { memberOpened = false } } }
    private var memberCustody: KeyCustody?
    /// The listing the engine last took (see `take(_:into:)`). Nil means the next reconcile refreshes in full.
    private var listingBaseline: ListingBaseline?
    /// The source `engine` reads through, which counts the reads it could not confirm (tests read it).
    private(set) var engineSource: MediumSource?
    /// How many reconciles handed the engine the whole listing, and how many only what changed (tests read these).
    private(set) var fullRefreshes = 0
    private(set) var incrementalRefreshes = 0
    private(set) var accountID: String?
    private(set) var memberID: String?
    private var journal = SessionJournalFile()
    private var journalLoaded = false
    private var locked = false
    /// A replacement of already accepted authority cannot be used for credential discovery in
    /// this worker, even when the regular session subsequently follows the new branch.
    private var reorganizedAuthority: Set<String> = []
    private var revision: UInt64 = 0
    private var lastRevisions: [String: UInt64] = [:]
    private var lastHead: UInt64 = 0
    private var lastPhase: SessionPhase = .opening
    /// True once this member opened its epoch shares (the engine then holds loaded records). Until then a
    /// refresh reopens the engine: a member that was not yet approved has nothing to refresh.
    private var memberOpened = false
    private var phaseIsReady: Bool { lastPhase == .ready }
    private var occupied = false
    private var waiters: [CheckedContinuation<Void, Never>] = []
    private let journalURL: URL
    private let cache: CheckpointCache
    private var faults: [HomeFault] = []
    private var issues: [HomeIssue] = []
    /// Per home, the time before which it is not contacted again (a `Retry-After` it sent with a result).
    private var notBefore: [String: Date] = [:]
    /// Per home, the refusal that came with its `Retry-After`, shown again while the home is not contacted.
    private var waitingIssue: [String: HomeIssue] = [:]
    /// Homes `appointHomes` appointed while this session runs, beside the configuration's: the exchange reaches them at once.
    private var appointedHomes: [HomeConfiguration] = []
    /// Every home this session may reach: the configuration's, then those appointed since it started.
    private var homeConfigurations: [HomeConfiguration] { configuration.homes + appointedHomes }

    init(configuration: SessionConfiguration) {
        self.configuration = configuration; memberKeys = SessionKeys(base: configuration.keys)
        journalURL = configuration.privateContainer.appendingPathComponent("session.json")
        cache = CheckpointCache(privateContainer: configuration.privateContainer)
    }

    // MARK: Gate

    nonisolated func termsJSONNonisolated(namespaces: [String], access: [Access], expires: String?, budget: UInt64?) -> String {
        Self.terms(namespaces: namespaces, access: access, expires: expires, budget: budget)
    }
    /// A member's terms (§9.1, §10.1): `records` for `namespaces` (sorted; absent when there are none) and `services`
    /// when asked, keys sorted.
    nonisolated static func terms(namespaces: [String], access: [Access], expires: String?, budget: UInt64?, services: [ServiceTerms] = []) -> String {
        var terms: [String: Any] = [:]
        if !namespaces.isEmpty { terms["records"] = namespaces.sorted().map { ["namespace": $0, "access": access.contains(.write) ? "write" : "read"] } }
        if !services.isEmpty { terms["services"] = servicesValue(services) }
        if let expires { terms["expires"] = expires }
        if let budget { terms["writes"] = budget }
        return canonicalJSON(terms) ?? "{}"
    }
    nonisolated static func servicesValue(_ services: [ServiceTerms]) -> [[String: Any]] {
        services.sorted { $0.audience < $1.audience }.map { ["audience": $0.audience, "purposes": $0.purposes.sorted()] }
    }
    /// JSON with every object's keys sorted and slashes unescaped; the core re-reads what it signs.
    nonisolated static func canonicalJSON(_ value: Any) -> String? {
        guard let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .withoutEscapingSlashes]) else { return nil }
        return String(decoding: data, as: UTF8.self)
    }
    /// The `services` a member's terms ask for (spec §10.1); anything not of that shape is left out.
    nonisolated static func requestedServices(_ termsJSON: String) -> [ServiceTerms] {
        guard let object = try? JSONSerialization.jsonObject(with: Data(termsJSON.utf8)) as? [String: Any],
              let list = object["services"] as? [[String: Any]] else { return [] }
        return list.compactMap { entry in
            guard let audience = entry["audience"] as? String, let purposes = entry["purposes"] as? [String] else { return nil }
            return ServiceTerms(audience: audience, purposes: purposes)
        }
    }
    /// Whether `asked` purposes cover `granted` ones (§10.3: `["*"]` covers all; a granted `["*"]` needs an asked one).
    nonisolated static func purposesCover(_ asked: [String], _ granted: [String]) -> Bool {
        if granted.isEmpty { return false }
        if asked.contains("*") { return true }
        return !granted.contains("*") && granted.allSatisfy(asked.contains)
    }
    /// Whether `services` name `purpose` at exactly `audience`.
    nonisolated static func servicesCover(_ services: [ServiceTerms], audience: String, purpose: String) -> Bool {
        services.contains { $0.audience == audience && purposesCover($0.purposes, [purpose]) }
    }
    /// Refuses `options` that would widen the request's own bounds (`invalidCommand`): an expiry later than a requested
    /// one, or a write budget larger than a requested one. `narrowed(requestTerms:options:)` replaces both as given, and
    /// the core does not compare them with the request (the approver sets them), so this is checked against the request
    /// as signed before anything is composed or signed.
    nonisolated static func checkBounds(requestTerms: String, options: GrantOptions) throws {
        guard let terms = (try? JSONSerialization.jsonObject(with: Data(requestTerms.utf8))) as? [String: Any] else { throw SessionError.invalidCommand }
        if let expires = options.expires, let asked = terms["expires"] as? String, expires > asked { throw SessionError.invalidCommand }
        if let budget = options.writeBudget, let asked = (terms["writes"] as? NSNumber)?.uint64Value, budget > asked { throw SessionError.invalidCommand }
    }
    /// The request's terms narrowed by `grant` (`ServiceGrant`): each granted service names an audience the request asks
    /// for with purposes it asks; `expires` is no later than a requested one; conditions are added to any the request
    /// carries. Everything else is kept. A grant wider than the request, or one that leaves no `records`, `services` or
    /// `serves`, is `invalidCommand`.
    nonisolated static func narrowed(requestTerms: String, grant: ServiceGrant) throws -> String {
        guard var terms = (try? JSONSerialization.jsonObject(with: Data(requestTerms.utf8))) as? [String: Any] else { throw SessionError.invalidCommand }
        if let granted = grant.services {
            let asked = requestedServices(requestTerms)
            for g in granted {
                guard let a = asked.first(where: { $0.audience == g.audience }), purposesCover(a.purposes, g.purposes) else { throw SessionError.invalidCommand }
            }
            if granted.isEmpty { terms.removeValue(forKey: "services") } else { terms["services"] = servicesValue(granted) }
        }
        if let expires = grant.expires {
            if let held = terms["expires"] as? String, expires > held { throw SessionError.invalidCommand }
            terms["expires"] = expires
        }
        if let text = grant.conditionsJSON {
            guard let added = (try? JSONSerialization.jsonObject(with: Data(text.utf8))) as? [Any] else { throw SessionError.invalidCommand }
            var held = terms["conditions"] as? [Any] ?? []
            var seen = Set(held.compactMap { canonicalJSON($0) })
            for c in added { if let key = canonicalJSON(c), seen.insert(key).inserted { held.append(c) } }
            if !held.isEmpty { terms["conditions"] = held }
        }
        guard terms["records"] != nil || terms["services"] != nil || terms["serves"] != nil, let out = canonicalJSON(terms) else { throw SessionError.invalidCommand }
        return out
    }
    /// The request's own terms, narrowed by `options` (spec §9.1: a grant is covered by its request). A nil field keeps
    /// the request's; `namespaces` keeps only those record entries; `access` without `.write` lowers each entry to read;
    /// `expires` and `writeBudget` are added. Everything else in the request (kinds, services, conditions) is kept.
    nonisolated static func narrowed(requestTerms: String, options: GrantOptions) -> String {
        guard var terms = (try? JSONSerialization.jsonObject(with: Data(requestTerms.utf8))) as? [String: Any] else { return requestTerms }
        if var records = terms["records"] as? [[String: Any]] {
            if let keep = options.namespaces { records = records.filter { keep.contains(($0["namespace"] as? String) ?? "") } }
            if let access = options.access, !access.contains(.write) {
                records = records.map { var entry = $0; entry["access"] = "read"; return entry }
            }
            terms["records"] = records
        }
        if let expires = options.expires { terms["expires"] = expires }
        if let budget = options.writeBudget { terms["writes"] = budget }
        guard let data = try? JSONSerialization.data(withJSONObject: terms, options: [.sortedKeys]) else { return requestTerms }
        return String(decoding: data, as: UTF8.self)
    }
    func enter() async { if occupied { await withCheckedContinuation { waiters.append($0) } } else { occupied = true } }
    func exit() { if waiters.isEmpty { occupied = false } else { waiters.removeFirst().resume() } }
    private func gated<T: Sendable>(_ body: () async throws -> T) async throws -> T {
        await enter(); defer { exit() }
        try Task.checkCancellation()
        return try await body()
    }

    // MARK: Storage

    func storage() throws -> any RecordMedium {
        if let medium { return medium }
        let resolved = try configuration.location.resolve(); medium = resolved; return resolved
    }
    func changes() throws -> AsyncStream<Void> { try storage().changes() }
    private func loadJournal() throws {
        guard !journalLoaded else { return }
        do { journal = try JSONDecoder().decode(SessionJournalFile.self, from: AtomicFile.read(journalURL, maximumBytes: 8 * 1024 * 1024)) }
        catch let error as CocoaError where error.code == .fileReadNoSuchFile || error.code == .fileNoSuchFile { journal = SessionJournalFile() }
        journalLoaded = true
    }
    private func saveJournal() throws { try AtomicFile.write(JSONEncoder().encode(journal), to: journalURL) }
    private var now: Date { configuration.now() }
    private var nowMs: Int64 { Int64((now.timeIntervalSince1970 * 1000).rounded()) }

    /// Persists the stores of one finished step, all or none. If the disk refuses, the engine is ahead of
    /// the disk: discard it so the next operation reopens over what is really stored, then fail.
    private func persist(_ stores: [Store], on target: ColophonEngine? = nil) async throws {
        guard !stores.isEmpty else { return }
        do { try storage().write(stores.map { MediumWrite(path: $0.path, bytes: $0.bytes) }) }
        catch {
            if let target, target !== engine { await target.discard() } else { await engine?.discard(); engine = nil }
            throw error
        }
    }
    private func persist(_ written: Written, on target: ColophonEngine? = nil) async throws {
        if let engine = target ?? engine { observeAuthorityChanges(written.changes, from: engine) }
        try await persist(written.stores, on: target)
    }

    /// Call under the session gate as soon as a selected engine mutation returns. The flag is
    /// relative to the previous engine state, so the next successful refresh may no longer report it.
    func observeAuthorityChanges(_ changes: Changes, from target: ColophonEngine) {
        if changes.reorganized, engine === target { reorganizedAuthority.insert(target.account) }
    }

    /// Compound core operations can commit an authority batch and then throw on a later batch.
    /// If the operation lost its summary and the head changed or became unreadable, the worker
    /// cannot prove continuity. An unchanged head leaves the original error and eligibility intact.
    private func trackInterruptedAuthorityChange<T: Sendable>(
        in engine: ColophonEngine, _ operation: () async throws -> T
    ) async throws -> T {
        let before = try? await engine.run { try $0.headDigest() }
        do { return try await operation() }
        catch {
            let after = try? await engine.run { try $0.headDigest() }
            if before != after, self.engine === engine { reorganizedAuthority.insert(engine.account) }
            throw error
        }
    }

    private func advance(_ engine: ColophonEngine, to time: Int64) async throws {
        let changes = try await engine.run { try $0.advance(nowMs: time) }
        observeAuthorityChanges(changes, from: engine)
    }

    private func refresh(_ engine: ColophonEngine, listing: [ListedPath]) async throws {
        // The engine's listing is now this one: a baseline taken earlier no longer describes it.
        listingBaseline = nil
        let changes = try await trackInterruptedAuthorityChange(in: engine) {
            try await engine.run { try $0.refresh(listing: listing) }
        }
        observeAuthorityChanges(changes, from: engine)
    }

    private func applyPaths(_ engine: ColophonEngine, _ paths: [ListedPath]) async throws {
        let changes = try await trackInterruptedAuthorityChange(in: engine) {
            try await engine.run { try $0.applyPaths(paths: paths) }
        }
        observeAuthorityChanges(changes, from: engine)
    }

    private func load(_ engine: ColophonEngine) async throws {
        let changes = try await trackInterruptedAuthorityChange(in: engine) {
            try await engine.run { try $0.load() }
        }
        observeAuthorityChanges(changes, from: engine)
    }

    private func persistDueWrites(_ engine: ColophonEngine) async throws {
        let writes = try await engine.run { try $0.recordDue() }
        // The batch already ran in the engine. A failure persisting an earlier write must
        // preserve the observation even if a later write is never persisted.
        for written in writes { observeAuthorityChanges(written.changes, from: engine) }
        for written in writes { try await persist(written.stores, on: engine) }
    }

    private func persist(_ report: Report, on engine: ColophonEngine) async throws {
        observeAuthorityChanges(report.changes, from: engine)
        try await persist(report.store, on: engine)
    }

    // MARK: Opening

    func restore() async throws -> SessionSnapshot { try await gated { try await reconcile() } }
    func refresh() async throws -> SessionSnapshot { try await gated { try await reconcile() } }

    func lock() async throws -> SessionSnapshot {
        try await gated {
            await engine?.lock(); engine = nil; locked = true; memberOpened = false
            return snapshot(phase: .locked, members: [], requests: [], notices: .empty)
        }
    }
    func unlock() async throws -> SessionSnapshot { try await gated { locked = false; return try await reconcile() } }

    private func listed(_ entries: [MediumEntry]) -> [ListedPath] { entries.map { ListedPath(path: $0.path, version: $0.version) } }

    private func reconcile() async throws -> SessionSnapshot {
        try loadJournal()
        if journal.left { return snapshot(phase: .noLibrary) }
        if locked { return snapshot(phase: .locked) }
        let medium = try storage()
        let entries = try medium.listing()
        guard entries.contains(where: { $0.path.hasPrefix("authority/") }) else {
            if journal.account != nil { throw StorageError.unavailable("Selected library is unavailable") }
            return snapshot(phase: .noLibrary)
        }
        do {
            if engine == nil { try await openEngine(entries) }
            else { try await refreshEngine(entries) }
        } catch let error as ColophonError where error.isNewerFormat {
            await engine?.discard(); engine = nil
            return snapshot(phase: .updateRequired)
        } catch let error as ColophonError {
            if case .integrity = error { await engine?.discard(); engine = nil }
            throw error
        }
        return try await build()
    }

    private func discoverAccount(_ entries: [MediumEntry]) throws -> String {
        let medium = try storage()
        func objects(_ prefix: String) throws -> [ByteString] {
            try entries.filter { $0.path.hasPrefix(prefix) }.map { ByteString(bytes: try medium.read($0.path)) }
        }
        let pending = try objects("transitions/") + objects("vetoes/") + objects("receipts/")
        let report = try accountVerifyHistory(objects: AuthorityObjects(entries: try objects("authority/"), pending: pending,
            heads: try objects("heads/"), predecessor: try objects("predecessor/")), nowMs: nowMs)
        // A history that stops at a final layout raise still names its account: the engine opens it, stopped (spec §1).
        if report.kind == .newerFormat, report.account == nil { throw ColophonError.newerFormat(code: report.code, detail: report.detail ?? "") }
        guard let account = report.account else {
            throw ColophonError.malformed(code: report.code, detail: report.detail ?? "the library's history does not verify")
        }
        return account
    }

    private func openEngine(_ entries: [MediumEntry]) async throws {
        let account = try journal.account ?? discoverAccount(entries)
        if let known = journal.account, known != account { throw SessionError.destinationChanged }
        let keyID = try await KeyCustody.keyID(of: memberKeys)
        memberID = keyID
        memberCustody = try await KeyCustody([memberKeys])
        let saved = try await loadSaved(account)
        let key = try configuration.deviceSecrets.key(for: account)
        let source = MediumSource(try storage())
        let opened = try await ColophonEngine.open(source: source, listing: listed(entries),
            identity: AccountIdentity(kind: .member, id: keyID), account: account, namespaces: configuration.libraryNamespaces,
            saved: saved, deviceKey: key, nowMs: nowMs)
        engine = opened; accountID = account; engineSource = source
        // Without a baseline the next reconcile refreshes in full: never a reason to fail this one. A read the open
        // could not confirm leaves none, so the next reconcile's full refresh reads that path again. The load and
        // unlock below can still drop a path; the next reconcile sees the counters moved and refreshes in full.
        if source.unconfirmedReads == 0, let stale = try? await opened.run({ try $0.staleLive() }).count, stale == 0 {
            listingBaseline = (try? await ListingBaseline(engine: opened, entries: entries, drops: .init(reads: 0, stale: 0))) ?? nil
        }
        // A member that is not approved yet holds no keys; the records can still be read and the exchange can
        // still bring the approval in. A member opens its epoch shares in `unlockIfPossible`.
        if try await opened.run({ try $0.me() }).kind != .member { try await load(opened) }
        if journal.account == nil { journal.account = account; try saveJournal() }
        try await unlockIfPossible()
    }

    private func refreshEngine(_ entries: [MediumEntry]) async throws {
        guard let engine else { return }
        // A stopped account reads nothing new (spec §1 "A stop"): what it held when the stop was verified stays readable.
        if try await Self.isStopped(engine) { return }
        try await advance(engine, to: nowMs)
        try await take(entries, into: engine)
        try await persistDueWrites(engine)
        try await unlockIfPossible()
    }

    /// Hands the engine a fresh, complete listing of the medium. When the listing only adds paths or changes versions
    /// relative to the listing the engine last took, the engine reads just those paths (`apply_paths`), which is what
    /// a full refresh would read: it reads a listed path again only when it is new, its version changed or it is
    /// unread. Anything else refreshes in full: a removed path, a path without a version, a listing out of path order
    /// or over the engine's listing bound, unread paths the engine retries, or a path the engine reports missing that
    /// reappeared. The listing itself is always complete, so missing, replaced and unavailable files are still found
    /// on every reconcile.
    ///
    /// A baseline is kept only when the engine held every path it was given: no read failed or was refused for its
    /// size, and no live slot was refused as stale. Otherwise a path may be listed but not held, which only a full
    /// refresh reads again, so the next reconcile refreshes in full. The baseline records those counters, and is used
    /// only while they have not moved since: a load, unlock or other call after it that dropped a path retires it too.
    private func take(_ entries: [MediumEntry], into engine: ColophonEngine) async throws {
        let baseline = listingBaseline
        listingBaseline = nil // set again only once the engine took this listing
        let before = await drops(engine)
        if let baseline, let before, baseline.drops == before, baseline.engine === engine,
           let delta = ListingBaseline.delta(from: baseline.entries, to: entries),
           !delta.contains(where: { baseline.missing.contains($0.path) }),
           try await engine.run({ try $0.stats() }).unreadPaths == 0 {
            if !delta.isEmpty { try await applyPaths(engine, listed(delta)) }
            incrementalRefreshes += 1
            if let after = await drops(engine), after == before {
                listingBaseline = ListingBaseline(engine: engine, entries: entries, missing: baseline.missing, drops: after)
            }
            return
        }
        try await refresh(engine, listing: listed(entries))
        fullRefreshes += 1
        if let before, let after = await drops(engine), after == before {
            listingBaseline = (try? await ListingBaseline(engine: engine, entries: entries, drops: after)) ?? nil
        }
    }

    /// The counters of paths `engine` may have dropped, or nil when they cannot be read (no baseline is kept then).
    private func drops(_ engine: ColophonEngine) async -> ListingBaseline.Drops? {
        guard let source = engineSource, let stale = try? await engine.run({ try $0.staleLive() }).count else { return nil }
        return ListingBaseline.Drops(reads: source.unconfirmedReads, stale: stale)
    }

    /// A member opens its epoch shares with its own agreement key (silent for a Secure Enclave key): at first, and
    /// again whenever new epochs were sealed to it (a revocation or a rekey makes new epochs; an unlocked engine
    /// still has to open its shares of them before it can write).
    private func unlockIfPossible() async throws {
        guard let engine, let custody = memberCustody else { return }
        guard case .member = try await engine.run({ try $0.me() }).kind else { return }
        let agreements = try await engine.run { try $0.beginUnlockEpochs() }
        guard !agreements.isEmpty else {
            // A revoked member (or a member with no readable namespaces) has no shares. The
            // core still requires load before notices/exchange; no finish-unlock will do it.
            if !memberOpened { try await load(engine); memberOpened = true }
            return
        }
        let answers = try await custody.answer(epochs: agreements)
        let changes = try await trackInterruptedAuthorityChange(in: engine) {
            try await engine.finishUnlockEpochs(answers: answers)
        }
        observeAuthorityChanges(changes, from: engine)
        memberOpened = true
    }

    private func loadSaved(_ account: String) async throws -> SavedState? {
        guard let bytes = try await cache.load(libraryID: account) else { return nil }
        return try? JSONDecoder().decode(SavedFile.self, from: bytes).state
    }
    func saveCheckpoint() async throws {
        try await gated {
            guard let engine, let account = accountID, phaseIsReady || lastPhase.isStopped else { return }
            try await persistSaved(engine, account: account)
        }
    }
    /// Seals and stores the engine's saved state (inside the gate). A stopped account's saved state carries the stop as a
    /// floor, so a relaunch whose store no longer holds the raise stays stopped (spec §1 "A stop").
    private func persistSaved(_ engine: ColophonEngine, account: String) async throws {
        _ = try await engine.run { try $0.verifyBatch(limit: 128) }
        let state = try await engine.run { engine in try withEntropy(32) { try engine.save(nonceSeed: $0) } }
        try await cache.save(JSONEncoder().encode(SavedFile(state)), libraryID: account)
    }

    // MARK: Snapshot

    private func snapshot(phase: SessionPhase, members: [AccountMember] = [], requests: [AccessRequest] = [],
                          notices: SessionNotices = .empty, revisions: [String: UInt64] = [:], homes: [Home] = [], duties: HostDuties = .none) -> SessionSnapshot {
        if phase != lastPhase || revisions != lastRevisions { revision &+= 1 }
        lastPhase = phase; lastRevisions = revisions
        return SessionSnapshot(phase: phase, revision: revision, namespaceRevisions: revisions, libraryID: accountID, memberID: memberID,
                               members: members, requests: requests, notices: notices, homes: homes, duties: duties)
    }

    private func build() async throws -> SessionSnapshot {
        guard let engine else { return snapshot(phase: .noLibrary) }
        let standing = try await engine.run { try $0.me() }
        let status = try await engine.run { try $0.status() }
        if let stop = status.stopped { return try await stoppedSnapshot(engine, stop: stop, standing: standing) }
        if status.kind == .newerFormat { return snapshot(phase: .updateRequired) }
        let members = try await engine.run { try $0.members() }
        let pending = try await pendingRequests(members: members)
        let homes = try await engine.run { try $0.homes() }
        var phase: SessionPhase
        var readable: [String] = []
        switch standing.kind {
        case .unknown:
            try await ensureOwnRequest()
            return snapshot(phase: .waitingForApproval, members: members, requests: pending, homes: homes)
        case .controller:
            phase = .failed(error: .other(detail: "this identity is a controller, not a member"))
        case .member:
            if standing.member?.revokedAt != nil { phase = .denied }
            else {
                // Denied only when this member lost access it was granted, never for a library namespace it was never
                // granted (`libraryNamespaces` wider than its grant, or an approval that narrowed its request):
                // `notGranted` on a namespace its verified grant does not name, while it is not provisional, is skipped
                // (neither denied nor published).
                phase = .ready
                let granted = standing.member?.grant?.namespaces ?? []
                let provisional = standing.member?.provisional ?? false
                for namespace in configuration.libraryNamespaces {
                    guard let denial = try await engine.run({ try $0.access(namespace: namespace) }) else { readable.append(namespace); continue }
                    if denial.reason == .notGranted, !provisional, !granted.contains(namespace) { continue }
                    phase = [.notReadable, .unavailable].contains(denial.reason) ? .unavailable(reason: denial.detail) : .denied
                    break
                }
            }
        }
        var revisions: [String: UInt64] = [:]
        if phase == .ready { for r in try await engine.run({ try $0.revisions() }) where readable.contains(r.namespace) { revisions[r.namespace] = r.revision } }
        let notices = try await currentNotices()
        let head = try await engine.run { try $0.headSeq() }
        lastHead = head
        if phase == .ready { revisions["colophon.authority"] = head }
        let visible = phase == .ready
        let duties = try await hostDuties(notices: notices, homes: homes)
        return snapshot(phase: phase, members: members, requests: pending, notices: notices, revisions: visible ? revisions : [:], homes: homes, duties: duties)
    }

    static func isStopped(_ engine: ColophonEngine) async throws -> Bool { try await engine.run { try $0.status() }.stopped != nil }

    /// The stopped phase (spec §1 "A stop"): only from the verified status. What the device holds stays readable as of the
    /// stop (revisions are published for the namespaces this member may read), and no notices or duties are computed:
    /// a stopped reader answers no question of currency, and the host builds nothing.
    private func stoppedSnapshot(_ engine: ColophonEngine, stop: AccountStop, standing: Standing) async throws -> SessionSnapshot {
        // The moment the stop is verified it is persisted (the sealed saved state carries it as a floor).
        if !lastPhase.isStopped, let account = accountID { try await persistSaved(engine, account: account) }
        let members = try await engine.run { try $0.members() }
        let homes = try await engine.run { try $0.homes() }
        var revisions: [String: UInt64] = [:]
        if standing.kind == .member, standing.member?.revokedAt == nil {
            for r in try await engine.run({ try $0.revisions() }) where configuration.libraryNamespaces.contains(r.namespace) {
                if try await engine.run({ try $0.access(namespace: r.namespace) }) == nil { revisions[r.namespace] = r.revision }
            }
            if !revisions.isEmpty { revisions["colophon.authority"] = try await engine.run { try $0.headSeq() } }
        }
        return snapshot(phase: .stopped(seq: stop.seq, layout: stop.layout), members: members, revisions: revisions, homes: homes)
    }

    private func localKeyIDs() async -> [String] {
        var ids: [String] = []
        if let memberID { ids.append(memberID) }
        if let owner = try? await KeyCustody.keyID(of: configuration.ownerController) { ids.append(owner) }
        if let kit = configuration.recoveryKeys, let id = try? await KeyCustody.keyID(of: kit) { ids.append(id) }
        return ids
    }
    private func currentNotices() async throws -> SessionNotices {
        guard let engine else { return .empty }
        let keys = await localKeyIDs()
        let seq = journal.shownSeq, shown = journal.shownTransitions
        let raw = try await engine.run { try $0.notices(shownSeq: seq, shownTransitions: shown, localKeys: keys) }
        // The member engine that reads the account is not a controller, so the engine reports nothing as vetoable
        // to it. The one-tap veto is the owner controller's: this device may offer it when the owner key is a
        // controller with `control` or `recover` and the deadline the engine computed has not passed.
        let controllers = try await engine.run { try $0.controllers() }
        let ownerID = try? await KeyCustody.keyID(of: configuration.ownerController)
        let ownerMayVeto = controllers.first { $0.id == ownerID }.map { $0.roles.contains(.control) || $0.roles.contains(.recover) } ?? false
        let now = nowMs
        let pending = raw.pending.map { p in
            Pending(digest: p.digest, by: p.by, signers: p.signers, issuedMs: p.issuedMs, anchorSeq: p.anchorSeq, firstSeenSeq: p.firstSeenSeq,
                    dueMs: p.dueMs, vetoDeadlineMs: p.vetoDeadlineMs, fullSet: p.fullSet, components: p.components, removes: p.removes,
                    adds: p.adds, vetoes: p.vetoes, vetoable: ownerMayVeto && p.fullSet != true && (p.vetoDeadlineMs.map { now <= $0 } ?? false))
        }
        let activations = raw.activations.filter { !journal.seenActivations.contains($0.seq) }
        return SessionNotices(notices: Notices(pending: pending, activations: activations, owed: raw.owed,
                                               controllersWithoutSlot: raw.controllersWithoutSlot, vaultRetiring: raw.vaultRetiring, noHome: raw.noHome))
    }
    /// Marks one activation seen, and nothing else: a pending transition is never dismissed by it (it stays until it is
    /// vetoed, activates or is dead). `shownSeq` moves up only over activations that are all seen, so an activation the
    /// person has not seen keeps being shown.
    func acknowledgeActivation(seq: UInt64) async throws -> SessionSnapshot {
        try await gated {
            guard engine != nil else { return snapshot(phase: lastPhase) }
            try loadJournal()
            journal.seenActivations.insert(seq)
            let raw = try await rawActivations()
            var floor = journal.shownSeq
            for activation in raw.sorted(by: { $0.seq < $1.seq }) {
                guard journal.seenActivations.contains(activation.seq) else { break }
                floor = max(floor, activation.seq)
            }
            journal.shownSeq = floor
            journal.seenActivations = journal.seenActivations.filter { $0 > floor }
            try saveJournal()
            return try await build()
        }
    }
    private func rawActivations() async throws -> [SeenActivation] {
        guard let engine else { return [] }
        let keys = await localKeyIDs()
        let seq = journal.shownSeq, shown = journal.shownTransitions
        return try await engine.run { try $0.notices(shownSeq: seq, shownTransitions: shown, localKeys: keys) }.activations
    }

    // MARK: Host duties (§17.5)

    private func hostDuties(notices: SessionNotices, homes: [Home]) async throws -> HostDuties {
        guard let engine else { return .none }
        var duties = HostDuties()
        let controllers = try await engine.run { try $0.controllers() }
        duties.soleDevice = controllers.filter { $0.roles.contains(.control) && !$0.suspended }.count <= 1
        duties.homeLabels = Dictionary(homes.map { ($0.id, $0.label) }, uniquingKeysWith: { first, _ in first })
        let policy = try await engine.run { try $0.policy() }
        let quorum = Int(max(1, policy.headQuorum))
        let now = nowMs
        if !homes.isEmpty {
            for pending in notices.pending where now > pending.issuedMs + 300_000 {
                let receipted = try await engine.run { try $0.receiptedBy(object: pending.digest) }.count
                if receipted < quorum {
                    duties.deadTransitions.append(DeadTransition(digest: pending.digest, receipted: receipted, quorum: quorum,
                                                                 canResign: journal.signedChanges[pending.digest] != nil))
                }
            }
        }
        for home in homes {
            let configured = transport(for: home)
            let routes = configured?.deliveryRoutes ?? []
            let label = home.label
            if Set(routes.map(\.reaches)).count < 2 {
                duties.routes.append(RouteState(home: home.id, label: label, registered: false,
                    detail: "This app has fewer than two ways to reach you about changes to your account (on different devices or services). Add a second one."))
            } else if journal.routes[home.id] == true {
                duties.routes.append(RouteState(home: home.id, label: label, registered: true, detail: ""))
            } else {
                duties.routes.append(RouteState(home: home.id, label: label, registered: false,
                    detail: journal.routes[home.id] == false || configured?.registerRoutes == nil
                        ? "\(label) does not offer notices yet, so it cannot tell you about a pending change. This app checks for them itself."
                        : "Your ways to be reached are not registered with \(label) yet."))
            }
        }
        let follow = try await engine.run { try $0.removalFollowUp() }.filter { !journal.answeredRemovals.contains($0.seq) }
        if !follow.isEmpty {
            let members = Dictionary(try await engine.run { try $0.members() }.map { ($0.id, $0.label) }, uniquingKeysWith: { first, _ in first })
            let labels = Dictionary(controllers.map { ($0.id, $0.label) }, uniquingKeysWith: { first, _ in first })
            duties.removals = follow.map { r in
                RemovalFollowUp(seq: r.seq, removed: r.removed,
                    members: r.members.map { RemovalFollowUp.Item(id: $0, label: members[$0] ?? String($0.prefix(8))) },
                    controllers: r.controllers.map { RemovalFollowUp.Item(id: $0, label: labels[$0] ?? String($0.prefix(8))) })
            }
        }
        let delay = Int64(policy.recoveryDelay) / 6
        duties.pollInterval = notices.pending.isEmpty ? .seconds(max(60, delay)) : .seconds(15)
        return duties
    }

    /// Registers this host's delivery routes with every home that offers it and has not got them (§17.5).
    func registerRoutes() async throws -> SessionSnapshot {
        try await gated {
            guard let engine, let account = accountID else { return snapshot(phase: lastPhase) }
            try loadJournal()
            for home in try await engine.run({ try $0.homes() }) where journal.routes[home.id] != true {
                guard let configured = transport(for: home), Set(configured.deliveryRoutes.map(\.reaches)).count >= 2 else { continue }
                guard let register = configured.registerRoutes else { journal.routes[home.id] = false; continue }
                journal.routes[home.id] = try await register(account, configured.deliveryRoutes)
            }
            try saveJournal()
            return try await build()
        }
    }

    /// Signs a transition with the owner's keys, stores it, and keeps its change so a dead one can be signed again.
    /// Returns its digest; the session then submits it to every home.
    func submitTransition(_ changeJSON: String, rule: RuleKind = .control) async throws -> (String, SessionSnapshot) {
        try await gated {
            if engine == nil { _ = try await reconcile() }
            let digest = try await withOwner { owner, custody, ownerID -> String in
                let signers = try await signers(owner, ownerID: ownerID, need: .control)
                let written = try await owner.execute(custody: custody) { try $0.beginTransition(changeJson: changeJSON, signers: signers, rule: rule, entropy: Data()) }
                try await persist(written, on: owner)
                return Self.objectDigest(in: written.stores, prefix: "transitions/") ?? ""
            }
            try loadJournal()
            if !digest.isEmpty { journal.signedChanges[digest] = changeJSON; try saveJournal() }
            return (digest, try await reconcile())
        }
    }
    /// Signs the same change again (a dead transition this device signed).
    func resign(_ digest: String) async throws -> (String, SessionSnapshot) {
        try loadJournal()
        guard let change = journal.signedChanges[digest] else { throw SessionError.invalidCommand }
        return try await submitTransition(change)
    }
    /// Suspends `key` while `transition` is pending (§8.7), signed by the owner key.
    func suspend(key: String, transition: String) async throws -> (String, SessionSnapshot) {
        try await gated {
            if engine == nil { _ = try await reconcile() }
            let digest = try await withOwner { owner, custody, ownerID -> String in
                let written = try await owner.execute(custody: custody) { engine in
                    try withEntropy(32) { try engine.beginSuspend(key: key, transition: transition, signer: ownerID, entropy: $0) }
                }
                try await persist(written, on: owner)
                return Self.objectDigest(in: written.stores, prefix: "") ?? ""
            }
            return (digest, try await reconcile())
        }
    }
    /// The digest an object's store path names (`transitions/<digest>.json`), or for an authority entry the SHA-256 of its
    /// body as the engine names it.
    static func objectDigest(in stores: [Store], prefix: String) -> String? {
        for store in stores where prefix.isEmpty || store.path.hasPrefix(prefix) {
            let name = (store.path as NSString).lastPathComponent.replacingOccurrences(of: ".json", with: "")
            if name.count == 64, name.allSatisfy({ $0.isHexDigit }) { return name }
        }
        return nil
    }

    // MARK: Requests (a member asking, an owner approving)

    private func requestPath(_ id: String) -> String { OwnRequest.path(id) }
    private func ownRequestBytes() async throws -> Data {
        guard let account = accountID, memberID != nil else { throw SessionError.notReady }
        return try await OwnRequest.make(configuration, keys: memberKeys, account: account, nowMs: nowMs)
    }
    private func ensureOwnRequest() async throws {
        guard let id = memberID else { return }
        guard let account = accountID else { throw SessionError.notReady }
        _ = try await OwnRequest.ensure(configuration, medium: try storage(), keys: memberKeys, account: account, memberID: id, nowMs: nowMs)
    }
    func exportRequest() async throws -> Data {
        try await gated {
            try loadJournal()
            if engine == nil { _ = try await reconcile() }
            guard let id = memberID else { throw SessionError.notReady }
            try await ensureOwnRequest()
            return try storage().read(requestPath(id))
        }
    }
    private func pendingRequests(members: [AccountMember]) async throws -> [AccessRequest] {
        let known = Set(members.map(\.id))
        var out: [AccessRequest] = []
        for entry in try storage().listing(prefix: "requests/") {
            // OwnRequest writes one flat record per member.
            guard !entry.path.dropFirst("requests/".count).contains("/") else { continue }
            guard let bytes = try? storage().read(entry.path), let info = try? accountRequestInfo(raw: bytes),
                  !known.contains(info.member), info.member != memberID else { continue }
            out.append(Self.accessRequest(info))
        }
        return out
    }
    private static func accessRequest(_ info: RequestInfo) -> AccessRequest {
        AccessRequest(id: info.member, label: info.label, kind: info.kind, termsJSON: info.termsJson, record: info.raw)
    }

    // MARK: Pairing before approval (§7.3, §9.1)

    /// The pairing ledger of this device (§7.3): five failed sessions an hour and one ceremony at a time, enforced by
    /// the core. Kept sealed under the device key in the private container (`pairing-ledger.bin`), with its generation
    /// recorded beside it (`pairing-ledger.generation`): a missing, edited or older ledger opens as a spent budget. It
    /// records sessions only, never a request.
    ///
    /// Every change happens under `withLedger`: an exclusive `flock` on `pairing-ledger.lock` in the private container,
    /// which every process and every session over that container takes, so two instances never change the ledger at
    /// once. Under the lock the ledger is reloaded whenever the stored generation is not the one held, so a ceremony
    /// another instance started is seen live (`pairing:busy`), and a change is sealed and written before the lock goes.
    /// The ledger held, and the stored generation it was loaded at or last persisted as.
    private var ledger: (account: String, limiter: PairingFailureLimiter, base: UInt64)?
    private var ledgerURL: URL { configuration.privateContainer.appendingPathComponent("pairing-ledger.bin") }
    private var ledgerFloorURL: URL { configuration.privateContainer.appendingPathComponent("pairing-ledger.generation") }
    private var ledgerLockURL: URL { configuration.privateContainer.appendingPathComponent("pairing-ledger.lock") }
    private func storedGeneration() -> UInt64 {
        (try? AtomicFile.read(ledgerFloorURL, maximumBytes: 64)).flatMap { UInt64(String(decoding: $0, as: UTF8.self)) } ?? 0
    }
    /// The ledger as stored now (the lock is held).
    private func loadLedger(_ account: String) throws -> PairingFailureLimiter {
        let sealed = (try? AtomicFile.read(ledgerURL, maximumBytes: 1 << 20)) ?? Data()
        let key = try configuration.deviceSecrets.key(for: account)
        let opened = try key.withUnsafeData {
            try PairingFailureLimiter.open(sealed: sealed, deviceKey: $0, account: account, floor: storedGeneration(), nowMs: nowMs)
        }
        ledger = (account, opened, try opened.generation())
        return opened
    }
    /// Persists the sealed ledger, then its generation (the lock is held). Throws when either cannot be written: a start
    /// is then never answered with a nonce (fail closed).
    private func keepLedger(_ account: String, _ limiter: PairingFailureLimiter) throws {
        let key = try configuration.deviceSecrets.key(for: account)
        let sealed = try key.withUnsafeData { k in try withEntropy(32) { try limiter.seal(deviceKey: k, account: account, entropy: $0) } }
        try AtomicFile.write(sealed, to: ledgerURL)
        let generation = try limiter.generation()
        try AtomicFile.write(Data(String(generation).utf8), to: ledgerFloorURL)
        ledger = (account, limiter, generation)
    }
    /// Runs `body` on the ledger under the cross-instance lock; a change it made is persisted before the lock is released,
    /// also when it throws.
    private func withLedger<T>(_ account: String, _ body: (PairingFailureLimiter) throws -> T) throws -> T {
        try FileManager.default.createDirectory(at: configuration.privateContainer, withIntermediateDirectories: true)
        let fd = open(ledgerLockURL.path, O_RDWR | O_CREAT | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw SessionError.notReady }
        defer { close(fd) }
        while flock(fd, LOCK_EX) != 0 { guard errno == EINTR else { throw SessionError.notReady } }
        defer { flock(fd, LOCK_UN) }
        var limiter: PairingFailureLimiter
        // The held ledger is current when the store still has the generation it was loaded or persisted at; its own
        // later changes (a confirmed pairing's release) are then kept. Otherwise another instance wrote: reload.
        if let held = ledger, held.account == account, held.base == storedGeneration() { limiter = held.limiter }
        else { limiter = try loadLedger(account) }
        let before = ledger?.base ?? 0
        do {
            let out = try body(limiter)
            if try limiter.generation() != before { try keepLedger(account, limiter) }
            return out
        } catch {
            if (try? limiter.generation()) != before { try? keepLedger(account, limiter) }
            throw error
        }
    }
    /// The joining device: a code-path pairing for its own member key. Send `commitment()` with the request.
    func beginJoinPairing() async throws -> AccountPairing {
        try await gated {
            try loadJournal()
            if engine == nil { _ = try await reconcile() }
            guard let account = accountID else { throw SessionError.notReady }
            let e = try await memberKeys.publicKeys().signing
            return try withEntropy(32) { try AccountPairing.join(account: account, e: e, nb: $0) }
        }
    }
    /// The approving device's person started a ceremony for one incoming commitment: a session that reserves one of
    /// the five an hour, and the nonce to send back. While another is live (in this session or any other instance over
    /// the same private container) this is refused (`pairing:busy`); the reservation is persisted before the nonce
    /// exists, and if it cannot be, no nonce is produced.
    func beginApproval(commitment: Data) async throws -> ApprovalStart {
        try await gated {
            if engine == nil { _ = try await reconcile() }
            guard let account = accountID else { throw SessionError.notReady }
            let at = nowMs
            let pairing = try withLedger(account) { limiter in
                try AccountPairing.existingReceiveCommitment(account: account, commitment: commitment, limiter: limiter, nowMs: at)
            }
            let nonce = try withEntropy(32) { try pairing.sendNonce(na: $0) }
            return ApprovalStart(pairing: pairing, nonce: nonce)
        }
    }
    /// The approving device received the joining device's reveal: the six digits both screens show. A reveal that does
    /// not open the commitment, or comes after the ten-minute timeout, aborts the session (it stays counted).
    func approvalCode(pairing: AccountPairing, e: Data, nb: Data) async throws -> String {
        try await gated {
            guard let account = accountID else { throw SessionError.notReady }
            let at = nowMs
            return try withLedger(account) { try pairing.receiveReveal(e: e, nb: nb, limiter: $0, nowMs: at) }
        }
    }
    /// The codes did not match (or the person stopped): the session ends on this device, counted.
    func rejectPairing(_ pairing: AccountPairing) async throws {
        try await gated {
            guard let account = accountID else { throw SessionError.notReady }
            let at = nowMs
            try withLedger(account) { limiter in
                switch try pairing.stage() {
                case .code, .revealed: try pairing.reject(limiter: limiter, nowMs: at)
                default: try pairing.abandon(nowMs: at)
                }
            }
        }
    }
    /// Ends a ceremony this device started, in any stage before it is confirmed (the person cancelled, the other device
    /// went away). It stays counted.
    func abandonApproval(_ pairing: AccountPairing) async throws {
        try await gated {
            let at = nowMs
            guard let account = accountID else { try pairing.abandon(nowMs: at); return }
            try withLedger(account) { _ in try pairing.abandon(nowMs: at) }
        }
    }
    /// The approving device scanned a request from the joining device's screen: its canonical envelope, the scan path's
    /// one payload (§9.1). Nothing is stored about the request; the result's pairing approves it once.
    func scanRequest(_ data: Data) async throws -> ScannedRequest {
        try await gated {
            if engine == nil { _ = try await reconcile() }
            guard let account = accountID else { throw SessionError.notReady }
            let at = nowMs
            let pairing = try withLedger(account) { try AccountPairing.scanRequest(account: account, request: data, limiter: $0, nowMs: at) }
            return ScannedRequest(request: Self.accessRequest(try accountRequestInfo(raw: data)), pairing: pairing)
        }
    }
    /// Keeps a change the app made to the ledger directly (a confirmed pairing gives its reservation back); a lost write
    /// only leaves it counted.
    private func keepLedgerChange(_ account: String) {
        guard ledger?.account == account else { return }
        _ = try? withLedger(account) { _ in () }
    }

    static func accountKind(_ kind: MemberKind) -> AccountMemberKind {
        switch kind { case .device: .device; case .app: .app; case .agent: .agent; case .server: .server }
    }

    func termsJSON(namespaces: [String], access: [Access], expires: String?, budget: UInt64?) -> String {
        Self.terms(namespaces: namespaces, access: access, expires: expires, budget: budget)
    }

    // MARK: Owner operations

    /// Opens a controller engine for the owner, unlocks it by the owner's slot, runs `body`, locks it.
    /// A passkey owner is asked once per call (the PRF ceremony). The owner key must be a controller of the account.
    func withOwnerForMove<T: Sendable>(_ body: (ColophonEngine, KeyCustody, String) async throws -> T) async throws -> T { try await withOwner(body) }
    private func withOwner<T: Sendable>(_ body: (ColophonEngine, KeyCustody, String) async throws -> T) async throws -> T {
        guard let account = accountID else { throw SessionError.notReady }
        let custody = try await ownerCustody()
        let ownerID = try await KeyCustody.keyID(of: configuration.ownerController)
        let entries = try storage().listing()
        let key = try configuration.deviceSecrets.key(for: account)
        let owner = try await ColophonEngine.open(label: "org.luff.colophon.owner", source: MediumSource(try storage()), listing: listed(entries),
            identity: AccountIdentity(kind: .controller, id: ownerID), account: account, namespaces: [],
            saved: nil, deviceKey: key, nowMs: nowMs)
        do {
            guard try await owner.run({ try $0.controllers() }).contains(where: { $0.id == ownerID }) else { throw SessionError.ownerRequired }
            try await unlockOwner(owner, custody: custody, ownerID: ownerID)
            let result = try await body(owner, custody, ownerID)
            await owner.lock()
            return result
        } catch { await owner.lock(); throw error }
    }
    private func ownerCustody() async throws -> KeyCustody {
        var list: [any AsyncKeyProvider] = [configuration.ownerController]
        if let kit = configuration.recoveryKeys { list.append(kit) }
        return try await KeyCustody(list)
    }
    /// Opens the controller's own slot with the owner's key (a PRF ceremony for a passkey, a silent ECDH for a device key).
    private func unlockOwner(_ owner: ColophonEngine, custody: KeyCustody, ownerID: String) async throws {
        let slots = try await owner.run { try $0.slots() }
        guard let slot = slots.first(where: { $0.controllers.count == 1 && $0.controllers[0].id == ownerID })
                ?? slots.first(where: { $0.controllers.contains { $0.id == ownerID } }) else { throw SessionError.ownerRequired }
        let inputs = try await owner.run { try $0.beginUnlockSlot(index: slot.index) }
        let secrets = try await custody.answer(unlock: inputs)
        _ = try await owner.finishUnlockSlot(index: slot.index, secrets: secrets)
    }
    private func signers(_ owner: ColophonEngine, ownerID: String, need: SignerNeed) async throws -> [String] {
        let chosen = try await owner.run { try $0.suggestSigners(available: [ownerID], need: need) }
        return chosen.isEmpty ? [ownerID] : chosen
    }

    /// Approves `request`, spending `pairing`: confirmed on this device for exactly the request's key (§9.1). The core
    /// refuses any other pairing; it is spent whatever the answer.
    func approve(_ request: AccessRequest, pairing: AccountPairing, terms: String?) async throws -> SessionSnapshot {
        try await gated {
            if engine == nil { _ = try await reconcile() }
            try await withOwner { owner, custody, ownerID in
                let signers = try await signers(owner, ownerID: ownerID, need: .member)
                let terms = terms ?? request.termsJSON
                let written = try await owner.execute(custody: custody) { engine in try withEntropy(32) { try engine.beginApprove(request: request.record, termsJson: terms, signers: signers, pairing: pairing, entropy: $0) } }
                try await persist(written, on: owner)
            }
            // The confirmed pairing gave its reservation back; keep the ledger (a lost write only leaves it counted).
            if let account = accountID { keepLedgerChange(account) }
            return try await reconcile()
        }
    }
    func revoke(_ member: String) async throws -> SessionSnapshot {
        try await gated {
            if engine == nil { _ = try await reconcile() }
            try await withOwner { owner, custody, ownerID in
                let signers = try await signers(owner, ownerID: ownerID, need: .control)
                let written = try await owner.execute(custody: custody) {
                    engine in try withEntropy(32) { try engine.beginRevoke(member: member, keep: RevokeKeep(mode: .everything, kept: [], heads: []), signers: signers, entropy: $0) }
                }
                try await persist(written, on: owner)
            }
            return try await reconcile()
        }
    }
    /// The removal follow-up's one action (§17.5): revokes every member the removed key admitted (keeping what they
    /// wrote) and removes every controller it added, signed by the owner, then records the follow-up as answered. What
    /// the engine lists now is what is removed: an item already gone is not touched again.
    func removeFollowUp(seq: UInt64) async throws -> SessionSnapshot {
        try await gated {
            if engine == nil { _ = try await reconcile() }
            try await withOwner { owner, custody, ownerID in
                guard let follow = try await owner.run({ try $0.removalFollowUp() }).first(where: { $0.seq == seq }) else { return }
                for member in follow.members {
                    let signers = try await signers(owner, ownerID: ownerID, need: .control)
                    let written = try await owner.execute(custody: custody) {
                        engine in try withEntropy(32) { try engine.beginRevoke(member: member, keep: RevokeKeep(mode: .everything, kept: [], heads: []), signers: signers, entropy: $0) }
                    }
                    try await persist(written, on: owner)
                }
                if !follow.controllers.isEmpty {
                    let signers = try await signers(owner, ownerID: ownerID, need: .control)
                    let list = follow.controllers
                    let written = try await owner.execute(custody: custody) {
                        engine in try withEntropy(32) { try engine.beginRemoveController(remove: list, keep: [], signers: signers, rule: .control, rotate: false, entropy: $0) }
                    }
                    try await persist(written, on: owner)
                }
            }
            journal.answeredRemovals.insert(seq); try saveJournal()
            return try await reconcile()
        }
    }
    /// The person keeps what a removed key admitted: the follow-up is recorded as answered.
    func keepFollowUp(seq: UInt64) async throws -> SessionSnapshot {
        try await gated {
            try loadJournal()
            journal.answeredRemovals.insert(seq); try saveJournal()
            return try await reconcile()
        }
    }
    /// One call: sign a veto of the pending transition with the keys this device holds, store it, and let the
    /// next exchange submit it to every home (§17.5).
    func veto(_ transition: String) async throws -> SessionSnapshot {
        try await gated {
            if engine == nil { _ = try await reconcile() }
            try await withOwner { owner, custody, ownerID in
                let signers = try await signers(owner, ownerID: ownerID, need: .veto)
                let written = try await owner.execute(custody: custody) { try $0.beginVeto(transition: transition, signers: signers, entropy: Data()) }
                try await persist(written, on: owner)
            }
            return try await reconcile()
        }
    }
    /// Adds a controller key (a second device, a passkey, a security key) as an immediate `approve` controller.
    func addController(_ spec: ControllerSpec, mode: AddMode, possession key: any AsyncKeyProvider) async throws -> SessionSnapshot {
        try await gated {
            if engine == nil { _ = try await reconcile() }
            try await withOwner { owner, ownerCustody, ownerID in
                // The new key signs its own possession proof; it is held for this call only.
                let custody = KeyCustody(providers: ownerCustody.providers.merging([try KeyCustody.keyID(of: spec): key]) { _, new in new })
                let signers = try await signers(owner, ownerID: ownerID, need: .control)
                let written = try await owner.execute(custody: custody) {
                    try $0.beginAddController(controller: spec, mode: mode, signers: signers, rule: .control, entropy: Data())
                }
                try await persist(written, on: owner)
            }
            return try await reconcile()
        }
    }
    /// The existing device's half of seed transfer: seals the vault seed to the device that confirmed `pairing`.
    func transferSeed(pairing: AccountPairing) async throws -> SealedSeed {
        try await gated {
            if engine == nil { _ = try await reconcile() }
            return try await withOwner { owner, _, _ in
                return try await owner.run { engine in try withEntropy(32) { try engine.transferSeed(pairing: pairing, entropy: $0) } }
            }
        }
    }
    /// The new device's half: takes the seed, builds this controller's own slot so it unlocks alone from now on.
    func acceptSeedTransfer(key: PairingTransferKey, pairing: AccountPairing, sealed: SealedSeed, label: String) async throws -> SessionSnapshot {
        try await gated {
            guard let account = accountID ?? journal.account ?? (try? discoverAccount(try storage().listing())) else { throw SessionError.notReady }
            accountID = account
            let custody = try await ownerCustody()
            let ownerID = try await KeyCustody.keyID(of: configuration.ownerController)
            let secret = try configuration.deviceSecrets.key(for: account)
            let owner = try await ColophonEngine.open(label: "org.luff.colophon.owner", source: MediumSource(try storage()),
                listing: listed(try storage().listing()), identity: AccountIdentity(kind: .controller, id: ownerID), account: account,
                namespaces: [], saved: nil, deviceKey: secret, nowMs: nowMs)
            do {
                _ = try await owner.run { try $0.acceptSeedTransfer(key: key, pairing: pairing, sealed: sealed) }
                _ = try await owner.run { try $0.load() }
                let written = try await owner.execute(custody: custody) {
                    engine in try withEntropy(32) { try engine.beginAddSlot(signer: ownerID, plan: SlotPlan(controllers: [ownerID], label: label), entropy: $0) }
                }
                try await persist(written, on: owner)
                await owner.lock()
            } catch { await owner.lock(); throw error }
            return try await reconcile()
        }
    }

    // MARK: Appointing homes later

    /// The steps of `appointHomes`, for the tests that stop a call between two of them (a crash).
    enum AppointStep: Sendable { case signed, recorded, slotted }
    /// Tests only: `appointHomes` throws right after this step, as if the process died there.
    private var appointStopForTests: AppointStep?
    func setAppointStopForTests(_ step: AppointStep?) { appointStopForTests = step }
    struct AppointStopped: Error {}
    private func reached(_ step: AppointStep) throws { if appointStopForTests == step { throw AppointStopped() } }

    /// Appoints `homes` (each one's request for this account, with its terms) and, with `adding`, adds that controller, in
    /// ONE transition signed by the owner under the control rule with the new key's possession proof (spec §8.7); records
    /// it when due; builds the new controller's own slot once it is current; and makes this session reach the homes.
    /// With no home in the state before it, the transition is due at `issued` and final at once (§13.1); with a home
    /// already current it waits out its delay and the call answers `.pending` with every transition it waits on.
    ///
    /// What is done is read from the account, never from local memory, and bound to what this call asks for: a home is
    /// done when a current home, or an appointment in a pending transition of this owner, names its configured endpoint
    /// (whatever member a home answers with on a later call); the controller when the keyring, or a pending transition of
    /// this owner, holds exactly the requested controller; the slot when a slot has exactly the new key as its holder. A
    /// call after a crash between any two steps finishes the rest and never signs any of these twice. A home request that
    /// names another account or does not name the configured endpoint, and a key already present (or pending) with another
    /// label or roles, are refused (`invalidCommand`) before anything is signed.
    func appointHomes(_ homes: [HomeConfiguration], adding: (spec: ControllerSpec, key: any AsyncKeyProvider)?) async throws -> (HomesAppointment, SessionSnapshot) {
        try await gated {
            guard homes.allSatisfy(\.isAllowed) else { throw SessionError.insecureHome }
            if engine == nil { _ = try await reconcile() }
            guard let account = accountID else { throw SessionError.notReady }
            let addedID = try adding.map { try KeyCustody.keyID(of: $0.spec) }
            let requested = try adding.map { try JSONSerialization.jsonObject(with: Data(try accountControllerJson(controller: $0.spec).utf8)) }
            var signedChange: (String, String)?
            let outcome = try await withOwner { owner, ownerCustody, ownerID -> HomesAppointment in
                var custody = ownerCustody
                if let adding, let addedID { custody = KeyCustody(providers: custody.providers.merging([addedID: adding.key]) { _, new in new }) }
                func covers(_ endpoints: [String], _ configured: HomeConfiguration) -> Bool {
                    endpoints.contains { Self.base($0) == Self.base(configured.endpoint.absoluteString) }
                }
                func isCurrent(_ configured: HomeConfiguration, in current: [Home]) -> Bool {
                    current.contains { $0.status == .home && covers($0.endpoints, configured) }
                }
                // What the pending transitions of this owner already appoint (by endpoint) or add (by controller JSON).
                let mine = try await owner.run { try $0.pending() }.filter { $0.by == ownerID }
                var inFlight: [String] = []
                var pendingEndpoints: [(digest: String, endpoints: [String])] = []
                var pendingControllers: [(digest: String, controller: Any)] = []
                for p in mine {
                    guard let change = pendingChange(p.digest) else { continue }
                    for request in ((change["homes"] as? [String: Any])?["appoint"] as? [[String: Any]]) ?? [] {
                        if let text = request["request"] as? String, let raw = Data(base64Encoded: text) { pendingEndpoints.append((p.digest, Self.requestBody(raw).endpoints)) }
                    }
                    for c in ((change["keyring"] as? [String: Any])?["add"] as? [Any]) ?? [] { pendingControllers.append((p.digest, c)) }
                }
                // 1. Each home neither current nor pending: its request for this account, checked, and the terms it asks.
                let current = try await owner.run { try $0.homes() }
                var appoint: [[String: Any]] = []
                for home in homes where !isCurrent(home, in: current) {
                    if let p = pendingEndpoints.first(where: { covers($0.endpoints, home) }) { inFlight.append(p.digest); continue }
                    guard let makeRequest = home.request else { throw SessionError.invalidCommand }
                    let raw = try await makeRequest(account)
                    let body = Self.requestBody(raw)
                    guard body.account == account, covers(body.endpoints, home) else { throw SessionError.invalidCommand }
                    let info = try accountRequestInfo(raw: raw)
                    appoint.append(["request": raw.base64EncodedString(), "terms": try JSONSerialization.jsonObject(with: Data(info.termsJson.utf8))])
                }
                // The controller: exactly the requested one, in the keyring or pending, or else added here.
                var add: [Any] = []
                if let adding, let addedID, let requested {
                    if let held = try await owner.run({ try $0.controllers() }).first(where: { $0.id == addedID }) {
                        guard held.label == adding.spec.label, Set(held.roles) == Set(adding.spec.roles) else { throw SessionError.invalidCommand }
                    } else if let p = pendingControllers.first(where: { Self.keyID(ofController: $0.controller) == addedID }) {
                        guard Self.canonicalJSON(p.controller) == Self.canonicalJSON(requested) else { throw SessionError.invalidCommand }
                        inFlight.append(p.digest)
                    } else {
                        add.append(requested)
                    }
                }
                // 2-3. One change, signed by the owner with the new key's possession proof, persisted.
                let possessionPRF: TransitionPossessionPRF?
                if !add.isEmpty, let addedID, let adding, adding.spec.key.form == .webauthn, adding.key.supportsPRF {
                    possessionPRF = try TransitionPossessionPRF(controller: addedID)
                    custody = KeyCustody(providers: custody.providers, possessionPRF: possessionPRF)
                } else {
                    possessionPRF = nil
                }
                if !appoint.isEmpty || !add.isEmpty {
                    var change: [String: Any] = [:]
                    if !appoint.isEmpty { change["homes"] = ["appoint": appoint] }
                    if !add.isEmpty { change["keyring"] = ["add": add] }
                    guard let json = Self.canonicalJSON(change) else { throw SessionError.invalidCommand }
                    let signers = try await signers(owner, ownerID: ownerID, need: .control)
                    let written = try await owner.execute(custody: custody) { try $0.beginTransition(changeJson: json, signers: signers, rule: .control, entropy: Data()) }
                    try await persist(written, on: owner)
                    if let digest = Self.objectDigest(in: written.stores, prefix: "transitions/") { inFlight.append(digest); signedChange = (digest, json) }
                    try reached(.signed)
                }
                // 4. Record what is due (at once when the account had no home).
                let at = nowMs
                _ = try await owner.run { try $0.advance(nowMs: at) }
                for due in try await owner.run({ try $0.recordDue() }) { try await persist(due, on: owner) }
                try reached(.recorded)
                let now = try await owner.run { try $0.homes() }
                var controller: Controller?
                if let addedID { controller = try await owner.run { try $0.controllers() }.first { $0.id == addedID } }
                let homesDone = homes.allSatisfy { isCurrent($0, in: now) }
                let controllerDone = addedID == nil || controller?.provisional == false
                guard homesDone, controllerDone else {
                    return .pending(transitions: Set(inFlight).sorted())
                }
                // 5. Give the new controller a slot it can unlock alone.
                if let adding, let addedID,
                   !(try await owner.run { try $0.slots() }).contains(where: { $0.controllers.map(\.id) == [addedID] }) {
                    let entrySigner = try await owner.run { engine in
                        guard try engine.policy().addThreshold == 1,
                              let held = try engine.controllers().first(where: { $0.id == ownerID }),
                              held.form == .raw, held.roles.contains(.control), !held.provisional, !held.suspended
                        else { return addedID }
                        return ownerID
                    }
                    let input = await possessionPRF?.input()
                    let plan = SlotPlan(controllers: [addedID], label: adding.spec.label)
                    let written = try await owner.execute(custody: custody) { engine in
                        try withEntropy(32) {
                            try engine.beginAddSlotWithSigners(entrySigners: [entrySigner], plan: plan,
                                                              prfSalt: input?.salt, prfChallenge: input?.challenge, entropy: $0)
                        }
                    }
                    try await persist(written, on: owner)
                }
                try reached(.slotted)
                return .done
            }
            if let (digest, json) = signedChange { try loadJournal(); journal.signedChanges[digest] = json; try saveJournal() }
            // 6. This session reaches the homes from now on (the exchange and the sync loop), without a relaunch.
            configureHomes(homes)
            return (outcome, try await reconcile())
        }
    }

    func configureHomes(_ homes: [HomeConfiguration]) {
        for home in homes where !homeConfigurations.contains(where: { Self.base($0.endpoint.absoluteString) == Self.base(home.endpoint.absoluteString) }) {
            appointedHomes.append(home)
        }
    }

    /// The `change` of a stored transition (its body's), or nil.
    private func pendingChange(_ digest: String) -> [String: Any]? {
        guard let bytes = try? storage().read("transitions/\(digest).json"),
              let envelope = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any],
              let body = (envelope["body"] as? String).flatMap({ Data(base64Encoded: $0) }),
              let value = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else { return nil }
        return value["change"] as? [String: Any]
    }
    /// The account and the `service.endpoints` a request envelope's signed body names (empty when it does not parse).
    nonisolated static func requestBody(_ raw: Data) -> (account: String?, endpoints: [String]) {
        guard let envelope = try? JSONSerialization.jsonObject(with: raw) as? [String: Any], let text = envelope["body"] as? String,
              let body = Data(base64Encoded: text), let value = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else { return (nil, []) }
        return (value["account"] as? String, ((value["service"] as? [String: Any])?["endpoints"] as? [String]) ?? [])
    }
    /// The key ID of a controller's protocol JSON (its `key.signing`), or nil.
    nonisolated static func keyID(ofController value: Any) -> String? {
        guard let text = ((value as? [String: Any])?["key"] as? [String: Any])?["signing"] as? String, let point = Data(base64Encoded: text) else { return nil }
        return try? accountKeyId(signing: point)
    }

    // MARK: Create

    func create() async throws -> SessionSnapshot {
        try await gated {
            try loadJournal()
            guard engine == nil, journal.account == nil, try storage().listing().allSatisfy({ !$0.path.hasPrefix("authority/") }) else {
                throw SessionError.destinationChanged
            }
            guard !configuration.homes.isEmpty || configuration.createWithoutHome else { throw SessionError.noHome }
            guard configuration.homes.allSatisfy(\.isAllowed) else { throw SessionError.insecureHome }
            journal.left = false
            let baseCustody = try await ownerCustody()
            let ownerKey = try await configuration.ownerController.keyDescriptor()
            let ownerID = try accountKeyId(signing: ownerKey.signing)
            let isPasskey = ownerKey.form == .webauthn
            var controllers = [ControllerSpec(key: ownerKey, label: "Owner", roles: [.approve, .control, .recover], verification: isPasskey, holder: nil, audiences: [])]
            var slots = [SlotPlan(controllers: [ownerID], label: "Owner")]
            if let kit = configuration.recoveryKeys {
                let descriptor = try await kit.keyDescriptor()
                let kitID = try accountKeyId(signing: descriptor.signing)
                controllers.append(ControllerSpec(key: descriptor, label: "Recovery kit", roles: [.recover], verification: descriptor.form == .webauthn, holder: nil, audiences: []))
                slots.append(SlotPlan(controllers: [kitID], label: "Recovery kit"))
            }
            var custody = baseCustody
            for extra in configuration.additionalControllers {
                let descriptor = try await extra.provider.keyDescriptor()
                let id = try accountKeyId(signing: descriptor.signing)
                controllers.append(ControllerSpec(key: descriptor, label: extra.label, roles: extra.roles, verification: descriptor.form == .webauthn, holder: nil, audiences: []))
                slots.append(SlotPlan(controllers: [id], label: extra.label))
                custody = KeyCustody(providers: custody.providers.merging([id: extra.provider]) { _, new in new })
            }
            var policy = try JSONSerialization.jsonObject(with: Data(accountDefaultPolicy().utf8)) as? [String: Any] ?? [:]
            if let delay = configuration.recoveryDelay { policy["recoveryDelay"] = delay }
            if let history = configuration.history { policy["history"] = history.rawValue }
            if let quorum = configuration.headQuorum { policy["headQuorum"] = quorum }
            let policyJSON = String(decoding: try JSONSerialization.data(withJSONObject: policy, options: [.sortedKeys]), as: UTF8.self)
            let params = CreateParams(label: configuration.memberLabel, namespaces: configuration.libraryNamespaces.sorted(), controllers: controllers,
                slots: slots, threshold: nil, recoverThreshold: nil, addThreshold: nil, countByHolders: false, policyJson: policyJSON,
                signers: [ownerID], rekeySigners: [ownerID])
            let (creation, created) = try await AccountCreator.create(params: params, identity: AccountIdentity(kind: .controller, id: ownerID),
                                                                       custody: custody, nowMs: nowMs)
            try storage().write(created.stores.map { MediumWrite(path: $0.path, bytes: $0.bytes) })
            journal.account = created.account; accountID = created.account
            try saveJournal()
            // The creation's own engine: unlocked as the creation left it, so the owner is asked once at first run.
            let owner = try await ColophonEngine.openCreated(creation, label: "org.luff.colophon.owner", source: MediumSource(try storage()),
                listing: listed(try storage().listing()), account: created.account, identity: AccountIdentity(kind: .controller, id: ownerID),
                namespaces: configuration.libraryNamespaces, deviceKey: try configuration.deviceSecrets.key(for: created.account), nowMs: nowMs)
            try await setUpFirstDevice(owner, account: created.account, ownerID: ownerID, custody: custody)
            return try await reconcile()
        }
    }

    /// Appoints the homes, records their activation and approves this device's member, with the creation's own
    /// engine (unlocked: the owner is not asked again). Every home is appointed in one transition, recorded at once
    /// (the state before it has no home to witness time, spec §13.1 "First upload").
    private func setUpFirstDevice(_ owner: ColophonEngine, account: String, ownerID: String, custody: KeyCustody) async throws {
        do {
            var appoint: [[String: Any]] = []
            for home in configuration.homes {
                guard let makeRequest = home.request else { continue }
                let raw = try await makeRequest(account)
                let info = try accountRequestInfo(raw: raw)
                appoint.append(["request": raw.base64EncodedString(), "terms": (try JSONSerialization.jsonObject(with: Data(info.termsJson.utf8)))])
            }
            if !appoint.isEmpty {
                let change: [String: Any] = ["homes": ["appoint": appoint]]
                let json = String(decoding: try JSONSerialization.data(withJSONObject: change, options: [.sortedKeys]), as: UTF8.self)
                let signers = try await signers(owner, ownerID: ownerID, need: .control)
                let written = try await owner.execute(custody: custody) { try $0.beginTransition(changeJson: json, signers: signers, rule: .control, entropy: Data()) }
                try await persist(written, on: owner)
                for due in try await owner.run({ try $0.recordDue() }) { try await persist(due, on: owner) }
            }
            let memberRaw = try await ownRequestBytesFor(account: account)
            // This device made the request itself, with its own member key: there is no second device to pair with,
            // so it reads its own canonical request as the scan path does (§9.1). A fresh ledger: nothing failed.
            // The creation's engine keeps the time it opened at; bring it to the scan's time, which the pairing may not
            // precede (§9.1).
            let at = nowMs
            _ = try await owner.run { try $0.advance(nowMs: at) }
            let own = try AccountPairing.scanRequest(account: account, request: memberRaw,
                                                     limiter: PairingFailureLimiter.fresh(), nowMs: at)
            let terms = Self.terms(namespaces: configuration.namespaces, access: configuration.access, expires: nil, budget: nil, services: configuration.services)
            let signers = try await signers(owner, ownerID: ownerID, need: .member)
            let approve = try await owner.execute(custody: custody) { engine in try withEntropy(32) { try engine.beginApprove(request: memberRaw, termsJson: terms, signers: signers, pairing: own, entropy: $0) } }
            try await persist(approve, on: owner)
            await owner.lock()
        } catch { await owner.lock(); throw error }
    }
    private func ownRequestBytesFor(account: String) async throws -> Data {
        memberID = try await KeyCustody.keyID(of: memberKeys)
        accountID = account
        return try await ownRequestBytes()
    }

    // MARK: Leave and rejoin

    func leave() async throws {
        try await gated {
            try loadJournal()
            await engine?.lock(); engine = nil
            journal.left = true; try saveJournal()
        }
    }
    func rejoin(keys: any AsyncKeyProvider) async throws -> SessionSnapshot {
        try await gated {
            try loadJournal()
            await engine?.lock(); engine = nil; memberOpened = false
            memberKeys = SessionKeys(base: keys); memberCustody = nil
            journal.left = false; try saveJournal()
            return try await reconcile()
        }
    }

    // MARK: Writes and queries

    func write(_ command: DomainCommand, observed: UInt64, ingress: IngressEnvelope? = nil, claimed: Date? = nil) async throws -> (WriteReceipt, SessionSnapshot) {
        if let claimed, !Self.claimable(claimed, now: now) { throw SessionError.invalidCommand }
        return try await gated {
            let fresh = try await reconcile()
            guard fresh.phase == .ready, let engine, let custody = memberCustody else { throw SessionRefusal(snapshot: fresh, error: .notReady) }
            guard observed == revision else { throw SessionRefusal(snapshot: fresh, error: .staleRevision) }
            guard configuration.namespaces.contains(command.namespace), configuration.access.contains(.write) else { throw SessionError.invalidCommand }
            let ceiling = command.kind == "colophon.blobPublish" ? 1024 * 1024 : 256 * 1024
            guard command.payload.count <= ceiling else { throw SessionError.invalidCommand }
            if let ingress {
                guard ingress.libraryID == accountID, ingress.memberID == memberID else { throw SessionError.destinationChanged }
                try ingress.validate()
                if let operation = journal.ingress[ingress.id] { return (.saved(operationID: operation), fresh) }
            }
            let payload = String(decoding: command.payload, as: UTF8.self)
            let claimedMs = claimed.map { Int64(($0.timeIntervalSince1970 * 1000).rounded(.down)) }
            let written = try await engine.execute(custody: custody) {
                engine in try withEntropy(32) { entropy in
                    if let claimedMs {
                        return try engine.beginWriteClaimed(namespace: command.namespace, kind: command.kind, payloadJson: payload, claimedMs: claimedMs, entropy: entropy)
                    }
                    return try engine.beginWrite(namespace: command.namespace, kind: command.kind, payloadJson: payload, entropy: entropy)
                }
            }
            try await persist(written)
            let operation = Self.operationID(in: written.stores) ?? ""
            if let ingress {
                // Receipts only matter while an envelope can still be drained (they expire within 7 days): keep the newest few thousand.
                if journal.ingress.count >= 4096 { journal.ingress = Dictionary(uniqueKeysWithValues: Array(journal.ingress.prefix(2048))) }
                journal.ingress[ingress.id] = operation; try saveJournal()
            }
            return (.saved(operationID: operation), try await build())
        }
    }
    /// A claimed date a write may carry: finite, no later than `now`, and within the years 0001–9999 (spec §2.2), so the
    /// conversion to milliseconds can never trap.
    static func claimable(_ claimed: Date, now: Date) -> Bool {
        let seconds = claimed.timeIntervalSince1970
        return seconds.isFinite && seconds >= -62_135_596_800 && seconds < 253_402_300_800 && claimed <= now
    }
    /// `ops/<author>/<namespace>/<clock>-<id>.json`: the operation ID is the part after the clock.
    static func operationID(in stores: [Store]) -> String? {
        for store in stores where store.path.hasPrefix("ops/") {
            let name = (store.path as NSString).lastPathComponent.replacingOccurrences(of: ".json", with: "")
            if let dash = name.firstIndex(of: "-") { return String(name[name.index(after: dash)...]) }
        }
        return nil
    }

    func query(namespace: String, name: String, arguments: Data) async throws -> Data {
        guard let engine else { throw SessionError.notReady }
        let args = String(decoding: arguments, as: UTF8.self)
        let text = try await engine.run { try $0.queryJson(namespace: namespace, name: name, argsJson: args) }
        return Self.queryResult(text)
    }
    /// The engine's `{"ok":true,"value":X}` outcome as the bytes `DomainQueryResult` decodes.
    static func queryResult(_ text: String) -> Data {
        guard let object = try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any] else { return Data(text.utf8) }
        if object["ok"] as? Bool == true, let value = object["value"],
           let data = try? JSONSerialization.data(withJSONObject: value, options: [.fragmentsAllowed, .sortedKeys]) { return data }
        let reason = (object["reason"] as? String) ?? "unavailable"
        let known = ["notFound", "deleted", "notGranted", "unavailable", "invalidArgument", "staleCursor", "contentTooLarge"]
        return Data("{\"ok\":false,\"reason\":\"\(known.contains(reason) ? reason : "unavailable")\"}".utf8)
    }
    /// The namespace's whole fold as the engine reports it (`view_json`), unchanged.
    func view(namespace: String) async throws -> Data {
        guard let engine else { throw SessionError.notReady }
        return Data(try await engine.run { try $0.viewJson(namespace: namespace) }.utf8)
    }
    /// Reads the already-open verifier under the worker gate without reconciling or opening storage.
    func acceptedAuthorityHead() async throws -> (account: String, sequence: UInt64, digest: String) {
        try await gated {
            guard !locked, let engine, let account = accountID else { throw SessionError.notReady }
            guard !reorganizedAuthority.contains(account) else { throw SessionError.staleRevision }
            return try await engine.run {
                let status = try $0.status()
                guard status.kind == .ok, !status.rollback, status.stopped == nil else { throw SessionError.staleRevision }
                let sequence = try $0.headSeq()
                let digest = try $0.headDigest()
                guard sequence > 0, !digest.isEmpty else { throw SessionError.notReady }
                return (account, sequence, digest)
            }
        }
    }

    func ledger() async throws -> Data {
        guard let engine else { throw SessionError.notReady }
        return Data(try await engine.run { try $0.ledgerJson() }.utf8)
    }

    // MARK: Exchange

    /// What the engine's homes are, matched to the transports this host configured.
    private func transport(for home: Home) -> HomeConfiguration? {
        func base(_ text: String) -> String { text.trimmingCharacters(in: CharacterSet(charactersIn: "/")) }
        return homeConfigurations.first { configured in home.endpoints.contains { base($0) == base(configured.endpoint.absoluteString) } }
    }

    struct ExchangeResult: Sendable {
        var passes = 0; var faults: [HomeFault] = []; var issues: [HomeIssue] = []; var changed = false; var unauthorized = false
        /// A pass that did not finish (the engine still waited after its one recovery): the exchange failed.
        var failed = false
        /// The account is stopped (a final layout raise this device verified, spec §1 "A stop"): no pass runs, and a pass that
        /// brought the stop in ended there. Not a failure: the session shows the stopped phase and runs no sync loop.
        var stopped = false
        /// A home answered `503 {"result":"unavailable"}`: the home is not available. Retried with backoff; not about this device.
        var homeUnavailable = false
    }
    /// One pass with every home. The network calls run outside the gate; each engine step and the
    /// persistence of its stores run inside it, so an unpersisted answer is never visible to a refresh.
    /// A home is held to `HomeLimits`: steps per pass, the time of an exchange, the size of each response.
    /// Tests only: answers `exchange_next` for a home instead of the engine when it returns a step.
    private var nextStepOverride: (@Sendable (String) -> ExchangeStep?)?
    func setNextStepOverride(_ override: (@Sendable (String) -> ExchangeStep?)?) { nextStepOverride = override }

    func exchange(nowMsOverride: Int64? = nil) async throws -> ExchangeResult {
        try await gated { if engine == nil { _ = try await reconcile() } }
        var result = ExchangeResult()
        guard let engine else { return result }
        let homes = try await engine.run { try $0.exchangeHomes() }
        // This device asked to join and holds no grant for itself: a `refused:revoked` for its own call means "not approved yet".
        let awaitingApproval = (try? await engine.run { try $0.me() }.kind) == .unknown
        for home in homes {
            guard let configured = transport(for: home) else { continue }
            // The home asked for time (`Retry-After`): it is not contacted again before then.
            // What it said stays shown until then.
            if let until = notBefore[home.id], now < until {
                if let said = waitingIssue[home.id] {
                    result.issues.append(said)
                    if case .homeUnavailable = said.problem { result.homeUnavailable = true }
                }
                continue
            }
            waitingIssue[home.id] = nil
            guard configured.isAllowed else {
                result.issues.append(HomeIssue(home: home.id, problem: .insecureEndpoint(configured.endpoint.absoluteString)))
                continue
            }
            if let token = configured.bearerToken { _ = try await engine.run { try $0.exchangeSetBearer(home: home.id, token: token) } }
            // The pass starts from fresh local state.
            try await gated {
                guard self.engine === engine else { throw SessionError.destinationChanged }
                let entries = try storage().listing()
                try await advance(engine, to: nowMs)
                try await refresh(engine, listing: listed(entries))
                try await unlockIfPossible()
            }
            // A stopped account runs no exchange pass (spec §1 "A stop": it accepts no head and asks no call).
            if try await Self.isStopped(engine) { result.stopped = true; break }
            let started = ContinuousClock.now
            var progress = true
            var passIndex = 0
            var stopped: HomeProblem?
            var recovered = false
            // The pass was left for a `Retry-After`: the answer was not given to the engine, so its request is abandoned.
            var abandon = false
            do {
            // A pass can end before everything moved (the engine plans the next stage from what the home just
            // said): run passes until one moves nothing, at most `HomeLimits.passes`.
            homeLoop: while progress, passIndex < HomeLimits.passes {
            progress = false; passIndex += 1
            var steps = 0
            loop: while true {
                steps += 1
                try Task.checkCancellation()
                if steps > HomeLimits.stepsPerPass { stopped = .tooManySteps(HomeLimits.stepsPerPass); break homeLoop }
                if ContinuousClock.now - started > HomeLimits.exchangeTime {
                    stopped = .tooSlow(seconds: Int(HomeLimits.exchangeTime.components.seconds)); break homeLoop
                }
                let step = try await gated { () -> ExchangeStep in
                    if let override = nextStepOverride, let step = override(home.id) { return step }
                    return try await engine.run { try $0.exchangeNext(home: home.id) }
                }
                switch step.kind {
                case .done: break loop
                // This loop answers every request it is given, so an outstanding one belongs to a pass that was interrupted
                // (a cancelled caller): abandon it and run the pass again, once.
                // A second `Waiting` after that recovery means the pass cannot finish: a failed exchange, never "done".
                case .waiting:
                    await abortPass(engine, home: home.id)
                    if recovered { stopped = .stillWaiting; break homeLoop }
                    recovered = true; progress = true
                    break loop
                case .needCall:
                    guard let need = step.need else { break loop }
                    do { try await provideCall(for: need, home: home, configured: configured) }
                    catch let problem as HomeProblem { stopped = problem == .callRefused(code: "refused:revoked") && awaitingApproval ? .waitingForApproval : problem; break homeLoop }
                case .request:
                    guard let request = step.request else { break loop }
                    // A request is for this home, except another home's public head (`headQuorum` above 1), which goes
                    // to the transport configured for the home its URL names, with no credential.
                    let target: HomeConfiguration
                    if request.url.hasPrefix(Self.base(configured.endpoint.absoluteString) + "/") { target = configured }
                    else if request.method == .get, request.url.hasSuffix("/head"), !request.headers.contains(where: { $0.name.lowercased() == "authorization" }),
                            let other = homeConfigurations.first(where: { request.url == Self.base($0.endpoint.absoluteString) + "/head" }), other.isAllowed {
                        target = other
                    } else {
                        stopped = .callNotBound("a request for another host than the configured home"); break homeLoop
                    }
                    if request.method != .get { progress = true }
                    let answer: HttpAnswer
                    do { answer = try await target.transport.send(request) }
                    catch HomeTransportError.responseTooLarge(let limit) { stopped = .responseTooLarge(limit: limit); break homeLoop }
                    catch HomeTransportError.insecureEndpoint(let url) { stopped = .insecureEndpoint(url); break homeLoop }
                    // A transport the host supplied is held to the same bound.
                    let limit = HomeLimits.responseBytes(for: request.url)
                    guard answer.body.count <= limit else { stopped = .responseTooLarge(limit: limit); break homeLoop }
                    // A home's answer that carries a §1 result (spec §14, §19): read only the `result`, validated against
                    // the result grammar and bounded (`HomeRefusal`), never any other byte of the body. It is the home's
                    // word about one request, not a verified state of the account.
                    var refusedCall: HomeProblem?
                    if request.home == home.id, let refusal = HomeRefusal(status: answer.status, headers: answer.headers, body: answer.body) {
                        if let wait = refusal.retryAfterSeconds { notBefore[home.id] = now.addingTimeInterval(Double(wait)) }
                        if refusal.isHomeUnavailable {
                            // `503 {"result":"unavailable"}` (a stopped or overloaded home, §13.6): the home is not available.
                            // The pass stops and the session retries with backoff; it says nothing about this device.
                            stopped = .homeUnavailable(retryAfterSeconds: refusal.retryAfterSeconds)
                            if refusal.retryAfterSeconds != nil { waitingIssue[home.id] = HomeIssue(home: home.id, problem: .homeUnavailable(retryAfterSeconds: refusal.retryAfterSeconds)) }
                            result.homeUnavailable = true
                            break homeLoop
                        }
                        if let code = refusal.code, code.hasPrefix("refused:") {
                            // A device that asked to join and holds no grant for itself sees `refused:revoked` for its own
                            // call (0.5 keeps that result; `refused:notGranted` is reserved): it is waiting for approval.
                            let problem: HomeProblem = code == "refused:revoked" && awaitingApproval
                                ? .waitingForApproval : .remoteCallRefused(code: code, retryAfterSeconds: refusal.retryAfterSeconds)
                            let signed = request.headers.contains { $0.name.lowercased() == "authorization" && $0.value.hasPrefix("Colophon ") }
                            if answer.status == 401 {
                                // The challenge for a call: the engine asks for one.
                            } else if answer.status == 403, signed {
                                // This device's signed call was refused: the engine is told, then the pass ends with the home's
                                // word, as for any refused call.
                                refusedCall = problem
                            } else {
                                // Any other refusal refuses only that request (an unknown or reserved name included) and the
                                // pass goes on, unless the home asked for time (`Retry-After`).
                                if !result.issues.contains(HomeIssue(home: home.id, problem: problem)) {
                                    result.issues.append(HomeIssue(home: home.id, problem: problem))
                                }
                                if refusal.retryAfterSeconds != nil { waitingIssue[home.id] = HomeIssue(home: home.id, problem: problem); abandon = true; break homeLoop }
                            }
                        } else if refusal.retryAfterSeconds != nil {
                            abandon = true; break homeLoop
                        }
                    }
                    let report = try await gated { () -> Report in
                        guard self.engine === engine else { throw SessionError.destinationChanged }
                        let report = try await trackInterruptedAuthorityChange(in: engine) {
                            try await engine.run { try $0.exchangeAnswer(home: home.id, ticket: request.ticket, answer: answer) }
                        }
                        try await persist(report, on: engine)
                        return report
                    }
                    for fault in report.faults {
                        result.faults.append(HomeFault(home: home.id, fault: fault))
                        if fault.kind == .unauthorized { result.unauthorized = true }
                    }
                    if !report.store.isEmpty || report.changes.reorganized
                        || report.changes.authorityToSeq != report.changes.authorityFromSeq || !report.changes.namespaces.isEmpty {
                        result.changed = true; progress = true
                    }
                    if let refusedCall { stopped = refusedCall; result.unauthorized = true; break homeLoop }
                }
            }
            result.passes += 1
            }
            } catch {
                // A transport failure, an engine error or a cancelled caller: the request in flight is forgotten, what was
                // pulled and verified is kept, and the next pass starts clean. The abort runs even for a cancelled caller.
                await abortPass(engine, home: home.id)
                // The pass brought in the final raise that stops this account: the engine then refuses the next step
                // (`unavailable`). That is the stop, not a fault of the exchange.
                if !(error is CancellationError), (try? await Self.isStopped(engine)) == true { result.stopped = true; result.changed = true; break }
                throw error
            }
            if let stopped {
                result.issues.append(HomeIssue(home: home.id, problem: stopped))
                if stopped == .stillWaiting { result.failed = true }
                await abortPass(engine, home: home.id)
            } else if abandon {
                await abortPass(engine, home: home.id)
            }
        }
        faults = result.faults
        issues = result.issues
        return result
    }

    /// Abandons the pass with `home` (`exchange_abort`) and persists what it took. It enters the gate without checking
    /// cancellation, so a cancelled caller still leaves the engine with no request outstanding.
    private func abortPass(_ engine: ColophonEngine, home: String) async {
        await enter(); defer { exit() }
        guard let report = try? await engine.run({ try $0.exchangeAbort(home: home) }) else { return }
        try? await persist(report, on: engine)
    }

    static func base(_ text: String) -> String { text.trimmingCharacters(in: CharacterSet(charactersIn: "/")) }
    static func hex<D: Sequence>(_ digest: D) -> String where D.Element == UInt8 { digest.map { String(format: "%02x", $0) }.joined() }

    /// The call a `NeedCall` asked for, built by the engine for exactly the request it will send (audience the home's
    /// base, purpose by the method, `args` `{"method","path","body"}` from the need: `exchange_begin_call`), signed by
    /// this device's member key and judged by the core with the home's own rule over what this device holds before it
    /// is returned. A need for another home or audience than the configured one is not signed (`callNotBound`); a call
    /// the core's own check refuses is `callRefused`.
    private func provideCall(for need: CallNeed, home: Home, configured: HomeConfiguration) async throws {
        guard let engine, let custody = memberCustody, let id = memberID else { throw SessionError.notReady }
        guard need.home == home.id, Self.base(need.audience) == Self.base(configured.endpoint.absoluteString),
              need.url == Self.base(need.audience) + need.path else {
            throw HomeProblem.callNotBound("the engine asked a call for another home than the configured one")
        }
        let signing = try await custody.provider(for: id).publicKeys().signing
        let written: Written
        do {
            written = try await gated {
                let written = try await engine.execute(custody: custody) { engine in
                    try withEntropy(32) { try engine.exchangeBeginCall(home: need.home, ticket: need.ticket, key: signing, entropy: $0) }
                }
                observeAuthorityChanges(written.changes, from: engine)
                return written
            }
        } catch let error as ColophonError {
            switch error {
            case .refused, .unavailable, .denied: throw HomeProblem.callRefused(code: error.code)
            default: throw error
            }
        }
        guard let artifact = written.artifact else { throw ColophonError.internalFailure(code: "internal", detail: "a call returned no envelope") }
        try await gated { try await engine.run { try $0.exchangeProvideCall(home: need.home, ticket: need.ticket, call: artifact) } }
    }
    /// A call (spec §12.2) for `audience` and `purpose` with `argsJSON` (a JSON object), signed by this device's member key
    /// with no links, as the envelope's bytes. The signer's own check comes first: a service this session did not ask for
    /// (`SessionConfiguration.services`) is `refused:outOfScope` before the key is asked; then the core judges the signed
    /// call by §12.3 over the history this device holds (its grant's services, expiry and conditions, a revocation it
    /// holds, fresh heads) and returns the bytes only when that judgement is `ok`. Each call has a fresh request ID.
    func signCall(audience: String, purpose: String, argsJSON: String) async throws -> Data {
        try await gated {
            if engine == nil { _ = try await reconcile() }
            guard let engine, let custody = memberCustody, let id = memberID else { throw SessionError.notReady }
            guard (try? JSONSerialization.jsonObject(with: Data(argsJSON.utf8))) is [String: Any] else { throw SessionError.invalidCommand }
            guard Self.servicesCover(configuration.services, audience: audience, purpose: purpose) else {
                throw ColophonError.refused(code: "refused:outOfScope", reason: "outOfScope", detail: "this session asked for no service \(purpose) at \(audience)")
            }
            let signing = try await custody.provider(for: id).publicKeys().signing
            // Judged at the session's clock, not the time of the engine's last refresh.
            try await advance(engine, to: nowMs)
            let target = CallTarget(audiences: [audience], callOrigins: [], controllerPurposes: [], homeEndpoints: [])
            let written = try await engine.execute(custody: custody) { engine in
                try withEntropy(32) { try engine.beginCall(key: signing, links: [], audience: audience, purpose: purpose, argsJson: argsJSON, target: target, entropy: $0) }
            }
            observeAuthorityChanges(written.changes, from: engine)
            guard let artifact = written.artifact else { throw ColophonError.internalFailure(code: "internal", detail: "a call returned no envelope") }
            return artifact
        }
    }
    static func base64url(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    var homeFaults: [HomeFault] { faults }
    var homeIssues: [HomeIssue] { issues }
    var hasConfiguredHomes: Bool { !homeConfigurations.isEmpty }

    /// Records transitions that came due (§8.7). A schedule calls it; refresh calls it too.
    func recordDue() async throws -> SessionSnapshot {
        try await gated {
            guard let engine else { return try await reconcile() }
            try await advance(engine, to: nowMs)
            try await persistDueWrites(engine)
            return try await build()
        }
    }
    /// How many homes hold a verified receipt for `object`, and how many the account names.
    func receipts(for object: String) async throws -> (receipted: Int, homes: Int) {
        guard let engine else { throw SessionError.notReady }
        let homes = try await engine.run { try $0.exchangeHomes() }.count
        return (try await engine.run { try $0.receiptedBy(object: object) }.count, homes)
    }

    // MARK: Engine access for blobs and tests

    func requireEngine() throws -> ColophonEngine { guard let engine else { throw SessionError.notReady }; return engine }
    func requireCustody() throws -> KeyCustody { guard let memberCustody else { throw SessionError.notReady }; return memberCustody }
    func persistStores(_ stores: [Store]) async throws { try await persist(stores) }
    func inGate<T: Sendable>(_ body: () async throws -> T) async throws -> T { try await gated(body) }
    func currentSnapshot() async throws -> SessionSnapshot { try await gated { try await build() } }
}

struct SavedFile: Codable {
    var verifier: Data
    var checkpoint: Data
    var parts: [Part]
    struct Part: Codable { var namespace: String; var bytes: Data }
    init(_ state: SavedState) { verifier = state.verifier; checkpoint = state.checkpoint; parts = state.parts.map { Part(namespace: $0.namespace, bytes: $0.bytes) } }
    var state: SavedState { SavedState(verifier: verifier, checkpoint: checkpoint, parts: parts.map { SavedPart(namespace: $0.namespace, bytes: $0.bytes) }) }
}
