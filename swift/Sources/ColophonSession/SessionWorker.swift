import CryptoKit
import Foundation

/// The record source the engine reads through: the medium, nothing else. It never calls the engine.
final class MediumSource: HostSource, @unchecked Sendable {
    let medium: any RecordMedium
    init(_ medium: any RecordMedium) { self.medium = medium }
    // Each callback in its own autorelease pool: Foundation's file reads autorelease, and the engine's queue runs a
    // whole engine call (many callbacks) as one job.
    func read(path: String) throws -> Data { try autoreleasepool { try medium.read(path) } }
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
    var usable: Bool { [.ready, .refreshing, .waitingForDownload, .retry].contains(phase) }
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
    private(set) var accountID: String?
    private(set) var memberID: String?
    private var journal = SessionJournalFile()
    private var journalLoaded = false
    private var locked = false
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

    init(configuration: SessionConfiguration) {
        self.configuration = configuration; memberKeys = SessionKeys(base: configuration.keys)
        journalURL = configuration.privateContainer.appendingPathComponent("session.json")
        cache = CheckpointCache(privateContainer: configuration.privateContainer)
    }

    // MARK: Gate

    nonisolated func termsJSONNonisolated(namespaces: [String], access: [Access], expires: String?, budget: UInt64?) -> String {
        Self.terms(namespaces: namespaces, access: access, expires: expires, budget: budget)
    }
    nonisolated static func terms(namespaces: [String], access: [Access], expires: String?, budget: UInt64?) -> String {
        var terms: [String: Any] = ["records": namespaces.sorted().map { ["namespace": $0, "access": access.contains(.write) ? "write" : "read"] }]
        if let expires { terms["expires"] = expires }
        if let budget { terms["writes"] = budget }
        let data = (try? JSONSerialization.data(withJSONObject: terms, options: [.sortedKeys])) ?? Data("{}".utf8)
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
    private func persist(_ written: Written, on target: ColophonEngine? = nil) async throws { try await persist(written.stores, on: target) }

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
        if report.kind == .newerFormat { throw ColophonError.newerFormat(code: report.code, detail: report.detail ?? "") }
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
        let opened = try await ColophonEngine.open(source: MediumSource(try storage()), listing: listed(entries),
            identity: AccountIdentity(kind: .member, id: keyID), account: account, namespaces: configuration.libraryNamespaces,
            saved: saved, deviceKey: key, nowMs: nowMs)
        engine = opened; accountID = account
        // A member that is not approved yet holds no keys; the records can still be read and the exchange can
        // still bring the approval in. A member opens its epoch shares in `unlockIfPossible`.
        if try await opened.run({ try $0.me() }).kind != .member { _ = try await opened.run { try $0.load() } }
        if journal.account == nil { journal.account = account; try saveJournal() }
        try await unlockIfPossible()
    }

    private func refreshEngine(_ entries: [MediumEntry]) async throws {
        guard let engine else { return }
        let list = listed(entries)
        let at = nowMs
        _ = try await engine.run { try $0.advance(nowMs: at) }
        _ = try await engine.run { try $0.refresh(listing: list) }
        for written in try await engine.run({ try $0.recordDue() }) { try await persist(written) }
        try await unlockIfPossible()
    }

    /// A member opens its epoch shares with its own agreement key (silent for a Secure Enclave key).
    private func unlockIfPossible() async throws {
        guard let engine, let custody = memberCustody else { return }
        if try await engine.run({ try $0.isUnlocked() }) { return }
        guard case .member = try await engine.run({ try $0.me() }).kind else { return }
        let agreements = try await engine.run { try $0.beginUnlockEpochs() }
        guard !agreements.isEmpty else { return }
        let answers = try await custody.answer(epochs: agreements)
        _ = try await engine.finishUnlockEpochs(answers: answers)
        memberOpened = true
    }

    private func loadSaved(_ account: String) async throws -> SavedState? {
        guard let bytes = try await cache.load(libraryID: account) else { return nil }
        return try? JSONDecoder().decode(SavedFile.self, from: bytes).state
    }
    func saveCheckpoint() async throws {
        try await gated {
            guard let engine, let account = accountID, phaseIsReady else { return }
            _ = try await engine.run { try $0.verifyBatch(limit: 128) }
            let state = try await engine.run { engine in try withEntropy(32) { try engine.save(nonceSeed: $0) } }
            try await cache.save(JSONEncoder().encode(SavedFile(state)), libraryID: account)
        }
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
        if status.kind == .newerFormat { return snapshot(phase: .updateRequired) }
        let members = try await engine.run { try $0.members() }
        let pending = try await pendingRequests(members: members)
        let homes = try await engine.run { try $0.homes() }
        var phase: SessionPhase
        switch standing.kind {
        case .unknown:
            try await ensureOwnRequest()
            let id = memberID ?? ""
            return snapshot(phase: .waitingForApproval(code: AccessRequest.code(for: id)), members: members, requests: pending, homes: homes)
        case .controller:
            phase = .failed(error: .other(detail: "this identity is a controller, not a member"))
        case .member:
            if standing.member?.revokedAt != nil { phase = .denied }
            else {
                phase = .ready
                for namespace in configuration.libraryNamespaces {
                    if let denial = try await engine.run({ try $0.access(namespace: namespace) }) {
                        phase = [.notReadable, .unavailable].contains(denial.reason) ? .unavailable(reason: denial.detail) : .denied
                        break
                    }
                }
            }
        }
        var revisions: [String: UInt64] = [:]
        if phase == .ready { for r in try await engine.run({ try $0.revisions() }) where configuration.libraryNamespaces.contains(r.namespace) { revisions[r.namespace] = r.revision } }
        let notices = try await currentNotices()
        let head = try await engine.run { try $0.headSeq() }
        lastHead = head
        if phase == .ready { revisions["colophon.authority"] = head }
        let visible = phase == .ready
        let duties = try await hostDuties(notices: notices, homes: homes)
        return snapshot(phase: phase, members: members, requests: pending, notices: notices, revisions: visible ? revisions : [:], homes: homes, duties: duties)
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

    private func requestPath(_ id: String) -> String { "requests/\(id).json" }
    private func ownRequestBytes() async throws -> Data {
        guard let account = accountID, let id = memberID else { throw SessionError.notReady }
        let keys = try await memberKeys.publicKeys()
        let spec = RequestSpec(account: account, signing: keys.signing, agreement: keys.agreement, label: configuration.memberLabel,
            kind: Self.accountKind(configuration.memberKind), termsJson: termsJSON(namespaces: configuration.namespaces, access: configuration.access, expires: nil, budget: nil),
            created: try accountFormatDate(ms: nowMs - 1000), custody: nil, operator: nil, endpoints: [])
        let request = try AccountRequest.prepare(spec: spec)
        let step = try request.step()
        let signature = try await memberKeys.sign(body: step.body)
        _ = id
        return try request.finish(signature: Signature(signature: signature, authenticatorData: nil, clientData: nil)).raw
    }
    private func ensureOwnRequest() async throws {
        guard let id = memberID else { return }
        let path = requestPath(id)
        if (try? storage().read(path)) != nil { return }
        try storage().write([MediumWrite(path: path, bytes: try await ownRequestBytes())])
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
    func importRequest(_ data: Data) async throws -> SessionSnapshot {
        try await gated {
            let info = try accountRequestInfo(raw: data)
            try storage().write([MediumWrite(path: requestPath(info.member), bytes: info.raw)])
            return try await reconcile()
        }
    }
    private func pendingRequests(members: [AccountMember]) async throws -> [AccessRequest] {
        let known = Set(members.map(\.id))
        var out: [AccessRequest] = []
        for entry in try storage().listing() where entry.path.hasPrefix("requests/") {
            guard let bytes = try? storage().read(entry.path), let info = try? accountRequestInfo(raw: bytes),
                  !known.contains(info.member), info.member != memberID else { continue }
            out.append(AccessRequest(id: info.member, label: info.label, kind: info.kind, termsJSON: info.termsJson,
                                     pairingCode: AccessRequest.code(for: info.member), record: info.raw))
        }
        return out
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
            identity: AccountIdentity(kind: .controller, id: ownerID), account: account, namespaces: configuration.libraryNamespaces,
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

    func approve(_ request: AccessRequest, terms: String?) async throws -> SessionSnapshot {
        try await gated {
            if engine == nil { _ = try await reconcile() }
            try await withOwner { owner, custody, ownerID in
                let signers = try await signers(owner, ownerID: ownerID, need: .member)
                let terms = terms ?? request.termsJSON
                let written = try await owner.execute(custody: custody) { engine in try withEntropy(32) { try engine.beginApprove(request: request.record, termsJson: terms, signers: signers, entropy: $0) } }
                try await persist(written, on: owner)
            }
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
                namespaces: configuration.libraryNamespaces, saved: nil, deviceKey: secret, nowMs: nowMs)
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
            let policyJSON = String(decoding: try JSONSerialization.data(withJSONObject: policy, options: [.sortedKeys]), as: UTF8.self)
            let params = CreateParams(label: configuration.memberLabel, namespaces: configuration.libraryNamespaces.sorted(), controllers: controllers,
                slots: slots, threshold: nil, recoverThreshold: nil, addThreshold: nil, countByHolders: false, policyJson: policyJSON,
                signers: [ownerID], rekeySigners: [ownerID])
            let created = try await AccountCreator.create(params: params, identity: AccountIdentity(kind: .controller, id: ownerID),
                                                           custody: custody, nowMs: nowMs)
            try storage().write(created.stores.map { MediumWrite(path: $0.path, bytes: $0.bytes) })
            journal.account = created.account; accountID = created.account
            try saveJournal()
            try await setUpFirstDevice(account: created.account, ownerID: ownerID, custody: custody)
            return try await reconcile()
        }
    }

    /// Appoints the homes, records their activation and approves this device's member. It needs the
    /// controller unlocked, and a creation leaves the session locked (the core has no engine constructor over
    /// a created account yet), so a passkey owner is asked a second time here.
    /// REMOVE `unlockCreatedAccount` when `Engine::from_account` is exported: use the creation's own engine.
    private func setUpFirstDevice(account: String, ownerID: String, custody: KeyCustody) async throws {
        let entries = try storage().listing()
        let secret = try configuration.deviceSecrets.key(for: account)
        let owner = try await ColophonEngine.open(label: "org.luff.colophon.owner", source: MediumSource(try storage()), listing: listed(entries),
            identity: AccountIdentity(kind: .controller, id: ownerID), account: account, namespaces: configuration.libraryNamespaces,
            saved: nil, deviceKey: secret, nowMs: nowMs)
        do {
            try await unlockCreatedAccount(owner, custody: custody, ownerID: ownerID)
            for home in configuration.homes {
                guard let makeRequest = home.request else { continue }
                let raw = try await makeRequest(account)
                let info = try accountRequestInfo(raw: raw)
                let change: [String: Any] = ["homes": ["appoint": [["request": raw.base64EncodedString(), "terms": (try JSONSerialization.jsonObject(with: Data(info.termsJson.utf8)))]]]]
                let json = String(decoding: try JSONSerialization.data(withJSONObject: change, options: [.sortedKeys]), as: UTF8.self)
                let signers = try await signers(owner, ownerID: ownerID, need: .control)
                let written = try await owner.execute(custody: custody) { try $0.beginTransition(changeJson: json, signers: signers, rule: .control, entropy: Data()) }
                try await persist(written, on: owner)
                for due in try await owner.run({ try $0.recordDue() }) { try await persist(due, on: owner) }
            }
            let memberRaw = try await ownRequestBytesFor(account: account)
            let terms = termsJSON(namespaces: configuration.namespaces, access: configuration.access, expires: nil, budget: nil)
            let signers = try await signers(owner, ownerID: ownerID, need: .member)
            let approve = try await owner.execute(custody: custody) { engine in try withEntropy(32) { try engine.beginApprove(request: memberRaw, termsJson: terms, signers: signers, entropy: $0) } }
            try await persist(approve, on: owner)
            await owner.lock()
        } catch { await owner.lock(); throw error }
    }
    private func unlockCreatedAccount(_ owner: ColophonEngine, custody: KeyCustody, ownerID: String) async throws {
        try await unlockOwner(owner, custody: custody, ownerID: ownerID)
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

    func write(_ command: DomainCommand, observed: UInt64, ingress: IngressEnvelope? = nil) async throws -> (WriteReceipt, SessionSnapshot) {
        try await gated {
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
            let written = try await engine.execute(custody: custody) {
                engine in try withEntropy(32) { try engine.beginWrite(namespace: command.namespace, kind: command.kind, payloadJson: payload, entropy: $0) }
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
    func ledger() async throws -> Data {
        guard let engine else { throw SessionError.notReady }
        return Data(try await engine.run { try $0.ledgerJson() }.utf8)
    }

    // MARK: Exchange

    /// What the engine's homes are, matched to the transports this host configured.
    private func transport(for home: Home) -> HomeConfiguration? {
        func base(_ text: String) -> String { text.trimmingCharacters(in: CharacterSet(charactersIn: "/")) }
        return configuration.homes.first { configured in home.endpoints.contains { base($0) == base(configured.endpoint.absoluteString) } }
    }

    struct ExchangeResult: Sendable {
        var passes = 0; var faults: [HomeFault] = []; var issues: [HomeIssue] = []; var changed = false; var unauthorized = false
    }
    /// The placeholder the engine attaches to a request whose call is built once the request is in hand (`signedRequest`).
    static let placeholderCall = Data("colophon-call-placeholder".utf8)

    /// One pass with every home. The network calls run outside the gate; each engine step and the
    /// persistence of its stores run inside it, so an unpersisted answer is never visible to a refresh.
    /// A home is held to `HomeLimits`: steps per pass, the time of an exchange, the size of each response.
    func exchange(nowMsOverride: Int64? = nil) async throws -> ExchangeResult {
        try await gated { if engine == nil { _ = try await reconcile() } }
        var result = ExchangeResult()
        guard let engine else { return result }
        let homes = try await engine.run { try $0.exchangeHomes() }
        for home in homes {
            guard let configured = transport(for: home) else { continue }
            guard configured.isAllowed else {
                result.issues.append(HomeIssue(home: home.id, problem: .insecureEndpoint(configured.endpoint.absoluteString)))
                continue
            }
            if let token = configured.bearerToken { _ = try await engine.run { try $0.exchangeSetBearer(home: home.id, token: token) } }
            // The pass starts from fresh local state.
            try await gated {
                let entries = try storage().listing(); let list = listed(entries); let at = nowMs
                _ = try await engine.run { try $0.advance(nowMs: at) }
                _ = try await engine.run { try $0.refresh(listing: list) }
                try await unlockIfPossible()
            }
            let started = ContinuousClock.now
            var progress = true
            var passIndex = 0
            var awaitingCall: CallNeed?
            var stopped: HomeProblem?
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
                let step = try await gated { try await engine.run { try $0.exchangeNext(home: home.id) } }
                switch step.kind {
                case .done, .waiting: break loop
                case .needCall:
                    guard let need = step.need else { break loop }
                    // Step one of two: the engine builds the request only once it holds a call, and `CallNeed` carries
                    // no body, so it gets a placeholder; `signedRequest` signs the real call from the request.
                    awaitingCall = need
                    let placeholder = Self.placeholderCall
                    try await gated { try await engine.run { try $0.exchangeProvideCall(home: need.home, ticket: need.ticket, call: placeholder) } }
                case .request:
                    guard let emitted = step.request else { break loop }
                    let request: HttpRequest
                    if let need = awaitingCall {
                        awaitingCall = nil
                        do { request = try await signedRequest(emitted, for: need, configured: configured) }
                        catch let problem as HomeProblem { stopped = problem; break homeLoop }
                    } else { request = emitted }
                    guard request.url.hasPrefix(Self.base(configured.endpoint.absoluteString)) else {
                        stopped = .callNotBound("a request for another host than the configured home"); break homeLoop
                    }
                    if request.method != .get { progress = true }
                    let answer: HttpAnswer
                    do { answer = try await configured.transport.send(request) }
                    catch HomeTransportError.responseTooLarge(let limit) { stopped = .responseTooLarge(limit: limit); break homeLoop }
                    catch HomeTransportError.insecureEndpoint(let url) { stopped = .insecureEndpoint(url); break homeLoop }
                    catch {
                        try await gated {
                            let report = try await engine.run { try $0.exchangeAbort(home: home.id) }
                            try await persist(report.store)
                        }
                        throw error
                    }
                    // A transport the host supplied is held to the same bound.
                    let limit = HomeLimits.responseBytes(for: request.url)
                    guard answer.body.count <= limit else { stopped = .responseTooLarge(limit: limit); break homeLoop }
                    let report = try await gated { () -> Report in
                        let report = try await engine.run { try $0.exchangeAnswer(home: home.id, ticket: request.ticket, answer: answer) }
                        try await persist(report.store)
                        return report
                    }
                    for fault in report.faults {
                        result.faults.append(HomeFault(home: home.id, fault: fault))
                        if fault.kind == .unauthorized { result.unauthorized = true }
                    }
                    if !report.store.isEmpty || report.changes.authorityToSeq != report.changes.authorityFromSeq || !report.changes.namespaces.isEmpty { result.changed = true; progress = true }
                }
            }
            result.passes += 1
            }
            if let stopped {
                result.issues.append(HomeIssue(home: home.id, problem: stopped))
                try await gated {
                    let report = try await engine.run { try $0.exchangeAbort(home: home.id) }
                    try await persist(report.store)
                }
            }
        }
        faults = result.faults
        issues = result.issues
        return result
    }

    static func base(_ text: String) -> String { text.hasSuffix("/") ? String(text.dropLast()) : text }
    static func hex<D: Sequence>(_ digest: D) -> String where D.Element == UInt8 { digest.map { String(format: "%02x", $0) }.joined() }

    /// Step two: a fresh `Authorization: Colophon` call for exactly this request, signed by this device's member key
    /// (§12.4), put in place of the placeholder the engine attached.
    ///
    /// `args` are exactly `{"method": <HTTP method>, "path": <path and query relative to the home's base, as sent>,
    /// "body": <lowercase hex SHA-256 of the request's body, of the empty string when there is none>}`, taken from the
    /// request itself; the purpose is `colophon.home.read` for GET and `colophon.home.write` otherwise; the audience is
    /// the engine's `need.audience`, the home's base URL (spec §14 "audience `{base}`", as the relay's home checks it).
    /// The request must be the one the need named (ticket, method, URL, the configured home's host) and carry the
    /// placeholder, else nothing is signed (`callNotBound`). The two steps exist because `CallNeed` carries neither the
    /// relative path nor the body digest (an export gap, reported in the PR).
    private func signedRequest(_ request: HttpRequest, for need: CallNeed, configured: HomeConfiguration) async throws -> HttpRequest {
        guard let engine, let custody = memberCustody, let id = memberID else { throw SessionError.notReady }
        let base = Self.base(need.audience)
        guard request.ticket == need.ticket, request.method == need.method, request.url == need.url, request.url.hasPrefix(base),
              base == Self.base(configured.endpoint.absoluteString) else {
            throw HomeProblem.callNotBound("the request for ticket \(request.ticket) is not the one the engine asked a call for")
        }
        let placeholder = "Colophon " + Self.base64url(Self.placeholderCall)
        guard let slot = request.headers.firstIndex(where: { $0.name.lowercased() == "authorization" && $0.value == placeholder }) else {
            throw HomeProblem.callNotBound("the request does not carry the call slot the engine was given")
        }
        let path = String(request.url.dropFirst(base.count))
        let method = switch request.method { case .get: "GET"; case .post: "POST"; case .put: "PUT" }
        let purpose = request.method == .get ? "colophon.home.read" : "colophon.home.write"
        guard need.purpose == purpose else { throw HomeProblem.callNotBound("the engine asked for purpose \(need.purpose) on \(method)") }
        let argsObject: [String: String] = ["method": method, "path": path, "body": Self.hex(SHA256.hash(data: request.body))]
        let args = String(decoding: try JSONSerialization.data(withJSONObject: argsObject, options: [.sortedKeys, .withoutEscapingSlashes]), as: UTF8.self)
        let signing = try await custody.provider(for: id).publicKeys().signing
        let target = CallTarget(audiences: [need.audience], callOrigins: [], controllerPurposes: [], homeEndpoints: [need.audience])
        let written = try await gated {
            try await engine.execute(custody: custody) {
                engine in try withEntropy(32) { try engine.beginCall(key: signing, links: [], audience: need.audience, purpose: purpose, argsJson: args, target: target, entropy: $0) }
            }
        }
        guard let artifact = written.artifact else { throw ColophonError.internalFailure(code: "internal", detail: "a call returned no envelope") }
        var headers = request.headers
        headers[slot] = Header(name: headers[slot].name, value: "Colophon " + Self.base64url(artifact))
        return HttpRequest(ticket: request.ticket, home: request.home, method: request.method, url: request.url, headers: headers, body: request.body)
    }
    static func base64url(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    var homeFaults: [HomeFault] { faults }
    var homeIssues: [HomeIssue] { issues }
    var hasConfiguredHomes: Bool { !configuration.homes.isEmpty }

    /// Records transitions that came due (§8.7). A schedule calls it; refresh calls it too.
    func recordDue() async throws -> SessionSnapshot {
        try await gated {
            guard let engine else { return try await reconcile() }
            let at = nowMs
            _ = try await engine.run { try $0.advance(nowMs: at) }
            for written in try await engine.run({ try $0.recordDue() }) { try await persist(written) }
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
