import Foundation
import Testing
@testable import ColophonSession
@testable import ColophonKitStorage

private func temporary() -> URL {
    FileManager.default.temporaryDirectory.appendingPathComponent("colophon-session-" + UUID().uuidString).resolvingSymlinksInPath()
}
private func configuration(_ home: URL, store: MemoryRecordStore, keys: any AsyncKeyProvider = SoftwareKeys(), kind: MemberKind = .app) -> SessionConfiguration {
    .init(memberLabel: "Test", memberKind: kind, namespaces: ["reading.saved", "notes"], location: .memory(store), privateContainer: home, keys: keys, ownerController: SoftwareKeys())
}
private func link(_ id: String = UUID().uuidString) throws -> DomainCommand {
    try .saveLink(id: id, url: #require(URL(string: "https://example.com/")), title: "Saved")
}

@MainActor struct SessionTests {
    @Test func restoreCreateUnavailableAndLeave() async throws {
        let store = MemoryRecordStore(), home = temporary(), keys = SoftwareKeys()
        defer { try? FileManager.default.removeItem(at: home) }
        let session = ColophonSession(configuration: configuration(home, store: store, keys: keys))
        #expect(session.phase == .opening)
        await session.restore()
        #expect(session.phase == .noLibrary)
        await session.create()
        #expect(session.phase == .ready)
        let id = try #require(session.libraryID)
        await store.setUnavailable("offline")
        await session.refresh()
        #expect(session.phase == .retry)
        #expect(session.libraryID == id)
        await store.setUnavailable(nil)
        await session.refresh()
        #expect(session.phase == .ready)
        try await session.leave()
        #expect(session.phase == .noLibrary)
        let reopened = ColophonSession(configuration: configuration(home, store: store, keys: keys))
        await reopened.restore()
        #expect(reopened.phase == .noLibrary)
        await reopened.rejoin(keys: keys)
        #expect(reopened.phase == .ready)
    }

    @Test func pairingDenialRevocationAndFreshRejoin() async throws {
        let store = MemoryRecordStore(), home = temporary(), otherHome = temporary()
        defer { try? FileManager.default.removeItem(at: home); try? FileManager.default.removeItem(at: otherHome) }
        let owner = ColophonSession(configuration: configuration(home, store: store))
        await owner.create()
        let other = ColophonSession(configuration: configuration(otherHome, store: store, kind: .agent))
        await other.restore()
        guard case .waitingForApproval(let code) = other.phase else { Issue.record("Expected pairing"); return }
        #expect(code.count == 6)
        await owner.refresh()
        let request = try #require(owner.requests.first)
        #expect(request.pairingCode == code)
        try await owner.approve(request)
        await other.refresh()
        #expect(other.phase == .ready)
        try await other.perform(link(), observed: other.observedRevision)
        await owner.refresh()
        #expect(owner.ledger.contains { $0.origin == .ai })
        let observedBeforeRevocation = other.observedRevision
        try await owner.revoke(memberID: request.id)
        await #expect(throws: SessionError.notReady) { try await other.perform(link(), observed: observedBeforeRevocation) }
        #expect(other.phase == .denied, "A write preflight must publish access loss immediately")
        await other.rejoin(keys: SoftwareKeys())
        guard case .waitingForApproval = other.phase else { Issue.record("Fresh identity must pair"); return }
        await owner.refresh()
        let fresh = try #require(owner.requests.first)
        try await owner.approve(fresh, grant: .narrowing(namespaces: ["notes"]))
        await other.refresh()
        #expect(other.phase == .denied, "Missing requested scope is explicit")
    }

    @Test func expiredGrantIsDenied() async throws {
        let store = MemoryRecordStore(), home = temporary(), otherHome = temporary()
        defer { try? FileManager.default.removeItem(at: home); try? FileManager.default.removeItem(at: otherHome) }
        let owner = ColophonSession(configuration: configuration(home, store: store))
        await owner.create()
        let other = ColophonSession(configuration: configuration(otherHome, store: store))
        await other.restore(); await owner.refresh()
        try await owner.approve(#require(owner.requests.first), grant: .narrowing(expires: "2000-01-01T00:00:00Z"))
        await other.refresh()
        #expect(other.phase == .denied)
    }

    @Test func namespaceCachesAndStaleActions() async throws {
        let store = MemoryRecordStore(), home = temporary()
        defer { try? FileManager.default.removeItem(at: home) }
        let session = ColophonSession(configuration: configuration(home, store: store))
        await session.create()
        let reading = NamespaceStore<SavedLinksQuery, [SavedLink]>(savedLinksIn: session)
        let notes = NamespaceStore<Int, Data>(session: session, namespace: "notes") { _, bytes in bytes }
        let query = SavedLinksQuery()
        _ = try await reading.load(query); _ = try await notes.load(0)
        #expect(reading.state == .ready)
        let noteValue = notes.cached(0)
        let old = session.observedRevision
        try await session.perform(link(), observed: old)
        #expect(reading.cached(query) == nil)
        #expect(notes.cached(0) == noteValue)
        #expect(notes.state == .ready)
        let links = try await reading.load(query)
        #expect(links.count == 1)
        await #expect(throws: SessionError.staleRevision) { try await session.perform(link(), observed: old) }
        await store.setUnavailable("gone"); await session.refresh()
        #expect(reading.cached(query)?.count == 1)
        #expect(notes.cached(0) == noteValue)
        #expect(session.hasUsableContent)
        let retained = try await session.query(namespace: "reading.saved", name: "items", arguments: Data("{}".utf8))
        #expect(!retained.isEmpty)
        reading.close(); notes.close()
    }

    @Test func externalBatchBumpsOnce() async throws {
        let store = MemoryRecordStore(), home = temporary(), keys = SoftwareKeys()
        defer { try? FileManager.default.removeItem(at: home) }
        let session = ColophonSession(configuration: configuration(home, store: store, keys: keys))
        await session.create()
        let external = try await Library.open(records: store.read(), me: keys)
        _ = try await external.write(namespace: "notes", kind: "createNotebook", payload: Data(#"{"id":"one","title":"One"}"#.utf8)).get()
        _ = try await external.write(namespace: "notes", kind: "createNotebook", payload: Data(#"{"id":"two","title":"Two"}"#.utf8)).get()
        let before = session.revision
        try await store.append(external.records)
        for _ in 0..<20 { session.externalChange() }
        await session.flushExternalChanges()
        #expect(session.revision == before + 1)
        await session.flushExternalChanges()
        #expect(session.revision == before + 1)
    }

    @Test func twoIndependentSessionsOnOneFolder() async throws {
        let root = temporary(), a = temporary(), b = temporary()
        defer { for url in [root, a, b] { try? FileManager.default.removeItem(at: url) } }
        let firstStore = FolderRecordStore(folder: root, coordinated: false)
        let secondStore = FolderRecordStore(folder: root, coordinated: false)
        let dummy = MemoryRecordStore()
        let owner = ColophonSession(configuration: configuration(a, store: dummy), store: firstStore)
        let memberKeys = SoftwareKeys()
        let member = ColophonSession(configuration: configuration(b, store: dummy, keys: memberKeys), store: secondStore)
        await owner.create(); #expect(owner.phase == .ready)
        await member.restore(); await owner.flushExternalChanges()
        try await owner.approve(#require(owner.requests.first))
        await member.flushExternalChanges(); #expect(member.phase == .ready)
        // Two stores on one folder notify each other through NSFilePresenter, asynchronously: under
        // a loaded parallel run a late notification can refresh between observing and writing.
        // That is the documented stale-observation refusal, so settle and retry, never re-sign.
        var attempts = 0
        while true {
            do { try await member.perform(link(), observed: member.observedRevision); break }
            catch let error as SessionError where [.staleRevision, .notReady].contains(error) && attempts < 3 {
                attempts += 1; await member.flushExternalChanges()
            }
        }
        await owner.flushExternalChanges()
        let query = NamespaceStore<SavedLinksQuery, [SavedLink]>(savedLinksIn: owner)
        #expect(try await query.load(.init()).count == 1)
        let restarted = ColophonSession(configuration: configuration(b, store: dummy, keys: memberKeys), store: FolderRecordStore(folder: root, coordinated: false))
        await restarted.restore(); #expect(restarted.phase == .ready)
        try await owner.revoke(memberID: #require(member.memberID))
        await restarted.flushExternalChanges(); #expect(restarted.phase == .denied)
        query.close()
    }

    @Test func ingressDestinationBoundsAndRetry() async throws {
        let store = MemoryRecordStore(), home = temporary(), shared = temporary()
        defer { try? FileManager.default.removeItem(at: home); try? FileManager.default.removeItem(at: shared) }
        let session = ColophonSession(configuration: configuration(home, store: store))
        await session.create()
        let inbox = IngressInbox(appGroupContainer: shared, maximumCount: 2)
        let envelope = IngressEnvelope(libraryID: try #require(session.libraryID), memberID: try #require(session.memberID), command: try link())
        #expect(try await inbox.enqueue(envelope) == .queued)
        await store.setUnavailable("offline")
        await #expect(throws: SessionError.notReady) { try await session.drain(inbox) }
        #expect(try await inbox.pending().count == 1)
        await store.setUnavailable(nil)
        let results = try await session.drain(inbox)
        guard case .saved = results[envelope.id] else { Issue.record("No saved receipt"); return }
        #expect(try await inbox.pending().isEmpty)
        let revision = session.revision
        // Extension retries after losing acknowledgement: durable receipt prevents another write.
        try await inbox.enqueue(envelope)
        _ = try await session.drain(inbox)
        #expect(session.revision == revision)
        let wrong = IngressEnvelope(libraryID: String(repeating: "0", count: 32), memberID: envelope.memberID, command: try link())
        try await inbox.enqueue(wrong)
        let rejected = try await session.drain(inbox)
        #expect(rejected[wrong.id] == .queued)
        #expect(try await inbox.pending().count == 1)
        let expired = IngressEnvelope(libraryID: envelope.libraryID, memberID: envelope.memberID, expires: .distantPast, command: try link())
        await #expect(throws: SessionError.invalidCommand) { try await inbox.enqueue(expired) }
    }
}

struct StorageTests {
    @Test func immutablePathsAndCloudPlaceholder() async throws {
        let root = temporary()
        defer { try? FileManager.default.removeItem(at: root) }
        let store = FolderRecordStore(folder: root, coordinated: false)
        let record = ["authority/00000001.json": Data("one".utf8)]
        try await store.append(record); try await store.append(record)
        await #expect(throws: StorageError.self) { try await store.append(["authority/00000001.json": Data("two".utf8)]) }
        await #expect(throws: StorageError.self) { try await store.append(["authority/../secret.json": Data()]) }
        try Data().write(to: root.appendingPathComponent("authority/.00000002.json.icloud"))
        await #expect(throws: StorageError.self) { try await store.read() }
        await #expect(throws: StorageError.self) { try await store.append(["authority/00000002.json": Data("new".utf8)]) }
    }
    @Test func privateAtomicPermissionsAndLastGoodValue() throws {
        let root = temporary(), file = root.appendingPathComponent("private.json")
        defer { try? FileManager.default.removeItem(at: root) }
        try AtomicFile.write(Data("old".utf8), to: file)
        let attributes = try FileManager.default.attributesOfItem(atPath: file.path)
        #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600)
        #expect(throws: StorageError.self) { try AtomicFile.write(Data("new".utf8), to: file, immutable: true) }
        #expect(try Data(contentsOf: file) == Data("old".utf8))
    }
}

private actor FailingPublicationStore: RecordStore {
    let memory = MemoryRecordStore()
    private var blocked = false
    func block(_ value: Bool) { blocked = value }
    func read() async throws -> [String: Data] { try await memory.read() }
    func append(_ records: [String: Data]) async throws {
        if blocked { throw StorageError.unavailable("Publication offline") }
        try await memory.append(records)
    }
    func changes() async -> AsyncStream<Void> { await memory.changes() }
}

@MainActor struct RetryTests {
    @Test func signedIngressSurvivesRestartWithoutDuplicate() async throws {
        let home = temporary(), shared = temporary(), keys = SoftwareKeys()
        defer { try? FileManager.default.removeItem(at: home); try? FileManager.default.removeItem(at: shared) }
        let store = FailingPublicationStore()
        let config = configuration(home, store: MemoryRecordStore(), keys: keys)
        let session = ColophonSession(configuration: config, store: store)
        await session.create()
        let inbox = IngressInbox(appGroupContainer: shared)
        let envelope = IngressEnvelope(libraryID: try #require(session.libraryID), memberID: try #require(session.memberID), command: try link())
        try await inbox.enqueue(envelope)
        await store.block(true)
        let queued = try await session.drain(inbox)
        #expect(queued[envelope.id] == .queued)
        #expect(try await inbox.pending().count == 1)
        let journal = try SessionJournal.load(at: home.appendingPathComponent("session.json"))
        #expect(!journal.pending.isEmpty)
        #expect(journal.ingress[envelope.id]?.operationID != nil)
        await store.block(false)
        let restored = ColophonSession(configuration: config, store: store)
        await restored.restore()
        let receipts = try await restored.drain(inbox)
        guard case .saved = receipts[envelope.id] else { Issue.record("Expected durable receipt"); return }
        let records = try await store.read()
        #expect(records.keys.filter { $0.hasPrefix("ops/") }.count == 1)
        #expect(try await inbox.pending().isEmpty)
    }

    @Test func deviceOnlyControllerUsesSignedPairingAndExactScopes() async throws {
        let home = temporary(), other = temporary(), store = MemoryRecordStore(), controller = SoftwareKeys()
        defer { try? FileManager.default.removeItem(at: home); try? FileManager.default.removeItem(at: other) }
        func config(_ home: URL, kind: MemberKind) -> SessionConfiguration {
            .init(memberLabel: "Sibling", memberKind: kind, namespaces: ["notes"], libraryNamespaces: ["notes", "reading.saved"],
                  location: .appGroup(identifier: "test.synthetic", libraryName: "Library"), privateContainer: home,
                  keys: SoftwareKeys(), ownerController: controller, enrollment: .deviceOnlyAppGroup(controller: controller))
        }
        let app = ColophonSession(configuration: config(home, kind: .app), store: store)
        await app.create()
        #expect(app.phase == .ready)
        let records = try await store.read()
        #expect(records.keys.contains { $0.hasPrefix("requests/") })
        let me = try #require(app.members.first { $0.id == app.memberID })
        #expect(me.kind == .device)
        #expect(me.grant?.namespaces == ["notes", "reading.saved"])
        let agent = ColophonSession(configuration: config(other, kind: .agent), store: store)
        await agent.restore()
        guard case .waitingForApproval = agent.phase else { Issue.record("Agents never auto-enroll"); return }
    }
}

@MainActor struct RestorationTests {
    @Test func missingKnownRecordsAndCorruptSelectionFailClosed() async throws {
        let home = temporary(), keys = SoftwareKeys(), store = MemoryRecordStore()
        defer { try? FileManager.default.removeItem(at: home) }
        let session = SessionWorker(configuration: configuration(home, store: store, keys: keys))
        _ = try await session.create()
        let missing = ColophonSession(configuration: configuration(home, store: MemoryRecordStore(), keys: keys))
        await missing.restore()
        guard case .retry = missing.phase else { Issue.record("Selected library must not become empty"); return }
        try AtomicFile.write(Data("invalid".utf8), to: home.appendingPathComponent("session.json"))
        let corrupt = ColophonSession(configuration: configuration(home, store: store, keys: keys))
        await corrupt.restore()
        guard case .failed = corrupt.phase else { Issue.record("Corrupt selection must fail closed"); return }
        await corrupt.refresh()
        guard case .failed = corrupt.phase else { Issue.record("Retry must not bypass corrupt selection"); return }
    }
    @Test func placeholderAtFirstLaunchIsUnavailable() async throws {
        let home = temporary(), root = temporary()
        defer { try? FileManager.default.removeItem(at: home); try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root.appendingPathComponent("authority"), withIntermediateDirectories: true)
        try Data().write(to: root.appendingPathComponent("authority/.00000001.json.icloud"))
        let session = ColophonSession(configuration: configuration(home, store: MemoryRecordStore()), store: FolderRecordStore(folder: root))
        await session.restore()
        guard case .waitingForDownload = session.phase else { Issue.record("Cloud placeholder must not become noLibrary"); return }
    }
    @Test func writesAndRefreshAreProportionalToTheChange() async throws {
        let store = MemoryRecordStore(), home = temporary()
        defer { try? FileManager.default.removeItem(at: home) }
        let session = ColophonSession(configuration: configuration(home, store: store))
        await session.create()
        let fullAfterCreate = await store.fullReads
        try await session.perform(link(), observed: session.observedRevision)
        #expect(await store.fullReads == fullAfterCreate, "A write must not reread the whole library")
        await session.refresh()
        #expect(await store.fullReads == fullAfterCreate, "A no-op refresh must not reread the whole library")
    }
    @Test func namespacedOperationsAndLivePlayback() async throws {
        let store = MemoryRecordStore(), home = temporary()
        defer { try? FileManager.default.removeItem(at: home) }
        let session = ColophonSession(configuration: .init(
            memberLabel: "Test", namespaces: ["listening.podcasts", "notes"],
            location: .memory(store), privateContainer: home, keys: SoftwareKeys(), ownerController: SoftwareKeys()))
        await session.create()
        try await session.perform(try DomainCommand(namespace: "notes", kind: "createNotebook",
            payloadJSON: Data(#"{"id":"n","title":"N"}"#.utf8)), observed: session.observedRevision)
        let paths = try await store.paths()
        #expect(paths.contains { $0.contains("/notes/") })
        try await session.perform(try DomainCommand(namespace: "listening.podcasts", kind: "position",
            payloadJSON: Data(#"{"id":"ep","seconds":12}"#.utf8)), observed: session.observedRevision)
        let after = try await store.paths()
        #expect(after.contains { $0.hasPrefix("state/") })
        #expect(after.contains { $0.hasPrefix("history/") })
        try await session.perform(try DomainCommand(namespace: "listening.podcasts", kind: "position",
            payloadJSON: Data(#"{"id":"ep","seconds":40}"#.utf8)), observed: session.observedRevision)
        let statePaths = (try await store.paths()).filter { $0.hasPrefix("state/") }
        #expect(statePaths.count == 1, "One live slot per episode")
    }
    @Test func ingressRejectsReadOnlyGrantAndQueueOverflow() async throws {
        let a = temporary(), b = temporary(), shared = temporary(), store = MemoryRecordStore()
        defer { for url in [a, b, shared] { try? FileManager.default.removeItem(at: url) } }
        let owner = ColophonSession(configuration: configuration(a, store: store))
        await owner.create()
        let member = ColophonSession(configuration: configuration(b, store: store))
        await member.restore(); await owner.refresh()
        try await owner.approve(#require(owner.requests.first), grant: .narrowing(access: [.read]))
        await member.refresh()
        let inbox = IngressInbox(appGroupContainer: shared, maximumCount: 1)
        let envelope = IngressEnvelope(libraryID: try #require(member.libraryID), memberID: try #require(member.memberID), command: try link())
        try await inbox.enqueue(envelope)
        let extra = IngressEnvelope(libraryID: envelope.libraryID, memberID: envelope.memberID, command: try link())
        await #expect(throws: StorageError.limitExceeded) { try await inbox.enqueue(extra) }
        let result = try await member.drain(inbox)
        #expect(result[envelope.id] == .queued)
        #expect(try await inbox.pending().count == 1)
        let records = try await store.read()
        #expect(!records.keys.contains { $0.hasPrefix("ops/") })
    }
}

private actor SuspendedSigningKeys: AsyncKeyProvider {
    let keys = SoftwareKeys()
    private var shouldPause = true
    private var signer: CheckedContinuation<Void, Never>?
    private var observer: CheckedContinuation<Void, Never>?
    func publicKeys() async throws -> PublicKeys { try await keys.publicKeys() }
    func agree(peer: Data) async throws -> Data { try keys.agree(peer: peer) }
    func sign(body: Data) async throws -> Data {
        if shouldPause {
            shouldPause = false
            await withCheckedContinuation { signer = $0; observer?.resume(); observer = nil }
        }
        return try keys.sign(body: body)
    }
    func waitForSigning() async { if signer == nil { await withCheckedContinuation { observer = $0 } } }
    func resume() { signer?.resume(); signer = nil }
}
@MainActor struct LifecycleTests {
    @Test(.timeLimit(.minutes(1))) func creatingDoesNotBlockMainActor() async throws {
        let home = temporary(), store = MemoryRecordStore(), keys = SuspendedSigningKeys()
        defer { try? FileManager.default.removeItem(at: home) }
        let session = ColophonSession(configuration: configuration(home, store: store, keys: keys))
        await session.restore()
        let creation = Task { await session.create() }
        await keys.waitForSigning()
        #expect(session.phase == .creating)
        await keys.resume()
        await creation.value
        #expect(session.phase == .ready)
    }
}

/// Real core delegate with one fault at the documented post-commit boundary.
private actor PostCommitFailureCore: SessionCore {
    let base = BindingSessionCore()
    private var failNextWrite = true
    func open(records: [String: Data], keys: any AsyncKeyProvider) async throws { try await base.open(records: records, keys: keys) }
    func create(configuration: SessionConfiguration) async throws { try await base.create(configuration: configuration) }
    func merge(_ records: [String: Data]) async throws { try await base.merge(records) }
    func records() async throws -> [String: Data] { try await base.records() }
    func snapshot(namespaces: [String]) async throws -> CoreSnapshot { try await base.snapshot(namespaces: namespaces) }
    func lastWrittenPaths() async throws -> [String] { try await base.lastWrittenPaths() }
    func request(configuration: SessionConfiguration, keys: any AsyncKeyProvider) async throws -> AccessRequest { try await base.request(configuration: configuration, keys: keys) }
    func write(_ command: DomainCommand) async throws -> OperationView {
        let operation = try await base.write(command)
        if failNextWrite { failNextWrite = false; throw StorageError.unavailable("Post-commit unlock fault") }
        return operation
    }
    func approve(_ request: Data, grant: GrantOptions?) async throws { try await base.approve(request, grant: grant) }
    func revoke(_ id: String) async throws { try await base.revoke(id) }
    func importRequest(_ data: Data) async throws -> AccessRequest { try await base.importRequest(data) }
    func approveWithController(_ request: Data, keys: any AsyncKeyProvider) async throws { try await base.approveWithController(request, keys: keys) }
}

@MainActor struct PostCommitTests {
    @Test func ingressDoesNotResignAfterPostCommitFailure() async throws {
        let home = temporary(), shared = temporary(), store = MemoryRecordStore()
        defer { try? FileManager.default.removeItem(at: home); try? FileManager.default.removeItem(at: shared) }
        let session = ColophonSession(configuration: configuration(home, store: store), store: store, core: PostCommitFailureCore())
        await session.create()
        let inbox = IngressInbox(appGroupContainer: shared)
        let envelope = IngressEnvelope(libraryID: try #require(session.libraryID), memberID: try #require(session.memberID), command: try link())
        try await inbox.enqueue(envelope)
        let queued = try await session.drain(inbox)
        #expect(queued[envelope.id] == .queued)
        #expect(try await inbox.pending().count == 1)
        let completed = try await session.drain(inbox)
        guard case .saved = completed[envelope.id] else { Issue.record("Expected verified saved receipt"); return }
        let records = try await store.read()
        #expect(records.keys.filter { $0.hasPrefix("ops/") }.count == 1)
        #expect(try await inbox.pending().isEmpty)
    }
}
