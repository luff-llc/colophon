import Foundation
import CryptoKit
import Testing
@testable import ColophonSession
@testable import ColophonKitStorage

private func temporary() -> URL {
    FileManager.default.temporaryDirectory.appendingPathComponent("colophon-relay-" + UUID().uuidString).resolvingSymlinksInPath()
}
private func hex(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
private let slotURL = URL(string: "https://relay.invalid/v1/libraries/home")!

/// An in-process relay implementing the §8.2 contract, with switches for failure states.
actor FakeRelay: RelayTransport {
    private var records: [String: Data] = [:]
    private var log: [RelayClient.Entry] = []
    private var instance = UUID().uuidString.lowercased()
    private var offline = false
    let token: String
    private(set) var puts = 0
    init(token: String = "secret-token") { self.token = token }
    func setOffline(_ value: Bool) { offline = value }
    /// Simulates a relay restored from an older backup: the log restarts and cursors fail.
    func resetLog(keeping keep: @Sendable (String) -> Bool) {
        records = records.filter { keep($0.key) }
        instance = UUID().uuidString.lowercased()
        log = records.keys.sorted().map { .init(path: $0, size: records[$0]?.count, sha256: hex(records[$0] ?? Data()), deleted: nil) }
    }
    func plant(_ path: String, _ bytes: Data) {
        records[path] = bytes
        log.append(.init(path: path, size: bytes.count, sha256: hex(bytes), deleted: nil))
    }
    func paths() -> Set<String> { Set(records.keys) }
    func send(_ request: RelayHTTPRequest) async throws -> RelayHTTPResponse {
        if offline { throw RelayError.offline("simulated outage") }
        guard request.headers["Authorization"] == "Bearer " + token else { return .init(status: 401) }
        guard let components = URLComponents(url: request.url, resolvingAgainstBaseURL: false) else { return .init(status: 400) }
        let prefix = "/v1/libraries/home"
        guard components.path.hasPrefix(prefix) else { return .init(status: 401) }
        let rest = String(components.path.dropFirst(prefix.count))
        let query = Dictionary((components.queryItems ?? []).map { ($0.name, $0.value ?? "") }, uniquingKeysWith: { $1 })
        if rest == "/changes" {
            var start = 0
            if let after = query["after"], !after.isEmpty {
                let parts = after.split(separator: ".")
                guard parts.count == 2, String(parts[0]) == instance, let seq = Int(parts[1]), seq <= log.count else { return .init(status: 410) }
                start = seq
            }
            let limit = Int(query["limit"] ?? "500") ?? 500
            let page = Array(log[start..<min(log.count, start + limit)])
            let next = start + page.count
            let body = try JSONEncoder().encode(RelayClient.ChangePage(entries: page, cursor: "\(instance).\(next)", more: next < log.count))
            return .init(status: 200, body: body)
        }
        guard rest.hasPrefix("/records/") else { return .init(status: 404) }
        let path = String(rest.dropFirst("/records/".count))
        switch request.method {
        case "GET":
            guard let bytes = records[path] else { return .init(status: 404) }
            return .init(status: 200, body: bytes)
        case "PUT":
            guard request.headers["If-None-Match"] == "*", let body = request.body else { return .init(status: 428) }
            puts += 1
            if let old = records[path] { return .init(status: old == body ? 200 : 412) }
            plant(path, body)
            return .init(status: 201)
        default: return .init(status: 405)
        }
    }
}

private func configuration(_ home: URL, store: MemoryRecordStore, keys: any AsyncKeyProvider = SoftwareKeys(),
                           relay: any RelayTransport, token: String = "secret-token", url: URL = slotURL) -> SessionConfiguration {
    .init(memberLabel: "Device", namespaces: ["reading.saved", "notes"], location: .memory(store), privateContainer: home, keys: keys, ownerController: SoftwareKeys(),
          relay: RelayConfiguration(url: url, token: token, automatic: false, transport: relay))
}
private func link(_ id: String) throws -> DomainCommand {
    try .saveLink(id: id, url: #require(URL(string: "https://example.com/\(id)")), title: id)
}
@MainActor private func links(_ session: ColophonSession) async throws -> [String] {
    let query = NamespaceStore<SavedLinksQuery, [SavedLink]>(savedLinksIn: session)
    defer { query.close() }
    return try await query.load(.init()).map(\.id).sorted()
}

private actor AuthorityOrderTransport: RelayTransport {
    private let base = FakeRelay()
    private var active = 0
    private(set) var overlapped = false
    func send(_ request: RelayHTTPRequest) async throws -> RelayHTTPResponse {
        let authority = request.method == "PUT" && request.url.absoluteString.contains("authority")
        if authority {
            active += 1
            overlapped = overlapped || active > 1
            // Simulate an in-flight upload; sync must await its acknowledgement.
            try await Task.sleep(for: .milliseconds(10))
        }
        defer { if authority { active -= 1 } }
        return try await base.send(request)
    }
}

@MainActor struct RelaySyncTests {
    @Test func authorityUploadsWaitForPredecessorAcknowledgement() async throws {
        let records = Dictionary(uniqueKeysWithValues: (1...3).map { (String(format: "authority/%08d.json", $0), Data("record\($0)".utf8)) })
        let transport = AuthorityOrderTransport()
        let report = try await RelaySync(local: MemoryRecordStore(records: records), endpoint: RelayEndpoint(url: slotURL, token: "secret-token"), transport: transport).sync()
        #expect(report.pushed == 3)
        #expect(await !transport.overlapped)
    }
    @Test func reconcilesBothWaysKeepsLocalTruthAndRelistsAfterReset() async throws {
        let relay = FakeRelay(), home = temporary()
        defer { try? FileManager.default.removeItem(at: home) }
        let endpoint = RelayEndpoint(url: slotURL, token: "secret-token")
        let a = MemoryRecordStore(records: ["authority/00000001.json": Data("g".utf8), "ops/m/000000000001-a.json": Data("a".utf8)])
        let b = MemoryRecordStore()
        let syncA = RelaySync(local: a, endpoint: endpoint, transport: relay, stateFile: home.appendingPathComponent("a.json"))
        let syncB = RelaySync(local: b, endpoint: endpoint, transport: relay)
        let first = try await syncA.sync()
        #expect(first.pushed == 2)
        let second = try await syncB.sync()
        #expect(second.pulled == 2)
        let pulled = try await b.read()
        #expect(pulled == (try await a.read()))
        try await b.append(["ops/n/000000000001-b.json": Data("b".utf8)])
        let pushedBack = try await syncB.sync()
        #expect(pushedBack.pushed == 1)
        let afterPush = try await syncA.sync()
        #expect(afterPush.pulled == 1)
        let putsBefore = await relay.puts
        let quiet = try await syncA.sync()
        #expect(quiet == RelaySync.Report())
        let putsAfter = await relay.puts
        #expect(putsAfter == putsBefore, "A persisted cursor and remote set avoid re-pushing")

        // A relay that lost records (restored from an old backup) never deletes local records.
        await relay.resetLog { $0.hasPrefix("authority/") }
        let healed = try await syncA.sync()
        #expect(healed.pushed == 2)
        let local = try await a.read()
        #expect(local.count == 3)

        // A different library in the slot stops synchronization before pulling anything.
        let foreign = MemoryRecordStore(records: ["authority/00000001.json": Data("other".utf8)])
        await #expect(throws: RelayError.differentLibrary) { try await RelaySync(local: foreign, endpoint: endpoint, transport: relay).sync() }
        let untouched = try await foreign.read()
        #expect(untouched.count == 1)

        // Conflicting bytes are reported, never overwritten.
        await relay.plant("requests/x.json", Data("relay".utf8))
        try await a.append(["requests/x.json": Data("local".utf8)])
        let conflict = try await syncA.sync()
        #expect(conflict.conflicts == ["requests/x.json"])
        let kept = try await a.read()
        #expect(kept["requests/x.json"] == Data("local".utf8))
    }

    @Test func unreachableOrUnauthorizedRelayIsNeverAnEmptyLibrary() async throws {
        let relay = FakeRelay(), home = temporary(), other = temporary()
        defer { try? FileManager.default.removeItem(at: home); try? FileManager.default.removeItem(at: other) }
        await relay.setOffline(true)
        let session = ColophonSession(configuration: configuration(home, store: MemoryRecordStore(), relay: relay), store: MemoryRecordStore())
        await session.restore()
        guard case .waitingForDownload = session.phase else { Issue.record("Expected waitingForDownload, got \(session.phase)"); return }
        await session.create()
        guard case .waitingForDownload = session.phase else { Issue.record("Create must not fork an unknown library, got \(session.phase)"); return }
        #expect(await session.syncNow() == false)
        guard case .offline = session.syncState else { Issue.record("Expected offline, got \(session.syncState)"); return }

        await relay.setOffline(false)
        #expect(await session.syncNow())
        #expect(session.phase == .noLibrary, "A listed, empty relay slot is an empty library")
        #expect(session.syncState == .idle)

        let wrong = ColophonSession(configuration: configuration(other, store: MemoryRecordStore(), relay: relay, token: "wrong-token"), store: MemoryRecordStore())
        await wrong.restore()
        guard case .waitingForDownload = wrong.phase else { Issue.record("Expected waitingForDownload, got \(wrong.phase)"); return }
        #expect(await wrong.syncNow() == false)
        #expect(wrong.syncState == .unauthorized)
    }

    @Test func twoMembersConvergeThroughOneRelayAndRevocationHolds() async throws {
        let relay = FakeRelay()
        try await runTwoClientJourney(relay: relay, url: slotURL, token: "secret-token")
    }

    @Test(.enabled(if: nodePath != nil), .timeLimit(.minutes(2)))
    func twoMembersConvergeThroughTheReferenceNodeRelay() async throws {
        let server = try ReferenceRelay.start()
        defer { server.stop() }
        try await runTwoClientJourney(relay: URLSessionRelayTransport(), url: server.slotURL, token: server.token)
    }

    @Test(.enabled(if: nodePath != nil), .timeLimit(.minutes(2)))
    func automaticSyncDeliversWithoutBarriers() async throws {
        let server = try ReferenceRelay.start()
        defer { server.stop() }
        let ownerHome = temporary(), memberHome = temporary()
        defer { for dir in [ownerHome, memberHome] { try? FileManager.default.removeItem(at: dir) } }
        func automatic(_ home: URL, _ store: MemoryRecordStore) -> SessionConfiguration {
            .init(memberLabel: "Device", namespaces: ["reading.saved", "notes"], location: .memory(store), privateContainer: home, keys: SoftwareKeys(), ownerController: SoftwareKeys(),
                  relay: RelayConfiguration(url: server.slotURL, token: server.token))
        }
        let ownerStore = MemoryRecordStore(), memberStore = MemoryRecordStore()
        let owner = ColophonSession(configuration: automatic(ownerHome, ownerStore), store: ownerStore)
        await owner.create()
        #expect(owner.phase == .ready)
        let member = ColophonSession(configuration: automatic(memberHome, memberStore), store: memberStore)
        await member.restore()
        try await eventually { !owner.requests.isEmpty }
        try await owner.approve(#require(owner.requests.first))
        try await eventually { member.phase == .ready }
        try await member.perform(link("pushed-automatically"), observed: member.observedRevision)
        try await eventually { (try? await links(owner)) == ["pushed-automatically"] }
        // The background loop may still be finishing a pass (it also checks required blobs).
        try await eventually { owner.syncState == .idle }
        owner.stopSync(); member.stopSync()
    }
}

/// Waits for state driven by background sync. Bounded; fails the test instead of hanging.
@MainActor private func eventually(_ condition: @MainActor () async -> Bool) async throws {
    let deadline = ContinuousClock.now + .seconds(20)
    while !(await condition()) {
        guard ContinuousClock.now < deadline else { Issue.record("Timed out waiting for background sync"); return }
        try await Task.sleep(for: .milliseconds(50))
    }
}

/// Owner creates; a second device joins from the relay, is approved, writes; both converge.
/// Then the member is revoked: its offline write is held on the owner, and after sync the
/// member's session refuses further writes.
@MainActor private func runTwoClientJourney(relay: any RelayTransport, url: URL, token: String) async throws {
    let ownerHome = temporary(), memberHome = temporary()
    defer { for dir in [ownerHome, memberHome] { try? FileManager.default.removeItem(at: dir) } }
    let ownerKeys = SoftwareKeys(), memberKeys = SoftwareKeys()
    let ownerStore = MemoryRecordStore(), memberStore = MemoryRecordStore()
    let owner = ColophonSession(configuration: configuration(ownerHome, store: ownerStore, keys: ownerKeys, relay: relay, token: token, url: url), store: ownerStore)
    await owner.restore()
    #expect(owner.phase == .noLibrary)
    await owner.create()
    #expect(owner.phase == .ready)
    try await owner.perform(link("from-owner"), observed: owner.observedRevision)
    #expect(await owner.syncNow())

    let member = ColophonSession(configuration: configuration(memberHome, store: memberStore, keys: memberKeys, relay: relay, token: token, url: url), store: memberStore)
    await member.restore()
    guard case .waitingForApproval(let code) = member.phase else { Issue.record("Expected pairing, got \(member.phase)"); return }
    #expect(member.libraryID == owner.libraryID)
    #expect(await member.syncNow())

    #expect(await owner.syncNow())
    // A store watcher may still be applying what sync delivered; act only once settled.
    try await eventually { owner.phase == .ready && !owner.requests.isEmpty }
    let request = try #require(owner.requests.first)
    #expect(request.pairingCode == code)
    try await owner.approve(request)
    #expect(await owner.syncNow())

    #expect(await member.syncNow())
    // A store watcher may already be refreshing the verified grant when sync returns.
    #expect(member.phase == .ready || member.phase == .refreshing)
    try await eventually { member.phase == .ready }
    #expect(member.members.contains { $0.id == member.memberID && $0.grant != nil })
    try await member.perform(link("from-member"), observed: member.observedRevision)
    #expect(await member.syncNow())
    #expect(await owner.syncNow())
    let ownerLinks = try await links(owner)
    let memberLinks = try await links(member)
    #expect(ownerLinks == ["from-member", "from-owner"])
    #expect(memberLinks == ownerLinks, "Both devices converge on the same query result")

    // Revocation. The member has not synced yet, so its session still writes locally.
    let memberID = try #require(member.memberID)
    try await eventually { owner.phase == .ready }
    try await owner.revoke(memberID: memberID)
    #expect(await owner.syncNow())
    try await member.perform(link("after-revocation"), observed: member.observedRevision)
    #expect(await member.syncNow())
    #expect(member.phase == .denied, "Pulling the revocation ends the member's access")
    await #expect(throws: SessionError.notReady) { try await member.perform(link("refused"), observed: member.observedRevision) }

    #expect(await owner.syncNow())
    let afterRevocation = try await links(owner)
    #expect(afterRevocation == ["from-member", "from-owner"], "A revoked member's later write never folds")
    let ownerView = try await Library.open(records: ownerStore.read(), me: ownerKeys).view(namespace: "reading.saved").get()
    // `revokedBackdated`: it cites authority from before the revocation it never saw.
    let rejected = ownerView.held + ownerView.refused
    #expect(rejected.contains { $0.author == memberID && $0.reason.localizedStandardContains("revoked") })
    let relayHasIt = try await ownerStore.read().keys.contains { $0.hasPrefix("ops/\(memberID)/") && $0.contains("-") }
    #expect(relayHasIt, "The relay delivered the bytes; the core decided they are not admitted")
}

let nodePath: String? = {
    let candidates = (ProcessInfo.processInfo.environment["PATH"] ?? "").split(separator: ":").map { "\($0)/node" }
        + ["/opt/homebrew/bin/node", "/usr/local/bin/node"]
    return candidates.first { FileManager.default.isExecutableFile(atPath: $0) }
}()

/// Starts relay/server.js on a free loopback port with a fresh data directory.
final class ReferenceRelay {
    let process: Process
    let data: URL
    let slotURL: URL
    let token = "swift-relay-token-0123456789"
    private init(process: Process, data: URL, port: Int) {
        self.process = process; self.data = data
        slotURL = URL(string: "http://127.0.0.1:\(port)/v1/libraries/home")!
    }
    static func start() throws -> ReferenceRelay {
        let node = try #require(nodePath)
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let data = temporary()
        let process = Process()
        process.executableURL = URL(fileURLWithPath: node)
        process.arguments = [root.appendingPathComponent("relay/server.js").path]
        process.environment = ["COLOPHON_RELAY_PORT": "0", "COLOPHON_RELAY_DATA": data.path,
                               "COLOPHON_RELAY_TOKENS": "home=swift-relay-token-0123456789"]
        let output = Pipe()
        process.standardOutput = output
        try process.run()
        var line = Data()
        while !line.contains(UInt8(ascii: "\n")) {
            let chunk = output.fileHandleForReading.availableData
            if chunk.isEmpty { break }
            line.append(chunk)
        }
        struct Ready: Decodable { struct Listening: Decodable { let port: Int }; let listening: Listening }
        let first = line.split(separator: UInt8(ascii: "\n")).first.map { Data($0) } ?? Data()
        let ready = try JSONDecoder().decode(Ready.self, from: first)
        return ReferenceRelay(process: process, data: data, port: ready.listening.port)
    }
    func stop() {
        process.terminate(); process.waitUntilExit()
        try? FileManager.default.removeItem(at: data)
    }
}
