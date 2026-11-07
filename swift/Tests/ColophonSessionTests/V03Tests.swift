import Foundation
import Testing
@testable import ColophonSession
@testable import ColophonKitStorage

@MainActor struct V03Tests {
    private func config(_ store: MemoryRecordStore, _ home: URL, _ keys: SoftwareKeys) -> SessionConfiguration {
        .init(memberLabel: "Playback", namespaces: ["listening.podcasts"], location: .memory(store), privateContainer: home, keys: keys)
    }
    @Test func livePlaybackReceiptsRefreshAndIncrementalReads() async throws {
        let store = MemoryRecordStore(), keys = SoftwareKeys()
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: home) }
        let worker = SessionWorker(configuration: config(store, home, keys))
        var snapshot = try await worker.create()
        for seconds in [10, 20, 30] {
            let command = try DomainCommand(namespace: "listening.podcasts", kind: "position", payloadJSON: Data("{\"id\":\"e\",\"seconds\":\(seconds)}".utf8))
            let (receipt, next) = try await worker.write(command, observed: snapshot.revision)
            guard case .saved = receipt else { Issue.record("Live write must have a saved receipt"); return }
            snapshot = next
        }
        let paths = try await store.paths()
        #expect(paths.filter { $0.hasPrefix("state/") }.count == 1)
        #expect(paths.filter { $0.hasPrefix("history/") }.count == 3)
        #expect(paths.filter { $0.hasPrefix("ops/") }.isEmpty)
        let before = await store.recordReads
        _ = try await worker.refresh()
        #expect(await store.recordReads == before, "Unchanged refresh must read zero record bodies")
        #expect(await store.fullReads == 0)
        let external = try await Library.open(records: store.read(), me: keys)
        _ = try await external.write(namespace: "listening.podcasts", kind: "position", payload: Data(#"{"id":"e","seconds":40}"#.utf8)).get()
        try await store.append(external.records(at: external.lastWrittenPaths))
        let refreshed = try await worker.refresh()
        let state = try #require(refreshed.core?.views["listening.podcasts"]?.state)
        let projection = try #require(JSONSerialization.jsonObject(with: state) as? [String: Any])
        let episodes = try #require(projection["episodes"] as? [[String: Any]])
        #expect(episodes.first?["seconds"] as? Double == 40)
    }
    @Test func futureLayoutStopsBeforeContentAndKeepsIdentity() async throws {
        let keys = SoftwareKeys()
        let library = try await Library.create(owner: keys, label: "Future", ownerLabel: "Owner", namespaces: ["listening.podcasts"])
        _ = try await library.write(namespace: "listening.podcasts", kind: "position", payload: Data(#"{"id":"e","seconds":10,"seek":true}"#.utf8)).get()
        guard case .ready(let action) = try library.native.beginLayout(layout: 99, now: "2026-11-07T12:00:00Z") else { Issue.record("Root layout action refused"); return }
        var signatures: [Data] = []
        for step in action.signingSteps() { signatures.append(try keys.sign(body: step.body)) }
        var records = try await library.records
        records.merge(try action.finish(signatures: signatures)) { _, new in new }
        let store = MemoryRecordStore(records: records)
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: home) }
        let identity = try keys.signingPublicKey()
        let session = ColophonSession(configuration: config(store, home, keys))
        await session.restore()
        #expect(session.phase == .updateRequired)
        #expect(await store.recordReads == records.keys.filter { $0.hasPrefix("authority/") }.count)
        #expect(try keys.signingPublicKey() == identity)
        #expect(try await store.read() == records)
        await session.retry()
        #expect(session.phase == .updateRequired)
        let remote = FakeRelay()
        for (path, bytes) in records { await remote.plant(path, bytes) }
        let empty = MemoryRecordStore()
        let remoteSession = ColophonSession(configuration: .init(memberLabel: "Reader", namespaces: ["listening.podcasts"], location: .memory(empty), privateContainer: home.appendingPathComponent("remote"), keys: keys,
            relay: .init(url: try #require(URL(string: "https://relay.invalid/v1/libraries/home")), token: "secret-token", automatic: false, transport: remote)))
        await remoteSession.restore()
        #expect(remoteSession.phase == .updateRequired)
        #expect(try await empty.paths().allSatisfy { $0.hasPrefix("authority/") }, "A future layout must stop relay content downloads")

    }
    @Test func conditionalLivePublicationCannotOverwriteNewerLocalWrite() async throws {
        let store = MemoryRecordStore()
        let path = "state/a/listening.podcasts/slot.json"
        let old = Data("old".utf8), newer = Data("newer".utf8), racing = Data("racing".utf8)
        #expect(try await store.replaceLive(path, expected: nil, bytes: old))
        #expect(try await store.replaceLive(path, expected: old, bytes: newer))
        #expect(try await !store.replaceLive(path, expected: old, bytes: racing))
        #expect(try await store.read(paths: [path])[path] == newer)
    }
    @Test func scopedFolderListingIgnoresMissingSiblingNamespace() async throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: home) }
        let store = FolderRecordStore(folder: home, coordinated: false)
        let note = "ops/a/notes/000000000001-n.json"
        let sibling = "ops/a/listening.podcasts/000000000001-p.json"
        let history = "history/a/notes/000000000001-h.json"
        let legacy = "ops/a/000000000002-u.json"
        try await store.append(Dictionary(uniqueKeysWithValues: [note, sibling, history, legacy].map { ($0, Data("record".utf8)) }))
        _ = try await store.paths()
        try FileManager.default.removeItem(at: home.appendingPathComponent(sibling))
        #expect(try await store.paths(namespaces: ["notes"]) == Set([note, legacy]))
        #expect(try await store.syncPaths(namespaces: ["notes"]) == Set([note, legacy, history]))
        try FileManager.default.removeItem(at: home.appendingPathComponent(note))
        await #expect(throws: StorageError.self) { _ = try await store.paths(namespaces: ["notes"]) }
    }

}
