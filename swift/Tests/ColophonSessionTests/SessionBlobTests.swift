import Foundation
import Testing
@testable import ColophonSession
@testable import ColophonKitStorage

private func temporary() -> URL {
    FileManager.default.temporaryDirectory.appendingPathComponent("colophon-blobs-" + UUID().uuidString).resolvingSymlinksInPath()
}
private let slotURL = URL(string: "https://relay.invalid/v1/libraries/home")!
private let syncBenchmark = ProcessInfo.processInfo.environment["COLOPHON_SYNC_BENCH"] == "1"

private func configuration(_ home: URL, store: MemoryRecordStore, relay: (any RelayTransport)?, url: URL = slotURL, token: String = "secret-token") -> SessionConfiguration {
    .init(memberLabel: "Device", namespaces: ["notes", "reading.saved"], location: .memory(store), privateContainer: home, keys: SoftwareKeys(),
          relay: relay.map { RelayConfiguration(url: url, token: token, automatic: false, transport: $0) })
}
private func content(_ count: Int, seed: UInt8 = 7) -> Data {
    Data((0..<count).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ Int(seed)) })
}

@MainActor private struct Pair {
    let owner: ColophonSession, member: ColophonSession
    let ownerStore: MemoryRecordStore, memberStore: MemoryRecordStore
    let homes: [URL]
}

/// Owner creates, member joins through the relay, owner approves, both ready.
@MainActor private func pair(relay: any RelayTransport, url: URL = slotURL, token: String = "secret-token") async throws -> Pair {
    let homes = [temporary(), temporary()]
    let ownerStore = MemoryRecordStore(), memberStore = MemoryRecordStore()
    let owner = ColophonSession(configuration: configuration(homes[0], store: ownerStore, relay: relay, url: url, token: token), store: ownerStore)
    await owner.create()
    #expect(owner.phase == .ready)
    #expect(await owner.syncNow())
    let member = ColophonSession(configuration: configuration(homes[1], store: memberStore, relay: relay, url: url, token: token), store: memberStore)
    await member.restore()
    #expect(await member.syncNow())
    #expect(await owner.syncNow())
    try await owner.approve(#require(owner.requests.first))
    #expect(await owner.syncNow())
    #expect(await member.syncNow())
    #expect(member.phase == .ready)
    return Pair(owner: owner, member: member, ownerStore: ownerStore, memberStore: memberStore, homes: homes)
}

@MainActor struct SessionBlobTests {
    @Test func putReadDeduplicateAndStreamWithoutARelay() async throws {
        let home = temporary(), store = MemoryRecordStore()
        defer { try? FileManager.default.removeItem(at: home) }
        let session = ColophonSession(configuration: configuration(home, store: store, relay: nil), store: store)
        await session.create()
        let bytes = content(200_000)
        let blob = try await session.putBlob(bytes, namespace: "notes", mediaType: "application/octet-stream", reference: "attachment-1")
        #expect(blob.size == 200_000)
        guard case .saved = blob.receipt else { Issue.record("Expected a saved publication"); return }
        #expect(await session.blobAvailability(namespace: "notes", digest: blob.digest) == .available)
        let read = try await session.blobData(namespace: "notes", digest: blob.digest)
        #expect(read == bytes)
        let chunks = try await store.blobPaths().count
        #expect(chunks == 4)
        // Identical content is addressed first and only gains a reference.
        let again = try await session.putBlob(bytes, namespace: "notes", mediaType: "application/octet-stream", reference: "attachment-2")
        #expect(again.digest == blob.digest)
        let after = try await store.blobPaths().count
        #expect(after == 4)
        // Files stream in and out without whole-content buffers.
        let source = home.appendingPathComponent("source.bin")
        let fileBytes = content(150_001, seed: 3)
        try fileBytes.write(to: source)
        let fileBlob = try await session.putBlob(contentsOf: source, namespace: "notes", mediaType: "audio/mpeg", reference: "recording")
        let url = try await session.blobFile(namespace: "notes", digest: fileBlob.digest)
        defer { try? FileManager.default.removeItem(at: url) }
        let copied = try Data(contentsOf: url)
        #expect(copied == fileBytes)
        var streamed = 0
        for try await part in session.blobStream(namespace: "notes", digest: fileBlob.digest) { streamed += part.count; #expect(part.count <= 65536) }
        #expect(streamed == 150_001)
        // Bounded reads refuse instead of truncating; unknown digests are unpublished, not empty.
        await #expect(throws: BlobError.tooLarge) { try await session.blobData(namespace: "notes", digest: fileBlob.digest, maximumBytes: 1000) }
        let unknown = String(repeating: "c", count: 64)
        #expect(await session.blobAvailability(namespace: "notes", digest: unknown) == .unpublished)
        await #expect(throws: BlobError.unpublished) { try await session.blobData(namespace: "notes", digest: unknown) }
        // A tampered local chunk is invalid, never returned.
        let manifest = try await session.worker.blobManifest(namespace: "notes", digest: blob.digest)
        try await store.removeBlob(manifest.chunks[0].path)
        await #expect(throws: BlobError.self) { try await session.blobData(namespace: "notes", digest: blob.digest) }
        #expect(await session.blobAvailability(namespace: "notes", digest: blob.digest) == .missing(presentChunks: 3, totalChunks: 4))
    }

    @Test func garbageCollectionRemovesOnlyUnreferencedAndStaleOrphanChunks() async throws {
        let home = temporary(), store = MemoryRecordStore()
        defer { try? FileManager.default.removeItem(at: home) }
        let session = ColophonSession(configuration: configuration(home, store: store, relay: nil), store: store)
        await session.create()
        let kept = try await session.putBlob(content(70_000, seed: 1), namespace: "notes", mediaType: "text/plain", reference: "kept")
        let released = try await session.putBlob(content(70_000, seed: 2), namespace: "notes", mediaType: "text/plain", reference: "released")
        // An upload that never published, and a chunk another app wrote into a shared store.
        _ = try await session.worker.stageBlob(namespace: "notes", mediaType: "text/plain", input: .data(content(10, seed: 9)))
        let foreign = "blobs/" + String(repeating: "d", count: 64)
        try await store.appendBlob(foreign, bytes: Data("other app".utf8))
        try await session.setBlobReference(released, reference: "released", retain: false)
        let keptSole = try await session.collectBlobGarbage()
        #expect(keptSole.removedChunks == 0, "A zero-reference blob with no other holder is the only copy")
        let fresh = try await session.collectBlobGarbage(discardSoleCopy: true)
        #expect(fresh.removedChunks == 2, "The owner may discard the sole copy; the fresh orphan waits for its grace period")
        for (path, _) in try await store.blobPaths() { await store.setBlobDate(path, .distantPast) }
        let stale = try await session.collectBlobGarbage()
        #expect(stale.removedChunks == 1)
        let remaining = try await store.blobPaths().keys.sorted()
        #expect(remaining.count == 3)
        #expect(remaining.contains(foreign), "Chunks this session never wrote are never collected")
        #expect(try await session.blobData(namespace: "notes", digest: kept.digest) == content(70_000, seed: 1))
    }

    @Test func blobsReachASecondDeviceLazilyAndRequiredOnesEagerly() async throws {
        let relay = FakeRelay()
        let devices = try await pair(relay: relay)
        defer { for home in devices.homes { try? FileManager.default.removeItem(at: home) } }
        try await crossDeviceJourney(devices)
    }

    @Test(.enabled(if: nodePath != nil), .timeLimit(.minutes(2)))
    func blobsReachASecondDeviceThroughTheReferenceNodeRelay() async throws {
        let server = try ReferenceRelay.start()
        defer { server.stop() }
        let devices = try await pair(relay: URLSessionRelayTransport(), url: server.slotURL, token: server.token)
        defer { for home in devices.homes { try? FileManager.default.removeItem(at: home) } }
        try await crossDeviceJourney(devices)
    }

    /// A sync pass after one new record reads one record and pushes one record, whatever the
    /// library size. Set COLOPHON_SYNC_BENCH=1 for the 100k-record timing run.
    @Test func incrementalSyncPassIsProportionalToTheChange() async throws {
        let count = syncBenchmark ? 100_000 : 5_000
        var records: [String: Data] = ["authority/00000001.json": Data("genesis".utf8)]
        for index in 0..<count { records[String(format: "ops/author/%012d-op%06d.json", index, index)] = Data("record \(index)".utf8) }
        let home = temporary()
        defer { try? FileManager.default.removeItem(at: home) }
        let store = MemoryRecordStore(records: records)
        let relay = FakeRelay()
        let endpoint = RelayEndpoint(url: slotURL, token: "secret-token")
        let state = home.appendingPathComponent("relay.json")
        let first = try await RelaySync(local: store, endpoint: endpoint, transport: relay, stateFile: state).sync()
        #expect(first.pushed == count + 1)
        // A new process: cursor and remote paths come from the private log, not a relisting.
        let sync = RelaySync(local: store, endpoint: endpoint, transport: relay, stateFile: state)
        try await store.append(["ops/author/999999999999-new.json": Data("new".utf8)])
        let fullBefore = await store.fullReads, readsBefore = await store.recordReads
        let started = ContinuousClock.now
        let pass = try await sync.sync()
        let elapsed = ContinuousClock.now - started
        #expect(pass.pushed == 1 && pass.pulled == 0)
        #expect(pass.localRecordReads <= 2, "Only the new record (and the one-time genesis check) is read")
        let fullAfter = await store.fullReads, readsAfter = await store.recordReads
        #expect(fullAfter == fullBefore, "A pass never reads the whole local store")
        #expect(readsAfter - readsBefore <= 2)
        try await store.append(["ops/author/999999999999-newer.json": Data("newer".utf8)])
        let warmStarted = ContinuousClock.now
        let warm = try await sync.sync()
        let warmElapsed = ContinuousClock.now - warmStarted
        #expect(warm.pushed == 1 && warm.localRecordReads == 1)
        let quiet = try await sync.sync()
        #expect(quiet.localRecordReads == 0 && quiet.pushed == 0)
        if syncBenchmark { print("sync-benchmark records=\(count + 3) newProcessPass=\(elapsed) warmPass=\(warmElapsed)") }
    }
}

@MainActor private func crossDeviceJourney(_ devices: Pair) async throws {
    let owner = devices.owner, member = devices.member
    let lazy = content(140_000, seed: 4)
    let blob = try await owner.putBlob(lazy, namespace: "notes", mediaType: "text/html", reference: "article-1")
    #expect(await owner.syncNow())
    #expect(await member.syncNow())
    // The manifest arrived; the ciphertext did not. Missing is never shown as empty.
    #expect(await member.blobAvailability(namespace: "notes", digest: blob.digest) == .missing(presentChunks: 0, totalChunks: 3))
    let fetched = try await member.blobData(namespace: "notes", digest: blob.digest)
    #expect(fetched == lazy)
    #expect(await member.blobAvailability(namespace: "notes", digest: blob.digest) == .available)

    // Required blobs download on the pass that delivers their manifest, without a read.
    let eager = content(90_000, seed: 5)
    let required = try await member.putBlob(eager, namespace: "notes", mediaType: "application/json", reference: "transcript", required: true)
    #expect(await member.syncNow())
    #expect(await owner.syncNow())
    #expect(await owner.blobAvailability(namespace: "notes", digest: required.digest) == .available)
    let ownerCopy = try await owner.blobData(namespace: "notes", digest: required.digest)
    #expect(ownerCopy == eager)

    // Revocation is checked on every read: a revoked device cannot open content it still holds.
    let memberID = try #require(member.memberID)
    try await owner.revoke(memberID: memberID)
    #expect(await owner.syncNow())
    #expect(await member.syncNow())
    #expect(member.phase == .denied)
    await #expect(throws: (any Error).self) { try await member.blobData(namespace: "notes", digest: required.digest) }
}
