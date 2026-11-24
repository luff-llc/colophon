import Foundation
import Testing
import ColophonKeys
import ColophonSavedKit
@testable import ColophonSession

/// Fires once: a folder batch fails after its commit point the first time, and its completion on the next open succeeds.
private final class Once: @unchecked Sendable {
    private let lock = NSLock()
    private var fired = false
    func take() -> Bool { lock.withLock { if fired { return false }; fired = true; return true } }
}

/// What a write reports matches what is durable: a write the store completes later is saved, and a receipt names the
/// operation the write made.
@MainActor struct WriteDurabilityTests {
    private struct Injected: Error {}
    private func link(_ id: String) throws -> DomainCommand {
        try .saveLink(id: id, url: URL(string: "https://example.org/\(id)")!, title: id.uppercased())
    }
    private func ids(_ session: ColophonSession) async throws -> [String] {
        try await SavedStore(session: session).load(ItemsQuery(limit: 100)).get().rows.map { $0.id }.sorted()
    }
    private func folderSession(_ medium: FolderMedium, private privateDir: URL, member: SoftwareKeys, owner: SoftwareKeys,
                               secrets: MemoryDeviceSecrets) -> ColophonSession {
        ColophonSession(configuration: .init(memberLabel: "Mac", namespaces: ["reading.saved"], location: .medium(medium), privateContainer: privateDir,
            keys: member, ownerController: owner, createWithoutHome: true, deviceSecrets: secrets))
    }

    /// A folder batch that fails after it is recorded completes on the next open. A single write and a batch over it are
    /// saved, not failed, so nothing is retried into a duplicate, and a new session reads each item once.
    @Test func aWriteThatFailsAfterTheCommitPointIsSavedOnce() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let library = root.appendingPathComponent("library"), privateDir = root.appendingPathComponent("private")
        let member = SoftwareKeys(), owner = SoftwareKeys(), secrets = MemoryDeviceSecrets()
        let medium = FolderMedium(folder: library, coordinated: false)
        let session = folderSession(medium, private: privateDir, member: member, owner: owner, secrets: secrets)
        await session.create()
        try #require(session.phase == .ready, "\(session.phase) \(session.lastError ?? "")")

        let single = Once()
        medium.batchHook = { step in if step == .applied(0), single.take() { throw Injected() } }
        let receipt = try await session.perform(try link("a"), observed: session.observedRevision)
        guard case .saved(let operation) = receipt, !operation.isEmpty else { Issue.record("not saved: \(receipt)"); return }
        #expect(session.phase == .ready, "\(session.phase)")

        let batch = Once()
        medium.batchHook = { step in if step == .applied(0), batch.take() { throw Injected() } }
        let receipts = try await session.perform([try link("b"), try link("c")], observed: session.observedRevision)
        #expect(receipts.count == 2)
        medium.batchHook = nil

        let reopened = folderSession(FolderMedium(folder: library, coordinated: false), private: privateDir, member: member, owner: owner, secrets: secrets)
        await reopened.restore()
        #expect(reopened.phase == .ready, "\(reopened.phase) \(reopened.lastError ?? "")")
        #expect(try await ids(reopened) == ["a", "b", "c"])
    }

    /// A deliberate seek on an episode with a live head retains that head under `ops/` before the new operation. The
    /// receipt names the seek, not the retained head.
    @Test func aReceiptNamesTheNewOperationNotARetainedHead() async throws {
        let listening = "listening.podcasts"
        let device = Device(namespaces: [listening])
        await device.session.create()
        try #require(device.session.phase == .ready)
        try await device.session.perform(try DomainCommand(namespace: listening, kind: "follow",
            payloadJSON: Data(#"{"id":"show","url":"https://example.org/f","title":"T"}"#.utf8)), observed: device.session.observedRevision)

        // A passive position sample makes the episode's live head.
        let worker = device.session.worker
        let engine = try await worker.requireEngine(), custody = try await worker.requireCustody()
        let live = try await engine.run { engine in
            try withEntropy(32) { try engine.beginLiveWrite(namespace: listening, kind: "position",
                payloadJson: #"{"id":"e1","show":"show","seconds":10.0}"#, entropy: $0) }
        }
        let signature = try #require(try await custody.sign([try live.step()]).first)
        let sample = try await engine.run { try $0.finishLiveWrite(live: live, signature: signature) }
        try await worker.persistStores(sample.stores)
        let head = try #require(sample.stores.last)
        await device.session.refresh()

        let receipt = try await device.session.perform(try DomainCommand(namespace: listening, kind: "position",
            payloadJSON: Data(#"{"id":"e1","show":"show","seconds":50.0,"seek":true}"#.utf8)), observed: device.session.observedRevision)
        guard case .saved(let operation) = receipt else { Issue.record("not saved: \(receipt)"); return }
        let files = device.medium.snapshot().filter { $0.key.hasPrefix("ops/") && $0.key.contains("/\(listening)/") }
        let retained = try #require(files.first { $0.value == head.bytes }, "the seek retained the head under ops/")
        #expect(!retained.key.hasSuffix("-\(operation).json"), "the receipt names the retained head: \(retained.key)")
        let named = files.keys.filter { $0.hasSuffix("-\(operation).json") }
        #expect(named.count == 1, "\(files.keys.sorted())")
    }
}
