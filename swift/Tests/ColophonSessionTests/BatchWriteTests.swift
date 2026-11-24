import Foundation
import Testing
import ColophonKeys
import ColophonSavedKit
import ColophonSession

/// `perform(_:observed:)` with many commands: one reconcile, each command stored as it is signed, one snapshot.
@MainActor struct BatchWriteTests {
    private func link(_ id: String) throws -> DomainCommand {
        try .saveLink(id: id, url: URL(string: "https://example.org/\(id)")!, title: id.uppercased())
    }
    private func elsewhere(_ id: String) throws -> DomainCommand {
        try DomainCommand(namespace: "reading.elsewhere", kind: "capture", payloadJSON: Data(#"{"id":"\#(id)"}"#.utf8))
    }
    private func ids(_ session: ColophonSession) async throws -> Set<String> {
        Set(try await SavedStore(session: session).load(ItemsQuery(limit: 100)).get().rows.map { $0.id })
    }
    /// The operation IDs on the medium, in clock order, with the version of the write that stored each.
    private func operations(_ medium: MemoryMedium) throws -> [(id: String, version: String?)] {
        try medium.listing().filter { $0.path.hasPrefix("ops/") && $0.path.contains("/reading.saved/") }
            .sorted { $0.path < $1.path }
            .map { entry in
                let name = (entry.path as NSString).lastPathComponent.replacingOccurrences(of: ".json", with: "")
                return (String(name.drop { $0 != "-" }.dropFirst()), entry.version)
            }
    }

    @Test func aBatchWritesEveryCommandInOrderEachInItsOwnStoreWrite() async throws {
        let device = Device()
        await device.session.create()
        let single = try await device.session.perform(try link("first"), observed: device.session.observedRevision)
        let before = device.session.revision

        let receipts = try await device.session.perform(try ["a", "b", "c", "d"].map(link), observed: device.session.observedRevision)
        let written: [String] = receipts.compactMap { if case .saved(let id) = $0, !id.isEmpty { id } else { nil } }
        #expect(written.count == 4, "\(receipts)")
        #expect(device.session.revision > before, "one snapshot after the batch moves the revision")
        let expected: Set<String> = ["first", "a", "b", "c", "d"]
        #expect(try await ids(device.session) == expected)

        // Receipts are those a single write gives: the stored operations, here in the order the batch signed them.
        let stored = try operations(device.medium)
        guard case .saved(let first) = single else { Issue.record("not saved"); return }
        let order: [String] = stored.map { $0.id }
        #expect(order == [first] + written)
        // Each command is stored in its own write, before the next is signed.
        let versions = Set(stored.dropFirst().map { $0.version })
        #expect(versions.count == 4, "\(stored)")

        // The revision the batch published is current: the next write is not stale.
        try await device.session.perform(try link("after"), observed: device.session.observedRevision)
    }

    @Test func aRefusedCommandStopsTheBatchAndKeepsWhatCameBefore() async throws {
        let device = Device()
        await device.session.create()
        let batch = [try link("a"), try link("b"), try elsewhere("x"), try link("c")]
        var interruption: BatchInterruption?
        do { _ = try await device.session.perform(batch, observed: device.session.observedRevision); Issue.record("the batch must stop") }
        catch let error as BatchInterruption { interruption = error }
        let stopped = try #require(interruption)
        #expect(stopped.index == 2)
        #expect(stopped.receipts.count == 2)
        #expect(stopped.error as? SessionError == .invalidCommand)
        let prefix: Set<String> = ["a", "b"]
        #expect(try await ids(device.session) == prefix)

        // The prefix is durable: a relaunch over the same store reads it, and nothing after the refused command.
        let relaunched = device.relaunch()
        await relaunched.restore()
        #expect(relaunched.phase == .ready, "\(relaunched.phase)")
        #expect(try await ids(relaunched) == prefix)
        // The session that stopped is current: retrying from the refused command's successor writes.
        try await device.session.perform([try link("c")], observed: device.session.observedRevision)
    }

    /// Over a real folder the prefix is one journalled batch, and a new session over the folder reads exactly it.
    @Test(.enabled(if: FileCoordinationProbe.available, FileCoordinationProbe.reason))
    func overAFolderThePrefixOfAStoppedBatchSurvivesAReopen() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let library = root.appendingPathComponent("library"), privateDir = root.appendingPathComponent("private")
        let member = SoftwareKeys(), owner = SoftwareKeys(), secrets = MemoryDeviceSecrets()
        func session() -> ColophonSession {
            ColophonSession(configuration: .init(memberLabel: "Mac", namespaces: ["reading.saved"], location: .folder(library), privateContainer: privateDir,
                keys: member, ownerController: owner, createWithoutHome: true, deviceSecrets: secrets))
        }
        let first = session()
        await first.create()
        #expect(first.phase == .ready, "\(first.phase) \(first.lastError ?? "")")
        await #expect(throws: BatchInterruption.self) {
            _ = try await first.perform([try link("a"), try link("b"), try elsewhere("x"), try link("c")], observed: first.observedRevision)
        }
        try await first.flushCheckpoint()
        let second = session()
        await second.restore()
        #expect(second.phase == .ready, "\(second.phase) \(second.lastError ?? "")")
        let prefix: Set<String> = ["a", "b"]
        #expect(try await ids(second) == prefix)
    }

    @Test func aStaleRevisionRefusesTheWholeBatch() async throws {
        let device = Device()
        await device.session.create()
        let stale = device.session.observedRevision
        try await device.session.perform(try link("a"), observed: stale)
        await #expect(throws: SessionError.staleRevision) {
            _ = try await device.session.perform([try link("b"), try link("c")], observed: stale)
        }
        let only: Set<String> = ["a"]
        #expect(try await ids(device.session) == only)
    }

    @Test func aStoreThatRefusesTheFirstCommandKeepsNoneOfIt() async throws {
        let device = Device()
        await device.session.create()
        device.medium.setFault(.failWrite(after: 0))
        do {
            _ = try await device.session.perform([try link("a"), try link("b")], observed: device.session.observedRevision)
            Issue.record("the batch must stop")
        } catch let stop as BatchInterruption {
            #expect(stop.index == 0)
            #expect(stop.receipts.isEmpty)
            #expect(stop.error is StorageError, "\(stop.error)")
        }
        device.medium.setFault(.none)
        await device.session.refresh()
        #expect(device.session.phase == .ready, "\(device.session.phase)")
        #expect(try await ids(device.session).isEmpty)
    }

    @Test func anEmptyBatchWritesNothingAndAnOversizedOneIsRefused() async throws {
        let device = Device()
        await device.session.create()
        let before = device.session.revision, listing = try device.medium.listing().count
        let receipts = try await device.session.perform([], observed: device.session.observedRevision)
        #expect(receipts.isEmpty)
        #expect(device.session.revision == before)
        #expect(try device.medium.listing().count == listing)

        let oversized = try (0...ColophonSession.maximumBatchCount).map { try link("item\($0)") }
        await #expect(throws: SessionError.invalidCommand) {
            _ = try await device.session.perform(oversized, observed: device.session.observedRevision)
        }
        #expect(try device.medium.listing().count == listing)
    }
}
