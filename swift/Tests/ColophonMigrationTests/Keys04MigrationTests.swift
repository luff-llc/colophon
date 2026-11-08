import CryptoKit
import Foundation
import Testing
import ColophonSession
@testable import ColophonMigration

private struct EvidenceSnapshot: LegacyLibrarySnapshot {
    let libraryID = String(repeating: "a", count: 32)
    let readerID = "legacy-reader"
    let members = [LegacyMember(id: "old-agent", label: "Old agent")]
    let namespaces: Set<String> = ["notes"]
    let changeToken = "snapshot-1"
    let records = ["ops/legacy/unreadable.json": Data("retained source envelope".utf8)]
    let operations: [String: [LegacyOperation]] = ["notes": []]
    let unresolved: [String] = []
    let unresolvedPaths = ["ops/legacy/unreadable.json"]
    func evaluate(namespace: String, index: Int, bindings: LegacyImportBindings) throws -> LegacyEvaluation {
        throw MigrationError.invalidSource
    }
}
private struct EvidenceSource: LegacyLibrarySource {
    func snapshot(namespaces: Set<String>) throws -> any LegacyLibrarySnapshot { EvidenceSnapshot() }
}

@MainActor struct Keys04MigrationTests {
    @Test func copyPublishesThroughDestinationImportGrantWithoutSourceAuthority() async throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: home) }
        let store = MemoryRecordStore(), marker = home.appendingPathComponent("rollout.json")
        let session = ColophonSession(configuration: .init(memberLabel: "Copying device", namespaces: ["notes"], location: .memory(store),
            privateContainer: home.appendingPathComponent("session"), keys: SoftwareKeys(), ownerController: SoftwareKeys(),
            migrationMarker: marker, migrationWriter: true, importExpires: Date.now.addingTimeInterval(3600).ISO8601Format(),
            importedFrom: EvidenceSnapshot().libraryID))
        let migration = LibraryMigration(source: EvidenceSource(), namespaces: ["notes"], destination: session,
            privateContainer: home.appendingPathComponent("migration"), evidenceKey: SymmetricKey(size: .bits256), markerURL: marker)
        let report = try await migration.run()
        #expect(report.remainingOperations == 0)
        #expect(report.unresolved.contains { $0.contains("unreadable.json") })
        #expect(report.membersNeedingRejoin.count == 1)
        #expect(session.members.count == 1, "Legacy membership must not carry over")
        #expect(session.members.first?.grant?.import == true)
        let records = try await store.read()
        #expect(records.keys.filter { $0.hasPrefix("ops/") }.count == 1)
        let state = try await session.query(namespace: "notes", name: "importEvidence", arguments: Data("{}".utf8))
        #expect(String(decoding: state, as: UTF8.self).contains("unresolved"))
        _ = try await migration.run()
        #expect(try await store.read() == records, "Resuming must reuse the import receipt")
    }
}
