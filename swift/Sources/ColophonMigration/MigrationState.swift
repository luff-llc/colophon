import Foundation
import CryptoKit
import ColophonSession
import ColophonCore

public enum MigrationError: Error, Equatable, Sendable {
    case rootRequired, invalidSource, busy, destinationUnavailable, destinationChanged
    case sourceUnavailable(String)
    case reconciliationRequired(String)
}
public struct MigrationReport: Sendable {
    public let sourceLibraryID: String
    public let destinationLibraryID: String
    public let importedOperations: Int
    public let remainingOperations: Int
    public let unresolved: [String]
    public let membersNeedingRejoin: [String]
}
struct MigrationProgress: Codable {
    var sourceLibraryID: String
    var destinationLibraryID: String?
    var prefixes: [String: [String]] = [:]
    var states: [String: Data] = [:]
    var revisions: [String: String] = [:]
    var heads: [String: String] = [:]
    var outputs: [String: String] = [:]
    var sourceOutcomes: [String: [String: Data]]?
    var lastImportedOperation: [String: String] = [:]
    var sourceRecords: [String: String] = [:]
    var unresolved: [String] = []
    var membersNeedingRejoin: [String] = []
}
/// Local encrypted resume journal and exact source archive. Synchronized evidence lives in the engine. The host
/// must persist this key independently; losing it makes resume fail closed, never start over.
struct MigrationFiles {
    let directory: URL
    let key: SymmetricKey
    var progressURL: URL { directory.appendingPathComponent("migration-progress.aesgcm") }
    func load() throws -> MigrationProgress? {
        do { return try JSONDecoder().decode(MigrationProgress.self, from: open(progressURL)) }
        catch let error as CocoaError where error.code == .fileReadNoSuchFile || error.code == .fileNoSuchFile { return nil }
    }
    func save(_ progress: MigrationProgress) throws { try write(JSONEncoder().encode(progress), to: progressURL) }
    func write(_ data: Data, to url: URL) throws {
        let box = try AES.GCM.seal(data, using: key, authenticating: Data(url.lastPathComponent.utf8))
        guard let bytes = box.combined else { throw MigrationError.invalidSource }
        try AtomicFile.write(bytes, to: url)
    }
    func open(_ url: URL) throws -> Data {
        try AES.GCM.open(AES.GCM.SealedBox(combined: AtomicFile.read(url, maximumBytes: 64 * 1024 * 1024)), using: key, authenticating: Data(url.lastPathComponent.utf8))
    }
}
func json(_ value: Any) throws -> Data { try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .fragmentsAllowed, .withoutEscapingSlashes]) }
func tuple(_ parts: String...) -> String { String(data: try! json(parts), encoding: .utf8)! }
