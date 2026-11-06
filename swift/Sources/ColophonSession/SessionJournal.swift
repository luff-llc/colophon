import Foundation
import ColophonKitStorage

/// Private, durable publication intent and receipts. No plaintext query state or private keys.
struct SessionJournal: Codable, Sendable {
    var libraryID: String?
    var left = false
    var knownPaths: Set<String> = []
    var pending: [String: Data] = [:]
    var migration: [String: MigrationReceipt]? = [:]
    struct MigrationReceipt: Codable, Sendable {
        let commandDigest: String
        var operationID: String?
        var uncertain: Bool?
    }
    var ingress: [UUID: IngressReceipt] = [:]
    struct IngressReceipt: Codable, Sendable {
        let envelope: IngressEnvelope
        var operationID: String?
        var uncertain: Bool?
    }
    static func load(at url: URL) throws -> Self {
        do { return try JSONDecoder().decode(Self.self, from: AtomicFile.read(url, maximumBytes: 64 * 1024 * 1024)) }
        catch let error as CocoaError where error.code == .fileReadNoSuchFile || error.code == .fileNoSuchFile { return Self() }
    }
    func save(at url: URL) throws { try AtomicFile.write(JSONEncoder().encode(self), to: url) }
}
