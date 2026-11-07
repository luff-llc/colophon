import Foundation
import ColophonKitStorage

/// Private, durable publication intent and receipts. No plaintext query state or private keys.
struct SessionJournal: Codable, Sendable {
    var libraryID: String?
    var left = false
    var knownPaths: Set<String> = []
    private var persistedKnown: Set<String> = []
    private var knownLogURL: URL?
    private var pendingKnown: Set<String> = []
    mutating func observe(_ paths: some Sequence<String>) {
        for path in paths where knownPaths.insert(path).inserted { pendingKnown.insert(path) }
    }
    enum CodingKeys: String, CodingKey { case libraryID, left, knownPaths, pending, migration, ingress }
    func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(libraryID, forKey: .libraryID)
        try container.encode(left, forKey: .left)
        try container.encode(Set<String>(), forKey: .knownPaths)
        try container.encode(pending, forKey: .pending)
        try container.encodeIfPresent(migration, forKey: .migration)
        try container.encode(ingress, forKey: .ingress)
    }
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
        do {
            var journal = try JSONDecoder().decode(Self.self, from: AtomicFile.read(url, maximumBytes: 64 * 1024 * 1024))
            let log = url.deletingPathExtension().appendingPathExtension("known.log")
            if FileManager.default.fileExists(atPath: log.path) {
                let bytes = try AtomicFile.read(log, maximumBytes: 256 * 1024 * 1024)
                if let end = bytes.lastIndex(of: 10) {
                    let paths = bytes[..<end].split(separator: 10).map { String(decoding: $0, as: UTF8.self) }
                    for path in paths { try RecordPath.validate(path) }
                    journal.persistedKnown = Set(paths); journal.knownPaths.formUnion(paths)
                }
                journal.knownLogURL = log
            }
            return journal
        }
        catch let error as CocoaError where error.code == .fileReadNoSuchFile || error.code == .fileNoSuchFile { return Self() }
    }
    mutating func save(at url: URL) throws {
        let log = url.deletingPathExtension().appendingPathExtension("known.log")
        if knownLogURL != log {
            try AtomicFile.write(Data(), to: log); knownLogURL = log; persistedKnown = []; pendingKnown = knownPaths
        }
        if !pendingKnown.isEmpty {
            try AtomicFile.append(Data(pendingKnown.map { $0 + "\n" }.joined().utf8), to: log)
            persistedKnown.formUnion(pendingKnown); pendingKnown.removeAll(keepingCapacity: true)
        }
        try AtomicFile.write(JSONEncoder().encode(self), to: url)
    }
}
