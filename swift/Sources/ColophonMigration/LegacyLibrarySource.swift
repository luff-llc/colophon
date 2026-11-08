import Foundation
import CryptoKit

/// A host-owned verifier for the application's actual 0.1 implementation.
/// See docs/migration.md for the security, ordering, snapshot and catch-up contract.
public protocol LegacyLibrarySource: Sendable {
    func snapshot(namespaces: Set<String>) throws -> any LegacyLibrarySnapshot
}

/// Immutable, verified source history. Evaluation must use this snapshot, never live storage.
public protocol LegacyLibrarySnapshot: Sendable {
    var libraryID: String { get }
    var readerID: String { get }
    var members: [LegacyMember] { get }
    var namespaces: Set<String> { get }
    /// Changes whenever relevant records, admission or evaluated source semantics change.
    var changeToken: String { get }
    /// Exact source bytes needed to audit this scope, including authority and rejected records.
    var records: [String: Data] { get }
    /// Complete deterministic 0.1 order for every requested namespace, including held evidence.
    var operations: [String: [LegacyOperation]] { get }
    var unresolved: [String] { get }
    /// Untrusted envelopes retained as evidence; must have matching entries in records.
    var unresolvedPaths: [String] { get }
    func evaluate(namespace: String, index: Int, bindings: LegacyImportBindings) throws -> LegacyEvaluation
}

public struct LegacyMember: Sendable {
    public let id: String
    public let label: String
    public init(id: String, label: String) { self.id = id; self.label = label }
}

public enum LegacyAdmission: String, Sendable { case admitted, held }

public struct LegacyOperation: Sendable {
    public let id: String
    public let authorID: String
    public let authorLabel: String
    public let signedBodyDigest: String
    public let kind: String
    public let version: UInt64
    public let payloadJSON: Data
    public let claimedDateJSON: Data
    public let admission: LegacyAdmission
    public let admissionDetail: String
    public let sourcePath: String
    /// Stable per-entry source semantics, including whole-history receipts where applicable.
    /// Change it if a later arrival changes this entry's old evaluated outcome.
    public let semanticFingerprint: String

    public init(id: String, authorID: String, authorLabel: String, signedBodyDigest: String,
                kind: String, version: UInt64, payloadJSON: Data, claimedDateJSON: Data,
                admission: LegacyAdmission, sourcePath: String, semanticFingerprint: String, admissionDetail: String? = nil) {
        self.id = id; self.authorID = authorID; self.authorLabel = authorLabel
        self.signedBodyDigest = signedBodyDigest; self.kind = kind; self.version = version
        self.payloadJSON = payloadJSON; self.claimedDateJSON = claimedDateJSON
        self.admission = admission; self.admissionDetail = admissionDetail ?? admission.rawValue
        self.sourcePath = sourcePath; self.semanticFingerprint = semanticFingerprint
    }
    // Keep the existing receipt key codec so resumed output keys remain deterministic.
    var key: String { migrationDigest(Data("\(authorID)/\(id)/\(signedBodyDigest)".utf8)) }
    var fingerprint: String { get throws { try tuple(key, admission.rawValue, admissionDetail, authorLabel, semanticFingerprint) } }
}

/// Imported destination heads only. Never replace these with current native destination heads.
/// Keys are compact JSON arrays: heads [namespace, objectID, component], revisions
/// [namespace, component, oldOperationID]. See the per-domain context contract in docs/migration.md.
public struct LegacyImportBindings: Sendable {
    public let heads: [String: String]
    public let revisions: [String: String]
    public init(heads: [String: String], revisions: [String: String]) {
        self.heads = heads; self.revisions = revisions
    }
}

public struct LegacyEvaluation: Sendable {
    public let outcome: String
    public let contextJSON: Data
    public init(outcome: String, contextJSON: Data) {
        self.outcome = outcome; self.contextJSON = contextJSON
    }
}

func migrationDigest(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
