import ColophonKit
import ColophonMigration
import Foundation

/// Accounting totals for one verified source author within a namespace.
public struct AuthorAccounting: Codable, Sendable, Equatable {
    /// Source operations in replica order, including held operations.
    public let expected: Int
    /// Source operations with admitted destination import children.
    public let imported: Int
    /// Source operations retained as unresolved, each with a reason.
    public let unresolved: Int
    /// Every source operation is accounted for exactly once.
    public var passed: Bool { expected == imported + unresolved }
}

/// The disposition of one exact authenticated source operation.
public struct OperationAccounting: Codable, Sendable, Equatable {
    /// Relative source envelope path.
    public let sourcePath: String
    /// Original author, never destination authorship.
    public let authorID: String
    /// Original source operation ID.
    public let operationID: String
    /// SHA-256 of the original exact signed body.
    public let signedBodyDigest: String
    /// `imported`, `unresolved`, or `missing`.
    public let disposition: String
    /// Destination admitted virtual child IDs, or an empty array for evidence only.
    public let children: [String]
    /// Explicit explanation for an unresolved or missing source operation.
    public let reason: String?
}

/// Source accounting for one namespace, independently checked against admitted core receipts.
public struct NamespaceAccounting: Codable, Sendable, Equatable {
    /// Number of verified source operations expected.
    public let expected: Int
    /// Operations with admitted import children.
    public let imported: Int
    /// Operations with no effective child and an explicit retained-evidence reason.
    public let unresolved: Int
    /// Counts grouped by original author.
    public let authors: [String: AuthorAccounting]
    /// One row per source operation, retaining replica order.
    public let operations: [OperationAccounting]
    /// Extra or missing publication/receipt diagnostics.
    public let failures: [String]
    /// Counts, receipts and source authors all match.
    public var passed: Bool {
        failures.isEmpty && expected == imported + unresolved && operations.count == expected &&
        authors.values.allSatisfy(\.passed) && authors.values.reduce(0) { $0 + $1.expected } == expected
    }
}

struct CopyVerification: Sendable {
    let views: [String: ViewDigests]
    let accounting: [String: NamespaceAccounting]
    let unresolved: [UnresolvedRecord]

    @MainActor
    static func check(snapshot: any LegacyLibrarySnapshot, destination: Library) async throws -> Self {
        let replay = try await InMemoryReference.replay(snapshot)
        let destinationID = try await destination.id
        var views: [String: ViewDigests] = [:]
        var accounting: [String: NamespaceAccounting] = [:]
        var unresolved: [UnresolvedRecord] = []
        for namespace in snapshot.namespaces.sorted() {
            let actual = try await destination.view(namespace: namespace).get()
            let reference = try await replay.library.view(namespace: namespace).get()
            let units = replay.units[namespace] ?? []
            var failures: [String] = []
            var rows: [OperationAccounting] = []
            let expectedBatchKeys = Set(units.map(\.batchKey))
            var actualIDs = Set(actual.admitted.map(\.id))
            var referenceIDs = Set(reference.admitted.map(\.id))
            for operation in reference.admitted where operation.kind == "colophon.importBatch" {
                let batch = try JSONSerialization.jsonObject(with: operation.payload) as? [String: Any] ?? [:]
                if let outputs = (batch["evidence"] as? [String: Any])?["outputOperationIDs"] as? [String: String] {
                    referenceIDs.formUnion(outputs.values)
                }
            }
            for operation in actual.admitted where operation.kind == "colophon.importBatch" {
                let batch = try JSONSerialization.jsonObject(with: operation.payload) as? [String: Any] ?? [:]
                if let evidence = batch["evidence"] as? [String: Any], evidence["sourceLibrary"] as? String == snapshot.libraryID,
                   evidence["namespace"] as? String == namespace, evidence["admittedOrder"] != nil,
                   let key = batch["key"] as? String, !expectedBatchKeys.contains(key) {
                    failures.append("Unexpected source import unit: " + key)
                }
            }
            for (index, unit) in units.enumerated() {
                let operation = unit.operation
                let bytes = try await destination.query(namespace: namespace, name: "importReceipt", arguments: json(["key": unit.batchKey])).get()
                let receipt = try JSONSerialization.jsonObject(with: bytes, options: .fragmentsAllowed) as? [String: Any]
                let evidence = receipt?["evidence"] as? [String: Any]
                let outputs = receipt?["outputOperationIDs"] as? [String: String] ?? [:]
                var expectedOutputs: [String: String] = [:]
                for key in unit.outputKeys {
                    expectedOutputs[key] = try importOutputId(library: destinationID, namespace: namespace, batch: unit.batchKey, child: key)
                }
                actualIDs.formUnion(outputs.values)
                let publication = receipt?["publication"] as? String
                let admitted = actual.admitted.contains { $0.id == publication && $0.kind == "colophon.importBatch" }
                let matches = admitted && outputs == expectedOutputs && evidence?["operationID"] as? String == operation.id &&
                    evidence?["authorID"] as? String == operation.authorID && evidence?["signedBodyDigest"] as? String == operation.signedBodyDigest &&
                    evidence?["sourceLibrary"] as? String == snapshot.libraryID && evidence?["namespace"] as? String == namespace &&
                    (evidence?["admittedOrder"] as? NSNumber)?.intValue == index && evidence?["authorLabel"] as? String == operation.authorLabel
                let disposition: String
                let reason: String?
                if !matches {
                    disposition = "missing"; reason = "Missing or mismatched admitted source-unit receipt/children"
                    failures.append(operation.sourcePath + ": " + (reason ?? "missing"))
                } else if outputs.isEmpty {
                    disposition = "unresolved"; reason = unit.reason
                } else { disposition = "imported"; reason = nil }
                if let reason { unresolved.append(UnresolvedRecord(path: operation.sourcePath, reason: reason)) }
                rows.append(OperationAccounting(sourcePath: operation.sourcePath, authorID: operation.authorID,
                    operationID: operation.id, signedBodyDigest: operation.signedBodyDigest, disposition: disposition,
                    children: outputs.values.sorted(), reason: reason))
            }
            let expectedAuthors = Dictionary(grouping: snapshot.operations[namespace] ?? [], by: \.authorID).mapValues(\.count)
            let groupedRows = Dictionary(grouping: rows, by: \.authorID)
            let authors = Dictionary(uniqueKeysWithValues: Set(expectedAuthors.keys).union(groupedRows.keys).map { author in
                let records = groupedRows[author] ?? []
                return (author, AuthorAccounting(expected: expectedAuthors[author] ?? 0,
                    imported: records.filter { $0.disposition == "imported" }.count,
                    unresolved: records.filter { $0.disposition == "unresolved" }.count))
            })
            accounting[namespace] = NamespaceAccounting(expected: (snapshot.operations[namespace] ?? []).count,
                imported: rows.filter { $0.disposition == "imported" }.count, unresolved: rows.filter { $0.disposition == "unresolved" }.count,
                authors: authors, operations: rows, failures: failures.sorted())
            let canonicalReference = try ViewNormalization.canonical(reference.state, namespace: namespace, operationIDs: referenceIDs)
            let canonicalDestination = try ViewNormalization.canonical(actual.state, namespace: namespace, operationIDs: actualIDs)
            views[namespace] = ViewDigests(reference: digest(canonicalReference), destination: digest(canonicalDestination),
                normalizedFields: ViewNormalization.printedFields(namespace: namespace),
                reason: canonicalReference == canonicalDestination ? nil : "Complete normalized domain views differ")
        }
        return Self(views: views, accounting: accounting, unresolved: unresolved)
    }
}

/// The one verified snapshot used by the real import and the independent reference replay.
struct FrozenLegacySource: LegacyLibrarySource {
    let value: any LegacyLibrarySnapshot
    func snapshot(namespaces: Set<String>) throws -> any LegacyLibrarySnapshot {
        guard namespaces == value.namespaces else { throw CleanCopyError.workspaceMismatch }
        return value
    }
}
