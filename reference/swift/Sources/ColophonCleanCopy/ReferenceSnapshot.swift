import Foundation
import ColophonCore
import ColophonStore
import ColophonMigration

struct ReferenceSnapshot: LegacyLibrarySnapshot {
    let source: SourceSnapshot
    let readerID: String
    let namespaces: Set<String>
    var libraryID: String { source.authority.libraryID }
    var members: [LegacyMember] { source.authority.members.values.map { .init(id: $0.id, label: $0.label) } }
    var records: [String: Data] { source.records }
    var unresolved: [String] { source.unresolved }
    var unresolvedPaths: [String] { source.unresolvedPaths }
    var changeToken: String {
        Canonical.digest(Data(records.keys.sorted().map { $0 + ":" + (records[$0].map(Canonical.digest) ?? "missing") }.joined(separator: "\n").utf8))
    }
    var operations: [String: [LegacyOperation]] {
        Dictionary(uniqueKeysWithValues: namespaces.map { namespace in
            let entries = source.operations[namespace] ?? []
            let counts = Dictionary(grouping: entries, by: { $0.admitted.id }).mapValues(\.count)
            return (namespace, entries.map { entry in
                let op = entry.admitted.operation
                // The service folds use whole-history duplicate-ID receipts. A new duplicate
                // changes old semantics even if the appended operation sorts after the tail.
                let duplicateCount = counts[op.id] ?? 0
                let receiptKind = ["legacy.bridge.import", "legacy.podcastState.import", "podcast.source.publish", "playback.naturalEnd.batch"].contains(op.kind)
                return LegacyOperation(id: op.id, authorID: entry.admitted.author, authorLabel: entry.admitted.authorLabel,
                    signedBodyDigest: entry.digest, kind: op.kind, version: UInt64(max(0, op.v)),
                    payloadJSON: entry.payloadJSON, claimedDateJSON: entry.claimedDateJSON,
                    admission: entry.admitted.status == .admitted ? .admitted : .held, sourcePath: entry.path,
                    semanticFingerprint: receiptKind ? "reference-fold-1/" + String(duplicateCount) : "reference-fold-1",
                    admissionDetail: String(describing: entry.admitted.status))
            })
        })
    }
    func evaluate(namespace: String, index: Int, bindings: LegacyImportBindings) throws -> LegacyEvaluation {
        guard namespaces.contains(namespace), let entries = source.operations[namespace], entries.indices.contains(index) else { throw MigrationError.invalidSource }
        let result = try SourceEvaluation.evaluate(namespace: namespace, entries: entries, index: index, library: libraryID, progress: bindings)
        return LegacyEvaluation(outcome: result.outcome, contextJSON: try json(result.context))
    }
}

func json(_ value: Any) throws -> Data { try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .fragmentsAllowed, .withoutEscapingSlashes]) }
func tuple(_ parts: String...) throws -> String { String(decoding: try json(parts), as: UTF8.self) }
