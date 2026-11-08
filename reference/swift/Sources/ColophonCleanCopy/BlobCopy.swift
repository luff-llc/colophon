import ColophonCore
import ColophonStore
import ColophonMigration
import ColophonReplica
import ColophonSession
import CryptoKit
import Foundation

/// Verified old blob references are the only source of namespace, epoch and plaintext digest.
struct SourceBlob {
    let namespace: String
    let reference: BlobRef
    let mediaType: String
    let operationID: String
    let signedBodyDigest: String
    let sourcePath: String
}

struct BlobCopyResult {
    var descriptors: [String: [String: Data]] = [:]
    var copiedPaths = Set<String>()
    var unresolved: [UnresolvedRecord] = []
    var failedReference = false
}

@MainActor
enum BlobCopy {
    static func run(snapshot: any LegacyLibrarySnapshot, reader: any Identity, session: ColophonSession,
                    directory: URL, key: SymmetricKey) async throws -> BlobCopyResult {
        var result = BlobCopyResult()
        let replica = Replica(store: try memoryStore(snapshot.records), identity: reader)
        let references = try references(snapshot)
        for blob in references {
            let path = LibraryPath.blob(blob.reference.digest)
            do {
                guard let plaintext = try replica.blob(blob.reference, in: blob.namespace) else {
                    throw MigrationError.sourceUnavailable(path)
                }
                guard plaintext.count == blob.reference.size else { throw MigrationError.invalidSource }
                let unit = "clean-copy-blob/" + digest(try json([snapshot.libraryID, blob.namespace, blob.reference.digest, blob.mediaType]))
                let manifestURL = directory.appendingPathComponent(digest(Data(unit.utf8)) + ".aesgcm")
                let manifest: Data
                if FileManager.default.fileExists(atPath: manifestURL.path) {
                    manifest = try AES.GCM.open(AES.GCM.SealedBox(combined: Data(contentsOf: manifestURL)), using: key,
                                                authenticating: Data(manifestURL.lastPathComponent.utf8))
                } else {
                    manifest = try await session.migrationBlob(namespace: blob.namespace, mediaType: blob.mediaType, bytes: plaintext)
                    let box = try AES.GCM.seal(manifest, using: key, authenticating: Data(manifestURL.lastPathComponent.utf8))
                    guard let bytes = box.combined else { throw MigrationError.invalidSource }
                    try writePrivate(bytes, to: manifestURL)
                }
                guard let decoded = try JSONSerialization.jsonObject(with: manifest) as? [String: Any],
                      let descriptor = decoded["descriptor"] as? [String: Any],
                      descriptor["digest"] as? String == blob.reference.plain,
                      (descriptor["size"] as? NSNumber)?.intValue == plaintext.count,
                      descriptor["mediaType"] as? String == blob.mediaType else { throw MigrationError.invalidSource }
                let payload: [String: Any] = ["key": unit, "children": [], "blobs": [decoded],
                    "evidence": ["sourceLibrary": snapshot.libraryID, "sourcePath": blob.sourcePath,
                        "operationID": blob.operationID, "signedBodyDigest": blob.signedBodyDigest,
                        "sourceBlob": blob.reference.digest, "plaintextDigest": blob.reference.plain]]
                let receipt = try await session.performMigration(DomainCommand(namespace: blob.namespace, kind: "colophon.importBatch",
                    payloadJSON: json(payload)), outputKey: unit)
                guard case .saved = receipt else { throw MigrationError.destinationUnavailable }
                let bytes = try json(descriptor)
                // The notes importer keys descriptors by old ciphertext digest; listening keys
                // them by authenticated plaintext digest. Preserve both lookups explicitly.
                for lookup in [blob.reference.digest, blob.reference.plain] {
                    if let old = result.descriptors[blob.namespace]?[lookup], old != bytes { throw MigrationError.invalidSource }
                    result.descriptors[blob.namespace, default: [:]][lookup] = bytes
                }
                result.copiedPaths.insert(path)
            } catch is CancellationError { throw CancellationError() }
            catch {
                result.failedReference = true
                result.unresolved.append(UnresolvedRecord(path: path, reason: "Blob could not be copied: \(error)"))
            }
        }
        for path in snapshot.records.keys.sorted() where path.hasPrefix("blobs/") && !result.copiedPaths.contains(path) && !result.unresolved.contains(where: { $0.path == path }) {
            result.unresolved.append(UnresolvedRecord(path: path,
                reason: "No authenticated readable BlobRef establishes this blob's namespace, epoch and plaintext digest"))
        }
        return result
    }

    /// Source-only descriptor preparation for the independent replay: verifies plaintext but
    /// never creates a destination blob writer, ciphertext, manifest, or file.
    static func referenceDescriptors(snapshot: any LegacyLibrarySnapshot, reader: any Identity) throws -> [String: [String: Data]] {
        let replica = Replica(store: try memoryStore(snapshot.records), identity: reader)
        var descriptors: [String: [String: Data]] = [:]
        for blob in try references(snapshot) {
            guard let plaintext = try replica.blob(blob.reference, in: blob.namespace), plaintext.count == blob.reference.size else {
                throw MigrationError.sourceUnavailable(LibraryPath.blob(blob.reference.digest))
            }
            let descriptor = try json(["digest": blob.reference.plain, "size": plaintext.count, "mediaType": blob.mediaType])
            for key in [blob.reference.digest, blob.reference.plain] {
                if let previous = descriptors[blob.namespace]?[key], previous != descriptor { throw MigrationError.invalidSource }
                descriptors[blob.namespace, default: [:]][key] = descriptor
            }
        }
        return descriptors
    }

    private static func references(_ snapshot: any LegacyLibrarySnapshot) throws -> [SourceBlob] {
        var blobs: [SourceBlob] = []
        var seen = Set<String>()
        for namespace in snapshot.namespaces.sorted() {
            for operation in snapshot.operations[namespace] ?? [] {
                func scan(_ value: JSONValue, mediaType: String?) {
                    if let reference = BlobRef(json: value) {
                        // 0.1 BlobRef has no type. Unknown binary content is explicitly represented
                        // as application/octet-stream; no codec or text interpretation is inferred.
                        let type = mediaType ?? "application/octet-stream"
                        let key = namespace + "/" + reference.digest + "/" + reference.plain + "/" + String(reference.epoch) + "/" + String(reference.size) + "/" + type
                        if seen.insert(key).inserted {
                            blobs.append(SourceBlob(namespace: namespace, reference: reference, mediaType: type,
                                operationID: operation.id, signedBodyDigest: operation.signedBodyDigest, sourcePath: operation.sourcePath))
                        }
                    }
                    if let object = value.object {
                        let type = object["mediaType"]?.string ?? object["mime"]?.string ?? mediaType
                        for name in object.keys.sorted() { if let child = object[name] { scan(child, mediaType: type) } }
                    } else if let array = value.array { for child in array { scan(child, mediaType: mediaType) } }
                }
                scan(try Canonical.decode(JSONValue.self, from: operation.payloadJSON), mediaType: nil)
            }
        }
        return blobs
    }
}

/// Supplies destination plaintext descriptors to the existing domain import context. Exact
/// source operations and evidence stay unchanged; no destination key is exposed to the reader.
struct BlobMappedSource: LegacyLibrarySource {
    let base: any LegacyLibrarySource
    let descriptors: [String: [String: Data]]
    func snapshot(namespaces: Set<String>) throws -> any LegacyLibrarySnapshot {
        BlobMappedSnapshot(base: try base.snapshot(namespaces: namespaces), descriptors: descriptors)
    }
}
private struct BlobMappedSnapshot: LegacyLibrarySnapshot {
    let base: any LegacyLibrarySnapshot
    let descriptors: [String: [String: Data]]
    var libraryID: String { base.libraryID }
    var readerID: String { base.readerID }
    var members: [LegacyMember] { base.members }
    var namespaces: Set<String> { base.namespaces }
    var changeToken: String { base.changeToken }
    var records: [String: Data] { base.records }
    var operations: [String: [LegacyOperation]] { base.operations }
    var unresolved: [String] { base.unresolved }
    var unresolvedPaths: [String] { base.unresolvedPaths }
    func evaluate(namespace: String, index: Int, bindings: LegacyImportBindings) throws -> LegacyEvaluation {
        let result = try base.evaluate(namespace: namespace, index: index, bindings: bindings)
        var context = try JSONSerialization.jsonObject(with: result.contextJSON) as? [String: Any] ?? [:]
        context["blobs"] = try (descriptors[namespace] ?? [:]).mapValues { try JSONSerialization.jsonObject(with: $0) }
        return LegacyEvaluation(outcome: result.outcome, contextJSON: try json(context))
    }
}
