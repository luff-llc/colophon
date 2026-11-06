import Foundation
import CryptoKit
import ColophonCore
import ColophonStore
import ColophonAuthority
import ColophonReplica
import ColophonMigration

struct SourceSnapshot: Sendable {
    let authority: AuthorityState
    let records: [String: Data]
    let operations: [String: [SourceEntry]]
    let unresolved: [String]
    let unresolvedPaths: [String]
}
struct SourceEntry: Sendable {
    let admitted: AdmittedOperation
    let digest: String
    let path: String
    let payloadJSON: Data
    let claimedDateJSON: Data
}

enum SourceReader {
    static let namespaces = ["reading.books", "listening.podcasts", "reading.saved", "notes"]
    /// Snapshot into a private immutable reader: no migration method writes to the source store.
    static func read(store: any ColophonStore.RecordStore, reader: any Identity, root: any Identity, namespaces: Set<String>) throws -> SourceSnapshot {
        let copy = MemoryStore()
        func copyFiles(_ directory: String) throws {
            for name in try store.list(directory) {
                guard !name.contains("/"), name != ".", name != ".." else { throw MigrationError.invalidSource }
                let path = directory + "/" + name
                guard let bytes = try store.read(path) else { throw MigrationError.sourceUnavailable(path) }
                try copy.create(path, bytes)
            }
        }
        try copyFiles("authority"); try copyFiles("requests"); try copyFiles("blobs")
        for author in try store.list("ops") {
            guard !author.contains("/"), author != ".", author != ".." else { throw MigrationError.invalidSource }
            try copyFiles("ops/" + author)
        }
        let replica = Replica(store: copy, identity: reader)
        let authority = try replica.authority()
        let rootPublic = try root.availablePublicIdentity()
        guard rootPublic == authority.root else { throw MigrationError.rootRequired }
        let challenge = Data(("colophon-migration-root/1/" + authority.libraryID + "/" + UUID().uuidString).utf8)
        guard authority.root.verify(try root.sign(challenge), over: challenge) else { throw MigrationError.rootRequired }
        let readerID = try reader.availablePublicIdentity().id
        var entries: [String: [SourceEntry]] = [:]
        var accounted = Set<String>(), unresolved: [String] = []
        for namespace in namespaces.sorted() {
            guard authority.keys[namespace] != nil else { throw MigrationError.sourceUnavailable(namespace) }
            guard let view = try replica.readComplete(namespace) else { throw MigrationError.sourceUnavailable(namespace) }
            for entry in view.operations {
                let path = LibraryPath.operation(author: entry.author, clock: entry.operation.clock, id: entry.id)
                guard let bytes = copy.snapshot[path] else { throw MigrationError.sourceUnavailable(path) }
                let signed = try Canonical.decode(SignedRecord.self, from: bytes)
                let header = try Canonical.decode(OperationHeader.self, from: signed.body)
                guard header.author == entry.author, header.namespace == namespace,
                      authority.members[entry.author]?.key.verify(signed) == true,
                      let sealedKey = authority.keys[namespace]?[header.epoch]?[readerID] else { throw MigrationError.invalidSource }
                let key = try reader.open(sealedKey)
                let plaintext = try AES.GCM.open(AES.GCM.SealedBox(combined: header.sealed), using: key)
                guard try Canonical.decode(ColophonOperation.self, from: plaintext) == entry.operation else { throw MigrationError.invalidSource }
                let original = try JSONSerialization.jsonObject(with: plaintext) as? [String: Any] ?? [:]
                entries[namespace, default: []].append(.init(admitted: entry, digest: Canonical.digest(signed.body), path: path,
                    payloadJSON: try json(original["payload"] ?? NSNull()), claimedDateJSON: try json(original["created"] ?? NSNull())))
                accounted.insert(path)
            }
            unresolved += view.rejected.map { "\($0.path): \($0.reason)" }
            if view.unreadable > 0 { unresolved.append("\(namespace): \(view.unreadable) unreadable records") }
        }
        // Only a verified signed header can establish that an envelope belongs to another
        // namespace. Never trust an unverified namespace field to suppress invalid evidence.
        let foreign = Set(copy.snapshot.compactMap { path, bytes -> String? in
            guard path.hasPrefix("ops/"),
                  let signed = try? Canonical.decode(SignedRecord.self, from: bytes),
                  let header = try? Canonical.decode(OperationHeader.self, from: signed.body),
                  authority.members[header.author]?.key.verify(signed) == true,
                  !namespaces.contains(header.namespace) else { return nil }
            return path
        })
        let selected = copy.snapshot.filter { !foreign.contains($0.key) }
        let unresolvedPaths = selected.keys.filter { $0.hasPrefix("ops/") && !accounted.contains($0) }.sorted()
        unresolved += unresolvedPaths.map { "Unresolved source envelope: " + $0 }
        return SourceSnapshot(authority: authority, records: selected, operations: entries, unresolved: unresolved, unresolvedPaths: unresolvedPaths)
    }
}
