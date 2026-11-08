import ColophonAuthority
import ColophonCore
import ColophonKit
import ColophonMigration
import ColophonSession
import CryptoKit
import Foundation

/// A source record that could not be projected, with its retained path and reason.
public struct UnresolvedRecord: Codable, Sendable, Equatable {
    /// Relative source path, or a namespace for an aggregate verifier diagnostic.
    public let path: String
    /// Why the record needs review.
    public let reason: String
}

/// Certification status for one domain. Missing digests are never interpreted as equality.
public struct ViewDigests: Codable, Sendable, Equatable {
    /// SHA-256 of the complete normalized in-memory reference domain view.
    public let reference: String?
    /// SHA-256 of the corresponding canonical 0.4 domain view, when available.
    public let destination: String?
    /// Fixed domain-specific JSON paths removed for this comparison.
    public let normalizedFields: [String]
    /// Why comparison is unavailable, if it cannot be performed.
    public let reason: String?
}

/// Durable machine-readable clean-copy results. A copied destination is not certified until
/// every domain passes source accounting and independent reference equality.
public struct CleanCopyReport: Codable, Sendable, Equatable {
    /// Verified old library ID.
    public let sourceLibraryID: String
    /// The fresh 0.4 library ID, once creation completed.
    public let newLibraryID: String?
    /// Admitted plus held operation counts for every namespace.
    public let countsPerNamespace: [String: Int]
    /// Admitted plus held operation counts for every verified source author.
    public let countsPerAuthor: [String: Int]
    /// Per-domain comparison results; unavailable comparisons have explicit reasons.
    public let viewDigests: [String: ViewDigests]
    /// Independent source-operation accounting by namespace and original author.
    public let accounting: [String: NamespaceAccounting]
    /// Source ciphertext paths successfully copied under destination namespace epochs.
    public let copiedBlobPaths: [String]
    /// Every record that needs reconciliation or a missing codec.
    public let unresolved: [UnresolvedRecord]
    /// Whether the original folder still equals its recorded source manifest.
    public let sourceUnchanged: Bool
    /// Number of source operations still awaiting import.
    public let remainingOperations: Int
    /// A failure that interrupted import, if any.
    public let failure: String?
    /// Follow-up steps for the person, including adding a passkey from an app.
    public let nextSteps: [String]
    /// True only when the entire copy has independently passed verification.
    public var verified: Bool {
        sourceUnchanged && remainingOperations == 0 && failure == nil && !viewDigests.isEmpty && Set(viewDigests.keys) == Set(accounting.keys) &&
        accounting.values.allSatisfy(\.passed) &&
        viewDigests.values.allSatisfy { $0.reference != nil && $0.reference == $0.destination && $0.reason == nil }
    }
}

private struct StoredKeys: Codable {
    let signing: Data
    let agreement: Data
    init(_ keys: SoftwareKeys) { signing = keys.signingPrivateKey; agreement = keys.agreementPrivateKey }
    func provider() throws -> SoftwareKeys { try SoftwareKeys(signingPrivateKey: signing, agreementPrivateKey: agreement) }
}
private struct DestinationState: Codable {
    let path: String
    let sourceID: String
    let namespaces: [String]
    let importedFrom: Bool
    let controllerSigning: Data
    let expiry: String
    var libraryID: String?
}

extension CleanCopyWorkspace {
    /// Import through ColophonMigration's atomic import-batch path. The default software owner
    /// and separate device member are persisted privately, never in library records. Supply the
    /// same raw owner provider on every rerun when using host-managed keys. The import grant
    /// expires one hour after the first run. Certification checks source accounting and the
    /// complete normalized views of an independent, IO-free import-transform replay.
    @MainActor
    public func copy(to destination: URL, importedFrom: Bool = false,
                     owner: (any AsyncKeyProvider)? = nil) async throws -> CleanCopyReport {
        let lease = try WorkspaceLease(directory: directory)
        defer { lease.close() }
        try validateDestination(destination)
        try assertSourceUnchanged()
        let source = try source()
        let authority = try AuthorityLog(store: memoryStore(snapshotRecords())).state()
        let namespaces = Set(authority.namespaces)
        // LibraryMigration supports precisely these domains. An undeclared codec must fail.
        let snapshot = try source.snapshot(namespaces: namespaces)
        let destination = canonicalLocation(destination)
        let stateURL = directory.appendingPathComponent("destination.json")
        let controller: any AsyncKeyProvider
        if let owner { controller = owner }
        else { controller = try softwareKeys("owner-keys.json", create: !FileManager.default.fileExists(atPath: stateURL.path)) }
        let member = try softwareKeys("member-keys.json", create: !FileManager.default.fileExists(atPath: stateURL.path))
        let controllerSigning = try await controller.publicKeys().signing
        var state: DestinationState
        if FileManager.default.fileExists(atPath: stateURL.path) {
            state = try JSONDecoder().decode(DestinationState.self, from: Data(contentsOf: stateURL))
            guard state.path == destination.path, state.sourceID == snapshot.libraryID,
                  state.namespaces == namespaces.sorted(), state.importedFrom == importedFrom,
                  state.controllerSigning == controllerSigning else { throw CleanCopyError.workspaceMismatch }
        } else {
            guard !FileManager.default.fileExists(atPath: destination.path) else { throw CleanCopyError.destinationExists }
            state = DestinationState(path: destination.path, sourceID: snapshot.libraryID, namespaces: namespaces.sorted(),
                importedFrom: importedFrom, controllerSigning: controllerSigning,
                expiry: Date.now.addingTimeInterval(3600).ISO8601Format())
            try writePrivate(try encode(state), to: stateURL)
        }
        try privateDirectory(destination)
        let marker = directory.appendingPathComponent("migration-marker.json")
        let session = ColophonSession(configuration: .init(memberLabel: "Clean copy (Mac)", memberKind: .device,
            namespaces: state.namespaces, location: .folder(destination), privateContainer: directory.appendingPathComponent("session"),
            keys: member, ownerController: controller, migrationMarker: marker, migrationWriter: true,
            importExpires: state.expiry, importedFrom: state.importedFrom ? snapshot.libraryID : nil))
        var result: MigrationReport?
        var evidence: [Data] = []
        var verification: CopyVerification?
        var blobs = BlobCopyResult()
        var failure: String?
        do {
            await session.refresh()
            if session.phase == .noLibrary {
                guard state.libraryID == nil else { throw CleanCopyError.workspaceMismatch }
                await session.create()
            }
            guard session.phase == .ready, let id = session.libraryID else {
                throw BindingError.InvalidData(detail: "Destination phase: \(session.phase); \(session.lastError ?? "no diagnostic")")
            }
            guard state.libraryID == nil || state.libraryID == id else { throw CleanCopyError.workspaceMismatch }
            state.libraryID = id
            try writePrivate(try encode(state), to: stateURL)
            let evidenceKey = try evidenceKey()
            blobs = try await BlobCopy.run(snapshot: snapshot, reader: readerIdentity(), session: session,
                directory: directory.appendingPathComponent("blob-manifests"), key: evidenceKey)
            guard !blobs.failedReference else { throw MigrationError.sourceUnavailable("source blobs (see unresolved records)") }
            let mappedSource = BlobMappedSource(base: FrozenLegacySource(value: snapshot), descriptors: blobs.descriptors)
            let migration = LibraryMigration(source: mappedSource, namespaces: namespaces, destination: session,
                destinationLibraryID: id, privateContainer: directory.appendingPathComponent("migration"),
                evidenceKey: evidenceKey, markerURL: marker)
            repeat { result = try await migration.run() } while (result?.remainingOperations ?? 0) > 0
            evidence = try await migration.evidence()
            try await session.flushCheckpoint()
            let persisted = try await Library.open(records: FolderRecordStore(folder: destination).read(), me: member)
            // Descriptor preparation reads only the same verified source snapshot, without
            // reusing output views or re-encrypting blobs in the reference library.
            let referenceDescriptors = try BlobCopy.referenceDescriptors(snapshot: snapshot, reader: readerIdentity())
            let referenceSnapshot = try BlobMappedSource(base: FrozenLegacySource(value: snapshot), descriptors: referenceDescriptors).snapshot(namespaces: namespaces)
            verification = try await CopyVerification.check(snapshot: referenceSnapshot, destination: persisted)
        } catch { failure = String(describing: error) }
        let report = try makeReport(snapshot: snapshot, destinationID: state.libraryID, migration: result, failure: failure, blobs: blobs, evidence: evidence, verification: verification)
        try saveReport(report)
        if !report.sourceUnchanged { throw CleanCopyError.changedSource("source manifest (see report.json)") }
        return report
    }

    /// Reopen the destination read-only with the device member, reverify source integrity and
    /// regenerate both reports. Does not publish requests, authority, operations or blobs.
    @MainActor
    public func verify(destination: URL) async throws -> CleanCopyReport {
        let lease = try WorkspaceLease(directory: directory)
        defer { lease.close() }
        try validateDestination(destination)
        let state = try JSONDecoder().decode(DestinationState.self, from: Data(contentsOf: directory.appendingPathComponent("destination.json")))
        guard state.path == canonicalLocation(destination).path else { throw CleanCopyError.workspaceMismatch }
        let source = try source()
        let snapshot = try source.snapshot(namespaces: Set(state.namespaces))
        guard snapshot.libraryID == state.sourceID else { throw CleanCopyError.workspaceMismatch }
        let records = try await FolderRecordStore(folder: destination).read()
        let library = try await Library.open(records: records, me: softwareKeys("member-keys.json", create: false))
        let id = try await library.id
        guard id == state.libraryID else { throw CleanCopyError.workspaceMismatch }
        let descriptors = try BlobCopy.referenceDescriptors(snapshot: snapshot, reader: readerIdentity())
        let mapped = try BlobMappedSource(base: FrozenLegacySource(value: snapshot), descriptors: descriptors).snapshot(namespaces: Set(state.namespaces))
        let verification = try await CopyVerification.check(snapshot: mapped, destination: library)
        let previous = try JSONDecoder().decode(CleanCopyReport.self, from: Data(contentsOf: directory.appendingPathComponent("report.json")))
        let report = try makeReport(snapshot: snapshot, destinationID: id, migration: nil,
                                    failure: nil, remaining: 0, previousUnresolved: previous.unresolved,
                                    copiedBlobPaths: previous.copiedBlobPaths, verification: verification)
        try saveReport(report)
        if !report.sourceUnchanged { throw CleanCopyError.changedSource("source manifest (see report.json)") }
        return report
    }

    private func softwareKeys(_ filename: String, create: Bool) throws -> SoftwareKeys {
        let url = directory.appendingPathComponent(filename)
        if FileManager.default.fileExists(atPath: url.path) {
            return try JSONDecoder().decode(StoredKeys.self, from: Data(contentsOf: url)).provider()
        }
        guard create else { throw CleanCopyError.workspaceMismatch }
        let keys = SoftwareKeys()
        try writePrivate(try encode(StoredKeys(keys)), to: url)
        return keys
    }
    private func evidenceKey() throws -> SymmetricKey {
        let url = directory.appendingPathComponent("evidence-key")
        if FileManager.default.fileExists(atPath: url.path) {
            let bytes = try Data(contentsOf: url)
            guard bytes.count == 32 else { throw CleanCopyError.workspaceMismatch }
            return SymmetricKey(data: bytes)
        }
        // Never replace a lost journal key with a new one.
        guard !FileManager.default.fileExists(atPath: directory.appendingPathComponent("migration").path) else {
            throw CleanCopyError.workspaceMismatch
        }
        let key = SymmetricKey(size: .bits256)
        try writePrivate(key.withUnsafeBytes { Data($0) }, to: url)
        return key
    }
    func makeReport(snapshot: any LegacyLibrarySnapshot, destinationID: String?, migration: MigrationReport?,
                            failure: String?, remaining: Int? = nil, previousUnresolved: [UnresolvedRecord] = [],
                            copiedBlobPaths: [String] = [], blobs: BlobCopyResult? = nil, evidence: [Data] = [], verification: CopyVerification? = nil) throws -> CleanCopyReport {
        var unchanged = true
        do { try assertSourceUnchanged() } catch { unchanged = false }
        var unresolved = previousUnresolved
        func record(_ path: String, _ reason: String) {
            let entry = UnresolvedRecord(path: path, reason: reason)
            if !unresolved.contains(entry) { unresolved.append(entry) }
        }
        for path in snapshot.unresolvedPaths { record(path, "Unverified or unreadable envelope; exact bytes retained in the private snapshot and encrypted source archive") }
        for reason in snapshot.unresolved {
            let path = snapshot.unresolvedPaths.first { reason.contains($0) } ?? "source"
            record(path, reason)
        }
        let evidenceRows = try evidence.compactMap { try JSONSerialization.jsonObject(with: $0) as? [String: Any] }
        for reason in migration?.unresolved ?? [] {
            let operation = snapshot.operations.first { namespace, entries in
                entries.contains { reason.hasPrefix(namespace + "/" + $0.id + ":") }
            }?.value.first { reason.contains("/" + $0.id + ":") }
            guard let operation else { record("source", reason); continue }
            let row = evidenceRows.first { $0["operationID"] as? String == operation.id && $0["signedBodyDigest"] as? String == operation.signedBodyDigest }
            var details: [String] = []
            for case let domain as [String: Any] in row?["domainEvidence"] as? [Any] ?? [] {
                details += domain["reasons"] as? [String] ?? []
                if let reason = domain["reason"] as? String, !reason.isEmpty { details.append(reason) }
                if let manifest = domain["manifest"] as? [String: Any] {
                    details += manifest["issues"] as? [String] ?? []
                    if let reason = manifest["reason"] as? String, !reason.isEmpty { details.append(reason) }
                }
                if let disposition = domain["disposition"] as? [String: Any] { details += disposition["diagnostics"] as? [String] ?? [] }
            }
            record(operation.sourcePath, details.isEmpty ? reason : details.joined(separator: "; "))
        }
        for (namespace, operations) in snapshot.operations {
            for (index, operation) in operations.enumerated() {
                if operation.admission == .held { record(operation.sourcePath, operation.admissionDetail) }
                let evaluation = try snapshot.evaluate(namespace: namespace, index: index, bindings: .init(heads: [:], revisions: [:]))
                if evaluation.outcome == "unresolved" { record(operation.sourcePath, "Reference domain codec cannot project this historical effect") }
            }
        }
        let copied = blobs?.copiedPaths ?? Set(copiedBlobPaths)
        for entry in blobs?.unresolved ?? [] { record(entry.path, entry.reason) }
        for path in snapshot.records.keys.sorted() where path.hasPrefix("blobs/") && !copied.contains(path) && !unresolved.contains(where: { $0.path == path }) {
            record(path, "Blob was not copied; see import failure")
        }
        for entry in verification?.unresolved ?? [] { record(entry.path, entry.reason) }
        let digests = verification?.views ?? Dictionary(uniqueKeysWithValues: snapshot.namespaces.sorted().map {
            ($0, ViewDigests(reference: nil, destination: nil, normalizedFields: ViewNormalization.printedFields(namespace: $0),
                             reason: failure ?? "Import verification did not run"))
        })
        let operations = snapshot.operations.values.flatMap { $0 }
        return CleanCopyReport(sourceLibraryID: snapshot.libraryID, newLibraryID: destinationID,
            countsPerNamespace: snapshot.operations.mapValues(\.count),
            countsPerAuthor: Dictionary(grouping: operations, by: \.authorID).mapValues(\.count),
            viewDigests: digests, accounting: verification?.accounting ?? [:], copiedBlobPaths: copied.sorted(), unresolved: unresolved.sorted { ($0.path, $0.reason) < ($1.path, $1.reason) },
            sourceUnchanged: unchanged, remainingOperations: migration?.remainingOperations ?? remaining ?? operations.count,
            failure: failure, nextSteps: ["Review source accounting, view equality and unresolved records before switching apps.",
                "Add a passkey from a signed app after the copy; this command does not register passkeys.",
                "Revoke Clean copy (Mac) in the old library using a controller, then remove the private workspace when no longer needed."])
    }
    func saveReport(_ report: CleanCopyReport) throws {
        try writePrivate(try encode(report), to: directory.appendingPathComponent("report.json"))
        var text = "# Clean copy\n\nSource: \(report.sourceLibraryID)\n\nNew library: \(report.newLibraryID ?? "not created")\n\nVerified: \(report.verified)\n\nSource unchanged: \(report.sourceUnchanged)\n\nRemaining operations: \(report.remainingOperations)\n"
        text += "\n## Counts per namespace\n\n"
        for (namespace, count) in report.countsPerNamespace.sorted(by: { $0.key < $1.key }) { text += "- \(namespace): \(count)\n" }
        text += "\n## Counts per author\n\n"
        for (author, count) in report.countsPerAuthor.sorted(by: { $0.key < $1.key }) { text += "- \(author): \(count)\n" }
        text += "\n## View digests\n\n"
        for (namespace, value) in report.viewDigests.sorted(by: { $0.key < $1.key }) {
            text += "- \(namespace): equality \(value.equal), reference \(value.reference ?? "unavailable"), persisted 0.4 \(value.destination ?? "unavailable"). \(value.reason ?? "")\n"
        }
        text += "\n## Accounting and normalization\n\n"
        for namespace in report.viewDigests.keys.sorted() {
            if let check = report.accounting[namespace] {
                text += "- \(namespace): accounting \(check.passed), expected \(check.expected), imported \(check.imported), unresolved \(check.unresolved)\n"
                for (author, counts) in check.authors.sorted(by: { $0.key < $1.key }) {
                    text += "  - Author \(author): expected \(counts.expected), imported \(counts.imported), unresolved \(counts.unresolved), passed \(counts.passed)\n"
                }
                for failure in check.failures { text += "  - Failure: \(failure)\n" }
            }
            text += "\nRemoved destination-derived fields for \(namespace) (all other fields compared):\n\n"
            for path in report.viewDigests[namespace]?.normalizedFields ?? [] { text += "- `\(path)`\n" }
        }
        text += "\nCopied blobs: \(report.copiedBlobPaths.count)\n"
        text += "\n## Unresolved records\n\n"
        for entry in report.unresolved { text += "- \(entry.path): \(entry.reason)\n" }
        if let failure = report.failure { text += "\nImport failure: \(failure)\n" }
        text += "\n## Next steps\n\n" + report.nextSteps.map { "- " + $0 }.joined(separator: "\n") + "\n"
        try writePrivate(Data(text.utf8), to: directory.appendingPathComponent("report.md"))
    }
}
