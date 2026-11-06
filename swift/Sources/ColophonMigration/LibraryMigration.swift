import Foundation
import CryptoKit
import Darwin
import ColophonCore
import ColophonStore
import ColophonReplica
import ColophonSession

/// One root-owned upgrade, with a separate 0.2 session configured as migrationWriter.
/// Persist the evidence key in the host's private key store. All suite apps must use markerURL.
public actor LibraryMigration {
    private let source: any ColophonStore.RecordStore
    private let reader: any Identity
    private let root: any Identity
    private let destination: ColophonSession
    private let files: MigrationFiles
    private let markerURL: URL
    private var running = false
    // Deterministic crash injection after publication and before checkpointing, for fixture tests.
    var afterPublication: (@Sendable () throws -> Void)?

    public init(source: any ColophonStore.RecordStore, readerIdentity: any Identity, rootIdentity: any Identity,
                destination: ColophonSession, privateContainer: URL, evidenceKey: SymmetricKey, markerURL: URL) {
        self.source = source; reader = readerIdentity; root = rootIdentity; self.destination = destination
        files = MigrationFiles(directory: privateContainer, key: evidenceKey); self.markerURL = markerURL
    }
    func setAfterPublication(_ hook: (@Sendable () throws -> Void)?) { afterPublication = hook }

    /// Imports at most batchSize source records, checkpointing every complete source unit.
    /// Call again until remainingOperations == 0; later calls perform a verified catch-up pass.
    public func run(batchSize: Int = 64) async throws -> MigrationReport {
        guard !running else { throw MigrationError.busy }
        guard (1...1024).contains(batchSize) else { throw SessionError.invalidCommand }
        running = true; defer { running = false }
        try FileManager.default.createDirectory(at: files.directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let lock = open(files.directory.appendingPathComponent("migration.lock").path, O_CREAT | O_RDWR, 0o600)
        guard lock >= 0 else { throw MigrationError.busy }
        defer { close(lock) }
        guard flock(lock, LOCK_EX | LOCK_NB) == 0 else { throw MigrationError.busy }
        defer { flock(lock, LOCK_UN) }
        try Task.checkCancellation()
        let snapshot = try SourceReader.read(store: source, reader: reader, root: root)
        let previous = try files.load()
        var progress = previous ?? MigrationProgress(sourceLibraryID: snapshot.authority.libraryID)
        guard progress.sourceLibraryID == snapshot.authority.libraryID else { throw MigrationError.invalidSource }
        // Every old immutable record must still be present and byte-identical. Requests can change.
        for (path, digest) in progress.sourceRecords where !path.hasPrefix("requests/") {
            guard snapshot.records[path].map(Canonical.digest) == digest else { throw MigrationError.sourceUnavailable(path) }
        }
        try MigrationMarker(sourceLibraryID: progress.sourceLibraryID, active: true).save(at: markerURL)
        for (path, bytes) in snapshot.records {
            let digest = Canonical.digest(bytes)
            let archive = files.directory.appendingPathComponent("source-archive/" + digest + ".aesgcm")
            if !FileManager.default.fileExists(atPath: archive.path) { try files.write(bytes, to: archive) }
            progress.sourceRecords[path] = digest
        }
        for path in snapshot.unresolvedPaths {
            guard let bytes = snapshot.records[path] else { throw MigrationError.sourceUnavailable(path) }
            let digest = Canonical.digest(bytes)
            let unresolved: [String: Any] = ["sourceLibrary": progress.sourceLibraryID, "sourcePath": path,
                "envelopeDigest": digest, "digestAlgorithm": "SHA-256", "digestPurpose": "exact source envelope bytes (not an authenticated signed-body digest)",
                "admission": "unresolved", "domainOutcome": "unresolved", "outputOperationIDs": [String: String](),
                "reason": "Refused, unreadable, invalid, or unsupported namespace; exact envelope retained in encrypted source archive"]
            try files.write(json(unresolved), to: evidenceURL("unresolved-" + Canonical.digest(Data((path + digest).utf8))))
        }
        progress.membersNeedingRejoin = snapshot.authority.members.values.sorted { $0.id < $1.id }.map { "\($0.label) (\($0.id)) — needs to rejoin" }
        for issue in snapshot.unresolved where !progress.unresolved.contains(issue) { progress.unresolved.append(issue) }
        // Re-evaluate complete admission/order, including held -> admitted transitions. Earlier
        // insertions need an engine historical overlay; do not rewrite already signed history.
        for namespace in SourceReader.namespaces {
            let current = (snapshot.operations[namespace] ?? []).map(\.fingerprint)
            let prior = progress.prefixes[namespace] ?? []
            let entries = snapshot.operations[namespace] ?? []
            let duplicateIDs = Dictionary(grouping: entries, by: { $0.admitted.id }).filter { $0.value.count > 1 }.keys
            let changedReceipt = namespace == "listening.podcasts" && entries.prefix(prior.count).contains {
                duplicateIDs.contains($0.admitted.id) && ["legacy.bridge.import", "legacy.podcastState.import", "podcast.source.publish", "playback.naturalEnd.batch"].contains($0.admitted.operation.kind)
            }
            if Array(current.prefix(prior.count)) != prior || changedReceipt {
                let reason = "\(namespace): source admission/order changed before the imported tail; historical reconciliation required"
                if !progress.unresolved.contains(reason) { progress.unresolved.append(reason) }
                try files.save(progress)
                throw MigrationError.reconciliationRequired(reason)
            }
        }
        await destination.refresh()
        if previous == nil, await destination.phase != .noLibrary { throw MigrationError.destinationChanged }
        try files.save(progress)
        if await destination.phase == .noLibrary { await destination.create() }
        guard await destination.phase == .ready, let destinationID = await destination.libraryID else { throw MigrationError.destinationUnavailable }
        guard progress.destinationLibraryID == nil || progress.destinationLibraryID == destinationID else { throw MigrationError.destinationChanged }
        progress.destinationLibraryID = destinationID
        try files.save(progress)
        var processed = 0
        for namespace in SourceReader.namespaces {
            let entries = snapshot.operations[namespace] ?? []
            var index = progress.prefixes[namespace]?.count ?? 0
            while index < entries.count && processed < batchSize {
                try Task.checkCancellation()
                let entry = entries[index], operation = entry.admitted.operation
                let evaluated = try SourceEvaluation.evaluate(namespace: namespace, entries: entries, index: index, library: progress.sourceLibraryID, progress: progress)
                let input = LegacyImportOperation(sourceLibrary: progress.sourceLibraryID, authorId: entry.admitted.author, authorLabel: entry.admitted.authorLabel,
                    operationId: operation.id, signedBodyDigest: entry.digest, kind: operation.kind, version: UInt64(max(0, operation.v)),
                    payloadJson: entry.payloadJSON, admittedOrder: UInt64(index), claimedDateJson: entry.claimedDateJSON,
                    admission: entry.admitted.status == .admitted ? "admitted" : "held", outcome: evaluated.outcome, contextJson: try json(evaluated.context))
                let plan = try importLegacyBatch(namespace: namespace, operations: [input], stateJson: progress.states[namespace] ?? Data("{}".utf8))
                let blobValues = try JSONSerialization.jsonObject(with: plan.blobsJson) as? [Any] ?? []
                // Retain supplied blob bytes encrypted; they are not yet accessible through the engine.
                if !blobValues.isEmpty {
                    try files.write(plan.blobsJson, to: files.directory.appendingPathComponent("import-evidence-local/" + entry.key + "-blobs.aesgcm"))
                    progress.unresolved.append("\(namespace)/\(operation.id): blob sidecar awaiting engine blob publication")
                }
                var childIDs: [String] = [], outputIDs: [String: String] = [:]
                for command in plan.commands {
                    var payload = try JSONSerialization.jsonObject(with: command.payloadJson) as? [String: Any] ?? [:]
                    // Only control/reference placeholders are rebound; original payload/provenance stays exact.
                    for control in ["expect", "expectActivity", "expectedPosition", "expectedState"] {
                        if let key = payload[control] as? String, let id = outputIDs[key] ?? progress.outputs[key] { payload[control] = id }
                    }
                    if let resolves = payload["resolves"] as? [String] { payload["resolves"] = resolves.map { outputIDs[$0] ?? progress.outputs[$0] ?? $0 } }
                    if let child = command.expectFromChild {
                        guard child < childIDs.count else { throw MigrationError.invalidSource }
                        payload[command.kind == "delete" ? "expectActivity" : "expect"] = childIDs[Int(child)]
                    }
                    let clean = try DomainCommand(namespace: namespace, kind: command.kind, payloadJSON: json(payload))
                    let receipt: WriteReceipt
                    do { receipt = try await destination.performMigration(clean, outputKey: tuple(progress.sourceLibraryID, namespace, command.outputKey)) }
                    catch SessionError.migrationCollision {
                        let reason = "\(namespace)/\(operation.id): native identity collision requires occurrence remapping"
                        if !progress.unresolved.contains(reason) { progress.unresolved.append(reason) }
                        try files.save(progress)
                        throw MigrationError.reconciliationRequired(reason)
                    }
                    guard case .saved(let id) = receipt else { throw MigrationError.destinationUnavailable }
                    try afterPublication?()
                    childIDs.append(id); outputIDs[command.outputKey] = id
                    SourceEvaluation.bind(namespace: namespace, source: entry, command: command, payload: payload, operationID: id, progress: &progress)
                }
                let evidence = try JSONSerialization.jsonObject(with: plan.evidenceJson)
                let record: [String: Any] = ["sourceLibrary": progress.sourceLibraryID, "namespace": namespace, "operationID": operation.id,
                    "authorID": entry.admitted.author, "authorLabel": entry.admitted.authorLabel, "signedBodyDigest": entry.digest,
                    "digestAlgorithm": "SHA-256", "digestPurpose": "exact authenticated signed operation body", "transformVersion": 1,
                    "admittedOrder": index, "claimedDate": try JSONSerialization.jsonObject(with: entry.claimedDateJSON, options: .fragmentsAllowed), "claimedDateCodec": "Colophon 0.1 Canonical/ISO8601",
                    "admission": input.admission, "admissionDetail": String(describing: entry.admitted.status), "sourceOutcome": evaluated.outcome, "domainEvidence": evidence, "outputOperationIDs": outputIDs]
                try files.write(json(record), to: evidenceURL(entry.key))
                if evaluated.outcome == "unresolved" || evidenceHasGap(evidence) || entry.admitted.status != .admitted {
                    let issue = "\(namespace)/\(operation.id): retained import evidence requires review"
                    if !progress.unresolved.contains(issue) { progress.unresolved.append(issue) }
                }
                progress.outputs.merge(outputIDs) { _, new in new }
                progress.states[namespace] = try bindLegacyImportState(namespace: namespace, stateJson: plan.stateJson, outputs: outputIDs)
                progress.prefixes[namespace, default: []].append(entry.fingerprint)
                progress.lastImportedOperation[namespace] = operation.id
                try files.save(progress)
                index += 1; processed += 1
            }
        }
        let remaining = SourceReader.namespaces.reduce(0) { $0 + (snapshot.operations[$1]?.count ?? 0) - (progress.prefixes[$1]?.count ?? 0) }
        if remaining == 0 && progress.unresolved.isEmpty { try MigrationMarker(sourceLibraryID: progress.sourceLibraryID, active: false).save(at: markerURL) }
        return MigrationReport(sourceLibraryID: progress.sourceLibraryID, destinationLibraryID: destinationID,
            importedOperations: progress.prefixes.values.reduce(0) { $0 + $1.count }, remainingOperations: remaining,
            unresolved: progress.unresolved, membersNeedingRejoin: progress.membersNeedingRejoin)
    }
    private func evidenceURL(_ key: String) -> URL { files.directory.appendingPathComponent("import-evidence-local/" + key + ".aesgcm") }
    /// Local evidence fallback for an upgrade review UI. No synchronized/grant-checked engine query yet.
    public func evidence() throws -> [Data] {
        let directory = files.directory.appendingPathComponent("import-evidence-local")
        guard FileManager.default.fileExists(atPath: directory.path) else { return [] }
        return try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil).filter { !$0.lastPathComponent.contains("-blobs") }.sorted { $0.path < $1.path }.map { try files.open($0) }
    }
}
private func evidenceHasGap(_ value: Any) -> Bool {
    if let array = value as? [Any] { return array.contains(where: evidenceHasGap) }
    guard let object = value as? [String: Any] else { return false }
    if object["disposition"] as? String == "unresolved" || object["outcome"] as? String == "unresolved" { return true }
    let historicalNotes = ["Ineffective duplicate add", "Ineffective duplicate note", "Ineffective operation on missing source book",
        "Ineffective operation on missing source note", "Ignored source ISBN edit retained only in evidence",
        "Ignored intent is historical provenance only", "Stale historical plan alternative",
        "Stale historical text alternative with full source attribution", "originally rejected by source domain",
        "evidenceOnly", "unresolvedOrIneffective"]
    for key in ["reason", "reasons", "issues", "diagnostics"] {
        if let text = object[key] as? String, !text.isEmpty, !historicalNotes.contains(text) { return true }
        if let list = object[key] as? [String], list.contains(where: { !historicalNotes.contains($0) }) { return true }
    }
    return object.filter { !["source", "payload", "historical_candidate"].contains($0.key) }.values.contains(where: evidenceHasGap)
}
