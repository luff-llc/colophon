import Foundation
import CryptoKit
import Darwin
import ColophonSession

/// One root-owned upgrade, with a separate 0.2 session configured as migrationWriter.
/// Persist the evidence key independently. Sessions gated by this scope share markerURL.
/// Use a separate journal and marker for each independently migrated namespace scope.
public actor LibraryMigration {
    private let source: any LegacyLibrarySource
    private let namespaces: [String]
    private let expectedDestinationID: String?
    private let destination: ColophonSession
    private let files: MigrationFiles
    private let markerURL: URL
    private var running = false
    // Deterministic crash injection after publication and before checkpointing, for fixture tests.
    var afterPublication: (@Sendable () throws -> Void)?

    public init(source: any LegacyLibrarySource, namespaces: Set<String>,
                destination: ColophonSession, destinationLibraryID: String? = nil,
                privateContainer: URL, evidenceKey: SymmetricKey, markerURL: URL) {
        self.source = source; self.namespaces = namespaces.sorted(); self.destination = destination
        expectedDestinationID = destinationLibraryID
        files = MigrationFiles(directory: privateContainer, key: evidenceKey); self.markerURL = markerURL
    }
    func setAfterPublication(_ hook: (@Sendable () throws -> Void)?) { afterPublication = hook }

    /// Imports at most batchSize source records, checkpointing every complete source unit.
    /// Call again until remainingOperations == 0; later calls perform a verified catch-up pass.
    public func run(batchSize: Int = 64) async throws -> MigrationReport {
        guard !running else { throw MigrationError.busy }
        guard !namespaces.isEmpty, Set(namespaces).isSubset(of: ["reading.books", "reading.saved", "listening.podcasts", "notes"]),
              (1...1024).contains(batchSize) else { throw SessionError.invalidCommand }
        running = true; defer { running = false }
        try FileManager.default.createDirectory(at: files.directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let lock = open(files.directory.appendingPathComponent("migration.lock").path, O_CREAT | O_RDWR, 0o600)
        guard lock >= 0 else { throw MigrationError.busy }
        defer { close(lock) }
        guard flock(lock, LOCK_EX | LOCK_NB) == 0 else { throw MigrationError.busy }
        defer { flock(lock, LOCK_UN) }
        try Task.checkCancellation()
        let snapshot = try source.snapshot(namespaces: Set(namespaces))
        let operations = snapshot.operations
        guard snapshot.namespaces == Set(namespaces), Set(operations.keys) == Set(namespaces),
              !snapshot.libraryID.isEmpty, !snapshot.readerID.isEmpty, !snapshot.rootID.isEmpty else { throw MigrationError.invalidSource }
        for entries in operations.values {
            for entry in entries where snapshot.records[entry.sourcePath] == nil {
                throw MigrationError.sourceUnavailable(entry.sourcePath)
            }
        }
        let previous = try files.load()
        var progress = previous ?? MigrationProgress(sourceLibraryID: snapshot.libraryID, namespaces: namespaces)
        guard progress.sourceLibraryID == snapshot.libraryID, progress.namespaces == namespaces else { throw MigrationError.invalidSource }
        // Every old immutable record must still be present and byte-identical. Requests can change.
        for (path, digest) in progress.sourceRecords where !path.hasPrefix("requests/") {
            guard snapshot.records[path].map(migrationDigest) == digest else { throw MigrationError.sourceUnavailable(path) }
        }
        try MigrationMarker(sourceLibraryID: progress.sourceLibraryID, active: true).save(at: markerURL)
        for (path, bytes) in snapshot.records {
            let digest = migrationDigest(bytes)
            let archive = files.directory.appendingPathComponent("source-archive/" + digest + ".aesgcm")
            if !FileManager.default.fileExists(atPath: archive.path) { try files.write(bytes, to: archive) }
            progress.sourceRecords[path] = digest
        }
        var unresolvedEvidence: [(String, Data)] = []
        for path in snapshot.unresolvedPaths {
            guard let bytes = snapshot.records[path] else { throw MigrationError.sourceUnavailable(path) }
            let digest = migrationDigest(bytes)
            let unresolved: [String: Any] = ["sourceLibrary": progress.sourceLibraryID, "sourcePath": path,
                "envelopeDigest": digest, "digestAlgorithm": "SHA-256", "digestPurpose": "exact source envelope bytes (not an authenticated signed-body digest)",
                "admission": "unresolved", "domainOutcome": "unresolved", "outputOperationIDs": [String: String](),
                "reason": "Refused, unreadable, invalid, or unsupported namespace; exact envelope retained in encrypted source archive"]
            let key = "unresolved-" + migrationDigest(Data(tuple(progress.sourceLibraryID, namespaces[0], path, digest).utf8))
            unresolvedEvidence.append((key, try json(unresolved)))
            let issue = "Unresolved source envelope: " + path
            if !progress.unresolved.contains(issue) { progress.unresolved.append(issue) }
        }
        progress.membersNeedingRejoin = snapshot.members.sorted { $0.id < $1.id }.map { "\($0.label) (\($0.id)) — needs to rejoin" }
        for issue in snapshot.unresolved where !progress.unresolved.contains(issue) { progress.unresolved.append(issue) }
        await destination.refresh()
        if previous == nil, await destination.phase != .noLibrary {
            guard let expectedDestinationID, await destination.libraryID == expectedDestinationID else { throw MigrationError.destinationChanged }
        }
        if let expectedDestinationID, await destination.libraryID != expectedDestinationID { throw MigrationError.destinationChanged }
        progress.sourceChangeToken = snapshot.changeToken
        try files.save(progress)
        if await destination.phase == .noLibrary { await destination.create() }
        guard await destination.phase == .ready, let destinationID = await destination.libraryID else { throw MigrationError.destinationUnavailable }
        guard progress.destinationLibraryID == nil || progress.destinationLibraryID == destinationID else { throw MigrationError.destinationChanged }
        progress.destinationLibraryID = destinationID
        try files.save(progress)
        // Unreadable envelopes have no trusted namespace. Publish only evidence in a selected
        // namespace; a books-only writer never needs an unrelated saved-reading grant.
        for (key, bytes) in unresolvedEvidence {
            let body: [String: Any] = ["key": key, "evidence": try JSONSerialization.jsonObject(with: bytes), "children": []]
            let command = try DomainCommand(namespace: namespaces[0], kind: "colophon.importBatch", payloadJSON: json(body))
            guard case .saved = try await destination.performMigration(command, outputKey: key) else { throw MigrationError.destinationUnavailable }
        }
        // Re-evaluate complete admission/order, including held -> admitted transitions. Earlier
        // insertions need an engine historical overlay; do not rewrite already signed history.
        for namespace in namespaces {
            let current = (operations[namespace] ?? []).map(\.fingerprint)
            let prior = progress.prefixes[namespace] ?? []
            let entries = operations[namespace] ?? []
            if Array(current.prefix(prior.count)) != prior {
                let reason = "\(namespace): source admission/order changed before the imported tail; historical reconciliation required"
                if !progress.unresolved.contains(reason) { progress.unresolved.append(reason) }
                var before: [String: Any] = [:], after: [String: Any] = [:]
                for (key, bytes) in progress.sourceOutcomes?[namespace] ?? [:] {
                    before[key] = try JSONSerialization.jsonObject(with: bytes)
                }
                for (index, entry) in entries.enumerated() {
                    let evaluated = try snapshot.evaluate(namespace: namespace, index: index, bindings: .init(heads: progress.heads, revisions: progress.revisions))
                    after[entry.key] = try sourceOutcome(entry, index: index, evaluated: evaluated)
                }
                let changes = try reconcileImportPrefix(previous: json(before), current: json(after), importedHeads: json(progress.heads))
                let rows = try JSONSerialization.jsonObject(with: changes) as? [Any] ?? []
                let key = "reconcile-" + migrationDigest(try json([progress.sourceLibraryID, namespace, migrationDigest(changes)]))
                // Each bounded reconciliation record is independently visible evidence, never effects.
                for offset in stride(from: 0, to: max(1, rows.count), by: 100) {
                    let unit = key + "/" + String(offset)
                    let body: [String: Any] = ["key": unit, "children": [], "alternatives": Array(rows.dropFirst(offset).prefix(100)),
                        "evidence": ["sourceLibrary": progress.sourceLibraryID, "namespace": namespace, "reason": reason,
                            "previousPrefixDigest": migrationDigest(try json(prior)), "currentPrefixDigest": migrationDigest(try json(current))]]
                    let command = try DomainCommand(namespace: namespace, kind: "colophon.importBatch", payloadJSON: json(body))
                    guard case .saved = try await destination.performMigration(command, outputKey: unit) else { throw MigrationError.destinationUnavailable }
                }
                try files.save(progress)
                throw MigrationError.reconciliationRequired(reason)
            }
        }
        var processed = 0
        for namespace in namespaces {
            let entries = operations[namespace] ?? []
            var index = progress.prefixes[namespace]?.count ?? 0
            while index < entries.count && processed < batchSize {
                try Task.checkCancellation()
                let entry = entries[index], operation = entry
                let evaluated = try snapshot.evaluate(namespace: namespace, index: index, bindings: .init(heads: progress.heads, revisions: progress.revisions))
                let input = LegacyImportOperation(sourceLibrary: progress.sourceLibraryID, authorId: entry.authorID, authorLabel: entry.authorLabel,
                    operationId: operation.id, signedBodyDigest: entry.signedBodyDigest, kind: operation.kind, version: operation.version,
                    payloadJson: entry.payloadJSON, admittedOrder: UInt64(index), claimedDateJson: entry.claimedDateJSON,
                    admission: entry.admission == .admitted ? "admitted" : "held", outcome: evaluated.outcome, contextJson: evaluated.contextJSON)
                let plan = try importLegacyBatch(namespace: namespace, operations: [input], stateJson: progress.states[namespace] ?? Data("{}".utf8))
                let blobValues = try JSONSerialization.jsonObject(with: plan.blobsJson) as? [Any] ?? []
                // Persist encrypted chunks before publishing the one-record source unit. Reuse
                // the staged manifest across crashes so the permanent receipt remains identical.
                let manifestURL = files.directory.appendingPathComponent("blob-manifests/" + entry.key + ".aesgcm")
                var manifests: [Any] = []
                if !blobValues.isEmpty {
                    if FileManager.default.fileExists(atPath: manifestURL.path) {
                        manifests = try JSONSerialization.jsonObject(with: files.open(manifestURL)) as? [Any] ?? []
                    } else {
                        for case let blob as [String: Any] in blobValues {
                            guard let text = blob["utf8"] as? String, let descriptor = blob["descriptor"] as? [String: Any],
                                  let mediaType = descriptor["mediaType"] as? String else { throw MigrationError.invalidSource }
                            let manifest = try await destination.migrationBlob(namespace: namespace, mediaType: mediaType, bytes: Data(text.utf8))
                            let decoded = try JSONSerialization.jsonObject(with: manifest) as? [String: Any] ?? [:]
                            guard let actual = decoded["descriptor"] as? [String: Any],
                                  NSDictionary(dictionary: actual).isEqual(to: descriptor) else { throw MigrationError.invalidSource }
                            manifests.append(decoded)
                        }
                        try files.write(json(manifests), to: manifestURL)
                    }
                }
                let batchKey = tuple(progress.sourceLibraryID, namespace, entry.key, "transform-1")
                var childIDs: [String] = [], outputIDs: [String: String] = [:], children: [[String: Any]] = []
                var bindings: [(LegacyImportCommand, Data, String)] = []
                var identities: [String: [String: String]] = [:]
                for command in plan.commands {
                    var payload = try JSONSerialization.jsonObject(with: command.payloadJson) as? [String: Any] ?? [:]
                    for control in ["expect", "expectActivity", "expectedPosition", "expectedState"] {
                        if let key = payload[control] as? String, let id = outputIDs[key] ?? progress.outputs[key] { payload[control] = id }
                    }
                    if let resolves = payload["resolves"] as? [String] { payload["resolves"] = resolves.map { outputIDs[$0] ?? progress.outputs[$0] ?? $0 } }
                    if let child = command.expectFromChild {
                        guard child < childIDs.count else { throw MigrationError.invalidSource }
                        payload[command.kind == "delete" ? "expectActivity" : "expect"] = childIDs[Int(child)]
                    }
                    if let id = payload["id"] as? String, migrationCreatesIdentity(namespace, command.kind, payload) {
                        let category = importIdentityCategory(namespace: namespace, kind: command.kind)
                        let key = tuple(progress.sourceLibraryID, namespace, category, id, entry.signedBodyDigest)
                        let reserved = try await destination.query(namespace: namespace, name: "importIdentity", arguments: json(["key": key, "preferred": id, "category": category]))
                        let status = try JSONSerialization.jsonObject(with: reserved) as? [String: Any] ?? [:]
                        if status["occupied"] as? Bool == true && status["reserved"] as? String != id {
                            let reason = "\(namespace)/\(operation.id): native identity collision requires occurrence remapping"
                            if !progress.unresolved.contains(reason) { progress.unresolved.append(reason) }
                            try files.save(progress); throw MigrationError.reconciliationRequired(reason)
                        }
                        identities[key] = ["category": category, "id": id]
                    }
                    let id = try importOutputId(library: destinationID, namespace: namespace, batch: batchKey, child: command.outputKey)
                    children.append(["key": command.outputKey, "kind": command.kind, "payload": payload, "baseline": command.baseline])
                    childIDs.append(id); outputIDs[command.outputKey] = id
                    bindings.append((command, try json(payload), id))
                }
                let evidence = try JSONSerialization.jsonObject(with: plan.evidenceJson)
                var record: [String: Any] = ["sourceLibrary": progress.sourceLibraryID, "namespace": namespace, "operationID": operation.id,
                    "authorID": entry.authorID, "authorLabel": entry.authorLabel, "signedBodyDigest": entry.signedBodyDigest,
                    "digestAlgorithm": "SHA-256", "digestPurpose": "exact authenticated signed operation body", "transformVersion": 1,
                    "admittedOrder": index, "claimedDate": try JSONSerialization.jsonObject(with: entry.claimedDateJSON, options: .fragmentsAllowed), "claimedDateCodec": "Colophon 0.1 Canonical/ISO8601",
                    "admission": input.admission, "admissionDetail": entry.admissionDetail, "sourceOutcome": evaluated.outcome, "domainEvidence": evidence, "outputOperationIDs": outputIDs]
                let firstOutput = children.first?["payload"] as? [String: Any]
                let originalPayload = try JSONSerialization.jsonObject(with: operation.payloadJSON) as? [String: Any] ?? [:]
                record["object"] = firstOutput?["id"] as? String ?? ["cell", "note", "entry", "book", "item", "episode", "show", "notebook"].compactMap { originalPayload[$0] as? String }.first
                let alternatives: [Any] = ["conflict", "lateEdit"].contains(evaluated.outcome) ? [record] : historicalCandidates(evidence)
                let body: [String: Any] = ["key": batchKey, "evidence": record, "children": children, "alternatives": alternatives, "identities": identities, "blobs": manifests]
                let clean = try DomainCommand(namespace: namespace, kind: "colophon.importBatch", payloadJSON: json(body))
                guard case .saved = try await destination.performMigration(clean, outputKey: batchKey) else { throw MigrationError.destinationUnavailable }
                let receiptBytes = try await destination.query(namespace: namespace, name: "importReceipt", arguments: json(["key": batchKey]))
                guard let receipt = try JSONSerialization.jsonObject(with: receiptBytes, options: .fragmentsAllowed) as? [String: Any],
                      receipt["outputOperationIDs"] as? [String: String] == outputIDs else {
                    throw MigrationError.reconciliationRequired("\(namespace): source unit was not accepted after refreshed admission")
                }
                try afterPublication?()
                for (command, payloadBytes, id) in bindings {
                    let payload = try JSONSerialization.jsonObject(with: payloadBytes) as? [String: Any] ?? [:]
                    ImportBindings.bind(namespace: namespace, source: entry, command: command, payload: payload, operationID: id, progress: &progress)
                }
                if evaluated.outcome == "unresolved" || evidenceHasGap(evidence) || entry.admission != .admitted {
                    let issue = "\(namespace)/\(operation.id): retained import evidence requires review"
                    if !progress.unresolved.contains(issue) { progress.unresolved.append(issue) }
                }
                if progress.sourceOutcomes == nil { progress.sourceOutcomes = [:] }
                progress.sourceOutcomes?[namespace, default: [:]][entry.key] = try json(sourceOutcome(entry, index: index, evaluated: evaluated))
                progress.outputs.merge(outputIDs) { _, new in new }
                progress.states[namespace] = try bindLegacyImportState(namespace: namespace, stateJson: plan.stateJson, outputs: outputIDs)
                progress.prefixes[namespace, default: []].append(entry.fingerprint)
                progress.lastImportedOperation[namespace] = operation.id
                try files.save(progress)
                index += 1; processed += 1
            }
        }
        let remaining = namespaces.reduce(0) { $0 + (operations[$1]?.count ?? 0) - (progress.prefixes[$1]?.count ?? 0) }
        if remaining == 0 && progress.unresolved.isEmpty { try MigrationMarker(sourceLibraryID: progress.sourceLibraryID, active: false).save(at: markerURL) }
        return MigrationReport(sourceLibraryID: progress.sourceLibraryID, destinationLibraryID: destinationID,
            importedOperations: progress.prefixes.values.reduce(0) { $0 + $1.count }, remainingOperations: remaining,
            unresolved: progress.unresolved, membersNeedingRejoin: progress.membersNeedingRejoin)
    }
    /// Grant-checked synchronized evidence. Pagination is bounded in the engine; callers that
    /// render pages should use ColophonSession.query(importEvidence) directly.
    public func evidence() async throws -> [Data] {
        var records: [Data] = []
        for namespace in namespaces {
            var cursor: Any? = nil
            repeat {
                var args: [String: Any] = ["limit": 100]
                if let cursor { args["cursor"] = cursor }
                let page = try await destination.query(namespace: namespace, name: "importEvidence", arguments: json(args))
                guard let envelope = try JSONSerialization.jsonObject(with: page) as? [String: Any],
                      let value = envelope["value"] as? [String: Any], let rows = value["rows"] as? [[String: Any]] else { throw MigrationError.invalidSource }
                for row in rows {
                    var evidence = row["evidence"] as? [String: Any] ?? [:]
                    evidence["outputOperationIDs"] = row["outputOperationIDs"]
                    evidence["publication"] = row["publication"]
                    records.append(try json(evidence))
                }
                cursor = value["next"] is NSNull ? nil : value["next"]
            } while cursor != nil
        }
        return records
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

private func migrationCreatesIdentity(_ namespace: String, _ kind: String, _ payload: [String: Any]) -> Bool {
    switch (namespace, kind) {
    case ("reading.books", "addBook"), ("reading.books", "addNote"), ("reading.saved", "capture"),
         ("notes", "createNotebook"), ("notes", "addNote"), ("listening.podcasts", "addNote"): return true
    case ("notes", "putCell"), ("notes", "putEntry"), ("listening.podcasts", "follow"): return payload["expect"] is NSNull
    default: return false
    }
}
private func historicalCandidates(_ value: Any) -> [Any] {
    if let rows = value as? [Any] { return rows.flatMap(historicalCandidates) }
    guard let row = value as? [String: Any] else { return [] }
    if let disposition = row["disposition"] as? String, ["historicalAlternative", "lateEdit"].contains(disposition) { return [row] }
    return []
}

private func sourceOutcome(_ entry: LegacyOperation, index: Int, evaluated: LegacyEvaluation) throws -> [String: Any] {
    let context = try JSONSerialization.jsonObject(with: evaluated.contextJSON) as? [String: Any] ?? [:]
    return ["key": entry.key, "authorID": entry.authorID, "authorLabel": entry.authorLabel,
     "operationID": entry.id, "signedBodyDigest": entry.signedBodyDigest, "admittedOrder": index,
     "admission": entry.admission == .admitted ? "admitted" : "held", "outcome": evaluated.outcome,
     "payload": try JSONSerialization.jsonObject(with: entry.payloadJSON),
     "effectivePayload": context["effective_payload"] ?? context["effectivePayload"] ?? NSNull()]
}
