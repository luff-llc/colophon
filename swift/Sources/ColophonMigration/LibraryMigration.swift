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
        var unresolvedEvidence: [(String, Data)] = []
        for path in snapshot.unresolvedPaths {
            guard let bytes = snapshot.records[path] else { throw MigrationError.sourceUnavailable(path) }
            let digest = Canonical.digest(bytes)
            let unresolved: [String: Any] = ["sourceLibrary": progress.sourceLibraryID, "sourcePath": path,
                "envelopeDigest": digest, "digestAlgorithm": "SHA-256", "digestPurpose": "exact source envelope bytes (not an authenticated signed-body digest)",
                "admission": "unresolved", "domainOutcome": "unresolved", "outputOperationIDs": [String: String](),
                "reason": "Refused, unreadable, invalid, or unsupported namespace; exact envelope retained in encrypted source archive"]
            unresolvedEvidence.append(("unresolved-" + Canonical.digest(Data((path + digest).utf8)), try json(unresolved)))
        }
        progress.membersNeedingRejoin = snapshot.authority.members.values.sorted { $0.id < $1.id }.map { "\($0.label) (\($0.id)) — needs to rejoin" }
        for issue in snapshot.unresolved where !progress.unresolved.contains(issue) { progress.unresolved.append(issue) }
        await destination.refresh()
        if previous == nil, await destination.phase != .noLibrary { throw MigrationError.destinationChanged }
        try files.save(progress)
        if await destination.phase == .noLibrary { await destination.create() }
        guard await destination.phase == .ready, let destinationID = await destination.libraryID else { throw MigrationError.destinationUnavailable }
        guard progress.destinationLibraryID == nil || progress.destinationLibraryID == destinationID else { throw MigrationError.destinationChanged }
        progress.destinationLibraryID = destinationID
        try files.save(progress)
        // Unreadable source envelopes have no trusted namespace. Retain their explicit archive
        // dispositions under the root's saved-reading grant; they never produce domain effects.
        for (key, bytes) in unresolvedEvidence {
            let body: [String: Any] = ["key": key, "evidence": try JSONSerialization.jsonObject(with: bytes), "children": []]
            let command = try DomainCommand(namespace: "reading.saved", kind: "colophon.importBatch", payloadJSON: json(body))
            guard case .saved = try await destination.performMigration(command, outputKey: key) else { throw MigrationError.destinationUnavailable }
        }
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
                var before: [String: Any] = [:], after: [String: Any] = [:]
                for (key, bytes) in progress.sourceOutcomes?[namespace] ?? [:] {
                    before[key] = try JSONSerialization.jsonObject(with: bytes)
                }
                for (index, entry) in entries.enumerated() {
                    let evaluated = try SourceEvaluation.evaluate(namespace: namespace, entries: entries, index: index, library: progress.sourceLibraryID, progress: progress)
                    after[entry.key] = try sourceOutcome(entry, index: index, evaluated: evaluated)
                }
                let changes = try reconcileImportPrefix(previous: json(before), current: json(after), importedHeads: json(progress.heads))
                let rows = try JSONSerialization.jsonObject(with: changes) as? [Any] ?? []
                let key = "reconcile-" + Canonical.digest(changes)
                // Each bounded reconciliation record is independently visible evidence, never effects.
                for offset in stride(from: 0, to: max(1, rows.count), by: 100) {
                    let unit = key + "/" + String(offset)
                    let body: [String: Any] = ["key": unit, "children": [], "alternatives": Array(rows.dropFirst(offset).prefix(100)),
                        "evidence": ["sourceLibrary": progress.sourceLibraryID, "namespace": namespace, "reason": reason,
                            "previousPrefixDigest": Canonical.digest(try json(prior)), "currentPrefixDigest": Canonical.digest(try json(current))]]
                    let command = try DomainCommand(namespace: namespace, kind: "colophon.importBatch", payloadJSON: json(body))
                    guard case .saved = try await destination.performMigration(command, outputKey: unit) else { throw MigrationError.destinationUnavailable }
                }
                try files.save(progress)
                throw MigrationError.reconciliationRequired(reason)
            }
        }
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
                        let key = tuple(progress.sourceLibraryID, namespace, category, id, entry.digest)
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
                    "authorID": entry.admitted.author, "authorLabel": entry.admitted.authorLabel, "signedBodyDigest": entry.digest,
                    "digestAlgorithm": "SHA-256", "digestPurpose": "exact authenticated signed operation body", "transformVersion": 1,
                    "admittedOrder": index, "claimedDate": try JSONSerialization.jsonObject(with: entry.claimedDateJSON, options: .fragmentsAllowed), "claimedDateCodec": "Colophon 0.1 Canonical/ISO8601",
                    "admission": input.admission, "admissionDetail": String(describing: entry.admitted.status), "sourceOutcome": evaluated.outcome, "domainEvidence": evidence, "outputOperationIDs": outputIDs]
                let firstOutput = children.first?["payload"] as? [String: Any]
                record["object"] = firstOutput?["id"] as? String ?? ["cell", "note", "entry", "book", "item", "episode", "show", "notebook"].compactMap { operation.payload[$0]?.string }.first
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
                    SourceEvaluation.bind(namespace: namespace, source: entry, command: command, payload: payload, operationID: id, progress: &progress)
                }
                if evaluated.outcome == "unresolved" || evidenceHasGap(evidence) || entry.admitted.status != .admitted {
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
        let remaining = SourceReader.namespaces.reduce(0) { $0 + (snapshot.operations[$1]?.count ?? 0) - (progress.prefixes[$1]?.count ?? 0) }
        if remaining == 0 && progress.unresolved.isEmpty { try MigrationMarker(sourceLibraryID: progress.sourceLibraryID, active: false).save(at: markerURL) }
        return MigrationReport(sourceLibraryID: progress.sourceLibraryID, destinationLibraryID: destinationID,
            importedOperations: progress.prefixes.values.reduce(0) { $0 + $1.count }, remainingOperations: remaining,
            unresolved: progress.unresolved, membersNeedingRejoin: progress.membersNeedingRejoin)
    }
    /// Grant-checked synchronized evidence. Pagination is bounded in the engine; callers that
    /// render pages should use ColophonSession.query(importEvidence) directly.
    public func evidence() async throws -> [Data] {
        var records: [Data] = []
        for namespace in SourceReader.namespaces {
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

private func sourceOutcome(_ entry: SourceEntry, index: Int, evaluated: SourceEvaluation) throws -> [String: Any] {
    ["key": entry.key, "authorID": entry.admitted.author, "authorLabel": entry.admitted.authorLabel,
     "operationID": entry.admitted.id, "signedBodyDigest": entry.digest, "admittedOrder": index,
     "admission": entry.admitted.status == .admitted ? "admitted" : "held", "outcome": evaluated.outcome,
     "payload": try JSONSerialization.jsonObject(with: entry.payloadJSON),
     "effectivePayload": evaluated.context["effective_payload"] ?? evaluated.context["effectivePayload"] ?? NSNull()]
}
