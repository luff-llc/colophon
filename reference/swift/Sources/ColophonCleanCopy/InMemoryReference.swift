import ColophonKit
import ColophonMigration
import CryptoKit
import Foundation

struct ReferenceProgress {
    var states: [String: Data] = [:]
    var heads: [String: String] = [:]
    var revisions: [String: String] = [:]
    var outputs: [String: String] = [:]
}
struct ReferenceUnit: Sendable {
    let operation: LegacyOperation
    let batchKey: String
    let outputKeys: [String]
    let reason: String
}
struct ReferenceReplay: Sendable {
    let library: Library
    let units: [String: [ReferenceUnit]]
}

/// This replay intentionally has no session, FileManager, journal, storage, retries, or blob
/// writer. The same public domain transforms and binding rules run against fresh core state.
@MainActor
enum InMemoryReference {
    static func replay(_ snapshot: any LegacyLibrarySnapshot) async throws -> ReferenceReplay {
        let destination = try await create(namespaces: snapshot.namespaces.sorted())
        let destinationID = try await destination.id
        var progress = ReferenceProgress()
        var units: [String: [ReferenceUnit]] = [:]
        for namespace in snapshot.namespaces.sorted() {
            let entries = snapshot.operations[namespace] ?? []
            units[namespace] = []
            for (index, _) in entries.enumerated() {
                let entry = entries[index], operation = entry
                let evaluated = try snapshot.evaluate(namespace: namespace, index: index, bindings: .init(heads: progress.heads, revisions: progress.revisions))
                let input = LegacyImportOperation(sourceLibrary: snapshot.libraryID, authorId: entry.authorID, authorLabel: entry.authorLabel,
                    operationId: operation.id, signedBodyDigest: entry.signedBodyDigest, kind: operation.kind, version: operation.version,
                    payloadJson: entry.payloadJSON, admittedOrder: UInt64(index), claimedDateJson: entry.claimedDateJSON,
                    admission: entry.admission == .admitted ? "admitted" : "held", outcome: evaluated.outcome, contextJson: evaluated.contextJSON)
                let plan = try importLegacyBatch(namespace: namespace, operations: [input], stateJson: progress.states[namespace] ?? Data("{}".utf8))
                let batchKey = try tuple(snapshot.libraryID, namespace, sourceUnitKey(entry), "transform-1")
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
                        let key = try tuple(snapshot.libraryID, namespace, category, id, entry.signedBodyDigest)
                        let reserved = try await destination.query(namespace: namespace, name: "importIdentity", arguments: json(["key": key, "preferred": id, "category": category])).get()
                        let status = try JSONSerialization.jsonObject(with: reserved) as? [String: Any] ?? [:]
                        if status["occupied"] as? Bool == true && status["reserved"] as? String != id {
                            let reason = "\(namespace)/\(operation.id): native identity collision requires occurrence remapping"
                            throw MigrationError.reconciliationRequired(reason)
                        }
                        identities[key] = ["category": category, "id": id]
                    }
                    let id = try importOutputId(library: destinationID, namespace: namespace, batch: batchKey, child: command.outputKey)
                    children.append(["key": command.outputKey, "kind": command.kind, "payload": payload, "baseline": command.baseline])
                    childIDs.append(id); outputIDs[command.outputKey] = id
                    bindings.append((command, try json(payload), id))
                }
                let evidence = try JSONSerialization.jsonObject(with: plan.evidenceJson)
                var record: [String: Any] = ["sourceLibrary": snapshot.libraryID, "namespace": namespace, "operationID": operation.id,
                    "authorID": entry.authorID, "authorLabel": entry.authorLabel, "signedBodyDigest": entry.signedBodyDigest,
                    "digestAlgorithm": "SHA-256", "digestPurpose": "exact authenticated signed operation body", "transformVersion": 1,
                    "admittedOrder": index, "claimedDate": try JSONSerialization.jsonObject(with: entry.claimedDateJSON, options: .fragmentsAllowed), "claimedDateCodec": "Colophon 0.1 Canonical/ISO8601",
                    "admission": input.admission, "admissionDetail": entry.admissionDetail, "sourceOutcome": evaluated.outcome, "domainEvidence": evidence, "outputOperationIDs": outputIDs]
                let firstOutput = children.first?["payload"] as? [String: Any]
                let originalPayload = try JSONSerialization.jsonObject(with: operation.payloadJSON) as? [String: Any] ?? [:]
                record["object"] = firstOutput?["id"] as? String ?? ["cell", "note", "entry", "book", "item", "episode", "show", "notebook"].compactMap { originalPayload[$0] as? String }.first
                let alternatives: [Any] = ["conflict", "lateEdit"].contains(evaluated.outcome) ? [record] : historicalCandidates(evidence)
                let body: [String: Any] = ["key": batchKey, "evidence": record, "children": children, "alternatives": alternatives, "identities": identities, "blobs": [Any]()]
                _ = try await destination.write(namespace: namespace, kind: "colophon.importBatch", payload: json(body)).get()
                let receiptBytes = try await destination.query(namespace: namespace, name: "importReceipt", arguments: json(["key": batchKey])).get()
                guard let receipt = try JSONSerialization.jsonObject(with: receiptBytes, options: .fragmentsAllowed) as? [String: Any],
                      receipt["outputOperationIDs"] as? [String: String] == outputIDs else {
                    throw MigrationError.reconciliationRequired("\(namespace): source unit was not accepted after refreshed admission")
                }
                for (command, payloadBytes, id) in bindings {
                    let payload = try JSONSerialization.jsonObject(with: payloadBytes) as? [String: Any] ?? [:]
                    try ReferenceBindings.bind(namespace: namespace, source: entry, command: command, payload: payload, operationID: id, progress: &progress)
                }
                units[namespace, default: []].append(ReferenceUnit(operation: entry, batchKey: batchKey,
                    outputKeys: plan.commands.map(\.outputKey), reason: unresolvedReason(entry, evaluated: evaluated, evidence: evidence)))
                progress.outputs.merge(outputIDs) { _, new in new }
                progress.states[namespace] = try bindLegacyImportState(namespace: namespace, stateJson: plan.stateJson, outputs: outputIDs)
            }
        }
        return ReferenceReplay(library: destination, units: units)
    }

    static func create(namespaces: [String]) async throws -> Library {
        let member = SoftwareKeys(), controller = SoftwareKeys()
        let now = Date.now.ISO8601Format()
        let action = try beginCreateWith(options: CreateLibraryOptions(member: await member.publicKeys(),
            controller: await controller.publicKeys(), vaultSeed: random(), label: "Clean copy reference", ownerLabel: "Reference owner",
            namespaces: namespaces, recovery: nil, importedFrom: nil,
            importExpires: Date.now.addingTimeInterval(3600).ISO8601Format()), now: now, entropy: random())
        func signatures(_ action: HostAction) throws -> [SignatureResult] {
            try action.signingSteps().map { step in
                let provider = try step.signingKey == member.signingPublicKey() ? member : controller
                return SignatureResult(signature: try provider.sign(body: step.body), assertion: nil)
            }
        }
        let next = try action.advanceCreate(signatures: signatures(action).map(\.signature))
        return try await Library.open(records: next.finishAuthority(results: signatures(next)), me: member)
    }
    private static func random() -> Data { SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) } }
}

func sourceUnitKey(_ operation: LegacyOperation) -> String {
    digest(Data("\(operation.authorID)/\(operation.id)/\(operation.signedBodyDigest)".utf8))
}

private func unresolvedReason(_ entry: LegacyOperation, evaluated: LegacyEvaluation, evidence: Any) -> String {
    if entry.admission != .admitted { return entry.admissionDetail }
    let details = importReasons(evidence)
    return details.isEmpty ? "Source fold outcome: " + evaluated.outcome + "; transform emitted no effective child" : details.joined(separator: "; ")
}

func importReasons(_ value: Any) -> [String] {
    if let array = value as? [Any] { return array.flatMap(importReasons) }
    guard let row = value as? [String: Any] else { return [] }
    var reasons: [String] = []
    for name in ["reason", "reasons", "issues", "diagnostics"] {
        if let text = row[name] as? String, !text.isEmpty { reasons.append(text) }
        if let texts = row[name] as? [String] { reasons += texts.filter { !$0.isEmpty } }
    }
    for name in ["manifest", "disposition"] { if let nested = row[name] { reasons += importReasons(nested) } }
    return reasons
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

