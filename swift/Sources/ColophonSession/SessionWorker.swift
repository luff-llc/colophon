import Foundation
import CryptoKit
import ColophonKit
import ColophonKitStorage

/// All filesystem, FFI, projections and signing run off the main actor. The suspension-aware
/// gate serializes full operations, including signing and durable publication, across awaits.
actor SessionWorker {
    let configuration: SessionConfiguration
    private var keys: any AsyncKeyProvider
    private let core: any SessionCore
    private var store: (any RecordStore)?
    private var journal = SessionJournal()
    private var loaded = false
    private var opened = false
    private var last: CoreSnapshot?
    private var revision: UInt64 = 0
    private var namespaceRevisions: [String: UInt64] = [:]
    private var occupied = false
    private var waiters: [CheckedContinuation<Void, Never>] = []
    private let journalURL: URL

    init(configuration: SessionConfiguration, core: any SessionCore = BindingSessionCore(), store: (any RecordStore)? = nil) {
        self.configuration = configuration; self.keys = configuration.keys; self.core = core; self.store = store
        journalURL = configuration.privateContainer.appendingPathComponent("session.json")
    }
    private func enter() async {
        if occupied { await withCheckedContinuation { waiters.append($0) } } else { occupied = true }
    }
    private func exit() {
        if waiters.isEmpty { occupied = false } else { waiters.removeFirst().resume() }
    }
    private func storage() throws -> any RecordStore {
        if let store { return store }
        let resolved = try configuration.location.resolve(); store = resolved; return resolved
    }
    func changes() async throws -> AsyncStream<Void> { try await storage().changes() }
    private func loadJournal() throws {
        if !loaded { journal = try SessionJournal.load(at: journalURL); loaded = true }
    }
    func restore() async throws -> SessionSnapshot {
        await enter(); defer { exit() }
        try Task.checkCancellation()
        try loadJournal()
        if journal.left { return empty(.noLibrary) }
        return try await refreshLocked()
    }
    func refresh() async throws -> SessionSnapshot {
        await enter(); defer { exit() }
        try Task.checkCancellation()
        try loadJournal()
        if journal.left { return empty(.noLibrary) }
        return try await refreshLocked()
    }
    private func refreshLocked() async throws -> SessionSnapshot {
        if !configuration.migrationWriter, let marker = configuration.migrationMarker,
           try MigrationMarker.isActive(at: marker) { return empty(.migrating) }
        let records = try await storage().read()
        guard journal.knownPaths.isSubset(of: Set(records.keys).union(journal.pending.keys)) else {
            throw StorageError.unavailable("Previously observed library records are unavailable")
        }
        if records.isEmpty && journal.pending.isEmpty {
            guard journal.libraryID == nil else { throw StorageError.unavailable("Selected library is unavailable") }
            return empty(.noLibrary)
        }
        var combined = records
        for (path, data) in journal.pending {
            if let old = combined[path], old != data { throw StorageError.conflict(path) }
            combined[path] = data
        }
        if opened { try await core.merge(combined) }
        else { try await core.open(records: combined, keys: keys); opened = true }
        var snapshot = try await core.snapshot(namespaces: configuration.namespaces)
        guard journal.libraryID == nil || journal.libraryID == snapshot.libraryID else { throw SessionError.destinationChanged }
        journal.libraryID = snapshot.libraryID
        if !journal.pending.isEmpty { try await publish() }
        if snapshot.me.since == 0 {
            let request: AccessRequest
            if let existing = snapshot.requests.first(where: { $0.id == snapshot.me.id }) { request = existing }
            else {
                request = try await core.request(configuration: configuration, keys: keys)
                let additions = ["requests/\(request.id).json": request.record]
                try await core.merge(additions)
                try await persistDelta()
                snapshot = try await core.snapshot(namespaces: configuration.namespaces)
            }
            if let starter = configuration.starterKeys {
                do {
                    try await core.approveWithStarter(request.record, keys: starter)
                    try await persistDelta()
                    snapshot = try await core.snapshot(namespaces: configuration.namespaces)
                } catch is AccessError {
                    // A former starter has no authority after protection/handover. Pair normally.
                    try remember(snapshot)
                    return makeSnapshot(snapshot, phase: .waitingForApproval(code: request.pairingCode))
                }
            } else {
                try remember(snapshot)
                return makeSnapshot(snapshot, phase: .waitingForApproval(code: request.pairingCode))
            }
        }
        try remember(snapshot)
        let phase: SessionPhase
        if snapshot.me.revokedAt != nil { phase = .denied }
        else if snapshot.denials.values.contains(where: { [.unavailable, .notReadable].contains($0.reason) }) {
            phase = .unavailable(reason: "Namespace keys or records are not available")
        } else if !snapshot.denials.isEmpty { phase = .denied }
        else { phase = .ready }
        return makeSnapshot(snapshot, phase: phase)
    }
    private func remember(_ snapshot: CoreSnapshot) throws {
        journal.knownPaths.formUnion(snapshot.records.keys)
        try journal.save(at: journalURL)
    }
    func create() async throws -> SessionSnapshot {
        await enter(); defer { exit() }
        if !configuration.migrationWriter, let marker = configuration.migrationMarker,
           try MigrationMarker.isActive(at: marker) { return empty(.migrating) }
        guard !opened, journal.libraryID == nil, try await storage().read().isEmpty else { throw SessionError.destinationChanged }
        try await core.create(configuration: configuration); opened = true
        journal.left = false
        journal.libraryID = try await core.snapshot(namespaces: configuration.namespaces).libraryID
        try await persistDelta()
        return try await refreshLocked()
    }
    func write(_ command: DomainCommand, observed: UInt64, ingress: IngressEnvelope? = nil, migrationKey: String? = nil) async throws -> (WriteReceipt, SessionSnapshot) {
        await enter(); defer { exit() }
        try Task.checkCancellation()
        let fresh = try await refreshLocked()
        guard fresh.phase == .ready else { throw SessionRefusal(snapshot: fresh, error: .notReady) }
        if let migrationKey {
            guard configuration.migrationWriter else { throw SessionError.invalidCommand }
            let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
            let commandDigest = SHA256.hash(data: try encoder.encode(command)).map { String(format: "%02x", $0) }.joined()
            if let receipt = journal.migration?[migrationKey] {
                guard receipt.commandDigest == commandDigest else { throw SessionError.invalidCommand }
                guard receipt.uncertain != true else { throw SessionError.publicationUncertain }
                if let id = receipt.operationID {
                    guard fresh.core?.views[command.namespace]?.admitted.contains(where: { $0.id == id }) == true else { throw SessionError.publicationUncertain }
                    return (.saved(operationID: id), fresh)
                }
            }
            try checkMigrationIdentity(command, in: fresh.core?.views[command.namespace]?.state)
            if journal.migration == nil { journal.migration = [:] }
            journal.migration?[migrationKey] = .init(commandDigest: commandDigest)
        }
        guard observed == revision else { throw SessionRefusal(snapshot: fresh, error: .staleRevision) }
        guard configuration.namespaces.contains(command.namespace), configuration.access.contains(.write) else { throw SessionError.invalidCommand }
        guard command.payload.count <= 256 * 1024 else { throw SessionError.invalidCommand }
        if let ingress {
            guard let snapshot = fresh.core, ingress.libraryID == snapshot.libraryID, ingress.memberID == snapshot.me.id else { throw SessionError.destinationChanged }
            if let receipt = journal.ingress[ingress.id] {
                guard receipt.envelope == ingress else { throw SessionError.invalidCommand }
                guard receipt.uncertain != true else { throw SessionError.publicationUncertain }
                if let operationID = receipt.operationID {
                    guard fresh.core?.views[command.namespace]?.admitted.contains(where: { $0.id == operationID }) == true
                    else { throw SessionError.publicationUncertain }
                    return (.saved(operationID: operationID), fresh)
                }
                // An interrupted signing operation has no durable effect; retry below.
            }
            try ingress.validate()
            journal.ingress = journal.ingress.filter { $0.value.envelope.expires > .now }
            guard journal.ingress.count < 4096 else { throw StorageError.limitExceeded }
            journal.ingress[ingress.id] = .init(envelope: ingress)
            try journal.save(at: journalURL)
        }
        let operation: OperationView
        do { operation = try await core.write(command) }
        catch {
            // A provider can fail after commit. Bind the durable receipt to the operation path
            // emitted by the core, so a subsequent drain never signs the same envelope twice.
            let after = try await core.records()
            let added = after.keys.filter { $0.hasPrefix("ops/") && fresh.core?.records[$0] == nil }
            if !added.isEmpty {
                if let migrationKey {
                    let parts = URL(fileURLWithPath: added[0]).deletingPathExtension().lastPathComponent.split(separator: "-")
                    if added.count == 1, parts.count == 2 { journal.migration?[migrationKey]?.operationID = String(parts[1]) }
                    else { journal.migration?[migrationKey]?.uncertain = true }
                }
                if let ingress {
                    let name = URL(fileURLWithPath: added[0]).deletingPathExtension().lastPathComponent
                    let parts = name.split(separator: "-")
                    if added.count == 1, parts.count == 2 {
                        journal.ingress[ingress.id]?.operationID = String(parts[1])
                    } else { journal.ingress[ingress.id]?.uncertain = true }
                }
                do { try await persistDelta() } catch is PendingPublication { }
                return (.queued, empty(.unavailable(reason: "Committed write awaits confirmation; refresh to retry publication")))
            }
            try await persistDelta()
            throw error
        }
        if let ingress { journal.ingress[ingress.id]?.operationID = operation.id }
        if let migrationKey { journal.migration?[migrationKey]?.operationID = operation.id }
        do { try await persistDelta() }
        catch is PendingPublication {
            return (.queued, empty(.unavailable(reason: "Write queued for durable publication")))
        }
        return (.saved(operationID: operation.id), try await refreshLocked())
    }
    /// Stop an unreserved native-identity collision before signing. The future engine should
    /// supply occurrence reservation/remapping atomically with the import write.
    private func checkMigrationIdentity(_ command: DomainCommand, in state: Data?) throws {
        guard let state,
              let payload = try JSONSerialization.jsonObject(with: command.payload) as? [String: Any],
              let id = payload["id"] as? String,
              let projection = try JSONSerialization.jsonObject(with: state) as? [String: Any] else { return }
        let collection: String?
        switch (command.namespace, command.kind) {
        case ("reading.books", "addBook"): collection = "books"
        case ("reading.books", "addNote"): collection = "notes"
        case ("reading.saved", "capture"): collection = "items"
        case ("notes", "createNotebook"): collection = "notebooks"
        case ("notes", "putCell") where payload["expect"] is NSNull: collection = "cells"
        case ("notes", "putEntry") where payload["expect"] is NSNull: collection = "entries"
        case ("listening.podcasts", "follow") where payload["expect"] is NSNull: collection = "shows"
        case ("listening.podcasts", "addNote"): collection = "notes"
        default: collection = nil
        }
        guard let collection else { return }
        if let map = projection[collection] as? [String: Any], map[id] != nil { throw SessionError.migrationCollision }
        if let rows = projection[collection] as? [[String: Any]], rows.contains(where: { $0["id"] as? String == id }) { throw SessionError.migrationCollision }
    }
    /// Replay pending exact bytes before accepting more commands. Conflicts stop; no silent rebase.
    private func persistDelta() async throws {
        let records = try await core.records()
        for (path, bytes) in records where !journal.knownPaths.contains(path) { journal.pending[path] = bytes }
        // Only a successfully persisted journal can produce a queued receipt.
        try journal.save(at: journalURL)
        do { try await publish() }
        catch StorageError.unavailable(let reason) { throw PendingPublication(reason: reason) }
    }
    private func publish() async throws {
        guard !journal.pending.isEmpty else { return }
        try await storage().append(journal.pending)
        let readback = try await storage().read()
        guard journal.pending.allSatisfy({ readback[$0.key] == $0.value }) else { throw StorageError.unavailable("Publication readback incomplete") }
        journal.knownPaths.formUnion(journal.pending.keys)
        journal.pending = [:]
        try journal.save(at: journalURL)
    }
    func approve(_ request: Data, grant: GrantOptions?) async throws -> SessionSnapshot {
        await enter(); defer { exit() }
        _ = try await refreshLocked()
        do { try await core.approve(request, grant: grant) }
        catch { try await persistDelta(); throw error }
        try await persistDelta()
        return try await refreshLocked()
    }
    func revoke(_ memberID: String) async throws -> SessionSnapshot {
        await enter(); defer { exit() }
        _ = try await refreshLocked()
        do { try await core.revoke(memberID) }
        catch { try await persistDelta(); throw error }
        try await persistDelta()
        return try await refreshLocked()
    }
    func leave() async throws {
        await enter(); defer { exit() }
        try loadJournal()
        guard journal.pending.isEmpty else { throw StorageError.unavailable("Retry pending publication before leaving") }
        journal.left = true; try journal.save(at: journalURL)
        opened = false; last = nil
    }
    func rejoin(keys: any AsyncKeyProvider) async throws -> SessionSnapshot {
        await enter(); defer { exit() }
        try loadJournal()
        guard journal.pending.isEmpty else { throw StorageError.unavailable("Retry pending publication before rejoining") }
        self.keys = keys; opened = false; last = nil; journal.left = false
        try journal.save(at: journalURL)
        return try await refreshLocked()
    }
    func importRequest(from url: URL) async throws -> SessionSnapshot {
        await enter(); defer { exit() }
        _ = try await refreshLocked()
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        let data = try AtomicFile.read(url, maximumBytes: 64 * 1024)
        _ = try await core.importRequest(data)
        try await persistDelta()
        return try await refreshLocked()
    }
    func recovery() async -> (any AsyncKeyProvider)? { await core.recovery() }
    private func empty(_ phase: SessionPhase) -> SessionSnapshot {
        SessionSnapshot(phase: phase, core: nil, revision: revision, namespaceRevisions: namespaceRevisions)
    }
    private func makeSnapshot(_ snapshot: CoreSnapshot, phase: SessionPhase) -> SessionSnapshot {
        // Legacy bindings report broad change hints. Compare complete per-namespace evidence
        // here, off-main; replace this work with native engine deltas when available.
        let changed = last?.records != snapshot.records || last?.denials != snapshot.denials || last?.views != snapshot.views
        if changed {
            revision += 1
            for namespace in configuration.namespaces where last?.views[namespace] != snapshot.views[namespace] || last?.denials[namespace] != snapshot.denials[namespace] {
                namespaceRevisions[namespace, default: 0] += 1
            }
        }
        last = snapshot
        return SessionSnapshot(phase: phase, core: snapshot, revision: revision, namespaceRevisions: namespaceRevisions)
    }
}

struct PendingPublication: Error, Sendable { let reason: String }

struct SessionRefusal: Error, Sendable { let snapshot: SessionSnapshot; let error: SessionError }
