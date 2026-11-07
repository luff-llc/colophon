import Foundation
import CryptoKit
import ColophonKit
import ColophonKitStorage

/// All filesystem, FFI, projections and signing run off the main actor. The suspension-aware
/// gate serializes full operations, including signing and durable publication, across awaits.
actor SessionWorker {
    let configuration: SessionConfiguration
    private var keys: any AsyncKeyProvider
    let core: any SessionCore
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
    var relaySync: RelaySync?
    var blobIndex: Set<String>?
    var completeRequired = Set<String>()
    /// Record paths already merged into the open core; storage reads skip these.
    private var merged = Set<String>()
    private var requestPaths = Set<String>()
    private var recordVersions: [String: String] = [:]
    private var liveBytes: [String: Data] = [:]

    init(configuration: SessionConfiguration, core: any SessionCore = BindingSessionCore(), store: (any RecordStore)? = nil) {
        self.configuration = configuration; self.keys = configuration.keys; self.core = core; self.store = store
        journalURL = configuration.privateContainer.appendingPathComponent("session.json")
    }
    func enter() async {
        if occupied { await withCheckedContinuation { waiters.append($0) } } else { occupied = true }
    }
    func exit() {
        if waiters.isEmpty { occupied = false } else { waiters.removeFirst().resume() }
    }
    func storage() throws -> any RecordStore {
        if let store { return store }
        let resolved = try configuration.location.resolve(); store = resolved; return resolved
    }
    func changes() async throws -> AsyncStream<Void> { try await storage().changes() }
    private var relayLiveVerifier: Library?
    func relay() throws -> RelaySync? {
        if let relaySync { return relaySync }
        guard let relay = configuration.relay else { return nil }
        let created = RelaySync(local: try storage(), endpoint: relay.endpoint, transport: relay.transport,
                                stateFile: configuration.privateContainer.appendingPathComponent("relay.json"),
                                namespaces: configuration.namespaces, verifyLive: { [weak self] path, bytes in
                                    guard let self else { throw SessionError.notReady }
                                    return try await self.verifySyncLive(path, bytes: bytes)
                                },
                                validateAuthority: { [weak self] records in try await self?.validateSyncAuthority(records) })
        relaySync = created; return created
    }
    private func validateSyncAuthority(_ records: [String: Data]) async throws {
        do { relayLiveVerifier = try await Library.open(records: records, me: keys) }
        catch let error as BindingError {
            if case .InvalidData(let detail) = error, detail.hasPrefix("Unsupported storage layout") { throw SessionLayoutError.updateRequired }
            throw error
        }
    }
    private func verifySyncLive(_ path: String, bytes: Data) throws -> UInt64 {
        guard let verifier = relayLiveVerifier else { throw SessionError.notReady }
        return try verifier.native.liveGeneration(path: path, bytes: bytes, now: Date.now.ISO8601Format())
    }
    /// One relay pass outside the worker gate: the relay only appends verified-digest records to
    /// local storage, and the session then refreshes them through the normal merge.
    func syncRelay() async throws -> RelaySync.Report? { try await relay()?.sync() }
    func waitForRemoteChanges(seconds: Int) async throws -> Bool { try await relay()?.waitForRemoteChanges(seconds: seconds) ?? false }
    /// An empty local store is not an empty library while a configured relay has not been listed.
    private func pullBeforeTrustingEmpty() async throws {
        guard let relay = try relay() else { return }
        do { try await relay.sync() }
        catch let error as RelayError {
            throw StorageError.unavailable("Waiting for the relay before opening this library. " + (error.errorDescription ?? ""))
        }
    }
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
    func refreshLocked() async throws -> SessionSnapshot {
        if !configuration.migrationWriter, let marker = configuration.migrationMarker,
           try MigrationMarker.isActive(at: marker) { return empty(.migrating) }
        var stored = try await storage().paths(namespaces: configuration.namespaces)
        stored = Set(stored.filter { RecordPath.listingIncludes($0, namespaces: configuration.namespaces) })
        if stored.isEmpty && journal.pending.isEmpty && configuration.relay != nil {
            try await pullBeforeTrustingEmpty()
            stored = Set((try await storage().paths(namespaces: configuration.namespaces)).filter { RecordPath.listingIncludes($0, namespaces: configuration.namespaces) })
        }
        let available = stored.union(journal.pending.keys)
        let blocking = journal.knownPaths.filter { RecordPath.missingBlocks($0) && RecordPath.listingIncludes($0, namespaces: configuration.namespaces) }
        guard blocking.isSubset(of: available) else {
            throw StorageError.unavailable("Previously observed library records are unavailable")
        }
        if stored.isEmpty && journal.pending.isEmpty {
            guard journal.libraryID == nil else { throw StorageError.unavailable("Selected library is unavailable") }
            return empty(.noLibrary)
        }
        let versions = try await storage().versions(paths: stored)
        let fresh = opened ? stored.filter { !merged.contains($0) || versions[$0] == nil || versions[$0] != recordVersions[$0] } : stored
        // Authenticate the authority barrier before fetching any content body.
        let authorityPaths = fresh.filter { $0.hasPrefix("authority/") }
        var authority = try await storage().read(paths: Array(authorityPaths))
        guard Set(authority.keys) == authorityPaths else { throw StorageError.unavailable("Authority download pending") }
        for (path, bytes) in journal.pending where path.hasPrefix("authority/") { authority[path] = bytes }
        do {
            if opened { if !authority.isEmpty { try await core.merge(authority) } }
            else { try await core.open(records: authority, keys: keys); try await core.setReadScope(configuration.namespaces); opened = true; merged.removeAll(); requestPaths.removeAll() }
        } catch let error as BindingError {
            if case .InvalidData(let detail) = error, detail.hasPrefix("Unsupported storage layout") { throw SessionLayoutError.updateRequired }
            throw error
        }
        let contentPaths = fresh.subtracting(authorityPaths)
        var incoming = try await storage().read(paths: Array(contentPaths))
        guard Set(incoming.keys) == contentPaths else { throw StorageError.unavailable("Record download pending") }
        incoming.merge(authority) { old, _ in old }
        let observedLive = incoming.filter { RecordPath.isReplaceable($0.key) }
        for (path, data) in journal.pending {
            if let old = incoming[path], old != data, !RecordPath.isReplaceable(path) { throw StorageError.conflict(path) }
            if !opened || !merged.contains(path) || RecordPath.isReplaceable(path) { incoming[path] = data }
        }
        do {
            if opened {
                if !incoming.isEmpty { try await core.merge(incoming) }
            } else {
                try await core.open(records: incoming, keys: keys)
                opened = true
                merged.removeAll(); requestPaths.removeAll()
            }
        } catch {
            if error.localizedDescription.hasPrefix("Unsupported storage layout") {
                throw SessionLayoutError.updateRequired
            }
            throw error
        }
        liveBytes.merge(observedLive) { _, new in new }
        track(incoming.keys)
        recordVersions.merge(versions) { _, new in new }
        let unseenRequests = stored.filter { $0.hasPrefix("requests/") && !merged.contains($0) }
        if !unseenRequests.isEmpty {
            let extra = try await storage().read(paths: Array(unseenRequests))
            if opened, !extra.isEmpty { try await core.merge(extra) }
            track(extra.keys)
        }
        requestPaths.formUnion(stored.filter { $0.hasPrefix("requests/") })
        var snapshot = try await core.snapshot(namespaces: configuration.namespaces, requestPaths: Array(requestPaths))
        guard journal.libraryID == nil || journal.libraryID == snapshot.libraryID else { throw SessionError.destinationChanged }
        journal.libraryID = snapshot.libraryID
        if !journal.pending.isEmpty { try await publish() }
        if snapshot.me.since == 0 {
            let request: AccessRequest
            if let existing = snapshot.requests.first(where: { $0.id == snapshot.me.id }) { request = existing }
            else {
                request = try await core.request(configuration: configuration, keys: keys)
                let path = "requests/\(request.id).json"
                try await core.merge([path: request.record])
                track([path])
                journal.pending[path] = request.record
                snapshot = try await core.snapshot(namespaces: configuration.namespaces, requestPaths: Array(requestPaths))
                try remember(snapshot, observed: [path])
                try await publish()
                snapshot = try await core.snapshot(namespaces: configuration.namespaces, requestPaths: Array(requestPaths))
            }
            if let starter = configuration.starterKeys {
                do {
                    try await core.approveWithStarter(request.record, keys: starter)
                    try await persistDelta()
                    snapshot = try await core.snapshot(namespaces: configuration.namespaces, requestPaths: Array(requestPaths))
                } catch is AccessError {
                    try remember(snapshot, observed: incoming.keys)
                    return makeSnapshot(snapshot, phase: .waitingForApproval(code: request.pairingCode))
                }
            } else {
                try remember(snapshot, observed: incoming.keys)
                return makeSnapshot(snapshot, phase: .waitingForApproval(code: request.pairingCode))
            }
        }
        try remember(snapshot, observed: incoming.keys)
        let phase: SessionPhase
        if snapshot.me.revokedAt != nil { phase = .denied }
        else if snapshot.denials.values.contains(where: { [.unavailable, .notReadable].contains($0.reason) }) {
            phase = .unavailable(reason: "Namespace keys or records are not available")
        } else if !snapshot.denials.isEmpty { phase = .denied }
        else { phase = .ready }
        return makeSnapshot(snapshot, phase: phase)
    }
    private func track(_ paths: some Collection<String>) {
        merged.formUnion(paths)
        for path in paths where path.hasPrefix("requests/") { requestPaths.insert(path) }
    }
    private func remember(_ snapshot: CoreSnapshot, observed: some Collection<String>) throws {
        journal.knownPaths.formUnion(observed)
        try journal.save(at: journalURL)
    }
    func create() async throws -> SessionSnapshot {
        await enter(); defer { exit() }
        if !configuration.migrationWriter, let marker = configuration.migrationMarker,
           try MigrationMarker.isActive(at: marker) { return empty(.migrating) }
        if configuration.relay != nil, try await storage().paths().isEmpty {
            try await pullBeforeTrustingEmpty()
            if !(try await storage().paths().isEmpty) { return try await refreshLocked() }
        }
        guard !opened, journal.libraryID == nil, try await storage().paths().isEmpty else { throw SessionError.destinationChanged }
        try await core.create(configuration: configuration); try await core.setReadScope(configuration.namespaces); opened = true
        journal.left = false
        journal.libraryID = try await core.snapshot(namespaces: configuration.namespaces).libraryID
        try await persistDelta()
        return try await refreshLocked()
    }
    func migrationBlob(namespace: String, mediaType: String, bytes: Data) async throws -> Data {
        await enter(); defer { exit() }
        let fresh = try await refreshLocked()
        guard fresh.phase == .ready, configuration.migrationWriter,
              let blobs = try storage() as? any BlobStore else { throw SessionError.notReady }
        let writer = try await core.beginBlob(namespace: namespace, mediaType: mediaType)
        for offset in stride(from: 0, to: bytes.count, by: 65536) {
            try Task.checkCancellation()
            let chunk = try writer.push(plaintext: bytes.subdata(in: offset..<min(bytes.count, offset + 65536)))
            try await blobs.appendBlob(chunk.path, bytes: chunk.bytes)
            guard try await blobs.readBlob(chunk.path) == chunk.bytes else { throw SessionError.publicationUncertain }
        }
        return try writer.finish()
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
        let ceiling = migrationKey != nil && command.kind == "colophon.importBatch" || command.kind == "colophon.blobPublish" ? 1024 * 1024 : 256 * 1024
        guard command.payload.count <= ceiling else { throw SessionError.invalidCommand }
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
        var written: [String] = []
        do {
            operation = try await core.write(command)
            written = try await core.lastWrittenPaths()
        }
        catch {
            // A provider can fail after commit. Bind the durable receipt to the operation path
            // emitted by the core, so a subsequent drain never signs the same envelope twice.
            let added = (try await core.lastWrittenPaths()).filter { $0.hasPrefix("ops/") || $0.hasPrefix("state/") || $0.hasPrefix("history/") }
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
                return (.queued, SessionSnapshot(phase: .retry, core: fresh.core, revision: fresh.revision, namespaceRevisions: fresh.namespaceRevisions))
            }
            try await persistDelta()
            throw error
        }
        if let ingress { journal.ingress[ingress.id]?.operationID = operation.id }
        if let migrationKey { journal.migration?[migrationKey]?.operationID = operation.id }
        do { try await persistDelta(paths: written.isEmpty ? nil : written) }
        catch is PendingPublication {
            return (.queued, SessionSnapshot(phase: .retry, core: fresh.core, revision: fresh.revision, namespaceRevisions: fresh.namespaceRevisions))
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
    private func persistDelta(paths: [String]? = nil) async throws {
        let candidates: [String]
        if let paths {
            candidates = paths.filter { !journal.knownPaths.contains($0) || RecordPath.isReplaceable($0) }
        } else {
            candidates = Array((try await core.records()).keys.filter { !journal.knownPaths.contains($0) || RecordPath.isReplaceable($0) })
        }
        let records = try await core.records(at: candidates)
        for (path, bytes) in records { journal.pending[path] = bytes }
        track(journal.pending.keys)
        try journal.save(at: journalURL)
        do { try await publish() }
        catch StorageError.unavailable(let reason) { throw PendingPublication(reason: reason) }
    }
    private func publish() async throws {
        guard !journal.pending.isEmpty else { return }
        try await storage().append(journal.pending.filter { !RecordPath.isReplaceable($0.key) })
        for (path, bytes) in journal.pending where RecordPath.isReplaceable(path) {
            let generation = try await core.liveGeneration(path: path, bytes: bytes)
            if let old = liveBytes[path], old != bytes, let oldGeneration = try? await core.liveGeneration(path: path, bytes: old), oldGeneration >= generation { throw StorageError.conflict(path) }
            guard try await storage().replaceLive(path, expected: liveBytes[path], bytes: bytes) else {
                throw StorageError.conflict(path)
            }
            liveBytes[path] = bytes
        }
        let readback = try await storage().read(paths: Array(journal.pending.keys))
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
        opened = false; last = nil; merged.removeAll(); requestPaths.removeAll()
    }
    func rejoin(keys: any AsyncKeyProvider) async throws -> SessionSnapshot {
        await enter(); defer { exit() }
        try loadJournal()
        guard journal.pending.isEmpty else { throw StorageError.unavailable("Retry pending publication before rejoining") }
        self.keys = keys; opened = false; last = nil; merged.removeAll(); requestPaths.removeAll(); journal.left = false
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
    func query(namespace: String, name: String, arguments: Data) async throws -> Data {
        await enter(); defer { exit() }
        try Task.checkCancellation()
        return try await core.query(namespace: namespace, name: name, arguments: arguments)
    }
    func recovery() async -> (any AsyncKeyProvider)? { await core.recovery() }
    private func empty(_ phase: SessionPhase) -> SessionSnapshot {
        SessionSnapshot(phase: phase, core: nil, revision: revision, namespaceRevisions: namespaceRevisions)
    }
    private func makeSnapshot(_ snapshot: CoreSnapshot, phase: SessionPhase) -> SessionSnapshot {
        // Legacy bindings report broad change hints. Compare complete per-namespace evidence
        // here, off-main; replace this work with native engine deltas when available.
        let changed = last?.records != snapshot.records || last?.denials != snapshot.denials || last?.views != snapshot.views || last?.ledger != snapshot.ledger
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

enum SessionLayoutError: Error, Sendable { case updateRequired }

struct SessionRefusal: Error, Sendable { let snapshot: SessionSnapshot; let error: SessionError }
