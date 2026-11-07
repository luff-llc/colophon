import Foundation
import ColophonKit
import ColophonKitStorage

/// Worker seam for the storage engine and test adapters. App lifecycle, domain caches and
/// extension envelopes remain independent of the native engine handles.
protocol SessionCore: Sendable {
    func openStorage(store: any RecordStore, paths: Set<String>, versions: [String: String], pending: [String: Data], keys: any AsyncKeyProvider, namespaces: [String], cache: CheckpointCache, libraryID: String?) async throws
    func saveCheckpoint() async throws
    func updateVersions(_ versions: [String: String], reader: RecordReader) async throws
    func operation(path: String, namespace: String) async throws -> OperationView
    func open(records: [String: Data], keys: any AsyncKeyProvider) async throws
    func create(configuration: SessionConfiguration) async throws
    func setReadScope(_ namespaces: [String]) async throws
    func liveGeneration(path: String, bytes: Data) async throws -> UInt64
    func merge(_ records: [String: Data]) async throws
    func mergeObserved(_ records: [String: Data], versions: [String: String]) async throws
    func records() async throws -> [String: Data]
    func records(at paths: [String]) async throws -> [String: Data]
    func lastWrittenPaths() async throws -> [String]
    func snapshot(namespaces: [String]) async throws -> CoreSnapshot
    func snapshot(namespaces: [String], requestPaths: [String]) async throws -> CoreSnapshot
    func request(configuration: SessionConfiguration, keys: any AsyncKeyProvider) async throws -> AccessRequest
    func query(namespace: String, name: String, arguments: Data) async throws -> Data
    func beginBlob(namespace: String, mediaType: String) async throws -> NativeBlobWriter
    func openBlobChunk(namespace: String, digest: String, index: Int, ciphertext: Data) async throws -> BlobReadOutcome
    func write(_ command: DomainCommand) async throws -> OperationView
    func approve(_ request: Data, grant: GrantOptions?) async throws
    func revoke(_ id: String) async throws
    func importRequest(_ data: Data) async throws -> AccessRequest
    func approveWithStarter(_ request: Data, keys: any AsyncKeyProvider) async throws
    func recovery() async -> (any AsyncKeyProvider)?
}

actor BindingSessionCore: SessionCore {
    private var library: StorageLibrary?
    private var cache: CheckpointCache?
    private var recoveryProvider: (any AsyncKeyProvider)?
    private func requireLibrary() throws -> StorageLibrary {
        guard let library else { throw SessionError.notReady }; return library
    }
    func openStorage(store: any RecordStore, paths: Set<String>, versions: [String: String], pending: [String: Data], keys: any AsyncKeyProvider, namespaces: [String], cache: CheckpointCache, libraryID: String?) async throws {
        let reader = try await store.engineReader()
        let source = SessionRecordSource(reader: reader, pending: pending)
        // Verify layout/current authority before the engine can request any operation body.
        var authority = try await store.read(paths: paths.filter { $0.hasPrefix("authority/") })
        authority.merge(pending.filter { $0.key.hasPrefix("authority/") }) { _, new in new }
        let barrier = try NativeLibrary.open(records: authority, me: await SessionKeys(base: keys).publicKeys())
        let id = try barrier.id()
        guard libraryID == nil || libraryID == id else { throw SessionError.destinationChanged }
        let checkpoint = try await cache.load(libraryID: id)
        var currentVersions = versions
        for path in pending.keys { currentVersions[path] = nil }
        library = try await StorageLibrary.open(source: source, listing: Array(paths.union(pending.keys)), versions: currentVersions,
            libraryID: id, namespaces: namespaces, checkpoint: checkpoint, keys: SessionKeys(base: keys))
        self.cache = cache
    }
    func open(records: [String: Data], keys: any AsyncKeyProvider) async throws {
        let id = try NativeLibrary.open(records: records.filter { $0.key.hasPrefix("authority/") }, me: await SessionKeys(base: keys).publicKeys()).id()
        library = try await StorageLibrary.open(source: SessionRecordSource(reader: RecordReader { path in
            guard let bytes = records[path] else { throw StorageError.unavailable("Missing record: " + path) }; return bytes
        }, pending: [:]), listing: Array(records.keys), versions: [:], libraryID: id, namespaces: [], checkpoint: nil, keys: SessionKeys(base: keys))
    }
    func updateVersions(_ versions: [String: String], reader: RecordReader) async throws {
        let native = try requireLibrary().native
        try native.setSource(source: SessionRecordSource(reader: reader, pending: [:]))
        try native.updateVersions(versions: versions)
    }
    func saveCheckpoint() async throws {
        guard let library, let cache else { return }
        _ = try library.native.verifyBatch(limit: 128)
        try await cache.save(library.checkpoint(), libraryID: library.id)
    }
    func operation(path: String, namespace: String) async throws -> OperationView { try await requireLibrary().operation(path: path, namespace: namespace) }
    func create(configuration: SessionConfiguration) async throws {
        let created = try await Library.create(owner: SessionKeys(base: configuration.starterKeys ?? configuration.keys), label: configuration.memberLabel,
            ownerLabel: configuration.memberLabel, namespaces: configuration.libraryNamespaces, recovery: configuration.recoveryKeys.map { SessionKeys(base: $0) })
        recoveryProvider = created.recoveryKeys
        let records = try await created.records
        let store = MemoryRecordStore(records: records)
        try await openStorage(store: store, paths: Set(records.keys), versions: [:], pending: [:], keys: configuration.keys,
            namespaces: configuration.namespaces, cache: CheckpointCache(privateContainer: configuration.privateContainer), libraryID: nil)
    }
    func approveWithStarter(_ request: Data, keys: any AsyncKeyProvider) async throws {
        let library = try requireLibrary()
        let owner = try await Library.open(records: library.records, me: SessionKeys(base: keys))
        // Core authority, not location or a display label, decides whether this key may grant.
        _ = try await owner.approve(request: request).get()
        try await library.merge(records: owner.records)
        try await library.ready()
    }
    func mergeObserved(_ records: [String: Data], versions: [String: String]) async throws {
        let library = try requireLibrary()
        _ = try library.native.mergeObserved(records: records, versions: Dictionary(uniqueKeysWithValues: records.keys.compactMap { path in versions[path].map { (path, $0) } }))
        try await library.ready()
    }
    func merge(_ records: [String: Data]) async throws {
        let library = try requireLibrary()
        try await library.merge(records: records)
        try await library.ready()
    }
    func setReadScope(_ namespaces: [String]) async throws {
        // Scope is bound at storage-engine open. Creation has no historical records.
    }
    func liveGeneration(path: String, bytes: Data) async throws -> UInt64 {
        try requireLibrary().native.liveGeneration(path: path, bytes: bytes, now: Date.now.ISO8601Format())
    }
    func records() async throws -> [String: Data] { try await requireLibrary().records }
    func records(at paths: [String]) async throws -> [String: Data] { try await requireLibrary().records(at: paths) }
    func lastWrittenPaths() async throws -> [String] { try await requireLibrary().lastWrittenPaths }
    func importRequest(_ data: Data) async throws -> AccessRequest {
        let library = try requireLibrary()
        let request = try requestInfo(record: data, libraryId: await library.id)
        try await library.merge(records: ["requests/\(request.id).json": data])
        return request
    }
    func recovery() -> (any AsyncKeyProvider)? { recoveryProvider }
    func snapshot(namespaces: [String]) async throws -> CoreSnapshot {
        let keys = Array((try await requireLibrary().records.keys).filter { $0.hasPrefix("requests/") })
        return try await snapshot(namespaces: namespaces, requestPaths: keys)
    }
    func snapshot(namespaces: [String], requestPaths: [String]) async throws -> CoreSnapshot {
        let library = try requireLibrary()
        let id = try await library.id
        let records = try await library.records(at: requestPaths)
        var views: [String: NamespaceView] = [:]
        var denials: [String: Denial] = [:]
        for namespace in namespaces {
            if let denial = try library.native.access(namespace: namespace, now: Date.now.ISO8601Format()) { denials[namespace] = denial }
            else { views[namespace] = NamespaceView(namespace: namespace, admitted: [], held: [], refused: [], state: Data()) }
        }
        let members = try await library.members()
        let requests = try records.sorted(by: { $0.key < $1.key }).filter { $0.key.hasPrefix("requests/") }
            .map { try requestInfo(record: $0.value, libraryId: id) }
            .filter { request in !members.contains { $0.id == request.id } }
        return CoreSnapshot(libraryID: id, me: try await library.me(), members: members,
            ledger: [], requests: requests, views: views, denials: denials, records: records, engine: library.native, engineRevisions: try library.native.revisions())
    }
    func request(configuration: SessionConfiguration, keys: any AsyncKeyProvider) async throws -> AccessRequest {
        try await Library.requestAccess(libraryID: requireLibrary().id, keys: SessionKeys(base: keys), label: configuration.memberLabel,
            kind: configuration.memberKind, namespaces: configuration.namespaces, access: configuration.access)
    }
    func query(namespace: String, name: String, arguments: Data) async throws -> Data {
        try await requireLibrary().query(namespace: namespace, name: name, arguments: arguments).get()
    }
    func beginBlob(namespace: String, mediaType: String) async throws -> NativeBlobWriter {
        try await requireLibrary().beginBlob(namespace: namespace, mediaType: mediaType)
    }
    func openBlobChunk(namespace: String, digest: String, index: Int, ciphertext: Data) async throws -> BlobReadOutcome {
        try await requireLibrary().openBlobChunk(namespace: namespace, digest: digest, index: index, ciphertext: ciphertext)
    }
    func write(_ command: DomainCommand) async throws -> OperationView {
        try await requireLibrary().write(namespace: command.namespace, kind: command.kind, payload: command.payload).get()
    }
    func approve(_ request: Data, grant: GrantOptions?) async throws { _ = try await requireLibrary().approve(request: request, grant: grant) }
    func revoke(_ id: String) async throws { try await requireLibrary().revoke(memberID: id) }
}

// Existing test/host adapters need not implement named queries until they support them.
extension SessionCore {
    func mergeObserved(_ records: [String: Data], versions: [String: String]) async throws { try await merge(records) }
    func openStorage(store: any RecordStore, paths: Set<String>, versions: [String: String], pending: [String: Data], keys: any AsyncKeyProvider, namespaces: [String], cache: CheckpointCache, libraryID: String?) async throws {
        var records = try await store.read(paths: Array(paths)); records.merge(pending) { _, new in new }
        try await open(records: records, keys: keys); try await setReadScope(namespaces)
    }
    func saveCheckpoint() async throws {}
    func updateVersions(_ versions: [String: String], reader: RecordReader) async throws {}
    func operation(path: String, namespace: String) async throws -> OperationView {
        let snapshot = try await snapshot(namespaces: [namespace])
        if let engine = snapshot.engine {
            switch try engine.operationAt(path: path, namespace: namespace, now: Date.now.ISO8601Format()) {
            case .success(let op): return op
            case .failure: throw SessionError.publicationUncertain
            }
        }
        guard let op = snapshot.views[namespace]?.admitted.first(where: { path.contains($0.id) }) else { throw SessionError.publicationUncertain }; return op
    }

    func setReadScope(_ namespaces: [String]) async throws {}
    func liveGeneration(path: String, bytes: Data) async throws -> UInt64 { throw SessionError.notReady }
    func beginBlob(namespace: String, mediaType: String) async throws -> NativeBlobWriter { throw SessionError.notReady }
    func openBlobChunk(namespace: String, digest: String, index: Int, ciphertext: Data) async throws -> BlobReadOutcome { throw SessionError.notReady }
    func query(namespace: String, name: String, arguments: Data) async throws -> Data {
        throw SessionError.notReady
    }
    func records(at paths: [String]) async throws -> [String: Data] {
        let all = try await records()
        var result: [String: Data] = [:]
        for path in paths { if let bytes = all[path] { result[path] = bytes } }
        return result
    }
    func lastWrittenPaths() async throws -> [String] { [] }
    func snapshot(namespaces: [String], requestPaths: [String]) async throws -> CoreSnapshot {
        try await snapshot(namespaces: namespaces)
    }
}

private final class SessionRecordSource: EngineRecordSource, Sendable {
    let reader: RecordReader
    let pending: [String: Data]
    init(reader: RecordReader, pending: [String: Data]) { self.reader = reader; self.pending = pending }
    func read(path: String) throws -> Data {
        do { return try pending[path] ?? reader.read(path) }
        catch { throw BindingError.InvalidData(detail: error.localizedDescription) }
    }
}
