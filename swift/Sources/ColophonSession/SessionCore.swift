import Foundation
import ColophonKit

/// The only engine seam. The future RecordSource/checkpoint engine replaces this adapter,
/// without changing storage, app lifecycle, domain caches or extension envelopes.
protocol SessionCore: Sendable {
    func open(records: [String: Data], keys: any AsyncKeyProvider) async throws
    func create(configuration: SessionConfiguration) async throws
    func merge(_ records: [String: Data]) async throws
    func records() async throws -> [String: Data]
    func snapshot(namespaces: [String]) async throws -> CoreSnapshot
    func request(configuration: SessionConfiguration, keys: any AsyncKeyProvider) async throws -> AccessRequest
    func query(namespace: String, name: String, arguments: Data) async throws -> Data
    func beginBlob(namespace: String, mediaType: String) async throws -> NativeBlobWriter
    func write(_ command: DomainCommand) async throws -> OperationView
    func approve(_ request: Data, grant: GrantOptions?) async throws
    func revoke(_ id: String) async throws
    func importRequest(_ data: Data) async throws -> AccessRequest
    func approveWithStarter(_ request: Data, keys: any AsyncKeyProvider) async throws
    func recovery() async -> (any AsyncKeyProvider)?
}

actor BindingSessionCore: SessionCore {
    private var library: Library?
    private var recoveryProvider: (any AsyncKeyProvider)?
    private func requireLibrary() throws -> Library {
        guard let library else { throw SessionError.notReady }; return library
    }
    func open(records: [String: Data], keys: any AsyncKeyProvider) async throws {
        library = try await Library.open(records: records, me: SessionKeys(base: keys))
    }
    func create(configuration: SessionConfiguration) async throws {
        library = try await Library.create(owner: SessionKeys(base: configuration.starterKeys ?? configuration.keys), label: configuration.memberLabel,
            ownerLabel: configuration.memberLabel, namespaces: configuration.libraryNamespaces, recovery: configuration.recoveryKeys.map { SessionKeys(base: $0) })
        recoveryProvider = library?.recoveryKeys
        if configuration.starterKeys != nil, let created = library {
            library = try await Library.open(records: created.records, me: SessionKeys(base: configuration.keys))
        }
    }
    func approveWithStarter(_ request: Data, keys: any AsyncKeyProvider) async throws {
        let library = try requireLibrary()
        let owner = try await Library.open(records: library.records, me: SessionKeys(base: keys))
        // Core authority, not location or a display label, decides whether this key may grant.
        _ = try await owner.approve(request: request).get()
        try await library.merge(records: owner.records)
        try await library.ready()
    }
    func merge(_ records: [String: Data]) async throws {
        let library = try requireLibrary()
        try await library.merge(records: records)
        try await library.ready()
    }
    func records() async throws -> [String: Data] { try await requireLibrary().records }
    func importRequest(_ data: Data) async throws -> AccessRequest {
        let library = try requireLibrary()
        let request = try requestInfo(record: data, libraryId: await library.id)
        try await library.merge(records: ["requests/\(request.id).json": data])
        return request
    }
    func recovery() -> (any AsyncKeyProvider)? { recoveryProvider }
    func snapshot(namespaces: [String]) async throws -> CoreSnapshot {
        let library = try requireLibrary()
        let id = try await library.id
        let records = try await library.records
        var views: [String: NamespaceView] = [:]
        var denials: [String: Denial] = [:]
        for namespace in namespaces {
            switch try await library.view(namespace: namespace) {
            case .success(let view): views[namespace] = view
            case .failure(let denial): denials[namespace] = denial
            }
        }
        let members = try await library.members()
        let requests = try records.sorted(by: { $0.key < $1.key }).filter { $0.key.hasPrefix("requests/") }
            .map { try requestInfo(record: $0.value, libraryId: id) }
            .filter { request in !members.contains { $0.id == request.id } }
        return CoreSnapshot(libraryID: id, me: try await library.me(), members: members,
            ledger: try await library.ledger(), requests: requests, views: views, denials: denials, records: records)
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
    func write(_ command: DomainCommand) async throws -> OperationView {
        try await requireLibrary().write(namespace: command.namespace, kind: command.kind, payload: command.payload).get()
    }
    func approve(_ request: Data, grant: GrantOptions?) async throws { _ = try await requireLibrary().approve(request: request, grant: grant).get() }
    func revoke(_ id: String) async throws { try await requireLibrary().revoke(memberID: id).get() }
}

// Existing test/host adapters need not implement named queries until they support them.
extension SessionCore {
    func beginBlob(namespace: String, mediaType: String) async throws -> NativeBlobWriter { throw SessionError.notReady }
    func query(namespace: String, name: String, arguments: Data) async throws -> Data {
        throw SessionError.notReady
    }
}
