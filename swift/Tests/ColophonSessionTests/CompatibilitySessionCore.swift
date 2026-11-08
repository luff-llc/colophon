// Test-only adapter baseline from f5839c2, running through the current session worker.
import Foundation
import ColophonKit
@testable import ColophonSession

actor CompatibilitySessionCore: SessionCore {
    private var library: Library?
    private var member: (any AsyncKeyProvider)?
    private var controller: (any AsyncKeyProvider)?
    func setOwnerController(_ provider: any AsyncKeyProvider) { controller = provider }
    private func requireLibrary() throws -> Library {
        guard let library else { throw SessionError.notReady }; return library
    }
    func open(records: [String: Data], keys: any AsyncKeyProvider) async throws {
        member = keys
        library = try await Library.open(records: records, me: SessionKeys(base: keys))
    }
    func create(configuration: SessionConfiguration) async throws {
        library = try await SessionAuthority.create(configuration)
        member = configuration.keys; controller = configuration.ownerController
    }
    private func authority(_ provider: any AsyncKeyProvider) async throws -> Library {
        guard let member else { throw SessionError.notReady }
        return try await SessionAuthority.open(records: requireLibrary().records, member: member, controller: provider)
    }
    func approveWithController(_ request: Data, keys: any AsyncKeyProvider) async throws {
        let owner = try await authority(keys)
        _ = try await owner.approve(request: request).get()
        try await merge(owner.records)
    }
    func merge(_ records: [String: Data]) async throws {
        let library = try requireLibrary()
        try await library.merge(records: records)
        try await library.ready()
    }
    func setReadScope(_ namespaces: [String]) async throws {
        try requireLibrary().native.setReadScope(namespaces: namespaces)
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
    func openBlobChunk(namespace: String, digest: String, index: Int, ciphertext: Data) async throws -> BlobReadOutcome {
        try await requireLibrary().openBlobChunk(namespace: namespace, digest: digest, index: index, ciphertext: ciphertext)
    }
    func write(_ command: DomainCommand) async throws -> OperationView {
        try await requireLibrary().write(namespace: command.namespace, kind: command.kind, payload: command.payload).get()
    }
    func approve(_ request: Data, grant: GrantOptions?) async throws {
        guard let controller else { throw SessionError.notReady }
        let owner = try await authority(controller)
        _ = try await owner.approve(request: request, grant: grant).get()
        try await merge(owner.records)
    }
    func revoke(_ id: String) async throws {
        guard let controller else { throw SessionError.notReady }
        let owner = try await authority(controller)
        try await owner.revoke(memberID: id).get()
        try await merge(owner.records)
    }
}

