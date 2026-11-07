import Foundation

/// Storage-backed native replica. Hosts supply synchronous immutable reads on their worker.
public actor StorageLibrary {
    public nonisolated let native: NativeEngine
    private let keys: any AsyncKeyProvider
    public private(set) var lastWrittenPaths: [String] = []

    private init(native: NativeEngine, keys: any AsyncKeyProvider) { self.native = native; self.keys = keys }

    public static func open(source: any EngineRecordSource, listing: [String], versions: [String: String],
                            libraryID: String, namespaces: [String], checkpoint: Data?, keys: any AsyncKeyProvider) async throws -> StorageLibrary {
        let member = try await keys.publicKeys()
        let key: NativeCheckpointKey
        if let checkpoint {
            let opening = try NativeCheckpointOpening(bytes: checkpoint, libraryId: libraryID, member: member)
            key = try opening.finish(shared: await keys.agree(peer: opening.agreementPeer()))
        } else {
            let preparation = try NativeCheckpointPreparation(libraryId: libraryID, member: member, entropy: HostInputs.entropy())
            key = try preparation.finish(signature: await keys.sign(body: preparation.signingBody()))
        }
        var inventory = Data()
        inventory.reserveCapacity(listing.count * 180)
        func append(_ value: String) {
            let bytes = value.utf8; var length = UInt32(bytes.count).littleEndian
            withUnsafeBytes(of: &length) { inventory.append(contentsOf: $0) }
            inventory.append(contentsOf: bytes)
        }
        for path in listing { append(path); append(versions[path] ?? "") }
        let native = try NativeEngine.openInventory(source: source, inventory: inventory, me: member,
                                          libraryId: libraryID, namespaces: namespaces, key: key)
        let library = StorageLibrary(native: native, keys: keys)
        try await library.ready()
        return library
    }
    public var id: String { get throws { try native.id() } }
    public var records: [String: Data] { get throws { try native.records() } }
    public func records(at paths: [String]) throws -> [String: Data] { try native.recordsAt(paths: paths) }
    public func me() throws -> Member { try native.me() }
    public func members() throws -> [Member] { try native.members() }
    public func checkpoint() throws -> Data { try native.checkpoint(entropy: HostInputs.entropy()) }
    public func merge(records: [String: Data]) throws { _ = try native.merge(records: records) }
    public func ready() async throws {
        var results: [UnlockResult] = []
        for step in try native.beginUnlock() { results.append(try await UnlockResult(step: step, shared: keys.agree(peer: step.peer))) }
        try native.finishUnlockMany(results: results)
    }
    public func query(namespace: String, name: String, arguments: Data) throws -> Outcome<Data> {
        switch try native.query(namespace: namespace, name: name, arguments: arguments, now: HostInputs.now()) {
        case .success(let value): .success(value)
        case .failure(let denial): .failure(denial)
        }
    }
    public func write(namespace: String, kind: String, payload: Data) async throws -> Outcome<OperationView> {
        let prepared = try native.beginWrite(namespace: namespace, kind: kind, payload: payload, now: HostInputs.now(), entropy: HostInputs.entropy())
        switch prepared {
        case .failure(let denial): lastWrittenPaths = []; return .failure(denial)
        case .ready(let action):
            lastWrittenPaths = action.recordPaths()
            try await commit(action)
            // A live action signs history and aliases it to state; only the state slot is indexed.
            let path = lastWrittenPaths.first { $0.hasPrefix("state/") } ?? lastWrittenPaths.first { $0.hasPrefix("ops/") }
            guard let path else { throw BindingError.InvalidData(detail: "Missing operation path") }
            switch try native.operationAt(path: path, namespace: namespace, now: HostInputs.now()) {
            case .success(let value): return .success(value)
            case .failure(let denial): return .failure(denial)
            }
        }
    }
    public func operation(path: String, namespace: String) throws -> OperationView {
        switch try native.operationAt(path: path, namespace: namespace, now: HostInputs.now()) {
        case .success(let value): return value
        case .failure(let denial): throw AccessError(denial: denial)
        }
    }
    public func approve(request: Data, grant: GrantOptions?) async throws {
        try await execute(native.beginApprove(request: request, grant: grant, now: HostInputs.now(), entropy: HostInputs.entropy()))
        try await ready()
    }
    public func revoke(memberID: String) async throws {
        try await execute(native.beginRevoke(memberId: memberID, now: HostInputs.now(), entropy: HostInputs.entropy()))
        try await ready()
    }
    public func beginBlob(namespace: String, mediaType: String) throws -> NativeBlobWriter {
        switch try native.beginBlob(namespace: namespace, mediaType: mediaType, now: HostInputs.now(), entropy: HostInputs.entropy()) {
        case .ready(let writer): return writer
        case .failure(let denial): throw AccessError(denial: denial)
        }
    }
    public func openBlobChunk(namespace: String, digest: String, index: Int, ciphertext: Data) throws -> BlobReadOutcome {
        try native.openBlobChunk(namespace: namespace, digest: digest, index: UInt32(index), ciphertext: ciphertext, now: HostInputs.now())
    }
    private func execute(_ prepared: PreparedAction) async throws {
        switch prepared {
        case .ready(let action): try await commit(action)
        case .failure(let denial): throw AccessError(denial: denial)
        }
    }
    private func commit(_ action: HostAction) async throws {
        let member = try await keys.publicKeys()
        var signatures: [Data] = []
        for step in action.signingSteps() {
            guard step.signingKey == member.signing else { throw BindingError.InvalidData(detail: "Unexpected signing identity") }
            signatures.append(try await keys.sign(body: step.body))
        }
        try Task.checkCancellation()
        _ = try native.commit(action: action, signatures: signatures)
    }
}
