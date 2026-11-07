import Foundation

/// Expected access refusals are values; malformed records and provider failures throw.
public enum Outcome<Value: Sendable>: Sendable {
    case success(Value)
    case failure(Denial)

    public func get() throws -> Value {
        switch self {
        case .success(let value): value
        case .failure(let denial): throw AccessError(denial: denial)
        }
    }
}

public struct AccessError: Error, Sendable {
    public let denial: Denial
}

/// In-memory Colophon 0.3 replica. Hosts own storage, sync, and key persistence.
/// Actor reentrancy is safe: a merge during signing makes commit throw BindingError.StaleAction.
/// Retry such an action explicitly; no stale grant or authority change is silently committed.
public actor Library {
    public nonisolated let native: NativeLibrary
    public nonisolated let recoveryKeys: (any AsyncKeyProvider)?
    private let keys: any AsyncKeyProvider
    /// Paths last written by `write`, including live-state aliases and retained copies.
    public private(set) var lastWrittenPaths: [String] = []

    private init(native: NativeLibrary, keys: any AsyncKeyProvider, recovery: (any AsyncKeyProvider)? = nil) {
        self.native = native
        self.keys = keys
        self.recoveryKeys = recovery
    }

    @concurrent
    public static func create(owner: any AsyncKeyProvider, label: String, ownerLabel: String,
                              namespaces: [String], recovery: (any AsyncKeyProvider)? = nil) async throws -> Library {
        let recovery = recovery ?? SoftwareKeys()
        let publicKeys = try await owner.publicKeys()
        let action = try beginCreate(owner: publicKeys, recovery: await recovery.publicKeys(), label: label,
                                     ownerLabel: ownerLabel, namespaces: namespaces, now: HostInputs.now(), entropy: HostInputs.entropy())
        let signed = try await signatures(action, keys: owner)
        try Task.checkCancellation()
        let records = try action.finish(signatures: signed)
        let library = Library(native: try NativeLibrary.open(records: records, me: publicKeys), keys: owner, recovery: recovery)
        try await library.ready()
        return library
    }

    @concurrent
    public static func open(records: [String: Data], me: any AsyncKeyProvider) async throws -> Library {
        let library = Library(native: try NativeLibrary.open(records: records, me: await me.publicKeys()), keys: me)
        try await library.ready()
        return library
    }

    @concurrent
    public static func requestAccess(libraryID: String, keys: any AsyncKeyProvider, label: String,
                                     kind: MemberKind, namespaces: [String], access: [Access]) async throws -> AccessRequest {
        let action = try beginRequest(libraryId: libraryID, keys: await keys.publicKeys(), label: label, kind: kind,
                                      namespaces: namespaces, access: access, now: HostInputs.now())
        let records = try action.finish(signatures: await signatures(action, keys: keys))
        guard let record = records.values.first else { throw BindingError.InvalidData(detail: "Empty request") }
        return try requestInfo(record: record, libraryId: libraryID)
    }

    public var id: String { get throws { try native.id() } }
    public var records: [String: Data] { get throws { try native.records() } }
    public var revision: UInt64 { get throws { try native.revision() } }
    public func me() throws -> Member { try native.me() }
    public func members() throws -> [Member] { try native.members() }
    public func ledger() throws -> [LedgerEntry] { try native.ledger() }
    public func tools() throws -> [Tool] { try native.tools(now: HostInputs.now()) }

    /// Revocations apply immediately. Await ready() to open newly received epoch shares.
    @discardableResult
    public func merge(records: [String: Data]) throws -> ChangeSummary { try native.merge(records: records) }

    public func ready() async throws {
        for step in try native.beginUnlock() {
            var secret = try await keys.agree(peer: step.peer)
            defer { secret.resetBytes(in: secret.startIndex..<secret.endIndex) }
            _ = try native.finishUnlock(step: step, shared: secret)
        }
    }

    public func approve(request: Data, grant: GrantOptions? = nil) async throws -> Outcome<Member> {
        try await ready()
        let info = try requestInfo(record: request, libraryId: native.id())
        let action = try native.beginApprove(request: request, grant: grant, now: HostInputs.now(), entropy: HostInputs.entropy())
        if let denied = try await execute(action) { return .failure(denied) }
        guard let member = try native.members().first(where: { $0.id == info.id }) else {
            throw BindingError.InvalidData(detail: "Approved member missing")
        }
        return .success(member)
    }

    public func revoke(memberID: String) async throws -> Outcome<Void> {
        try await ready()
        return try await executeVoid(native.beginRevoke(memberId: memberID, now: HostInputs.now(), entropy: HostInputs.entropy()))
    }

    /// A streaming writer; the host persists each encrypted chunk before publishing its manifest.
    public func beginBlob(namespace: String, mediaType: String) async throws -> NativeBlobWriter {
        try await ready()
        switch try native.beginBlob(namespace: namespace, mediaType: mediaType, now: HostInputs.now(), entropy: HostInputs.entropy()) {
        case .ready(let writer): return writer
        case .failure(let denial): throw AccessError(denial: denial)
        }
    }

    /// Authenticates ciphertext the host fetched for chunk `index` of a published blob. Rechecks
    /// the current grant, the content address, AEAD and the chunk's plaintext digest.
    public func openBlobChunk(namespace: String, digest: String, index: Int, ciphertext: Data) throws -> BlobReadOutcome {
        try native.openBlobChunk(namespace: namespace, digest: digest, index: UInt32(index), ciphertext: ciphertext, now: HostInputs.now())
    }

    /// Exact bytes for the given paths, without copying the whole record map.
    public func records(at paths: [String]) throws -> [String: Data] { try native.recordsAt(paths: paths) }

    public func write(namespace: String, kind: String, payload: Data) async throws -> Outcome<OperationView> {
        try await ready()
        let prepared = try native.beginWrite(namespace: namespace, kind: kind, payload: payload, now: HostInputs.now(), entropy: HostInputs.entropy())
        switch prepared {
        case .failure(let denial): lastWrittenPaths = []; return .failure(denial)
        case .ready(let action):
            lastWrittenPaths = action.recordPaths()
            try await commit(action)
            return operationOutcome(try native.writtenOperation(action: action, namespace: namespace, now: HostInputs.now()))
        }
    }

    public func view(namespace: String) throws -> Outcome<NamespaceView> {
        switch try native.view(namespace: namespace, now: HostInputs.now()) {
        case .success(let value): .success(value)
        case .failure(let denial): .failure(denial)
        }
    }

    /// Read-only tool dispatch. A command name can never commit a write through this API.
    public func query(namespace: String, name: String, arguments: Data) async throws -> Outcome<Data> {
        try await ready()
        switch try native.query(namespace: namespace, name: name, arguments: arguments, now: HostInputs.now()) {
        case .success(let value): return .success(value)
        case .failure(let denial): return .failure(denial)
        }
    }

    public func call(tool: String, input: Data) async throws -> Outcome<Data> {
        try await ready()
        switch try native.beginCall(tool: tool, input: input, now: HostInputs.now(), entropy: HostInputs.entropy()) {
        case .read(let value): return .success(value)
        case .failure(let denial): return .failure(denial)
        case .write(let action):
            try await commit(action)
            let namespace = tool.components(separatedBy: "__")[0]
            switch try native.writtenOperationJson(action: action, namespace: namespace, now: HostInputs.now()) {
            case .failure(let denial): return .failure(denial)
            case .success(let value): return .success(value)
            }
        }
    }

    public func handover(newRoot: any AsyncKeyProvider, label: String) async throws -> Outcome<Void> {
        try await ready()
        return try await executeVoid(native.beginHandover(newRoot: await newRoot.publicKeys(), label: label,
                                                         now: HostInputs.now(), entropy: HostInputs.entropy()))
    }

    public func recover(newRoot: any AsyncKeyProvider, label: String) async throws -> Outcome<Void> {
        try await ready()
        return try await executeVoid(native.beginRecover(newRoot: await newRoot.publicKeys(), label: label,
                                                        now: HostInputs.now(), entropy: HostInputs.entropy()))
    }

    private static func signatures(_ action: HostAction, keys: any AsyncKeyProvider) async throws -> [Data] {
        let publicKeys = try await keys.publicKeys()
        var signatures: [Data] = []
        for step in action.signingSteps() {
            guard step.signingKey == publicKeys.signing else { throw BindingError.KeyProvider(detail: "Unexpected signing identity") }
            signatures.append(try await keys.sign(body: step.body))
        }
        return signatures
    }
    private func commit(_ action: HostAction) async throws {
        let signatures = try await Self.signatures(action, keys: keys)
        try Task.checkCancellation()
        _ = try native.commit(action: action, signatures: signatures)
        try await ready()
    }
    private func execute(_ action: PreparedAction) async throws -> Denial? {
        switch action {
        case .failure(let denial): return denial
        case .ready(let action): try await commit(action); return nil
        }
    }
    private func executeVoid(_ action: PreparedAction) async throws -> Outcome<Void> {
        if let denial = try await execute(action) { .failure(denial) } else { .success(()) }
    }
    private func operationOutcome(_ outcome: OperationOutcome) -> Outcome<OperationView> {
        switch outcome {
        case .success(let value): .success(value)
        case .failure(let denial): .failure(denial)
        }
    }
}

extension GrantOptions {
    public static func narrowing(namespaces: [String]? = nil, access: [Access]? = nil, expires: String? = nil, writeBudget: UInt64? = nil) -> GrantOptions {
        GrantOptions(namespaces: namespaces, access: access, expires: expires, writeBudget: writeBudget)
    }
}
