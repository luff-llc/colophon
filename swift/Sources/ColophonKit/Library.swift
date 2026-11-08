import Foundation
import CryptoKit

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

/// In-memory Colophon 0.4 replica. Hosts own storage, sync, and key persistence.
/// Actor reentrancy is safe: a merge during signing makes commit throw BindingError.StaleAction.
/// Retry such an action explicitly; no stale grant or authority change is silently committed.
public actor Library {
    public nonisolated let native: NativeLibrary
    private let keys: any AsyncKeyProvider
    private var controllers: [any AsyncKeyProvider] = []
    /// Paths last written by `write`, including live-state aliases and retained copies.
    public private(set) var lastWrittenPaths: [String] = []

    private init(native: NativeLibrary, keys: any AsyncKeyProvider) {
        self.native = native
        self.keys = keys
    }

    /// Create a library with separate controller and content-member identities.
    @concurrent
    public static func create(owner: any AsyncKeyProvider, label: String, ownerLabel: String,
                              namespaces: [String], controller: any AsyncKeyProvider) async throws -> Library {
        let publicKeys = try await owner.publicKeys()
        let action = try beginCreate(owner: publicKeys, controller: await controller.publicKeys(),
                                     vaultSeed: HostInputs.entropy(), label: label, ownerLabel: ownerLabel,
                                     namespaces: namespaces, now: HostInputs.now(), entropy: HostInputs.entropy())
        let first = try await signatures(action, providers: [owner, controller])
        let final = try action.advanceCreate(signatures: first.map(\.signature))
        let records = try final.finishAuthority(results: await signatures(final, providers: [controller]))
        let library = Library(native: try NativeLibrary.open(records: records, me: publicKeys), keys: owner)
        try library.native.selectController(id: controllerID(try await controller.publicKeys().signing))
        await library.setControllers([controller])
        try await library.ready()
        try await library.unlockVault(using: [controller])
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
        let records = try action.finishAuthority(results: await signatures(action, providers: [keys]))
        guard let record = records.values.first else { throw BindingError.InvalidData(detail: "Empty request") }
        return try requestInfo(record: record, libraryId: libraryID)
    }

    public var id: String { get throws { try native.id() } }
    public var records: [String: Data] { get throws { try native.records() } }
    public var revision: UInt64 { get throws { try native.revision() } }
    public func me() throws -> Member { try native.me() }
    public func members() throws -> [Member] { try native.members() }
    public func ledger() throws -> [LedgerEntry] { try native.ledger() }
    /// Current controllers, thresholds, vault identity and slots in protocol JSON.
    public func keyring() throws -> Data { try native.keyring() }
    /// Choose a controller for convenience grant, revoke, rekey and layout actions.
    public func selectController(id: String) throws { try native.selectController(id: id) }
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

    /// Set available controller providers; content writes continue to use the member provider.
    public func setControllers(_ providers: [any AsyncKeyProvider]) { controllers = providers }

    /// Open one complete vault route using ECDH or exact PRF outputs.
    public func unlockVault(using providers: [any AsyncKeyProvider]) async throws {
        var available: [String: any AsyncKeyProvider] = [:]
        for provider in providers { available[Self.controllerID(try await provider.publicKeys().signing)] = provider }
        for option in try native.beginUnlockSlots() {
            let ids = option.inputs.map { input in
                switch input { case .ecdh(let controller, _), .prf(let controller, _): controller }
            }
            guard ids.allSatisfy({ available[$0] != nil }) else { continue }
            var secrets: [SlotSecret] = []
            for input in option.inputs {
                switch input {
                case .ecdh(let controller, let enc):
                    guard let provider = available[controller] else { throw BindingError.KeyProvider(detail: "Missing controller") }
                    secrets.append(.ecdh(secret: try await provider.agree(peer: enc)))
                case .prf(let controller, let salt):
                    guard let provider = available[controller], let output = try await provider.prf(salt: salt) else {
                        throw BindingError.KeyProvider(detail: "WebAuthn PRF unsupported or missing results.first")
                    }
                    secrets.append(.prf(output: output))
                }
            }
            try Task.checkCancellation()
            _ = try native.finishUnlockSlot(option: option, secrets: secrets)
            return
        }
        throw BindingError.KeyProvider(detail: "No available vault route")
    }

    /// Prepare an authority action encoded in protocol JSON, with explicit signer IDs.
    public func prepareAuthority(action: Data, by: String, signers: [String]) throws -> HostAction {
        try native.prepareAuthority(action: action, by: by, signers: signers, now: HostInputs.now())
    }
    /// Sign a prepared action with the available controllers and atomically commit it.
    public func finishAuthority(_ action: HostAction) async throws {
        let results = try await Self.signatures(action, providers: controllers)
        try Task.checkCancellation()
        _ = try native.finishAuthority(action: action, results: results)
    }
    /// Verify a new-credential get assertion, build and reopen its PRF route.
    public func buildPasskeySlot(descriptor: Data, provider: any AsyncKeyProvider, label: String,
                                 newSeed: Data? = nil) async throws -> Data {
        let action = try native.beginPrfSlot(descriptor: descriptor, entropy: HostInputs.entropy())
        guard let result = try await provider.assert(challenge: action.challenge(), prfSalt: action.salt()) else {
            throw BindingError.KeyProvider(detail: "WebAuthn assertion or PRF unsupported")
        }
        try Task.checkCancellation()
        return try native.finishPrfSlot(action: action, result: result, label: label, newSeed: newSeed, entropy: HostInputs.entropy())
    }
    /// Verify new PRF assertions, build fresh part secrets and reopen the complete combined route.
    public func buildCombinedSlot(parts: [CombinedRoutePart], label: String, newSeed: Data? = nil) async throws -> Data {
        var inputs: [CombinedSlotPart] = []
        var outputs: [Data?] = []
        for part in parts {
            if part.provider.form == .raw {
                inputs.append(.sealed(controller: part.controller)); outputs.append(nil)
            } else {
                let action = try native.beginPrfSlot(descriptor: part.descriptor, entropy: HostInputs.entropy())
                guard let result = try await part.provider.assert(challenge: action.challenge(), prfSalt: action.salt()), let output = result.prf else {
                    throw BindingError.KeyProvider(detail: "WebAuthn assertion or PRF unsupported")
                }
                inputs.append(.prf(controller: part.controller, action: action, result: result)); outputs.append(output)
            }
        }
        try Task.checkCancellation()
        let action = try native.beginCombinedSlot(parts: inputs, label: label, newSeed: newSeed, entropy: HostInputs.entropy())
        var secrets: [SlotSecret] = []
        for (index, input) in action.inputs().enumerated() {
            switch input {
            case .ecdh(_, let enc): secrets.append(.ecdh(secret: try await parts[index].provider.agree(peer: enc)))
            case .prf:
                guard let output = outputs[index] else { throw BindingError.KeyProvider(detail: "Missing combined PRF output") }
                secrets.append(.prf(output: output))
            }
        }
        try Task.checkCancellation()
        return try native.finishCombinedSlot(action: action, secrets: secrets)
    }
    /// Candidate controllers in protocol JSON, including each form and roles.
    public func eligibleSigners(action: Data) throws -> [Data] { try native.eligibleSigners(action: action) }
    /// Add a passkey with a checked slot under the prior control rule.
    public func addPasskey(controller: Data, slot: Data, signers: [String]) async throws {
        try await finishAuthority(native.beginAddPasskey(controller: controller, slot: slot, signers: signers, now: HostInputs.now()))
    }
    /// Add a controller, optionally including a checked vault route.
    public func addController(controller: Data, slot: Data? = nil, signers: [String]) async throws {
        try await finishAuthority(native.beginAddController(controller: controller, slot: slot, signers: signers, now: HostInputs.now()))
    }
    /// Recovery only-adds with prior recovery signers.
    public func recoveryAdd(controller: Data, slot: Data? = nil, signers: [String]) async throws {
        try await finishAuthority(native.beginRecoveryAdd(controller: controller, slot: slot, signers: signers, now: HostInputs.now()))
    }
    /// Remove a controller and rotate the vault with checked replacement routes.
    public func removeController(id: String, newSeed: Data, slots: [Data], signers: [String]) async throws {
        try await finishAuthority(native.beginRemoveController(id: id, newSeed: newSeed, slots: slots, signers: signers,
                                                               now: HostInputs.now(), entropy: HostInputs.entropy()))
    }
    /// Replace the whole keyring, including threshold and vault changes.
    public func replaceKeyring(_ keyring: Data, newSeed: Data? = nil, signers: [String]) async throws {
        try await finishAuthority(native.beginKeyring(keyring: keyring, newSeed: newSeed, signers: signers,
                                                      now: HostInputs.now(), entropy: HostInputs.entropy()))
    }
    /// Build an HPKE route for a current or rotated vault.
    public func buildSealedSlot(controller: Data, label: String, newSeed: Data? = nil) throws -> Data {
        try native.buildSealedSlot(controller: controller, label: label, newSeed: newSeed, entropy: HostInputs.entropy())
    }
    /// Grant explicit scoped, expiring import permission.
    public func importGrant(request: Data, grant: Data, signers: [String]) async throws {
        try await finishAuthority(native.beginImportGrant(request: request, grant: grant, signers: signers,
                                                          now: HostInputs.now(), entropy: HostInputs.entropy()))
    }
    /// Introduce namespace epochs through the selected controller.
    public func rekey(namespaces: [String]) async throws -> Outcome<Void> {
        try await executeVoid(native.beginRekey(namespaces: namespaces, now: HostInputs.now(), entropy: HostInputs.entropy()))
    }
    private static func controllerID(_ signing: Data) -> String {
        SHA256.hash(data: signing).prefix(16).map { String(format: "%02x", $0) }.joined()
    }
    private static func signatures(_ action: HostAction, providers: [any AsyncKeyProvider]) async throws -> [SignatureResult] {
        var available: [Data: any AsyncKeyProvider] = [:]
        for provider in providers { available[try await provider.publicKeys().signing] = provider }
        var results: [SignatureResult] = []
        for step in action.signingSteps() {
            guard let provider = available[step.signingKey], provider.form == step.form else {
                throw BindingError.KeyProvider(detail: "Unexpected signing identity or form")
            }
            if let challenge = step.challenge {
                guard let assertion = try await provider.assert(challenge: challenge, prfSalt: nil) else {
                    throw BindingError.KeyProvider(detail: "WebAuthn assertion unsupported")
                }
                results.append(SignatureResult(signature: assertion.signature, assertion: assertion))
            } else {
                results.append(SignatureResult(signature: try await provider.sign(body: step.body), assertion: nil))
            }
        }
        return results
    }
    private func commit(_ action: HostAction) async throws {
        let results = try await Self.signatures(action, providers: [keys] + controllers)
        try Task.checkCancellation()
        _ = try native.finishAuthority(action: action, results: results)
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
