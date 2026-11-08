import CryptoKit
import Foundation
import Security
import ColophonKit

/// Host orchestration only: the core constructs, authorizes and verifies every authority record.
enum SessionAuthority {
    static func entropy() throws -> Data {
        var bytes = Data(count: 32)
        let status = bytes.withUnsafeMutableBytes { buffer in
            guard let address = buffer.baseAddress else { return errSecParam }
            return SecRandomCopyBytes(kSecRandomDefault, buffer.count, address)
        }
        guard status == errSecSuccess else { throw KeyError.randomGenerationFailed(status) }
        return bytes
    }

    static func id(_ provider: any AsyncKeyProvider) async throws -> String {
        SHA256.hash(data: try await provider.publicKeys().signing).prefix(16)
            .map { String(format: "%02x", $0) }.joined()
    }

    static func signatures(_ action: HostAction, providers: [any AsyncKeyProvider]) async throws -> [SignatureResult] {
        var available: [Data: any AsyncKeyProvider] = [:]
        for provider in providers { available[try await provider.publicKeys().signing] = provider }
        var results: [SignatureResult] = []
        for step in action.signingSteps() {
            guard let provider = available[step.signingKey], provider.form == step.form else {
                throw BindingError.KeyProvider(detail: "Unexpected signing identity or form")
            }
            if let challenge = step.challenge {
                guard let assertion = try await provider.assert(challenge: challenge, prfSalt: nil) else {
                    throw BindingError.KeyProvider(detail: "WebAuthn assertion unsupported or missing")
                }
                results.append(SignatureResult(signature: assertion.signature, assertion: assertion))
            } else {
                results.append(SignatureResult(signature: try await provider.sign(body: step.body), assertion: nil))
            }
        }
        try Task.checkCancellation()
        return results
    }

    static func create(_ configuration: SessionConfiguration) async throws -> Library {
        let member = SessionKeys(base: configuration.keys)
        let controller = SessionKeys(base: configuration.ownerController)
        guard member.form == .raw, controller.form == .raw else {
            throw BindingError.KeyProvider(detail: "Creation requires raw member and owner controller keys")
        }
        var recovery: RecoveryKitController?
        if let provider = configuration.recoveryKeys {
            guard provider.form == .raw else { throw BindingError.KeyProvider(detail: "Recovery kits require raw keys") }
            recovery = RecoveryKitController(keys: try await SessionKeys(base: provider).publicKeys(), label: "Recovery Kit")
        }
        let action = try beginCreateWith(options: CreateLibraryOptions(
            member: await member.publicKeys(), controller: await controller.publicKeys(), vaultSeed: entropy(),
            label: configuration.memberLabel, ownerLabel: configuration.memberLabel, namespaces: configuration.libraryNamespaces,
            recovery: recovery, importedFrom: configuration.importedFrom, importExpires: configuration.importExpires),
            now: Date.now.ISO8601Format(), entropy: entropy())
        let first = try await signatures(action, providers: [member, controller])
        let final = try action.advanceCreate(signatures: first.map(\.signature))
        let records = try final.finishAuthority(results: await signatures(final, providers: [controller]))
        return try await open(records: records, member: member, controller: controller)
    }

    static func open(records: [String: Data], member: any AsyncKeyProvider, controller: any AsyncKeyProvider) async throws -> Library {
        let library = try await Library.open(records: records, me: SessionKeys(base: member))
        let provider = SessionKeys(base: controller)
        try await library.selectController(id: id(provider))
        await library.setControllers([provider])
        try await library.unlockVault(using: [provider])
        return library
    }

    static func restore(records: [String: Data], configuration: SessionConfiguration, member: any AsyncKeyProvider,
                        kit: any AsyncKeyProvider) async throws -> Library {
        let library = try await Library.open(records: records, me: SessionKeys(base: member))
        let recovery = SessionKeys(base: kit), owner = SessionKeys(base: configuration.ownerController)
        await library.setControllers([recovery])
        try await library.unlockVault(using: [recovery])
        struct Ring: Decodable { let threshold: UInt64; let recoverThreshold: UInt64 }
        let ring = try JSONDecoder().decode(Ring.self, from: await library.keyring())
        guard owner.form == .raw else { throw BindingError.KeyProvider(detail: "Device restoration requires a raw owner controller") }
        let keys = try await owner.publicKeys()
        let roles = ring.recoverThreshold < ring.threshold ? ["approve"] : ["approve", "control"]
        let controller = try JSONSerialization.data(withJSONObject: [
            "key": ["form": "raw", "signing": keys.signing.base64EncodedString(), "agreement": keys.agreement.base64EncodedString()],
            "label": configuration.memberLabel, "roles": roles
        ], options: [.sortedKeys])
        let slot = try await library.buildSealedSlot(controller: controller, label: configuration.memberLabel)
        try await library.recoveryAdd(controller: controller, slot: slot, signers: [id(recovery)])
        try await library.selectController(id: id(owner))
        await library.setControllers([owner])
        try await library.unlockVault(using: [owner])
        let request = try await Library.requestAccess(libraryID: library.id, keys: SessionKeys(base: member),
            label: configuration.memberLabel, kind: configuration.memberKind,
            namespaces: configuration.libraryNamespaces, access: [.read, .write])
        _ = try await library.approve(request: request.record).get()
        return library
    }
}
