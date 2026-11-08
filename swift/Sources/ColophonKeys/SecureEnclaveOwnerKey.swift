import ColophonKit
import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// A device-only raw controller with separate signing and agreement keys.
/// Persist with `store(tag:)`: the keychain item is non-synchronizing and excluded from backups.
public struct SecureEnclaveOwnerKey: AsyncKeyProvider {
    private let backend: any OwnerKeyBackend
    private let references: References?
    /// Whether this key requests presence for each action session.
    public let requiresPresence: Bool
    /// Whether this device has a Secure Enclave; no software fallback is performed.
    public static var isAvailable: Bool { SecureEnclave.isAvailable }
    /// The owner signs raw ES256 bodies.
    public var form: KeyForm { .raw }

    /// Creates independent P-256 keys protected by WhenUnlockedThisDeviceOnly access control.
    public init(requiresPresence: Bool) throws {
        guard Self.isAvailable else { throw KeyProviderError.hardwareUnavailable }
        let flags: SecAccessControlCreateFlags = requiresPresence ? [.privateKeyUsage, .userPresence] : [.privateKeyUsage]
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &error) else {
            throw error.map { KeyProviderError.map($0.takeRetainedValue()) } ?? .hardwareUnavailable
        }
        do {
            let signing = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
            let agreement = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
            let references = References(signing: signing.dataRepresentation, agreement: agreement.dataRepresentation,
                                        requiresPresence: requiresPresence)
            self.init(references: references)
        } catch { throw KeyProviderError.map(error) }
    }

    private init(references: References) {
        self.references = references
        requiresPresence = references.requiresPresence
        backend = EnclaveOwnerBackend(references: references)
    }

    // A fake backend exercises action sessions without Secure Enclave or LocalAuthentication UI.
    init(backend: any OwnerKeyBackend, requiresPresence: Bool) {
        self.backend = backend
        self.requiresPresence = requiresPresence
        references = nil
    }

    /// Loads this device's opaque handles. Missing items never create replacement identities.
    public static func load(tag: String) throws -> Self {
        var query = keychainQuery(tag: tag)
        query[kSecReturnData] = true
        query[kSecMatchLimit] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else { throw KeyProviderError.map(NSError(domain: NSOSStatusErrorDomain, code: Int(status))) }
        guard let data = result as? Data else { throw KeyProviderError.credentialMissing }
        let references = try JSONDecoder().decode(References.self, from: data)
        guard Self.isAvailable else { throw KeyProviderError.hardwareUnavailable }
        return Self(references: references)
    }

    /// Saves encrypted enclave handles in a non-backup, non-synchronizing device-only keychain item.
    /// An existing tag is never overwritten: callers must choose a new tag for a new owner.
    public func store(tag: String) throws {
        guard let references else { throw KeyProviderError.unsupportedHere }
        let attributes = Self.storageAttributes(tag: tag, data: try JSONEncoder().encode(references))
        let status = SecItemAdd(attributes as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeyProviderError.map(NSError(domain: NSOSStatusErrorDomain, code: Int(status))) }
    }

    /// Evaluates presence once, returning keys bound to one LAContext for every body of this action.
    /// Keep the returned session only for the action's lifetime; no session or context is persisted.
    public func presence(scope: String) async throws -> any AsyncKeyProvider {
        do {
            try Task.checkCancellation()
            let session = try await backend.presence(scope: scope)
            try Task.checkCancellation()
            return session
        } catch { throw KeyProviderError.map(error) }
    }
    /// Reads the separate public points without returning empty placeholders on failure.
    public func publicKeys() async throws -> PublicKeys {
        do { return try await backend.publicKeys() } catch { throw KeyProviderError.map(error) }
    }
    /// Signs a raw body. Use presence(scope:) to share authentication across an action.
    public func sign(body: Data) async throws -> Data {
        do { return try await backend.sign(body: body) } catch { throw KeyProviderError.map(error) }
    }
    /// Returns the raw 32-byte ECDH secret from the separate agreement key.
    public func agree(peer: Data) async throws -> Data {
        do { return try await backend.agree(peer: peer) } catch { throw KeyProviderError.map(error) }
    }

    static func storageAttributes(tag: String, data: Data) -> [CFString: Any] {
        var attributes = keychainQuery(tag: tag)
        attributes[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        attributes[kSecValueData] = data
        return attributes
    }

    private static func keychainQuery(tag: String) -> [CFString: Any] {
        [kSecClass: kSecClassGenericPassword, kSecAttrService: "ColophonKeys.SecureEnclaveOwnerKey",
         kSecAttrAccount: tag, kSecAttrSynchronizable: false, kSecUseDataProtectionKeychain: true]
    }
}

private struct References: Codable, Sendable {
    let signing: Data
    let agreement: Data
    let requiresPresence: Bool
}

protocol OwnerKeyBackend: AsyncKeyProvider {
    func presence(scope: String) async throws -> any AsyncKeyProvider
}

private actor EnclaveOwnerBackend: OwnerKeyBackend {
    let references: References
    init(references: References) { self.references = references }
    func publicKeys() throws -> PublicKeys {
        PublicKeys(signing: try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: references.signing).publicKey.x963Representation,
                   agreement: try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: references.agreement).publicKey.x963Representation)
    }
    func sign(body: Data) throws -> Data {
        try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: references.signing).signature(for: body).rawRepresentation
    }
    func agree(peer: Data) throws -> Data {
        try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: references.agreement)
            .sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: peer)).withUnsafeBytes { Data($0) }
    }
    func presence(scope: String) async throws -> any AsyncKeyProvider {
        guard references.requiresPresence else { return self }
        let session = try OwnerKeySession(references: references)
        try await session.authenticate(scope: scope)
        return session
    }
}

/// Actor isolation keeps the authentication context and CryptoKit operations serialized.
private actor OwnerKeySession: AsyncKeyProvider {
    private let authentication: OwnerAuthentication
    private let signing: SecureEnclave.P256.Signing.PrivateKey
    private let agreement: SecureEnclave.P256.KeyAgreement.PrivateKey
    init(references: References) throws {
        let authentication = OwnerAuthentication()
        self.authentication = authentication
        let context = authentication.context
        signing = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: references.signing, authenticationContext: context)
        agreement = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: references.agreement, authenticationContext: context)
    }
    func authenticate(scope: String) async throws {
        let accepted = try await authentication.context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: scope)
        guard accepted else { throw KeyProviderError.presenceFailed }
        try Task.checkCancellation()
    }
    func publicKeys() -> PublicKeys {
        PublicKeys(signing: signing.publicKey.x963Representation, agreement: agreement.publicKey.x963Representation)
    }
    func sign(body: Data) throws -> Data {
        try Task.checkCancellation()
        do { return try signing.signature(for: body).rawRepresentation } catch { throw KeyProviderError.map(error) }
    }
    func agree(peer: Data) throws -> Data {
        try Task.checkCancellation()
        do {
            return try agreement.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: peer))
                .withUnsafeBytes { Data($0) }
        } catch { throw KeyProviderError.map(error) }
    }
}

// Never shared outside the session actor. Its ordinary class deinit can invalidate LAContext
// without accessing a non-Sendable actor property from a nonisolated actor deinit.
private final class OwnerAuthentication {
    let context = LAContext()
    deinit { context.invalidate() }
}
