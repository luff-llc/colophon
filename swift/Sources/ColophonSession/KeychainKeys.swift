import Foundation
import Security
import ColophonKit

/// Process-private Keychain identity. Never replaces an unreadable or invalid existing key.
/// Select software explicitly for simulators; production can require Secure Enclave.
public actor KeychainKeys: AsyncKeyProvider {
    public enum Backend: String, Codable, Sendable { case secureEnclave, software }
    private struct Stored: Codable {
        let backend: Backend
        let signing: Data
        let agreement: Data
    }
    private let service: String
    private let account: String
    private let backend: Backend
    private var provider: (any AsyncKeyProvider)?
    public init(service: String, account: String = "member", backend: Backend = .secureEnclave) {
        self.service = service; self.account = account; self.backend = backend
    }
    private func load() throws -> any AsyncKeyProvider {
        if let provider { return provider }
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service, kSecAttrAccount as String: account]
        var lookup = query
        lookup[kSecReturnData as String] = true
        lookup[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(lookup as CFDictionary, &result)
        let value: any AsyncKeyProvider
        if status == errSecSuccess, let data = result as? Data {
            let stored = try JSONDecoder().decode(Stored.self, from: data)
            switch stored.backend {
            case .software: value = try SoftwareKeys(signingPrivateKey: stored.signing, agreementPrivateKey: stored.agreement)
            case .secureEnclave: value = try SecureEnclaveKeys(signingReference: stored.signing, agreementReference: stored.agreement)
            }
        } else if status == errSecItemNotFound {
            let stored: Stored
            switch backend {
            case .software:
                let keys = SoftwareKeys(); value = keys
                stored = Stored(backend: .software, signing: keys.signingPrivateKey, agreement: keys.agreementPrivateKey)
            case .secureEnclave:
                let keys = try SecureEnclaveKeys(); value = keys
                guard let signing = keys.signingReference, let agreement = keys.agreementReference else { throw KeyError.secureEnclaveUnavailable }
                stored = Stored(backend: .secureEnclave, signing: signing, agreement: agreement)
            }
            var addition = query
            addition[kSecValueData as String] = try JSONEncoder().encode(stored)
            addition[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            let created = SecItemAdd(addition as CFDictionary, nil)
            if created == errSecDuplicateItem { return try load() }
            guard created == errSecSuccess else { throw StorageError.unavailable("Keychain: \(created)") }
        } else { throw StorageError.unavailable("Keychain: \(status)") }
        provider = value
        return value
    }
    public func publicKeys() async throws -> PublicKeys { try await load().publicKeys() }
    public func sign(body: Data) async throws -> Data { try await load().sign(body: body) }
    public func agree(peer: Data) async throws -> Data { try await load().agree(peer: peer) }
}
