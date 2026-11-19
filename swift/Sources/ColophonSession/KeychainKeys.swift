import Foundation
import Security
import ColophonKit

/// Process-private Keychain identity. Never replaces an unreadable or invalid existing key.
///
/// Production keys are Secure Enclave keys: the item holds the enclave's two encrypted key handles (not scalars;
/// useless off this device's enclave), and the decoded handles are kept for the actor's lifetime.
///
/// The software backend exists only in debug builds and simulator builds (`#if DEBUG || targetEnvironment(simulator)`):
/// a release build for a real device has no way to create or read one. Its item holds the two raw P-256 scalars in a
/// fixed binary layout (never JSON), written from `SecretBytes` without a copy; every operation reads the item again
/// into `SecretBytes`, builds the CryptoKit key in place and drops both. Nothing decoded is cached. The copies it
/// cannot reach are those of `KeychainSecret` (the `CFData` a read returns, the Keychain's own buffers) and CryptoKit's
/// key storage for the duration of one operation (zeroed by CryptoKit on release).
public actor KeychainKeys: AsyncKeyProvider {
    public enum Backend: String, Sendable {
        case secureEnclave
        #if DEBUG || targetEnvironment(simulator)
        /// Simulator and tests only. Compiled out of release builds for devices.
        case software
        #endif
    }
    private let service: String
    private let account: String
    private let backend: Backend
    private var enclave: SecureEnclaveKeys?
    public init(service: String, account: String = "member", backend: Backend = .secureEnclave) {
        self.service = service; self.account = account; self.backend = backend
    }

    // Layout: [version 1][backend: 0 enclave, 1 software][u16 length][signing][u16 length][agreement], lengths big-endian.
    private static let version: UInt8 = 1

    private var query: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account,
         kSecAttrSynchronizable as String: false]
    }

    /// Runs `body` with this identity's key, creating it on first use.
    private func withKey<R>(_ body: (any AsyncKeyProvider) async throws -> R) async throws -> R {
        if let enclave { return try await body(enclave) }
        guard let stored = try KeychainSecret.read(query) else {
            try create()
            return try await withKey(body)
        }
        let parts = try Self.parse(stored)
        switch parts.backend {
        case 0:
            let keys = try stored.withUnsafeBytes { bytes in
                try SecureEnclaveKeys(signingReference: Data(bytes[parts.signing]), agreementReference: Data(bytes[parts.agreement]))
            }
            enclave = keys
            return try await body(keys)
        case 1:
            #if DEBUG || targetEnvironment(simulator)
            let keys = try stored.withUnsafeBytes { bytes in
                try SoftwareKeys(signingPrivateKey: UnsafeRawBufferPointer(rebasing: bytes[parts.signing]),
                                 agreementPrivateKey: UnsafeRawBufferPointer(rebasing: bytes[parts.agreement]))
            }
            return try await body(keys)
            #else
            throw KeyError.secureEnclaveUnavailable
            #endif
        default:
            throw StorageError.unavailable("Keychain: an identity item of an unknown form")
        }
    }

    private func create() throws {
        let item: SecretBytes
        switch backend {
        case .secureEnclave:
            let keys = try SecureEnclaveKeys()
            guard let signing = keys.signingReference, let agreement = keys.agreementReference else { throw KeyError.secureEnclaveUnavailable }
            item = try Self.encode(backend: 0, signing.count, agreement.count) { s, a in
                signing.withUnsafeBytes { s.copyMemory(from: $0) }; agreement.withUnsafeBytes { a.copyMemory(from: $0) }
            }
        #if DEBUG || targetEnvironment(simulator)
        case .software:
            item = try Self.encode(backend: 1, 32, 32) { s, a in
                try Self.fillScalar(s); try Self.fillScalar(a)
            }
        #endif
        }
        let created = KeychainSecret.add(query, secret: item, accessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
        guard created == errSecSuccess || created == errSecDuplicateItem else { throw StorageError.unavailable("Keychain: \(created)") }
    }

    private static func encode(backend: UInt8, _ signingCount: Int, _ agreementCount: Int,
                               fill: (UnsafeMutableRawBufferPointer, UnsafeMutableRawBufferPointer) throws -> Void) throws -> SecretBytes {
        guard signingCount <= Int(UInt16.max), agreementCount <= Int(UInt16.max) else { throw KeyError.secureEnclaveUnavailable }
        return try SecretBytes(count: 6 + signingCount + agreementCount) { buffer in
            buffer[0] = version; buffer[1] = backend
            buffer[2] = UInt8(signingCount >> 8); buffer[3] = UInt8(signingCount & 0xff)
            let agreementLength = 4 + signingCount
            buffer[agreementLength] = UInt8(agreementCount >> 8); buffer[agreementLength + 1] = UInt8(agreementCount & 0xff)
            try fill(UnsafeMutableRawBufferPointer(rebasing: buffer[4..<agreementLength]),
                     UnsafeMutableRawBufferPointer(rebasing: buffer[(agreementLength + 2)...]))
        }
    }

    private static func parse(_ item: SecretBytes) throws -> (backend: UInt8, signing: Range<Int>, agreement: Range<Int>) {
        try item.withUnsafeBytes { bytes in
            guard bytes.count >= 6, bytes[0] == version else { throw StorageError.unavailable("Keychain: an identity item of an unknown form") }
            let signingCount = Int(bytes[2]) << 8 | Int(bytes[3])
            let at = 4 + signingCount
            guard bytes.count >= at + 2 else { throw StorageError.unavailable("Keychain: a truncated identity item") }
            let agreementCount = Int(bytes[at]) << 8 | Int(bytes[at + 1])
            guard bytes.count == at + 2 + agreementCount else { throw StorageError.unavailable("Keychain: a truncated identity item") }
            return (bytes[1], 4..<at, (at + 2)..<(at + 2 + agreementCount))
        }
    }

    #if DEBUG || targetEnvironment(simulator)
    /// A valid P-256 scalar written straight into `target` (retried in the negligible case it is out of range).
    private static func fillScalar(_ target: UnsafeMutableRawBufferPointer) throws {
        guard let address = target.baseAddress else { return }
        for _ in 0..<16 {
            let status = SecRandomCopyBytes(kSecRandomDefault, target.count, address)
            guard status == errSecSuccess else { throw KeyError.randomGenerationFailed(status) }
            if (try? SoftwareKeys(signingPrivateKey: UnsafeRawBufferPointer(target), agreementPrivateKey: UnsafeRawBufferPointer(target))) != nil { return }
        }
        throw KeyError.randomGenerationFailed(errSecParam)
    }
    #endif

    public func publicKeys() async throws -> PublicKeys { try await withKey { try await $0.publicKeys() } }
    public func sign(body: Data) async throws -> Data { try await withKey { try await $0.sign(body: body) } }
    public func sharedSecret(peer: Data) async throws -> SecretBytes { try await withKey { try await $0.sharedSecret(peer: peer) } }
}
