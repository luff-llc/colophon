import CryptoKit
import Foundation
import Security

/// Async providers can suspend for authentication, a KMS, or platform key-store work.
/// Raw signatures use r || s; WebAuthn assertions retain DER and original signed bytes.
/// Public points use X9.63 and raw ECDH returns 32 bytes.
public protocol AsyncKeyProvider: Sendable {
    /// Select raw ES256 or WebAuthn get assertions.
    var form: KeyForm { get }
    /// Restrict get to this provider's credential and optionally evaluate the exact salt.
    func assert(challenge: String, prfSalt: Data?) async throws -> WebauthnResult?
    /// Evaluate an existing route; nil explicitly means unsupported or missing output.
    func prf(salt: Data) async throws -> Data?
    func publicKeys() async throws -> PublicKeys
    func sign(body: Data) async throws -> Data
    func agree(peer: Data) async throws -> Data
}

extension AsyncKeyProvider {
    /// Raw providers need no WebAuthn ceremony.
    public var form: KeyForm { .raw }
    /// Unsupported assertions are explicit; callers must not derive a fallback secret.
    public func assert(challenge: String, prfSalt: Data?) async throws -> WebauthnResult? { nil }
    /// Exact WebAuthn results.first for an existing slot; nil means unsupported.
    public func prf(salt: Data) async throws -> Data? { nil }
}

extension AsyncKeyProvider where Self: KeyProvider {
    public func publicKeys() async throws -> PublicKeys {
        PublicKeys(signing: try signingPublicKey(), agreement: try agreementPublicKey())
    }
}

public enum KeyError: Error, Sendable {
    case secureEnclaveUnavailable
    case randomGenerationFailed(Int32)
}

/// Exportable software keys for tests and platforms without hardware protection.
/// Persist private representations only in host-protected storage, never in library records.
public final class SoftwareKeys: KeyProvider, AsyncKeyProvider, Sendable {
    private let signing: P256.Signing.PrivateKey
    private let agreement: P256.KeyAgreement.PrivateKey

    public init() {
        signing = P256.Signing.PrivateKey()
        agreement = P256.KeyAgreement.PrivateKey()
    }

    public init(signingPrivateKey: Data, agreementPrivateKey: Data) throws {
        signing = try P256.Signing.PrivateKey(rawRepresentation: signingPrivateKey)
        agreement = try P256.KeyAgreement.PrivateKey(rawRepresentation: agreementPrivateKey)
    }

    public var signingPrivateKey: Data { signing.rawRepresentation }
    public var agreementPrivateKey: Data { agreement.rawRepresentation }
    public func signingPublicKey() throws -> Data { signing.publicKey.x963Representation }
    public func agreementPublicKey() throws -> Data { agreement.publicKey.x963Representation }
    public func sign(body: Data) throws -> Data {
        try keyOperation { try signing.signature(for: body).rawRepresentation }
    }
    public func agree(peer: Data) throws -> Data {
        try keyOperation {
            let key = try P256.KeyAgreement.PublicKey(x963Representation: peer)
            return try agreement.sharedSecretFromKeyAgreement(with: key).withUnsafeBytes { Data($0) }
        }
    }
}

/// Hardware-backed keys. Software fallback must be explicitly requested at construction.
public final class SecureEnclaveKeys: KeyProvider, AsyncKeyProvider, Sendable {
    public enum Fallback: Sendable { case never, software }
    private enum Storage: Sendable {
        case enclave(SecureEnclave.P256.Signing.PrivateKey, SecureEnclave.P256.KeyAgreement.PrivateKey)
        case software(SoftwareKeys)
    }
    private let storage: Storage

    public init(fallback: Fallback = .never) throws {
        guard SecureEnclave.isAvailable else {
            guard fallback == .software else { throw KeyError.secureEnclaveUnavailable }
            storage = .software(SoftwareKeys())
            return
        }
        // A hardware creation error is propagated; fallback is only for unavailable hardware.
        storage = .enclave(try SecureEnclave.P256.Signing.PrivateKey(), try SecureEnclave.P256.KeyAgreement.PrivateKey())
    }

    /// Restore opaque, device-bound CryptoKit key references from host-protected storage.
    public init(signingReference: Data, agreementReference: Data) throws {
        guard SecureEnclave.isAvailable else { throw KeyError.secureEnclaveUnavailable }
        storage = .enclave(
            try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: signingReference),
            try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: agreementReference))
    }

    /// Present only after explicit software fallback. Persist with the SoftwareKeys policy.
    public var softwareFallbackKeys: SoftwareKeys? {
        if case .software(let keys) = storage { keys } else { nil }
    }

    public var isHardwareBacked: Bool {
        if case .enclave = storage { true } else { false }
    }
    /// Nil when explicit software fallback was used; no private scalar is exported.
    public var signingReference: Data? {
        if case .enclave(let key, _) = storage { key.dataRepresentation } else { nil }
    }
    public var agreementReference: Data? {
        if case .enclave(_, let key) = storage { key.dataRepresentation } else { nil }
    }
    public func signingPublicKey() throws -> Data {
        switch storage {
        case .enclave(let key, _): key.publicKey.x963Representation
        case .software(let keys): try keys.signingPublicKey()
        }
    }
    public func agreementPublicKey() throws -> Data {
        switch storage {
        case .enclave(_, let key): key.publicKey.x963Representation
        case .software(let keys): try keys.agreementPublicKey()
        }
    }
    public func sign(body: Data) throws -> Data {
        try keyOperation {
            switch storage {
            case .enclave(let key, _): try key.signature(for: body).rawRepresentation
            case .software(let keys): try keys.sign(body: body)
            }
        }
    }
    public func agree(peer: Data) throws -> Data {
        try keyOperation {
            switch storage {
            case .enclave(_, let key):
                try key.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: peer))
                    .withUnsafeBytes { Data($0) }
            case .software(let keys): try keys.agree(peer: peer)
            }
        }
    }
}

enum HostInputs {
    static func now() -> String { Date.now.ISO8601Format() }
    static func entropy() throws -> Data {
        var bytes = Data(count: 32)
        let status = bytes.withUnsafeMutableBytes { buffer in
            guard let address = buffer.baseAddress else { return errSecParam }
            return SecRandomCopyBytes(kSecRandomDefault, buffer.count, address)
        }
        guard status == errSecSuccess else { throw KeyError.randomGenerationFailed(status) }
        return bytes
    }
}

// UniFFI callbacks require their declared error type; preserve platform failures as that type.
private func keyOperation<T>(_ operation: () throws -> T) throws -> T {
    do { return try operation() }
    catch let error as BindingError { throw error }
    catch { throw BindingError.KeyProvider(detail: error.localizedDescription) }
}

/// Public controller JSON and provider for one ordered combined-route part.
public struct CombinedRoutePart: Sendable {
    /// Complete controller in protocol JSON.
    public let controller: Data
    /// Key descriptor in protocol JSON; required for a WebAuthn get ceremony.
    public let descriptor: Data
    /// Host-owned private-key and ceremony operations.
    public let provider: any AsyncKeyProvider
    /// Create one part without retaining platform secrets in records.
    public init(controller: Data, descriptor: Data, provider: any AsyncKeyProvider) {
        self.controller = controller; self.descriptor = descriptor; self.provider = provider
    }
}
