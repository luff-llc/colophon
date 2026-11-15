import CryptoKit
import Foundation
import Security

/// Async providers can suspend for authentication, a KMS, or platform key-store work.
/// Raw signatures use r || s; WebAuthn assertions retain DER and original signed bytes.
/// Public points use X9.63 and raw ECDH returns 32 bytes.
///
/// Secrets come back as `SecretBytes` (memory the SDK owns and zeroes): a provider takes a platform
/// secret into one at the moment the platform hands it over, inside the platform's own `withUnsafeBytes`.
public protocol AsyncKeyProvider: Sendable {
    /// Select raw ES256 or WebAuthn get assertions.
    var form: KeyForm { get }
    /// Restrict get to this provider's credential and optionally evaluate the exact salt.
    func assert(challenge: String, prfSalt: Data?) async throws -> KeyAssertion?
    /// Evaluate an existing route; nil explicitly means unsupported or missing output.
    func prf(salt: Data) async throws -> SecretBytes?
    func publicKeys() async throws -> PublicKeys
    func sign(body: Data) async throws -> Data
    /// Raw 32-byte ECDH with this provider's agreement key.
    func sharedSecret(peer: Data) async throws -> SecretBytes
    /// The key as the protocol writes it (spec §3.1), the form every 0.5 export takes. Raw keys are
    /// described by `publicKeys()`; a passkey provider overrides it with its `rp`, credential and origins.
    func keyDescriptor() async throws -> KeyDescriptorView
}

/// A WebAuthn get result: the signed bytes exactly as the authenticator returned them, and the PRF
/// output (`results.first`) when a salt was evaluated, held as `SecretBytes`.
public struct KeyAssertion: Sendable {
    public let signature: Data
    public let authenticatorData: Data
    public let clientData: Data
    public let prf: SecretBytes?
    public init(signature: Data, authenticatorData: Data, clientData: Data, prf: SecretBytes?) {
        self.signature = signature; self.authenticatorData = authenticatorData; self.clientData = clientData; self.prf = prf
    }
    /// The assertion without its PRF output, as a signature step takes it.
    public var signatureValue: Signature { Signature(signature: signature, authenticatorData: authenticatorData, clientData: clientData) }
}

extension AsyncKeyProvider {
    public func keyDescriptor() async throws -> KeyDescriptorView {
        let keys = try await publicKeys()
        return KeyDescriptorView(form: .raw, signing: keys.signing, agreement: keys.agreement.isEmpty ? nil : keys.agreement,
                                 rp: nil, credential: nil, origins: [], authorityOrigins: [])
    }
}

extension AsyncKeyProvider {
    /// Raw providers need no WebAuthn ceremony.
    public var form: KeyForm { .raw }
    /// Unsupported assertions are explicit; callers must not derive a fallback secret.
    public func assert(challenge: String, prfSalt: Data?) async throws -> KeyAssertion? { nil }
    /// Exact WebAuthn results.first for an existing slot; nil means unsupported.
    public func prf(salt: Data) async throws -> SecretBytes? { nil }
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

/// Software keys: CryptoKit P-256 keys in process memory, for tests, previews and the simulator.
/// Production member and owner keys are Secure Enclave keys (`SecureEnclaveKeys`, `SecureEnclaveOwnerKey`).
/// No accessor exports a private scalar; a host that must persist one (only `KeychainKeys` in a debug or
/// simulator build does) creates the scalar itself as `SecretBytes` and passes it in.
public final class SoftwareKeys: KeyProvider, AsyncKeyProvider, Sendable {
    private let signing: P256.Signing.PrivateKey
    private let agreement: P256.KeyAgreement.PrivateKey

    public init() {
        signing = P256.Signing.PrivateKey()
        agreement = P256.KeyAgreement.PrivateKey()
    }

    /// Builds the keys from raw 32-byte scalars, read in place (pass `SecretBytes`; CryptoKit copies them into its own
    /// storage, which it zeroes when the key is released).
    public init<S: ContiguousBytes, A: ContiguousBytes>(signingPrivateKey: S, agreementPrivateKey: A) throws {
        signing = try P256.Signing.PrivateKey(rawRepresentation: signingPrivateKey)
        agreement = try P256.KeyAgreement.PrivateKey(rawRepresentation: agreementPrivateKey)
    }

    public func signingPublicKey() throws -> Data { signing.publicKey.x963Representation }
    public func agreementPublicKey() throws -> Data { agreement.publicKey.x963Representation }
    public func sign(body: Data) throws -> Data {
        try keyOperation { try signing.signature(for: body).rawRepresentation }
    }
    /// The 0.4 callback interface (generated) can only return `Data`: this one is allocated once, straight from
    /// CryptoKit's shared secret, and zeroed when it is released. The binding's own copy is Rust's to wipe.
    public func agree(peer: Data) throws -> Data {
        try keyOperation { try wipingData(copying: sharedSecretValue(peer: peer)) }
    }
    public func sharedSecret(peer: Data) async throws -> SecretBytes {
        try keyOperation { SecretBytes(copying: try sharedSecretValue(peer: peer)) }
    }
    private func sharedSecretValue(peer: Data) throws -> SharedSecret {
        try agreement.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: peer))
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

    /// Present only after explicit software fallback. It is never persisted by the SDK.
    public var softwareFallbackKeys: SoftwareKeys? {
        if case .software(let keys) = storage { keys } else { nil }
    }

    public var isHardwareBacked: Bool {
        if case .enclave = storage { true } else { false }
    }
    /// Nil when explicit software fallback was used. A reference is the enclave's encrypted handle, not a scalar:
    /// it is useless off this device's Secure Enclave.
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
    /// The 0.4 callback form; see `SoftwareKeys.agree(peer:)`.
    public func agree(peer: Data) throws -> Data {
        try keyOperation {
            switch storage {
            case .enclave(_, let key):
                try wipingData(copying: key.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: peer)))
            case .software(let keys): try keys.agree(peer: peer)
            }
        }
    }
    public func sharedSecret(peer: Data) async throws -> SecretBytes {
        switch storage {
        case .enclave(_, let key):
            return try keyOperation { SecretBytes(copying: try key.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: peer))) }
        case .software(let keys): return try await keys.sharedSecret(peer: peer)
        }
    }
}

/// A `Data` allocated once from `bytes` and zeroed when its last reference goes, for the generated 0.4 callback
/// interface only (it cannot take `SecretBytes`). Shared storage never arises: nobody mutates it.
func wipingData<Bytes: ContiguousBytes>(copying bytes: Bytes) -> Data {
    bytes.withUnsafeBytes { source in
        guard let from = source.baseAddress, source.count > 0 else { return Data() }
        let memory = UnsafeMutableRawPointer.allocate(byteCount: source.count, alignment: 16)
        memory.copyMemory(from: from, byteCount: source.count)
        return Data(bytesNoCopy: memory, count: source.count, deallocator: .custom { pointer, count in
            _ = memset_s(pointer, count, 0, count)
            pointer.deallocate()
        })
    }
}

/// Inputs for the 0.4 exports (`Library`, `StorageLibrary`). Those take `Data` in expression position; their secrets
/// are `wipingData` values (one allocation, zeroed on release), not `SecretBytes` lent per call as on the 0.5 path.
enum HostInputs {
    static func now() -> String { Date.now.ISO8601Format() }
    static func entropy() throws -> Data { wipingData(copying: try SecretBytes.random(count: 32)) }
}

extension KeyAssertion {
    /// The generated 0.4 record, its PRF output as a `wipingData` value.
    var legacyRecord: WebauthnResult {
        WebauthnResult(signature: signature, authenticatorData: authenticatorData, clientData: clientData, prf: prf.map { wipingData(copying: $0) })
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
