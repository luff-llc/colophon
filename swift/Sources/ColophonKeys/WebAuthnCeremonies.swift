import Foundation

/// AuthenticationServices credential family.
public enum CredentialKind: Sendable {
    /// A platform passkey.
    case passkey
    /// An external security key.
    case securityKey
}

/// Registration evidence. PRF outputs are deliberately absent: slots require a subsequent get.
public struct Registration: Sendable {
    /// Platform lookup identifier.
    public let credentialID: Data
    /// Attestation container passed unchanged to the core registration parser.
    public let attestationObject: Data
    /// Creates registration evidence without any registration-time PRF secret.
    public init(credentialID: Data, attestationObject: Data) {
        self.credentialID = credentialID
        self.attestationObject = attestationObject
    }
}

/// Original signed bytes and optional results.first from one get ceremony.
public struct AssertionResult: Sendable {
    /// Credential selected by the authenticator.
    public let credentialID: Data
    /// Original DER signature.
    public let signature: Data
    /// Original authenticator data.
    public let authenticatorData: Data
    /// Original clientDataJSON bytes.
    public let clientData: Data
    /// Exact WebAuthn PRF results.first, without a host-side transformation.
    public let prfOutput: Data?
    /// Creates evidence passed unchanged to ColophonKit for verification.
    public init(credentialID: Data, signature: Data, authenticatorData: Data, clientData: Data, prfOutput: Data?) {
        self.credentialID = credentialID
        self.signature = signature
        self.authenticatorData = authenticatorData
        self.clientData = clientData
        self.prfOutput = prfOutput
    }
}

/// Injectable ceremonies; test implementations never present AuthenticationServices UI.
public protocol WebAuthnCeremonies: Sendable {
    /// Whether external credentials can be used on this platform.
    var supportsSecurityKeys: Bool { get }
    /// Whether this platform supports PRF assertions for this credential family.
    func supportsPRF(kind: CredentialKind) -> Bool
    /// Registers an ES256 credential. Never evaluates PRF for slot construction.
    func register(kind: CredentialKind, rpID: String, userID: Data, userName: String, challenge: Data) async throws -> Registration
    /// Gets an assertion restricted to exactly one credential, optionally evaluating the exact salt.
    func assert(kind: CredentialKind, rpID: String, credential: Data, challenge: Data, prfSalt: Data?,
                requireVerification: Bool) async throws -> AssertionResult
}
