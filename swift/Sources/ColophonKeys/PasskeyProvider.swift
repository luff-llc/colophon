import ColophonKit
import Foundation

/// A platform passkey controller. All assertions and slot evidence are verified by ColophonKit.
public struct PasskeyProvider: AsyncKeyProvider {
    private let base: WebAuthnProvider
    /// Core-parsed public descriptor to use in a controller or a PRF route.
    public var descriptor: KeyDescriptor { base.descriptor }
    /// WebAuthn assertions retain their original DER and signed bytes.
    public var form: KeyForm { .webauthn }
    public var supportsPRF: Bool { base.ceremonies.supportsPRF(kind: .passkey) }

    /// Uses a registered credential with injectable platform ceremonies.
    public init(descriptor: KeyDescriptor, ceremonies: any WebAuthnCeremonies = SystemWebAuthnCeremonies()) {
        base = WebAuthnProvider(kind: .passkey, descriptor: descriptor, ceremonies: ceremonies)
    }

    /// Registers an ES256 credential and returns the core-parsed descriptor, never a registration PRF output.
    public static func register(relyingParty: String, userID: Data, userName: String, challenge: Data,
                                authorityOrigins: [String] = [], ceremonies: any WebAuthnCeremonies = SystemWebAuthnCeremonies()) async throws -> KeyDescriptor {
        try await WebAuthnProvider.register(kind: .passkey, relyingParty: relyingParty, userID: userID,
                                           userName: userName, challenge: challenge, authorityOrigins: authorityOrigins, ceremonies: ceremonies)
    }

    /// Restricts get to this credential; use the core's fresh challenge and salt when building a slot.
    public func assert(challenge: String, prfSalt: Data?) async throws -> KeyAssertion? {
        try await base.assert(challenge: challenge, prfSalt: prfSalt)
    }
    /// Evaluates an existing slot's exact salt. Missing PRF fails explicitly without a fallback.
    public func prf(salt: Data) async throws -> SecretBytes? { try await base.prf(salt: salt) }
    /// Returns the signing point; WebAuthn has no agreement key, represented here by empty bytes.
    public func publicKeys() async throws -> PublicKeys { PublicKeys(signing: descriptor.signing, agreement: Data()) }
    /// WebAuthn requires assert so its authenticatorData and clientData cannot be discarded.
    public func sign(body: Data) async throws -> Data { throw KeyProviderError.unsupportedHere }
    /// WebAuthn credentials do not expose ECDH.
    public func sharedSecret(peer: Data) async throws -> SecretBytes { throw KeyProviderError.unsupportedHere }
    /// The protocol descriptor of this credential, with its `authorityOrigins`.
    public func keyDescriptor() async throws -> KeyDescriptorView { descriptor.view }
}

extension PasskeyProvider {
    /// The WebAuthn `user.id` to register with (spec §17.4): the UTF-8 account ID (64 hex characters)
    /// when the account exists, 32 random bytes when it does not. A lookup hint only: verifiers find a
    /// controller by `rp` and `credential` and never require it.
    public static func userID(account: String?) throws -> Data {
        if let account { return Data(account.utf8) }
        return try SecretBytes.random(count: 32).withUnsafeBytes { Data($0) }
    }
}

/// The passkeys of `rp` through AuthenticationServices, for a device that does not know their public keys yet
/// (Colophon 0.5.7): a joining or recovering device reads the history with one
/// (`ColophonJoin.readHistoryWithPasskey`). Every get requires user verification; with no credential it is
/// discoverable (any passkey of `rp` the platform lists), otherwise it allows only that credential. Once the history
/// names the passkey, restore it with `PasskeyProvider(descriptor: KeyDescriptor(passkey:))`.
public struct DiscoverablePasskeys: PasskeyAuthenticator {
    public let rp: String
    private let ceremonies: any WebAuthnCeremonies

    public init(rp: String, ceremonies: any WebAuthnCeremonies = SystemWebAuthnCeremonies()) {
        self.rp = rp; self.ceremonies = ceremonies
    }

    public func get(challenge: String, credential: Data?) async throws -> PasskeyGet {
        let encoded = challenge.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        guard let bytes = Data(base64Encoded: encoded + String(repeating: "=", count: (4 - encoded.count % 4) % 4)) else {
            throw KeyProviderError.unsupportedHere
        }
        let result: AssertionResult
        do {
            try Task.checkCancellation()
            if let credential {
                result = try await ceremonies.assert(kind: .passkey, rpID: rp, credential: credential, challenge: bytes, prfSalt: nil,
                                                     requireVerification: true)
            } else {
                result = try await ceremonies.assertDiscoverable(rpID: rp, challenge: bytes, requireVerification: true)
            }
            try Task.checkCancellation()
        } catch { throw KeyProviderError.map(error) }
        if let credential, result.credentialID != credential { throw KeyProviderError.credentialMissing }
        return PasskeyGet(credential: result.credentialID, signature: result.signature, authenticatorData: result.authenticatorData,
                          clientData: result.clientData)
    }
}
