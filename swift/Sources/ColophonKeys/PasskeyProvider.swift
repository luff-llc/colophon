import ColophonKit
import Foundation

/// A platform passkey controller. All assertions and slot evidence are verified by ColophonKit.
public struct PasskeyProvider: AsyncKeyProvider {
    private let base: WebAuthnProvider
    /// Core-parsed public descriptor to use in a controller or a PRF route.
    public var descriptor: KeyDescriptor { base.descriptor }
    /// WebAuthn assertions retain their original DER and signed bytes.
    public var form: KeyForm { .webauthn }

    /// Uses a registered credential with injectable platform ceremonies.
    public init(descriptor: KeyDescriptor, ceremonies: any WebAuthnCeremonies = SystemWebAuthnCeremonies()) {
        base = WebAuthnProvider(kind: .passkey, descriptor: descriptor, ceremonies: ceremonies)
    }

    /// Registers an ES256 credential and returns the core-parsed descriptor, never a registration PRF output.
    public static func register(relyingParty: String, userID: Data, userName: String, challenge: Data,
                                ceremonies: any WebAuthnCeremonies = SystemWebAuthnCeremonies()) async throws -> KeyDescriptor {
        try await WebAuthnProvider.register(kind: .passkey, relyingParty: relyingParty, userID: userID,
                                           userName: userName, challenge: challenge, ceremonies: ceremonies)
    }

    /// Restricts get to this credential; use the core's fresh challenge and salt when building a slot.
    public func assert(challenge: String, prfSalt: Data?) async throws -> WebauthnResult? {
        try await base.assert(challenge: challenge, prfSalt: prfSalt)
    }
    /// Evaluates an existing slot's exact salt. Missing PRF fails explicitly without a fallback.
    public func prf(salt: Data) async throws -> Data? { try await base.prf(salt: salt) }
    /// Returns the signing point; WebAuthn has no agreement key, represented here by empty bytes.
    public func publicKeys() async throws -> PublicKeys { PublicKeys(signing: descriptor.signing, agreement: Data()) }
    /// WebAuthn requires assert so its authenticatorData and clientData cannot be discarded.
    public func sign(body: Data) async throws -> Data { throw KeyProviderError.unsupportedHere }
    /// WebAuthn credentials do not expose ECDH.
    public func agree(peer: Data) async throws -> Data { throw KeyProviderError.unsupportedHere }
}
