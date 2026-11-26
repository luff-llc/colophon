import Foundation

/// One WebAuthn get, as a platform passkey API returns it: the credential's raw ID and the exact signed bytes (DER
/// signature, authenticator data, client data JSON).
public struct PasskeyGet: Sendable {
    public let credential: Data
    public let signature: Data
    public let authenticatorData: Data
    public let clientData: Data
    public init(credential: Data, signature: Data, authenticatorData: Data, clientData: Data) {
        self.credential = credential; self.signature = signature; self.authenticatorData = authenticatorData; self.clientData = clientData
    }
}

/// The passkeys of one relying party, for a device that may not know their public keys yet (Colophon 0.5.7): a joining
/// or recovering device that holds no history. Apple platforms: `DiscoverablePasskeys` in ColophonKeys.
public protocol PasskeyAuthenticator: Sendable {
    /// The relying-party ID the passkeys belong to.
    var rp: String { get }
    /// A WebAuthn get over `challenge` (unpadded base64url), user verification required: for any passkey of `rp` (a
    /// discoverable get) when `credential` is nil, else only that credential.
    func get(challenge: String, credential: Data?) async throws -> PasskeyGet
}
