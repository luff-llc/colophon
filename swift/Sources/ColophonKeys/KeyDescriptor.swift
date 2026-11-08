import ColophonKit
import Foundation

/// A WebAuthn descriptor produced by the Rust registration parser; contains no private material.
public struct KeyDescriptor: Sendable, Equatable {
    /// Canonical protocol JSON for ColophonKit keyring and slot APIs.
    public let json: Data
    /// Uncompressed P-256 signing point.
    public let signing: Data
    /// Caller-selected relying party.
    public let relyingParty: String
    /// Credential lookup identifier; the core verifies signatures independently of this hint.
    public let credential: Data

    /// Parses COSE and registration authenticator data exclusively through the Rust core.
    public init(attestationObject: Data, relyingParty: String) throws {
        let json = try parseRegistration(attestationObject: attestationObject, rp: relyingParty)
        struct Fields: Decodable { let signing: Data; let rp: String; let credential: Data }
        let fields = try JSONDecoder().decode(Fields.self, from: json)
        self.json = json
        signing = fields.signing
        self.relyingParty = fields.rp
        credential = fields.credential
    }
}
