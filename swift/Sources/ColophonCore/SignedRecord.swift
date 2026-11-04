import Foundation

/// A WebAuthn assertion over a signed record. `clientData` is the exact clientDataJSON bytes.
public struct Assertion: Codable, Sendable, Equatable {
  public let authenticatorData: Data
  public let clientData: Data

  public init(authenticatorData: Data, clientData: Data) {
    self.authenticatorData = authenticatorData
    self.clientData = clientData
  }
}

/// A stored record (spec §2): the exact body bytes and a signature over them. A P-256 identity
/// signs raw `r || s` (64 bytes). A WebAuthn controller attaches `assertion` and a DER signature
/// (§6.6). Absent optional fields are omitted, so a 0.1 record's bytes do not change.
public struct SignedRecord: Codable, Sendable {
  public struct Cosignature: Codable, Sendable {
    public let signer: String
    public let signature: Data
    public var assertion: Assertion?
    public init(signer: String, signature: Data, assertion: Assertion? = nil) {
      self.signer = signer
      self.signature = signature
      self.assertion = assertion
    }
  }

  public let body: Data
  public let signature: Data
  /// Present only for a WebAuthn signature.
  public var assertion: Assertion?
  /// Extra signatures over the same body, for entries a quorum or a keyring threshold must sign.
  public var cosignatures: [Cosignature]?

  public init(body: Data, signature: Data, assertion: Assertion? = nil) {
    self.body = body
    self.signature = signature
    self.assertion = assertion
  }

  public init(signing body: Data, with identity: some Identity) throws {
    self.body = body
    signature = try identity.sign(body)
  }
}
