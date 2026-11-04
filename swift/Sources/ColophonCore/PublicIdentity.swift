import CryptoKit
import Foundation

/// The public half of any principal: root, recovery key, device, app, web client or agent
/// (spec §3). Both keys are P-256, encoded X9.63 uncompressed (65 bytes), which is WebCrypto's
/// "raw" EC public key format.
public struct PublicIdentity: Codable, Hashable, Sendable {
  public let signing: Data
  public let agreement: Data

  public init(signing: Data, agreement: Data) {
    self.signing = signing
    self.agreement = agreement
  }

  /// First 16 bytes of SHA-256 over the signing key, lowercase hex.
  public var id: String { String(Canonical.digest(signing).prefix(32)) }

  public func verify(_ signature: Data, over bytes: Data) -> Bool {
    guard let key = try? P256.Signing.PublicKey(x963Representation: signing),
      let parsed = try? P256.Signing.ECDSASignature(rawRepresentation: signature)
    else { return false }
    return key.isValidSignature(parsed, for: bytes)
  }

  public func verify(_ record: SignedRecord) -> Bool { verify(record.signature, over: record.body) }

  var agreementKey: P256.KeyAgreement.PublicKey {
    get throws { try P256.KeyAgreement.PublicKey(x963Representation: agreement) }
  }
}
