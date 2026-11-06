import CryptoKit
import Foundation

/// A namespace key sealed to one principal (spec §4): ephemeral P-256 ECDH, HKDF-SHA256 with the
/// recipient's signing key as salt and `colophon/sealed-key/1` as info, then AES-256-GCM
/// (`nonce || ciphertext || tag`).
public struct SealedKey: Codable, Hashable, Sendable {
  public let ephemeral: Data
  public let box: Data

  static let info = Data("colophon/sealed-key/1".utf8)

  public init(_ key: SymmetricKey, to recipient: PublicIdentity) throws {
    let ephemeralKey = P256.KeyAgreement.PrivateKey()
    let wrapping = try ephemeralKey.sharedSecretFromKeyAgreement(with: recipient.agreementKey)
      .hkdfDerivedSymmetricKey(using: SHA256.self, salt: recipient.signing, sharedInfo: Self.info, outputByteCount: 32)
    guard let combined = try AES.GCM.seal(key.withUnsafeBytes { Data($0) }, using: wrapping).combined else {
      throw ColophonError.malformed("sealed key")
    }
    ephemeral = ephemeralKey.publicKey.x963Representation
    box = combined
  }

  func open(with identity: some Identity) throws -> SymmetricKey {
    let sender = try P256.KeyAgreement.PublicKey(x963Representation: ephemeral)
    let wrapping = try identity.sharedSecret(with: sender)
      .hkdfDerivedSymmetricKey(using: SHA256.self, salt: identity.publicIdentity.signing, sharedInfo: Self.info,
        outputByteCount: 32)
    return SymmetricKey(data: try AES.GCM.open(AES.GCM.SealedBox(combined: box), using: wrapping))
  }
}
