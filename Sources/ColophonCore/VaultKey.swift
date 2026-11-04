import CryptoKit
import Foundation

/// HKDF-SHA256 derivation of a P-256 signing scalar and agreement scalar from a 32-byte secret.
/// The counter loop is the recovery kit's (§3.3); only the salt and the failure change.
enum P256Derivation {
  static func identity(secret: Data, salt: Data, failure: ColophonError) throws -> SoftwareIdentity {
    try SoftwareIdentity(signingScalar: scalar(secret, salt: salt, purpose: "signing", failure: failure),
      agreementScalar: scalar(secret, salt: salt, purpose: "agreement", failure: failure))
  }

  /// Each scalar is HKDF-SHA256(secret, salt, info "<purpose>/<counter>") for the first counter
  /// from 0 that yields a valid P-256 scalar. The agreement scalar uses the same check as signing.
  static func scalar(_ secret: Data, salt: Data, purpose: String, failure: ColophonError) throws -> Data {
    for counter in 0 ..< 256 {
      let bytes = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: secret), salt: salt,
        info: Data("\(purpose)/\(counter)".utf8), outputByteCount: 32).withUnsafeBytes { Data($0) }
      if (try? P256.Signing.PrivateKey(rawRepresentation: bytes)) != nil { return bytes }
    }
    throw failure
  }
}

/// The 32-byte seed whose agreement key namespace keys are sealed to. It is derived like a
/// recovery kit, with HKDF salt `colophon/vault/1`. The seed itself stays inside vault slots.
public struct VaultKey: Sendable, Equatable {
  public let seed: Data

  static let salt = Data("colophon/vault/1".utf8)

  public init() { seed = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) } }

  public init(seed: Data) throws {
    guard seed.count == 32 else { throw ColophonError.malformed("vault key") }
    self.seed = seed
  }

  public func identity() throws -> SoftwareIdentity {
    try P256Derivation.identity(secret: seed, salt: Self.salt, failure: .malformed("vault key"))
  }
}
