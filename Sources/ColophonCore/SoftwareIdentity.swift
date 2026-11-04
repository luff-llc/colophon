import CryptoKit
import Foundation

/// Keys held as bytes. Used for agents, tests, devices without a Secure Enclave, and the
/// recovery key derived from a kit.
public struct SoftwareIdentity: Identity, Codable {
  let signingKey: Data
  let agreementKey: Data

  public init() {
    signingKey = P256.Signing.PrivateKey().rawRepresentation
    agreementKey = P256.KeyAgreement.PrivateKey().rawRepresentation
  }

  /// From raw 32-byte private scalars.
  public init(signingScalar: Data, agreementScalar: Data) throws {
    _ = try P256.Signing.PrivateKey(rawRepresentation: signingScalar)
    _ = try P256.KeyAgreement.PrivateKey(rawRepresentation: agreementScalar)
    signingKey = signingScalar
    agreementKey = agreementScalar
  }

  public var custody: KeyCustody { .software }

  public var publicIdentity: PublicIdentity {
    // Both scalars were validated when this value was made.
    let signing = (try? P256.Signing.PrivateKey(rawRepresentation: signingKey))?.publicKey.x963Representation ?? Data()
    let agreement = (try? P256.KeyAgreement.PrivateKey(rawRepresentation: agreementKey))?.publicKey.x963Representation ?? Data()
    return PublicIdentity(signing: signing, agreement: agreement)
  }

  public func sign(_ bytes: Data) throws -> Data {
    try P256.Signing.PrivateKey(rawRepresentation: signingKey).signature(for: bytes).rawRepresentation
  }

  public func sharedSecret(with peer: P256.KeyAgreement.PublicKey) throws -> SharedSecret {
    try P256.KeyAgreement.PrivateKey(rawRepresentation: agreementKey).sharedSecretFromKeyAgreement(with: peer)
  }
}
