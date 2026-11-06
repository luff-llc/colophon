import CryptoKit
import Foundation
import LocalAuthentication

/// Keys that never leave this device's Secure Enclave. The stored representation is an
/// encrypted handle that only this device's enclave can use; copying it elsewhere is useless.
public struct SecureEnclaveIdentity: Identity, Codable {
  let signingHandle: Data
  let agreementHandle: Data
  /// Whether every signature needs Face ID, Touch ID or the device passcode.
  public let requiresPresence: Bool

  public static var isAvailable: Bool { SecureEnclave.isAvailable }

  /// Creates new enclave keys. Root identities should require presence, so approving,
  /// revoking and handing over always needs the person; everyday member keys shouldn't.
  public init(requiresPresence: Bool) throws {
    guard SecureEnclave.isAvailable else { throw ColophonError.unavailable("The Secure Enclave") }
    let flags: SecAccessControlCreateFlags = requiresPresence ? [.privateKeyUsage, .userPresence] : [.privateKeyUsage]
    var error: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &error) else {
      throw error.map { $0.takeRetainedValue() as Error } ?? ColophonError.unavailable("Key access control")
    }
    signingHandle = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access).dataRepresentation
    agreementHandle = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access).dataRepresentation
    self.requiresPresence = requiresPresence
  }

  public var custody: KeyCustody { .hardware }

  public var publicIdentity: PublicIdentity {
    let signing = (try? SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: signingHandle))?.publicKey
      .x963Representation ?? Data()
    let agreement = (try? SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: agreementHandle))?.publicKey
      .x963Representation ?? Data()
    return PublicIdentity(signing: signing, agreement: agreement)
  }

  public func availablePublicIdentity() throws -> PublicIdentity {
    try Self.readPublicIdentity(signing: {
      try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: signingHandle).publicKey.x963Representation
    }, agreement: {
      try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: agreementHandle).publicKey.x963Representation
    })
  }

  /// The injected readers let software fixtures exercise the same error boundary without hardware keys.
  static func readPublicIdentity(signing: () throws -> Data, agreement: () throws -> Data) throws -> PublicIdentity {
    do {
      return try PublicIdentity(signing: signing(), agreement: agreement())
    } catch {
      if let failure = DeviceKeyFailure(error) { throw failure }
      throw error
    }
  }

  public func sign(_ bytes: Data) throws -> Data {
    try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: signingHandle).signature(for: bytes).rawRepresentation
  }

  public func sharedSecret(with peer: P256.KeyAgreement.PublicKey) throws -> SharedSecret {
    try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: agreementHandle).sharedSecretFromKeyAgreement(with: peer)
  }
}
