import CryptoKit
import Foundation

/// A principal's private keys: something that can sign and agree on secrets. Where the keys live
/// is an implementation choice — the Secure Enclave, a browser's non-extractable key store, or
/// software for agents and tests.
public protocol Identity: Sendable {
  var publicIdentity: PublicIdentity { get }
  /// Loads public keys without hiding a device-key failure, including through `any Identity`.
  func availablePublicIdentity() throws -> PublicIdentity
  func sign(_ bytes: Data) throws -> Data
  func sharedSecret(with peer: P256.KeyAgreement.PublicKey) throws -> SharedSecret
  /// Where the private keys are held, for display and for the member record.
  var custody: KeyCustody { get }
}

public enum KeyCustody: String, Codable, Sendable {
  /// Non-extractable hardware: Secure Enclave, TPM, StrongBox.
  case hardware
  /// A platform store that keeps the key non-extractable but not in dedicated hardware,
  /// such as a browser's IndexedDB `CryptoKey` with `extractable: false`.
  case platform
  /// Bytes in memory or a file. Agents, tests and recovery.
  case software
  /// Held by a service on behalf of a client that can't hold keys itself, such as a remote MCP
  /// client reached over OAuth. The grant names the operator; the member is only as trustworthy
  /// as that operator.
  case custodial
}

public extension Identity {
  var id: String { publicIdentity.id }

  /// A temporarily unavailable hardware key must not become a different member identity.
  func availablePublicIdentity() throws -> PublicIdentity {
    let identity = publicIdentity
    guard !identity.signing.isEmpty, !identity.agreement.isEmpty else {
      throw ColophonError.unavailable("The device identity")
    }
    return identity
  }

  func open(_ sealed: SealedKey) throws -> SymmetricKey {
    try sealed.open(with: self)
  }
}
