import CryptoKit
import Foundation
import LocalAuthentication

public extension DeviceIdentity {
  /// For an identity that requires the person's presence, asks once and returns an identity that
  /// signs a whole action — every entry of an approval, say — without asking again. Other
  /// identities are returned unchanged.
  func unlocked(reason: String) async throws -> any Identity {
    guard case .enclave(let enclave) = self, enclave.requiresPresence else { return self }
    let context = LAContext()
    try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)
    return try UnlockedEnclaveIdentity(enclave, context: context)
  }
}

/// Enclave keys bound to an authenticated context. Lives only for one action.
final class UnlockedEnclaveIdentity: Identity, @unchecked Sendable {
  // Immutable after init; the context is kept alive for the keys and never mutated.
  private let context: LAContext
  private let signing: SecureEnclave.P256.Signing.PrivateKey
  private let agreement: SecureEnclave.P256.KeyAgreement.PrivateKey
  let publicIdentity: PublicIdentity

  init(_ identity: SecureEnclaveIdentity, context: LAContext) throws {
    self.context = context
    signing = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: identity.signingHandle,
      authenticationContext: context)
    agreement = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: identity.agreementHandle,
      authenticationContext: context)
    publicIdentity = PublicIdentity(signing: signing.publicKey.x963Representation,
      agreement: agreement.publicKey.x963Representation)
  }

  var custody: KeyCustody { .hardware }
  func sign(_ bytes: Data) throws -> Data { try signing.signature(for: bytes).rawRepresentation }
  func sharedSecret(with peer: P256.KeyAgreement.PublicKey) throws -> SharedSecret {
    try agreement.sharedSecretFromKeyAgreement(with: peer)
  }
}
