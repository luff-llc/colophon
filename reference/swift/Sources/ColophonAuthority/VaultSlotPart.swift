import ColophonCore
import CryptoKit
import Foundation

/// One input to a combined vault slot (spec §6.6). Opening the slot needs every part's secret.
public struct VaultSlotPart: Codable, Sendable, Hashable {
  public static let kinds = ["prf", "sealed"]
  public static let partInfo = Data("colophon/vault-part/1".utf8)

  public let kind: String
  /// `prf`: WebAuthn credential ID.
  public let credential: Data?
  /// `prf`: the 32-byte PRF evaluation input.
  public let salt: Data?
  /// `sealed`: who can open this part.
  public let recipient: PublicIdentity?
  /// `sealed`: a random 32-byte part secret, sealed to `recipient`.
  public let sealed: SealedKey?
  /// Controller this part belongs to, when it is one.
  public let controller: String?

  public init(kind: String, credential: Data?, salt: Data?, recipient: PublicIdentity?, sealed: SealedKey?,
    controller: String?)
  {
    self.kind = kind
    self.credential = credential
    self.salt = salt
    self.recipient = recipient
    self.sealed = sealed
    self.controller = controller
  }

  /// The part secret is HKDF-SHA256(IKM = PRF output, salt = `salt`, info = `colophon/vault-part/1`).
  public static func prf(prfOutput: Data, salt: Data, credential: Data, controller: String?) throws
    -> (part: VaultSlotPart, secret: Data)
  {
    guard !prfOutput.isEmpty, salt.count == 32, !credential.isEmpty else { throw ColophonError.malformed("vault slot") }
    let part = VaultSlotPart(kind: "prf", credential: credential, salt: salt, recipient: nil, sealed: nil, controller: controller)
    return (part, derived(prfOutput: prfOutput, salt: salt))
  }

  /// Seals a fresh 32-byte part secret to `recipient`.
  public static func sealed(to recipient: PublicIdentity, controller: String?) throws -> (part: VaultSlotPart, secret: Data) {
    let secret = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
    let sealed = try SealedKey(SymmetricKey(data: secret), to: recipient)
    let part = VaultSlotPart(kind: "sealed", credential: nil, salt: nil, recipient: recipient, sealed: sealed,
      controller: controller)
    return (part, secret)
  }

  public func secret(with identity: some Identity) throws -> Data {
    guard kind == "sealed", let sealed, let recipient else { throw ColophonError.malformed("vault slot") }
    guard recipient == identity.publicIdentity else { throw ColophonError.vaultLocked }
    do {
      let opened = try identity.open(sealed).withUnsafeBytes { Data($0) }
      guard opened.count == 32 else { throw ColophonError.vaultLocked }
      return opened
    } catch let error as ColophonError {
      throw error
    } catch {
      throw ColophonError.vaultLocked
    }
  }

  public func secret(prfOutput: Data) throws -> Data {
    guard kind == "prf", let salt, salt.count == 32 else { throw ColophonError.malformed("vault slot") }
    guard !prfOutput.isEmpty else { throw ColophonError.vaultLocked }
    return Self.derived(prfOutput: prfOutput, salt: salt)
  }

  private static func derived(prfOutput: Data, salt: Data) -> Data {
    HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: prfOutput), salt: salt, info: partInfo, outputByteCount: 32)
      .withUnsafeBytes { Data($0) }
  }
}
