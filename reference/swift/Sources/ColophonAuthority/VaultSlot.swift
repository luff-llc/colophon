import ColophonCore
import CryptoKit
import Foundation

/// One way to open the vault seed (spec §6.6). `sealed` uses the same box as a namespace key.
/// `prf` wraps the seed with a WebAuthn PRF output. `combined` wraps it so every part is required.
public struct VaultSlot: Codable, Sendable, Hashable {
  public static let kinds = ["sealed", "prf", "combined"]
  public static let prfInfo = Data("colophon/vault-prf/1".utf8)
  public static let combinedInfo = Data("colophon/vault-combined/1".utf8)

  public let kind: String
  /// Controller this slot belongs to. Absent when the recipient is not a controller yet.
  public let controller: String?
  public let label: String
  public let recipient: PublicIdentity?
  public let sealed: SealedKey?
  public let credential: Data?
  public let salt: Data?
  public let box: Data?
  /// `combined`: the parts whose secrets, in this order, wrap `box`.
  public let parts: [VaultSlotPart]?

  public init(kind: String, controller: String?, label: String, recipient: PublicIdentity?, sealed: SealedKey?,
    credential: Data?, salt: Data?, box: Data?, parts: [VaultSlotPart]? = nil)
  {
    self.kind = kind
    self.controller = controller
    self.label = label
    self.recipient = recipient
    self.sealed = sealed
    self.credential = credential
    self.salt = salt
    self.box = box
    self.parts = parts
  }

  /// Seals the 32-byte vault seed to an app owner key or a recovery identity.
  public static func sealed(seed: Data, to recipient: PublicIdentity, controller: String?, label: String) throws -> VaultSlot {
    guard seed.count == 32 else { throw ColophonError.malformed("vault slot") }
    let sealed = try SealedKey(SymmetricKey(data: seed), to: recipient)
    return VaultSlot(kind: "sealed", controller: controller, label: label, recipient: recipient, sealed: sealed,
      credential: nil, salt: nil, box: nil)
  }

  /// Wraps the seed with HKDF-SHA256(IKM = PRF output, salt = `salt`, info = `colophon/vault-prf/1`).
  public static func prf(seed: Data, prfOutput: Data, salt: Data, credential: Data, controller: String?, label: String)
    throws -> VaultSlot
  {
    guard seed.count == 32, salt.count == 32, !credential.isEmpty, !prfOutput.isEmpty else {
      throw ColophonError.malformed("vault slot")
    }
    let wrapping = wrappingKey(prfOutput: prfOutput, salt: salt)
    guard let combined = try AES.GCM.seal(seed, using: wrapping).combined else { throw ColophonError.malformed("vault slot") }
    return VaultSlot(kind: "prf", controller: controller, label: label, recipient: nil, sealed: nil, credential: credential,
      salt: salt, box: combined)
  }

  /// Wraps the seed so opening needs every part secret, concatenated in `parts` order.
  /// The box key is HKDF-SHA256(IKM = that concatenation, salt = empty, info = `colophon/vault-combined/1`).
  public static func combined(seed: Data, parts: [(part: VaultSlotPart, secret: Data)], controller: String?, label: String)
    throws -> VaultSlot
  {
    guard seed.count == 32, parts.count >= 2, parts.allSatisfy({ $0.secret.count == 32 }) else {
      throw ColophonError.malformed("vault slot")
    }
    var material = Data()
    for part in parts { material.append(part.secret) }
    let wrapping = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: material), salt: Data(), info: combinedInfo,
      outputByteCount: 32)
    guard let box = try AES.GCM.seal(seed, using: wrapping).combined else { throw ColophonError.malformed("vault slot") }
    return VaultSlot(kind: "combined", controller: controller, label: label, recipient: nil, sealed: nil, credential: nil,
      salt: nil, box: box, parts: parts.map(\.part))
  }

  public func open(with identity: some Identity) throws -> VaultKey {
    guard kind == "sealed", let sealed, let recipient else { throw ColophonError.malformed("vault slot") }
    guard recipient == identity.publicIdentity else { throw ColophonError.vaultLocked }
    do {
      let opened = try identity.open(sealed).withUnsafeBytes { Data($0) }
      return try VaultKey(seed: opened)
    } catch let error as ColophonError where error == .malformed("vault key") {
      throw ColophonError.vaultLocked
    } catch let error as ColophonError {
      throw error
    } catch {
      throw ColophonError.vaultLocked
    }
  }

  public func open(prfOutput: Data) throws -> VaultKey {
    guard kind == "prf", let salt, salt.count == 32, let box, !prfOutput.isEmpty else { throw ColophonError.malformed("vault slot") }
    do {
      let opened = try AES.GCM.open(AES.GCM.SealedBox(combined: box), using: Self.wrappingKey(prfOutput: prfOutput, salt: salt))
      return try VaultKey(seed: opened)
    } catch let error as ColophonError where error == .malformed("vault key") {
      throw ColophonError.vaultLocked
    } catch {
      throw ColophonError.vaultLocked
    }
  }

  /// Opens a combined slot. The wrong number, length or order of secrets is `vaultLocked`.
  public func open(partSecrets: [Data]) throws -> VaultKey {
    guard kind == "combined", let parts, let box, parts.count >= 2 else { throw ColophonError.malformed("vault slot") }
    guard partSecrets.count == parts.count, partSecrets.allSatisfy({ $0.count == 32 }) else { throw ColophonError.vaultLocked }
    var material = Data()
    for secret in partSecrets { material.append(secret) }
    let wrapping = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: material), salt: Data(), info: Self.combinedInfo,
      outputByteCount: 32)
    do {
      let opened = try AES.GCM.open(AES.GCM.SealedBox(combined: box), using: wrapping)
      return try VaultKey(seed: opened)
    } catch let error as ColophonError where error == .malformed("vault key") {
      throw ColophonError.vaultLocked
    } catch {
      throw ColophonError.vaultLocked
    }
  }

  private static func wrappingKey(prfOutput: Data, salt: Data) -> SymmetricKey {
    HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: prfOutput), salt: salt, info: prfInfo, outputByteCount: 32)
  }
}
