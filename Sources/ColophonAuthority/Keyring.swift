import ColophonCore
import CryptoKit
import Foundation

/// The authority in force after a library adopts a controller keyring (spec §6.6).
public struct Keyring: Sendable, Equatable {
  public var controllers: [String: Controller]
  public var threshold: Int
  /// How many distinct `recover` controllers a recovery change needs. Absent on the entry means 1.
  public var recoverThreshold: Int
  public var vault: PublicIdentity
  public var slots: [VaultSlot]

  public init(controllers: [String: Controller], threshold: Int, vault: PublicIdentity, slots: [VaultSlot],
    recoverThreshold: Int = 1)
  {
    self.controllers = controllers
    self.threshold = threshold
    self.recoverThreshold = recoverThreshold
    self.vault = vault
    self.slots = slots
  }

  /// Recovery may only add. Every current controller, both thresholds, the vault and every current
  /// slot stay as they are. Controller equality is the whole record, so a role or label change is
  /// a demotion. Slots may be reordered. An added controller may have `control` only when the
  /// current `recoverThreshold` is at least `threshold`. Otherwise it may hold only `approve`.
  func admitsRecovery(controllers: [Controller], threshold: Int, vault: PublicIdentity, slots: [VaultSlot],
    recoverThreshold: Int) -> Bool
  {
    guard threshold == self.threshold, vault == self.vault, recoverThreshold == self.recoverThreshold else { return false }
    var proposed: [String: Controller] = [:]
    for controller in controllers {
      guard proposed[controller.id] == nil else { return false }
      proposed[controller.id] = controller
    }
    for (id, controller) in self.controllers where proposed[id] != controller { return false }
    if self.recoverThreshold < self.threshold {
      for (id, controller) in proposed where self.controllers[id] == nil {
        guard controller.roles.contains("approve"), controller.roles.allSatisfy({ $0 == "approve" }) else { return false }
      }
    }
    var remaining = slots
    for slot in self.slots {
      guard let index = remaining.firstIndex(of: slot) else { return false }
      remaining.remove(at: index)
    }
    return true
  }
}

/// Checks a keyring entry's vocabulary and shape. Unknown vocabulary is a newer client; a keyring
/// this version understands but cannot apply breaks the chain.
enum KeyringRules {
  static func rejectUnknown(controllers: [Controller]?, slots: [VaultSlot]?, seq: Int) throws {
    if let controllers {
      for controller in controllers {
        let knownKind = Controller.kinds.contains(controller.kind)
        let knownRoles = controller.roles.allSatisfy { Controller.roles.contains($0) }
        guard knownKind, knownRoles else { throw ColophonError.newerAuthority(seq) }
      }
    }
    if let slots {
      for slot in slots {
        guard VaultSlot.kinds.contains(slot.kind) else { throw ColophonError.newerAuthority(seq) }
        for part in slot.parts ?? [] where !VaultSlotPart.kinds.contains(part.kind) {
          throw ColophonError.newerAuthority(seq)
        }
      }
    }
  }

  static func chainProblem(controllers: [Controller]?, threshold: Int?, slots: [VaultSlot]?, recoverThreshold: Int?, seq: Int)
    -> ColophonError?
  {
    guard let controllers, let threshold, let slots else { return .brokenAuthorityChain(seq) }
    var seen = Set<String>()
    var control = 0
    var recover = 0
    for controller in controllers {
      guard seen.insert(controller.id).inserted else { return .brokenAuthorityChain(seq) }
      guard controller.key.count == 65, (try? P256.Signing.PublicKey(x963Representation: controller.key)) != nil else {
        return .brokenAuthorityChain(seq)
      }
      if controller.kind == "webauthn" {
        guard let rpID = controller.rpID, !rpID.isEmpty else { return .brokenAuthorityChain(seq) }
      }
      if controller.roles.contains("control") { control += 1 }
      if controller.roles.contains("recover") { recover += 1 }
    }
    if thresholdFault(threshold: threshold, control: control, recover: recover, recoverThreshold: recoverThreshold) != nil {
      return .brokenAuthorityChain(seq)
    }
    for slot in slots where slotIncomplete(slot) { return .brokenAuthorityChain(seq) }
    return nil
  }

  static func validate(controllers: [Controller], threshold: Int, slots: [VaultSlot], recoverThreshold: Int?, seq: Int) throws {
    try rejectUnknown(controllers: controllers, slots: slots, seq: seq)
    guard !controllers.isEmpty else { throw ColophonError.malformed("keyring") }
    var seen = Set<String>()
    var control = 0
    var recover = 0
    for controller in controllers {
      guard seen.insert(controller.id).inserted else { throw ColophonError.malformed("keyring") }
      guard controller.key.count == 65, (try? P256.Signing.PublicKey(x963Representation: controller.key)) != nil else {
        throw ColophonError.malformed("controller key")
      }
      if controller.kind == "webauthn" {
        guard let rpID = controller.rpID, !rpID.isEmpty else { throw ColophonError.malformed("webauthn controller") }
      }
      if controller.roles.contains("control") { control += 1 }
      if controller.roles.contains("recover") { recover += 1 }
    }
    switch thresholdFault(threshold: threshold, control: control, recover: recover, recoverThreshold: recoverThreshold) {
    case .control: throw ColophonError.malformed("keyring")
    case .threshold: throw ColophonError.malformed("keyring threshold")
    case .recover: throw ColophonError.malformed("recover threshold")
    case nil: break
    }
    for slot in slots where slotIncomplete(slot) { throw ColophonError.malformed("vault slot") }
  }

  /// Explicit `recoverThreshold` of 1 is not canonical: writers omit it. Above 1 it cannot exceed
  /// the controllers that recover, and `threshold` must be at least that high, with at least that
  /// many `control` controllers. One key then cannot change a Two Keys ring.
  private enum ThresholdFault { case control, threshold, recover }

  private static func thresholdFault(threshold: Int, control: Int, recover: Int, recoverThreshold: Int?) -> ThresholdFault? {
    if control < 1 { return .control }
    if threshold < 1 || threshold > control { return .threshold }
    if let recoverThreshold, recoverThreshold <= 1 || recoverThreshold > recover { return .recover }
    let required = recoverThreshold ?? 1
    if required > 1, threshold < required || control < threshold { return .threshold }
    return nil
  }

  /// A slot this version understands but cannot open. Unknown kinds are rejected earlier.
  private static func slotIncomplete(_ slot: VaultSlot) -> Bool {
    switch slot.kind {
    case "sealed": return slot.recipient == nil || slot.sealed == nil
    case "prf": return slot.credential?.isEmpty != false || slot.salt?.count != 32 || slot.box == nil
    case "combined":
      guard let parts = slot.parts, parts.count >= 2, slot.box != nil else { return true }
      return parts.contains { part in
        switch part.kind {
        case "prf": part.credential?.isEmpty != false || part.salt?.count != 32
        case "sealed": part.recipient == nil || part.sealed == nil
        default: false
        }
      }
    default: return false
    }
  }
}
