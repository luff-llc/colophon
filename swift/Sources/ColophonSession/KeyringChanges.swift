import Foundation
import ColophonKit

/// The outcome of `removeController`, `replaceController` and `completeKeyChanges`.
public enum KeyringChange: Sendable, Equatable {
    /// The change is in force and nothing it leaves is owed by this host: the vault is not retiring, every namespace has an
    /// epoch introduced after the latest rotation, and a replacement key has its own slot.
    case done
    /// Not done yet. `transitions` are the digests of the pending transitions this host signed that carry the change
    /// (sorted; each was submitted to every home); empty when only an activation's finality, or a duty another host must
    /// do, is awaited. Call the same function again with the same arguments later to finish: it never signs anything twice.
    case pending(transitions: [String])
}

/// What removing (or replacing) a controller would do, judged before anything is signed (spec §6.2, §6.4, §8.3, §8.4).
/// `removeController` and `replaceController` refuse with `SessionError.invalidCommand` whenever `refusal` is set; the
/// `warnings` are what spec §6.4 says a host MUST say, in words, before it signs.
public struct RemovalCheck: Equatable, Sendable {
    public enum Refusal: String, Equatable, Sendable {
        /// The ID names no controller of the account.
        case notAController
        /// No controller with `control` would remain (§6.2).
        case lastControlKey
        /// Fewer `control` units than the threshold would remain (§6.2): the transition would be void.
        case noControlQuorum
        /// Fewer `recover` units than `recoverThreshold` would remain (§6.2): the transition would be void.
        case noRecoveryQuorum
        /// No remaining controller would have a slot: nobody could open the vault (§6.4).
        case noOpenableSlot
        /// The replacement key is already a controller, or the ID is the replacement key itself.
        case replacementPresent
    }
    public enum Warning: Equatable, Sendable {
        /// Losing any one more control unit would leave no control quorum (§6.4).
        case oneLossFromNoControlQuorum
        /// Only one remaining controller has a slot: losing it leaves no way to open the vault (§6.4).
        case oneLossFromNoOpenableSlot
        /// The `recover` controllers would form exactly one unit (§6.4).
        case singleRecoveryUnit
        /// These remaining controllers would have no slot in the vault after the change (§6.4, §8.3). Each needs to be
        /// used once more on a device that holds the vault (`ColophonSession.restoreSlot(for:label:)`).
        case keysWithoutSlot([String])
        /// The transition cannot rotate the vault at once (a remaining passkey is not present here): the vault retires at
        /// activation until a `vault` entry rotates it (§8.3), and the removed key can read what is written meanwhile.
        case vaultRetiresUntilRotated
        /// The removal also removes these `approve` or `sign` controllers the removed key added (§8.4 removal follow-up).
        case alsoRemoves([String])
        /// This device's owner key is removed: configure another owner controller for this session afterwards.
        case removesThisDevicesOwner

        /// Words a host may show before the person signs.
        public var words: String {
            switch self {
            case .oneLossFromNoControlQuorum: "After this change, losing one more key leaves nobody able to change the account's keys."
            case .oneLossFromNoOpenableSlot: "After this change, only one key can open your library. If you lose it, the library cannot be opened."
            case .singleRecoveryUnit: "After this change, one recovery key remains. A thief holding any one of your other keys could then block recovery; add a second recovery key."
            case .keysWithoutSlot: "Some of your keys will need to be used once more on a device that has your library before they can open it again."
            case .vaultRetiresUntilRotated: "Until your library is re-locked under a new key, the removed key can still read what is written. This app re-locks it as soon as the change takes effect."
            case .alsoRemoves: "Keys that the removed key added are removed with it."
            case .removesThisDevicesOwner: "This removes the key this device uses to manage your account. Choose another key for this device afterwards."
            }
        }
    }
    /// The controller asked about.
    public let controller: String
    /// Every controller the transition removes: the one asked about and what it added (§8.4).
    public let removes: [String]
    public let refusal: Refusal?
    /// The removal rotates the vault in the same transition (§8.3), so it never retires.
    public let rotatesAtOnce: Bool
    /// For a replacement: the new key is added and the old one removed by one transition. When false the replacement is
    /// staged (spec §8.3): the new key is added first, gets its own slot, and only then is the old one removed with a
    /// rotation, so there is never a moment with fewer ways in.
    public let inOneTransition: Bool
    public let warnings: [Warning]
    public var allowed: Bool { refusal == nil }
    public init(controller: String, removes: [String], refusal: Refusal?, rotatesAtOnce: Bool, inOneTransition: Bool, warnings: [Warning]) {
        self.controller = controller; self.removes = removes; self.refusal = refusal; self.rotatesAtOnce = rotatesAtOnce
        self.inOneTransition = inOneTransition; self.warnings = warnings
    }
}

/// The pure judgement behind `RemovalCheck`, over what the account states and what this host holds.
enum RemovalAnalysis {
    struct Facts {
        var controllers: [Controller]
        var slots: [SlotInfo]
        var policy: Policy
        /// Key IDs this host holds providers for.
        var held: Set<String>
        /// This device's owner key.
        var ownerID: String?
    }

    static func unit(_ c: Controller, holders: Bool) -> String { holders ? (c.holder ?? c.id) : c.id }

    /// `adding`: the replacement's ID and roles, counted as remaining (it is current once its activation is final).
    static func check(remove id: String, adding: (id: String, roles: [ControllerRole])?, facts f: Facts) -> RemovalCheck {
        func refused(_ r: RemovalCheck.Refusal) -> RemovalCheck {
            RemovalCheck(controller: id, removes: [id], refusal: r, rotatesAtOnce: false, inOneTransition: false, warnings: [])
        }
        guard f.controllers.contains(where: { $0.id == id }) else { return refused(.notAController) }
        if let adding, adding.id == id || f.controllers.contains(where: { $0.id == adding.id }) { return refused(.replacementPresent) }
        // The removal follow-up (§8.4): `approve` or `sign` keys the removed key added by immediate entries go with it.
        let planted = f.controllers.filter { c in
            c.id != id && c.addedBy.contains(id) && !c.roles.isEmpty && c.roles.allSatisfy { $0 == .approve || $0 == .sign }
        }.map(\.id)
        let removes = [id] + planted.sorted()
        let removed = Set(removes)
        let remaining = f.controllers.filter { !removed.contains($0.id) }
        let holders = f.policy.countByHolders
        var controlUnits = Set(remaining.filter { $0.roles.contains(.control) }.map { unit($0, holders: holders) })
        var recoverUnits = Set(remaining.filter { $0.roles.contains(.recover) }.map { unit($0, holders: holders) })
        if let adding {
            if adding.roles.contains(.control) { controlUnits.insert(adding.id) }
            if adding.roles.contains(.recover) { recoverUnits.insert(adding.id) }
        }
        if controlUnits.isEmpty { return refused(.lastControlKey) }
        if UInt64(controlUnits.count) < f.policy.threshold { return refused(.noControlQuorum) }
        if f.policy.recoverThreshold > 0, UInt64(recoverUnits.count) < f.policy.recoverThreshold { return refused(.noRecoveryQuorum) }
        let byID = Dictionary(f.controllers.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        let remainingSlots = f.slots.filter { s in !s.controllers.contains { removed.contains($0.id) } }
        if remainingSlots.isEmpty && adding == nil { return refused(.noOpenableSlot) }
        // A slot this host can build again for a new vault: every PRF route's credential is held (sealed routes need only
        // the public agreement key).
        func buildable(_ s: SlotInfo) -> Bool {
            s.controllers.allSatisfy { byID[$0.id]?.form != .webauthn || f.held.contains($0.id) }
        }
        let removesSlotted = f.slots.contains { s in s.controllers.contains { removed.contains($0.id) } }
        let inOne = adding.map { _ in oneTransitionReplacement(remove: removed, facts: f) } ?? false
        let rotates = adding == nil && removesSlotted && remainingSlots.allSatisfy(buildable)
        var warnings: [RemovalCheck.Warning] = []
        if !planted.isEmpty { warnings.append(.alsoRemoves(planted.sorted())) }
        if let ownerID = f.ownerID, removed.contains(ownerID) { warnings.append(.removesThisDevicesOwner) }
        if UInt64(controlUnits.count) <= f.policy.threshold { warnings.append(.oneLossFromNoControlQuorum) }
        if recoverUnits.count == 1 { warnings.append(.singleRecoveryUnit) }
        // Who has a slot once the change and its rotation are done.
        let slotted: Set<String>
        if rotates || adding != nil {
            // Rebuilt at once (or, for a replacement, in the `vault` entry or rotation this host writes, which also gives
            // the new key its slot).
            var s = Set(remainingSlots.filter(buildable).flatMap { $0.controllers.map(\.id) })
            if let adding { s.insert(adding.id) }
            slotted = s
        } else if removesSlotted {
            slotted = Set(remainingSlots.filter(buildable).flatMap { $0.controllers.map(\.id) })
        } else {
            slotted = Set(remainingSlots.flatMap { $0.controllers.map(\.id) })
        }
        let without = remaining.filter { !($0.roles == [.sign]) && !slotted.contains($0.id) }.map(\.id).sorted()
        if !without.isEmpty { warnings.append(.keysWithoutSlot(without)) }
        if slotted.count <= 1 { warnings.append(.oneLossFromNoOpenableSlot) }
        if adding == nil, removesSlotted, !rotates { warnings.append(.vaultRetiresUntilRotated) }
        if adding != nil, removesSlotted, inOne || !remainingSlots.allSatisfy(buildable) { warnings.append(.vaultRetiresUntilRotated) }
        return RemovalCheck(controller: id, removes: removes, refusal: nil, rotatesAtOnce: rotates, inOneTransition: inOne, warnings: warnings)
    }

    /// A replacement is one transition only when, after it activates, this host can still open the retiring vault and
    /// write its `vault` entry (§8.3): a held controller other than the removed ones, current, holding `control` or
    /// `recover`, with a slot this host can open. Otherwise the only keys that could rotate the seed are gone (a slot in
    /// a transition's `vault` component for a key the same transition adds is dropped at activation), so it is staged.
    static func oneTransitionReplacement(remove removed: Set<String>, facts f: Facts) -> Bool {
        f.controllers.contains { c in
            !removed.contains(c.id) && f.held.contains(c.id) && !c.provisional && !c.suspended
                && (c.roles.contains(.control) || c.roles.contains(.recover))
                && f.slots.contains { s in s.controllers.contains { $0.id == c.id } && s.controllers.allSatisfy { f.held.contains($0.id) } }
        }
    }

    /// The namespaces owed a `rekey` (§8.3): every namespace whose latest epoch was introduced before the latest vault
    /// change (a genesis, a `vault` entry, or an activation whose transition has a `vault` component). `entries` are the
    /// authority bodies by seq, as stored; nil when one is missing (unknown).
    static func rekeyOwed(bodies: [UInt64: [String: Any]], head: UInt64) -> [String]? {
        guard head > 0 else { return [] }
        var vaultSeq: UInt64 = 0
        var latest: [String: UInt64] = [:]
        for seq in 1...head {
            guard let body = bodies[seq] else { return nil }
            switch body["kind"] as? String {
            case "genesis":
                vaultSeq = seq
                for ns in (body["namespaces"] as? [String]) ?? [] where latest[ns] == nil { latest[ns] = 0 }
            case "vault":
                vaultSeq = seq
            case "activate":
                if let text = body["transition"] as? String, let inner = decodeEnvelopeBody(base64: text),
                   (inner["change"] as? [String: Any])?["vault"] != nil {
                    vaultSeq = seq
                }
            case "rekey", "revoke":
                for e in (body["epochs"] as? [[String: Any]]) ?? [] {
                    if let ns = e["namespace"] as? String { latest[ns] = seq }
                }
            default: break
            }
        }
        return latest.filter { $0.value < vaultSeq }.map(\.key).sorted()
    }

    /// The body of an envelope (`{"body": base64, …}`) given as its own JSON bytes.
    static func envelopeBody(_ bytes: Data) -> [String: Any]? {
        guard let envelope = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any],
              let text = envelope["body"] as? String, let body = Data(base64Encoded: text) else { return nil }
        return try? JSONSerialization.jsonObject(with: body) as? [String: Any]
    }
    /// The body of an embedded envelope (standard base64 of its canonical JSON, §2.2).
    static func decodeEnvelopeBody(base64 text: String) -> [String: Any]? {
        Data(base64Encoded: text).flatMap(envelopeBody)
    }
}
