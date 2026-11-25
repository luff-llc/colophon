import Foundation
import ColophonKit

/// Removing and replacing controllers, cosigned transitions, and the duties a removal leaves (spec §8.3, §8.4, §8.7).
extension SessionWorker {
    /// The steps of `removeController` and `replaceController`, for the tests that stop a call between two of them.
    enum KeyringStep: Sendable { case signed, recorded, slotted }
    struct KeyringStopped: Error {}
    func setKeyringStopForTests(_ step: KeyringStep?) { keyringStopForTests = step }
    func reachedKeyring(_ step: KeyringStep) throws { if keyringStopForTests == step { throw KeyringStopped() } }

    // MARK: Held keys

    /// The providers this host holds for owner operations: the owner controller, the recovery kit, then `extra`.
    func heldCustody(_ extra: [any AsyncKeyProvider]) async throws -> KeyCustody {
        var list: [any AsyncKeyProvider] = [configuration.ownerController]
        if let kit = configuration.recoveryKeys { list.append(kit) }
        return try await KeyCustody(list + extra)
    }
    func keyIDs(_ providers: [any AsyncKeyProvider]) async throws -> [String] {
        var out: [String] = []
        for p in providers { out.append(try await KeyCustody.keyID(of: p)) }
        return out
    }
    /// `base` with the providers of `extra` beside it (same IDs answer from `extra`).
    func merged(_ base: KeyCustody, _ extra: [any AsyncKeyProvider]) async throws -> KeyCustody {
        guard !extra.isEmpty else { return base }
        let more = try await KeyCustody(extra)
        return KeyCustody(providers: base.providers.merging(more.providers) { _, new in new })
    }

    /// Opens a controller engine as a key this host holds (the owner controller while it is one, else the first held
    /// current controller), unlocks it by a slot every route of which this host holds (the owner's own first), runs
    /// `body` with the custody and the identity's key ID, and locks it.
    func withControllers<T: Sendable>(_ extra: [any AsyncKeyProvider], unlock: Bool = true,
                                      _ body: (ColophonEngine, KeyCustody, String) async throws -> T) async throws -> T {
        guard let account = accountID else { throw SessionError.notReady }
        let custody = try await heldCustody(extra)
        let ownerID = try await KeyCustody.keyID(of: configuration.ownerController)
        func open(_ id: String) async throws -> ColophonEngine {
            try await ColophonEngine.open(label: "org.luff.colophon.owner", source: MediumSource(try storage()), listing: listed(try storage().listing()),
                identity: AccountIdentity(kind: .controller, id: id), account: account, namespaces: [], saved: nil,
                deviceKey: try configuration.deviceSecrets.key(for: account), nowMs: nowMs)
        }
        var engine = try await open(ownerID)
        do {
            var primary = ownerID
            let controllers = try await engine.run { try $0.controllers() }
            if !controllers.contains(where: { $0.id == ownerID }) {
                guard let other = controllers.first(where: { custody.holds($0.id) && !$0.provisional && $0.roles != [.sign] }) else {
                    throw SessionError.ownerRequired
                }
                await engine.lock()
                primary = other.id
                engine = try await open(primary)
            }
            if unlock { guard try await unlockHeld(engine, custody: custody, prefer: primary) else { throw SessionError.ownerRequired } }
            let result = try await body(engine, custody, primary)
            await engine.lock()
            return result
        } catch { await engine.lock(); throw error }
    }

    /// Opens a slot of the current vault that this host holds every route of, unless the engine already holds its seed.
    /// False when there is none.
    func unlockHeld(_ engine: ColophonEngine, custody: KeyCustody, prefer: String) async throws -> Bool {
        if try await engine.run({ try $0.isUnlocked() }) { return true }
        let slots = try await engine.run { try $0.slots() }
        let open = slots.filter { $0.controllers.allSatisfy { custody.holds($0.id) } }
        guard let slot = open.first(where: { $0.controllers.map(\.id) == [prefer] })
                ?? open.first(where: { $0.controllers.contains { $0.id == prefer } }) ?? open.first else { return false }
        let index = slot.index
        let inputs = try await engine.run { try $0.beginUnlockSlot(index: index) }
        let secrets = try await custody.answer(unlock: inputs)
        _ = try await engine.finishUnlockSlot(index: index, secrets: secrets)
        return true
    }

    /// The signers of a change: those the engine suggests from `primary` and `cosigners`, then every other cosigner that is
    /// a current `control` or `recover` controller, so a person holding several control keys signs one change with all of
    /// them and it can be a full set (§8.7).
    func signerSet(_ engine: ColophonEngine, primary: String, need: SignerNeed, cosigners: [String]) async throws -> [String] {
        let available = [primary] + cosigners.filter { $0 != primary }
        let chosen = try await engine.run { try $0.suggestSigners(available: available, need: need) }
        var set = chosen.isEmpty ? [primary] : chosen
        guard !cosigners.isEmpty else { return set }
        let controllers = try await engine.run { try $0.controllers() }
        for id in cosigners where !set.contains(id) {
            guard let c = controllers.first(where: { $0.id == id }), !c.provisional, !c.suspended,
                  c.roles.contains(.control) || c.roles.contains(.recover) else { continue }
            set.append(id)
        }
        return set
    }

    func removalFacts(_ engine: ColophonEngine, custody: KeyCustody) async throws -> RemovalAnalysis.Facts {
        let controllers = try await engine.run { try $0.controllers() }
        let slots = try await engine.run { try $0.slots() }
        let policy = try await engine.run { try $0.policy() }
        let ownerID = try? await KeyCustody.keyID(of: configuration.ownerController)
        return .init(controllers: controllers, slots: slots, policy: policy, held: Set(custody.providers.keys), ownerID: ownerID)
    }

    /// Records what is due (§8.7) and persists it, then makes sure the engine holds the current vault's seed (a rotation
    /// that activated moves it to a new vault).
    func recordDue(_ engine: ColophonEngine, custody: KeyCustody, primary: String) async throws {
        let at = nowMs
        _ = try await engine.run { try $0.advance(nowMs: at) }
        for due in try await engine.run({ try $0.recordDue() }) { try await persist(due, on: engine) }
        _ = try? await unlockHeld(engine, custody: custody, prefer: primary)
    }

    // MARK: Duties after a removal (§8.3)

    /// The namespaces owed a `rekey` at the verified head: those whose latest epoch is older than the latest vault change.
    /// Read from the stored authority entries and cached by head. Nil when an entry is not stored here.
    func rekeyOwed(head: UInt64, digest: String) -> [String]? {
        if let c = rekeyCache, c.head == head, c.digest == digest { return c.owed }
        var bodies: [UInt64: [String: Any]] = [:]
        if head > 0 {
            for seq in 1...head {
                let path = String(format: "authority/%08llu.json", seq)
                guard let bytes = try? storage().read(path), let body = RemovalAnalysis.envelopeBody(bytes) else { break }
                bodies[seq] = body
            }
        }
        let owed = RemovalAnalysis.rekeyOwed(bodies: bodies, head: head)
        rekeyCache = (head, digest, owed)
        return owed
    }
    func rekeyOwed(_ engine: ColophonEngine) async throws -> [String]? {
        let head = try await engine.run { try $0.headSeq() }
        let digest = try await engine.run { try $0.headDigest() }
        return rekeyOwed(head: head, digest: digest)
    }

    /// Builds `id`'s own slot of the current vault (a self-slot `keyring` entry, §8.4), with the possession assertion's
    /// PRF output when this call made one (§7.2), unless a slot already names only it.
    func buildOwnSlot(_ engine: ColophonEngine, custody: KeyCustody, id: String, label: String, possession: TransitionPossessionPRF?) async throws {
        guard !(try await engine.run { try $0.slots() }).contains(where: { $0.controllers.map(\.id) == [id] }) else { return }
        let ownerID = try? await KeyCustody.keyID(of: configuration.ownerController)
        let entrySigner = try await engine.run { engine in
            guard let ownerID, ownerID != id, try engine.policy().addThreshold == 1,
                  let held = try engine.controllers().first(where: { $0.id == ownerID }),
                  held.form == .raw, held.roles.contains(.control), !held.provisional, !held.suspended
            else { return id }
            return ownerID
        }
        let input = await possession?.input()
        let plan = SlotPlan(controllers: [id], label: label)
        let written = try await engine.execute(custody: custody) { engine in
            try withEntropy(32) {
                try engine.beginAddSlotWithSigners(entrySigners: [entrySigner], plan: plan, prfSalt: input?.salt, prfChallenge: input?.challenge, entropy: $0)
            }
        }
        try await persist(written, on: engine)
    }

    /// What a removal leaves this host to do (§8.3): while the vault is retiring, the `vault` entry, signed by a held
    /// `control` or `recover` controller (the longest-standing one, so one that was current at the removal's anchor), with
    /// every slot this host can build (sealed slots, and PRF or combined slots whose credentials it holds) and a slot of its
    /// own for each held controller that has none; then, after any rotation, the `rekey` of every namespace owed one; then
    /// `newKey`'s own slot. True when nothing is left that this host can see.
    func performKeyDuties(_ engine: ColophonEngine, custody: KeyCustody, primary: String,
                          newKey: (id: String, label: String)?, possession: TransitionPossessionPRF?) async throws -> Bool {
        let held = Set(custody.providers.keys)
        var retiring = try await engine.run { try $0.notices(shownSeq: 0, shownTransitions: [], localKeys: []) }.vaultRetiring
        if retiring {
            let controllers = try await engine.run { try $0.controllers() }
            let slots = try await engine.run { try $0.slots() }
            let form = Dictionary(controllers.map { ($0.id, $0.form) }, uniquingKeysWith: { a, _ in a })
            let candidates = controllers.filter {
                held.contains($0.id) && !$0.provisional && !$0.suspended && ($0.roles.contains(.control) || $0.roles.contains(.recover))
            }.sorted { ($0.addedSeq, $0.id) < ($1.addedSeq, $1.id) }
            if let signer = candidates.first, try await unlockHeld(engine, custody: custody, prefer: primary) {
                var plans = slots.filter { s in s.controllers.allSatisfy { form[$0.id] != .webauthn || held.contains($0.id) } }
                    .map { SlotPlan(controllers: $0.controllers.map(\.id), label: $0.label) }
                let named = Set(plans.flatMap(\.controllers))
                for c in controllers where held.contains(c.id) && !c.provisional && c.roles != [.sign] && !named.contains(c.id) {
                    plans.append(SlotPlan(controllers: [c.id], label: c.label))
                }
                let signerID = signer.id, chosen = plans
                let written = try await engine.execute(custody: custody) { engine in
                    try withEntropy(64) { try engine.beginRotateVault(signer: signerID, hasPlans: true, plans: chosen, entropy: $0) }
                }
                try await persist(written, on: engine)
                retiring = false
            }
        }
        if retiring { return false }
        var owedLeft = false
        if let owed = try await rekeyOwed(engine), !owed.isEmpty {
            if try await unlockHeld(engine, custody: custody, prefer: primary) {
                let controllers = try await engine.run { try $0.controllers() }
                let available = [primary] + controllers.filter { held.contains($0.id) && $0.id != primary }.map(\.id)
                let signers = try await engine.run { try $0.suggestSigners(available: available, need: .rekey) }
                let written = try await engine.execute(custody: custody) { engine in
                    try withEntropy(32) { try engine.beginRekey(namespaces: owed, signers: signers, entropy: $0) }
                }
                try await persist(written, on: engine)
            } else {
                owedLeft = true
            }
        }
        if let newKey {
            guard let c = try await engine.run({ try $0.controllers() }).first(where: { $0.id == newKey.id }), !c.provisional else { return false }
            try await buildOwnSlot(engine, custody: custody, id: newKey.id, label: newKey.label, possession: possession)
        }
        return !owedLeft
    }

    // MARK: Checking, removing, replacing

    func checkRemoval(_ id: String, replacingWith key: (any AsyncKeyProvider)?, roles: [ControllerRole], cosigners: [any AsyncKeyProvider]) async throws -> RemovalCheck {
        try await gated {
            if engine == nil { _ = try await reconcile() }
            var adding: (id: String, roles: [ControllerRole])?
            if let key { adding = (try await KeyCustody.keyID(of: key), roles) }
            let given = adding
            return try await withControllers(cosigners + (key.map { [$0] } ?? []), unlock: false) { owner, custody, _ in
                RemovalAnalysis.check(remove: id, adding: given, facts: try await removalFacts(owner, custody: custody))
            }
        }
    }

    /// Removes controller `id` by one transition (§8.7) signed by the owner and `cosigners`. When the removed key had a
    /// slot and this host can build every remaining slot again, the transition rotates the vault at once (a `vault`
    /// component with `previousVault`, §8.3); otherwise the vault retires at activation and this host writes the `vault`
    /// entry then. After activation it appends the `rekey` the rotation owes. Idempotent: what is done is read from the
    /// account, and a call after `.pending` or a crash signs nothing twice.
    func removeController(_ id: String, cosigners: [any AsyncKeyProvider]) async throws -> (KeyringChange, SessionSnapshot) {
        try await gated {
            if engine == nil { _ = try await reconcile() }
            let cosignerIDs = try await keyIDs(cosigners)
            var signedChange: (String, String)?
            let outcome = try await withControllers(cosigners) { owner, custody, primary -> KeyringChange in
                let held = Set(custody.providers.keys)
                var inFlight: [String] = []
                if try await owner.run({ try $0.controllers() }).contains(where: { $0.id == id }) {
                    let mine = try await owner.run { try $0.pending() }.filter { held.contains($0.by) && $0.removes.contains(id) }
                    if !mine.isEmpty {
                        inFlight = mine.map(\.digest)
                    } else {
                        let check = RemovalAnalysis.check(remove: id, adding: nil, facts: try await removalFacts(owner, custody: custody))
                        guard check.allowed else { throw SessionError.invalidCommand }
                        let signers = try await signerSet(owner, primary: primary, need: .control, cosigners: cosignerIDs)
                        let remove = check.removes, rotate = check.rotatesAtOnce
                        let written = try await owner.execute(custody: custody) { engine in
                            if rotate {
                                return try withEntropy(64) { try engine.beginRemoveController(remove: remove, keep: [], signers: signers, rule: .control, rotate: true, entropy: $0) }
                            }
                            return try engine.beginRemoveController(remove: remove, keep: [], signers: signers, rule: .control, rotate: false, entropy: Data())
                        }
                        try await persist(written, on: owner)
                        if let digest = Self.objectDigest(in: written.stores, prefix: "transitions/") {
                            inFlight.append(digest)
                            // A removal without a rotation can be signed again as it stands (§17.5); one with a rotation
                            // carries a seed this call held only once, so it is not kept for re-signing.
                            if !rotate, let json = Self.canonicalJSON(["keyring": ["remove": remove]]) { signedChange = (digest, json) }
                        }
                        try reachedKeyring(.signed)
                    }
                }
                try await recordDue(owner, custody: custody, primary: primary)
                try reachedKeyring(.recorded)
                if try await owner.run({ try $0.controllers() }).contains(where: { $0.id == id }) {
                    return .pending(transitions: Set(inFlight).sorted())
                }
                let done = try await performKeyDuties(owner, custody: custody, primary: primary, newKey: nil, possession: nil)
                return done ? .done : .pending(transitions: [])
            }
            if let (digest, json) = signedChange { try loadJournal(); journal.signedChanges[digest] = json; try saveJournal() }
            return (outcome, try await reconcile())
        }
    }

    /// Replaces controller `id` with `spec` (signed for by `key`). When this host keeps another current `control` or
    /// `recover` key with a slot it can open, ONE transition adds the new key (its possession proof, with PRF in the same
    /// assertion) and removes the old one; at activation the vault retires and this host writes the `vault` entry, which
    /// gives the new key its slot, then the `rekey`. Otherwise (the old key is the only one that can rotate the seed) the
    /// replacement is staged so there is never a moment with fewer ways in: the new key is added, builds its own slot once
    /// its activation is final, and only then the old key is removed with a rotation (signed by both, so a full set when
    /// they are every control key), then the `rekey`. Idempotent, as `removeController`.
    func replaceController(_ id: String, with spec: ControllerSpec, key: any AsyncKeyProvider, cosigners: [any AsyncKeyProvider]) async throws -> (KeyringChange, SessionSnapshot) {
        try await gated {
            if engine == nil { _ = try await reconcile() }
            let newID = try KeyCustody.keyID(of: spec)
            guard newID != id else { throw SessionError.invalidCommand }
            let requested = try JSONSerialization.jsonObject(with: Data(try accountControllerJson(controller: spec).utf8))
            let cosignerIDs = try await keyIDs(cosigners)
            var signedChanges: [(String, String)] = []
            let outcome = try await withControllers(cosigners + [key]) { owner, base, primary -> KeyringChange in
                var custody = base
                let held = Set(custody.providers.keys)
                var inFlight: [String] = []
                var possession: TransitionPossessionPRF?
                func mine() async throws -> [Pending] { try await owner.run { try $0.pending() }.filter { held.contains($0.by) } }
                func controllers() async throws -> [Controller] { try await owner.run { try $0.controllers() } }
                // A: the new key, in the keyring, pending, or added here (with the old key's removal when one transition is safe).
                if let present = try await controllers().first(where: { $0.id == newID }) {
                    guard present.label == spec.label, Set(present.roles) == Set(spec.roles) else { throw SessionError.invalidCommand }
                } else if let p = try await mine().first(where: { $0.adds.contains(newID) }) {
                    let change = pendingChange(p.digest)
                    let proposed = ((change?["keyring"] as? [String: Any])?["add"] as? [Any])?.first { Self.keyID(ofController: $0) == newID }
                    guard let proposed, Self.canonicalJSON(proposed) == Self.canonicalJSON(requested) else { throw SessionError.invalidCommand }
                    inFlight.append(p.digest)
                } else {
                    guard try await controllers().contains(where: { $0.id == id }) else { throw SessionError.invalidCommand }
                    let check = RemovalAnalysis.check(remove: id, adding: (newID, spec.roles), facts: try await removalFacts(owner, custody: custody))
                    guard check.allowed else { throw SessionError.invalidCommand }
                    if spec.key.form == .webauthn, key.supportsPRF {
                        possession = try TransitionPossessionPRF(controller: newID)
                        custody = KeyCustody(providers: custody.providers, possessionPRF: possession)
                    }
                    var keyring: [String: Any] = ["add": [requested]]
                    if check.inOneTransition { keyring["remove"] = check.removes }
                    guard let json = Self.canonicalJSON(["keyring": keyring]) else { throw SessionError.invalidCommand }
                    let signers = try await signerSet(owner, primary: primary, need: .control, cosigners: cosignerIDs)
                    let written = try await owner.execute(custody: custody) { try $0.beginTransition(changeJson: json, signers: signers, rule: .control, entropy: Data()) }
                    try await persist(written, on: owner)
                    if let digest = Self.objectDigest(in: written.stores, prefix: "transitions/") { inFlight.append(digest); signedChanges.append((digest, json)) }
                    try reachedKeyring(.signed)
                }
                try await recordDue(owner, custody: custody, primary: primary)
                try reachedKeyring(.recorded)
                guard let added = try await controllers().first(where: { $0.id == newID }), !added.provisional else {
                    return .pending(transitions: Set(inFlight).sorted())
                }
                // B: the new key's own slot, before the old key goes (while the vault retires, the `vault` entry builds it).
                let retiring = try await owner.run { try $0.notices(shownSeq: 0, shownTransitions: [], localKeys: []) }.vaultRetiring
                if !retiring {
                    try await buildOwnSlot(owner, custody: custody, id: newID, label: spec.label, possession: possession)
                    try reachedKeyring(.slotted)
                }
                // C: the old key, if still there (the staged replacement): removed with a rotation, signed by the new key too.
                if try await controllers().contains(where: { $0.id == id }) {
                    if let p = try await mine().first(where: { $0.removes.contains(id) }) {
                        inFlight.append(p.digest)
                    } else {
                        let check = RemovalAnalysis.check(remove: id, adding: nil, facts: try await removalFacts(owner, custody: custody))
                        guard check.allowed else { throw SessionError.invalidCommand }
                        let signers = try await signerSet(owner, primary: primary, need: .control, cosigners: cosignerIDs + [newID])
                        let remove = check.removes, rotate = check.rotatesAtOnce
                        let written = try await owner.execute(custody: custody) { engine in
                            if rotate {
                                return try withEntropy(64) { try engine.beginRemoveController(remove: remove, keep: [], signers: signers, rule: .control, rotate: true, entropy: $0) }
                            }
                            return try engine.beginRemoveController(remove: remove, keep: [], signers: signers, rule: .control, rotate: false, entropy: Data())
                        }
                        try await persist(written, on: owner)
                        if let digest = Self.objectDigest(in: written.stores, prefix: "transitions/") {
                            inFlight.append(digest)
                            if !rotate, let json = Self.canonicalJSON(["keyring": ["remove": remove]]) { signedChanges.append((digest, json)) }
                        }
                        try reachedKeyring(.signed)
                        try await recordDue(owner, custody: custody, primary: primary)
                    }
                    if try await controllers().contains(where: { $0.id == id }) { return .pending(transitions: Set(inFlight).sorted()) }
                }
                // D: what the removal leaves: the `vault` entry, the `rekey`, the new key's slot.
                let done = try await performKeyDuties(owner, custody: custody, primary: primary, newKey: (newID, spec.label), possession: possession)
                return done ? .done : .pending(transitions: [])
            }
            if !signedChanges.isEmpty {
                try loadJournal()
                for (digest, json) in signedChanges { journal.signedChanges[digest] = json }
                try saveJournal()
            }
            return (outcome, try await reconcile())
        }
    }

    /// The duties a removal left (the `vault` entry while the vault is retiring, the `rekey` after a rotation), done with
    /// the keys this host holds and `cosigners`.
    func completeKeyChanges(cosigners: [any AsyncKeyProvider]) async throws -> (KeyringChange, SessionSnapshot) {
        try await gated {
            if engine == nil { _ = try await reconcile() }
            let outcome = try await withControllers(cosigners) { owner, custody, primary -> KeyringChange in
                try await recordDue(owner, custody: custody, primary: primary)
                return try await performKeyDuties(owner, custody: custody, primary: primary, newKey: nil, possession: nil) ? .done : .pending(transitions: [])
            }
            return (outcome, try await reconcile())
        }
    }

    /// Gives `key` (a current controller with no slot of its own, for example after a rotation it was not present for) its
    /// own slot of the current vault, opened by another key this host holds.
    func restoreSlot(for key: any AsyncKeyProvider, label: String) async throws -> SessionSnapshot {
        try await gated {
            if engine == nil { _ = try await reconcile() }
            let id = try await KeyCustody.keyID(of: key)
            try await withControllers([key]) { owner, custody, _ in
                guard let c = try await owner.run({ try $0.controllers() }).first(where: { $0.id == id }), !c.provisional, c.roles != [.sign] else {
                    throw SessionError.invalidCommand
                }
                try await buildOwnSlot(owner, custody: custody, id: id, label: label, possession: nil)
            }
            return try await reconcile()
        }
    }
}
