import Foundation
import Testing
import ColophonKit
import ColophonSavedKit
@testable import ColophonSession

/// `removeController`, `replaceController`, `completeKeyChanges`, `restoreSlot` and cosigned transitions (spec §8.3, §8.7).
/// Accounts without a home record every transition at once; the journeys with a home run against the real relay
/// (`RelayHome`) on one clock the test moves.
@MainActor @Suite(.serialized) struct KeyringChangeTests {
    nonisolated private static let t0: Int64 = 1_795_165_200_000 // 2026-11-20T09:00:00Z

    private final class Once: @unchecked Sendable {
        private let lock = NSLock()
        private var done = false
        func run(_ body: () throws -> Void) rethrows { try lock.withLock { if !done { try body(); done = true } } }
    }
    private func appointable(_ relay: RelayHome) -> HomeConfiguration {
        let once = Once()
        return HomeConfiguration(endpoint: URL(string: relay.base + "/")!, label: "Relay home", request: { account in
            try once.run { try relay.start(account: account) }
            return try relay.memberRequest(account: account)
        }, transport: relay.transport())
    }
    private func describe(_ device: Device) -> String {
        "phase \(device.session.phase) error \(device.session.lastError ?? "-") issues \(device.session.homeIssues) faults \(device.session.homeFaults.map { "\($0.fault.kind)" })"
    }
    private func settle(_ session: ColophonSession, _ relay: RelayHome, _ clock: TestClock) async throws {
        for _ in 0..<6 {
            clock.advance(1000)
            let ok = await session.syncNow()
            try await relay.tick()
            if ok, session.homeIssues.isEmpty, session.homeFaults.isEmpty { return }
        }
        Issue.record("did not settle: phase \(session.phase) error \(session.lastError ?? "-") issues \(session.homeIssues) faults \(session.homeFaults.map { "\($0.fault.kind) \($0.fault.status.map(String.init) ?? "") \($0.fault)" })")
    }
    private func items(_ session: ColophonSession) async throws -> Int {
        try await SavedStore(session: session).load(ItemsQuery(limit: 50)).get().total
    }
    private func save(_ session: ColophonSession, _ id: String) async throws {
        try await session.perform(try .saveLink(id: id, url: URL(string: "https://example.org/\(id)")!, title: id), observed: session.observedRevision)
    }
    private func controllerEngine(_ medium: MemoryMedium, id: String, account: String, clock: TestClock) async throws -> ColophonEngine {
        try await ColophonEngine.open(label: "test.controller", source: MediumSource(medium), listing: medium.listing().map { ListedPath(path: $0.path, version: $0.version) },
            identity: AccountIdentity(kind: .controller, id: id), account: account, namespaces: [], saved: nil,
            deviceKey: SecretBytes(copying: Data(repeating: 0x33, count: 32)), nowMs: clock.now)
    }
    /// The account as it is stated: controllers, slots, the latest epoch of `reading.saved`.
    private func state(_ device: Device, as id: String, clock: TestClock) async throws -> (controllers: [Controller], slots: [SlotInfo], epoch: UInt64) {
        let account = try #require(device.session.libraryID)
        let engine = try await controllerEngine(device.medium, id: id, account: account, clock: clock)
        let controllers = try await engine.run { try $0.controllers() }
        let slots = try await engine.run { try $0.slots() }
        let epoch = try await engine.run { try $0.latestEpoch(namespace: "reading.saved") }
        await engine.lock()
        return (controllers, slots, epoch)
    }
    /// `key` opens its own slot with nothing else.
    private func unlocksAlone(_ device: Device, key: any AsyncKeyProvider, clock: TestClock) async throws -> Bool {
        let account = try #require(device.session.libraryID)
        let id = try await KeyCustody.keyID(of: key)
        let engine = try await controllerEngine(device.medium, id: id, account: account, clock: clock)
        defer { Task { await engine.lock() } }
        guard let slot = try await engine.run({ try $0.slots() }).first(where: { $0.controllers.map(\.id) == [id] }) else { return false }
        let inputs = try await engine.run { try $0.beginUnlockSlot(index: slot.index) }
        _ = try await engine.finishUnlockSlot(index: slot.index, secrets: try await KeyCustody([key]).answer(unlock: inputs))
        return try await engine.run { try $0.isUnlocked() }
    }
    private func transitions(_ medium: MemoryMedium) -> Int { medium.snapshot().keys.filter { $0.hasPrefix("transitions/") }.count }
    /// The kinds of the stored authority entries, in seq order, with whether an `activate`'s transition rotates the vault.
    private func kinds(_ medium: MemoryMedium) -> [String] {
        medium.snapshot().filter { $0.key.hasPrefix("authority/") }.sorted { $0.key < $1.key }.compactMap { _, bytes in
            guard let body = RemovalAnalysis.envelopeBody(bytes), let kind = body["kind"] as? String else { return nil }
            if kind == "activate", let t = body["transition"] as? String, let inner = RemovalAnalysis.decodeEnvelopeBody(base64: t),
               (inner["change"] as? [String: Any])?["vault"] != nil { return "activate+vault" }
            return kind
        }
    }
    /// A second raw control key, added by a transition (final at once without a home), with its own slot.
    private func addSecondControlKey(_ device: Device) async throws -> (SoftwareKeys, String) {
        let other = SoftwareKeys()
        try await device.session.addController(other, label: "Second", roles: [.control], immediate: false)
        await device.session.refresh()
        try await device.session.restoreSlot(for: other, label: "Second")
        return (other, try await KeyCustody.keyID(of: other))
    }

    /// A removal of a slotted key rotates the vault in the same transition: the removed key holds no slot of the new vault
    /// and every namespace gets an epoch introduced after the rotation, so it opens nothing written from now on.
    @Test func removingAKeyRotatesAtOnceAndRekeys() async throws {
        let clock = TestClock(Self.t0)
        let first = Device(createWithoutHome: true, clock: { clock.date })
        await first.session.create()
        try #require(first.session.phase == .ready, "\(describe(first))")
        try await save(first.session, "a")
        let ownerID = try await KeyCustody.keyID(of: first.owner)
        let (_, otherID) = try await addSecondControlKey(first)
        let before = try await state(first, as: ownerID, clock: clock)
        #expect(before.controllers.count == 2 && before.slots.contains { $0.controllers.map(\.id) == [otherID] })

        let check = try await first.session.checkRemoval(otherID)
        #expect(check.allowed && check.rotatesAtOnce && check.removes == [otherID], "\(check)")
        #expect(!check.warnings.contains(.vaultRetiresUntilRotated))
        let outcome = try await first.session.removeController(otherID)
        #expect(outcome == .done)

        let after = try await state(first, as: ownerID, clock: clock)
        #expect(after.controllers.map(\.id) == [ownerID])
        #expect(!after.slots.contains { $0.controllers.contains { $0.id == otherID } }, "no slot of the new vault names the removed key")
        #expect(after.epoch > before.epoch, "a rekey after the rotation")
        let k = kinds(first.medium)
        #expect(k.contains("activate+vault"), "the removal carried the vault component: \(k)")
        #expect(k.last == "rekey", "\(k)")
        #expect(!first.session.duties.vaultRotationOwed && first.session.duties.rekeyOwed.isEmpty && first.session.duties.keysWithoutSlot.isEmpty)
        try await save(first.session, "b")
        #expect(try await items(first.session) == 2)
        #expect(try await unlocksAlone(first, key: first.owner, clock: clock))
    }

    /// Removing the last control key is refused before anything is signed.
    @Test func theLastControlKeyCannotBeRemoved() async throws {
        let clock = TestClock(Self.t0)
        let first = Device(createWithoutHome: true, clock: { clock.date })
        await first.session.create()
        let ownerID = try await KeyCustody.keyID(of: first.owner)
        let check = try await first.session.checkRemoval(ownerID)
        #expect(check.refusal == .lastControlKey)
        let files = first.medium.snapshot().count
        await #expect(throws: SessionError.invalidCommand) { try await first.session.removeController(ownerID) }
        #expect(first.medium.snapshot().count == files && transitions(first.medium) == 0, "nothing signed")
        #expect(try await first.session.checkRemoval("00000000000000000000000000000000").refusal == .notAController)
    }

    /// The only passkey, the account's root, is replaced end to end: the new passkey is added, builds its own slot, and
    /// then the old one is removed with a rotation that both sign. The new passkey alone unlocks the account, and a
    /// device configured with it as its owner works.
    @Test func theOnlyPasskeyIsReplaced() async throws {
        let clock = TestClock(Self.t0)
        let old = TestPasskey(credential: Data([1, 1, 1]))
        let first = Device(createWithoutHome: true, ownerKey: old, clock: { clock.date })
        await first.session.create()
        try #require(first.session.phase == .ready, "\(describe(first))")
        try await save(first.session, "a")
        let oldID = try await KeyCustody.keyID(of: old)
        let next = TestPasskey(credential: Data([2, 2, 2]))
        let nextID = try await KeyCustody.keyID(of: next)
        let epoch = try await state(first, as: oldID, clock: clock).epoch

        let check = try await first.session.checkRemoval(oldID, replacingWith: next)
        #expect(check.allowed && !check.inOneTransition, "staged: the old key is the only one that can rotate the seed: \(check)")
        #expect(check.warnings.contains(.removesThisDevicesOwner))
        let outcome = try await first.session.replaceController(oldID, with: next, label: "New passkey")
        #expect(outcome == .done)

        let after = try await state(first, as: nextID, clock: clock)
        #expect(after.controllers.map(\.id) == [nextID])
        #expect(after.controllers.first?.roles == [.control, .recover])
        #expect(after.slots.map { $0.controllers.map(\.id) } == [[nextID]])
        #expect(after.epoch > epoch)
        #expect(kinds(first.medium).contains("activate+vault"))
        #expect(try await unlocksAlone(first, key: next, clock: clock), "the new passkey unlocks alone")

        // The same device, configured with the new passkey as its owner.
        let again = Device(medium: first.medium, member: first.member, ownerKey: next, clock: { clock.date })
        await again.session.restore()
        #expect(again.session.phase == .ready, "\(describe(again))")
        #expect(try await items(again.session) == 1)
        #expect(try await again.session.checkRemoval(nextID).refusal == .lastControlKey)
        #expect(again.session.duties.rekeyOwed.isEmpty && !again.session.duties.vaultRotationOwed)
    }

    /// A bare `keyring.remove` (a removal another host made without a rotation) leaves the vault retiring: the session
    /// shows the duty and `completeKeyChanges` writes the `vault` entry and the `rekey`.
    @Test func aRetiringVaultIsRotatedByThisHost() async throws {
        let clock = TestClock(Self.t0)
        let first = Device(createWithoutHome: true, clock: { clock.date })
        await first.session.create()
        try await save(first.session, "a")
        let ownerID = try await KeyCustody.keyID(of: first.owner)
        let (_, otherID) = try await addSecondControlKey(first)
        let epoch = try await state(first, as: ownerID, clock: clock).epoch
        _ = try await first.session.proposeTransition("{\"keyring\":{\"remove\":[\"\(otherID)\"]}}")
        await first.session.refresh()
        #expect(first.session.duties.vaultRotationOwed, "the vault is retiring")
        #expect(try await state(first, as: ownerID, clock: clock).epoch == epoch)

        let outcome = try await first.session.completeKeyChanges()
        #expect(outcome == .done)
        #expect(!first.session.duties.vaultRotationOwed && first.session.duties.rekeyOwed.isEmpty)
        let after = try await state(first, as: ownerID, clock: clock)
        #expect(after.epoch > epoch)
        let k = kinds(first.medium)
        #expect(Array(k.suffix(2)) == ["vault", "rekey"], "\(k)")
        #expect(try await unlocksAlone(first, key: first.owner, clock: clock))
        try await save(first.session, "b")
        #expect(try await items(first.session) == 2)
    }

    /// A removal stopped once it was recorded (a crash before the rekey) shows the owed rekey, and calling it again
    /// finishes with the rekey and signs no second transition.
    @Test func aStoppedRemovalOwesItsRekeyUntilCalledAgain() async throws {
        let clock = TestClock(Self.t0)
        let first = Device(createWithoutHome: true, clock: { clock.date })
        await first.session.create()
        let (_, otherID) = try await addSecondControlKey(first)
        let before = transitions(first.medium)
        await first.session.worker.setKeyringStopForTests(.recorded)
        await #expect(throws: SessionWorker.KeyringStopped.self) { try await first.session.removeController(otherID) }
        await first.session.worker.setKeyringStopForTests(nil)
        let again = first.relaunch()
        await again.restore()
        #expect(again.duties.rekeyOwed == ["reading.saved"], "\(again.duties.rekeyOwed)")
        #expect(try await again.removeController(otherID) == .done)
        #expect(again.duties.rekeyOwed.isEmpty)
        #expect(transitions(first.medium) == before + 1, "one removal")
    }

    /// With a home, a removal signed by every control key (two units) is a full set: it takes effect once the home has
    /// receipted it, without the recovery delay.
    @Test func aCosignedRemovalIsAFullSetAndActivatesAtOnce() async throws {
        let clock = TestClock(Self.t0)
        let relay = RelayHome(base: "https://keyring.test/v1/accounts/swift-fullset", port: RelayHome.freePort(), clock: { clock.now })
        defer { relay.stop() }
        let first = Device(createWithoutHome: true, clock: { clock.date })
        await first.session.create()
        try await save(first.session, "a")
        let ownerID = try await KeyCustody.keyID(of: first.owner)
        let (other, otherID) = try await addSecondControlKey(first)
        #expect(try await first.session.appointHomes([appointable(relay)]) == .done)
        first.session.stopSync()
        try await settle(first.session, relay, clock)

        let outcome = try await first.session.removeController(otherID, cosigners: [other])
        first.session.stopSync()
        guard case .pending(let digests) = outcome, let digest = digests.first else { Issue.record("expected pending, got \(outcome)"); return }
        let body = try #require(RemovalAnalysis.envelopeBody(try first.medium.read("transitions/\(digest).json")))
        #expect(Set((body["signers"] as? [String]) ?? []) == [ownerID, otherID], "signed by every control key")
        try await settle(first.session, relay, clock)
        let done = try await first.session.removeController(otherID, cosigners: [other])
        first.session.stopSync()
        #expect(done == .done, "no delay to wait out")
        #expect(clock.now - Self.t0 < 600_000, "far less than the recovery delay passed")
        #expect(try await state(first, as: ownerID, clock: clock).controllers.map(\.id) == [ownerID])
        #expect(first.session.duties.rekeyOwed.isEmpty)
    }

    /// With a home, replacing a passkey while the device keeps its own owner key is ONE transition. A call stopped once it
    /// is signed, and a call while it is pending, answer the same transition; after the delay the call finishes: the vault
    /// entry gives the new passkey its slot, and the rekey follows.
    @Test func aReplacementIsOneTransitionAndIdempotent() async throws {
        let clock = TestClock(Self.t0)
        let relay = RelayHome(base: "https://keyring.test/v1/accounts/swift-replace", port: RelayHome.freePort(), clock: { clock.now })
        defer { relay.stop() }
        let first = Device(createWithoutHome: true, clock: { clock.date })
        await first.session.create()
        try await save(first.session, "a")
        let ownerID = try await KeyCustody.keyID(of: first.owner)
        let old = TestPasskey(credential: Data([3, 3, 3]))
        #expect(try await first.session.appointHomes([appointable(relay)], adding: (key: old, label: "Passkey", roles: [.control, .recover])) == .done)
        first.session.stopSync()
        try await settle(first.session, relay, clock)
        let oldID = try await KeyCustody.keyID(of: old)
        let next = TestPasskey(credential: Data([4, 4, 4]))
        let nextID = try await KeyCustody.keyID(of: next)
        let check = try await first.session.checkRemoval(oldID, replacingWith: next)
        #expect(check.allowed && check.inOneTransition, "\(check)")

        let before = transitions(first.medium)
        await first.session.worker.setKeyringStopForTests(.signed)
        await #expect(throws: SessionWorker.KeyringStopped.self) { try await first.session.replaceController(oldID, with: next, label: "New passkey") }
        await first.session.worker.setKeyringStopForTests(nil)
        first.session.stopSync()
        #expect(transitions(first.medium) == before + 1)
        let again = first.relaunch()
        await again.restore()
        await again.configureHomes([HomeConfiguration(endpoint: URL(string: relay.base + "/")!, transport: relay.transport())])
        let pending = try await again.replaceController(oldID, with: next, label: "New passkey")
        again.stopSync()
        guard case .pending(let digests) = pending, digests.count == 1 else { Issue.record("expected one pending, got \(pending)"); return }
        #expect(transitions(first.medium) == before + 1, "the same transition, not a second one")
        let repeated = try await again.replaceController(oldID, with: next, label: "New passkey")
        again.stopSync()
        #expect(repeated == pending)
        try await settle(again, relay, clock)

        clock.advance(259_200_000 + 600_000)
        var outcome = repeated
        for _ in 0..<6 where outcome != .done {
            try await settle(again, relay, clock)
            outcome = try await again.replaceController(oldID, with: next, label: "New passkey")
            again.stopSync()
        }
        #expect(outcome == .done, "\(describe(first))")
        #expect(transitions(first.medium) == before + 1)
        let after = try await state(first, as: ownerID, clock: clock)
        #expect(Set(after.controllers.map(\.id)) == [ownerID, nextID])
        #expect(try await unlocksAlone(first, key: next, clock: clock), "the vault entry built the new passkey's slot")
        #expect(try await unlocksAlone(first, key: first.owner, clock: clock))
        #expect(kinds(first.medium).contains("vault"))
        #expect(again.duties.rekeyOwed.isEmpty && !again.duties.vaultRotationOwed && again.duties.keysWithoutSlot.isEmpty)
    }
}
