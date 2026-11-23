import Foundation
import Testing
import ColophonKit
import ColophonSavedKit
@testable import ColophonSession

/// `appointHomes` against the REAL relay (`RelayHome`): an account created without a home appoints one later and adds a
/// passkey-form controller in one transition. Every session and relay run on one clock the test moves, and the relay has
/// no scheduler timer (heads are published by `RelayHome.tick`), so nothing waits on real time.
@MainActor @Suite(.serialized) struct AppointHomesTests {
    nonisolated private static let t0: Int64 = 1_795_165_200_000 // 2026-11-20T09:00:00Z

    /// Starts its relay for the account the first time the session asks for the home's request; later calls (a second
    /// `appointHomes`) get a fresh request from the running relay.
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
    private func joining(_ relay: RelayHome) -> HomeConfiguration { HomeConfiguration(endpoint: URL(string: relay.base + "/")!, transport: relay.transport()) }
    private func describe(_ device: Device) -> String {
        "phase \(device.session.phase) error \(device.session.lastError ?? "-") issues \(device.session.homeIssues) faults \(device.session.homeFaults.map { "\($0.fault.kind) \($0.fault.status.map(String.init) ?? "")" })"
    }
    /// Exchanges until clean, one relay pass after each exchange.
    private func settle(_ device: Device, _ relay: RelayHome, _ clock: TestClock) async throws {
        for _ in 0..<6 {
            clock.advance(1000)
            let ok = await device.session.syncNow()
            try await relay.tick()
            if ok, device.session.homeIssues.isEmpty, device.session.homeFaults.isEmpty { return }
        }
        Issue.record("did not settle: \(describe(device))")
    }
    private func items(_ device: Device) async throws -> Int {
        try await SavedStore(session: device.session).load(ItemsQuery(limit: 50)).get().total
    }
    private func save(_ device: Device, _ id: String) async throws {
        try await device.session.perform(try .saveLink(id: id, url: URL(string: "https://example.org/\(id)")!, title: id), observed: device.session.observedRevision)
    }
    /// A controller engine over `medium` (locked), to read the keyring as the account states it.
    private func controllerEngine(_ medium: MemoryMedium, id: String, account: String, clock: TestClock) async throws -> ColophonEngine {
        try await ColophonEngine.open(label: "test.controller", source: MediumSource(medium), listing: medium.listing().map { ListedPath(path: $0.path, version: $0.version) },
            identity: AccountIdentity(kind: .controller, id: id), account: account, namespaces: [], saved: nil,
            deviceKey: SecretBytes(copying: Data(repeating: 0x33, count: 32)), nowMs: clock.now)
    }
    /// The passkey opens its own slot with nothing else: the account unlocks by it alone.
    private func unlocksAlone(_ medium: MemoryMedium, passkey: TestPasskey, account: String, clock: TestClock) async throws -> Bool {
        let id = try await KeyCustody.keyID(of: passkey)
        let engine = try await controllerEngine(medium, id: id, account: account, clock: clock)
        let slots = try await engine.run { try $0.slots() }
        guard let slot = slots.first(where: { $0.controllers.map(\.id) == [id] }) else { return false }
        let inputs = try await engine.run { try $0.beginUnlockSlot(index: slot.index) }
        let secrets = try await KeyCustody([passkey]).answer(unlock: inputs)
        _ = try await engine.finishUnlockSlot(index: slot.index, secrets: secrets)
        let unlocked = try await engine.run { try $0.isUnlocked() }
        await engine.lock()
        return unlocked
    }
    private func transitions(_ medium: MemoryMedium) -> Int { medium.snapshot().keys.filter { $0.hasPrefix("transitions/") }.count }

    /// (2) Created without a home, records written, then one `appointHomes` appoints the relay and adds a passkey (control,
    /// recover): done at once, the session uploads without a relaunch, a second device joins through the home and reads the
    /// records, and the passkey unlocks the account alone.
    @Test func aHomeAppointedLaterWithAPasskeyServesASecondDevice() async throws {
        let clock = TestClock(Self.t0)
        let relay = RelayHome(base: "https://appoint.test/v1/accounts/swift", port: RelayHome.freePort(), clock: { clock.now })
        defer { relay.stop() }
        let first = Device(createWithoutHome: true, clock: { clock.date })
        await first.session.create()
        try #require(first.session.phase == .ready, "\(describe(first))")
        #expect(first.session.homes.isEmpty && first.session.notices.noHome)
        try await save(first, "a"); try await save(first, "b")
        let account = try #require(first.session.libraryID)

        let passkey = TestPasskey()
        let outcome = try await first.session.appointHomes([appointable(relay)], adding: (key: passkey, label: "Passkey", roles: [.control, .recover]))
        first.session.stopSync()
        #expect(outcome == .done, "no home before: final at once")
        #expect(passkey.assertCount == 1)
        #expect(first.session.homes.count == 1 && !first.session.notices.noHome, "\(first.session.homes)")
        #expect(first.session.syncState != .disabled, "the running session syncs with the appointed home")
        let passkeyID = try await KeyCustody.keyID(of: passkey)
        let keyring = try await controllerEngine(first.medium, id: passkeyID, account: account, clock: clock)
        let controllers = try await keyring.run { try $0.controllers() }
        await keyring.lock()
        let added = try #require(controllers.first { $0.id == passkeyID })
        #expect(added.roles == [.control, .recover] && added.hasSlot && !added.provisional && added.form == .webauthn)
        try await settle(first, relay, clock)

        // A second device holding the account's history (as a folder would deliver it), and no records, joins through the home.
        let second = Device(medium: MemoryMedium(files: first.medium.snapshot().filter { $0.key.hasPrefix("authority/") }),
                            homes: [joining(relay)], createWithoutHome: false, clock: { clock.date })
        await second.session.restore()
        second.session.stopSync()
        guard case .waitingForApproval = second.session.phase else { Issue.record("expected waiting, got \(describe(second))"); return }
        try await approveByCode(joining: second.session, approving: first.session)
        try await settle(first, relay, clock)
        try await settle(second, relay, clock)
        await second.session.refresh()
        #expect(second.session.phase == .ready, "\(describe(second))")
        try await settle(second, relay, clock)
        #expect(try await items(second) == 2, "the second device reads, through the home, what was written before the home existed")
        #expect(try await unlocksAlone(second.medium, passkey: passkey, account: account, clock: clock), "the passkey unlocks alone")
    }

    /// (3) A call that stops after any one of its steps (the transition signed, then recorded, then the slot built) is
    /// finished by the same call on a relaunched session: one transition, one controller, one slot, one home.
    @Test(arguments: [SessionWorker.AppointStep.signed, .recorded, .slotted])
    func aCallStoppedBetweenStepsIsFinishedByCallingAgain(_ step: SessionWorker.AppointStep) async throws {
        let clock = TestClock(Self.t0)
        let relay = RelayHome(base: "https://appoint.test/v1/accounts/swift-crash", port: RelayHome.freePort(), clock: { clock.now })
        defer { relay.stop() }
        let first = Device(createWithoutHome: true, clock: { clock.date })
        await first.session.create()
        try #require(first.session.phase == .ready)
        try await save(first, "a")
        let account = try #require(first.session.libraryID)
        let home = appointable(relay)
        let passkey = TestPasskey()
        await first.session.worker.setAppointStopForTests(step)
        await #expect(throws: SessionWorker.AppointStopped.self) {
            try await first.session.appointHomes([home], adding: (key: passkey, label: "Passkey", roles: [.control, .recover]))
        }
        first.session.stopSync()
        #expect(transitions(first.medium) == 1, "one transition signed before the stop")
        #expect(passkey.assertCount == 1)

        let again = first.relaunch()
        await again.restore()
        clock.advance(1000)
        let outcome = try await again.appointHomes([home], adding: (key: passkey, label: "Passkey", roles: [.control, .recover]))
        again.stopSync()
        #expect(outcome == .done)
        #expect(passkey.assertCount == (step == .slotted ? 1 : 2), "resume needs one fresh PRF get only if the slot was absent")
        #expect(transitions(first.medium) == 1, "nothing was appointed or added twice")
        #expect(again.homes.count == 1)
        let passkeyID = try await KeyCustody.keyID(of: passkey)
        let keyring = try await controllerEngine(first.medium, id: passkeyID, account: account, clock: clock)
        let controllers = try await keyring.run { try $0.controllers() }
        let slots = try await keyring.run { try $0.slots() }
        await keyring.lock()
        #expect(controllers.filter { $0.id == passkeyID }.count == 1 && controllers.count == 2)
        #expect(slots.filter { $0.controllers.map(\.id) == [passkeyID] }.count == 1, "one slot of the passkey's own")
        #expect(try await unlocksAlone(first.medium, passkey: passkey, account: account, clock: clock))
    }

    /// (4) With a home already current the same call is an ordinary pending transition: it answers `.pending`, and calling
    /// it again answers the same transition without signing another.
    @Test func withAHomeAlreadyCurrentTheCallIsPending() async throws {
        let clock = TestClock(Self.t0)
        let current = RelayHome(base: "https://appoint.test/v1/accounts/swift-a", port: RelayHome.freePort(), clock: { clock.now })
        let next = RelayHome(base: "https://appoint.test/v1/accounts/swift-b", port: RelayHome.freePort(), clock: { clock.now })
        defer { current.stop(); next.stop() }
        let first = Device(homes: [appointable(current)], createWithoutHome: false, clock: { clock.date })
        await first.session.create()
        first.session.stopSync()
        try #require(first.session.phase == .ready, "\(describe(first))")
        try await settle(first, current, clock)
        let before = transitions(first.medium)
        let passkey = TestPasskey()
        let home = appointable(next)
        let outcome = try await first.session.appointHomes([home], adding: (key: passkey, label: "Passkey", roles: [.control, .recover]))
        first.session.stopSync()
        guard case .pending(let digests) = outcome, digests.count == 1, let digest = digests.first else { Issue.record("expected one pending, got \(outcome)"); return }
        #expect(transitions(first.medium) == before + 1)
        #expect(first.session.homes.count == 1, "not appointed before its delay")
        #expect(first.session.notices.pending.contains { $0.digest == digest })
        clock.advance(1000)
        let repeated = try await first.session.appointHomes([home], adding: (key: passkey, label: "Passkey", roles: [.control, .recover]))
        first.session.stopSync()
        #expect(repeated == .pending(transitions: [digest]), "the same transition, not a second one")
        #expect(transitions(first.medium) == before + 1)
    }

    /// A home that answers with another identity after a crash (same endpoint, another member) is not appointed again: the
    /// pending appointment names its endpoint. A request that does not name the configured endpoint is refused unsigned.
    @Test func aHomeIsBoundByItsEndpointNotByTheMemberItAnswersWith() async throws {
        let clock = TestClock(Self.t0)
        let relay = RelayHome(base: "https://appoint.test/v1/accounts/swift-rotating", port: RelayHome.freePort(), clock: { clock.now })
        let impostor = RelayHome(base: relay.base, port: RelayHome.freePort(), clock: { clock.now })
        let elsewhere = RelayHome(base: "https://elsewhere.test/v1/accounts/swift", port: RelayHome.freePort(), clock: { clock.now })
        defer { relay.stop() }
        let first = Device(createWithoutHome: true, clock: { clock.date })
        await first.session.create()
        try #require(first.session.phase == .ready)
        // A request for another endpoint than the configured one: refused before anything is signed.
        let wrong = HomeConfiguration(endpoint: URL(string: relay.base + "/")!, request: { try elsewhere.memberRequest(account: $0) }, transport: relay.transport())
        await #expect(throws: SessionError.invalidCommand) { try await first.session.appointHomes([wrong]) }
        #expect(transitions(first.medium) == 0)
        // The first call stops once its transition is signed; the home then answers as another member.
        let started = Once()
        let rotating = HomeConfiguration(endpoint: URL(string: relay.base + "/")!, request: { account in
            var first = false
            try started.run { try relay.start(account: account); first = true }
            return try (first ? relay : impostor).memberRequest(account: account)
        }, transport: relay.transport())
        await first.session.worker.setAppointStopForTests(.signed)
        await #expect(throws: SessionWorker.AppointStopped.self) { try await first.session.appointHomes([rotating]) }
        first.session.stopSync()
        let again = first.relaunch()
        await again.restore()
        let outcome = try await again.appointHomes([rotating])
        again.stopSync()
        #expect(outcome == .done)
        #expect(transitions(first.medium) == 1, "not appointed twice")
        #expect(again.homes.map(\.id) == [relay.id], "the home first appointed, not the impostor")
    }

    /// A key already in the keyring with other roles than asked is refused, not taken as done; nothing is signed.
    @Test func anExistingKeyWithOtherRolesIsRefused() async throws {
        let clock = TestClock(Self.t0)
        let relay = RelayHome(base: "https://appoint.test/v1/accounts/swift-roles", port: RelayHome.freePort(), clock: { clock.now })
        defer { relay.stop() }
        let first = Device(createWithoutHome: true, clock: { clock.date })
        await first.session.create()
        let key = SoftwareKeys()
        try await first.session.addController(key, label: "Key", roles: [.approve], immediate: true)
        let before = first.medium.snapshot().count
        await #expect(throws: SessionError.invalidCommand) {
            try await first.session.appointHomes([appointable(relay)], adding: (key: key, label: "Key", roles: [.control, .recover]))
        }
        #expect(first.medium.snapshot().count == before && transitions(first.medium) == 0, "nothing signed")
        #expect(first.session.homes.isEmpty)
    }

    /// A key that is a controller but held only in a combined [owner, key] slot gets its own slot: done means it unlocks alone.
    @Test func aKeyInOnlyACombinedSlotGetsItsOwn() async throws {
        let clock = TestClock(Self.t0)
        let relay = RelayHome(base: "https://appoint.test/v1/accounts/swift-combined", port: RelayHome.freePort(), clock: { clock.now })
        defer { relay.stop() }
        let first = Device(createWithoutHome: true, clock: { clock.date })
        await first.session.create()
        let account = try #require(first.session.libraryID)
        let key = SoftwareKeys()
        try await first.session.addController(key, label: "Key", roles: [.approve], immediate: true)
        let ownerID = try await KeyCustody.keyID(of: first.owner), keyID = try await KeyCustody.keyID(of: key)
        // The owner builds a slot both keys must open together.
        let owner = try await controllerEngine(first.medium, id: ownerID, account: account, clock: clock)
        let own = try #require(try await owner.run { try $0.slots() }.first { $0.controllers.map(\.id) == [ownerID] })
        let custody = try await KeyCustody([first.owner, key])
        let inputs = try await owner.run { try $0.beginUnlockSlot(index: own.index) }
        _ = try await owner.finishUnlockSlot(index: own.index, secrets: try await custody.answer(unlock: inputs))
        let written = try await owner.execute(custody: custody) { e in
            try withEntropy(32) { try e.beginAddSlot(signer: ownerID, plan: SlotPlan(controllers: [ownerID, keyID], label: "Both"), entropy: $0) }
        }
        await owner.lock()
        try first.medium.write(written.stores.map { MediumWrite(path: $0.path, bytes: $0.bytes) })
        let outcome = try await first.session.appointHomes([appointable(relay)], adding: (key: key, label: "Key", roles: [.approve]))
        first.session.stopSync()
        #expect(outcome == .done)
        let keyring = try await controllerEngine(first.medium, id: keyID, account: account, clock: clock)
        let slots = try await keyring.run { try $0.slots() }
        await keyring.lock()
        #expect(slots.filter { $0.controllers.map(\.id) == [keyID] }.count == 1, "its own slot was built")
        #expect(slots.contains { Set($0.controllers.map(\.id)) == [ownerID, keyID] })
    }
}
