import Foundation
import Testing
import ColophonSessionUI
@testable import ColophonSession

@MainActor struct NoticesTests {
    /// The owner's device has a second control key (the laptop). The laptop alone proposes a change: it is pending
    /// (the owner did not sign), and the owner may veto it until its deadline (spec §8.7).
    private func proposeAsLaptop(_ device: Device, laptop: SoftwareKeys) async throws {
        let ownerID = try await KeyCustody.keyID(of: device.owner)
        let laptopID = try await KeyCustody.keyID(of: laptop)
        let account = try #require(device.session.libraryID)
        let listing = try device.medium.listing().map { ListedPath(path: $0.path, version: $0.version) }
        // The engine is the owner's (it holds the owner's slot); the signature is the laptop's.
        let engine = try await ColophonEngine.open(source: MediumSource(device.medium), listing: listing,
            identity: AccountIdentity(kind: .controller, id: ownerID), account: account, namespaces: ["reading.saved"],
            deviceKey: try SecretBytes.random(count: 32), nowMs: Int64(Date().timeIntervalSince1970 * 1000))
        let custody = try await KeyCustody([device.owner, laptop])
        let slot = try #require(try await engine.run { try $0.slots() }.first { $0.controllers.contains { $0.id == ownerID } })
        let index = slot.index
        let inputs = try await engine.run { try $0.beginUnlockSlot(index: index) }
        let secrets = try await custody.answer(unlock: inputs)
        _ = try await engine.finishUnlockSlot(index: index, secrets: secrets)
        let home = SimHome()
        let raw = try home.memberRequest(account: account, createdMs: Int64(Date().timeIntervalSince1970 * 1000) - 5000)
        let change = "{\"homes\":{\"appoint\":[{\"request\":\"\(raw.base64EncodedString())\",\"terms\":{\"serves\":[\"home\"]}}]}}"
        let written = try await engine.execute(custody: custody) {
            try $0.beginTransition(changeJson: change, signers: [laptopID], rule: .control, entropy: Data())
        }
        try device.medium.write(written.stores.map { MediumWrite(path: $0.path, bytes: $0.bytes) })
        await engine.lock()
    }

    private func deviceWithALaptop(home withHome: Bool = true) async throws -> (Device, SoftwareKeys, SimHome?) {
        let laptop = SoftwareKeys()
        if !withHome {
            let device = Device(additional: [AdditionalController(provider: laptop, label: "Laptop", roles: [.approve, .control, .recover])])
            await device.session.create()
            return (device, laptop, nil)
        }
        // With no home nothing witnesses time, so a change takes effect at once: the delay and the veto need a home.
        let home = SimHome()
        let make: @Sendable (String) async throws -> Data = { account in
            home.setAccount(account)
            return try home.memberRequest(account: account, createdMs: Int64(Date().timeIntervalSince1970 * 1000) - 5000)
        }
        let device = Device(homes: [HomeConfiguration(endpoint: URL(string: home.base + "/")!, request: make, transport: home)],
                            createWithoutHome: false, additional: [AdditionalController(provider: laptop, label: "Laptop", roles: [.approve, .control, .recover])])
        await device.session.create()
        device.session.stopSync()
        return (device, laptop, home)
    }

    @Test func aPendingChangeIsShownWithItsSignersAndDeadlineAndOneCallVetoesIt() async throws {
        let (device, laptop, simHome) = try await deviceWithALaptop()
        let home = try #require(simHome)
        #expect(device.session.notices.pending.isEmpty)
        try await proposeAsLaptop(device, laptop: laptop)
        await device.session.refresh()
        // The laptop's change reaches the home, which receipts it (spec §13.5); the receipt starts the deadline.
        #expect(await device.session.syncNow())
        let pending = try #require(device.session.notices.pending.first, "the proposal is shown")
        let laptopID = try await KeyCustody.keyID(of: laptop)
        #expect(pending.signers.map(\.id) == [laptopID])
        #expect(pending.signers.first?.label == "Laptop")
        #expect(pending.vetoable)
        #expect(pending.vetoDeadlineMs != nil, "the veto deadline is shown")
        #expect(NoticeWords.vetoDeadline(pending.vetoDeadlineMs).hasPrefix("You can say no until"))
        try await device.session.veto(pending.digest)
        #expect(device.medium.snapshot().keys.contains { $0.hasPrefix("vetoes/") }, "the veto is stored")
        await device.session.refresh()
        #expect(device.session.notices.pending.isEmpty, "a vetoed change is no longer pending")
        #expect(home.pendingObjects.count >= 2, "the veto reaches the home")
    }

    @Test func vetoingSomethingThatIsNotPendingIsRefusedWithATypedError() async throws {
        let device = Device()
        await device.session.create()
        let before = device.medium.snapshot().count
        await #expect(throws: ColophonError.self) { try await device.session.veto(String(repeating: "0", count: 64)) }
        #expect(device.medium.snapshot().count == before, "a refused veto stores nothing")
    }

    @Test func aChangeNoKeyOnThisDeviceSignedIsShownAfterwardsUntilTheyAcknowledge() async throws {
        let (device, laptop, _) = try await deviceWithALaptop(home: false)
        // The laptop's key is not on this device: a change it makes alone and that takes effect is shown afterwards.
        try await proposeAsLaptop(device, laptop: laptop)
        // Let the delay pass: the clock the engine judges by is the host's.
        let later = Device(medium: device.medium, member: device.member, owner: device.owner, clock: { Date().addingTimeInterval(4 * 86400) })
        await later.session.restore()
        await later.session.refresh()
        _ = try await later.session.worker.recordDue()
        await later.session.refresh()
        let unseen = later.session.notices.unseenActivations
        #expect(!unseen.isEmpty, "an activation no key on this device signed is shown")
        for activation in unseen { await later.session.acknowledgeActivation(seq: activation.seq) }
        #expect(later.session.notices.unseenActivations.isEmpty, "acknowledged")
    }
}
