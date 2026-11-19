import Foundation
import Testing
@testable import ColophonSession

/// Ported from the independent check's probe (`IndependentCheckerNoticeProbe`): acknowledging what took effect must
/// not dismiss a change that is still waiting. Before the fix the pending transition vanished after the acknowledgement.
@MainActor struct AcknowledgeTests {
    @Test func acknowledgingActivationsNeverDismissesAPendingTransition() async throws {
        let laptop = SoftwareKeys()
        let home = SimHome()
        let request: @Sendable (String) async throws -> Data = { account in
            home.setAccount(account)
            return try home.memberRequest(account: account, createdMs: Int64(Date().timeIntervalSince1970 * 1000) - 5_000)
        }
        let device = Device(homes: [.init(endpoint: URL(string: home.base + "/")!, request: request, transport: home)], createWithoutHome: false,
                            additional: [.init(provider: laptop, label: "Laptop", roles: [.approve, .control, .recover])])
        await device.session.create()
        device.session.stopSync()

        // The laptop alone signs a transition (appointing a second home); this device holds no key that signed it.
        let ownerID = try await KeyCustody.keyID(of: device.owner)
        let laptopID = try await KeyCustody.keyID(of: laptop)
        let account = try #require(device.session.libraryID)
        let listing = try device.medium.listing().map { ListedPath(path: $0.path, version: $0.version) }
        let engine = try await ColophonEngine.open(source: MediumSource(device.medium), listing: listing,
            identity: AccountIdentity(kind: .controller, id: ownerID), account: account, namespaces: ["reading.saved"],
            deviceKey: try SecretBytes.random(count: 32), nowMs: Int64(Date().timeIntervalSince1970 * 1000))
        let custody = try await KeyCustody([device.owner, laptop])
        let slot = try #require(try await engine.run { try $0.slots() }.first { $0.controllers.contains { $0.id == ownerID } })
        let inputs = try await engine.run { try $0.beginUnlockSlot(index: slot.index) }
        _ = try await engine.finishUnlockSlot(index: slot.index, secrets: try await custody.answer(unlock: inputs))
        let raw = try SimHome(base: "https://second.example").memberRequest(account: account, createdMs: Int64(Date().timeIntervalSince1970 * 1000) - 5_000)
        let change = "{\"homes\":{\"appoint\":[{\"request\":\"" + raw.base64EncodedString() + "\",\"terms\":{\"serves\":[\"home\"]}}]}}"
        let written = try await engine.execute(custody: custody) { try $0.beginTransition(changeJson: change, signers: [laptopID], rule: .control, entropy: Data()) }
        try device.medium.write(written.stores.map { MediumWrite(path: $0.path, bytes: $0.bytes) })
        await engine.lock()

        await device.session.refresh()
        #expect(await device.session.syncNow())
        let pending = device.session.notices.pending
        #expect(!pending.isEmpty, "the laptop's change is pending")
        // Acknowledge every activation shown (and one that is not): the pending change stays.
        for activation in device.session.notices.unseenActivations { await device.session.acknowledgeActivation(seq: activation.seq) }
        await device.session.acknowledgeActivation(seq: 1)
        #expect(device.session.notices.pending.map(\.digest) == pending.map(\.digest), "a pending transition is not dismissed by acknowledging activations")
        await device.session.refresh()
        #expect(device.session.notices.pending.map(\.digest) == pending.map(\.digest), "nor after a refresh")
    }
}
