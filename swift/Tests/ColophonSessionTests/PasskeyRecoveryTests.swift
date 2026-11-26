import Foundation
import Testing
import ColophonKit
import ColophonKeys
@testable import ColophonSession

/// A history read with a passkey before admission, and recovery and self-approval built on it (0.5.7), against the REAL
/// relay as the home (`relay/server.js` with the Rust home module, history for members only). A device that holds only
/// the account ID, the home's base and the person's passkey reads and verifies the history, then enrols itself with the
/// passkey and opens a session the owner's other device sees through the home. Refused: a passkey that is no controller
/// (the home's `refused:revoked`), a passkey of another relying party, an assertion from an origin that is no authority
/// origin of the descriptor (the home's `refused:origin`), a `recover`-only passkey asked to approve. The same journeys
/// run in Kotlin (`PasskeyRecoveryTest.kt`).
@MainActor @Suite(.serialized) struct PasskeyRecoveryTests {
    private let base = "https://home-passkey.test/v1/accounts/swift"
    private var home: URL { URL(string: base + "/")! }

    private func settle(_ device: Device) async throws {
        for _ in 0..<40 {
            if await device.session.syncNow(), device.session.homeIssues.isEmpty, device.session.homeFaults.isEmpty { return }
            try await Task.sleep(for: .milliseconds(150))
        }
        Issue.record("the device did not settle: \(device.session.phase) \(device.session.homeIssues)")
    }
    private func rejected(_ code: String, _ body: () async throws -> Void) async {
        do { try await body(); Issue.record("expected \(code)") }
        catch let JoinError.rejected(c, d) { #expect(c == code, "\(c) \(d)") }
        catch { Issue.record("expected \(code), got \(error)") }
    }
    private func refusedByHome(_ code: String, _ body: () async throws -> Void) async {
        do { try await body(); Issue.record("expected the home to refuse with \(code)") }
        catch let JoinError.refused(status, c) { #expect(status == 403 && c == code, "\(status) \(c ?? "-")") }
        catch { Issue.record("expected \(code), got \(error)") }
    }
    private func owner(_ relay: RelayHome, passkey: TestPasskey, roles: [ControllerRole]) -> Device {
        Device(homes: [HomeConfiguration(endpoint: home, request: { account in
            try relay.start(account: account)
            return try relay.memberRequest(account: account)
        }, transport: relay.transport())], createWithoutHome: false,
               additional: [AdditionalController(provider: passkey, label: "Passkey", roles: roles)], history: .members)
    }
    private func fresh(_ relay: RelayHome) -> Device {
        Device(homes: [HomeConfiguration(endpoint: home, transport: relay.transport())], createWithoutHome: false)
    }
    private func ready(_ session: ColophonSession) async throws {
        for _ in 0..<20 where session.phase != .ready {
            await session.syncNow(); await session.refresh(); try await Task.sleep(for: .milliseconds(100))
        }
        #expect(session.phase == .ready, "\(session.phase)")
    }

    @Test(.timeLimit(.minutes(10))) func recoverFromTheHomeWithAPasskey() async throws {
        let relay = RelayHome(base: base, port: RelayHome.freePort())
        defer { relay.stop() }
        let passkey = TestPasskey()
        let owner = owner(relay, passkey: passkey, roles: [.approve, .control])
        await owner.session.create()
        owner.session.stopSync()
        try #require(owner.session.phase == .ready)
        try await owner.session.perform(try .saveLink(id: "a", url: URL(string: "https://example.org/a")!, title: "A"), observed: owner.session.observedRevision)
        try await settle(owner)
        let account = try #require(owner.session.libraryID)
        let passkeyID = try await KeyCustody.keyID(of: passkey)

        // A new device: the account ID, the home's base and the passkey. Nothing else.
        let device = fresh(relay)
        let recovery = ColophonJoin.recovery(configuration: device.configuration, account: account, home: home)
        var before = passkey.assertCount
        let read = try await recovery.readHistoryWithPasskey(TestPasskeyAuthenticator(passkey: passkey))
        #expect((2...3).contains(passkey.assertCount - before), "gets: \(passkey.assertCount - before)")
        #expect(read.signerController.id == passkeyID)
        #expect(read.signerController.ownSlot)
        #expect(read.signer.view.signing == passkey.key.publicKey.x963Representation)
        #expect(read.controllers.map(\.id) == [passkeyID], "the one current passkey controller")
        let ownerFiles = Set(owner.medium.snapshot().keys.filter { $0.hasPrefix("authority/") })
        #expect(Set(read.files.keys) == ownerFiles)
        // With the key ID (an invite names it): exactly two gets.
        before = passkey.assertCount
        _ = try await recovery.readHistoryWithPasskey(TestPasskeyAuthenticator(passkey: passkey), ownerKeyID: passkeyID)
        #expect(passkey.assertCount - before == 2)
        #expect(device.medium.snapshot().keys.allSatisfy { !$0.hasPrefix("authority/") }, "a read stores nothing")

        // Refused: a passkey that is no controller; an assertion for another rp; an origin that is no authority origin;
        // another passkey's key ID.
        await refusedByHome("refused:revoked") { _ = try await recovery.readHistoryWithPasskey(TestPasskeyAuthenticator(passkey: TestPasskey())) }
        await rejected("badSignature") {
            _ = try await recovery.readHistoryWithPasskey(TestPasskeyAuthenticator(passkey: TestPasskey(rp: "other.example"), claimedRP: passkey.rp))
        }
        await refusedByHome("refused:origin") {
            _ = try await recovery.readHistoryWithPasskey(TestPasskeyAuthenticator(passkey: passkey, origin: "https://keys.\(passkey.rp)"), ownerKeyID: passkeyID)
        }
        await rejected("badSignature") { _ = try await recovery.readHistoryWithPasskey(TestPasskeyAuthenticator(passkey: passkey), ownerKeyID: String(repeating: "00", count: 16)) }

        // Recover: the history stored, this device's member approved by the passkey, the session opened.
        var restored: OwnerPasskey?
        var recovered: Device?
        let session = try await ColophonJoin.recoverWithPasskey(configuration: device.configuration, account: account, home: home,
                                                               passkey: TestPasskeyAuthenticator(passkey: passkey)) { ownerPasskey in
            restored = ownerPasskey
            let d = Device(medium: device.medium, member: device.member, homes: [HomeConfiguration(endpoint: home, transport: relay.transport())],
                           createWithoutHome: false, ownerKey: passkey)
            recovered = d
            return d.session
        }
        session.stopSync()
        #expect(restored?.view.signing == passkey.key.publicKey.x963Representation)
        try await ready(session)
        #expect(session.memberID == (try await KeyCustody.keyID(of: device.member)))
        try await session.perform(try .saveLink(id: "b", url: URL(string: "https://example.org/b")!, title: "B"), observed: session.observedRevision)
        #expect(await session.syncNow())
        _ = recovered

        // The owner's device sees the new member through the home, and the member's own key now reads the history.
        let memberID = try #require(session.memberID)
        var seen = false
        for _ in 0..<40 where !seen {
            await owner.session.syncNow(); await owner.session.refresh()
            seen = owner.session.members.contains { $0.id == memberID }
            if !seen { try await Task.sleep(for: .milliseconds(150)) }
        }
        #expect(seen, "the owner sees the recovered member")
        if case .admitted = try await recovery.fetchHistory() {} else { Issue.record("the recovered member is admitted") }
    }

    @Test(.timeLimit(.minutes(10))) func approveOwnJoinWithAPasskey() async throws {
        let relay = RelayHome(base: base, port: RelayHome.freePort())
        defer { relay.stop() }
        let passkey = TestPasskey()
        let owner = owner(relay, passkey: passkey, roles: [.approve, .control])
        await owner.session.create()
        owner.session.stopSync()
        try await settle(owner)
        let account = try #require(owner.session.libraryID)
        let entries = owner.medium.snapshot().filter { $0.key.hasPrefix("authority/") }.sorted { $0.key < $1.key }.map { ByteString(bytes: $0.value) }
        let report = try accountVerifyHistory(objects: AuthorityObjects(entries: entries, pending: [], heads: [], predecessor: []), nowMs: RelayHome.nowMs())
        let passkeyID = try await KeyCustody.keyID(of: passkey)

        // A short invite's join: the joiner waits, then approves itself with the owner's passkey (named by key ID).
        let joiner = fresh(relay)
        let join = ColophonJoin(configuration: joiner.configuration, account: account, home: home, seq: UInt64(report.branch.count), head: report.branch.last!)
        _ = try await join.request()
        #expect(try await join.fetchHistory() == .notAdmitted)
        // A session whose owner is not the passkey that read the history.
        await rejected("refused:conflict") {
            _ = try await join.approveOwnJoinWithPasskey(TestPasskeyAuthenticator(passkey: passkey), ownerKeyID: passkeyID) { _ in
                Device(medium: joiner.medium, member: joiner.member, homes: [HomeConfiguration(endpoint: home, transport: relay.transport())],
                       createWithoutHome: false).session
            }
        }
        var kept: Device?
        let session = try await join.approveOwnJoinWithPasskey(TestPasskeyAuthenticator(passkey: passkey), ownerKeyID: passkeyID) { _ in
            let d = Device(medium: joiner.medium, member: joiner.member, homes: [HomeConfiguration(endpoint: home, transport: relay.transport())],
                           createWithoutHome: false, ownerKey: passkey)
            kept = d
            return d.session
        }
        session.stopSync()
        try await ready(session)
        _ = kept
        if case .admitted = try await join.fetchHistory() {} else { Issue.record("the home holds the grant") }
    }

    @Test(.timeLimit(.minutes(10))) func aRecoverOnlyPasskeyReadsButDoesNotApprove() async throws {
        let relay = RelayHome(base: base, port: RelayHome.freePort())
        defer { relay.stop() }
        let passkey = TestPasskey()
        let owner = owner(relay, passkey: passkey, roles: [.recover])
        await owner.session.create()
        owner.session.stopSync()
        try await settle(owner)
        let account = try #require(owner.session.libraryID)
        let passkeyID = try await KeyCustody.keyID(of: passkey)
        let device = fresh(relay)
        let recovery = ColophonJoin.recovery(configuration: device.configuration, account: account, home: home)
        // §13.4: a recover controller reads the history.
        let read = try await recovery.readHistoryWithPasskey(TestPasskeyAuthenticator(passkey: passkey), ownerKeyID: passkeyID)
        #expect(read.signerController.roles == [.recover])
        // It cannot grant at once: refused before anything is stored or signed.
        let gets = passkey.assertCount
        await rejected("refused:outOfScope") {
            _ = try await recovery.approveOwnJoinWithPasskey(TestPasskeyAuthenticator(passkey: passkey), ownerKeyID: passkeyID) { _ in
                Issue.record("no session is opened"); return device.session
            }
        }
        #expect(passkey.assertCount - gets == 2, "only the read's gets")
        #expect(device.medium.snapshot().keys.allSatisfy { !$0.hasPrefix("authority/") }, "nothing stored")
    }
}
