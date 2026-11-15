import CryptoKit
import Foundation
import Testing
import ColophonKeys
import ColophonSavedKit
import ColophonSession

@MainActor struct SessionTests {
    @Test func createdWithAPasskeyOwnerAndADeviceKeyIsReadyAndWarnsThereIsNoHome() async throws {
        let passkey = TestPasskey()
        let medium = MemoryMedium()
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: home) }
        let session = ColophonSession(configuration: .init(memberLabel: "Mac", namespaces: ["reading.saved"], location: .memory(medium),
            privateContainer: home, keys: SoftwareKeys(), ownerController: passkey, createWithoutHome: true, deviceSecrets: MemoryDeviceSecrets()))
        await session.restore()
        #expect(session.phase == .noLibrary)
        await session.create()
        #expect(session.phase == .ready)
        #expect(session.libraryID?.count == 64)
        #expect(session.notices.noHome, "an account with no home warns (spec §18)")
        #expect(session.members.contains { $0.label == "Mac" && $0.grant?.namespaces == ["reading.saved"] })
        // The known gap: creation leaves the session locked, so the passkey is asked for the creation's own
        // PRF (the new slot) and a second time to unlock the controller that sets the device up.
        #expect(passkey.prfRequests >= 2)
        let paths = medium.snapshot().keys
        #expect(paths.contains("authority/00000001.json") && !paths.contains { $0.hasPrefix(".") })
    }

    @Test func aWriteAndAReadThroughSavedKitAndTheObservedRevisionIsEnforced() async throws {
        let device = Device()
        await device.session.create()
        let store = SavedStore(session: device.session)
        let observed = device.session.observedRevision
        let receipt = try await device.session.perform(try .saveLink(id: "a", url: URL(string: "https://example.org/a")!, title: "First"), observed: observed)
        guard case .saved(let operation) = receipt else { Issue.record("not saved"); return }
        #expect(!operation.isEmpty)
        let page = try await store.load(ItemsQuery(limit: 10)).get()
        #expect(page.total == 1)
        // A write bound to the revision seen before the first one is refused as stale and signs nothing.
        let before = device.medium.snapshot().count
        await #expect(throws: SessionError.staleRevision) {
            try await device.session.perform(try .saveLink(id: "b", url: URL(string: "https://example.org/b")!, title: "Second"), observed: observed)
        }
        #expect(device.medium.snapshot().count == before, "a refused write leaves no file")
        #expect(try await store.load(ItemsQuery(limit: 10)).get().total == 1)
    }

    @Test func lockHidesTheContentAndUnlockOpensItAgain() async throws {
        let device = Device()
        await device.session.create()
        try await device.session.perform(try .saveLink(url: URL(string: "https://example.org/x")!, title: "X"), observed: device.session.observedRevision)
        await device.session.lock()
        #expect(device.session.phase == .locked)
        #expect(!device.session.hasUsableContent)
        await #expect(throws: SessionError.notReady) { _ = try await device.session.query(namespace: "reading.saved", name: "items", arguments: Data("{}".utf8)) }
        await device.session.unlock()
        #expect(device.session.phase == .ready)
        let bytes = try await device.session.query(namespace: "reading.saved", name: "items", arguments: Data("{}".utf8))
        let value = try #require((try JSONSerialization.jsonObject(with: bytes) as? [String: Any])?["value"] as? [String: Any])
        #expect(value["total"] as? Int == 1)
    }

    @Test func aHostIsRequiredUnlessTheHostOptsOut() async throws {
        let device = Device(createWithoutHome: false)
        await device.session.create()
        #expect(device.session.phase == .noLibrary)
        #expect(device.medium.snapshot().isEmpty, "nothing was created")
        #expect(device.session.lastError?.contains("no home") == true)
    }

    @Test func aSecondDeviceInTheSameFolderRequestsAccessIsApprovedAndSeesWhatTheFirstWrote() async throws {
        let first = Device()
        await first.session.create()
        try await first.session.perform(try .saveLink(id: "a", url: URL(string: "https://example.org/a")!, title: "A"), observed: first.session.observedRevision)
        let second = Device(medium: first.medium, owner: SoftwareKeys())
        await second.session.restore()
        guard case .waitingForApproval(let code) = second.session.phase else { Issue.record("expected waiting, got \(second.session.phase)"); return }
        await first.session.refresh()
        let request = try #require(first.session.requests.first)
        #expect(request.pairingCode == code, "both devices show the same code")
        try await first.session.approve(request)
        await second.session.refresh()
        #expect(second.session.phase == .ready)
        #expect(try await SavedStore(session: second.session).load(ItemsQuery(limit: 10)).get().total == 1)
        try await second.session.perform(try .saveLink(id: "b", url: URL(string: "https://example.org/b")!, title: "B"), observed: second.session.observedRevision)
        await first.session.refresh()
        #expect(try await SavedStore(session: first.session).load(ItemsQuery(limit: 10)).get().total == 2)
    }

    @Test func aRevokedDeviceReadsNothingNew() async throws {
        let first = Device()
        await first.session.create()
        let second = Device(medium: first.medium)
        await second.session.restore()
        await first.session.refresh()
        try await first.session.approve(try #require(first.session.requests.first))
        await second.session.refresh()
        #expect(second.session.phase == .ready)
        try await first.session.revoke(memberID: try #require(second.session.memberID))
        try await first.session.perform(try .saveLink(id: "secret", url: URL(string: "https://example.org/secret")!, title: "After"), observed: first.session.observedRevision)
        await second.session.refresh()
        #expect(second.session.phase == .denied)
        #expect(!second.session.hasUsableContent)
        await #expect(throws: SessionError.notReady) { _ = try await second.session.query(namespace: "reading.saved", name: "items", arguments: Data("{}".utf8)) }
    }
}
