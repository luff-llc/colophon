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
        // A passkey owner is asked once at first run: the creation's own PRF (its new slot). The session that sets the
        // device up is the creation's own engine, unlocked (`AccountCreation.open_engine`); before, a second PRF
        // ceremony unlocked it.
        #expect(passkey.prfRequests == 1, "asked \(passkey.prfRequests) times")
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

    /// A failed `create()` stays published: a sync pass with no library does not refresh it away. Deterministic: the pass
    /// is run explicitly after the failure (the Kotlin session showed the race as "noLibrary, no error").
    @Test func aFailedCreationIsNotErasedByASyncPass() async throws {
        let device = Device(homes: [HomeConfiguration(endpoint: URL(string: "http://home.example/v1/")!)], createWithoutHome: false)
        await device.session.create()
        guard case .failed = device.session.phase else { Issue.record("expected failed, got \(device.session.phase)"); return }
        let failed = device.session.phase, error = try #require(device.session.lastError)
        #expect(await device.session.syncNow() == false, "with no library there is nothing to exchange")
        #expect(device.session.phase == failed)
        #expect(device.session.lastError == error)
    }

    @Test func aSecondDeviceInTheSameFolderRequestsAccessIsApprovedAndSeesWhatTheFirstWrote() async throws {
        let first = Device()
        await first.session.create()
        try await first.session.perform(try .saveLink(id: "a", url: URL(string: "https://example.org/a")!, title: "A"), observed: first.session.observedRevision)
        let second = Device(medium: first.medium, owner: SoftwareKeys())
        await second.session.restore()
        guard case .waitingForApproval = second.session.phase else { Issue.record("expected waiting, got \(second.session.phase)"); return }
        try await approveByCode(joining: second.session, approving: first.session)
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
        try await approveByScan(joining: second.session, approving: first.session)
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

@MainActor struct RelaunchTests {
    /// A session over a real folder: created, written to, flushed, then a new process-like session reopens it from the
    /// folder and the sealed saved state (the device key and the member's key persist, as the Keychain does).
    @Test(.enabled(if: FileCoordinationProbe.available, FileCoordinationProbe.reason))
    func aSessionOverARealFolderSurvivesARelaunchAndResumes() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let library = root.appendingPathComponent("library"), privateDir = root.appendingPathComponent("private")
        let member = SoftwareKeys(), owner = SoftwareKeys(), secrets = MemoryDeviceSecrets()
        func session() -> ColophonSession {
            ColophonSession(configuration: .init(memberLabel: "Mac", namespaces: ["reading.saved"], location: .folder(library), privateContainer: privateDir,
                keys: member, ownerController: owner, createWithoutHome: true, deviceSecrets: secrets))
        }
        let first = session()
        await first.create()
        #expect(first.phase == .ready, "\(first.phase) \(first.lastError ?? "")")
        try await first.perform(try .saveLink(id: "a", url: URL(string: "https://example.org/a")!, title: "A"), observed: first.observedRevision)
        try await first.flushCheckpoint()
        #expect(FileManager.default.fileExists(atPath: library.appendingPathComponent("authority/00000001.json").path))
        let second = session()
        await second.restore()
        #expect(second.phase == .ready, "\(second.phase) \(second.lastError ?? "")")
        #expect(try await SavedStore(session: second).load(ItemsQuery(limit: 10)).get().total == 1)
        // Someone else's key cannot open it: the same folder with another member is only waiting for approval.
        let stranger = ColophonSession(configuration: .init(memberLabel: "Stranger", namespaces: ["reading.saved"], location: .folder(library),
            privateContainer: root.appendingPathComponent("stranger"), keys: SoftwareKeys(), ownerController: SoftwareKeys(), createWithoutHome: true, deviceSecrets: MemoryDeviceSecrets()))
        await stranger.restore()
        guard case .waitingForApproval = stranger.phase else { Issue.record("a stranger must wait, got \(stranger.phase)"); return }
        #expect(!stranger.hasUsableContent)
    }
}

@MainActor struct DenialTests {
    /// The owner approves the second device for reading only. The device's own configuration allows writing, so the
    /// session lets the attempt through to the engine, which refuses it as a value the SDK throws as `ColophonError.denied`.
    @Test func aReadOnlyMemberIsRefusedAWriteWithATypedDenialAndNothingIsStored() async throws {
        let first = Device()
        await first.session.create()
        let second = Device(medium: first.medium)
        await second.session.restore()
        try await approveByCode(joining: second.session, approving: first.session,
                                grant: GrantOptions(namespaces: ["reading.saved"], access: [.read], expires: nil, writeBudget: nil))
        await second.session.refresh()
        #expect(second.session.phase == .ready)
        let before = first.medium.snapshot().count
        do {
            try await second.session.perform(try .saveLink(url: URL(string: "https://example.org/x")!, title: "X"), observed: second.session.observedRevision)
            Issue.record("a read-only member wrote")
        } catch let error as ColophonError {
            guard case .denied(_, let reason, _, _) = error else { Issue.record("expected denied, got \(error)"); return }
            #expect(reason == .notGranted)
        }
        #expect(first.medium.snapshot().count == before, "a refused write stores nothing")
    }
}
