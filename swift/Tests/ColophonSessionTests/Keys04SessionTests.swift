import CryptoKit
import Foundation
import Testing
@testable import ColophonSession

private actor ObservedKeys: AsyncKeyProvider {
    let base = SoftwareKeys()
    var signed: [Data] = []
    var agreementFails = false
    func publicKeys() async throws -> PublicKeys { try await base.publicKeys() }
    func sign(body: Data) async throws -> Data { signed.append(body); return try base.sign(body: body) }
    func agree(peer: Data) async throws -> Data {
        if agreementFails { throw BindingError.KeyProvider(detail: "Controller locked") }
        return try base.agree(peer: peer)
    }
    func lockAgreement() { agreementFails = true }
}

@MainActor struct Keys04SessionTests {
    private func home() -> URL { FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString) }
    private func object(_ bytes: Data) throws -> [String: Any] {
        try #require(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
    }
    private func body(_ records: [String: Data], _ seq: Int) throws -> [String: Any] {
        let record = try #require(records[String(format: "authority/%08d.json", seq)])
        let envelope = try object(record)
        let encoded = try #require(envelope["body"] as? String)
        let bytes = try #require(Data(base64Encoded: encoded))
        return try object(bytes)
    }
    private func id(_ keys: any AsyncKeyProvider) async throws -> String { try await SessionAuthority.id(keys) }

    @Test(arguments: [false, true]) func genesisUsesSeparatePrincipalsAndTwoSigningRounds(_ withKit: Bool) async throws {
        let home = home(); defer { try? FileManager.default.removeItem(at: home) }
        let member = ObservedKeys(), owner = ObservedKeys(), kit = SoftwareKeys(), store = MemoryRecordStore()
        let configuration = SessionConfiguration(memberLabel: "Device", namespaces: ["notes"], libraryNamespaces: ["notes", "reading.saved"],
            location: .memory(store), privateContainer: home, keys: member, ownerController: owner, recoveryKeys: withKit ? kit : nil)
        let session = ColophonSession(configuration: configuration)
        await session.create(); try #require(session.phase == .ready)
        let records = try await store.read(), genesis = try body(records, 1)
        #expect(genesis["protocol"] as? String == "colophon/authority/4")
        let ring = try #require(genesis["keyring"] as? [String: Any])
        let controllers = try #require(ring["controllers"] as? [[String: Any]])
        #expect(controllers.count == (withKit ? 2 : 1))
        let roleSets = controllers.compactMap { $0["roles"] as? [String] }
        #expect(roleSets.contains(["approve", "control"]))
        #expect(roleSets.contains(["recover"]) == withKit)
        #expect(ring["threshold"] as? Int == 1)
        #expect(ring["recoverThreshold"] as? Int == (withKit ? 1 : 0))
        #expect((ring["slots"] as? [Any])?.count == controllers.count)
        let ownerID = try await id(owner), memberID = try await id(member)
        #expect(ownerID != memberID)
        #expect(genesis["by"] as? String == ownerID)
        #expect(try body(records, 2)["kind"] as? String == "rekey")
        #expect(try body(records, 3)["kind"] as? String == "grant")
        #expect(try body(records, 4)["layout"] as? Int == 2)
        #expect(session.memberID == memberID)
        #expect(session.members.count == 1)
        #expect(session.members.first?.grant?.namespaces == ["notes", "reading.saved"])
        #expect(session.members.first?.grant?.access == [.read, .write])
        let memberBodies = try await member.signed.map(object)
        let controllerBodies = try await owner.signed.map(object)
        #expect(memberBodies.filter { $0["protocol"] as? String == "colophon/request/3" }.count == 1)
        #expect(memberBodies.first?["kind"] as? String == "device")
        #expect(controllerBodies.compactMap { $0["kind"] as? String } == ["genesis", "rekey", "grant", "layout"])
        let reopened = ColophonSession(configuration: configuration)
        await reopened.restore(); #expect(reopened.phase == .ready)
    }

    @Test func sharingMemberAndControllerKeysFailsBeforePublication() async throws {
        let home = home(); defer { try? FileManager.default.removeItem(at: home) }
        let keys = SoftwareKeys(), store = MemoryRecordStore()
        let session = ColophonSession(configuration: .init(memberLabel: "Invalid", namespaces: ["notes"], location: .memory(store),
            privateContainer: home, keys: keys, ownerController: keys))
        await session.create()
        guard case .failed = session.phase else { Issue.record("Shared principals must be rejected"); return }
        #expect(try await store.read().isEmpty)
    }

    @Test func controllerUnlockFailureDoesNotPublishAnApproval() async throws {
        let home = home(); defer { try? FileManager.default.removeItem(at: home) }
        let store = MemoryRecordStore(), owner = ObservedKeys()
        let session = ColophonSession(configuration: .init(memberLabel: "Owner", namespaces: ["notes"], location: .memory(store),
            privateContainer: home, keys: SoftwareKeys(), ownerController: owner))
        await session.create(); try #require(session.phase == .ready)
        let request = try await Library.requestAccess(libraryID: #require(session.libraryID), keys: SoftwareKeys(), label: "Reader", kind: .app,
            namespaces: ["notes"], access: [.read])
        try await store.append(["requests/\(request.id).json": request.record])
        await session.refresh()
        // Let any store-watcher refresh triggered by the append finish before the failing action,
        // so it can't land afterwards and replace the failure phase.
        let deadline = ContinuousClock.now + .seconds(20)
        while !(session.phase == .ready && session.requests.contains { $0.id == request.id }) {
            guard ContinuousClock.now < deadline else { Issue.record("Session never settled"); return }
            try await Task.sleep(for: .milliseconds(50))
        }
        let before = try await store.read()
        await owner.lockAgreement()
        await #expect(throws: (any Error).self) { try await session.approve(request) }
        #expect(try await store.read() == before)
        guard case .failed(.keysUnavailable) = session.phase else { Issue.record("Controller failure must be retryable"); return }
    }

    @Test func kitRestoresControllerThenGrantsTheNewMember() async throws {
        let home = home(); defer { try? FileManager.default.removeItem(at: home) }
        let store = MemoryRecordStore(), kit = SoftwareKeys(), owner = SoftwareKeys()
        let first = ColophonSession(configuration: .init(memberLabel: "Original", namespaces: ["notes"], location: .memory(store),
            privateContainer: home.appendingPathComponent("original"), keys: SoftwareKeys(), ownerController: owner, recoveryKeys: kit))
        await first.create(); try #require(first.phase == .ready)
        try await first.perform(DomainCommand(namespace: "notes", kind: "createNotebook", payloadJSON: Data(#"{"id":"n","title":"History"}"#.utf8)), observed: first.observedRevision)
        let before = try await store.read()
        let member = SoftwareKeys(), replacement = SoftwareKeys()
        let configuration = SessionConfiguration(memberLabel: "Replacement", namespaces: ["notes"], location: .memory(store),
            privateContainer: home.appendingPathComponent("replacement"), keys: member, ownerController: replacement)
        let restored = ColophonSession(configuration: configuration)
        await restored.restore()
        guard case .waitingForApproval = restored.phase else { Issue.record("Expected a new member request"); return }
        try await restored.restoreDevice(using: kit)
        #expect(restored.phase == .ready)
        let memberID = try await id(member), kitID = try await id(kit), replacementID = try await id(replacement)
        #expect(restored.memberID == memberID)
        #expect(restored.libraryID == first.libraryID)
        let after = try await store.read()
        for (path, bytes) in before { #expect(after[path] == bytes) }
        let change = try body(after, 5)
        #expect(change["kind"] as? String == "keyring")
        #expect(change["by"] as? String == kitID)
        #expect(try body(after, 6)["by"] as? String == replacementID)
        let ring = try #require(change["keyring"] as? [String: Any])
        #expect((ring["controllers"] as? [Any])?.count == 3)
        #expect((ring["slots"] as? [Any])?.count == 3)
        let state = try await restored.query(namespace: "notes", name: "read", arguments: Data("{}".utf8))
        #expect(String(decoding: state, as: UTF8.self).contains("History"))
        let reopened = ColophonSession(configuration: configuration)
        await reopened.restore(); #expect(reopened.phase == .ready)
        let request = try await Library.requestAccess(libraryID: #require(reopened.libraryID), keys: SoftwareKeys(), label: "Next", kind: .agent, namespaces: ["notes"], access: [.read])
        try await store.append(["requests/\(request.id).json": request.record]); await reopened.refresh()
        try await reopened.approve(request)
        #expect(reopened.members.contains { $0.id == request.id })
    }

    @Test(arguments: [false, true]) func copyingUsesExplicitImportGrant(_ allowed: Bool) async throws {
        let home = home(); defer { try? FileManager.default.removeItem(at: home) }
        let store = MemoryRecordStore()
        let sourceID = String(repeating: "a", count: 32)
        let session = ColophonSession(configuration: .init(memberLabel: "Copy", namespaces: ["notes"], location: .memory(store),
            privateContainer: home, keys: SoftwareKeys(), ownerController: SoftwareKeys(), migrationWriter: true,
            importExpires: allowed ? Date.now.addingTimeInterval(3600).ISO8601Format() : nil, importedFrom: sourceID))
        await session.create(); try #require(session.phase == .ready)
        let before = try await store.read()
        #expect(try body(before, 1)["importedFrom"] as? String == sourceID)
        #expect(session.members.first?.grant?.import == (allowed ? true : nil))
        let command = try DomainCommand(namespace: "notes", kind: "colophon.importBatch", payloadJSON: Data(#"{"key":"unit","evidence":{"sourceLibrary":"old"},"children":[]}"#.utf8))
        if allowed {
            let receipt = try await session.performMigration(command, outputKey: "unit")
            guard case .saved = receipt else { Issue.record("Import did not publish"); return }
            #expect(try await session.performMigration(command, outputKey: "unit") == receipt)
            #expect(try await store.paths().filter { $0.hasPrefix("ops/") }.count == 1)
        } else {
            await #expect(throws: (any Error).self) { try await session.performMigration(command, outputKey: "unit") }
            #expect(try await store.read() == before)
        }
    }
}

private struct TestPasskey: AsyncKeyProvider {
    let signing = P256.Signing.PrivateKey()
    let output = Data(repeating: 71, count: 32)
    var form: KeyForm { .webauthn }
    func publicKeys() async throws -> PublicKeys { PublicKeys(signing: signing.publicKey.x963Representation, agreement: Data()) }
    func sign(body: Data) async throws -> Data { throw BindingError.KeyProvider(detail: "Assertion required") }
    func agree(peer: Data) async throws -> Data { throw BindingError.KeyProvider(detail: "PRF required") }
    func prf(salt: Data) async throws -> Data? { output }
    func assert(challenge: String, prfSalt: Data?) async throws -> WebauthnResult? {
        let auth = Data(SHA256.hash(data: Data("id.luff.works".utf8))) + Data([5, 0, 0, 0, 0])
        let client = try JSONSerialization.data(withJSONObject: ["type": "webauthn.get", "challenge": challenge, "origin": "https://id.luff.works"])
        let message = auth + Data(SHA256.hash(data: client))
        return WebauthnResult(signature: try signing.signature(for: message).derRepresentation, authenticatorData: auth,
            clientData: client, prf: prfSalt == nil ? nil : output)
    }
    func controller() throws -> Data {
        try JSONSerialization.data(withJSONObject: ["key": ["form": "webauthn", "signing": signing.publicKey.x963Representation.base64EncodedString(),
            "rp": "id.luff.works", "credential": Data([1, 2, 3]).base64EncodedString()], "label": "External passkey", "roles": ["approve", "control"], "verification": true], options: [.sortedKeys])
    }
}

extension Keys04SessionTests {
    @Test func externalProviderOpensPrfSlotAndSignsApproval() async throws {
        let home = home(); defer { try? FileManager.default.removeItem(at: home) }
        let store = MemoryRecordStore(), member = SoftwareKeys(), owner = SoftwareKeys(), passkey = TestPasskey()
        let initial = SessionConfiguration(memberLabel: "Device", namespaces: ["notes"], location: .memory(store), privateContainer: home,
            keys: member, ownerController: owner)
        let library = try await SessionAuthority.create(initial)
        let controller = try passkey.controller()
        let descriptor = try JSONSerialization.data(withJSONObject: #require(object(controller)["key"]))
        let slot = try await library.buildPasskeySlot(descriptor: descriptor, provider: passkey, label: "External passkey")
        try await library.addPasskey(controller: controller, slot: slot, signers: [id(owner)])
        try await store.append(library.records)
        let session = ColophonSession(configuration: .init(memberLabel: "Device", namespaces: ["notes"], location: .memory(store),
            privateContainer: home, keys: member, ownerController: passkey))
        await session.restore(); try #require(session.phase == .ready)
        let request = try await Library.requestAccess(libraryID: #require(session.libraryID), keys: SoftwareKeys(), label: "Reader", kind: .app,
            namespaces: ["notes"], access: [.read])
        try await store.append(["requests/\(request.id).json": request.record]); await session.refresh()
        try await session.approve(request)
        #expect(session.members.contains { $0.id == request.id })
        let envelope = try object(#require(try await store.read()["authority/00000006.json"]))
        #expect(envelope["assertion"] != nil)
    }

    @Test func smallerRecoveryQuorumAddsApproveOnlyController() async throws {
        let home = home(); defer { try? FileManager.default.removeItem(at: home) }
        let store = MemoryRecordStore(), owner = SoftwareKeys(), second = SoftwareKeys(), kit = SoftwareKeys()
        let initial = SessionConfiguration(memberLabel: "Original", namespaces: ["notes"], location: .memory(store), privateContainer: home,
            keys: SoftwareKeys(), ownerController: owner, recoveryKeys: kit)
        let library = try await SessionAuthority.create(initial)
        let publicKeys = try await second.publicKeys()
        let controller = try JSONSerialization.data(withJSONObject: ["key": ["form": "raw", "signing": publicKeys.signing.base64EncodedString(),
            "agreement": publicKeys.agreement.base64EncodedString()], "label": "Second", "roles": ["control"]], options: [.sortedKeys])
        let slot = try await library.buildSealedSlot(controller: controller, label: "Second")
        try await library.addController(controller: controller, slot: slot, signers: [id(owner)])
        var ring = try object(await library.keyring()); ring["threshold"] = 2
        try await library.replaceKeyring(JSONSerialization.data(withJSONObject: ring), signers: [id(owner)])
        try await store.append(library.records)
        let replacement = SoftwareKeys()
        let session = ColophonSession(configuration: .init(memberLabel: "Replacement", namespaces: ["notes"], location: .memory(store),
            privateContainer: home.appendingPathComponent("replacement"), keys: SoftwareKeys(), ownerController: replacement))
        await session.restore(); try await session.restoreDevice(using: kit)
        #expect(session.phase == .ready)
        let records = try await store.read(), restoredRing = try #require(body(records, 7)["keyring"] as? [String: Any])
        let controllers = try #require(restoredRing["controllers"] as? [[String: Any]])
        let signing = try replacement.signingPublicKey().base64EncodedString()
        let added = try #require(controllers.first { ($0["key"] as? [String: Any])?["signing"] as? String == signing })
        #expect(added["roles"] as? [String] == ["approve"])
        #expect(restoredRing["threshold"] as? Int == 2)
        #expect(restoredRing["recoverThreshold"] as? Int == 1)
        #expect(try body(records, 8)["kind"] as? String == "grant")
    }
}
