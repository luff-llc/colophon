import ColophonKit
import CryptoKit
import Foundation
import Testing

private func json(_ text: String) -> Data { Data(text.utf8) }

struct LibraryTests {
    @Test func agentJourney() async throws {
        let owner = SoftwareKeys()
        let agentKeys = SoftwareKeys()
        let library = try await createLibrary(owner: owner, label: "Library", ownerLabel: "Owner",
                                            namespaces: ["notes", "reading.saved"])
        let notebook = try await library.write(namespace: "notes", kind: "createNotebook",
                                             payload: json(#"{"id":"book","title":"Ideas"}"#)).get()
        #expect(notebook.origin == .person)
        let request = try await Library.requestAccess(libraryID: library.id, keys: agentKeys, label: "Muse", kind: .agent,
                                                      namespaces: ["notes", "reading.saved"], access: [.read, .write])
        #expect(request.pairingCode.count == 6)
        let approved = try await library.approve(request: request.record, grant: GrantOptions.narrowing(namespaces: ["notes"], writeBudget: 3)).get()
        #expect(approved.kind == .agent)
        #expect(approved.grant?.namespaces == ["notes"])
        let agent = try await Library.open(records: library.records, me: agentKeys)
        let note = try await agent.write(namespace: "notes", kind: "addNote",
                                         payload: json(#"{"id":"note","notebook":"book","text":"Keep this","origin":"person"}"#)).get()
        #expect(note.origin == .ai)
        #expect(note.author == request.id)
        if case .failure(let denial) = try await agent.view(namespace: "reading.saved") {
            #expect(denial.reason == .notGranted)
        } else { Issue.record("Narrowed namespace was readable") }
        let changes = try await library.merge(records: agent.records)
        #expect(changes.recordsAdded == 1)
        #expect(changes.namespaces.contains("notes"))
        try await library.revoke(memberID: request.id).get()
        try await agent.merge(records: library.records)
        if case .failure(let denial) = try await agent.write(namespace: "notes", kind: "addNote",
                                                             payload: json(#"{"id":"later","notebook":"book","text":"No"}"#)) {
            #expect(denial.reason == .revoked)
        } else { Issue.record("Revoked agent wrote") }
        let restoredKeys = try SoftwareKeys(signingPrivateKey: owner.signingPrivateKey, agreementPrivateKey: owner.agreementPrivateKey)
        let restored = try await Library.open(records: library.records, me: restoredKeys)
        let view = try await restored.view(namespace: "notes").get()
        #expect(view.admitted.contains { $0.id == note.id && $0.origin == .ai && $0.authorLabel == "Muse" })
        #expect(String(decoding: view.state, as: UTF8.self).contains("Keep this"))
        let ledger = try await restored.ledger()
        #expect(ledger.contains { $0.event == .revoked })
        #expect(ledger.contains { $0.event == .wrote && $0.origin == .ai && $0.namespace == "notes" })
        #expect(try await restored.members().first { $0.id == request.id }?.revokedAt != nil)
        let queried = try await restored.call(tool: "notes__read", input: json("{}")).get()
        #expect(String(decoding: queried, as: UTF8.self).contains("Keep this"))
        #expect(try await restored.tools().contains { $0.name == "notes__addNote" })
        let toolWrite = try await restored.call(tool: "notes__createNotebook", input: json(#"{"id":"tools","title":"Tools"}"#)).get()
        #expect(String(decoding: toolWrite, as: UTF8.self).contains("\"payload\":{\"id\":\"tools\""))
        let unchanged = try await restored.merge(records: restored.records)
        #expect(unchanged.recordsAdded == 0)
        #expect(unchanged.namespaces.isEmpty)
    }

    @Test func softwareProviderAndCallbackRoundTrip() async throws {
        let keys = SoftwareKeys()
        let peer = SoftwareKeys()
        let message = json("exact bytes")
        let publicKey = try P256.Signing.PublicKey(x963Representation: keys.signingPublicKey())
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: keys.sign(body: message))
        #expect(publicKey.isValidSignature(signature, for: message))
        #expect(try keys.agree(peer: peer.agreementPublicKey()) == peer.agree(peer: keys.agreementPublicKey()))
        #expect(throws: BindingError.self) { try keys.agree(peer: Data([0])) }
        let action = try beginCreate(owner: await keys.publicKeys(), controller: await peer.publicKeys(), vaultSeed: Data(repeating: 8, count: 32), label: "Callbacks",
                                     ownerLabel: "Owner", namespaces: ["notes"], now: "2026-11-06T00:00:00Z", entropy: Data(repeating: 7, count: 32))
        let first = try action.signingSteps().map { step in
            try (step.signingKey == keys.signingPublicKey() ? keys : peer).sign(body: step.body)
        }
        let final = try action.advanceCreate(signatures: first)
        let records = try final.finish(signatures: final.signWith(keys: peer))
        let native = try NativeLibrary.open(records: records, me: await keys.publicKeys())
        let change = try native.readyWith(keys: keys)
        #expect(change.namespaces == ["notes"])
        if case .success = try native.view(namespace: "notes", now: "2026-11-06T00:00:00Z") {} else { Issue.record("Callback failed to unlock") }
        #expect(throws: BindingError.self) { try action.signWith(keys: peer) }
        #expect(throws: BindingError.self) { try native.readyWith(keys: peer) }
    }

    @Test func invalidSignatureIsAtomicAndStaleActionsRefuse() async throws {
        let keys = SoftwareKeys()
        let library = try await createLibrary(owner: keys, label: "L", ownerLabel: "O", namespaces: ["notes"])
        let native = library.native
        let first = try native.beginWrite(namespace: "notes", kind: "createNotebook", payload: json(#"{"id":"a","title":"A"}"#),
                                          now: "2026-11-06T00:00:00Z", entropy: Data(repeating: 1, count: 32))
        let second = try native.beginWrite(namespace: "notes", kind: "createNotebook", payload: json(#"{"id":"b","title":"B"}"#),
                                           now: "2026-11-06T00:00:00Z", entropy: Data(repeating: 2, count: 32))
        guard case .ready(let a) = first, case .ready(let b) = second else { Issue.record("Expected prepared writes"); return }
        let before = try native.records()
        #expect(throws: BindingError.self) { try native.commit(action: a, signatures: [Data(repeating: 0, count: 64)]) }
        #expect(try native.records() == before)
        _ = try native.commit(action: a, signatures: a.signWith(keys: keys))
        #expect(throws: BindingError.StaleAction) { try native.commit(action: b, signatures: b.signWith(keys: keys)) }
        #expect(try native.records().count == before.count + 1)
    }

    @Test(.enabled(if: !SecureEnclave.isAvailable)) func enclaveRequiresExplicitFallback() throws {
        // Hardware use needs an entitled host; this test covers simulator/unavailable policy.
        if !SecureEnclave.isAvailable {
            #expect(throws: KeyError.self) { try SecureEnclaveKeys() }
            let fallback = try SecureEnclaveKeys(fallback: .software)
            #expect(!fallback.isHardwareBacked)
            #expect(fallback.signingReference == nil)
            #expect(try fallback.sign(body: json("body")).count == 64)
        }
    }
}

private actor PausingKeys: AsyncKeyProvider {
    let base = SoftwareKeys()
    private var armed = false
    private var paused = false
    private var continuation: CheckedContinuation<Void, Never>?
    private var observer: CheckedContinuation<Void, Never>?
    func publicKeys() async throws -> PublicKeys { try await base.publicKeys() }
    func agree(peer: Data) async throws -> Data { try base.agree(peer: peer) }
    func sign(body: Data) async throws -> Data {
        if armed {
            armed = false
            await withCheckedContinuation { continuation in
                self.continuation = continuation
                paused = true
                observer?.resume()
                observer = nil
            }
        }
        return try base.sign(body: body)
    }
    func arm() { armed = true; paused = false }
    func waitUntilPaused() async {
        if !paused { await withCheckedContinuation { observer = $0 } }
    }
    func resume() { continuation?.resume(); continuation = nil; paused = false }
}

struct AsyncProviderTests {
    @Test(.timeLimit(.minutes(1))) func mergeWhileSigningRejectsStaleAction() async throws {
        let keys = PausingKeys()
        let library = try await createLibrary(owner: keys, label: "L", ownerLabel: "O", namespaces: ["notes"])
        let other = try await Library.open(records: library.records, me: keys.base)
        await keys.arm()
        let task = Task {
            try await library.write(namespace: "notes", kind: "createNotebook", payload: json(#"{"id":"stale","title":"Stale"}"#))
        }
        await keys.waitUntilPaused()
        _ = try await other.write(namespace: "notes", kind: "createNotebook", payload: json(#"{"id":"new","title":"New"}"#)).get()
        try await library.merge(records: other.records)
        await keys.resume()
        await #expect(throws: BindingError.StaleAction) { try await task.value }
        let view = try await library.view(namespace: "notes").get()
        #expect(view.admitted.count == 1)
        #expect(String(decoding: view.state, as: UTF8.self).contains("New"))
    }

    @Test(.timeLimit(.minutes(1))) func cancellationBeforeCommitLeavesRecordsUntouched() async throws {
        let keys = PausingKeys()
        let library = try await createLibrary(owner: keys, label: "L", ownerLabel: "O", namespaces: ["notes"])
        let before = try await library.records
        await keys.arm()
        let task = Task {
            try await library.write(namespace: "notes", kind: "createNotebook", payload: json(#"{"id":"cancelled","title":"Cancelled"}"#))
        }
        await keys.waitUntilPaused()
        task.cancel()
        await keys.resume()
        await #expect(throws: CancellationError.self) { try await task.value }
        #expect(try await library.records == before)
    }
}


private final class FailingKeys: KeyProvider {
    let base: SoftwareKeys
    init(_ base: SoftwareKeys) { self.base = base }
    func signingPublicKey() throws -> Data { try base.signingPublicKey() }
    func agreementPublicKey() throws -> Data { try base.agreementPublicKey() }
    func sign(body: Data) throws -> Data { throw BindingError.KeyProvider(detail: "Host denied signing") }
    func agree(peer: Data) throws -> Data { throw BindingError.KeyProvider(detail: "Host denied agreement") }
}

struct RefusalTests {
    @Test(arguments: [DenialReason.expired, .budgetSpent])
    func restrictedGrant(reason: DenialReason) async throws {
        let owner = SoftwareKeys()
        let agentKeys = SoftwareKeys()
        let library = try await createLibrary(owner: owner, label: "L", ownerLabel: "O", namespaces: ["notes"])
        let request = try await Library.requestAccess(libraryID: library.id, keys: agentKeys, label: "A", kind: .agent,
                                                      namespaces: ["notes"], access: [.read, .write])
        _ = try await library.approve(request: request.record, grant: GrantOptions.narrowing(
            expires: reason == .expired ? "2000-01-01T00:00:00Z" : nil,
            writeBudget: reason == .budgetSpent ? 0 : nil)).get()
        let agent = try await Library.open(records: library.records, me: agentKeys)
        let outcome = try await agent.write(namespace: "notes", kind: "createNotebook", payload: json(#"{"id":"n","title":"N"}"#))
        if case .failure(let denial) = outcome { #expect(denial.reason == reason) }
        else { Issue.record("Expected typed refusal") }
    }

    @Test func lockedKeysAndProviderFailuresAreExplicit() async throws {
        let owner = SoftwareKeys()
        let library = try await createLibrary(owner: owner, label: "L", ownerLabel: "O", namespaces: ["notes"])
        let locked = try NativeLibrary.open(records: await library.records, me: await owner.publicKeys())
        if case .failure(let denial) = try locked.view(namespace: "notes", now: "2026-11-06T00:00:00Z") {
            #expect(denial.reason == .notReadable)
        } else { Issue.record("Locked data should not appear empty") }
        if case .failure(let denial) = try locked.beginWrite(namespace: "notes", kind: "createNotebook", payload: json(#"{"id":"n","title":"N"}"#), now: "2026-11-06T00:00:00Z", entropy: Data(repeating: 8, count: 32)) {
            #expect(denial.reason == .unavailable)
        } else { Issue.record("Locked write should be unavailable") }
        #expect(throws: BindingError.KeyProvider(detail: "Host denied agreement")) {
            try locked.readyWith(keys: FailingKeys(owner))
        }
        let action = try beginRequest(libraryId: await library.id, keys: await owner.publicKeys(), label: "O", kind: .app,
                                      namespaces: ["notes"], access: [.read], now: "2026-11-06T00:00:00Z")
        #expect(throws: BindingError.KeyProvider(detail: "Host denied signing")) { try action.signWith(keys: FailingKeys(owner)) }
    }
}

private func createLibrary(owner: any AsyncKeyProvider, label: String, ownerLabel: String, namespaces: [String]) async throws -> Library {
    try await Library.create(owner: owner, label: label, ownerLabel: ownerLabel, namespaces: namespaces, controller: SoftwareKeys())
}
