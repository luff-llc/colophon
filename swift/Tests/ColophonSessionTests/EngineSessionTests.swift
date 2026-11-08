import Foundation
import Testing
@testable import ColophonSession
@testable import ColophonKitStorage

@MainActor struct EngineSessionTests {
    @Test func checkpointSkipsHistoryAndOnlyAdmitsSuffix() async throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: home) }
        let keys = SoftwareKeys(), store = MemoryRecordStore()
        let configuration = SessionConfiguration(memberLabel: "Engine", namespaces: ["notes"], location: .memory(store), privateContainer: home, keys: keys)
        let first = SessionWorker(configuration: configuration, store: store)
        var snapshot = try await first.create()
        let command = try DomainCommand(namespace: "notes", kind: "createNotebook", payloadJSON: Data(#"{"id":"n","title":"Notebook"}"#.utf8))
        (_, snapshot) = try await first.write(command, observed: snapshot.revision)
        try await first.saveCheckpoint()
        let reopened = SessionWorker(configuration: configuration, store: store)
        let restored = try await reopened.restore()
        #expect(restored.phase == .ready)
        let engine = try #require(restored.core?.engine)
        let work = try engine.work()
        #expect(work.openMode == "VerifiedPrefix")
        #expect(work.signaturesVerified == 0)
        #expect(work.payloadsDecrypted == 0)
        #expect(work.appliedOperations == 0)
        let suffix = try DomainCommand(namespace: "notes", kind: "addNote", payloadJSON: Data(#"{"id":"a","notebook":"n","text":"Suffix"}"#.utf8))
        _ = try await first.write(suffix, observed: snapshot.revision)
        let third = SessionWorker(configuration: configuration, store: store)
        let changed = try await third.restore()
        let suffixWork = try #require(changed.core?.engine).work()
        #expect(suffixWork.openMode == "VerifiedPrefix")
        #expect(suffixWork.signaturesVerified == 1)
        #expect(suffixWork.appliedOperations == 1)
        let note = try await third.query(namespace: "notes", name: "note", arguments: Data(#"{"id":"a"}"#.utf8))
        #expect(String(decoding: note, as: UTF8.self).contains("Suffix"))
    }
    @Test func protectedCheckpointCannotCrossIdentities() async throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: home) }
        let store = MemoryRecordStore(), keys = SoftwareKeys()
        let config = SessionConfiguration(memberLabel: "Owner", namespaces: ["notes"], location: .memory(store), privateContainer: home, keys: keys)
        let worker = SessionWorker(configuration: config, store: store)
        let snapshot = try await worker.create()
        try await worker.saveCheckpoint()
        let id = try #require(snapshot.core?.libraryID)
        let bytes = try #require(await CheckpointCache(privateContainer: home).load(libraryID: id))
        let other = SoftwareKeys()
        #expect(throws: BindingError.self) {
            _ = try NativeCheckpointOpening(bytes: bytes, libraryId: id, member: PublicKeys(signing: other.signingPublicKey(), agreement: other.agreementPublicKey()))
        }
    }
}

@MainActor struct ThirdReviewSessionTests {
    @Test func authorityRefreshVerifiesHistoryOnce() async throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: home) }
        let store = MemoryRecordStore(), keys = SoftwareKeys()
        func configuration(_ name: String, _ identity: SoftwareKeys, _ kind: MemberKind = .app) -> SessionConfiguration {
            SessionConfiguration(memberLabel: name, memberKind: kind, namespaces: ["notes"], location: .memory(store), privateContainer: home.appendingPathComponent(name), keys: identity)
        }
        let owner = SessionWorker(configuration: configuration("owner", keys), store: store)
        let created = try await owner.create()
        _ = try await owner.write(DomainCommand(namespace: "notes", kind: "createNotebook", payloadJSON: Data(#"{"id":"n","title":"N"}"#.utf8)), observed: created.revision)
        let joining = SessionWorker(configuration: configuration("joining", SoftwareKeys(), .agent), store: store)
        _ = try await joining.restore()
        let request = try #require(try await owner.refresh().core?.requests.first)
        _ = try await owner.approve(request.record, grant: nil)
        let reader = SessionWorker(configuration: configuration("reader", keys), store: store)
        let restored = try await reader.restore()
        let engine = try #require(restored.core?.engine)
        let before = try engine.work()
        _ = try await owner.revoke(request.id)
        let changed = try await reader.refresh()
        #expect(changed.phase == .ready)
        #expect(try engine.work().signaturesVerified - before.signaturesVerified == 1)
        #expect(try engine.work().appliedOperations - before.appliedOperations == 1)
        try await reader.saveCheckpoint()
    }
    @Test func waitingMemberWithLiveStateCanFlushWithoutScheduling() async throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: home) }
        let store = MemoryRecordStore()
        let owner = ColophonSession(configuration: SessionConfiguration(memberLabel: "Owner", namespaces: ["listening.podcasts"], location: .memory(store), privateContainer: home.appendingPathComponent("owner"), keys: SoftwareKeys()))
        await owner.create()
        try await owner.perform(DomainCommand(namespace: "listening.podcasts", kind: "position", payloadJSON: Data(#"{"id":"ep","seconds":10}"#.utf8)), observed: owner.observedRevision)
        let member = ColophonSession(configuration: SessionConfiguration(memberLabel: "Reader", memberKind: .agent, namespaces: ["listening.podcasts"], location: .memory(store), privateContainer: home.appendingPathComponent("reader"), keys: SoftwareKeys()))
        await member.restore()
        guard case .waitingForApproval = member.phase else { Issue.record("Expected approval request"); return }
        #expect(member.checkpointTask == nil)
        try await member.flushCheckpoint()
        guard case .waitingForApproval = member.phase else { Issue.record("Checkpoint changed pairing phase"); return }
    }
}
