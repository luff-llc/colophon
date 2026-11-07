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
