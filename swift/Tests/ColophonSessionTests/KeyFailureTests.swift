import Foundation
import Testing
@testable import ColophonSession

private actor FailingKeys: AsyncKeyProvider {
    let base = SoftwareKeys()
    var failPublic = false
    var failSign = false
    func set(publicKeys: Bool = false, sign: Bool = false) { failPublic = publicKeys; failSign = sign }
    func publicKeys() async throws -> PublicKeys {
        if failPublic { throw Failure.locked }
        return try await base.publicKeys()
    }
    func sign(body: Data) async throws -> Data {
        if failSign { throw Failure.locked }
        return try base.sign(body: body)
    }
    func agree(peer: Data) async throws -> Data { try base.agree(peer: peer) }
    enum Failure: Error { case locked }
}
@MainActor struct KeyFailureTests {
    @Test func createRestoreAndRequestHaveRetryableKeyFailures() async throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: home) }
        let store = MemoryRecordStore(), keys = FailingKeys()
        func config(_ sub: String, _ provider: any AsyncKeyProvider) -> SessionConfiguration {
            .init(memberLabel: "Fixture", namespaces: ["notes"], location: .memory(store), privateContainer: home.appendingPathComponent(sub), keys: provider)
        }
        func expectKeyFailure(_ session: ColophonSession) {
            guard case .failed(.keysUnavailable(let detail)) = session.phase else { Issue.record("Expected explicit key failure, got \(session.phase)"); return }
            #expect(!detail.isEmpty)
        }
        await keys.set(publicKeys: true)
        let owner = ColophonSession(configuration: config("owner", keys))
        await owner.create(); expectKeyFailure(owner)
        await keys.set()
        await owner.retry()
        #expect(owner.phase == .ready)
        await keys.set(publicKeys: true)
        let restored = ColophonSession(configuration: config("restore", keys))
        await restored.restore(); expectKeyFailure(restored)
        await keys.set(); await restored.retry()
        #expect(restored.phase == .ready)
        let joinKeys = FailingKeys()
        await joinKeys.set(sign: true)
        let joining = ColophonSession(configuration: config("join", joinKeys))
        await joining.restore(); expectKeyFailure(joining)
        await joinKeys.set(); await joining.retry()
        guard case .waitingForApproval = joining.phase else { Issue.record("Expected signed pairing request after retry"); return }
    }

    @Test func sharedMarkerPreventsEmptyLibraryAndCreation() async throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: home) }
        let marker = home.appendingPathComponent("rollout.json"), store = MemoryRecordStore()
        try MigrationMarker(sourceLibraryID: "old", active: true).save(at: marker)
        let session = ColophonSession(configuration: .init(memberLabel: "Sibling", namespaces: ["notes"], location: .memory(store), privateContainer: home.appendingPathComponent("sibling"), keys: SoftwareKeys(), migrationMarker: marker))
        await session.restore(); #expect(session.phase == .migrating)
        await session.create(); #expect(session.phase == .migrating)
        #expect(try await store.read().isEmpty)
        try MigrationMarker(sourceLibraryID: "old", active: false).save(at: marker)
        await session.refresh(); #expect(session.phase == .noLibrary)
    }
}
