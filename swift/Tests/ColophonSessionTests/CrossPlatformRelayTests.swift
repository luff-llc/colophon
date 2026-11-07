import Foundation
import Testing
@testable import ColophonSession
@testable import ColophonKitStorage

/// One step of scripts/test-relay-cross.sh: an Apple session and an Android session share one
/// library through one reference relay. Skipped unless the script sets COLOPHON_CROSS_STEP.
private let crossEnvironment = ProcessInfo.processInfo.environment
private let crossStep = crossEnvironment["COLOPHON_CROSS_STEP"]

/// Deterministic blob content both platforms compute: three 64 KiB chunks plus a tail.
func crossBlob(seed: Int) -> Data { Data((0..<150_000).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ seed) }) }

@MainActor struct CrossPlatformRelayTests {
    @Test(.enabled(if: crossStep != nil)) func crossPlatformStep() async throws {
        let dir = URL(fileURLWithPath: try #require(crossEnvironment["COLOPHON_CROSS_DIR"]))
        let url = try #require(crossEnvironment["COLOPHON_CROSS_URL"].flatMap(URL.init(string:)))
        let token = try #require(crossEnvironment["COLOPHON_CROSS_TOKEN"])
        let keyFile = dir.appendingPathComponent("apple-keys.json")
        let keys: SoftwareKeys
        if let stored = try? JSONDecoder().decode([Data].self, from: Data(contentsOf: keyFile)), stored.count == 2 {
            keys = try SoftwareKeys(signingPrivateKey: stored[0], agreementPrivateKey: stored[1])
        } else {
            keys = SoftwareKeys()
            try JSONEncoder().encode([keys.signingPrivateKey, keys.agreementPrivateKey]).write(to: keyFile)
        }
        let library = dir.appendingPathComponent("apple-library")
        let session = ColophonSession(configuration: .init(memberLabel: "iPhone", namespaces: ["reading.saved", "notes", "listening.podcasts"], location: .folder(library),
                                                           privateContainer: dir.appendingPathComponent("apple-home"), keys: keys,
                                                           relay: RelayConfiguration(url: url, token: token, automatic: false)),
                                      store: FolderRecordStore(folder: library, coordinated: false))
        await session.restore()
        switch crossStep {
        case "create":
            #expect(session.phase == .noLibrary)
            await session.create()
            #expect(session.phase == .ready)
            try await session.perform(.saveLink(id: "from-apple", url: #require(URL(string: "https://example.com/apple")), title: "Apple"), observed: session.observedRevision)
            for seconds in [10, 20, 30] {
                let command = try DomainCommand(namespace: "listening.podcasts", kind: "position", payloadJSON: Data("{\"id\":\"cross-episode\",\"seconds\":\(seconds)}".utf8))
                try await session.perform(command, observed: session.observedRevision)
            }
            // A lazily fetched blob: Android reads it on demand through the relay.
            let blob = try await session.putBlob(crossBlob(seed: 1), namespace: "notes", mediaType: "application/octet-stream", reference: "apple-attachment")
            try Data(blob.digest.utf8).write(to: dir.appendingPathComponent("apple-blob.txt"))
        case "approve":
            #expect(await session.syncNow())
            let request = try #require(session.requests.first, "The Android request should arrive through the relay")
            try await session.approve(request)
        case "verify":
            #expect(await session.syncNow())
            let store = NamespaceStore<SavedLinksQuery, [SavedLink]>(savedLinksIn: session)
            let ids = try await store.load(.init()).map(\.id).sorted()
            store.close()
            #expect(ids == ["from-android", "from-apple"])
            let episode = try await session.query(namespace: "listening.podcasts", name: "getEpisode", arguments: Data(#"{"id":"cross-episode"}"#.utf8))
            let row = try #require(JSONSerialization.jsonObject(with: episode) as? [String: Any])
            #expect(row["seconds"] as? Double == 50, "Playback row: \(row)")
            let seek = try DomainCommand(namespace: "listening.podcasts", kind: "position", payloadJSON: Data(#"{"id":"cross-episode","seconds":5,"seek":true}"#.utf8))
            try await session.perform(seek, observed: session.observedRevision)
            // Android marked its blob required: the pass that delivered its manifest downloaded it.
            let digest = try String(decoding: Data(contentsOf: dir.appendingPathComponent("android-blob.txt")), as: UTF8.self)
            #expect(await session.blobAvailability(namespace: "notes", digest: digest) == .available)
            let bytes = try await session.blobData(namespace: "notes", digest: digest)
            #expect(bytes == crossBlob(seed: 2), "Android's blob reached Apple intact")
        default: Issue.record("Unknown step \(crossStep ?? "")")
        }
        #expect(await session.syncNow())
        #expect(session.syncState == .idle)
    }
}
