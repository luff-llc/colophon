import CryptoKit
import Foundation
import Testing
import ColophonSession

@MainActor struct BlobTests {
    private func digest(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
    private func bytes(_ count: Int, seed: UInt8 = 7) -> Data { Data((0..<count).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ Int(seed)) }) }

    @Test func aBlobIsStoredInChunksAndReadBackVerified() async throws {
        let device = Device()
        await device.session.create()
        let content = bytes(200_000)
        let blob = try await device.session.putBlob(content, namespace: "reading.saved", mediaType: "application/octet-stream", reference: "item-1")
        #expect(blob.digest == digest(content) && blob.size == content.count)
        guard case .saved = blob.receipt else { Issue.record("not saved"); return }
        #expect(await device.session.blobAvailability(namespace: "reading.saved", digest: blob.digest) == .available)
        #expect(try await device.session.blobData(namespace: "reading.saved", digest: blob.digest) == content)
        let file = try await device.session.blobFile(namespace: "reading.saved", digest: blob.digest)
        defer { try? FileManager.default.removeItem(at: file) }
        #expect(try Data(contentsOf: file) == content)
        let chunks = device.medium.snapshot().keys.filter { $0.hasPrefix("blobs/") }
        #expect(chunks.count == 4, "200,000 bytes are four chunks of at most 64 KiB")
        // The same content again adds a reference, not chunks.
        let again = try await device.session.putBlob(content, namespace: "reading.saved", mediaType: "application/octet-stream", reference: "item-2")
        #expect(again.digest == blob.digest)
        #expect(device.medium.snapshot().keys.filter { $0.hasPrefix("blobs/") }.count == 4)
    }

    @Test func aBlobThatWasNeverPublishedIsUnpublishedNotEmpty() async throws {
        let device = Device()
        await device.session.create()
        #expect(await device.session.blobAvailability(namespace: "reading.saved", digest: String(repeating: "a", count: 64)) == .unpublished)
        await #expect(throws: (any Error).self) { _ = try await device.session.blobData(namespace: "reading.saved", digest: String(repeating: "a", count: 64)) }
    }

    @Test func aChunkThatWasChangedOnDiskFailsVerificationAndIsNeverReturnedAsContent() async throws {
        let device = Device()
        await device.session.create()
        let content = bytes(70_000, seed: 3)
        let blob = try await device.session.putBlob(content, namespace: "reading.saved", mediaType: "application/octet-stream", reference: "r")
        let chunk = try #require(device.medium.snapshot().keys.sorted().first { $0.hasPrefix("blobs/") })
        var corrupted = try #require(device.medium.snapshot()[chunk])
        corrupted[corrupted.startIndex + 5] ^= 0xff
        device.medium.put(chunk, corrupted)
        var delivered = Data()
        do { delivered = try await device.session.blobData(namespace: "reading.saved", digest: blob.digest); Issue.record("corrupted content was delivered") }
        catch { /* a typed error of the engine or of the blob API; never the bytes */ }
        #expect(delivered.isEmpty)
    }

    // Required and optional blobs through a home: `RelayJourneyTests`, against the real relay.
}
