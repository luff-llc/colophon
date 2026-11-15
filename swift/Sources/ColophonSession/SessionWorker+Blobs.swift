import CryptoKit
import Foundation

enum BlobStagePlan: Sendable {
    case published(BlobManifestInfo)
    case write(AccountBlobWriter, any RecordMedium)
}

struct StagedBlob: Sendable {
    let digest: String
    let size: Int
    let mediaType: String
    /// The signed manifest to publish; nil when identical content is already published (a reference suffices).
    let manifest: Data?
}

extension SessionWorker {
    /// The engine half of an upload, inside the gate and quick: the published manifest when identical content is
    /// already published, else a blob writer and the medium to store its chunks in. The chunks themselves are
    /// encrypted and stored outside the gate (`BlobIO.store`), so a large upload holds no other session operation.
    func beginBlobStage(namespace: String, mediaType: String, digest: String) async throws -> BlobStagePlan {
        try await inGate {
            let engine = try requireEngine()
            if let existing = try? await blobManifestLocked(engine, namespace: namespace, digest: digest) { return .published(existing) }
            let writer = try await engine.run { engine in try withEntropy(32) { try engine.beginBlob(namespace: namespace, mediaType: mediaType, entropy: $0) } }
            return .write(writer, try storage())
        }
    }

    private func blobManifestLocked(_ engine: ColophonEngine, namespace: String, digest: String) async throws -> BlobManifestInfo {
        let text = try await engine.run { try $0.blobManifestJson(namespace: namespace, digest: digest) }
        guard let info = Self.parseManifest(text) else { throw BlobError.unpublished }
        return info
    }
    func blobManifest(namespace: String, digest: String) async throws -> BlobManifestInfo {
        try await blobManifestLocked(try requireEngine(), namespace: namespace, digest: digest)
    }
    static func parseManifest(_ text: String) -> BlobManifestInfo? {
        guard let object = try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any], object["ok"] as? Bool == true,
              var value = object["value"] as? [String: Any] else { return nil }
        if let inner = value["manifest"] as? [String: Any] { value = inner }
        let descriptor = (value["descriptor"] as? [String: Any]) ?? value
        guard let digest = descriptor["digest"] as? String, let size = (descriptor["size"] as? NSNumber)?.uint64Value,
              let chunks = value["chunks"] as? [Any] else { return nil }
        return BlobManifestInfo(digest: digest, size: size, mediaType: (descriptor["mediaType"] as? String) ?? "application/octet-stream", chunks: chunks.count)
    }
    func blobAvailability(namespace: String, digest: String) async throws -> BlobAvailability {
        let engine = try requireEngine()
        guard let manifest = try? await blobManifestLocked(engine, namespace: namespace, digest: digest) else { return .unpublished }
        let availability = try await engine.run { try $0.blobAvailability(namespace: namespace, digest: digest) }
        switch availability.state {
        case .complete: return .available
        case .partial: return .missing(presentChunks: Int(availability.present), totalChunks: Int(availability.total))
        case .missing: return .missing(presentChunks: 0, totalChunks: manifest.chunks)
        case .inaccessible: return .inaccessible(reason: availability.detail ?? "not readable")
        }
    }
    func blobChunk(namespace: String, digest: String, index: Int) async throws -> Data {
        let engine = try requireEngine()
        do { return try await engine.run { try $0.blobChunk(namespace: namespace, digest: digest, index: UInt64(index)) } }
        catch let error as ColophonError {
            switch error {
            case .unavailable(_, let detail): throw BlobError.missing(detail)
            case .denied(_, _, _, let detail): throw BlobError.inaccessible(detail)
            case .malformed(_, let detail), .badSignature(_, _, let detail): throw BlobError.invalid(detail)
            default: throw error
            }
        }
    }
    func requiredBlobFetches(namespace: String) async throws -> [String] {
        try await requireEngine().run { try $0.requiredBlobFetches(namespace: namespace) }
    }
    func homeIDs() async throws -> [String] { try await requireEngine().run { try $0.exchangeHomes() }.map(\.id) }
    func wantBlob(home: String, namespace: String, digest: String) async throws {
        _ = try await requireEngine().run { try $0.exchangeWantBlob(home: home, namespace: namespace, digest: digest) }
    }
}
