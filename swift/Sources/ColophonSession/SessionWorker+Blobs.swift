import Foundation
import CryptoKit
import ColophonKit
import ColophonKitStorage

/// The signed manifest fields the session needs to locate and verify chunks.
struct BlobManifestInfo: Decodable, Sendable {
    struct Descriptor: Decodable, Sendable { let digest: String; let size: UInt64; let mediaType: String }
    struct Chunk: Decodable, Sendable { let path: String; let size: UInt64 }
    let descriptor: Descriptor
    let chunks: [Chunk]
}
private struct BlobQueryResult: Decodable {
    let manifest: BlobManifestInfo?
    let references: Int
    let required: Bool?
}
private struct BlobsPage: Decodable {
    struct Row: Decodable { let digest: String; let references: Int; let required: Bool }
    let blobs: [Row]
    let next: String?
}
struct StagedBlob: Sendable {
    /// Signed-manifest JSON to publish, or nil when identical content is already published.
    let manifest: Data?
    let digest: String
    let size: Int
    let mediaType: String
}

/// Streaming SHA-256 and length over plaintext in manifest order.
struct BlobDigest {
    private var hash = SHA256()
    private var size: UInt64 = 0
    mutating func update(_ bytes: Data) { hash.update(data: bytes); size += UInt64(bytes.count) }
    func finish() -> (String, UInt64) { (hash.finalize().map { String(format: "%02x", $0) }.joined(), size) }
}

/// One manifest is published in one ordinary command (at most 1 MiB), which bounds it to
/// 4,000 chunks (250 MiB). Larger assets are split into application-level parts.
let maximumBlobChunks = 4000

extension SessionWorker {
    private func blobStore() throws -> any BlobStore {
        guard let blobs = try storage() as? any BlobStore else { throw BlobError.inaccessible("This storage location keeps no blobs") }
        return blobs
    }

    func stageBlob(namespace: String, mediaType: String, input: BlobInput) async throws -> StagedBlob {
        await enter(); defer { exit() }
        let fresh = try await refreshLocked()
        guard fresh.phase == .ready else { throw SessionError.notReady }
        guard configuration.namespaces.contains(namespace), configuration.access.contains(.write) else { throw SessionError.invalidCommand }
        let blobs = try blobStore()
        // Pass 1 addresses the content, so identical bytes are never stored twice.
        var addressing = BlobDigest()
        try await input.forEachChunk { addressing.update($0) }
        let (digest, size) = addressing.finish()
        guard size <= UInt64(maximumBlobChunks) * 65536 else { throw BlobError.tooLarge }
        if let existing = try await blobQuery(namespace: namespace, digest: digest).manifest, existing.descriptor.size == size {
            return StagedBlob(manifest: nil, digest: digest, size: Int(size), mediaType: existing.descriptor.mediaType)
        }
        let writer = try await core.beginBlob(namespace: namespace, mediaType: mediaType)
        var written: [String] = []
        var sealing = BlobDigest()
        // Pass 2 seals and persists. Each chunk is durable and read back before the next is read,
        // so at most one 64 KiB chunk is in memory.
        try await input.forEachChunk { plaintext in
            try Task.checkCancellation()
            sealing.update(plaintext)
            let sealed = try writer.push(plaintext: plaintext)
            try await blobs.appendBlob(sealed.path, bytes: sealed.bytes)
            guard try await blobs.readBlob(sealed.path) == sealed.bytes else { throw SessionError.publicationUncertain }
            written.append(sealed.path)
        }
        try indexBlobs(written)
        guard sealing.finish() == (digest, size) else { throw BlobError.digestMismatch }
        let manifest = try writer.finish()
        guard manifest.count <= 1024 * 1024 - 4096 else { throw BlobError.tooLarge }
        return StagedBlob(manifest: manifest, digest: digest, size: Int(size), mediaType: mediaType)
    }

    private func blobQuery(namespace: String, digest: String) async throws -> BlobQueryResult {
        let arguments = try JSONEncoder().encode(["digest": digest])
        let bytes: Data
        do { bytes = try await core.query(namespace: namespace, name: "blob", arguments: arguments) }
        catch let error as AccessError { throw BlobError.inaccessible(error.denial.detail) }
        do { return try JSONDecoder().decode(BlobQueryResult.self, from: bytes) }
        catch { throw BlobError.invalid("Unreadable blob manifest") }
    }

    func blobManifest(namespace: String, digest: String) async throws -> BlobManifestInfo {
        guard configuration.namespaces.contains(namespace) else { throw SessionError.invalidCommand }
        guard let manifest = try await blobQuery(namespace: namespace, digest: digest).manifest else { throw BlobError.unpublished }
        return manifest
    }

    func blobAvailability(namespace: String, digest: String) async throws -> BlobAvailability {
        let manifest: BlobManifestInfo
        do { manifest = try await blobManifest(namespace: namespace, digest: digest) }
        catch BlobError.unpublished { return .unpublished }
        let blobs = try blobStore()
        var present = 0
        for chunk in manifest.chunks where try await blobs.hasBlob(chunk.path) { present += 1 }
        return present == manifest.chunks.count ? .available : .missing(presentChunks: present, totalChunks: manifest.chunks.count)
    }

    /// Makes one encrypted chunk local: present already, or fetched lazily from the relay.
    func ensureChunk(_ path: String) async throws {
        let blobs = try blobStore()
        if try await blobs.hasBlob(path) { return }
        guard let relay = try relay() else { throw BlobError.missing("No relay is configured to fetch it.") }
        let fetched: Data?
        do { fetched = try await relay.fetchBlob(path) }
        catch let error as RelayError { throw BlobError.missing(error.localizedDescription) }
        guard fetched != nil else { throw BlobError.missing("The relay does not hold it yet.") }
        try indexBlobs([path])
    }

    func readChunk(namespace: String, manifest: BlobManifestInfo, index: Int) async throws -> Data {
        let path = manifest.chunks[index].path
        try await ensureChunk(path)
        let ciphertext = try await blobStore().readBlob(path)
        switch try await core.openBlobChunk(namespace: namespace, digest: manifest.descriptor.digest, index: index, ciphertext: ciphertext) {
        case .available(let bytes): return bytes
        case .missing: throw BlobError.unpublished
        case .inaccessible(let detail): throw BlobError.inaccessible(detail)
        case .invalid(let detail): throw BlobError.invalid(detail)
        }
    }

    private func pageBlobs(namespace: String, requiredOnly: Bool) async throws -> [BlobsPage.Row] {
        var rows: [BlobsPage.Row] = []
        var after: String?
        repeat {
            var arguments: [String: DomainJSON] = ["limit": .number(500)]
            if requiredOnly { arguments["required"] = .bool(true) }
            if let after { arguments["after"] = .string(after) }
            let bytes: Data
            do { bytes = try await core.query(namespace: namespace, name: "blobs", arguments: try JSONEncoder().encode(DomainJSON.object(arguments))) }
            catch let error as AccessError { throw BlobError.inaccessible(error.denial.detail) }
            let page = try JSONDecoder().decode(BlobsPage.self, from: bytes)
            rows += page.blobs; after = page.next
        } while after != nil
        return rows
    }

    /// Required blobs not yet complete here. Completed digests are remembered for this process.
    func incompleteRequiredBlobs(namespace: String) async throws -> [BlobManifestInfo] {
        let blobs = try blobStore()
        var result: [BlobManifestInfo] = []
        for row in try await pageBlobs(namespace: namespace, requiredOnly: true) where !completeRequired.contains(row.digest) {
            guard let manifest = try await blobQuery(namespace: namespace, digest: row.digest).manifest else { continue }
            var complete = true
            for chunk in manifest.chunks where !(try await blobs.hasBlob(chunk.path)) { complete = false; break }
            if complete { completeRequired.insert(row.digest) } else { result.append(manifest) }
        }
        return result
    }

    func collectBlobGarbage(gracePeriod: TimeInterval, evictReplicated: Bool, discardSoleCopy: Bool = false) async throws -> BlobCollection {
        await enter(); defer { exit() }
        let blobs = try blobStore()
        var live = Set<String>(), dead = Set<String>(), pinned = Set<String>()
        for namespace in configuration.namespaces {
            // An unreadable namespace throws here, so nothing is deleted without complete evidence.
            for row in try await pageBlobs(namespace: namespace, requiredOnly: false) {
                guard let manifest = try await blobQuery(namespace: namespace, digest: row.digest).manifest else { continue }
                let paths = manifest.chunks.map(\.path)
                if row.references > 0 || row.required { live.formUnion(paths) } else { dead.formUnion(paths) }
                if row.required { pinned.formUnion(paths) }
            }
        }
        let indexed = try loadBlobIndex()
        let local = try await blobs.blobPaths()
        let relay = try relay()
        var result = BlobCollection()
        var removed: [String] = []
        for (path, modified) in local where indexed.contains(path) {
            var remove = false
            if live.contains(path) {
                if evictReplicated, !pinned.contains(path), let relay, try await relay.relayHolds(path) { remove = true }
            } else if dead.contains(path) {
                // A zero-reference blob on a device without a confirmed other holder is the only copy.
                if discardSoleCopy { remove = true }
                else if let relay, try await relay.relayHolds(path) { remove = true }
            } else if modified.addingTimeInterval(gracePeriod) < .now {
                // A chunk no manifest names: an upload that never published.
                remove = true
            }
            if remove {
                let size = (try? await blobs.readBlob(path).count) ?? 0
                try await blobs.removeBlob(path)
                removed.append(path); result.removedChunks += 1; result.removedBytes += size
            } else { result.keptChunks += 1 }
        }
        if !removed.isEmpty { try rewriteBlobIndex(indexed.subtracting(removed)) }
        completeRequired = []
        return result
    }

    // Private index of chunks this session wrote or downloaded. Garbage collection only ever
    // considers these, so a shared App Group store never loses another app's chunks.
    private var blobIndexURL: URL { configuration.privateContainer.appendingPathComponent("blob-index.log") }
    private func loadBlobIndex() throws -> Set<String> {
        if let blobIndex { return blobIndex }
        var paths = Set<String>()
        if FileManager.default.fileExists(atPath: blobIndexURL.path) {
            let text = String(decoding: try AtomicFile.read(blobIndexURL, maximumBytes: 64 * 1024 * 1024), as: UTF8.self)
            for line in text.split(separator: "\n") where (try? BlobPath.validate(String(line))) != nil { paths.insert(String(line)) }
        }
        blobIndex = paths
        return paths
    }
    func indexBlobs(_ paths: [String]) throws {
        var index = try loadBlobIndex()
        let new = paths.filter { !index.contains($0) }
        guard !new.isEmpty else { return }
        try AtomicFile.append(Data(new.map { $0 + "\n" }.joined().utf8), to: blobIndexURL)
        index.formUnion(new); blobIndex = index
    }
    private func rewriteBlobIndex(_ paths: Set<String>) throws {
        try AtomicFile.write(Data(paths.sorted().map { $0 + "\n" }.joined().utf8), to: blobIndexURL)
        blobIndex = paths
    }
}

