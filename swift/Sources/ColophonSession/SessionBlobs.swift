import Foundation

/// A published, encrypted, content-addressed blob in one namespace. `digest`, `size` and
/// `mediaType` are the plaintext descriptor domains reference (`{digest,size,mediaType}`).
public struct ColophonBlob: Equatable, Sendable {
    public let namespace: String
    /// SHA-256 of the complete plaintext, lowercase hex.
    public let digest: String
    public let size: Int
    public let mediaType: String
    /// `.saved` when the publication is durable in the local store; `.queued` when it awaits
    /// publication through the session journal (refresh or Retry completes it).
    public let receipt: WriteReceipt?
    public init(namespace: String, digest: String, size: Int, mediaType: String, receipt: WriteReceipt? = nil) {
        self.namespace = namespace; self.digest = digest; self.size = size; self.mediaType = mediaType; self.receipt = receipt
    }
    /// The domain descriptor object, ready for typed or raw command payloads.
    public var descriptor: DomainJSON {
        .object(["digest": .string(digest), "size": .number(Double(size)), "mediaType": .string(mediaType)])
    }
}

/// Never treat anything other than `.available` as empty content.
public enum BlobAvailability: Equatable, Sendable {
    /// No readable manifest: not published yet, its publication has not synced here, or the
    /// namespace is not readable. Show "not downloaded yet", never an empty document.
    case unpublished
    /// The manifest is known and some encrypted chunks are not on this device.
    case missing(presentChunks: Int, totalChunks: Int)
    /// Chunks are being fetched from the relay.
    case downloading(completedChunks: Int, totalChunks: Int)
    /// Every chunk is local; reads verify them again.
    case available
    /// Current grants, keys or storage prevent reading.
    case inaccessible(reason: String)
}

public enum BlobError: Error, Equatable, Sendable {
    case unpublished
    /// A chunk is neither local nor fetchable (no relay, relay unreachable, or relay lacks it).
    case missing(String)
    case inaccessible(String)
    /// Bytes failed their content address, AEAD tag or chunk digest.
    case invalid(String)
    /// The complete content did not match the descriptor.
    case digestMismatch
    case tooLarge
}

extension BlobError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .unpublished: "This content has not reached this device yet."
        case .missing(let detail): "This content is not downloaded yet. " + detail
        case .inaccessible(let detail): "This content is not readable with the current access. " + detail
        case .invalid(let detail): "Stored content failed verification. " + detail
        case .digestMismatch: "Stored content does not match its descriptor."
        case .tooLarge: "This content is too large for one blob. Split it into parts."
        }
    }
}

/// Result of a local garbage-collection pass.
public struct BlobCollection: Equatable, Sendable {
    public var removedChunks = 0
    public var removedBytes = 0
    public var keptChunks = 0
    public init() {}
}

extension ColophonSession {
    /// Encrypts and stores `data` in 64 KiB content-addressed chunks under the namespace epoch
    /// key, then publishes a signed `colophon.blobPublish` manifest with one live reference.
    /// Identical content already published is not uploaded again; a reference is added instead.
    /// `required` asks every device to download it eagerly (offline reading, transcripts).
    public func putBlob(_ data: Data, namespace: String, mediaType: String, reference: String, required: Bool = false) async throws -> ColophonBlob {
        try await putBlob(.data(data), namespace: namespace, mediaType: mediaType, reference: reference, required: required)
    }

    /// Streams a file without loading it into memory. The file is read twice: once to address it,
    /// once to encrypt it. It must not change in between (the digest check would fail).
    public func putBlob(contentsOf file: URL, namespace: String, mediaType: String, reference: String, required: Bool = false) async throws -> ColophonBlob {
        try await putBlob(.file(file), namespace: namespace, mediaType: mediaType, reference: reference, required: required)
    }

    private func putBlob(_ input: BlobInput, namespace: String, mediaType: String, reference: String, required: Bool) async throws -> ColophonBlob {
        await restore()
        guard phase == .ready else { throw SessionError.notReady }
        let lease = context
        let staged = try await worker.stageBlob(namespace: namespace, mediaType: mediaType, input: input)
        guard lease == context else { throw SessionError.destinationChanged }
        // The signed manifest's bytes are embedded unchanged: no numeric re-encoding.
        var fields: [(String, Data)] = [("reference", try JSONEncoder().encode(reference)), ("required", Data((required ? "true" : "false").utf8))]
        let kind: String
        if let manifest = staged.manifest {
            kind = "colophon.blobPublish"; fields.append(("manifest", manifest))
        } else {
            kind = "colophon.blobReference"
            fields.append(("digest", try JSONEncoder().encode(staged.digest))); fields.append(("retain", Data("true".utf8)))
        }
        let command = try DomainCommand(namespace: namespace, kind: kind, payloadJSON: rawJSONObject(fields))
        let receipt = try await perform(command, observed: observedRevision)
        if relayConfigured { requestSync() }
        return ColophonBlob(namespace: namespace, digest: staged.digest, size: staged.size, mediaType: staged.mediaType, receipt: receipt)
    }

    /// Adds (`retain: true`) or removes a live reference. Zero references lets local garbage
    /// collection reclaim this device's copy; it never deletes the relay's or another device's.
    @discardableResult
    public func setBlobReference(_ blob: ColophonBlob, reference: String, retain: Bool, required: Bool? = nil) async throws -> WriteReceipt {
        var payload: [String: DomainJSON] = ["digest": .string(blob.digest), "reference": .string(reference), "retain": .bool(retain)]
        if let required { payload["required"] = .bool(required) }
        let command = try DomainCommand(namespace: blob.namespace, kind: "colophon.blobReference", payload: DomainJSON.object(payload))
        return try await perform(command, observed: observedRevision)
    }

    /// Checks local presence without downloading or decrypting anything.
    public func blobAvailability(namespace: String, digest: String) async -> BlobAvailability {
        await restore()
        if let progress = blobDownloads[digest] { return progress }
        guard phase == .ready else { return .inaccessible(reason: "The library is not ready") }
        do { return try await worker.blobAvailability(namespace: namespace, digest: digest) }
        catch let error as BlobError {
            if case .inaccessible(let reason) = error { return .inaccessible(reason: reason) }
            return .inaccessible(reason: error.localizedDescription)
        } catch { return .inaccessible(reason: error.localizedDescription) }
    }

    /// Complete verified plaintext. Missing chunks are fetched from the relay on demand.
    /// Use `blobFile` or `blobStream` for anything larger than `maximumBytes`.
    public func blobData(namespace: String, digest: String, maximumBytes: Int = 16 * 1024 * 1024) async throws -> Data {
        var result = Data()
        for try await chunk in blobStream(namespace: namespace, digest: digest, maximumBytes: maximumBytes) { result.append(chunk) }
        return result
    }

    /// Writes verified plaintext to a new private temporary file. The caller owns and removes it.
    /// The file only appears at its final URL after the complete digest has been verified.
    public func blobFile(namespace: String, digest: String) async throws -> URL {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("ColophonBlobs", isDirectory: true)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let partial = folder.appendingPathComponent(".partial-" + UUID().uuidString)
        let final = folder.appendingPathComponent(digest + "-" + UUID().uuidString)
        guard FileManager.default.createFile(atPath: partial.path, contents: nil, attributes: [.posixPermissions: 0o600]) else {
            throw StorageFailure.cannotCreate
        }
        do {
            let handle = try FileHandle(forWritingTo: partial)
            defer { try? handle.close() }
            for try await chunk in blobStream(namespace: namespace, digest: digest, maximumBytes: .max) { try handle.write(contentsOf: chunk) }
            try handle.synchronize()
            try FileManager.default.moveItem(at: partial, to: final)
            return final
        } catch { try? FileManager.default.removeItem(at: partial); throw error }
    }

    /// Verified plaintext chunks in order. Each chunk is authenticated before it is yielded; the
    /// stream throws `BlobError.digestMismatch` at the end if the whole content does not match,
    /// so consumers must not certify content until the stream finishes without error.
    public func blobStream(namespace: String, digest: String, maximumBytes: Int = .max) -> AsyncThrowingStream<Data, any Error> {
        let worker = self.worker
        let (stream, continuation) = AsyncThrowingStream<Data, any Error>.makeStream(bufferingPolicy: .bufferingNewest(2))
        let task = Task { [weak self] in
            do {
                guard let self else { throw SessionError.notReady }
                await self.restore()
                guard self.phase == .ready else { throw SessionError.notReady }
                let lease = self.context
                let manifest = try await worker.blobManifest(namespace: namespace, digest: digest)
                guard manifest.descriptor.size <= UInt64(max(0, maximumBytes)) else { throw BlobError.tooLarge }
                var verifier = BlobDigest()
                for index in manifest.chunks.indices {
                    try Task.checkCancellation()
                    let plaintext = try await worker.readChunk(namespace: namespace, manifest: manifest, index: index)
                    guard self.context == lease else { throw SessionError.destinationChanged }
                    verifier.update(plaintext)
                    continuation.yield(plaintext)
                }
                guard verifier.finish() == (manifest.descriptor.digest, manifest.descriptor.size) else { throw BlobError.digestMismatch }
                continuation.finish()
            } catch { continuation.finish(throwing: error) }
        }
        continuation.onTermination = { _ in task.cancel() }
        return stream
    }

    /// Downloads every missing chunk (ciphertext only) so later reads work offline. Progress is
    /// published in `blobDownloads` while it runs.
    public func prefetchBlob(namespace: String, digest: String) async throws {
        await restore()
        guard phase == .ready else { throw SessionError.notReady }
        let manifest = try await worker.blobManifest(namespace: namespace, digest: digest)
        try await download(namespace: namespace, manifest: manifest)
    }

    /// Fetches every blob marked `required` in the configured namespaces that is not complete on
    /// this device. Runs after relay passes automatically; hosts may call it on foreground entry.
    public func downloadRequiredBlobs() async {
        await restore()
        guard phase == .ready, relayConfigured else { return }
        for namespace in worker.configuration.namespaces {
            guard let manifests = try? await worker.incompleteRequiredBlobs(namespace: namespace) else { continue }
            for manifest in manifests { try? await download(namespace: namespace, manifest: manifest) }
        }
    }

    /// Removes local encrypted chunks this session wrote or downloaded that no live reference
    /// needs, after a holder elsewhere is confirmed (relay receipt) or the owner passes
    /// `discardSoleCopy`. Failed uploads older than `gracePeriod` may go. With `evictReplicated`,
    /// chunks the relay already holds are also evicted unless required. Chunks other apps wrote
    /// into a shared App Group store are never touched. Stops without deleting anything when a
    /// configured namespace is unreadable.
    @discardableResult
    public func collectBlobGarbage(gracePeriod: TimeInterval = 24 * 60 * 60, evictReplicated: Bool = false, discardSoleCopy: Bool = false) async throws -> BlobCollection {
        await restore()
        guard phase == .ready else { throw SessionError.notReady }
        return try await worker.collectBlobGarbage(gracePeriod: gracePeriod, evictReplicated: evictReplicated, discardSoleCopy: discardSoleCopy)
    }

    private func download(namespace: String, manifest: BlobManifestInfo) async throws {
        let digest = manifest.descriptor.digest
        let total = manifest.chunks.count
        blobDownloads[digest] = .downloading(completedChunks: 0, totalChunks: total)
        defer { blobDownloads[digest] = nil }
        for index in manifest.chunks.indices {
            try Task.checkCancellation()
            try await worker.ensureChunk(manifest.chunks[index].path)
            blobDownloads[digest] = .downloading(completedChunks: index + 1, totalChunks: total)
        }
    }
}

enum StorageFailure: Error { case cannotCreate }

/// Joins already-encoded JSON values into one object, preserving their exact bytes.
func rawJSONObject(_ fields: [(String, Data)]) -> Data {
    var out = Data("{".utf8)
    for (index, (key, value)) in fields.enumerated() {
        if index > 0 { out.append(Data(",".utf8)) }
        out.append((try? JSONEncoder().encode(key)) ?? Data("\"\"".utf8)); out.append(Data(":".utf8)); out.append(value)
    }
    out.append(Data("}".utf8))
    return out
}

/// Input for an upload; files are streamed in 64 KiB reads.
enum BlobInput: Sendable {
    case data(Data)
    case file(URL)

    func forEachChunk(_ body: (Data) async throws -> Void) async throws {
        switch self {
        case .data(let data):
            var offset = 0
            while offset < data.count {
                try await body(data.subdata(in: offset..<min(data.count, offset + 65536)))
                offset += 65536
            }
        case .file(let url):
            let handle = try FileHandle(forReadingFrom: url)
            defer { try? handle.close() }
            while let chunk = try handle.read(upToCount: 65536), !chunk.isEmpty { try await body(chunk) }
        }
    }
}
