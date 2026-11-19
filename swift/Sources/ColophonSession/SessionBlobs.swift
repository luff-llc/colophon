import CryptoKit
import Foundation

/// A published, encrypted, content-addressed blob in one namespace. `digest`, `size` and
/// `mediaType` are the plaintext descriptor domains reference (`{digest,size,mediaType}`).
public struct ColophonBlob: Equatable, Sendable {
    public let namespace: String
    /// SHA-256 of the complete plaintext, lowercase hex.
    public let digest: String
    public let size: Int
    public let mediaType: String
    /// `.saved` when the publication is durable in the local store.
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
    /// No readable manifest: not published yet, its publication has not synced here, or the namespace is not readable.
    case unpublished
    /// The manifest is known and some encrypted chunks are not on this device.
    case missing(presentChunks: Int, totalChunks: Int)
    /// Chunks are being fetched from a home.
    case downloading(completedChunks: Int, totalChunks: Int)
    /// Every chunk is local; reads verify them again.
    case available
    /// Current grants, keys or storage prevent reading.
    case inaccessible(reason: String)
}

public enum BlobError: Error, Equatable, Sendable {
    case unpublished
    /// A chunk is neither local nor fetchable (no home, home unreachable, or the home lacks it).
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

struct BlobManifestInfo: Sendable { let digest: String; let size: UInt64; let mediaType: String; let chunks: Int }

/// Progress of a blob upload or download, in plaintext bytes.
public struct BlobProgress: Equatable, Sendable {
    public enum Stage: Equatable, Sendable {
        /// Pass one of an upload: reading the content to address it.
        case addressing
        /// Pass two of an upload: encrypting and storing the chunks.
        case storing
        /// A download to a file: verifying and writing the plaintext.
        case writing
    }
    public let stage: Stage
    public let completed: Int64
    /// Nil when the size is not known yet.
    public let total: Int64?
    public init(stage: Stage, completed: Int64, total: Int64?) { self.stage = stage; self.completed = completed; self.total = total }
}

extension ColophonSession {
    /// Encrypts and stores `data` in 64 KiB content-addressed chunks under the namespace epoch key, then
    /// publishes a signed `colophon.blobPublish` manifest with one live reference. Identical content already
    /// published is not stored again; a reference is added instead. `required` asks every device to download it.
    /// The hashing, encryption and chunk writes run off the main actor and outside the session's gate.
    public func putBlob(_ data: Data, namespace: String, mediaType: String, reference: String, required: Bool = false,
                        progress: (@Sendable (BlobProgress) -> Void)? = nil) async throws -> ColophonBlob {
        try await putBlob(.data(data), namespace: namespace, mediaType: mediaType, reference: reference, required: required, progress: progress)
    }
    /// Streams a file without loading it into memory: 64 KiB at a time, read twice (once to address it, once to
    /// encrypt it), on a background executor, never on the main actor. The file must not change in between (the
    /// digest check would fail). `progress` is called from that background executor.
    public func putBlob(contentsOf file: URL, namespace: String, mediaType: String, reference: String, required: Bool = false,
                        progress: (@Sendable (BlobProgress) -> Void)? = nil) async throws -> ColophonBlob {
        try await putBlob(.file(file), namespace: namespace, mediaType: mediaType, reference: reference, required: required, progress: progress)
    }

    private func putBlob(_ input: BlobInput, namespace: String, mediaType: String, reference: String, required: Bool,
                         progress: (@Sendable (BlobProgress) -> Void)?) async throws -> ColophonBlob {
        await restore()
        guard phase == .ready || phase == .refreshing else { throw SessionError.notReady }
        let lease = context
        let address = try await BlobIO.address(input, progress: progress)
        guard lease == context else { throw SessionError.destinationChanged }
        let staged: StagedBlob
        switch try await worker.beginBlobStage(namespace: namespace, mediaType: mediaType, digest: address.digest) {
        case .published(let existing):
            staged = StagedBlob(digest: address.digest, size: Int(existing.size), mediaType: existing.mediaType, manifest: nil)
        case .write(let writer, let medium):
            let manifest = try await BlobIO.store(input, writer: writer, medium: medium, expected: address, progress: progress)
            staged = StagedBlob(digest: address.digest, size: address.size, mediaType: mediaType, manifest: manifest)
        }
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
        return ColophonBlob(namespace: namespace, digest: staged.digest, size: staged.size, mediaType: staged.mediaType, receipt: receipt)
    }

    /// Adds (`retain: true`) or removes a live reference.
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
        guard phase == .ready || phase == .refreshing else { return .inaccessible(reason: "The library is not ready") }
        do { return try await worker.blobAvailability(namespace: namespace, digest: digest) }
        catch let error as BlobError {
            if case .inaccessible(let reason) = error { return .inaccessible(reason: reason) }
            return .inaccessible(reason: error.localizedDescription)
        } catch { return .inaccessible(reason: error.localizedDescription) }
    }

    /// Complete verified plaintext. Missing chunks are fetched from the homes on demand. Use `blobFile` or
    /// `blobStream` for anything larger than `maximumBytes`.
    public func blobData(namespace: String, digest: String, maximumBytes: Int = 16 * 1024 * 1024) async throws -> Data {
        var result = Data()
        for try await chunk in blobStream(namespace: namespace, digest: digest, maximumBytes: maximumBytes) { result.append(chunk) }
        return result
    }

    /// Writes verified plaintext to a new private temporary file. The caller owns and removes it. The file
    /// only appears at its final URL after the complete digest has been verified. Every file operation and the
    /// hashing run on a background executor, chunk by chunk: neither the main actor nor the session's gate is held,
    /// and memory stays at a few chunks whatever the size. `progress` is called from that executor.
    @concurrent
    public nonisolated func blobFile(namespace: String, digest: String, progress: (@Sendable (BlobProgress) -> Void)? = nil) async throws -> URL {
        let chunks = await blobStream(namespace: namespace, digest: digest, maximumBytes: .max)
        return try await BlobIO.writeFile(chunks, digest: digest, progress: progress)
    }

    /// Verified plaintext chunks in order, read on demand (the next chunk is read and decrypted only when the
    /// consumer asks for it, so a slow consumer never makes the stream buffer the blob). Each chunk is authenticated
    /// before it is yielded; the stream throws `BlobError.digestMismatch` at the end if the whole content does not
    /// match, so consumers must not certify content until the stream finishes without error. The reading and
    /// hashing run on a background executor.
    public func blobStream(namespace: String, digest: String, maximumBytes: Int = .max) -> AsyncThrowingStream<Data, any Error> {
        let reader = BlobReader(session: self, worker: worker, namespace: namespace, digest: digest, maximumBytes: maximumBytes)
        return AsyncThrowingStream(unfolding: { try await reader.next() })
    }

    /// The checks a read starts with, on the main actor: ready, and the context it is fenced to. Fetches missing chunks.
    func beginRead(namespace: String, digest: String, maximumBytes: Int) async throws -> (lease: UUID, manifest: BlobManifestInfo) {
        await restore()
        guard phase == .ready || phase == .refreshing else { throw SessionError.notReady }
        let lease = context
        let manifest = try await worker.blobManifest(namespace: namespace, digest: digest)
        guard manifest.size <= UInt64(max(0, maximumBytes)) else { throw BlobError.tooLarge }
        if case .missing = try await worker.blobAvailability(namespace: namespace, digest: digest) { try await fetch(namespace: namespace, digest: digest) }
        return (lease, manifest)
    }

    /// Downloads every missing chunk (ciphertext only) from the homes so later reads work offline.
    /// Progress is published in `blobDownloads` while it runs.
    public func prefetchBlob(namespace: String, digest: String) async throws {
        await restore()
        guard phase == .ready || phase == .refreshing else { throw SessionError.notReady }
        try await fetch(namespace: namespace, digest: digest)
    }

    /// Fetches every blob marked `required` that is not complete on this device (one exchange pass pulls them).
    /// Runs after exchange passes automatically; hosts may call it on foreground entry.
    public func downloadRequiredBlobs() async {
        await restore()
        guard phase == .ready, relayConfigured else { return }
        for namespace in worker.configuration.namespaces where ((try? await worker.requiredBlobFetches(namespace: namespace))?.isEmpty == false) {
            _ = await syncNow(); return
        }
    }

    /// 0.5 core does not collect blob garbage (spec 0.3 §7.2: a client removes a chunk only under confirmed
    /// custody, and the core leaves that to a later package). This removes nothing and says so.
    @discardableResult
    public func collectBlobGarbage(gracePeriod: TimeInterval = 24 * 60 * 60, evictReplicated: Bool = false, discardSoleCopy: Bool = false) async throws -> BlobCollection {
        BlobCollection()
    }

    private func fetch(namespace: String, digest: String) async throws {
        let manifest = try await worker.blobManifest(namespace: namespace, digest: digest)
        blobDownloads[digest] = .downloading(completedChunks: 0, totalChunks: manifest.chunks)
        defer { blobDownloads[digest] = nil }
        guard relayConfigured else { throw BlobError.missing("No home is configured to fetch it from.") }
        for home in try await worker.homeIDs() { try await worker.wantBlob(home: home, namespace: namespace, digest: digest) }
        _ = await syncNow()
        if case .available = try await worker.blobAvailability(namespace: namespace, digest: digest) { return }
        throw BlobError.missing("No home holds every chunk yet.")
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

    var knownSize: Int64? {
        switch self {
        case .data(let data): Int64(data.count)
        case .file(let url): (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize).map(Int64.init)
        }
    }

    func forEachChunk(isolation: isolated (any Actor)? = #isolation, _ body: (Data) async throws -> Void) async throws {
        switch self {
        case .data(let data):
            var offset = 0
            while offset < data.count {
                try await body(data.subdata(in: offset..<min(data.count, offset + 65536)))
                offset += 65536
            }
        case .file(let url):
            BlobIO.requireBackground()
            let handle = try FileHandle(forReadingFrom: url)
            defer { try? handle.close() }
            // Each read in its own autorelease pool: a cooperative thread drains none between iterations.
            while let chunk = try autoreleasepool(invoking: { try handle.read(upToCount: 65536) }), !chunk.isEmpty { try await body(chunk) }
        }
    }
}

/// One read of a blob, pulled chunk by chunk. An actor: its state (the position and the running digest) is touched
/// by one `next()` at a time, on the global executor, never on the main actor.
actor BlobReader {
    private weak var session: ColophonSession?
    private let worker: SessionWorker
    private let namespace: String, digest: String, maximumBytes: Int
    private var started: (lease: UUID, manifest: BlobManifestInfo)?
    private var index = 0
    private var total: UInt64 = 0
    private var hasher = SHA256()
    private var finished = false
    init(session: ColophonSession, worker: SessionWorker, namespace: String, digest: String, maximumBytes: Int) {
        self.session = session; self.worker = worker; self.namespace = namespace; self.digest = digest; self.maximumBytes = maximumBytes
    }
    func next() async throws -> Data? {
        guard !finished else { return nil }
        do {
            try Task.checkCancellation()
            guard let session else { throw SessionError.notReady }
            let state: (lease: UUID, manifest: BlobManifestInfo)
            if let started { state = started } else {
                state = try await session.beginRead(namespace: namespace, digest: digest, maximumBytes: maximumBytes)
                started = state
            }
            guard index < state.manifest.chunks else {
                finished = true
                let actual = hasher.finalize().map { String(format: "%02x", $0) }.joined()
                guard total == state.manifest.size, actual == state.manifest.digest else { throw BlobError.digestMismatch }
                return nil
            }
            let plaintext = try await worker.blobChunk(namespace: namespace, digest: digest, index: index)
            guard await session.context == state.lease else { throw SessionError.destinationChanged }
            index += 1
            hasher.update(data: plaintext); total += UInt64(plaintext.count)
            return plaintext
        } catch { finished = true; throw error }
    }
}

/// The file work of blobs and request import, on the global executor. Each entry point checks (in every build) that
/// it is not on the main thread: a regression that moves file I/O onto the main actor stops at once.
enum BlobIO {
    static func requireBackground() { dispatchPrecondition(condition: .notOnQueue(.main)) }

    struct Address: Sendable { let digest: String; let size: Int }

    /// Pass one of an upload: the plaintext digest and size.
    @concurrent static func address(_ input: BlobInput, progress: (@Sendable (BlobProgress) -> Void)?) async throws -> Address {
        requireBackground()
        var hasher = SHA256(); var size = 0
        try await input.forEachChunk { chunk in
            try Task.checkCancellation()
            hasher.update(data: chunk); size += chunk.count
            progress?(BlobProgress(stage: .addressing, completed: Int64(size), total: input.knownSize))
        }
        return Address(digest: hasher.finalize().map { String(format: "%02x", $0) }.joined(), size: size)
    }

    /// Pass two: encrypts each chunk with the writer and stores it, then returns the signed manifest. A chunk file is
    /// immutable and named by its ciphertext digest, so a chunk stored by an interrupted upload is reused, never wrong.
    @concurrent static func store(_ input: BlobInput, writer: AccountBlobWriter, medium: any RecordMedium, expected: Address,
                                  progress: (@Sendable (BlobProgress) -> Void)?) async throws -> Data {
        requireBackground()
        var hasher = SHA256(); var count = 0
        try await input.forEachChunk { chunk in
            try Task.checkCancellation()
            hasher.update(data: chunk); count += chunk.count
            try autoreleasepool {
                let sealed: BlobChunk
                do { sealed = try writer.push(plaintext: chunk) } catch { throw ColophonError.wrap(error) }
                try medium.write([MediumWrite(path: sealed.path, bytes: sealed.bytes)])
            }
            progress?(BlobProgress(stage: .storing, completed: Int64(count), total: Int64(expected.size)))
        }
        guard hasher.finalize().map({ String(format: "%02x", $0) }).joined() == expected.digest, count == expected.size else { throw BlobError.digestMismatch }
        do { return Data(try writer.finish().utf8) } catch { throw ColophonError.wrap(error) }
    }

    /// Writes verified chunks to a private temporary file and moves it into place only after the stream finished
    /// without error (the stream verifies the whole digest at its end).
    @concurrent static func writeFile(_ chunks: AsyncThrowingStream<Data, any Error>, digest: String,
                                      progress: (@Sendable (BlobProgress) -> Void)?) async throws -> URL {
        requireBackground()
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
            var written: Int64 = 0
            for try await chunk in chunks {
                requireBackground()
                try autoreleasepool { try handle.write(contentsOf: chunk) }
                written += Int64(chunk.count)
                progress?(BlobProgress(stage: .writing, completed: written, total: nil))
            }
            try handle.synchronize()
            try FileManager.default.moveItem(at: partial, to: final)
            return final
        } catch { try? FileManager.default.removeItem(at: partial); throw error }
    }

    /// A request file that arrived out of band, read off the main actor, at most `maximumBytes`.
    @concurrent static func readRequest(_ url: URL, maximumBytes: Int = RecordPaths.maximumBytes) async throws -> Data {
        requireBackground()
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        let data = try handle.read(upToCount: maximumBytes + 1) ?? Data()
        guard data.count <= maximumBytes else { throw StorageError.limitExceeded }
        return data
    }
}
