import Foundation

public enum StorageError: Error, Equatable, Sendable {
    case unavailable(String)
    case invalidPath(String)
    case conflict(String)
    case limitExceeded
}

/// A complete readable snapshot, or an explicit error. No partial maps escape this boundary.
public protocol RecordStore: Sendable {
    func read() async throws -> [String: Data]
    /// Exact duplicates are idempotent. Existing different bytes must never be overwritten.
    func append(_ records: [String: Data]) async throws
    func changes() async -> AsyncStream<Void>
    /// Every record path, without reading record bytes. Errors are never an empty set.
    func paths() async throws -> Set<String>
    /// Exact bytes of the requested records that exist; absent paths are omitted.
    func read(paths: [String]) async throws -> [String: Data]
}

/// Compatibility defaults for stores that only implement complete snapshots.
extension RecordStore {
    public func paths() async throws -> Set<String> { Set(try await read().keys) }
    public func read(paths: [String]) async throws -> [String: Data] {
        let all = try await read()
        var result: [String: Data] = [:]
        for path in paths { if let bytes = all[path] { result[path] = bytes } }
        return result
    }
}

public enum RecordPath {
    public static func validate(_ path: String) throws {
        let parts = path.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        let validComponent: (String) -> Bool = { !$0.isEmpty && $0 != "." && $0 != ".." && !$0.hasPrefix(".") && !$0.contains("\\") && !$0.contains("\0") }
        guard parts.allSatisfy(validComponent), path.utf8.count < 512,
              (parts.count == 2 && ["authority", "requests"].contains(parts[0]) || parts.count == 3 && parts[0] == "ops"),
              path.hasSuffix(".json") else { throw StorageError.invalidPath(path) }
    }
}

/// Each subscriber gets a bounded wake-up hint; consumers re-read the complete store.
public actor MemoryRecordStore: RecordStore {
    private var records: [String: Data]
    private var blobs: [String: Data] = [:]
    private var blobDates: [String: Date] = [:]
    private var observers: [UUID: AsyncStream<Void>.Continuation] = [:]
    private var unavailable: String?
    /// Complete snapshots served, for tests and benchmarks that prove incremental access.
    public private(set) var fullReads = 0
    /// Record bodies served by `read(paths:)`.
    public private(set) var recordReads = 0
    public init(records: [String: Data] = [:]) { self.records = records }
    deinit { for observer in observers.values { observer.finish() } }
    public func setUnavailable(_ reason: String?) {
        unavailable = reason
        notify()
    }
    public func read() throws -> [String: Data] {
        if let unavailable { throw StorageError.unavailable(unavailable) }
        fullReads += 1
        return records
    }
    public func paths() throws -> Set<String> {
        if let unavailable { throw StorageError.unavailable(unavailable) }
        return Set(records.keys)
    }
    public func read(paths: [String]) throws -> [String: Data] {
        if let unavailable { throw StorageError.unavailable(unavailable) }
        var result: [String: Data] = [:]
        for path in paths { if let bytes = records[path] { result[path] = bytes } }
        recordReads += result.count
        return result
    }
    public func append(_ incoming: [String: Data]) throws {
        if let unavailable { throw StorageError.unavailable(unavailable) }
        for (path, bytes) in incoming {
            try RecordPath.validate(path)
            if let old = records[path], old != bytes { throw StorageError.conflict(path) }
        }
        let changed = incoming.contains { records[$0.key] == nil }
        records.merge(incoming) { old, _ in old }
        if changed { notify() }
    }
    public func changes() -> AsyncStream<Void> {
        let id = UUID()
        let (stream, continuation) = AsyncStream<Void>.makeStream(bufferingPolicy: .bufferingNewest(1))
        observers[id] = continuation
        continuation.onTermination = { [weak self] _ in Task { await self?.remove(id) } }
        return stream
    }
    private func remove(_ id: UUID) { observers[id] = nil }
    private func notify() { for observer in observers.values { observer.yield(()) } }
}

extension StorageError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .unavailable(let reason): reason
        case .invalidPath(let path): "Invalid record path: \(path)"
        case .conflict(let path): "Immutable record conflict: \(path)"
        case .limitExceeded: "Storage limit exceeded"
        }
    }
}

/// Immutable encrypted blob chunks live alongside records but are never loaded in snapshots.
public protocol BlobStore: Sendable {
    /// Ciphertext at `blobs/<sha256>`; a missing chunk throws `StorageError.unavailable`.
    func readBlob(_ path: String) async throws -> Data
    func appendBlob(_ path: String, bytes: Data) async throws
    /// Presence without reading bytes. Errors (for example iCloud hydration) are not absence.
    func hasBlob(_ path: String) async throws -> Bool
    /// Local cache eviction only. Never call it for a chunk that may be the last copy unless the
    /// blob is unreferenced; the session's garbage collector decides.
    func removeBlob(_ path: String) async throws
    /// Every local chunk path with its modification date, without reading bytes.
    func blobPaths() async throws -> [String: Date]
}
public enum BlobPath {
    public static func validate(_ path: String) throws {
        let digest = path.dropFirst(6)
        guard path.hasPrefix("blobs/"), digest.count == 64,
              digest.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) })
        else { throw StorageError.invalidPath(path) }
    }
}

extension MemoryRecordStore: BlobStore {
    public func readBlob(_ path: String) throws -> Data {
        try BlobPath.validate(path)
        if let unavailable { throw StorageError.unavailable(unavailable) }
        guard let bytes = blobs[path] else { throw StorageError.unavailable("Blob chunk is missing: " + path) }
        return bytes
    }
    public func appendBlob(_ path: String, bytes: Data) throws {
        try BlobPath.validate(path)
        if let unavailable { throw StorageError.unavailable(unavailable) }
        guard bytes.count <= 65536 + 16 else { throw StorageError.limitExceeded }
        if let old = blobs[path], old != bytes { throw StorageError.conflict(path) }
        if blobs[path] == nil { blobDates[path] = .now }
        blobs[path] = bytes
    }
    public func hasBlob(_ path: String) throws -> Bool {
        try BlobPath.validate(path)
        if let unavailable { throw StorageError.unavailable(unavailable) }
        return blobs[path] != nil
    }
    public func removeBlob(_ path: String) throws {
        try BlobPath.validate(path)
        if let unavailable { throw StorageError.unavailable(unavailable) }
        blobs[path] = nil; blobDates[path] = nil
    }
    public func blobPaths() throws -> [String: Date] {
        if let unavailable { throw StorageError.unavailable(unavailable) }
        return blobDates
    }
    /// Test seam: age a chunk past a garbage-collection grace period.
    public func setBlobDate(_ path: String, _ date: Date) { if blobs[path] != nil { blobDates[path] = date } }
}
