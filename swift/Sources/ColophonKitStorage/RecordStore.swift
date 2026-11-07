import Foundation
import CryptoKit

public enum StorageError: Error, Equatable, Sendable {
    case unavailable(String)
    case invalidPath(String)
    case conflict(String)
    case limitExceeded
}

/// A complete readable snapshot, or an explicit error. No partial maps escape this boundary.
public protocol RecordStore: Sendable {
    func changeToken() async throws -> String?
    func changes(since token: String) async throws -> RecordDelta?
    /// A synchronous reader for engine callbacks; built-in stores avoid loading history.
    func engineReader() async throws -> RecordReader
    func read() async throws -> [String: Data]
    /// Exact duplicates are idempotent. Existing different bytes must never be overwritten.
    func append(_ records: [String: Data]) async throws
    /// Atomically replace a live slot only if its exact old bytes still match.
    func replaceLive(_ path: String, expected: Data?, bytes: Data) async throws -> Bool
    func changes() async -> AsyncStream<Void>
    /// Every record path, without reading record bytes. Errors are never an empty set.
    func paths() async throws -> Set<String>
    func paths(namespaces: [String]) async throws -> Set<String>
    /// Scoped synchronization inventory, including append-only engagement evidence.
    func syncPaths(namespaces: [String]) async throws -> Set<String>
    /// Cheap provider versions; nil values require conservative body reads.
    func versions(paths: Set<String>) async throws -> [String: String]
    /// Exact bytes of the requested records that exist; absent paths are omitted.
    func read(paths: [String]) async throws -> [String: Data]
}

/// Compatibility defaults for stores that only implement complete snapshots.
extension RecordStore {
    public func changeToken() async throws -> String? { nil }
    public func changes(since token: String) async throws -> RecordDelta? { nil }
    public func engineReader() async throws -> RecordReader {
        let records = try await read()
        return RecordReader { path in
            guard let bytes = records[path] else { throw StorageError.unavailable("Missing record: " + path) }; return bytes
        }
    }
    public func replaceLive(_ path: String, expected: Data?, bytes: Data) async throws -> Bool {
        throw StorageError.unavailable("This provider does not support conditional live publication")
    }
    public func paths(namespaces: [String]) async throws -> Set<String> {
        Set(try await paths().filter { !$0.hasPrefix("history/") && RecordPath.listingIncludes($0, namespaces: namespaces) })
    }
    public func syncPaths(namespaces: [String]) async throws -> Set<String> {
        Set(try await paths().filter { RecordPath.listingIncludes($0, namespaces: namespaces) })
    }
    public func versions(paths: Set<String>) async throws -> [String: String] { [:] }
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
        let bytes = path.utf8
        let parts = bytes.split(separator: 47, omittingEmptySubsequences: false)
        guard bytes.count < 512, path.hasSuffix(".json"), !bytes.contains(0), !bytes.contains(92),
              parts.allSatisfy({ !$0.isEmpty && $0.first != 46 }) else { throw StorageError.invalidPath(path) }
        let root = parts.first.map { String(decoding: $0, as: UTF8.self) } ?? ""
        switch parts.count {
        case 2 where root == "authority" || root == "requests": return
        case 3 where root == "ops": return
        case 4 where root == "ops" || root == "state" || root == "history": return
        default: throw StorageError.invalidPath(path)
        }
    }
    public static func isReplaceable(_ path: String) -> Bool { path.hasPrefix("state/") }
    /// Empty `namespaces` means every namespace. Authority, requests and legacy three-part ops always match.
    public static func listingIncludes(_ path: String, namespaces: [String]) -> Bool {
        let parts = path.utf8.split(separator: 47, omittingEmptySubsequences: false)
        guard let first = parts.first else { return false }
        let root = String(decoding: first, as: UTF8.self)
        if parts.count == 2 && (root == "authority" || root == "requests") { return true }
        if parts.count == 3 && root == "ops" { return true }
        if parts.count == 4 && (root == "ops" || root == "state" || root == "history") {
            return namespaces.isEmpty || namespaces.contains(String(decoding: parts[2], as: UTF8.self))
        }
        return false
    }
    public static func missingBlocks(_ path: String) -> Bool {
        path.hasPrefix("ops/") || path.hasPrefix("authority/") || path.hasPrefix("requests/")
    }
}

/// Each subscriber gets a bounded wake-up hint; consumers re-read the complete store.
public actor MemoryRecordStore: RecordStore {
    private let records: LockedMemoryRecords
    private var versionsByPath: [String: String] = [:]
    private var recentChanges: [(UInt64, String)] = []
    private var changeFloor: UInt64 = 0
    private var generation: UInt64 = 0
    private var blobs: [String: Data] = [:]
    private var blobDates: [String: Date] = [:]
    private var observers: [UUID: AsyncStream<Void>.Continuation] = [:]
    private var unavailable: String?
    /// Complete snapshots served, for tests and benchmarks that prove incremental access.
    public private(set) var fullReads = 0
    /// Record bodies served by `read(paths:)`.
    public private(set) var recordReads = 0
    public init(records: [String: Data] = [:]) {
        self.records = LockedMemoryRecords(records)
        self.versionsByPath = records.mapValues { Data(SHA256.hash(data: $0)).base64EncodedString() }
    }
    public func changeToken() throws -> String? {
        if let unavailable { throw StorageError.unavailable(unavailable) }; return String(generation)
    }
    public func changes(since token: String) throws -> RecordDelta? {
        if let unavailable { throw StorageError.unavailable(unavailable) }
        guard let previous = UInt64(token), previous >= changeFloor, previous <= generation else { return nil }
        return RecordDelta(token: String(generation), paths: Set(recentChanges.lazy.filter { $0.0 > previous }.map { $0.1 }))
    }
    deinit { for observer in observers.values { observer.finish() } }
    public func setUnavailable(_ reason: String?) {
        unavailable = reason
        records.setUnavailable(reason)
        notify()
    }
    public func engineReader() throws -> RecordReader {
        if let unavailable { throw StorageError.unavailable(unavailable) }
        let snapshot = records
        return RecordReader { path in
            return try snapshot.read(path)
        }
    }
    public func read() throws -> [String: Data] {
        if let unavailable { throw StorageError.unavailable(unavailable) }
        fullReads += 1
        return records.snapshot()
    }
    public func paths() async throws -> Set<String> {
        if let unavailable { throw StorageError.unavailable(unavailable) }
        return Set(records.keys)
    }
    public func versions(paths: Set<String>) async throws -> [String: String] {
        if let unavailable { throw StorageError.unavailable(unavailable) }
        return Dictionary(uniqueKeysWithValues: paths.compactMap { path in records[path].map { _ in (path, versionsByPath[path] ?? "") } })
    }
    public func read(paths: [String]) async throws -> [String: Data] {
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
            if let old = records[path], old != bytes, !RecordPath.isReplaceable(path) {
                throw StorageError.conflict(path)
            }
        }
        let changed = incoming.contains { records[$0.key] != $0.value }
        for (path, bytes) in incoming {
            if records[path] != bytes {
                generation += 1; versionsByPath[path] = Data(SHA256.hash(data: bytes)).base64EncodedString()
                recentChanges.append((generation, path))
                if recentChanges.count > 4096 { changeFloor = recentChanges[2047].0; recentChanges.removeFirst(2048) }
            }
            records[path] = bytes
        }
        if changed { notify() }
    }
    public func replaceLive(_ path: String, expected: Data?, bytes: Data) async throws -> Bool {
        try RecordPath.validate(path)
        guard RecordPath.isReplaceable(path) else { throw StorageError.invalidPath(path) }
        if let unavailable { throw StorageError.unavailable(unavailable) }
        if records[path] == bytes { return true }
        guard records[path] == expected else { return false }
        try append([path: bytes]); return true
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
    /// owner explicitly requests discarding it; reference count alone is insufficient.
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

/// Read-only callback value. The closure must be thread-safe and return exact coherent bytes.
public struct RecordReader: Sendable {
    private let body: @Sendable (String) throws -> Data
    public init(read: @escaping @Sendable (String) throws -> Data) { body = read }
    public func read(_ path: String) throws -> Data { try body(path) }
}

/// Complete changes since a provider token. Missing history must return nil, never a partial delta.
public struct RecordDelta: Sendable {
    public let token: String
    public let paths: Set<String>
    public init(token: String, paths: Set<String>) { self.token = token; self.paths = paths }
}

/// Callback reads and actor mutations share the same lock; no mutable dictionary escapes it.
private final class LockedMemoryRecords: @unchecked Sendable {
    private let lock = NSLock()
    private var values: [String: Data]
    private var unavailable: String?
    init(_ values: [String: Data]) { self.values = Dictionary(uniqueKeysWithValues: values.map { ($0.key, $0.value) }) }
    subscript(path: String) -> Data? {
        get { lock.withLock { values[path] } }
        set { lock.withLock { values[path] = newValue } }
    }
    var keys: [String] { lock.withLock { Array(values.keys) } }
    func snapshot() -> [String: Data] { lock.withLock { values } }
    func setUnavailable(_ reason: String?) { lock.withLock { unavailable = reason } }
    func read(_ path: String) throws -> Data {
        try lock.withLock {
            if let unavailable { throw StorageError.unavailable(unavailable) }
            guard let bytes = values[path] else { throw StorageError.unavailable("Missing record: " + path) }; return bytes
        }
    }
}
