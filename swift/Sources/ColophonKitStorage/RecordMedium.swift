import Foundation

/// A path the medium holds and the provider's content-version token for it (nil: no cheap version).
public struct MediumEntry: Equatable, Hashable, Sendable {
    public let path: String
    public let version: String?
    public init(path: String, version: String?) { self.path = path; self.version = version }
}

/// Exact bytes to store at a path.
public struct MediumWrite: Equatable, Sendable {
    public let path: String
    public let bytes: Data
    public init(path: String, bytes: Data) { self.path = path; self.bytes = bytes }
}

public enum StorageError: Error, Equatable, Sendable {
    /// The medium cannot answer now (iCloud download pending, a container that is inaccessible, a read
    /// that failed). Never read as "empty".
    case unavailable(String)
    case invalidPath(String)
    /// Immutable bytes already exist at the path and differ.
    case conflict(String)
    case limitExceeded
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

/// Where an account's records live: the host's record store of docs/bindings-05.md.
///
/// All calls are synchronous: the engine's `HostSource` callbacks run on the engine's queue and need
/// the bytes at once, and a medium is thread-safe. A medium must not call into the engine.
public protocol RecordMedium: Sendable {
    /// Every path held, with versions, in one batch. A listing that cannot be completed throws: an
    /// error is never an empty store.
    func listing() throws -> [MediumEntry]
    /// The exact bytes at `path`. Missing or unreadable throws `StorageError.unavailable`.
    func read(_ path: String) throws -> Data
    /// A blob chunk's ciphertext; empty means "not held here" (the engine fetches it from a home).
    func readBlob(_ path: String) throws -> Data
    /// Stores every write, in order, or none: a failure removes what this call created and restores
    /// what it replaced. Exact duplicates are idempotent; different bytes at an existing path are
    /// `conflict` except at a replaceable path (`state/`, `heads/`).
    func write(_ writes: [MediumWrite]) throws
    /// Wake-up hints when something changes (including this process's own writes). A hint carries
    /// nothing: the consumer lists again.
    func changes() -> AsyncStream<Void>
}

public enum RecordPaths {
    /// The maximum size of one stored object (docs/bindings-05.md §5: a request or entry blob is 40 MiB).
    public static let maximumBytes = 40 * 1024 * 1024

    /// A relative path of at most 512 bytes, in components that are neither empty nor hidden.
    public static func validate(_ path: String) throws {
        let bytes = Array(path.utf8)
        guard !bytes.isEmpty, bytes.count <= 512, !bytes.contains(0), !bytes.contains(92), bytes.first != 47, bytes.last != 47 else {
            throw StorageError.invalidPath(path)
        }
        for part in bytes.split(separator: 47, omittingEmptySubsequences: false) {
            guard !part.isEmpty, part.count <= 255, part.first != 46 else { throw StorageError.invalidPath(path) }
        }
    }
    /// Live slots and head marks are replaced by newer bytes; everything else is immutable.
    public static func isReplaceable(_ path: String) -> Bool { path.hasPrefix("state/") || path.hasPrefix("heads/") }
    public static func isBlob(_ path: String) -> Bool { path.hasPrefix("blobs/") }
}
