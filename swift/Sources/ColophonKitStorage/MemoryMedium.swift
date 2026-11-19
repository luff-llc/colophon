import Foundation

/// An in-memory medium for tests and previews, with the same atomic-write contract as the folder, a
/// call counter and fault injection (the hostile-host tests drive the engine through these).
public final class MemoryMedium: RecordMedium, @unchecked Sendable {
    public enum Fault: Sendable, Equatable {
        case none
        /// Every read throws.
        case throwOnRead(String)
        /// Every read returns these bytes instead of the stored ones.
        case garbage(Data)
        /// The listing throws.
        case throwOnListing(String)
        /// A write throws after `after` writes of one batch were applied (to test the rollback).
        case failWrite(after: Int)
    }
    private let lock = NSLock()
    private var files: [String: Data]
    private var generation: UInt64 = 0
    private var versions: [String: UInt64] = [:]
    private var fault: Fault = .none
    private var observers: [UUID: AsyncStream<Void>.Continuation] = [:]
    private var readHook: (@Sendable (String) -> Void)?
    private(set) var readCount = 0

    public init(files: [String: Data] = [:]) { self.files = files; for key in files.keys { versions[key] = 0 } }

    public var reads: Int { lock.withLock { readCount } }
    public func setFault(_ value: Fault) { lock.withLock { fault = value } }
    /// Runs on every `read`, inside the engine's call: the re-entrancy test calls the engine from it.
    public func setReadHook(_ hook: (@Sendable (String) -> Void)?) { lock.withLock { readHook = hook } }
    public func snapshot() -> [String: Data] { lock.withLock { files } }
    public func copy() -> MemoryMedium { MemoryMedium(files: snapshot()) }
    /// Puts bytes without the immutability check (a test of an outside change).
    public func put(_ path: String, _ bytes: Data) {
        lock.withLock { files[path] = bytes; generation += 1; versions[path] = generation }
        notify()
    }
    public func remove(_ path: String) { lock.withLock { files[path] = nil; versions[path] = nil }; notify() }

    public func listing() throws -> [MediumEntry] {
        try lock.withLock {
            if case .throwOnListing(let why) = fault { throw StorageError.unavailable(why) }
            return files.keys.sorted().map { MediumEntry(path: $0, version: String(versions[$0] ?? 0)) }
        }
    }
    public func read(_ path: String) throws -> Data {
        let hook = lock.withLock { readHook }
        hook?(path)
        return try lock.withLock {
            readCount += 1
            switch fault {
            case .throwOnRead(let why): throw StorageError.unavailable(why)
            case .garbage(let bytes): return bytes
            default: break
            }
            guard let bytes = files[path] else { throw StorageError.unavailable("Missing record: " + path) }
            return bytes
        }
    }
    public func readBlob(_ path: String) throws -> Data {
        try lock.withLock {
            if case .throwOnRead(let why) = fault { throw StorageError.unavailable(why) }
            return files[path] ?? Data()
        }
    }
    public func write(_ writes: [MediumWrite]) throws {
        try lock.withLock {
            for item in writes {
                try RecordPaths.validate(item.path)
                guard item.bytes.count <= RecordPaths.maximumBytes else { throw StorageError.limitExceeded }
            }
            var undo: [(String, Data?)] = []
            var applied = 0
            do {
                for item in writes {
                    if case .failWrite(let after) = fault, applied >= after { throw StorageError.unavailable("injected write failure") }
                    let old = files[item.path]
                    if let old, old == item.bytes { applied += 1; continue }
                    if old != nil, !RecordPaths.isReplaceable(item.path) { throw StorageError.conflict(item.path) }
                    undo.append((item.path, old))
                    files[item.path] = item.bytes
                    applied += 1
                }
            } catch {
                for (path, old) in undo.reversed() { files[path] = old }
                throw error
            }
            generation += 1
            for item in writes { versions[item.path] = generation }
        }
        notify()
    }
    public func changes() -> AsyncStream<Void> {
        let id = UUID()
        let (stream, continuation) = AsyncStream<Void>.makeStream(bufferingPolicy: .bufferingNewest(1))
        lock.withLock { observers[id] = continuation }
        continuation.onTermination = { [weak self] _ in self?.lock.withLock { self?.observers[id] = nil } }
        return stream
    }
    private func notify() { let all = lock.withLock { Array(observers.values) }; for each in all { each.yield(()) } }
}
