import Foundation
import os

/// A save's fencing value: two non-negative integers no greater than 2^53 − 1 (the range every Colophon host can store
/// and compare exactly), compared by `generation`, then `seq`.
public struct Fence: Sendable, Hashable, Comparable, CustomStringConvertible {
    /// The greatest value of either part.
    public static let maximum: Int64 = (1 << 53) - 1
    public let generation: Int64
    public let seq: Int64
    /// A fence, or `ClaimStoreError.badFence` when either part is outside 0...2^53 − 1.
    public init(generation: Int64, seq: Int64) throws {
        guard (0...Self.maximum).contains(generation), (0...Self.maximum).contains(seq) else { throw ClaimStoreError.badFence }
        self.generation = generation; self.seq = seq
    }
    public static func < (a: Fence, b: Fence) -> Bool { a.generation != b.generation ? a.generation < b.generation : a.seq < b.seq }
    public var description: String { "\(generation).\(seq)" }
}

/// A claim (the `Persist` effect's `persisted_json`, or none yet) with the fence it was saved under.
public struct StoredClaim: Sendable, Hashable {
    public let claim: String?
    public let fence: Fence
    public init(claim: String?, fence: Fence) { self.claim = claim; self.fence = fence }
}

/// What a compare-and-set save did.
public enum SaveOutcome: Sendable, Equatable {
    /// The held fence was the expected one and the new one greater: the record is written durably.
    case stored
    /// It was not: nothing was written.
    case stale
}

public enum ClaimStoreError: Error, Equatable, Sendable {
    /// A fence part outside 0...2^53 − 1.
    case badFence
    /// The store holds something it cannot read, parse or validate (it fails closed: never skipped).
    case unreadable(String)
    /// The storage failed (the write may or may not have happened: the host reads again).
    case storage(String)
}

/// Where a cell's persisted claim lives, fenced so that no save can overwrite a newer one, whichever client makes it.
///
/// `save(record, expected:)` is a compare-and-set, **linearizable across every client of the same storage** (other
/// instances, processes, apps sharing a container): if the held fence equals `expected` (nil: nothing is held) and
/// `record.fence` is greater, the record is written durably and it returns `.stored`; otherwise nothing is written and
/// it returns `.stale`. It throws when the write failed (and then it may or may not have been written: the host reads
/// again). A store that reads, compares and writes as separate steps is incorrect: two clients could both read fence F
/// and both write, and two hosts would each believe they hold the cell.
///
/// Three further properties (docs/hosts-06.md §3a): no reader sees a commit before it is irrevocable; `.stored` is
/// returned only once the commit is durable; anything unrecognised in the store's namespace fails closed.
public protocol ClaimStore: Sendable {
    func load() async throws -> StoredClaim?
    /// The held fence alone, read cheaply (a host asks every beat).
    func fence() async throws -> Fence?
    func save(_ record: StoredClaim, expected: Fence?) async throws -> SaveOutcome
}

/// The compare-and-set every store applies: the record to write, or nil.
public func compareAndSet(held: StoredClaim?, record: StoredClaim, expected: Fence?) -> StoredClaim? {
    guard held?.fence == expected else { return nil }
    if let held, !(record.fence > held.fence) { return nil }
    return record
}

/// A claim store in memory: every client that shares this object shares the record, and `save` compares and writes in
/// one step under one lock (tests, previews).
public final class MemoryClaimStore: ClaimStore {
    private let record = OSAllocatedUnfairLock<StoredClaim?>(initialState: nil)
    public init(_ initial: StoredClaim? = nil) { record.withLock { $0 = initial } }
    public func load() async throws -> StoredClaim? { record.withLock { $0 } }
    public func fence() async throws -> Fence? { record.withLock { $0?.fence } }
    public func save(_ new: StoredClaim, expected: Fence?) async throws -> SaveOutcome {
        record.withLock { held in
            guard let next = compareAndSet(held: held, record: new, expected: expected) else { return .stale }
            held = next
            return .stored
        }
    }
}
