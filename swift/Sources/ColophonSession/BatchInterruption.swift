import Foundation

extension ColophonSession {
    /// The most commands one `perform(_:observed:)` batch takes. A longer import is split into batches of at most this
    /// many, each observing the revision the previous one left.
    public nonisolated static let maximumBatchCount = 256
}

/// A batch `perform(_:observed:)` stopped at the command at `index`, which failed with `error` (what the single
/// `perform(_:observed:claimed:)` would have thrown for it). The commands before it are durable, and `receipts` holds
/// theirs in order; the command at `index` and every command after it were not written. Retry from `index`, with the
/// session's new `observedRevision`.
public struct BatchInterruption: Error, Sendable {
    public let receipts: [WriteReceipt]
    public let index: Int
    public let error: any Error
}
