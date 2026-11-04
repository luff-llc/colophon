import Foundation

/// Optional capability for recovery evidence. Implementations enforce the limit before
/// allocating transport-sized Data; callers must reject unsupported stores, not use read().
public protocol BoundedRecordStore: RecordStore {
  func read(_ path: String, maximumBytes: Int) throws -> Data?
}
