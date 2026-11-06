import ColophonCore
import Foundation

/// An in-memory store for tests, previews and conformance runs.
public final class MemoryStore: BoundedRecordStore, @unchecked Sendable {
  private let lock = NSLock()
  // Protected by `lock`.
  private var files: [String: Data] = [:]

  public init() {}

  public func list(_ directory: String) throws -> [String] {
    let prefix = directory + "/"
    return lock.withLock {
      Set(files.keys.filter { $0.hasPrefix(prefix) }.compactMap { $0.dropFirst(prefix.count).split(separator: "/").first }
        .map(String.init)).sorted()
    }
  }

  public func read(_ path: String) throws -> Data? { lock.withLock { files[path] } }

  public func read(_ path: String, maximumBytes: Int) throws -> Data? {
    guard maximumBytes >= 0 else { throw BoundedRecordReadError.exceedsLimit }
    return try lock.withLock {
      guard let bytes = files[path] else { return nil }
      guard bytes.count <= maximumBytes else { throw BoundedRecordReadError.exceedsLimit }
      return bytes
    }
  }

  public func create(_ path: String, _ data: Data) throws {
    try lock.withLock {
      guard files[path] == nil else { throw ColophonError.alreadyExists(path) }
      files[path] = data
    }
  }

  public func replace(_ path: String, _ data: Data) throws { lock.withLock { files[path] = data } }

  /// Every record, for writing a fixture to disk.
  public var snapshot: [String: Data] { lock.withLock { files } }

  /// Replaces a record's bytes without the immutability rule, for tamper tests.
  public func tamper(_ path: String, _ data: Data) { lock.withLock { files[path] = data } }
}
