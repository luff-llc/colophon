import ColophonCore
import ColophonStore
import Foundation

/// One-shot deterministic authority-create failure. Mutable state is protected by lock.
final class AdditionalAccessTestStore: RecordStore, @unchecked Sendable {
  enum Injected: Error { case create }
  let memory = MemoryStore()
  private let lock = NSLock()
  private var remaining: Int?
  func failAfterAuthorityCreates(_ count: Int) { lock.withLock { remaining = count } }
  func list(_ directory: String) throws -> [String] { try memory.list(directory) }
  func read(_ path: String) throws -> Data? { try memory.read(path) }
  func replace(_ path: String, _ data: Data) throws { try memory.replace(path, data) }
  func create(_ path: String, _ data: Data) throws {
    let fail = lock.withLock { () -> Bool in
      guard path.hasPrefix("authority/"), let value = remaining else { return false }
      if value == 0 { remaining = nil; return true }
      remaining = value - 1; return false
    }
    if fail { throw Injected.create }
    try memory.create(path, data)
  }
}
