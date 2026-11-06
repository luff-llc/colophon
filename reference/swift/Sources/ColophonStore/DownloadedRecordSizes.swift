import Darwin
import Foundation

/// Logical size is a completed-byte measurement only after availability has been proven.
/// Immutable records need this metadata read once; pending files never use this cache.
final class DownloadedRecordSizes: @unchecked Sendable {
  private let lock = NSLock()
  private var sizes: [String: Int64] = [:]

  func record(_ size: Int64, for file: URL) {
    lock.withLock { sizes[file.path(percentEncoded: false)] = size }
  }

  func size(of file: URL) -> Int64? {
    let path = file.path(percentEncoded: false)
    if let size = lock.withLock({ sizes[path] }) { return size }
    var info = Darwin.stat()
    guard path.withCString({ lstat($0, &info) }) == 0,
      (info.st_mode & S_IFMT) == S_IFREG, info.st_size >= 0,
      (UInt32(info.st_flags) & 0x40000000) == 0 else { return nil }
    let size = Int64(info.st_size)
    lock.withLock { sizes[path] = size }
    return size
  }
}
