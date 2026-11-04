import Darwin
import Foundation

/// Final-component nofollow read inside an existing coordinated FolderStore claim.
/// The chosen library's ancestor path ownership remains the caller/provider's responsibility.
enum BoundedRecordFile {
  static func read(_ file: URL, maximumBytes: Int) throws -> Data? {
    guard maximumBytes >= 0 else { throw BoundedRecordReadError.exceedsLimit }
    let descriptor = file.withUnsafeFileSystemRepresentation { path in
      path.map { Darwin.open($0, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC) } ?? -1
    }
    guard descriptor >= 0 else {
      if errno == ENOENT { return nil }
      throw BoundedRecordReadError.invalidFile
    }
    defer { Darwin.close(descriptor) }
    var before = stat()
    guard fstat(descriptor, &before) == 0, before.st_mode & S_IFMT == S_IFREG,
      before.st_size >= 0 else { throw BoundedRecordReadError.invalidFile }
    guard before.st_size <= maximumBytes else { throw BoundedRecordReadError.exceedsLimit }
    let expected = Int(before.st_size)
    var output = Data()
    output.reserveCapacity(expected)
    var buffer = [UInt8](repeating: 0, count: min(65_536, max(1, maximumBytes)))
    while true {
      try Task.checkCancellation()
      let count = buffer.withUnsafeMutableBytes { Darwin.read(descriptor, $0.baseAddress, $0.count) }
      if count < 0 {
        if errno == EINTR { continue }
        throw BoundedRecordReadError.invalidFile
      }
      if count == 0 { break }
      guard count <= maximumBytes - output.count else { throw BoundedRecordReadError.exceedsLimit }
      output.append(contentsOf: buffer.prefix(count))
    }
    var after = stat()
    guard output.count == expected, fstat(descriptor, &after) == 0,
      after.st_dev == before.st_dev, after.st_ino == before.st_ino, after.st_size == before.st_size,
      after.st_mtimespec.tv_sec == before.st_mtimespec.tv_sec,
      after.st_mtimespec.tv_nsec == before.st_mtimespec.tv_nsec,
      after.st_ctimespec.tv_sec == before.st_ctimespec.tv_sec,
      after.st_ctimespec.tv_nsec == before.st_ctimespec.tv_nsec else {
      throw BoundedRecordReadError.changedDuringRead
    }
    return output
  }
}
