import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// Publishes a private file atomically within a caller-owned parent directory.
/// The parent must already exist. This does not harden arbitrary ancestors or promise crash durability.
public enum PrivateAtomicFile {
  public static func write(_ data: Data, to destination: URL) throws {
    try write(data, to: destination, beforePublish: { _ in })
  }

  // A deterministic checkpoint tests failure and privacy before the destination changes.
  static func write(_ data: Data, to destination: URL, beforePublish: (URL) throws -> Void) throws {
    guard destination.isFileURL else { throw CocoaError(.fileWriteUnsupportedScheme) }
    let stage = destination.deletingLastPathComponent()
      .appendingPathComponent(".colophon-private-" + UUID().uuidString, isDirectory: true)
    let created = stage.withUnsafeFileSystemRepresentation { path in
      guard let path else { return Int32(-1) }
      return mkdir(path, mode_t(0o700))
    }
    guard created == 0 else { throw posixError() }
    // Cleanup starts only after exclusive creation succeeds; never adopt a preexisting directory.
    defer { try? FileManager.default.removeItem(at: stage) }
    let payload = stage.appendingPathComponent("payload")
    guard FileManager.default.createFile(atPath: payload.path, contents: nil,
      attributes: [.posixPermissions: 0o600]) else { throw CocoaError(.fileWriteUnknown) }
    #if os(iOS) || os(visionOS)
    try data.write(to: payload, options: [.atomic, .completeFileProtection])
    #else
    try data.write(to: payload, options: .atomic)
    #endif
    // Foundation's atomic replacement may create a new inode. It remains inside the private
    // directory until its final permissions (and on iOS/visionOS protection) are established.
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: payload.path)
    try beforePublish(payload)
    let result = payload.withUnsafeFileSystemRepresentation { source in
      destination.withUnsafeFileSystemRepresentation { target in
        guard let source, let target else { return Int32(-1) }
        return rename(source, target)
      }
    }
    guard result == 0 else { throw posixError() }
  }

  private static func posixError() -> NSError {
    NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
  }
}
