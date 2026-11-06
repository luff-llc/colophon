import Foundation
import Darwin

/// Private files are staged with protection/permissions before atomic publication.
/// Shared records use link(2), so a racing writer cannot replace an immutable record.
public enum AtomicFile {
    public static func write(_ bytes: Data, to url: URL, immutable: Bool = false) throws {
        let manager = FileManager.default
        let parent = url.deletingLastPathComponent()
        try manager.createDirectory(at: parent, withIntermediateDirectories: true,
                                    attributes: [.posixPermissions: 0o700])
        let staged = parent.appendingPathComponent(".stage-" + UUID().uuidString)
        defer { try? manager.removeItem(at: staged) }
        guard manager.createFile(atPath: staged.path, contents: nil, attributes: [.posixPermissions: 0o600]) else {
            throw StorageError.unavailable("Cannot stage private file")
        }
        #if os(iOS) || os(visionOS)
        try manager.setAttributes([.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication], ofItemAtPath: staged.path)
        #endif
        let handle = try FileHandle(forWritingTo: staged)
        do { try handle.write(contentsOf: bytes); try handle.synchronize(); try handle.close() }
        catch { try? handle.close(); throw error }
        if immutable {
            if link(staged.path, url.path) != 0 {
                if errno == EEXIST {
                    guard try read(url, maximumBytes: bytes.count) == bytes else { throw StorageError.conflict(url.lastPathComponent) }
                } else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
            }
        } else if rename(staged.path, url.path) != 0 {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        let descriptor = open(parent.path, O_RDONLY)
        guard descriptor >= 0 else { throw StorageError.unavailable("Cannot synchronize directory") }
        defer { close(descriptor) }
        guard fsync(descriptor) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    }

    public static func read(_ url: URL, maximumBytes: Int) throws -> Data {
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        guard attributes[.type] as? FileAttributeType == .typeRegular,
              let size = attributes[.size] as? NSNumber, size.intValue <= maximumBytes else { throw StorageError.limitExceeded }
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        let bytes = try handle.read(upToCount: maximumBytes + 1) ?? Data()
        guard bytes.count <= maximumBytes else { throw StorageError.limitExceeded }
        return bytes
    }
}
