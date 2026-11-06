import Foundation
import ColophonKitStorage

/// Shared status only: no source payloads, identity keys or grants. A missing destination
/// with an active marker is an upgrade in progress, never an empty library.
public struct MigrationMarker: Codable, Sendable {
    public let sourceLibraryID: String
    public let active: Bool
    public init(sourceLibraryID: String, active: Bool) { self.sourceLibraryID = sourceLibraryID; self.active = active }
    public func save(at url: URL) throws { try AtomicFile.write(JSONEncoder().encode(self), to: url) }
    public static func isActive(at url: URL) throws -> Bool {
        do { return try JSONDecoder().decode(Self.self, from: AtomicFile.read(url, maximumBytes: 4096)).active }
        catch let error as CocoaError where error.code == .fileReadNoSuchFile || error.code == .fileNoSuchFile { return false }
    }
}
