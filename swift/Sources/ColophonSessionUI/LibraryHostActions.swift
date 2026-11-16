import ColophonSession
import Foundation

public enum LibraryConnectionPurpose: Sendable { case join, connectAnotherDevice }

/// Only list containers for which the host has entitlements. App Groups share on this device.
public struct LibraryContainerChoice: Identifiable, Sendable {
    public enum Kind: Sendable { case iCloud, appGroup }
    public let id: String
    public let title: String
    public let kind: Kind
    public let location: StorageLocation
    public init(id: String, title: String, kind: Kind, location: StorageLocation) {
        self.id = id; self.title = title; self.kind = kind; self.location = location
    }
}

/// Host policy at the edges of ColophonSession. No closure is an implicit approval or key fallback.
/// A connection handler must persist bookmarks/configuration and replace the process session after
/// successful preparation. Folder security scope is held for the duration of the callback only.
/// Recovery handlers own the kit format and protected persistence; restoreDevice adds a controller through the keyring.
/// The session does not define a recovery kit serialization format.
@MainActor public struct LibraryHostActions {
    public var containers: [LibraryContainerChoice]
    public var connect: ((LibraryConnectionPurpose, StorageLocation) async throws -> Void)?
    public var rejoinKeys: (() async throws -> any AsyncKeyProvider)?
    public var exportRecoveryKit: (() async throws -> String)?
    public var importRecoveryKit: ((String) async throws -> Void)?
    /// The host's camera: reads the request a joining device shows as a QR code and returns its bytes (the canonical
    /// request envelope, spec §9.1). Without it, the settings screen offers no scan; a host that pairs by the six-digit
    /// code opens `ApproveRequestView(request:pairing:code:session:)` itself.
    public var scanRequest: (() async throws -> Data)?
    public init(containers: [LibraryContainerChoice] = [],
                connect: ((LibraryConnectionPurpose, StorageLocation) async throws -> Void)? = nil,
                rejoinKeys: (() async throws -> any AsyncKeyProvider)? = nil,
                exportRecoveryKit: (() async throws -> String)? = nil,
                importRecoveryKit: ((String) async throws -> Void)? = nil,
                scanRequest: (() async throws -> Data)? = nil) {
        self.containers = containers; self.connect = connect; self.rejoinKeys = rejoinKeys
        self.exportRecoveryKit = exportRecoveryKit; self.importRecoveryKit = importRecoveryKit; self.scanRequest = scanRequest
    }
}
