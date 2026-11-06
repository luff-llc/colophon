@_exported import ColophonKit
@_exported import ColophonKitStorage
import Foundation

public enum SessionPhase: Equatable, Sendable {
    case opening, noLibrary, creating
    case waitingForApproval(code: String)
    case denied
    case unavailable(reason: String)
    case ready
    case failed(error: String)
}

public enum SessionError: Error, Equatable, Sendable {
    case notReady, staleRevision, destinationChanged, invalidCommand, publicationUncertain
}

/// A command is bound to the context and revision observed before the user's action began.
public struct ObservedRevision: Equatable, Sendable {
    public let context: UUID
    public let revision: UInt64
}

public struct DomainCommand: Codable, Equatable, Sendable {
    public let namespace: String
    public let kind: String
    public let payload: Data
    public init<Payload: Encodable & Sendable>(namespace: String, kind: String, payload: Payload) throws {
        self.namespace = namespace; self.kind = kind
        self.payload = try JSONEncoder().encode(payload)
    }
    public static func saveLink(id: String = UUID().uuidString, url: URL, title: String) throws -> Self {
        guard ["http", "https"].contains(url.scheme?.lowercased()), url.host != nil else { throw SessionError.invalidCommand }
        struct Link: Encodable, Sendable { let id: String; let url: String; let title: String }
        return try Self(namespace: "reading.saved", kind: "capture", payload: Link(id: id, url: url.absoluteString, title: title))
    }
}

public enum WriteReceipt: Equatable, Sendable {
    case saved(operationID: String)
    /// Signed records are journaled privately; retry publishes the same bytes, never re-signs.
    case queued
}

public enum EnrollmentPolicy: Sendable {
    case pairing
    /// Only device-local App Group app identities, while this key is still the current root.
    /// The host must stop supplying it when protecting or moving the library.
    case deviceOnlyAppGroup(starterKeys: any AsyncKeyProvider)
}

public struct SessionConfiguration: Sendable {
    public let memberLabel: String
    public let memberKind: MemberKind
    public let namespaces: [String]
    public let access: [Access]
    public let libraryNamespaces: [String]
    public let location: StorageLocation
    public let privateContainer: URL
    public let keys: any AsyncKeyProvider
    public let enrollment: EnrollmentPolicy
    public let recoveryKeys: (any AsyncKeyProvider)?
    public init(memberLabel: String, memberKind: MemberKind = .app, namespaces: [String], access: [Access] = [.read, .write],
                libraryNamespaces: [String]? = nil, location: StorageLocation, privateContainer: URL,
                keys: any AsyncKeyProvider, recoveryKeys: (any AsyncKeyProvider)? = nil, enrollment: EnrollmentPolicy = .pairing) {
        self.memberLabel = memberLabel; self.memberKind = memberKind; self.namespaces = namespaces
        self.access = access; self.libraryNamespaces = libraryNamespaces ?? namespaces
        self.enrollment = enrollment
        self.location = location; self.privateContainer = privateContainer; self.keys = keys; self.recoveryKeys = recoveryKeys
    }
}

struct CoreSnapshot: Sendable {
    let libraryID: String
    let me: Member
    let members: [Member]
    let ledger: [LedgerEntry]
    let requests: [AccessRequest]
    let views: [String: NamespaceView]
    let denials: [String: Denial]
    let records: [String: Data]
}

struct SessionSnapshot: Sendable {
    let phase: SessionPhase
    let core: CoreSnapshot?
    let revision: UInt64
    let namespaceRevisions: [String: UInt64]
}

extension SessionConfiguration {
    var starterKeys: (any AsyncKeyProvider)? {
        guard memberKind == .app, case .appGroup = location,
              case .deviceOnlyAppGroup(let keys) = enrollment else { return nil }
        return keys
    }
}

extension SessionError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .publicationUncertain: "Publication needs review. Refresh and inspect the ledger before retrying this action."
        case .notReady: "The library is not ready. Restore access and retry."
        case .staleRevision: "The library changed while this action was open. Review the current values and try again."
        case .destinationChanged: "The selected library or member changed. Start this action again."
        case .invalidCommand: "This command or extension envelope is invalid."
        }
    }
}
