import ColophonSession
import Foundation

/// Strict allowlist: no arbitrary errors, paths, IDs, labels, codes, records or kit material.
public struct SupportReport: Encodable, Equatable, Sendable {
    public let schema = 1
    public let phase: String
    public let failureCategory: String?
    public let memberCount: Int
    public let requestCount: Int
    public let ledgerEntryCount: Int
    public let system: String
    @MainActor public init(session: any LibrarySessionSource) {
        switch session.phase {
        case .opening: phase = "opening"
        case .noLibrary: phase = "noLibrary"
        case .creating: phase = "creating"
        case .migrating: phase = "migrating"
        case .waitingForApproval: phase = "waitingForApproval"
        case .denied: phase = "denied"
        case .unavailable: phase = "unavailable"
        case .ready: phase = "ready"
        case .failed: phase = "failed"
        }
        switch session.phase {
        case .failed(.keysUnavailable): failureCategory = "keysUnavailable"
        case .failed(.other): failureCategory = "other"
        case .unavailable: failureCategory = "unavailable"
        default: failureCategory = nil
        }
        memberCount = session.members.count; requestCount = session.requests.count
        ledgerEntryCount = session.ledger.count
        let version = ProcessInfo.processInfo.operatingSystemVersion
        #if os(macOS)
        let platform = "macOS"
        #elseif os(iOS)
        let platform = "iOS"
        #else
        let platform = "Apple platform"
        #endif
        system = "\(platform) \(version.majorVersion).\(version.minorVersion).\(version.patchVersion)"
    }
    public func text() throws -> String {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return String(decoding: try encoder.encode(self), as: UTF8.self)
    }
}
