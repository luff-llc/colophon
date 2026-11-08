import ColophonSession
import Foundation

/// App-owned welcome copy. Supply artwork using LibraryGate's artwork builder.
public struct LibraryPresentation: Sendable {
    public var appName: String
    public var welcomeTitle: String
    public var promise: String
    public var createTitle: String
    public var joinTitle: String
    public var dataNote: String
    public init(appName: String, promise: String, welcomeTitle: String? = nil,
                createTitle: String = "Get Started", joinTitle: String? = nil,
                dataNote: String = "Your library belongs to you.") {
        self.appName = appName; self.promise = promise
        self.welcomeTitle = welcomeTitle ?? "Welcome to \(appName)"
        self.createTitle = createTitle
        self.joinTitle = joinTitle ?? "I Use \(appName) on Another Device"
        self.dataNote = dataNote
    }
}

public enum LibraryWords {
    public static func namespace(_ value: String) -> String {
        switch value {
        case "reading.books": "Books"
        case "reading.saved": "Saved links"
        case "listening.podcasts": "Podcasts"
        case "notes": "Notes"
        default: value
        }
    }
    public static func kind(_ value: MemberKind) -> String {
        switch value { case .app: "App"; case .device: "Device"; case .agent: "AI agent"; case .server: "Server" }
    }
    public static func access(_ value: [Access]) -> String {
        if value.contains(.read) && value.contains(.write) { return "Read and change" }
        if value.contains(.read) { return "Read only" }
        if value.contains(.write) { return "Write only" }
        return "No access"
    }
    public static func grant(_ member: Member) -> String {
        if member.revokedAt != nil { return "Access ended" }
        guard let grant = member.grant else { return "Waiting for approval" }
        var lines = [access(grant.access), grant.namespaces.map(namespace).joined(separator: ", ")]
        if grant.import == true { lines.append("Can import history") }
        if let expires = grant.expires { lines.append("Expires \(date(expires))") }
        if let budget = grant.writeBudget { lines.append("Up to \(budget) changes; \(member.writes) made") }
        return lines.joined(separator: " · ")
    }
    public static func date(_ value: String) -> String {
        guard let date = try? Date(value, strategy: .iso8601) else { return value }
        return date.formatted(date: .abbreviated, time: .shortened)
    }
    public static let revocation = "Future access ends. Past contributions stay attributed to this member. Ending access cannot make a device forget content it has already read."
    public static let leaving = "This disconnects this app on this device. Your library and past contributions stay intact, and membership is not revoked. You can rejoin later."
}
