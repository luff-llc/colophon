import Foundation

/// A delivery route a host registers with each home at setup (§17.5: at least two, on different devices or services),
/// over which the home tells the person about pending changes. 0.5 gives notices no wire format: the host supplies
/// the registration through `HomeConfiguration.registerRoutes`.
public struct DeliveryRoute: Equatable, Hashable, Sendable {
    public enum Kind: String, Equatable, Hashable, Sendable { case push, email, sms, webhook, other }
    public let kind: Kind
    /// The address on that route (a push token, an address). Given only to the home.
    public let address: String
    /// The device or service the route reaches; two routes must name different ones.
    public let reaches: String
    public init(kind: Kind, address: String, reaches: String) { self.kind = kind; self.address = address; self.reaches = reaches }
}

/// Whether a home holds this host's delivery routes, as a value the UI shows.
public struct RouteState: Equatable, Sendable {
    public let home: String
    public let label: String
    public let registered: Bool
    /// What the person is told when `registered` is false.
    public let detail: String
    public init(home: String, label: String, registered: Bool, detail: String) {
        self.home = home; self.label = label; self.registered = registered; self.detail = detail
    }
}

/// The outcome of submitting a transition, veto or `suspend` to every current home (§17.5): retried until each home has
/// receipted it or 300 s have passed.
public struct Submission: Equatable, Sendable {
    public enum Kind: String, Equatable, Sendable { case transition, veto, suspend }
    public let object: String
    public let kind: Kind
    public let receipted: Int
    public let homes: Int
    /// True when the retry window closed (every home receipted, or 300 s passed).
    public let finished: Bool
    public init(object: String, kind: Kind, receipted: Int, homes: Int, finished: Bool) {
        self.object = object; self.kind = kind; self.receipted = receipted; self.homes = homes; self.finished = finished
    }
    public var complete: Bool { homes > 0 && receipted >= homes }
    public var words: String {
        if homes == 0 { return "No home to submit it to." }
        if complete { return "Every home (\(homes)) has receipted it." }
        return finished ? "Only \(receipted) of \(homes) homes receipted it within 5 minutes." : "Submitting to every home: \(receipted) of \(homes) have receipted it."
    }
}

/// A transition that fewer than `headQuorum` homes receipted within 300 s of its `issued`: dead (§17.5). It can be signed
/// again when this device signed it and kept its change.
public struct DeadTransition: Equatable, Sendable {
    public let digest: String
    public let receipted: Int
    public let quorum: Int
    public let canResign: Bool
    public init(digest: String, receipted: Int, quorum: Int, canResign: Bool) {
        self.digest = digest; self.receipted = receipted; self.quorum = quorum; self.canResign = canResign
    }
}

/// What a host must do and say beyond the engine's notices (§17.5), computed by the session from the account.
public struct HostDuties: Equatable, Sendable {
    /// The account has one control key: a stolen sole device can't be vetoed (guide §5). Shown at setup and after.
    public var soleDevice = false
    /// Per home: whether it holds this host's delivery routes.
    public var routes: [RouteState] = []
    /// The latest submissions this session made, with their receipts.
    public var submissions: [Submission] = []
    public var deadTransitions: [DeadTransition] = []
    /// Home labels by ID, for receipt times.
    public var homeLabels: [String: String] = [:]
    /// How often the session polls the homes now: `recoveryDelay` / 6, or 15 s while something is pending.
    public var pollInterval: Duration = .seconds(600)
    public static let none = HostDuties()
    public init() {}
}
