import Foundation

@_exported import ColophonKit
@_exported import ColophonKitStorage

public enum SessionPhase: Equatable, Sendable {
    case opening, noLibrary, creating, migrating
    case waitingForDownload
    /// This device asked to join and is not approved yet. It shows no code of its own: the six-digit code
    /// appears only while it pairs with the approving device (`ColophonSession.beginJoinPairing()`).
    case waitingForApproval
    case denied
    case unavailable(reason: String)
    /// Authenticated content of a newer format than this client evaluates. Nothing is changed or lost.
    case updateRequired
    /// New in 0.5 (freeze package): this account was moved to a newer format. A layout raise (spec §20) became final in
    /// the history this device verified, so this app must be updated to continue with the account. It is a verified
    /// state, never a home's word or a refusal. What the device holds stays readable (`hasUsableContent`), as of the
    /// stop; nothing is written and no exchange runs; it persists across relaunch; `lock()` and `leave()` still work.
    /// `seq` is the raising activation's, `layout` the one it names (nil: an entry of a newer format, not a raise).
    case stopped(seq: UInt64, layout: UInt64?)
    case ready
    /// A refresh is in flight; previously verified content from this connection is still usable.
    case refreshing
    case retry
    /// New in 0.5: `lock()` ran (the app went to the background, or the engine was discarded). Content is
    /// hidden and no secret is held; `restore()`, `refresh()` or `unlock()` opens it again.
    case locked
    case failed(error: SessionFailure)
}

extension SessionPhase {
    /// True in the stopped phase (`stopped(seq:layout:)`): this app must be updated to continue with this account.
    public var isStopped: Bool { if case .stopped = self { true } else { false } }
}

public enum SessionFailure: Equatable, Sendable {
    case keysUnavailable(detail: String)
    case other(detail: String)
    public var message: String {
        switch self {
        case .keysUnavailable(let detail): "Your identity keys are unavailable. Unlock this device or restore key access, then retry. " + detail
        case .other(let detail): detail
        }
    }
}

public enum SessionError: Error, Equatable, Sendable {
    case notReady, staleRevision, destinationChanged, invalidCommand, publicationUncertain, migrationCollision
    /// New in 0.5: the account was created without a home and the host did not opt out (spec §18).
    case noHome
    /// New in 0.5: a step needs the owner controller (the person's passkey or owner key) and this
    /// configuration holds none that the account's keyring names.
    case ownerRequired
    /// New in 0.5: a configured home's endpoint is not `https` (see `HomeConfiguration.allowsLoopbackHTTP`).
    case insecureHome
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
    public init(namespace: String, kind: String, payloadJSON: Data) throws {
        guard (try JSONSerialization.jsonObject(with: payloadJSON)) is [String: Any] else { throw SessionError.invalidCommand }
        self.namespace = namespace; self.kind = kind; self.payload = payloadJSON
    }
    public static func saveLink(id: String = UUID().uuidString, url: URL, title: String) throws -> Self {
        guard ["http", "https"].contains(url.scheme?.lowercased()), url.host != nil else { throw SessionError.invalidCommand }
        struct Link: Encodable, Sendable { let id: String; let url: String; let title: String }
        return try Self(namespace: "reading.saved", kind: "capture", payload: Link(id: id, url: url.absoluteString, title: title))
    }
}

public enum WriteReceipt: Equatable, Sendable {
    /// The signed record is durable in this device's store. Homes receive it on the next exchange.
    case saved(operationID: String)
    /// Not durable yet (an ingress envelope that must be retried). Retry publishes the same envelope.
    case queued
}

public enum EnrollmentPolicy: Sendable {
    case pairing
    /// Approve device-local App Group app members through this controller's current authority.
    case deviceOnlyAppGroup(controller: any AsyncKeyProvider)
}

/// A home the account names, as this host reaches it.
public struct HomeConfiguration: Sendable {
    /// The home's base URL, as named in the account (`Home.endpoints`).
    public let endpoint: URL
    public let label: String
    /// Asks the home service for its own signed member request (§9.1) for a new account, to appoint it when
    /// this host creates the account. A request names the account, so it cannot exist before creation: the
    /// session calls this with the new account's ID. Nil: the home is not appointed here (it is reached only
    /// if the account already names it).
    public let request: (@Sendable (_ account: String) async throws -> Data)?
    /// Storage bearer token for the home (access to its store only, never membership).
    public let bearerToken: String?
    public let transport: any HomeTransport
    /// Delivery routes to register with this home at setup (§17.5): at least two, reaching different devices or services.
    public let deliveryRoutes: [DeliveryRoute]
    /// Registers `routes` for `account` with the home; returns false when the home offers no registration. 0.5 gives
    /// notices no wire format, so the host supplies the call (the relay does not implement notices yet). Nil: not offered.
    public let registerRoutes: (@Sendable (_ account: String, _ routes: [DeliveryRoute]) async throws -> Bool)?
    /// Testing option: allow a plain `http` endpoint on a loopback address. Every other home must be `https`; a session
    /// neither appoints nor contacts one that is not (`HomeProblem.insecureEndpoint`).
    public let allowsLoopbackHTTP: Bool
    public init(endpoint: URL, label: String = "Home", request: (@Sendable (_ account: String) async throws -> Data)? = nil, bearerToken: String? = nil,
                transport: (any HomeTransport)? = nil, allowsLoopbackHTTP: Bool = false, deliveryRoutes: [DeliveryRoute] = [],
                registerRoutes: (@Sendable (_ account: String, _ routes: [DeliveryRoute]) async throws -> Bool)? = nil) {
        self.endpoint = endpoint; self.label = label; self.request = request; self.bearerToken = bearerToken
        self.deliveryRoutes = deliveryRoutes; self.registerRoutes = registerRoutes
        self.transport = transport ?? URLSessionHomeTransport(allowingLoopbackHTTP: allowsLoopbackHTTP)
        self.allowsLoopbackHTTP = allowsLoopbackHTTP
    }
    /// Whether this endpoint may be used (`https`, or loopback `http` with the testing option).
    public var isAllowed: Bool { HomeLimits.isAllowed(endpoint, allowingLoopbackHTTP: allowsLoopbackHTTP) }
}

/// Who may read an account's history at its homes (`policy.history`, spec §13.4).
public enum HistoryAccess: String, Sendable {
    /// Anyone.
    case everyone = "public"
    /// Callers presenting a valid call: current members and the controllers §13.4 names.
    case members
}

public struct SessionConfiguration: Sendable {
    public let memberLabel: String
    public let memberKind: MemberKind
    public let namespaces: [String]
    public let access: [Access]
    public let libraryNamespaces: [String]
    public let location: StorageLocation
    public let privateContainer: URL
    /// Per-app content member; never reused as a controller or vault.
    public let keys: any AsyncKeyProvider
    /// Owner controller provider, separate from the content member. Hosts own persistence and presence policy.
    public let ownerController: any AsyncKeyProvider
    public let enrollment: EnrollmentPolicy
    /// Optional host-persisted recovery-kit controller (`recover` only, with its own sealed slot).
    public let recoveryKeys: (any AsyncKeyProvider)?
    /// The homes to appoint at creation and to exchange with. Spec §18: a host creates every account with
    /// at least one and warns when there is none. Empty and `createWithoutHome` false makes `create()`
    /// refuse with `SessionError.noHome`.
    public let homes: [HomeConfiguration]
    /// Explicit opt-out of §18 (tests, an account that will be given a home later). The account then
    /// reports `Notices.noHome` until a home is appointed.
    public let createWithoutHome: Bool
    /// Further controllers to create the account with (the reference setup has several control keys).
    public let additionalControllers: [AdditionalController]
    /// Where the 32-byte device-held key that seals saved state is kept (per account).
    public let deviceSecrets: any DeviceSecretStore
    /// The clock, for tests. Everything the engine judges by time uses it.
    public let now: @Sendable () -> Date
    /// `recoveryDelay` for a new account, in seconds (`policy.recoveryDelay`; spec §18: at least 3,600 with a home).
    public let recoveryDelay: Int?
    /// `policy.history` for a new account (spec §13.4): who may read the history at a home. Nil: the default policy's.
    public let history: HistoryAccess?
    /// `policy.headQuorum` for a new account (spec §12.3): how many homes' fresh heads a call needs. Nil: the default.
    public let headQuorum: Int?
    /// Whether the owner key alone is enough to sign the controller's own steps (no other control key).
    public init(memberLabel: String, memberKind: MemberKind = .app, namespaces: [String], access: [Access] = [.read, .write],
                libraryNamespaces: [String]? = nil, location: StorageLocation, privateContainer: URL,
                keys: any AsyncKeyProvider, ownerController: any AsyncKeyProvider, recoveryKeys: (any AsyncKeyProvider)? = nil,
                enrollment: EnrollmentPolicy = .pairing, homes: [HomeConfiguration] = [], createWithoutHome: Bool = false, additionalControllers: [AdditionalController] = [],
                deviceSecrets: any DeviceSecretStore = KeychainDeviceSecrets(), recoveryDelay: Int? = nil,
                history: HistoryAccess? = nil, headQuorum: Int? = nil,
                now: @escaping @Sendable () -> Date = { Date() }) {
        self.history = history; self.headQuorum = headQuorum
        self.ownerController = ownerController; self.homes = homes; self.createWithoutHome = createWithoutHome
        self.additionalControllers = additionalControllers
        self.memberLabel = memberLabel; self.memberKind = memberKind; self.namespaces = namespaces
        self.access = access; self.libraryNamespaces = libraryNamespaces ?? namespaces
        self.enrollment = enrollment; self.deviceSecrets = deviceSecrets; self.recoveryDelay = recoveryDelay; self.now = now
        self.location = location; self.privateContainer = privateContainer; self.keys = keys; self.recoveryKeys = recoveryKeys
    }
}

/// A further controller the account is created with (spec §18: each device's owner key, a passkey per platform,
/// recovery keys). It signs its own possession proof at creation, so its provider is needed then.
public struct AdditionalController: Sendable {
    public let provider: any AsyncKeyProvider
    public let label: String
    public let roles: [ControllerRole]
    public init(provider: any AsyncKeyProvider, label: String, roles: [ControllerRole] = [.approve, .control]) {
        self.provider = provider; self.label = label; self.roles = roles
    }
}

/// A member's request for access, as an approver sees it. It carries no code: approving it spends a
/// confirmed pairing for exactly its key (spec §9.1), from the six-digit code (`beginApproval`,
/// `approvalCode`) or from scanning the request on the joining device's screen (`scanRequest`).
public struct AccessRequest: Equatable, Sendable, Identifiable {
    /// The member's key ID.
    public let id: String
    public let label: String
    public let kind: AccountMemberKind
    public let termsJSON: String
    /// The request exactly as signed (the canonical envelope); the joining device shows it as a QR
    /// code (`ColophonSession.exportRequest()`) for the approving device to scan.
    public let record: Data
    public init(id: String, label: String, kind: AccountMemberKind, termsJSON: String, record: Data) {
        self.id = id; self.label = label; self.kind = kind; self.termsJSON = termsJSON; self.record = record
    }
    /// The namespaces the request asks for, read from its terms.
    public var namespaces: [String] { records.map(\.0) }
    /// The access it asks for: read, plus write when any record entry asks for it.
    public var access: [Access] { records.contains { $0.1 == "write" } ? [.read, .write] : [.read] }
    private var records: [(String, String)] {
        guard let object = try? JSONSerialization.jsonObject(with: Data(termsJSON.utf8)) as? [String: Any],
              let list = object["records"] as? [[String: Any]] else { return [] }
        return list.compactMap { entry in (entry["namespace"] as? String).map { ($0, (entry["access"] as? String) ?? "read") } }
    }
}

/// The approving device's half of the six-digit code (§7.3): the session it opened when the joining
/// device's commitment arrived, and the nonce to send back. Send `nonce`; when the joining device's
/// reveal arrives, `ColophonSession.approvalCode(pairing:e:nb:)` gives the code both screens show.
public struct ApprovalStart: @unchecked Sendable {
    public let pairing: AccountPairing
    public let nonce: Data
}

/// A request scanned from the joining device's screen, with the confirmed pairing that scan made
/// (§7.3, §9.1): `ColophonSession.approve(_:pairing:grant:)` spends it. Nothing is stored for it.
public struct ScannedRequest: @unchecked Sendable {
    public let request: AccessRequest
    public let pairing: AccountPairing
}

/// What a person may be shown about this account that is not content (§17.5, §18).
public struct SessionNotices: Equatable, Sendable {
    public let notices: Notices
    public init(notices: Notices) { self.notices = notices }
    /// Transitions not yet shown or still pending, with signers, first-seen seq, deadline and `vetoable`.
    public var pending: [Pending] { notices.pending }
    /// Activations no key on this device signed that the person has not seen.
    public var unseenActivations: [SeenActivation] { notices.activations }
    /// The account names no home: warn (spec §18, guide §5). Without a home there is no witness of time or order.
    public var noHome: Bool { notices.noHome }
    public var owed: [Owed] { notices.owed }
    public static let empty = SessionNotices(notices: Notices(pending: [], activations: [], owed: [], controllersWithoutSlot: [], vaultRetiring: false, noHome: false))
}

extension SessionError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .migrationCollision: "A native object already uses this imported identity. Review and remap the source occurrence before continuing the upgrade."
        case .publicationUncertain: "Publication needs review. Refresh and inspect the ledger before retrying this action."
        case .notReady: "The library is not ready. Restore access and retry."
        case .staleRevision: "The library changed while this action was open. Review the current values and try again."
        case .destinationChanged: "The selected library or member changed. Start this action again."
        case .invalidCommand: "This command or extension envelope is invalid."
        case .noHome: "This account has no home. Without one there is no witness of time or order for your changes; add a home before relying on it."
        case .ownerRequired: "This step needs the account owner's key."
        case .insecureHome: "A home must be reached over HTTPS. This one is not, so it was not used."
        }
    }
}
