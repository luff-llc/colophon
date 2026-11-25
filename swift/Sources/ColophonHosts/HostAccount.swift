import Foundation
@_spi(Hosts) import ColophonSession

/// The account a host acts for, made from a ready `ColophonSession`. It is opaque: the engine, the member key and the
/// session's exchange stay inside the hosts, which use them only from their own serial queues. Nothing in the hosts'
/// public API returns the engine, a signer or an endpoint.
public struct ColophonHostAccount: Sendable {
    let source: any HostAccount
    /// The host account of `session`, which must be ready (it knows its account and member).
    @MainActor init(session: ColophonSession) throws { source = try SessionHostAccount(session: session) }
    init(_ source: any HostAccount) { self.source = source }
    /// The account (64 hex).
    public var account: String { source.account }
    /// This device's member ID.
    public var member: String { source.member }
    /// The transport the session was configured with for `home` (its ticket requests go there), if any.
    public func transport(home: String) async -> (any HomeTransport)? { await (source as? SessionHostAccount)?.transport(home: home) }
}

/// What the 0.6 hosts need from the account: the member engine, the ticket call, an exchange pass, and the member key
/// for one raw signature. Internal: `ColophonHostAccount` is the only way in from outside the module.
protocol HostAccount: Sendable {
    /// The account (64 hex).
    var account: String { get }
    /// This device's member ID.
    var member: String { get }
    /// The member engine as it is now. Stream and endpoint calls take it; it is asked for again for every call, so a
    /// locked or reopened engine is seen at once (a locked one fails with `locked`; a reopened one is another engine to
    /// an endpoint, `session:wrongView`).
    func engine() async throws -> AccountEngine
    /// The `colophon.home.stream` call for `home`, signed and judged by the core, as the envelope's bytes.
    func streamCall(home: String) async throws -> Data
    /// One ordinary exchange pass with the homes (the stream's `Wake`).
    func exchange() async throws
    /// A raw P-256 signature (`r || s`) by this member's key over `body` (a session delegation, sessions §S2).
    func signRaw(_ body: Data) async throws -> Data
}

/// The host account of a restored `ColophonSession`. The session keeps owning the engine, its lock and its exchange;
/// this only reaches them. `exchange` is the session's own `syncNow`, so passes never overlap with its poll loop.
struct SessionHostAccount: HostAccount {
    let account: String
    let member: String
    private let access: SessionHostAccess

    /// The host account of `session`, which must be ready (it knows its account and member).
    @MainActor init(session: ColophonSession) throws {
        guard let account = session.libraryID, let member = session.memberID else { throw HostError.notReady }
        self.account = account; self.member = member
        access = session.hostAccess
    }
    func engine() async throws -> AccountEngine { try await access.engine() }
    func streamCall(home: String) async throws -> Data { try await access.streamCall(home: home) }
    func exchange() async throws { try await access.exchange() }
    func signRaw(_ body: Data) async throws -> Data { try await access.signRaw(body) }
    func transport(home: String) async -> (any HomeTransport)? { await access.transport(home: home) }
}

/// What a host refuses on its own (the core's refusals arrive as `ColophonError`).
public enum HostError: Error, Equatable, Sendable {
    /// The session is not ready: it knows no account or member yet.
    case notReady
    /// The socket factory refused the URL (not `wss`, and not an allowed loopback `ws`).
    case insecureSocket
}

/// The code of an error as the core spells it (`session:staleAccount`, `locked`, ...), or the error's type name.
func codeOf(_ error: any Error) -> String {
    if let account = error as? AccountError { return ColophonError(account).code }
    if let colophon = error as? ColophonError { return colophon.code }
    if let host = error as? CellHostError { return host.code.rawValue }
    return String(describing: type(of: error))
}
