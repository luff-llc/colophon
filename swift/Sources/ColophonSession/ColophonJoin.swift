import Foundation

/// What `ColophonJoin.fetchHistory()` found.
public enum JoinHistory: Sendable, Equatable {
    /// Not admitted yet: the home refused the read with `403 refused:revoked` (no grant names this key), or its history
    /// names no member with this ID. Spec 0.5 gives the same result after a revocation, so this also covers a member
    /// revoked before its first fetch: show "Waiting for approval", and at a deadline "Not approved, or no longer allowed".
    case waiting
    /// The verified history, as files to store (`authority/<seq, eight digits>.json`), before the session is opened.
    case admitted(files: [String: Data])
}

/// Why a join at an invite's head failed. Anything here is an error, never "waiting".
public enum JoinError: Error, Equatable, Sendable {
    /// The home refused the read for another reason than "not a member" (its status, and the `result` it gave, validated).
    case refused(status: UInt32, code: String?)
    /// The fetched history was not accepted (`code` as the core gives it): another account or digest at the invite's seq
    /// (`refused:fork`), a history shorter than the signed head (`refused:rollback`), this member revoked
    /// (`refused:revoked`) or expired (`refused:expired`), a grant of another request (`refused:conflict`), a history that
    /// does not reach the invite's head or a head that stayed behind (`unavailable`), or a page that is not one.
    case rejected(code: String, detail: String)
    /// The request stored at `requests/<member ID>.json` names another account (an earlier join on this medium).
    case otherRequest(path: String)
}

/// Joining an account at an invite's head (Colophon 0.5.2): a device that holds only the account ID, the home's base, the
/// invite's head `(seq, entry digest)` and its own member keys asks to join and, once approved, fetches and verifies the
/// account's history from the home.
///
/// - `request()` makes this device's signed membership request exactly as the session does and stores it at
///   `requests/<member ID>.json` in the configuration's storage (or returns the one stored there), so a session opened
///   later with the same configuration finds and reuses it. Show it as the request QR code.
/// - `fetchHistory()` reads `GET {home}/authority` page by page, each with a `colophon.history.read` call signed by the
///   member key whose `asOf` is the invite's head, and `GET {home}/head`. It accepts the history only when it verifies
///   completely, is the account's, holds the invite's head at its seq, ends at the home's signed head and grants this
///   member from exactly the stored request, still current. Write the files to the storage, then open the session.
///
/// The transport is the configured home whose endpoint is `home` (same base), else HTTPS with no loopback.
public struct ColophonJoin: Sendable {
    /// The result a home gives a call from a key no grant names (spec 0.5 keeps it; `refused:notGranted` is reserved).
    public static let waitingCode = "refused:revoked"
    static let maxPages = 4096

    public let configuration: SessionConfiguration
    public let account: String
    public let home: URL
    public let seq: UInt64
    public let head: String
    private let keys: any AsyncKeyProvider
    private let base: String
    private let homeConfiguration: HomeConfiguration

    public init(configuration: SessionConfiguration, account: String, home: URL, seq: UInt64, head: String) {
        self.configuration = configuration; self.account = account; self.home = home; self.seq = seq; self.head = head
        keys = SessionKeys(base: configuration.keys)
        let base = Self.trimmed(home.absoluteString)
        self.base = base
        homeConfiguration = configuration.homes.first { Self.trimmed($0.endpoint.absoluteString) == base }
            ?? HomeConfiguration(endpoint: URL(string: base + "/") ?? home)
    }
    private static func trimmed(_ s: String) -> String { var s = s; while s.hasSuffix("/") { s.removeLast() }; return s }
    private var nowMs: Int64 { Int64((configuration.now().timeIntervalSince1970 * 1000).rounded()) }

    /// This device's member ID (the key ID of its member signing key).
    public func memberID() async throws -> String { try await KeyCustody.keyID(of: keys) }

    /// The signed request, made as the session's own (stored once in the storage, then reused).
    public func request() async throws -> Data {
        let id = try await memberID()
        let raw = try await OwnRequest.ensure(configuration, medium: try configuration.location.resolve(), keys: keys, account: account,
                                              memberID: id, nowMs: nowMs)
        guard OwnRequest.account(raw) == account else { throw JoinError.otherRequest(path: OwnRequest.path(id)) }
        return raw
    }

    /// Fetch and verify the history. `.waiting` while this member is not admitted; `JoinError` for any other refusal or a
    /// history that is not accepted; a transport failure is thrown as it came (`HomeTransportError`). A home whose signed
    /// head moved while the history was read is read again, at most three times.
    public func fetchHistory() async throws -> JoinHistory {
        let request = try await request()
        var attempt = 0
        while true {
            attempt += 1
            guard let entries = try await readHistory() else { return .waiting }
            let signedHead = try await get("/head", authorization: nil)
            guard signedHead.status == 200 else { throw refused(signedHead) }
            let verdict: JoinedHistory
            do {
                verdict = try accountVerifyAtHead(account: account, seq: seq, head: head, request: request, base: base,
                                                  signedHead: signedHead.body, entries: entries, nowMs: nowMs)
            } catch {
                let e = ColophonError.wrap(error)
                guard let typed = e as? ColophonError else { throw e }
                if typed.code == "unavailable", attempt < 3 { continue }
                throw JoinError.rejected(code: typed.code, detail: typed.detail)
            }
            guard verdict.admitted else { return .waiting }
            return .admitted(files: Dictionary(uniqueKeysWithValues: verdict.stores.map { ($0.path, $0.bytes) }))
        }
    }

    /// The WebAuthn descriptor (`rp`, credential, origins) of controller `keyID` in the verified history `files` (as
    /// `.admitted` gave them), when it is a current WebAuthn controller; nil for a removed, provisional, suspended or raw
    /// controller, or one the keyring does not hold. An invite names the owner's key ID only.
    public static func ownerDescriptor(files: [String: Data], keyID: String, now: Date = Date()) throws -> KeyDescriptorView? {
        let entries = files.filter { $0.key.hasPrefix("authority/") }.sorted { $0.key < $1.key }.map { ByteString(bytes: $0.value) }
        do { return try accountCurrentWebauthnController(entries: entries, id: keyID, nowMs: Int64((now.timeIntervalSince1970 * 1000).rounded())) }
        catch { throw ColophonError.wrap(error) }
    }

    /// Every page of the history, or nil when the home refuses the read as from a non-member.
    private func readHistory() async throws -> [ByteString]? {
        let signing = try await keys.publicKeys().signing
        var entries: [ByteString] = []
        var after: UInt64 = 0
        var pages = 0
        while true {
            pages += 1
            if pages > Self.maxPages { throw JoinError.rejected(code: "malformed", detail: "the history has too many pages") }
            let path = accountHistoryPagePath(after: after)
            let call: HistoryReadCall
            do {
                let created = try accountFormatDate(ms: nowMs)
                let prepared = try withEntropy(32) { id in
                    try AccountHistoryRead.prepare(spec: HistoryReadSpec(account: account, asOfSeq: seq, asOfDigest: head, signing: signing,
                        audience: base, path: path, requestId: Data(Array(id)), created: created))
                }
                let signature = try await keys.sign(body: try prepared.step().body)
                call = try prepared.finish(signature: Signature(signature: signature, authenticatorData: nil, clientData: nil))
            } catch { throw ColophonError.wrap(error) }
            let answer = try await get(path, authorization: call.authorization)
            if answer.status == 403, HomeRefusal.result(of: answer.body) == Self.waitingCode { return nil }
            guard answer.status == 200 else { throw refused(answer) }
            let page: HistoryPage
            do { page = try accountHistoryPage(body: answer.body) } catch {
                let e = ColophonError.wrap(error)
                throw JoinError.rejected(code: (e as? ColophonError)?.code ?? "malformed", detail: (e as? ColophonError)?.detail ?? "")
            }
            if page.more && page.entries.isEmpty { throw JoinError.rejected(code: "malformed", detail: "a history page made no progress") }
            entries += page.entries
            after += UInt64(page.entries.count)
            if !page.more { return entries }
        }
    }

    private func get(_ path: String, authorization: String?) async throws -> HttpAnswer {
        let url = base + path
        guard homeConfiguration.isAllowed else { throw HomeTransportError.insecureEndpoint(homeConfiguration.endpoint.absoluteString) }
        let headers = authorization.map { [Header(name: "Authorization", value: $0)] } ?? []
        let answer = try await homeConfiguration.transport.send(HttpRequest(ticket: 0, home: "", method: .get, url: url, headers: headers, body: Data()))
        let limit = HomeLimits.responseBytes(for: url)
        if answer.body.count > limit { throw HomeTransportError.responseTooLarge(limit: limit) }
        return answer
    }

    private func refused(_ answer: HttpAnswer) -> JoinError { .refused(status: answer.status, code: HomeRefusal.result(of: answer.body)) }
}
