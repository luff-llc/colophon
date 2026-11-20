import Foundation

/// What `ColophonJoin.fetchHistory()` found.
public enum JoinHistory: Sendable, Equatable {
    /// Not yet admitted, or no longer admitted; the home's answer is the same for both by design. The home refused the
    /// read with `403 refused:revoked` (the result spec 0.5 gives a key no current grant names, before an approval and
    /// after a revocation alike), or the history it served names no member with this ID. A host shows that it is waiting
    /// for approval and, at its own deadline, that the device was not approved or is no longer allowed.
    case notAdmitted
    /// The accepted history. Only `fetchHistory()` makes one, after every acceptance condition held.
    case admitted(AdmittedHistory)
}

/// A history `ColophonJoin.fetchHistory()` accepted: it verified from seq 1 as the account's, holds the given entry at its
/// seq, ends at a fresh head signed by a current home serving at the base, and grants this member from its exact request.
/// Nothing in it reaches the host before then: it has no public initialiser.
public struct AdmittedHistory: Sendable, Equatable {
    /// The files to store (`authority/<seq, eight digits>.json`) before the session is opened.
    public let files: [String: Data]
    init(files: [String: Data]) { self.files = files }

    /// The WebAuthn descriptor (`rp`, credential, origins) of controller `keyID` in this accepted history, when it is a
    /// current WebAuthn controller; nil for a removed, provisional, suspended or raw controller, or one the keyring does
    /// not hold. `KeyDescriptor(view:)` (ColophonKeys) turns it into a descriptor a passkey provider takes.
    public func ownerDescriptor(keyID: String, now: Date = Date()) throws -> KeyDescriptorView? {
        let entries = files.filter { $0.key.hasPrefix("authority/") }.sorted { $0.key < $1.key }.map { ByteString(bytes: $0.value) }
        do { return try accountCurrentWebauthnController(entries: entries, id: keyID, nowMs: Int64((now.timeIntervalSince1970 * 1000).rounded())) }
        catch { throw ColophonError.wrap(error) }
    }
}

/// Why a join at an invite's head failed. Anything here is an error, never "not admitted".
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
    /// Reads of the history and head in one `fetchHistory()` when the signed head moved meanwhile.
    public static let attempts = 3
    /// Spec §2.4's portability floor for envelopes: the most entry bytes a joining device holds.
    public static let maxHistoryBytes = 256 * 1024 * 1024
    /// 4,096 pages of 64 entries.
    public static let maxEntries = 1 << 18

    public let configuration: SessionConfiguration
    public let account: String
    public let home: URL
    public let seq: UInt64
    public let head: String
    private let keys: any AsyncKeyProvider
    private let base: String
    private let homeConfiguration: HomeConfiguration
    /// The entry-byte bound while paging (`maxHistoryBytes`); tests lower it to exercise the bound cheaply.
    var historyByteLimit = ColophonJoin.maxHistoryBytes

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

    /// Fetch and verify the history. `.notAdmitted` while this member is not (or no longer) admitted; `JoinError` for any
    /// other refusal or a history that is not accepted; a transport failure is thrown as it came (`HomeTransportError`).
    /// A home whose signed head moved while the history was read (`unavailable`: behind; `refused:rollback`: beyond what
    /// was served) is read again, at most `attempts` times in all; a home that keeps serving less than it signed then
    /// fails with `refused:rollback`.
    public func fetchHistory() async throws -> JoinHistory {
        let request = try await request()
        var attempt = 0
        while true {
            attempt += 1
            guard let entries = try await readHistory() else { return .notAdmitted }
            let signedHead = try await get("/head", authorization: nil)
            guard signedHead.status == 200 else { throw refused(signedHead) }
            let verdict: JoinedHistory
            do {
                verdict = try accountVerifyAtHead(account: account, seq: seq, head: head, request: request, base: base,
                                                  signedHead: signedHead.body, entries: entries, nowMs: nowMs)
            } catch {
                let e = ColophonError.wrap(error)
                guard let typed = e as? ColophonError else { throw e }
                if typed.code == "unavailable" || typed.code == "refused:rollback", attempt < Self.attempts { continue }
                throw JoinError.rejected(code: typed.code, detail: typed.detail)
            }
            guard verdict.admitted else { return .notAdmitted }
            return .admitted(AdmittedHistory(files: Dictionary(uniqueKeysWithValues: verdict.stores.map { ($0.path, $0.bytes) })))
        }
    }

    /// Every page of the history, or nil when the home refuses the read as from a non-member.
    private func readHistory() async throws -> [ByteString]? {
        let signing = try await keys.publicKeys().signing
        var entries: [ByteString] = []
        var after: UInt64 = 0
        var pages = 0
        var bytes = 0
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
            // The joining device's bounds, checked while paging (the core checks them again): spec §2.4's portability
            // floor of 256 MiB of envelopes, and 2^18 entries (4,096 pages of 64).
            bytes += page.entries.reduce(0) { $0 + $1.bytes.count }
            if bytes > historyByteLimit || entries.count + page.entries.count > Self.maxEntries {
                throw JoinError.rejected(code: "unavailable", detail: "the history passes what a joining device holds (2^18 entries, 256 MiB)")
            }
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
