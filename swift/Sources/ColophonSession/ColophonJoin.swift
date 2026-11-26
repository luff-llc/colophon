import CryptoKit
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

    /// The passkey of controller `keyID` in this accepted history, when it is a current WebAuthn controller; nil for a
    /// removed, provisional, suspended or raw controller, or one the keyring does not hold. `KeyDescriptor(passkey:)`
    /// (ColophonKeys) turns it into a descriptor a passkey provider takes.
    public func ownerDescriptor(keyID: String, now: Date = Date()) throws -> OwnerPasskey? {
        let entries = files.filter { $0.key.hasPrefix("authority/") }.sorted { $0.key < $1.key }.map { ByteString(bytes: $0.value) }
        do {
            let view = try accountCurrentWebauthnController(entries: entries, id: keyID, nowMs: Int64((now.timeIntervalSince1970 * 1000).rounded()))
            return view.flatMap { OwnerPasskey(view: $0) }
        } catch { throw ColophonError.wrap(error) }
    }
}

/// A history read with a passkey before admission and accepted (`ColophonJoin.readHistoryWithPasskey` makes one only
/// after every acceptance condition held): it verified from seq 1 as the account's, holds the given entry, ends at a
/// fresh head signed by a current home serving at the base, and names the passkey that read it as a current WebAuthn
/// controller. It has no public initialiser.
public struct PasskeyHistory: Sendable {
    /// The files to store (`authority/<seq, eight digits>.json`) before a session is opened.
    public let files: [String: Data]
    /// The passkey that read the history, as the history names it: restore it as the owner controller
    /// (`KeyDescriptor(passkey:)` in ColophonKeys).
    public let signer: OwnerPasskey
    /// The same controller's ID, label, roles and whether it holds a slot of its own.
    public let signerController: PasskeyControllerView
    /// Every current WebAuthn controller at the tip, the signer included.
    public let controllers: [PasskeyControllerView]
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

    /// The joining device's bounds, checked while paging (the core checks them again): the bytes so far plus this page's
    /// within `maxBytes`, and the entries so far plus this page's within `maxEntries`. Pure; paging passes the fixed
    /// `maxHistoryBytes` and `maxEntries`. Returns the new byte total.
    static func bounded(bytes: Int, count: Int, page: [ByteString], maxBytes: Int, maxEntries: Int) throws -> Int {
        let total = bytes + page.reduce(0) { $0 + $1.bytes.count }
        guard total <= maxBytes, count + page.count <= maxEntries else {
            throw JoinError.rejected(code: "unavailable", detail: "the history passes what a joining device holds (2^18 entries, 256 MiB)")
        }
        return total
    }

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

    /// Fetch and verify the history. `.notAdmitted` while this member is not (or no longer) admitted; `JoinError` for any
    /// other refusal or a history that is not accepted; a transport failure is thrown as it came (`HomeTransportError`).
    /// A home whose signed head moved while the history was read (`unavailable`: behind; `refused:rollback`: beyond what
    /// was served) is read again, at most `attempts` times in all; a home that keeps serving less than it signed then
    /// fails with `refused:rollback`.
    public func fetchHistory() async throws -> JoinHistory {
        let request = try await request()
        let member = try await memberID()
        var attempt = 0
        while true {
            attempt += 1
            guard let entries = try await readHistory() else { return .notAdmitted }
            let signedHead = try await get("/head", authorization: nil)
            guard signedHead.status == 200 else { throw refused(signedHead) }
            let verdict: JoinedHistory
            do {
                verdict = try accountVerifyAtHead(account: account, seq: seq, head: head, member: member, request: request, base: base,
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
            bytes = try Self.bounded(bytes: bytes, count: entries.count, page: page.entries, maxBytes: Self.maxHistoryBytes, maxEntries: Self.maxEntries)
            entries += page.entries
            after += UInt64(page.entries.count)
            if !page.more { return entries }
        }
    }

    /// A recovery (Colophon 0.5.7): a device that knows only the account ID and its home's base reads the history at the
    /// genesis, `(1, account)` (the account ID is the genesis body's digest, spec 0.5 §5.1), which every history of the
    /// account holds. Use `readHistoryWithPasskey` and `approveOwnJoinWithPasskey` on it, or `recoverWithPasskey`.
    public static func recovery(configuration: SessionConfiguration, account: String, home: URL) -> ColophonJoin {
        ColophonJoin(configuration: configuration, account: account, home: home, seq: 1, head: account)
    }

    /// Recover an account onto this device with its passkey, from its home alone (Colophon 0.5.7): the history is read and
    /// verified with the passkey (`readHistoryWithPasskey` at the genesis), stored, and this device's new member is
    /// approved by the passkey and opened (`approveOwnJoinWithPasskey`). `open` makes the session with the passkey as its
    /// owner controller.
    @MainActor public static func recoverWithPasskey(configuration: SessionConfiguration, account: String, home: URL,
                                                     passkey: any PasskeyAuthenticator, ownerKeyID: String? = nil,
                                                     open: @MainActor (OwnerPasskey) async throws -> ColophonSession) async throws -> ColophonSession {
        try await recovery(configuration: configuration, account: account, home: home)
            .approveOwnJoinWithPasskey(passkey, ownerKeyID: ownerKeyID, open: open)
    }

    /// Read and verify the history with a passkey, before this device is a member (Colophon 0.5.7, spec 0.5 §12.3 and
    /// §13.4): a home serves the history to a current controller holding `approve`, `control` or `recover`. Works for an
    /// invite's head and, with `recovery(configuration:account:home:)`, for a device that knows only the account and its
    /// home.
    ///
    /// A discoverable get returns no public key, so the passkey is asked first over a challenge this device chose, and its
    /// signing point is recovered from that assertion (`ownerKeyID`, an invite's owner key ID, picks it at once; without
    /// one, the first read's assertion settles which of the two candidate points it is). Each page is then read with its
    /// own `colophon.history.read` call signed by that passkey (`asOf` the given entry), and the history is accepted only
    /// when it verifies completely, is the account's, holds the given entry, ends at the home's fresh signed head and
    /// names the passkey as a current WebAuthn controller. The person is asked once to identify the passkey and once per
    /// page of 64 entries (once more without `ownerKeyID` half of the time).
    ///
    /// Nothing is stored. A home that refuses the passkey (`403 refused:revoked`: not a current controller of this
    /// account) or a history that is not accepted throws `JoinError`; a passkey failure is thrown as the authenticator gave it.
    public func readHistoryWithPasskey(_ passkey: any PasskeyAuthenticator, ownerKeyID: String? = nil) async throws -> PasskeyHistory {
        // Identify: one get over a body this device chose, never sent anywhere.
        var body = Data(count: 32)
        let status = body.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        guard status == errSecSuccess else { throw JoinError.rejected(code: "unavailable", detail: "no randomness") }
        let first = try await passkey.get(challenge: Self.base64url(Data(SHA256.hash(data: body))), credential: nil)
        var candidates = try points(body, rp: passkey.rp, first, keyID: ownerKeyID)
        var attempt = 0
        while true {
            attempt += 1
            let (point, entries) = try await passkeyPages(passkey, credential: first.credential, candidates: candidates)
            candidates = [point]
            let signedHead = try await get("/head", authorization: nil)
            guard signedHead.status == 200 else { throw refused(signedHead) }
            let verdict: PasskeyHistoryView
            do {
                verdict = try accountVerifyWithPasskey(account: account, seq: seq, head: head, signing: point, base: base,
                                                       signedHead: signedHead.body, entries: entries, nowMs: nowMs)
            } catch {
                let e = ColophonError.wrap(error)
                guard let typed = e as? ColophonError else { throw e }
                if typed.code == "unavailable" || typed.code == "refused:rollback", attempt < Self.attempts { continue }
                throw JoinError.rejected(code: typed.code, detail: typed.detail)
            }
            guard let signer = OwnerPasskey(view: verdict.signer.key) else {
                throw JoinError.rejected(code: "malformed", detail: "the signer is not a passkey the history names")
            }
            guard verdict.signer.key.rp == passkey.rp else {
                throw JoinError.rejected(code: "badSignature", detail: "the history names the passkey under another relying party")
            }
            guard verdict.signer.key.credential == first.credential else {
                throw JoinError.rejected(code: "badSignature", detail: "the passkey's credential is not the one the history names")
            }
            return PasskeyHistory(files: Dictionary(uniqueKeysWithValues: verdict.stores.map { ($0.path, $0.bytes) }), signer: signer,
                                  signerController: verdict.signer, controllers: verdict.controllers)
        }
    }

    /// Approve this device's own request with a passkey, without another device (Colophon 0.5.7):
    /// `readHistoryWithPasskey`, then the accepted history is stored in the configuration's storage beside this device's
    /// request, `open` makes the session that holds the passkey as its owner controller (restore it from
    /// `PasskeyHistory.signer`; lock any other session open on this storage first), and that session approves its own
    /// request (`ColophonSession.approveOwnRequest(expected:)`: exactly the request this join stored, for this account; the
    /// passkey opens its own slot and signs the grant) and syncs. Returns the session, ready, once the home holds the grant
    /// (this member's own key reads the history there); otherwise `JoinError.rejected` `unavailable`, with the grant stored
    /// on this device for the session's next sync to publish.
    ///
    /// The passkey must hold `approve` or `control` and a slot of its own (a `recover`-only key proposes recovery with a
    /// delay instead, which this does not do): otherwise `JoinError.rejected` `refused:outOfScope` before anything is
    /// stored or signed.
    @MainActor public func approveOwnJoinWithPasskey(_ passkey: any PasskeyAuthenticator, ownerKeyID: String? = nil,
                                                     open: @MainActor (OwnerPasskey) async throws -> ColophonSession) async throws -> ColophonSession {
        let request = try await request()
        let member = try await memberID()
        let history = try await readHistoryWithPasskey(passkey, ownerKeyID: ownerKeyID)
        let roles = history.signerController.roles
        guard roles.contains(.approve) || roles.contains(.control) else {
            throw JoinError.rejected(code: "refused:outOfScope", detail: "the passkey holds neither approve nor control")
        }
        guard history.signerController.ownSlot else {
            throw JoinError.rejected(code: "refused:outOfScope", detail: "the passkey holds no slot of its own")
        }
        try await Self.store(history.files, request: request, member: member, medium: try configuration.location.resolve())
        let session = try await open(history.signer)
        let owner = try await KeyCustody.keyID(of: session.worker.configuration.ownerController)
        guard owner == history.signerController.id else {
            throw JoinError.rejected(code: "refused:conflict", detail: "the session's owner controller is not this passkey")
        }
        guard try await KeyCustody.keyID(of: session.worker.configuration.keys) == member else {
            throw JoinError.rejected(code: "refused:conflict", detail: "the session's member key is not this device's")
        }
        // The session must sign on exactly the history verified here: its storage holds every
        // verified entry, byte for byte, and no other authority entry.
        try await Self.holdsExactly(history.files, medium: try session.worker.configuration.location.resolve())
        await session.restore()
        guard session.libraryID == account else {
            throw JoinError.rejected(code: "refused:conflict", detail: "the session opened another account")
        }
        try await session.approveOwnRequest(expected: request)
        // Returned once the home holds the grant: this member's own key then reads the history there.
        for _ in 0..<Self.attempts {
            await session.syncNow()
            if case .admitted = try await fetchHistory() { return session }
        }
        throw JoinError.rejected(code: "unavailable",
                                 detail: "the grant is stored on this device but the home does not hold it yet; the session publishes it at its next sync")
    }

    /// The files of an accepted history, stored where they are missing; one already stored must hold the same bytes.
    private static func store(_ files: [String: Data], request: Data, member: String, medium: any RecordMedium) async throws {
        let held = Set(try medium.listing().map(\.path))
        var writes: [MediumWrite] = []
        for (path, bytes) in files.sorted(by: { $0.key < $1.key }) {
            if held.contains(path) {
                guard try medium.read(path) == bytes else { throw JoinError.rejected(code: "refused:fork", detail: "\(path) holds another entry") }
            } else { writes.append(MediumWrite(path: path, bytes: bytes)) }
        }
        let requestPath = OwnRequest.path(member)
        if !held.contains(requestPath) { writes.append(MediumWrite(path: requestPath, bytes: request)) }
        if !writes.isEmpty { try medium.write(writes) }
    }

    private static func holdsExactly(_ files: [String: Data], medium: any RecordMedium) async throws {
        let authority = Set(try medium.listing().map(\.path).filter { $0.hasPrefix("authority/") })
        let expected = Set(files.keys.filter { $0.hasPrefix("authority/") })
        guard authority == expected, try files.allSatisfy({ try medium.read($0.key) == $0.value }) else {
            throw JoinError.rejected(code: "refused:conflict", detail: "the session's storage holds another history")
        }
    }

    /// The candidate points of a passkey assertion over `body` (exactly one with `keyID`).
    private func points(_ body: Data, rp: String, _ get: PasskeyGet, keyID: String?) throws -> [Data] {
        do {
            return try accountPasskeyPoints(body: body, rp: rp, authenticatorData: get.authenticatorData, clientData: get.clientData,
                                            signature: get.signature, keyId: keyID).map(\.bytes)
        } catch {
            let e = ColophonError.wrap(error)
            throw JoinError.rejected(code: (e as? ColophonError)?.code ?? "badSignature", detail: (e as? ColophonError)?.detail ?? "")
        }
    }

    /// Every page of the history read with the passkey, and the passkey's point. With two candidates the first page's
    /// assertion, recovered again over its own body, names the one true point; a call made with the other is signed again
    /// with it (one more get), never sent.
    private func passkeyPages(_ passkey: any PasskeyAuthenticator, credential: Data, candidates: [Data]) async throws -> (Data, [ByteString]) {
        guard var point = candidates.first else { throw JoinError.rejected(code: "badSignature", detail: "no candidate point") }
        var known = candidates.count == 1
        var entries: [ByteString] = []
        var after: UInt64 = 0
        var pages = 0
        var bytes = 0
        while true {
            pages += 1
            if pages > Self.maxPages { throw JoinError.rejected(code: "malformed", detail: "the history has too many pages") }
            let path = accountHistoryPagePath(after: after)
            var call: HistoryReadCall?
            while call == nil {
                let prepared: AccountHistoryRead
                let step: AccountSigningStep
                do {
                    let created = try accountFormatDate(ms: nowMs)
                    prepared = try withEntropy(32) { id in
                        try AccountHistoryRead.preparePasskey(spec: HistoryReadSpec(account: account, asOfSeq: seq, asOfDigest: head,
                            signing: point, audience: base, path: path, requestId: Data(Array(id)), created: created))
                    }
                    step = try prepared.step()
                } catch { throw ColophonError.wrap(error) }
                guard let challenge = step.challenge else { throw JoinError.rejected(code: "malformed", detail: "a passkey read has no challenge") }
                let signed = try await passkey.get(challenge: challenge, credential: credential)
                guard signed.credential == credential else { throw JoinError.rejected(code: "badSignature", detail: "another passkey answered") }
                if !known {
                    let again = try points(step.body, rp: passkey.rp, signed, keyID: nil)
                    let truth = candidates.filter { again.contains($0) }
                    guard truth.count == 1 else { throw JoinError.rejected(code: "badSignature", detail: "the passkey's assertions name no one key") }
                    known = true
                    if truth[0] != point { point = truth[0]; continue }
                }
                do {
                    call = try prepared.finish(signature: Signature(signature: signed.signature, authenticatorData: signed.authenticatorData,
                                                                    clientData: signed.clientData))
                } catch {
                    let e = ColophonError.wrap(error)
                    throw JoinError.rejected(code: (e as? ColophonError)?.code ?? "badSignature", detail: (e as? ColophonError)?.detail ?? "")
                }
            }
            guard let call else { continue }
            let answer = try await get(path, authorization: call.authorization)
            guard answer.status == 200 else { throw refused(answer) }
            let page: HistoryPage
            do { page = try accountHistoryPage(body: answer.body) } catch {
                let e = ColophonError.wrap(error)
                throw JoinError.rejected(code: (e as? ColophonError)?.code ?? "malformed", detail: (e as? ColophonError)?.detail ?? "")
            }
            if page.more && page.entries.isEmpty { throw JoinError.rejected(code: "malformed", detail: "a history page made no progress") }
            bytes = try Self.bounded(bytes: bytes, count: entries.count, page: page.entries, maxBytes: Self.maxHistoryBytes, maxEntries: Self.maxEntries)
            entries += page.entries
            after += UInt64(page.entries.count)
            if !page.more { return (point, entries) }
        }
    }

    private static func base64url(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
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
