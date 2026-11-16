import CryptoKit
import Foundation
import ColophonSession

/// An in-process home, for unit tests that need a home the test controls: one that is offline, answers past its bound,
/// is not `https`, offers (or does not offer) delivery-route registration, or never receipts so a change goes dead.
/// It is NOT the home the SDK is proven against: two devices syncing through a home that requires calls run against the
/// real relay (`RelayHome`, `RelayJourneyTests`). Its admission is partial: `POST /authority` is checked with
/// `accountVerifyHistory`; it receipts transitions and vetoes posted to `/pending` and signs heads with its own key; with
/// `requireCalls` it checks a call's shape, audience, purpose, args, replay, signature and membership. It has none of the
/// relay's replay shares, rate limits, links, controller calls or per-namespace write grants.
final class SimHome: HomeTransport, @unchecked Sendable {
    let key = P256.Signing.PrivateKey()
    let agreement = P256.KeyAgreement.PrivateKey()
    let base: String
    private let lock = NSLock()
    private var account: String?
    private var entries: [UInt64: Data] = [:]
    private(set) var files: [String: Data] = [:]
    private var log: [String] = []
    private(set) var requestLog: [String] = []
    private(set) var pendingObjects: [Data] = []
    private var pendingList: [[String: Any]] = []
    var online = true
    /// Answers a request instead of the home when it returns an answer (a refusal, a 503, a `Retry-After`).
    var answer: (@Sendable (HttpRequest) -> HttpAnswer?)?
    /// Whether reading records and the change feed needs a call.
    var requireCalls = false
    /// Every call that was refused, with its reason, and every call accepted.
    private(set) var refusedCalls: [String] = []
    private(set) var acceptedCalls = 0
    private var seenRequests: Set<String> = []
    private var membersCache: (count: Int, members: [String: Bool])?
    var now: @Sendable () -> Int64 = { Int64(Date().timeIntervalSince1970 * 1000) }

    init(base: String = "https://home.example") { self.base = base }
    var id: String { (try? accountKeyId(signing: key.publicKey.x963Representation)) ?? "" }

    /// The home's own member request (§9.1) for the account to appoint it.
    func memberRequest(account: String, createdMs: Int64) throws -> Data {
        let terms = "{\"serves\":[\"home\"]}"
        let spec = RequestSpec(account: account, signing: key.publicKey.x963Representation, agreement: agreement.publicKey.x963Representation,
            label: "Home", kind: .server, termsJson: terms, created: try accountFormatDate(ms: createdMs), custody: nil, operator: nil, endpoints: [base + "/"])
        let request = try AccountRequest.prepare(spec: spec)
        let step = try request.step()
        let signature = try key.signature(for: step.body).rawRepresentation
        return try request.finish(signature: Signature(signature: signature, authenticatorData: nil, clientData: nil)).raw
    }
    func setAccount(_ id: String) { lock.withLock { account = id } }
    func holds(prefix: String) -> [String] { lock.withLock { files.keys.filter { $0.hasPrefix(prefix) }.sorted() } }
    var entryCount: Int { lock.withLock { entries.count } }

    private static func canonical(_ value: Any) -> Data {
        (try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .withoutEscapingSlashes, .fragmentsAllowed])) ?? Data()
    }
    private static func hex(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
    private func entrySeq(_ bytes: Data) -> UInt64? {
        guard let object = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any], let body = object["body"] as? String,
              let decoded = Data(base64Encoded: body), let inner = try? JSONSerialization.jsonObject(with: decoded) as? [String: Any] else { return nil }
        if account == nil, let a = inner["account"] as? String { account = a }
        return (inner["seq"] as? NSNumber)?.uint64Value
    }
    private func headEnvelope() -> Data? {
        guard let seq = entries.keys.max(), let entry = entries[seq], let account,
              let object = try? JSONSerialization.jsonObject(with: entry) as? [String: Any], let body = object["body"] as? String,
              let decoded = Data(base64Encoded: body) else { return nil }
        let head: [String: Any] = ["protocol": "colophon/head/5", "account": account, "authority": ["seq": seq, "digest": Self.hex(decoded)],
                                   "by": id, "issued": (try? accountFormatDate(ms: now())) ?? ""]
        let headBody = Self.canonical(head)
        guard let signature = try? key.signature(for: headBody).rawRepresentation else { return nil }
        return Self.canonical(["body": headBody.base64EncodedString(), "signature": signature.base64EncodedString()])
    }
    private func response(_ status: Int, _ value: Any = [String: Any]()) -> HttpAnswer {
        HttpAnswer(status: UInt32(status), headers: [], body: Self.canonical(value))
    }
    private func query(_ text: Substring, _ name: String) -> String? {
        text.split(separator: "&").compactMap { pair -> String? in
            let parts = pair.split(separator: "=", maxSplits: 1)
            return parts.count == 2 && parts[0] == name ? String(parts[1]) : nil
        }.first
    }

    func send(_ request: HttpRequest) async throws -> HttpAnswer {
        try lock.withLock {
            guard online else { throw HomeTransportError.offline("the home is offline") }
            if let answer, let given = answer(request) { requestLog.append("ANSWERED \(request.url)"); return given }
            guard request.url.hasPrefix(base) else { return response(404) }
            let rest = String(request.url.dropFirst(base.count))
            let parts = rest.split(separator: "?", maxSplits: 1, omittingEmptySubsequences: false)
            let path = String(parts[0]); let queryText = parts.count > 1 ? parts[1] : ""
            let method = switch request.method { case .get: "GET"; case .post: "POST"; case .put: "PUT" }
            requestLog.append("\(method) \(path)")
            func header(_ name: String) -> String? { request.headers.first { $0.name.lowercased() == name.lowercased() }?.value }
            // Records, blob chunks and the change feed always need a call (§13.4). The history is served as under
            // `policy.history: public`: under `members` the engine's first pass asks for `/authority` before `/head`, and
            // `begin_call` needs a fresh head, so no call can be built (a core ordering gap, reported in the PR).
            // Writes take a call when one is sent and are otherwise admitted: the core's `begin_call` refuses a member's
            // `colophon.home.write` whose terms do not grant it (§12.3 step 7), although §14 lets any member write paths
            // under its own author ID, so the host cannot sign one yet (a core gap, reported in the PR).
            let isWrite = method != "GET"
            let needsCall = (path.hasPrefix("/records/") && !path.hasPrefix("/records/heads/") || path == "/changes")
                && (!isWrite || header("Authorization") != nil)
            if requireCalls, needsCall, account != nil {
                if let refusal = admitCall(header("Authorization"), method: method, path: rest, body: request.body) { return refusal }
            }
            switch (method, path) {
            case ("GET", "/head"):
                guard let head = headEnvelope() else { return response(404) }
                return HttpAnswer(status: 200, headers: [], body: head)
            case ("GET", "/authority"):
                let after = UInt64(query(queryText, "after") ?? "0") ?? 0
                let limit = min(64, Int(query(queryText, "limit") ?? "64") ?? 64)
                let all = entries.keys.sorted().filter { $0 > after }
                let page = all.prefix(limit).compactMap { entries[$0] }.compactMap { try? JSONSerialization.jsonObject(with: $0) }
                return response(200, ["entries": page, "receipts": [Any](), "more": all.count > limit])
            case ("POST", "/authority"):
                guard let object = try? JSONSerialization.jsonObject(with: request.body) as? [String: Any], let incoming = object["entries"] as? [Any] else { return response(422) }
                // Admission: the history these entries extend must verify.
                var proposed = entries
                for entry in incoming {
                    let bytes = Self.canonical(entry)
                    guard let seq = entrySeq(bytes) else { return response(422, ["result": "malformed"]) }
                    if proposed[seq] == nil { proposed[seq] = bytes }
                }
                let ordered = proposed.keys.sorted().compactMap { proposed[$0] }.map { ByteString(bytes: $0) }
                if let report = try? accountVerifyHistory(objects: AuthorityObjects(entries: ordered, pending: [], heads: [], predecessor: []), nowMs: now()),
                   report.account == nil {
                    return response(422, ["result": report.code])
                }
                for entry in incoming {
                    let bytes = Self.canonical(entry)
                    guard let seq = entrySeq(bytes) else { return response(422, ["result": "malformed"]) }
                    if let existing = entries[seq], existing != bytes {
                        return HttpAnswer(status: 409, headers: [], body: headEnvelope() ?? Self.canonical([String: Any]()))
                    }
                    if entries[seq] == nil { entries[seq] = bytes; store("authority/" + String(format: "%08llu", seq) + ".json", bytes) }
                }
                let head = headEnvelope().flatMap { try? JSONSerialization.jsonObject(with: $0) } ?? NSNull()
                return response(200, ["head": head, "receipts": [Any]()])
            case ("GET", "/pending"):
                let after = Int(query(queryText, "after") ?? "0") ?? 0
                let page = pendingList.filter { ($0["seq"] as? Int ?? 0) > after }
                return response(200, ["objects": page, "more": false])
            case ("POST", "/pending"):
                var receipts: [Any] = []
                if let object = try? JSONSerialization.jsonObject(with: request.body) as? [String: Any], let objects = object["objects"] as? [Any] {
                    for item in objects {
                        pendingObjects.append(Self.canonical(item))
                        guard let envelope = item as? [String: Any], let text = envelope["body"] as? String, let body = Data(base64Encoded: text),
                              let inner = try? JSONSerialization.jsonObject(with: body) as? [String: Any], let account,
                              let proto = inner["protocol"] as? String, proto.hasSuffix("/transition/5") || proto.hasSuffix("/veto/5") else { continue }
                        let digest = Self.hex(body)
                        let issuedMs = Self.parseDate((inner["issued"] as? String) ?? "") ?? now()
                        let receiptBody = Self.canonical(["protocol": "colophon/receipt/5", "account": account, "object": digest,
                                                          "received": (try? accountFormatDate(ms: max(now(), issuedMs))) ?? "", "by": id])
                        guard let signature = try? key.signature(for: receiptBody).rawRepresentation else { continue }
                        let receipt: [String: Any] = ["body": receiptBody.base64EncodedString(), "signature": signature.base64EncodedString()]
                        receipts.append(receipt)
                        let kind = proto.hasSuffix("/veto/5") ? "veto" : "transition"
                        pendingList.append(["seq": pendingList.count + 1, "digest": digest, "kind": kind, "envelope": item])
                        pendingList.append(["seq": pendingList.count + 1, "digest": digest, "kind": "receipt", "envelope": receipt])
                    }
                }
                return response(200, ["receipts": receipts])
            case ("GET", "/changes"):
                let after = Int(query(queryText, "after") ?? "0") ?? 0
                let limit = min(500, Int(query(queryText, "limit") ?? "500") ?? 500)
                if after > log.count { return response(410) }
                let slice = log[after...]
                let page = slice.prefix(limit).map { ["path": $0, "size": files[$0]?.count ?? 0, "sha256": Self.hex(files[$0] ?? Data())] as [String: Any] }
                return response(200, ["entries": page, "cursor": String(after + page.count), "more": slice.count > limit])
            default:
                guard path.hasPrefix("/records/") else { return response(404) }
                let record = String(path.dropFirst("/records/".count))
                if method == "GET" { return files[record].map { HttpAnswer(status: 200, headers: [], body: $0) } ?? response(404) }
                guard method == "PUT" else { return response(404) }
                if record.hasPrefix("blobs/"), Self.hex(request.body) != String(record.dropFirst(6)) { return response(400) }
                let live = record.hasPrefix("state/")
                switch (files[record], header("If-None-Match"), header("If-Match")) {
                case (nil, .some, nil): store(record, request.body); return response(201)
                case (.some(let old), .some, nil) where !live: return old == request.body ? response(200) : response(412)
                case (.some(let old), nil, .some(let match)) where live:
                    if "\"\(Self.hex(old))\"" == match { store(record, request.body); return response(200) }
                    return response(412)
                case (.some(let old), .some, nil) where live: return old == request.body ? response(200) : response(412)
                default: return response(428)
                }
            }
        }
    }
    /// The §12.3 checks a home makes of a call for this request (nil: admitted).
    private func admitCall(_ authorization: String?, method: String, path: String, body: Data) -> HttpAnswer? {
        func refuse(_ result: String) -> HttpAnswer { refusedCalls.append(result); return response(403, ["result": result]) }
        guard let authorization, authorization.hasPrefix("Colophon ") else {
            return HttpAnswer(status: 401, headers: [Header(name: "WWW-Authenticate", value: "Colophon")], body: Data())
        }
        let encoded = String(authorization.dropFirst("Colophon ".count))
        guard let raw = Self.base64url(encoded), let envelope = try? JSONSerialization.jsonObject(with: raw) as? [String: Any],
              let bodyText = envelope["body"] as? String, let callBody = Data(base64Encoded: bodyText),
              let signatureText = envelope["signature"] as? String, let signature = Data(base64Encoded: signatureText),
              let call = try? JSONSerialization.jsonObject(with: callBody) as? [String: Any] else { return refuse("malformed") }
        guard call["protocol"] as? String == "colophon/call/5", call["account"] as? String == account else { return refuse("malformed") }
        guard (call["audience"] as? String).map({ $0.hasSuffix("/") ? String($0.dropLast()) : $0 }) == base else { return refuse("refused:audience") }
        guard call["purpose"] as? String == (method == "GET" ? "colophon.home.read" : "colophon.home.write") else { return refuse("refused:outOfScope") }
        guard let args = call["args"] as? [String: Any], args.count == 3, args["method"] as? String == method, args["path"] as? String == path,
              args["body"] as? String == Self.hex(body) else { return refuse("refused:outOfScope") }
        guard let requestID = call["requestId"] as? String, !seenRequests.contains(requestID) else { return refuse("refused:replay") }
        guard let keyText = call["key"] as? String, let key = Data(base64Encoded: keyText),
              let signer = (call["signer"] as? [String: Any])?["member"] as? String,
              (try? accountKeyId(signing: key)) == signer else { return refuse("badSignature") }
        guard let publicKey = try? P256.Signing.PublicKey(x963Representation: key),
              let ecdsa = try? P256.Signing.ECDSASignature(rawRepresentation: signature),
              publicKey.isValidSignature(ecdsa, for: callBody) else { return refuse("badSignature") }
        guard members()[signer] == true else { return refuse("refused:revoked") }
        seenRequests.insert(requestID)
        acceptedCalls += 1
        return nil
    }

    /// Current members of the history this home holds (ID to "not revoked"), read by an engine opened over its files.
    private func members() -> [String: Bool] {
        if let cache = membersCache, cache.count == entries.count { return cache.members }
        guard let account else { return [:] }
        var held: [String: Data] = [:]
        for (seq, bytes) in entries { held["authority/" + String(format: "%08llu", seq) + ".json"] = bytes }
        let source = HeldSource(files: held)
        let listing = held.keys.sorted().map { ListedPath(path: $0, version: nil) }
        guard let engine = try? withEntropy(32, { key in
            try AccountEngine.open(source: source, listing: listing, identity: AccountIdentity(kind: .member, id: id), account: account,
                                   namespaces: [], batch: 0, saved: SavedState(verifier: Data(), checkpoint: Data(), parts: []), key: key, nowMs: now())
        }), let list = try? engine.members() else { return [:] }
        let result = Dictionary(list.map { ($0.id, $0.revokedAt == nil) }, uniquingKeysWith: { $1 })
        membersCache = (entries.count, result)
        return result
    }
    private static func base64url(_ text: String) -> Data? {
        var base = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        base += String(repeating: "=", count: (4 - base.count % 4) % 4)
        return Data(base64Encoded: base)
    }

    private static func parseDate(_ text: String) -> Int64? {
        let plain = ISO8601DateFormatter(); let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return (plain.date(from: text) ?? fractional.date(from: text)).map { Int64($0.timeIntervalSince1970 * 1000) }
    }
    private func store(_ path: String, _ bytes: Data) { files[path] = bytes; log.append(path) }
}

/// The home's own files as a record source for its engine.
private final class HeldSource: HostSource, @unchecked Sendable {
    let files: [String: Data]
    init(files: [String: Data]) { self.files = files }
    func read(path: String) throws -> Data {
        guard let bytes = files[path] else { throw StorageError.unavailable("Missing record: " + path) }
        return bytes
    }
    func readBlob(path: String) throws -> Data { Data() }
}
