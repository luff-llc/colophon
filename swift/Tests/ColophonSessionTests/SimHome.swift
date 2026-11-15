import CryptoKit
import Foundation
import ColophonSession

/// An in-process home: the HTTP surface the engine's exchange speaks (head, authority, pending, change feed,
/// records), driven by the requests the engine emits, as `crates/colophon-ffi/tests/v05_support` does in Rust.
///
/// What it is not: it does no admission checking (the Rust double runs the core's home rules; the core's home
/// logic is not exported to Swift), and it issues no receipts. It signs heads with its own key. When the relay
/// grows into a home (a separate package) a real one replaces this double: swap `SimHome` for a transport that
/// speaks to it. The engine on the other side verifies everything it is told, so a dishonest double could not
/// make a verifier accept a bad history; it can only fail to be a faithful home.
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
            guard request.url.hasPrefix(base) else { return response(404) }
            let rest = String(request.url.dropFirst(base.count))
            let parts = rest.split(separator: "?", maxSplits: 1, omittingEmptySubsequences: false)
            let path = String(parts[0]); let queryText = parts.count > 1 ? parts[1] : ""
            let method = switch request.method { case .get: "GET"; case .post: "POST"; case .put: "PUT" }
            requestLog.append("\(method) \(path)")
            func header(_ name: String) -> String? { request.headers.first { $0.name.lowercased() == name.lowercased() }?.value }
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
    private static func parseDate(_ text: String) -> Int64? {
        let plain = ISO8601DateFormatter(); let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return (plain.date(from: text) ?? fractional.date(from: text)).map { Int64($0.timeIntervalSince1970 * 1000) }
    }
    private func store(_ path: String, _ bytes: Data) { files[path] = bytes; log.append(path) }
}
