import ColophonSession
import Foundation
import Synchronization

/// What this device last heard from its home, as the transport saw it. The engine verifies everything; this is only
/// what the status screen shows (the head's seq and time are read from the head's body without verifying it).
struct HomeSighting: Sendable, Equatable {
    struct Head: Sendable, Equatable { var seq: UInt64; var issued: String; var at: Date }
    struct Answer: Sendable, Equatable {
        var method: String; var path: String; var status: UInt32; var detail: String; var at: Date
    }
    var head: Head?
    var last: Answer?
    var lastRefusal: Answer?
    var transportError: String?
    var requests = 0
}

final class HomeObserver: Sendable {
    private let state = Mutex(HomeSighting())
    func snapshot() -> HomeSighting { state.withLock { $0 } }
    func reset() { state.withLock { $0 = HomeSighting() } }

    fileprivate func record(method: String, path: String, answer: HttpAnswer) {
        let detail = answer.status >= 400 ? (ResultCode.of(body: answer.body) ?? "no result") : ""
        let seen = HomeSighting.Answer(method: method, path: path, status: answer.status, detail: detail, at: .now)
        let head = (path.hasSuffix("/head") || path.contains("/records/heads/")) && answer.status == 200 ? Self.head(answer.body) : nil
        state.withLock { s in
            s.requests += 1; s.last = seen; s.transportError = nil
            // A 401 asks for a call (the session then sends one); it is not a refusal.
            if answer.status >= 400, answer.status != 401 { s.lastRefusal = seen }
            if let head { s.head = head }
        }
    }
    fileprivate func record(error: Error) { state.withLock { $0.transportError = "\(error)" } }

    /// A head's `issued` as a plain UTC date, or "-": nothing else from a response body is kept.
    static func plainDate(_ value: Any?) -> String {
        guard let text = value as? String, text.count <= 30,
              text.range(of: #"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z$"#, options: .regularExpression) != nil else { return "-" }
        return text
    }
    /// A signed head is an envelope whose `body` is base64 JSON with `seq` and `issued`.
    private static func head(_ data: Data) -> HomeSighting.Head? {
        guard let envelope = try? JSONSerialization.jsonObject(with: data) as? [String: Any], let text = envelope["body"] as? String else { return nil }
        var b64 = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while b64.count % 4 != 0 { b64 += "=" }
        guard let bytes = Data(base64Encoded: b64), let body = try? JSONSerialization.jsonObject(with: bytes) else { return nil }
        func find(_ key: String, in value: Any) -> Any? {
            if let object = value as? [String: Any] {
                if let hit = object[key] { return hit }
                for child in object.values { if let hit = find(key, in: child) { return hit } }
            }
            return nil
        }
        guard let seq = (find("seq", in: body) as? NSNumber)?.uint64Value else { return nil }
        return .init(seq: seq, issued: plainDate(find("issued", in: body)), at: .now)
    }
}

/// The session's transport to the home. When `reachPrefix` is set, a URL that starts with the account's home prefix (the
/// `https` name the account appoints) is sent to the same path under `reachPrefix` instead: a relay on this Mac's
/// loopback during development. Plain `http` is allowed to a loopback address only (the SDK's rule). Every answer is
/// shown to `observer`.
struct MappedTransport: HomeTransport {
    let homePrefix: String
    let reachPrefix: String
    let observer: HomeObserver
    private let inner: any HomeTransport

    /// `inner` is for tests; by default `URLSessionHomeTransport`, allowing loopback `http` only when `reachPrefix` is set.
    init(homePrefix: String, reachPrefix: String, observer: HomeObserver, inner: (any HomeTransport)? = nil) {
        self.homePrefix = homePrefix.hasSuffix("/") ? homePrefix : homePrefix + "/"
        self.reachPrefix = reachPrefix.isEmpty || reachPrefix.hasSuffix("/") ? reachPrefix : reachPrefix + "/"
        self.observer = observer
        self.inner = inner ?? URLSessionHomeTransport(allowingLoopbackHTTP: !reachPrefix.isEmpty)
    }

    func send(_ request: HttpRequest) async throws -> HttpAnswer {
        var url = request.url
        if !reachPrefix.isEmpty {
            guard url.hasPrefix(homePrefix) else { throw HomeTransportError.invalidRequest("not under the home prefix: \(url)") }
            url = reachPrefix + url.dropFirst(homePrefix.count)
        }
        let method = switch request.method { case .get: "GET"; case .post: "POST"; case .put: "PUT" }
        let path = URL(string: request.url)?.path ?? request.url
        do {
            let answer = try await inner.send(HttpRequest(ticket: request.ticket, home: request.home, method: request.method, url: url,
                                                          headers: request.headers, body: request.body))
            observer.record(method: method, path: path, answer: answer)
            return answer
        } catch {
            observer.record(error: error)
            throw error
        }
    }
}

/// Asks the home service for the home's signed member request for a new account (it provisions the slot first).
enum Provisioner {
    struct Failure: LocalizedError { let text: String; var errorDescription: String? { text } }

    static func memberRequest(service: String, token: String, slot: String, base: String, account: String) async throws -> Data {
        guard let url = URL(string: service), url.scheme == "https" || HomeLimits.isAllowed(url, allowingLoopbackHTTP: true) else {
            throw Failure(text: "The home service URL must be https, or http on this device's loopback: \(service)")
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if !token.isEmpty { request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization") }
        request.httpBody = try JSONSerialization.data(withJSONObject: ["slot": slot, "base": base, "account": account])
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 30
        let (data, response) = try await URLSession(configuration: configuration).data(for: request)
        guard let http = response as? HTTPURLResponse else { throw Failure(text: "The home service gave no HTTP answer") }
        guard http.statusCode == 200 else {
            throw Failure(text: "The home service answered \(http.statusCode)")
        }
        return data
    }
}

/// The one thing from a refusal body the app shows or logs: its `result`, and only when it is a result the spec's §1
/// grammar allows (`ok`, `malformed`, `badSignature`, `newerFormat`, `unavailable`, `refused:<reason>` with a short
/// alphanumeric reason). Anything else, and every other byte of the body, is dropped: a hostile home could put record
/// or call bytes there.
enum ResultCode {
    static let named: Set<String> = ["ok", "malformed", "badSignature", "newerFormat", "unavailable"]
    static func isValid(_ text: String) -> Bool {
        if named.contains(text) { return true }
        guard text.hasPrefix("refused:"), text.count <= 8 + 48 else { return false }
        let reason = text.dropFirst(8)
        guard let first = reason.first, first.isASCII, first.isLowercase else { return false }
        return reason.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber) }
    }
    static func of(body: Data) -> String? {
        guard body.count <= 64 * 1024, let object = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let result = object["result"] as? String, isValid(result) else { return nil }
        return result
    }
}
