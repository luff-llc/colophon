import Foundation

/// Performs the HTTP requests the engine returns for a home (`ExchangeStep.request`). The engine owns
/// every decision: this only moves bytes. Implement it to test with an in-process home.
public protocol HomeTransport: Sendable {
    func send(_ request: HttpRequest) async throws -> HttpAnswer
}

public enum HomeTransportError: Error, Equatable, Sendable {
    case offline(String)
    case invalidRequest(String)
    /// The response passed the bound for its kind of request (`HomeLimits.responseBytes(for:)`); it was refused unread.
    case responseTooLarge(limit: Int)
    /// The endpoint is not `https` (plain `http` is allowed only to a loopback address with the testing option).
    case insecureEndpoint(String)
}

/// The bounds a session holds a home to, so that a hostile or broken home cannot take memory or hold a pass.
public enum HomeLimits {
    /// The most bytes of one response, by request: the signed head 64 KiB, a blob chunk 1 MiB, a record 41 MiB (a
    /// record is at most 40 MiB, docs/bindings-05.md §5), every other answer (authority pages, the pending list, the
    /// change feed, an index) 32 MiB.
    public static func responseBytes(for url: String) -> Int {
        let path = URL(string: url)?.path ?? url
        if path.hasSuffix("/head") || path.contains("/records/heads/") { return 64 * 1024 }
        if path.contains("/records/blobs/") { return 1024 * 1024 }
        if path.contains("/records/") { return 41 * 1024 * 1024 }
        return 32 * 1024 * 1024
    }
    /// Steps (requests and calls) in one pass with one home, and passes in one exchange.
    public static let stepsPerPass = 20_000
    public static let passes = 4
    /// The longest one exchange with one home may take.
    public static let exchangeTime: Duration = .seconds(180)

    /// Whether `endpoint` may be a home: `https`, or `http` to a loopback address when `allowingLoopbackHTTP` (tests and a
    /// home on this machine during development): `localhost`, a literal `127.0.0.0/8` address (four decimal octets) or
    /// `::1`. Parsed, never matched by prefix: `127.attacker.example` is a remote host.
    public static func isAllowed(_ endpoint: URL, allowingLoopbackHTTP: Bool) -> Bool {
        guard let scheme = endpoint.scheme?.lowercased(), let host = endpoint.host?.lowercased(), !host.isEmpty else { return false }
        if scheme == "https" { return true }
        guard scheme == "http", allowingLoopbackHTTP else { return false }
        return isLoopbackLiteral(host)
    }
    static func isLoopbackLiteral(_ host: String) -> Bool {
        if host == "localhost" { return true }
        let bare = host.hasPrefix("[") && host.hasSuffix("]") ? String(host.dropFirst().dropLast()) : host
        if bare == "::1" || bare == "0:0:0:0:0:0:0:1" { return true }
        let parts = bare.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return false }
        var octets: [Int] = []
        for part in parts {
            guard (1...3).contains(part.count), part.allSatisfy({ $0 >= "0" && $0 <= "9" }), !(part.count > 1 && part.first == "0"),
                  let value = Int(part), value <= 255 else { return false }
            octets.append(value)
        }
        return octets[0] == 127
    }
}

/// `URLSession` (no cookies, no cache, no redirects: a redirect is a fault the engine reports). Only `https` URLs are
/// sent, unless `allowingLoopbackHTTP` (tests) permits plain `http` to a loopback address. A response is read as a
/// stream and refused as soon as it passes `HomeLimits.responseBytes(for:)`.
public struct URLSessionHomeTransport: HomeTransport {
    private let session: URLSession
    private let allowingLoopbackHTTP: Bool
    public init(configuration: URLSessionConfiguration = .ephemeral, allowingLoopbackHTTP: Bool = false) {
        let copy = configuration
        copy.httpCookieStorage = nil; copy.urlCache = nil; copy.requestCachePolicy = .reloadIgnoringLocalCacheData
        copy.timeoutIntervalForRequest = 60; copy.timeoutIntervalForResource = 300
        session = URLSession(configuration: copy, delegate: NoRedirects(), delegateQueue: nil)
        self.allowingLoopbackHTTP = allowingLoopbackHTTP
    }
    public func send(_ request: HttpRequest) async throws -> HttpAnswer {
        guard let url = URL(string: request.url) else { throw HomeTransportError.invalidRequest("not a URL") }
        guard HomeLimits.isAllowed(url, allowingLoopbackHTTP: allowingLoopbackHTTP) else { throw HomeTransportError.insecureEndpoint(request.url) }
        var urlRequest = URLRequest(url: url)
        urlRequest.httpMethod = switch request.method { case .get: "GET"; case .post: "POST"; case .put: "PUT" }
        for header in request.headers { urlRequest.setValue(header.value, forHTTPHeaderField: header.name) }
        if request.method != .get { urlRequest.httpBody = request.body }
        let limit = HomeLimits.responseBytes(for: request.url)
        do {
            let (bytes, response) = try await session.bytes(for: urlRequest)
            guard let http = response as? HTTPURLResponse else { throw HomeTransportError.offline("no HTTP response") }
            if http.expectedContentLength > Int64(limit) { bytes.task.cancel(); throw HomeTransportError.responseTooLarge(limit: limit) }
            var body = Data()
            body.reserveCapacity(Int(min(max(http.expectedContentLength, 0), Int64(limit))))
            for try await byte in bytes {
                guard body.count < limit else { bytes.task.cancel(); throw HomeTransportError.responseTooLarge(limit: limit) }
                body.append(byte)
            }
            let headers = http.allHeaderFields.compactMap { key, value -> Header? in
                guard let key = key as? String, let value = value as? String else { return nil }
                return Header(name: key, value: value)
            }
            return HttpAnswer(status: UInt32(http.statusCode), headers: headers, body: body)
        } catch is CancellationError { throw CancellationError() }
        catch let error as URLError { throw HomeTransportError.offline(error.localizedDescription) }
    }
    private final class NoRedirects: NSObject, URLSessionTaskDelegate, Sendable {
        func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                        newRequest request: URLRequest) async -> URLRequest? { nil }
    }
}

/// Something this host refused about a home on its own account (beside the engine's `ExchangeFault`s).
public enum HomeProblem: Error, Equatable, Sendable {
    /// The configured endpoint is not `https`; the home is not contacted.
    case insecureEndpoint(String)
    /// A response passed its bound and was refused unread.
    case responseTooLarge(limit: Int)
    /// A pass with this home took more than `HomeLimits.stepsPerPass` steps; it was stopped.
    case tooManySteps(Int)
    /// An exchange with this home took longer than `HomeLimits.exchangeTime`; it was stopped.
    case tooSlow(seconds: Int)
    /// A request needed a call this host cannot bind to its exact body, or the request the engine then produced was not
    /// the one the call was signed for. No call was sent.
    case callNotBound(String)
    /// This device's own check of the call it would send refused it, by the home's rule over what the device holds
    /// (for example it holds its own revocation, or too few homes' fresh heads). No call was sent.
    case callRefused(code: String)
    /// The engine still had a request outstanding after the pass was abandoned and run again once: the pass could not
    /// finish, and the exchange failed.
    case stillWaiting
    /// A home refused a request of this device with a `refused:<reason>` result (spec §14, §19). `code` is the result as
    /// the home gave it, validated against the result grammar and bounded (`HomeRefusal`); a name this session does not
    /// know, the reserved `refused:overQuota`, `refused:noEntitlement`, `refused:closed`, `refused:notProvisioned` and
    /// `refused:subscriptionLapsed`
    /// included, is shown as received. It refuses only that request: an unverified remote claim, never a verified state of
    /// the account (`refused:closed` is not evidence that anything was deleted, and `refused:revoked` is not proof of
    /// revocation; only verified authority records deny local reads or change custody). A refused call (401/403) ends the
    /// pass; any other refusal lets it go on. `retryAfterSeconds` is the home's `Retry-After`, honoured: the home is not
    /// contacted again before then.
    case remoteCallRefused(code: String, retryAfterSeconds: Int? = nil)
    /// The home answered `503 {"result":"unavailable"}`: the home is not available (a stopped home answers so, §13.6). It
    /// says nothing about this device or the account; the exchange is retried with backoff (and not before
    /// `retryAfterSeconds`, when the home sent `Retry-After`).
    case homeUnavailable(retryAfterSeconds: Int?)
    /// This device asked to join and holds no grant for itself, and a home (or its own check) answered `refused:revoked`
    /// for its call: in 0.5 that is the result for a member no grant names (`refused:notGranted` is reserved), so the
    /// device is waiting for approval, not revoked. A device that holds its own verified revocation is `denied`.
    case waitingForApproval
}

/// The one thing a session reads from a home's error answer: its `result`, only when it is a result the spec's §1 grammar
/// allows (`ok`, `malformed`, `badSignature`, `newerFormat`, `unavailable`, or `refused:<reason>` with a reason of a
/// lower-case letter then letters and digits, at most 48 characters), from a JSON body of at most 64 KiB. Every other byte
/// of the body is dropped, never echoed: a hostile home could put record or call bytes there. With it, `Retry-After` in
/// whole seconds (1 to 86,400).
public struct HomeRefusal: Equatable, Sendable {
    public static let named: Set<String> = ["ok", "malformed", "badSignature", "newerFormat", "unavailable"]
    public let status: UInt32
    public let code: String?
    public let retryAfterSeconds: Int?
    /// `503` with `{"result":"unavailable"}`: the home is not available.
    public var isHomeUnavailable: Bool { status == 503 && code == "unavailable" }

    /// Nil for a success, or an answer that carries neither a valid result nor a `Retry-After`.
    public init?(status: UInt32, headers: [Header], body: Data) {
        guard status >= 400 else { return nil }
        let code = Self.result(of: body)
        let retry = headers.first { $0.name.lowercased() == "retry-after" }.flatMap { Self.seconds($0.value) }
        guard code != nil || retry != nil else { return nil }
        self.status = status; self.code = code; self.retryAfterSeconds = retry
    }
    public static func isValid(_ text: String) -> Bool {
        if named.contains(text) { return true }
        guard text.hasPrefix("refused:"), text.utf8.count <= 8 + 48 else { return false }
        let reason = text.dropFirst(8)
        guard let first = reason.first, first.isASCII, first.isLowercase else { return false }
        return reason.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber) }
    }
    static func result(of body: Data) -> String? {
        guard body.count <= 64 * 1024, let object = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let result = object["result"] as? String, isValid(result) else { return nil }
        return result
    }
    static func seconds(_ text: String) -> Int? {
        let t = text.trimmingCharacters(in: .whitespaces)
        guard !t.isEmpty, t.count <= 6, t.allSatisfy({ $0.isASCII && $0.isNumber }), let n = Int(t), (1...86_400).contains(n) else { return nil }
        return n
    }
}

public struct HomeIssue: Equatable, Sendable {
    public let home: String
    public let problem: HomeProblem
}

public enum HomeSyncState: Equatable, Sendable {
    case disabled, idle, syncing
    case offline(reason: String)
    case unauthorized
    case error(reason: String)
}
/// The 0.4 name.
public typealias RelaySyncState = HomeSyncState

/// A fault a home raised that the engine did not follow, for the person (or the log) to see.
public struct HomeFault: Equatable, Sendable {
    public let home: String
    public let fault: ExchangeFault
}

/// Words a host may show for a home's state.
public enum HomeWords {
    /// `HomeProblem.homeUnavailable`: the home answered `503 {"result":"unavailable"}`.
    public static let unavailable = "The home is not available right now. This app will try again."
}
