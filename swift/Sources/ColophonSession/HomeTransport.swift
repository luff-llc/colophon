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

    /// Whether `endpoint` may be a home: `https`, or `http` to `localhost`, `127.0.0.0/8` or `::1` when
    /// `allowingLoopbackHTTP` (tests and a home on this machine during development).
    public static func isAllowed(_ endpoint: URL, allowingLoopbackHTTP: Bool) -> Bool {
        guard let scheme = endpoint.scheme?.lowercased(), let host = endpoint.host?.lowercased(), !host.isEmpty else { return false }
        if scheme == "https" { return true }
        guard scheme == "http", allowingLoopbackHTTP else { return false }
        return host == "localhost" || host.hasSuffix(".localhost") || host == "::1" || host == "[::1]" || host.hasPrefix("127.")
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
