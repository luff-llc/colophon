import Foundation

/// Performs the HTTP requests the engine returns for a home (`ExchangeStep.request`). The engine owns
/// every decision: this only moves bytes. Implement it to test with an in-process home.
public protocol HomeTransport: Sendable {
    func send(_ request: HttpRequest) async throws -> HttpAnswer
}

public enum HomeTransportError: Error, Equatable, Sendable {
    case offline(String)
    case invalidRequest(String)
}

/// `URLSession` (no cookies, no cache, no redirects: a redirect is a fault the engine reports).
public struct URLSessionHomeTransport: HomeTransport {
    private let session: URLSession
    public init(configuration: URLSessionConfiguration = .ephemeral) {
        let copy = configuration
        copy.httpCookieStorage = nil; copy.urlCache = nil; copy.requestCachePolicy = .reloadIgnoringLocalCacheData
        session = URLSession(configuration: copy, delegate: NoRedirects(), delegateQueue: nil)
    }
    public func send(_ request: HttpRequest) async throws -> HttpAnswer {
        guard let url = URL(string: request.url), url.scheme == "https" || url.scheme == "http", url.host != nil else {
            throw HomeTransportError.invalidRequest("not an http(s) URL")
        }
        var urlRequest = URLRequest(url: url)
        urlRequest.httpMethod = switch request.method { case .get: "GET"; case .post: "POST"; case .put: "PUT" }
        for header in request.headers { urlRequest.setValue(header.value, forHTTPHeaderField: header.name) }
        if request.method != .get { urlRequest.httpBody = request.body }
        do {
            let (data, response) = try await session.data(for: urlRequest)
            guard let http = response as? HTTPURLResponse else { throw HomeTransportError.offline("no HTTP response") }
            let headers = http.allHeaderFields.compactMap { key, value -> Header? in
                guard let key = key as? String, let value = value as? String else { return nil }
                return Header(name: key, value: value)
            }
            return HttpAnswer(status: UInt32(http.statusCode), headers: headers, body: data)
        } catch is CancellationError { throw CancellationError() }
        catch let error as URLError { throw HomeTransportError.offline(error.localizedDescription) }
    }
    private final class NoRedirects: NSObject, URLSessionTaskDelegate, Sendable {
        func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                        newRequest request: URLRequest) async -> URLRequest? { nil }
    }
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
