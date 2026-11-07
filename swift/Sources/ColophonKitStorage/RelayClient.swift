import Foundation

/// A Colophon 0.3 HTTP exchange endpoint (spec §8): one library slot URL and its storage token.
/// The token grants relay storage only; it is never library membership.
public struct RelayEndpoint: Sendable, Equatable {
    public let url: URL
    public let token: String?
    public init(url: URL, token: String?) { self.url = url; self.token = token }
}

public struct RelayHTTPRequest: Sendable, Equatable {
    public var method: String
    public var url: URL
    public var headers: [String: String]
    public var body: Data?
    public var timeout: TimeInterval
}

public struct RelayHTTPResponse: Sendable, Equatable {
    public let status: Int
    /// Lowercased header names.
    public let headers: [String: String]
    public let body: Data
    public init(status: Int, headers: [String: String] = [:], body: Data = Data()) {
        self.status = status; self.headers = headers; self.body = body
    }
}

/// The HTTP seam. `URLSessionRelayTransport` is the production implementation; tests may supply
/// an in-process relay with the same contract. Throw `RelayError.offline` for transport failures.
public protocol RelayTransport: Sendable {
    func send(_ request: RelayHTTPRequest) async throws -> RelayHTTPResponse
}

public struct URLSessionRelayTransport: RelayTransport {
    private let session: URLSession
    public init() {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.urlCache = nil
        configuration.httpCookieStorage = nil
        configuration.waitsForConnectivity = false
        session = URLSession(configuration: configuration)
    }
    public func send(_ request: RelayHTTPRequest) async throws -> RelayHTTPResponse {
        var urlRequest = URLRequest(url: request.url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: request.timeout)
        urlRequest.httpMethod = request.method
        for (name, value) in request.headers { urlRequest.setValue(value, forHTTPHeaderField: name) }
        do {
            let (data, response): (Data, URLResponse)
            if let body = request.body { (data, response) = try await session.upload(for: urlRequest, from: body) }
            else { (data, response) = try await session.data(for: urlRequest) }
            guard let http = response as? HTTPURLResponse else { throw RelayError.offline("The relay did not answer over HTTP") }
            var headers: [String: String] = [:]
            for (key, value) in http.allHeaderFields {
                if let key = key as? String, let value = value as? String { headers[key.lowercased()] = value }
            }
            return RelayHTTPResponse(status: http.statusCode, headers: headers, body: data)
        } catch let error as RelayError { throw error }
        catch is CancellationError { throw CancellationError() }
        catch let error as URLError where error.code == .cancelled { throw CancellationError() }
        catch { throw RelayError.offline(error.localizedDescription) }
    }
}

public enum RelayError: Error, Equatable, Sendable {
    /// The relay could not be reached. Never evidence that a library is empty.
    case offline(String)
    /// The relay refused the storage token (401/403).
    case unauthorized
    /// The relay cannot continue the cursor (410); the client relists from the beginning.
    case cursorReset
    /// The slot holds a different library than the local store.
    case differentLibrary
    /// The relay is shedding load (429/503). `retryAfter` is in seconds when the relay said.
    case busy(retryAfter: TimeInterval?)
    /// A response that breaks the exchange contract (bad JSON, wrong digest, invalid path).
    case protocolViolation(String)
    case server(status: Int, message: String)
}

extension RelayError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .offline(let reason): "The relay is unreachable: \(reason)"
        case .unauthorized: "The relay refused this device's storage token."
        case .cursorReset: "The relay reset its change feed."
        case .differentLibrary: "The relay holds a different library than this device."
        case .busy: "The relay is busy. Sync will retry."
        case .protocolViolation(let detail): "The relay sent an invalid response: \(detail)"
        case .server(let status, let message): "The relay failed (\(status)): \(message)"
        }
    }
}

/// Typed client for the §8.2 endpoints. Holds no state beyond the endpoint.
public struct RelayClient: Sendable {
    public struct Entry: Codable, Equatable, Sendable {
        public let path: String
        public let size: Int?
        public let sha256: String?
        public let deleted: Bool?
    }
    public struct ChangePage: Codable, Equatable, Sendable {
        public let entries: [Entry]
        public let cursor: String
        public let more: Bool
    }
    public enum PutResult: Equatable, Sendable { case created, present, conflict }

    public let endpoint: RelayEndpoint
    let transport: any RelayTransport
    public init(endpoint: RelayEndpoint, transport: any RelayTransport = URLSessionRelayTransport()) {
        self.endpoint = endpoint; self.transport = transport
    }

    private var base: String {
        var value = endpoint.url.absoluteString
        while value.hasSuffix("/") { value.removeLast() }
        return value
    }
    private func request(_ method: String, _ suffix: String, body: Data? = nil, headers: [String: String] = [:], timeout: TimeInterval = 30) throws -> RelayHTTPRequest {
        guard let url = URL(string: base + suffix) else { throw RelayError.protocolViolation("Invalid relay URL") }
        var all = headers
        if let token = endpoint.token { all["Authorization"] = "Bearer " + token }
        return RelayHTTPRequest(method: method, url: url, headers: all, body: body, timeout: timeout)
    }
    private func check(_ response: RelayHTTPResponse, allowing allowed: Set<Int>) throws {
        if allowed.contains(response.status) { return }
        switch response.status {
        case 401, 403: throw RelayError.unauthorized
        case 410: throw RelayError.cursorReset
        case 429, 503: throw RelayError.busy(retryAfter: response.headers["retry-after"].flatMap(TimeInterval.init))
        default:
            let message = (try? JSONDecoder().decode([String: String].self, from: response.body))?["error"] ?? ""
            throw RelayError.server(status: response.status, message: message)
        }
    }

    /// `GET {base}`: proves the slot and token are accepted.
    public func info() async throws -> Data {
        let response = try await transport.send(request("GET", ""))
        try check(response, allowing: [200]); return response.body
    }

    public func changes(after cursor: String?, limit: Int = 500, wait: Int = 0, namespaces: [String] = []) async throws -> ChangePage {
        var query = "?limit=\(limit)"
        if let cursor, !cursor.isEmpty {
            guard let escaped = cursor.addingPercentEncoding(withAllowedCharacters: .alphanumerics.union(CharacterSet(charactersIn: "-._~"))) else {
                throw RelayError.protocolViolation("Invalid cursor")
            }
            query += "&after=" + escaped
        }
        if wait > 0 { query += "&wait=\(wait)" }
        for namespace in namespaces {
            guard let escaped = namespace.addingPercentEncoding(withAllowedCharacters: .alphanumerics.union(CharacterSet(charactersIn: "-._~"))) else {
                throw RelayError.protocolViolation("Invalid namespace")
            }
            query += "&namespace=" + escaped
        }
        let response = try await transport.send(request("GET", "/changes" + query, timeout: TimeInterval(wait + 30)))
        try check(response, allowing: [200])
        do { return try JSONDecoder().decode(ChangePage.self, from: response.body) }
        catch { throw RelayError.protocolViolation("Unreadable change page") }
    }

    /// Exact stored bytes, or nil when the relay has no record at `path`.
    public func get(_ path: String, maximumBytes: Int = 16 * 1024 * 1024) async throws -> Data? {
        let response = try await transport.send(request("GET", "/records/" + path))
        if response.status == 404 { return nil }
        try check(response, allowing: [200])
        guard response.body.count <= maximumBytes else { throw RelayError.protocolViolation("Oversized record") }
        return response.body
    }

    public func putIfAbsent(_ path: String, bytes: Data, replacing digest: String? = nil) async throws -> PutResult {
        var headers = ["Content-Type": "application/octet-stream"]
        if let digest { headers["If-Match"] = "\"" + digest + "\"" } else { headers["If-None-Match"] = "*" }
        let response = try await transport.send(request("PUT", "/records/" + path, body: bytes,
            headers: headers, timeout: 60))
        switch response.status {
        case 201: return .created
        case 200: return .present
        case 412: return .conflict
        default: try check(response, allowing: []); return .conflict
        }
    }
}
