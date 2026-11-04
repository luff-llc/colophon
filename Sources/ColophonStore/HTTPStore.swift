import ColophonCore
import Foundation

/// The HTTP storage profile (spec §5.3), for relays such as one on Cloudflare Workers and R2.
///
/// - `GET  {base}/{directory}/` → 200 with a JSON array of names, or 404.
/// - `GET  {base}/{path}` → 200 with the record's bytes, or 404.
/// - `PUT  {base}/{path}` with `If-None-Match: *` → 201 created, or 412 if it exists.
/// - `PUT  {base}/{path}` without it → 200/201; only for `requests/`.
///
/// The relay sees only signed records and ciphertext. It may refuse writes it can't verify
/// against the library's authority history; it can never forge one.
public struct HTTPStore: RemoteStore {
  public let base: URL
  public let session: URLSession
  /// Sent as `Authorization` if set. Storage access only; it grants nothing in the library.
  public let token: String?

  public init(base: URL, token: String? = nil, session: URLSession = .shared) {
    self.base = base
    self.token = token
    self.session = session
  }

  public func list(_ directory: String) async throws -> [String] {
    let (data, status) = try await send("GET", base.appending(path: directory + "/"))
    if status == 404 { return [] }
    try expect(status, [200])
    return try JSONDecoder().decode([String].self, from: data).sorted()
  }

  public func read(_ path: String) async throws -> Data? {
    let (data, status) = try await send("GET", base.appending(path: path))
    if status == 404 { return nil }
    try expect(status, [200])
    return data
  }

  public func create(_ path: String, _ data: Data) async throws -> Bool {
    let (_, status) = try await send("PUT", base.appending(path: path), body: data, ifNoneMatch: true)
    if status == 412 { return false }
    try expect(status, [200, 201])
    return true
  }

  public func replace(_ path: String, _ data: Data) async throws {
    let (_, status) = try await send("PUT", base.appending(path: path), body: data)
    try expect(status, [200, 201])
  }

  private func send(_ method: String, _ url: URL, body: Data? = nil, ifNoneMatch: Bool = false) async throws -> (Data, Int) {
    var request = URLRequest(url: url)
    request.httpMethod = method
    request.httpBody = body
    if ifNoneMatch { request.setValue("*", forHTTPHeaderField: "If-None-Match") }
    if let token { request.setValue("Bearer " + token, forHTTPHeaderField: "Authorization") }
    if body != nil { request.setValue("application/json", forHTTPHeaderField: "Content-Type") }
    let (data, response) = try await session.data(for: request)
    return (data, (response as? HTTPURLResponse)?.statusCode ?? 0)
  }

  private func expect(_ status: Int, _ allowed: Set<Int>) throws {
    guard allowed.contains(status) else { throw ColophonError.unavailable("The library relay (HTTP \(status))") }
  }
}

/// A `RemoteStore` over any local store: another folder, or memory in tests.
public struct LocalRemote: RemoteStore {
  public let store: any RecordStore
  public init(_ store: any RecordStore) { self.store = store }
  public func list(_ directory: String) async throws -> [String] { try store.list(directory) }
  public func read(_ path: String) async throws -> Data? { try store.read(path) }
  public func create(_ path: String, _ data: Data) async throws -> Bool {
    do { try store.create(path, data); return true } catch ColophonError.alreadyExists { return false }
  }
  public func replace(_ path: String, _ data: Data) async throws { try store.replace(path, data) }
}
