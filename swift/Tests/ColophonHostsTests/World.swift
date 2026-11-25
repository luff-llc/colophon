import CryptoKit
import Foundation
import os
import Testing
@testable import ColophonHosts
import ColophonSession

// The end-to-end world: a real home (relay/server.js on Bun with the Rust home module), an account with two members A
// and B entitled to write `listening.podcasts`, each with its own `ColophonSession`, a `HomeStreamHost` over a real
// WebSocket (`URLSessionWebSocketTask`) and a `now-playing` cell. A's network can be cut and restored
// (js/test06/world.ts).

/// Milliseconds on a monotonic clock, with sub-millisecond precision, for measuring.
func nowMs() -> Double { Double(DispatchTime.now().uptimeNanoseconds) / 1_000_000 }

/// The real relay on loopback, with its explicit test clock kept moving, one slot for the account. It needs Bun and the
/// home module (`COLOPHON_HOME_WASM`, built from this tree by `scripts/test-swift-hosts.sh`): without them it throws,
/// and the test fails; it never passes by skipping.
final class Relay: Sendable {
    struct Missing: Error, CustomStringConvertible { let description: String }
    let base: String
    let port: Int
    private let key = P256.Signing.PrivateKey()
    private let agreement = P256.KeyAgreement.PrivateKey()
    private let dir: URL
    private let process = OSAllocatedUnfairLock<Process?>(initialState: nil)
    private let ticker = OSAllocatedUnfairLock<Task<Void, Never>?>(initialState: nil)

    init(base: String) {
        self.base = base
        port = Self.freePort()
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("colophon-swift-hosts-relay-\(UUID().uuidString)")
    }
    deinit { stop() }

    static var repository: URL { URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent() }
    static func bun() throws -> URL {
        let env = ProcessInfo.processInfo.environment
        var candidates = (env["PATH"] ?? "").split(separator: ":").map { URL(fileURLWithPath: String($0)).appendingPathComponent("bun") }
        candidates += [URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent(".bun/bin/bun"), URL(fileURLWithPath: "/opt/homebrew/bin/bun")]
        if let path = env["COLOPHON_BUN"] { candidates.insert(URL(fileURLWithPath: path), at: 0) }
        guard let bun = candidates.first(where: { FileManager.default.isExecutableFile(atPath: $0.path) }) else { throw Missing(description: "bun (set COLOPHON_BUN)") }
        return bun
    }
    static func module() throws -> URL {
        guard let path = ProcessInfo.processInfo.environment["COLOPHON_HOME_WASM"], FileManager.default.fileExists(atPath: path) else {
            throw Missing(description: "the home module built from this tree (set COLOPHON_HOME_WASM)")
        }
        return URL(fileURLWithPath: path)
    }
    static func freePort() -> Int {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        defer { close(fd) }
        var addr = sockaddr_in(); addr.sin_family = sa_family_t(AF_INET); addr.sin_port = 0; addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, len) } }
        _ = withUnsafeMutablePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) } }
        return Int(UInt16(bigEndian: addr.sin_port))
    }
    /// Where the account's `https` name is served on loopback.
    var local: String { "127.0.0.1:\(port)/v1/libraries/home" }
    private var clockFile: URL { dir.appendingPathComponent("clock") }
    func touch() { try? String(Int64(Date().timeIntervalSince1970 * 1000)).write(to: clockFile, atomically: true, encoding: .utf8) }

    private var jwk: String {
        let point = key.publicKey.x963Representation
        return #"{"kty":"EC","crv":"P-256","x":"\#(Base64.url(point[1..<33]))","y":"\#(Base64.url(point[33..<65]))","d":"\#(Base64.url(key.rawRepresentation))"}"#
    }
    /// Starts the relay for `account`, its clock kept moving so its rate buckets refill and its timers run.
    func start(account: String) throws {
        let bun = try Self.bun(), module = try Self.module()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        touch()
        let config = dir.appendingPathComponent("config.json")
        try Data(#"{"resolve":{}}"#.utf8).write(to: config)
        let p = Process()
        p.executableURL = bun
        p.arguments = [Self.repository.appendingPathComponent("relay/server.js").path, "--test-clock", "--config", config.path]
        var env = ProcessInfo.processInfo.environment
        env["COLOPHON_RELAY_PORT"] = String(port)
        env["COLOPHON_RELAY_DATA"] = dir.appendingPathComponent("data").path
        env["COLOPHON_RELAY_HOME_SLOTS"] = "home=\(account)@\(base)"
        env["COLOPHON_HOME_KEY"] = jwk
        env["COLOPHON_HOME_WASM"] = module.path
        env["COLOPHON_RELAY_CLOCK_FILE"] = clockFile.path
        env["COLOPHON_RELAY_TICK_MS"] = "50"
        p.environment = env
        let out = Pipe()
        p.standardOutput = out
        p.standardInput = Pipe()
        p.standardError = FileHandle.nullDevice
        try p.run()
        process.withLock { $0 = p }
        var line = Data()
        while !line.contains(0x0a) {
            let chunk = out.fileHandleForReading.availableData
            if chunk.isEmpty { throw Missing(description: "the relay did not start: \(String(decoding: line, as: UTF8.self))") }
            line.append(chunk)
        }
        guard String(decoding: line, as: UTF8.self).contains("\"listening\"") else { throw Missing(description: "the relay did not start") }
        let ticking = Task { [weak self] in
            while !Task.isCancelled { self?.touch(); try? await Task.sleep(for: .milliseconds(20)) }
        }
        ticker.withLock { $0 = ticking }
    }
    func stop() {
        ticker.withLock { $0?.cancel(); $0 = nil }
        if let p = process.withLock({ p -> Process? in let v = p; p = nil; return v }), p.isRunning { p.terminate(); p.waitUntilExit() }
        try? FileManager.default.removeItem(at: dir)
    }
    /// The home's signed member request (§9.1) naming `account`.
    func memberRequest(account: String) throws -> Data {
        let spec = RequestSpec(account: account, signing: key.publicKey.x963Representation, agreement: agreement.publicKey.x963Representation,
            label: "Relay home", kind: .server, termsJson: #"{"serves":["home"]}"#, created: try accountFormatDate(ms: Int64(Date().timeIntervalSince1970 * 1000) - 5_000),
            custody: nil, operator: nil, endpoints: [base + "/"])
        let request = try AccountRequest.prepare(spec: spec)
        let signature = try key.signature(for: try request.step().body).rawRepresentation
        return try request.finish(signature: Signature(signature: signature, authenticatorData: nil, clientData: nil)).raw
    }
    /// The session's transport: the account's `https` name goes to the process on loopback.
    var transport: any HomeTransport { Transport(relay: self) }
    private struct Transport: HomeTransport {
        let relay: Relay
        let inner = URLSessionHomeTransport(allowingLoopbackHTTP: true)
        func send(_ request: HttpRequest) async throws -> HttpAnswer {
            relay.touch()
            guard request.url.hasPrefix(relay.base) else { throw URLError(.unsupportedURL) }
            let local = "http://\(relay.local)" + request.url.dropFirst(relay.base.count)
            return try await inner.send(HttpRequest(ticket: request.ticket, home: request.home, method: request.method, url: local, headers: request.headers, body: request.body))
        }
    }
}

/// A device's network: when down, sockets fail and requests are offline.
final class Network: Sendable {
    private struct State { var up = true; var open: [UUID: @Sendable () -> Void] = [:] }
    private let state = OSAllocatedUnfairLock(initialState: State())
    var up: Bool { state.withLock { $0.up } }
    /// A socket factory reaching `relay` on loopback for the account's `wss` name, through `URLSessionWebSocketTask`.
    func sockets(_ relay: Relay) -> SocketFactory {
        let inner = URLSessionSocketFactory(allowingLoopback: true).factory
        let state = state
        return { url, handlers in
            let host = relay.base.replacingOccurrences(of: "https://", with: "")
            let local = url.replacingOccurrences(of: "wss://" + host, with: "ws://" + relay.local)
            guard state.withLock({ $0.up }) else {
                Task { handlers.closed(nil) }
                return Offline()
            }
            let id = UUID()
            let ended = OSAllocatedUnfairLock(initialState: false)
            let end: @Sendable () -> Bool = { ended.withLock { e in if e { return false }; e = true; return true } }
            let socket = try inner(local, SocketHandlers(open: handlers.open, message: handlers.message,
                refused: { a in if end() { state.withLock { _ = $0.open.removeValue(forKey: id) }; handlers.refused(a) } },
                closed: { c in if end() { state.withLock { _ = $0.open.removeValue(forKey: id) }; handlers.closed(c) } }))
            // Cutting the network ends the socket as a transport failure would.
            state.withLock { $0.open[id] = { if end() { socket.close(code: 1000); handlers.closed(nil) } } }
            return Cut(socket: socket, network: state, id: id, end: end)
        }
    }
    private struct Offline: HostSocket { func send(_ text: String) {}; func close(code: UInt32) {} }
    private struct Cut: HostSocket {
        let socket: any HostSocket
        let network: OSAllocatedUnfairLock<State>
        let id: UUID
        let end: @Sendable () -> Bool
        func send(_ text: String) { if network.withLock({ $0.up }) { socket.send(text) } }
        func close(code: UInt32) { _ = end(); network.withLock { _ = $0.open.removeValue(forKey: id) }; socket.close(code: code) }
    }
    func transport(_ inner: any HomeTransport) -> any HomeTransport { Gated(inner: inner, network: self) }
    private struct Gated: HomeTransport {
        let inner: any HomeTransport
        let network: Network
        func send(_ request: HttpRequest) async throws -> HttpAnswer {
            guard network.up else { throw HomeTransportError.offline("the network is down") }
            return try await inner.send(request)
        }
    }
    func down() {
        let open = state.withLock { s -> [@Sendable () -> Void] in s.up = false; let o = Array(s.open.values); s.open = [:]; return o }
        for end in open { end() }
    }
    func restore() { state.withLock { $0.up = true } }
}

/// One member: its device, network, stream host and (once joined) its cell.
@MainActor final class Member {
    let name: String
    let device: Device
    let relay: Relay
    let network = Network()
    let store = TestStore()
    let log = Log<(at: Double, event: CellHostEvent)>()
    let events = Log<(at: Double, event: CellEvent)>()
    private(set) var stream: HomeStreamHost!
    private(set) var cell: CellSession!
    /// The application's own state (its last anchor), kept to supply on join after a restart (§S12).
    let appState = OSAllocatedUnfairLockBox<Data?>(nil)

    init(_ name: String, device: Device, relay: Relay) { self.name = name; self.device = device; self.relay = relay }
    var id: String { device.id }

    func startStream() async throws {
        let home = try #require(device.session.homes.first)
        stream = try await HomeStreamHost(account: try ColophonHostAccount(session: device.session), home: home.id, transport: network.transport(relay.transport),
                                          socket: network.sockets(relay))
        stream.start()
    }
    func join(policy: String? = nil) async throws {
        var options = CellHostOptions(account: try ColophonHostAccount(session: device.session), carrier: stream, namespace: listening, cell: nowPlaying, store: store)
        options.policy = policy
        let state = appState
        options.state = { state.get() }
        let log = log, events = events
        cell = try await CellSession.join(options)
        _ = cell.host.on { log.append((nowMs(), $0)) }
        _ = cell.events { events.append((nowMs(), $0)) }
    }
    /// The first event named `name` after `since` that `match` accepts, waiting up to `seconds`.
    func until(_ name: String, since: Double = 0, seconds: Double = 10, sourceLocation: SourceLocation = #_sourceLocation,
               _ match: (CellEvent) -> Bool = { _ in true }) async throws -> (at: Double, event: CellEvent) {
        let end = nowMs() + seconds * 1000
        while true {
            if let found = events.all.first(where: { $0.at >= since && $0.event.name == name && match($0.event) }) { return found }
            if nowMs() > end {
                let seen = events.all.filter { $0.at >= since }.map(\.event.name).joined(separator: ", ")
                Issue.record("\(self.name): no \(name) within \(seconds) s; saw \(seen)", sourceLocation: sourceLocation)
                throw Relay.Missing(description: "no \(name)")
            }
            try await Task.sleep(for: .milliseconds(2))
        }
    }
    /// Waits for `condition`, up to `seconds`; returns when it held.
    @discardableResult func when(_ what: String, seconds: Double = 10, sourceLocation: SourceLocation = #_sourceLocation,
                                 _ condition: () async -> Bool) async throws -> Double {
        let end = nowMs() + seconds * 1000
        while !(await condition()) {
            if nowMs() > end { Issue.record("\(name): \(what) did not happen within \(seconds) s", sourceLocation: sourceLocation); throw Relay.Missing(description: what) }
            try await Task.sleep(for: .milliseconds(2))
        }
        return nowMs()
    }
    /// Plaintext kinds of the frames this member handed to the carrier after `since` (and before `to`).
    func sentKinds(since: Double, to: Double = .infinity) -> [String] {
        log.all.filter { $0.at >= since && $0.at < to }.compactMap { if case .sent(let kind, _) = $0.event { kind } else { nil } }
    }
    func close() { cell?.close(); stream?.stop(); device.close() }
}

/// A home and two members of one account, both write-entitled to `listening.podcasts`. B holds the same owner key as A
/// (one person's two devices), so B can revoke A. The history is public, so a revoked A can still read its revocation.
@MainActor func world() async throws -> (relay: Relay, a: Member, b: Member) {
    let relay = Relay(base: "https://home-0.test/v1/accounts/swift06-\(UUID().uuidString.prefix(8).lowercased())")
    let appointing = HomeConfiguration(endpoint: URL(string: relay.base + "/")!, label: "Relay", request: { account in
        try relay.start(account: account)
        return try relay.memberRequest(account: account)
    }, transport: relay.transport)
    let first = Device(homes: [appointing], createWithoutHome: false, history: .everyone)
    await first.session.create()
    first.session.stopSync()
    try #require(first.session.phase == .ready, "A is ready: \(first.session.phase) \(first.session.lastError ?? "")")
    try #require(await syncUntilClean(first), "A syncs with the home")
    let authority = first.medium.snapshot().filter { $0.key.hasPrefix("authority/") }
    let second = Device(medium: MemoryMedium(files: authority), owner: first.owner,
                        homes: [HomeConfiguration(endpoint: URL(string: relay.base + "/")!, transport: relay.transport)], createWithoutHome: false)
    await second.session.restore()
    second.session.stopSync()
    try await approveByScan(joining: second.session, approving: first.session)
    try #require(await syncUntilClean(first))
    for _ in 0..<40 where second.session.phase != .ready {
        _ = await second.session.syncNow()
        await second.session.refresh()
        if second.session.phase != .ready { try await Task.sleep(for: .milliseconds(100)) }
    }
    try #require(second.session.phase == .ready, "B learnt its approval through the home: \(second.session.phase)")
    try #require(await syncUntilClean(second))
    return (relay, Member("A", device: first, relay: relay), Member("B", device: second, relay: relay))
}
/// Syncs until the session says nothing is wrong (a home records entries and forwards heads on its own schedule).
@MainActor func syncUntilClean(_ device: Device, tries: Int = 40) async -> Bool {
    for _ in 0..<tries {
        if await device.session.syncNow(), device.session.homeIssues.isEmpty, device.session.homeFaults.isEmpty { return true }
        try? await Task.sleep(for: .milliseconds(150))
    }
    return false
}

/// The `now-playing` anchor (sessions §S12).
struct Anchor: Codable, Equatable, Sendable {
    var episode: String
    var show: String
    var positionMs: Int64
    var ratePermille: Int64
    var playing: Bool
    var at: Int64
    var data: Data { (try? Self.encoder.encode(self)) ?? Data() }
    static func read(_ data: Data?) -> Anchor? { data.flatMap { try? JSONDecoder().decode(Anchor.self, from: $0) } }
    private static let encoder: JSONEncoder = { let e = JSONEncoder(); e.outputFormatting = .sortedKeys; return e }()
    /// A member's projected position (§S12): `offset` is the holder's clock minus this member's (0 for the holder itself).
    func project(now: Int64, offset: Int64) -> Int64 { playing ? positionMs + ratePermille * (now + offset - at) / 1000 : positionMs }
}
/// The clock anchors are stamped with (the same one `SessionClock` reads: `CLOCK_MONOTONIC`).
func anchorNow() -> Int64 { SystemClock().monoMs() }

/// A fast policy for scenarios that wait out timeouts: the default with shorter timers.
func fastPolicy() throws -> String {
    var p = try #require(try JSONSerialization.jsonObject(with: Data(try sessionDefaultPolicy().utf8)) as? [String: Any])
    p["beatMs"] = 400; p["holderTimeoutMs"] = 1_500; p["askTimeoutMs"] = 300; p["presenceTimeoutMs"] = 1_500
    return json(p)
}
let holderFrames = ["state", "beat", "msg", "refuse", "pass", "decline"]
