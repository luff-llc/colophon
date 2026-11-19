import CryptoKit
import Foundation
import ColophonSession

/// The real relay as a home: `bun relay/server.js` started on loopback with a temporary data directory and the explicit
/// test clock (`--test-clock`, a clock file the transport sets to the device's clock before each request), one slot
/// provisioned for one account. Its key is a P-256 key this test made, given to the relay as a private JWK; the home's
/// signed member request is made with the same key, so the account can appoint it. Stopped (and its directory removed)
/// by `stop()` or when it goes.
///
/// It needs Bun and the home module (`colophon_home_wasm.wasm`, built by `scripts/test-swift.sh` or
/// `scripts/test-home.sh`): without them `start` throws and the test fails; it never passes by skipping.
final class RelayHome: @unchecked Sendable {
    enum Failure: Error, CustomStringConvertible {
        case missing(String), noListeningLine(String)
        var description: String {
            switch self { case .missing(let m): "relay prerequisite missing: \(m)"; case .noListeningLine(let m): "the relay did not start: \(m)" }
        }
    }
    let key = P256.Signing.PrivateKey()
    let agreement = P256.KeyAgreement.PrivateKey()
    /// The public base the account names (an `https://` name; spec §9.1).
    let base: String
    let port: Int
    private let lock = NSLock()
    private var process: Process?
    private let dir: URL
    private let clock: URL

    /// With `clock`, the relay runs on that clock (set before every request and pass) with no scheduler timer: heads are
    /// published only by `tick()`, so nothing waits on real time.
    let clockSource: (@Sendable () -> Int64)?
    private var input: FileHandle?
    private var output: FileHandle?
    private var buffered = Data()

    init(base: String, port: Int, clock source: (@Sendable () -> Int64)? = nil) {
        self.base = base; self.port = port; self.clockSource = source
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("colophon-swift-relay-\(UUID().uuidString)")
        clock = dir.appendingPathComponent("clock")
    }
    deinit { stop() }

    var id: String { (try? accountKeyId(signing: key.publicKey.x963Representation)) ?? "" }

    static var repository: URL { URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent() }
    static func bun() throws -> URL {
        let env = ProcessInfo.processInfo.environment
        var candidates = (env["PATH"] ?? "").split(separator: ":").map { URL(fileURLWithPath: String($0)).appendingPathComponent("bun") }
        candidates += [URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent(".bun/bin/bun"), URL(fileURLWithPath: "/opt/homebrew/bin/bun"), URL(fileURLWithPath: "/usr/local/bin/bun")]
        if let path = env["COLOPHON_BUN"] { candidates.insert(URL(fileURLWithPath: path), at: 0) }
        guard let bun = candidates.first(where: { FileManager.default.isExecutableFile(atPath: $0.path) }) else { throw Failure.missing("bun (set COLOPHON_BUN)") }
        return bun
    }
    static func module() throws -> URL {
        let env = ProcessInfo.processInfo.environment
        let path = env["COLOPHON_HOME_WASM"].map { URL(fileURLWithPath: $0) }
            ?? URL(fileURLWithPath: env["CARGO_TARGET_DIR"] ?? repository.appendingPathComponent("target").path)
                .appendingPathComponent("wasm32-unknown-unknown/release/colophon_home_wasm.wasm")
        guard FileManager.default.fileExists(atPath: path.path) else { throw Failure.missing("the home module at \(path.path) (set COLOPHON_HOME_WASM)") }
        return path
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

    /// The private JWK the relay signs with.
    private var jwk: String {
        let point = key.publicKey.x963Representation
        func b64(_ d: Data) -> String { d.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") }
        return "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"\(b64(point[1..<33]))\",\"y\":\"\(b64(point[33..<65]))\",\"d\":\"\(b64(key.rawRepresentation))\"}"
    }

    /// Start the relay for `account`; `peers` are the other homes of the account (forwarding). `provision` is the
    /// config file's `provision` object (the door), as JSON.
    func start(account: String, peers: [RelayHome] = [], provision: String? = nil) throws {
        let bun = try Self.bun(), module = try Self.module()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try String(clockSource?() ?? Self.nowMs()).write(to: clock, atomically: true, encoding: .utf8)
        let resolve = Dictionary(uniqueKeysWithValues: peers.map { ($0.base, "http://127.0.0.1:\($0.port)/v1/libraries/home") })
        let config = dir.appendingPathComponent("config.json")
        var settings: [String: Any] = ["resolve": resolve]
        if let provision { settings["provision"] = try JSONSerialization.jsonObject(with: Data(provision.utf8)) }
        try JSONSerialization.data(withJSONObject: settings).write(to: config)
        let p = Process()
        p.executableURL = bun
        p.arguments = [Self.repository.appendingPathComponent("relay/server.js").path, "--test-clock", "--config", config.path]
        var env = ProcessInfo.processInfo.environment
        env["COLOPHON_RELAY_PORT"] = String(port)
        env["COLOPHON_RELAY_DATA"] = dir.appendingPathComponent("data").path
        env["COLOPHON_RELAY_HOME_SLOTS"] = "home=\(account)@\(base)"
        env["COLOPHON_HOME_KEY"] = jwk
        env["COLOPHON_HOME_WASM"] = module.path
        env["COLOPHON_RELAY_CLOCK_FILE"] = clock.path
        env["COLOPHON_RELAY_TICK_MS"] = clockSource == nil ? "50" : "0"
        p.environment = env
        let out = Pipe(), inPipe = Pipe()
        p.standardOutput = out
        p.standardInput = inPipe
        p.standardError = FileHandle.nullDevice
        try p.run()
        lock.withLock { process = p }
        // The first stdout line is machine-readable: {"listening":{…}}.
        var line = Data()
        while !line.contains(0x0a) {
            let chunk = out.fileHandleForReading.availableData
            if chunk.isEmpty { throw Failure.noListeningLine(String(decoding: line, as: UTF8.self)) }
            line.append(chunk)
        }
        guard String(decoding: line, as: UTF8.self).contains("\"listening\"") else { throw Failure.noListeningLine(String(decoding: line, as: UTF8.self)) }
        lock.withLock {
            input = inPipe.fileHandleForWriting; output = out.fileHandleForReading
            buffered = line.suffix(from: line.firstIndex(of: 0x0a)! + 1)
        }
    }
    /// One scheduler pass of the relay (its test hook: a `tick` line on stdin), on its clock, finished when it answers:
    /// the deterministic way to publish heads.
    func tick() async throws {
        // The read blocks until the relay answers: off the main actor, so other tests' tasks keep running meanwhile.
        try await Task.detached { try self.tickBlocking() }.value
    }
    private func tickBlocking() throws {
        touch()
        let (input, output) = lock.withLock { (self.input, self.output) }
        guard let input, let output else { throw Failure.missing("a started relay") }
        try input.write(contentsOf: Data("tick\n".utf8))
        while true {
            let line: Data? = lock.withLock {
                guard let end = buffered.firstIndex(of: 0x0a) else { return nil }
                let l = buffered.prefix(upTo: end); buffered = Data(buffered.suffix(from: end + 1)); return Data(l)
            }
            if let line { if String(decoding: line, as: UTF8.self).contains("\"ticked\"") { return } else { continue } }
            let chunk = output.availableData
            if chunk.isEmpty { throw Failure.noListeningLine("the relay closed its output") }
            lock.withLock { buffered.append(chunk) }
        }
    }
    /// Sets the relay's clock: to the injected clock when there is one, else to now.
    func touch() { setClock(clockSource?() ?? Self.nowMs()) }
    func stop() {
        let p = lock.withLock { () -> Process? in let p = process; process = nil; return p }
        if let p, p.isRunning { p.terminate(); p.waitUntilExit() }
        try? FileManager.default.removeItem(at: dir)
    }
    static func nowMs() -> Int64 { Int64(Date().timeIntervalSince1970 * 1000) }
    /// Moves the relay's test clock to `ms` (the device's clock).
    func setClock(_ ms: Int64) { try? String(ms).write(to: clock, atomically: true, encoding: .utf8) }

    /// The home's signed member request (§9.1) naming `account`, as a home service answers it.
    func memberRequest(account: String) throws -> Data {
        let spec = RequestSpec(account: account, signing: key.publicKey.x963Representation, agreement: agreement.publicKey.x963Representation,
            label: "Relay home", kind: .server, termsJson: "{\"serves\":[\"home\"]}", created: try accountFormatDate(ms: (clockSource?() ?? Self.nowMs()) - 5_000),
            custody: nil, operator: nil, endpoints: [base + "/"])
        let request = try AccountRequest.prepare(spec: spec)
        let signature = try key.signature(for: try request.step().body).rawRepresentation
        return try request.finish(signature: Signature(signature: signature, authenticatorData: nil, clientData: nil)).raw
    }

    /// The session's transport to this relay: the account's `https://` name goes to the process on loopback (`http`,
    /// allowed for loopback only, by the SDK's testing option), and the relay's clock is set to the device's first.
    /// With `refusals`, the `result` of every 403 the relay answers is recorded there (`-` when it names none; a 401 only
    /// asks for a call).
    func transport(refusals: Refusals? = nil) -> any HomeTransport { Transport(relay: self, refusals: refusals) }
    private struct Transport: HomeTransport {
        let relay: RelayHome
        let refusals: Refusals?
        let inner = URLSessionHomeTransport(allowingLoopbackHTTP: true)
        func send(_ request: HttpRequest) async throws -> HttpAnswer {
            relay.touch()
            guard request.url.hasPrefix(relay.base) else { throw URLError(.unsupportedURL) }
            let local = "http://127.0.0.1:\(relay.port)/v1/libraries/home" + request.url.dropFirst(relay.base.count)
            let answer = try await inner.send(HttpRequest(ticket: request.ticket, home: request.home, method: request.method, url: local,
                                                          headers: request.headers, body: request.body))
            if answer.status == 403 {
                let result = (try? JSONSerialization.jsonObject(with: answer.body) as? [String: Any])?["result"] as? String
                refusals?.append(result ?? "-")
            }
            return answer
        }
    }

    /// This relay's door (`POST /v1/provision`) on loopback.
    var door: URL { URL(string: "http://127.0.0.1:\(port)/v1/provision")! }
    /// A transport to the door that sets the relay's clock first.
    func doorTransport() -> any HomeTransport { Slot(relay: self, base: nil, local: "") }
    /// The transport to a slot this relay provisioned: `base` (its `https://` name) goes to `/v1/libraries/<slot>`.
    func slotTransport(base: String, slot: String) -> any HomeTransport { Slot(relay: self, base: base, local: "http://127.0.0.1:\(port)/v1/libraries/\(slot)") }
    private struct Slot: HomeTransport {
        let relay: RelayHome
        let base: String?
        let local: String
        let inner = URLSessionHomeTransport(allowingLoopbackHTTP: true)
        func send(_ request: HttpRequest) async throws -> HttpAnswer {
            relay.touch()
            guard let base else { return try await inner.send(request) }
            guard request.url.hasPrefix(base) else { throw URLError(.unsupportedURL) }
            return try await inner.send(HttpRequest(ticket: request.ticket, home: request.home, method: request.method, url: local + request.url.dropFirst(base.count),
                                                    headers: request.headers, body: request.body))
        }
    }

    /// The refusals one device's transports saw, in order.
    final class Refusals: @unchecked Sendable {
        private let lock = NSLock()
        private var codes: [String] = []
        func append(_ code: String) { lock.withLock { codes.append(code) } }
        var all: [String] { lock.withLock { codes } }
        func clear() { lock.withLock { codes.removeAll() } }
    }
}
