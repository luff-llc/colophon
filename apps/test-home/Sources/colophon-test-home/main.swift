import ColophonKit
import CryptoKit
import Foundation
import Network

// colophon-test-home: the home service the Colophon test apps talk to on this Mac.
//
// A 0.5 home slot is provisioned for one account (relay/README.md, "Provisioning"), and the account does not exist
// until the app creates it. So, as `RelayJourneyTests` does in-process, the app asks this service at creation: it sends
// the new account ID with the slot and base it chose, this service adds the slot to the reference relay (restarting
// `bun relay/server.js` with every slot it has provisioned) and answers with the home's signed member request (§9.1),
// which the app's session uses to appoint the home.
//
//   swift run --package-path apps/test-home colophon-test-home [--port 8791] [--relay-port 8790] [--data DIR] [--wasm FILE]
//
//   GET  /status      {"relay": "http://127.0.0.1:8790/v1/libraries/", "slots": {...}}
//   POST /provision   {"slot": "t…", "base": "https://…/<slot>", "account": "<64 hex>"} -> the member request (JSON bytes)
//
// It listens on 127.0.0.1 only. The home's signing key is a P-256 key made on first start and kept, as a private JWK
// with mode 0600, in the data directory (default $TMPDIR/colophon-test-home); it never leaves this Mac and is never
// printed. The relay runs on the real clock (no --test-clock). Stopping this service (Ctrl-C, SIGTERM) stops the relay.

struct Options {
    var port: UInt16 = 8791
    var relayPort: UInt16 = 8790
    var data = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("colophon-test-home")
    var repository = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    var wasm: URL?

    static func parse(_ arguments: [String]) -> Options {
        var options = Options()
        var rest = arguments.dropFirst().makeIterator()
        while let flag = rest.next() {
            guard let value = rest.next() else { fail("missing value for \(flag)") }
            switch flag {
            case "--port": options.port = UInt16(value) ?? { fail("bad --port") }()
            case "--relay-port": options.relayPort = UInt16(value) ?? { fail("bad --relay-port") }()
            case "--data": options.data = URL(fileURLWithPath: value)
            case "--wasm": options.wasm = URL(fileURLWithPath: value)
            default: fail("unknown option \(flag)")
            }
        }
        return options
    }
}

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("colophon-test-home: \(message)\n".utf8))
    exit(1)
}

func log(_ message: String) {
    FileHandle.standardError.write(Data("colophon-test-home: \(message)\n".utf8))
}

struct Slot: Codable, Equatable { let account: String; let base: String }

/// Everything here runs on `queue`, one request at a time (a development tool: provisioning restarts the relay).
final class Service: @unchecked Sendable {
    let options: Options
    let queue = DispatchQueue(label: "colophon-test-home")
    private let key: P256.Signing.PrivateKey
    private var slots: [String: Slot]
    private var relay: Process?
    private var slotsURL: URL { options.data.appendingPathComponent("slots.json") }
    private var keyURL: URL { options.data.appendingPathComponent("home-key.jwk") }

    init(options: Options) throws {
        self.options = options
        try FileManager.default.createDirectory(at: options.data, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        key = try Self.loadOrCreateKey(at: options.data.appendingPathComponent("home-key.jwk"))
        slots = (try? JSONDecoder().decode([String: Slot].self, from: Data(contentsOf: options.data.appendingPathComponent("slots.json")))) ?? [:]
    }

    // MARK: Key

    private static func b64url(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
    private static func unb64url(_ text: String) -> Data? {
        var s = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while s.count % 4 != 0 { s += "=" }
        return Data(base64Encoded: s)
    }
    private static func loadOrCreateKey(at url: URL) throws -> P256.Signing.PrivateKey {
        if let data = try? Data(contentsOf: url) {
            guard let jwk = try JSONSerialization.jsonObject(with: data) as? [String: String], let d = jwk["d"].flatMap(unb64url) else {
                fail("\(url.path) is not a private P-256 JWK")
            }
            return try P256.Signing.PrivateKey(rawRepresentation: d)
        }
        let key = P256.Signing.PrivateKey()
        let point = key.publicKey.x963Representation
        let jwk = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"\(b64url(point[1..<33]))\",\"y\":\"\(b64url(point[33..<65]))\",\"d\":\"\(b64url(key.rawRepresentation))\"}"
        guard FileManager.default.createFile(atPath: url.path, contents: Data(jwk.utf8), attributes: [.posixPermissions: 0o600]) else {
            fail("cannot write \(url.path)")
        }
        return key
    }

    // MARK: Relay

    private func bun() -> String {
        let env = ProcessInfo.processInfo.environment
        var candidates = (env["PATH"] ?? "").split(separator: ":").map { "\($0)/bun" }
        candidates += [NSHomeDirectory() + "/.bun/bin/bun", "/opt/homebrew/bin/bun", "/usr/local/bin/bun"]
        if let path = env["COLOPHON_BUN"] { candidates.insert(path, at: 0) }
        guard let found = candidates.first(where: { FileManager.default.isExecutableFile(atPath: $0) }) else { fail("bun not found (set COLOPHON_BUN)") }
        return found
    }
    private func wasm() -> URL {
        let env = ProcessInfo.processInfo.environment
        let url = options.wasm ?? env["COLOPHON_HOME_WASM"].map { URL(fileURLWithPath: $0) }
            ?? URL(fileURLWithPath: env["CARGO_TARGET_DIR"] ?? options.repository.appendingPathComponent("target").path)
                .appendingPathComponent("wasm32-unknown-unknown/release/colophon_home_wasm.wasm")
        guard FileManager.default.fileExists(atPath: url.path) else {
            fail("the home module is missing at \(url.path): cargo build --target wasm32-unknown-unknown --release -p colophon-home-wasm")
        }
        return url
    }

    func stopRelay() {
        guard let process = relay else { return }
        relay = nil
        if process.isRunning { process.terminate(); process.waitUntilExit() }
    }

    /// Starts (or restarts) the relay with every provisioned slot; returns once it prints its listening line.
    func startRelay() throws {
        stopRelay()
        guard !slots.isEmpty else { log("no slot yet: the relay starts with the first provisioned slot"); return }
        let config = options.data.appendingPathComponent("relay-config.json")
        var libraries: [String: Any] = [:]
        for (name, slot) in slots { libraries[name] = ["home": true, "account": slot.account, "base": slot.base] }
        let object: [String: Any] = ["libraries": libraries, "home": ["keyFile": keyURL.path, "wasm": wasm().path]]
        try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]).write(to: config)
        let process = Process()
        process.executableURL = URL(fileURLWithPath: bun())
        process.arguments = [options.repository.appendingPathComponent("relay/server.js").path, "--config", config.path]
        var env = ProcessInfo.processInfo.environment
        env["COLOPHON_RELAY_HOST"] = "127.0.0.1"
        env["COLOPHON_RELAY_PORT"] = String(options.relayPort)
        env["COLOPHON_RELAY_DATA"] = options.data.appendingPathComponent("relay").path
        env.removeValue(forKey: "COLOPHON_HOME_KEY")
        process.environment = env
        let out = Pipe()
        process.standardOutput = out
        process.standardError = FileHandle.standardError
        try process.run()
        relay = process
        var line = Data()
        while !line.contains(0x0a) {
            let chunk = out.fileHandleForReading.availableData
            if chunk.isEmpty { stopRelay(); throw ServiceError.relay("the relay exited before listening: \(String(decoding: line, as: UTF8.self))") }
            line.append(chunk)
        }
        out.fileHandleForReading.readabilityHandler = { handle in _ = handle.availableData }
        log("relay \(String(decoding: line, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)) with \(slots.count) slot(s)")
    }

    // MARK: Requests

    enum ServiceError: Error { case bad(String), conflict(String), relay(String) }

    func handle(method: String, path: String, body: Data) -> (Int, Data) {
        do {
            switch (method, path) {
            case ("GET", "/status"):
                let object: [String: Any] = ["relay": "http://127.0.0.1:\(options.relayPort)/v1/libraries/",
                                             "slots": slots.mapValues { ["account": $0.account, "base": $0.base] }]
                return (200, try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]))
            case ("POST", "/provision"):
                return (200, try provision(body))
            default:
                return (404, Data("{\"error\":\"not found\"}".utf8))
            }
        } catch ServiceError.bad(let why) {
            return (400, Self.error(why))
        } catch ServiceError.conflict(let why) {
            return (409, Self.error(why))
        } catch {
            return (500, Self.error("\(error)"))
        }
    }
    private static func error(_ text: String) -> Data {
        (try? JSONSerialization.data(withJSONObject: ["error": text])) ?? Data()
    }

    private func provision(_ body: Data) throws -> Data {
        guard let object = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let name = object["slot"] as? String, let base = object["base"] as? String, let account = object["account"] as? String else {
            throw ServiceError.bad("expected {\"slot\",\"base\",\"account\"}")
        }
        guard (1...40).contains(name.count), name.allSatisfy({ ($0.isASCII && ($0.isLowercase || $0.isNumber)) || $0 == "-" }) else {
            throw ServiceError.bad("slot is 1 to 40 of a-z, 0-9 and -")
        }
        guard account.count == 64, account.allSatisfy({ $0.isHexDigit && !$0.isUppercase }) else { throw ServiceError.bad("account is 64 lowercase hex") }
        let trimmed = base.hasSuffix("/") ? String(base.dropLast()) : base
        guard let url = URL(string: trimmed), url.scheme == "https", url.host != nil else { throw ServiceError.bad("base must be an https URL") }
        let slot = Slot(account: account, base: trimmed)
        if let existing = slots[name] {
            guard existing == slot else { throw ServiceError.conflict("slot \(name) is provisioned for another account or base") }
        } else {
            slots[name] = slot
            try JSONEncoder().encode(slots).write(to: slotsURL)
            do { try startRelay() } catch {
                slots[name] = nil
                try? JSONEncoder().encode(slots).write(to: slotsURL)
                try? startRelay()
                throw error
            }
            log("provisioned slot \(name) for account \(account.prefix(12))…")
        }
        return try memberRequest(account: account, base: trimmed)
    }

    /// The home's signed member request (§9.1) naming `account`, with `base/` as its endpoint.
    private func memberRequest(account: String, base: String) throws -> Data {
        let agreement = P256.KeyAgreement.PrivateKey()
        let spec = RequestSpec(account: account, signing: key.publicKey.x963Representation, agreement: agreement.publicKey.x963Representation,
                               label: "Test home", kind: .server, termsJson: "{\"serves\":[\"home\"]}",
                               created: try accountFormatDate(ms: Int64(Date().timeIntervalSince1970 * 1000) - 5_000),
                               custody: nil, operator: nil, endpoints: [base + "/"])
        let request = try AccountRequest.prepare(spec: spec)
        let signature = try key.signature(for: try request.step().body).rawRepresentation
        return try request.finish(signature: Signature(signature: signature, authenticatorData: nil, clientData: nil)).raw
    }
}

// MARK: HTTP (just enough: one request per connection, Content-Length bodies up to 64 KiB)

final class Connection: @unchecked Sendable {
    let connection: NWConnection
    let service: Service
    var buffer = Data()
    init(_ connection: NWConnection, service: Service) { self.connection = connection; self.service = service }

    func start() {
        connection.start(queue: service.queue)
        receive()
    }
    private func receive() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { [self] data, _, complete, error in
            if let data { buffer.append(data) }
            if buffer.count > 128 * 1024 { return respond(413, Data()) }
            if let request = parse() { return respond(service.handle(method: request.method, path: request.path, body: request.body)) }
            if complete || error != nil { connection.cancel(); return }
            receive()
        }
    }
    private func parse() -> (method: String, path: String, body: Data)? {
        guard let end = buffer.range(of: Data("\r\n\r\n".utf8)) else { return nil }
        let head = String(decoding: buffer[..<end.lowerBound], as: UTF8.self).split(separator: "\r\n")
        let first = head.first?.split(separator: " ") ?? []
        guard first.count >= 2 else { return ("BAD", "", Data()) }
        var length = 0
        for line in head.dropFirst() {
            let parts = line.split(separator: ":", maxSplits: 1)
            if parts.count == 2, parts[0].lowercased() == "content-length" { length = Int(parts[1].trimmingCharacters(in: .whitespaces)) ?? 0 }
        }
        guard length <= 65_536 else { return ("BAD", "", Data()) }
        let body = buffer[end.upperBound...]
        guard body.count >= length else { return nil }
        return (String(first[0]), String(first[1]), Data(body.prefix(length)))
    }
    private func respond(_ answer: (Int, Data)) { respond(answer.0, answer.1) }
    private func respond(_ status: Int, _ body: Data) {
        let reason = [200: "OK", 400: "Bad Request", 404: "Not Found", 409: "Conflict", 413: "Content Too Large"][status] ?? "Error"
        var head = "HTTP/1.1 \(status) \(reason)\r\nContent-Type: application/json\r\nContent-Length: \(body.count)\r\nConnection: close\r\n\r\n"
        if status == 413 { head = "HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n" }
        connection.send(content: Data(head.utf8) + body, completion: .contentProcessed { [connection] _ in connection.cancel() })
    }
}

let options = Options.parse(CommandLine.arguments)
let service: Service
do { service = try Service(options: options) } catch { fail("\(error)") }

let parameters = NWParameters.tcp
parameters.requiredLocalEndpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: options.port)!)
parameters.allowLocalEndpointReuse = true
let listener: NWListener
do { listener = try NWListener(using: parameters) } catch { fail("cannot listen on 127.0.0.1:\(options.port): \(error)") }
listener.newConnectionHandler = { Connection($0, service: service).start() }
listener.stateUpdateHandler = { state in
    switch state {
    case .ready: print("{\"listening\":{\"host\":\"127.0.0.1\",\"port\":\(options.port)},\"relay\":\"http://127.0.0.1:\(options.relayPort)/v1/libraries/\"}"); fflush(stdout)
    case .failed(let error): fail("listener failed: \(error)")
    default: break
    }
}
service.queue.sync { do { try service.startRelay() } catch { fail("\(error)") } }
listener.start(queue: service.queue)

let signalSources = [SIGINT, SIGTERM].map { sig in
    signal(sig, SIG_IGN)
    let source = DispatchSource.makeSignalSource(signal: sig, queue: service.queue)
    source.setEventHandler { service.stopRelay(); exit(0) }
    source.resume()
    return source
}
withExtendedLifetime(signalSources) { dispatchMain() }
