import Darwin
import CryptoKit
import Foundation
import ColophonSession
import ColophonKitStorage

// Test protocol only. Synthetic software keys and the cache key stay in each device's private directory.
private func bytes(_ s: String) -> Data { Data(base64Encoded: s)! }
private func emit(_ object: [String: Any]) throws {
    let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
    FileHandle.standardOutput.write(data + Data([10]))
}
private func event(_ object: [String: Any]) throws -> [String: Any] {
    try emit(object)
    guard let line = readLine(), let reply = try JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any], reply["error"] == nil else {
        throw DriverError.invalid("event failed")
    }
    return reply
}
private enum DriverError: Error { case invalid(String) }
private struct RemoteOwner: AsyncKeyProvider {
    let signing: Data
    let agreement: Data
    func publicKeys() async throws -> PublicKeys { PublicKeys(signing: signing, agreement: agreement) }
    func sign(body: Data) async throws -> Data { bytes(try event(["event": "sign", "body": body.base64EncodedString()])["signature"] as! String) }
    func sharedSecret(peer: Data) async throws -> SecretBytes { throw DriverError.invalid("remote ECDH not offered") }
}
private struct FileSecrets: DeviceSecretStore {
    let directory: URL
    func key(for account: String) throws -> SecretBytes {
        let path = directory.appendingPathComponent("device-secret-" + account)
        if !FileManager.default.fileExists(atPath: path.path) {
            try withEntropy(32) { try $0.write(to: path, options: .atomic) }
        }
        return try SecretBytes(copying: Data(contentsOf: path))
    }
    func remove(account: String) throws { try FileManager.default.removeItem(at: directory.appendingPathComponent("device-secret-" + account)) }
}
private actor Audit {
    var refused: [String] = []
    var refusesCalls = false
    func setRefusesCalls(_ value: Bool) { refusesCalls = value }
    func add(_ code: String) { refused.append(code) }
    func clear() { refused = [] }
}
private struct Transport: HomeTransport {
    let base: String
    let local: String
    let audit: Audit
    let inner = URLSessionHomeTransport(allowingLoopbackHTTP: true)
    func send(_ request: HttpRequest) async throws -> HttpAnswer {
        guard request.url.hasPrefix(base + "/") else { throw DriverError.invalid("wrong home") }
        if await audit.refusesCalls, request.headers.contains(where: { $0.name.lowercased() == "authorization" && $0.value.hasPrefix("Colophon ") }) {
            return HttpAnswer(status: 403, headers: [], body: Data("{\"result\":\"refused:revoked\"}".utf8))
        }
        let answer = try await inner.send(HttpRequest(ticket: request.ticket, home: request.home, method: request.method,
            url: local + request.url.dropFirst(base.count), headers: request.headers, body: request.body))
        if answer.status == 403 {
            let v = try JSONSerialization.jsonObject(with: answer.body) as? [String: Any]
            await audit.add(v?["result"] as? String ?? "missing-result")
        }
        return answer
    }
}
@main
@MainActor struct CrossDevice {
    static func main() async {
        umask(0o077)
        let driver = Driver()
        while let line = readLine() {
            do {
                let command = try JSONSerialization.jsonObject(with: Data(line.utf8)) as! [String: Any]
                let result = try await driver.run(command)
                try emit(["ok": true, "value": result])
            } catch { try? emit(["ok": false, "error": String(describing: error)]) }
        }
        driver.session?.stopSync()
        await driver.session?.lock()
    }
}
@MainActor private final class Driver {
    var session: ColophonSession?
    var owner: SoftwareKeys?
    var pairing: AccountPairing?
    var transferKey: PairingTransferKey?
    let limiter = try! PairingFailureLimiter.fromState(state: "")
    let audit = Audit()
    func keys(_ directory: URL, _ name: String) throws -> SoftwareKeys {
        func scalar(_ suffix: String, make: () -> Data) throws -> Data {
            let path = directory.appendingPathComponent(name + suffix)
            if !FileManager.default.fileExists(atPath: path.path) { try make().write(to: path, options: .atomic) }
            return try Data(contentsOf: path)
        }
        return try SoftwareKeys(signingPrivateKey: scalar("-signing", make: { P256.Signing.PrivateKey().rawRepresentation }),
                                agreementPrivateKey: scalar("-agreement", make: { P256.KeyAgreement.PrivateKey().rawRepresentation }))
    }
    func state() async -> [String: Any] {
        guard let s = session else { return [:] }
        let phase: String = switch s.phase { case .ready: "ready"; case .locked: "locked"; case .denied: "denied"; case .waitingForApproval: "waiting"; default: String(describing: s.phase) }
        return ["phase": phase, "account": s.libraryID ?? "", "member": s.memberID ?? "", "homes": s.homes.count,
                "error": s.lastError ?? "", "issues": s.homeIssues.map { issue in
                    switch issue.problem {
                    case .callRefused(let code), .remoteCallRefused(let code): return code
                    default: return String(describing: issue.problem)
                    }
                }, "faults": s.homeFaults.map { String(describing: $0.fault) }, "refusals": await audit.refused,
                "remoteRefusals": s.homeIssues.compactMap { if case .remoteCallRefused(let code) = $0.problem { return code }; return nil },
                "pending": s.notices.pending.map { ["digest": $0.digest, "vetoable": $0.vetoable] as [String: Any] }]
    }
    func run(_ c: [String: Any]) async throws -> Any {
        func text(_ key: String) -> String { c[key] as! String }
        func data(_ key: String) -> Data { bytes(text(key)) }
        if text("op") == "init" {
            let root = URL(fileURLWithPath: text("root"))
            let privateDir = root.appendingPathComponent("private")
            try FileManager.default.createDirectory(at: privateDir, withIntermediateDirectories: true)
            let member = try keys(privateDir, "member"), owner = try keys(privateDir, "owner")
            self.owner = owner
            let configs = try (c["homes"] as! [[String: String]]).map { h -> HomeConfiguration in
                let base = h["base"]!, homeKey = try P256.Signing.PrivateKey(rawRepresentation: bytes(h["secret"]!))
                let agreement = bytes(h["agreement"]!)
                return HomeConfiguration(endpoint: URL(string: base + "/")!, request: { account in
                    _ = try event(["event": "provision", "account": account])
                    let request = try AccountRequest.prepare(spec: RequestSpec(account: account, signing: homeKey.publicKey.x963Representation,
                        agreement: agreement, label: "Cross home", kind: .server, termsJson: "{\"serves\":[\"home\"]}",
                        created: try accountFormatDate(ms: Int64(Date().timeIntervalSince1970 * 1000) - 5000), custody: nil, operator: nil, endpoints: [base + "/"]))
                    return try request.finish(signature: Signature(signature: homeKey.signature(for: request.step().body).rawRepresentation,
                                                                  authenticatorData: nil, clientData: nil)).raw
                }, transport: Transport(base: base, local: h["local"]!, audit: audit))
            }
            var additional: [AdditionalController] = []
            if let extra = c["extra"] as? [String: String] {
                additional = [AdditionalController(provider: RemoteOwner(signing: bytes(extra["signing"]!), agreement: bytes(extra["agreement"]!)), label: "Other platform owner")]
            }
            session = ColophonSession(configuration: .init(memberLabel: "Swift cross device", namespaces: ["reading.saved"],
                location: .medium(FolderMedium(folder: root.appendingPathComponent("records"), coordinated: false)), privateContainer: privateDir,
                keys: member, ownerController: owner, homes: configs, additionalControllers: additional,
                deviceSecrets: FileSecrets(directory: privateDir), history: text("history") == "members" ? .members : .everyone,
                headQuorum: configs.count))
            let p = try await owner.publicKeys()
            return ["signing": p.signing.base64EncodedString(), "agreement": p.agreement.base64EncodedString()]
        }
        if text("op") == "sign" { return try owner!.sign(body: data("body")).base64EncodedString() }
        // Pairing values travel as exact base64 bytes, without interpreting/re-encoding their contents.
        switch text("op") {
        case "join":
            transferKey = try PairingTransferKey.create(entropy: data("entropy"))
            let e = transferKey!.public()
            if text("mode") == "qr" {
                pairing = try AccountPairing.joinQr(account: text("account"), e: e, nb: data("nb"))
                return ["qr": try pairing!.qrPayload().base64EncodedString(), "e": e.base64EncodedString()]
            }
            pairing = try AccountPairing.join(account: text("account"), e: e, nb: data("nb"))
            return ["commitment": try pairing!.commitment().base64EncodedString(), "e": e.base64EncodedString()]
        case "scan":
            if text("mode") == "qr" { pairing = try AccountPairing.existingScanQr(account: text("account"), payload: data("qr"), limiter: limiter, nowMs: 1000) }
            else { pairing = try AccountPairing.existingReceiveCommitment(account: text("account"), commitment: data("commitment"), limiter: limiter, nowMs: 1000) }
            return true
        case "nonce": return try pairing!.sendNonce(na: data("na")).base64EncodedString()
        case "receiveNonce":
            if let r = try pairing!.receiveNonce(na: data("na")) {
                return ["e": r.e.base64EncodedString(), "nb": r.nb.base64EncodedString(), "digits": try pairing!.digits()]
            }
            return ["stage": String(describing: try pairing!.stage())]
        case "reveal": return try pairing!.receiveReveal(e: data("e"), nb: data("nb"), limiter: limiter, nowMs: 1000)
        case "confirm":
            let matches = try pairing!.digits() == text("digits")
            if matches { try pairing!.confirm() } else { try pairing!.reject(limiter: limiter, nowMs: 1000) }
            return ["accepted": matches, "stage": String(describing: try pairing!.stage())]
        case "pairingStage": return String(describing: try pairing!.stage())
        default: break
        }
        let s = session!
        switch text("op") {
        case "create": await s.create()
        case "restore": await s.restore()
        case "refresh": await s.refresh()
        case "refuseCalls": await audit.setRefusesCalls(c["enabled"] as! Bool)
        case "sync": await audit.clear(); _ = await s.syncNow(); await s.refresh()
        case "request": return try await s.exportRequest().base64EncodedString()
        case "approve":
            try await s.importRequest(data("request"))
            guard let request = s.requests.first else { throw DriverError.invalid("no request") }
            try await s.approve(request)
        case "revoke": try await s.revoke(memberID: text("member"))
        case "write":
            try await s.perform(DomainCommand(namespace: "reading.saved", kind: "capture", payloadJSON: data("payload")), observed: s.observedRevision)
        case "ledger": return try JSONSerialization.jsonObject(with: await s.ledger())
        case "read": return try await s.query(namespace: "reading.saved", name: "read", arguments: Data("{}".utf8)).base64EncodedString()
        case "putBlob":
            let b = try await s.putBlob(data("bytes"), namespace: "reading.saved", mediaType: "application/octet-stream", reference: text("reference"), required: c["required"] as! Bool)
            return b.digest
        case "availability":
            let a = await s.blobAvailability(namespace: "reading.saved", digest: text("digest"))
            return a == .available ? "available" : "missing"
        case "blob": return try await s.blobData(namespace: "reading.saved", digest: text("digest")).base64EncodedString()
        case "prefetch": try await s.prefetchBlob(namespace: "reading.saved", digest: text("digest"))
        case "propose": return try await s.proposeTransition(text("change"))
        case "veto": try await s.veto(text("digest"))
        case "transfer":
            let sealed = try await s.transferSeed(pairing: pairing!)
            return ["enc": sealed.enc.base64EncodedString(), "ciphertext": sealed.ciphertext.base64EncodedString()]
        case "accept":
            try await s.acceptSeedTransfer(key: transferKey!, pairing: pairing!, sealed: SealedSeed(enc: data("enc"), ciphertext: data("ciphertext")), label: "Swift paired owner")
        case "checkpoint": try await s.flushCheckpoint()
        case "lock": try await s.flushCheckpoint(); await s.lock()
        case "state": break
        default: throw DriverError.invalid("unknown operation")
        }
        s.stopSync()
        return await state()
    }
}
