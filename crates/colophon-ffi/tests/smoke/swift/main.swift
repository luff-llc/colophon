// Swift smoke test over the generated typed 0.5 bindings. See ../README.md for how to run it.
import CryptoKit
import Foundation

func fresh(_ n: Int) -> Data { Data((0..<n).map { _ in UInt8.random(in: 0...255) }) }
struct NotAnAccountError: Error {}

final class ThrowingSource: HostSource, @unchecked Sendable {
    func read(path: String) throws -> Data { throw NotAnAccountError() }
    func readBlob(path: String) throws -> Data { Data() }
}
final class MemSource: HostSource, @unchecked Sendable {
    var files: [String: Data] = [:]
    func read(path: String) throws -> Data {
        guard let d = files[path] else { throw AccountError.Host(code: "host", detail: "missing \(path)") }
        return d
    }
    func readBlob(path: String) throws -> Data { files[path] ?? Data() }
}
var failures = 0
@MainActor func check(_ ok: Bool, _ what: String) {
    print((ok ? "PASS " : "FAIL ") + what)
    if !ok { failures += 1 }
}
let empty = SavedState(verifier: Data(), checkpoint: Data(), parts: [])

// 1. A plain call and a typed error.
check(try accountDefaultPolicy().contains("recoveryDelay"), "accountDefaultPolicy returns the policy document")
do {
    _ = try AccountCreation.begin(
        params: CreateParams(label: "x", namespaces: [], controllers: [], slots: [], threshold: nil,
            recoverThreshold: nil, addThreshold: nil, countByHolders: false, policyJson: "", signers: [], rekeySigners: []),
        identity: AccountIdentity(kind: .controller, id: "00"), nowMs: 0, entropy: Data([1]))
    check(false, "short entropy refused")
} catch AccountError.Bound(let code, _) {
    check(code == "bound", "short entropy is AccountError.Bound(code: bound)")
}

// 2. Create an account with CryptoKit P-256 keys: typed steps in, typed signatures out.
let signing = P256.Signing.PrivateKey()
let agreement = P256.KeyAgreement.PrivateKey()
let id = try accountKeyId(signing: signing.publicKey.x963Representation)
func rawController(_ s: P256.Signing.PrivateKey, _ a: P256.KeyAgreement.PrivateKey, _ label: String, _ roles: [ControllerRole]) -> ControllerSpec {
    ControllerSpec(
        key: KeyDescriptorView(form: .raw, signing: s.publicKey.x963Representation, agreement: a.publicKey.x963Representation,
            rp: nil, credential: nil, origins: [], authorityOrigins: []),
        label: label, roles: roles, verification: false, holder: nil, audiences: [])
}
let controller = rawController(signing, agreement, "Mac", [.approve, .control])
let second = P256.Signing.PrivateKey()
let secondAgree = P256.KeyAgreement.PrivateKey()
let secondId = try accountKeyId(signing: second.publicKey.x963Representation)
let laptop = rawController(second, secondAgree, "Laptop", [.approve])
let now = Int64(Date().timeIntervalSince1970 * 1000)
func sign(_ steps: [AccountSigningStep]) -> [Signature] {
    steps.map { st in
        let key = st.signer == secondId ? second : signing
        return Signature(signature: try! key.signature(for: st.body).rawRepresentation, authenticatorData: nil, clientData: nil)
    }
}
let params = CreateParams(label: "Swift smoke", namespaces: ["notes"], controllers: [controller],
    slots: [SlotPlan(controllers: [id], label: "Mac")], threshold: nil, recoverThreshold: nil, addThreshold: nil,
    countByHolders: false, policyJson: "", signers: [id], rekeySigners: [id])
let creation = try AccountCreation.begin(params: params, identity: AccountIdentity(kind: .controller, id: id), nowMs: now, entropy: fresh(96))
var rounds = 0
while true {
    rounds += 1
    if try creation.provideSignatures(signatures: sign(try creation.steps())) == .done { break }
}
check(rounds == 2, "creation finished in two rounds")
let created = try creation.takeResult()
check(created.account.count == 64, "account id is 64 hex")

// 3. An engine over a Swift record source; the typed error of a callback that throws something else.
let src = MemSource()
for s in created.stores { src.files[s.path] = s.bytes }
let listing = src.files.keys.sorted().map { ListedPath(path: $0, version: nil) }
let engine = try AccountEngine.open(source: src, listing: listing, identity: AccountIdentity(kind: .controller, id: id), account: created.account,
    namespaces: [], batch: 0, saved: empty, key: fresh(32), nowMs: now)
check(try engine.openInfo().mode == .cold, "engine opens over a Swift source (OpenMode enum)")
let slot = try engine.slots()[0]
let inputs = try engine.beginUnlockSlot(index: slot.index)
check(inputs.count == 1 && inputs[0].kind == .ecdh, "the slot asks for one ECDH")
// The host answers the ECDH with its own agreement key.
let peer = try P256.KeyAgreement.PublicKey(x963Representation: inputs[0].enc)
let shared = try agreement.sharedSecretFromKeyAgreement(with: peer).withUnsafeBytes { Data($0) }
_ = try engine.finishUnlockSlot(index: slot.index, secrets: [UnlockSecret(kind: .ecdh, secret: shared)])
check(try engine.isUnlocked(), "the engine unlocks from the host's ECDH result")
check(try engine.status().kind == .ok && (try engine.controllers().count) == 1, "typed status and controllers")
check(try engine.controllers()[0].roles == [.approve, .control] && (try engine.identity().kind) == .controller, "roles and identity are enums")
check(try action0IsTyped(engine), "an action's kind is an enum")

func action0IsTyped(_ e: AccountEngine) throws -> Bool {
    let a = try e.beginRekey(namespaces: ["notes"], signers: [id], entropy: fresh(32))
    return try a.kind() == .rekey
}
// 4. An action through begin and finish, and a replay refused.
let action = try engine.beginAddController(controller: laptop, mode: .immediate, signers: [id], rule: .control, entropy: Data())
let steps = try action.steps()
check(steps.count == 2 && steps.contains { $0.role == .possession }, "typed steps: a primary and a possession proof")
let sigs = sign(steps)
let written = try engine.finish(action: action, signatures: sigs)
check(!written.stores.isEmpty && written.changes.controllersAdded == [secondId], "finish returns typed stores and changes")
do {
    _ = try engine.finish(action: action, signatures: sigs)
    check(false, "replay refused")
} catch AccountError.Consumed(let code, _) {
    check(code == "consumed", "replay is AccountError.Consumed")
}

// 4b. The calls the engine forwards: a due-transition pass, then pairing, seed transfer and lock.
for st in written.stores { src.files[st.path] = st.bytes }
check(try engine.recordDue().isEmpty, "recordDue: nothing is due")
let src2 = MemSource()
src2.files = src.files
let listing2 = src2.files.keys.sorted().map { ListedPath(path: $0, version: nil) }
let engine2 = try AccountEngine.open(source: src2, listing: listing2, identity: AccountIdentity(kind: .controller, id: secondId), account: created.account,
    namespaces: [], batch: 0, saved: empty, key: fresh(32), nowMs: now)
let tkey = try PairingTransferKey.create(entropy: fresh(32))
let joiner = try AccountPairing.join(account: created.account, e: tkey.public(), nb: fresh(32))
let limiter = try PairingFailureLimiter.fromState(state: "")
let existing = try AccountPairing.existingReceiveCommitment(account: created.account, commitment: try joiner.commitment(), limiter: limiter, nowMs: now)
let na = try existing.sendNonce(na: fresh(32))
let reveal = try joiner.receiveNonce(na: na)!
let digits = try existing.receiveReveal(e: reveal.e, nb: reveal.nb, limiter: limiter, nowMs: now)
check(digits == (try joiner.digits()), "both devices show the same six digits")
try existing.confirm()
try joiner.confirm()
let sealed = try engine.transferSeed(pairing: existing, entropy: fresh(32))
check(!(try engine2.isUnlocked()), "the second device holds no seed yet")
_ = try engine2.acceptSeedTransfer(key: tkey, pairing: joiner, sealed: sealed)
check(try engine2.isUnlocked(), "the seed transferred through the exports unlocks the second engine")
_ = try engine.lock()
check(try engine.isLocked(), "lock: the engine reports it is locked")
do { _ = try engine.save(nonceSeed: fresh(32)); check(false, "a locked engine saves") }
catch AccountError.Locked(let code, _) { check(code == "locked", "a locked engine refuses to save with AccountError.Locked") }
do { _ = try engine.finish(action: try engine.beginRekey(namespaces: ["notes"], signers: [id], entropy: fresh(32)), signatures: []); check(false, "a locked engine prepares") }
catch AccountError.Locked { check(true, "a locked engine refuses to prepare an action (AccountError.Locked)") }

// 5. A callback that throws a non-AccountError, and one that throws an AccountError with a message.
do {
    _ = try AccountEngine.open(source: ThrowingSource(), listing: listing, identity: AccountIdentity(kind: .controller, id: id), account: created.account,
        namespaces: [], batch: 0, saved: empty, key: fresh(32), nowMs: now)
    check(false, "throwing source refused")
} catch let e as AccountError {
    print("  throwing source -> \(e)")
    if case .Host = e { check(true, "a foreign Swift error from the callback arrives as AccountError.Host") }
    else { check(false, "arrived as \(e), not Host") }
}
do {
    let m = MemSource()
    _ = try AccountEngine.open(source: m, listing: listing, identity: AccountIdentity(kind: .controller, id: id), account: created.account,
        namespaces: [], batch: 0, saved: empty, key: fresh(32), nowMs: now)
    check(false, "missing files refused")
} catch AccountError.Host(_, let detail) {
    check(detail.contains("missing"), "the host's own message reaches the caller: \(detail)")
}

// 6. The successor genesis of a Swift keyring library (the repository's conformance fixture),
// through the export: one passkey assertion rebuilds the passkey's slot and opens the Swift slot.
func b64(_ s: String) -> Data { Data(base64Encoded: s)! }
func b64url(_ d: Data) -> String {
    d.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
}
let repo = ProcessInfo.processInfo.environment["COLOPHON_REPO"] ?? "."
let fixture = "\(repo)/conformance/keyring"
let keysJson = try JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: "\(fixture)/keys.json"))) as! [String: Any]
let expected = try JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: "\(fixture)/expected.json"))) as! [String: Any]
let who = (expected["controllers"] as! [String: String])
let ownerKey = try P256.Signing.PrivateKey(rawRepresentation: b64((keysJson["owner"] as! [String: String])["signingKey"]!))
let passkey = try P256.Signing.PrivateKey(rawRepresentation: b64(keysJson["webauthnScalar"] as! String))
let libDir = "\(fixture)/library/authority"
let entries: [ByteString] = try FileManager.default.contentsOfDirectory(atPath: libDir).sorted().map {
    var d = try Data(contentsOf: URL(fileURLWithPath: "\(libDir)/\($0)"))
    if d.last == 0x0A { d.removeLast() }
    return ByteString(bytes: d)
}
let swiftSource = try SwiftSource.read(entries: entries)
let recoverySecs: Int64 = 3600
let policyDoc = (try JSONSerialization.jsonObject(with: Data(try accountDefaultPolicy().utf8)) as! [String: Any]).merging(["recoveryDelay": recoverySecs]) { _, n in n }
let policyText = String(data: try JSONSerialization.data(withJSONObject: policyDoc), encoding: .utf8)!
let successor = try SwiftSuccessorCreation.begin(
    source: swiftSource,
    params: SwiftSuccessorParams(label: "Library", namespaces: ["reading.saved"], includeStewards: false,
        authorityOrigins: [OriginsFor(controller: who["webauthn"]!, origins: ["https://id.luff.works"])], agreements: [],
        threshold: 1, recoverThreshold: 1, addThreshold: 1, countByHolders: false, policyJson: policyText,
        signers: [who["owner"]!], handover: [who["owner"]!], issuedMs: now - 60_000, earlierAttempts: []),
    nowMs: now, entropy: fresh(64))
check(try successor.stage() == .prf, "the successor genesis asks for a passkey ceremony first")
let ceremonies = try successor.ceremonies()
let requests = try successor.prfRequests()
let unpaired = try successor.unpaired()
check(ceremonies.count == 1 && requests.count == 1 && ceremonies[0].userVerification && unpaired.isEmpty,
      "one passkey, one ceremony: one assertion rebuilds the slot and opens the Swift slot")
let cer = ceremonies[0]
// The one assertion: authenticator data with UP and UV, the client data over the core's challenge.
var authData = Data(SHA256.hash(data: Data(cer.rp.utf8)))
authData.append(contentsOf: [0x05, 0, 0, 0, 0])
let clientData = Data("{\"challenge\":\"\(b64url(cer.challenge))\",\"origin\":\"https://\(cer.rp)\",\"type\":\"webauthn.get\"}".utf8)
let assertionSig = try passkey.signature(for: authData + Data(SHA256.hash(data: clientData))).derRepresentation
try successor.providePrf(results: [PrfAnswer(authenticatorData: authData, clientData: clientData, signature: assertionSig,
    output: Data(SHA256.hash(data: cer.newSalt)))])
// The same assertion's second output opens the Swift slot.
try swiftSource.finishOpenSlot(index: cer.oldSlot, secrets: [UnlockSecret(kind: .prf, secret: b64(keysJson["prfOutput"] as! String))])
check(try swiftSource.openNamespaceKeys() >= 1, "the Swift vault opened by the second output of the same assertion")
let successorSteps = try successor.steps()
check(successorSteps.map { $0.role } == [.primary, .handover], "the genesis and the handover are the steps")
check(try successor.provideSignatures(signatures: successorSteps.map {
    Signature(signature: try! ownerKey.signature(for: $0.body).rawRepresentation, authenticatorData: nil, clientData: nil) }) == .done,
    "the successor genesis is signed and checked")
let moved = try successor.takeResult()
check(moved.stores.contains { $0.path == "authority/00000001.json" } && moved.stores.contains { $0.path.hasPrefix("predecessor/authority/") },
      "the genesis and the predecessor entries are handed back to store")
let moveSrc = MemSource()
for s in moved.stores { moveSrc.files[s.path] = s.bytes }
let moveEngine = try AccountEngine.open(source: moveSrc, listing: moveSrc.files.keys.sorted().map { ListedPath(path: $0, version: nil) },
    identity: AccountIdentity(kind: .controller, id: who["owner"]!), account: moved.account, namespaces: [], batch: 0, saved: empty,
    key: fresh(32), nowMs: now)
check(try moveEngine.swiftSuccession().stage == .windowNotOpen, "the successor reports the Swift succession (stage WindowNotOpen)")
do { _ = try moveEngine.beginSwiftFreeze(signers: [who["owner"]!], issuedMs: now, earlierAttempts: []); check(false, "F before the due time") }
catch is AccountError { check(true, "F is refused before the succession is due (a typed AccountError; earlierAttempts is an argument)") }
check(accountMapSwiftRole(role: "service") == .server && accountMapSwiftRole(role: "web") == .app && accountMapSwiftRole(role: "robot") == nil,
      "the Swift role to member kind map is exported")
check(try engine2.controllers()[0].key.signing.count == 65, "a controller carries its key descriptor")
print(failures == 0 ? "ALL PASS" : "\(failures) FAILED")
exit(failures == 0 ? 0 : 1)
