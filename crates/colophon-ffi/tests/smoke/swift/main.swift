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
        params: CreateParams(label: "x", namespaces: [], controllersJson: [], slots: [], threshold: nil,
            recoverThreshold: nil, addThreshold: nil, countByHolders: false, policyJson: "", signers: [], rekeySigners: []),
        identity: "controller:00", nowMs: 0, entropy: Data([1]))
    check(false, "short entropy refused")
} catch AccountError.Bound(let code, _) {
    check(code == "bound", "short entropy is AccountError.Bound(code: bound)")
}

// 2. Create an account with CryptoKit P-256 keys: typed steps in, typed signatures out.
let signing = P256.Signing.PrivateKey()
let agreement = P256.KeyAgreement.PrivateKey()
let id = try accountKeyId(signing: signing.publicKey.x963Representation)
let controller = """
{"key":{"form":"raw","signing":"\(signing.publicKey.x963Representation.base64EncodedString())","agreement":"\(agreement.publicKey.x963Representation.base64EncodedString())"},"label":"Mac","roles":["approve","control"]}
"""
let second = P256.Signing.PrivateKey()
let secondAgree = P256.KeyAgreement.PrivateKey()
let secondId = try accountKeyId(signing: second.publicKey.x963Representation)
let laptop = """
{"key":{"form":"raw","signing":"\(second.publicKey.x963Representation.base64EncodedString())","agreement":"\(secondAgree.publicKey.x963Representation.base64EncodedString())"},"label":"Laptop","roles":["approve"]}
"""
let now = Int64(Date().timeIntervalSince1970 * 1000)
func sign(_ steps: [AccountSigningStep]) -> [Signature] {
    steps.map { st in
        let key = st.signer == secondId ? second : signing
        return Signature(signature: try! key.signature(for: st.body).rawRepresentation, authenticatorData: nil, clientData: nil)
    }
}
let params = CreateParams(label: "Swift smoke", namespaces: ["notes"], controllersJson: [controller],
    slots: [SlotPlan(controllers: [id], label: "Mac")], threshold: nil, recoverThreshold: nil, addThreshold: nil,
    countByHolders: false, policyJson: "", signers: [id], rekeySigners: [id])
let creation = try AccountCreation.begin(params: params, identity: "controller:\(id)", nowMs: now, entropy: fresh(96))
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
let listing = src.files.keys.sorted().map { ListedPath(path: $0, version: "") }
let engine = try AccountEngine.open(source: src, listing: listing, identity: "controller:\(id)", account: created.account,
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
check(try engine.status().code == "ok" && (try engine.controllers().count) == 1, "typed status and controllers")

// 4. An action through begin and finish, and a replay refused.
let action = try engine.beginAddController(controllerJson: laptop, mode: .immediate, signers: [id], rule: .control, entropy: Data())
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

// 5. A callback that throws a non-AccountError, and one that throws an AccountError with a message.
do {
    _ = try AccountEngine.open(source: ThrowingSource(), listing: listing, identity: "controller:\(id)", account: created.account,
        namespaces: [], batch: 0, saved: empty, key: fresh(32), nowMs: now)
    check(false, "throwing source refused")
} catch let e as AccountError {
    print("  throwing source -> \(e)")
    if case .Host = e { check(true, "a foreign Swift error from the callback arrives as AccountError.Host") }
    else { check(false, "arrived as \(e), not Host") }
}
do {
    let m = MemSource()
    _ = try AccountEngine.open(source: m, listing: listing, identity: "controller:\(id)", account: created.account,
        namespaces: [], batch: 0, saved: empty, key: fresh(32), nowMs: now)
    check(false, "missing files refused")
} catch AccountError.Host(_, let detail) {
    check(detail.contains("missing"), "the host's own message reaches the caller: \(detail)")
}
print(failures == 0 ? "ALL PASS" : "\(failures) FAILED")
exit(failures == 0 ? 0 : 1)
