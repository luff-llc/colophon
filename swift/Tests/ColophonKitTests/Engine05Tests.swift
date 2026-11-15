import CryptoKit
import Foundation
import Testing
@testable import ColophonKit

/// A device key and the controller descriptor of it, as the smoke program makes them.
private final class Account: @unchecked Sendable {
    let signing = P256.Signing.PrivateKey()
    let agreement = P256.KeyAgreement.PrivateKey()
    var id: String { (try? accountKeyId(signing: signing.publicKey.x963Representation)) ?? "" }
    let files = Files()
    var accountID = ""
    let now = Int64(Date().timeIntervalSince1970 * 1000)
    var spec: ControllerSpec {
        ControllerSpec(key: KeyDescriptorView(form: .raw, signing: signing.publicKey.x963Representation, agreement: agreement.publicKey.x963Representation,
                       rp: nil, credential: nil, origins: [], authorityOrigins: []), label: "Mac", roles: [.approve, .control], verification: false, holder: nil, audiences: [])
    }
    init() throws {
        let params = CreateParams(label: "T", namespaces: ["notes"], controllers: [spec], slots: [SlotPlan(controllers: [id], label: "Mac")],
            threshold: nil, recoverThreshold: nil, addThreshold: nil, countByHolders: false, policyJson: "", signers: [id], rekeySigners: [id])
        let creation = try AccountCreation.begin(params: params, identity: AccountIdentity(kind: .controller, id: id), nowMs: now, entropy: Data((0..<96).map { UInt8($0) }))
        while try creation.provideSignatures(signatures: try creation.steps().map { try sign($0) }) != .done {}
        let created = try creation.takeResult()
        accountID = created.account
        for store in created.stores { files.put(store.path, store.bytes) }
    }
    func sign(_ step: AccountSigningStep) throws -> Signature {
        Signature(signature: try signing.signature(for: step.body).rawRepresentation, authenticatorData: nil, clientData: nil)
    }
    func openRaw(source: (any HostSource)? = nil, key: Data = Data(repeating: 9, count: 32)) throws -> AccountEngine {
        try AccountEngine.open(source: source ?? files, listing: files.listing(), identity: AccountIdentity(kind: .controller, id: id), account: accountID,
                               namespaces: [], batch: 0, saved: SavedState(verifier: Data(), checkpoint: Data(), parts: []), key: key, nowMs: now)
    }
    func unlock(_ engine: AccountEngine) throws {
        let slot = try engine.slots()[0]
        let inputs = try engine.beginUnlockSlot(index: slot.index)
        let shared = try agreement.sharedSecretFromKeyAgreement(with: try P256.KeyAgreement.PublicKey(x963Representation: inputs[0].enc)).withUnsafeBytes { Data($0) }
        _ = try engine.finishUnlockSlot(index: slot.index, secrets: [UnlockSecret(kind: .ecdh, secret: shared)])
    }
}
private final class Files: HostSource, @unchecked Sendable {
    private let lock = NSLock()
    private var map: [String: Data] = [:]
    var mode = 0 // 0 honest, 1 garbage, 2 throws
    var onRead: (@Sendable () -> Void)?
    func put(_ path: String, _ bytes: Data) { lock.withLock { map[path] = bytes } }
    func listing() -> [ListedPath] { lock.withLock { map.keys.sorted().map { ListedPath(path: $0, version: nil) } } }
    func read(path: String) throws -> Data {
        onRead?()
        switch mode {
        case 1: return Data(repeating: 0xff, count: 17)
        case 2: throw ColophonTestFailure.disk
        default: return try lock.withLock { guard let bytes = map[path] else { throw ColophonTestFailure.missing(path) }; return bytes }
        }
    }
    func readBlob(path: String) throws -> Data { lock.withLock { map[path] ?? Data() } }
}
private enum ColophonTestFailure: Error { case disk, missing(String) }

struct Engine05Tests {
    @Test func everyBindingErrorIsATypedSwiftError() {
        let cases: [(AccountError, (ColophonError) -> Bool)] = [
            (.Malformed(code: "malformed", detail: "d"), { if case .malformed = $0 { true } else { false } }),
            (.BadSignature(code: "badSignature:origin", check: .origin, detail: "d"), { if case .badSignature(_, let c, _) = $0 { c == .origin } else { false } }),
            (.NewerFormat(code: "newerFormat", detail: "d"), { $0.isNewerFormat }),
            (.Unavailable(code: "unavailable", detail: "d"), { if case .unavailable = $0 { true } else { false } }),
            (.Refused(code: "refused:fork", reason: "fork", detail: "d"), { $0.reason == "fork" && $0.code == "refused:fork" }),
            (.Denied(code: "denied:revoked", reason: .revoked, reasonRaw: nil, detail: "d"), { if case .denied(_, let r, _, _) = $0 { r == .revoked } else { false } }),
            (.Host(code: "host", detail: "d"), { if case .host = $0 { true } else { false } }),
            (.Reentered(code: "reentered", detail: "d"), { if case .reentered = $0 { true } else { false } }),
            (.Consumed(code: "consumed", detail: "d"), { if case .consumed = $0 { true } else { false } }),
            (.WrongObject(code: "wrongObject", detail: "d"), { if case .wrongObject = $0 { true } else { false } }),
            (.Bound(code: "bound", detail: "d"), { if case .bound = $0 { true } else { false } }),
            (.Integrity(code: "integrity", detail: "d"), { if case .integrity = $0 { true } else { false } }),
            (.Locked(code: "locked", detail: "d"), { if case .locked = $0 { true } else { false } }),
            (.Internal(code: "internal", detail: "d"), { if case .internalFailure = $0 { true } else { false } }),
        ]
        for (error, check) in cases {
            let typed = ColophonError(error)
            #expect(check(typed), "\(error) became \(typed)")
            #expect(typed.code == ColophonError.wrap(error).codeOrEmpty)
        }
        struct Foreign: Error {}
        #expect(ColophonError.wrap(Foreign()) is Foreign, "an error that is not the engine's is left alone")
    }

    @Test func realRefusalsArriveAsTheRightErrors() async throws {
        let account = try Account()
        // Bound: entropy of the wrong length.
        #expect(throws: AccountError.self) {
            _ = try AccountCreation.begin(params: CreateParams(label: "x", namespaces: [], controllers: [], slots: [], threshold: nil, recoverThreshold: nil,
                addThreshold: nil, countByHolders: false, policyJson: "", signers: [], rekeySigners: []), identity: AccountIdentity(kind: .controller, id: account.id), nowMs: 0, entropy: Data([1]))
        }
        let engine = try await ColophonEngine.open(source: account.files, listing: account.files.listing(), identity: AccountIdentity(kind: .controller, id: account.id),
            account: account.accountID, deviceKey: Data.secret(Data(repeating: 9, count: 32)), nowMs: account.now)
        let slot = try await engine.run { try $0.slots() }[0]
        let inputs = try await engine.run { try $0.beginUnlockSlot(index: slot.index) }
        let custody = try await KeyCustody([SoftwareKeysAdapter(account)])
        let secrets = try await custody.answer(unlock: inputs)
        _ = try await engine.run { try $0.finishUnlockSlot(index: slot.index, secrets: secrets) }
        // Bound: a write needs exactly 32 bytes of entropy.
        do { _ = try await engine.run { try $0.beginWrite(namespace: "notes", kind: "createNotebook", payloadJson: "{}", entropy: Data([1])) }; Issue.record("bound") }
        catch let error as ColophonError { if case .bound = error {} else { Issue.record("expected bound, got \(error)") } }
        // Consumed: finishing a finished action again.
        let action = try await engine.run { try $0.beginRekey(namespaces: ["notes"], signers: [account.id], entropy: try colophonEntropy(32)) }
        let steps = try action.steps()
        let signatures = try steps.map { try account.sign($0) }
        _ = try await engine.run { try $0.finish(action: action, signatures: signatures) }
        do { _ = try await engine.run { try $0.finish(action: action, signatures: signatures) }; Issue.record("replay") }
        catch let error as ColophonError { if case .consumed = error {} else { Issue.record("expected consumed, got \(error)") } }
        // BadSignature: a signature over other bytes.
        let other = try await engine.run { try $0.beginRekey(namespaces: ["notes"], signers: [account.id], entropy: try colophonEntropy(32)) }
        let bad = Signature(signature: try account.signing.signature(for: Data("not the body".utf8)).rawRepresentation, authenticatorData: nil, clientData: nil)
        do { _ = try await engine.run { try $0.finish(action: other, signatures: [bad]) }; Issue.record("bad signature") }
        catch let error as ColophonError { if case .badSignature = error {} else { Issue.record("expected badSignature, got \(error)") } }
        // WrongObject: an action of this engine finished on another.
        let elsewhere = try account.openRaw()
        let foreign = try await engine.run { try $0.beginRekey(namespaces: ["notes"], signers: [account.id], entropy: try colophonEntropy(32)) }
        do { _ = try elsewhere.finish(action: foreign, signatures: []); Issue.record("wrong object") }
        catch let error as AccountError { if case .WrongObject = error {} else { Issue.record("expected wrongObject, got \(error)") } }
        // Locked: after lock(), nothing prepares and the typed error is `.locked`.
        await engine.lock()
        #expect(await engine.isLocked)
        do { _ = try await engine.run { try $0.beginRekey(namespaces: ["notes"], signers: [account.id], entropy: try colophonEntropy(32)) }; Issue.record("locked") }
        catch let error as ColophonError { if case .locked = error {} else { Issue.record("expected locked, got \(error)") } }
    }

    // MARK: A hostile host

    @Test func aRecordSourceThatThrowsReturnsGarbageOrReentersGivesTypedErrorsNotCrashes() async throws {
        let account = try Account()
        // Throwing: the host's own failure arrives as `.host` with the host's message.
        account.files.mode = 2
        do { _ = try await ColophonEngine.open(source: account.files, listing: account.files.listing(), identity: AccountIdentity(kind: .controller, id: account.id),
            account: account.accountID, deviceKey: Data.secret(Data(repeating: 9, count: 32)), nowMs: account.now)
            // An open may not read; the first read happens at unlock.
            let engine = try account.openRaw()
            _ = try engine.slots(); try account.unlock(engine); Issue.record("a throwing source unlocked") }
        catch let error as AccountError { if case .Host = error {} else { _ = ColophonError(error) } }
        catch let error as ColophonError { if case .host = error {} else { _ = error } }
        // Garbage: wrong bytes are judged by the core, never accepted.
        account.files.mode = 1
        do { let engine = try account.openRaw(); try account.unlock(engine); Issue.record("garbage unlocked an engine") }
        catch let error as AccountError { _ = ColophonError(error) }
        // Re-entrant: a callback that calls the engine that is calling it fails at once with `.reentered`; no deadlock.
        account.files.mode = 0
        let holder = EngineHolder()
        let seen = ErrorBox()
        account.files.onRead = { do { _ = try holder.engine?.refresh(listing: []) } catch { seen.set(error) } }
        let engine = try account.openRaw()
        holder.engine = engine
        try account.unlock(engine)
        // A new path in scope makes the engine read it: the callback runs inside the engine's own call.
        account.files.put("ops/" + String(repeating: "a", count: 32) + "/notes/000000000001-" + String(repeating: "b", count: 32) + ".json", Data("junk".utf8))
        _ = try engine.refresh(listing: account.files.listing())
        account.files.onRead = nil
        guard let inner = seen.error as? AccountError, case .Reentered = inner else { Issue.record("expected the re-entrant call to be .Reentered, got \(String(describing: seen.error))"); return }
        #expect(try engine.isUnlocked(), "the outer call still completed")
    }

    // MARK: Secrets

    @Test func secretRecordsNeverPrintTheirBytesAndWipeClearsAValue() {
        let answer = PrfAnswer(authenticatorData: Data([1]), clientData: Data([2]), signature: Data([3]), output: Data.secret([0xde, 0xad, 0xbe, 0xef]))
        for text in [String(describing: answer), String(reflecting: answer), { var out = ""; dump(answer, to: &out); return out }()] {
            #expect(!text.contains("222") && !text.lowercased().contains("deadbeef") && !text.contains("deadbeef"), "no secret in \(text)")
        }
        #expect(String(describing: UnlockSecret(kind: .ecdh, secret: Data.secret([9, 9]))) == "UnlockSecret(redacted)")
        #expect(String(describing: EpochAnswer(namespace: "n", epoch: 1, shared: Data.secret([9, 9]))) == "EpochAnswer(redacted)")
        var value = Data.secret([1, 2, 3, 4])
        value.wipe()
        #expect(value.isEmpty)
        #expect(ColophonError(AccountError.Host(code: "host", detail: "disk")).localizedDescription == "host: disk")
    }
}

private extension Error { var codeOrEmpty: String { (self as? ColophonError)?.code ?? "" } }
private final class EngineHolder: @unchecked Sendable { var engine: AccountEngine? }
private final class ErrorBox: @unchecked Sendable { private let lock = NSLock(); private var value: (any Error)?
    func set(_ e: any Error) { lock.withLock { value = e } }
    var error: (any Error)? { lock.withLock { value } } }
/// The test account's agreement key as an `AsyncKeyProvider`.
private struct SoftwareKeysAdapter: AsyncKeyProvider {
    let account: Account
    init(_ account: Account) { self.account = account }
    func publicKeys() async throws -> PublicKeys { PublicKeys(signing: account.signing.publicKey.x963Representation, agreement: account.agreement.publicKey.x963Representation) }
    func sign(body: Data) async throws -> Data { try account.signing.signature(for: body).rawRepresentation }
    func agree(peer: Data) async throws -> Data {
        try account.agreement.sharedSecretFromKeyAgreement(with: try P256.KeyAgreement.PublicKey(x963Representation: peer)).withUnsafeBytes { Data($0) }
    }
}
