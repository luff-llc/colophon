import ColophonKit
import Foundation
import CryptoKit
import Testing

/// Replay exact public software-credential results through the generated UniFFI surface.
struct Keys04Tests {
    @Test func keyringJourney() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let fixtureURL = ProcessInfo.processInfo.environment["COLOPHON_W5_FIXTURE"].map { URL(fileURLWithPath: $0) } ?? root.appendingPathComponent("crates/colophon-ffi/tests/keys-flow.json")
        let fixture = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: fixtureURL)) as? [String: Any])
        func data(_ value: Any) -> Data { Data((value as! [NSNumber]).map(\.uint8Value)) }
        func encoded(_ value: Any) throws -> Data { try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) }
        func keys(_ name: String) -> PublicKeys {
            let value = fixture[name] as! [String: String]
            return PublicKeys(signing: Data(base64Encoded: value["signing"]!)!, agreement: Data(base64Encoded: value["agreement"]!)!)
        }
        let stages = fixture["stages"] as! [[String: Any]]
        var cursor = 0
        func stage(_ name: String) -> [String: Any] {
            let value = stages[cursor]; cursor += 1
            #expect(value["name"] as? String == name)
            return value
        }
        func signatures(_ action: HostAction, _ name: String) -> [SignatureResult] {
            let expected = stage(name)["signing"] as! [[String: Any]]
            #expect(action.signingSteps().count == expected.count)
            return zip(action.signingSteps(), expected).map { step, value in
                #expect(step.body == data(value["body"]!))
                let signature = data(value["signature"]!)
                let assertion = (value["assertion"] as? [String: Any]).map { a in
                    WebauthnResult(signature: signature, authenticatorData: data(a["authenticatorData"]!), clientData: data(a["clientData"]!), prf: nil)
                }
                return SignatureResult(signature: signature, assertion: assertion)
            }
        }
        func repeated(_ byte: UInt8) -> Data { Data(repeating: byte, count: 32) }
        let now = fixture["now"] as! String
        let owner = keys("owner"), member = keys("member")
        let first = try beginCreate(owner: member, controller: owner, vaultSeed: repeated(21), label: "Keys", ownerLabel: "Device", namespaces: ["notes"], now: now, entropy: repeated(22))
        let final = try first.advanceCreate(signatures: signatures(first, "create").map(\.signature))
        let records = try final.finishAuthority(results: signatures(final, "createFinal"))
        let lib = try NativeLibrary.open(records: records, me: member)
        let openings = fixture["openings"] as! [String: [[NSNumber]]]
        func unlock(_ session: NativeLibrary, _ name: String, _ id: String) throws {
            let option = try session.beginUnlockSlots().first { option in
                option.inputs.allSatisfy { input in if case .ecdh(let controller, _) = input { controller == id } else { false } }
            }!
            _ = try session.finishUnlockSlot(option: option, secrets: openings[name]!.map { .ecdh(secret: data($0)) })
        }
        func controllerID(_ value: [String: Any]) -> String {
            let key = value["key"] as! [String: Any]
            return SHA256.hash(data: Data(base64Encoded: key["signing"] as! String)!).prefix(16)
                .map { String(format: "%02x", $0) }.joined()
        }
        let initial = try JSONSerialization.jsonObject(with: lib.keyring()) as! [String: Any]
        let ownerID = ((initial["slots"] as! [[String: Any]])[0]["controllers"] as! [String])[0]
        try unlock(lib,"owner",ownerID)
        let passkey = fixture["passkey"] as! [String: Any]
        #expect(try JSONSerialization.jsonObject(with: parseRegistration(attestationObject: data(fixture["registration"]!), rp: "id.luff.works")) as? NSDictionary == passkey["key"] as? NSDictionary)
        func prf(_ newSeed: Data?, _ byte: UInt8) throws -> Data {
            let pending = try lib.beginPrfSlot(descriptor: encoded(passkey["key"]!), entropy: repeated(byte))
            let value = stage("prf")
            #expect(pending.challenge() == value["challenge"] as? String)
            #expect(pending.salt() == data(value["salt"]!))
            return try lib.finishPrfSlot(action: pending, result: WebauthnResult(signature: data(value["signature"]!), authenticatorData: data(value["authenticatorData"]!), clientData: data(value["clientData"]!), prf: data(value["output"]!)), label: "Passkey", newSeed: newSeed, entropy: repeated(byte+1))
        }
        func commit(_ session: NativeLibrary, _ action: HostAction, _ name: String) throws { _ = try session.finishAuthority(action: action, results: signatures(action,name)) }
        let passkeySlot = try prf(nil,31)
        try commit(lib,lib.beginAddPasskey(controller: encoded(passkey), slot: passkeySlot, signers: [ownerID], now: now),"addPasskey")
        let reopened = try NativeLibrary.open(records: lib.records(), me: member)
        let option = try reopened.beginUnlockSlots().first { $0.inputs.contains { if case .prf = $0 { true } else { false } } }!
        _ = try reopened.finishUnlockSlot(option: option, secrets: [.prf(output: repeated(71))])
        let recovery = fixture["recovery"] as! [String: Any]
        let recoverySlot = try lib.buildSealedSlot(controller: encoded(recovery), label: "Recovery", newSeed: nil, entropy: repeated(33))
        var ring = try JSONSerialization.jsonObject(with: lib.keyring()) as! [String: Any]
        var controllers = ring["controllers"] as! [[String: Any]]; controllers.append(recovery)
        controllers.sort { controllerID($0) < controllerID($1) }
        ring["controllers"] = controllers; ring["recoverThreshold"] = 1
        var slots = ring["slots"] as! [Any]; slots.append(try JSONSerialization.jsonObject(with: recoverySlot)); ring["slots"] = slots
        try commit(lib,lib.beginKeyring(keyring: encoded(ring), newSeed: nil, signers: [ownerID], now: now, entropy: repeated(34)),"enableRecovery")
        let rotated = try prf(repeated(41),35)
        let recoveryRotated = try lib.buildSealedSlot(controller: encoded(recovery), label: "Recovery", newSeed: repeated(41), entropy: repeated(37))
        try commit(lib,lib.beginRemoveController(id: ownerID,newSeed: repeated(41),slots: [rotated,recoveryRotated],signers: [ownerID],now: now,entropy: repeated(38)),"removeDevice")
        let recovering = try NativeLibrary.open(records: lib.records(),me: member)
        let recoveryID = controllerID(recovery)
        try unlock(recovering,"recovery",recoveryID)
        let added = fixture["added"] as! [String: Any]
        let addedSlot = try recovering.buildSealedSlot(controller: encoded(added),label: "Replacement",newSeed: nil,entropy: repeated(39))
        try commit(recovering,recovering.beginRecoveryAdd(controller: encoded(added),slot: addedSlot,signers: [recoveryID],now: now),"recoveryAdd")
        let passkeyID = controllerID(passkey)
        try commit(recovering,recovering.prepareAuthority(action: encoded(["kind":"layout","layout":2]),by: passkeyID,signers: [passkeyID],now: now),"passkeyLayout")
        let expected = fixture["records"] as! [String: [NSNumber]]
        #expect(try recovering.records() == expected.mapValues { data($0) })
        #expect(cursor == stages.count)
    }
}
