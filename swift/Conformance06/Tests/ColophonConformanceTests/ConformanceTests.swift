import Foundation
import Testing
@testable import ColophonConformanceBindings

/// The 0.6 session conformance vectors replayed from Swift through the conformance crate's artifact, as
/// `crates/colophon-conformance/tests/support/vectors.rs` replays them in Rust and js/test06/conformance.test.ts from
/// JavaScript: every machine transcript (one machine per member, each step's outputs compared in order, restarts from
/// `persisted_json`, the final views and digests) and the wire file (positive frames, scenarios, negative frames). The
/// `offset.json` cases go through the shipping surface's `sessionClockSample` (ColophonHostsTests.ShippingSurfaceTests).
@Suite struct ConformanceTests {
    static let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        .deletingLastPathComponent().deletingLastPathComponent()
    static let dir = root.appendingPathComponent("conformance/0.6-sessions")

    static func read(_ url: URL) throws -> [String: Any] {
        try #require(try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
    }
    static func text(_ value: Any) throws -> String { String(decoding: try JSONSerialization.data(withJSONObject: value, options: [.fragmentsAllowed]), as: UTF8.self) }
    static func unhex(_ t: String) -> Data {
        var out = Data(); var it = t.makeIterator()
        while let a = it.next(), let b = it.next() { out.append(UInt8(String([a, b]), radix: 16) ?? 0) }
        return out
    }
    static func unb64(_ t: String) -> Data { Data(base64Encoded: t) ?? Data() }
    /// The code of a conformance error (`Failed(code, detail)`).
    static func code(_ error: any Error) -> String {
        if case .Failed(let code, _) = error as? ConformanceError { return code }
        return String(describing: error)
    }
    static func thrown(_ run: () throws -> Void) -> String? {
        do { try run(); return nil } catch { return code(error) }
    }
    static func same(_ a: Any?, _ b: Any?) -> Bool {
        switch (a, b) {
        case (nil, nil): true
        case (let a?, let b?): (a as AnyObject).isEqual(b)
        default: false
        }
    }
    static var machineFiles: [String] {
        ((try? FileManager.default.contentsOfDirectory(atPath: dir.path)) ?? []).filter { $0.hasSuffix(".json") }.sorted().filter { name in
            guard let v = try? read(dir.appendingPathComponent(name)) else { return false }
            return v["format"] as? String == "colophon/session-vectors/6"
        }
    }

    @Test func thereAreTwentySixMachineTranscripts() {
        #expect(Self.machineFiles.count == 26)
    }

    @Test(arguments: machineFiles) func everyMachineTranscriptReplays(_ file: String) throws {
        let v = try Self.read(Self.dir.appendingPathComponent(file))
        let policy = try Self.text(try #require(v["policy"]))
        let fixes = try v["fixes"].map(Self.text)
        var machines: [String: ConformanceMachine] = [:], canWrite: [String: Bool] = [:]
        for case let m as [String: Any] in try #require(v["members"] as? [Any]) {
            let id = try #require(m["id"] as? String), write = try #require(m["canWrite"] as? Bool)
            let persisted = m["persisted"].flatMap { $0 is NSNull ? nil : try? Self.text($0) }
            let seed = (m["freshSeed"] as? String).map(Self.unhex)
            machines[id] = try ConformanceMachine(me: id, canWrite: write, policyJson: policy, persistedJson: persisted, fixesJson: fixes, freshSeed: seed)
            canWrite[id] = write
        }
        for (k, item) in try #require(v["steps"] as? [Any]).enumerated() {
            let step = try #require(item as? [String: Any])
            let member = try #require(step["member"] as? String)
            if step["restart"] != nil {
                let persisted = try machines[member]?.persistedJson()
                machines[member] = try ConformanceMachine(me: member, canWrite: canWrite[member] ?? false, policyJson: policy, persistedJson: persisted,
                                                          fixesJson: fixes, freshSeed: nil)
                continue
            }
            let at = try #require(step["at"] as? NSNumber).uint64Value
            let got = try #require(machines[member]).handle(inputJson: try Self.text(try #require(step["input"])), at: at)
            let parsed = try JSONSerialization.jsonObject(with: Data(got.utf8))
            #expect(Self.same(parsed, step["outputs"]), "\(file) step \(k): got \(got)")
        }
        for case let f as [String: Any] in try #require(v["final"] as? [Any]) {
            let member = try #require(f["member"] as? String)
            let m = try #require(machines[member])
            #expect(try m.digest() == f["digest"] as? String, "\(file) final digest")
            #expect(Self.same(try JSONSerialization.jsonObject(with: Data(try m.viewJson().utf8)), f["view"]), "\(file) final view")
        }
    }

    static func members(_ list: [Any], _ ns: String) throws -> [ConformanceMember] {
        try list.map { item in
            let m = try #require(item as? [String: Any])
            return ConformanceMember(signing: unb64(try #require(m["signing"] as? String)), session: try #require(m["session"] as? NSNumber).uint64Value,
                                     expiresMs: nil, records: [ConformanceRecordEntry(namespace: ns, access: m["access"] as? String == "write" ? .write : .read)])
        }
    }
    static func held(_ rx: ConformanceReceiver) throws -> [String] {
        try rx.keys().map { "\($0.member) \($0.key) \(try rx.windowHigh(member: $0.member, key: $0.key).map(String.init) ?? "-")" }
    }

    @Test func theWireFileReplaysPositiveFramesScenariosAndNegativeFrames() throws {
        let v = try Self.read(Self.dir.appendingPathComponent("wire/vectors.json"))
        let account = try #require(v["account"] as? String), ns = try #require(v["namespace"] as? String), cell = try #require(v["cell"] as? String)
        let me = try #require(v["receiver"] as? String)
        let clock = try #require(v["clockMs"] as? NSNumber).int64Value, max = try #require(v["maxPayload"] as? NSNumber).uint64Value
        let keys = try #require(v["epochs"] as? [[String: Any]]).map { ConformanceEpochKey(epoch: ($0["epoch"] as? NSNumber)?.uint64Value ?? 0, key: Self.unhex($0["key"] as? String ?? "")) }
        let table = try ConformanceEpochs(namespace: ns, keys: keys)
        #expect(table.currentEpoch() == 1)
        let view = try ConformanceView(account: account, members: try Self.members(try #require(v["members"] as? [Any]), ns))

        // The session key and the exact delegation body; a changed signature refused, the real one installed.
        let sk = try #require(v["sessionKey"] as? [String: Any])
        let tx = try ConformanceSender(account: account, namespace: ns, cell: cell, me: try #require(sk["member"] as? String),
                                       keyRandom: Self.unhex(try #require(sk["privateKey"] as? String)))
        #expect(try tx.keyId() == sk["id"] as? String)
        let delegation = try #require(v["delegation"] as? [String: Any])
        let body = try tx.delegationBody(session: 0, notBeforeMs: clock, expiresMs: clock + 86_400_000)
        #expect(String(decoding: body, as: UTF8.self) == delegation["body"] as? String)
        let signature = Self.unb64(try #require(delegation["signature"] as? String))
        var forged = signature; forged[forged.startIndex + 5] ^= 1
        #expect(Self.thrown { try tx.install(body: body, signature: forged, view: view, wallMs: clock) } == "session:delegation")
        try tx.install(body: body, signature: signature, view: view, wallMs: clock)

        let rx = ConformanceReceiver(account: account, namespace: ns, cell: cell, me: me)
        let frames = try #require(v["frames"] as? [[String: Any]])
        for f in frames {
            let name = f["name"] as? String ?? "?"
            let r = try rx.open(bytes: Data(try #require(f["frame"] as? String).utf8), view: view, epochs: table, wallMs: clock, maxPayload: max)
            #expect(r.dropped == nil, "\(name): \(r.dropped?.reason ?? "")")
            let o = try #require(r.opened, "\(name)")
            #expect(String(decoding: o.plaintext, as: UTF8.self) == f["plaintext"] as? String, "\(name)")
            #expect(o.writer == f["writer"] as? Bool && o.n == (f["n"] as? NSNumber)?.uint64Value && o.to == f["to"] as? String && o.epoch == 1, "\(name)")
        }

        var steps = 0
        let views = try #require(v["views"] as? [String: Any])
        for sc in try #require(v["scenarios"] as? [[String: Any]]) {
            let scenario = sc["name"] as? String ?? "?"
            let rx2 = ConformanceReceiver(account: account, namespace: ns, cell: cell, me: sc["receiver"] as? String ?? me)
            var current = try ConformanceView(account: account, members: try Self.members(try #require(views["default"] as? [Any]), ns))
            for (k, item) in try #require(sc["steps"] as? [[String: Any]]).enumerated() {
                steps += 1
                let ex = item["expect"] as? [String: Any] ?? [:], what = "\(scenario) step \(k)"
                if let setView = item["setView"] as? String {
                    current = try ConformanceView(account: account, members: try Self.members(try #require(views[setView] as? [Any]), ns))
                    let gone = try rx2.setAccount(view: current, wallMs: clock)
                    #expect(gone.members == (ex["forgottenMembers"] as? [String] ?? []), "\(what)")
                    let closed = (ex["closedKeys"] as? [[String]] ?? []).map { $0.joined(separator: " ") }
                    #expect(gone.keys.map { "\($0.member) \($0.key)" } == closed, "\(what)")
                    continue
                }
                let at = (item["clockMs"] as? NSNumber)?.int64Value ?? clock
                let before = try Self.held(rx2)
                let r = try rx2.open(bytes: Data(try #require(item["open"] as? String).utf8), view: current, epochs: table, wallMs: at, maxPayload: max)
                if let drop = ex["drop"] as? String {
                    #expect(r.dropped?.reason == drop, "\(what)")
                    #expect(r.opened == nil, "\(what)")
                    #expect(try Self.held(rx2) == before, "\(what): a drop changes nothing")
                    if ex.keys.contains("helloTo") { #expect(r.dropped?.helloTo == ex["helloTo"] as? String, "\(what)") }
                } else {
                    #expect(r.dropped == nil, "\(what): \(r.dropped?.reason ?? "")")
                    if let writer = ex["writer"] as? Bool { #expect(r.opened?.writer == writer, "\(what)") }
                }
            }
        }

        let negative = try #require(v["negative"] as? [[String: Any]])
        for n in negative {
            let name = n["name"] as? String ?? "?"
            let rx3 = ConformanceReceiver(account: account, namespace: ns, cell: cell, me: me)
            let at = (n["clockMs"] as? NSNumber)?.int64Value ?? clock
            let maxp = (n["maxPayload"] as? NSNumber)?.uint64Value ?? max
            for case let accepted as String in n["accept"] as? [Any] ?? [] {
                #expect(try rx3.open(bytes: Data(accepted.utf8), view: view, epochs: table, wallMs: clock, maxPayload: max).opened != nil, "\(name)")
            }
            let before = try Self.held(rx3)
            let r = try rx3.open(bytes: Data(try #require(n["frame"] as? String).utf8), view: view, epochs: table, wallMs: at, maxPayload: maxp)
            if let drop = n["drop"] as? String {
                #expect(r.dropped?.reason == drop, "\(name)")
                #expect(try Self.held(rx3) == before, "\(name): a drop changes nothing")
            } else {
                #expect(r.opened != nil && r.dropped == nil, "\(name)")
            }
        }
        print("conformance (Swift): wire \(frames.count) frames / \(steps) scenario steps / \(negative.count) negative frames")
        #expect(frames.count == 19 && steps == 20 && negative.count == 26)
    }

    @Test func sessionInputsAreDecodedStrictly() throws {
        let v = try Self.read(Self.dir.appendingPathComponent("take-publish.json"))
        let policy = try Self.text(try #require(v["policy"]))
        let m = try ConformanceMachine(me: "a", canWrite: true, policyJson: policy, persistedJson: nil, fixesJson: nil, freshSeed: nil)
        for bad in [#"{"input":"wave"}"#, #"{"input":"tick","extra":1}"#, #"{"input":"app","command":{"command":"jump"}}"#,
                    #"{"input":"app","command":{"command":"join"}}"#, "not json"] {
            #expect(Self.thrown { _ = try m.handle(inputJson: bad, at: 0) } == "malformed", "\(bad)")
        }
        var surprising = try #require(try JSONSerialization.jsonObject(with: Data(policy.utf8)) as? [String: Any])
        surprising["surprise"] = true
        let surprise = try Self.text(surprising)
        #expect(Self.thrown { _ = try ConformanceMachine(me: "a", canWrite: true, policyJson: surprise, persistedJson: nil, fixesJson: nil, freshSeed: nil) } == "malformed")
        #expect(Self.thrown { _ = try ConformanceMachine(me: "a", canWrite: true, policyJson: policy,
                                                         persistedJson: #"{"claim":{"term":0,"rank":0,"holder":"a"},"released":false}"#, fixesJson: nil, freshSeed: nil) } == "malformed")
        #expect(Self.thrown { _ = try ConformanceMachine(me: "a", canWrite: true, policyJson: policy, persistedJson: nil, fixesJson: nil, freshSeed: Data(count: 15)) } == "bound")
        #expect(Self.thrown { _ = try ConformanceEpochs(namespace: "listening.podcasts", keys: [ConformanceEpochKey(epoch: 1, key: Data(count: 31))]) } == "bound")
    }
}
