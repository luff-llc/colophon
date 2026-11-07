import Foundation
import Testing
@testable import ColophonSession
@testable import ColophonKitStorage

@MainActor struct SessionPerformanceTests {
    @Test(.enabled(if: ProcessInfo.processInfo.environment["COLOPHON_SESSION_BENCH"] != nil))
    func nativeSessionTimings() async throws {
        let root = URL(fileURLWithPath: ProcessInfo.processInfo.environment["COLOPHON_SESSION_FIXTURE"] ?? FileManager.default.currentDirectoryPath + "/target/engine-sessions")
        let keys = try SoftwareKeys(signingPrivateKey: Data(contentsOf: root.appendingPathComponent("signing-private.bin")), agreementPrivateKey: Data(contentsOf: root.appendingPathComponent("agreement-private.bin")))
        let records = try load(root.appendingPathComponent("100k.records"))
        let suffix = try load(root.appendingPathComponent("suffix.records"))
        let taupe = try load(root.appendingPathComponent("taupe.records"))
        let legacy = ProcessInfo.processInfo.environment["COLOPHON_SESSION_BENCH"] == "legacy"
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: home) }
        let store = MemoryRecordStore(records: records)
        func session(_ store: MemoryRecordStore, _ home: URL, taupeOnly: Bool = false) -> ColophonSession {
            let configuration = SessionConfiguration(memberLabel: "Bench", namespaces: taupeOnly ? ["listening.podcasts"] : ["notes", "listening.podcasts", "reading.saved", "reading.books"], location: .memory(store), privateContainer: home, keys: keys)
            return ColophonSession(configuration: configuration, store: store, core: legacy ? CompatibilitySessionCore() : BindingSessionCore())
        }
        var first: ColophonSession? = session(store, home)
        await first?.restore()
        #expect(first?.phase == .ready)
        if !legacy { try await first?.flushCheckpoint() }
        first = nil
        let suffixHome = home.deletingLastPathComponent().appendingPathComponent(home.lastPathComponent + "-suffix")
        defer { try? FileManager.default.removeItem(at: suffixHome) }
        try FileManager.default.createDirectory(at: suffixHome, withIntermediateDirectories: true)
        for file in try FileManager.default.contentsOfDirectory(at: home, includingPropertiesForKeys: nil) where file.lastPathComponent != "suffix-home" {
            try FileManager.default.copyItem(at: file, to: suffixHome.appendingPathComponent(file.lastPathComponent))
        }
        let reopened = session(store, home)
        var started = ContinuousClock.now
        await reopened.restore()
        report("checkpoint_open", started)
        #expect(reopened.phase == .ready)
        if !legacy {
            let snapshot = try await reopened.worker.core.snapshot(namespaces: ["notes"], requestPaths: [])
            let work = try #require(snapshot.engine).work()
            print("SESSION_WORK checkpoint", work)
            #expect(work.signaturesVerified == 0 && work.payloadsDecrypted == 0 && work.appliedOperations == 0)
        }
        started = .now
        let passive = try DomainCommand(namespace: "listening.podcasts", kind: "position", payloadJSON: Data(#"{"id":"ep1","seconds":300000}"#.utf8))
        _ = try await reopened.perform(passive, observed: reopened.observedRevision)
        report("passive_write", started)
        if !legacy {
            let snapshot = try await reopened.worker.core.snapshot(namespaces: [], requestPaths: [])
            #expect(try #require(snapshot.engine).work().appliedOperations == 0)
        }
        started = .now
        let note = try DomainCommand(namespace: "notes", kind: "addNote", payloadJSON: Data(#"{"id":"session-bench-note","notebook":"journal","text":"Measured note"}"#.utf8))
        _ = try await reopened.perform(note, observed: reopened.observedRevision)
        report("notes_write", started)
        // The suffix uses an independent source, so the checkpoint covers exactly the original prefix.
        let withSuffix = MemoryRecordStore(records: records.merging(suffix) { _, new in new })
        let added = session(withSuffix, suffixHome)
        started = .now
        await added.restore()
        report("checkpoint_plus_1_percent", started)
        #expect(added.phase == .ready)
        if !legacy {
            let snapshot = try await added.worker.core.snapshot(namespaces: [], requestPaths: [])
            let work = try #require(snapshot.engine).work()
            print("SESSION_WORK suffix", work)
            #expect(work.signaturesVerified == 1000 && work.payloadsDecrypted == 1000 && work.appliedOperations == 1000)
        }
        let small = session(MemoryRecordStore(records: taupe), home.appendingPathComponent("taupe"), taupeOnly: true)
        started = .now
        await small.restore()
        report("taupe_open", started)
        #expect(small.phase == .ready)
    }
    private func report(_ label: String, _ start: ContinuousClock.Instant) {
        let d = start.duration(to: .now).components
        let ms = Double(d.seconds) * 1000 + Double(d.attoseconds) / 1e15
        print("SESSION_BENCH swift \(label) \(String(format: "%.3f", ms)) ms")
    }
    private func load(_ url: URL) throws -> [String: Data] {
        let data = try Data(contentsOf: url); var offset = 0
        func length() -> Int { defer { offset += 8 }; return Int(data.withUnsafeBytes { UInt64(littleEndian: $0.loadUnaligned(fromByteOffset: offset, as: UInt64.self)) }) }
        var result: [String: Data] = [:]
        for _ in 0..<length() {
            let n = length(); let path = String(decoding: data[offset..<offset+n], as: UTF8.self); offset += n
            let size = length(); result[path] = data.subdata(in: offset..<offset+size); offset += size
        }
        return result
    }
}
