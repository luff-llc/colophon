import ColophonKit
import Foundation
import Testing

struct PerformanceTests {
    @Test(.enabled(if: ProcessInfo.processInfo.environment["COLOPHON_FFI_BENCH"] == "1"))
    func ffiPerformance() throws {
        struct Fixture: Decodable {
            let records: [String: [UInt8]]
            let signatures: [[UInt8]]
            let now: String
        }
        let file = URL(filePath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent().appending(path: "target/ffi-bench/fixture.json")
        let fixture = try JSONDecoder().decode(Fixture.self, from: Data(contentsOf: file))
        let keys = try SoftwareKeys(signingPrivateKey: Data(repeating: 1, count: 32), agreementPrivateKey: Data(repeating: 2, count: 32))
        let publicKeys = PublicKeys(signing: try keys.signingPublicKey(), agreement: try keys.agreementPublicKey())
        let records = fixture.records.mapValues { Data($0) }
        func open() throws -> NativeLibrary {
            let library = try NativeLibrary.open(records: records, me: publicKeys)
            _ = try library.readyWith(keys: keys)
            return library
        }
        func microseconds(_ duration: Duration) -> Double {
            Double(duration.components.seconds) * 1e6 + Double(duration.components.attoseconds) / 1e12
        }
        let library = try open()
        let input = Data("{}".utf8)
        let payload = Data(#"{"id":"bench-note","notebook":"book","text":"One more note"}"#.utf8)
        let signatures = fixture.signatures.map { Data($0) }
        _ = try library.beginCall(tool: "notes__read", input: input, now: fixture.now, entropy: Data(repeating: 0, count: 32))
        var queries: [Double] = []
        var writes: [Double] = []
        for _ in 0..<100 {
            let start = ContinuousClock.now
            let result = try library.beginCall(tool: "notes__read", input: input, now: fixture.now, entropy: Data(repeating: 0, count: 32))
            queries.append(microseconds(start.duration(to: .now)))
            if case .read(let data) = result { #expect(!data.isEmpty) } else { Issue.record("Expected query") }
        }
        for _ in 0..<50 {
            let library = try open()
            let start = ContinuousClock.now
            let result = try library.beginWrite(namespace: "notes", kind: "addNote", payload: payload, now: fixture.now, entropy: Data(repeating: 201, count: 32))
            guard case .ready(let action) = result else { Issue.record("Expected write"); return }
            _ = try library.commit(action: action, signatures: signatures)
            let written = try library.writtenOperation(action: action, namespace: "notes", now: fixture.now)
            writes.append(microseconds(start.duration(to: .now)))
            if case .success = written {} else { Issue.record("Expected admitted operation") }
        }
        queries.sort(); writes.sort()
        print("FFI_SWIFT {\"unit\":\"microseconds_median\",\"query\":\(queries[queries.count / 2]),\"write\":\(writes[writes.count / 2])}")
    }
}
