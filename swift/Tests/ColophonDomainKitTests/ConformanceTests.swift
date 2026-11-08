import CryptoKit
import Foundation
import Testing
import ColophonBooksKit
import ColophonListeningKit
import ColophonSavedKit
import ColophonNotesKit

let domainRoot = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
func fixture(_ path: String) throws -> Data { try Data(contentsOf: domainRoot.appendingPathComponent(path)) }
func jsonData(_ value: Any) throws -> Data { try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .fragmentsAllowed, .withoutEscapingSlashes]) }
func object(_ data: Data) throws -> [String: Any] { try #require(JSONSerialization.jsonObject(with: data) as? [String: Any]) }
func syntheticKeys(_ seed: UInt8) throws -> SoftwareKeys {
    let key = SymmetricKey(data: Data(repeating: seed, count: 32))
    func scalar(_ n: UInt8) -> Data {
        let value = HKDF<SHA256>.deriveKey(inputKeyMaterial: key, salt: Data("colophon/entropy/3".utf8), info: Data(repeating: 0, count: 7) + Data([n]), outputByteCount: 32)
        return value.withUnsafeBytes { Data($0) }
    }
    return try SoftwareKeys(signingPrivateKey: scalar(0), agreementPrivateKey: scalar(1))
}

@MainActor struct DomainConformanceTests {
    @Test(arguments: ["Books", "Listening", "Saved", "Notes"])
    func domainPayloadsAndQueriesAcrossAuthorityCutover(_ domain: String) async throws {
        let namespace: String
        let queries: [[String: Any]]
        let encodedRecords: [String: String]
        let seed: UInt8
        switch domain {
        case "Books":
            namespace = "reading.books"; seed = 5
            queries = try #require(object(fixture("conformance/0.3/reading.books/expected.json"))["queries"] as? [[String: Any]])
            encodedRecords = try JSONDecoder().decode([String: String].self, from: fixture("conformance/0.3/reading.books/records.json"))
        case "Listening":
            namespace = "listening.podcasts"; seed = 1
            queries = try #require(JSONSerialization.jsonObject(with: fixture("conformance/0.3/listening.podcasts.expected.json")) as? [[String: Any]])
            encodedRecords = try JSONDecoder().decode([String: String].self, from: fixture("conformance/0.3/listening.podcasts.records.json"))
        default:
            namespace = domain == "Saved" ? "reading.saved" : "notes"; seed = 1
            let value = try object(fixture("conformance/0.3/\(namespace).json"))
            queries = try #require(value["queries"] as? [[String: Any]])
            encodedRecords = try #require(value["records"] as? [String: String])
        }
        let records = try encodedRecords.mapValues { try #require(Data(base64Encoded: $0)) }
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: home) }
        let memory = MemoryRecordStore(records: records)
        let session = ColophonSession(configuration: .init(memberLabel: "Fixture", namespaces: [namespace], location: .memory(memory), privateContainer: home, keys: try syntheticKeys(seed), ownerController: SoftwareKeys()))
        await session.restore()
        guard case .failed = session.phase else { Issue.record("0.3 authority must be rejected"); return }
        #expect(try await memory.read() == records, "Opening old authority must not rewrite it")
        let current = MemoryRecordStore()
        let active = ColophonSession(configuration: .init(memberLabel: "Fixture", namespaces: [namespace], location: .memory(current),
            privateContainer: home.appendingPathComponent("current"), keys: SoftwareKeys(), ownerController: SoftwareKeys()))
        await active.create()
        try #require(active.phase == .ready)
        let books = BooksStore(session: active), listening = ListeningStore(session: active)
        let saved = SavedStore(session: active), notes = NotesStore(session: active)
        for query in queries {
            let name = try #require((query["name"] ?? query["query"]) as? String)
            let args = try jsonData(query["args"] ?? query["arguments"] ?? [:])
            let expected = try jsonData(try #require(query["result"] ?? query["expected"]))
            switch domain {
            case "Books": try BooksTestDispatch.decodeExpected(name: name, expected: expected)
            case "Listening": try ListeningTestDispatch.decodeExpected(name: name, expected: expected)
            case "Saved": try SavedTestDispatch.decodeExpected(name: name, expected: expected)
            default: try NotesTestDispatch.decodeExpected(name: name, expected: expected)
            }
            let currentExpected = try await active.query(namespace: namespace, name: name, arguments: args)
            switch domain {
            case "Books": try await BooksTestDispatch.query(name: name, arguments: args, expected: currentExpected, store: books)
            case "Listening": try await ListeningTestDispatch.query(name: name, arguments: args, expected: currentExpected, store: listening)
            case "Saved": try await SavedTestDispatch.query(name: name, arguments: args, expected: currentExpected, store: saved)
            default: try await NotesTestDispatch.query(name: name, arguments: args, expected: currentExpected, store: notes)
            }
        }
        try await active.leave()
    }
}
