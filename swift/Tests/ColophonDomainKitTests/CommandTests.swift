import CryptoKit
import Foundation
import Testing
import ColophonBooksKit
import ColophonListeningKit
import ColophonSavedKit
import ColophonNotesKit

@MainActor final class DomainHarness {
    let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let memory = MemoryRecordStore()
    let session: ColophonSession
    var exercised: Set<String> = []
    init() {
        session = ColophonSession(configuration: .init(memberLabel: "Owner", namespaces: ["reading.books", "listening.podcasts", "reading.saved", "notes"], location: .memory(memory), privateContainer: home, keys: SoftwareKeys(), ownerController: SoftwareKeys()))
    }
    isolated deinit { try? FileManager.default.removeItem(at: home) }
    func start() async throws { await session.create(); try #require(session.phase == .ready) }
    @discardableResult func send(_ namespace: String, _ kind: String, _ payload: [String: Any], using writer: ColophonSession? = nil) async throws -> String {
        let bytes = try jsonData(payload)
        let command: DomainCommand
        switch namespace {
        case "reading.books": command = try BooksTestDispatch.command(kind: kind, payload: bytes)
        case "listening.podcasts": command = try ListeningTestDispatch.command(kind: kind, payload: bytes)
        case "reading.saved": command = try SavedTestDispatch.command(kind: kind, payload: bytes)
        default: command = try NotesTestDispatch.command(kind: kind, payload: bytes)
        }
        let input = try JSONDecoder().decode(DomainJSON.self, from: bytes)
        let encoded = try JSONDecoder().decode(DomainJSON.self, from: command.payload)
        #expect(input == encoded, "Typed command changed the core payload for \(kind)")
        let writer = writer ?? session
        await writer.refresh()
        let receipt: WriteReceipt
        do { receipt = try await writer.perform(command, observed: writer.observedRevision) }
        catch { Issue.record("Core rejected \(namespace).\(kind): \(error)"); throw error }
        exercised.insert(kind)
        guard case .saved(let operationID) = receipt else { throw SessionError.publicationUncertain }
        if writer !== session { await session.refresh() }
        return operationID
    }
    func value(_ namespace: String, _ name: String, _ args: [String: Any] = [:]) async throws -> [String: Any] {
        let response = try object(await session.query(namespace: namespace, name: name, arguments: jsonData(args)))
        return try #require(response["value"] as? [String: Any])
    }
    func noInvalid(_ namespace: String) async throws {
        let result = try await value(namespace, "invalid")
        let rows = try #require(result["rows"] as? [Any])
        #expect(rows.isEmpty, "Unexpected core diagnostics: \(rows)")
    }
    func agent() async throws -> ColophonSession {
        let agent = ColophonSession(configuration: .init(memberLabel: "Worker", memberKind: .agent, namespaces: ["listening.podcasts"], location: .memory(memory), privateContainer: home.appendingPathComponent("agent"), keys: SoftwareKeys(), ownerController: SoftwareKeys()))
        await agent.restore(); await session.refresh()
        let request = try #require(session.requests.first)
        try await session.approve(request)
        await agent.refresh()
        try #require(agent.phase == .ready)
        return agent
    }
}
func sha(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
func blob(_ digit: String = "a", media: String = "text/plain") -> [String: Any] { ["digest": String(repeating: digit, count: 64), "size": 10, "mediaType": media] }

@MainActor struct DomainCommandTests {
    @Test func everyBooksCommandAndIndependentHeads() async throws {
        let h = DomainHarness(); try await h.start()
        let ns = "reading.books"
        let added = try await h.send(ns, "addBook", ["id":"b", "title":"Book", "creator":"Writer", "pages":100, "future":["kept":true]])
        let edited = try await h.send(ns, "editBook", ["id":"b", "title":"Revised", "isbn":NSNull(), "expect":added])
        try await h.send(ns, "setPlan", ["id":"b", "status":"reading", "started":"2024-02-29", "expect":added])
        try await h.send(ns, "position", ["id":"b", "fraction":0.5, "page":50])
        let note = try await h.send(ns, "addNote", ["id":"n", "book":"b", "text":"Initial", "quote":"Quote"])
        let stale = try await h.send(ns, "editNote", ["id":"n", "text":"Alternative", "expect":NSNull()])
        let resolved = try await h.send(ns, "resolveNote", ["id":"n", "text":"Reviewed", "expect":note, "resolves":[stale]])
        try await h.send(ns, "deleteNote", ["id":"n", "expect":resolved])
        try await h.send(ns, "setCopyLoan", ["id":"b", "status":"needsReturn", "requestID":"loan", "reflection":"Read", "expect":NSNull()])
        let store = BooksStore(session: h.session)
        let detail = try await store.load(BookQuery(id: "b")).get()
        #expect(detail.heads.metadata == edited)
        #expect(detail.book.title == "Revised")
        #expect(detail.book.fraction == 0.5)
        let activity = try #require(detail.heads.activity)
        try await h.send(ns, "deleteBook", ["id":"b", "expect":activity])
        let deleted = try await store.load(BookQuery(id: "b"))
        #expect(deleted == .failure(.deleted))
        try await h.noInvalid(ns)
        #expect(h.exercised.count == 10)
    }

    @Test func everyNotesCommandAndRetainedOutput() async throws {
        let h = DomainHarness(); try await h.start(); let ns = "notes"
        let notebook = try await h.send(ns, "createNotebook", ["id":"b", "title":"Notebook", "kind":"seminar", "topic":NSNull()])
        let renamed = try await h.send(ns, "renameNotebook", ["id":"b", "title":"Renamed", "expect":notebook])
        let entry = try await h.send(ns, "putEntry", ["id":"e", "notebook":"b", "title":"Entry", "date":"2024-02-29", "tags":[]])
        let alternative = try await h.send(ns, "putEntry", ["id":"e", "notebook":"b", "title":"Alternative", "expect":NSNull()])
        try await h.send(ns, "resolveEntry", ["id":"e", "notebook":"b", "title":"Reviewed", "tags":["kept"], "date":NSNull(), "expect":entry, "resolves":[alternative]])
        let cell = try await h.send(ns, "putCell", ["id":"c", "notebook":"b", "entry":"e", "kind":"code", "language":"js", "source":"1 + 1"])
        try await h.send(ns, "recordOutput", ["id":"run", "notebook":"b", "cell":"c", "sourceDigest":sha(Data("1 + 1".utf8)), "runtime":"test", "outputs":[["mime":"text/plain", "text":"2", "future":true]]])
        let store = NotesStore(session: h.session)
        let current = try await store.load(CellQuery(id: "c", notebook: "b")).get()
        #expect(current.outputIsCurrent)
        let conflict = try await h.send(ns, "putCell", ["id":"c", "notebook":"b", "entry":NSNull(), "language":NSNull(), "kind":"markdown", "source":"Alternative", "expect":NSNull()])
        let resolved = try await h.send(ns, "resolveCell", ["id":"c", "notebook":"b", "source":"Reviewed", "expect":cell, "resolves":[conflict]])
        try await h.send(ns, "moveCell", ["id":"c", "notebook":"b", "after":NSNull()])
        try await h.send(ns, "addAttachment", ["id":"a", "notebook":"b", "entry":"e", "role":"link", "name":"Source", "source":["kind":"web", "url":"https://example.com/", "future":true]])
        let proposal = try await h.send(ns, "proposeEntry", ["id":"p", "notebook":"b", "entry":"e", "markdown":"Proposal", "inputs":["c":resolved], "tags":[]])
        try await h.send(ns, "reviewProposal", ["id":"p", "notebook":"b", "keep":true, "expect":proposal])
        try await h.send(ns, "deleteCell", ["id":"c", "notebook":"b", "expect":resolved])
        try await h.send(ns, "archiveNotebook", ["id":"b", "archived":true, "expect":renamed])
        let counts = try await store.load(NoteCountsQuery()).get()
        #expect(counts.archived == 1)
        #expect(counts.cells == 0)
        let output = try await store.load(ContentDetailQuery(category: .run, id: "run", notebook: "b")).get()
        #expect(output.record?.outputs?.first?.text == "2")
        try await h.noInvalid(ns)
        #expect(h.exercised.count == 13)
    }
}
