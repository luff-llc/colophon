import Foundation
import Observation
import Testing
import ColophonBooksKit
import ColophonListeningKit
import ColophonSavedKit
import ColophonNotesKit

private actor LoadGate {
    var started = false
    var waiter: CheckedContinuation<Void, Never>?
    var release: CheckedContinuation<Void, Never>?
    var calls = 0
    func run() async -> Int {
        calls += 1; started = true; waiter?.resume(); waiter = nil
        await withCheckedContinuation { release = $0 }
        return 42
    }
    func waitUntilStarted() async {
        if !started { await withCheckedContinuation { waiter = $0 } }
    }
    func finish() { release?.resume(); release = nil }
}

@MainActor struct DomainStoreTests {
    @Test func pagesCacheOnlyTheirNamespaceAndRestartStaleCursors() async throws {
        let h = DomainHarness(); try await h.start()
        for i in 0..<3 {
            try await h.send("reading.books", "addBook", ["id":"b\(i)", "title":"Book \(i)", "creator":"Writer"])
            try await h.send("listening.podcasts", "follow", ["id":"s\(i)", "url":"https://example.org/\(i)", "title":"Show \(i)"])
            try await h.send("reading.saved", "capture", ["id":"i\(i)", "title":"Item \(i)"])
            try await h.send("notes", "createNotebook", ["id":"n\(i)", "title":"Notebook \(i)"])
        }
        let books = BooksStore(session:h.session), listening = ListeningStore(session:h.session)
        let saved = SavedStore(session:h.session), notes = NotesStore(session:h.session)
        let bq = BooksQuery(limit:1), lq = ShowsQuery(limit:1), sq = ItemsQuery(limit:1), nq = NotebooksQuery(limit:1)
        #expect(books.cached(bq) == nil)
        let bp = try await books.load(bq).get(), lp = try await listening.load(lq).get()
        let sp = try await saved.load(sq).get(), np = try await notes.load(nq).get()
        #expect(bp.total == 3)
        #expect(lp.total == 3)
        #expect(sp.total == 3)
        #expect(np.total == 3)
        let bnext = try #require(bq.nextPage(after:bp)), lnext = try #require(lq.nextPage(after:lp))
        let snext = try #require(sq.nextPage(after:sp)), nnext = try #require(nq.nextPage(after:np))
        let secondBook = try await books.load(bnext).get()
        let secondShow = try await listening.load(lnext).get()
        let secondItem = try await saved.load(snext).get()
        let secondNotebook = try await notes.load(nnext).get()
        #expect(secondBook.rows.first?.id != bp.rows.first?.id)
        #expect(secondShow.rows.first?.id != lp.rows.first?.id)
        #expect(secondItem.rows.first?.id != sp.rows.first?.id)
        #expect(secondNotebook.rows.first?.id != np.rows.first?.id)
        let bookRevision = books.revision
        let listeningRevision = listening.revision
        let savedRevision = saved.revision
        try await h.send("notes", "renameNotebook", ["id":"n0", "title":"Changed"])
        #expect(books.cached(bq)?.value == bp)
        #expect(listening.cached(lq)?.value == lp)
        #expect(saved.cached(sq)?.value == sp)
        #expect(books.revision == bookRevision)
        #expect(listening.revision == listeningRevision)
        #expect(saved.revision == savedRevision)
        #expect(notes.cached(nq) == nil)
        let staleNotes = try await notes.load(nnext)
        #expect(staleNotes == .failure(.staleCursor))
        try await h.send("reading.books", "editBook", ["id":"b0", "title":"Changed"])
        try await h.send("listening.podcasts", "editShow", ["id":"s0", "title":"Changed"])
        try await h.send("reading.saved", "editMetadata", ["id":"i0", "title":"Changed"])
        let staleBooks = try await books.load(bnext)
        let staleListening = try await listening.load(lnext)
        let staleSaved = try await saved.load(snext)
        #expect(staleBooks == .failure(.staleCursor))
        #expect(staleListening == .failure(.staleCursor))
        #expect(staleSaved == .failure(.staleCursor))
        let restarted = try await books.load(bnext.firstPage()).get()
        #expect(restarted.total == 3)
        let absent = try await books.load(BookQuery(id:"missing"))
        #expect(absent == .failure(.notFound))
        try await h.session.leave()
        #expect(books.cached(bq) == nil)
        #expect(saved.cached(sq) == nil)
        #expect(notes.cached(nq) == nil)
        #expect(listening.cached(lq) == nil)
    }

    @Test func coldCompletionCachesAndCloseFencesInflightWork() async throws {
        let h = DomainHarness(); try await h.start()
        let gate = LoadGate()
        let cache = NamespaceStore<Int,Int>(session:h.session, namespace:"notes", maximumQueries:1, load:{ _ in await gate.run() })
        let task = Task { try await cache.load(0) }
        await gate.waitUntilStarted()
        #expect(cache.state == .warming)
        #expect(cache.cached(0) == nil)
        await gate.finish()
        let result = try await task.value
        #expect(result == 42)
        #expect(cache.cached(0) == 42)
        let second = try await cache.load(0)
        let calls = await gate.calls
        #expect(second == result)
        #expect(calls == 1)
        let closedGate = LoadGate()
        let closed = NamespaceStore<Int,Int>(session:h.session, namespace:"notes", load:{ _ in await closedGate.run() })
        let pending = Task { try await closed.load(0) }
        await closedGate.waitUntilStarted()
        closed.close()
        await closedGate.finish()
        await #expect(throws: SessionError.staleRevision) { try await pending.value }
        #expect(closed.cached(0) == nil)
        #expect(closed.state == .unavailable)
        await #expect(throws: SessionError.notReady) { try await closed.load(0) }
    }

    @Test func namespaceChangeFencesSuspendedLoadsAndCacheCapacityIsBounded() async throws {
        let h = DomainHarness(); try await h.start()
        let gate = LoadGate()
        let cache = NamespaceStore<Int,Int>(session:h.session, namespace:"notes", load:{ _ in await gate.run() })
        let pending = Task { try await cache.load(0) }
        await gate.waitUntilStarted()
        try await h.send("notes", "createNotebook", ["id":"new", "title":"Changed"])
        await gate.finish()
        await #expect(throws: SessionError.staleRevision) { try await pending.value }
        #expect(cache.cached(0) == nil)
        #expect(cache.state == .idle)
        let bounded = NamespaceStore<Int,Int>(session:h.session, namespace:"notes", maximumQueries:1, load:{ $0 })
        try await bounded.load(1)
        try await bounded.load(2)
        #expect(bounded.cached(1) == nil)
        #expect(bounded.cached(2) == 2)
    }

    @Test func nullablePatchesDistinguishMissingNullAndValue() throws {
        let omitted = ColophonBooksKit.EditBook(id:"b")
        let cleared = ColophonBooksKit.EditBook(id:"b", isbn:.null)
        let supplied = ColophonBooksKit.EditBook(id:"b", isbn:.value("isbn"))
        let omittedJSON = try object(omitted.domainCommand().payload)
        let clearedJSON = try object(cleared.domainCommand().payload)
        let suppliedJSON = try object(supplied.domainCommand().payload)
        #expect(omittedJSON["isbn"] == nil)
        #expect(clearedJSON["isbn"] is NSNull)
        #expect(suppliedJSON["isbn"] as? String == "isbn")
        let roundTrip = try JSONDecoder().decode(ColophonBooksKit.EditBook.self, from: cleared.domainCommand().payload)
        #expect(roundTrip == cleared)
        let query = CellsQuery(entry:.null, notebook:"b")
        let queryJSON = try object(JSONEncoder().encode(query))
        #expect(queryJSON["entry"] is NSNull)
    }

    @Test func queryDispatchNeverWrites() async throws {
        let h = DomainHarness(); try await h.start()
        let before = h.session.revision
        let bytes = try await h.session.query(namespace:"notes", name:"createNotebook", arguments:jsonData(["id":"bad", "title":"No query write"]))
        let refusal = try JSONDecoder().decode(DomainQueryResult<ColophonNotesKit.NoteCounts>.self, from:bytes)
        #expect(refusal == .failure(.invalidArgument))
        #expect(h.session.revision == before)
        let store = NotesStore(session:h.session)
        let count = try await store.load(NoteCountsQuery()).get()
        #expect(count.notebooks == 0)
    }
}
