import Foundation
import Testing
import ColophonListeningKit

/// Queries Taupe needs to save preferences, enumerate recordings, show note dates and read
/// imported history, plus the incremental, revision-keyed query cache.
@MainActor struct ListeningLibraryQueryTests {
    @Test func preferencesRecordingsNoteDatesAndImportedHistory() async throws {
        let h = DomainHarness(); try await h.start(); let ns = "listening.podcasts"
        try await h.send(ns, "follow", ["id":"show", "url":"https://example.org/feed", "title":"Show"])
        try await h.send(ns, "episode", ["id":"e", "show":"show", "title":"Episode", "duration":120])
        try await h.send(ns, "setPreferences", ["id":"prefs", "changes":[["scope":"global", "field":"speed", "value":1.5, "expect":NSNull()],
                                                                         ["scope":"show", "target":"show", "field":"forward", "value":30, "expect":NSNull()]]])
        let recording = String(repeating: "a", count: 64)
        try await h.send(ns, "setChapters", ["episode":"e", "show":"show", "recording":recording, "source":"publisher", "origin":"id3", "entries":[["start":0, "title":"Opening"]]])
        try await h.send(ns, "addNote", ["id":"n", "episode":"e", "show":"show", "text":"Thought", "seconds":12])
        let store = ListeningStore(session: h.session)
        let global = try await store.load(PreferencesQuery(scope: .global)).get()
        #expect(global.rows.map(\.field) == ["speed"])
        let speedHead = try #require(global.rows.first?.revision)
        let all = try await store.load(PreferencesQuery()).get()
        #expect(all.total == 2)
        // A preference write can now supply the current head and save.
        try await h.send(ns, "setPreferences", ["id":"prefs-2", "changes":[["scope":"global", "field":"speed", "value":2, "expect":speedHead]]])
        let updated = try await store.load(PreferencesQuery(scope: .global)).get()
        #expect(updated.rows.first?.value == .number(2))
        let recordings = try await store.load(RecordingsQuery(episode: "e")).get()
        #expect(recordings.rows.map(\.kind) == ["chapters"])
        #expect(recordings.rows.first?.contentOrigin == "id3")
        let chapters = try await store.load(RecordingContentQuery(episode: "e", kind: .chapters, recording: recording)).get()
        #expect(chapters.contentOrigin == "id3")
        let notes = try await store.load(NotesQuery(episode: "e")).get()
        #expect(notes.rows.first?.created?.isEmpty == false, "Notes carry a wall-clock creation date")
        let imported = try await store.load(HistoryQuery(mode: .importedSession)).get()
        #expect(imported.total == 0, "Imported history is a page, not unavailable")
        try await h.noInvalid(ns)
    }

    @Test func revisionKeyedCacheReloadsOnlyRequestedQueriesAndKeepsLatestValues() async throws {
        let h = DomainHarness(); try await h.start(); let ns = "listening.podcasts"
        try await h.send(ns, "follow", ["id":"show", "url":"https://example.org/feed", "title":"Show"])
        let session = h.session
        let cache = NamespaceStore<String, Data>(session: session, namespace: ns) { name in
            let bytes = try await session.query(namespace: ns, name: name, arguments: Data("{}".utf8))
            return bytes
        }
        _ = try await cache.load("shows"); _ = try await cache.load("listeningCounts")
        #expect(cache.reads == 2)
        // Concurrent loads of one query share one read.
        try await h.send(ns, "episode", ["id":"e", "show":"show", "title":"Episode"])
        #expect(cache.cached("shows") == nil, "Stale values are not current")
        #expect(cache.latest("shows")?.current == false, "but stay renderable while reloading")
        async let first = cache.load("listeningCounts")
        async let second = cache.load("listeningCounts")
        _ = try await (first, second)
        #expect(cache.reads == 3, "Only the requested query was read again, once")
        #expect(cache.latest("listeningCounts")?.current == true)
        #expect(cache.latest("shows")?.current == false)
        cache.close()
    }
}
