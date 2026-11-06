import Foundation
import CryptoKit
import Testing
import ColophonCore
import ColophonStore
import ColophonAuthority
import ColophonReplica
import ColophonBooks
import ColophonListening
import ColophonSaved
import ColophonNotes
import ColophonSession
@testable import ColophonMigration
import ColophonLegacyAdapter

private let allNamespaces = ["reading.books", "listening.podcasts", "reading.saved", "notes"]

private struct Fixture {
    let source = MemoryStore()
    let root = SoftwareIdentity(), phone = SoftwareIdentity(), mac = SoftwareIdentity(), agent = SoftwareIdentity()
    let holder: AuthorityHolder
    init() throws {
        holder = try AuthorityHolder.create(in: source, label: "Four apps", root: root, firstMember: phone.publicIdentity,
            memberLabel: "iPhone", role: .app, custody: .software, namespaces: allNamespaces).0
        try holder.admit(mac.publicIdentity, label: "Mac", role: .device, custody: .software, namespaces: allNamespaces, write: true)
        try holder.admit(agent.publicIdentity, label: "Old assistant", role: .agent, custody: .software, namespaces: allNamespaces, write: true)
    }
    var replica: Replica { Replica(store: source, identity: phone) }
    func populate() throws {
        let other = Replica(store: source, identity: mac)
        try replica.perform(Books.add(book: "book", title: "Middlemarch", author: "George Eliot"))
        let note = try replica.perform(Books.note("note", book: "book", text: "First thought"))
        try replica.perform(Books.editNote("note", text: "On the train", expect: note.id))
        try other.perform(Books.editNote("note", text: "At the desk", expect: note.id))
        try replica.perform(Books.progress(book: "book", fraction: 0.4))
        let capture = try replica.perform(SavedLinks.capture(item: "article", url: "https://example.com/essay", title: "An essay"))
        try other.perform(SavedLinks.setState(item: "article", consumption: "inProgress", expect: capture.id))
        try replica.perform(SavedLinks.setState(item: "article", consumption: "completed", expect: capture.id)) // historical conflict
        try replica.perform(Notes.create(notebook: "notebook", title: "Field notes"))
        let cell = try replica.perform(Notes.putCell("cell", notebook: "notebook", kind: .markdown, source: "First"))
        try other.perform(Notes.putCell("cell", notebook: "notebook", kind: .markdown, source: "Second", expect: cell.id))
        try replica.perform(Notes.putCell("cell", notebook: "notebook", kind: .markdown, source: "Alternative", expect: cell.id))
        let feed = "https://example.com/podcast.xml"
        try replica.perform(Podcasts.follow(feed: feed, title: "A podcast"))
        try replica.perform(Podcasts.position(episode: Podcasts.episodeID(feed: feed, guid: "episode"), show: Podcasts.showID(feed: feed), seconds: 120, duration: 600, deliberate: true, expect: nil))
        let mapped = LegacyPodcastFeedCrosswalk(legacyID: "old-feed", feedURL: "https://example.com/legacy.xml", title: "Legacy podcast", targetShowID: Podcasts.showID(feed: "https://example.com/legacy.xml"))
        let payload = try LegacyBridgeImport.payload(targetLibraryID: replica.authority().libraryID,
            lineageID: "0d73b5e3-dbd5-47e1-9438-b050a15f5e84", sourceRoot: String(repeating: "a", count: 64), parentSourceRoot: nil,
            feeds: [mapped], sharedOperationInventory: [], expectedLineageRoot: nil, expectedShowHeads: [mapped.targetShowID: nil], commandID: "legacy-import")
        try replica.perform(Command(namespace: Podcasts.namespace, kind: LegacyBridgeImport.kind, payload: payload))
        let legacyFeed = "https://example.com/legacy.xml"
        let legacy = LegacyPodcastStateRecord(legacyID: Canonical.digest(Data((legacyFeed + "|legacy-episode").utf8)),
            feed: legacyFeed, guid: "legacy-episode", seconds: 37, consumption: "completed", updated: Date(timeIntervalSince1970: 1_700_000_000))
        _ = try LegacyPodcastStateImportService(replica: replica).commit(libraryID: replica.authority().libraryID,
            lineageID: "0d73b5e3-dbd5-47e1-9438-b050a15f5e84", sourceRoot: String(repeating: "a", count: 64), records: [legacy])
        let fact = PodcastSourceFact(sourceActor: "old-reader", operationID: "legacy-source-position", sourceClock: 12,
            sourceDate: Date(timeIntervalSince1970: 1_700_000_001), sourceDigest: String(repeating: "b", count: 64), kind: "position",
            metadata: ["itemID": .string(Canonical.digest(Data((legacyFeed + "|source-episode").utf8))), "feedURL": .string(legacyFeed)],
            body: ["seconds": .number(19), "deliberate": .bool(false)])
        let action = PodcastSourceAction(actionID: "source-baseline", factKey: fact.key, feed: legacyFeed, guid: "source-episode", mode: .baseline, expectedRevision: nil)
        _ = try PodcastSourcePublicationService(replica: replica).publish(libraryID: replica.authority().libraryID, facts: [fact], actions: [action])
        // A service-only old kind stays evidence, and must never start a worker job.
        try replica.perform(Command(namespace: Podcasts.namespace, kind: "transcript.prepare", payload: ["request": .string("old-job")]))
        // Later's missing full content fold is explicitly unresolved, not an invented effect.
        try replica.perform(Command(namespace: SavedLinks.namespace, kind: "content.restoreDeleted", payload: ["item": .string("missing-history")]))
        let held = try Replica(store: source, identity: agent).perform(Books.add(book: "held-book", title: "Unapproved", author: "Agent"))
        try holder.revoke(agent.publicIdentity.id, seen: [])
        #expect(try replica.read(Books.namespace).held.contains { $0.id == held.id })
    }
}
@MainActor private struct Destination {
    let home: URL
    let store = MemoryRecordStore()
    let keys = SoftwareKeys()
    let evidenceKey = SymmetricKey(size: .bits256)
    var marker: URL { home.appendingPathComponent("migration-status.json") }
    init() { home = FileManager.default.temporaryDirectory.appendingPathComponent("migration-test-" + UUID().uuidString) }
    func session() -> ColophonSession {
        ColophonSession(configuration: .init(memberLabel: "Migration root", namespaces: allNamespaces, location: .memory(store), privateContainer: home.appendingPathComponent("session"), keys: keys, migrationMarker: marker, migrationWriter: true))
    }
    func migration(_ source: Fixture, _ session: ColophonSession) -> LibraryMigration {
        LibraryMigration(source: ColophonLegacyAdapter(store: source.source, readerIdentity: source.phone, rootIdentity: source.root), namespaces: Set(allNamespaces), destination: session,
            privateContainer: home.appendingPathComponent("migration"), evidenceKey: evidenceKey, markerURL: marker)
    }
    func library() async throws -> Library { try await Library.open(records: store.read(), me: keys) }
}
@MainActor struct MigrationTests {
    @Test func fourDomainFixtureKeepsFoldsHistoryAndSourceBytes() async throws {
        let f = try Fixture(); try f.populate()
        let original = f.source.snapshot, destination = Destination()
        defer { try? FileManager.default.removeItem(at: destination.home) }
        let session = destination.session(), migration = destination.migration(f, session)
        var report = try await migration.run(batchSize: 3)
        while report.remainingOperations > 0 { report = try await migration.run(batchSize: 3) }
        #expect(f.source.snapshot == original)
        #expect(report.membersNeedingRejoin.count == 3)
        #expect(!report.unresolved.isEmpty)
        let library = try await destination.library()
        #expect(try await library.members().count == 1, "Old grants are never recreated")
        let books = try await library.view(namespace: Books.namespace).get()
        let importer = try await library.me().id
        #expect(books.admitted.allSatisfy { $0.author == importer })
        let bookState = try JSONSerialization.jsonObject(with: books.state) as? [String: Any]
        #expect(bookState != nil)
        let queries: [(String, String, [String: String])] = [
            (Books.namespace, "book", ["id":"book"]), (SavedLinks.namespace, "item", ["id":"article"]),
            (Notes.namespace, "cell", ["notebook":"notebook", "id":"cell"])]
        for (namespace, query, args) in queries {
            let result = try await library.call(tool: namespace + "__" + query, input: json(args)).get()
            let response = try #require(JSONSerialization.jsonObject(with: result) as? [String: Any])
            let value = try #require(response["value"] as? [String: Any])
            switch namespace {
            case Books.namespace:
                let old = try #require(f.replica.state(of: Books.self).books["book"])
                let book = try #require(value["book"] as? [String: Any])
                #expect(book["title"] as? String == old.title)
                #expect(book["creator"] as? String == old.author)
                #expect(book["fraction"] as? Double == old.fraction)
            case SavedLinks.namespace:
                let old = try #require(f.replica.state(of: SavedLinks.self).items["article"])
                let item = try #require(value["item"] as? [String: Any])
                #expect(item["title"] as? String == old.title)
                #expect(item["consumption"] as? String == old.consumption)
                #expect(item["retention"] as? String == old.retention)
            default:
                let old = try #require(f.replica.state(of: Notes.self).cells["cell"])
                #expect(value["source"] as? String == old.source)
                #expect(value["kind"] as? String == old.kind.rawValue)
            }
        }
        let listening = try await library.view(namespace: Podcasts.namespace).get()
        let listeningChildren = try listening.admitted.flatMap { operation -> [[String: Any]] in
            let batch = try JSONSerialization.jsonObject(with: operation.payload) as? [String: Any] ?? [:]
            return batch["children"] as? [[String: Any]] ?? []
        }
        #expect(listening.admitted.allSatisfy { $0.kind == "colophon.importBatch" })
        #expect(listeningChildren.contains { $0["kind"] as? String == "follow" })
        #expect(listeningChildren.contains { $0["kind"] as? String == "position" })
        #expect(!listeningChildren.contains { $0["kind"] as? String == "requestTranscript" })
        #expect(!String(decoding: books.state, as: UTF8.self).contains("held-book"))
        #expect(!FileManager.default.fileExists(atPath: destination.home.appendingPathComponent("migration/import-evidence-local").path))
        let evidence = try await migration.evidence()
        #expect(evidence.count == report.importedOperations)
        let allEvidence = evidence.map { String(decoding: $0, as: UTF8.self) }.joined()
        #expect(allEvidence.contains("Old assistant")); #expect(allEvidence.contains("historical"))
        #expect(allEvidence.contains("exact authenticated signed operation body"))
        #expect(allEvidence.contains("outputOperationIDs"))
        #expect(allEvidence.contains("legacy.podcastState.import"))
        for bytes in evidence {
            let record = try #require(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
            guard let oldID = record["operationID"] as? String, let author = record["authorID"] as? String else { continue }
            let matching = try #require(original.first { $0.key.hasPrefix("ops/" + author + "/") && $0.key.hasSuffix("-" + oldID + ".json") })
            let signed = try Canonical.decode(SignedRecord.self, from: matching.value)
            #expect(record["signedBodyDigest"] as? String == Canonical.digest(signed.body))
        }
        let oldListening = try f.replica.state(of: Podcasts.self)
        for oldEpisode in oldListening.episodes.values {
            let result = try await library.call(tool: Podcasts.namespace + "__getEpisode", input: json(["id":oldEpisode.id])).get()
            let object = try #require(JSONSerialization.jsonObject(with: result) as? [String: Any])
            let value = (object["value"] as? [String: Any]) ?? object
            #expect(value["seconds"] as? Double == oldEpisode.seconds, "query: \(String(decoding: result, as: UTF8.self))")
            #expect(value["consumption"] as? String == oldEpisode.consumption)
        }
        #expect(try MigrationMarker.isActive(at: destination.marker))
        let before = try await destination.store.read()
        _ = try await migration.run()
        #expect(try await destination.store.read() == before)
    }

    @Test func interruptionAfterSignedWriteResumesWithoutDuplicates() async throws {
        let f = try Fixture(); try f.replica.perform(Books.add(book: "b", title: "Book", author: "Author"))
        let d = Destination(); defer { try? FileManager.default.removeItem(at: d.home) }
        let first = d.migration(f, d.session())
        enum Stop: Error { case interrupted }
        await first.setAfterPublication { throw Stop.interrupted }
        await #expect(throws: Stop.interrupted) { try await first.run() }
        let published = try await d.store.read()
        let resumed = d.migration(f, d.session())
        let report = try await resumed.run()
        #expect(report.remainingOperations == 0); #expect(report.unresolved.isEmpty)
        #expect(try await d.store.read() == published)
        #expect(try await resumed.evidence().count == 1)
        #expect(try !MigrationMarker.isActive(at: d.marker))
    }

    @Test func catchUpPreservesNativeEditsAndImportsNewObjects() async throws {
        let f = try Fixture(); try f.replica.perform(Books.add(book: "b", title: "Original", author: "Author"))
        let d = Destination(); defer { try? FileManager.default.removeItem(at: d.home) }
        let session = d.session(), migration = d.migration(f, session)
        _ = try await migration.run()
        try await session.perform(DomainCommand(namespace: Books.namespace, kind: "editBook", payloadJSON: json(["id":"b", "title":"Native title"])), observed: session.observedRevision)
        try f.replica.perform(Books.edit(book: "b", title: "Old phone title"))
        try f.replica.perform(Books.add(book: "new", title: "New on old phone", author: "Author"))
        _ = try await migration.run()
        let lib = try await d.library()
        let result = try await lib.call(tool: Books.namespace + "__book", input: json(["id":"b"])).get()
        #expect(String(decoding: result, as: UTF8.self).contains("Native title"))
        let added = try await lib.call(tool: Books.namespace + "__book", input: json(["id":"new"])).get()
        #expect(String(decoding: added, as: UTF8.self).contains("New on old phone"))
        let before = try await d.store.read(); _ = try await migration.run()
        #expect(try await d.store.read() == before)
    }

    @Test func largeOutputPublishesEncryptedBlobAndSynchronizedEvidence() async throws {
        let f = try Fixture()
        try f.replica.perform(Notes.create(notebook: "n", title: "Notebook"))
        try f.replica.perform(Notes.putCell("c", notebook: "n", kind: .code, source: "source"))
        let text = String(repeating: "retained output ", count: 5000)
        try f.replica.perform(Notes.output(cell: "c", notebook: "n", source: "source", runtime: "historical",
            outputs: [(mime: "text/plain", data: text)]))
        let d = Destination(); defer { try? FileManager.default.removeItem(at: d.home) }
        let migration = d.migration(f, d.session()), report = try await migration.run()
        #expect(report.remainingOperations == 0)
        let digest = Canonical.digest(Data(text.utf8))
        let library = try await d.library()
        let blob = try await library.query(namespace: Notes.namespace, name: "blob", arguments: json(["digest": digest])).get()
        let envelope = try #require(JSONSerialization.jsonObject(with: blob) as? [String: Any])
        let manifest = try #require(envelope["manifest"] as? [String: Any])
        let chunks = try #require(manifest["chunks"] as? [[String: Any]])
        #expect(chunks.count == 2)
        let records = try await d.store.read()
        #expect(!records.keys.contains { $0.hasPrefix("blobs/") }, "Snapshots must not eagerly load blobs")
        let native = try NativeLibrary.open(records: records, me: await d.keys.publicKeys())
        _ = try native.readyWith(keys: d.keys)
        var plaintext = Data()
        for (index, chunk) in chunks.enumerated() {
            let path = try #require(chunk["path"] as? String)
            let ciphertext = try await d.store.readBlob(path)
            #expect(ciphertext.range(of: Data("retained output".utf8)) == nil)
            let read = try native.readBlobChunk(namespace: Notes.namespace, digest: digest, index: UInt32(index),
                now: "2026-11-06T18:00:00Z", source: MigrationChunkSource(path: path, bytes: ciphertext))
            guard case .available(let bytes) = read else { Issue.record("Blob must authenticate"); return }
            plaintext.append(bytes)
        }
        #expect(plaintext == Data(text.utf8))
        #expect(Canonical.digest(plaintext) == digest)
        #expect(try await migration.evidence().count == 3)
        let before = try await d.store.read(); _ = try await migration.run()
        #expect(try await d.store.read() == before)
    }

    @Test func onlyRootCanStartMigration() async throws {
        let f = try Fixture(), d = Destination(); defer { try? FileManager.default.removeItem(at: d.home) }
        let migration = LibraryMigration(source: ColophonLegacyAdapter(store: f.source, readerIdentity: f.phone, rootIdentity: f.mac), namespaces: Set(allNamespaces),
            destination: d.session(), privateContainer: d.home, evidenceKey: d.evidenceKey, markerURL: d.marker)
        await #expect(throws: MigrationError.rootRequired) { try await migration.run() }
        #expect(try await d.store.read().isEmpty)
    }
    @Test func lateEarlierOperationStopsForReconciliationWithoutRewriting() async throws {
        let f = try Fixture(), offline = MemoryStore()
        for (path, bytes) in f.source.snapshot { try offline.create(path, bytes) }
        try f.replica.perform(Books.add(book: "one", title: "One", author: "Author"))
        try f.replica.perform(Books.add(book: "two", title: "Two", author: "Author"))
        let d = Destination(); defer { try? FileManager.default.removeItem(at: d.home) }
        let migration = d.migration(f, d.session()); _ = try await migration.run()
        let before = try await d.store.read()
        try Replica(store: offline, identity: f.mac).perform(Books.add(book: "late", title: "Earlier offline", author: "Author"))
        for (path, bytes) in offline.snapshot where f.source.snapshot[path] == nil { try f.source.create(path, bytes) }
        do { _ = try await migration.run(); Issue.record("Earlier prefix must require reconciliation") }
        catch MigrationError.reconciliationRequired(let reason) { #expect(reason.contains(Books.namespace)) }
        let after = try await d.store.read()
        #expect(before.allSatisfy { after[$0.key] == $0.value }, "Signed native history remains byte-identical")
        let library = try await d.library()
        let overlay = try await library.query(namespace: Books.namespace, name: "historicalAlternatives", arguments: json([:])).get()
        #expect(String(decoding: overlay, as: UTF8.self).contains("Earlier offline"))
        let state = try await library.view(namespace: Books.namespace).get().state
        #expect(!String(decoding: state, as: UTF8.self).contains("Earlier offline"), "Late evidence is not silently made effective")
        do { _ = try await migration.run() } catch MigrationError.reconciliationRequired { }
        #expect(try await d.store.read() == after, "Reconciliation publication is idempotent")
        #expect(try MigrationMarker.isActive(at: d.marker))
    }

    @Test func badSignatureIsArchivedAsUnresolvedAndNeverProjected() async throws {
        let f = try Fixture()
        let op = try f.replica.perform(Books.add(book: "tampered", title: "Untrusted", author: "Author"))
        let path = LibraryPath.operation(author: f.phone.publicIdentity.id, clock: op.clock, id: op.id)
        let record = try Canonical.decode(SignedRecord.self, from: #require(try f.source.read(path)))
        f.source.tamper(path, try Canonical.encode(SignedRecord(body: record.body, signature: Data(repeating: 0, count: 64))))
        let original = f.source.snapshot, d = Destination(); defer { try? FileManager.default.removeItem(at: d.home) }
        let migration = d.migration(f, d.session()), report = try await migration.run()
        #expect(!report.unresolved.isEmpty)
        #expect(report.importedOperations == 0)
        let evidence = try await migration.evidence()
        #expect(evidence.count == 1)
        #expect(String(decoding: evidence[0], as: UTF8.self).contains("unresolved"))
        #expect(try await d.library().view(namespace: Books.namespace).get().admitted.isEmpty)
        #expect(f.source.snapshot == original)
    }

    @Test func lostEvidenceKeyAndWrongSourceCannotRestartOverProgress() async throws {
        let f = try Fixture(); try f.replica.perform(Books.add(book: "b", title: "Private title", author: "Author"))
        let d = Destination(); defer { try? FileManager.default.removeItem(at: d.home) }
        let session = d.session(); _ = try await d.migration(f, session).run()
        let before = try await d.store.read()
        let wrongKey = LibraryMigration(source: ColophonLegacyAdapter(store: f.source, readerIdentity: f.phone, rootIdentity: f.root), namespaces: Set(allNamespaces),
            destination: session, privateContainer: d.home.appendingPathComponent("migration"),
            evidenceKey: SymmetricKey(size: .bits256), markerURL: d.marker)
        await #expect(throws: (any Error).self) { try await wrongKey.run() }
        let other = try Fixture()
        await #expect(throws: MigrationError.invalidSource) { try await d.migration(other, session).run() }
        #expect(try await d.store.read() == before)
        let encrypted = try Data(contentsOf: d.home.appendingPathComponent("migration/migration-progress.aesgcm"))
        #expect(encrypted.range(of: Data("Private title".utf8)) == nil)
    }

    @Test func catchUpCreationCannotCollideWithNativeIdentity() async throws {
        let f = try Fixture(); try f.replica.perform(Books.add(book: "first", title: "First", author: "Author"))
        let d = Destination(); defer { try? FileManager.default.removeItem(at: d.home) }
        let session = d.session(), migration = d.migration(f, session); _ = try await migration.run()
        try await session.perform(DomainCommand(namespace: Books.namespace, kind: "addBook", payloadJSON: json(["id":"collision", "title":"Native", "creator":"Author"])), observed: session.observedRevision)
        let before = try await d.store.read()
        try f.replica.perform(Books.add(book: "collision", title: "Source", author: "Author"))
        do { _ = try await migration.run(); Issue.record("Native identity requires remapping") }
        catch MigrationError.reconciliationRequired(let reason) { #expect(reason.contains("collision")) }
        #expect(try await d.store.read() == before)
        #expect(try MigrationMarker.isActive(at: d.marker))
    }

    @Test func booksOnlyMixedSourceThenNotesUpgradeAndCatchUp() async throws {
        let f = try Fixture()
        try f.replica.perform(Books.add(book: "book", title: "Book", author: "Author"))
        try f.replica.perform(Notes.create(notebook: "notebook", title: "Notes later"))
        // This reference does not implement Later's full codec; it must not block Shelf.
        try f.replica.perform(Command(namespace: SavedLinks.namespace, kind: "content.restoreDeleted", payload: [:]))
        let original = f.source.snapshot
        let d = Destination(); defer { try? FileManager.default.removeItem(at: d.home) }
        let source = ColophonLegacyAdapter(store: f.source, readerIdentity: f.phone, rootIdentity: f.root)
        let booksMarker = d.home.appendingPathComponent("books-marker.json")
        let booksSession = ColophonSession(configuration: .init(memberLabel: "Books migration", namespaces: [Books.namespace],
            location: .memory(d.store), privateContainer: d.home.appendingPathComponent("books-session"), keys: d.keys,
            migrationMarker: booksMarker, migrationWriter: true))
        func booksMigration() -> LibraryMigration {
            LibraryMigration(source: source, namespaces: [Books.namespace], destination: booksSession,
                privateContainer: d.home.appendingPathComponent("books-migration"), evidenceKey: d.evidenceKey, markerURL: booksMarker)
        }
        var migration = booksMigration()
        let first = try await migration.run(batchSize: 1)
        #expect(first.importedOperations == 1 && first.remainingOperations == 0)
        #expect(first.unresolved.isEmpty)
        #expect(try !MigrationMarker.isActive(at: booksMarker))
        #expect(try await migration.evidence().count == 1)
        let destinationID = try #require(booksSession.libraryID)
        // No saved-reading grant is needed, even when invalid envelopes need evidence.
        #expect(f.source.snapshot == original)
        let before = try await d.store.read()
        try f.replica.perform(Command(namespace: SavedLinks.namespace, kind: "content.restoreDeleted", payload: ["item": .string("other")]))
        migration = booksMigration() // cold journal resume ignores changes to the other scope
        let unchanged = try await migration.run()
        #expect(unchanged.unresolved.isEmpty && unchanged.importedOperations == 1)
        #expect(try await d.store.read() == before)
        try f.replica.perform(Books.add(book: "second", title: "Catch up", author: "Author"))
        let appended = try await migration.run()
        #expect(appended.importedOperations == 2 && appended.unresolved.isEmpty)

        // A second app can choose its own destination and migrate its namespace later.
        let notesDestination = Destination(); defer { try? FileManager.default.removeItem(at: notesDestination.home) }
        let notesSession = ColophonSession(configuration: .init(memberLabel: "Notes migration", namespaces: [Notes.namespace],
            location: .memory(notesDestination.store), privateContainer: notesDestination.home.appendingPathComponent("notes-session"),
            keys: notesDestination.keys, migrationMarker: notesDestination.marker, migrationWriter: true))
        let notes = LibraryMigration(source: source, namespaces: [Notes.namespace], destination: notesSession,
            privateContainer: notesDestination.home.appendingPathComponent("notes-migration"), evidenceKey: notesDestination.evidenceKey,
            markerURL: notesDestination.marker)
        let notesReport = try await notes.run()
        #expect(notesReport.importedOperations == 1 && notesReport.unresolved.isEmpty)
        #expect(try await notes.evidence().count == 1)
        #expect(booksSession.libraryID == destinationID)
        #expect(original.allSatisfy { f.source.snapshot[$0.key] == $0.value })
    }

    @Test func laterScopeCanUseExplicitExistingDestinationAndScopeCannotChange() async throws {
        let f = try Fixture()
        try f.replica.perform(Books.add(book: "book", title: "Book", author: "Author"))
        try f.replica.perform(Notes.create(notebook: "notebook", title: "Notebook"))
        let d = Destination(); defer { try? FileManager.default.removeItem(at: d.home) }
        let session = d.session(), source = ColophonLegacyAdapter(store: f.source, readerIdentity: f.phone, rootIdentity: f.root)
        let books = LibraryMigration(source: source, namespaces: [Books.namespace], destination: session,
            privateContainer: d.home.appendingPathComponent("books"), evidenceKey: d.evidenceKey, markerURL: d.marker)
        _ = try await books.run()
        let id = try #require(session.libraryID)
        let changed = LibraryMigration(source: source, namespaces: [Notes.namespace], destination: session,
            privateContainer: d.home.appendingPathComponent("books"), evidenceKey: d.evidenceKey, markerURL: d.marker)
        await #expect(throws: MigrationError.invalidSource) { try await changed.run() }
        let wrong = LibraryMigration(source: source, namespaces: [Notes.namespace], destination: session, destinationLibraryID: "wrong",
            privateContainer: d.home.appendingPathComponent("notes"), evidenceKey: d.evidenceKey, markerURL: d.marker)
        await #expect(throws: MigrationError.destinationChanged) { try await wrong.run() }
        let notes = LibraryMigration(source: source, namespaces: [Notes.namespace], destination: session, destinationLibraryID: id,
            privateContainer: d.home.appendingPathComponent("notes"), evidenceKey: d.evidenceKey, markerURL: d.marker)
        let result = try await notes.run()
        #expect(result.importedOperations == 1 && result.unresolved.isEmpty)
        #expect(try await books.evidence().count == 1)
        #expect(try await notes.evidence().count == 1)
    }

    @Test func booksOnlyInvalidSignaturePublishesEvidenceWithinBooks() async throws {
        let f = try Fixture()
        let op = try f.replica.perform(Books.add(book: "bad", title: "Untrusted", author: "Author"))
        let path = LibraryPath.operation(author: f.phone.publicIdentity.id, clock: op.clock, id: op.id)
        let record = try Canonical.decode(SignedRecord.self, from: #require(try f.source.read(path)))
        f.source.tamper(path, try Canonical.encode(SignedRecord(body: record.body, signature: Data(repeating: 0, count: 64))))
        let d = Destination(); defer { try? FileManager.default.removeItem(at: d.home) }
        let session = ColophonSession(configuration: .init(memberLabel: "Books migration", namespaces: [Books.namespace],
            location: .memory(d.store), privateContainer: d.home.appendingPathComponent("books-session"), keys: d.keys,
            migrationMarker: d.marker, migrationWriter: true))
        let migration = LibraryMigration(source: ColophonLegacyAdapter(store: f.source, readerIdentity: f.phone, rootIdentity: f.root),
            namespaces: [Books.namespace], destination: session, privateContainer: d.home.appendingPathComponent("migration"),
            evidenceKey: d.evidenceKey, markerURL: d.marker)
        let report = try await migration.run()
        #expect(report.importedOperations == 0 && !report.unresolved.isEmpty)
        #expect(try await migration.evidence().count == 1)
        #expect(try MigrationMarker.isActive(at: d.marker))
    }

    @Test func adapterSemanticChangeStopsCatchUpWithoutNativeEffects() async throws {
        let f = try Fixture()
        try f.replica.perform(Books.add(book: "book", title: "Book", author: "Author"))
        let d = Destination(); defer { try? FileManager.default.removeItem(at: d.home) }
        let session = d.session()
        let base = ColophonLegacyAdapter(store: f.source, readerIdentity: f.phone, rootIdentity: f.root)
        func migration(_ revision: String) -> LibraryMigration {
            LibraryMigration(source: RevisedSource(base: base, revision: revision), namespaces: [Books.namespace], destination: session,
                privateContainer: d.home.appendingPathComponent("migration"), evidenceKey: d.evidenceKey, markerURL: d.marker)
        }
        _ = try await migration("codec-1").run()
        let before = try await d.store.read()
        do { _ = try await migration("codec-2").run(); Issue.record("Expected reconciliation") }
        catch MigrationError.reconciliationRequired { }
        let after = try await d.store.read()
        #expect(before.allSatisfy { after[$0.key] == $0.value })
        #expect(try MigrationMarker.isActive(at: d.marker))
        // Repeating the same reconciliation remains idempotent.
        do { _ = try await migration("codec-2").run(); Issue.record("Expected reconciliation") }
        catch MigrationError.reconciliationRequired { }
        #expect(try await d.store.read() == after)
    }

}

private final class MigrationChunkSource: BlobSource {
    let path: String
    let bytes: Data
    init(path: String, bytes: Data) { self.path = path; self.bytes = bytes }
    func read(path: String) throws -> BlobReadOutcome {
        guard path == self.path else { return .missing }
        return .available(bytes: bytes)
    }
}

// An app-owned adapter can revise evaluated semantics independently of the reference modules.
private struct RevisedSource: LegacyLibrarySource {
    let base: any LegacyLibrarySource
    let revision: String
    func snapshot(namespaces: Set<String>) throws -> any LegacyLibrarySnapshot {
        RevisedSnapshot(base: try base.snapshot(namespaces: namespaces), revision: revision)
    }
}
private struct RevisedSnapshot: LegacyLibrarySnapshot {
    let base: any LegacyLibrarySnapshot
    let revision: String
    var libraryID: String { base.libraryID }
    var readerID: String { base.readerID }
    var rootID: String { base.rootID }
    var members: [LegacyMember] { base.members }
    var namespaces: Set<String> { base.namespaces }
    var changeToken: String { base.changeToken + revision }
    var records: [String: Data] { base.records }
    var unresolved: [String] { base.unresolved }
    var unresolvedPaths: [String] { base.unresolvedPaths }
    var operations: [String: [LegacyOperation]] {
        base.operations.mapValues { entries in entries.map { entry in
            LegacyOperation(id: entry.id, authorID: entry.authorID, authorLabel: entry.authorLabel,
                signedBodyDigest: entry.signedBodyDigest, kind: entry.kind, version: entry.version,
                payloadJSON: entry.payloadJSON, claimedDateJSON: entry.claimedDateJSON, admission: entry.admission,
                sourcePath: entry.sourcePath, semanticFingerprint: entry.semanticFingerprint + revision, admissionDetail: entry.admissionDetail)
        } }
    }
    func evaluate(namespace: String, index: Int, bindings: LegacyImportBindings) throws -> LegacyEvaluation {
        try base.evaluate(namespace: namespace, index: index, bindings: bindings)
    }
}
