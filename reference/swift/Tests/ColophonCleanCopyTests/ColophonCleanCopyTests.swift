@testable import ColophonCleanCopy
import ColophonAuthority
import ColophonBooks
import ColophonCore
import ColophonKit
import ColophonMigration
import ColophonNotes
import ColophonSession
import ColophonReplica
import ColophonSaved
import ColophonStore
import CryptoKit
import Foundation
import Testing

private let namespaces = ["reading.books", "reading.saved", "listening.podcasts", "notes"]

struct ColophonCleanCopyTests {
    @Test func snapshotIsByteExactPrivateAndRepeatable() throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let binary = Data([0, 255, 10, 13, 0, 17])
        try writePrivate(binary, to: fixture.source.appendingPathComponent(".extra/raw"))
        let before = try fileManifest(fixture.source)
        let workspace = try fixture.snapshot()
        #expect(try workspace.manifest() == before)
        #expect(try fileManifest(workspace.snapshotDirectory) == before)
        #expect(try Data(contentsOf: workspace.snapshotDirectory.appendingPathComponent(".extra/raw")) == binary)
        #expect(try FileManager.default.attributesOfItem(atPath: workspace.directory.path)[.posixPermissions] as? Int == 0o700)
        #expect(try FileManager.default.attributesOfItem(atPath: workspace.snapshotDirectory.appendingPathComponent(".extra/raw").path)[.posixPermissions] as? Int == 0o600)
        _ = try fixture.snapshot()
        #expect(try fileManifest(fixture.source) == before)
        try workspace.assertSourceUnchanged()
    }

    @Test func memberReaderVerifiesKeyringWithoutAnOldRoot() throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let authority = try AuthorityLog(store: fixture.store).state()
        #expect(authority.isKeyring)
        #expect(authority.keyring?.controllers.values.contains { $0.kind == "webauthn" } == true)
        #expect(fixture.freshRoot.publicIdentity != authority.root)
        let source = MemberLegacySource(snapshot: fixture.store, readerIdentity: fixture.secondDevice)
        let snapshot = try source.snapshot(namespaces: Set(namespaces))
        #expect(snapshot.libraryID == authority.libraryID)
        #expect(snapshot.operations.values.reduce(0) { $0 + $1.count } == 5)
        #expect(snapshot.unresolved.isEmpty)
        for operations in snapshot.operations.values {
            for operation in operations {
                let envelope = try Canonical.decode(SignedRecord.self, from: #require(snapshot.records[operation.sourcePath]))
                #expect(operation.signedBodyDigest == Canonical.digest(envelope.body))
            }
        }
        let books = try Replica(store: fixture.store, identity: fixture.secondDevice).readComplete("reading.books")
        #expect(snapshot.operations["reading.books"]?.map(\.id) == books?.operations.map(\.id))
        // The adapter captures bytes, rather than retaining a mutable live store.
        try fixture.replica.perform(Books.add(book: "later", title: "Later", author: "Later"))
        #expect(try source.snapshot(namespaces: Set(namespaces)).operations["reading.books"]?.count == 2)
    }

    @Test func rootlessReaderKeepsSignatureAndAuthorityChecks() throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let good = try MemberLegacySource(snapshot: fixture.store, readerIdentity: fixture.secondDevice).snapshot(namespaces: Set(namespaces))
        let op = try #require(good.operations["reading.books"]?.first)
        let envelope = try Canonical.decode(SignedRecord.self, from: #require(good.records[op.sourcePath]))
        fixture.store.tamper(op.sourcePath, try Canonical.encode(SignedRecord(body: envelope.body, signature: Data(repeating: 0, count: 64))))
        let bad = try MemberLegacySource(snapshot: fixture.store, readerIdentity: fixture.secondDevice).snapshot(namespaces: Set(namespaces))
        #expect(bad.unresolvedPaths.contains(op.sourcePath))
        let last = try AuthorityLog(store: fixture.store).state().latest
        fixture.store.tamper(LibraryPath.authority(last), Data("{}".utf8))
        #expect(throws: (any Error).self) {
            try MemberLegacySource(snapshot: fixture.store, readerIdentity: fixture.secondDevice).snapshot(namespaces: Set(namespaces))
        }
    }

    @Test func enrollmentOnlyWritesTheSnapshotAndResnapshotDetectsApproval() throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let before = try fileManifest(fixture.source)
        let workspace = try fixture.snapshot()
        let request = try workspace.request()
        #expect(try workspace.request() == request)
        #expect(try fileManifest(fixture.source) == before)
        #expect(try workspace.readerApproved() == false)
        let signed = try Canonical.decode(SignedRecord.self, from: request.bytes)
        let decoded = try Canonical.decode(EnrollmentRequest.self, from: signed.body)
        #expect(decoded.write == false)
        #expect(decoded.label == "Clean copy (Mac)")
        #expect(Set(decoded.namespaces) == Set(namespaces))
        #expect(decoded.member.verify(signed))
        try fixture.approve(request)
        #expect(try workspace.readerApproved() == false)
        _ = try fixture.snapshot()
        #expect(try workspace.readerApproved())
        #expect(try workspace.request() == request)
        try workspace.assertSnapshotUnchanged()
        try workspace.assertSourceUnchanged()
    }

    @Test func changedSourceAndTamperedSnapshotFailVisibly() throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let workspace = try fixture.snapshot()
        try writePrivate(Data("unexpected".utf8), to: fixture.source.appendingPathComponent("unexpected"))
        #expect(throws: (any Error).self) { try workspace.assertSourceUnchanged() }
        #expect(throws: (any Error).self) { try workspace.request() }
        _ = try fixture.snapshot()
        try writePrivate(Data("tampered".utf8), to: workspace.snapshotDirectory.appendingPathComponent("ops/tampered"))
        #expect(throws: CleanCopyError.changedSource("private snapshot")) { try workspace.snapshotRecords() }
    }

    @Test func overlappingPathsAndSymlinksAreRefused() throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let workspace = try fixture.snapshot()
        #expect(throws: (any Error).self) { try workspace.validateDestination(fixture.source.appendingPathComponent("new")) }
        #expect(throws: (any Error).self) { try workspace.validateDestination(fixture.home) }
        #expect(throws: (any Error).self) { try CleanCopyWorkspace.snapshot(source: fixture.source, work: fixture.source.appendingPathComponent("work")) }
        let link = fixture.home.appendingPathComponent("link")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: fixture.source)
        #expect(throws: (any Error).self) { try workspace.validateDestination(link.appendingPathComponent("new")) }
        try FileManager.default.createSymbolicLink(at: fixture.source.appendingPathComponent("escape"), withDestinationURL: fixture.home)
        #expect(throws: (any Error).self) { try fixture.snapshot() }
    }

    @MainActor @Test func rootlessImportIsFreshScopedAndIdempotentWithVerifiedReport() async throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let workspace = try fixture.approvedWorkspace()
        let original = try fileManifest(fixture.source)
        let report = try await workspace.copy(to: fixture.destination, importedFrom: true)
        try #require(report.failure == nil)
        #expect(report.remainingOperations == 0)
        #expect(report.newLibraryID != report.sourceLibraryID)
        #expect(report.countsPerNamespace["reading.books"] == 2)
        #expect(report.countsPerAuthor.count == 2)
        #expect(report.sourceUnchanged)
        #expect(report.unresolved.isEmpty)
        #expect(report.verified)
        #expect(report.accounting.values.allSatisfy { $0.passed })
        #expect(report.viewDigests.values.allSatisfy { $0.reference != nil && $0.reference == $0.destination && $0.reason == nil })
        let records = try await FolderRecordStore(folder: fixture.destination).read()
        let authority = try records.filter { $0.key.hasPrefix("authority/") }.values.map { bytes -> [String: Any] in
            let envelope = try #require(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
            let bodyText = try #require(envelope["body"] as? String)
            let body = try #require(Data(base64Encoded: bodyText))
            return try #require(JSONSerialization.jsonObject(with: body) as? [String: Any])
        }
        #expect(authority.contains { $0["importedFrom"] as? String == report.sourceLibraryID })
        let grant = try #require(authority.first { ($0["grant"] as? [String: Any])?["import"] as? Bool == true })
        let fields = try #require(grant["grant"] as? [String: Any])
        #expect(Set(fields["access"] as? [String] ?? []) == ["read", "write"])
        #expect(fields["expires"] as? String != nil)
        let before = try fileManifest(fixture.destination)
        let again = try await workspace.copy(to: fixture.destination, importedFrom: true)
        #expect(again == report)
        #expect(try fileManifest(fixture.destination) == before)
        #expect(try fileManifest(fixture.source) == original)
        let verified = try await workspace.verify(destination: fixture.destination)
        #expect(verified == report)
        #expect(try fileManifest(fixture.destination) == before)
        // A source change after import cannot be erased by rerunning snapshot.
        try writePrivate(Data("changed".utf8), to: fixture.source.appendingPathComponent("unexpected"))
        #expect(throws: (any Error).self) { try fixture.snapshot() }
        await #expect(throws: (any Error).self) { try await workspace.verify(destination: fixture.destination) }
    }

    @MainActor @Test func copyReportsUnknownRejectedAndUnconvertedBlobs() async throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let unknown = try fixture.replica.perform(Command(namespace: "notes", kind: "future.kind", payload: [:]))
        let bad = try fixture.replica.perform(Books.add(book: "bad", title: "Bad", author: "Bad"))
        let path = LibraryPath.operation(author: fixture.phone.id, clock: bad.clock, id: bad.id)
        let envelope = try Canonical.decode(SignedRecord.self, from: #require(try fixture.store.read(path)))
        fixture.store.tamper(path, try Canonical.encode(SignedRecord(body: envelope.body, signature: Data(repeating: 0, count: 64))))
        let blob = try fixture.replica.putBlob(Data("blob".utf8), in: "notes")
        try fixture.persist()
        let workspace = try fixture.approvedWorkspace()
        let report = try await workspace.copy(to: fixture.destination)
        try #require(report.failure == nil)
        #expect(report.remainingOperations == 0)
        #expect(report.unresolved.contains { $0.path == path })
        #expect(report.unresolved.contains { $0.path == LibraryPath.operation(author: fixture.phone.id, clock: unknown.clock, id: unknown.id) })
        #expect(report.unresolved.contains { $0.path == LibraryPath.blob(blob.digest) })
        #expect(report.verified) // Unresolved records are explicitly accounted for, rather than omitted.
        #expect(FileManager.default.fileExists(atPath: workspace.directory.appendingPathComponent("report.json").path))
        #expect(FileManager.default.fileExists(atPath: workspace.directory.appendingPathComponent("report.md").path))
    }

    @MainActor @Test func inMemoryImportUsesFreshAuthorityAndPreservesVerifiedEvidence() async throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let before = fixture.store.snapshot
        let source = MemberLegacySource(snapshot: fixture.store, readerIdentity: fixture.secondDevice)
        let sourceID = try source.snapshot(namespaces: Set(namespaces)).libraryID
        let member = SoftwareKeys(), controller = SoftwareKeys()
        let store = MemoryRecordStore()
        let marker = fixture.home.appendingPathComponent("memory-marker")
        let session = ColophonSession(configuration: .init(memberLabel: "Clean copy (Mac)", memberKind: .device,
            namespaces: namespaces, location: .memory(store), privateContainer: fixture.home.appendingPathComponent("memory-session"),
            keys: member, ownerController: controller, migrationMarker: marker, migrationWriter: true,
            importExpires: Date.now.addingTimeInterval(3600).ISO8601Format(), importedFrom: sourceID))
        let migration = LibraryMigration(source: source, namespaces: Set(namespaces), destination: session,
            privateContainer: fixture.home.appendingPathComponent("memory-migration"),
            evidenceKey: SymmetricKey(size: .bits256), markerURL: marker)
        var report = try await migration.run(batchSize: 2)
        while report.remainingOperations > 0 { report = try await migration.run(batchSize: 2) }
        #expect(report.importedOperations == 5)
        #expect(report.remainingOperations == 0)
        #expect(report.unresolved.isEmpty)
        #expect(report.destinationLibraryID != sourceID)
        #expect(fixture.store.snapshot == before)
        let records = try await store.read()
        let library = try await Library.open(records: records, me: member)
        #expect(try await library.members().count == 1)
        let importer = try await library.me().id
        for namespace in namespaces {
            let view = try await library.view(namespace: namespace).get()
            #expect(view.admitted.allSatisfy { $0.author == importer && $0.kind == "colophon.importBatch" })
        }
        let response = try await library.call(tool: "reading.books__book", input: json(["id": "book"])).get()
        let wrapper = try #require(JSONSerialization.jsonObject(with: response) as? [String: Any])
        let value = try #require(wrapper["value"] as? [String: Any])
        let book = try #require(value["book"] as? [String: Any])
        let oldBook = try #require(fixture.replica.state(of: Books.self).books["book"])
        #expect(book["title"] as? String == oldBook.title)
        #expect(book["creator"] as? String == oldBook.author)
        let evidence = try await migration.evidence()
        #expect(evidence.count == 5)
        let verified = try source.snapshot(namespaces: Set(namespaces)).operations.values.flatMap { $0 }
        for bytes in evidence {
            let row = try #require(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
            let operationID = try #require(row["operationID"] as? String)
            let operation = try #require(verified.first { $0.id == operationID })
            #expect(row["signedBodyDigest"] as? String == operation.signedBodyDigest)
            #expect(row["authorID"] as? String == operation.authorID)
        }
        _ = try await migration.run()
        #expect(try await store.read() == records)
        let snapshot = try source.snapshot(namespaces: Set(namespaces))
        let verification = try await CopyVerification.check(snapshot: snapshot, destination: library)
        #expect(verification.views.values.allSatisfy { $0.reference != nil && $0.reference == $0.destination && $0.reason == nil })
        #expect(verification.accounting.values.allSatisfy { $0.passed })
        let workspace = try fixture.snapshot()
        let certified = try workspace.makeReport(snapshot: snapshot, destinationID: report.destinationLibraryID,
            migration: report, failure: nil, evidence: evidence, verification: verification)
        #expect(certified.verified)
        #expect(certified.accounting.values.reduce(0) { $0 + $1.expected } == 5)
        try workspace.saveReport(certified)
        let decoded = try JSONDecoder().decode(CleanCopyReport.self, from: Data(contentsOf: workspace.directory.appendingPathComponent("report.json")))
        #expect(decoded == certified)
        let reportJSON = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: workspace.directory.appendingPathComponent("report.json"))) as? [String: Any])
        #expect(reportJSON["verified"] as? Bool == true)
        let reportChecks = try #require(reportJSON["accounting"] as? [String: [String: Any]])
        #expect(reportChecks["notes"]?["passed"] as? Bool == true)
        let markdown = try String(contentsOf: workspace.directory.appendingPathComponent("report.md"), encoding: .utf8)
        #expect(markdown.contains("accounting true"))
        #expect(markdown.contains("/books/*/book/revision"))
        // Fresh reference identities and signatures must not change normalized digests.
        let freshVerification = try await CopyVerification.check(snapshot: snapshot, destination: library)
        #expect(freshVerification.views == verification.views)
        _ = try await library.write(namespace: "reading.books", kind: "editBook", payload: json(["id": "book", "title": "Changed after copy"])).get()
        let changed = try await CopyVerification.check(snapshot: snapshot, destination: library)
        #expect(changed.accounting.values.allSatisfy { $0.passed })
        #expect(changed.views["reading.books"]?.reason != nil)
        #expect(changed.views["reading.books"]?.reference != changed.views["reading.books"]?.destination)
    }

    @MainActor @Test func referencedBlobIsReencryptedDigestPreservedAndRerunIsIdempotent() async throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let plaintext = Data("Verified old attachment".utf8)
        let reference = try fixture.replica.putBlob(plaintext, in: "notes")
        try fixture.replica.perform(Notes.attach("attachment", notebook: "n", role: .file, name: "sample.txt",
                                                mime: "text/plain", blob: reference))
        let source = MemberLegacySource(snapshot: fixture.store, readerIdentity: fixture.secondDevice)
        let snapshot = try source.snapshot(namespaces: Set(namespaces))
        let member = SoftwareKeys(), owner = SoftwareKeys(), store = MemoryRecordStore()
        let marker = fixture.home.appendingPathComponent("blob-marker")
        let session = ColophonSession(configuration: .init(memberLabel: "Clean copy (Mac)", memberKind: .device,
            namespaces: namespaces, location: .memory(store), privateContainer: fixture.home.appendingPathComponent("blob-session"),
            keys: member, ownerController: owner, migrationMarker: marker, migrationWriter: true,
            importExpires: Date.now.addingTimeInterval(3600).ISO8601Format()))
        await session.create()
        #expect(session.phase == .ready)
        let key = SymmetricKey(size: .bits256)
        let manifests = fixture.home.appendingPathComponent("blob-manifests")
        let copied = try await BlobCopy.run(snapshot: snapshot, reader: fixture.secondDevice, session: session, directory: manifests, key: key)
        #expect(copied.failedReference == false)
        #expect(copied.unresolved.isEmpty)
        #expect(copied.copiedPaths == [LibraryPath.blob(reference.digest)])
        let sourceWithBlobs = BlobMappedSource(base: source, descriptors: copied.descriptors)
        let migration = LibraryMigration(source: sourceWithBlobs, namespaces: Set(namespaces), destination: session,
            destinationLibraryID: session.libraryID,
            privateContainer: fixture.home.appendingPathComponent("blob-migration"), evidenceKey: key, markerURL: marker)
        let report = try await migration.run()
        #expect(report.remainingOperations == 0)
        #expect(report.unresolved.contains { $0.hasPrefix("notes/") && $0.contains("requires review") })
        let records = try await store.read()
        let library = try await Library.open(records: records, me: member)
        let response = try await library.query(namespace: "notes", name: "blob", arguments: json(["digest": reference.plain])).get()
        let result = try #require(JSONSerialization.jsonObject(with: response) as? [String: Any])
        let manifest = try #require(result["manifest"] as? [String: Any])
        let descriptor = try #require(manifest["descriptor"] as? [String: Any])
        #expect(descriptor["digest"] as? String == reference.plain)
        let chunks = try #require(manifest["chunks"] as? [[String: Any]])
        let first = try #require(chunks.first)
        let path = try #require(first["path"] as? String)
        let ciphertext = try await store.readBlob(path)
        #expect(ciphertext != fixture.store.snapshot[LibraryPath.blob(reference.digest)])
        let opened = try await library.openBlobChunk(namespace: "notes", digest: reference.plain, index: 0, ciphertext: ciphertext)
        guard case .available(let actual) = opened else { Issue.record("Destination blob unavailable"); return }
        #expect(actual == plaintext)
        let blobPaths = try await store.blobPaths()
        let again = try await BlobCopy.run(snapshot: snapshot, reader: fixture.secondDevice, session: session, directory: manifests, key: key)
        #expect(again.unresolved.isEmpty)
        #expect(try await store.read() == records)
        #expect(try await store.blobPaths() == blobPaths)
        let mappedSnapshot = try sourceWithBlobs.snapshot(namespaces: Set(namespaces))
        let verification = try await CopyVerification.check(snapshot: mappedSnapshot, destination: library)
        #expect(verification.views.values.allSatisfy { $0.reference == $0.destination })
        #expect(verification.accounting.values.allSatisfy { $0.passed })
    }

    @MainActor @Test func unresolvedAccountingDetectsMissingEvidenceEvenWhenViewsAreEqual() async throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let unknown = try fixture.replica.perform(Command(namespace: "notes", kind: "future.kind", payload: [:]))
        try fixture.persist()
        let source = MemberLegacySource(snapshot: fixture.store, readerIdentity: fixture.secondDevice)
        let snapshot = try source.snapshot(namespaces: Set(namespaces))
        let (library, member, migrationReport, evidence) = try await importFixture(snapshot, home: fixture.home)
        let check = try await CopyVerification.check(snapshot: snapshot, destination: library)
        #expect(check.accounting.values.allSatisfy { $0.passed })
        let notes = try #require(check.accounting["notes"])
        #expect(notes.expected == 2)
        #expect(notes.imported == 1)
        #expect(notes.unresolved == 1)
        let row = try #require(notes.operations.first { $0.operationID == unknown.id })
        #expect(row.reason?.isEmpty == false)
        let workspace = try fixture.snapshot()
        let report = try workspace.makeReport(snapshot: snapshot, destinationID: migrationReport.destinationLibraryID,
            migration: migrationReport, failure: nil, evidence: evidence, verification: check)
        #expect(report.verified)
        #expect(report.unresolved.contains { $0.path == row.sourcePath })
        let parents = try await library.view(namespace: "notes").get().admitted
        let missing = try #require(try parents.first { parent in
            let body = try JSONSerialization.jsonObject(with: parent.payload) as? [String: Any]
            return (body?["evidence"] as? [String: Any])?["operationID"] as? String == unknown.id
        })
        let records = try await library.records
        let reduced = records.filter { !$0.key.hasSuffix("-" + missing.id + ".json") }
        #expect(reduced.count < records.count)
        let damaged = try await Library.open(records: reduced, me: member)
        let failed = try await CopyVerification.check(snapshot: snapshot, destination: damaged)
        #expect(failed.views.values.allSatisfy { $0.reference == $0.destination })
        #expect(failed.accounting["notes"]?.passed == false)
        let failureReport = try workspace.makeReport(snapshot: snapshot, destinationID: migrationReport.destinationLibraryID,
            migration: migrationReport, failure: nil, verification: failed)
        #expect(failureReport.verified == false)
    }

    @MainActor @Test func completeViewsIncludeEditsConflictsAndLargeOutputs() async throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let replica = fixture.replica
        let note = try replica.perform(Books.note("note", book: "book", text: "First"))
        try replica.perform(Books.editNote("note", text: "Second", expect: note.id))
        try Replica(store: fixture.store, identity: fixture.secondDevice).perform(Books.editNote("note", text: "Alternative", expect: note.id))
        let cell = try replica.perform(Notes.putCell("cell", notebook: "n", kind: .markdown, source: "First cell"))
        try replica.perform(Notes.putCell("cell", notebook: "n", kind: .markdown, source: "Edited cell", expect: cell.id))
        try replica.perform(Notes.output(cell: "cell", notebook: "n", source: "Edited cell", runtime: "fixture",
            outputs: [(mime: "text/plain", data: String(repeating: "large verified output ", count: 90))]))
        let snapshot = try MemberLegacySource(snapshot: fixture.store, readerIdentity: fixture.secondDevice).snapshot(namespaces: Set(namespaces))
        let (library, _, _, _) = try await importFixture(snapshot, home: fixture.home)
        let check = try await CopyVerification.check(snapshot: snapshot, destination: library)
        for namespace in namespaces {
            #expect(check.views[namespace]?.reason == nil, "\(namespace): \(String(describing: check.views[namespace]))")
            #expect(check.accounting[namespace]?.passed == true)
        }
    }

    @Test func normalizationPreservesAllOtherFieldsAndUserExtensionNames() throws {
        let before: [String: Any] = ["books": ["book": ["book": ["title": "Original", "creator": "Writer", "revision": "one",
            "author": "importer one", "extensions": ["revision": "user revision", "author": "user author", "unknown": NSNull()]]]]]
        var same = before
        var books = try #require(same["books"] as? [String: [String: Any]])
        var book = try #require(books["book"]?["book"] as? [String: Any])
        book["revision"] = "two"; book["author"] = "importer two"
        books["book"]?["book"] = book; same["books"] = books
        let canonical = try ViewNormalization.canonical(json(before), namespace: "reading.books", operationIDs: [])
        #expect(try ViewNormalization.canonical(json(same), namespace: "reading.books", operationIDs: []) == canonical)
        book["title"] = "Changed"
        books["book"]?["book"] = book; same["books"] = books
        #expect(try ViewNormalization.canonical(json(same), namespace: "reading.books", operationIDs: []) != canonical)
        book["title"] = "Original"
        book["extensions"] = ["revision": "Changed user revision", "author": "user author", "unknown": NSNull()]
        books["book"]?["book"] = book; same["books"] = books
        #expect(try ViewNormalization.canonical(json(same), namespace: "reading.books", operationIDs: []) != canonical)
        let ordered = try canonicalJSON(["z": NSNull(), "a10": true, "a2": [1, 2]])
        #expect(String(decoding: ordered, as: UTF8.self) == "{\"a10\":true,\"a2\":[1,2],\"z\":null}")
    }

    @MainActor @Test func insideSourceCopyFailsBeforeAnyDestinationWrite() async throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let workspace = try fixture.approvedWorkspace()
        let before = try fileManifest(fixture.source)
        await #expect(throws: (any Error).self) { try await workspace.copy(to: fixture.source.appendingPathComponent("new")) }
        #expect(try fileManifest(fixture.source) == before)
    }
}

@MainActor
private func importFixture(_ snapshot: any LegacyLibrarySnapshot, home: URL) async throws -> (Library, SoftwareKeys, MigrationReport, [Data]) {
    let member = SoftwareKeys(), controller = SoftwareKeys(), store = MemoryRecordStore()
    let directory = home.appendingPathComponent(UUID().uuidString)
    let marker = directory.appendingPathComponent("marker")
    let session = ColophonSession(configuration: .init(memberLabel: "Clean copy (Mac)", memberKind: .device,
        namespaces: snapshot.namespaces.sorted(), location: .memory(store), privateContainer: directory.appendingPathComponent("session"),
        keys: member, ownerController: controller, migrationMarker: marker, migrationWriter: true,
        importExpires: Date.now.addingTimeInterval(3600).ISO8601Format()))
    let migration = LibraryMigration(source: FrozenLegacySource(value: snapshot), namespaces: snapshot.namespaces, destination: session,
        privateContainer: directory.appendingPathComponent("migration"), evidenceKey: SymmetricKey(size: .bits256), markerURL: marker)
    var report = try await migration.run(batchSize: 2)
    while report.remainingOperations > 0 { report = try await migration.run(batchSize: 2) }
    return (try await Library.open(records: store.read(), me: member), member, report, try await migration.evidence())
}

private struct Fixture {
    let home: URL
    let source: URL
    let work: URL
    let destination: URL
    let store: MemoryStore
    let phone: SoftwareIdentity
    let secondDevice: SoftwareIdentity
    let freshRoot: SoftwareIdentity
    let controller: KeyringHolder
    var replica: Replica { Replica(store: store, identity: phone) }

    init() throws {
        home = FileManager.default.temporaryDirectory.appendingPathComponent("colophon-clean-copy-tests-" + UUID().uuidString)
        source = home.appendingPathComponent("original")
        work = home.appendingPathComponent("work")
        destination = home.appendingPathComponent("new")
        store = MemoryStore(); phone = SoftwareIdentity(); secondDevice = SoftwareIdentity(); freshRoot = SoftwareIdentity()
        // The only reference to the original root is local to this function; the returned fixture
        // has a fresh unrelated root as a restored second device would.
        controller = try Self.keyring(store: store, phone: phone)
        let second = Replica(store: store, identity: secondDevice)
        try second.requestEnrollment(label: "Restored Mac", role: .device, namespaces: namespaces)
        try controller.approveAsRequested(try #require(controller.pendingRequests().first { $0.member.id == secondDevice.id }))
        let first = Replica(store: store, identity: phone)
        try first.perform(Books.add(book: "book", title: "Book", author: "Writer"))
        try second.perform(Books.add(book: "second", title: "Second", author: "Another writer"))
        try first.perform(SavedLinks.capture(url: "https://example.com/one", title: "One"))
        try first.perform(Command(namespace: "notes", kind: "notebook.create", payload: ["notebook": "n", "title": "Notes"]))
        try first.perform(Command(namespace: "listening.podcasts", kind: "show.follow", payload: ["show": "s", "feed": "https://example.com/feed", "title": "Show"]))
        try persist()
    }
    private static func keyring(store: MemoryStore, phone: SoftwareIdentity) throws -> KeyringHolder {
        let oldRoot = SoftwareIdentity()
        let (holder, _) = try AuthorityHolder.create(in: store, label: "Old library", root: oldRoot,
            firstMember: phone.publicIdentity, memberLabel: "Phone", custody: .software, namespaces: namespaces)
        let authenticator = SyntheticAuthenticator()
        let passkey = try authenticator.controller()
        let vault = try holder.upgrade(to: [passkey], threshold: 1) { key in
            [try VaultSlot.prf(seed: key.seed, prfOutput: Data(repeating: 7, count: 32), salt: Data(repeating: 8, count: 32),
                credential: authenticator.credential, controller: passkey.id, label: "Passkey")]
        }
        return try KeyringHolder(log: AuthorityLog(store: store), signer: authenticator.signer(passkey), vault: vault)
    }
    func remove() { try? FileManager.default.removeItem(at: home) }
    func persist() throws {
        for (path, bytes) in store.snapshot { try writePrivate(bytes, to: source.appendingPathComponent(path)) }
    }
    func snapshot() throws -> CleanCopyWorkspace { try CleanCopyWorkspace.snapshot(source: source, work: work) }
    func approve(_ request: ReaderRequest) throws {
        // Simulates the person transferring the export to the old library's controller.
        try store.replace(request.path, request.bytes)
        let enrollment = try Canonical.decode(EnrollmentRequest.self, from: Canonical.decode(SignedRecord.self, from: request.bytes).body)
        try controller.approveAsRequested(enrollment)
        try persist()
    }
    func approvedWorkspace() throws -> CleanCopyWorkspace {
        let workspace = try snapshot()
        try approve(workspace.request())
        return try snapshot()
    }
}

/// Synthetic authenticator using the same COSE, challenge and assertion construction as KeyringTests.
private struct SyntheticAuthenticator: Sendable {
    let key = P256.Signing.PrivateKey()
    let credential = Data(repeating: 4, count: 32)
    func controller() throws -> Controller {
        let point = key.publicKey.x963Representation
        var cose = Data([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20])
        cose += point.subdata(in: 1..<33)
        cose += Data([0x22, 0x58, 0x20]); cose += point.subdata(in: 33..<65)
        return try Controller.webauthn(coseKey: cose, rpID: "id.luff.works", credential: credential,
                                      label: "Passkey", roles: ["approve", "control"], verification: true)
    }
    func signer(_ controller: Controller) throws -> WebAuthnControllerSigner {
        try WebAuthnControllerSigner(controller: controller) { challenge in
            let base64 = challenge.base64EncodedString().replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
            let client = try JSONSerialization.data(withJSONObject: ["type": "webauthn.get", "challenge": base64,
                "origin": "https://id.luff.works"], options: [.sortedKeys, .withoutEscapingSlashes])
            var auth = Data(SHA256.hash(data: Data("id.luff.works".utf8)))
            auth += Data([0x05, 0, 0, 0, 0])
            let signature = try key.signature(for: auth + Data(SHA256.hash(data: client))).derRepresentation
            return (signature, auth, client)
        }
    }
}
