import ColophonAuthority
import ColophonCore
import ColophonListening
import ColophonNotes
import ColophonReplica
import ColophonStore
import CryptoKit
import Foundation
import Testing

struct PodcastNoteContinuityTests {
  private struct Fixture {
    let store = MemoryStore()
    let writer = SoftwareIdentity()
    let reader = SoftwareIdentity()
    let holder: AuthorityHolder
    let library: String
    let added: ColophonOperation

    init(readerNamespaces: [String] = [Notes.namespace, Podcasts.namespace], write: Bool = true) throws {
      let founded = try AuthorityHolder.create(in: store, label: "Continuity fixture", root: SoftwareIdentity(),
        firstMember: writer.publicIdentity, memberLabel: "Taupe fixture", role: .app, custody: .software,
        namespaces: [Notes.namespace, Podcasts.namespace])
      holder = founded.0
      library = try holder.state().libraryID
      try holder.admit(reader.publicIdentity, label: "Scribenda fixture", role: .app, custody: .software,
        namespaces: readerNamespaces, write: write)
      added = try Replica(store: store, identity: writer).perform(Podcasts.note("note", episode: "episode / ? #", show: "show",
        seconds: 42.25, text: "My original thought", quote: "Original quote"))
    }
    var taupe: Replica { Replica(store: store, identity: writer) }
    var scribenda: Replica { Replica(store: store, identity: reader) }
    var link: PodcastNoteLink { get throws { try #require(PodcastNoteLink(libraryID: library, noteID: "note", revision: added.id)) } }
  }

  @Test func routesRoundTripReservedCharactersWithoutPrivateText() throws {
    let f = try Fixture()
    let link = try f.link
    let writingURL = try #require(link.url)
    #expect(PodcastNoteLink(url: writingURL) == link)
    let source = try PodcastNoteSource.resolve(link, in: f.scribenda)
    let momentURL = try #require(source.momentURL)
    let moment = try #require(PodcastNoteLink(url: momentURL))
    #expect(moment.destination == .moment(episode: "episode / ? #", seconds: 42.25))
    #expect(writingURL.absoluteString.contains("original") == false)
    #expect(momentURL.absoluteString.contains("Original") == false)
  }

  @Test(arguments: [
    "scribenda://continue?library=l&note=n&revision=r&note=other",
    "scribenda://continue?library=l&note=n&revision=r&unknown=value",
    "scribenda://continue?library=l&note=n&revision=r#fragment",
    "scribenda://user@continue?library=l&note=n&revision=r",
    "scribenda://continue:123?library=l&note=n&revision=r",
    "scribenda://continue/path?library=l&note=n&revision=r",
    "scribenda://continue?library=l&note=&revision=r",
    "taupe://moment/episode?library=l&note=n&revision=r&t=nan",
    "taupe://moment/episode?library=l&note=n&revision=r&t=inf",
    "taupe://moment/episode?library=l&note=n&revision=r&t=-1",
    "taupe://moment/episode?library=l&note=n&revision=r&t=1e300",
    "taupe://moment/episode?library=l&note=n&revision=r&t=0&t=1",
    "taupe://moment/?library=l&note=n&revision=r&t=0",
  ])
  func malformedRoutesAreRejected(_ raw: String) throws {
    let url = try #require(URL(string: raw))
    #expect(PodcastNoteLink(url: url) == nil)
  }

  @Test func routeSizeBoundsRejectOversizedAndControlCharacterIDs() throws {
    let huge = String(repeating: "a", count: 513)
    #expect(PodcastNoteLink(libraryID: "l", noteID: huge, revision: "r") == nil)
    #expect(PodcastNoteLink(libraryID: "l", noteID: "n\n", revision: "r") == nil)
    let url = try #require(URL(string: "scribenda://continue?library=l&note=n&revision=" + String(repeating: "a", count: 8_192)))
    #expect(PodcastNoteLink(url: url) == nil)
  }

  @Test func continuedEntryPinsOriginalRevisionAndNeverOverwritesWriting() throws {
    let f = try Fixture()
    let link = try f.link
    let first = try PodcastNoteContinuation.open(link, in: f.scribenda)
    var state = try f.scribenda.state(of: Notes.self)
    let cell = try #require(state.cells(in: first.notebookID, entry: first.entryID).first)
    let edited = try f.scribenda.perform(Notes.putCell(cell.id, notebook: first.notebookID, kind: .markdown,
      source: "Continued privately in Scribenda", expect: cell.revision, entry: first.entryID))
    let changed = try f.taupe.perform(Podcasts.editNote("note", text: "Changed in Taupe", expect: f.added.id))
    let changedLink = try #require(PodcastNoteLink(libraryID: f.library, noteID: "note", revision: changed.id))
    let reopened = try PodcastNoteContinuation.open(changedLink, in: f.scribenda)
    state = try f.scribenda.state(of: Notes.self)
    #expect(reopened.entryID == first.entryID)
    #expect(state.entries.count == 1)
    #expect(state.cells[cell.id]?.revision == edited.id)
    #expect(state.cells[cell.id]?.source == "Continued privately in Scribenda")
    let reference = try #require(state.attachments(in: first.notebookID, entry: first.entryID).first?.source)
    #expect(reference.revision == f.added.id)
    #expect(reference.artifactID == "note")
    #expect(reference.quote == "Original quote")
  }

  @Test func interruptedContinuationFinishesFromPinnedSource() throws {
    let f = try Fixture()
    let identity: JSONValue = .array([.string(f.library), .string("note"), .string(f.added.id)])
    let key = Canonical.digest(try Canonical.encode(identity))
    let entry = "taupe-note-" + key
    let notebook = "scribenda-loose-notes"
    try f.scribenda.perform(Notes.create(notebook: notebook, title: "Loose notes"))
    try f.scribenda.perform(Notes.putEntry(entry, notebook: notebook))
    let reference = NotesAttachment.SourceReference(libraryID: f.library, namespace: Podcasts.namespace,
      artifactID: "note", revision: f.added.id, quote: "Original quote")
    try f.scribenda.perform(Notes.attach("taupe-source-" + key, notebook: notebook, entry: entry,
      role: .reading, name: "Moment from Taupe", source: reference))
    let changed = try f.taupe.perform(Podcasts.editNote("note", text: "Newer Taupe text", expect: f.added.id))
    let link = try #require(PodcastNoteLink(libraryID: f.library, noteID: "note", revision: changed.id))
    let recovered = try PodcastNoteContinuation.open(link, in: f.scribenda)
    let state = try f.scribenda.state(of: Notes.self)
    #expect(recovered.entryID == entry)
    #expect(state.cells(in: notebook, entry: entry).first?.source == "My original thought")
    #expect(state.attachments.count == 1)
  }

  @Test func foreignLibraryAndForgedMomentNeverWrite() throws {
    let f = try Fixture()
    let wrong = try #require(PodcastNoteLink(libraryID: "another-library", noteID: "note", revision: f.added.id))
    #expect(throws: PodcastNoteSource.Failure.wrongLibrary) { try PodcastNoteContinuation.open(wrong, in: f.scribenda) }
    let forged = try #require(PodcastNoteLink(libraryID: f.library, noteID: "note", revision: f.added.id,
      destination: .moment(episode: "episode / ? #", seconds: 43)))
    #expect(throws: PodcastNoteSource.Failure.invalidMoment) { try PodcastNoteSource.resolve(forged, in: f.scribenda) }
    let state = try f.scribenda.state(of: Notes.self)
    #expect(state.entries.isEmpty)
  }

  @Test func notesOnlyAndReadOnlyMembershipsFailClosed() throws {
    let notesOnly = try Fixture(readerNamespaces: [Notes.namespace])
    let link = try notesOnly.link
    #expect(throws: PodcastNoteSource.Failure.accessRequired) { try PodcastNoteContinuation.open(link, in: notesOnly.scribenda) }
    let deniedState = try notesOnly.scribenda.state(of: Notes.self)
    #expect(deniedState.entries.isEmpty)
    let readonly = try Fixture(write: false)
    let readonlyLink = try readonly.link
    #expect(throws: PodcastNoteSource.Failure.accessRequired) { try PodcastNoteContinuation.open(readonlyLink, in: readonly.scribenda) }
    try notesOnly.holder.revoke(notesOnly.reader.id)
    #expect(throws: PodcastNoteSource.Failure.accessRequired) { try PodcastNoteSource.resolve(link, in: notesOnly.scribenda) }
  }

  @Test func deletedNotesRetainHistoricalCitationButMissingRevisionCannotResolve() throws {
    let f = try Fixture()
    try f.taupe.perform(Podcasts.deleteNote("note"))
    let source = try PodcastNoteSource.resolve(f.link, in: f.scribenda)
    #expect(source.note.text == "My original thought")
    let absent = try #require(PodcastNoteLink(libraryID: f.library, noteID: "note", revision: "not-a-signed-revision"))
    #expect(throws: PodcastNoteSource.Failure.sourceUnavailable) { try PodcastNoteSource.resolve(absent, in: f.scribenda) }
  }

  @Test func expiredReceiverCannotResolveOrCreateContinuation() throws {
    let f = try Fixture()
    try f.holder.admit(f.reader.publicIdentity, label: "Scribenda fixture", role: .app, custody: .software,
      namespaces: [Notes.namespace, Podcasts.namespace], write: true, expires: .distantPast)
    let link = try f.link
    #expect(throws: PodcastNoteSource.Failure.accessRequired) { try PodcastNoteSource.resolve(link, in: f.scribenda) }
    #expect(throws: PodcastNoteSource.Failure.accessRequired) { try PodcastNoteContinuation.open(link, in: f.scribenda) }
  }

  @Test func heldAndRejectedSourcesCannotResolve() throws {
    let held = try Fixture()
    let heldLink = try held.link
    try held.holder.revoke(held.writer.id, seen: [])
    #expect(throws: PodcastNoteSource.Failure.sourceUnavailable) { try PodcastNoteSource.resolve(heldLink, in: held.scribenda) }
    let rejected = try Fixture()
    let rejectedLink = try rejected.link
    let path = try #require(rejected.store.snapshot.keys.first { $0.hasSuffix("-\(rejected.added.id).json") })
    let stored = try rejected.store.read(path)
    let bytes = try #require(stored)
    let record = try Canonical.decode(SignedRecord.self, from: bytes)
    let broken = SignedRecord(body: record.body, signature: Data(repeating: 0, count: record.signature.count))
    rejected.store.tamper(path, try Canonical.encode(broken))
    #expect(throws: PodcastNoteSource.Failure.sourceUnavailable) { try PodcastNoteSource.resolve(rejectedLink, in: rejected.scribenda) }
  }

  @Test func duplicateSignedOperationIDsCannotResolve() throws {
    let f = try Fixture()
    let path = try #require(f.store.snapshot.keys.first { $0.hasSuffix("-\(f.added.id).json") })
    let stored = try f.store.read(path)
    let bytes = try #require(stored)
    let header = try Canonical.decode(OperationHeader.self, from: Canonical.decode(SignedRecord.self, from: bytes).body)
    let duplicate = OperationHeader(author: f.reader.id, namespace: header.namespace, epoch: header.epoch, sealed: header.sealed)
    let signed = try SignedRecord(signing: Canonical.encode(duplicate), with: f.reader)
    try f.store.create(LibraryPath.operation(author: f.reader.id, clock: 999, id: f.added.id), Canonical.encode(signed))
    let link = try f.link
    #expect(throws: PodcastNoteSource.Failure.sourceUnavailable) { try PodcastNoteSource.resolve(link, in: f.scribenda) }
  }
}
