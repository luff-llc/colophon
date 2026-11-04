import ColophonAuthority
import ColophonCore
import ColophonListening
import ColophonReplica
import ColophonStore
import Foundation
import Testing

@Suite struct TranscriptNoteAnchorTests {
  private struct Fixture {
    let store = MemoryStore()
    let person = SoftwareIdentity()
    let otherEditor = SoftwareIdentity()
    let replica: Replica

    init() throws {
      let root = SoftwareIdentity()
      let (holder, _) = try AuthorityHolder.create(in: store, label: "Library", root: root,
        firstMember: person.publicIdentity, memberLabel: "Phone", role: .app,
        custody: .software, namespaces: [Podcasts.namespace])
      try holder.admit(otherEditor.publicIdentity, label: "Other device", role: .device,
        custody: .software, namespaces: [Podcasts.namespace], write: true)
      replica = Replica(store: store, identity: person)
    }

    func save(_ text: String) throws -> SharedTranscriptReference {
      try replica.saveTranscript(TranscriptDocument(text: text, words: nil), episode: "episode",
        show: "show", source: "publisher", language: "en")
      let reference = try SharedTranscriptService(replica: replica).reference(episode: "episode")
      return try #require(reference)
    }

    func anchor(_ quote: String, in text: String, reference: SharedTranscriptReference) throws -> TranscriptNoteAnchor {
      let range = try #require(text.range(of: quote))
      let offset = NSRange(range, in: text)
      return TranscriptNoteAnchor(reference: reference, startUTF16: offset.location,
        lengthUTF16: offset.length, quote: quote)
    }
  }

  @Test func unicodeSliceStaysPinnedAfterTranscriptReplacementAndEdit() throws {
    let f = try Fixture()
    let text = "Before 🐋 the harbour. After."
    let reference = try f.save(text)
    let anchor = try f.anchor("the harbour", in: text, reference: reference)
    let service = TranscriptNoteService(replica: f.replica)
    #expect(anchor.startUTF16 == 10)
    let command = try service.noteCommand(episode: "episode", show: "show", text: "Remember this.",
      anchor: anchor, seconds: 12, noteID: "anchored")
    try f.replica.perform(command)
    let first = try #require(f.replica.state(of: Podcasts.self).notes["anchored"])
    #expect(first.anchor == anchor)
    #expect(first.quote == anchor.quote)
    #expect(first.authorID == f.person.id)
    #expect(first.creationRevision == first.revision)
    #expect(first.lastTextEditorID == f.person.id)
    #expect(service.status(of: first) == .verified)
    #expect(try service.signer(of: first)?.role == .app)
    let notesQuery = try #require(Podcasts.queries.first { $0.name == "notes" })
    let queried = try notesQuery.run(f.replica, ["episode": .string("episode")])
    let row = try #require(queried.object?["notes"]?.array?.first?.object)
    #expect(row["authorID"]?.string == f.person.id)
    #expect(row["authorLabel"]?.string == "Phone")
    #expect(row["transcriptAnchor"] == anchor.json)
    #expect(row["anchorClaimed"]?.bool == true)
    let otherReplica = Replica(store: f.store, identity: f.otherEditor)
    try otherReplica.perform(Podcasts.editNote("anchored", text: "Edited thought.", expect: first.revision))
    _ = try f.save("Corrected transcript with different words.")
    let revised = try #require(f.replica.state(of: Podcasts.self).notes["anchored"])
    #expect(revised.text == "Edited thought.")
    #expect(revised.anchor == anchor)
    #expect(revised.creationRevision == first.creationRevision)
    #expect(revised.revision != revised.creationRevision)
    #expect(revised.authorID == f.person.id)
    #expect(revised.lastTextEditorID == f.otherEditor.id)
    #expect(revised.lastTextEditorLabel == "Other device")
    #expect(service.status(of: revised) == .verified)
    #expect(try SharedTranscriptService(replica: f.replica).reference(episode: "episode") != reference)
  }

  @Test func rawSignedMismatchedAndMalformedClaimsNeverVerify() throws {
    let f = try Fixture()
    let text = "An exact passage."
    let reference = try f.save(text)
    let anchor = try f.anchor("exact passage", in: text, reference: reference)
    let service = TranscriptNoteService(replica: f.replica)
    let forged = Podcasts.note("wrong-episode", episode: "other", show: "show", seconds: 1,
      text: "Claim", quote: anchor.quote, origin: "person", anchor: anchor)
    try f.replica.perform(forged)
    let bad = Command(namespace: Podcasts.namespace, kind: Podcasts.ContentKind.addNote, v: 1,
      payload: ["note": .string("malformed"), "episode": .string("episode"),
        "show": .string("show"), "text": .string("Claim"), "origin": .string("person"),
        "quote": .string("exact passage"), "transcriptAnchor": .object(["quote": .string("exact passage")])])
    try f.replica.perform(bad)
    let state = try f.replica.state(of: Podcasts.self)
    let mismatched = try #require(state.notes["wrong-episode"])
    let malformed = try #require(state.notes["malformed"])
    #expect(service.status(of: mismatched) == .mismatch)
    #expect(service.status(of: malformed) == .mismatch)
    #expect(malformed.hasAnchorClaim)
    #expect(malformed.anchor == nil)
  }

  @Test func legacyTimestampAndWrongRangeRemainExplicit() throws {
    let f = try Fixture()
    let text = "A line worth keeping."
    let reference = try f.save(text)
    let service = TranscriptNoteService(replica: f.replica)
    try f.replica.perform(Podcasts.note("legacy", episode: "episode", show: "show", seconds: 4,
      text: "Old note", quote: "line worth"))
    let legacy = try #require(f.replica.state(of: Podcasts.self).notes["legacy"])
    #expect(service.status(of: legacy) == .legacy)
    #expect(legacy.anchor == nil)
    let oversized = TranscriptNoteAnchor(reference: reference, startUTF16: Int.max, lengthUTF16: Int.max,
      quote: "line worth")
    #expect(!oversized.matches(TranscriptDocument(text: text, words: nil)))
    #expect(throws: SharedTranscriptError.wrongCitation) {
      try service.noteCommand(episode: "episode", show: "show", text: "Invalid", anchor: oversized)
    }
  }
}
