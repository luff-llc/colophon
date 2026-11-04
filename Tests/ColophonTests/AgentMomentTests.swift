import ColophonAuthority
import ColophonCore
import ColophonListening
import ColophonMCP
import ColophonReplica
import ColophonStore
import Foundation
import Testing

/// What agents can learn about a moment: timed transcript segments, the words around a second,
/// the chapter it falls in, and notes nearby.
@Suite struct AgentMomentTests {
  private let digest = String(repeating: "ab", count: 32)

  private func library() throws -> Replica {
    let store = MemoryStore()
    let member = SoftwareIdentity()
    _ = try AuthorityHolder.create(in: store, label: "Moment test", root: SoftwareIdentity(),
      firstMember: member.publicIdentity, memberLabel: "Player", custody: .software,
      namespaces: [Podcasts.namespace])
    return Replica(store: store, identity: member)
  }

  private func query(_ name: String, _ replica: Replica, _ arguments: [String: JSONValue]) throws -> [String: JSONValue] {
    let adapter = ModuleAdapter(Podcasts.self)
    let spec = try #require(adapter.queries.first { $0.name == name })
    return try #require(try spec.run(replica, arguments).object)
  }

  private func timedTranscript(_ replica: Replica) throws {
    let words = "Welcome back to the harbour. The keeper logged every ship."
      .split(separator: " ").enumerated().map { index, word in
        TranscriptDocument.Word(text: String(word), start: Double(index), end: Double(index) + 0.9)
      }
    try replica.saveTranscript(TranscriptDocument(text: words.map(\.text).joined(separator: " "), words: words),
      episode: "e", show: "s", source: "onDevice", language: "en")
  }

  @Test func transcriptCarriesTimedSentences() throws {
    let replica = try library()
    try timedTranscript(replica)
    let result = try query("transcript", replica, ["episode": "e"])
    let segments = result["segments"]?.array ?? []
    let texts = segments.compactMap { $0.object?["text"]?.string }
    let expected: [String] = ["Welcome back to the harbour.", "The keeper logged every ship."]
    #expect(texts == expected)
    let secondStart = segments.last?.object?["start"]?.double
    #expect(secondStart == 5)
  }

  @Test func momentGivesWhatWasSaidItsChapterAndNearbyNotes() throws {
    let replica = try library()
    try timedTranscript(replica)
    try replica.perform(Podcasts.chapters(episode: "e", show: "s", audio: digest,
      entries: [(0, "Arrival"), (5, "The keeper's log")], source: "generated", origin: "Transcript sections"))
    try replica.perform(Podcasts.note(episode: "e", show: "s", seconds: 7, text: "", quote: "every ship"))
    let result = try query("moment", replica, ["episode": "e", "seconds": .number(8), "window": .number(3)])
    let said = result["said"]?.string ?? ""
    #expect(said.contains("logged every ship"))
    #expect(!said.contains("Welcome"))
    let chapter = result["chapter"]?.object?["title"]?.string
    #expect(chapter == "The keeper's log")
    let notes = result["notes"]?.array ?? []
    #expect(notes.count == 1)
  }

  @Test func momentSaysWhenThereIsNoTranscriptYet() throws {
    let replica = try library()
    let result = try query("moment", replica, ["episode": "e", "seconds": .number(8)])
    #expect(result["said"] == .null)
    #expect(result["transcript"]?.string == "none")
  }

  @Test func personsChaptersBeatGeneratedOnesForTheSameRecording() throws {
    let replica = try library()
    try replica.perform(Podcasts.chapters(episode: "e", show: "s", audio: digest, entries: [(0, "Mine")],
      source: "person", origin: nil))
    try replica.perform(Podcasts.chapters(episode: "e", show: "s", audio: digest, entries: [(0, "Model's")],
      source: "generated", origin: "Apple Intelligence"))
    let state = try replica.state(of: Podcasts.self)
    let title = state.chapterSet(for: "e", recordingDigest: digest)?.entries.first?.title
    #expect(title == "Mine")
    #expect(state.chapterSet(for: "e", recordingDigest: nil) == nil)
  }

  @Test func chaptersForAnotherRecordingAreIgnoredAndBadDigestsRejected() throws {
    let replica = try library()
    try replica.perform(Podcasts.chapters(episode: "e", show: "s", audio: "not-a-digest", entries: [(0, "X")],
      source: "generated", origin: nil))
    let state = try replica.state(of: Podcasts.self)
    #expect(state.chapters.isEmpty)
    let other = String(repeating: "cd", count: 32)
    #expect(state.chapterSet(for: "e", recordingDigest: other) == nil)
  }

  @Test func agentsSeeTheListFieldsInToolSchemas() throws {
    let adapter = ModuleAdapter(Podcasts.self)
    let chapters = try #require(adapter.operations.first { $0.kind == Podcasts.ChapterKind.save })
    let entries = try #require(chapters.fields.first { $0.name == "entries" })
    #expect(entries.schema.object?["type"]?.string == "array")
    let segments = try #require(adapter.operations.first { $0.kind == Podcasts.ContentKind.segments })
    let hasSegmentsField = segments.fields.contains { $0.name == "segments" }
    #expect(hasSegmentsField)
  }
}
