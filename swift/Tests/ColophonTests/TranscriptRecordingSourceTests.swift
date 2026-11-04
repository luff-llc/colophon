import ColophonAuthority
import ColophonCore
import ColophonListening
import ColophonReplica
import ColophonStore
import Foundation
import Testing

@Suite struct TranscriptRecordingSourceTests {
  private let source = TranscriptRecordingSource(feed: "https://example.org/feed", guid: "episode-1",
    enclosure: "https://example.org/audio.mp3", byteLength: 1234)

  @Test func metadataRequiresEveryFieldAndValidPositiveLength() throws {
    try source.validate()
    #expect(source.matches(source))
    let changed = TranscriptRecordingSource(feed: source.feed, guid: source.guid,
      enclosure: source.enclosure, byteLength: 1235)
    #expect(!source.matches(changed))
    let otherFeed = TranscriptRecordingSource(feed: "https://example.org/other-feed", guid: source.guid,
      enclosure: source.enclosure, byteLength: source.byteLength)
    let otherEpisode = TranscriptRecordingSource(feed: source.feed, guid: "other-episode",
      enclosure: source.enclosure, byteLength: source.byteLength)
    let otherEnclosure = TranscriptRecordingSource(feed: source.feed, guid: source.guid,
      enclosure: "https://example.org/replacement.mp3", byteLength: source.byteLength)
    #expect(!source.matches(otherFeed))
    #expect(!source.matches(otherEpisode))
    #expect(!source.matches(otherEnclosure))
    let missing = TranscriptRecordingSource(feed: source.feed, guid: "", enclosure: source.enclosure, byteLength: 1234)
    #expect(!source.matches(missing))
    let zero = TranscriptRecordingSource(feed: source.feed, guid: source.guid, enclosure: source.enclosure, byteLength: 0)
    #expect(!zero.matches(zero))
    let credential = TranscriptRecordingSource(feed: source.feed, guid: source.guid,
      enclosure: "https://person:secret@example.org/audio.mp3", byteLength: 1234)
    #expect(!credential.matches(credential))
  }

  @Test func receiptAndRequestWithoutSourceRemainReadable() throws {
    let receipt = TranscriptSourceReceipt()
    let data = try JSONEncoder().encode(receipt)
    let restored = try JSONDecoder().decode(TranscriptSourceReceipt.self, from: data)
    #expect(restored.recordingSource == nil)
    let request = TranscriptPreparationRequest(id: "request", libraryID: "library", episode: "episode", show: "show")
    let requestData = try JSONEncoder().encode(request)
    let restoredRequest = try JSONDecoder().decode(TranscriptPreparationRequest.self, from: requestData)
    #expect(restoredRequest.recordingSource == nil)
  }

  @Test func receiptRetainsHistoricalSourceWithoutClaimingDigestVerification() throws {
    let receipt = TranscriptSourceReceipt(recordingSource: source)
    try receipt.validate()
    let data = try JSONEncoder().encode(receipt)
    let restored = try JSONDecoder().decode(TranscriptSourceReceipt.self, from: data)
    #expect(restored.recordingSource == source)
    #expect(restored.recordingDigest == nil)
  }

  @Test func signedRecordingSourceSurvivesSyncToAnotherReplica() async throws {
    let store = MemoryStore()
    let member = SoftwareIdentity()
    let (holder, _) = try AuthorityHolder.create(in: store, label: "Source round trip",
      root: SoftwareIdentity(), firstMember: member.publicIdentity, memberLabel: "Phone",
      role: .app, custody: .software, namespaces: [Podcasts.namespace])
    let libraryID = try holder.state().libraryID
    let first = Replica(store: store, identity: member)
    let digest = Canonical.digest(Data("recording".utf8))
    let request = TranscriptPreparationRequest(id: "source-round-trip", libraryID: libraryID,
      episode: "episode", show: "show", recordingDigest: digest, recordingSource: source)
    let result = TranscriptPreparationResult(document: TranscriptDocument(text: "Original words.",
      words: [.init(text: "Original", start: 0, end: 1, timing: "word"),
        .init(text: "words.", start: 1, end: 2, timing: "word")]), source: "onDevice",
      receipt: TranscriptSourceReceipt(engine: "Synthetic recording source fixture", recordingDigest: digest,
        recordingSource: source, completeness: .complete))
    let saved = try TranscriptPreparationService(replica: first).apply(request: request, result: result)
    let secondStore = MemoryStore()
    _ = try await StoreSync(local: secondStore, remote: LocalRemote(store)).run()
    let second = Replica(store: secondStore, identity: member)
    let service = TranscriptPreparationService(replica: second)
    let receipt = try service.receipt(for: saved)
    let restoredReceipt = try #require(receipt)
    #expect(restoredReceipt.recordingSource == source)
    #expect(restoredReceipt.recordingDigest == digest)
    let document = try SharedTranscriptService(replica: second).resolve(saved)
    #expect(document == result.document)
  }

}
