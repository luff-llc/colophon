import ColophonAuthority
import ColophonCore
import ColophonReplica
import ColophonStore
import Foundation
import Testing
@testable import ColophonListening

struct QueueRetentionTests {
  private let feed = "https://example.invalid/exact-feed.xml?token=synthetic"

  private func metadata(_ guid: String = "a", title: String = "Private queued title") throws -> QueuedEpisodeMetadata {
    try QueuedEpisodeMetadata(episodeID: Podcasts.episodeID(feed: feed, guid: guid), showID: Podcasts.showID(feed: feed),
      feedURL: feed, guid: guid, title: title, showTitle: "Retained show",
      audioURL: "https://media.example.invalid/" + guid + ".mp3", duration: 600, published: 1_700_000_000)
  }

  private func fixture() throws -> (MemoryStore, Replica, AuthorityHolder) {
    let store = MemoryStore()
    let member = SoftwareIdentity()
    let holder = try AuthorityHolder.create(in: store, label: "Synthetic", root: SoftwareIdentity(),
      firstMember: member.publicIdentity, memberLabel: "Fixture", role: .app, custody: .software,
      namespaces: [Podcasts.namespace]).0
    return (store, Replica(store: store, identity: member), holder)
  }

  @Test func encryptedReferencesSurviveFreshReplicaAndLegacyEditsPruneOnlyRemovedEntries() throws {
    let (store, replica, _) = try fixture()
    let a = try metadata("a"), b = try metadata("b")
    let initial = try replica.perform(Podcasts.queue([a.episodeID, b.episodeID], retaining: [a, b]))
    let fresh = Replica(store: store, identity: replica.identity)
    let before = try fresh.state(of: Podcasts.self)
    let expected = Podcasts.queueRevision(authorID: replica.identity.id, operation: initial)
    #expect(before.queueRevision == expected)
    #expect(before.queuedEpisodeMetadata[a.episodeID] == a)
    #expect(before.queuedEpisodeMetadata[b.episodeID] == b)
    let plaintext = store.snapshot.values.map { String(decoding: $0, as: UTF8.self) }.joined()
    #expect(!plaintext.contains(a.title))
    #expect(!plaintext.contains(a.feedURL))
    try replica.perform(Podcasts.queue([b.episodeID, a.episodeID]))
    let reordered = try replica.state(of: Podcasts.self)
    #expect(reordered.queuedEpisodeMetadata[a.episodeID] == a)
    #expect(reordered.queuedEpisodeMetadata[b.episodeID] == b)
    try replica.perform(Podcasts.queue([b.episodeID]))
    let removed = try fresh.state(of: Podcasts.self)
    #expect(removed.queuedEpisodeMetadata[a.episodeID] == nil)
    #expect(removed.queuedEpisodeMetadata[b.episodeID] == b)
    try replica.perform(Podcasts.queue([]))
    let empty = try fresh.state(of: Podcasts.self)
    #expect(empty.queuedEpisodeMetadata.isEmpty)
  }

  @Test func staleEnrichmentCannotRestoreOldQueueOrderOrRemovedMetadata() throws {
    let (_, replica, _) = try fixture()
    let a = try metadata("a"), b = try metadata("b")
    try replica.perform(Podcasts.queue([a.episodeID, b.episodeID]))
    let initial = try replica.state(of: Podcasts.self)
    try replica.perform(Podcasts.queue([b.episodeID]))
    try replica.perform(Podcasts.retainQueueMetadata([a, b], expectedQueueRevision: initial.queueRevision))
    let stale = try replica.state(of: Podcasts.self)
    let expected = [b.episodeID]
    #expect(stale.queue == expected)
    #expect(stale.queuedEpisodeMetadata.isEmpty)
    try replica.perform(Podcasts.retainQueueMetadata([b], expectedQueueRevision: stale.queueRevision))
    let enriched = try replica.state(of: Podcasts.self)
    #expect(enriched.queue == expected)
    #expect(enriched.queueRevision == stale.queueRevision)
    #expect(enriched.queuedEpisodeMetadata[b.episodeID] == b)
    #expect(enriched.episodes.isEmpty)
    #expect(enriched.shows.isEmpty)
    let olderCache = try metadata("b", title: "Older cached title")
    try replica.perform(Podcasts.retainQueueMetadata([olderCache], expectedQueueRevision: enriched.queueRevision))
    let preserved = try replica.state(of: Podcasts.self)
    #expect(preserved.queuedEpisodeMetadata[b.episodeID] == b)
  }

  @Test func malformedMetadataKeepsLegacyQueueSemanticsWithoutPartiallyReplacingRetainedValues() throws {
    let (_, replica, _) = try fixture()
    let a = try metadata("a"), b = try metadata("b")
    try replica.perform(Podcasts.queue([a.episodeID], retaining: [a]))
    var bad = b.json.object ?? [:]
    bad["episode"] = .string(a.episodeID)
    try replica.perform(Command(namespace: Podcasts.namespace, kind: Podcasts.Kind.queue,
      payload: ["episodes": .array([.string(b.episodeID), .string(a.episodeID)]),
        "metadata": .array([b.json, .object(bad)])]))
    let state = try replica.state(of: Podcasts.self)
    let expected = [b.episodeID, a.episodeID]
    #expect(state.queue == expected)
    #expect(state.queuedEpisodeMetadata[a.episodeID] == a)
    #expect(state.queuedEpisodeMetadata[b.episodeID] == nil)
    let legacy = Command(namespace: Podcasts.namespace, kind: Podcasts.Kind.queue,
      payload: ["episodes": .array([.string("legacy"), .number(1), .string("legacy")])])
    try replica.perform(legacy)
    let oldBehavior = try replica.state(of: Podcasts.self)
    let oldExpected = ["legacy", "legacy"]
    #expect(oldBehavior.queue == oldExpected)
  }

  @Test(arguments: ["file:///private/reading.mp3", "data:audio/wav;base64,AAAA", "https://user:pass@example.invalid/a.mp3",
    "javascript:alert(1)", "https:///missing-host.mp3", "https://example.invalid/\nfile.mp3"])
  func unsafePlaybackURLsAreRejected(_ audio: String) throws {
    #expect(throws: QueuedEpisodeMetadataError.self) {
      try QueuedEpisodeMetadata(episodeID: Podcasts.episodeID(feed: feed, guid: "a"), showID: Podcasts.showID(feed: feed),
        feedURL: feed, guid: "a", title: "Episode", showTitle: "Show", audioURL: audio)
    }
  }

  @Test func exactIdentitiesSizeLimitsAndExpectedQueueTokenAreValidated() throws {
    let a = try metadata()
    #expect(throws: QueuedEpisodeMetadataError.self) {
      try QueuedEpisodeMetadata(episodeID: "wrong", showID: a.showID, feedURL: feed, guid: a.guid,
        title: a.title, showTitle: a.showTitle, audioURL: a.audioURL)
    }
    #expect(throws: QueuedEpisodeMetadataError.self) { try metadata(title: String(repeating: "x", count: 2_049)) }
    #expect(throws: QueuedEpisodeMetadataError.self) { try Podcasts.queue([a.episodeID], retaining: [a, a]) }
    #expect(throws: QueuedEpisodeMetadataError.self) { try Podcasts.queue([], retaining: [a]) }
    #expect(throws: QueuedEpisodeMetadataError.self) { try Podcasts.retainQueueMetadata([a], expectedQueueRevision: "") }
    let tooMany = (0...QueuedEpisodeMetadata.maximumEntries).map { _ in a }
    #expect(throws: QueuedEpisodeMetadataError.self) { try Podcasts.retainQueueMetadata(tooMany, expectedQueueRevision: nil) }
  }

  @Test func aggregateMetadataSizeIsBoundedBeforeWriting() throws {
    let title = String(repeating: "x", count: 2_048)
    let entries = try (0..<QueuedEpisodeMetadata.maximumEntries).map { try metadata("episode-\($0)", title: title) }
    #expect(throws: QueuedEpisodeMetadataError.self) {
      try Podcasts.queue(entries.map(\.episodeID), retaining: entries)
    }
  }

  @Test func missingExpectationOrOutsideQueueMetadataCannotEnrich() throws {
    let (_, replica, _) = try fixture()
    let a = try metadata()
    try replica.perform(Podcasts.queue([a.episodeID]))
    try replica.perform(Command(namespace: Podcasts.namespace, kind: Podcasts.Kind.queueRetain,
      payload: ["metadata": .array([a.json])]))
    var state = try replica.state(of: Podcasts.self)
    #expect(state.queuedEpisodeMetadata.isEmpty)
    let other = try metadata("other")
    try replica.perform(Podcasts.retainQueueMetadata([other], expectedQueueRevision: state.queueRevision))
    state = try replica.state(of: Podcasts.self)
    #expect(state.queuedEpisodeMetadata.isEmpty)
    let expected = [a.episodeID]
    #expect(state.queue == expected)
  }
}
