import ColophonAuthority
import ColophonCore
import ColophonListening
import ColophonReplica
import ColophonStore
import Foundation
import Testing

struct LegacyPodcastStateImportTests {
  private struct Fixture {
    let store = MemoryStore()
    let root = SoftwareIdentity()
    let phone = SoftwareIdentity()
    let second = SoftwareIdentity()
    let agent = SoftwareIdentity()
    let holder: AuthorityHolder
    let lineage = "0d73b5e3-dbd5-47e1-9438-b050a15f5e84"
    let sourceRoot = String(repeating: "b", count: 64)
    let feed = "https://example.invalid/podcast.xml"
    init() throws {
      holder = try AuthorityHolder.create(in: store, label: "Synthetic migration", root: root,
        firstMember: phone.publicIdentity, memberLabel: "Phone", role: .app,
        custody: .software, namespaces: [Podcasts.namespace]).0
      try holder.admit(second.publicIdentity, label: "Second", role: .device,
        custody: .software, namespaces: [Podcasts.namespace], write: true)
      try holder.admit(agent.publicIdentity, label: "Agent", role: .agent,
        custody: .software, namespaces: [Podcasts.namespace], write: true)
    }
    var replica: Replica { Replica(store: store, identity: phone) }
    var libraryID: String { get throws { try replica.authority().libraryID } }
    func record(_ guid: String = "exact-guid", seconds: Double? = 37, state: String? = "completed") -> LegacyPodcastStateRecord {
      LegacyPodcastStateRecord(legacyID: Canonical.digest(Data((feed + "|" + guid).utf8)),
        feed: feed, guid: guid, seconds: seconds, consumption: state,
        updated: Date(timeIntervalSince1970: 1_700_000_000))
    }
    func signFeeds() throws {
      let show = Podcasts.showID(feed: feed)
      _ = try LegacyBridgeImportService(replica: replica).commit(targetLibraryID: libraryID,
        lineageID: lineage, sourceRoot: sourceRoot, parentSourceRoot: nil,
        feeds: [LegacyPodcastFeedCrosswalk(legacyID: "source-feed", feedURL: feed, title: "Source show", targetShowID: show)],
        sharedOperationInventory: [], expectedLineageRoot: nil, expectedShowHeads: [show: nil], commandID: "reviewed-source")
    }
    @discardableResult func commit(_ records: [LegacyPodcastStateRecord], on target: Replica? = nil) throws -> String {
      try LegacyPodcastStateImportService(replica: target ?? replica).commit(libraryID: libraryID,
        lineageID: lineage, sourceRoot: sourceRoot, records: records.sorted { $0.legacyID < $1.legacyID })
    }
  }

  @Test func interruptionAfterFeedReceiptAndStateWriteIsIdempotentAcrossRestartAndSigner() throws {
    let f = try Fixture()
    try f.signFeeds() // Simulate termination before any progress batch.
    let record = f.record()
    _ = try f.commit([record])
    let before = try f.replica.read(Podcasts.namespace).admitted.count
    let restarted = Replica(store: f.store, identity: f.phone)
    _ = try f.commit([record], on: restarted)
    _ = try f.commit([record], on: Replica(store: f.store, identity: f.second))
    let after = try f.replica.read(Podcasts.namespace).admitted.count
    let state = try f.replica.state(of: Podcasts.self)
    let episode = try #require(state.episodes[record.episodeID])
    #expect(episode.seconds == 37)
    #expect(episode.consumption == "completed")
    #expect(episode.updated == record.updated)
    #expect(before == after)
    #expect(state.legacyPodcastStateReceipts.count == 1)
    #expect(state.notes.isEmpty)
    #expect(state.queue.isEmpty)
  }

  @Test func interruptedPrefixRetryKeepsNativeRewindAndImportsRemainingBatch() throws {
    let f = try Fixture()
    try f.signFeeds()
    let first = f.record("first")
    let second = f.record("second", seconds: 19, state: "inProgress")
    _ = try f.commit([first])
    _ = try f.replica.perform(Podcasts.position(episode: first.episodeID, show: first.showID,
      seconds: 2, duration: nil, deliberate: true, expect: nil))
    _ = try f.replica.perform(Podcasts.setState(episode: first.episodeID, show: first.showID,
      consumption: "abandoned", expect: nil))
    _ = try f.commit([first, second])
    let state = try f.replica.state(of: Podcasts.self)
    #expect(state.episodes[first.episodeID]?.seconds == 2)
    #expect(state.episodes[first.episodeID]?.consumption == "abandoned")
    #expect(state.episodes[second.episodeID]?.seconds == 19)
    #expect(state.legacyPodcastStateDigests.count == 2)
  }

  @Test func nativeFieldsWinBeforeImportAndPassiveNativeWriteSupersedesImportedBaseline() throws {
    let f = try Fixture()
    try f.signFeeds()
    let record = f.record()
    _ = try f.replica.perform(Podcasts.position(episode: record.episodeID, show: record.showID,
      seconds: 0, duration: nil, deliberate: true, expect: nil))
    _ = try f.replica.perform(Podcasts.setState(episode: record.episodeID, show: record.showID,
      consumption: "notStarted", expect: nil))
    _ = try f.commit([record])
    let state = try f.replica.state(of: Podcasts.self)
    #expect(state.episodes[record.episodeID]?.seconds == 0)
    #expect(state.episodes[record.episodeID]?.consumption == "notStarted")
    let other = f.record("another-guid")
    _ = try f.commit([other])
    _ = try f.replica.perform(Podcasts.position(episode: other.episodeID, show: other.showID,
      seconds: 1, duration: nil, deliberate: false, expect: nil))
    let later = try f.replica.state(of: Podcasts.self)
    #expect(later.episodes[other.episodeID]?.seconds == 1)
  }

  @Test func forgedIdentityMalformedBatchChangedSourceAndAgentCannotProject() throws {
    let f = try Fixture()
    try f.signFeeds()
    let valid = f.record()
    let forged = LegacyPodcastStateRecord(legacyID: "wrong", feed: f.feed, guid: "actual-guid",
      seconds: 10, consumption: nil, updated: valid.updated)
    #expect(throws: LegacyBridgeImportError.invalidCommand) { try f.commit([valid, forged]) }
    let agent = Replica(store: f.store, identity: f.agent)
    let payload = try LegacyPodcastStateImport.payload(libraryID: f.libraryID, lineageID: f.lineage,
      sourceRoot: f.sourceRoot, records: [valid])
    _ = try agent.perform(Command(namespace: Podcasts.namespace, kind: LegacyPodcastStateImport.kind, payload: payload))
    let before = try f.replica.state(of: Podcasts.self)
    #expect(before.episodes.isEmpty)
    _ = try f.commit([valid])
    let changed = f.record(seconds: 99)
    #expect(throws: LegacyBridgeImportError.sourceRecordConflict) { try f.commit([changed]) }
    let after = try f.replica.state(of: Podcasts.self)
    #expect(after.episodes[valid.episodeID]?.seconds == 37)
  }

  private enum OldPodcastClient: DomainModule {
    static let namespace = Podcasts.namespace
    static let version = 1
    static let kinds = [Podcasts.Kind.legacyBridgeImport]
    static func fold(_ view: ReplicaView) -> Int {
      view.admitted.filter { kinds.contains($0.operation.kind) }.count
    }
  }

  @Test func oldClientIgnoresUnknownKindWithoutRejectingLibraryHistory() throws {
    let f = try Fixture()
    try f.signFeeds()
    _ = try f.commit([f.record()])
    let oldState = try f.replica.state(of: OldPodcastClient.self)
    let view = try f.replica.read(Podcasts.namespace)
    #expect(oldState == 1)
    #expect(view.admitted.count == 2)
    #expect(view.rejected.isEmpty)
    #expect(view.held.isEmpty)
  }

  @Test func unreviewedFeedRetriesFailBeforeAddingAnyJournalEntry() throws {
    let f = try Fixture()
    try f.signFeeds()
    let otherFeed = "https://example.invalid/not-reviewed.xml"
    let record = LegacyPodcastStateRecord(legacyID: Canonical.digest(Data((otherFeed + "|guid").utf8)),
      feed: otherFeed, guid: "guid", seconds: 3, consumption: nil,
      updated: Date(timeIntervalSince1970: 1_700_000_000))
    let before = try f.replica.read(Podcasts.namespace).admitted.count
    #expect(throws: LegacyBridgeImportError.invalidCommand) { try f.commit([record]) }
    #expect(throws: LegacyBridgeImportError.invalidCommand) { try f.commit([record]) }
    let after = try f.replica.read(Podcasts.namespace).admitted.count
    #expect(before == after)
    let state = try f.replica.state(of: Podcasts.self)
    #expect(state.episodes.isEmpty)
  }
}
