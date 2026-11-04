import ColophonAuthority
import ColophonCore
import ColophonListening
import ColophonReplica
import ColophonStore
import Foundation
import Testing

struct PodcastSourcePublicationTests {
  @Test func fractionalSourceDatesRoundTripAndRetryWithoutFactCollisions() throws {
    let f = try Fixture()
    let originalDate = Date(timeIntervalSinceReferenceDate: 123_456_789.12345678)
    let base = f.fact()
    let fact = PodcastSourceFact(sourceActor: base.sourceActor, operationID: base.operationID,
      sourceClock: base.sourceClock, sourceDate: originalDate, sourceDigest: base.sourceDigest,
      kind: base.kind, metadata: base.metadata, body: base.body)
    try f.publish([fact], [f.action(fact)])
    let state = try f.replica.state(of: Podcasts.self)
    #expect(state.podcastSourceFacts[fact.key] == fact)
    #expect(state.episodes[f.episode]?.seconds == 37)
    try f.publish([fact], [f.action(fact)], replica: Replica(store: f.store, identity: f.second))
    let reopened = try f.replica.state(of: Podcasts.self)
    #expect(reopened.podcastSourceFacts.count == 1)
    #expect(reopened.podcastSourceFacts[fact.key]?.sourceDigest == base.sourceDigest)
  }
  struct Fixture {
    let store = MemoryStore()
    let root = SoftwareIdentity()
    let phone = SoftwareIdentity()
    let second = SoftwareIdentity()
    let agent = SoftwareIdentity()
    let holder: AuthorityHolder
    let feed = "https://example.invalid/feed"
    init() throws {
      holder = try AuthorityHolder.create(in: store, label: "Source test", root: root,
        firstMember: phone.publicIdentity, memberLabel: "Phone", role: .app,
        custody: .software, namespaces: [Podcasts.namespace]).0
      try holder.admit(second.publicIdentity, label: "Other", role: .device, custody: .software, namespaces: [Podcasts.namespace], write: true)
      try holder.admit(agent.publicIdentity, label: "Agent", role: .agent, custody: .software, namespaces: [Podcasts.namespace], write: true)
    }
    var replica: Replica { Replica(store: store, identity: phone) }
    var library: String { get throws { try replica.authority().libraryID } }
    var episode: String { Podcasts.episodeID(feed: feed, guid: "guid") }
    var show: String { Podcasts.showID(feed: feed) }
    func fact(_ id: String = "source-op", seconds: Double = 37, kind: String = "position") -> PodcastSourceFact {
      PodcastSourceFact(sourceActor: "original-device", operationID: id, sourceClock: 12,
        sourceDate: Date(timeIntervalSince1970: 1234), sourceDigest: String(repeating: "a", count: 64), kind: kind,
        metadata: ["itemID": .string(Canonical.digest(Data((feed + "|guid").utf8))), "feedURL": .string(feed)],
        body: kind == "position" ? ["seconds": .number(seconds), "deliberate": .bool(false)] : ["consumption": .string("completed")])
    }
    func action(_ fact: PodcastSourceFact, id: String = "baseline", mode: PodcastSourceAction.Mode = .baseline, head: String? = nil) -> PodcastSourceAction {
      PodcastSourceAction(actionID: id, factKey: fact.key, feed: feed, guid: "guid", mode: mode, expectedRevision: head)
    }
    func publish(_ facts: [PodcastSourceFact], _ actions: [PodcastSourceAction], replica target: Replica? = nil) throws {
      _ = try PodcastSourcePublicationService(replica: target ?? replica).publish(libraryID: library, facts: facts, actions: actions)
    }
  }

  @Test func offlineFactsLaterMappingThenNativeRewindAndRestartReplay() throws {
    let f = try Fixture(); let fact = f.fact(); let action = f.action(fact)
    try f.publish([fact], [])
    #expect(try f.replica.state(of: Podcasts.self).episodes.isEmpty)
    try f.publish([], [action])
    let baseline = try f.replica.state(of: Podcasts.self)
    #expect(baseline.episodes[f.episode]?.seconds == 37)
    #expect(baseline.episodes[f.episode]?.updated == fact.sourceDate)
    let head = try #require(baseline.episodes[f.episode]?.positionRevision)
    let reopened = try Replica(store: f.store, identity: f.second).state(of: Podcasts.self)
    let predecessor = try #require(reopened.podcastSourceRevisions[head])
    #expect(predecessor.applied)
    #expect(predecessor.action == action)
    _ = try f.replica.perform(Podcasts.position(episode: f.episode, show: f.show, seconds: 2, duration: nil, deliberate: false, expect: nil))
    try f.publish([fact], [action], replica: Replica(store: f.store, identity: f.second))
    let state = try f.replica.state(of: Podcasts.self)
    #expect(state.episodes[f.episode]?.seconds == 2)
    #expect(state.podcastSourceFacts.count == 1)
    #expect(state.podcastSourceActions.count == 1)
    let nativeHead = try #require(state.episodes[f.episode]?.positionRevision)
    #expect(state.podcastSourceRevisions[nativeHead] == nil)
  }

  @Test func baselinePreservesNativeZeroAndCompletionAndLiveUsesExactHead() throws {
    let f = try Fixture(); let fact = f.fact(); let consumption = f.fact("state", kind: "consumption")
    _ = try f.replica.perform(Podcasts.position(episode: f.episode, show: f.show, seconds: 0, duration: nil, deliberate: true, expect: nil))
    _ = try f.replica.perform(Podcasts.setState(episode: f.episode, show: f.show, consumption: "abandoned", expect: nil))
    try f.publish([fact, consumption], [f.action(fact), f.action(consumption, id: "state")])
    let before = try f.replica.state(of: Podcasts.self)
    #expect(before.episodes[f.episode]?.seconds == 0)
    #expect(before.episodes[f.episode]?.consumption == "abandoned")
    let head = before.episodes[f.episode]?.positionRevision
    try f.publish([], [f.action(fact, id: "stale", mode: .live)])
    try f.publish([], [f.action(fact, id: "live", mode: .live, head: head)])
    let state = try f.replica.state(of: Podcasts.self)
    #expect(state.podcastSourceActions["stale"]?.applied == false)
    #expect(state.podcastSourceActions["live"]?.applied == true)
    #expect(state.episodes[f.episode]?.seconds == 37)
    let changed = f.action(fact, id: "live", mode: .live, head: state.episodes[f.episode]?.positionRevision)
    #expect(throws: PodcastSourcePublication.Failure.self) { try f.publish([], [changed]) }
  }

  @Test func wholeBatchCollisionAndInvalidRoleAreRejectedBeforeWrite() throws {
    let f = try Fixture(); let fact = f.fact()
    try f.publish([fact], [])
    let changed = f.fact(seconds: 99)
    #expect(throws: PodcastSourcePublication.Failure.self) { try f.publish([changed, f.fact("new")], []) }
    #expect(try f.replica.state(of: Podcasts.self).podcastSourceFacts.count == 1)
    #expect(throws: PodcastSourcePublication.Failure.self) {
      try f.publish([f.fact("agent")], [], replica: Replica(store: f.store, identity: f.agent))
    }
    let invalid = PodcastSourceFact(sourceActor: "a", operationID: "b", sourceClock: 0, sourceDate: .now,
      sourceDigest: String(repeating: "a", count: 64), kind: "position", metadata: ["itemID": .string("i")],
      body: ["seconds": .number(1), "deliberate": .bool(false), "privateText": .string("forbidden")])
    #expect(throws: PodcastSourcePublication.Failure.self) { try f.publish([invalid], []) }
  }
  @Test func rawWrongLibraryAndMalformedFactsNeverPartiallyFold() throws {
    let f = try Fixture(); let fact = f.fact()
    let wrong = try PodcastSourcePublication.payload(libraryID: String(repeating: "0", count: 32), facts: [fact], actions: [])
    _ = try f.replica.perform(Command(namespace: Podcasts.namespace, kind: PodcastSourcePublication.kind, payload: wrong))
    var malformed = try PodcastSourcePublication.payload(libraryID: f.library, facts: [fact], actions: [])
    malformed["extra"] = .string("bad")
    _ = try f.replica.perform(Command(namespace: Podcasts.namespace, kind: PodcastSourcePublication.kind, payload: malformed))
    let state = try f.replica.state(of: Podcasts.self)
    #expect(state.podcastSourceFacts.isEmpty)
    #expect(state.podcastSourceReceipts.isEmpty)
  }

  @Test func longSourceClockRoundTripsAndAudioOnlyActionsAreRequired() throws {
    let f = try Fixture()
    let fact = PodcastSourceFact(sourceActor: "device", operationID: "bookmark", sourceClock: Int64.max,
      sourceDate: Date(timeIntervalSince1970: 1234), sourceDigest: String(repeating: "b", count: 64), kind: "position",
      metadata: ["itemID": .string(f.episode), "feedURL": .string(f.feed), "guid": .string("guid")],
      body: ["seconds": .null, "fraction": .number(0.5), "deliberate": .bool(true), "passageAnchor": .string("passage")])
    try f.publish([fact], [])
    let state = try f.replica.state(of: Podcasts.self)
    #expect(state.podcastSourceFacts[fact.key]?.sourceClock == Int64.max)
    #expect(throws: PodcastSourcePublication.Failure.self) { try f.publish([], [f.action(fact)]) }
  }

  @Test func baselineMissingFieldPreservesExistingNativeActivityDateAndLongActionHead() throws {
    let f = try Fixture(); let consumption = f.fact("consumption", kind: "consumption")
    _ = try f.replica.perform(Podcasts.position(episode: f.episode, show: f.show, seconds: 0, duration: nil, deliberate: true, expect: nil))
    let native = try f.replica.state(of: Podcasts.self)
    try f.publish([consumption], [f.action(consumption, id: "missing-state")])
    let filled = try f.replica.state(of: Podcasts.self)
    #expect(filled.episodes[f.episode]?.updated == native.episodes[f.episode]?.updated)
    #expect(filled.episodes[f.episode]?.consumption == "completed")
    let position = f.fact()
    let longID = String(repeating: "a", count: 128)
    try f.publish([position], [f.action(position, id: longID, mode: .live, head: filled.episodes[f.episode]?.positionRevision)])
    let applied = try f.replica.state(of: Podcasts.self)
    try f.publish([], [f.action(position, id: "quote-long-head", mode: .live, head: applied.episodes[f.episode]?.positionRevision)])
    let quoted = try f.replica.state(of: Podcasts.self)
    #expect(quoted.podcastSourceActions["quote-long-head"]?.applied == true)
  }

  @Test func playbackVisibilityHidesPresentationWithoutChangingRetainedEvidence() throws {
    let f = try Fixture()
    let event = PodcastSourceFact(sourceActor: "source", operationID: "session", sourceClock: 1, sourceDate: .distantPast,
      sourceDigest: String(repeating: "a", count: 64), kind: "playbackEvidence", metadata: ["itemID": .string("opaque")],
      body: ["sessionID": .string("session"), "startSeconds": .number(1), "endSeconds": .number(3), "elapsed": .number(2), "audioDigest": .null, "started": .number(10), "ended": .number(12)])
    func visibility(_ id: String, clock: Int64, hidden: Bool) -> PodcastSourceFact {
      PodcastSourceFact(sourceActor: "source", operationID: id, sourceClock: clock, sourceDate: .distantPast,
        sourceDigest: String(repeating: "b", count: 64), kind: "playbackVisibility", metadata: ["itemID": .string("opaque")],
        body: ["sessionID": .string("session"), "hidden": .bool(hidden)])
    }
    let hide = visibility("hide", clock: 2, hidden: true)
    try f.publish([event, hide], [])
    let retained = try f.replica.state(of: Podcasts.self)
    let hidden = PodcastSourcePublication.visibleFacts(Array(retained.podcastSourceFacts.values))
    #expect(hidden.isEmpty)
    #expect(retained.podcastSourceFacts[event.key] == event)
    let show = visibility("show", clock: 3, hidden: false)
    try f.publish([show], [])
    let shown = PodcastSourcePublication.visibleFacts(Array(try f.replica.state(of: Podcasts.self).podcastSourceFacts.values))
    #expect(shown.count == 1)
    #expect(shown.first == event)
  }

  @Test func visibilityUsesSourceCausalOrderingWhenWallClocksDisagree() throws {
    let f = try Fixture()
    let event = PodcastSourceFact(sourceActor: "source", operationID: "event", sourceClock: 1,
      sourceDate: Date(timeIntervalSince1970: 1), sourceDigest: String(repeating: "a", count: 64),
      kind: "playbackEvidence", metadata: ["itemID": .string("opaque")],
      body: ["sessionID": .string("session"), "startSeconds": .number(1), "endSeconds": .number(3),
        "elapsed": .number(2), "audioDigest": .null, "started": .number(10), "ended": .number(12)])
    func visibility(actor: String, id: String, date: Double, hidden: Bool) -> PodcastSourceFact {
      PodcastSourceFact(sourceActor: actor, operationID: id, sourceClock: 2,
        sourceDate: Date(timeIntervalSince1970: date), sourceDigest: String(repeating: "b", count: 64),
        kind: "playbackVisibility", metadata: ["itemID": .string("opaque")],
        body: ["sessionID": .string("session"), "hidden": .bool(hidden)])
    }
    let laterCausalHide = visibility(actor: "z", id: "hide", date: 100, hidden: true)
    let earlierCausalShow = visibility(actor: "a", id: "show", date: 200, hidden: false)
    try f.publish([event, laterCausalHide, earlierCausalShow], [])
    let state = try f.replica.state(of: Podcasts.self)
    let visible = PodcastSourcePublication.visibleFacts(Array(state.podcastSourceFacts.values))
    #expect(visible.isEmpty)
    #expect(state.podcastSourceFacts[event.key] == event)
    #expect(state.podcastSourceFacts.count == 3)
  }

}
