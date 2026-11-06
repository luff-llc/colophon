import ColophonAuthority
import ColophonCore
import ColophonListening
import ColophonReplica
import ColophonStore
import Foundation
import Testing

@Suite struct PlaybackNaturalEndBatchTests {
  private struct Fixture {
    let store = MemoryStore()
    let root = SoftwareIdentity()
    let phone = SoftwareIdentity()
    let agent = SoftwareIdentity()
    let holder: AuthorityHolder
    let feed = "https://example.test/natural-end.xml"
    var show: String { Podcasts.showID(feed: feed) }
    var a: String { Podcasts.episodeID(feed: feed, guid: "A") }
    var b: String { Podcasts.episodeID(feed: feed, guid: "B") }
    var unresolved: String { Podcasts.episodeID(feed: feed, guid: "unresolved") }
    var replica: Replica { Replica(store: store, identity: phone) }
    var service: PlaybackNaturalEndBatchService { PlaybackNaturalEndBatchService(replica: replica) }

    init() throws {
      holder = try AuthorityHolder.create(in: store, label: "Natural end", root: root,
        firstMember: phone.publicIdentity, memberLabel: "Taupe", role: .app,
        custody: .software, namespaces: [Podcasts.namespace]).0
      try holder.admit(agent.publicIdentity, label: "Agent", role: .agent,
        custody: .software, namespaces: [Podcasts.namespace], write: true)
    }

    func seed(queue rawQueue: [String], metadata: [QueuedEpisodeMetadata] = [],
      seedB: Bool = true) throws {
      _ = try replica.perform(Podcasts.follow(feed: feed, title: "Example"))
      for id in seedB ? [a, b] : [a] {
        _ = try replica.perform(Podcasts.setState(episode: id, show: show,
          consumption: "inProgress", expect: nil))
        _ = try replica.perform(Podcasts.position(episode: id, show: show, seconds: 40,
          duration: 120, deliberate: true, expect: nil))
      }
      if !metadata.isEmpty {
        var seen: Set<String> = []
        let unique = rawQueue.filter { seen.insert($0).inserted }
        _ = try replica.perform(Podcasts.queue(unique, retaining: metadata))
      }
      _ = try replica.perform(Podcasts.queue(rawQueue))
    }

    func end(_ id: String, eventID: String, duration: Double = 120) throws
      -> PlaybackNaturalEndBatch.EndEvent {
      let state = try replica.state(of: Podcasts.self)
      let item = try #require(state.episodes[id])
      return .init(eventID: eventID, episodeID: id, showID: show,
        audioIdentity: "recording:\(id)", endSeconds: duration, actualDuration: duration,
        expectedPositionRevision: item.positionRevision,
        expectedStateRevision: item.stateRevision)
    }
  }

  @Test func atomicTwoEpisodeCompletionPreservesUnresolvedHeadAndRemainingMetadata() throws {
    let f = try Fixture()
    let keep = try QueuedEpisodeMetadata(episodeID: f.unresolved, showID: f.show,
      feedURL: f.feed, guid: "unresolved", title: "Unresolved", showTitle: "Example",
      audioURL: "https://example.test/unresolved.mp3")
    try f.seed(queue: [f.a, f.unresolved, f.a, f.b, f.unresolved], metadata: [keep])
    let state = try f.replica.state(of: Podcasts.self)
    let events = try [f.end(f.a, eventID: "end-A"), f.end(f.b, eventID: "end-B")]
    let receipts = try f.service.commit(events: events, baseQueue: state.queue,
      expectedQueueRevision: state.queueRevision)
    let after = try f.replica.state(of: Podcasts.self)
    let expectedQueue = [f.unresolved]
    #expect(receipts.count == 2)
    #expect(receipts.allSatisfy { $0.outcome == .applied })
    #expect(after.queue == expectedQueue)
    #expect(after.queuedEpisodeMetadata[f.unresolved] == keep)
    #expect(after.episodes[f.a]?.consumption == "completed")
    #expect(after.episodes[f.b]?.consumption == "completed")
    #expect(after.episodes[f.a]?.seconds == 120)
    #expect(after.episodes[f.b]?.duration == 120)
    #expect(after.episodes[f.a]?.positionRevision == receipts[0].operationID)
    #expect(after.episodes[f.a]?.stateRevision == receipts[0].operationID)
    #expect(after.queueRevision == receipts[0].revision)
  }

  @Test func stalePeerSeekOrQueueEditRejectsWholeBatchWithReceipts() throws {
    for change in ["position", "state", "queue"] {
      let f = try Fixture()
      try f.seed(queue: [f.a, f.b])
      let before = try f.replica.state(of: Podcasts.self)
      let events = try [f.end(f.a, eventID: "A-" + change), f.end(f.b, eventID: "B-" + change)]
      switch change {
      case "position":
        _ = try f.replica.perform(Podcasts.position(episode: f.b, show: f.show, seconds: 12,
          duration: 120, deliberate: true, expect: nil))
      case "state":
        _ = try f.replica.perform(Podcasts.setState(episode: f.b, show: f.show,
          consumption: "notStarted", expect: nil))
      default:
        _ = try f.replica.perform(Podcasts.queue([f.b, f.a]))
      }
      let prior = try f.replica.state(of: Podcasts.self)
      let receipts = try f.service.commit(events: events, baseQueue: before.queue,
        expectedQueueRevision: before.queueRevision)
      let after = try f.replica.state(of: Podcasts.self)
      #expect(receipts.count == 2)
      #expect(receipts.allSatisfy { $0.outcome == .stale })
      #expect(after.queue == prior.queue)
      #expect(after.episodes[f.a] == prior.episodes[f.a])
      #expect(after.episodes[f.b] == prior.episodes[f.b])
    }
  }

  @Test func individualEventReceiptSurvivesReplayAfterOneJournalAcknowledgement() throws {
    let f = try Fixture()
    try f.seed(queue: [f.a, f.b])
    let before = try f.replica.state(of: Podcasts.self)
    let events = try [f.end(f.a, eventID: "stable-A"), f.end(f.b, eventID: "stable-B")]
    let first = try f.service.commit(events: events, baseQueue: before.queue,
      expectedQueueRevision: before.queueRevision)
    // The caller can have tombstoned A's local event but crashed before tombstoning B.
    let remaining = try f.service.commit(events: [events[1]], baseQueue: before.queue,
      expectedQueueRevision: before.queueRevision)
    let expectedRemaining = [first[1]]
    #expect(remaining == expectedRemaining)
    let replay = try f.service.commit(events: events, baseQueue: before.queue,
      expectedQueueRevision: before.queueRevision)
    #expect(replay == first)
    let after = try f.replica.state(of: Podcasts.self)
    #expect(after.naturalEndReceipts.count == 2)
    #expect(after.queue.isEmpty)
    let altered = PlaybackNaturalEndBatch.EndEvent(eventID: events[1].eventID,
      episodeID: events[1].episodeID, showID: events[1].showID,
      audioIdentity: "other-audio", endSeconds: 120, actualDuration: 120,
      expectedPositionRevision: events[1].expectedPositionRevision,
      expectedStateRevision: events[1].expectedStateRevision)
    #expect(throws: PlaybackNaturalEndBatchError.eventIDConflict) {
      try f.service.commit(events: [altered], baseQueue: before.queue,
        expectedQueueRevision: before.queueRevision)
    }
  }

  @Test func nilHeadsCreateFirstLoadedEpisodeButLaterStateMakesThemStale() throws {
    let f = try Fixture()
    try f.seed(queue: [f.a, f.b], seedB: false)
    let initial = try f.replica.state(of: Podcasts.self)
    let a = try f.end(f.a, eventID: "nil-chain-A")
    let b = PlaybackNaturalEndBatch.EndEvent(eventID: "nil-chain-B", episodeID: f.b,
      showID: f.show, audioIdentity: "recording:B", endSeconds: 120,
      actualDuration: 120, expectedPositionRevision: nil, expectedStateRevision: nil)
    let applied = try f.service.commit(events: [a, b], baseQueue: initial.queue,
      expectedQueueRevision: initial.queueRevision)
    let completed = try f.replica.state(of: Podcasts.self)
    #expect(applied.allSatisfy { $0.outcome == .applied })
    #expect(completed.episodes[f.b]?.show == f.show)
    #expect(completed.episodes[f.b]?.consumption == "completed")
    #expect(completed.episodes[f.b]?.seconds == 120)
    #expect(completed.queue.isEmpty)

    let changed = try Fixture()
    try changed.seed(queue: [changed.a, changed.b], seedB: false)
    let before = try changed.replica.state(of: Podcasts.self)
    let pendingA = try changed.end(changed.a, eventID: "wrong-nil-A")
    let pendingB = PlaybackNaturalEndBatch.EndEvent(eventID: "wrong-nil-B", episodeID: changed.b,
      showID: changed.show, audioIdentity: "recording:B", endSeconds: 120,
      actualDuration: 120, expectedPositionRevision: nil, expectedStateRevision: nil)
    _ = try changed.replica.perform(Podcasts.setState(episode: changed.b, show: changed.show,
      consumption: "inProgress", expect: nil))
    let stale = try changed.service.commit(events: [pendingA, pendingB], baseQueue: before.queue,
      expectedQueueRevision: before.queueRevision)
    let after = try changed.replica.state(of: Podcasts.self)
    #expect(stale.allSatisfy { $0.outcome == .stale })
    #expect(after.episodes[changed.a]?.consumption == "inProgress")
    #expect(after.episodes[changed.b]?.consumption == "inProgress")
    #expect(after.queue == before.queue)
  }

  @Test func exactlyObservedDoneEnoughAndLegacyV1ActionsKeepTheirSemantics() throws {
    let f = try Fixture()
    try f.seed(queue: [f.a])
    _ = try f.replica.perform(Podcasts.setState(episode: f.a, show: f.show,
      consumption: "doneEnough", expect: nil))
    let observed = try f.replica.state(of: Podcasts.self)
    let event = try f.end(f.a, eventID: "ended-after-done-enough")
    let receipt = try f.service.commit(events: [event], baseQueue: observed.queue,
      expectedQueueRevision: observed.queueRevision)
    #expect(receipt.first?.outcome == .applied)
    let after = try f.replica.state(of: Podcasts.self)
    #expect(after.episodes[f.a]?.consumption == "completed")
    // Legacy v1 writes still use their existing independent paths.
    _ = try f.replica.perform(Podcasts.setState(episode: f.b, show: f.show,
      consumption: "notStarted", expect: nil))
    _ = try f.replica.perform(Podcasts.position(episode: f.b, show: f.show,
      seconds: 7, duration: 120, deliberate: true, expect: nil))
    _ = try f.replica.perform(Podcasts.queue([f.b, f.b]))
    let legacy = try f.replica.state(of: Podcasts.self)
    #expect(legacy.episodes[f.b]?.consumption == "notStarted")
    #expect(legacy.episodes[f.b]?.seconds == 7)
    let legacyQueue = [f.b, f.b]
    #expect(legacy.queue == legacyQueue)
  }

  @Test func malformedVersionUnknownFieldDuplicateEventAndAgentCannotApply() throws {
    let f = try Fixture()
    try f.seed(queue: [f.a, f.b])
    let before = try f.replica.state(of: Podcasts.self)
    let a = try f.end(f.a, eventID: "A")
    let b = try f.end(f.b, eventID: "B")
    #expect(throws: PlaybackNaturalEndBatchError.invalidCommand) {
      try f.service.commit(events: [a, a], baseQueue: before.queue,
        expectedQueueRevision: before.queueRevision)
    }
    let duplicateEpisode = PlaybackNaturalEndBatch.EndEvent(eventID: "A-again",
      episodeID: a.episodeID, showID: a.showID, audioIdentity: a.audioIdentity,
      endSeconds: 120, actualDuration: 120, expectedPositionRevision: a.expectedPositionRevision,
      expectedStateRevision: a.expectedStateRevision)
    #expect(throws: PlaybackNaturalEndBatchError.invalidCommand) {
      try f.service.commit(events: [a, duplicateEpisode], baseQueue: before.queue,
        expectedQueueRevision: before.queueRevision)
    }
    let wrongEnd = PlaybackNaturalEndBatch.EndEvent(eventID: "wrong-end",
      episodeID: a.episodeID, showID: a.showID, audioIdentity: a.audioIdentity,
      endSeconds: 119, actualDuration: 120, expectedPositionRevision: a.expectedPositionRevision,
      expectedStateRevision: a.expectedStateRevision)
    #expect(throws: PlaybackNaturalEndBatchError.invalidCommand) {
      try f.service.commit(events: [wrongEnd], baseQueue: before.queue,
        expectedQueueRevision: before.queueRevision)
    }
    let libraryID = try f.replica.authority().libraryID
    let valid = try PlaybackNaturalEndBatch.payload(libraryID: libraryID, events: [a, b],
      baseQueue: before.queue, expectedQueueRevision: before.queueRevision)
    _ = try f.replica.perform(Command(namespace: Podcasts.namespace,
      kind: PlaybackNaturalEndBatch.kind, v: 2, payload: valid))
    var extra = valid
    extra["unexpected"] = .bool(true)
    _ = try f.replica.perform(Command(namespace: Podcasts.namespace,
      kind: PlaybackNaturalEndBatch.kind, payload: extra))
    let agentReplica = Replica(store: f.store, identity: f.agent)
    #expect(throws: PlaybackNaturalEndBatchError.wrongRole) {
      try PlaybackNaturalEndBatchService(replica: agentReplica).commit(events: [a],
        baseQueue: before.queue, expectedQueueRevision: before.queueRevision)
    }
    _ = try agentReplica.perform(Command(namespace: Podcasts.namespace,
      kind: PlaybackNaturalEndBatch.kind, payload: valid))
    let after = try f.replica.state(of: Podcasts.self)
    #expect(after.queue == before.queue)
    #expect(after.episodes[f.a] == before.episodes[f.a])
    #expect(after.naturalEndReceipts.isEmpty)
  }

  @Test func rawConflictingEventIDCannotPartiallyApplyAnotherEvent() throws {
    let f = try Fixture()
    try f.seed(queue: [f.a, f.b])
    let initial = try f.replica.state(of: Podcasts.self)
    let firstEvent = try f.end(f.a, eventID: "reused")
    let first = try f.service.commit(events: [firstEvent], baseQueue: initial.queue,
      expectedQueueRevision: initial.queueRevision)
    #expect(first.first?.outcome == .applied)

    let afterFirst = try f.replica.state(of: Podcasts.self)
    let conflicting = PlaybackNaturalEndBatch.EndEvent(eventID: "reused",
      episodeID: f.a, showID: f.show, audioIdentity: "different-recording",
      endSeconds: 120, actualDuration: 120,
      expectedPositionRevision: firstEvent.expectedPositionRevision,
      expectedStateRevision: firstEvent.expectedStateRevision)
    let secondEvent = try f.end(f.b, eventID: "new-B")
    let payload = try PlaybackNaturalEndBatch.payload(
      libraryID: f.replica.authority().libraryID, events: [conflicting, secondEvent],
      baseQueue: afterFirst.queue, expectedQueueRevision: afterFirst.queueRevision)
    _ = try f.replica.perform(Command(namespace: Podcasts.namespace,
      kind: PlaybackNaturalEndBatch.kind, payload: payload))
    let afterConflict = try f.replica.state(of: Podcasts.self)
    #expect(afterConflict.naturalEndEventConflicts.contains(
      PlaybackNaturalEndBatch.signerKey(f.phone.id, "reused")))
    #expect(afterConflict.naturalEndReceipts.count == 1)
    #expect(afterConflict.queue == afterFirst.queue)
    #expect(afterConflict.episodes[f.b] == afterFirst.episodes[f.b])
  }

  @Test func staleReceiptThenConflictingEventIDBlocksRawMatchingReceiptAndFreshEvent() throws {
    let f = try Fixture()
    try f.seed(queue: [f.a, f.b])
    let initial = try f.replica.state(of: Podcasts.self)
    let originalA = try f.end(f.a, eventID: "stale-conflicted-A")
    _ = try f.replica.perform(Podcasts.position(episode: f.a, show: f.show, seconds: 41,
      duration: 120, deliberate: true, expect: nil))
    let stale = try f.service.commit(events: [originalA], baseQueue: initial.queue,
      expectedQueueRevision: initial.queueRevision)
    #expect(stale.first?.outcome == .stale)
    let afterStale = try f.replica.state(of: Podcasts.self)
    #expect(afterStale.queue == initial.queue)
    #expect(afterStale.queueRevision == initial.queueRevision)

    let changedA = PlaybackNaturalEndBatch.EndEvent(eventID: originalA.eventID,
      episodeID: originalA.episodeID, showID: originalA.showID,
      audioIdentity: "different-recording", endSeconds: originalA.endSeconds,
      actualDuration: originalA.actualDuration,
      expectedPositionRevision: originalA.expectedPositionRevision,
      expectedStateRevision: originalA.expectedStateRevision)
    let libraryID = try f.replica.authority().libraryID
    let conflicting = try PlaybackNaturalEndBatch.payload(libraryID: libraryID,
      events: [changedA], baseQueue: initial.queue,
      expectedQueueRevision: initial.queueRevision)
    _ = try f.replica.perform(Command(namespace: Podcasts.namespace,
      kind: PlaybackNaturalEndBatch.kind, payload: conflicting))
    let key = PlaybackNaturalEndBatch.signerKey(f.phone.id, originalA.eventID)
    let afterConflict = try f.replica.state(of: Podcasts.self)
    #expect(afterConflict.naturalEndEventConflicts.contains(key))
    #expect(afterConflict.queue == afterStale.queue)

    let freshB = try f.end(f.b, eventID: "fresh-after-conflict-B")
    let mixed = try PlaybackNaturalEndBatch.payload(libraryID: libraryID,
      events: [originalA, freshB], baseQueue: initial.queue,
      expectedQueueRevision: initial.queueRevision)
    _ = try f.replica.perform(Command(namespace: Podcasts.namespace,
      kind: PlaybackNaturalEndBatch.kind, payload: mixed))
    let afterMixed = try f.replica.state(of: Podcasts.self)
    #expect(afterMixed.queue == afterConflict.queue)
    #expect(afterMixed.queueRevision == afterConflict.queueRevision)
    #expect(afterMixed.episodes[f.a] == afterConflict.episodes[f.a])
    #expect(afterMixed.episodes[f.b] == afterConflict.episodes[f.b])
    #expect(afterMixed.naturalEndReceipts[key] == afterConflict.naturalEndReceipts[key])
    #expect(afterMixed.naturalEndReceipts[
      PlaybackNaturalEndBatch.signerKey(f.phone.id, freshB.eventID)] == nil)
  }

  @Test func changedQueueContextForSameEventIDConflictsAndBlocksMixedBatch() throws {
    let f = try Fixture()
    try f.seed(queue: [f.a, f.b])
    let initial = try f.replica.state(of: Podcasts.self)
    let a = try f.end(f.a, eventID: "context-A")
    let applied = try f.service.commit(events: [a], baseQueue: initial.queue,
      expectedQueueRevision: initial.queueRevision)
    #expect(applied.first?.outcome == .applied)
    let afterA = try f.replica.state(of: Podcasts.self)
    let b = try f.end(f.b, eventID: "context-B")
    #expect(throws: PlaybackNaturalEndBatchError.eventIDConflict) {
      try f.service.commit(events: [a, b], baseQueue: afterA.queue,
        expectedQueueRevision: afterA.queueRevision)
    }
    let raw = try PlaybackNaturalEndBatch.payload(libraryID: f.replica.authority().libraryID,
      events: [a, b], baseQueue: afterA.queue,
      expectedQueueRevision: afterA.queueRevision)
    _ = try f.replica.perform(Command(namespace: Podcasts.namespace,
      kind: PlaybackNaturalEndBatch.kind, payload: raw))
    let afterConflict = try f.replica.state(of: Podcasts.self)
    #expect(afterConflict.queue == afterA.queue)
    #expect(afterConflict.episodes[f.b] == afterA.episodes[f.b])
    #expect(afterConflict.naturalEndReceipts.count == 1)
  }

  @Test func wrongLibraryAndInvalidNumbersOrBoundsNeverMutate() throws {
    let f = try Fixture()
    try f.seed(queue: [f.a])
    let before = try f.replica.state(of: Podcasts.self)
    let event = try f.end(f.a, eventID: "valid")
    let wrongLibrary = try PlaybackNaturalEndBatch.payload(libraryID: "another-library",
      events: [event], baseQueue: before.queue,
      expectedQueueRevision: before.queueRevision)
    _ = try f.replica.perform(Command(namespace: Podcasts.namespace,
      kind: PlaybackNaturalEndBatch.kind, payload: wrongLibrary))
    let afterWrongLibrary = try f.replica.state(of: Podcasts.self)
    #expect(afterWrongLibrary.queue == before.queue)
    #expect(afterWrongLibrary.naturalEndReceipts.isEmpty)
    let invalid = PlaybackNaturalEndBatch.EndEvent(eventID: "not-finite",
      episodeID: f.a, showID: f.show, audioIdentity: "recording:A",
      endSeconds: .nan, actualDuration: .nan,
      expectedPositionRevision: event.expectedPositionRevision,
      expectedStateRevision: event.expectedStateRevision)
    #expect(throws: PlaybackNaturalEndBatchError.invalidCommand) {
      try f.service.commit(events: [invalid], baseQueue: before.queue,
        expectedQueueRevision: before.queueRevision)
    }
    let excessiveQueue = Array(repeating: f.a, count: PlaybackNaturalEndBatch.maximumQueueEntries + 1)
    #expect(throws: PlaybackNaturalEndBatchError.invalidCommand) {
      try f.service.commit(events: [event], baseQueue: excessiveQueue,
        expectedQueueRevision: before.queueRevision)
    }
  }

  @Test func rawSignedOversizedArraysAreRejectedBeforeElementTraversal() throws {
    let f = try Fixture()
    try f.seed(queue: [f.a])
    let before = try f.replica.state(of: Podcasts.self)
    let event = try f.end(f.a, eventID: "bound-seed")
    let libraryID = try f.replica.authority().libraryID
    let valid = try PlaybackNaturalEndBatch.payload(libraryID: libraryID, events: [event],
      baseQueue: before.queue, expectedQueueRevision: before.queueRevision)
    let eventObject = try #require(valid["events"]?.array?.first?.object)

    var excessiveEvents: [JSONValue] = []
    for index in 0...PlaybackNaturalEndBatch.maximumEvents {
      var fields = eventObject
      fields["eventID"] = .string("event-\(index)")
      fields["episode"] = .string(Podcasts.episodeID(feed: f.feed, guid: "overflow-\(index)"))
      excessiveEvents.append(.object(fields))
    }
    var eventBody = valid
    eventBody["events"] = .array(excessiveEvents)
    eventBody.removeValue(forKey: "bodyDigest")
    eventBody["bodyDigest"] = .string(Canonical.digest(try Canonical.encode(eventBody)))
    _ = try f.replica.perform(Command(namespace: Podcasts.namespace,
      kind: PlaybackNaturalEndBatch.kind, payload: eventBody))

    var queueBody = valid
    queueBody["baseQueue"] = .array(Array(repeating: .string(f.a),
      count: PlaybackNaturalEndBatch.maximumQueueEntries + 1))
    queueBody.removeValue(forKey: "bodyDigest")
    queueBody["bodyDigest"] = .string(Canonical.digest(try Canonical.encode(queueBody)))
    _ = try f.replica.perform(Command(namespace: Podcasts.namespace,
      kind: PlaybackNaturalEndBatch.kind, payload: queueBody))

    let after = try f.replica.state(of: Podcasts.self)
    #expect(after.queue == before.queue)
    #expect(after.episodes[f.a] == before.episodes[f.a])
    #expect(after.naturalEndReceipts.isEmpty)
  }

  @Test func topLevelCostsAreCeiledFromFractionalSumAndRealCaveatsApply() throws {
    let f = try Fixture()
    try f.seed(queue: [f.a, f.b])
    let caveatedIdentity = SoftwareIdentity()
    try f.holder.admit(caveatedIdentity.publicIdentity, label: "Caveated playback",
      role: .device, custody: .software, namespaces: [Podcasts.namespace], write: true,
      caveats: [.only([PlaybackNaturalEndBatch.kind], in: Podcasts.namespace),
        .ceiling("seconds", max: 121, in: Podcasts.namespace),
        .ceiling("duration", max: 121, in: Podcasts.namespace),
        .budget("seconds", max: 200, in: Podcasts.namespace),
        .budget("duration", max: 200, in: Podcasts.namespace)])
    let writer = Replica(store: f.store, identity: caveatedIdentity)
    let service = PlaybackNaturalEndBatchService(replica: writer)
    let before = try writer.state(of: Podcasts.self)
    let originalA = try f.end(f.a, eventID: "fractional-A")
    let a = PlaybackNaturalEndBatch.EndEvent(eventID: originalA.eventID,
      episodeID: originalA.episodeID, showID: originalA.showID,
      audioIdentity: originalA.audioIdentity, endSeconds: 120.25, actualDuration: 120.25,
      expectedPositionRevision: originalA.expectedPositionRevision,
      expectedStateRevision: originalA.expectedStateRevision)
    let payload = try PlaybackNaturalEndBatch.payload(
      libraryID: writer.authority().libraryID, events: [a], baseQueue: before.queue,
      expectedQueueRevision: before.queueRevision)
    #expect(payload["seconds"] == .number(121))
    #expect(payload["duration"] == .number(121))
    let first = try service.commit(events: [a], baseQueue: before.queue,
      expectedQueueRevision: before.queueRevision)
    #expect(first.first?.outcome == .applied)
    let afterA = try writer.state(of: Podcasts.self)
    #expect(afterA.episodes[f.a]?.seconds == 120.25)

    let originalB = try f.end(f.b, eventID: "fractional-B")
    let aggregateB = PlaybackNaturalEndBatch.EndEvent(eventID: originalB.eventID,
      episodeID: originalB.episodeID, showID: originalB.showID,
      audioIdentity: originalB.audioIdentity, endSeconds: 120.25, actualDuration: 120.25,
      expectedPositionRevision: originalB.expectedPositionRevision,
      expectedStateRevision: originalB.expectedStateRevision)
    let aggregate = try PlaybackNaturalEndBatch.payload(
      libraryID: writer.authority().libraryID, events: [a, aggregateB], baseQueue: before.queue,
      expectedQueueRevision: before.queueRevision)
    #expect(aggregate["seconds"] == .number(241))
    #expect(aggregate["duration"] == .number(241))
    let overCeiling = PlaybackNaturalEndBatch.EndEvent(eventID: "over-ceiling-B",
      episodeID: originalB.episodeID, showID: originalB.showID,
      audioIdentity: originalB.audioIdentity, endSeconds: 121.01, actualDuration: 121.01,
      expectedPositionRevision: originalB.expectedPositionRevision,
      expectedStateRevision: originalB.expectedStateRevision)
    #expect(throws: PlaybackNaturalEndBatchError.notAdmitted) {
      try service.commit(events: [overCeiling], baseQueue: afterA.queue,
        expectedQueueRevision: afterA.queueRevision)
    }
    #expect(throws: PlaybackNaturalEndBatchError.notAdmitted) {
      try service.commit(events: [aggregateB], baseQueue: afterA.queue,
        expectedQueueRevision: afterA.queueRevision)
    }
    let final = try writer.state(of: Podcasts.self)
    #expect(final.episodes[f.b]?.consumption == "inProgress")
    #expect(final.naturalEndReceipts.count == 1)
    let view = try writer.read(Podcasts.namespace)
    #expect(view.rejected.count == 2)
  }

  @Test func signedForgedLowerOrMissingCostDoesNotBypassFold() throws {
    let f = try Fixture()
    try f.seed(queue: [f.a])
    let before = try f.replica.state(of: Podcasts.self)
    let original = try f.end(f.a, eventID: "cost-claim")
    let event = PlaybackNaturalEndBatch.EndEvent(eventID: original.eventID,
      episodeID: original.episodeID, showID: original.showID,
      audioIdentity: original.audioIdentity, endSeconds: 120.25, actualDuration: 120.25,
      expectedPositionRevision: original.expectedPositionRevision,
      expectedStateRevision: original.expectedStateRevision)
    let valid = try PlaybackNaturalEndBatch.payload(libraryID: f.replica.authority().libraryID,
      events: [event], baseQueue: before.queue,
      expectedQueueRevision: before.queueRevision)
    for variant in ["lower", "missing", "fractional"] {
      var forged = valid
      switch variant {
      case "lower":
        forged["seconds"] = .number(1)
        forged["duration"] = .number(1)
      case "missing":
        forged.removeValue(forKey: "seconds")
      default:
        forged["seconds"] = .number(120.25)
      }
      forged.removeValue(forKey: "bodyDigest")
      forged["bodyDigest"] = .string(Canonical.digest(try Canonical.encode(forged)))
      _ = try f.replica.perform(Command(namespace: Podcasts.namespace,
        kind: PlaybackNaturalEndBatch.kind, payload: forged))
    }
    let after = try f.replica.state(of: Podcasts.self)
    #expect(after.episodes[f.a] == before.episodes[f.a])
    #expect(after.queue == before.queue)
    #expect(after.naturalEndReceipts.isEmpty)
  }

  @Test func malformedNegativeNaturalEndCannotRefundARealBudget() throws {
    let f = try Fixture()
    try f.seed(queue: [f.a, f.b])
    let identity = SoftwareIdentity()
    try f.holder.admit(identity.publicIdentity, label: "Budgeted device", role: .device,
      custody: .software, namespaces: [Podcasts.namespace], write: true,
      caveats: [.only([PlaybackNaturalEndBatch.kind], in: Podcasts.namespace),
        .budget("seconds", max: 200, in: Podcasts.namespace),
        .budget("duration", max: 200, in: Podcasts.namespace)])
    let writer = Replica(store: f.store, identity: identity)
    let service = PlaybackNaturalEndBatchService(replica: writer)
    let before = try writer.state(of: Podcasts.self)
    let originalA = try f.end(f.a, eventID: "budget-A")
    let a = PlaybackNaturalEndBatch.EndEvent(eventID: originalA.eventID,
      episodeID: originalA.episodeID, showID: originalA.showID,
      audioIdentity: originalA.audioIdentity, endSeconds: 120.25, actualDuration: 120.25,
      expectedPositionRevision: originalA.expectedPositionRevision,
      expectedStateRevision: originalA.expectedStateRevision)
    let admitted = try service.commit(events: [a], baseQueue: before.queue,
      expectedQueueRevision: before.queueRevision)
    #expect(admitted.first?.outcome == .applied)
    let afterA = try writer.state(of: Podcasts.self)
    let originalB = try f.end(f.b, eventID: "budget-B")
    let b = PlaybackNaturalEndBatch.EndEvent(eventID: originalB.eventID,
      episodeID: originalB.episodeID, showID: originalB.showID,
      audioIdentity: originalB.audioIdentity, endSeconds: 120.25, actualDuration: 120.25,
      expectedPositionRevision: originalB.expectedPositionRevision,
      expectedStateRevision: originalB.expectedStateRevision)
    let validRaw = try PlaybackNaturalEndBatch.payload(libraryID: writer.authority().libraryID,
      events: [b], baseQueue: afterA.queue, expectedQueueRevision: afterA.queueRevision)
    var rejectedSoFar = 0
    for variant in ["negative", "missing", "zero", "fractional", "string", "oversized", "positiveUnderstatement"] {
      var forged = validRaw
      switch variant {
      case "negative":
        forged["seconds"] = .number(-1_000)
        forged["duration"] = .number(-1_000)
      case "missing":
        forged.removeValue(forKey: "seconds")
      case "zero":
        forged["seconds"] = .number(0)
        forged["duration"] = .number(0)
      case "fractional":
        forged["seconds"] = .number(0.5)
      case "string":
        forged["duration"] = .string("121")
      case "oversized":
        forged["seconds"] = .number(1e15)
      default:
        // This is admitted and costs one unit, but the strict domain fold refuses the
        // understatement. It cannot create a budget credit for the later valid B.
        forged["seconds"] = .number(1)
        forged["duration"] = .number(1)
      }
      forged.removeValue(forKey: "bodyDigest")
      forged["bodyDigest"] = .string(Canonical.digest(try Canonical.encode(forged)))
      _ = try writer.perform(Command(namespace: Podcasts.namespace,
        kind: PlaybackNaturalEndBatch.kind, payload: forged))
      if variant != "positiveUnderstatement" { rejectedSoFar += 1 }
      let observedRejections = try writer.read(Podcasts.namespace).rejected.count
      #expect(observedRejections == rejectedSoFar)
    }
    #expect(throws: PlaybackNaturalEndBatchError.notAdmitted) {
      try service.commit(events: [b], baseQueue: afterA.queue,
        expectedQueueRevision: afterA.queueRevision)
    }
    let final = try writer.state(of: Podcasts.self)
    #expect(final.naturalEndReceipts.count == 1)
    #expect(final.episodes[f.b]?.consumption == "inProgress")
    let view = try writer.read(Podcasts.namespace)
    #expect(view.rejected.count == 7)
    let admittedNatural = view.admitted.filter { $0.operation.kind == PlaybackNaturalEndBatch.kind }
    #expect(admittedNatural.count == 2)
  }

  @Test func revokedWriterCannotCommitAndDuplicateSignedOperationIDCannotSupplyHeads() throws {
    let f = try Fixture()
    try f.seed(queue: [f.a])
    let before = try f.replica.state(of: Podcasts.self)
    let event = try f.end(f.a, eventID: "duplicate-operation")
    let first = try f.service.commit(events: [event], baseQueue: before.queue,
      expectedQueueRevision: before.queueRevision)
    let receipt = try #require(first.first)
    let operation = try #require(f.replica.read(Podcasts.namespace).admitted.first {
      $0.operation.id == receipt.operationID
    }?.operation)
    let path = try #require(f.store.snapshot.keys.first {
      $0.hasPrefix("ops/\(f.phone.id)/") && $0.hasSuffix("-\(receipt.operationID).json")
    })
    let maybeBytes = try f.store.read(path)
    let bytes = try #require(maybeBytes)
    let signedRecord = try Canonical.decode(SignedRecord.self, from: bytes)
    let header = try Canonical.decode(OperationHeader.self, from: signedRecord.body)
    let duplicate = OperationHeader(author: f.agent.id, namespace: header.namespace,
      epoch: header.epoch, sealed: header.sealed)
    let signedDuplicate = try SignedRecord(signing: Canonical.encode(duplicate), with: f.agent)
    try f.store.create(LibraryPath.operation(author: f.agent.id, clock: operation.clock,
      id: receipt.operationID), Canonical.encode(signedDuplicate))
    let conflicted = try f.replica.state(of: Podcasts.self)
    #expect(conflicted.naturalEndIntegrityConflicts.contains(receipt.operationID))
    #expect(conflicted.naturalEndReceipts.isEmpty)
    #expect(conflicted.episodes[f.a]?.consumption == "inProgress")
    #expect(conflicted.queue == before.queue)

    let revoked = try Fixture()
    try revoked.seed(queue: [revoked.a])
    let original = try revoked.replica.state(of: Podcasts.self)
    let blocked = try revoked.end(revoked.a, eventID: "revoked")
    try revoked.holder.revoke(revoked.phone.id)
    #expect(throws: PlaybackNaturalEndBatchError.noCurrentAccess) {
      try revoked.service.commit(events: [blocked], baseQueue: original.queue,
        expectedQueueRevision: original.queueRevision)
    }

    let narrow = try Fixture()
    try narrow.seed(queue: [narrow.a])
    let restrictedIdentity = SoftwareIdentity()
    try narrow.holder.admit(restrictedIdentity.publicIdentity, label: "Legacy position writer",
      role: .device, custody: .software, namespaces: [Podcasts.namespace], write: true,
      caveats: [.only([Podcasts.Kind.position], in: Podcasts.namespace)])
    let restricted = Replica(store: narrow.store, identity: restrictedIdentity)
    let narrowState = try restricted.state(of: Podcasts.self)
    let narrowEvent = try narrow.end(narrow.a, eventID: "restricted-kind")
    #expect(throws: PlaybackNaturalEndBatchError.noCurrentAccess) {
      try PlaybackNaturalEndBatchService(replica: restricted).commit(events: [narrowEvent],
        baseQueue: narrowState.queue, expectedQueueRevision: narrowState.queueRevision)
    }
  }
}
