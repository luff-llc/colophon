import ColophonAuthority
import ColophonCore
import ColophonListening
import ColophonReplica
import ColophonStore
import Foundation
import Testing

@Suite struct PlaybackPreferenceBatchTests {
  private struct Fixture {
    let phoneStore = MemoryStore()
    let relay = MemoryStore()
    let laterStore = MemoryStore()
    let root = SoftwareIdentity()
    let phone = SoftwareIdentity()
    let later = SoftwareIdentity()
    let agent = SoftwareIdentity()
    let holder: AuthorityHolder

    init() throws {
      holder = try AuthorityHolder.create(in: phoneStore, label: "Preference fixture", root: root,
        firstMember: phone.publicIdentity, memberLabel: "Taupe", role: .app, custody: .software,
        namespaces: [Podcasts.namespace]).0
      try holder.admit(later.publicIdentity, label: "Later", role: .device, custody: .software,
        namespaces: [Podcasts.namespace], write: true)
      try holder.admit(agent.publicIdentity, label: "Agent", role: .agent, custody: .software,
        namespaces: [Podcasts.namespace], write: true)
    }

    var onPhone: Replica { Replica(store: phoneStore, identity: phone) }
    var onLater: Replica { Replica(store: laterStore, identity: later) }
    var phoneService: PlaybackPreferenceBatchService { PlaybackPreferenceBatchService(replica: onPhone) }

    func syncPhoneToRelay() async throws {
      _ = try await StoreSync(local: phoneStore, remote: LocalRemote(relay)).run()
    }

    func syncLaterToRelay() async throws {
      _ = try await StoreSync(local: laterStore, remote: LocalRemote(relay)).run()
    }
  }

  @Test func signedBatchSurvivesFolderReconstructionSyncAndReplay() async throws {
    let directory = FileManager.default.temporaryDirectory.appending(path: "settings-restart-\(UUID().uuidString)")
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = FolderStore(directory)
    let root = SoftwareIdentity()
    let phone = SoftwareIdentity()
    let later = SoftwareIdentity()
    let holder = try AuthorityHolder.create(in: store, label: "Durable settings", root: root,
      firstMember: phone.publicIdentity, memberLabel: "Phone", role: .app, custody: .software,
      namespaces: [Podcasts.namespace]).0
    try holder.admit(later.publicIdentity, label: "Later", role: .device, custody: .software,
      namespaces: [Podcasts.namespace], write: true)

    let relay = MemoryStore()
    _ = try await StoreSync(local: store, remote: LocalRemote(relay)).run()
    let laterStore = MemoryStore()
    _ = try await StoreSync(local: laterStore, remote: LocalRemote(relay)).run()
    let key = "playback.speed"
    let expected: [String: String?] = [key: nil]
    let firstReplica = Replica(store: FolderStore(directory), identity: phone)
    let firstService = PlaybackPreferenceBatchService(replica: firstReplica)
    let first = try firstService.commit(changes: [key: "1.25"], expected: expected, commandID: "durable-one")
    #expect(first.outcome == .applied)

    _ = try await StoreSync(local: store, remote: LocalRemote(relay)).run()
    _ = try await StoreSync(local: laterStore, remote: LocalRemote(relay)).run()
    let reconstructed = Replica(store: FolderStore(directory), identity: phone)
    let recovered = try reconstructed.state(of: Podcasts.self)
    #expect(recovered.preferences[key] == "1.25")
    #expect(recovered.preferenceReceipts[PlaybackPreferenceBatch.signerKey(phone.id, "durable-one")] == first)
    let synced = try Replica(store: laterStore, identity: later).state(of: Podcasts.self)
    #expect(synced.preferences[key] == "1.25")
    #expect(synced.preferenceReceipts[PlaybackPreferenceBatch.signerKey(phone.id, "durable-one")] == first)

    let replay = try PlaybackPreferenceBatchService(replica: reconstructed)
      .commit(changes: [key: "1.25"], expected: expected, commandID: "durable-one")
    #expect(replay == first)
    #expect(try reconstructed.state(of: Podcasts.self).preferenceReceipts.count == 1)
  }

  @Test func opaqueScopesExplicitFalseAndEmptyInheritanceArePreserved() throws {
    let showID = "https://feed.example/a:b.part/1"
    let episodeID = "import:folder.with.dots/episode-1"
    let falseShow = try #require(PlaybackPreferenceBatch.parse(
      key: "playback.show:\(showID).skipSponsors", value: "false"))
    let inheritEpisode = try #require(PlaybackPreferenceBatch.parse(
      key: "playback.episode:\(episodeID).speed", value: ""))
    #expect(falseShow.scope == .show(showID))
    #expect(falseShow.value == "false")
    #expect(inheritEpisode.scope == .episode(episodeID))
    #expect(inheritEpisode.value.isEmpty)
    #expect(PlaybackPreferenceBatch.parse(key: "playback.show: \n.speed", value: "1.25") == nil)
    #expect(PlaybackPreferenceBatch.parse(key: "playback.speed", value: "") == nil)
  }

  @Test func staleBatchDoesNotPartiallyApplyAndNineFieldResetIsOneReceipt() throws {
    let fields = ["speed", "backward", "forward", "shortenSilence", "levelSpeech", "monoAudio",
      "skipSponsors", "skipDetectedSponsors", "skipAdChapters"]
    let show = "show:opaque.a:b"
    let keys = fields.map { "playback.\(show).\($0)" }
    let configured = Dictionary(uniqueKeysWithValues: zip(keys, ["1.5", "15", "45", "true", "false", "true", "false", "true", "false"]))
    let noPrior: [String: String?] = Dictionary(uniqueKeysWithValues: keys.map { ($0, nil) })
    let initial = try PlaybackPreferenceBatchService(replica: fixture().onPhone)
      .commit(changes: configured, expected: noPrior, commandID: "nine-field-config")
    #expect(initial.outcome == .applied)
    #expect(initial.changedKeys.count == 9)

    let f = try fixture()
    let staleTarget = "playback.forward"
    let targetSpeed = "playback.speed"
    let speedReceipt = try f.phoneService.commit(changes: [targetSpeed: "1.25"],
      expected: [targetSpeed: nil], commandID: "seed-speed")
    let speedRevision = speedReceipt.revision
    let stale = try f.phoneService.commit(changes: [targetSpeed: "1.5", staleTarget: "45"],
      expected: [targetSpeed: nil, staleTarget: nil], commandID: "stale-whole-batch")
    #expect(stale.outcome == .stale)
    let state = try f.onPhone.state(of: Podcasts.self)
    #expect(state.preferences[targetSpeed] == "1.25")
    #expect(state.preferences[staleTarget] == nil)
    #expect(state.preferenceRevisionByKey[targetSpeed] == speedRevision)

    let resetKeys = keys
    let current = try f.phoneService.commit(changes: configured, expected: noPrior, commandID: "reset-seed")
    let _ = current
    let seededState = try f.onPhone.state(of: Podcasts.self)
    let resetExpected: [String: String?] = Dictionary(uniqueKeysWithValues: resetKeys.map {
      ($0, seededState.preferenceRevisionByKey[$0])
    })
    let reset = try f.phoneService.commit(changes: Dictionary(uniqueKeysWithValues: resetKeys.map { ($0, "") }),
      expected: resetExpected, commandID: "reset-nine")
    #expect(reset.outcome == .applied)
    #expect(reset.changedKeys.count == 9)
    let resetState = try f.onPhone.state(of: Podcasts.self)
    #expect(resetKeys.allSatisfy { resetState.preferences[$0] == "" })
    #expect(resetState.preferenceReceipts[PlaybackPreferenceBatch.signerKey(f.phone.id, "reset-nine")] == reset)
  }

  @Test func callerCommandIDIsSignerScopedReplayableAndCannotChangeMeaning() throws {
    let f = try fixture()
    let key = "playback.speed"
    let change: [String: String] = [key: "1.25"]
    let expected: [String: String?] = [key: nil]
    let first = try f.phoneService.commit(changes: change, expected: expected, commandID: "same-name")
    let replay = try f.phoneService.commit(changes: change, expected: expected, commandID: "same-name")
    #expect(replay == first)
    #expect(throws: PlaybackPreferenceBatchError.commandIDConflict) {
      try f.phoneService.commit(changes: [key: "1.5"], expected: expected, commandID: "same-name")
    }

    let laterReplica = Replica(store: f.phoneStore, identity: f.later)
    let laterState = try laterReplica.state(of: Podcasts.self)
    let laterExpected: [String: String?] = [key: laterState.preferenceRevisionByKey[key]]
    let otherSigner = try PlaybackPreferenceBatchService(replica: laterReplica)
      .commit(changes: [key: "1.5"], expected: laterExpected, commandID: "same-name")
    #expect(otherSigner.authorID == f.later.id)
    #expect(otherSigner.outcome == .applied)
    let receipts = try laterReplica.state(of: Podcasts.self).preferenceReceipts
    #expect(receipts.count == 2)
  }

  @Test func invalidRawBatchVersionAndValuesDoNotPartiallyApply() throws {
    let f = try fixture()
    let goodKey = "playback.speed"
    let badKey = "playback.backward"
    let body: [String: JSONValue] = [
      "changes": .object([goodKey: .string("1.25"), badKey: .string("12")]),
      "expected": .object([goodKey: .null, badKey: .null]),
    ]
    let digest = Canonical.digest(try Canonical.encode(body))
    let payload = body.merging(["commandID": .string("invalid-value"), "commandDigest": .string(digest)]) {
      _, new in new
    }
    _ = try f.onPhone.perform(Command(namespace: Podcasts.namespace,
      kind: Podcasts.Kind.preferenceBatch, payload: payload))
    var wrongVersion = try PlaybackPreferenceBatch.payload(changes: [goodKey: "1.25"],
      expected: [goodKey: nil], commandID: "wrong-version")
    _ = try f.onPhone.perform(Command(namespace: Podcasts.namespace,
      kind: Podcasts.Kind.preferenceBatch, v: 2, payload: wrongVersion))
    wrongVersion["extra"] = .bool(true)
    _ = try f.onPhone.perform(Command(namespace: Podcasts.namespace,
      kind: Podcasts.Kind.preferenceBatch, payload: wrongVersion))

    let state = try f.onPhone.state(of: Podcasts.self)
    #expect(state.preferences.isEmpty)
    #expect(state.preferenceReceipts.isEmpty)
  }

  @Test func agentCannotWriteNewBatchButLegacyGrantedSpeedStillFolds() throws {
    let f = try fixture()
    let feed = "https://example.test/legacy.xml"
    let show = Podcasts.showID(feed: feed)
    try f.onPhone.perform(Podcasts.follow(feed: feed, title: "Legacy show"))
    let agentReplica = Replica(store: f.phoneStore, identity: f.agent)
    let agentService = PlaybackPreferenceBatchService(replica: agentReplica)
    #expect(throws: PlaybackPreferenceBatchError.wrongRole) {
      try agentService.commit(changes: ["playback.show:\(show).speed": "1.5"],
        expected: ["playback.show:\(show).speed": nil], commandID: "agent-batch")
    }
    let raw = try PlaybackPreferenceBatch.payload(changes: ["playback.show:\(show).speed": "1.5"],
      expected: ["playback.show:\(show).speed": nil], commandID: "agent-raw-batch")
    _ = try agentReplica.perform(Command(namespace: Podcasts.namespace,
      kind: Podcasts.Kind.preferenceBatch, payload: raw))
    let afterNewBatch = try f.onPhone.state(of: Podcasts.self)
    #expect(afterNewBatch.preferences["playback.show:\(show).speed"] == nil)

    _ = try agentReplica.perform(Podcasts.settings(show: show, speed: 1.5))
    let legacy = try f.onPhone.state(of: Podcasts.self)
    #expect(legacy.preferences["playback.show:\(show).speed"] == "1.5")
    #expect(legacy.shows[show]?.speed == 1.5)

    try f.holder.revoke(f.agent.id)
    #expect(throws: PlaybackPreferenceBatchError.noCurrentAccess) {
      try agentService.commit(changes: ["playback.show:\(show).speed": "1.75"],
        expected: ["playback.show:\(show).speed": legacy.preferenceRevisionByKey["playback.show:\(show).speed"]],
        commandID: "revoked-agent-batch")
    }
    let afterRevoke = try f.onPhone.state(of: Podcasts.self)
    #expect(afterRevoke.preferences["playback.show:\(show).speed"] == "1.5")
  }

  @Test func legacySpeedAndBatchSpeedFollowAdmittedClockOrdering() throws {
    let f = try fixture()
    let feedA = "https://example.test/order-a.xml"
    let feedB = "https://example.test/order-b.xml"
    let showA = Podcasts.showID(feed: feedA)
    let showB = Podcasts.showID(feed: feedB)
    try f.onPhone.perform(Podcasts.follow(feed: feedA, title: "Order A"))
    try f.onPhone.perform(Podcasts.follow(feed: feedB, title: "Order B"))
    let agentReplica = Replica(store: f.phoneStore, identity: f.agent)
    let keyA = "playback.show:\(showA).speed"
    let keyB = "playback.show:\(showB).speed"
    _ = try agentReplica.perform(Podcasts.settings(show: showA, speed: 1.5))
    let aRevision = try f.onPhone.state(of: Podcasts.self).preferenceRevisionByKey[keyA]
    let afterLegacy: [String: String?] = [keyA: aRevision]
    _ = try f.phoneService.commit(changes: [keyA: "1.25"], expected: afterLegacy, commandID: "batch-after-legacy")
    _ = try f.phoneService.commit(changes: [keyB: "1.25"], expected: [keyB: nil], commandID: "batch-before-legacy")
    _ = try agentReplica.perform(Podcasts.settings(show: showB, speed: 1.75))

    let state = try f.onPhone.state(of: Podcasts.self)
    #expect(state.preferences[keyA] == "1.25")
    #expect(state.shows[showA]?.speed == 1.25)
    #expect(state.preferences[keyB] == "1.75")
    #expect(state.shows[showB]?.speed == 1.75)
  }

  @Test func duplicateSignedOperationIdentityDoesNotBecomePreferenceRevision() throws {
    let f = try fixture()
    let key = "playback.speed"
    let first = try f.phoneService.commit(changes: [key: "1.25"], expected: [key: nil], commandID: "duplicate-identity")
    let operation = try #require(f.onPhone.read(Podcasts.namespace).admitted.first {
      $0.operation.id == first.operationID
    }?.operation)
    let path = try #require(f.phoneStore.snapshot.keys.first {
      $0.hasPrefix("ops/\(f.phone.id)/") && $0.hasSuffix("-\(first.operationID).json")
    })
    let maybeBytes = try f.phoneStore.read(path)
    let bytes = try #require(maybeBytes)
    let record = try Canonical.decode(SignedRecord.self, from: bytes)
    let header = try Canonical.decode(OperationHeader.self, from: record.body)
    let duplicate = OperationHeader(author: f.later.id, namespace: header.namespace,
      epoch: header.epoch, sealed: header.sealed)
    let signed = try SignedRecord(signing: Canonical.encode(duplicate), with: f.later)
    try f.phoneStore.create(LibraryPath.operation(author: f.later.id, clock: operation.clock, id: first.operationID),
      Canonical.encode(signed))

    let state = try f.onPhone.state(of: Podcasts.self)
    #expect(state.preferences[key] == nil)
    #expect(state.preferenceIntegrityConflicts.contains(first.operationID))
  }

  private func fixture() throws -> Fixture { try Fixture() }
}
