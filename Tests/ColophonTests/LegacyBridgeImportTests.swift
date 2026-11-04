import ColophonAuthority
import ColophonCore
import ColophonListening
import ColophonReplica
import ColophonStore
import Foundation
import Testing

@Suite struct LegacyBridgeImportTests {
  private struct Fixture {
    let store = MemoryStore()
    let root = SoftwareIdentity()
    let phone = SoftwareIdentity()
    let second = SoftwareIdentity()
    let agent = SoftwareIdentity()
    let holder: AuthorityHolder

    init() throws {
      holder = try AuthorityHolder.create(in: store, label: "Bridge test", root: root,
        firstMember: phone.publicIdentity, memberLabel: "Phone", role: .app,
        custody: .software, namespaces: [Podcasts.namespace]).0
      try holder.admit(second.publicIdentity, label: "Second", role: .device,
        custody: .software, namespaces: [Podcasts.namespace], write: true)
      try holder.admit(agent.publicIdentity, label: "Agent", role: .agent,
        custody: .software, namespaces: [Podcasts.namespace], write: true)
    }

    var onPhone: Replica { Replica(store: store, identity: phone) }
    var onSecond: Replica { Replica(store: store, identity: second) }
    var onAgent: Replica { Replica(store: store, identity: agent) }
    var libraryID: String { get throws { try onPhone.authority().libraryID } }
    var service: LegacyBridgeImportService { LegacyBridgeImportService(replica: onPhone) }
  }

  private let lineage = "0d73b5e3-dbd5-47e1-9438-b050a15f5e84"
  private let rootA = String(repeating: "a", count: 64)
  private let rootB = String(repeating: "b", count: 64)

  private func feed(_ suffix: String) -> LegacyPodcastFeedCrosswalk {
    let url = "https://feeds.example.test/\(suffix).xml"
    return LegacyPodcastFeedCrosswalk(legacyID: "opaque-\(suffix)", feedURL: url,
      title: "Show \(suffix)", targetShowID: Podcasts.showID(feed: url))
  }

  @Test func oneSignedWriteSurvivesRestartRetryAndOtherSignerWithoutForgingLegacyEvents() throws {
    let f = try Fixture()
    let mapped = feed("first")
    let payload = try LegacyBridgeImport.payload(targetLibraryID: f.libraryID, lineageID: lineage,
      sourceRoot: rootA, parentSourceRoot: nil, feeds: [mapped], sharedOperationInventory: [], expectedLineageRoot: nil,
      expectedShowHeads: [mapped.targetShowID: nil], commandID: "interrupted-after-write")
    // Simulates termination after the single signed write and before the service returns.
    let op = try f.onPhone.perform(Command(namespace: Podcasts.namespace,
      kind: LegacyBridgeImport.kind, payload: payload))
    let before = try f.onPhone.read(Podcasts.namespace).admitted.count
    let receipt = try LegacyBridgeImportService(replica: Replica(store: f.store, identity: f.phone))
      .commit(targetLibraryID: f.libraryID, lineageID: lineage, sourceRoot: rootA,
        parentSourceRoot: nil, feeds: [mapped], sharedOperationInventory: [], expectedLineageRoot: nil,
        expectedShowHeads: [mapped.targetShowID: nil], commandID: "interrupted-after-write")
    let after = try f.onPhone.read(Podcasts.namespace).admitted.count
    #expect(before == after)
    #expect(receipt.operationID == op.id)
    #expect(receipt.outcome == .applied)
    let secondReceipt = try LegacyBridgeImportService(replica: f.onSecond).commit(
      targetLibraryID: f.libraryID, lineageID: lineage, sourceRoot: rootA,
      parentSourceRoot: nil, feeds: [mapped], sharedOperationInventory: [], expectedLineageRoot: nil,
      expectedShowHeads: [mapped.targetShowID: nil], commandID: "different-signer")
    #expect(secondReceipt == receipt)
    let afterSecond = try f.onPhone.read(Podcasts.namespace).admitted.count
    #expect(afterSecond == after)
    let state = try f.onSecond.state(of: Podcasts.self)
    #expect(state.shows[mapped.targetShowID]?.following == true)
    #expect(state.episodes.isEmpty)
    #expect(state.notes.isEmpty)
    #expect(state.queue.isEmpty)
  }

  @Test func nativeShowAndUnfollowTombstoneWinAndStaleHeadsRejectWholeBatch() throws {
    let f = try Fixture()
    let native = feed("native")
    let absent = feed("absent")
    _ = try f.onPhone.perform(Podcasts.follow(feed: native.feedURL, title: "Native title"))
    let head = try f.onPhone.state(of: Podcasts.self).showRevisions[native.targetShowID]
    let rows = [absent, native].sorted { ($0.feedURL, $0.legacyID) < ($1.feedURL, $1.legacyID) }
    let stale = try f.service.commit(targetLibraryID: f.libraryID, lineageID: lineage,
      sourceRoot: rootA, parentSourceRoot: nil, feeds: rows, sharedOperationInventory: [], expectedLineageRoot: nil,
      expectedShowHeads: [native.targetShowID: nil, absent.targetShowID: nil], commandID: "stale")
    #expect(stale.outcome == .stale)
    let afterStale = try f.onPhone.state(of: Podcasts.self)
    #expect(afterStale.shows[absent.targetShowID] == nil)
    let applied = try f.service.commit(targetLibraryID: f.libraryID, lineageID: lineage,
      sourceRoot: rootA, parentSourceRoot: nil, feeds: rows, sharedOperationInventory: [], expectedLineageRoot: nil,
      expectedShowHeads: [native.targetShowID: head, absent.targetShowID: nil], commandID: "reviewed")
    #expect(applied.outcome == .applied)
    #expect(applied.appliedShowIDs == [absent.targetShowID])
    let state = try f.onPhone.state(of: Podcasts.self)
    #expect(state.shows[native.targetShowID]?.title == "Native title")
    _ = try f.onPhone.perform(Podcasts.unfollow(show: absent.targetShowID))
    let later = feed("later")
    let current = try f.onPhone.state(of: Podcasts.self)
    #expect(throws: LegacyBridgeImportError.sourceRootConflict) {
      try f.service.commit(targetLibraryID: f.libraryID, lineageID: lineage,
        sourceRoot: rootB, parentSourceRoot: rootA, feeds: [later], sharedOperationInventory: [],
        expectedLineageRoot: rootA, expectedShowHeads: [later.targetShowID: nil], commandID: "successor")
    }
    // A second device without the original local capsule can still sign a raw operation.
    // The shared fold must quarantine the changed root on its own.
    let rawSuccessor = try LegacyBridgeImport.payload(targetLibraryID: f.libraryID,
      lineageID: lineage, sourceRoot: rootB, parentSourceRoot: rootA,
      feeds: [later], sharedOperationInventory: [], expectedLineageRoot: rootA,
      expectedShowHeads: [later.targetShowID: nil], commandID: "raw-successor")
    _ = try f.onSecond.perform(Command(namespace: Podcasts.namespace,
      kind: LegacyBridgeImport.kind, payload: rawSuccessor))
    let final = try f.onPhone.state(of: Podcasts.self)
    #expect(final.shows[absent.targetShowID]?.following == false)
    #expect(final.shows[later.targetShowID] == nil)
    #expect(final.legacyBridgeLineageRoots[lineage] == rootA)
    let rawKey = LegacyBridgeImport.signerKey(f.second.id, "raw-successor")
    #expect(final.legacyBridgeReceipts[rawKey]?.outcome == .conflict)
    #expect(current.showRevisions[absent.targetShowID] == final.showRevisions[absent.targetShowID])
  }

  @Test func rawAgentWriteAndChangedCommandIDAreRejectedByFold() throws {
    let f = try Fixture()
    let mapped = feed("agent")
    let payload = try LegacyBridgeImport.payload(targetLibraryID: f.libraryID, lineageID: lineage,
      sourceRoot: rootA, parentSourceRoot: nil, feeds: [mapped], sharedOperationInventory: [], expectedLineageRoot: nil,
      expectedShowHeads: [mapped.targetShowID: nil], commandID: "agent-raw")
    #expect(throws: LegacyBridgeImportError.wrongRole) {
      try LegacyBridgeImportService(replica: f.onAgent).commit(targetLibraryID: f.libraryID,
        lineageID: lineage, sourceRoot: rootA, parentSourceRoot: nil, feeds: [mapped], sharedOperationInventory: [],
        expectedLineageRoot: nil, expectedShowHeads: [mapped.targetShowID: nil], commandID: "agent-typed")
    }
    _ = try f.onAgent.perform(Command(namespace: Podcasts.namespace, kind: LegacyBridgeImport.kind, payload: payload))
    let afterAgent = try f.onPhone.state(of: Podcasts.self)
    #expect(afterAgent.shows[mapped.targetShowID] == nil)
    #expect(afterAgent.legacyBridgeReceipts.isEmpty)
    let first = try f.service.commit(targetLibraryID: f.libraryID, lineageID: lineage,
      sourceRoot: rootA, parentSourceRoot: nil, feeds: [mapped], sharedOperationInventory: [], expectedLineageRoot: nil,
      expectedShowHeads: [mapped.targetShowID: nil], commandID: "same-command")
    #expect(first.outcome == .applied)
    let changed = feed("changed")
    #expect(throws: LegacyBridgeImportError.commandIDConflict) {
      try f.service.commit(targetLibraryID: f.libraryID, lineageID: lineage,
        sourceRoot: rootB, parentSourceRoot: rootA, feeds: [changed], sharedOperationInventory: [], expectedLineageRoot: rootA,
        expectedShowHeads: [changed.targetShowID: nil], commandID: "same-command")
    }
  }

  @Test func rawWrongLibraryClaimAndContextlessSyntheticViewCannotProject() throws {
    let f = try Fixture()
    let mapped = feed("wrong-library")
    let wrongLibrary = String(repeating: "c", count: 32)
    let wrongPayload = try LegacyBridgeImport.payload(targetLibraryID: wrongLibrary, lineageID: lineage,
      sourceRoot: rootA, parentSourceRoot: nil, feeds: [mapped], sharedOperationInventory: [],
      expectedLineageRoot: nil, expectedShowHeads: [mapped.targetShowID: nil], commandID: "wrong-library")
    _ = try f.onPhone.perform(Command(namespace: Podcasts.namespace, kind: LegacyBridgeImport.kind,
      payload: wrongPayload))
    let live = try f.onPhone.state(of: Podcasts.self)
    #expect(live.shows[mapped.targetShowID] == nil)
    #expect(live.legacyBridgeReceipts.isEmpty)

    let correct = try LegacyBridgeImport.payload(targetLibraryID: f.libraryID, lineageID: lineage,
      sourceRoot: rootA, parentSourceRoot: nil, feeds: [mapped], sharedOperationInventory: [],
      expectedLineageRoot: nil, expectedShowHeads: [mapped.targetShowID: nil], commandID: "correct-library")
    _ = try f.onPhone.perform(Command(namespace: Podcasts.namespace, kind: LegacyBridgeImport.kind,
      payload: correct))
    let view = try f.onPhone.read(Podcasts.namespace)
    let synthetic = ReplicaView(operations: view.operations, rejected: view.rejected,
      unreadable: view.unreadable)
    let noContext = Podcasts.fold(synthetic)
    #expect(noContext.shows[mapped.targetShowID] == nil)
    #expect(noContext.legacyBridgeReceipts.isEmpty)
    let authenticated = Podcasts.fold(view)
    #expect(authenticated.shows[mapped.targetShowID]?.following == true)
  }

  @Test func duplicateSignedOperationIDCannotProjectOrProvideARevision() throws {
    let f = try Fixture()
    let mapped = feed("duplicate-id")
    let receipt = try f.service.commit(targetLibraryID: f.libraryID, lineageID: lineage,
      sourceRoot: rootA, parentSourceRoot: nil, feeds: [mapped], sharedOperationInventory: [],
      expectedLineageRoot: nil, expectedShowHeads: [mapped.targetShowID: nil], commandID: "first")
    let view = try f.onPhone.read(Podcasts.namespace)
    let original = try #require(view.admitted.first { $0.operation.id == receipt.operationID }?.operation)
    let path = try #require(f.store.snapshot.keys.first {
      $0.hasPrefix("ops/\(f.phone.id)/") && $0.hasSuffix("-\(receipt.operationID).json")
    })
    let maybeRecord = try f.store.read(path)
    let recordData = try #require(maybeRecord)
    let record = try Canonical.decode(SignedRecord.self, from: recordData)
    let header = try Canonical.decode(OperationHeader.self, from: record.body)
    let duplicateHeader = OperationHeader(author: f.second.id, namespace: header.namespace,
      epoch: header.epoch, sealed: header.sealed)
    let duplicate = try SignedRecord(signing: Canonical.encode(duplicateHeader), with: f.second)
    try f.store.create(LibraryPath.operation(author: f.second.id, clock: original.clock,
      id: receipt.operationID), Canonical.encode(duplicate))
    let after = try f.onPhone.state(of: Podcasts.self)
    #expect(after.shows[mapped.targetShowID] == nil)
    #expect(after.legacyBridgeReceipts.isEmpty)
    #expect(after.legacyBridgeIntegrityConflicts.contains(receipt.operationID))
  }

  @Test func revocationKeepsObservedImportButHoldsExplicitlyUnseenWork() throws {
    let f = try Fixture()
    let mapped = feed("revoked")
    _ = try f.service.commit(targetLibraryID: f.libraryID, lineageID: lineage,
      sourceRoot: rootA, parentSourceRoot: nil, feeds: [mapped], sharedOperationInventory: [],
      expectedLineageRoot: nil, expectedShowHeads: [mapped.targetShowID: nil], commandID: "before-revocation")
    try f.holder.revoke(f.phone.id)
    let view = try f.onSecond.read(Podcasts.namespace)
    #expect(view.held.isEmpty)
    let after = Podcasts.fold(view)
    #expect(after.shows[mapped.targetShowID]?.following == true)
    #expect(throws: LegacyBridgeImportError.noCurrentAccess) {
      try f.service.commit(targetLibraryID: f.libraryID, lineageID: lineage,
        sourceRoot: rootA, parentSourceRoot: nil, feeds: [mapped], sharedOperationInventory: [],
        expectedLineageRoot: nil, expectedShowHeads: [mapped.targetShowID: nil], commandID: "after-revocation")
    }

    // A holder can explicitly decline to keep an operation it has not accepted as seen.
    let unseen = try Fixture()
    let other = feed("unseen")
    _ = try unseen.service.commit(targetLibraryID: unseen.libraryID, lineageID: lineage,
      sourceRoot: rootA, parentSourceRoot: nil, feeds: [other], sharedOperationInventory: [],
      expectedLineageRoot: nil, expectedShowHeads: [other.targetShowID: nil], commandID: "unseen-write")
    try unseen.holder.revoke(unseen.phone.id, seen: [])
    let heldView = try unseen.onSecond.read(Podcasts.namespace)
    #expect(!heldView.held.isEmpty)
    let heldProjection = Podcasts.fold(heldView)
    #expect(heldProjection.shows[other.targetShowID] == nil)
  }

  @Test func twoRawOfflineIntentsWithSameRootButDifferentCrosswalkDoNotMerge() throws {
    let f = try Fixture()
    let first = feed("winner")
    let second = feed("loser")
    let firstPayload = try LegacyBridgeImport.payload(targetLibraryID: f.libraryID,
      lineageID: lineage, sourceRoot: rootA, parentSourceRoot: nil,
      feeds: [first], sharedOperationInventory: [], expectedLineageRoot: nil,
      expectedShowHeads: [first.targetShowID: nil], commandID: "offline-phone")
    let secondPayload = try LegacyBridgeImport.payload(targetLibraryID: f.libraryID,
      lineageID: lineage, sourceRoot: rootA, parentSourceRoot: nil,
      feeds: [second], sharedOperationInventory: [], expectedLineageRoot: nil,
      expectedShowHeads: [second.targetShowID: nil], commandID: "offline-second")
    _ = try f.onPhone.perform(Command(namespace: Podcasts.namespace, kind: LegacyBridgeImport.kind,
      payload: firstPayload))
    _ = try f.onSecond.perform(Command(namespace: Podcasts.namespace, kind: LegacyBridgeImport.kind,
      payload: secondPayload))
    let after = try f.onPhone.state(of: Podcasts.self)
    let following = Set(after.following.map(\.id))
    #expect(following.count == 1)
    #expect(after.legacyBridgeSourceRootConflicts.contains(LegacyBridgeImport.rootKey(lineage, rootA)))
  }

  private func snapshotLineage(_ format: LegacyBridgeSourceDescriptor.Format, rawDigest: String) -> String {
    let seed = "org.marginalia.podcast-source.snapshot.v1\n" + format.rawValue + "\n" + rawDigest
    let hash = Array(Canonical.digest(Data(seed.utf8)).prefix(32))
    return String(hash[0..<8]) + "-" + String(hash[8..<12]) + "-" + String(hash[12..<16])
      + "-" + String(hash[16..<20]) + "-" + String(hash[20..<32])
  }

  @Test func sourceSnapshotDescriptorIsSignedAndRetryDoesNotAddAnotherOperation() throws {
    let f = try Fixture()
    let raw = String(repeating: "c", count: 64)
    let semanticRoot = String(repeating: "d", count: 64)
    let lineage = snapshotLineage(.opmlSubscriptionsV1, rawDigest: raw)
    let descriptor = LegacyBridgeSourceDescriptor(format: .opmlSubscriptionsV1,
      rawSourceDigest: raw, semanticFactsRoot: semanticRoot)
    let mapped = feed("provider")
    let payload = try LegacyBridgeImport.payload(targetLibraryID: f.libraryID, lineageID: lineage,
      sourceRoot: semanticRoot, parentSourceRoot: nil, feeds: [mapped], sharedOperationInventory: [],
      expectedLineageRoot: nil, expectedShowHeads: [mapped.targetShowID: nil],
      commandID: "provider-snapshot", sourceDescriptor: descriptor)
    #expect(payload["sourceDescriptor"] != nil)
    let op = try f.onPhone.perform(Command(namespace: Podcasts.namespace,
      kind: LegacyBridgeImport.kind, payload: payload))
    let before = try f.onPhone.read(Podcasts.namespace).admitted.count
    let receipt = try f.service.commit(targetLibraryID: f.libraryID, lineageID: lineage,
      sourceRoot: semanticRoot, parentSourceRoot: nil, feeds: [mapped], sharedOperationInventory: [],
      expectedLineageRoot: nil, expectedShowHeads: [mapped.targetShowID: nil],
      commandID: "provider-snapshot", sourceDescriptor: descriptor)
    #expect(receipt.operationID == op.id)
    #expect(receipt.sourceDescriptor == descriptor)
    #expect(receipt.outcome == .applied)
    let second = try LegacyBridgeImportService(replica: f.onSecond).commit(
      targetLibraryID: f.libraryID, lineageID: lineage, sourceRoot: semanticRoot,
      parentSourceRoot: nil, feeds: [mapped], sharedOperationInventory: [],
      expectedLineageRoot: nil, expectedShowHeads: [mapped.targetShowID: nil],
      commandID: "second-provider-snapshot", sourceDescriptor: descriptor)
    #expect(second == receipt)
    let after = try f.onPhone.read(Podcasts.namespace).admitted.count
    let state = try f.onPhone.state(of: Podcasts.self)
    #expect(after == before)
    #expect(state.shows[mapped.targetShowID]?.following == true)
  }

  @Test func sourceSnapshotRejectsFabricatedLineageHistoryAndProvenanceCollision() throws {
    let f = try Fixture()
    let raw = String(repeating: "e", count: 64)
    let semanticRoot = String(repeating: "f", count: 64)
    let lineage = snapshotLineage(.overcastAllDataV1, rawDigest: raw)
    let descriptor = LegacyBridgeSourceDescriptor(format: .overcastAllDataV1,
      rawSourceDigest: raw, semanticFactsRoot: semanticRoot)
    let mapped = feed("overcast")
    #expect(throws: LegacyBridgeImportError.invalidCommand) {
      try LegacyBridgeImport.payload(targetLibraryID: f.libraryID, lineageID: self.lineage,
        sourceRoot: semanticRoot, parentSourceRoot: nil, feeds: [mapped], sharedOperationInventory: [],
        expectedLineageRoot: nil, expectedShowHeads: [mapped.targetShowID: nil],
        commandID: "fabricated-lineage", sourceDescriptor: descriptor)
    }
    #expect(throws: LegacyBridgeImportError.invalidCommand) {
      try LegacyBridgeImport.payload(targetLibraryID: f.libraryID, lineageID: lineage,
        sourceRoot: semanticRoot, parentSourceRoot: nil, feeds: [mapped],
        sharedOperationInventory: [LegacyBridgeOperationDigest(operationID: "fake-old-op", digest: raw)],
        expectedLineageRoot: nil, expectedShowHeads: [mapped.targetShowID: nil],
        commandID: "fabricated-history", sourceDescriptor: descriptor)
    }
    #expect(throws: LegacyBridgeImportError.invalidCommand) {
      try LegacyBridgeImport.payload(targetLibraryID: f.libraryID, lineageID: lineage,
        sourceRoot: semanticRoot, parentSourceRoot: rootA, feeds: [mapped], sharedOperationInventory: [],
        expectedLineageRoot: rootA, expectedShowHeads: [mapped.targetShowID: nil],
        commandID: "invented-parent", sourceDescriptor: descriptor)
    }
    #expect(throws: LegacyBridgeImportError.invalidCommand) {
      try LegacyBridgeImport.payload(targetLibraryID: f.libraryID, lineageID: lineage,
        sourceRoot: rootA, parentSourceRoot: nil, feeds: [mapped], sharedOperationInventory: [],
        expectedLineageRoot: nil, expectedShowHeads: [mapped.targetShowID: nil],
        commandID: "mismatched-facts-root", sourceDescriptor: descriptor)
    }
    let wrongSemantics = LegacyBridgeSourceDescriptor(format: .overcastAllDataV1,
      rawSourceDigest: raw, semanticFactsRoot: semanticRoot, lineageSemantics: "mutable-account")
    #expect(throws: LegacyBridgeImportError.invalidCommand) {
      try LegacyBridgeImport.payload(targetLibraryID: f.libraryID, lineageID: lineage,
        sourceRoot: semanticRoot, parentSourceRoot: nil, feeds: [mapped], sharedOperationInventory: [],
        expectedLineageRoot: nil, expectedShowHeads: [mapped.targetShowID: nil],
        commandID: "wrong-semantics", sourceDescriptor: wrongSemantics)
    }
    var tampered = try LegacyBridgeImport.payload(targetLibraryID: f.libraryID, lineageID: lineage,
      sourceRoot: semanticRoot, parentSourceRoot: nil, feeds: [mapped], sharedOperationInventory: [],
      expectedLineageRoot: nil, expectedShowHeads: [mapped.targetShowID: nil],
      commandID: "raw-tamper", sourceDescriptor: descriptor)
    tampered["sourceDescriptor"] = .object([
      "format": .string(descriptor.format.rawValue), "rawSourceDigest": .string(raw),
      "semanticFactsRoot": .string(rootA), "lineageSemantics": .string("immutable-file-snapshot"),
    ])
    _ = try f.onSecond.perform(Command(namespace: Podcasts.namespace,
      kind: LegacyBridgeImport.kind, payload: tampered))
    let afterTamper = try f.onPhone.state(of: Podcasts.self)
    #expect(afterTamper.shows[mapped.targetShowID] == nil)
    #expect(afterTamper.legacyBridgeReceipts.isEmpty)
    let old = try LegacyBridgeImport.payload(targetLibraryID: f.libraryID, lineageID: lineage,
      sourceRoot: semanticRoot, parentSourceRoot: nil, feeds: [mapped], sharedOperationInventory: [],
      expectedLineageRoot: nil, expectedShowHeads: [mapped.targetShowID: nil], commandID: "old-shape")
    #expect(old["sourceDescriptor"] == nil)
    _ = try f.onPhone.perform(Command(namespace: Podcasts.namespace, kind: LegacyBridgeImport.kind,
      payload: old))
    #expect(throws: LegacyBridgeImportError.sourceRootConflict) {
      try f.service.commit(targetLibraryID: f.libraryID, lineageID: lineage,
        sourceRoot: semanticRoot, parentSourceRoot: nil, feeds: [mapped], sharedOperationInventory: [],
        expectedLineageRoot: nil, expectedShowHeads: [mapped.targetShowID: nil],
        commandID: "different-provenance", sourceDescriptor: descriptor)
    }
  }

  @Test func nilDescriptorRetainsTheVersionOneCanonicalBodyAndDigest() throws {
    let mapped = feed("golden")
    let id = "264ecc81c1036da01601d0d36f35d0e8"
    #expect(mapped.targetShowID == id)
    let payload = try LegacyBridgeImport.payload(targetLibraryID: String(repeating: "1", count: 32),
      lineageID: lineage, sourceRoot: rootA, parentSourceRoot: nil, feeds: [mapped],
      sharedOperationInventory: [], expectedLineageRoot: nil, expectedShowHeads: [id: nil],
      commandID: "golden-command")
    let explicitNil = try LegacyBridgeImport.payload(targetLibraryID: String(repeating: "1", count: 32),
      lineageID: lineage, sourceRoot: rootA, parentSourceRoot: nil, feeds: [mapped],
      sharedOperationInventory: [], expectedLineageRoot: nil, expectedShowHeads: [id: nil],
      commandID: "golden-command", sourceDescriptor: nil)
    #expect(payload == explicitNil)
    #expect(payload["sourceDescriptor"] == nil)
    var body = payload
    body.removeValue(forKey: "commandID")
    body.removeValue(forKey: "commandDigest")
    let bytes = try Canonical.encode(body)
    let expected = #"{"bridgeVersion":1,"crosswalkDigest":"2b940aa75e5fefc736706556a64bcc2aaf7c3f54afa0a94f88e29039bbdc7daa","crosswalkVersion":1,"expectedLineageRoot":null,"expectedShowHeads":{"264ecc81c1036da01601d0d36f35d0e8":null},"feeds":[{"feedURL":"https://feeds.example.test/golden.xml","legacyID":"opaque-golden","targetShowID":"264ecc81c1036da01601d0d36f35d0e8","title":"Show golden"}],"lineageID":"0d73b5e3-dbd5-47e1-9438-b050a15f5e84","parentSourceRoot":null,"sharedInventoryDigest":"4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945","sharedOperationInventory":[],"sourceRoot":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","targetLibraryID":"11111111111111111111111111111111"}"#
    #expect(String(data: bytes, encoding: .utf8) == expected)
    #expect(payload["commandDigest"]?.string == "b6d2f0a2d2a431bee9a6d70d414afb3cb1d819cbf5813be5fd2d50e555c351ea")
  }

  @Test func overcastSnapshotStaleHeadsCannotPartiallyFollowAndReviewedRetryCanApply() throws {
    let f = try Fixture()
    let raw = String(repeating: "3", count: 64)
    let semanticRoot = String(repeating: "4", count: 64)
    let lineage = snapshotLineage(.overcastAllDataV1, rawDigest: raw)
    let descriptor = LegacyBridgeSourceDescriptor(format: .overcastAllDataV1,
      rawSourceDigest: raw, semanticFactsRoot: semanticRoot)
    let native = feed("overcast-native")
    let absent = feed("overcast-absent")
    _ = try f.onPhone.perform(Podcasts.follow(feed: native.feedURL, title: "Native"))
    let rows = [native, absent].sorted { ($0.feedURL, $0.legacyID) < ($1.feedURL, $1.legacyID) }
    let stale = try f.service.commit(targetLibraryID: f.libraryID, lineageID: lineage,
      sourceRoot: semanticRoot, parentSourceRoot: nil, feeds: rows, sharedOperationInventory: [],
      expectedLineageRoot: nil, expectedShowHeads: [native.targetShowID: nil, absent.targetShowID: nil],
      commandID: "overcast-stale", sourceDescriptor: descriptor)
    #expect(stale.outcome == .stale)
    let afterStale = try f.onPhone.state(of: Podcasts.self)
    #expect(afterStale.shows[absent.targetShowID] == nil)
    #expect(afterStale.legacyBridgeLineageRoots[lineage] == nil)
    let nativeHead = afterStale.showRevisions[native.targetShowID]
    let applied = try f.service.commit(targetLibraryID: f.libraryID, lineageID: lineage,
      sourceRoot: semanticRoot, parentSourceRoot: nil, feeds: rows, sharedOperationInventory: [],
      expectedLineageRoot: nil, expectedShowHeads: [native.targetShowID: nativeHead, absent.targetShowID: nil],
      commandID: "overcast-reviewed", sourceDescriptor: descriptor)
    #expect(applied.outcome == .applied)
    #expect(applied.sourceDescriptor == descriptor)
    #expect(applied.appliedShowIDs == [absent.targetShowID])
    let after = try f.onPhone.state(of: Podcasts.self)
    #expect(after.shows[native.targetShowID]?.title == "Native")
    #expect(after.shows[absent.targetShowID]?.following == true)
  }
}
