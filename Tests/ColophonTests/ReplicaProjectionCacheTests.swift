import ColophonAuthority
import ColophonCore
import ColophonStore
import CryptoKit
import Foundation
import Testing

@testable import ColophonReplica

private final class HydrationGateStore: RecordStore, @unchecked Sendable {
  let base: MemoryStore
  let gatedPath: String
  private let lock = NSLock()
  private var revealed = false

  init(base: MemoryStore, gatedPath: String) {
    self.base = base
    self.gatedPath = gatedPath
  }

  func list(_ directory: String) throws -> [String] { try base.list(directory) }
  func read(_ path: String) throws -> Data? {
    if path == gatedPath, !lock.withLock({ revealed }) { return nil }
    return try base.read(path)
  }
  func create(_ path: String, _ data: Data) throws { try base.create(path, data) }
  func replace(_ path: String, _ data: Data) throws { try base.replace(path, data) }
  func reveal() { lock.withLock { revealed = true } }
}

struct ReplicaProjectionCacheTests {
  private let namespace = "cache.test"

  private func command(_ value: Int, namespace: String = "cache.test") -> Command {
    Command(namespace: namespace, kind: "cache.add", payload: ["amount": .number(Double(value))])
  }

  private func library(namespaces: [String]) throws -> (MemoryStore, AuthorityHolder, SoftwareIdentity) {
    let store = MemoryStore()
    let member = SoftwareIdentity()
    let (holder, _) = try AuthorityHolder.create(in: store, label: "Cache test", root: SoftwareIdentity(),
      firstMember: member.publicIdentity, memberLabel: "Member", role: .app, custody: .software,
      namespaces: namespaces)
    return (store, holder, member)
  }

  @Test func warmReadAndLocalAppendsDoNotReplayAdmission() throws {
    let (store, _, member) = try library(namespaces: [namespace, "cache.other"])
    let replica = Replica(store: store, identity: member)
    let empty = try replica.read(namespace)
    #expect(empty.operations.isEmpty)
    let initialBuilds: Int = replica.projectionBuildCount
    #expect(initialBuilds == 1)

    for value in 1...4 {
      let operation = try replica.perform(command(value))
      let view = try replica.read(namespace)
      #expect(operation.clock == value)
      #expect(view.operations.count == value)
      #expect(replica.projectionBuildCount == initialBuilds)
    }

    let other = try replica.perform(command(9, namespace: "cache.other"))
    #expect(other.clock == 1)
    let original = try replica.read(namespace)
    #expect(original.operations.count == 4)
    #expect(replica.projectionBuildCount == initialBuilds + 2)
  }

  @Test func ownWriteProjectionUsesThePersistedCanonicalOperation() throws {
    let (store, _, member) = try library(namespaces: [namespace])
    let writer = Replica(store: store, identity: member)
    let written = try writer.perform(command(1))
    let warm = try writer.read(namespace)
    let fresh = try Replica(store: store, identity: member).read(namespace)
    let cachedOperation: ColophonOperation = try #require(warm.operations.first?.operation)
    let persistedOperation: ColophonOperation = try #require(fresh.operations.first?.operation)
    #expect(cachedOperation.id == written.id)
    #expect(cachedOperation == persistedOperation)
    #expect(cachedOperation.created == persistedOperation.created)
  }

  @Test func externalEarlierClockAndAuthorityChangeRebuildProjection() throws {
    let (store, holder, member) = try library(namespaces: [namespace])
    let replica = Replica(store: store, identity: member)
    let first = try replica.perform(command(1))
    let second = try replica.perform(command(2))
    let warm = try replica.read(namespace)
    let warmClocks: [Int] = warm.operations.map(\.operation.clock)
    let expectedWarmClocks: [Int] = [1, 2]
    #expect(warmClocks == expectedWarmClocks)
    let warmBuilds: Int = replica.projectionBuildCount

    let authority = try holder.state()
    let epoch = try #require(authority.epoch(of: namespace))
    let sealedKey = try #require(authority.keys[namespace]?[epoch]?[member.id])
    let operation = ColophonOperation(id: "late-earlier", kind: "cache.add", v: 1, clock: 1,
      authority: authority.latest, created: Date(timeIntervalSince1970: 1_800_000_000),
      payload: ["amount": .number(3)])
    let key: SymmetricKey = try member.open(sealedKey)
    let combined: Data? = try AES.GCM.seal(Canonical.encode(operation), using: key).combined
    let ciphertext = try #require(combined)
    let header = OperationHeader(author: member.id, namespace: namespace, epoch: epoch, sealed: ciphertext)
    let path = LibraryPath.operation(author: member.id, clock: operation.clock, id: operation.id)
    try store.create(path, Canonical.encode(SignedRecord(signing: Canonical.encode(header), with: member)))

    let withExternal = try replica.read(namespace)
    let externalClocks: [Int] = withExternal.operations.map(\.operation.clock)
    let expectedExternalClocks: [Int] = [1, 1, 2]
    let actualIDs: Set<String> = Set(withExternal.operations.map(\.id))
    let expectedIDs: Set<String> = [first.id, second.id, operation.id]
    #expect(externalClocks == expectedExternalClocks)
    #expect(actualIDs == expectedIDs)
    #expect(replica.projectionBuildCount == warmBuilds + 1)

    try holder.revoke(member.id, seen: [])
    let afterRevocation = try replica.read(namespace)
    #expect(afterRevocation.admitted.isEmpty)
    #expect(afterRevocation.held.count == 3)
    #expect(replica.projectionBuildCount == warmBuilds + 2)
  }

  @Test func localBudgetRejectionForcesFullReplayBeforeNextAppend() throws {
    let (store, holder, _) = try library(namespaces: [namespace])
    let agent = SoftwareIdentity()
    try holder.admit(agent.publicIdentity, label: "Agent", role: .agent, custody: .software,
      namespaces: [namespace], write: true, caveats: [.budget("amount", max: 8, in: namespace)])
    let replica = Replica(store: store, identity: agent)
    _ = try replica.perform(command(4))
    _ = try replica.perform(command(3))
    let beforeRejection: Int = replica.projectionBuildCount
    _ = try replica.perform(command(2))
    let rejected = try replica.read(namespace)
    let admittedAmounts: [JSONValue?] = rejected.admitted.map { $0.operation.payload["amount"] }
    let expectedAdmittedAmounts: [JSONValue?] = [.number(4), .number(3)]
    #expect(rejected.admitted.count == 2)
    #expect(admittedAmounts == expectedAdmittedAmounts)
    #expect(rejected.rejected.count == 1)
    #expect(replica.projectionBuildCount == beforeRejection + 1)

    _ = try replica.perform(command(1))
    let afterAppend = try replica.read(namespace)
    let afterAmounts: [JSONValue?] = afterAppend.admitted.map { $0.operation.payload["amount"] }
    let expectedAfterAmounts: [JSONValue?] = [.number(4), .number(3), .number(1)]
    #expect(afterAppend.admitted.count == 3)
    #expect(afterAmounts == expectedAfterAmounts)
    #expect(afterAppend.rejected.count == 1)
    #expect(replica.projectionBuildCount == beforeRejection + 2)
  }

  @Test func laterRejectedBudgetOperationCanBeAdmittedAfterLocalRefund() throws {
    let (store, holder, _) = try library(namespaces: [namespace])
    let agent = SoftwareIdentity()
    try holder.admit(agent.publicIdentity, label: "Agent", role: .agent, custody: .software,
      namespaces: [namespace], write: true, caveats: [.budget("amount", max: 8, in: namespace)])
    let replica = Replica(store: store, identity: agent)
    let spent = try replica.perform(command(8))

    let authority = try holder.state()
    let epoch = try #require(authority.epoch(of: namespace))
    let sealedKey = try #require(authority.keys[namespace]?[epoch]?[agent.id])
    let key: SymmetricKey = try agent.open(sealedKey)
    let later = ColophonOperation(id: "later-budget-charge", kind: "cache.add", v: 1, clock: 100,
      authority: authority.latest, created: Date(timeIntervalSince1970: 1_800_000_000),
      payload: ["amount": .number(2)])
    let combined: Data? = try AES.GCM.seal(Canonical.encode(later), using: key).combined
    let ciphertext = try #require(combined)
    let header = OperationHeader(author: agent.id, namespace: namespace, epoch: epoch, sealed: ciphertext)
    let path = LibraryPath.operation(author: agent.id, clock: later.clock, id: later.id)
    try store.create(path, Canonical.encode(SignedRecord(signing: Canonical.encode(header), with: agent)))

    let rejected = try replica.read(namespace)
    let initialAdmittedIDs: [String] = rejected.admitted.map(\.id)
    let expectedInitialIDs: [String] = [spent.id]
    #expect(initialAdmittedIDs == expectedInitialIDs)
    #expect(rejected.rejected.count == 1)
    let buildsBeforeRefund: Int = replica.projectionBuildCount

    let refund = try replica.perform(command(-2))
    #expect(refund.clock == 2)
    let warm = try replica.read(namespace)
    let fresh = try Replica(store: store, identity: agent).read(namespace)
    let warmIDs: [String] = warm.admitted.map(\.id)
    let freshIDs: [String] = fresh.admitted.map(\.id)
    let expectedIDs: [String] = [spent.id, refund.id, later.id]
    #expect(warmIDs == expectedIDs)
    #expect(warmIDs == freshIDs)
    #expect(warm.rejected.isEmpty)
    #expect(fresh.rejected.isEmpty)
    #expect(replica.projectionBuildCount == buildsBeforeRefund + 1)
  }

  @Test func pendingHydrationByAnotherReaderInvalidatesWarmProjection() async throws {
    let (memory, _, member) = try library(namespaces: [namespace])
    let writer = Replica(store: memory, identity: member)
    let operation = try writer.perform(command(1))
    let path = LibraryPath.operation(author: member.id, clock: operation.clock, id: operation.id)
    let gated = HydrationGateStore(base: memory, gatedPath: path)
    let replica = Replica(store: gated, identity: member)

    let before = try replica.read(namespace)
    #expect(before.operations.isEmpty)
    let beforeAgain = try replica.read(namespace)
    #expect(beforeAgain.operations.isEmpty)
    #expect(replica.projectionBuildCount == 2)

    gated.reveal()
    let independent = try await Task.detached { try replica.read("cache.test") }.value
    #expect(independent.operations.count == 1)
    let after = try replica.read(namespace)
    #expect(after.operations.count == 1)
    let settledBuilds: Int = replica.projectionBuildCount
    let warm = try replica.read(namespace)
    #expect(warm.operations.count == 1)
    #expect(replica.projectionBuildCount == settledBuilds)
  }
}

extension ReplicaProjectionCacheTests {
  @Test func conditionalWriteRejectsStaleWrongOwnerAndNamespace() throws {
    let (store, _, member) = try library(namespaces: [namespace, "cache.other"])
    let replica = Replica(store: store, identity: member)
    let otherReplica = Replica(store: store, identity: member)
    let prepared: ReplicaWriteSnapshot? = try replica.writeSnapshot(namespace)
    let snapshot = try #require(prepared)
    #expect(throws: ReplicaWriteError.staleSnapshot) {
      try otherReplica.perform(command(1), ifUnchanged: snapshot)
    }
    #expect(throws: ReplicaWriteError.staleSnapshot) {
      try replica.perform(command(1, namespace: "cache.other"), ifUnchanged: snapshot)
    }
    _ = try replica.perform(command(2))
    #expect(throws: ReplicaWriteError.staleSnapshot) {
      try replica.perform(command(3), ifUnchanged: snapshot)
    }
    let view = try replica.read(namespace)
    #expect(view.admitted.count == 1)
  }

  @Test func conditionalWriteRejectsPendingAndAuthorityChange() throws {
    let (store, holder, member) = try library(namespaces: [namespace])
    let writer = Replica(store: store, identity: member)
    let first = try writer.perform(command(1))
    let gated = HydrationGateStore(base: store, gatedPath: LibraryPath.operation(author: member.id, clock: first.clock, id: first.id))
    let replica = Replica(store: gated, identity: member)
    let incomplete = try replica.writeSnapshot(namespace)
    #expect(incomplete == nil)
    gated.reveal()
    let prepared: ReplicaWriteSnapshot? = try replica.writeSnapshot(namespace)
    let snapshot = try #require(prepared)
    try holder.revoke(member.id, seen: [])
    #expect(throws: ReplicaWriteError.staleSnapshot) {
      try replica.perform(command(2), ifUnchanged: snapshot)
    }
  }

  @Test func conditionalWriteUsesCachedCompleteView() throws {
    let (store, _, member) = try library(namespaces: [namespace])
    let replica = Replica(store: store, identity: member)
    let prepared: ReplicaWriteSnapshot? = try replica.writeSnapshot(namespace)
    let snapshot = try #require(prepared)
    let before: Int = replica.projectionBuildCount
    _ = try replica.perform(command(1), ifUnchanged: snapshot)
    #expect(replica.projectionBuildCount == before)
    let view = try replica.read(namespace)
    #expect(view.admitted.count == 1)
  }

  @Test func simultaneousConditionalWritesHaveOneWinner() async throws {
    let (store, _, member) = try library(namespaces: [namespace])
    let replica = Replica(store: store, identity: member)
    let prepared: ReplicaWriteSnapshot? = try replica.writeSnapshot(namespace)
    let snapshot = try #require(prepared)
    let successes = await withTaskGroup(of: Bool.self, returning: Int.self) { group in
      for value in 0..<12 {
        group.addTask {
          do {
            _ = try replica.perform(Command(namespace: "cache.test", kind: "cache.add", payload: ["amount": .number(Double(value))]), ifUnchanged: snapshot)
            return true
          } catch { return false }
        }
      }
      var count = 0
      for await success in group where success { count += 1 }
      return count
    }
    #expect(successes == 1)
    let view = try replica.read(namespace)
    #expect(view.admitted.count == 1)
  }
}

private final class ReentrantWriteStore: RecordStore, @unchecked Sendable {
  let base: MemoryStore
  private let lock = NSLock()
  private var hook: (@Sendable () -> Void)?
  init(base: MemoryStore) { self.base = base }
  func setHook(_ value: @escaping @Sendable () -> Void) { lock.withLock { hook = value } }
  func list(_ directory: String) throws -> [String] { try base.list(directory) }
  func read(_ path: String) throws -> Data? { try base.read(path) }
  func create(_ path: String, _ data: Data) throws {
    if path.hasPrefix("ops/") {
      let action = lock.withLock { () -> (@Sendable () -> Void)? in
        let action = hook; hook = nil; return action
      }
      action?()
    }
    try base.create(path, data)
  }
  func replace(_ path: String, _ data: Data) throws { try base.replace(path, data) }
}

extension ReplicaProjectionCacheTests {
  @Test func reentrantWriteFailsRatherThanDeadlockingOrAppending() throws {
    let (store, _, member) = try library(namespaces: [namespace])
    let wrapped = ReentrantWriteStore(base: store)
    let replica = Replica(store: wrapped, identity: member)
    let prepared: ReplicaWriteSnapshot? = try replica.writeSnapshot(namespace)
    let snapshot = try #require(prepared)
    wrapped.setHook {
      #expect(throws: ReplicaWriteError.reentrantWrite) {
        try replica.perform(Command(namespace: "cache.test", kind: "cache.add", payload: [:]))
      }
    }
    _ = try replica.perform(command(1), ifUnchanged: snapshot)
    let view = try replica.read(namespace)
    #expect(view.admitted.count == 1)
  }
}

private final class SigningHookIdentity: Identity, @unchecked Sendable {
  let base: SoftwareIdentity
  private let lock = NSLock()
  private var hook: (@Sendable () throws -> Void)?
  init(base: SoftwareIdentity) { self.base = base }
  var publicIdentity: PublicIdentity { base.publicIdentity }
  var custody: KeyCustody { base.custody }
  func sharedSecret(with peer: P256.KeyAgreement.PublicKey) throws -> SharedSecret { try base.sharedSecret(with: peer) }
  func setHook(_ value: @escaping @Sendable () throws -> Void) { lock.withLock { hook = value } }
  func sign(_ bytes: Data) throws -> Data {
    let action = lock.withLock { () -> (@Sendable () throws -> Void)? in
      let action = hook; hook = nil; return action
    }
    try action?()
    return try base.sign(bytes)
  }
}

extension ReplicaProjectionCacheTests {
  @Test func changedViewDiscoveredDuringSigningRejectsBeforeCreate() throws {
    let (store, _, member) = try library(namespaces: [namespace])
    let identity = SigningHookIdentity(base: member)
    let replica = Replica(store: store, identity: identity)
    let external = Replica(store: store, identity: member)
    let prepared: ReplicaWriteSnapshot? = try replica.writeSnapshot(namespace)
    let snapshot = try #require(prepared)
    identity.setHook {
      _ = try external.perform(Command(namespace: "cache.test", kind: "cache.add", payload: [:]))
      _ = try replica.read("cache.test")
    }
    #expect(throws: ReplicaWriteError.staleSnapshot) {
      try replica.perform(command(1), ifUnchanged: snapshot)
    }
    let view = try replica.read(namespace)
    #expect(view.admitted.count == 1)
  }

  @Test func unconditionalWritesSerializeOnOneReplica() async throws {
    let (store, _, member) = try library(namespaces: [namespace])
    let replica = Replica(store: store, identity: member)
    let clocks = try await withThrowingTaskGroup(of: Int.self, returning: [Int].self) { group in
      for value in 0..<12 {
        group.addTask {
          let operation = try replica.perform(Command(namespace: "cache.test", kind: "cache.add", payload: ["amount": .number(Double(value))]))
          return operation.clock
        }
      }
      var values: [Int] = []
      for try await clock in group { values.append(clock) }
      return values.sorted()
    }
    let expected: [Int] = Array(1...12)
    #expect(clocks == expected)
    let view = try replica.read(namespace)
    #expect(view.admitted.count == 12)
  }
}
