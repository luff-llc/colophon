import ColophonAuthority
import ColophonCore
@testable import ColophonReplica
import ColophonStore
import Foundation
import Testing
@testable import ColophonListening

struct PositionRecoveryTests {
  private func fixture() throws -> (Replica, AuthorityHolder) {
    let store = MemoryStore()
    let member = SoftwareIdentity()
    let holder = try AuthorityHolder.create(in: store, label: "Synthetic", root: SoftwareIdentity(),
      firstMember: member.publicIdentity, memberLabel: "Fixture", role: .app, custody: .software,
      namespaces: [Podcasts.namespace]).0
    return (Replica(store: store, identity: member), holder)
  }

  private func command(seconds: Double = 40, expectedPosition: String? = nil, expectedState: String? = nil,
    inProgress: Bool = false) -> Command {
    Podcasts.recoverPosition(episode: "episode", show: "show", seconds: seconds, duration: 600,
      expectedPosition: expectedPosition, expectedState: expectedState, inProgress: inProgress)
  }

  @Test func explicitNullExpectationsRecoverAnAbsentPositionAndCanAtomicallyRestart() throws {
    let (replica, _) = try fixture()
    let passive = command()
    #expect(passive.payload["expectedPosition"] == .null)
    #expect(passive.payload["expectedState"] == .null)
    let written = try replica.perform(passive)
    let first = try replica.state(of: Podcasts.self)
    #expect(first.episodes["episode"]?.seconds == 40)
    #expect(first.episodes["episode"]?.positionRevision == written.id)
    #expect(first.episodes["episode"]?.consumption == nil)
    try replica.perform(Podcasts.setState(episode: "episode", show: "show", consumption: "completed", expect: nil))
    let completed = try replica.state(of: Podcasts.self)
    let restart = try replica.perform(command(seconds: 0, expectedPosition: written.id,
      expectedState: completed.episodes["episode"]?.stateRevision, inProgress: true))
    let state = try replica.state(of: Podcasts.self)
    #expect(state.episodes["episode"]?.seconds == 0)
    #expect(state.episodes["episode"]?.consumption == "inProgress")
    #expect(state.episodes["episode"]?.positionRevision == restart.id)
    #expect(state.episodes["episode"]?.stateRevision == restart.id)
    #expect(state.queue.isEmpty)
  }

  @Test func peerRewindWinsEvenWhenRecoveryWouldMoveForward() throws {
    let (replica, _) = try fixture()
    let old = try replica.perform(Podcasts.position(episode: "episode", show: "show", seconds: 80,
      duration: 600, deliberate: true, expect: nil))
    let rewind = try replica.perform(Podcasts.position(episode: "episode", show: "show", seconds: 10,
      duration: 600, deliberate: true, expect: old.id))
    try replica.perform(command(seconds: 120, expectedPosition: old.id))
    let state = try replica.state(of: Podcasts.self)
    #expect(state.episodes["episode"]?.seconds == 10)
    #expect(state.episodes["episode"]?.positionRevision == rewind.id)
  }

  @Test func newerConsumptionRejectsRecoveryWithoutChangingPositionOrCompletion() throws {
    let (replica, _) = try fixture()
    let old = try replica.perform(Podcasts.position(episode: "episode", show: "show", seconds: 40,
      duration: 600, deliberate: true, expect: nil))
    let completed = try replica.perform(Podcasts.setState(episode: "episode", show: "show", consumption: "completed", expect: nil))
    try replica.perform(command(seconds: 0, expectedPosition: old.id, expectedState: nil, inProgress: true))
    let state = try replica.state(of: Podcasts.self)
    #expect(state.episodes["episode"]?.seconds == 40)
    #expect(state.episodes["episode"]?.positionRevision == old.id)
    #expect(state.episodes["episode"]?.consumption == "completed")
    #expect(state.episodes["episode"]?.stateRevision == completed.id)
  }

  @Test(arguments: ["expectedPosition", "expectedState", "duration", "inProgress"])
  func missingRequiredFieldRejectsWholeRecovery(_ field: String) throws {
    let (replica, _) = try fixture()
    var payload = command(inProgress: true).payload
    payload[field] = nil
    try replica.perform(Command(namespace: Podcasts.namespace, kind: Podcasts.Kind.recoverPosition, payload: payload))
    let state = try replica.state(of: Podcasts.self)
    #expect(state.episodes["episode"] == nil)
  }

  @Test(arguments: [JSONValue.number(12), .bool(false), .string("")])
  func malformedExpectedTokenRejectsWholeRecovery(_ token: JSONValue) throws {
    let (replica, _) = try fixture()
    var payload = command(inProgress: true).payload
    payload["expectedState"] = token
    try replica.perform(Command(namespace: Podcasts.namespace, kind: Podcasts.Kind.recoverPosition, payload: payload))
    let state = try replica.state(of: Podcasts.self)
    #expect(state.episodes["episode"] == nil)
  }

  @Test(arguments: [-1.0, -Double.infinity, Double.infinity, Double.nan])
  func invalidNumericValuesAreRejected(_ seconds: Double) throws {
    // Nonfinite JSON cannot be serialized. Construct the already-admitted view to test the fold's own fence too.
    let operation = ColophonOperation(id: "invalid", kind: Podcasts.Kind.recoverPosition, v: 1, clock: 1, authority: 1,
      created: .now, payload: command(seconds: seconds, inProgress: true).payload)
    let entry = AdmittedOperation(operation: operation, author: "writer", authorLabel: "Fixture", authorRole: .app, status: .admitted)
    let state = Podcasts.fold(ReplicaView(operations: [entry], rejected: [], unreadable: 0, libraryID: "fixture"))
    #expect(state.episodes["episode"] == nil)
  }

  @Test func aGrantForLegacyPositionDoesNotAuthorizeRecoveryKind() throws {
    let (replica, holder) = try fixture()
    let agent = SoftwareIdentity()
    try holder.admit(agent.publicIdentity, label: "Narrow writer", role: .agent, custody: .software,
      namespaces: [Podcasts.namespace], write: true, caveats: [.only([Podcasts.Kind.position], in: Podcasts.namespace)])
    let restricted = Replica(store: replica.store, identity: agent)
    try restricted.perform(command(inProgress: true))
    let state = try replica.state(of: Podcasts.self)
    #expect(state.episodes["episode"] == nil)
    let view = try replica.read(Podcasts.namespace)
    #expect(view.rejected.count == 1)
  }
}
