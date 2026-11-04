import ColophonAuthority
import ColophonCore
import ColophonReplica
import ColophonStore
import Foundation
import Testing

/// Requirements from luff.works merchant accounts: caveated grants, custodial members for remote
/// MCP clients, controllers and a steward quorum instead of one person's recovery kit.
@Suite struct OrganizationTests {
  let store = MemoryStore()
  let root = SoftwareIdentity()
  let owner = SoftwareIdentity()
  let stewards = [SoftwareIdentity(), SoftwareIdentity(), SoftwareIdentity()]
  static let orders = "commerce.orders"
  static let drops = "commerce.drops"

  func merchant() throws -> AuthorityHolder {
    try AuthorityHolder.create(in: store, label: "Studio", root: root, firstMember: owner.publicIdentity,
      memberLabel: "Owner's phone", custody: .hardware, namespaces: [Self.orders, Self.drops],
      controller: ["legalName": "Studio LLC", "terms": "merch-terms-v2"],
      stewards: stewards.map(\.publicIdentity), threshold: 2).0
  }

  func order(_ cents: Int) -> Command {
    Command(namespace: Self.orders, kind: "order.createFromStock", payload: ["amount": .number(Double(cents))])
  }

  @Test func caveatsBoundAnAgent() throws {
    let holder = try merchant()
    let agent = SoftwareIdentity()
    try holder.admit(agent.publicIdentity, label: "Claude (custodial)", role: .agent, custody: .custodial,
      namespaces: [Self.orders, Self.drops], write: true,
      caveats: [.only(["order.createFromStock"], in: Self.orders), .ceiling("amount", max: 5_000, in: Self.orders),
        .budget("amount", max: 8_000, in: Self.orders), .only(["drop.draft"], in: Self.drops)],
      keyOperator: "luff.works")
    let replica = Replica(store: store, identity: agent)
    try replica.perform(order(4_000))
    try replica.perform(order(6_000)) // over the per-order ceiling
    try replica.perform(order(3_000))
    try replica.perform(order(2_000)) // 4,000 + 3,000 + 2,000 exceeds the budget
    try replica.perform(Command(namespace: Self.orders, kind: "order.cancel", payload: [:]))
    try replica.perform(Command(namespace: Self.drops, kind: "drop.publish", payload: [:]))

    let ordersView = try Replica(store: store, identity: owner).read(Self.orders)
    let amounts = ordersView.admitted.compactMap { $0.operation.payload["amount"] }
    #expect(amounts == [.number(4_000), .number(3_000)])
    #expect(ordersView.rejected.count == 3)
    let drops = try Replica(store: store, identity: owner).read(Self.drops)
    #expect(drops.rejected.count == 1)
    let member = try #require(try holder.state().members[agent.id])
    #expect(member.custody == .custodial)
    #expect(member.keyOperator == "luff.works")
  }

  @Test func unknownCaveatFailsClosed() throws {
    let holder = try merchant()
    let agent = SoftwareIdentity()
    try holder.admit(agent.publicIdentity, label: "Agent", role: .agent, custody: .software, namespaces: [Self.orders],
      write: true, caveats: [Caveat(kind: "geofence", namespace: Self.orders)])
    try Replica(store: store, identity: agent).perform(order(100))
    let view = try Replica(store: store, identity: owner).read(Self.orders)
    #expect(view.admitted.isEmpty)
    #expect(view.rejected.count == 1)
  }

  @Test func stewardQuorumHandsOverTheRoot() throws {
    let holder = try merchant()
    let state = try holder.state()
    #expect(state.controller["legalName"] == "Studio LLC")
    let newRoot = SoftwareIdentity()
    let log = AuthorityLog(store: store)
    let body = try AuthorityHolder.quorumHandoverBody(log: log, newRoot: newRoot.publicIdentity)

    // One steward isn't enough.
    let one = [SignedRecord.Cosignature(signer: stewards[0].id, signature: try stewards[0].sign(body))]
    #expect(throws: ColophonError.self) {
      try AuthorityHolder.completeQuorumHandover(log: AuthorityLog(store: MemoryStoreCopy.of(store)), body: body,
        signatures: one, newRoot: newRoot, keysFrom: stewards[0])
    }
    let two = one + [SignedRecord.Cosignature(signer: stewards[2].id, signature: try stewards[2].sign(body))]
    let moved = try AuthorityHolder.completeQuorumHandover(log: log, body: body, signatures: two, newRoot: newRoot,
      keysFrom: stewards[0])
    #expect(try moved.state().root == newRoot.publicIdentity)
    #expect(try moved.key(Self.orders, epoch: 1).bitCount == 256)
  }
}

/// A copy of a memory store, so a failing attempt can't leave records behind in the original.
enum MemoryStoreCopy {
  static func of(_ store: MemoryStore) throws -> MemoryStore {
    let copy = MemoryStore()
    for (path, data) in store.snapshot { try copy.create(path, data) }
    return copy
  }
}
