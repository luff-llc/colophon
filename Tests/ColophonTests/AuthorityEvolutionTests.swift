import ColophonAuthority
import ColophonCore
import ColophonSaved
import ColophonReplica
import ColophonStore
import Foundation
import Testing

/// How a library's history changes after it is made: replacing the recovery kit, and what an
/// older app does when a newer one writes an entry it can't check.
@Suite struct AuthorityEvolutionTests {
  let store = MemoryStore()
  let root = SoftwareIdentity()
  let phone = SoftwareIdentity()

  func library() throws -> (AuthorityHolder, RecoveryKit) {
    try AuthorityHolder.create(in: store, label: "Library", root: root, firstMember: phone.publicIdentity,
      memberLabel: "Phone", custody: .software, namespaces: [SavedLinks.namespace])
  }

  func save(_ title: String, as identity: SoftwareIdentity) throws {
    try Replica(store: store, identity: identity).perform(Command(namespace: SavedLinks.namespace,
      kind: SavedLinks.Kind.capture, payload: ["item": .string(UUID().uuidString), "url": .string("https://example.com"),
        "title": .string(title)]))
  }

  // MARK: Rotating the recovery kit

  @Test func rotatedKitRecoversAndTheOldOneDoesNot() throws {
    let (holder, oldKit) = try library()
    try save("Before", as: phone)
    let newKit = try holder.rotateRecovery()
    let state = try holder.state()
    let newRecovery = try newKit.identity().publicIdentity
    #expect(state.recovery == newRecovery)

    #expect(throws: ColophonError.wrongRecoveryKit) {
      try AuthorityHolder.recover(log: AuthorityLog(store: store), kit: oldKit, newRoot: SoftwareIdentity())
    }
    let newPhone = SoftwareIdentity()
    let recovered = try AuthorityHolder.recover(log: AuthorityLog(store: store), kit: newKit, newRoot: newPhone)
    try recovered.admit(newPhone.publicIdentity, label: "New phone", role: .device, custody: .software,
      namespaces: [SavedLinks.namespace], write: true)
    let view = try Replica(store: store, identity: newPhone).read(SavedLinks.namespace)
    let titles = view.admitted.compactMap { $0.operation.payload["title"]?.string }
    #expect(titles == ["Before"])
  }

  @Test func rotationMovesEveryNamespaceToAnEpochTheOldKitCantOpen() throws {
    let (holder, oldKit) = try library()
    let before = try #require(try holder.state().epoch(of: SavedLinks.namespace))
    _ = try holder.rotateRecovery()
    let state = try holder.state()
    let after = try #require(state.epoch(of: SavedLinks.namespace))
    #expect(after == before + 1)
    let oldRecoveryID = try oldKit.identity().publicIdentity.id
    let sealedToOldKit = state.keys[SavedLinks.namespace]?[after]?[oldRecoveryID]
    #expect(sealedToOldKit == nil)
    // Members keep reading and writing across the rotation.
    try save("After", as: phone)
    let view = try Replica(store: store, identity: phone).read(SavedLinks.namespace)
    #expect(view.admitted.count == 1)
  }

  // MARK: Entries from a newer app

  @Test func unknownEntryKindClosesTheLibraryAsNewer() throws {
    _ = try library()
    try appendRaw { entry in entry["kind"] = .string("delegate") }
    let newer = ColophonError.newerAuthority(try latest())
    #expect(throws: newer) { try AuthorityLog(store: store).state() }
  }

  @Test func unknownRoleOrCustodyClosesTheLibraryAsNewer() throws {
    let (holder, _) = try library()
    try holder.admit(SoftwareIdentity().publicIdentity, label: "Agent", role: .agent, custody: .software,
      namespaces: [SavedLinks.namespace], write: false)
    try appendRaw(copying: 2) { entry in entry["role"] = .string("household") }
    let newer = ColophonError.newerAuthority(try latest())
    #expect(throws: newer) { try AuthorityLog(store: store).state() }
  }

  @Test func damagedEntryIsStillReportedAsDamaged() throws {
    _ = try library()
    try appendRaw { entry in entry["kind"] = .number(7) }
    #expect(throws: DecodingError.self) { try AuthorityLog(store: store).state() }
  }

  /// The newest entry's number in the store, read without verifying.
  private func latest() throws -> Int {
    var seq = 1
    while try store.read(LibraryPath.authority(seq + 1)) != nil { seq += 1 }
    return seq
  }

  /// Appends a root-signed entry built from an existing entry's JSON (the newest by default), as
  /// a newer app would write it.
  private func appendRaw(copying source: Int? = nil, _ change: (inout [String: JSONValue]) -> Void) throws {
    let last = try latest()
    let lastRecord = try Canonical.decode(SignedRecord.self, from: #require(try store.read(LibraryPath.authority(last))))
    let sourceRecord = try Canonical.decode(SignedRecord.self,
      from: #require(try store.read(LibraryPath.authority(source ?? last))))
    var entry = try Canonical.decode([String: JSONValue].self, from: sourceRecord.body)
    entry["seq"] = .number(Double(last + 1))
    entry["previous"] = .string(Canonical.digest(lastRecord.body))
    change(&entry)
    try store.create(LibraryPath.authority(last + 1),
      Canonical.encode(SignedRecord(signing: Canonical.encode(entry), with: root)))
  }
}
