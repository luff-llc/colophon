import ColophonAuthority
import ColophonCore
import ColophonSaved
import ColophonReplica
import ColophonStore
import CryptoKit
import Foundation
import Testing

/// The standard's core promises as executable checks: a separately installed app joins a library
/// through storage and the protocol alone, sees only what it was granted, and stops when revoked;
/// the root survives losing the device that held it.
@Suite struct ThesisTests {
  let store = MemoryStore()
  let rootKey = SoftwareIdentity()
  let mac = SoftwareIdentity()
  let laterKey = SoftwareIdentity()
  static let notes = "notes.private"

  /// Marginalia creates the library, its Mac holds the root; Later asks to join for saved links.
  func enrolled() throws -> (holder: AuthorityHolder, kit: RecoveryKit, home: Replica, later: Replica) {
    let (holder, kit) = try AuthorityHolder.create(in: store, label: "Ada's library", root: rootKey,
      firstMember: mac.publicIdentity, memberLabel: "Marginalia on Mac", custody: .software,
      namespaces: [SavedLinks.namespace, Self.notes])
    let later = Replica(store: store, identity: laterKey)
    try later.requestEnrollment(label: "Later", role: .app, namespaces: [SavedLinks.namespace])
    let pending = try holder.pendingRequests()
    let request = try #require(pending.first)
    let holderCode = EnrollmentRequest.pairingCode(libraryID: try holder.state().libraryID, member: request.member)
    let laterCode = try later.pairingCode()
    #expect(holderCode == laterCode)
    try holder.approve(request, namespaces: [SavedLinks.namespace], write: true)
    return (holder, kit, Replica(store: store, identity: mac), later)
  }

  @Test func secondAppSeesTheSameShelfAndWritesBack() throws {
    let (_, _, home, later) = try enrolled()
    try home.perform(SavedLinks.capture(item: "a1", url: "https://example.com/essay", title: "An essay"))
    let item = try #require(try later.state(of: SavedLinks.self).items["a1"])
    #expect(item.title == "An essay")
    try later.perform(SavedLinks.setState(item: "a1", consumption: "completed", expect: item.revision))
    let finished = try #require(try home.state(of: SavedLinks.self).items["a1"])
    #expect(finished.consumption == "completed")
    #expect(finished.changedBy == "Later")
  }

  @Test func grantIsEnforcedByKeysNotByTheClient() throws {
    let (_, _, home, later) = try enrolled()
    try home.perform(Command(namespace: Self.notes, kind: "note.add", payload: ["text": .string("private")]))
    let view = try later.read(Self.notes)
    #expect(view.operations.isEmpty)
    #expect(view.unreadable == 1)
    #expect(throws: ColophonError.noAccess(Self.notes)) {
      try later.perform(Command(namespace: Self.notes, kind: "note.add", payload: [:]))
    }
  }

  @Test func concurrentChangesConflictTheSameWayEverywhere() throws {
    let (_, _, home, later) = try enrolled()
    let capture = try home.perform(SavedLinks.capture(item: "c3", url: "https://example.com/c", title: "C"))
    try home.perform(SavedLinks.setState(item: "c3", retention: "released", expect: capture.id))
    try later.perform(SavedLinks.setState(item: "c3", consumption: "completed", expect: capture.id))
    let homeShelf = try home.state(of: SavedLinks.self)
    let laterShelf = try later.state(of: SavedLinks.self)
    #expect(homeShelf.conflicts.count == 1)
    #expect(laterShelf.conflicts.count == 1)
    #expect(homeShelf.items["c3"] == laterShelf.items["c3"])
  }

  @Test func unknownFieldsSurvive() throws {
    let (_, _, home, later) = try enrolled()
    try home.perform(SavedLinks.capture(item: "d4", url: "https://example.com/d", title: "D",
      extra: ["publisherVoice": .string("Granta")]))
    let item = try #require(try later.state(of: SavedLinks.self).items["d4"])
    #expect(item.extra["publisherVoice"] == .string("Granta"))
  }

  @Test func revocationEndsTheFutureNotThePast() throws {
    let (holder, _, home, later) = try enrolled()
    try later.perform(SavedLinks.capture(item: "z0", url: "https://example.com/z", title: "Saved in Later"))
    let before = try holder.state().latest
    let seen = try home.read(SavedLinks.namespace).operations.filter { $0.author == laterKey.id }.map(\.id)
    try holder.revoke(laterKey.id, seen: seen)

    #expect(try later.membership() == .revoked)
    #expect(throws: ColophonError.revoked) { try later.perform(SavedLinks.capture(url: "https://example.com/x", title: "X")) }
    try home.perform(SavedLinks.capture(item: "f6", url: "https://example.com/f", title: "After"))
    #expect(try later.read(SavedLinks.namespace).unreadable == 1)

    try forge(by: laterKey, citing: before, item: "g7")
    try forge(by: laterKey, citing: try holder.state().latest, item: "h8")
    let shelf = try home.state(of: SavedLinks.self)
    #expect(shelf.items["g7"] == nil)
    #expect(shelf.items["h8"] == nil)
    #expect(shelf.held.count == 1)
    #expect(shelf.rejected == 1)
    let earlier = shelf.items["z0"]?.title
    #expect(earlier == "Saved in Later")
  }

  @Test func regrantingKeepsEarlierWorkValid() throws {
    let (holder, _, home, later) = try enrolled()
    try later.perform(SavedLinks.capture(item: "r1", url: "https://example.com/r", title: "Before regrant"))
    try holder.admit(laterKey.publicIdentity, label: "Later", role: .app, custody: .software,
      namespaces: [SavedLinks.namespace], write: false)
    let title = try home.state(of: SavedLinks.self).items["r1"]?.title
    #expect(title == "Before regrant")
    #expect(throws: ColophonError.noAccess(SavedLinks.namespace)) {
      try later.perform(SavedLinks.capture(url: "https://example.com/ro", title: "Read only"))
    }
  }

  @Test func recoveryKitTakesTheRootAndTheData() throws {
    let (_, kit, home, _) = try enrolled()
    try home.perform(SavedLinks.capture(item: "k9", url: "https://example.com/k", title: "Kept"))
    // The Mac is lost with its root and member keys. Only storage and the paper kit remain.
    let newRoot = SoftwareIdentity()
    let recovered = try AuthorityHolder.recover(log: AuthorityLog(store: store), kit: RecoveryKit(kit.text), newRoot: newRoot)
    let phone = SoftwareIdentity()
    try recovered.admit(phone.publicIdentity, label: "New phone", role: .device, custody: .hardware,
      namespaces: [SavedLinks.namespace, Self.notes], write: true)
    try recovered.revoke(mac.id)
    let kept = try Replica(store: store, identity: phone).state(of: SavedLinks.self).items["k9"]?.title
    #expect(kept == "Kept")
    #expect(try recovered.state().root == newRoot.publicIdentity)
    #expect(throws: ColophonError.notTheRoot) { try AuthorityHolder(log: AuthorityLog(store: store), root: rootKey) }
    #expect(throws: ColophonError.wrongRecoveryKit) {
      try AuthorityHolder.recover(log: AuthorityLog(store: store), kit: RecoveryKit(), newRoot: SoftwareIdentity())
    }
  }

  @Test func plannedHandoverMovesTheRoot() throws {
    let (holder, _, _, _) = try enrolled()
    let phoneRoot = SoftwareIdentity()
    try holder.handOver(to: phoneRoot.publicIdentity)
    let moved = try AuthorityHolder(log: AuthorityLog(store: store), root: phoneRoot)
    let key = try moved.key(SavedLinks.namespace, epoch: 1)
    #expect(key.bitCount == 256)
  }

  @Test func recoveryKeyIsDeterministic() throws {
    let kit = RecoveryKit()
    let parsed = try RecoveryKit(kit.text.lowercased().replacingOccurrences(of: "-", with: " "))
    #expect(parsed == kit)
    #expect(try parsed.identity().publicIdentity == kit.identity().publicIdentity)
  }

  @Test func tamperedAuthorityIsRefused() throws {
    _ = try enrolled()
    let path = LibraryPath.authority(2)
    let record = try Canonical.decode(SignedRecord.self, from: #require(try store.read(path)))
    var entry = try Canonical.decode(AuthorityEntry.self, from: record.body)
    entry.write = false
    store.tamper(path, try Canonical.encode(SignedRecord(body: Canonical.encode(entry), signature: record.signature)))
    #expect(throws: ColophonError.self) { try AuthorityLog(store: store).state() }
  }

  /// Writes an operation the way a modified client could, skipping every local check.
  private func forge(by identity: SoftwareIdentity, citing authority: Int, item: String) throws {
    let state = try AuthorityLog(store: store).state()
    let sealed = try #require(state.keys[SavedLinks.namespace]?[1]?[identity.id])
    let operation = ColophonOperation(id: UUID().uuidString, kind: SavedLinks.Kind.capture, v: 1, clock: 99,
      authority: authority, created: .now,
      payload: ["item": .string(item), "url": .string("https://evil.example"), "title": .string("Forged")])
    let ciphertext = try #require(try AES.GCM.seal(Canonical.encode(operation), using: identity.open(sealed)).combined)
    let header = OperationHeader(author: identity.id, namespace: SavedLinks.namespace, epoch: 1, sealed: ciphertext)
    try store.create(LibraryPath.operation(author: identity.id, clock: 99, id: operation.id),
      Canonical.encode(SignedRecord(signing: Canonical.encode(header), with: identity)))
  }
}
