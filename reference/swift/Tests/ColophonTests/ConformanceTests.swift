import ColophonAuthority
import ColophonCore
import ColophonSaved
import ColophonReplica
import ColophonStore
import CryptoKit
import Foundation
import Testing

/// Conformance vectors (spec §11). With `COLOPHON_WRITE_VECTORS=1` this writes a fresh set into
/// `conformance/`; otherwise it checks that this implementation still produces
/// the recorded results from the committed records. Other implementations run the same checks.
private let writing = ProcessInfo.processInfo.environment["COLOPHON_WRITE_VECTORS"] == "1"
private let vectorsExist = FileManager.default.fileExists(atPath: ConformanceTests.root.appending(path: "expected.json").path)

@Suite struct ConformanceTests {
  static let root = URL(filePath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    .deletingLastPathComponent().deletingLastPathComponent()
    .appending(path: "conformance", directoryHint: .isDirectory)
  static var library: URL { root.appending(path: "library", directoryHint: .isDirectory) }

  struct Keys: Codable {
    var root: SoftwareIdentity
    var mac: SoftwareIdentity
    var later: SoftwareIdentity
    var agent: SoftwareIdentity
    var newRoot: SoftwareIdentity
  }

  @Test(.enabled(if: writing)) func writeVectors() throws {
    // Only the 0.1 library set. `conformance/keyring/` is a separate vector and must survive.
    try? FileManager.default.removeItem(at: Self.library)
    try? FileManager.default.removeItem(at: Self.root.appending(path: "keys.json"))
    try? FileManager.default.removeItem(at: Self.root.appending(path: "expected.json"))
    try FileManager.default.createDirectory(at: Self.library, withIntermediateDirectories: true)
    let store = FolderStore(Self.library)
    let keys = Keys(root: SoftwareIdentity(), mac: SoftwareIdentity(), later: SoftwareIdentity(), agent: SoftwareIdentity(),
      newRoot: SoftwareIdentity())

    // 1. Genesis and the first member.
    let (holder, kit) = try AuthorityHolder.create(in: store, label: "Conformance library", root: keys.root,
      firstMember: keys.mac.publicIdentity, memberLabel: "Mac", custody: .hardware,
      namespaces: [SavedLinks.namespace, "notes"])
    let mac = Replica(store: store, identity: keys.mac)
    let a = try mac.perform(SavedLinks.capture(item: "a", url: "https://example.com/a", title: "A"))

    // 2. A second app joins with a request and a pairing code.
    let later = Replica(store: store, identity: keys.later)
    try later.requestEnrollment(label: "Later", role: .app, namespaces: [SavedLinks.namespace])
    try holder.approve(try #require(holder.pendingRequests().first), namespaces: [SavedLinks.namespace], write: true)
    try later.perform(SavedLinks.setState(item: "a", consumption: "completed", expect: a.id))
    try later.perform(SavedLinks.capture(item: "b", url: "https://example.com/b", title: "B"))
    try mac.perform(SavedLinks.setState(item: "a", retention: "released", expect: a.id)) // conflicts
    try mac.perform(Command(namespace: "notes", kind: "notebook.create", payload: ["notebook": "n", "title": "Private"]))

    // 3. A caveated agent.
    try holder.admit(keys.agent.publicIdentity, label: "Agent", role: .agent, custody: .custodial,
      namespaces: [SavedLinks.namespace], write: true, caveats: [.only([SavedLinks.Kind.capture], in: SavedLinks.namespace)],
      keyOperator: "example.service")
    let agent = Replica(store: store, identity: keys.agent)
    try agent.perform(SavedLinks.capture(item: "c", url: "https://example.com/c", title: "C"))
    try agent.perform(SavedLinks.setState(item: "c", consumption: "completed", expect: nil)) // refused by caveat

    // 4. Later is revoked; a forged backdated write is held, a current one refused.
    let beforeRevoke = try holder.state().latest
    try holder.revoke(keys.later.id)
    try forge(store, keys.later, citing: beforeRevoke, item: "held")
    try forge(store, keys.later, citing: try holder.state().latest, item: "refused")
    try mac.perform(SavedLinks.capture(item: "d", url: "https://example.com/d", title: "D")) // epoch 2

    // 5. The Mac is lost: the kit recovers the root onto a new identity.
    _ = try AuthorityHolder.recover(log: AuthorityLog(store: store), kit: kit, newRoot: keys.newRoot)

    try Canonical.encode(keys).write(to: Self.root.appending(path: "keys.json"))
    try Canonical.encode(try expected(store, keys: keys, kit: kit)).write(to: Self.root.appending(path: "expected.json"))
  }

  @Test(.enabled(if: vectorsExist && !writing)) func vectorsStillHold() throws {
    let keys = try Canonical.decode(Keys.self, from: Data(contentsOf: Self.root.appending(path: "keys.json")))
    let recorded = try JSONDecoder().decode(JSONValue.self, from: Data(contentsOf: Self.root.appending(path: "expected.json")))
    let kit = try RecoveryKit(#require(recorded.object?["recoveryKit"]?.object?["text"]?.string))
    let now = try expected(FolderStore(Self.library), keys: keys, kit: kit)
    #expect(now == recorded)
  }

  /// Everything an implementation must reproduce from the records and keys.
  private func expected(_ store: any RecordStore, keys: Keys, kit: RecoveryKit) throws -> JSONValue {
    let state = try AuthorityLog(store: store).state()
    let recovery = try kit.identity().publicIdentity
    func view(_ identity: SoftwareIdentity) throws -> JSONValue {
      let replica = Replica(store: store, identity: identity)
      let read = try replica.read(SavedLinks.namespace)
      return .object([
        "admitted": .array(read.admitted.map { .string($0.id) }),
        "held": .array(read.held.map { .string($0.id) }),
        "rejected": .number(Double(read.rejected.count)),
        "unreadable": .number(Double(read.unreadable)),
        "shelf": SavedLinks.describe(SavedLinks.fold(read)),
      ])
    }
    return .object([
      "libraryID": .string(state.libraryID),
      "latest": .number(Double(state.latest)),
      "root": .string(state.root.signing.base64EncodedString()),
      "recoveryKit": .object(["text": .string(kit.text), "secretHex": .string(Canonical.hex(kit.secret)),
        "signing": .string(recovery.signing.base64EncodedString()),
        "agreement": .string(recovery.agreement.base64EncodedString())]),
      "memberIDs": .object(["mac": .string(keys.mac.id), "later": .string(keys.later.id), "agent": .string(keys.agent.id)]),
      "pairingCodes": .object(["later": .string(EnrollmentRequest.pairingCode(libraryID: state.libraryID,
        member: keys.later.publicIdentity))]),
      "members": .array(state.members.values.sorted { $0.grantedAt < $1.grantedAt }.map { member in
        .object(["id": .string(member.id), "label": .string(member.label), "revokedAt": JSONValue(member.revokedAt),
          "grants": .number(Double(member.grants.count))])
      }),
      "epochs": .object([SavedLinks.namespace: .array(state.allEpochs(of: SavedLinks.namespace).map { .number(Double($0)) })]),
      "views": .object(["mac": try view(keys.mac), "agent": try view(keys.agent), "newRoot": try view(keys.newRoot)]),
    ])
  }

  private func forge(_ store: any RecordStore, _ identity: SoftwareIdentity, citing authority: Int, item: String) throws {
    let state = try AuthorityLog(store: store).state()
    let sealed = try #require(state.keys[SavedLinks.namespace]?[1]?[identity.id])
    let operation = ColophonOperation(id: "forged-" + item, kind: SavedLinks.Kind.capture, v: 1, clock: 50,
      authority: authority, created: Date(timeIntervalSince1970: 1_790_000_000),
      payload: ["item": .string(item), "url": .string("https://forged.example"), "title": .string("Forged")])
    let ciphertext = try #require(try AES.GCM.seal(Canonical.encode(operation), using: identity.open(sealed)).combined)
    let header = OperationHeader(author: identity.id, namespace: SavedLinks.namespace, epoch: 1, sealed: ciphertext)
    try store.create(LibraryPath.operation(author: identity.id, clock: 50, id: operation.id),
      Canonical.encode(SignedRecord(signing: Canonical.encode(header), with: identity)))
  }
}
