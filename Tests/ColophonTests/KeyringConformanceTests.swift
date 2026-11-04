import ColophonAuthority
import ColophonCore
import ColophonSaved
import ColophonReplica
import ColophonStore
import CryptoKit
import Foundation
import Testing

/// A 0.2 library: upgraded keyring, one WebAuthn approval, and a recovery that adds a controller.
/// Separate from `conformance/library`, which stays the 0.1 set.
@Suite struct KeyringConformanceTests {
  static let writing = ProcessInfo.processInfo.environment["COLOPHON_WRITE_VECTORS"] == "1"
  static let root = ConformanceTests.root.appending(path: "keyring", directoryHint: .isDirectory)
  static var library: URL { root.appending(path: "library", directoryHint: .isDirectory) }
  static let vectorsExist = FileManager.default.fileExists(atPath: root.appending(path: "expected.json").path)

  struct Keys: Codable {
    var root: SoftwareIdentity
    var owner: SoftwareIdentity
    var webauthnScalar: Data
    var credential: Data
    var prfOutput: Data
    var prfSalt: Data
    var member: SoftwareIdentity
    var added: SoftwareIdentity
    var kitSecret: Data
  }

  @Test(.enabled(if: writing)) func writeKeyringVectors() throws {
    try? FileManager.default.removeItem(at: Self.root)
    try FileManager.default.createDirectory(at: Self.library, withIntermediateDirectories: true)
    let store = FolderStore(Self.library)
    let keys = Keys(root: SoftwareIdentity(), owner: SoftwareIdentity(), webauthnScalar: Data(), credential: Data(),
      prfOutput: random32(), prfSalt: random32(), member: SoftwareIdentity(), added: SoftwareIdentity(), kitSecret: Data())
    let written = try ceremony(in: store, keys: keys)
    try Canonical.encode(written).write(to: Self.root.appending(path: "keys.json"))
    try Canonical.encode(try expected(store, keys: written)).write(to: Self.root.appending(path: "expected.json"))
  }

  @Test(.enabled(if: vectorsExist && !writing)) func keyringVectorsStillHold() throws {
    let keys = try Canonical.decode(Keys.self, from: Data(contentsOf: Self.root.appending(path: "keys.json")))
    let recorded = try JSONDecoder().decode(JSONValue.self, from: Data(contentsOf: Self.root.appending(path: "expected.json")))
    let now = try expected(FolderStore(Self.library), keys: keys)
    #expect(now == recorded)
  }

  /// Builds the library and returns the keys that were actually used. The placeholder scalars in
  /// `keys` are replaced from the authenticator and the recovery kit.
  private func ceremony(in store: FolderStore, keys: Keys) throws -> Keys {
    let authenticator = SyntheticAuthenticator()
    let (holder, kit) = try AuthorityHolder.create(in: store, label: "Keyring library", root: keys.root,
      firstMember: keys.owner.publicIdentity, memberLabel: "Owner", custody: .software, namespaces: [SavedLinks.namespace])
    _ = try Replica(store: store, identity: keys.owner).perform(SavedLinks.capture(item: "a", url: "https://example.com/a",
      title: "A"))

    let ownerController = p256Controller(keys.owner, roles: ["approve", "control"], label: "Owner")
    let passkey = try authenticator.controller(roles: ["approve", "control"], label: "Passkey")
    let kitIdentity = try kit.identity()
    let kitController = p256Controller(kitIdentity, roles: ["recover"], label: "Recovery kit")
    let vault = try holder.upgrade(to: [ownerController, passkey, kitController], threshold: 1) { key in
      [
        try VaultSlot.sealed(seed: key.seed, to: keys.owner.publicIdentity, controller: ownerController.id, label: "Owner"),
        try VaultSlot.prf(seed: key.seed, prfOutput: keys.prfOutput, salt: keys.prfSalt, credential: authenticator.credential,
          controller: passkey.id, label: "Passkey"),
        try VaultSlot.sealed(seed: key.seed, to: kitIdentity.publicIdentity, controller: kitController.id, label: "Kit"),
      ]
    }

    let member = Replica(store: store, identity: keys.member)
    try member.requestEnrollment(label: "Later", role: .app, namespaces: [SavedLinks.namespace], write: true)
    let approver = try KeyringHolder(log: AuthorityLog(store: store), signer: try authenticator.signer(controller: passkey),
      vault: vault)
    try approver.approveAsRequested(try #require(approver.pendingRequests().first))
    _ = try member.perform(SavedLinks.capture(item: "b", url: "https://example.com/b", title: "B"))

    let addedController = p256Controller(keys.added, roles: ["approve"], label: "Added device")
    let kitSigner = try P256ControllerSigner(identity: kitIdentity, controller: kitController)
    let recovery = try KeyringHolder(log: AuthorityLog(store: store), signer: kitSigner, vault: nil)
    try recovery.addController(addedController, slot: try VaultSlot.sealed(seed: vault.seed, to: keys.added.publicIdentity,
      controller: addedController.id, label: "Added device"))

    return Keys(root: keys.root, owner: keys.owner, webauthnScalar: authenticator.signingScalar,
      credential: authenticator.credential, prfOutput: keys.prfOutput, prfSalt: keys.prfSalt, member: keys.member,
      added: keys.added, kitSecret: kit.secret)
  }

  private func expected(_ store: any RecordStore, keys: Keys) throws -> JSONValue {
    let state = try AuthorityLog(store: store).state()
    let ring = try #require(state.keyring)
    let signing = try P256.Signing.PrivateKey(rawRepresentation: keys.webauthnScalar)
    let webauthnID = String(Canonical.digest(signing.publicKey.x963Representation).prefix(32))
    let kitID = try RecoveryKit(secret: keys.kitSecret).identity().id
    guard ring.controllers[webauthnID]?.kind == "webauthn" else { throw ColophonError.malformed("keyring") }
    guard ring.controllers[keys.owner.id]?.roles.contains("control") == true else { throw ColophonError.malformed("keyring") }
    guard ring.controllers[kitID]?.roles.contains("recover") == true else { throw ColophonError.malformed("keyring") }
    guard ring.controllers[keys.added.id]?.roles.contains("approve") == true else { throw ColophonError.malformed("keyring") }
    let opened = try KeyringHolder.openVault(state: state, prfOutput: keys.prfOutput, credential: keys.credential)
    guard try opened.identity().publicIdentity == ring.vault else { throw ColophonError.vaultLocked }
    guard let member = state.members[keys.member.id], member.current?.write == true,
      member.current?.namespaces.contains(SavedLinks.namespace) == true
    else { throw ColophonError.notAMember }

    func admitted(_ identity: SoftwareIdentity) throws -> [String] {
      try Replica(store: store, identity: identity).read(SavedLinks.namespace).admitted.map(\.id).sorted()
    }
    let ownerIDs = try admitted(keys.owner)
    let memberIDs = try admitted(keys.member)
    guard ownerIDs == memberIDs, ownerIDs.count == 2 else { throw ColophonError.malformed("operation") }
    let controllerIDs: Set<String> = [keys.owner.id, webauthnID, kitID, keys.added.id]
    guard Set(ring.controllers.keys) == controllerIDs else { throw ColophonError.malformed("keyring") }

    let members = state.members.values.sorted { $0.grantedAt < $1.grantedAt }.map { member -> JSONValue in
      .object([
        "id": .string(member.id),
        "label": .string(member.label),
        "namespaces": .array((member.current?.namespaces ?? []).sorted().map { .string($0) }),
        "write": .bool(member.current?.write ?? false),
        "revoked": .bool(member.revokedAt != nil),
      ])
    }
    return .object([
      "libraryID": .string(state.libraryID),
      "vaultID": .string(ring.vault.id),
      "threshold": .number(Double(ring.threshold)),
      "recoverThreshold": .number(Double(ring.recoverThreshold)),
      "controllers": .object([
        "owner": .string(keys.owner.id),
        "webauthn": .string(webauthnID),
        "kit": .string(kitID),
        "added": .string(keys.added.id),
      ]),
      "members": .array(members),
      "admitted": .array(ownerIDs.map { .string($0) }),
    ])
  }
}
