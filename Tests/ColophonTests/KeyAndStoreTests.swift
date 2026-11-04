import ColophonAuthority
import ColophonCore
import ColophonSaved
import ColophonReplica
import ColophonStore
import CryptoKit
import Foundation
import Testing

private let enclaveAvailable = SecureEnclaveIdentity.isAvailable
  && ProcessInfo.processInfo.environment["COLOPHON_SOFTWARE_KEYS"] != "1"

@Suite struct KeyAndStoreTests {
  @Test(.enabled(if: enclaveAvailable)) func secureEnclaveIdentitySignsAndOpens() throws {
    let identity = try SecureEnclaveIdentity(requiresPresence: false)
    let body = Data("hello".utf8)
    let signature = try identity.sign(body)
    #expect(identity.publicIdentity.verify(signature, over: body))
    let key = SymmetricKey(size: .bits256)
    let sealed = try SealedKey(key, to: identity.publicIdentity)
    let opened = try identity.open(sealed)
    #expect(opened == key)
    let restored = try Canonical.decode(SecureEnclaveIdentity.self, from: Canonical.encode(identity))
    #expect(restored.publicIdentity == identity.publicIdentity)
  }

  @Test func folderStoreCarriesALibrary() throws {
    let url = FileManager.default.temporaryDirectory.appending(path: "colophon-folder-" + UUID().uuidString)
    let store = FolderStore(url)
    let member = SoftwareIdentity()
    _ = try AuthorityHolder.create(in: store, label: "Folder", root: SoftwareIdentity(), firstMember: member.publicIdentity,
      memberLabel: "Mac", custody: .software, namespaces: [SavedLinks.namespace])
    let replica = Replica(store: store, identity: member)
    try replica.perform(SavedLinks.capture(item: "x", url: "https://example.com/x", title: "X"))
    // A second process opening the same folder sees the same shelf.
    let fresh = Replica(store: FolderStore(url), identity: member)
    let title = try fresh.state(of: SavedLinks.self).items["x"]?.title
    #expect(title == "X")
    #expect(throws: ColophonError.alreadyExists(LibraryPath.authority(1))) {
      try store.create(LibraryPath.authority(1), Data())
    }
  }

  @Test func deviceIdentityPersists() throws {
    let url = FileManager.default.temporaryDirectory.appending(path: "colophon-id-" + UUID().uuidString + "/id.json")
    let first = try DeviceIdentity.loadOrCreate(at: url)
    let second = try DeviceIdentity.loadOrCreate(at: url)
    #expect(first.publicIdentity == second.publicIdentity)
  }
}
