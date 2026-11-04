import ColophonAuthority
import ColophonCore
import ColophonSaved
import ColophonReplica
import ColophonStore
import Foundation
import Testing

/// Two devices that never share storage directly, each working offline on its own copy, converge
/// through a relay that holds only ciphertext.
@Suite struct SyncTests {
  @Test func offlineCopiesConvergeThroughARelay() async throws {
    let relay = MemoryStore()
    let phoneStore = MemoryStore()
    let macStore = MemoryStore()
    let phone = SoftwareIdentity()
    let mac = SoftwareIdentity()
    let holder = try AuthorityHolder.create(in: phoneStore, label: "Library", root: SoftwareIdentity(),
      firstMember: phone.publicIdentity, memberLabel: "Phone", custody: .software, namespaces: [SavedLinks.namespace]).0
    let phoneSync = StoreSync(local: phoneStore, remote: LocalRemote(relay))
    let macSync = StoreSync(local: macStore, remote: LocalRemote(relay))
    try await phoneSync.run()

    // The Mac asks to join through the relay; the phone approves.
    try await macSync.run()
    try Replica(store: macStore, identity: mac).requestEnrollment(label: "Mac", role: .device, namespaces: [SavedLinks.namespace])
    try await macSync.run()
    try await phoneSync.run()
    let request = try #require(try holder.pendingRequests().first)
    try holder.approve(request, namespaces: [SavedLinks.namespace], write: true)
    try await phoneSync.run()
    try await macSync.run()

    // Both write offline, then sync.
    try Replica(store: phoneStore, identity: phone).perform(SavedLinks.capture(item: "p", url: "https://example.com/p", title: "P"))
    try Replica(store: macStore, identity: mac).perform(SavedLinks.capture(item: "m", url: "https://example.com/m", title: "M"))
    try await phoneSync.run()
    try await macSync.run()
    try await phoneSync.run()

    let onPhone = try Replica(store: phoneStore, identity: phone).state(of: SavedLinks.self).items.keys.sorted()
    let onMac = try Replica(store: macStore, identity: mac).state(of: SavedLinks.self).items.keys.sorted()
    #expect(onPhone == ["m", "p"])
    #expect(onMac == ["m", "p"])

    // The relay can't read anything it holds.
    let stored = relay.snapshot.filter { $0.key.hasPrefix("ops/") }.values
    #expect(!stored.isEmpty)
    #expect(stored.allSatisfy { String(decoding: $0, as: UTF8.self).contains("example.com") == false })
  }
}
