import ColophonAuthority
import ColophonCore
import ColophonListening
import ColophonReplica
import ColophonStore
import CryptoKit
import CryptoTokenKit
import Foundation
import Testing

struct ReplicaInvalidatedKeyTests {
  enum Operation: Sendable { case agreement, signing }

  /// Immutable software test identity; never creates, reads or changes a hardware key.
  private struct InvalidatedIdentity: Identity {
    let base: SoftwareIdentity
    let failure: Operation
    var publicIdentity: PublicIdentity { base.publicIdentity }
    var custody: KeyCustody { .software }
    func sign(_ bytes: Data) throws -> Data {
      if failure == .signing { throw NSError(domain: TKErrorDomain, code: -10) }
      return try base.sign(bytes)
    }
    func sharedSecret(with peer: P256.KeyAgreement.PublicKey) throws -> SharedSecret {
      if failure == .agreement { throw NSError(domain: TKErrorDomain, code: -10) }
      return try base.sharedSecret(with: peer)
    }
  }

  @Test(arguments: [Operation.agreement, .signing])
  func failedFollowAndRepeatedAttemptPreservePriorDataAndIdentity(operation: Operation) throws {
    let store = MemoryStore()
    let member = SoftwareIdentity()
    _ = try AuthorityHolder.create(in: store, label: "Synthetic", root: SoftwareIdentity(),
      firstMember: member.publicIdentity, memberLabel: "Fixture", role: .app, custody: .software,
      namespaces: [Podcasts.namespace])
    let writer = Replica(store: store, identity: member)
    try writer.perform(Podcasts.position(episode: "existing-episode", show: "existing-show", seconds: 5_555,
      duration: 7_200, deliberate: true, expect: nil))
    let original = store.snapshot
    let originalIdentity = try Canonical.encode(member)
    let failedIdentity = InvalidatedIdentity(base: member, failure: operation)
    let failed = Replica(store: store, identity: failedIdentity)
    let feed = "https://synthetic.invalid/feed.xml"

    for _ in 0..<2 {
      do {
        _ = try failed.perform(Podcasts.follow(feed: feed, title: "Synthetic"))
        Issue.record("A failed hardware-key operation must not append a Follow or claim success")
      } catch {
        #expect(DeviceKeyFailure(error) == .invalidated)
      }
      let after = store.snapshot
      #expect(after == original)
      #expect(failedIdentity.publicIdentity == member.publicIdentity)
      let identityAfter = try Canonical.encode(member)
      #expect(identityAfter == originalIdentity)
    }

    // This positive control uses the original fixture identity, not a generated replacement
    // or an assertion that retrying a genuinely invalidated hardware key repairs it.
    let followed = try writer.perform(Podcasts.follow(feed: feed, title: "Synthetic"))
    let fresh = Replica(store: store, identity: member)
    let state = try fresh.state(of: Podcasts.self)
    #expect(state.shows[Podcasts.showID(feed: feed)]?.following == true)
    #expect(state.episodes["existing-episode"]?.seconds == 5_555)
    let view = try fresh.read(Podcasts.namespace)
    let matchingOperations = view.operations.filter { $0.id == followed.id }
    #expect(matchingOperations.count == 1)
  }
}
