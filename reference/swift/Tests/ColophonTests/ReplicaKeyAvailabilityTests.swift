import ColophonAuthority
import ColophonCore
import ColophonListening
import ColophonStore
import CryptoKit
import Foundation
import Testing
@testable import ColophonReplica

struct ReplicaKeyAvailabilityTests {
  /// Every mutable field is protected by `lock`; the wrapped software identity is immutable.
  private final class GatedIdentity: Identity, @unchecked Sendable {
    let base: SoftwareIdentity
    private let lock = NSLock()
    private var secretFailure: Int?
    private var emptySigning = false
    private var emptyAgreement = false

    init(_ base: SoftwareIdentity) { self.base = base }
    func setSecretFailure(_ code: Int?) { lock.withLock { secretFailure = code } }
    func setEmptyKeys(signing: Bool, agreement: Bool) {
      lock.withLock { emptySigning = signing; emptyAgreement = agreement }
    }
    var publicIdentity: PublicIdentity {
      let empty = lock.withLock { (emptySigning, emptyAgreement) }
      return PublicIdentity(signing: empty.0 ? Data() : base.publicIdentity.signing,
        agreement: empty.1 ? Data() : base.publicIdentity.agreement)
    }
    var custody: KeyCustody { .software }
    func sign(_ bytes: Data) throws -> Data { try base.sign(bytes) }
    func sharedSecret(with peer: P256.KeyAgreement.PublicKey) throws -> SharedSecret {
      if let code = lock.withLock({ secretFailure }) {
        throw NSError(domain: NSOSStatusErrorDomain, code: code)
      }
      return try base.sharedSecret(with: peer)
    }
  }

  private func fixture() throws -> (MemoryStore, SoftwareIdentity) {
    let store = MemoryStore()
    let member = SoftwareIdentity()
    _ = try AuthorityHolder.create(in: store, label: "Original", root: SoftwareIdentity(),
      firstMember: member.publicIdentity, memberLabel: "Fixture", role: .app, custody: .software,
      namespaces: [Podcasts.namespace])
    let writer = Replica(store: store, identity: member)
    try writer.perform(Podcasts.position(episode: "episode", show: "show", seconds: 5_555,
      duration: 7_200, deliberate: true, expect: nil))
    return (store, member)
  }

  @Test func protectedSecretReadFailsAndRetriesSameReplicaWithoutWrites() throws {
    let (store, member) = try fixture()
    let original = store.snapshot
    let identity = GatedIdentity(member)
    let replica = Replica(store: store, identity: identity)
    identity.setSecretFailure(-25308)
    do {
      _ = try replica.read(Podcasts.namespace)
      Issue.record("Protected namespace key must fail the read instead of publishing an empty projection")
    } catch {
      let failure = error as NSError
      #expect(failure.domain == NSOSStatusErrorDomain)
      #expect(failure.code == -25308)
    }
    identity.setSecretFailure(nil)
    let recovered = try replica.state(of: Podcasts.self)
    let membership = try replica.membership()
    let expected = Replica.Membership.member(namespaces: [Podcasts.namespace], write: true)
    #expect(recovered.episodes["episode"]?.seconds == 5_555)
    #expect(membership == expected)
    let after = store.snapshot
    #expect(after == original)
  }

  @Test(arguments: [true, false])
  func missingPublicKeyDoesNotBecomePending(signing: Bool) throws {
    let (store, member) = try fixture()
    let original = store.snapshot
    let identity = GatedIdentity(member)
    let replica = Replica(store: store, identity: identity)
    identity.setEmptyKeys(signing: signing, agreement: !signing)
    #expect(throws: ColophonError.self) { try replica.membership() }
    #expect(throws: ColophonError.self) { try replica.read(Podcasts.namespace) }
    identity.setEmptyKeys(signing: false, agreement: false)
    let membership = try replica.membership()
    let expected = Replica.Membership.member(namespaces: [Podcasts.namespace], write: true)
    let recovered = try replica.state(of: Podcasts.self)
    #expect(membership == expected)
    #expect(recovered.episodes["episode"]?.seconds == 5_555)
    let after = store.snapshot
    #expect(after == original)
  }

  @Test func otherSecretFailuresRemainUnreadableAndRecoverOnDirectRetry() throws {
    let (store, member) = try fixture()
    let original = store.snapshot
    let identity = GatedIdentity(member)
    let replica = Replica(store: store, identity: identity)
    identity.setSecretFailure(-50)
    let unavailable = try replica.read(Podcasts.namespace)
    #expect(unavailable.operations.isEmpty)
    #expect(unavailable.unreadable == 1)
    identity.setSecretFailure(nil)
    let recovered = try replica.state(of: Podcasts.self)
    #expect(recovered.episodes["episode"]?.seconds == 5_555)
    let after = store.snapshot
    #expect(after == original)
  }
}
