import ColophonCore
import ColophonStore
import CryptoKit
import Foundation

/// The device holding a library's root (spec §6). It alone writes the authority history: it
/// approves and revokes members, shares namespace keys, and hands the root on.
///
/// The root is normally a Secure Enclave identity that requires the person's presence. Every
/// namespace key is sealed to the root and to the recovery identity, so whoever holds either can
/// give keys to a new member.
public struct AuthorityHolder: Sendable {
  public let log: AuthorityLog
  let root: any Identity
  let intents: AuthorityIntentStore?

  /// Opens a library this identity is the root of. A keyring library has no root holder.
  public init(log: AuthorityLog, root: any Identity, intents: AuthorityIntentStore? = nil) throws {
    let state = try log.state()
    guard !state.isKeyring, state.root == root.publicIdentity else { throw ColophonError.notTheRoot }
    self.log = log
    self.root = root
    self.intents = intents
  }

  private init(unchecked log: AuthorityLog, root: any Identity, intents: AuthorityIntentStore? = nil) {
    self.log = log
    self.root = root
    self.intents = intents
  }

  public func state() throws -> AuthorityState { try log.state() }

  // MARK: Creating and recovering

  /// Creates a library in an empty store. Returns the holder and the recovery kit, which the
  /// person must keep: it is the only way back if the root's device is lost.
  public static func create(in store: any RecordStore, label: String, root: any Identity, firstMember: PublicIdentity,
    memberLabel: String, role: MemberRole = .device, custody: KeyCustody, namespaces: [String],
    controller: [String: String] = [:], stewards: [PublicIdentity] = [], threshold: Int = 0)
    throws -> (AuthorityHolder, RecoveryKit)
  {
    let log = AuthorityLog(store: store)
    guard !log.exists else { throw ColophonError.alreadyExists("A library here") }
    let kit = RecoveryKit()
    var genesis = AuthorityEntry(seq: 1, previous: nil, kind: .genesis)
    genesis.label = label
    genesis.root = root.publicIdentity
    genesis.recovery = try kit.identity().publicIdentity
    genesis.controller = controller.isEmpty ? nil : controller
    genesis.stewards = stewards.isEmpty ? nil : stewards
    genesis.threshold = stewards.isEmpty ? nil : threshold
    try store.create(LibraryPath.authority(1), Canonical.encode(SignedRecord(signing: Canonical.encode(genesis), with: root)))

    let holder = AuthorityHolder(unchecked: log, root: root)
    let state = try log.state()
    var drafts = [grant(firstMember, label: memberLabel, role: role, custody: custody, namespaces: namespaces, write: true,
      expires: nil, caveats: [], keyOperator: nil)]
    for namespace in namespaces {
      drafts += try holder.newEpoch(namespace, epoch: 1, for: [firstMember], in: state)
    }
    try holder.append(drafts, after: state)
    return (holder, kit)
  }

  /// Adopts a controller keyring. Every existing epoch is shared to the new vault, then the root
  /// signs the `keyring` entry. The closure builds the slots, including one the caller can open.
  public func upgrade(to controllers: [Controller], threshold: Int, recoverThreshold: Int = 1,
    slots build: (VaultKey) throws -> [VaultSlot]) throws -> VaultKey
  {
    let state = try log.state()
    guard !state.isKeyring else { throw ColophonError.notTheRoot }
    let vaultKey = VaultKey()
    let slots = try build(vaultKey)
    guard recoverThreshold >= 1 else { throw ColophonError.malformed("recover threshold") }
    let encodedRecover = recoverThreshold == 1 ? nil : recoverThreshold
    try KeyringRules.validate(controllers: controllers, threshold: threshold, slots: slots, recoverThreshold: encodedRecover,
      seq: state.latest + 1)
    let vaultIdentity = try vaultKey.identity().publicIdentity
    var drafts: [AuthorityEntry] = []
    for namespace in state.namespaces {
      for epoch in state.allEpochs(of: namespace) {
        drafts.append(try Self.share(open(namespace, epoch, in: state), namespace: namespace, epoch: epoch, with: vaultIdentity))
      }
    }
    var entry = AuthorityEntry.draft(.keyring)
    entry.controllers = controllers.sorted { $0.id < $1.id }
    entry.threshold = threshold
    entry.recoverThreshold = encodedRecover
    entry.vault = vaultIdentity
    entry.slots = slots
    drafts.append(entry)
    try append(drafts, after: state)
    return vaultKey
  }

  /// Takes the root with only the store and the recovery kit, for example on a new device after
  /// the old one was lost. The recovery identity signs the handover and re-shares every key.
  public static func recover(log: AuthorityLog, kit: RecoveryKit, newRoot: any Identity) throws -> AuthorityHolder {
    let state = try log.state()
    guard !state.isKeyring else { throw ColophonError.notTheRoot }
    let recovery = try kit.identity()
    guard recovery.publicIdentity == state.recovery else { throw ColophonError.wrongRecoveryKit }
    var handover = AuthorityEntry.draft(.handover, by: .recovery)
    handover.root = newRoot.publicIdentity
    let reshares = try reshare(state, opener: recovery, to: newRoot.publicIdentity)
    try log.append([handover] + reshares, signer: { $0.by == .recovery ? recovery : newRoot }, after: state)
    return AuthorityHolder(unchecked: log, root: newRoot)
  }

  /// Hands the root to another identity, such as the person's new phone, while this one still works.
  public func handOver(to next: PublicIdentity) throws {
    let state = try log.state()
    var handover = AuthorityEntry.draft(.handover)
    handover.root = next
    // Keys first: once the handover is written, only the new root's signatures count.
    try append(Self.reshare(state, opener: root, to: next) + [handover], after: state)
  }

  /// Replaces the recovery kit, for example after the old one was copied, lost or kept somewhere
  /// the person no longer trusts. The new recovery identity gets every existing epoch key, then
  /// every namespace moves to a fresh epoch the old kit can't open. From this entry on the old kit
  /// recovers nothing; what it could already open stays open to it.
  public func rotateRecovery() throws -> RecoveryKit {
    let state = try log.state()
    let kit = RecoveryKit()
    let next = try kit.identity().publicIdentity
    var drafts: [AuthorityEntry] = []
    for namespace in state.namespaces {
      for epoch in state.allEpochs(of: namespace) {
        drafts.append(try Self.share(open(namespace, epoch, in: state), namespace: namespace, epoch: epoch, with: next))
      }
    }
    var rotation = AuthorityEntry.draft(.rotateRecovery)
    rotation.recovery = next
    drafts.append(rotation)
    for namespace in state.namespaces {
      let members = state.activeMembers.filter { $0.namespaces.contains(namespace) }.map(\.key)
      drafts += try newEpoch(namespace, epoch: (state.epoch(of: namespace) ?? 0) + 1, for: members, in: state,
        recovery: next)
    }
    try append(drafts, after: state)
    return kit
  }

  // MARK: Members

  /// Requests with valid signatures from keys that aren't members.
  public func pendingRequests() throws -> [EnrollmentRequest] {
    let scan = try pendingRequestScan()
    guard scan.availability != .unavailable else {
      throw ColophonError.unavailable("Requests to join your library")
    }
    return scan.requests
  }

  /// Reads each request independently, retaining fresh valid requests during partial delivery.
  public func pendingRequestScan() throws -> EnrollmentRequestScan {
    EnrollmentRequestScan.read(store: log.store, authority: try log.state())
  }

  public func approve(_ request: EnrollmentRequest, namespaces: [String], write: Bool, expires: Date? = nil,
    caveats: [Caveat] = []) throws
  {
    try admit(request.member, label: request.label, role: request.role, custody: request.custody, namespaces: namespaces,
      write: write, expires: expires, caveats: caveats, keyOperator: request.keyOperator, app: request.app,
      device: request.device)
  }

  /// Completes only the sealed shares missing from an existing active grant. The grant itself
  /// remains unchanged, including its scopes, write access, expiry and caveats.
  @discardableResult public func finishApproval(memberID: String, expectedGrantSequence: Int) throws -> Bool {
    let state = try log.state()
    guard state.root == root.publicIdentity else { throw ColophonError.notTheRoot }
    guard let member = state.members[memberID], member.revokedAt == nil,
      let grant = member.current, grant.seq == expectedGrantSequence,
      grant.expires.map({ $0 > Date.now }) ?? true else { throw ColophonError.notAMember }
    for namespace in grant.namespaces where state.allEpochs(of: namespace).isEmpty {
      throw ColophonError.noAccess(namespace)
    }
    let missing = state.missingKeyShares(for: memberID)
    guard !missing.isEmpty else { return false }
    let drafts = try missing.map { share in
      try Self.share(open(share.namespace, share.epoch, in: state), namespace: share.namespace,
        epoch: share.epoch, with: member.key)
    }
    try append(drafts, after: state)
    return true
  }

  /// Admits a principal the holder already trusts, or changes an existing member's grant. Keys
  /// for every epoch of a newly granted namespace are shared, so the member can read its history.
  public func admit(_ member: PublicIdentity, label: String, role: MemberRole, custody: KeyCustody, namespaces: [String],
    write: Bool, expires: Date? = nil, caveats: [Caveat] = [], keyOperator: String? = nil, app: String? = nil,
    device: String? = nil) throws
  {
    let state = try log.state()
    var drafts = [Self.grant(member, label: label, role: role, custody: custody, namespaces: namespaces, write: write,
      expires: expires, caveats: caveats, keyOperator: keyOperator, app: app, device: device)]
    for namespace in namespaces {
      for epoch in state.allEpochs(of: namespace) where state.keys[namespace]?[epoch]?[member.id] == nil {
        drafts.append(try Self.share(open(namespace, epoch, in: state), namespace: namespace, epoch: epoch, with: member))
      }
    }
    try append(drafts, after: state)
  }

  /// Ends a member's access. Each namespace it could read moves to a fresh key for the root, the
  /// recovery identity and the members who remain. Operations of its that the holder can already
  /// see are listed and stay admitted; anything else from it is held or refused (spec §8.3).
  /// It keeps whatever it already decrypted.
  public func revoke(_ memberID: String, seen kept: [String]? = nil) throws {
    let state = try log.state()
    guard let member = state.members[memberID] else { return }
    if member.revokedAt != nil, state.incompleteRevocationNamespaces(for: memberID).isEmpty { return }
    var revoke = AuthorityEntry.draft(.revoke)
    revoke.memberID = memberID
    revoke.kept = try (member.revokedAt == nil ? (kept ?? operations(by: member, in: state)) : Array(member.kept)).sorted()
    var drafts = [revoke]
    for namespace in member.namespaces {
      let remaining = state.activeMembers.filter { $0.id != memberID && $0.namespaces.contains(namespace) }.map(\.key)
      var recipients: [String: PublicIdentity] = [:]
      for recipient in [state.root, state.recovery] + state.stewards + remaining { recipients[recipient.id] = recipient }
      for epoch in state.allEpochs(of: namespace) {
        let missing = recipients.values.filter { state.keys[namespace]?[epoch]?[$0.id] == nil }.sorted { $0.id < $1.id }
        if !missing.isEmpty {
          // New batches put the root's envelope first, so a stopped prefix can be completed
          // with the same key. A legacy prefix without that envelope remains unavailable.
          guard state.keys[namespace]?[epoch]?[root.id] != nil else {
            throw ColophonError.keysCantDoThis(String(localized:
              "A key from an interrupted access removal is missing. Keep the library folder and contact support before changing access again."))
          }
          let key = try open(namespace, epoch, in: state)
          drafts += try missing.map { try Self.share(key, namespace: namespace, epoch: epoch, with: $0) }
        }
      }
      if member.revokedAt == nil || state.needsRevocationRotation(in: namespace) {
        drafts += try newEpoch(namespace, epoch: (state.epoch(of: namespace) ?? 0) + 1, for: remaining, in: state,
          openerFirst: true)
      }
    }
    try append(drafts, after: state)
  }

  /// Replaces the stewards who can hand the root over together.
  public func setStewards(_ stewards: [PublicIdentity], threshold: Int) throws {
    guard threshold > 0, threshold <= stewards.count else { throw ColophonError.malformed("steward threshold") }
    let state = try log.state()
    var entry = AuthorityEntry.draft(.stewards)
    entry.stewards = stewards
    entry.threshold = threshold
    var drafts = [entry]
    for namespace in state.namespaces {
      for epoch in state.allEpochs(of: namespace) {
        let key = try open(namespace, epoch, in: state)
        for steward in stewards where state.keys[namespace]?[epoch]?[steward.id] == nil {
          drafts.append(try Self.share(key, namespace: namespace, epoch: epoch, with: steward))
        }
      }
    }
    try append(drafts, after: state)
  }

  // MARK: Quorum handover

  /// The exact bytes stewards sign to hand the root to `newRoot`. Valid only while the history
  /// hasn't moved on; collect signatures, then call `completeQuorumHandover`.
  public static func quorumHandoverBody(log: AuthorityLog, newRoot: PublicIdentity) throws -> Data {
    let state = try log.state()
    guard !state.isKeyring else { throw ColophonError.notTheRoot }
    var draft = AuthorityEntry.draft(.handover, by: .quorum)
    draft.root = newRoot
    return try Canonical.encode(draft.numbered(state.latest + 1, after: state.lastBody))
  }

  /// Writes a steward-signed handover, then gives the new root every key using one steward's
  /// identity (stewards hold every namespace key). Run on the new root's device.
  public static func completeQuorumHandover(log: AuthorityLog, body: Data, signatures: [SignedRecord.Cosignature],
    newRoot: any Identity, keysFrom steward: any Identity) throws -> AuthorityHolder
  {
    let state = try log.state()
    guard !state.isKeyring else { throw ColophonError.notTheRoot }
    guard let first = signatures.first else { throw ColophonError.badSignature("handover") }
    var record = SignedRecord(body: body, signature: first.signature)
    record.cosignatures = Array(signatures.dropFirst())
    let entry = try AuthorityEntry.decode(body, at: state.latest + 1)
    guard entry.seq == state.latest + 1, entry.root == newRoot.publicIdentity else { throw ColophonError.malformed("handover") }
    try log.store.create(LibraryPath.authority(entry.seq), Canonical.encode(record))
    let after = try log.state() // verifies the quorum
    let reshares = try reshare(after, opener: steward, to: newRoot.publicIdentity)
    try log.append(reshares, signer: { _ in newRoot }, after: after)
    return AuthorityHolder(unchecked: log, root: newRoot)
  }

  /// Adds a namespace, shared with the root, the recovery identity and the given members.
  public func addNamespace(_ namespace: String, for members: [PublicIdentity] = []) throws {
    let state = try log.state()
    guard state.epoch(of: namespace) == nil else { return }
    try append(newEpoch(namespace, epoch: 1, for: members, in: state), after: state)
  }

  /// A namespace key as the root holds it. Lets the holder app read every namespace.
  public func key(_ namespace: String, epoch: Int) throws -> SymmetricKey { try open(namespace, epoch, in: log.state()) }

  /// IDs of a member's operations that verify and open with the root's keys: what the holder
  /// can see it wrote.
  private func operations(by member: AuthorityState.Member, in state: AuthorityState) throws -> [String] {
    let folder = LibraryPath.operations + "/" + member.id
    return try log.store.list(folder).compactMap { name in
      guard let data = try log.store.read(folder + "/" + name),
        let record = try? Canonical.decode(SignedRecord.self, from: data), member.key.verify(record),
        let header = try? Canonical.decode(OperationHeader.self, from: record.body),
        let key = try? open(header.namespace, header.epoch, in: state),
        let plaintext = try? AES.GCM.open(AES.GCM.SealedBox(combined: header.sealed), using: key),
        let operation = try? Canonical.decode(ColophonOperation.self, from: plaintext)
      else { return nil }
      return operation.id
    }
  }

  // MARK: Entries

  private func open(_ namespace: String, _ epoch: Int, in state: AuthorityState) throws -> SymmetricKey {
    guard let sealed = state.keys[namespace]?[epoch]?[root.id] else { throw ColophonError.noAccess(namespace) }
    return try root.open(sealed)
  }

  /// `recovery` replaces the state's recovery identity when the same batch rotates it.
  private func newEpoch(_ namespace: String, epoch: Int, for members: [PublicIdentity], in state: AuthorityState,
    recovery: PublicIdentity? = nil, openerFirst: Bool = false) throws -> [AuthorityEntry]
  {
    let key = SymmetricKey(size: .bits256)
    var recipients: [String: PublicIdentity] = [:]
    for identity in [state.root, recovery ?? state.recovery] + state.stewards + members { recipients[identity.id] = identity }
    let ordered = recipients.values.sorted { $0.id < $1.id }
    let ownersFirst = openerFirst ? [state.root] + ordered.filter { $0.id != state.root.id } : ordered
    return try ownersFirst.map {
      try Self.share(key, namespace: namespace, epoch: epoch, with: $0)
    }
  }

  private static func reshare(_ state: AuthorityState, opener: any Identity, to next: PublicIdentity) throws -> [AuthorityEntry] {
    try state.namespaces.flatMap { namespace in
      try state.allEpochs(of: namespace).compactMap { epoch -> AuthorityEntry? in
        guard let sealed = state.keys[namespace]?[epoch]?[opener.id] else { return nil }
        return try share(opener.open(sealed), namespace: namespace, epoch: epoch, with: next)
      }
    }
  }

  private static func grant(_ member: PublicIdentity, label: String, role: MemberRole, custody: KeyCustody,
    namespaces: [String], write: Bool, expires: Date?, caveats: [Caveat], keyOperator: String?, app: String? = nil,
    device: String? = nil) -> AuthorityEntry
  {
    var entry = AuthorityEntry.draft(.grant)
    entry.caveats = caveats.isEmpty ? nil : caveats
    entry.keyOperator = keyOperator
    entry.app = app
    entry.device = device
    entry.member = member
    entry.label = label
    entry.role = role
    entry.custody = custody
    entry.namespaces = namespaces
    entry.write = write
    entry.expires = expires
    return entry
  }

  private static func share(_ key: SymmetricKey, namespace: String, epoch: Int, with member: PublicIdentity) throws
    -> AuthorityEntry
  {
    var entry = AuthorityEntry.draft(.shareKey)
    entry.memberID = member.id
    entry.namespace = namespace
    entry.epoch = epoch
    entry.key = try SealedKey(key, to: member)
    return entry
  }

  private func append(_ drafts: [AuthorityEntry], after state: AuthorityState) throws {
    guard !state.isKeyring else { throw ColophonError.notTheRoot }
    try log.append(drafts, signer: { _ in root }, after: state, intents: intents)
  }
}
