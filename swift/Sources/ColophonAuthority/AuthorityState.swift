import ColophonCore
import CryptoKit
import Foundation

/// The verified fold of an authority history: the current root, the members and their grants
/// over time, and every sealed namespace key.
public struct AuthorityState: Sendable {
  public struct Grant: Sendable, Equatable {
    public let seq: Int
    public let namespaces: [String]
    public let write: Bool
    public let expires: Date?
    public let caveats: [Caveat]
    public let issued: Date
    /// Informational. Absent on grants written before apps recorded where a request came from.
    public let app: String?
    public let device: String?
    /// Controller id that signed the grant. Nil when the 0.1 root signed it.
    public let approvedBy: String?
  }

  /// A controller added by a recovery-path keyring change.
  public struct RecoveryAddition: Sendable, Equatable {
    public let controllerID: String
    public let label: String
    public let issued: Date
    public let sequence: Int
    /// True when exactly one passkey signed. A kit, a security key, or two keys stays false.
    public let addedWithPasskey: Bool
  }

  public struct Member: Sendable, Identifiable {
    public let key: PublicIdentity
    public let label: String
    public let role: MemberRole
    public let custody: KeyCustody?
    /// For a custodial member, who holds its key.
    public let keyOperator: String?
    /// From the latest grant. Informational.
    public internal(set) var app: String?
    public internal(set) var device: String?
    /// Every grant this member has had, oldest first.
    public internal(set) var grants: [Grant]
    public internal(set) var revokedAt: Int?
    public internal(set) var kept: Set<String> = []

    public var id: String { key.id }
    public var grantedAt: Int { grants.first?.seq ?? 0 }
    public var current: Grant? { revokedAt == nil ? grants.last : nil }
    public var namespaces: [String] { grants.last?.namespaces ?? [] }

    /// The grant in force when `seq` was the newest entry.
    public func grant(at seq: Int) -> Grant? { grants.last { $0.seq <= seq } }
  }

  public let libraryID: String
  public let label: String
  /// When the library was created.
  public let created: Date
  public private(set) var recovery: PublicIdentity
  public let controller: [String: String]
  public private(set) var root: PublicIdentity
  /// Identities that can hand the root over together, and how many of them must sign.
  public private(set) var stewards: [PublicIdentity] = []
  public private(set) var threshold = 0
  /// Set once a root-signed `keyring` entry has been accepted. Nil in a 0.1 library.
  public private(set) var keyring: Keyring?
  /// Actual vault rotations after adoption. A first keyring adopts the existing history.
  public private(set) var vaultChangedAt: Int?
  public var isKeyring: Bool { keyring != nil }
  public private(set) var latest = 0
  public private(set) var members: [String: Member] = [:]
  /// When each controller id first appeared.
  public private(set) var controllerAdded: [String: Date] = [:]
  /// Controllers added by the recovery path, oldest first.
  public private(set) var recoveryAdditions: [RecoveryAddition] = []
  /// namespace → epoch → principal ID → sealed key.
  public private(set) var keys: [String: [Int: [String: SealedKey]]] = [:]
  /// namespace → epochs with the entry that introduced each, oldest first.
  private var epochs: [String: [(epoch: Int, seq: Int)]] = [:]
  private(set) var lastBody = Data()

  /// Verifies the chain and every signature, in order.
  public init(records: [SignedRecord]) throws {
    guard let first = records.first else { throw ColophonError.notALibrary }
    let genesis = try AuthorityEntry.decode(first.body, at: 1)
    guard genesis.seq == 1, genesis.kind == .genesis, genesis.by == .root, let root = genesis.root,
      let recovery = genesis.recovery
    else { throw ColophonError.brokenAuthorityChain(1) }
    guard root.verify(first) else { throw ColophonError.badSignature("authority entry 1") }
    libraryID = String(Canonical.digest(first.body).prefix(32))
    label = genesis.label ?? "Library"
    created = genesis.issued
    self.root = root
    self.recovery = recovery
    controller = genesis.controller ?? [:]
    stewards = genesis.stewards ?? []
    threshold = genesis.threshold ?? 0
    latest = 1
    lastBody = first.body
    for record in records.dropFirst() { try consume(record) }
  }

  /// Accepts one more entry. Kind misuse breaks the chain; a signature that does not verify is a
  /// bad signature.
  private mutating func consume(_ record: SignedRecord) throws {
    let entry = try AuthorityEntry.decode(record.body, at: latest + 1)
    guard entry.seq == latest + 1, entry.previous == Canonical.digest(lastBody) else {
      throw ColophonError.brokenAuthorityChain(entry.seq)
    }
    if let problem = structuralProblem(entry) { throw problem }
    guard verify(record, entry) else { throw ColophonError.badSignature("authority entry \(entry.seq)") }
    recordControllers(record, entry)
    apply(entry)
    latest = entry.seq
    lastBody = record.body
  }

  func appending(_ record: SignedRecord) throws -> AuthorityState {
    var copy = self
    try copy.consume(record)
    return copy
  }

  /// A keyring entry must be whole. After adoption, 0.1 authority kinds cannot appear again.
  private func structuralProblem(_ entry: AuthorityEntry) -> ColophonError? {
    if keyring != nil {
      switch entry.kind {
      case .genesis, .handover, .stewards, .rotateRecovery: return .brokenAuthorityChain(entry.seq)
      case .grant, .revoke, .shareKey, .keyring: break
      }
    }
    guard entry.kind == .keyring else { return nil }
    guard entry.vault != nil else { return .brokenAuthorityChain(entry.seq) }
    return KeyringRules.chainProblem(controllers: entry.controllers, threshold: entry.threshold, slots: entry.slots,
      recoverThreshold: entry.recoverThreshold, seq: entry.seq)
  }

  /// Before a keyring, the root signs everything and recovery or a steward quorum may sign only a
  /// handover. The root-signed `keyring` entry is the upgrade. After it, only controllers sign.
  private func verify(_ record: SignedRecord, _ entry: AuthorityEntry) -> Bool {
    if let ring = keyring { return verify(record, entry, in: ring) }
    if entry.kind == .keyring {
      guard entry.by == .root, record.assertion == nil, (record.cosignatures ?? []).isEmpty else { return false }
      return root.verify(record)
    }
    switch entry.by {
    case .root: return root.verify(record)
    case .recovery: return entry.kind == .handover && recovery.verify(record)
    case .quorum:
      guard entry.kind == .handover, threshold > 0 else { return false }
      let signatures = [record.signature] + (record.cosignatures ?? []).map(\.signature)
      let signed = Set(stewards.filter { steward in signatures.contains { steward.verify($0, over: record.body) } }.map(\.id))
      return signed.count >= threshold
    case .controller: return false
    }
  }

  private func verify(_ record: SignedRecord, _ entry: AuthorityEntry, in ring: Keyring) -> Bool {
    switch entry.kind {
    case .grant, .revoke, .shareKey:
      guard entry.by == .controller, (record.cosignatures ?? []).isEmpty,
        let signers = verifiedSigners(record, entry, ring: ring, requireVerification: false), signers.count == 1
      else { return false }
      if entry.kind == .shareKey {
        if signers[0].roles.contains("approve") { return true }
        // A control-only key shares keys only while rotating the vault: to the vault itself, or to a
        // member that already holds the namespace. It can't give a key to anyone new.
        guard signers[0].roles.contains("control"), let recipient = entry.memberID, let namespace = entry.namespace
        else { return false }
        return recipient == ring.vault.id || members[recipient]?.current?.namespaces.contains(namespace) == true
      }
      return signers[0].roles.contains("approve")
    case .keyring:
      guard entry.by == .controller else { return false }
      return verifyKeyringChange(record, entry, ring: ring)
    case .genesis, .handover, .stewards, .rotateRecovery:
      return false
    }
  }

  /// Threshold path: enough distinct `control` controllers. Lowering `recoverThreshold` also needs
  /// that many distinct `recover` controllers, so one key cannot leave Two Keys. Recovery path:
  /// at least `recoverThreshold` distinct `recover` controllers, and the new keyring only adds.
  /// WebAuthn signatures on either path require user verification.
  private func verifyKeyringChange(_ record: SignedRecord, _ entry: AuthorityEntry, ring: Keyring) -> Bool {
    guard let controllers = entry.controllers, let threshold = entry.threshold, let vault = entry.vault, let slots = entry.slots,
      let signers = verifiedSigners(record, entry, ring: ring, requireVerification: true)
    else { return false }
    let proposedRecover = entry.recoverThreshold ?? 1
    let control = signers.filter { $0.roles.contains("control") }.count
    let recovering = signers.filter { $0.roles.contains("recover") }
    if control >= ring.threshold, proposedRecover >= ring.recoverThreshold || recovering.count >= ring.recoverThreshold {
      return true
    }
    guard recovering.count == signers.count, recovering.count >= ring.recoverThreshold else { return false }
    return ring.admitsRecovery(controllers: controllers, threshold: threshold, vault: vault, slots: slots,
      recoverThreshold: proposedRecover)
  }

  /// The primary signature plus each cosignature, or nil if any of them fails.
  private func verifiedSigners(_ record: SignedRecord, _ entry: AuthorityEntry, ring: Keyring, requireVerification: Bool)
    -> [Controller]?
  {
    guard let primaryID = entry.signer, let primary = ring.controllers[primaryID],
      primary.verify(signature: record.signature, assertion: record.assertion, over: record.body,
        requireVerification: requireVerification)
    else { return nil }
    var signers = [primary]
    var seen: Set<String> = [primaryID]
    for cosignature in record.cosignatures ?? [] {
      guard seen.insert(cosignature.signer).inserted, let controller = ring.controllers[cosignature.signer],
        controller.verify(signature: cosignature.signature, assertion: cosignature.assertion, over: record.body,
          requireVerification: requireVerification)
      else { return nil }
      signers.append(controller)
    }
    return signers
  }

  /// Records when a controller first appears, and when a recovery-path change added one.
  private mutating func recordControllers(_ record: SignedRecord, _ entry: AuthorityEntry) {
    guard entry.kind == .keyring, let controllers = entry.controllers else { return }
    let previous = keyring?.controllers ?? [:]
    let added = controllers.filter { previous[$0.id] == nil }
    for controller in added where controllerAdded[controller.id] == nil {
      controllerAdded[controller.id] = entry.issued
    }
    guard let ring = keyring, !added.isEmpty, let signers = recoverySigners(record, entry, ring: ring) else { return }
    // Exactly one WebAuthn passkey with a PRF slot. A security key has control, and two keys are a pair.
    let addedWithPasskey = Self.signedByOnePasskey(signers, ring: ring)
    for controller in added {
      recoveryAdditions.append(RecoveryAddition(controllerID: controller.id, label: controller.label, issued: entry.issued,
        sequence: entry.seq, addedWithPasskey: addedWithPasskey))
    }
  }

  /// A passkey admission is one WebAuthn signer with no control role whose credential has a PRF slot.
  public static func signedByOnePasskey(_ signers: [Controller], ring: Keyring) -> Bool {
    guard signers.count == 1, let signer = signers.first, signer.kind == "webauthn",
      !signer.roles.contains("control"), let credential = signer.credential else { return false }
    if ring.slots.contains(where: { $0.kind == "prf" && $0.credential == credential }) { return true }
    return ring.slots.contains { ($0.parts ?? []).contains { $0.kind == "prf" && $0.credential == credential } }
  }

  /// Signers of a recovery-path keyring change, or nil when an existing device approved it.
  /// A new device was let in without an existing device approving it: only passkeys, security keys
  /// or a recovery kit signed. Another device's owner key is an existing `p256` controller that
  /// can approve or control. A kit is `p256` too, but it only recovers, so it still raises the notice.
  private func recoverySigners(_ record: SignedRecord, _ entry: AuthorityEntry, ring: Keyring) -> [Controller]? {
    guard let signers = verifiedSigners(record, entry, ring: ring, requireVerification: true),
      let controllers = entry.controllers else { return nil }
    let added = controllers.filter { ring.controllers[$0.id] == nil }
    guard added.contains(where: { $0.kind == "p256" && $0.roles.contains("control") }) else { return nil }
    let existingDeviceApproved = signers.contains { signer in
      guard let existing = ring.controllers[signer.id], existing.kind == "p256" else { return false }
      return existing.roles.contains("approve") || existing.roles.contains("control")
    }
    guard !existingDeviceApproved else { return nil }
    return signers
  }

  private mutating func apply(_ entry: AuthorityEntry) {
    switch entry.kind {
    case .genesis:
      break
    case .grant:
      guard let key = entry.member else { return }
      let grant = Grant(seq: entry.seq, namespaces: entry.namespaces ?? [], write: entry.write ?? false, expires: entry.expires,
        caveats: entry.caveats ?? [], issued: entry.issued, app: entry.app, device: entry.device,
        approvedBy: entry.by == .controller ? entry.signer : nil)
      if var member = members[key.id], member.revokedAt == nil {
        member.grants.append(grant)
        if let app = entry.app { member.app = app }
        if let device = entry.device { member.device = device }
        members[key.id] = member
      } else if members[key.id] == nil {
        members[key.id] = Member(key: key, label: entry.label ?? "Member", role: entry.role ?? .app, custody: entry.custody,
          keyOperator: entry.keyOperator, app: entry.app, device: entry.device, grants: [grant])
      }
    case .revoke:
      guard let id = entry.memberID, members[id]?.revokedAt == nil else { return }
      members[id]?.revokedAt = entry.seq
      members[id]?.kept = Set(entry.kept ?? [])
    case .shareKey:
      guard let id = entry.memberID, let namespace = entry.namespace, let epoch = entry.epoch, let key = entry.key else { return }
      keys[namespace, default: [:]][epoch, default: [:]][id] = key
      if !(epochs[namespace] ?? []).contains(where: { $0.epoch == epoch }) {
        epochs[namespace, default: []].append((epoch, entry.seq))
      }
    case .handover:
      if let next = entry.root { root = next }
    case .stewards:
      stewards = entry.stewards ?? []
      threshold = entry.threshold ?? 0
    case .rotateRecovery:
      if let next = entry.recovery { recovery = next }
    case .keyring:
      guard let controllers = entry.controllers, let threshold = entry.threshold, let vault = entry.vault, let slots = entry.slots
      else { return }
      if let previous = keyring, previous.vault != vault { vaultChangedAt = entry.seq }
      var map: [String: Controller] = [:]
      for controller in controllers { map[controller.id] = controller }
      keyring = Keyring(controllers: map, threshold: threshold, vault: vault, slots: slots,
        recoverThreshold: entry.recoverThreshold ?? 1)
    }
  }

  public var namespaces: [String] { epochs.keys.sorted() }

  /// The namespace's current key epoch.
  public func epoch(of namespace: String) -> Int? { epochs[namespace]?.last?.epoch }

  /// The epoch that was current when `seq` was the newest entry.
  public func epoch(of namespace: String, at seq: Int) -> Int? { epochs[namespace]?.last { $0.seq <= seq }?.epoch }

  /// Every epoch a namespace has had.
  public func allEpochs(of namespace: String) -> [Int] { epochs[namespace]?.map(\.epoch) ?? [] }

  /// Honest writers must wait until a revocation has advanced this namespace to a key the
  /// removed members were never given. This also fails closed for a legacy partial revoke.
  public func needsRevocationRotation(in namespace: String) -> Bool {
    guard let epoch = epoch(of: namespace), let introduced = epochs[namespace]?.last?.seq else { return false }
    return members.values.contains { member in
      guard let revoked = member.revokedAt, member.namespaces.contains(namespace) else { return false }
      return introduced <= revoked || keys[namespace]?[epoch]?[member.id] != nil
    }
  }

  /// A new vault must hold every historical epoch, and a fresh epoch must be fully shared,
  /// before an SDK writer can publish bytes that a removed controller might otherwise open.
  public func needsVaultRotationCompletion(in namespace: String) -> Bool {
    guard let changed = vaultChangedAt, let ring = keyring, let epoch = epoch(of: namespace) else { return false }
    guard let introduced = epochs[namespace]?.last?.seq, introduced > changed else { return true }
    if allEpochs(of: namespace).contains(where: { keys[namespace]?[$0]?[ring.vault.id] == nil }) { return true }
    return activeMembers.contains { member in
      member.namespaces.contains(namespace) && keys[namespace]?[epoch]?[member.id] == nil
    }
  }

  /// Namespaces an interrupted removal still needs to rotate or finish sharing. A complete
  /// prefix excludes the removed identity and gives the current epoch to every remaining reader.
  public func incompleteRevocationNamespaces(for memberID: String) -> [String] {
    guard let member = members[memberID], member.revokedAt != nil else { return [] }
    return member.namespaces.filter { namespace in
      if needsRevocationRotation(in: namespace) { return true }
      guard epoch(of: namespace) != nil else { return true }
      var recipients = activeMembers.filter { $0.namespaces.contains(namespace) }.map(\.key)
      if let keyring { recipients.append(keyring.vault) }
      else { recipients += [root, recovery] + stewards }
      return allEpochs(of: namespace).contains { epoch in
        recipients.contains { keys[namespace]?[epoch]?[$0.id] == nil }
      }
    }
  }

  /// Sealed shares still needed by the member's current grant. This does not make an expired or
  /// revoked grant eligible for repair; callers must check the grant before acting.
  public func missingKeyShares(for memberID: String) -> [(namespace: String, epoch: Int)] {
    guard let grant = members[memberID]?.current else { return [] }
    return grant.namespaces.flatMap { namespace in
      allEpochs(of: namespace).compactMap { epoch in
        keys[namespace]?[epoch]?[memberID] == nil ? (namespace: namespace, epoch: epoch) : nil
      }
    }
  }

  public var activeMembers: [Member] {
    members.values.filter { $0.revokedAt == nil }.sorted { $0.grantedAt < $1.grantedAt }
  }
}
