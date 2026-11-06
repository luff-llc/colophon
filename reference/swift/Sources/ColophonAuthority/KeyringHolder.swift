import ColophonCore
import ColophonStore
import CryptoKit
import Foundation

/// One controller of a keyring library. It approves writers and, when its roles allow, changes
/// the keyring. Namespace keys open through `vault`; a missing vault fails only when a call needs it.
public struct KeyringHolder: Sendable {
  public let log: AuthorityLog
  let signer: any ControllerSigner
  let vault: VaultKey?
  let intents: AuthorityIntentStore?

  public init(log: AuthorityLog, signer: any ControllerSigner, vault: VaultKey?, intents: AuthorityIntentStore? = nil) throws {
    let state = try log.state()
    guard let current = state.keyring?.controllers[signer.controller.id], current.key == signer.controller.key else {
      throw ColophonError.notTheRoot
    }
    self.log = log
    self.signer = signer
    self.vault = vault
    self.intents = intents
  }

  public func state() throws -> AuthorityState { try log.state() }

  /// Opens the sealed slot whose recipient is `identity` and whose seed is the current vault.
  /// An older slot for the same recipient is skipped.
  public static func openVault(state: AuthorityState, with identity: some Identity) throws -> VaultKey {
    guard let expected = state.keyring?.vault else { throw ColophonError.vaultLocked }
    let matches = state.keyring?.slots.filter { $0.kind == "sealed" && $0.recipient == identity.publicIdentity } ?? []
    return try openMatching(matches, vault: expected) { try $0.open(with: identity) }
  }

  /// Opens the PRF slot for `credential` when the unwrapped seed is the current vault.
  public static func openVault(state: AuthorityState, prfOutput: Data, credential: Data) throws -> VaultKey {
    guard let expected = state.keyring?.vault else { throw ColophonError.vaultLocked }
    let matches = state.keyring?.slots.filter { $0.kind == "prf" && $0.credential == credential } ?? []
    return try openMatching(matches, vault: expected) { try $0.open(prfOutput: prfOutput) }
  }

  public func pendingRequests() throws -> [EnrollmentRequest] {
    let scan = try pendingRequestScan()
    guard scan.availability != .unavailable else { throw ColophonError.unavailable("Requests to join your library") }
    return scan.requests
  }

  public func pendingRequestScan() throws -> EnrollmentRequestScan {
    EnrollmentRequestScan.read(store: log.store, authority: try log.state())
  }

  /// Grants exactly the namespaces the request names, and `request.write` (false when an older
  /// client omitted it). A namespace with no epoch yet gets epoch 1.
  public func approveAsRequested(_ request: EnrollmentRequest, expires: Date? = nil, caveats: [Caveat] = []) throws {
    try grant(request.member, label: request.label, role: request.role, custody: request.custody, namespaces: request.namespaces,
      write: request.write ?? false, expires: expires, caveats: caveats, keyOperator: request.keyOperator, app: request.app,
      device: request.device, createMissingEpochs: true)
  }

  public func approve(_ request: EnrollmentRequest, namespaces: [String], write: Bool, expires: Date? = nil,
    caveats: [Caveat] = [], createMissingEpochs: Bool = false) throws
  {
    try grant(request.member, label: request.label, role: request.role, custody: request.custody, namespaces: namespaces,
      write: write, expires: expires, caveats: caveats, keyOperator: request.keyOperator, app: request.app,
      device: request.device, createMissingEpochs: createMissingEpochs)
  }

  /// The grant and shares `approve` would write, still unsigned. A passkey signs these bodies
  /// asynchronously; `commitSigned` is what writes them. `openedEpochs` supplies keys this device
  /// already holds when the vault itself cannot be opened here.
  public func approvalDrafts(_ request: EnrollmentRequest, namespaces: [String], write: Bool, expires: Date? = nil,
    caveats: [Caveat] = [], createMissingEpochs: Bool = false, openedEpochs: [String: [Int: SymmetricKey]] = [:]) throws -> [AuthorityEntry]
  {
    try grantDrafts(request.member, label: request.label, role: request.role, custody: request.custody, namespaces: namespaces,
      write: write, expires: expires, caveats: caveats, keyOperator: request.keyOperator, app: request.app,
      device: request.device, createMissingEpochs: createMissingEpochs, openedEpochs: openedEpochs)
  }

  /// Numbered, chained bodies for `drafts`, with nothing signed and nothing written.
  public func numberedBodies(_ drafts: [AuthorityEntry]) throws -> [Data] {
    let state = try log.state()
    var previous = state.lastBody
    var seq = state.latest
    var bodies: [Data] = []
    for draft in drafts {
      seq += 1
      let entry = draft.numbered(seq, after: previous)
      let body = try Canonical.encode(entry)
      bodies.append(body)
      previous = body
    }
    return bodies
  }

  /// Verifies `records`, saves the intent, then writes. A verification failure leaves the store unchanged.
  public func commitSigned(_ records: [SignedRecord], drafts: [AuthorityEntry]) throws {
    let state = try log.state()
    var projected = state
    for record in records { projected = try projected.appending(record) }
    if let intents, var intent = AuthorityWriteIntent.capture(libraryID: state.libraryID, drafts: drafts, state: state) {
      intent.sequences = Array(records.indices).map { state.latest + 1 + $0 }
      intent.digests = records.map { Canonical.digest($0.body) }
      try intents.save(intent)
    }
    try write(records, startingAt: state.latest + 1)
  }

  /// Finishes only the exact previously authorized records. No controller key or vault is needed.
  /// A different canonical branch keeps the journal and requires explicit repair.
  public static func resumeSignedBatches(log: AuthorityLog, intents: AuthorityIntentStore) throws {
    let libraryID = try log.state().libraryID
    for batch in intents.loadSignedBatches(libraryID: libraryID) {
      try resume(batch, log: log, intents: intents)
    }
  }

  private static func resume(_ batch: AuthoritySignedBatch, log: AuthorityLog, intents: AuthorityIntentStore) throws {
    defer { log.invalidateCache() }
    let current = try AuthorityIntentRebase.read(store: log.store)
    let currentState = try AuthorityState(records: current)
    guard batch.libraryID == currentState.libraryID, batch.baseSequence > 0,
      current.count >= batch.baseSequence, !batch.records.isEmpty,
      Canonical.digest(try Canonical.encode(batch.records)) == batch.id else { throw interruptedKeyringConflict() }
    let base = Array(current.prefix(batch.baseSequence))
    guard let anchor = base.last, Canonical.digest(anchor.body) == batch.baseDigest else {
      throw interruptedKeyringConflict()
    }
    var expected = try AuthorityState(records: base)
    for (offset, record) in batch.records.enumerated() {
      let entry = try AuthorityEntry.decode(record.body, at: batch.baseSequence + offset + 1)
      guard offset == 0 ? entry.kind == .keyring : entry.kind == .shareKey else { throw interruptedKeyringConflict() }
      expected = try expected.appending(record)
      let index = batch.baseSequence + offset
      if current.indices.contains(index) {
        guard try Canonical.encode(current[index]) == Canonical.encode(record) else { throw interruptedKeyringConflict() }
      }
    }
    guard expected.namespaces.allSatisfy({ !expected.needsVaultRotationCompletion(in: $0) }) else {
      throw interruptedKeyringConflict()
    }
    let installed = min(batch.records.count, current.count - batch.baseSequence)
    for offset in installed..<batch.records.count {
      try Task.checkCancellation()
      let path = LibraryPath.authority(batch.baseSequence + offset + 1)
      let bytes = try Canonical.encode(batch.records[offset])
      do { try log.store.create(path, bytes) }
      catch ColophonError.alreadyExists {
        guard let existing = try log.store.read(path), existing == bytes else { throw interruptedKeyringConflict() }
      }
    }
    // Re-read before clearing: a provider may replace a prefix while the tail was being written.
    let finished = try AuthorityIntentRebase.read(store: log.store)
    _ = try AuthorityState(records: finished)
    for (offset, record) in batch.records.enumerated() {
      let index = batch.baseSequence + offset
      guard finished.indices.contains(index), try Canonical.encode(finished[index]) == Canonical.encode(record) else {
        throw interruptedKeyringConflict()
      }
    }
    try intents.confirmSignedBatch(batch)
  }

  private static func interruptedKeyringConflict() -> ColophonError {
    .keysCantDoThis(String(localized:
      "A library key change was interrupted and the history has changed. Keep the library folder and contact support before changing keys again."))
  }

  public func admit(_ member: PublicIdentity, label: String, role: MemberRole, custody: KeyCustody, namespaces: [String],
    write: Bool, expires: Date? = nil, caveats: [Caveat] = [], keyOperator: String? = nil, app: String? = nil,
    device: String? = nil) throws
  {
    try grant(member, label: label, role: role, custody: custody, namespaces: namespaces, write: write, expires: expires,
      caveats: caveats, keyOperator: keyOperator, app: app, device: device, createMissingEpochs: false)
  }

  @discardableResult public func finishApproval(memberID: String, expectedGrantSequence: Int) throws -> Bool {
    let state = try log.state()
    _ = try require("approve", in: state)
    guard let member = state.members[memberID], member.revokedAt == nil, let grant = member.current, grant.seq == expectedGrantSequence,
      grant.expires.map({ $0 > Date.now }) ?? true else { throw ColophonError.notAMember }
    for namespace in grant.namespaces where state.allEpochs(of: namespace).isEmpty { throw ColophonError.noAccess(namespace) }
    let missing = state.missingKeyShares(for: memberID)
    guard !missing.isEmpty else { return false }
    let drafts = try missing.map { share in
      try self.share(open(share.namespace, share.epoch, in: state), namespace: share.namespace, epoch: share.epoch, with: member.key)
    }
    try commit(drafts)
    return true
  }

  public func revoke(_ memberID: String, seen kept: [String]? = nil) throws {
    let state = try log.state()
    let ring = try require("approve", in: state)
    guard let member = state.members[memberID] else { return }
    if member.revokedAt != nil, state.incompleteRevocationNamespaces(for: memberID).isEmpty { return }
    var revoke = controllerDraft(.revoke)
    revoke.memberID = memberID
    revoke.kept = try (member.revokedAt == nil ? (kept ?? operations(by: member, in: state)) : Array(member.kept)).sorted()
    var drafts = [revoke]
    for namespace in member.namespaces {
      let remaining = state.activeMembers.filter { $0.id != memberID && $0.namespaces.contains(namespace) }.map(\.key)
      var recipients: [String: PublicIdentity] = [ring.vault.id: ring.vault]
      for recipient in remaining { recipients[recipient.id] = recipient }
      for epoch in state.allEpochs(of: namespace) {
        let missing = recipients.values.filter { state.keys[namespace]?[epoch]?[$0.id] == nil }.sorted { $0.id < $1.id }
        if !missing.isEmpty {
          guard state.keys[namespace]?[epoch]?[ring.vault.id] != nil else {
            throw ColophonError.keysCantDoThis(String(localized:
              "A key from an interrupted access removal is missing. Keep the library folder and contact support before changing access again."))
          }
          let key = try open(namespace, epoch, in: state)
          drafts += try missing.map { try share(key, namespace: namespace, epoch: epoch, with: $0) }
        }
      }
      if member.revokedAt == nil || state.needsRevocationRotation(in: namespace) {
        drafts += try sealedShares(namespace: namespace, epoch: (state.epoch(of: namespace) ?? 0) + 1, vault: ring.vault,
          members: remaining, openerFirst: true)
      }
    }
    try commit(drafts)
  }

  public func addNamespace(_ namespace: String, for members: [PublicIdentity] = []) throws {
    let state = try log.state()
    let ring = try require("approve", in: state)
    guard state.epoch(of: namespace) == nil else { return }
    try commit(sealedShares(namespace: namespace, epoch: 1, vault: ring.vault, members: members))
  }

  /// The body of a keyring change, for every controller that must sign it. Pass `rotatingVault`
  /// when the change replaces the vault; its public identity is the entry's vault, and the slots
  /// must already be sealed to it.
  public func keyringChange(rotatingVault: VaultKey? = nil, _ build: (Keyring) throws -> (controllers: [Controller], threshold: Int,
    slots: [VaultSlot], rotateVault: Bool, recoverThreshold: Int)) throws -> Data
  {
    let state = try log.state()
    guard let ring = state.keyring else { throw ColophonError.notTheRoot }
    let proposal = try build(ring)
    let vaultIdentity: PublicIdentity
    if proposal.rotateVault {
      guard let rotatingVault else { throw ColophonError.malformed("vault rotation") }
      vaultIdentity = try rotatingVault.identity().publicIdentity
      guard vaultIdentity != ring.vault else { throw ColophonError.malformed("vault rotation") }
    } else {
      guard rotatingVault == nil else { throw ColophonError.malformed("vault rotation") }
      vaultIdentity = ring.vault
    }
    guard proposal.recoverThreshold >= 1 else { throw ColophonError.malformed("recover threshold") }
    let encodedRecover = proposal.recoverThreshold == 1 ? nil : proposal.recoverThreshold
    try KeyringRules.validate(controllers: proposal.controllers, threshold: proposal.threshold, slots: proposal.slots,
      recoverThreshold: encodedRecover, seq: state.latest + 1)
    var entry = controllerDraft(.keyring)
    entry.controllers = proposal.controllers.sorted { $0.id < $1.id }
    entry.threshold = proposal.threshold
    entry.recoverThreshold = encodedRecover
    entry.vault = vaultIdentity
    entry.slots = proposal.slots
    return try Canonical.encode(entry.numbered(state.latest + 1, after: state.lastBody))
  }

  /// Writes a signed keyring change. When the vault identity changes, `newVault` must be that vault
  /// and `vault` must open the current one. The same batch shares every existing epoch to the new
  /// vault, then starts a fresh epoch for every namespace. A `control` signer may write those shares.
  public func completeKeyringChange(body: Data, signatures: [SignedRecord.Cosignature], newVault: VaultKey? = nil) throws {
    let state = try log.state()
    guard state.keyring?.controllers[signer.controller.id] != nil, let currentVault = state.keyring?.vault else {
      throw ColophonError.notTheRoot
    }
    let entry = try AuthorityEntry.decode(body, at: state.latest + 1)
    guard entry.kind == .keyring, entry.by == .controller, let proposedVault = entry.vault else {
      throw ColophonError.malformed("keyring")
    }
    let record = try assembled(body, entry: entry, signatures: signatures)
    var projected = try state.appending(record)
    var records = [record]
    if proposedVault != currentVault {
      // Check the current vault directly: a library with no namespaces would never open it below.
      guard let newVault, let vault, try vault.identity().publicIdentity == currentVault else {
        throw ColophonError.vaultLocked
      }
      let identity = try newVault.identity().publicIdentity
      guard identity == proposedVault else { throw ColophonError.malformed("vault rotation") }
      guard let roles = projected.keyring?.controllers[signer.controller.id]?.roles,
        roles.contains("approve") || roles.contains("control")
      else { throw ColophonError.notTheRoot }
      let carried = try existingEpochShares(in: state, to: identity)
      let created = try freshEpochs(in: state, vault: identity)
      let shares = try signed(carried + created, after: projected)
      for share in shares { projected = try projected.appending(share) }
      records += shares
    } else if newVault != nil {
      throw ColophonError.malformed("vault rotation")
    }
    if let intents {
      let batch = try AuthoritySignedBatch(libraryID: state.libraryID, baseSequence: state.latest,
        baseDigest: Canonical.digest(state.lastBody), records: records)
      try intents.saveSignedBatch(batch)
      try Self.resume(batch, log: log, intents: intents)
    } else {
      // SDK callers without a local journal still fail closed on an incomplete vault rotation.
      // Applications supply their intent store so a process restart can finish the signed tail.
      try write(records, startingAt: state.latest + 1)
    }
  }

  /// Adds a controller. One signature is enough when this controller meets the threshold, or when
  /// it has `recover` and the change only adds.
  public func addController(_ controller: Controller, slot: VaultSlot?) throws {
    let state = try log.state()
    guard var ring = state.keyring else { throw ColophonError.notTheRoot }
    guard ring.controllers[controller.id] == nil else { throw ColophonError.alreadyExists("A controller") }
    ring.controllers[controller.id] = controller
    var slots = ring.slots
    if let slot { slots.append(slot) }
    let body = try keyringChange { _ in
      (controllers: Array(ring.controllers.values), threshold: ring.threshold, slots: slots, rotateVault: false,
        recoverThreshold: ring.recoverThreshold)
    }
    try completeKeyringChange(body: body, signatures: [try cosignature(over: body)])
  }

  /// Removes a controller and moves the library to a new vault the removed controller cannot open.
  public func removeController(id: String, newSlots: (VaultKey) throws -> [VaultSlot]) throws {
    let state = try log.state()
    guard var ring = state.keyring, ring.controllers[id] != nil else { throw ColophonError.malformed("controller") }
    let rotating = VaultKey()
    let slots = try newSlots(rotating)
    ring.controllers.removeValue(forKey: id)
    let body = try keyringChange(rotatingVault: rotating) { _ in
      (controllers: Array(ring.controllers.values), threshold: ring.threshold, slots: slots, rotateVault: true,
        recoverThreshold: ring.recoverThreshold)
    }
    try completeKeyringChange(body: body, signatures: [try cosignature(over: body)], newVault: rotating)
  }

  // MARK: Entries

  private func grant(_ member: PublicIdentity, label: String, role: MemberRole, custody: KeyCustody, namespaces: [String],
    write: Bool, expires: Date?, caveats: [Caveat], keyOperator: String?, app: String?, device: String?,
    createMissingEpochs: Bool) throws
  {
    try commit(try grantDrafts(member, label: label, role: role, custody: custody, namespaces: namespaces, write: write,
      expires: expires, caveats: caveats, keyOperator: keyOperator, app: app, device: device,
      createMissingEpochs: createMissingEpochs))
  }

  private func grantDrafts(_ member: PublicIdentity, label: String, role: MemberRole, custody: KeyCustody, namespaces: [String],
    write: Bool, expires: Date?, caveats: [Caveat], keyOperator: String?, app: String?, device: String?,
    createMissingEpochs: Bool, openedEpochs: [String: [Int: SymmetricKey]] = [:]) throws -> [AuthorityEntry]
  {
    let state = try log.state()
    let ring = try require("approve", in: state)
    var draft = controllerDraft(.grant)
    draft.caveats = caveats.isEmpty ? nil : caveats
    draft.keyOperator = keyOperator
    draft.app = app
    draft.device = device
    draft.member = member
    draft.label = label
    draft.role = role
    draft.custody = custody
    draft.namespaces = namespaces
    draft.write = write
    draft.expires = expires
    var drafts = [draft]
    for namespace in namespaces {
      let epochs = state.allEpochs(of: namespace)
      if epochs.isEmpty, createMissingEpochs {
        let holders = state.activeMembers.filter { $0.namespaces.contains(namespace) }.map(\.key)
        drafts += try sealedShares(namespace: namespace, epoch: 1, vault: ring.vault, members: holders + [member])
      } else {
        for epoch in epochs where state.keys[namespace]?[epoch]?[member.id] == nil {
          drafts.append(try share(open(namespace, epoch, in: state, openedEpochs: openedEpochs), namespace: namespace, epoch: epoch,
            with: member))
        }
      }
    }
    return drafts
  }

  private func require(_ role: String, in state: AuthorityState) throws -> Keyring {
    guard let ring = state.keyring, let current = ring.controllers[signer.controller.id], current.roles.contains(role) else {
      throw ColophonError.notTheRoot
    }
    return ring
  }

  private func open(_ namespace: String, _ epoch: Int, in state: AuthorityState,
    openedEpochs: [String: [Int: SymmetricKey]] = [:]) throws -> SymmetricKey
  {
    if let key = openedEpochs[namespace]?[epoch] { return key }
    guard let vault else { throw ColophonError.vaultLocked }
    guard let ring = state.keyring, let sealed = state.keys[namespace]?[epoch]?[ring.vault.id] else {
      throw ColophonError.noAccess(namespace)
    }
    return try vault.identity().open(sealed)
  }

  private func controllerDraft(_ kind: AuthorityEntry.Kind) -> AuthorityEntry {
    var entry = AuthorityEntry.draft(kind, by: .controller)
    entry.signer = signer.controller.id
    return entry
  }

  private func share(_ key: SymmetricKey, namespace: String, epoch: Int, with member: PublicIdentity) throws -> AuthorityEntry {
    var entry = controllerDraft(.shareKey)
    entry.memberID = member.id
    entry.namespace = namespace
    entry.epoch = epoch
    entry.key = try SealedKey(key, to: member)
    return entry
  }

  private func sealedShares(namespace: String, epoch: Int, vault: PublicIdentity, members: [PublicIdentity], openerFirst: Bool = false)
    throws -> [AuthorityEntry]
  {
    let key = SymmetricKey(size: .bits256)
    var recipients: [String: PublicIdentity] = [vault.id: vault]
    for member in members { recipients[member.id] = member }
    let ordered = recipients.values.sorted { $0.id < $1.id }
    let ownersFirst = openerFirst ? [vault] + ordered.filter { $0.id != vault.id } : ordered
    return try ownersFirst.map { recipient in
      try share(key, namespace: namespace, epoch: epoch, with: recipient)
    }
  }

  /// Seals every epoch that already exists to the new vault. `state` is the keyring before the
  /// change, so `open` still finds those epochs under the current vault.
  private func existingEpochShares(in state: AuthorityState, to vault: PublicIdentity) throws -> [AuthorityEntry] {
    var drafts: [AuthorityEntry] = []
    for namespace in state.namespaces {
      for epoch in state.allEpochs(of: namespace) {
        drafts.append(try share(open(namespace, epoch, in: state), namespace: namespace, epoch: epoch, with: vault))
      }
    }
    return drafts
  }

  private func freshEpochs(in state: AuthorityState, vault: PublicIdentity) throws -> [AuthorityEntry] {
    try state.namespaces.flatMap { namespace in
      let members = state.activeMembers.filter { $0.namespaces.contains(namespace) }.map(\.key)
      return try sealedShares(namespace: namespace, epoch: (state.epoch(of: namespace) ?? 0) + 1, vault: vault,
        members: members, openerFirst: true)
    }
  }

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

  private func cosignature(over body: Data) throws -> SignedRecord.Cosignature {
    let signed = try signer.sign(body)
    return SignedRecord.Cosignature(signer: signer.controller.id, signature: signed.signature, assertion: signed.assertion)
  }

  private func assembled(_ body: Data, entry: AuthorityEntry, signatures: [SignedRecord.Cosignature]) throws -> SignedRecord {
    guard let primaryID = entry.signer else { throw ColophonError.badSignature("keyring") }
    var primary: SignedRecord.Cosignature?
    var extras: [SignedRecord.Cosignature] = []
    var seen = Set<String>()
    for signature in signatures {
      guard seen.insert(signature.signer).inserted else { throw ColophonError.badSignature("keyring") }
      if signature.signer == primaryID { primary = signature } else { extras.append(signature) }
    }
    guard let primary else { throw ColophonError.badSignature("keyring") }
    var record = SignedRecord(body: body, signature: primary.signature, assertion: primary.assertion)
    record.cosignatures = extras.isEmpty ? nil : extras
    return record
  }

  /// Signs every draft and checks the batch verifies before anything is written.
  private func commit(_ drafts: [AuthorityEntry]) throws {
    let state = try log.state()
    let records = try signed(drafts, after: state)
    if let intents, var intent = AuthorityWriteIntent.capture(libraryID: state.libraryID, drafts: drafts, state: state) {
      intent.sequences = Array(records.indices).map { state.latest + 1 + $0 }
      intent.digests = records.map { Canonical.digest($0.body) }
      try intents.save(intent)
    }
    try write(records, startingAt: state.latest + 1)
  }

  private func signed(_ drafts: [AuthorityEntry], after state: AuthorityState) throws -> [SignedRecord] {
    var projected = state
    var previous = state.lastBody
    var seq = state.latest
    var records: [SignedRecord] = []
    for draft in drafts {
      seq += 1
      let entry = draft.numbered(seq, after: previous)
      let body = try Canonical.encode(entry)
      let signed = try signer.sign(body)
      var record = SignedRecord(body: body, signature: signed.signature)
      record.assertion = signed.assertion
      projected = try projected.appending(record)
      records.append(record)
      previous = body
    }
    return records
  }

  private func write(_ records: [SignedRecord], startingAt seq: Int) throws {
    for (offset, record) in records.enumerated() {
      try log.store.create(LibraryPath.authority(seq + offset), try Canonical.encode(record))
    }
  }

  /// The first slot that opens to `vault`. A slot that opens a different seed is skipped.
  private static func openMatching(_ slots: [VaultSlot], vault: PublicIdentity, _ open: (VaultSlot) throws -> VaultKey) throws -> VaultKey {
    guard !slots.isEmpty else { throw ColophonError.vaultLocked }
    var locked = false
    for slot in slots {
      do {
        let opened = try open(slot)
        if try opened.identity().publicIdentity == vault { return opened }
        locked = true
      } catch ColophonError.vaultLocked {
        locked = true
      }
    }
    throw locked ? ColophonError.vaultLocked : ColophonError.malformed("vault slot")
  }
}
