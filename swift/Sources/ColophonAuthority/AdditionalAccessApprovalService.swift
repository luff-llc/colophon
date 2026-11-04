import ColophonCore
import ColophonStore
import Foundation

/// Publication is fenced by immutable authority sequence creation, not a distributed request/store CAS.
public struct AdditionalAccessApprovalService: Sendable {
  public struct Receipt: Sendable {
    public let libraryID: String
    public let memberID: String
    public let requestID: UUID
    public let requestBodyDigest: String
    public let grantSequence: Int
    public let namespaces: [String]
    public let write: Bool
  }
  public let log: AuthorityLog
  public let journal: AdditionalAccessApprovalJournal
  private let now: @Sendable () -> Date
  public init(log: AuthorityLog, journal: AdditionalAccessApprovalJournal, authorizationNow: @escaping @Sendable () -> Date = { .now }) {
    self.log = log; self.journal = journal; now = authorizationNow
  }
  public func commit(_ prepared: PreparedAdditionalAccessApproval, records: [SignedRecord]) throws -> Receipt {
    guard records.count == prepared.signingBodies.count,
      zip(records, prepared.signingBodies).allSatisfy({ $0.0.body == $0.1 }) else { throw AdditionalAccessError.journalConflict }
    let batch = try AdditionalAccessApprovalBatch(prepared: prepared, records: records)
    let current = try log.state()
    // A saved exact batch is recovered, not re-signed, after an uncertain first attempt.
    if let existing = try journal.matching(prepared.request, selected: prepared.selectedNamespaces) {
      guard existing.batch.baseSequence == prepared.baseSequence, existing.batch.baseDigest == prepared.baseDigest,
        existing.batch.records.map(\.body) == prepared.signingBodies else { throw AdditionalAccessError.journalConflict }
      return try resume(existing.batch)
    }
    guard current.latest == batch.baseSequence, Canonical.digest(current.lastBody) == batch.baseDigest else { throw AdditionalAccessError.authorityChanged }
    _ = try AdditionalAccessApprovalBuilder.current(prepared.request, log: log, state: current, now: now())
    _ = try validate(batch, against: current)
    try Task.checkCancellation()
    let saved = try journal.save(batch)
    return try resume(saved)
  }
  /// Resumes only this exact signed tail. Zero installed records require a still-pending request.
  /// Once the first grant is installed, withdrawal cannot revoke it or change its share tail.
  public func resume(_ batch: AdditionalAccessApprovalBatch) throws -> Receipt {
    _ = try batch.validatedRequest()
    defer { log.invalidateCache() }
    guard let saved = try journal.load(id: batch.id), try Canonical.encode(saved.batch) == Canonical.encode(batch) else { throw AdditionalAccessError.journalConflict }
    let records = try AuthorityIntentRebase.read(store: log.store)
    guard records.count >= batch.baseSequence, batch.baseSequence > 0,
      Canonical.digest(records[batch.baseSequence - 1].body) == batch.baseDigest else { throw AdditionalAccessError.journalConflict }
    let base = try AuthorityState(records: Array(records.prefix(batch.baseSequence)))
    let expected = try validate(batch, against: base)
    let installed = min(batch.records.count, records.count - batch.baseSequence)
    for offset in 0..<installed {
      guard try Canonical.encode(records[batch.baseSequence + offset]) == Canonical.encode(batch.records[offset]) else { throw AdditionalAccessError.journalConflict }
    }
    if saved.confirmed && installed != batch.records.count { throw AdditionalAccessError.journalConflict }
    if installed == 0 {
      guard records.count == batch.baseSequence else { throw AdditionalAccessError.authorityChanged }
      _ = try AdditionalAccessApprovalBuilder.current(batch.validatedRequest(), log: log, state: base, now: now())
    }
    if installed < batch.records.count {
      // Re-read provider authority before issuing any missing share. An installed grant is not
      // a license to complete an expired or replaced approval; immutable creates fence races.
      let freshRecords = try AuthorityIntentRebase.read(store: log.store)
      guard freshRecords.count == batch.baseSequence + installed else { throw AdditionalAccessError.authorityChanged }
      let fresh = try AuthorityState(records: freshRecords)
      let wanted = installed == 0 ? base.members[batch.memberID]?.current : expected.members[batch.memberID]?.current
      guard let member = fresh.members[batch.memberID], member.revokedAt == nil,
        let grant = member.current, grant == wanted,
        grant.expires.map({ now() < $0 }) ?? true else { throw AdditionalAccessError.staleGrant }
    }
    for offset in installed..<batch.records.count {
      try Task.checkCancellation()
      guard expected.members[batch.memberID]?.current?.expires.map({ now() < $0 }) ?? true else {
        throw AdditionalAccessError.staleGrant
      }
      let path = LibraryPath.authority(batch.baseSequence + offset + 1)
      let bytes = try Canonical.encode(batch.records[offset])
      do { try log.store.create(path, bytes) }
      catch ColophonError.alreadyExists {
        guard let actual = try log.store.read(path), actual == bytes else { throw AdditionalAccessError.journalConflict }
      }
    }
    let finished = try AuthorityIntentRebase.read(store: log.store)
    guard finished.count >= batch.baseSequence + batch.records.count else { throw AdditionalAccessError.incompleteApproval }
    for (offset, record) in batch.records.enumerated() {
      guard try Canonical.encode(finished[batch.baseSequence + offset]) == Canonical.encode(record) else { throw AdditionalAccessError.journalConflict }
    }
    let current = try AuthorityState(records: finished)
    let receipt = try verifyComplete(batch, state: current, expected: expected)
    try journal.confirm(batch)
    return receipt
  }
  func retry(_ request: AdditionalAccessRequest.Record, selected: [String]) throws -> Receipt? {
    guard let found = try journal.matching(request, selected: selected) else { return nil }
    return try resume(found.batch)
  }
  private func validate(_ batch: AdditionalAccessApprovalBatch, against state: AuthorityState) throws -> AuthorityState {
    let record = try batch.validatedRequest()
    guard batch.libraryID == state.libraryID, batch.baseSequence == state.latest,
      batch.baseDigest == Canonical.digest(state.lastBody) else { throw AdditionalAccessError.journalConflict }
    // The signed request was eligible at its base grant; expiry is checked against the current clock
    // again before a zero-prefix publication. Recovery never creates a different grant.
    let member = try record.request.validate(in: state, now: .distantPast)
    guard let old = member.current else { throw AdditionalAccessError.staleGrant }
    let desired = old.namespaces + batch.selectedNamespaces
    let first = try AuthorityEntry.decode(batch.records[0].body, at: state.latest + 1)
    guard first.kind == .grant, first.member == member.key, first.label == member.label,
      first.role == member.role, first.custody == member.custody, first.keyOperator == member.keyOperator,
      first.namespaces == desired, first.write == old.write, first.expires == old.expires,
      (first.caveats ?? []) == old.caveats, first.app == member.app, first.device == member.device else { throw AdditionalAccessError.journalConflict }
    var projected = state
    for (offset, signed) in batch.records.enumerated() {
      let entry = try AuthorityEntry.decode(signed.body, at: state.latest + offset + 1)
      guard offset == 0 ? entry.kind == .grant : entry.kind == .shareKey else { throw AdditionalAccessError.journalConflict }
      if offset > 0 {
        guard let namespace = entry.namespace, desired.contains(namespace) else { throw AdditionalAccessError.journalConflict }
      }
      projected = try projected.appending(signed)
    }
    _ = try verifyComplete(batch, state: projected, expected: projected, requireUnexpired: false)
    return projected
  }
  private func verifyComplete(_ batch: AdditionalAccessApprovalBatch, state: AuthorityState, expected: AuthorityState, requireUnexpired: Bool = true) throws -> Receipt {
    guard let member = state.members[batch.memberID], member.revokedAt == nil, let grant = member.current,
      grant.seq == batch.baseSequence + 1, grant == expected.members[batch.memberID]?.current,
      (!requireUnexpired || (grant.expires.map({ now() < $0 }) ?? true)),
      let desired = expected.members[batch.memberID]?.current?.namespaces else { throw AdditionalAccessError.incompleteApproval }
    for namespace in desired {
      let epochs = state.allEpochs(of: namespace)
      guard !epochs.isEmpty, epochs.allSatisfy({ state.keys[namespace]?[$0]?[member.id] != nil }) else { throw AdditionalAccessError.incompleteApproval }
    }
    return .init(libraryID: batch.libraryID, memberID: member.id, requestID: batch.requestID,
      requestBodyDigest: batch.requestBodyDigest, grantSequence: grant.seq, namespaces: grant.namespaces, write: grant.write)
  }
}
