import ColophonCore
import ColophonStore
import Foundation

/// A current-provider signed request slot. No namespace keys, grant changes or deletes are written.
/// Local serialization is not cross-device compare-and-swap; withdrawal is not revocation.
public struct AdditionalAccessRequestService: Sendable {
  public let log: AuthorityLog
  public let identity: any Identity
  private let now: @Sendable () -> Date
  private static let localWrites = NSLock()
  public init(log: AuthorityLog, identity: any Identity, authorizationNow: @escaping @Sendable () -> Date = { .now }) {
    self.log = log; self.identity = identity; now = authorizationNow
  }
  public func request(additionalNamespaces: [String], requestID: UUID = UUID()) throws -> AdditionalAccessRequest.Record {
    try Self.localWrites.withLock {
      try Task.checkCancellation()
      let state = try log.state()
      guard let member = state.members[identity.publicIdentity.id], member.key == identity.publicIdentity,
        member.revokedAt == nil, let grant = member.current, grant.expires.map({ now() < $0 }) ?? true else { throw AdditionalAccessError.staleGrant }
      let request = AdditionalAccessRequest(libraryID: state.libraryID, member: member.key, expectedGrantSequence: grant.seq,
        requestID: requestID, additionalNamespaces: Array(Set(additionalNamespaces)).sorted(), status: .pending)
      _ = try request.validate(in: state, now: now())
      if let old = try currentRecord(), old.request.requestID == requestID {
        guard old.request.status == .pending else { throw AdditionalAccessError.withdrawn }
        guard old.request == request else { throw AdditionalAccessError.conflictingRequest }
        return old
      }
      return try write(request, expectedState: state)
    }
  }
  @discardableResult public func withdraw(requestID: UUID) throws -> AdditionalAccessRequest.Record {
    try Self.localWrites.withLock {
      let state = try log.state()
      guard let old = try currentRecord(), old.request.requestID == requestID else { throw AdditionalAccessError.requestChanged }
      _ = try old.request.validate(in: state, now: now(), pending: false)
      if old.request.status == .withdrawn { return old }
      let request = AdditionalAccessRequest(libraryID: old.request.libraryID, member: old.request.member,
        expectedGrantSequence: old.request.expectedGrantSequence, requestID: requestID,
        additionalNamespaces: old.request.additionalNamespaces, status: .withdrawn)
      return try write(request, expectedState: state)
    }
  }
  public func currentRecord() throws -> AdditionalAccessRequest.Record? {
    let path = AdditionalAccessRequest.path(memberID: identity.publicIdentity.id)
    guard let bytes = try log.store.read(path) else { return nil }
    return try AdditionalAccessRequest.Record.decode(bytes, path: path)
  }
  private func write(_ request: AdditionalAccessRequest, expectedState: AuthorityState) throws -> AdditionalAccessRequest.Record {
    let current = try log.state()
    guard current.libraryID == expectedState.libraryID,
      current.members[request.member.id]?.current == expectedState.members[request.member.id]?.current else { throw AdditionalAccessError.staleGrant }
    _ = try request.validate(in: current, now: now(), pending: false)
    let record = try SignedRecord(signing: Canonical.encode(request), with: identity)
    let data = try Canonical.encode(record)
    guard data.count <= AdditionalAccessRequest.maximumRecordBytes else { throw AdditionalAccessError.exceedsLimits }
    let afterSigning = try log.state()
    _ = try request.validate(in: afterSigning, now: now(), pending: false)
    try Task.checkCancellation()
    let path = AdditionalAccessRequest.path(memberID: request.member.id)
    try log.store.replace(path, data)
    return try AdditionalAccessRequest.Record.decode(data, path: path)
  }
}
