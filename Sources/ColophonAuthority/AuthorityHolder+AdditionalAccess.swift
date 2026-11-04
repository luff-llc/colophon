import ColophonCore
import CryptoKit
import Foundation

public extension AuthorityHolder {
  func prepareAdditionalAccess(_ request: AdditionalAccessRequest.Record, selectedNamespaces: [String],
    authorizationNow: @Sendable () -> Date = { .now }) throws -> PreparedAdditionalAccessApproval {
    let state = try log.state()
    guard !state.isKeyring, state.root == root.publicIdentity else { throw ColophonError.notTheRoot }
    return try AdditionalAccessApprovalBuilder.prepare(log: log, state: state, request: request,
      selectedNamespaces: selectedNamespaces, issuer: .root, keeper: state.root, now: authorizationNow()) { namespace, epoch in
      guard let sealed = state.keys[namespace]?[epoch]?[root.publicIdentity.id] else { throw ColophonError.noAccess(namespace) }
      return try root.open(sealed)
    }
  }
  @discardableResult func approveAdditionalAccess(_ request: AdditionalAccessRequest.Record, selectedNamespaces: [String],
    journal: AdditionalAccessApprovalJournal, authorizationNow: @escaping @Sendable () -> Date = { .now }) throws -> AdditionalAccessApprovalService.Receipt {
    let service = AdditionalAccessApprovalService(log: log, journal: journal, authorizationNow: authorizationNow)
    if let old = try service.retry(request, selected: selectedNamespaces) { return old }
    let prepared = try prepareAdditionalAccess(request, selectedNamespaces: selectedNamespaces, authorizationNow: authorizationNow)
    let records = try prepared.signingBodies.map { try SignedRecord(signing: $0, with: root) }
    return try service.commit(prepared, records: records)
  }
}
