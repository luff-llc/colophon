import ColophonCore
import CryptoKit
import Foundation

public extension KeyringHolder {
  /// The immutable bodies can also be signed asynchronously by a passkey and passed to commit below.
  func prepareAdditionalAccess(_ request: AdditionalAccessRequest.Record, selectedNamespaces: [String],
    openedEpochs: [String: [Int: SymmetricKey]] = [:],
    authorizationNow: @Sendable () -> Date = { .now }) throws -> PreparedAdditionalAccessApproval {
    let state = try log.state()
    guard let ring = state.keyring, let controller = ring.controllers[signer.controller.id],
      controller.key == signer.controller.key, controller.roles.contains("approve") else { throw ColophonError.notTheRoot }
    return try AdditionalAccessApprovalBuilder.prepare(log: log, state: state, request: request,
      selectedNamespaces: selectedNamespaces, issuer: .controller(controller.id), keeper: ring.vault, now: authorizationNow()) { namespace, epoch in
      if let key = openedEpochs[namespace]?[epoch] { return key }
      guard let vault, let sealed = state.keys[namespace]?[epoch]?[ring.vault.id] else { throw ColophonError.vaultLocked }
      let identity = try vault.identity()
      guard identity.publicIdentity == ring.vault else { throw ColophonError.vaultLocked }
      return try identity.open(sealed)
    }
  }
  @discardableResult func approveAdditionalAccess(_ request: AdditionalAccessRequest.Record, selectedNamespaces: [String],
    journal: AdditionalAccessApprovalJournal, openedEpochs: [String: [Int: SymmetricKey]] = [:],
    authorizationNow: @escaping @Sendable () -> Date = { .now }) throws -> AdditionalAccessApprovalService.Receipt {
    let service = AdditionalAccessApprovalService(log: log, journal: journal, authorizationNow: authorizationNow)
    if let old = try service.retry(request, selected: selectedNamespaces) { return old }
    let prepared = try prepareAdditionalAccess(request, selectedNamespaces: selectedNamespaces,
      openedEpochs: openedEpochs, authorizationNow: authorizationNow)
    let records = try prepared.signingBodies.map { body -> SignedRecord in
      let signed = try signer.sign(body)
      return SignedRecord(body: body, signature: signed.signature, assertion: signed.assertion)
    }
    return try service.commit(prepared, records: records)
  }
  @discardableResult func commitAdditionalAccess(_ prepared: PreparedAdditionalAccessApproval, records: [SignedRecord],
    journal: AdditionalAccessApprovalJournal, authorizationNow: @escaping @Sendable () -> Date = { .now }) throws -> AdditionalAccessApprovalService.Receipt {
    try AdditionalAccessApprovalService(log: log, journal: journal, authorizationNow: authorizationNow).commit(prepared, records: records)
  }
}
