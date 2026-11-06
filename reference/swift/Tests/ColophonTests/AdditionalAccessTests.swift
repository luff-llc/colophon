@testable import ColophonAuthority
import ColophonCore
import ColophonReplica
import ColophonStore
import Foundation
import Testing

struct AdditionalAccessTests {
  private struct Fixture: Sendable {
    let store = AdditionalAccessTestStore()
    let root = SoftwareIdentity(), member = SoftwareIdentity()
    let holder: AuthorityHolder
    let requests: AdditionalAccessRequestService
    let journal: AdditionalAccessApprovalJournal
    let directory: URL
    init() throws {
      holder = try AuthorityHolder.create(in: store, label: "Additional scopes", root: root,
        firstMember: member.publicIdentity, memberLabel: "Existing app", role: .app, custody: .software,
        namespaces: ["reading.saved"]).0
      requests = .init(log: holder.log, identity: member)
      directory = FileManager.default.temporaryDirectory.appendingPathComponent("additional-access-" + UUID().uuidString)
      journal = .init(directory: directory)
    }
    func cleanup() { try? FileManager.default.removeItem(at: directory) }
    func signed(_ plan: PreparedAdditionalAccessApproval) throws -> [SignedRecord] {
      try plan.signingBodies.map { try SignedRecord(signing: $0, with: root) }
    }
    func request(_ id: UUID = UUID(), scopes: [String] = ["source.native"]) throws -> AdditionalAccessRequest.Record {
      try requests.request(additionalNamespaces: scopes, requestID: id)
    }
  }

  @Test func requestIsSeparateSignedIdempotentAndWithdrawnWithoutRevocation() throws {
    let f = try Fixture(); defer { f.cleanup() }
    let id = UUID(), first = try f.request(id)
    let before = f.store.memory.snapshot
    let repeated = try f.request(id)
    let after = f.store.memory.snapshot
    #expect(first.bodyDigest == repeated.bodyDigest)
    #expect(before == after)
    #expect(throws: DecodingError.self) { try Canonical.decode(EnrollmentRequest.self, from: first.signed.body) }
    let oldScan = try f.holder.pendingRequestScan()
    #expect(oldScan.requests.isEmpty)
    let pending = AdditionalAccessRequestScan.read(store: f.store, authority: try f.holder.state())
    #expect(pending.pending.count == 1)
    let withdrawn = try f.requests.withdraw(requestID: id)
    let withdrawal = AdditionalAccessRequestScan.read(store: f.store, authority: try f.holder.state())
    #expect(withdrawn.request.status == .withdrawn)
    #expect(withdrawal.pending.isEmpty)
    #expect(withdrawal.withdrawn.count == 1)
    #expect(throws: AdditionalAccessError.withdrawn) { try f.request(id) }
    let state = try f.holder.state()
    let member = try #require(state.members[f.member.id])
    #expect(member.revokedAt == nil)
    let again = try f.requests.withdraw(requestID: id)
    #expect(again.bodyDigest == withdrawn.bodyDigest)
  }

  @Test func scanChecksSignaturePathLibraryExpiryAndCurrentGrant() throws {
    let f = try Fixture(); defer { f.cleanup() }
    let request = try f.request()
    let other = SoftwareIdentity()
    let wrongPath = AdditionalAccessRequest.path(memberID: other.id)
    try f.store.replace(wrongPath, Canonical.encode(request.signed))
    let scan = AdditionalAccessRequestScan.read(store: f.store, authority: try f.holder.state())
    #expect(scan.pending.count == 1)
    #expect(scan.invalidCount == 1)
    let forged = try SignedRecord(signing: request.signed.body, with: other)
    try f.store.replace(request.path, Canonical.encode(forged))
    let forgedScan = AdditionalAccessRequestScan.read(store: f.store, authority: try f.holder.state())
    #expect(forgedScan.pending.isEmpty)
    let wrongLibrary = AdditionalAccessRequest(libraryID: "another-library", member: f.member.publicIdentity,
      expectedGrantSequence: request.request.expectedGrantSequence, requestID: UUID(),
      additionalNamespaces: ["source.native"], status: .pending)
    let wrongLibraryRecord = try SignedRecord(signing: Canonical.encode(wrongLibrary), with: f.member)
    try f.store.replace(request.path, Canonical.encode(wrongLibraryRecord))
    let wrongLibraryScan = AdditionalAccessRequestScan.read(store: f.store, authority: try f.holder.state())
    #expect(wrongLibraryScan.pending.isEmpty)
    let substitutedKey = PublicIdentity(signing: f.member.publicIdentity.signing, agreement: other.publicIdentity.agreement)
    let wrongAgreement = AdditionalAccessRequest(libraryID: request.request.libraryID, member: substitutedKey,
      expectedGrantSequence: request.request.expectedGrantSequence, requestID: UUID(),
      additionalNamespaces: ["source.native"], status: .pending)
    let wrongAgreementRecord = try SignedRecord(signing: Canonical.encode(wrongAgreement), with: f.member)
    try f.store.replace(request.path, Canonical.encode(wrongAgreementRecord))
    let wrongAgreementScan = AdditionalAccessRequestScan.read(store: f.store, authority: try f.holder.state())
    #expect(wrongAgreementScan.pending.isEmpty)
    try f.store.replace(request.path, Canonical.encode(request.signed))
    try f.holder.admit(f.member.publicIdentity, label: "Existing app", role: .app, custody: .software,
      namespaces: ["reading.saved"], write: true)
    let stale = AdditionalAccessRequestScan.read(store: f.store, authority: try f.holder.state())
    #expect(stale.pending.isEmpty)
    #expect(throws: AdditionalAccessError.staleGrant) {
      try f.holder.prepareAdditionalAccess(request, selectedNamespaces: ["source.native"])
    }
    try f.holder.revoke(f.member.id)
    #expect(throws: AdditionalAccessError.staleGrant) { try f.request() }
  }

  @Test func approvalAddsOnlySelectedScopesAndPreservesReadOnlyGrantAttributes() throws {
    let f = try Fixture(); defer { f.cleanup() }
    let expiry = Date(timeIntervalSince1970: 2_000_000_000)
    let caveats = [Caveat(kind: "kinds", kinds: ["capture.link"])]
    try f.holder.admit(f.member.publicIdentity, label: "Retained label", role: .app, custody: .custodial,
      namespaces: ["reading.saved"], write: false, expires: expiry, caveats: caveats,
      keyOperator: "operator.example", app: "org.luff.later", device: "Synthetic device")
    let originalState = try f.holder.state()
    let old = try #require(originalState.members[f.member.id])
    let request = try f.request(scopes: ["source.native", "notes"])
    #expect(throws: AdditionalAccessError.invalidSelection) {
      try f.holder.prepareAdditionalAccess(request, selectedNamespaces: ["unrequested"])
    }
    let receipt = try f.holder.approveAdditionalAccess(request, selectedNamespaces: ["source.native"], journal: f.journal)
    let state = try f.holder.state(), member = try #require(state.members[f.member.id])
    let grant = try #require(member.current)
    let expectedNamespaces = ["reading.saved", "source.native"]
    #expect(grant.namespaces == expectedNamespaces)
    #expect(receipt.write == false)
    #expect(grant.write == old.current?.write)
    #expect(grant.expires == old.current?.expires)
    #expect(grant.caveats == old.current?.caveats)
    #expect(member.label == old.label)
    #expect(member.role == old.role)
    #expect(member.custody == old.custody)
    #expect(member.keyOperator == old.keyOperator)
    #expect(member.app == old.app)
    #expect(member.device == old.device)
    let hasSourceKey = state.keys["source.native"]?[1]?[f.member.id] != nil
    #expect(hasSourceKey)
    #expect(state.allEpochs(of: "notes").isEmpty)
    let currentHead = state.latest
    let retry = try f.holder.approveAdditionalAccess(request, selectedNamespaces: ["source.native"], journal: f.journal)
    #expect(retry.grantSequence == receipt.grantSequence)
    let retriedState = try f.holder.state()
    #expect(retriedState.latest == currentHead)
  }

  @Test func requestReplacementAndCompetingAuthorityInvalidatePreparedApproval() throws {
    let f = try Fixture(); defer { f.cleanup() }
    let first = try f.request()
    _ = try f.request(scopes: ["notes"])
    let before = f.store.memory.snapshot
    #expect(throws: AdditionalAccessError.requestChanged) {
      try f.holder.approveAdditionalAccess(first, selectedNamespaces: ["source.native"], journal: f.journal)
    }
    let after = f.store.memory.snapshot
    #expect(before == after)
    let current = try f.request()
    let plan = try f.holder.prepareAdditionalAccess(current, selectedNamespaces: ["source.native"])
    let records = try f.signed(plan)
    try f.holder.addNamespace("unrelated")
    let service = AdditionalAccessApprovalService(log: f.holder.log, journal: f.journal)
    #expect(throws: AdditionalAccessError.authorityChanged) { try service.commit(plan, records: records) }
    let state = try f.holder.state()
    let granted = state.members[f.member.id]?.namespaces.contains("source.native") ?? false
    #expect(granted == false)
  }

  @Test func zeroPrefixJournalCannotPublishAfterWithdrawal() throws {
    let f = try Fixture(); defer { f.cleanup() }
    let request = try f.request()
    f.store.failAfterAuthorityCreates(0)
    #expect(throws: AdditionalAccessTestStore.Injected.self) {
      try f.holder.approveAdditionalAccess(request, selectedNamespaces: ["source.native"], journal: f.journal)
    }
    let pending = try f.journal.pending(libraryID: request.request.libraryID)
    let batch = try #require(pending.first)
    _ = try f.requests.withdraw(requestID: request.request.requestID)
    let before = f.store.memory.snapshot
    let service = AdditionalAccessApprovalService(log: f.holder.log, journal: f.journal)
    #expect(throws: AdditionalAccessError.requestChanged) { try service.resume(batch) }
    let after = f.store.memory.snapshot
    #expect(before == after)
  }

  @Test func installedGrantRecoversOnlyExactSignedMissingEpochTailEvenAfterWithdrawal() throws {
    let f = try Fixture(); defer { f.cleanup() }
    let request = try f.request()
    f.store.failAfterAuthorityCreates(1) // Grant is installed; no new-namespace epoch share exists yet.
    #expect(throws: AdditionalAccessTestStore.Injected.self) {
      try f.holder.approveAdditionalAccess(request, selectedNamespaces: ["source.native"], journal: f.journal)
    }
    let partial = try f.holder.state()
    #expect(partial.members[f.member.id]?.namespaces.contains("source.native") == true)
    #expect(partial.allEpochs(of: "source.native").isEmpty)
    let pending = try f.journal.pending(libraryID: request.request.libraryID)
    let batch = try #require(pending.first)
    let withdrawn = AdditionalAccessRequest(libraryID: request.request.libraryID, member: f.member.publicIdentity,
      expectedGrantSequence: request.request.expectedGrantSequence, requestID: request.request.requestID,
      additionalNamespaces: request.request.additionalNamespaces, status: .withdrawn)
    let signedWithdrawal = try SignedRecord(signing: Canonical.encode(withdrawn), with: f.member)
    try f.store.replace(request.path, Canonical.encode(signedWithdrawal))
    let service = AdditionalAccessApprovalService(log: f.holder.log, journal: f.journal)
    let receipt = try service.resume(batch)
    #expect(receipt.grantSequence == batch.baseSequence + 1)
    let final = try f.holder.state()
    let keys = final.keys["source.native"]?[1]?[f.member.id] != nil
    #expect(keys)
    let remaining = try f.journal.pending(libraryID: request.request.libraryID)
    #expect(remaining.isEmpty)
    let installed = try AuthorityIntentRebase.read(store: f.store)
    for (offset, exact) in batch.records.enumerated() {
      let actual = try Canonical.encode(installed[batch.baseSequence + offset])
      let expected = try Canonical.encode(exact)
      #expect(actual == expected)
    }
  }

  @Test func expiredPartialApprovalCannotPublishMissingSharesOrReturnAReceipt() throws {
    let f = try Fixture(); defer { f.cleanup() }
    let expiry = Date(timeIntervalSince1970: 2_000_000_000)
    let beforeExpiry = expiry.addingTimeInterval(-60)
    try f.holder.admit(f.member.publicIdentity, label: "App", role: .app, custody: .software,
      namespaces: ["reading.saved"], write: true, expires: expiry)
    let request = try f.request()
    let plan = try f.holder.prepareAdditionalAccess(request, selectedNamespaces: ["source.native"],
      authorizationNow: { beforeExpiry })
    let records = try f.signed(plan)
    let initial = AdditionalAccessApprovalService(log: f.holder.log, journal: f.journal,
      authorizationNow: { beforeExpiry })
    f.store.failAfterAuthorityCreates(1)
    #expect(throws: AdditionalAccessTestStore.Injected.self) { try initial.commit(plan, records: records) }
    let pending = try f.journal.pending(libraryID: request.request.libraryID)
    let batch = try #require(pending.first)
    let partial = try f.holder.state()
    #expect(partial.allEpochs(of: "source.native").isEmpty)
    let before = f.store.memory.snapshot
    let expired = AdditionalAccessApprovalService(log: f.holder.log, journal: f.journal,
      authorizationNow: { expiry.addingTimeInterval(1) })
    #expect(throws: AdditionalAccessError.staleGrant) { try expired.resume(batch) }
    let after = f.store.memory.snapshot
    #expect(before == after)
    // Completion before expiry does not make a later receipt claim that the grant is usable.
    _ = try initial.resume(batch)
    let complete = f.store.memory.snapshot
    #expect(throws: AdditionalAccessError.incompleteApproval) { try expired.resume(batch) }
    let unchanged = f.store.memory.snapshot
    #expect(complete == unchanged)
  }

  @Test func repeatedCosignatureMetadataIsBudgetedBeforeCanonicalEncoding() throws {
    // Array repetitions share tiny Data/String storage. The prospective wire encoding would
    // exceed the batch limit even though body/signature bytes alone are almost empty.
    let signer = String(repeating: "\u{0001}", count: 1024)
    let signature = SignedRecord.Cosignature(signer: signer, signature: Data())
    var record = SignedRecord(body: Data(), signature: Data())
    record.cosignatures = Array(repeating: signature, count: 64)
    let repeated = Array(repeating: record, count: 64)
    #expect(throws: AdditionalAccessError.exceedsLimits) {
      try AdditionalAccessApprovalBatch.validateBoundedRecords(repeated)
    }
  }

  @Test func expiredGrantAndOversizedRecordsRejectWithoutApprovalWrites() throws {
    let f = try Fixture(); defer { f.cleanup() }
    let expiry = Date(timeIntervalSince1970: 2_000_000_000)
    try f.holder.admit(f.member.publicIdentity, label: "App", role: .app, custody: .software,
      namespaces: ["reading.saved"], write: true, expires: expiry)
    let request = try f.request()
    let scan = AdditionalAccessRequestScan.read(store: f.store, authority: try f.holder.state(), now: expiry)
    #expect(scan.pending.isEmpty)
    #expect(throws: AdditionalAccessError.staleGrant) {
      try f.holder.prepareAdditionalAccess(request, selectedNamespaces: ["source.native"], authorizationNow: { expiry })
    }
    let oversized = Data(repeating: 0, count: AdditionalAccessRequest.maximumRecordBytes + 1)
    #expect(throws: AdditionalAccessError.exceedsLimits) {
      try AdditionalAccessRequest.Record.decode(oversized, path: request.path)
    }
  }

  @Test func keyringApprovalUsesSameScopedGrantContractAndPreservesGlobalCaveat() throws {
    let f = try Fixture(); defer { f.cleanup() }
    let global = Caveat(kind: "kinds", kinds: ["capture.link"])
    try f.holder.admit(f.member.publicIdentity, label: "App", role: .app, custody: .software,
      namespaces: ["reading.saved"], write: true, caveats: [global])
    let owner = Controller(kind: "p256", key: f.root.publicIdentity.signing, rpID: nil, credential: nil,
      label: "Owner", roles: ["approve", "control"], verification: nil)
    let vault = try f.holder.upgrade(to: [owner], threshold: 1) { vault in
      [try VaultSlot.sealed(seed: vault.seed, to: f.root.publicIdentity, controller: owner.id, label: owner.label)]
    }
    let signer = try P256ControllerSigner(identity: f.root, controller: owner)
    let holder = try KeyringHolder(log: f.holder.log, signer: signer, vault: vault)
    let request = try f.request()
    let receipt = try holder.approveAdditionalAccess(request, selectedNamespaces: ["source.native"], journal: f.journal)
    let state = try holder.state(), grant = try #require(state.members[f.member.id]?.current)
    let expected = [global]
    #expect(grant.caveats == expected)
    #expect(receipt.write)
    let replica = Replica(store: f.store, identity: f.member)
    // Generic Replica can store an attempted command; admission must still reject the forbidden kind.
    let attempted = try replica.perform(.init(namespace: "source.native", kind: "nativeSource.preserve", payload: [:]))
    let supplied = try replica.readComplete("source.native")
    let view = try #require(supplied)
    #expect(view.admitted.contains { $0.id == attempted.id } == false)
    #expect(view.rejected.contains { $0.path.contains(attempted.id) })
  }
}
