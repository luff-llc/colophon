import ColophonCore
import CryptoKit
import Foundation

/// A fresh snapshot is passed through draft construction without calling check-then-admit helpers.
enum AdditionalAccessApprovalBuilder {
  enum Issuer { case root; case controller(String) }
  static let maximumRecords = 4096
  static func current(_ reviewed: AdditionalAccessRequest.Record, log: AuthorityLog,
    state: AuthorityState, now: Date) throws -> AuthorityState.Member {
    guard let data = try log.store.read(reviewed.path) else { throw AdditionalAccessError.requestChanged }
    let actual = try AdditionalAccessRequest.Record.decode(data, path: reviewed.path)
    guard actual.bodyDigest == reviewed.bodyDigest, actual.request == reviewed.request else { throw AdditionalAccessError.requestChanged }
    return try actual.request.validate(in: state, now: now)
  }
  static func prepare(log: AuthorityLog, state: AuthorityState, request: AdditionalAccessRequest.Record,
    selectedNamespaces: [String], issuer: Issuer, keeper: PublicIdentity, now: Date,
    open: (String, Int) throws -> SymmetricKey) throws -> PreparedAdditionalAccessApproval {
    let member = try current(request, log: log, state: state, now: now)
    guard let old = member.current else { throw AdditionalAccessError.staleGrant }
    let selected = Array(Set(selectedNamespaces)).sorted()
    guard !selected.isEmpty, selected.count == selectedNamespaces.count,
      selected.allSatisfy({ request.request.additionalNamespaces.contains($0) && !old.namespaces.contains($0) }) else {
      throw AdditionalAccessError.invalidSelection
    }
    let desired = old.namespaces + selected
    func draft(_ kind: AuthorityEntry.Kind) -> AuthorityEntry {
      switch issuer {
      case .root: return AuthorityEntry.draft(kind)
      case .controller(let id):
        var entry = AuthorityEntry.draft(kind, by: .controller); entry.signer = id; return entry
      }
    }
    var grant = draft(.grant)
    grant.member = member.key; grant.label = member.label; grant.role = member.role; grant.custody = member.custody
    grant.keyOperator = member.keyOperator; grant.namespaces = desired; grant.write = old.write
    grant.expires = old.expires; grant.caveats = old.caveats
    grant.app = member.app; grant.device = member.device
    var drafts = [grant]
    func share(_ key: SymmetricKey, namespace: String, epoch: Int, to recipient: PublicIdentity) throws -> AuthorityEntry {
      var entry = draft(.shareKey); entry.namespace = namespace; entry.epoch = epoch
      entry.memberID = recipient.id; entry.key = try SealedKey(key, to: recipient); return entry
    }
    for namespace in desired {
      guard !state.needsRevocationRotation(in: namespace), !state.needsVaultRotationCompletion(in: namespace) else {
        throw AdditionalAccessError.authorityChanged
      }
      let epochs = state.allEpochs(of: namespace)
      if epochs.isEmpty {
        let key = SymmetricKey(size: .bits256)
        var recipients: [String: PublicIdentity] = [keeper.id: keeper, member.id: member.key]
        if case .root = issuer {
          for key in [state.root, state.recovery] + state.stewards { recipients[key.id] = key }
        }
        // Existing explicitly granted readers may also be waiting for this missing first epoch.
        for reader in state.activeMembers {
          if let grant = reader.current, grant.namespaces.contains(namespace), grant.expires.map({ now < $0 }) ?? true {
            recipients[reader.id] = reader.key
          }
        }
        let ordered = [keeper] + recipients.values.filter { $0.id != keeper.id }.sorted { $0.id < $1.id }
        for recipient in ordered {
          guard drafts.count < maximumRecords else { throw AdditionalAccessError.exceedsLimits }
          drafts.append(try share(key, namespace: namespace, epoch: 1, to: recipient))
        }
      } else {
        for epoch in epochs where state.keys[namespace]?[epoch]?[member.id] == nil {
          guard drafts.count < maximumRecords else { throw AdditionalAccessError.exceedsLimits }
          drafts.append(try share(open(namespace, epoch), namespace: namespace, epoch: epoch, to: member.key))
        }
      }
      guard drafts.count <= maximumRecords else { throw AdditionalAccessError.exceedsLimits }
    }
    var previous = state.lastBody, sequence = state.latest
    let bodies = try drafts.map { draft -> Data in
      sequence += 1
      let bytes = try Canonical.encode(draft.numbered(sequence, after: previous))
      guard bytes.count <= AdditionalAccessRequest.maximumBodyBytes else { throw AdditionalAccessError.exceedsLimits }
      previous = bytes; return bytes
    }
    return .init(request: request, selectedNamespaces: selected, desiredNamespaces: desired,
      baseSequence: state.latest, baseDigest: Canonical.digest(state.lastBody), signingBodies: bodies, drafts: drafts)
  }
}
