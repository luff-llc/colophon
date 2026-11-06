import ColophonAuthority
import ColophonCore
import ColophonReplica
import Foundation

/// An additive, provisional facade over Colophon's real signed `listening.podcasts` log.
/// It writes no parallel ledger. A caller ID is scoped to one authenticated member and
/// repeated commands are collapsed when the admitted log is projected. Offline merges can
/// change a conditional outcome; this is not distributed CAS or exactly-once external work.
public struct SharedTranscriptService {
  public static let proposeKind = "context.propose"
  public static let acceptKind = "context.accept"

  public let replica: Replica
  public init(replica: Replica) { self.replica = replica }

  /// Every admitted immutable version, including a version no longer selected by Taupe.
  public func references() throws -> [SharedTranscriptReference] {
    try requireCurrentRead()
    let libraryID = try replica.authority().libraryID
    return try admittedOperations().compactMap { entry in
      let op = entry.operation
      guard op.kind == Podcasts.ContentKind.transcript,
        let episode = op.payload["episode"]?.string, let show = op.payload["show"]?.string,
        let blob = BlobRef(json: op.payload["blob"])
      else { return nil }
      return SharedTranscriptReference(libraryID: libraryID, episode: episode, show: show,
        revision: op.id, blob: blob)
    }
  }

  /// The selected transcript's immutable revision, found from its signed operation and blob.
  public func reference(episode: String) throws -> SharedTranscriptReference? {
    try requireCurrentRead()
    guard let selected = try replica.state(of: Podcasts.self).transcripts[episode] else { return nil }
    let candidates = try admittedOperations().filter { entry in
      let op = entry.operation
      return op.kind == Podcasts.ContentKind.transcript && op.payload["episode"]?.string == episode
        && op.payload["source"]?.string == selected.source
        && op.payload["language"]?.string == selected.language
        && BlobRef(json: op.payload["blob"]) == selected.blob
        && (op.payload["timed"]?.bool ?? false) == selected.timed
    }
    guard let op = candidates.last?.operation, let show = op.payload["show"]?.string else { return nil }
    return SharedTranscriptReference(libraryID: try replica.authority().libraryID, episode: episode,
      show: show, revision: op.id, blob: selected.blob)
  }

  /// Resolves exact quoted text against the pinned blob, even after another version wins.
  /// There is no recording-digest or timed-word claim in this first contract.
  public func resolve(_ reference: SharedTranscriptReference,
    citation: SharedTranscriptCitation? = nil) throws -> TranscriptDocument
  {
    try requireCurrentRead()
    guard reference.libraryID == (try replica.authority().libraryID) else { throw SharedTranscriptError.wrongLibrary }
    let operations = try admittedOperations()
    guard Self.transcriptReferences(in: operations, libraryID: reference.libraryID).contains(reference) else {
      throw SharedTranscriptError.missingTranscript
    }
    let document = try transcriptDocument(reference)
    if let citation {
      guard !citation.quote.isEmpty, document.text.contains(citation.quote) else {
        throw SharedTranscriptError.wrongCitation
      }
    }
    return document
  }

  /// Native Taupe/Later projection from the same admitted records. `revision` on a contribution
  /// is the proposal operation ID; acceptance has its own authenticated signer and revision.
  public func state(for reference: SharedTranscriptReference) throws -> SharedTranscriptState {
    _ = try resolve(reference)
    let folded = try fold()
    let contributions = folded.contributions.values.filter { $0.reference == reference }
      .map(\.value).sorted { ($0.proposalRevision, $0.id) < ($1.proposalRevision, $1.id) }
    let receipts = folded.receipts.values.filter { $0.reference == reference }
      .map(\.value).sorted { $0.operationID < $1.operationID }
    var currentRevisionByContributionID: [String: String] = [:]
    for contribution in contributions {
      currentRevisionByContributionID[contribution.id] =
        folded.heads[Self.key(reference.revision, contribution.id)]
    }
    let source = folded.sources[reference]
    return SharedTranscriptState(contributions: contributions, receipts: receipts,
      currentRevisionByContributionID: currentRevisionByContributionID,
      heldContextCount: folded.heldContextCounts[reference] ?? 0,
      transcriptAuthor: source?.id, transcriptAuthorLabel: source?.label)
  }

  /// An enrolled agent authors a suggestion; no payload claim can turn it into user words.
  @discardableResult public func propose(reference: SharedTranscriptReference, citation: SharedTranscriptCitation,
    text: String, contributionID: String, commandID: String, expectedRevision: String? = nil)
    throws -> SharedTranscriptReceipt
  {
    try requireCurrentWriter(kind: Self.proposeKind, role: .agent)
    guard !text.isEmpty, !contributionID.isEmpty, !commandID.isEmpty else { throw SharedTranscriptError.invalidCommand }
    _ = try resolve(reference, citation: citation)
    let body = body(reference: reference, contributionID: contributionID, expectedRevision: expectedRevision,
      fields: ["citation": .string(citation.quote), "text": .string(text)])
    return try submit(kind: Self.proposeKind, body: body, commandID: commandID)
  }

  /// A separately signed app/device command records explicit acceptance. The key establishes
  /// which enrolled device/app acted, not user presence or biometric consent.
  @discardableResult public func accept(reference: SharedTranscriptReference, contributionID: String,
    proposalRevision: String, commandID: String, expectedRevision: String?, note: String? = nil)
    throws -> SharedTranscriptReceipt
  {
    try requireCurrentWriter(kind: Self.acceptKind, role: .app)
    guard !contributionID.isEmpty, !proposalRevision.isEmpty, !commandID.isEmpty else {
      throw SharedTranscriptError.invalidCommand
    }
    _ = try resolve(reference)
    let body = body(reference: reference, contributionID: contributionID, expectedRevision: expectedRevision,
      fields: ["proposalRevision": .string(proposalRevision), "note": JSONValue(note)])
    return try submit(kind: Self.acceptKind, body: body, commandID: commandID)
  }

  private func submit(kind: String, body: [String: JSONValue], commandID: String) throws -> SharedTranscriptReceipt {
    let digest = Canonical.digest(try Canonical.encode(body))
    let key = Self.key(replica.identity.id, commandID)
    let prior = try fold().receipts[key]
    if let prior {
      guard prior.digest == digest, prior.kind == kind else { throw SharedTranscriptError.commandIDConflict }
      return prior.value
    }
    var payload = body
    payload["commandID"] = .string(commandID)
    payload["commandDigest"] = .string(digest)
    let op = try replica.perform(Command(namespace: Podcasts.namespace, kind: kind, payload: payload))
    guard let receipt = try fold().receipts[key]?.value, receipt.operationID == op.id else {
      // `perform` can write a record that admission holds or refuses under a caveat.
      throw SharedTranscriptError.invalidCommand
    }
    return receipt
  }

  private struct Projected<Value> { let reference: SharedTranscriptReference; let value: Value }
  private struct SourceAuthor { let id: String; let label: String }
  private struct SavedReceipt {
    let reference: SharedTranscriptReference
    let kind: String
    let digest: String
    let value: SharedTranscriptReceipt
  }
  private struct Fold {
    var contributions: [String: Projected<SharedTranscriptContribution>] = [:]
    var receipts: [String: SavedReceipt] = [:]
    var heads: [String: String] = [:]
    var proposers: [String: String] = [:]
    var heldContextCounts: [SharedTranscriptReference: Int] = [:]
    var sources: [SharedTranscriptReference: SourceAuthor] = [:]
  }

  private enum FoldDocument {
    case available(TranscriptDocument)
    case pending
    case invalid
  }

  private static func transcriptReferences(in operations: [AdmittedOperation], libraryID: String)
    -> Set<SharedTranscriptReference>
  {
    Set(operations.compactMap { entry in
      let op = entry.operation
      guard op.kind == Podcasts.ContentKind.transcript,
        let episode = op.payload["episode"]?.string, let show = op.payload["show"]?.string,
        let blob = BlobRef(json: op.payload["blob"])
      else { return nil }
      return SharedTranscriptReference(libraryID: libraryID, episode: episode, show: show,
        revision: op.id, blob: blob)
    })
  }

  private func transcriptDocument(_ reference: SharedTranscriptReference) throws -> TranscriptDocument {
    guard let bytes = try replica.blob(reference.blob, in: Podcasts.namespace) else {
      throw SharedTranscriptError.missingTranscript
    }
    return try Canonical.decode(TranscriptDocument.self, from: bytes)
  }

  /// Revision IDs are used as immutable source and proposal identities throughout this
  /// facade. Replica admits signed operations independently, so enforce uniqueness here
  /// before a duplicate ID can make either identity ambiguous.
  private func admittedOperations() throws -> [AdmittedOperation] {
    try admittedOperations(in: replica.read(Podcasts.namespace))
  }

  private func admittedOperations(in view: ReplicaView) throws -> [AdmittedOperation] {
    let operations = view.admitted
    var seen: Set<String> = []
    for entry in operations {
      guard seen.insert(entry.operation.id).inserted else {
        throw SharedTranscriptError.duplicateOperationID(entry.operation.id)
      }
    }
    return operations
  }

  /// Deterministic local fold. A newly received earlier operation can change a previous
  /// conditional result; clients must re-read after synchronization.
  private func fold() throws -> Fold {
    try requireCurrentRead()
    let authority = try replica.authority()
    var result = Fold()
    let view = try replica.read(Podcasts.namespace)
    let operations = try admittedOperations(in: view)
    let transcriptReferences = Self.transcriptReferences(in: operations, libraryID: authority.libraryID)
    var documents: [SharedTranscriptReference: FoldDocument] = [:]
    var pendingContributionKeys: Set<String> = []
    var pendingCommandKeys: Set<String> = []
    for entry in operations where entry.operation.kind == Podcasts.ContentKind.transcript {
      let op = entry.operation
      guard let episode = op.payload["episode"]?.string, let show = op.payload["show"]?.string,
        let blob = BlobRef(json: op.payload["blob"])
      else { continue }
      let reference = SharedTranscriptReference(libraryID: authority.libraryID, episode: episode,
        show: show, revision: op.id, blob: blob)
      result.sources[reference] = SourceAuthor(id: entry.author, label: entry.authorLabel)
    }
    for entry in view.held where entry.operation.kind == Self.proposeKind || entry.operation.kind == Self.acceptKind {
      guard let reference = Self.reference(from: entry.operation.payload), reference.libraryID == authority.libraryID else {
        continue
      }
      result.heldContextCounts[reference, default: 0] += 1
    }
    for entry in operations {
      let op = entry.operation
      guard (op.kind == Self.proposeKind || op.kind == Self.acceptKind), op.v == 1,
        let commandID = op.payload["commandID"]?.string, !commandID.isEmpty,
        let claimedDigest = op.payload["commandDigest"]?.string,
        let reference = Self.reference(from: op.payload), reference.libraryID == authority.libraryID,
        let contributionID = op.payload["contributionID"]?.string, !contributionID.isEmpty,
        Self.validExpectedRevision(op.payload["expectedRevision"]),
        op.kind != Self.acceptKind || Self.validOptionalString(op.payload["note"]),
        let member = authority.members[entry.author],
        op.kind == Self.proposeKind ? member.role == .agent : (member.role == .app || member.role == .device)
      else { continue }
      var body = op.payload
      body["commandID"] = nil
      body["commandDigest"] = nil
      guard claimedDigest == Canonical.digest(try Canonical.encode(body)) else { continue }
      let key = Self.key(entry.author, commandID)
      if result.receipts[key] != nil || pendingCommandKeys.contains(key) { continue }
      let contributionKey = Self.key(reference.revision, contributionID)
      // A proposal whose source has not arrived may become the head later. Do not
      // finalize an acceptance or revision that depends on that unknown head.
      if pendingContributionKeys.contains(contributionKey) { continue }
      let head = result.heads[contributionKey]
      let expect = op.payload["expectedRevision"]?.string
      var outcome: SharedTranscriptReceipt.Outcome = .staleRevision
      if expect == head {
        if op.kind == Self.proposeKind {
          if let proposer = result.proposers[contributionKey], proposer != entry.author {
            outcome = .invalidProposal
          } else if let quote = op.payload["citation"]?.string, !quote.isEmpty,
            let text = op.payload["text"]?.string, !text.isEmpty, transcriptReferences.contains(reference)
          {
            let document: FoldDocument
            if let cached = documents[reference] {
              document = cached
            } else {
              do {
                document = .available(try transcriptDocument(reference))
              } catch SharedTranscriptError.missingTranscript {
                document = .pending
              } catch ColophonError.noAccess {
                document = .pending
              } catch {
                document = .invalid
              }
              documents[reference] = document
            }
            switch document {
            case .pending:
              pendingContributionKeys.insert(contributionKey)
              pendingCommandKeys.insert(key)
              continue
            case .invalid:
              outcome = .invalidCitation
            case .available(let resolved) where resolved.text.contains(quote):
              outcome = .applied
              result.proposers[contributionKey] = entry.author
              result.contributions[op.id] = Projected(reference: reference,
                value: SharedTranscriptContribution(id: contributionID, proposalRevision: op.id, text: text,
                  citation: .init(quote: quote), proposedBy: entry.author, proposedByLabel: entry.authorLabel,
                  acceptanceRevision: nil, acceptedBy: nil, acceptedByLabel: nil, intentionalNote: nil))
            case .available:
              outcome = .invalidCitation
            }
          } else { outcome = .invalidCitation }
        } else if let proposalID = op.payload["proposalRevision"]?.string,
          proposalID == head, result.contributions[proposalID]?.reference == reference,
          var proposed = result.contributions[proposalID]?.value,
          proposed.id == contributionID,
          proposed.proposalRevision == proposalID, proposed.acceptanceRevision == nil
        {
          outcome = .applied
          proposed.acceptanceRevision = op.id
          proposed.acceptedBy = entry.author
          proposed.acceptedByLabel = entry.authorLabel
          proposed.intentionalNote = op.payload["note"]?.string
          result.contributions[proposalID] = Projected(reference: reference, value: proposed)
        } else { outcome = .invalidProposal }
      }
      let applied = outcome == .applied
      let receipt = SharedTranscriptReceipt(commandID: commandID, author: entry.author, operationID: op.id,
        outcome: outcome, revision: applied ? op.id : nil, observedRevision: head)
      result.receipts[key] = SavedReceipt(reference: reference, kind: op.kind, digest: claimedDigest, value: receipt)
      if applied { result.heads[contributionKey] = op.id }
    }
    return result
  }

  private func requireCurrentRead() throws {
    let authority = try replica.authority()
    guard let member = authority.members[replica.identity.id], let grant = member.current,
      grant.namespaces.contains(Podcasts.namespace)
    else {
      throw SharedTranscriptError.noCurrentAccess
    }
    if let expires = grant.expires, expires < .now { throw SharedTranscriptError.noCurrentAccess }
  }

  private func requireCurrentWriter(kind: String, role: MemberRole) throws {
    try requireCurrentRead()
    let authority = try replica.authority()
    guard let member = authority.members[replica.identity.id], let grant = member.current,
      grant.write, grant.namespaces.contains(Podcasts.namespace),
      (role == .agent ? member.role == .agent : (member.role == .app || member.role == .device))
    else { throw SharedTranscriptError.wrongRole }
    if let expires = grant.expires, expires < .now { throw SharedTranscriptError.noCurrentAccess }
    // A replay still needs the current grant. Kinds caveats are checked here; other caveats
    // fail closed because their cumulative admission rules belong to Replica's log fold.
    for caveat in grant.caveats where caveat.namespace == nil || caveat.namespace == Podcasts.namespace {
      guard caveat.kind == Caveat.Kind.kinds.rawValue, caveat.kinds?.contains(kind) == true else {
        throw SharedTranscriptError.noCurrentAccess
      }
    }
  }

  private func body(reference: SharedTranscriptReference, contributionID: String, expectedRevision: String?,
    fields: [String: JSONValue]) -> [String: JSONValue]
  {
    var value = fields
    value["reference"] = Self.json(reference)
    value["contributionID"] = .string(contributionID)
    value["expectedRevision"] = JSONValue(expectedRevision)
    return value
  }

  private static func key(_ first: String, _ second: String) -> String {
    // Length-prefixed pair: arbitrary caller IDs cannot create a delimiter collision.
    "\(first.utf8.count):\(first)\(second.utf8.count):\(second)"
  }

  private static func json(_ reference: SharedTranscriptReference) -> JSONValue {
    .object(["libraryID": .string(reference.libraryID), "episode": .string(reference.episode),
      "show": .string(reference.show), "revision": .string(reference.revision), "blob": reference.blob.json])
  }

  private static func reference(from payload: [String: JSONValue]) -> SharedTranscriptReference? {
    guard let data = try? Canonical.encode(payload["reference"]),
      let reference = try? Canonical.decode(SharedTranscriptReference.self, from: data)
    else { return nil }
    return reference
  }

  private static func validExpectedRevision(_ value: JSONValue?) -> Bool {
    switch value {
    case .null: true
    case .string(let revision): !revision.isEmpty
    default: false
    }
  }

  private static func validOptionalString(_ value: JSONValue?) -> Bool {
    switch value {
    case .null, .string: true
    default: false
    }
  }
}
