import ColophonAuthority
import ColophonCore
import ColophonReplica
import Foundation

/// Durable local/on-device answer retention in the existing signed podcast log. This starts
/// no model, dispatch, provider or external job. An enrolled agent's signer is always shown as
/// an agent; a payload cannot impersonate a person. All citations survive sync independently
/// of any runtime session and remain pinned when the selected transcript changes.
public struct TranscriptAnswerService {
  public static let saveKind = "answer.save"
  public static let maximumClaims = 50
  public static let maximumCitations = 200
  public let replica: Replica

  public init(replica: Replica) { self.replica = replica }

  @discardableResult public func save(question: String, claims: [TranscriptAnswerClaim], commandID: String)
    throws -> TranscriptAnswerRecord
  {
    try requireCurrentAccess(write: true)
    guard Self.valid(question: question, claims: claims), !commandID.isEmpty, commandID.utf16.count <= 256 else {
      throw TranscriptAnswerError.invalidInput
    }
    let libraryID = try replica.authority().libraryID
    let body = try Self.body(libraryID: libraryID, question: question, claims: claims)
    let digest = Canonical.digest(try Canonical.encode(body))
    let prior = try projected().filter {
      $0.authorID == replica.identity.id && $0.commandID == commandID
    }
    if !prior.isEmpty {
      guard prior.count == 1, let record = prior.first, record.question == question, record.claims == claims,
        record.status != .conflict else { throw TranscriptAnswerError.commandIDConflict }
      // Current access and exact sources must still verify, including an idempotent replay.
      try validate(claims)
      return record
    }
    try validate(claims)
    var payload = body
    payload["commandID"] = .string(commandID)
    payload["commandDigest"] = .string(digest)
    let operation = try replica.perform(Command(namespace: Podcasts.namespace, kind: Self.saveKind, payload: payload))
    guard let record = try projected().first(where: { $0.id == operation.id }), record.status == .verified else {
      throw TranscriptAnswerError.notAdmitted
    }
    return record
  }

  /// Rechecks admission, current read access, command conflicts and exact citations on every
  /// projection. Source arrival promotes pending records without rewriting signed evidence.
  public func collection() throws -> TranscriptAnswerCollection {
    let records = try projected()
    let view = try replica.read(Podcasts.namespace)
    return TranscriptAnswerCollection(records: records,
      heldCount: view.held.filter { $0.operation.kind == Self.saveKind }.count)
  }

  public func record(revision: String) throws -> TranscriptAnswerRecord? {
    try projected().first { $0.id == revision }
  }

  private func projected() throws -> [TranscriptAnswerRecord] {
    try requireCurrentAccess(write: false)
    let libraryID = try replica.authority().libraryID
    let view = try replica.read(Podcasts.namespace)
    var seen: Set<String> = []
    for entry in view.admitted where !seen.insert(entry.operation.id).inserted {
      throw TranscriptAnswerError.duplicateOperationID(entry.operation.id)
    }
    struct Candidate {
      let entry: AdmittedOperation
      let commandID: String
      let digest: String
      let question: String
      let claims: [TranscriptAnswerClaim]
      var key: String { "\(entry.author.utf8.count):\(entry.author)\(commandID.utf8.count):\(commandID)" }
    }
    var candidates: [Candidate] = []
    for entry in view.admitted {
      let op = entry.operation
      guard op.kind == Self.saveKind, op.v == 1,
        entry.authorRole == .agent || entry.authorRole == .app || entry.authorRole == .device,
        op.payload["libraryID"]?.string == libraryID,
        let commandID = op.payload["commandID"]?.string, !commandID.isEmpty, commandID.utf16.count <= 256,
        let digest = op.payload["commandDigest"]?.string,
        let question = op.payload["question"]?.string,
        let rawClaims = op.payload["claims"],
        let data = try? Canonical.encode(rawClaims),
        let claims = try? Canonical.decode([TranscriptAnswerClaim].self, from: data),
        Self.valid(question: question, claims: claims)
      else { continue }
      var body = op.payload
      body["commandID"] = nil
      body["commandDigest"] = nil
      guard digest == Canonical.digest(try Canonical.encode(body)) else { continue }
      candidates.append(Candidate(entry: entry, commandID: commandID, digest: digest,
        question: question, claims: claims))
    }
    let grouped = Dictionary(grouping: candidates, by: \.key)
    var records: [TranscriptAnswerRecord] = []
    for group in grouped.values {
      let conflict = Set(group.map(\.digest)).count > 1
      // Identical retries collapse; different requests under one command remain visible.
      var seenDigests: Set<String> = []
      for candidate in group where seenDigests.insert(candidate.digest).inserted {
        var status: TranscriptAnswerRecord.Status = conflict ? .conflict : .verified
        if !conflict {
          var pending = false
          var invalid = false
          // Preserve the entire original answer even while one source is not materialized.
          // Invalid evidence takes precedence over pending evidence.
          for claim in candidate.claims {
            for anchor in claim.citations {
              do { try TranscriptNoteService(replica: replica).validate(anchor) }
              catch SharedTranscriptError.missingTranscript { pending = true }
              catch ColophonError.noAccess { pending = true }
              catch { invalid = true }
            }
          }
          status = invalid ? .invalidCitation : (pending ? .pendingSource : .verified)
        }
        let entry = candidate.entry
        records.append(TranscriptAnswerRecord(id: entry.operation.id, libraryID: libraryID,
          commandID: candidate.commandID, question: candidate.question, claims: candidate.claims,
          authorID: entry.author, authorLabel: entry.authorLabel, authorRole: entry.authorRole,
          origin: entry.authorRole == .agent ? .agent : .onDevice, status: status))
      }
    }
    return records.sorted { $0.id < $1.id }
  }

  private func validate(_ claims: [TranscriptAnswerClaim]) throws {
    for claim in claims {
      for anchor in claim.citations { try TranscriptNoteService(replica: replica).validate(anchor) }
    }
  }

  private static func valid(question: String, claims: [TranscriptAnswerClaim]) -> Bool {
    guard !question.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
      question.utf16.count <= 4_000, !claims.isEmpty, claims.count <= maximumClaims,
      claims.reduce(0, { $0 + $1.citations.count }) <= maximumCitations,
      claims.reduce(0, { $0 + $1.text.utf16.count }) <= 40_000
    else { return false }
    return claims.allSatisfy { claim in
      !claim.text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && !claim.citations.isEmpty
        && claim.citations.allSatisfy { anchor in
          anchor.startUTF16 >= 0 && anchor.lengthUTF16 > 0 && !anchor.quote.isEmpty
            && anchor.quote.utf16.count <= 8_000 && anchor.quote.utf16.count == anchor.lengthUTF16
        }
    }
  }

  private static func body(libraryID: String, question: String, claims: [TranscriptAnswerClaim])
    throws -> [String: JSONValue]
  {
    ["libraryID": .string(libraryID), "question": .string(question),
      "claims": try Canonical.decode(JSONValue.self, from: Canonical.encode(claims))]
  }

  private func requireCurrentAccess(write: Bool) throws {
    let authority = try replica.authority()
    guard let member = authority.members[replica.identity.id], member.revokedAt == nil,
      let grant = member.current, grant.namespaces.contains(Podcasts.namespace),
      grant.expires.map({ $0 >= .now }) ?? true
    else { throw TranscriptAnswerError.noCurrentAccess }
    if write {
      guard grant.write, member.role == .agent || member.role == .app || member.role == .device else {
        throw TranscriptAnswerError.noCurrentAccess
      }
      // Fail closed for caveats whose cumulative semantics belong to Replica admission.
      for caveat in grant.caveats where caveat.namespace == nil || caveat.namespace == Podcasts.namespace {
        guard caveat.kind == Caveat.Kind.kinds.rawValue, caveat.kinds?.contains(Self.saveKind) == true else {
          throw TranscriptAnswerError.noCurrentAccess
        }
      }
    }
  }
}
