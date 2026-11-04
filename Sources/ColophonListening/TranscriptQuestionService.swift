import ColophonAuthority
import ColophonCore
import ColophonReplica
import Foundation

/// A narrow durable broker contract, independent of agent runtime sessions. Hosts must expose
/// only `packet` and `respond` to an untrusted model, keeping the replica and namespace keys in
/// their trusted process. An agent already holding keys retains broad namespace read access;
/// a request scope does not create item-level cryptographic isolation for that agent.
public struct TranscriptQuestionService {
  public static let requestKind = "question.request"
  public static let responseKind = "question.response"
  public static let cancelKind = "question.cancel"
  public static let admitKind = "question.admit"
  public static let maximumPassages = 20
  public static let maximumScopeUTF16 = 20_000
  public static let maximumPending = 32
  public let replica: Replica
  private let now: @Sendable () -> Date

  public init(replica: Replica, now: @escaping @Sendable () -> Date = { .now }) {
    self.replica = replica
    self.now = now
  }

  @discardableResult public func request(question: String, scope: [TranscriptNoteAnchor], targetAgentID: String,
    expires: Date, commandID: String) throws -> TranscriptQuestionRequest
  {
    try requireWriter(kind: Self.requestKind, agent: false)
    guard Self.valid(question: question, scope: scope), !targetAgentID.isEmpty,
      expires.timeIntervalSince1970.isFinite
    else { throw TranscriptQuestionError.invalidInput }
    try requireTarget(targetAgentID)
    try validate(scope)
    let body: [String: JSONValue] = ["libraryID": .string(try replica.authority().libraryID),
      "question": .string(question), "scope": try Self.json(scope), "targetAgentID": .string(targetAgentID),
      "expires": .number(expires.timeIntervalSince1970)]
    let entries = try envelopes()
    if try prior(kind: Self.requestKind, body: body, commandID: commandID, entries: entries) == nil {
      guard expires > now(), expires.timeIntervalSince(now()) <= 7 * 86_400 else {
        throw TranscriptQuestionError.invalidInput
      }
      let pending = try states().filter {
        $0.request.authorID == replica.identity.id
          && $0.request.expires > now()
          && [.queued, .sourcePending, .awaitingReview].contains($0.status)
      }
      guard pending.count < Self.maximumPending else { throw TranscriptQuestionError.tooManyPending }
    }
    let id = try submit(kind: Self.requestKind, body: body, commandID: commandID)
    guard let request = try states().first(where: { $0.id == id })?.request else {
      throw TranscriptQuestionError.notAdmitted
    }
    return request
  }

  /// Returns only the request's exact passages after rechecking current authority, deadline,
  /// cancellation and source admission. No full-transcript fetch is exposed by this broker.
  public func packet(requestRevision: String) throws -> TranscriptQuestionPacket {
    let state = try actionable(requestRevision)
    let caller = try replica.authority().members[replica.identity.id]
    guard caller?.role == .app || caller?.role == .device
      || (caller?.role == .agent && replica.identity.id == state.request.targetAgentID)
    else { throw TranscriptQuestionError.wrongAgent }
    return TranscriptQuestionPacket(request: state.request, passages: state.request.scope)
  }

  @discardableResult public func respond(requestRevision: String, claims: [TranscriptAnswerClaim], commandID: String)
    throws -> TranscriptQuestionResponse
  {
    try requireWriter(kind: Self.responseKind, agent: true)
    guard let state = try self.state(revision: requestRevision) else { throw TranscriptQuestionError.missingRequest }
    guard state.request.targetAgentID == replica.identity.id else { throw TranscriptQuestionError.wrongAgent }
    guard Self.valid(claims: claims, scope: state.request.scope) else { throw TranscriptQuestionError.outsideScope }
    try validate(claims.flatMap(\.citations))
    let body: [String: JSONValue] = ["libraryID": .string(state.request.libraryID),
      "requestRevision": .string(requestRevision), "scopeDigest": .string(state.request.scopeDigest),
      "claims": try Self.json(claims)]
    let entries = try envelopes()
    let replay = try prior(kind: Self.responseKind, body: body, commandID: commandID, entries: entries)
    if let replay {
      guard let response = state.responses.first(where: { $0.id == replay }) else {
        throw TranscriptQuestionError.conflict
      }
      return response
    }
    _ = try actionable(requestRevision)
    if !state.responses.isEmpty { throw TranscriptQuestionError.conflict }
    let id = try submit(kind: Self.responseKind, body: body, commandID: commandID)
    guard let response = try self.state(revision: requestRevision)?.responses.first(where: { $0.id == id }) else {
      throw TranscriptQuestionError.notAdmitted
    }
    return response
  }

  /// The trusted receiving app verifies before signing this technical receipt. It checks its
  /// local clock now, never the agent's author-reported operation date. Accepted answers stay
  /// durable after expiry; a late arrival with no receipt cannot acquire one after expiry.
  @discardableResult public func admit(responseRevision: String, commandID: String) throws -> TranscriptQuestionResponse {
    try requireWriter(kind: Self.admitKind, agent: false)
    let states = try self.states()
    guard let state = states.first(where: { $0.responses.contains { $0.id == responseRevision } }),
      let response = state.responses.first(where: { $0.id == responseRevision })
    else { throw TranscriptQuestionError.missingResponse }
    let body: [String: JSONValue] = ["libraryID": .string(state.request.libraryID),
      "requestRevision": .string(state.id), "responseRevision": .string(responseRevision)]
    // An already admitted receipt can be reconciled after expiry, but still needs current
    // write authority and a byte-identical command. No new receipt is emitted on this path.
    if let prior = try prior(kind: Self.admitKind, body: body, commandID: commandID, entries: envelopes()) {
      guard response.admissionRevision == prior else { throw TranscriptQuestionError.conflict }
      return response
    }
    _ = try actionable(state.id)
    guard state.responses.count == 1 else { throw TranscriptQuestionError.conflict }
    _ = try submit(kind: Self.admitKind, body: body, commandID: commandID)
    guard let admitted = try self.state(revision: state.id)?.responses.first(where: { $0.id == responseRevision }),
      admitted.admissionRevision != nil else { throw TranscriptQuestionError.notAdmitted }
    return admitted
  }

  public func cancel(requestRevision: String, commandID: String) throws {
    try requireWriter(kind: Self.cancelKind, agent: false)
    guard let state = try state(revision: requestRevision) else { throw TranscriptQuestionError.missingRequest }
    // Any currently enrolled app/device can cancel the person's library request.
    let body: [String: JSONValue] = ["libraryID": .string(state.request.libraryID),
      "requestRevision": .string(requestRevision)]
    _ = try submit(kind: Self.cancelKind, body: body, commandID: commandID)
    guard try self.state(revision: requestRevision)?.status == .cancelled else {
      throw TranscriptQuestionError.notAdmitted
    }
  }

  public func state(revision: String) throws -> TranscriptQuestionState? { try states().first { $0.id == revision } }

  public func states() throws -> [TranscriptQuestionState] {
    try requireRead()
    let entries = try envelopes()
    let libraryID = try replica.authority().libraryID
    let authority = try replica.authority()
    let view = try replica.read(Podcasts.namespace)
    var requests: [(Envelope, TranscriptQuestionRequest)] = []
    for envelope in entries where envelope.entry.operation.kind == Self.requestKind {
      let entry = envelope.entry
      let body = envelope.body
      guard entry.authorRole == .app || entry.authorRole == .device,
        let question = body["question"]?.string, let scope: [TranscriptNoteAnchor] = Self.decode(body["scope"]),
        Self.valid(question: question, scope: scope), scope.allSatisfy({ $0.reference.libraryID == libraryID }),
        let target = body["targetAgentID"]?.string, !target.isEmpty,
        let seconds = body["expires"]?.double, seconds.isFinite
      else { continue }
      let request = TranscriptQuestionRequest(id: entry.operation.id, libraryID: libraryID,
        question: question, scope: scope, scopeDigest: Canonical.digest(try Canonical.encode(scope)),
        targetAgentID: target, expires: Date(timeIntervalSince1970: seconds), commandID: envelope.commandID,
        authorID: entry.author, authorLabel: entry.authorLabel)
      requests.append((envelope, request))
    }
    let commandGroups = Dictionary(grouping: entries, by: \.key)
    let conflictingKeys = Set(commandGroups.filter {
      Set($0.value.map { $0.entry.operation.kind + ":" + $0.digest }).count > 1
    }.keys)
    var result: [TranscriptQuestionState] = []
    var projectedCommands: Set<String> = []
    for (envelope, request) in requests {
      // Exact retries project once; conflicting bodies remain visible for reconciliation.
      let projectionKey = envelope.key + ":" + envelope.digest
      guard projectedCommands.insert(projectionKey).inserted else { continue }
      let relevant = entries.filter { $0.body["requestRevision"]?.string == request.id }
      let cancelled = relevant.contains {
        $0.entry.operation.kind == Self.cancelKind && ($0.entry.authorRole == .app || $0.entry.authorRole == .device)
          && !conflictingKeys.contains($0.key)
      }
      var responses: [TranscriptQuestionResponse] = []
      var responseDigests: Set<String> = []
      for candidate in relevant where candidate.entry.operation.kind == Self.responseKind {
        guard candidate.entry.author == request.targetAgentID, candidate.entry.authorRole == .agent,
          candidate.body["scopeDigest"]?.string == request.scopeDigest,
          let claims: [TranscriptAnswerClaim] = Self.decode(candidate.body["claims"]),
          Self.valid(claims: claims, scope: request.scope), responseDigests.insert(candidate.digest).inserted
        else { continue }
        let admission = relevant.first {
          $0.entry.operation.kind == Self.admitKind && ($0.entry.authorRole == .app || $0.entry.authorRole == .device)
            && $0.body["responseRevision"]?.string == candidate.entry.operation.id
            && !conflictingKeys.contains($0.key)
        }
        responses.append(TranscriptQuestionResponse(id: candidate.entry.operation.id,
          requestRevision: request.id, claims: claims, agentID: candidate.entry.author,
          agentLabel: candidate.entry.authorLabel, commandID: candidate.commandID,
          admissionRevision: admission?.entry.operation.id))
      }
      let sourceReady = (try? validate(request.scope)) != nil
      let accessReady = Self.memberAllows(authority.members[request.authorID], kind: Self.requestKind, now: now())
        && Self.memberAllows(authority.members[request.targetAgentID], kind: Self.responseKind, now: now(), agent: true)
      let hasConflict = conflictingKeys.contains(envelope.key) || responses.count > 1
        || relevant.contains { conflictingKeys.contains($0.key) }
      let held = view.held.contains {
        $0.operation.payload["requestRevision"]?.string == request.id
          && [Self.responseKind, Self.cancelKind, Self.admitKind].contains($0.operation.kind)
      }
      let status: TranscriptQuestionState.Status
      if cancelled { status = .cancelled }
      else if hasConflict { status = .conflict }
      else if request.expires <= now(), responses.first?.admissionRevision == nil { status = .expired }
      else if !sourceReady { status = .sourcePending }
      else if responses.first?.admissionRevision != nil { status = .answered }
      else if !accessReady { status = .accessUnavailable }
      else if held { status = .held }
      else if !responses.isEmpty { status = .awaitingReview }
      else { status = .queued }
      result.append(TranscriptQuestionState(request: request, responses: responses, status: status, sourceReady: sourceReady))
    }
    return result.sorted { $0.id < $1.id }
  }

  private func actionable(_ revision: String) throws -> TranscriptQuestionState {
    guard let state = try state(revision: revision) else { throw TranscriptQuestionError.missingRequest }
    switch state.status {
    case .cancelled: throw TranscriptQuestionError.cancelled
    case .expired: throw TranscriptQuestionError.expired
    case .conflict, .held: throw TranscriptQuestionError.conflict
    case .accessUnavailable: throw TranscriptQuestionError.noCurrentAccess
    case .sourcePending: throw TranscriptQuestionError.missingSource
    case .queued, .awaitingReview, .answered: break
    }
    // A retained answer may remain visible after deadline/revocation, but its broker cannot
    // export another packet or start fresh work after either boundary changes.
    guard state.request.expires > now() else { throw TranscriptQuestionError.expired }
    let authority = try replica.authority()
    guard Self.memberAllows(authority.members[state.request.authorID], kind: Self.requestKind, now: now()),
      Self.memberAllows(authority.members[state.request.targetAgentID], kind: Self.responseKind, now: now(), agent: true)
    else { throw TranscriptQuestionError.noCurrentAccess }
    return state
  }

  private struct Envelope {
    let entry: AdmittedOperation
    let body: [String: JSONValue]
    let commandID: String
    let digest: String
    var key: String { "\(entry.author.utf8.count):\(entry.author)\(commandID.utf8.count):\(commandID)" }
  }

  private func envelopes() throws -> [Envelope] {
    try requireRead()
    let libraryID = try replica.authority().libraryID
    let view = try replica.read(Podcasts.namespace)
    var seen: Set<String> = []
    var entries: [Envelope] = []
    for entry in view.admitted {
      guard seen.insert(entry.operation.id).inserted else {
        throw TranscriptQuestionError.duplicateOperationID(entry.operation.id)
      }
      let op = entry.operation
      guard [Self.requestKind, Self.responseKind, Self.cancelKind, Self.admitKind].contains(op.kind), op.v == 1,
        op.payload["libraryID"]?.string == libraryID,
        let commandID = op.payload["commandID"]?.string, !commandID.isEmpty, commandID.utf16.count <= 256,
        let digest = op.payload["commandDigest"]?.string
      else { continue }
      var body = op.payload
      body["commandID"] = nil
      body["commandDigest"] = nil
      guard digest == Canonical.digest(try Canonical.encode(body)) else { continue }
      entries.append(Envelope(entry: entry, body: body, commandID: commandID, digest: digest))
    }
    return entries
  }

  private func prior(kind: String, body: [String: JSONValue], commandID: String, entries: [Envelope]) throws -> String? {
    guard !commandID.isEmpty, commandID.utf16.count <= 256 else { throw TranscriptQuestionError.invalidInput }
    let digest = Canonical.digest(try Canonical.encode(body))
    let prior = entries.filter { $0.entry.author == replica.identity.id && $0.commandID == commandID }
    guard prior.allSatisfy({ $0.entry.operation.kind == kind && $0.digest == digest }) else {
      throw TranscriptQuestionError.commandIDConflict
    }
    return prior.first?.entry.operation.id
  }

  private func submit(kind: String, body: [String: JSONValue], commandID: String) throws -> String {
    if let prior = try prior(kind: kind, body: body, commandID: commandID, entries: envelopes()) { return prior }
    var payload = body
    payload["commandID"] = .string(commandID)
    payload["commandDigest"] = .string(Canonical.digest(try Canonical.encode(body)))
    let op = try replica.perform(Command(namespace: Podcasts.namespace, kind: kind, payload: payload))
    guard try envelopes().contains(where: { $0.entry.operation.id == op.id }) else {
      throw TranscriptQuestionError.notAdmitted
    }
    return op.id
  }

  private func validate(_ anchors: [TranscriptNoteAnchor]) throws {
    for anchor in anchors { try TranscriptNoteService(replica: replica).validate(anchor) }
  }

  private static func valid(question: String, scope: [TranscriptNoteAnchor]) -> Bool {
    !question.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && question.utf16.count <= 4_000
      && !scope.isEmpty && scope.count <= maximumPassages && Set(scope).count == scope.count
      && scope.reduce(0, { $0 + $1.quote.utf16.count }) <= maximumScopeUTF16
      && scope.allSatisfy { $0.startUTF16 >= 0 && $0.lengthUTF16 > 0
        && $0.lengthUTF16 == $0.quote.utf16.count && $0.quote.utf16.count <= 8_000 }
  }

  private static func valid(claims: [TranscriptAnswerClaim], scope: [TranscriptNoteAnchor]) -> Bool {
    let allowed = Set(scope)
    return !claims.isEmpty && claims.count <= TranscriptAnswerService.maximumClaims
      && claims.reduce(0, { $0 + $1.text.utf16.count }) <= 40_000
      && claims.reduce(0, { $0 + $1.citations.count }) <= TranscriptAnswerService.maximumCitations
      && claims.allSatisfy { !$0.text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        && !$0.citations.isEmpty && $0.citations.allSatisfy { allowed.contains($0) } }
  }

  private func requireRead() throws {
    let authority = try replica.authority()
    guard let member = authority.members[replica.identity.id], member.revokedAt == nil,
      let grant = member.current, grant.namespaces.contains(Podcasts.namespace),
      grant.expires.map({ $0 >= now() }) ?? true else { throw TranscriptQuestionError.noCurrentAccess }
  }

  private func requireWriter(kind: String, agent: Bool) throws {
    try requireRead()
    let member = try replica.authority().members[replica.identity.id]
    guard member?.role == (agent ? .agent : .app) || (!agent && member?.role == .device) else {
      throw TranscriptQuestionError.wrongRole
    }
    guard Self.memberAllows(member, kind: kind, now: now(), agent: agent) else {
      throw TranscriptQuestionError.noCurrentAccess
    }
  }

  private func requireTarget(_ target: String) throws {
    guard Self.memberAllows(try replica.authority().members[target], kind: Self.responseKind, now: now(), agent: true) else {
      throw TranscriptQuestionError.wrongAgent
    }
  }

  private static func memberAllows(_ member: AuthorityState.Member?, kind: String, now: Date, agent: Bool = false) -> Bool {
    guard let member, member.revokedAt == nil, let grant = member.current, grant.write,
      grant.namespaces.contains(Podcasts.namespace), grant.expires.map({ $0 >= now }) ?? true,
      agent ? member.role == .agent : (member.role == .app || member.role == .device)
    else { return false }
    return grant.caveats.filter { $0.namespace == nil || $0.namespace == Podcasts.namespace }.allSatisfy {
      $0.kind == Caveat.Kind.kinds.rawValue && $0.kinds?.contains(kind) == true
    }
  }

  private static func json<Value: Encodable>(_ value: Value) throws -> JSONValue {
    try Canonical.decode(JSONValue.self, from: Canonical.encode(value))
  }

  private static func decode<Value: Decodable>(_ value: JSONValue?) -> Value? {
    guard let value, let data = try? Canonical.encode(value) else { return nil }
    return try? Canonical.decode(Value.self, from: data)
  }
}
