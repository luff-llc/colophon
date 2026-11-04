import ColophonAuthority
import ColophonCore
import ColophonReplica
import Foundation

/// The source and playback position observed before Capture pauses the player. An anchor, when
/// available, pins exact words to an immutable transcript operation; seconds alone are approximate.
public struct CaptureThoughtSnapshot: Sendable, Equatable {
  public let episode: String
  public let show: String
  public let seconds: Double
  public let anchor: TranscriptNoteAnchor?
  public let surroundingText: String

  public init(episode: String, show: String, seconds: Double, anchor: TranscriptNoteAnchor? = nil,
    surroundingText: String = "")
  {
    self.episode = episode
    self.show = show
    self.seconds = seconds
    self.anchor = anchor
    self.surroundingText = surroundingText
  }
}

public enum CaptureThoughtInput: Sendable, Equatable {
  case text(String)
  case voice(data: Data, mimeType: String, text: String? = nil)
}

public struct CaptureThoughtRequest: Sendable, Equatable {
  public let requestID: String
  public let noteID: String
  /// The signed `note.add` operation ID. A response must name this exact revision.
  public let revision: String
  public let snapshot: CaptureThoughtSnapshot
  public let text: String?
  public let voice: BlobRef?
  public let voiceMimeType: String?
  public let targetAgentID: String?
  public let authorID: String
}

public struct CaptureThoughtResponse: Sendable, Equatable {
  public let revision: String
  public let requestRevision: String
  public let text: String
  /// Taken from the admitted operation signature, never from response payload.
  public let agentID: String
  public let agentLabel: String
}

public struct CaptureThoughtState: Sendable, Equatable {
  /// `held` reflects current local authority, not a historical or distributed CAS result.
  public enum Status: Sendable, Equatable { case queued, awaitingAgent, responded, cancelled, conflict, held }
  public let request: CaptureThoughtRequest
  public let response: CaptureThoughtResponse?
  public let status: Status
  /// False while a claimed transcript or original voice blob has not synced or failed validation.
  public let sourceReady: Bool
}

public enum CaptureThoughtError: Error, Equatable {
  case invalidInput, noCurrentAccess, wrongRole, wrongAgent, missingRequest
  case staleRequest, missingSource, cancelled, commandIDConflict, duplicateOperationID(String)
}

/// A narrow signed contract over the existing podcast log. Saving performs no agent work or
/// network call. A nil target keeps the complete original capture queued until an endpoint and
/// an enrolled agent are explicitly selected by a later flow.
public struct CaptureThoughtService {
  public static let responseKind = "capture.response"
  public static let cancelKind = "capture.cancel"
  public static let maximumVoiceBytes = 6 * 1_024 * 1_024
  public static let maximumContextUTF16 = 2_000
  public static let maximumTextUTF16 = 10_000

  public let replica: Replica
  public init(replica: Replica) { self.replica = replica }

  @discardableResult public func save(snapshot: CaptureThoughtSnapshot, input: CaptureThoughtInput,
    targetAgentID: String? = nil, requestID: String = UUID().uuidString.lowercased()) throws -> CaptureThoughtRequest
  {
    try requireWriter(role: .app, kind: Podcasts.ContentKind.addNote)
    guard !requestID.isEmpty, !snapshot.episode.isEmpty, !snapshot.show.isEmpty,
      snapshot.seconds.isFinite, snapshot.seconds >= 0,
      snapshot.surroundingText.utf16.count <= Self.maximumContextUTF16
    else { throw CaptureThoughtError.invalidInput }
    if let anchor = snapshot.anchor {
      guard anchor.reference.episode == snapshot.episode, anchor.reference.show == snapshot.show else {
        throw CaptureThoughtError.invalidInput
      }
      try TranscriptNoteService(replica: replica).validate(anchor)
    }
    if let targetAgentID { try requireTarget(targetAgentID) }
    let text: String?
    let voicePlain: String?
    let mimeType: String?
    switch input {
    case .text(let value):
      guard !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
        throw CaptureThoughtError.invalidInput
      }
      text = value
      voicePlain = nil
      mimeType = nil
    case .voice(let data, let mime, let thought):
      guard !data.isEmpty, data.count <= Self.maximumVoiceBytes, !mime.isEmpty else {
        throw CaptureThoughtError.invalidInput
      }
      text = thought
      voicePlain = Canonical.digest(data)
      mimeType = mime
    }
    guard text.map({ !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
      && $0.utf16.count <= Self.maximumTextUTF16 }) ?? true else { throw CaptureThoughtError.invalidInput }
    let identityBody = Self.identityBody(requestID: requestID, snapshot: snapshot, text: text,
      voicePlain: voicePlain, voiceMimeType: mimeType, targetAgentID: targetAgentID)
    let digest = Canonical.digest(try Canonical.encode(identityBody))
    let projection = try fold()
    let requestKey = Self.key(replica.identity.id, requestID)
    guard !projection.conflictedRequestKeys.contains(requestKey) else { throw CaptureThoughtError.commandIDConflict }
    let existing = projection.requests[requestKey]
    if let existing {
      guard existing.digest == digest else { throw CaptureThoughtError.commandIDConflict }
      return existing.request
    }
    // `note.add` keeps the first note with a given ID; refusing collisions prevents a
    // signed capture whose note would be silently shadowed by an older ordinary note.
    let noteID = Self.key(replica.identity.id, requestID)
    guard try replica.state(of: Podcasts.self).notes[noteID] == nil else {
      throw CaptureThoughtError.commandIDConflict
    }
    let voice: BlobRef?
    if case .voice(let data, _, _) = input { voice = try replica.putBlob(data, in: Podcasts.namespace) }
    else { voice = nil }
    var payload: [String: JSONValue] = [
      "note": .string(noteID), "episode": .string(snapshot.episode), "show": .string(snapshot.show),
      "seconds": .number(snapshot.seconds), "text": .string(text ?? "Voice thought"),
      "quote": JSONValue(snapshot.anchor?.quote), "origin": .string("person"),
      "captureThought": .object([
        "requestID": .string(requestID), "digest": .string(digest),
        "surroundingText": .string(snapshot.surroundingText), "originalText": JSONValue(text),
        "voice": voice?.json ?? .null, "voicePlain": JSONValue(voicePlain),
        "voiceMimeType": JSONValue(mimeType), "targetAgentID": JSONValue(targetAgentID)
      ])
    ]
    if let anchor = snapshot.anchor { payload["transcriptAnchor"] = anchor.json }
    let op = try replica.perform(Command(namespace: Podcasts.namespace, kind: Podcasts.ContentKind.addNote,
      payload: payload))
    guard let saved = try fold().requests[Self.key(replica.identity.id, requestID)]?.request,
      saved.revision == op.id else { throw CaptureThoughtError.staleRequest }
    return saved
  }

  /// Called only by the agent's own replica identity. Payloads cannot impersonate another agent.
  @discardableResult public func respond(requestID: String, requestRevision: String, text: String,
    commandID: String) throws -> CaptureThoughtResponse
  {
    try requireWriter(role: .agent, kind: Self.responseKind)
    guard !requestID.isEmpty, !requestRevision.isEmpty, !commandID.isEmpty,
      !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
      text.utf16.count <= Self.maximumTextUTF16
    else { throw CaptureThoughtError.invalidInput }
    let state: CaptureThoughtState
    do { state = try self.state(requestID: requestID, requestRevision: requestRevision) }
    catch CaptureThoughtError.missingRequest { throw CaptureThoughtError.staleRequest }
    guard state.request.revision == requestRevision else { throw CaptureThoughtError.staleRequest }
    guard state.request.targetAgentID == replica.identity.id else { throw CaptureThoughtError.wrongAgent }
    guard state.status != .cancelled else { throw CaptureThoughtError.cancelled }
    guard state.status != .conflict else { throw CaptureThoughtError.commandIDConflict }
    guard state.status != .held else { throw CaptureThoughtError.noCurrentAccess }
    guard state.sourceReady else { throw CaptureThoughtError.missingSource }
    let body: [String: JSONValue] = ["requestID": .string(requestID),
      "requestRevision": .string(requestRevision), "text": .string(text)]
    let digest = Canonical.digest(try Canonical.encode(body))
    let key = Self.key(replica.identity.id, commandID)
    let projection = try fold()
    guard !projection.conflictedResponseKeys.contains(key) else { throw CaptureThoughtError.commandIDConflict }
    if let prior = projection.responsesByCommand[key] {
      guard prior.digest == digest else { throw CaptureThoughtError.commandIDConflict }
      return prior.response
    }
    guard state.response == nil else { throw CaptureThoughtError.staleRequest }
    var payload = body
    payload["commandID"] = .string(commandID)
    payload["commandDigest"] = .string(digest)
    let op = try replica.perform(Command(namespace: Podcasts.namespace, kind: Self.responseKind, payload: payload))
    guard let response = try fold().responsesByCommand[key]?.response, response.revision == op.id else {
      throw CaptureThoughtError.staleRequest
    }
    return response
  }

  public func cancel(requestID: String, requestRevision: String) throws {
    try requireWriter(role: .app, kind: Self.cancelKind)
    let state = try self.state(requestID: requestID, requestRevision: requestRevision)
    guard state.request.revision == requestRevision else { throw CaptureThoughtError.staleRequest }
    guard state.request.authorID == replica.identity.id else { throw CaptureThoughtError.wrongRole }
    guard state.status != .conflict else { throw CaptureThoughtError.commandIDConflict }
    if state.status == .cancelled { return }
    _ = try replica.perform(Command(namespace: Podcasts.namespace, kind: Self.cancelKind,
      payload: ["requestID": .string(requestID), "requestRevision": .string(requestRevision)]))
  }

  public func state(requestID: String, requestRevision: String? = nil) throws -> CaptureThoughtState {
    try requireRead()
    let projection = try fold()
    let matches = projection.requests.values.filter { $0.request.requestID == requestID
      && (requestRevision == nil || $0.request.revision == requestRevision) }
    guard matches.count == 1, let saved = matches.first else {
      throw CaptureThoughtError.missingRequest
    }
    return sourceState(saved.request, projection: projection)
  }

  /// Use this for a persisted note row after relaunch; note IDs are signer-scoped.
  public func state(noteID: String, requestRevision: String? = nil) throws -> CaptureThoughtState {
    try requireRead()
    let projection = try fold()
    let matches = projection.requests.values.filter { $0.request.noteID == noteID
      && (requestRevision == nil || $0.request.revision == requestRevision) }
    guard matches.count == 1, let saved = matches.first else {
      throw CaptureThoughtError.missingRequest
    }
    return sourceState(saved.request, projection: projection)
  }

  /// One admitted-log fold for a note list. Call outside row rendering and cache by the
  /// replica/session revision; individual `state` calls each read the log again.
  public func states() throws -> [String: CaptureThoughtState] {
    try requireRead()
    let projection = try fold()
    var result: [String: CaptureThoughtState] = [:]
    for saved in projection.requests.values {
      let noteID = saved.request.noteID
      guard result[noteID] == nil else { throw CaptureThoughtError.commandIDConflict }
      result[noteID] = sourceState(saved.request, projection: projection)
    }
    return result
  }

  private func sourceState(_ request: CaptureThoughtRequest, projection: Projection) -> CaptureThoughtState {
    let cancelled = projection.cancelled.contains(request.revision)
    let conflict = projection.conflictedRequestKeys.contains(Self.key(request.authorID, request.requestID))
      || projection.conflictedResponseRevisions.contains(request.revision)
    let response = (cancelled || conflict) ? nil : projection.responses[request.revision]
    let status: CaptureThoughtState.Status = if conflict { .conflict }
      else if cancelled { .cancelled }
      else if response != nil { .responded }
      else if projection.heldRequestRevisions.contains(request.revision) { .held }
      else if request.targetAgentID == nil { .queued }
      else { .awaitingAgent }
    return CaptureThoughtState(request: request, response: response, status: status,
      sourceReady: !conflict && (projection.sourceReadiness[request.revision] ?? false))
  }

  private struct SavedRequest { let digest: String; let request: CaptureThoughtRequest }
  private struct SavedResponse { let digest: String; let response: CaptureThoughtResponse }
  private struct Projection {
    var requests: [String: SavedRequest] = [:]
    var responses: [String: CaptureThoughtResponse] = [:]
    var responsesByCommand: [String: SavedResponse] = [:]
    var cancelled: Set<String> = []
    var conflictedRequestKeys: Set<String> = []
    var conflictedResponseKeys: Set<String> = []
    var conflictedResponseRevisions: Set<String> = []
    var heldRequestRevisions: Set<String> = []
    var sourceReadiness: [String: Bool] = [:]
  }

  private func fold() throws -> Projection {
    try requireRead()
    let authority = try replica.authority()
    let entries = try replica.read(Podcasts.namespace).admitted
    var ids: Set<String> = []
    for entry in entries {
      guard ids.insert(entry.operation.id).inserted else {
        throw CaptureThoughtError.duplicateOperationID(entry.operation.id)
      }
    }
    var result = Projection()
    // Discover requests first so physical operation ordering across offline members does not
    // make an otherwise valid response disappear merely because it arrived before its request.
    for entry in entries where entry.operation.kind == Podcasts.ContentKind.addNote {
      guard let member = authority.members[entry.author], member.role == .app || member.role == .device,
        let saved = Self.parseRequest(entry, libraryID: authority.libraryID)
      else { continue }
      let key = Self.key(entry.author, saved.request.requestID)
      if let prior = result.requests[key] {
        if prior.digest != saved.digest { result.conflictedRequestKeys.insert(key) }
        continue
      }
      result.requests[key] = saved
    }
    let byRevision = Dictionary(uniqueKeysWithValues: result.requests.values.map { ($0.request.revision, $0.request) })
    for request in byRevision.values {
      result.sourceReadiness[request.revision] = sourceReady(request)
      if !Self.currentlyAuthorized(request, authority: authority) {
        result.heldRequestRevisions.insert(request.revision)
      }
    }
    for entry in entries where entry.operation.kind == Self.cancelKind {
      let op = entry.operation
      guard let requestID = op.payload["requestID"]?.string,
        let revision = op.payload["requestRevision"]?.string,
        let request = byRevision[revision], request.requestID == requestID,
        request.authorID == entry.author else { continue }
      result.cancelled.insert(revision)
    }
    for entry in entries where entry.operation.kind == Self.responseKind {
      let op = entry.operation
      guard op.v == 1, let requestID = op.payload["requestID"]?.string,
        let revision = op.payload["requestRevision"]?.string,
        let request = byRevision[revision], request.requestID == requestID,
        request.targetAgentID == entry.author, !result.cancelled.contains(revision),
        !result.conflictedRequestKeys.contains(Self.key(request.authorID, request.requestID)),
        !result.heldRequestRevisions.contains(revision),
        result.sourceReadiness[revision] == true,
        let requester = authority.members[request.authorID], requester.revokedAt == nil,
        (requester.role == .app || requester.role == .device),
        let requesterGrant = requester.current, requesterGrant.write,
        requesterGrant.namespaces.contains(Podcasts.namespace),
        requesterGrant.expires.map({ $0 >= .now }) ?? true,
        Self.allowsKind(Podcasts.ContentKind.addNote, grant: requesterGrant),
        let member = authority.members[entry.author], member.role == .agent,
        member.revokedAt == nil, let grant = member.current, grant.write,
        grant.namespaces.contains(Podcasts.namespace), grant.expires.map({ $0 >= .now }) ?? true,
        Self.allowsKind(Self.responseKind, grant: grant),
        let text = op.payload["text"]?.string, !text.isEmpty,
        text.utf16.count <= Self.maximumTextUTF16,
        let commandID = op.payload["commandID"]?.string, !commandID.isEmpty,
        let claimed = op.payload["commandDigest"]?.string
      else { continue }
      let body: [String: JSONValue] = ["requestID": .string(requestID),
        "requestRevision": .string(revision), "text": .string(text)]
      guard claimed == Canonical.digest(try Canonical.encode(body)) else { continue }
      let key = Self.key(entry.author, commandID)
      if let prior = result.responsesByCommand[key] {
        if prior.digest != claimed {
          result.conflictedResponseKeys.insert(key)
          result.conflictedResponseRevisions.insert(prior.response.requestRevision)
          result.conflictedResponseRevisions.insert(revision)
          result.responses[prior.response.requestRevision] = nil
        }
        continue
      }
      guard result.responses[revision] == nil else { continue }
      let response = CaptureThoughtResponse(revision: op.id, requestRevision: revision, text: text,
        agentID: entry.author, agentLabel: entry.authorLabel)
      result.responses[revision] = response
      result.responsesByCommand[key] = SavedResponse(digest: claimed, response: response)
    }
    return result
  }

  private func sourceReady(_ request: CaptureThoughtRequest) -> Bool {
    if let anchor = request.snapshot.anchor,
      (try? TranscriptNoteService(replica: replica).validate(anchor)) == nil { return false }
    if let voice = request.voice {
      guard (try? replica.blob(voice, in: Podcasts.namespace)) != nil else { return false }
    }
    return true
  }

  private static func currentlyAuthorized(_ request: CaptureThoughtRequest, authority: AuthorityState) -> Bool {
    guard let requester = authority.members[request.authorID], requester.revokedAt == nil,
      requester.role == .app || requester.role == .device,
      let requesterGrant = requester.current, requesterGrant.write,
      requesterGrant.namespaces.contains(Podcasts.namespace),
      requesterGrant.expires.map({ $0 >= .now }) ?? true,
      allowsKind(Podcasts.ContentKind.addNote, grant: requesterGrant)
    else { return false }
    guard let targetID = request.targetAgentID else { return true }
    guard let target = authority.members[targetID], target.revokedAt == nil,
      target.role == .agent, let grant = target.current, grant.write,
      grant.namespaces.contains(Podcasts.namespace),
      grant.expires.map({ $0 >= .now }) ?? true,
      allowsKind(responseKind, grant: grant)
    else { return false }
    return true
  }

  private static func parseRequest(_ entry: AdmittedOperation, libraryID: String) -> SavedRequest? {
    let op = entry.operation
    guard op.v == 1, let capture = op.payload["captureThought"]?.object,
      let requestID = capture["requestID"]?.string, !requestID.isEmpty,
      op.payload["note"]?.string == key(entry.author, requestID),
      let episode = op.payload["episode"]?.string, !episode.isEmpty,
      let show = op.payload["show"]?.string, !show.isEmpty,
      let seconds = op.payload["seconds"]?.double, seconds.isFinite, seconds >= 0,
      let context = capture["surroundingText"]?.string,
      context.utf16.count <= maximumContextUTF16,
      let digest = capture["digest"]?.string,
      let originalText = Self.optionalString(capture["originalText"]),
      let voicePlain = Self.optionalString(capture["voicePlain"]),
      let voiceMimeType = Self.optionalString(capture["voiceMimeType"]),
      let target = Self.optionalString(capture["targetAgentID"])
    else { return nil }
    let voice = BlobRef(json: capture["voice"])
    guard (originalText != nil || voice != nil),
      originalText.map({ !$0.isEmpty && $0.utf16.count <= maximumTextUTF16 }) ?? true,
      voice?.plain == voicePlain,
      (voice == nil) == (voiceMimeType == nil),
      op.payload["origin"]?.string == "person",
      op.payload["text"]?.string == (originalText ?? "Voice thought")
    else { return nil }
    let anchor: TranscriptNoteAnchor?
    if let claimed = op.payload["transcriptAnchor"] {
      guard let parsed = TranscriptNoteAnchor(json: claimed),
        parsed.reference.libraryID == libraryID, parsed.reference.episode == episode,
        parsed.reference.show == show, op.payload["quote"]?.string == parsed.quote
      else { return nil }
      anchor = parsed
    } else { anchor = nil }
    let snapshot = CaptureThoughtSnapshot(episode: episode, show: show, seconds: seconds,
      anchor: anchor, surroundingText: context)
    let identity = identityBody(requestID: requestID, snapshot: snapshot, text: originalText,
      voicePlain: voicePlain, voiceMimeType: voiceMimeType, targetAgentID: target)
    guard let encoded = try? Canonical.encode(identity), digest == Canonical.digest(encoded) else { return nil }
    let request = CaptureThoughtRequest(requestID: requestID, noteID: key(entry.author, requestID), revision: op.id,
      snapshot: snapshot, text: originalText, voice: voice, voiceMimeType: voiceMimeType,
      targetAgentID: target, authorID: entry.author)
    return SavedRequest(digest: digest, request: request)
  }

  private static func optionalString(_ value: JSONValue?) -> String?? {
    switch value { case .none: return nil; case .some(.null): return .some(nil)
    case .some(.string(let text)): return .some(text); default: return nil }
  }

  private static func identityBody(requestID: String, snapshot: CaptureThoughtSnapshot,
    text: String?, voicePlain: String?, voiceMimeType: String?, targetAgentID: String?) -> [String: JSONValue]
  {
    ["requestID": .string(requestID), "episode": .string(snapshot.episode),
      "show": .string(snapshot.show), "seconds": .number(snapshot.seconds),
      "anchor": snapshot.anchor?.json ?? .null,
      "surroundingText": .string(snapshot.surroundingText), "originalText": JSONValue(text),
      "voicePlain": JSONValue(voicePlain), "voiceMimeType": JSONValue(voiceMimeType),
      "targetAgentID": JSONValue(targetAgentID)]
  }

  private func requireRead() throws {
    let authority = try replica.authority()
    guard let member = authority.members[replica.identity.id], member.revokedAt == nil,
      let grant = member.current, grant.namespaces.contains(Podcasts.namespace),
      grant.expires.map({ $0 >= .now }) ?? true
    else { throw CaptureThoughtError.noCurrentAccess }
  }

  private func requireWriter(role: MemberRole, kind: String) throws {
    try requireRead()
    let member = try replica.authority().members[replica.identity.id]
    guard let member, let grant = member.current, grant.write,
      (role == .agent ? member.role == .agent : (member.role == .app || member.role == .device))
    else { throw CaptureThoughtError.wrongRole }
    guard Self.allowsKind(kind, grant: grant) else { throw CaptureThoughtError.noCurrentAccess }
  }

  private func requireTarget(_ id: String) throws {
    let authority = try replica.authority()
    guard let member = authority.members[id], member.role == .agent, member.revokedAt == nil,
      let grant = member.current, grant.write, grant.namespaces.contains(Podcasts.namespace),
      grant.expires.map({ $0 >= .now }) ?? true,
      Self.allowsKind(Self.responseKind, grant: grant)
    else { throw CaptureThoughtError.wrongAgent }
  }

  private static func allowsKind(_ kind: String, grant: AuthorityState.Grant) -> Bool {
    for caveat in grant.caveats where caveat.namespace == nil || caveat.namespace == Podcasts.namespace {
      guard caveat.kind == Caveat.Kind.kinds.rawValue, caveat.kinds?.contains(kind) == true else {
        return false
      }
    }
    return true
  }

  private static func key(_ a: String, _ b: String) -> String {
    "\(a.utf8.count):\(a)\(b.utf8.count):\(b)"
  }
}
