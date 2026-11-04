import ColophonAuthority
import ColophonCore
import ColophonReplica
import Foundation

public struct TranscriptPreparationAssignment: Codable, Hashable, Sendable {
  public let revision: String
  public let requester: String
  public let worker: String
  public let request: TranscriptPreparationRequest
  public let audio: BlobRef
  public var cancelled: Bool
  public var result: BlobRef?
}

/// An explicitly selected enrolled worker prepares one exact encrypted recording. Results
/// remain proposals until the requesting app validates and applies them. No distributed
/// exactly-once execution is claimed; replay collapses against signed request/result identity.
public struct TranscriptPreparationService: Sendable {
  public static let requestKind = "transcript.prepare"
  public static let cancelKind = "transcript.prepare.cancel"
  public static let resultKind = "transcript.prepare.result"
  public let replica: Replica
  public init(replica: Replica) { self.replica = replica }

  /// Check the same current app permission used at commit before starting costly work.
  /// Applying a result always checks again; this preflight grants no durable permission.
  public func validateApplicationAccess() throws {
    try require(replica.identity.id, writer: true, app: true, kind: Podcasts.ContentKind.transcript)
  }

  public struct Worker: Identifiable, Hashable, Sendable {
    public let id: String
    public let label: String
  }
  public func workers() throws -> [Worker] {
    try require(replica.identity.id)
    return try replica.authority().activeMembers.filter { member in
      member.role == .agent && (try? require(member.id, writer: true, kind: Self.resultKind)) != nil
    }.map { Worker(id: $0.id, label: $0.label) }.sorted { $0.label.localizedStandardCompare($1.label) == .orderedAscending }
  }

  public func request(_ request: TranscriptPreparationRequest, audio: BlobRef,
    worker: String) throws -> TranscriptPreparationAssignment
  {
    try require(replica.identity.id, writer: true, app: true, kind: Self.requestKind)
    try require(worker, writer: true, kind: Self.resultKind)
    guard try replica.authority().members[worker]?.role == .agent else { throw TranscriptPreparationError.wrongWorker }
    guard request.policy == .mac, request.audioURL == nil,
      request.libraryID == (try replica.authority().libraryID),
      request.recordingDigest == audio.plain, PodcastRecordingIdentity.isDigest(audio.plain),
      audio.size > 0, audio.size <= 2_000_000_000, request.language?.isEmpty == false,
      !request.id.isEmpty, !request.episode.isEmpty, !request.show.isEmpty else {
      throw TranscriptPreparationError.invalidSource
    }
    if let prior = try assignments().first(where: { $0.requester == replica.identity.id && $0.request.id == request.id }) {
      guard prior.request == request, prior.audio.plain == audio.plain, prior.audio.size == audio.size,
        prior.worker == worker else {
        throw TranscriptPreparationError.conflictingRequest
      }
      return prior
    }
    let operation = try replica.perform(Command(namespace: Podcasts.namespace, kind: Self.requestKind,
      payload: ["request": try json(request), "audio": audio.json, "worker": .string(worker)]))
    guard let admitted = try assignments().first(where: { $0.revision == operation.id }) else {
      throw TranscriptPreparationError.noAccess
    }
    return admitted
  }

  public func assignments() throws -> [TranscriptPreparationAssignment] {
    try require(replica.identity.id)
    let view = try replica.read(Podcasts.namespace)
    var ids: Set<String> = []
    for entry in view.admitted {
      guard ids.insert(entry.operation.id).inserted else { throw TranscriptPreparationError.conflictingRequest }
    }
    var result: [TranscriptPreparationAssignment] = []
    var keys: [String: String] = [:]
    var conflicts: Set<String> = []
    let library = try replica.authority().libraryID
    for entry in view.admitted where entry.operation.kind == Self.requestKind && entry.operation.v == 1 {
      let payload = entry.operation.payload
      guard let object = payload["request"],
        let request = try? Canonical.decode(TranscriptPreparationRequest.self, from: Canonical.encode(object)),
        request.libraryID == library, request.policy == .mac, request.audioURL == nil,
        let audio = BlobRef(json: payload["audio"]), request.recordingDigest == audio.plain,
        PodcastRecordingIdentity.isDigest(audio.plain), audio.size > 0, audio.size <= 2_000_000_000,
        request.language?.isEmpty == false, !request.id.isEmpty, !request.episode.isEmpty, !request.show.isEmpty,
        let worker = payload["worker"]?.string,
        (try? require(entry.author, writer: true, app: true, kind: Self.requestKind)) != nil
      else { continue }
      let key = entry.author + ":" + request.id
      let digest = Canonical.digest(try Canonical.encode(payload))
      if let prior = keys[key] {
        if prior != digest { conflicts.insert(key) }
        continue
      }
      keys[key] = digest
      result.append(TranscriptPreparationAssignment(revision: entry.operation.id, requester: entry.author,
        worker: worker, request: request, audio: audio, cancelled: false, result: nil))
    }
    result.removeAll { conflicts.contains($0.requester + ":" + $0.request.id) }
    for index in result.indices {
      let assignment = result[index]
      result[index].cancelled = view.admitted.contains { entry in
        entry.author == assignment.requester && entry.operation.kind == Self.cancelKind && entry.operation.v == 1
          && entry.operation.payload["requestRevision"]?.string == assignment.revision
      }
      // A revoked/expired selected worker leaves work held, never silently reassigns it.
      guard (try? require(assignment.worker, writer: true, kind: Self.resultKind)) != nil else { continue }
      var results: Set<BlobRef> = []
      for entry in view.admitted where entry.author == assignment.worker && entry.operation.kind == Self.resultKind && entry.operation.v == 1 {
        guard entry.operation.payload["requestRevision"]?.string == assignment.revision,
          let blob = BlobRef(json: entry.operation.payload["result"]) else { continue }
        results.insert(blob)
      }
      // An equivocal worker result is held rather than selecting one physical delivery.
      let semantic = Set(results.map(\.plain))
      if semantic.count == 1 { result[index].result = results.sorted { $0.digest < $1.digest }.first }
    }
    return result
  }

  public func cancel(_ assignment: TranscriptPreparationAssignment) throws {
    try require(replica.identity.id, writer: true, app: true, kind: Self.cancelKind)
    guard assignment.requester == replica.identity.id else { throw TranscriptPreparationError.noAccess }
    let current = try current(assignment.revision)
    guard !current.cancelled else { return }
    _ = try replica.perform(Command(namespace: Podcasts.namespace, kind: Self.cancelKind,
      payload: ["requestRevision": .string(assignment.revision)]))
    guard try self.current(assignment.revision).cancelled else { throw TranscriptPreparationError.noAccess }
  }

  /// Called only after the worker has durably saved its complete ready result.
  @discardableResult public func complete(_ assignment: TranscriptPreparationAssignment,
    result: TranscriptPreparationResult) throws -> BlobRef
  {
    try require(replica.identity.id, writer: true, kind: Self.resultKind)
    let current = try current(assignment.revision)
    guard current.worker == replica.identity.id else { throw TranscriptPreparationError.wrongWorker }
    try result.validate()
    guard result.source == "onDevice", result.receipt.recordingDigest == current.request.recordingDigest,
      result.receipt.language == current.request.language, result.receipt.completeness == .complete,
      result.receipt.recordingSource == nil || result.receipt.recordingSource == current.request.recordingSource else {
      throw TranscriptPreparationError.recordingChanged
    }
    let bytes = try Canonical.encode(result)
    if let prior = current.result {
      guard prior.plain == Canonical.digest(bytes) else { throw TranscriptPreparationError.conflictingRequest }
      return prior
    }
    guard !current.cancelled else { throw TranscriptPreparationError.cancelled }
    let blob = try replica.putBlob(bytes, in: Podcasts.namespace)
    // Refresh authority/cancellation after the larger blob write.
    guard !(try self.current(assignment.revision)).cancelled else { throw TranscriptPreparationError.cancelled }
    _ = try replica.perform(Command(namespace: Podcasts.namespace, kind: Self.resultKind,
      payload: ["requestRevision": .string(assignment.revision), "result": blob.json]))
    guard try self.current(assignment.revision).result?.plain == blob.plain else {
      throw TranscriptPreparationError.noAccess
    }
    return blob
  }

  /// Only the requesting app can make a remote result the episode's current reading source.
  /// The caller supplies its retained recording identity; changed bytes keep the result for
  /// review but never acquire the earlier recording's times.
  @discardableResult public func accept(_ assignment: TranscriptPreparationAssignment,
    recordingDigest: String) throws -> SharedTranscriptReference
  {
    try require(replica.identity.id, writer: true, app: true, kind: Podcasts.ContentKind.transcript)
    let current = try self.current(assignment.revision)
    guard current.requester == replica.identity.id else { throw TranscriptPreparationError.noAccess }
    guard !current.cancelled else { throw TranscriptPreparationError.cancelled }
    try require(current.worker, writer: true, kind: Self.resultKind)
    guard current.request.recordingDigest == recordingDigest else { throw TranscriptPreparationError.recordingChanged }
    guard let blob = current.result, let bytes = try replica.blob(blob, in: Podcasts.namespace) else {
      throw TranscriptPreparationError.notReady
    }
    let result = try Canonical.decode(TranscriptPreparationResult.self, from: bytes)
    guard result.source == "onDevice", result.receipt.completeness == .complete,
      result.receipt.language == current.request.language,
      result.receipt.recordingDigest == recordingDigest,
      result.receipt.recordingSource == nil || result.receipt.recordingSource == current.request.recordingSource
    else { throw TranscriptPreparationError.recordingChanged }
    return try apply(request: current.request, result: result, identity: current.revision)
  }

  /// Local and remote application share the same replay receipt in the signed transcript.
  /// A crash after commit is recovered by this check, without re-running recognition.
  @discardableResult public func apply(request: TranscriptPreparationRequest,
    result: TranscriptPreparationResult, identity: String? = nil) throws -> SharedTranscriptReference
  {
    try validateApplicationAccess()
    try result.validate()
    if result.source == "onDevice", result.receipt.completeness != .complete {
      throw TranscriptPreparationError.notReady
    }
    let library = try replica.authority().libraryID
    guard request.libraryID == library else { throw TranscriptPreparationError.invalidSource }
    if let expected = request.recordingDigest, result.source == "onDevice",
      expected != result.receipt.recordingDigest { throw TranscriptPreparationError.recordingChanged }
    let id = identity ?? request.id
    let digest = Canonical.digest(try Canonical.encode(result))
    for entry in try replica.read(Podcasts.namespace).admitted where entry.author == replica.identity.id
      && entry.operation.kind == Podcasts.ContentKind.transcript
      && entry.operation.payload["preparationID"]?.string == id {
      let payload = entry.operation.payload
      guard payload["preparationDigest"]?.string == digest,
        payload["episode"]?.string == request.episode, payload["show"]?.string == request.show,
        let blob = BlobRef(json: payload["blob"]) else { throw TranscriptPreparationError.conflictingRequest }
      return SharedTranscriptReference(libraryID: library, episode: request.episode, show: request.show,
        revision: entry.operation.id, blob: blob)
    }
    var receipt = result.receipt
    if let raw = result.raw { receipt.raw = try replica.putBlob(raw, in: Podcasts.namespace) }
    let document = try replica.putBlob(Canonical.encode(result.document), in: Podcasts.namespace)
    var command = Podcasts.transcript(episode: request.episode, show: request.show, source: result.source,
      language: receipt.language, blob: document, timed: result.document.words?.isEmpty == false,
      audio: receipt.recordingDigest)
    var payload = command.payload
    payload["sourceReceipt"] = try json(receipt)
    payload["preparationID"] = .string(id)
    payload["preparationDigest"] = .string(digest)
    command = Command(namespace: Podcasts.namespace, kind: Podcasts.ContentKind.transcript, payload: payload)
    try Task.checkCancellation()
    let operation = try replica.perform(command)
    let reference = SharedTranscriptReference(libraryID: library, episode: request.episode, show: request.show,
      revision: operation.id, blob: document)
    guard try SharedTranscriptService(replica: replica).references().contains(reference) else {
      throw TranscriptPreparationError.noAccess
    }
    return reference
  }

  public func receipt(for reference: SharedTranscriptReference) throws -> TranscriptSourceReceipt? {
    _ = try SharedTranscriptService(replica: replica).resolve(reference)
    guard let entry = try replica.read(Podcasts.namespace).admitted.first(where: { $0.operation.id == reference.revision }),
      let receipt = entry.operation.payload["sourceReceipt"] else { return nil }
    let decoded = try Canonical.decode(TranscriptSourceReceipt.self, from: Canonical.encode(receipt))
    try decoded.validate(); return decoded
  }

  private func current(_ revision: String) throws -> TranscriptPreparationAssignment {
    guard let assignment = try assignments().first(where: { $0.revision == revision }) else {
      throw TranscriptPreparationError.missingRequest
    }; return assignment
  }
  private func json(_ value: some Encodable) throws -> JSONValue {
    try Canonical.decode(JSONValue.self, from: Canonical.encode(value))
  }
  private func require(_ id: String, writer: Bool = false, app: Bool = false, kind: String? = nil) throws {
    guard let member = try replica.authority().members[id], member.revokedAt == nil,
      let grant = member.current, grant.namespaces.contains(Podcasts.namespace),
      grant.expires.map({ $0 >= .now }) ?? true, !writer || grant.write,
      !app || member.role == .app || member.role == .device else { throw TranscriptPreparationError.noAccess }
    if let kind {
      for caveat in grant.caveats where caveat.namespace == nil || caveat.namespace == Podcasts.namespace {
        guard caveat.kind == Caveat.Kind.kinds.rawValue, caveat.kinds?.contains(kind) == true else {
          throw TranscriptPreparationError.noAccess
        }
      }
    }
  }
}
