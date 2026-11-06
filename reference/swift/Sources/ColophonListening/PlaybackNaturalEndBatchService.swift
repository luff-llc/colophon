import ColophonAuthority
import ColophonCore
import ColophonReplica
import Foundation

/// One signed operation settles the exact natural ends and raw queue snapshot captured by
/// playback. A receipt is keyed by each event, so a retry can survive individual journal ACKs.
/// This is an ordered local fold, not a distributed compare-and-swap.
public enum PlaybackNaturalEndBatch {
  public static let kind = "playback.naturalEnd.batch"
  public static let maximumEvents = 16
  public static let maximumQueueEntries = 1_024
  public static let maximumBodyBytes = 65_536

  public struct EndEvent: Codable, Sendable, Equatable {
    public let eventID: String
    public let episodeID: String
    public let showID: String
    public let audioIdentity: String
    public let endSeconds: Double
    public let actualDuration: Double
    public let expectedPositionRevision: String?
    public let expectedStateRevision: String?

    public init(eventID: String, episodeID: String, showID: String, audioIdentity: String,
      endSeconds: Double, actualDuration: Double, expectedPositionRevision: String?,
      expectedStateRevision: String?) {
      self.eventID = eventID
      self.episodeID = episodeID
      self.showID = showID
      self.audioIdentity = audioIdentity
      self.endSeconds = endSeconds
      self.actualDuration = actualDuration
      self.expectedPositionRevision = expectedPositionRevision
      self.expectedStateRevision = expectedStateRevision
    }
  }

  public struct Body: Sendable {
    public let libraryID: String
    public let events: [EndEvent]
    public let baseQueue: [String]
    public let expectedQueueRevision: String?
  }

  private static func validText(_ text: String, maximum: Int) -> Bool {
    !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && text.utf8.count <= maximum
      && !text.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
  }

  private static func valid(_ event: EndEvent) -> Bool {
    validText(event.eventID, maximum: 128) && validText(event.episodeID, maximum: 256)
      && validText(event.showID, maximum: 256) && validText(event.audioIdentity, maximum: 512)
      && event.endSeconds.isFinite && event.actualDuration.isFinite
      && event.actualDuration > 0 && event.actualDuration <= 604_800
      && event.endSeconds == event.actualDuration
      && QueuedEpisodeMetadata.validRevision(JSONValue(event.expectedPositionRevision))
      && QueuedEpisodeMetadata.validRevision(JSONValue(event.expectedStateRevision))
  }

  private static func eventJSON(_ event: EndEvent) -> [String: JSONValue] {
    ["eventID": .string(event.eventID), "episode": .string(event.episodeID),
      "show": .string(event.showID), "audio": .string(event.audioIdentity),
      "endSeconds": .number(event.endSeconds), "actualDuration": .number(event.actualDuration),
      "expectedPosition": JSONValue(event.expectedPositionRevision),
      "expectedState": JSONValue(event.expectedStateRevision)]
  }

  /// The receipt binds one event to its original library and queue capture. A subset retry
  /// after another event's journal ACK passes the same context and gets the same digest.
  public static func eventDigest(_ event: EndEvent, libraryID: String, baseQueue: [String],
    expectedQueueRevision: String?) throws -> String {
    guard valid(event), validContext(libraryID: libraryID, baseQueue: baseQueue,
      expectedQueueRevision: expectedQueueRevision) else {
      throw PlaybackNaturalEndBatchError.invalidCommand
    }
    let meaning: [String: JSONValue] = [
      "event": .object(eventJSON(event)), "libraryID": .string(libraryID),
      "baseQueue": .array(baseQueue.map(JSONValue.string)),
      "expectedQueueRevision": JSONValue(expectedQueueRevision),
    ]
    return Canonical.digest(try Canonical.encode(meaning))
  }

  private static func validContext(libraryID: String, baseQueue: [String],
    expectedQueueRevision: String?) -> Bool {
    validText(libraryID, maximum: 256) && baseQueue.count <= maximumQueueEntries
      && baseQueue.allSatisfy { validText($0, maximum: 256) }
      && QueuedEpisodeMetadata.validRevision(JSONValue(expectedQueueRevision))
  }

  public static func payload(libraryID: String, events: [EndEvent], baseQueue: [String],
    expectedQueueRevision: String?) throws -> [String: JSONValue] {
    guard validContext(libraryID: libraryID, baseQueue: baseQueue,
        expectedQueueRevision: expectedQueueRevision),
      !events.isEmpty, events.count <= maximumEvents,
      events.allSatisfy(valid), Set(events.map(\.eventID)).count == events.count,
      Set(events.map(\.episodeID)).count == events.count
    else { throw PlaybackNaturalEndBatchError.invalidCommand }
    let body: [String: JSONValue] = [
      "libraryID": .string(libraryID),
      "events": .array(events.map { .object(eventJSON($0)) }),
      "baseQueue": .array(baseQueue.map(JSONValue.string)),
      "expectedQueueRevision": JSONValue(expectedQueueRevision),
      // Admission caveats inspect top-level integer fields before the domain fold. Charge
      // the conservative sum once per signed batch, including subsecond end durations.
      "seconds": .number(ceil(events.reduce(0) { $0 + $1.endSeconds })),
      "duration": .number(ceil(events.reduce(0) { $0 + $1.actualDuration })),
    ]
    let bytes = try Canonical.encode(body)
    guard bytes.count <= maximumBodyBytes else { throw PlaybackNaturalEndBatchError.invalidCommand }
    return body.merging(["bodyDigest": .string(Canonical.digest(bytes))]) { _, newer in newer }
  }

  public static func decode(_ operation: ColophonOperation) -> Body? {
    guard operation.kind == kind, operation.v == 1,
      Set(operation.payload.keys) == ["libraryID", "events", "baseQueue", "expectedQueueRevision",
        "seconds", "duration", "bodyDigest"],
      let libraryID = operation.payload["libraryID"]?.string,
      let rawEvents = operation.payload["events"]?.array,
      let rawQueue = operation.payload["baseQueue"]?.array,
      !rawEvents.isEmpty, rawEvents.count <= maximumEvents,
      rawQueue.count <= maximumQueueEntries,
      operation.payload["seconds"]?.int != nil, operation.payload["duration"]?.int != nil,
      let expectedRaw = operation.payload["expectedQueueRevision"],
      let claimedDigest = operation.payload["bodyDigest"]?.string,
      QueuedEpisodeMetadata.validRevision(expectedRaw)
    else { return nil }
    let expectedQueueRevision = expectedRaw.string
    let queue = rawQueue.compactMap(\.string)
    guard queue.count == rawQueue.count else { return nil }
    let events = rawEvents.compactMap { raw -> EndEvent? in
      guard let fields = raw.object,
        Set(fields.keys) == ["eventID", "episode", "show", "audio", "endSeconds", "actualDuration",
          "expectedPosition", "expectedState"],
        let eventID = fields["eventID"]?.string, let episode = fields["episode"]?.string,
        let show = fields["show"]?.string, let audio = fields["audio"]?.string,
        let end = fields["endSeconds"]?.double, let duration = fields["actualDuration"]?.double,
        QueuedEpisodeMetadata.validRevision(fields["expectedPosition"]),
        QueuedEpisodeMetadata.validRevision(fields["expectedState"])
      else { return nil }
      return EndEvent(eventID: eventID, episodeID: episode, showID: show, audioIdentity: audio,
        endSeconds: end, actualDuration: duration,
        expectedPositionRevision: fields["expectedPosition"]?.string,
        expectedStateRevision: fields["expectedState"]?.string)
    }
    guard events.count == rawEvents.count,
      let reconstructed = try? payload(libraryID: libraryID, events: events, baseQueue: queue,
        expectedQueueRevision: expectedQueueRevision),
      reconstructed == operation.payload, reconstructed["bodyDigest"]?.string == claimedDigest
    else { return nil }
    return Body(libraryID: libraryID, events: events, baseQueue: queue,
      expectedQueueRevision: expectedQueueRevision)
  }

  public static func signerKey(_ signer: String, _ eventID: String) -> String {
    PlaybackPreferenceBatch.signerKey(signer, eventID)
  }
}

public struct PlaybackNaturalEndReceipt: Sendable, Equatable {
  public enum Outcome: Sendable, Equatable { case applied, stale }
  public let eventID: String
  public let authorID: String
  public let operationID: String
  public let revision: String
  public let digest: String
  public let outcome: Outcome
}

public enum PlaybackNaturalEndBatchError: Error, Equatable {
  case invalidCommand, noCurrentAccess, wrongRole, eventIDConflict, notAdmitted
}

public struct PlaybackNaturalEndBatchService {
  public let replica: Replica
  public init(replica: Replica) { self.replica = replica }

  /// Retry with the same captured events and raw queue, including their original revisions.
  /// An already receipted event returns its prior result without another signed mutation.
  @discardableResult public func commit(events: [PlaybackNaturalEndBatch.EndEvent], baseQueue: [String],
    expectedQueueRevision: String?) throws -> [PlaybackNaturalEndReceipt] {
    try requireCurrentWriter()
    let libraryID = try replica.authority().libraryID
    let payload = try PlaybackNaturalEndBatch.payload(libraryID: libraryID, events: events,
      baseQueue: baseQueue, expectedQueueRevision: expectedQueueRevision)
    let signer = replica.identity.id
    let before = try replica.state(of: Podcasts.self)
    var existing: [PlaybackNaturalEndReceipt] = []
    for event in events {
      let key = PlaybackNaturalEndBatch.signerKey(signer, event.eventID)
      guard !before.naturalEndEventConflicts.contains(key) else {
        throw PlaybackNaturalEndBatchError.eventIDConflict
      }
      if let receipt = before.naturalEndReceipts[key] {
        guard receipt.digest == (try PlaybackNaturalEndBatch.eventDigest(event,
          libraryID: libraryID, baseQueue: baseQueue,
          expectedQueueRevision: expectedQueueRevision)) else {
          throw PlaybackNaturalEndBatchError.eventIDConflict
        }
        existing.append(receipt)
      }
    }
    if existing.count == events.count { return existing }
    let operation = try replica.perform(Command(namespace: Podcasts.namespace,
      kind: PlaybackNaturalEndBatch.kind, payload: payload))
    let after = try replica.state(of: Podcasts.self)
    let revision = PlaybackPreferenceBatch.revision(authorID: signer, operation: operation)
    return try events.map { event in
      let key = PlaybackNaturalEndBatch.signerKey(signer, event.eventID)
      guard !after.naturalEndEventConflicts.contains(key),
        let receipt = after.naturalEndReceipts[key],
        receipt.digest == (try PlaybackNaturalEndBatch.eventDigest(event,
          libraryID: libraryID, baseQueue: baseQueue,
          expectedQueueRevision: expectedQueueRevision)),
        receipt.revision == revision || existing.contains(receipt)
      else { throw PlaybackNaturalEndBatchError.notAdmitted }
      return receipt
    }
  }

  private func requireCurrentWriter() throws {
    let authority = try replica.authority()
    guard let member = authority.members[replica.identity.id], member.revokedAt == nil,
      let grant = member.current, grant.write, grant.namespaces.contains(Podcasts.namespace),
      grant.expires.map({ $0 > .now }) ?? true
    else { throw PlaybackNaturalEndBatchError.noCurrentAccess }
    guard member.role == .app || member.role == .device else { throw PlaybackNaturalEndBatchError.wrongRole }
    for caveat in grant.caveats where caveat.namespace == nil || caveat.namespace == Podcasts.namespace {
      switch Caveat.Kind(rawValue: caveat.kind) {
      case .kinds:
        guard caveat.kinds?.contains(PlaybackNaturalEndBatch.kind) == true else {
          throw PlaybackNaturalEndBatchError.noCurrentAccess
        }
      case .ceiling, .budget:
        guard caveat.field != nil, caveat.max != nil else {
          throw PlaybackNaturalEndBatchError.noCurrentAccess
        }
      case nil: throw PlaybackNaturalEndBatchError.noCurrentAccess
      }
    }
  }
}
