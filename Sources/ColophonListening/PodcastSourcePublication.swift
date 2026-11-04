import ColophonAuthority
import ColophonCore
import ColophonReplica
import Foundation

/// Minimal podcast history attested by a producer; never a private item or transcript payload.
public struct PodcastSourceFact: Sendable, Equatable {
  public let sourceActor: String
  public let operationID: String
  public let sourceClock: Int64
  public let sourceDate: Date
  public let sourceDigest: String
  public let kind: String
  public let metadata: [String: JSONValue]
  public let body: [String: JSONValue]
  public init(sourceActor: String, operationID: String, sourceClock: Int64, sourceDate: Date,
    sourceDigest: String, kind: String, metadata: [String: JSONValue], body: [String: JSONValue]) {
    self.sourceActor = sourceActor; self.operationID = operationID; self.sourceClock = sourceClock
    // Match the existing numeric wire representation once. Date's reference epoch
    // otherwise retains finer precision than a Unix-epoch Double can round-trip.
    self.sourceDate = Date(timeIntervalSince1970: sourceDate.timeIntervalSince1970)
    self.sourceDigest = sourceDigest; self.kind = kind
    self.metadata = metadata; self.body = body
  }
  public var key: String { Canonical.digest(Data("org.marginalia.reader\u{0}\(sourceActor)\u{0}\(operationID)".utf8)) }
  var json: JSONValue { .object(["actor": .string(sourceActor), "operationID": .string(operationID),
    "clock": .string(String(sourceClock)), "date": .number(sourceDate.timeIntervalSince1970),
    "sourceDigest": .string(sourceDigest), "kind": .string(kind), "metadata": .object(metadata), "body": .object(body)]) }
  var digest: String { (try? Canonical.digest(Canonical.encode(json))) ?? "" }
}

public struct PodcastSourceAction: Sendable, Equatable {
  public enum Mode: String, Sendable { case baseline, live }
  public let actionID: String
  public let factKey: String
  public let feed: String
  public let guid: String?
  public let rssMemberID: String?
  public let identityFactKey: String?
  public let mode: Mode
  public let expectedRevision: String?
  public init(actionID: String, factKey: String, feed: String, guid: String? = nil,
    rssMemberID: String? = nil, identityFactKey: String? = nil, mode: Mode, expectedRevision: String?) {
    self.actionID = actionID; self.factKey = factKey; self.feed = feed; self.guid = guid
    self.rssMemberID = rssMemberID; self.identityFactKey = identityFactKey; self.mode = mode; self.expectedRevision = expectedRevision
  }
  var json: JSONValue { .object(["actionID": .string(actionID), "factKey": .string(factKey),
    "feed": .string(feed), "guid": JSONValue(guid), "rssMemberID": JSONValue(rssMemberID),
    "identityFactKey": JSONValue(identityFactKey), "mode": .string(mode.rawValue), "expect": JSONValue(expectedRevision)]) }
  var digest: String { (try? Canonical.digest(Canonical.encode(json))) ?? "" }
}

public struct PodcastSourceActionReceipt: Sendable, Equatable {
  /// The signed action retained by the fold, so a producer can recognize an
  /// accepted causal predecessor after reopening without replaying its session.
  public let action: PodcastSourceAction
  public let digest: String
  public let revision: String
  public let applied: Bool
}

public enum PodcastSourcePublication {
  public static let kind = "podcast.source.publish"
  public struct Body: Sendable {
    public let libraryID: String
    public let facts: [PodcastSourceFact]
    public let actions: [PodcastSourceAction]
    public let digest: String
  }
  public enum Failure: Error { case invalid, access, collision, notAdmitted }
  static func text(_ value: String, limit: Int = 4096) -> Bool {
    !value.isEmpty && value.utf8.count <= limit && !value.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
  }
  static func valid(_ fact: PodcastSourceFact) -> Bool {
    let allowed: Set<String>
    switch fact.kind {
    case "item", "follow", "unfollow", "deleteItem": allowed = []
    case "position": allowed = ["seconds", "fraction", "deliberate", "passageAnchor"]
    case "consumption": allowed = ["consumption"]
    case "playbackVisibility": allowed = ["sessionID", "hidden"]
    case "playbackEvidence": allowed = ["sessionID", "startSeconds", "endSeconds", "elapsed", "audioDigest", "started", "ended", "hidden"]
    default: return false
    }
    guard text(fact.sourceActor, limit: 512), text(fact.operationID, limit: 512), fact.sourceClock >= 0,
      fact.sourceDate.timeIntervalSince1970.isFinite, PodcastRecordingIdentity.isDigest(fact.sourceDigest),
      Set(fact.metadata.keys).isSubset(of: ["itemID", "title", "feedID", "feedURL", "guid", "rssMemberIDs"]),
      Set(fact.body.keys).isSubset(of: allowed),
      fact.metadata["itemID"]?.string.map({ text($0, limit: 512) }) == true else { return false }
    for (key, value) in fact.metadata {
      if key == "rssMemberIDs" {
        guard let ids = value.array, ids.count <= 128, ids.allSatisfy({ $0.string.map { text($0, limit: 512) } == true }) else { return false }
      } else if value.string.map({ text($0) }) != true { return false }
    }
    for (key, value) in fact.body {
      if value == .null && ["seconds", "passageAnchor", "audioDigest"].contains(key) { continue }
      switch key {
      case "seconds", "startSeconds", "endSeconds", "elapsed":
        guard let n = value.double, n.isFinite, (0...604800).contains(n) else { return false }
      case "fraction": guard let n = value.double, n.isFinite, (0...1).contains(n) else { return false }
      case "started", "ended": guard let n = value.double, n.isFinite else { return false }
      case "deliberate", "hidden": guard value.bool != nil else { return false }
      case "audioDigest": guard let s = value.string, PodcastRecordingIdentity.isDigest(s) else { return false }
      case "consumption": guard let s = value.string, ["notStarted", "inProgress", "doneEnough", "completed", "abandoned"].contains(s) else { return false }
      default: guard value.string.map({ text($0) }) == true else { return false }
      }
    }
    if fact.kind == "playbackVisibility" { return Set(fact.body.keys) == ["sessionID", "hidden"] }
    if fact.kind == "position" { return fact.body["deliberate"]?.bool != nil && (fact.body["seconds"]?.double != nil || fact.body["fraction"]?.double != nil) }
    if fact.kind == "consumption" { return fact.body["consumption"]?.string != nil }
    if fact.kind == "playbackEvidence" {
      return Set(fact.body.keys).isSuperset(of: ["sessionID", "startSeconds", "endSeconds", "elapsed", "audioDigest", "started", "ended"])
        && (fact.body["ended"]?.double ?? 0) >= (fact.body["started"]?.double ?? 0)
    }
    return true
  }
  /// Evidence remains retained; the latest original visibility mutation controls presentation.
  public static func visibleFacts(_ facts: [PodcastSourceFact]) -> [PodcastSourceFact] {
    let ordered = facts.sorted {
      ($0.sourceClock, $0.sourceActor, $0.operationID) < ($1.sourceClock, $1.sourceActor, $1.operationID)
    }
    var hidden: [String: Bool] = [:]
    for fact in ordered where fact.kind == "playbackVisibility" {
      if let session = fact.body["sessionID"]?.string { hidden[session] = fact.body["hidden"]?.bool }
    }
    return facts.filter { fact in
      if fact.kind == "playbackVisibility" { return false }
      return fact.kind != "playbackEvidence" || hidden[fact.body["sessionID"]?.string ?? ""] != true
    }
  }

  public static func payload(libraryID: String, facts: [PodcastSourceFact], actions: [PodcastSourceAction]) throws -> [String: JSONValue] {
    guard libraryID.count == 32, libraryID.allSatisfy({ $0.isHexDigit && !$0.isUppercase }),
      facts.count <= 128, actions.count <= 128, !facts.isEmpty || !actions.isEmpty,
      Set(facts.map(\.key)).count == facts.count, Set(actions.map(\.actionID)).count == actions.count,
      facts.allSatisfy(valid), actions.allSatisfy({ a in
        text(a.actionID, limit: 128) && PodcastRecordingIdentity.isDigest(a.factKey)
          && URL(string: a.feed).map { ["http", "https"].contains($0.scheme ?? "") && $0.host != nil && $0.user == nil && $0.password == nil } == true
          && text(a.feed) && (a.guid.map { text($0) } ?? true)
          && (a.identityFactKey.map { PodcastRecordingIdentity.isDigest($0) } ?? true)
          && (a.rssMemberID.map { text($0, limit: 512) } ?? true)
          && (a.expectedRevision.map { text($0, limit: 512) } ?? true)
      }) else { throw Failure.invalid }
    let body: [String: JSONValue] = ["version": .number(1), "libraryID": .string(libraryID),
      "facts": .array(facts.map(\.json)), "actions": .array(actions.map(\.json))]
    let bytes = try Canonical.encode(body)
    guard bytes.count <= 2 * 1024 * 1024 else { throw Failure.invalid }
    return body.merging(["digest": .string(Canonical.digest(bytes))]) { _, n in n }
  }
  public static func decode(_ operation: ColophonOperation) -> Body? {
    let p = operation.payload
    guard operation.v == 1, operation.kind == kind, Set(p.keys) == ["version", "libraryID", "facts", "actions", "digest"],
      p["version"]?.int == 1, let library = p["libraryID"]?.string,
      let fs = p["facts"]?.array, fs.count <= 128, let acts = p["actions"]?.array, acts.count <= 128, let digest = p["digest"]?.string else { return nil }
    let facts = fs.compactMap { value -> PodcastSourceFact? in
      guard let o = value.object, Set(o.keys) == ["actor", "operationID", "clock", "date", "sourceDigest", "kind", "metadata", "body"],
        let actor = o["actor"]?.string, let id = o["operationID"]?.string, let clockText = o["clock"]?.string, let clock = Int64(clockText),
        let date = o["date"]?.double, let hash = o["sourceDigest"]?.string, let kind = o["kind"]?.string,
        let metadata = o["metadata"]?.object, let body = o["body"]?.object else { return nil }
      return PodcastSourceFact(sourceActor: actor, operationID: id, sourceClock: clock, sourceDate: Date(timeIntervalSince1970: date), sourceDigest: hash, kind: kind, metadata: metadata, body: body)
    }
    let actions = acts.compactMap { value -> PodcastSourceAction? in
      guard let o = value.object, Set(o.keys) == ["actionID", "factKey", "feed", "guid", "rssMemberID", "identityFactKey", "mode", "expect"],
        let id = o["actionID"]?.string, let key = o["factKey"]?.string, let feed = o["feed"]?.string,
        let raw = o["mode"]?.string, let mode = PodcastSourceAction.Mode(rawValue: raw),
        ["guid", "rssMemberID", "identityFactKey", "expect"].allSatisfy({ o[$0] == .null || o[$0]?.string != nil }) else { return nil }
      return PodcastSourceAction(actionID: id, factKey: key, feed: feed, guid: o["guid"]?.string, rssMemberID: o["rssMemberID"]?.string, identityFactKey: o["identityFactKey"]?.string, mode: mode, expectedRevision: o["expect"]?.string)
    }
    guard facts.count == fs.count, actions.count == acts.count,
      (try? payload(libraryID: library, facts: facts, actions: actions)) == p else { return nil }
    return Body(libraryID: library, facts: facts, actions: actions, digest: digest)
  }
}

public struct PodcastSourcePublicationService {
  public let replica: Replica
  public init(replica: Replica) { self.replica = replica }
  @discardableResult public func publish(libraryID: String, facts: [PodcastSourceFact], actions: [PodcastSourceAction]) throws -> String {
    let payload = try PodcastSourcePublication.payload(libraryID: libraryID, facts: facts, actions: actions)
    let authority = try replica.authority()
    guard authority.libraryID == libraryID, let member = authority.members[replica.identity.id], member.revokedAt == nil,
      member.role == .app || member.role == .device, let grant = member.current, grant.write,
      grant.namespaces.contains(Podcasts.namespace), grant.expires.map({ $0 >= .now }) ?? true else { throw PodcastSourcePublication.Failure.access }
    let state = try replica.state(of: Podcasts.self)
    guard state.acceptsSource(facts: facts, actions: actions) else { throw PodcastSourcePublication.Failure.collision }
    let digest = payload["digest"]?.string ?? ""
    if state.podcastSourceReceipts.contains(digest) { return digest }
    _ = try replica.perform(Command(namespace: Podcasts.namespace, kind: PodcastSourcePublication.kind, payload: payload))
    guard try replica.state(of: Podcasts.self).podcastSourceReceipts.contains(digest) else { throw PodcastSourcePublication.Failure.notAdmitted }
    return digest
  }
}
