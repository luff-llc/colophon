import ColophonAuthority
import ColophonCore
import ColophonReplica
import Foundation

/// An importer-attested saved state, never a fabricated historical playback event.
public struct LegacyPodcastStateRecord: Sendable, Equatable {
  public let legacyID: String
  public let feed: String
  public let guid: String
  public let rssLegacyID: String
  public let seconds: Double?
  public let consumption: String?
  public let updated: Date
  public var episodeID: String { Podcasts.episodeID(feed: feed, guid: guid) }
  public var showID: String { Podcasts.showID(feed: feed) }

  public init(legacyID: String, feed: String, guid: String, rssLegacyID: String? = nil,
    seconds: Double?, consumption: String?, updated: Date) {
    self.legacyID = legacyID; self.feed = feed; self.guid = guid
    self.seconds = seconds; self.consumption = consumption; self.updated = updated
    self.rssLegacyID = rssLegacyID ?? legacyID
  }

  var json: JSONValue { .object([
    "legacyID": .string(legacyID), "feed": .string(feed), "guid": .string(guid),
    "rssLegacyID": .string(rssLegacyID),
    "seconds": JSONValue(seconds), "consumption": JSONValue(consumption),
    "updated": .number(updated.timeIntervalSince1970),
  ]) }
  public var digest: String { get throws { Canonical.digest(try Canonical.encode(json)) } }
}

/// Separate versioned operation: the original feed-only v1 bridge retains its exact wire bytes.
/// Old clients retain/hold this unknown kind; progress becomes visible when they update.
public enum LegacyPodcastStateImport {
  public static let kind = "legacy.podcastState.import"
  public static let maximumRecords = 500
  public static let maximumBytes = 2 * 1_024 * 1_024

  public struct Body: Sendable {
    public let libraryID: String
    public let lineageID: String
    public let sourceRoot: String
    public let records: [LegacyPodcastStateRecord]
    public let digest: String
  }

  public static func recordKey(lineageID: String, sourceRoot: String, legacyID: String) -> String {
    lineageID + ":" + sourceRoot + ":" + legacyID
  }

  public static func payload(libraryID: String, lineageID: String, sourceRoot: String,
    records: [LegacyPodcastStateRecord]) throws -> [String: JSONValue] {
    guard libraryID.count == 32, libraryID.allSatisfy({ $0.isHexDigit && !$0.isUppercase }),
      UUID(uuidString: lineageID)?.uuidString.lowercased() == lineageID,
      PodcastRecordingIdentity.isDigest(sourceRoot), !records.isEmpty, records.count <= maximumRecords,
      records == records.sorted(by: { $0.legacyID < $1.legacyID }),
      Set(records.map(\.legacyID)).count == records.count,
      Set(records.map(\.episodeID)).count == records.count
    else { throw LegacyBridgeImportError.invalidCommand }
    for record in records {
      guard !record.legacyID.isEmpty, record.legacyID.utf8.count <= 512,
        !record.legacyID.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains),
        record.rssLegacyID == Canonical.digest(Data((record.feed + "|" + record.guid).utf8)),
        !record.guid.isEmpty, record.guid.utf8.count <= 4_096,
        record.feed.utf8.count <= 4_096,
        let url = URL(string: record.feed), ["https", "http"].contains(url.scheme?.lowercased() ?? ""),
        url.host?.isEmpty == false, url.user == nil, url.password == nil,
        record.seconds.map({ $0.isFinite && (0...604_800).contains($0) }) ?? true,
        record.consumption.map({ ["notStarted", "inProgress", "doneEnough", "completed", "abandoned"].contains($0) }) ?? true,
        record.seconds != nil || record.consumption != nil,
        record.updated.timeIntervalSince1970.isFinite
      else { throw LegacyBridgeImportError.invalidCommand }
    }
    let body: [String: JSONValue] = ["version": .number(1), "libraryID": .string(libraryID),
      "lineageID": .string(lineageID), "sourceRoot": .string(sourceRoot),
      "records": .array(records.map(\.json))]
    let bytes = try Canonical.encode(body)
    guard bytes.count <= maximumBytes else { throw LegacyBridgeImportError.invalidCommand }
    return body.merging(["digest": .string(Canonical.digest(bytes))]) { _, new in new }
  }

  public static func decode(_ operation: ColophonOperation) -> Body? {
    let p = operation.payload
    guard operation.v == 1, operation.kind == kind,
      Set(p.keys) == ["version", "libraryID", "lineageID", "sourceRoot", "records", "digest"],
      p["version"]?.int == 1, let library = p["libraryID"]?.string,
      let lineage = p["lineageID"]?.string, let root = p["sourceRoot"]?.string,
      let values = p["records"]?.array, !values.isEmpty, values.count <= maximumRecords,
      let digest = p["digest"]?.string else { return nil }
    let records = values.compactMap { value -> LegacyPodcastStateRecord? in
      guard let o = value.object,
        Set(o.keys) == ["legacyID", "feed", "guid", "rssLegacyID", "seconds", "consumption", "updated"],
        let id = o["legacyID"]?.string, let feed = o["feed"]?.string,
        let guid = o["guid"]?.string, let rss = o["rssLegacyID"]?.string, let date = o["updated"]?.double,
        o["seconds"] == .null || o["seconds"]?.double != nil,
        o["consumption"] == .null || o["consumption"]?.string != nil else { return nil }
      return LegacyPodcastStateRecord(legacyID: id, feed: feed, guid: guid, rssLegacyID: rss,
        seconds: o["seconds"]?.double, consumption: o["consumption"]?.string,
        updated: Date(timeIntervalSince1970: date))
    }
    guard records.count == values.count,
      let rebuilt = try? payload(libraryID: library, lineageID: lineage, sourceRoot: root, records: records),
      rebuilt == p else { return nil }
    return Body(libraryID: library, lineageID: lineage, sourceRoot: root, records: records, digest: digest)
  }
}

public struct LegacyPodcastStateImportService {
  public let replica: Replica
  public init(replica: Replica) { self.replica = replica }

  /// The source must already have its verified retained capsule and signed feed receipt.
  /// Replays, including a restart after an uncertain write, add no further operation.
  @discardableResult public func commit(libraryID: String, lineageID: String, sourceRoot: String,
    records: [LegacyPodcastStateRecord]) throws -> String {
    let payload = try LegacyPodcastStateImport.payload(libraryID: libraryID, lineageID: lineageID,
      sourceRoot: sourceRoot, records: records)
    let authority = try replica.authority()
    guard authority.libraryID == libraryID,
      let member = authority.members[replica.identity.id], member.revokedAt == nil,
      member.role == .app || member.role == .device,
      let grant = member.current, grant.write, grant.namespaces.contains(Podcasts.namespace),
      grant.expires.map({ $0 >= .now }) ?? true
    else { throw LegacyBridgeImportError.noCurrentAccess }
    let state = try replica.state(of: Podcasts.self)
    let root = LegacyBridgeImport.rootKey(lineageID, sourceRoot)
    guard let receipt = state.legacyBridgeRootReceipts[root], receipt.sourceDescriptor == nil else {
      throw LegacyBridgeImportError.sourceRootConflict
    }
    let reviewedShows = Set(receipt.appliedShowIDs + receipt.skippedShowIDs)
    guard records.allSatisfy({ reviewedShows.contains($0.showID) }) else {
      throw LegacyBridgeImportError.invalidCommand
    }
    for record in records {
      let key = LegacyPodcastStateImport.recordKey(lineageID: lineageID, sourceRoot: sourceRoot, legacyID: record.legacyID)
      if let old = state.legacyPodcastStateDigests[key], old != (try record.digest) {
        throw LegacyBridgeImportError.sourceRecordConflict
      }
    }
    let digest = payload["digest"]?.string ?? ""
    if state.legacyPodcastStateReceipts.contains(digest) { return digest }
    _ = try replica.perform(Command(namespace: Podcasts.namespace, kind: LegacyPodcastStateImport.kind, payload: payload))
    guard try replica.state(of: Podcasts.self).legacyPodcastStateReceipts.contains(digest) else {
      throw LegacyBridgeImportError.notAdmitted
    }
    return digest
  }
}
