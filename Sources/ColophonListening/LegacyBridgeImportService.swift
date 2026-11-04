import ColophonAuthority
import ColophonCore
import ColophonReplica
import Foundation

/// The small, signed podcast projection of a separately verified Marginalia bridge export.
/// The complete legacy archive and its inventory remain local to the importing client.
public struct LegacyPodcastFeedCrosswalk: Codable, Sendable, Equatable {
  public let legacyID: String
  public let feedURL: String
  public let title: String
  public let targetShowID: String

  public init(legacyID: String, feedURL: String, title: String, targetShowID: String) {
    self.legacyID = legacyID
    self.feedURL = feedURL
    self.title = title
    self.targetShowID = targetShowID
  }
}

/// Only identities and canonical content hashes of old subscription mutations participating
/// in the shared feed projection. This is not the full legacy operation inventory.
public struct LegacyBridgeOperationDigest: Codable, Sendable, Equatable {
  public let operationID: String
  public let digest: String

  public init(operationID: String, digest: String) {
    self.operationID = operationID
    self.digest = digest
  }
}

/// An importer-signed description of a locally retained podcast source file. The semantic facts
/// root also commits to the raw evidence digest, not just parsed facts. This is not a provider
/// signature, account identity, legacy operation proof, or verified listening history. The file
/// and its full facts remain in the importing client's capsule.
public struct LegacyBridgeSourceDescriptor: Codable, Sendable, Equatable {
  public enum Format: String, Codable, Sendable {
    case opmlSubscriptionsV1 = "opml-subscriptions-v1"
    case overcastAllDataV1 = "overcast-all-data-v1"
  }

  public let format: Format
  public let rawSourceDigest: String
  public let semanticFactsRoot: String
  public let lineageSemantics: String

  public init(format: Format, rawSourceDigest: String, semanticFactsRoot: String,
    lineageSemantics: String = "immutable-file-snapshot")
  {
    self.format = format
    self.rawSourceDigest = rawSourceDigest
    self.semanticFactsRoot = semanticFactsRoot
    self.lineageSemantics = lineageSemantics
  }
}

public struct LegacyBridgeImportReceipt: Sendable, Equatable {
  public enum Outcome: Sendable, Equatable { case applied, stale, conflict, reused }
  public let commandID: String
  public let authorID: String
  public let operationID: String
  public let revision: String
  public let targetLibraryID: String
  public let lineageID: String
  public let sourceRoot: String
  public let crosswalkDigest: String
  public let sharedInventoryDigest: String
  public let sourceDescriptor: LegacyBridgeSourceDescriptor?
  public let commandDigest: String
  public let outcome: Outcome
  public let appliedShowIDs: [String]
  public let skippedShowIDs: [String]
}

public enum LegacyBridgeImportError: LocalizedError, Equatable {
  case invalidCommand, noCurrentAccess, wrongRole, commandIDConflict, sourceRootConflict,
    sourceRecordConflict, notAdmitted

  public var errorDescription: String? {
    switch self {
    case .invalidCommand:
      "This bridge plan is invalid, targets another library, or exceeds the import limit. Review the source package."
    case .noCurrentAccess:
      "This device no longer has permission to import into this library. The retained source remains available."
    case .wrongRole:
      "Only a library app or device can import this bridge."
    case .commandIDConflict:
      "This import request ID was already used for different content. Start a new reviewed import."
    case .sourceRootConflict:
      "This legacy lineage has a different source history or crosswalk. Keep the archive and review the conflict."
    case .sourceRecordConflict:
      "A previously imported legacy podcast record changed or is missing. Keep the archive and review the conflict."
    case .notAdmitted:
      "The signed import was not admitted by this library. Check its access and retry only after review."
    }
  }
}

/// One bounded version-1 bridge command. Its digest covers all expected heads, so a retry with
/// the same command ID cannot quietly change the crosswalk or overwrite a newer local show.
public enum LegacyBridgeImport {
  public static let kind = "legacy.bridge.import"
  public static let maximumFeeds = 2_000
  public static let maximumSharedOperations = 256
  public static let maximumBodyBytes = 2 * 1_024 * 1_024

  public struct Body: Sendable, Equatable {
    public let commandID: String
    public let commandDigest: String
    public let targetLibraryID: String
    public let lineageID: String
    public let sourceRoot: String
    public let parentSourceRoot: String?
    public let crosswalkDigest: String
    public let sharedOperationInventory: [LegacyBridgeOperationDigest]
    public let sharedInventoryDigest: String
    public let sourceDescriptor: LegacyBridgeSourceDescriptor?
    public let feeds: [LegacyPodcastFeedCrosswalk]
    public let expectedLineageRoot: String?
    public let expectedShowHeads: [String: String?]
  }

  private static func hex64(_ value: String) -> Bool {
    value.utf8.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
  }

  private static func hex32(_ value: String) -> Bool {
    value.utf8.count == 32 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
  }

  private static func validRevision(_ value: String?) -> Bool {
    value.map { !$0.isEmpty && $0.utf8.count <= 160 } ?? true
  }

  private static func validLineage(_ value: String) -> Bool {
    UUID(uuidString: value).map { $0.uuidString.lowercased() == value } ?? false
  }

  private static func feedJSON(_ feeds: [LegacyPodcastFeedCrosswalk]) -> [JSONValue] {
    feeds.map { feed in .object([
      "legacyID": .string(feed.legacyID), "feedURL": .string(feed.feedURL),
      "title": .string(feed.title), "targetShowID": .string(feed.targetShowID),
    ]) }
  }

  private static func inventoryJSON(_ inventory: [LegacyBridgeOperationDigest]) -> [JSONValue] {
    inventory.map { .object(["operationID": .string($0.operationID), "digest": .string($0.digest)]) }
  }

  private static func descriptorJSON(_ descriptor: LegacyBridgeSourceDescriptor) -> JSONValue {
    .object([
      "format": .string(descriptor.format.rawValue),
      "rawSourceDigest": .string(descriptor.rawSourceDigest),
      "semanticFactsRoot": .string(descriptor.semanticFactsRoot),
      "lineageSemantics": .string(descriptor.lineageSemantics),
    ])
  }

  private static func sourceDescriptor(_ value: JSONValue) -> LegacyBridgeSourceDescriptor? {
    guard let object = value.object,
      Set(object.keys) == ["format", "rawSourceDigest", "semanticFactsRoot", "lineageSemantics"],
      let rawFormat = object["format"]?.string,
      let format = LegacyBridgeSourceDescriptor.Format(rawValue: rawFormat),
      let rawSourceDigest = object["rawSourceDigest"]?.string,
      let semanticFactsRoot = object["semanticFactsRoot"]?.string,
      let lineageSemantics = object["lineageSemantics"]?.string
    else { return nil }
    return LegacyBridgeSourceDescriptor(format: format, rawSourceDigest: rawSourceDigest,
      semanticFactsRoot: semanticFactsRoot, lineageSemantics: lineageSemantics)
  }

  private static func validSourceDescriptor(_ descriptor: LegacyBridgeSourceDescriptor,
    lineageID: String, sourceRoot: String, parentSourceRoot: String?,
    sharedOperationInventory: [LegacyBridgeOperationDigest], expectedLineageRoot: String?) -> Bool
  {
    guard hex64(descriptor.rawSourceDigest), hex64(descriptor.semanticFactsRoot),
      descriptor.semanticFactsRoot == sourceRoot,
      descriptor.lineageSemantics == "immutable-file-snapshot",
      parentSourceRoot == nil, sharedOperationInventory.isEmpty,
      expectedLineageRoot == nil || expectedLineageRoot == sourceRoot
    else { return false }
    let seed = "org.marginalia.podcast-source.snapshot.v1\n" + descriptor.format.rawValue + "\n"
      + descriptor.rawSourceDigest
    let hash = Array(Canonical.digest(Data(seed.utf8)).prefix(32))
    let derived = String(hash[0..<8]) + "-" + String(hash[8..<12]) + "-" + String(hash[12..<16])
      + "-" + String(hash[16..<20]) + "-" + String(hash[20..<32])
    return lineageID == derived
  }

  private static func validInventory(_ inventory: [LegacyBridgeOperationDigest]) -> Bool {
    guard inventory.count <= maximumSharedOperations,
      inventory == inventory.sorted(by: { $0.operationID < $1.operationID }),
      Set(inventory.map(\.operationID)).count == inventory.count
    else { return false }
    return inventory.allSatisfy { record in
      !record.operationID.isEmpty && record.operationID.utf8.count <= 128
        && !record.operationID.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
        && hex64(record.digest)
    }
  }

  /// Same canonical field names and sorted-key JSON as the versioned source manifest.
  public static func crosswalkDigest(_ feeds: [LegacyPodcastFeedCrosswalk]) throws -> String {
    Canonical.digest(try Canonical.encode(JSONValue.array(feedJSON(feeds))))
  }

  private static func validFeeds(_ feeds: [LegacyPodcastFeedCrosswalk]) -> Bool {
    guard !feeds.isEmpty, feeds.count <= maximumFeeds,
      feeds == feeds.sorted(by: { ($0.feedURL, $0.legacyID) < ($1.feedURL, $1.legacyID) }),
      Set(feeds.map(\.legacyID)).count == feeds.count,
      Set(feeds.map(\.targetShowID)).count == feeds.count
    else { return false }
    return feeds.allSatisfy { feed in
      guard feed.legacyID.utf8.count <= 512, !feed.legacyID.isEmpty,
        !feed.legacyID.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains),
        feed.feedURL.utf8.count <= 4_096,
        feed.title.utf8.count <= 2_048,
        feed.targetShowID == Podcasts.showID(feed: feed.feedURL),
        let url = URL(string: feed.feedURL),
        ["https", "http"].contains(url.scheme?.lowercased() ?? ""),
        url.host?.isEmpty == false, url.user == nil, url.password == nil
      else { return false }
      return true
    }
  }

  private static func bodyJSON(targetLibraryID: String, lineageID: String, sourceRoot: String, parentSourceRoot: String?,
    feeds: [LegacyPodcastFeedCrosswalk], sharedOperationInventory: [LegacyBridgeOperationDigest],
    expectedLineageRoot: String?, expectedShowHeads: [String: String?],
    sourceDescriptor: LegacyBridgeSourceDescriptor?)
    throws -> [String: JSONValue]
  {
    let crosswalkDigest = try crosswalkDigest(feeds)
    let sharedInventoryDigest = Canonical.digest(try Canonical.encode(JSONValue.array(inventoryJSON(sharedOperationInventory))))
    var body: [String: JSONValue] = [
      "bridgeVersion": .number(1), "crosswalkVersion": .number(1),
      "targetLibraryID": .string(targetLibraryID), "lineageID": .string(lineageID), "sourceRoot": .string(sourceRoot),
      "parentSourceRoot": JSONValue(parentSourceRoot), "crosswalkDigest": .string(crosswalkDigest),
      "feeds": .array(feedJSON(feeds)), "sharedOperationInventory": .array(inventoryJSON(sharedOperationInventory)),
      "sharedInventoryDigest": .string(sharedInventoryDigest), "expectedLineageRoot": JSONValue(expectedLineageRoot),
      "expectedShowHeads": .object(expectedShowHeads.mapValues { JSONValue($0) }),
    ]
    if let sourceDescriptor { body["sourceDescriptor"] = descriptorJSON(sourceDescriptor) }
    return body
  }

  public static func payload(targetLibraryID: String, lineageID: String, sourceRoot: String, parentSourceRoot: String?,
    feeds: [LegacyPodcastFeedCrosswalk], sharedOperationInventory: [LegacyBridgeOperationDigest],
    expectedLineageRoot: String?, expectedShowHeads: [String: String?],
    commandID: String, sourceDescriptor: LegacyBridgeSourceDescriptor? = nil) throws -> [String: JSONValue]
  {
    guard hex32(targetLibraryID),
      validLineage(lineageID), hex64(sourceRoot), parentSourceRoot.map(hex64) ?? true,
      expectedLineageRoot.map(hex64) ?? true,
      !commandID.isEmpty, commandID.utf8.count <= 128,
      validFeeds(feeds), validInventory(sharedOperationInventory),
      Set(expectedShowHeads.keys) == Set(feeds.map(\.targetShowID)),
      expectedShowHeads.values.allSatisfy(validRevision)
    else { throw LegacyBridgeImportError.invalidCommand }
    if let sourceDescriptor {
      guard validSourceDescriptor(sourceDescriptor, lineageID: lineageID, sourceRoot: sourceRoot,
        parentSourceRoot: parentSourceRoot, sharedOperationInventory: sharedOperationInventory,
        expectedLineageRoot: expectedLineageRoot)
      else { throw LegacyBridgeImportError.invalidCommand }
    }
    let body = try bodyJSON(targetLibraryID: targetLibraryID, lineageID: lineageID,
      sourceRoot: sourceRoot, parentSourceRoot: parentSourceRoot,
      feeds: feeds, sharedOperationInventory: sharedOperationInventory,
      expectedLineageRoot: expectedLineageRoot, expectedShowHeads: expectedShowHeads,
      sourceDescriptor: sourceDescriptor)
    let bytes = try Canonical.encode(body)
    guard bytes.count <= maximumBodyBytes else { throw LegacyBridgeImportError.invalidCommand }
    return body.merging(["commandID": .string(commandID), "commandDigest": .string(Canonical.digest(bytes))]) { _, new in new }
  }

  public static func decode(_ operation: ColophonOperation) -> Body? {
    var keys: Set<String> = ["bridgeVersion", "crosswalkVersion", "targetLibraryID",
        "lineageID", "sourceRoot", "parentSourceRoot",
        "crosswalkDigest", "feeds", "sharedOperationInventory", "sharedInventoryDigest",
        "expectedLineageRoot", "expectedShowHeads", "commandID", "commandDigest"]
    if operation.payload["sourceDescriptor"] != nil { keys.insert("sourceDescriptor") }
    guard operation.kind == kind, operation.v == 1,
      Set(operation.payload.keys) == keys,
      operation.payload["bridgeVersion"]?.int == 1, operation.payload["crosswalkVersion"]?.int == 1,
      let targetLibraryID = operation.payload["targetLibraryID"]?.string,
      let lineageID = operation.payload["lineageID"]?.string,
      let sourceRoot = operation.payload["sourceRoot"]?.string,
      let crosswalkDigest = operation.payload["crosswalkDigest"]?.string,
      let feedValues = operation.payload["feeds"]?.array,
      let inventoryValues = operation.payload["sharedOperationInventory"]?.array,
      let sharedInventoryDigest = operation.payload["sharedInventoryDigest"]?.string,
      let expectedValues = operation.payload["expectedShowHeads"]?.object,
      let commandID = operation.payload["commandID"]?.string,
      let commandDigest = operation.payload["commandDigest"]?.string
    else { return nil }
    let parentSourceRoot = operation.payload["parentSourceRoot"]?.string
    let expectedLineageRoot = operation.payload["expectedLineageRoot"]?.string
    let descriptor = operation.payload["sourceDescriptor"].flatMap(sourceDescriptor)
    guard operation.payload["parentSourceRoot"] == .null || parentSourceRoot != nil,
      operation.payload["expectedLineageRoot"] == .null || expectedLineageRoot != nil,
      operation.payload["sourceDescriptor"] == nil || descriptor != nil
    else { return nil }
    let feeds = feedValues.compactMap { value -> LegacyPodcastFeedCrosswalk? in
      guard let object = value.object, Set(object.keys) == ["legacyID", "feedURL", "title", "targetShowID"],
        let legacyID = object["legacyID"]?.string, let feedURL = object["feedURL"]?.string,
        let title = object["title"]?.string, let targetShowID = object["targetShowID"]?.string
      else { return nil }
      return LegacyPodcastFeedCrosswalk(legacyID: legacyID, feedURL: feedURL, title: title,
        targetShowID: targetShowID)
    }
    let sharedOperationInventory = inventoryValues.compactMap { value -> LegacyBridgeOperationDigest? in
      guard let object = value.object, Set(object.keys) == ["operationID", "digest"],
        let operationID = object["operationID"]?.string, let digest = object["digest"]?.string
      else { return nil }
      return LegacyBridgeOperationDigest(operationID: operationID, digest: digest)
    }
    guard feeds.count == feedValues.count, sharedOperationInventory.count == inventoryValues.count,
      expectedValues.values.allSatisfy({ $0 == .null || $0.string != nil })
    else { return nil }
    let expected = expectedValues.mapValues(\.string)
    guard let rebuilt = try? payload(targetLibraryID: targetLibraryID, lineageID: lineageID, sourceRoot: sourceRoot,
      parentSourceRoot: parentSourceRoot, feeds: feeds, sharedOperationInventory: sharedOperationInventory,
      expectedLineageRoot: expectedLineageRoot, expectedShowHeads: expected, commandID: commandID,
      sourceDescriptor: descriptor),
      rebuilt == operation.payload, rebuilt["crosswalkDigest"]?.string == crosswalkDigest,
      rebuilt["sharedInventoryDigest"]?.string == sharedInventoryDigest,
      rebuilt["commandDigest"]?.string == commandDigest
    else { return nil }
    return Body(commandID: commandID, commandDigest: commandDigest, targetLibraryID: targetLibraryID, lineageID: lineageID,
      sourceRoot: sourceRoot, parentSourceRoot: parentSourceRoot, crosswalkDigest: crosswalkDigest,
      sharedOperationInventory: sharedOperationInventory, sharedInventoryDigest: sharedInventoryDigest,
      sourceDescriptor: descriptor,
      feeds: feeds,
      expectedLineageRoot: expectedLineageRoot, expectedShowHeads: expected)
  }

  public static func signerKey(_ signer: String, _ commandID: String) -> String {
    PlaybackPreferenceBatch.signerKey(signer, commandID)
  }

  public static func rootKey(_ lineageID: String, _ sourceRoot: String) -> String {
    "\(lineageID):\(sourceRoot)"
  }
}

public struct LegacyBridgeImportService {
  public let replica: Replica
  public init(replica: Replica) { self.replica = replica }

  public func checkWriter() throws {
    let authority = try replica.authority()
    guard let member = authority.members[replica.identity.id], member.revokedAt == nil,
      let grant = member.current, grant.write, grant.namespaces.contains(Podcasts.namespace)
    else { throw LegacyBridgeImportError.noCurrentAccess }
    guard member.role == .app || member.role == .device else { throw LegacyBridgeImportError.wrongRole }
    if let expires = grant.expires, expires < .now { throw LegacyBridgeImportError.noCurrentAccess }
    for caveat in grant.caveats where caveat.namespace == nil || caveat.namespace == Podcasts.namespace {
      switch Caveat.Kind(rawValue: caveat.kind) {
      case .kinds:
        guard caveat.kinds?.contains(LegacyBridgeImport.kind) == true else {
          throw LegacyBridgeImportError.noCurrentAccess
        }
      case .ceiling, .budget:
        guard caveat.field != nil, caveat.max != nil else { throw LegacyBridgeImportError.noCurrentAccess }
      case nil: throw LegacyBridgeImportError.noCurrentAccess
      }
    }
  }

  /// A local ordered-fold receipt, not a distributed compare-and-swap promise. The caller must
  /// first verify and retain the complete source archive; this command contains podcast feeds only.
  @discardableResult public func commit(targetLibraryID: String, lineageID: String, sourceRoot: String, parentSourceRoot: String?,
    feeds: [LegacyPodcastFeedCrosswalk], sharedOperationInventory: [LegacyBridgeOperationDigest],
    expectedLineageRoot: String?, expectedShowHeads: [String: String?],
    commandID: String, sourceDescriptor: LegacyBridgeSourceDescriptor? = nil) throws -> LegacyBridgeImportReceipt
  {
    let payload = try LegacyBridgeImport.payload(targetLibraryID: targetLibraryID, lineageID: lineageID, sourceRoot: sourceRoot,
      parentSourceRoot: parentSourceRoot, feeds: feeds, sharedOperationInventory: sharedOperationInventory,
      expectedLineageRoot: expectedLineageRoot,
      expectedShowHeads: expectedShowHeads, commandID: commandID, sourceDescriptor: sourceDescriptor)
    try checkWriter()
    guard try replica.authority().libraryID == targetLibraryID else { throw LegacyBridgeImportError.invalidCommand }
    let state = try replica.state(of: Podcasts.self)
    let key = LegacyBridgeImport.signerKey(replica.identity.id, commandID)
    guard !state.legacyBridgeCommandConflicts.contains(key) else { throw LegacyBridgeImportError.commandIDConflict }
    if let prior = state.legacyBridgeReceipts[key] {
      guard prior.commandDigest == payload["commandDigest"]?.string else {
        throw LegacyBridgeImportError.commandIDConflict
      }
      return prior
    }
    let rootKey = LegacyBridgeImport.rootKey(lineageID, sourceRoot)
    if let currentRoot = state.legacyBridgeLineageRoots[lineageID], currentRoot != sourceRoot {
      throw LegacyBridgeImportError.sourceRootConflict
    }
    let known = state.legacyBridgeSourceOperationHashes[lineageID] ?? [:]
    let proposed = Dictionary(uniqueKeysWithValues: sharedOperationInventory.map { ($0.operationID, $0.digest) })
    if known.contains(where: { proposed[$0.key] != $0.value }) {
      throw LegacyBridgeImportError.sourceRecordConflict
    }
    if let prior = state.legacyBridgeRootReceipts[rootKey] {
      guard prior.crosswalkDigest == payload["crosswalkDigest"]?.string,
        prior.sharedInventoryDigest == payload["sharedInventoryDigest"]?.string,
        prior.sourceDescriptor == sourceDescriptor else {
        throw LegacyBridgeImportError.sourceRootConflict
      }
      return prior
    }
    let op = try replica.perform(Command(namespace: Podcasts.namespace, kind: LegacyBridgeImport.kind, payload: payload))
    guard let receipt = try replica.state(of: Podcasts.self).legacyBridgeReceipts[key],
      receipt.operationID == op.id
    else { throw LegacyBridgeImportError.notAdmitted }
    return receipt
  }
}
