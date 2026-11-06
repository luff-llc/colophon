import ColophonCore
import Foundation

/// A bounded playback reference, retained inside the encrypted listening namespace.
/// The feed string is preserved exactly: normalizing it would change the episode identity.
public struct QueuedEpisodeMetadata: Sendable, Equatable {
  public static let maximumEntries = 512
  public static let maximumEntryBytes = 16_384
  public static let maximumBatchBytes = 1_048_576

  public let episodeID: String
  public let showID: String
  public let feedURL: String
  public let guid: String
  public let title: String
  public let showTitle: String
  public let audioURL: String
  public let duration: Double?
  /// Unix seconds, including subsecond precision if supplied by the publisher.
  public let published: Double?

  public init(episodeID: String, showID: String, feedURL: String, guid: String,
    title: String, showTitle: String, audioURL: String, duration: Double? = nil, published: Double? = nil) throws
  {
    self.episodeID = episodeID
    self.showID = showID
    self.feedURL = feedURL
    self.guid = guid
    self.title = title
    self.showTitle = showTitle
    self.audioURL = audioURL
    self.duration = duration
    self.published = published
    guard Self.validText(guid, maximum: 4_096), Self.validText(title, maximum: 2_048),
      Self.validText(showTitle, maximum: 2_048), Self.validURL(feedURL), Self.validURL(audioURL),
      episodeID == Podcasts.episodeID(feed: feedURL, guid: guid), showID == Podcasts.showID(feed: feedURL),
      duration.map({ $0.isFinite && $0 >= 0 && $0 <= 604_800 }) ?? true,
      published.map({ $0.isFinite && (-62_135_596_800.0...253_402_300_799.0).contains($0) }) ?? true,
      (try Canonical.encode(json)).count <= Self.maximumEntryBytes
    else { throw QueuedEpisodeMetadataError.invalidMetadata }
  }

  var json: JSONValue {
    var fields: [String: JSONValue] = ["episode": .string(episodeID), "show": .string(showID),
      "feed": .string(feedURL), "guid": .string(guid), "title": .string(title),
      "showTitle": .string(showTitle), "audio": .string(audioURL)]
    if let duration { fields["duration"] = .number(duration) }
    if let published { fields["published"] = .number(published) }
    return .object(fields)
  }

  static func decode(_ value: JSONValue) -> Self? {
    let required: Set<String> = ["episode", "show", "feed", "guid", "title", "showTitle", "audio"]
    let allowed = required.union(["duration", "published"])
    guard let fields = value.object, required.isSubset(of: Set(fields.keys)), Set(fields.keys).isSubset(of: allowed),
      let episode = fields["episode"]?.string, let show = fields["show"]?.string,
      let feed = fields["feed"]?.string, let guid = fields["guid"]?.string,
      let title = fields["title"]?.string, let showTitle = fields["showTitle"]?.string,
      let audio = fields["audio"]?.string else { return nil }
    for name in ["duration", "published"] {
      if let raw = fields[name], raw != .null, raw.double == nil { return nil }
    }
    return try? Self(episodeID: episode, showID: show, feedURL: feed, guid: guid, title: title,
      showTitle: showTitle, audioURL: audio, duration: fields["duration"]?.double, published: fields["published"]?.double)
  }

  static func batchJSON(_ entries: [Self]) throws -> JSONValue {
    guard entries.count <= maximumEntries, Set(entries.map(\.episodeID)).count == entries.count else {
      throw QueuedEpisodeMetadataError.exceedsLimits
    }
    let value = JSONValue.array(entries.sorted { $0.episodeID < $1.episodeID }.map(\.json))
    guard (try Canonical.encode(value)).count <= maximumBatchBytes else { throw QueuedEpisodeMetadataError.exceedsLimits }
    return value
  }

  static func decodeBatch(_ value: JSONValue) -> [String: Self]? {
    guard let entries = value.array, entries.count <= maximumEntries else { return nil }
    var result: [String: Self] = [:]
    for raw in entries {
      guard let entry = decode(raw), result[entry.episodeID] == nil else { return nil }
      result[entry.episodeID] = entry
    }
    guard (try? batchJSON(Array(result.values))) != nil else { return nil }
    return result
  }

  static func merging(_ retained: [String: Self], _ additions: [String: Self]) -> [String: Self]? {
    let merged = retained.merging(additions) { _, new in new }
    guard (try? batchJSON(Array(merged.values))) != nil else { return nil }
    return merged
  }

  static func validRevision(_ value: JSONValue?) -> Bool {
    switch value {
    case .some(.null): true
    case .some(.string(let revision)): validText(revision, maximum: 512)
    default: false
    }
  }

  private static func validText(_ value: String, maximum: Int) -> Bool {
    !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && value.utf8.count <= maximum
      && !value.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
  }

  private static func validURL(_ value: String) -> Bool {
    guard validText(value, maximum: 4_096), let components = URLComponents(string: value),
      ["http", "https"].contains(components.scheme?.lowercased() ?? ""),
      components.host?.isEmpty == false, components.user == nil, components.password == nil,
      components.url != nil else { return false }
    return true
  }
}

public enum QueuedEpisodeMetadataError: Error, Sendable, Equatable, LocalizedError {
  case invalidMetadata
  case exceedsLimits
  public var errorDescription: String? {
    switch self {
    case .invalidMetadata: String(localized: "This episode's saved playback details are incomplete or unsupported.")
    case .exceedsLimits: String(localized: "The saved Up Next playback details exceed the supported size.")
    }
  }
}
