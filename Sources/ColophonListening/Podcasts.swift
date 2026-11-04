import ColophonCore
import ColophonReplica
import CryptoKit
import Foundation

/// `listening.podcasts` v1: the shows a person follows and where they are in each episode.
///
/// Episodes themselves come from public feeds, which every client fetches; only the person's
/// state travels. An episode's ID is derived from its feed and GUID, so every client names it
/// the same without coordinating.
public enum Podcasts: DomainModule {
  public static let namespace = "listening.podcasts"
  public static let version = 1
  public static let kinds = [Kind.follow, Kind.unfollow, Kind.showSettings, Kind.preferenceBatch,
    Kind.setState, Kind.position, Kind.recoverPosition, Kind.queue, Kind.queueRetain,
    Kind.naturalEndBatch, PodcastSourcePublication.kind, Kind.legacyBridgeImport, LegacyPodcastStateImport.kind,
    ContentKind.addNote, ContentKind.editNote, ContentKind.resolveNote, ContentKind.deleteNote, ContentKind.segments,
    ContentKind.transcript, PlaylistKind.save, ChapterKind.save,
    TranscriptAnswerService.saveKind,
    TranscriptPreparationService.requestKind, TranscriptPreparationService.cancelKind, TranscriptPreparationService.resultKind,
    TranscriptQuestionService.requestKind, TranscriptQuestionService.responseKind,
    TranscriptQuestionService.cancelKind, TranscriptQuestionService.admitKind]

  public enum Kind {
    public static let follow = "show.follow"
    public static let unfollow = "show.unfollow"
    public static let showSettings = "show.settings"
    public static let preferenceBatch = PlaybackPreferenceBatch.kind
    public static let setState = "episode.setState"
    public static let position = "episode.position"
    public static let queue = "queue.set"
    public static let queueRetain = "queue.retain"
    public static let recoverPosition = "position.recover"
    /// Signed, exact-head natural completion and queue advance, separate from legacy writes.
    public static let naturalEndBatch = PlaybackNaturalEndBatch.kind
    /// Internal-only import of a bounded, verified legacy feed crosswalk. Not a generic MCP action.
    public static let legacyBridgeImport = LegacyBridgeImport.kind
  }

  /// First 16 bytes of SHA-256 over "<feed URL>\n<GUID>", lowercase hex.
  public static func episodeID(feed: String, guid: String) -> String {
    String(Canonical.digest(Data((feed + "\n" + guid).utf8)).prefix(32))
  }

  public static func showID(feed: String) -> String { String(Canonical.digest(Data(feed.utf8)).prefix(32)) }

  public static func follow(feed: String, title: String) -> Command {
    command(Kind.follow, ["show": .string(showID(feed: feed)), "feed": .string(feed), "title": .string(title)])
  }

  public static func unfollow(show: String) -> Command { command(Kind.unfollow, ["show": .string(show)]) }

  /// Per-show listening preferences. Absent fields keep their current value.
  public static func settings(show: String, speed: Double? = nil, skipIntro: Double? = nil, skipOutro: Double? = nil)
    -> Command
  {
    var payload: [String: JSONValue] = ["show": .string(show)]
    if let speed { payload["speed"] = .number(speed) }
    if let skipIntro { payload["skipIntro"] = .number(skipIntro) }
    if let skipOutro { payload["skipOutro"] = .number(skipOutro) }
    return command(Kind.showSettings, payload)
  }

  /// Consumption uses Marginalia's vocabulary (`completed`, `abandoned`, ...).
  public static func setState(episode: String, show: String, consumption: String, expect: String?) -> Command {
    command(Kind.setState, ["episode": .string(episode), "show": .string(show), "consumption": .string(consumption),
      "expect": JSONValue(expect)])
  }

  /// A playback position. `deliberate` marks a seek or rewind the person chose; passive progress
  /// from playing is not deliberate. `expect` is the position revision the player started from.
  public static func position(episode: String, show: String, seconds: Double, duration: Double?, deliberate: Bool,
    expect: String?) -> Command
  {
    command(Kind.position, ["episode": .string(episode), "show": .string(show), "seconds": .number(max(0, seconds)),
      "duration": JSONValue(duration), "deliberate": .bool(deliberate), "expect": JSONValue(expect)])
  }

  public static func queue(_ episodes: [String]) -> Command { command(Kind.queue, ["episodes": .array(episodes.map(JSONValue.string))]) }

  /// Retain playback references with a real queue edit. The legacy IDs-only API is unchanged.
  public static func queue(_ episodes: [String], retaining metadata: [QueuedEpisodeMetadata]) throws -> Command {
    guard Set(episodes).count == episodes.count,
      Set(metadata.map(\.episodeID)).isSubset(of: Set(episodes)) else {
      throw QueuedEpisodeMetadataError.invalidMetadata
    }
    return command(Kind.queue, ["episodes": .array(episodes.map(JSONValue.string)),
      "metadata": try QueuedEpisodeMetadata.batchJSON(metadata)])
  }

  /// Background enrichment cannot replace queue order, including on an older reader.
  public static func retainQueueMetadata(_ metadata: [QueuedEpisodeMetadata], expectedQueueRevision: String?) throws -> Command {
    let expected = JSONValue(expectedQueueRevision)
    guard QueuedEpisodeMetadata.validRevision(expected) else { throw QueuedEpisodeMetadataError.invalidMetadata }
    return command(Kind.queueRetain, ["metadata": try QueuedEpisodeMetadata.batchJSON(metadata),
      "expectedQueueRevision": expected])
  }

  public static func queueRevision(authorID: String, operation: ColophonOperation) -> String {
    PlaybackPreferenceBatch.revision(authorID: authorID, operation: operation)
  }

  /// Replay a durable checkpoint only over the exact position and consumption state observed.
  /// Older readers ignore this distinct kind instead of applying an unconditional rewind.
  public static func recoverPosition(episode: String, show: String, seconds: Double, duration: Double?,
    expectedPosition: String?, expectedState: String?, inProgress: Bool) -> Command
  {
    command(Kind.recoverPosition, ["episode": .string(episode), "show": .string(show),
      "seconds": .number(seconds), "duration": JSONValue(duration),
      "expectedPosition": JSONValue(expectedPosition), "expectedState": JSONValue(expectedState),
      "inProgress": .bool(inProgress)])
  }

  public static func fold(_ view: ReplicaView) -> Listening { Listening(view) }
}
