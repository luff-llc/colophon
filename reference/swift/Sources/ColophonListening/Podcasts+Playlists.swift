import ColophonCore
import ColophonReplica
import Foundation

/// Playlists: named lists of episodes, either chosen one by one or drawn live from shows by
/// a rule (which shows, pinned shows first, played state, length, a title word, and episodes
/// forced in or out). Every rule field is optional, so an older payload reads unchanged.
/// A playlist is saved whole with `playlist.save`; archiving hides it reversibly instead of
/// deleting it. Which episodes a rule-based playlist holds is worked out by each client from
/// the feeds, so only the person's rule travels.
public extension Podcasts {
  enum PlaylistKind {
    public static let save = "playlist.save"
  }

  /// Saves a playlist. `expect` is the revision the writer last saw; a stale save is kept as
  /// a competing version instead of silently replacing a concurrent edit.
  static func savePlaylist(_ playlist: Listening.Playlist, expect: String?) -> Command {
    command(PlaylistKind.save, [
      "playlist": .string(playlist.id), "name": .string(playlist.name), "mode": .string(playlist.mode.rawValue),
      "allShows": .bool(playlist.allShows), "shows": .array(playlist.shows.map(JSONValue.string)),
      "episodes": .array(playlist.episodes.map(JSONValue.string)),
      "excluded": .array(playlist.excluded.map(JSONValue.string)), "order": .string(playlist.order.rawValue),
      "includeFinished": .bool(playlist.includeFinished), "archived": .bool(playlist.archived),
      "pinned": .array(playlist.pinned.map(JSONValue.string)),
      "included": .array(playlist.included.map(JSONValue.string)),
      "progress": .string(playlist.progress.rawValue),
      "maxMinutes": playlist.maxMinutes.map { .number(Double($0)) } ?? .null,
      "titleContains": JSONValue(playlist.titleContains),
      "expect": JSONValue(expect),
    ])
  }

  internal static var playlistSpecs: [OperationSpec] {
    [
      OperationSpec(PlaylistKind.save, "Create, change or archive a playlist.", [
        FieldSpec("playlist", .string, required: true, "The playlist's ID; a new unique ID creates one."),
        FieldSpec("name", .string, required: true, "Its name."),
        FieldSpec("mode", .string, required: true, "Chosen episodes, or episodes from shows.",
          values: ["manual", "automatic"]),
        FieldSpec("allShows", .boolean, "Automatic: draw from every followed show."),
        FieldSpec("shows", .strings, "Automatic: the shows to draw from, in order."),
        FieldSpec("episodes", .strings, "Manual: the episodes, in order."),
        FieldSpec("excluded", .strings, "Automatic: episodes left out."),
        FieldSpec("order", .string, "Automatic: the order.", values: ["newest", "oldest", "byShow"]),
        FieldSpec("includeFinished", .boolean, "Keep episodes already played."),
        FieldSpec("archived", .boolean, "Hide it without deleting it."),
        FieldSpec("pinned", .strings, "Automatic: shows whose episodes come first, in order."),
        FieldSpec("included", .strings, "Automatic: episodes always in it, whatever the rule says."),
        FieldSpec("progress", .string, "Automatic: which episodes by listening state.",
          values: ["any", "unplayed", "inProgress"]),
        FieldSpec("maxMinutes", .number, "Automatic: only episodes no longer than this many minutes."),
        FieldSpec("titleContains", .string, "Automatic: only episodes whose title contains this."),
        FieldSpec("expect", .string, "The revision you last saw; a stale save keeps both versions."),
      ]),
    ]
  }
}

public extension Listening {
  struct Playlist: Sendable, Identifiable, Hashable {
    public enum Mode: String, Sendable, CaseIterable { case manual, automatic }
    public enum Order: String, Sendable, CaseIterable { case newest, oldest, byShow }
    /// Which episodes by listening state; `any` keeps today's behaviour.
    public enum Progress: String, Sendable, CaseIterable { case any, unplayed, inProgress }

    public let id: String
    public var name: String
    public var mode: Mode
    public var allShows: Bool
    public var shows: [String]
    public var episodes: [String]
    public var excluded: [String]
    public var order: Order
    public var includeFinished: Bool
    public var archived: Bool
    /// Automatic: shows whose episodes come first, in this order.
    public var pinned: [String] = []
    /// Automatic: episodes always included, whatever the rule says.
    public var included: [String] = []
    public var progress: Progress = .any
    /// Automatic: only episodes no longer than this.
    public var maxMinutes: Int?
    /// Automatic: only episodes whose title contains this.
    public var titleContains: String?
    /// The operation that last saved it; pass as `expect` when saving a change.
    public var revision: String
    /// Saves made without seeing the latest version, newest last.
    public var competing: [Playlist] = []

    public init(id: String = UUID().uuidString.lowercased(), name: String, mode: Mode = .automatic,
      allShows: Bool = false, shows: [String] = [], episodes: [String] = [], excluded: [String] = [],
      order: Order = .newest, includeFinished: Bool = false, archived: Bool = false, revision: String = "")
    {
      self.id = id
      self.name = name
      self.mode = mode
      self.allShows = allShows
      self.shows = shows
      self.episodes = episodes
      self.excluded = excluded
      self.order = order
      self.includeFinished = includeFinished
      self.archived = archived
      self.revision = revision
    }

    /// Reads a `playlist.save` payload; nil when it isn't a usable playlist.
    init?(payload: [String: JSONValue], revision: String) {
      let strings: (String) -> [String] = { key in
        var seen: Set<String> = []
        return (payload[key]?.array ?? []).compactMap(\.string).filter { !$0.isEmpty && seen.insert($0).inserted }
      }
      guard let id = payload["playlist"]?.string, !id.isEmpty,
        let name = payload["name"]?.string?.trimmingCharacters(in: .whitespacesAndNewlines), !name.isEmpty,
        let mode = payload["mode"]?.string.flatMap(Mode.init(rawValue:))
      else { return nil }
      self.init(id: id, name: String(name.prefix(120)), mode: mode, allShows: payload["allShows"]?.bool ?? false,
        shows: strings("shows"), episodes: strings("episodes"), excluded: strings("excluded"),
        order: payload["order"]?.string.flatMap(Order.init(rawValue:)) ?? .newest,
        includeFinished: payload["includeFinished"]?.bool ?? false, archived: payload["archived"]?.bool ?? false,
        revision: revision)
      pinned = strings("pinned")
      included = strings("included")
      progress = payload["progress"]?.string.flatMap(Progress.init(rawValue:)) ?? .any
      maxMinutes = payload["maxMinutes"]?.double.flatMap { $0.isFinite && $0 >= 1 ? Int(min($0, 24 * 60)) : nil }
      let word = payload["titleContains"]?.string?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
      titleContains = word.isEmpty ? nil : String(word.prefix(80))
    }
  }

  /// Playlists that aren't archived, by name.
  var activePlaylists: [Playlist] {
    playlists.values.filter { !$0.archived }
      .sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
  }
}
