import ColophonCore
import ColophonReplica
import Foundation

/// `reading.saved` v1: links a person keeps to read later, and their reading state.
///
/// States use this vocabulary — consumption `notStarted`, `inProgress`, `doneEnough`,
/// `completed`, `abandoned`; retention `captured`, `saved`, `chosen`, `resurface`, `released`.
/// A client keeps values it doesn't recognise rather than mapping them to ones it does.
public enum SavedLinks: DomainModule {
  public static let namespace = "reading.saved"
  public static let version = 1
  /// Kinds this module folds. `item.delete` and the reading extensions (content, feeds,
  /// annotations, browser checkpoints) are written by fuller clients; this module keeps them
  /// in history but doesn't fold them yet, so a shelf here may still list a deleted item.
  public static let kinds = [Kind.capture, Kind.setState, Kind.editMetadata]

  public enum Kind {
    public static let capture = "capture.link"
    public static let setState = "item.setState"
    public static let editMetadata = "item.editMetadata"
    public static let delete = "item.delete"
  }

  /// Saves a link. The writer chooses the item ID, so every replica names it the same.
  public static func capture(item: String = UUID().uuidString.lowercased(), url: String, title: String,
    extra: [String: JSONValue] = [:]) -> Command
  {
    var payload = extra
    payload["item"] = .string(item)
    payload["url"] = .string(url)
    payload["title"] = .string(title)
    return command(Kind.capture, payload)
  }

  /// Changes reading state. `expect` is the revision the writer last saw; if another change
  /// landed first, every replica records a conflict instead of applying this one.
  public static func setState(item: String, consumption: String? = nil, retention: String? = nil, expect: String?) -> Command {
    var payload: [String: JSONValue] = ["item": .string(item), "expect": expect.map { .string($0) } ?? .null]
    if let consumption { payload["consumption"] = .string(consumption) }
    if let retention { payload["retention"] = .string(retention) }
    return command(Kind.setState, payload)
  }

  /// Updates only supplied fields. Empty tags or collection remove those memberships.
  /// Unknown capture fields remain intact, and a stale revision records a conflict.
  public static func editMetadata(item: String, title: String? = nil, author: String? = nil,
    summary: String? = nil, tags: [String]? = nil, collection: String? = nil, expect: String?) -> Command
  {
    var payload: [String: JSONValue] = ["item": .string(item), "expect": JSONValue(expect)]
    if let title { payload["title"] = .string(title) }
    if let author { payload["author"] = .string(author) }
    if let summary { payload["summary"] = .string(summary) }
    if let tags { payload["tags"] = .array(normalizedTags(tags).map(JSONValue.string)) }
    if let collection { payload["collection"] = .string(collection.trimmingCharacters(in: .whitespacesAndNewlines)) }
    return command(Kind.editMetadata, payload)
  }

  /// Stable, case-preserving tag names with blank and duplicate names removed.
  public static func normalizedTags(_ values: [String]) -> [String] {
    Array(Set(values.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty })).sorted()
  }

  public static func fold(_ view: ReplicaView) -> SavedShelf { SavedShelf(view) }
}
