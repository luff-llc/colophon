import ColophonCore
import ColophonReplica
import Foundation

/// The `reading.saved/1` projection. Every replica folds the same admitted operations in the
/// same order, so every replica computes the same shelf.
public struct SavedShelf: Sendable {
  public struct Item: Sendable, Identifiable, Hashable {
    public let id: String
    public var url: String
    public var title: String
    public var added: Date
    /// Position of the capture in the agreed operation order: the deterministic sort key.
    public var sequence: Int
    /// Consumption: `notStarted`, `inProgress`, `doneEnough`, `completed`, `abandoned`; nil until set.
    public var consumption: String?
    /// Retention: `captured`, `saved`, `chosen`, `resurface`, `released`.
    public var retention: String?
    /// The operation that last changed state, or the capture.
    public var revision: String
    public var changedBy: String
    /// Capture fields this client doesn't interpret, kept as they arrived.
    public var extra: [String: JSONValue]

    public init(id: String, url: String, title: String, added: Date, sequence: Int = 0,
      consumption: String? = nil, retention: String? = nil, revision: String, changedBy: String,
      extra: [String: JSONValue] = [:])
    {
      self.id = id; self.url = url; self.title = title; self.added = added; self.sequence = sequence
      self.consumption = consumption; self.retention = retention; self.revision = revision
      self.changedBy = changedBy; self.extra = extra
    }

    public var isFinished: Bool { consumption == "completed" || consumption == "doneEnough" }
    public var isArchived: Bool { retention == "released" }
    public var isReadingNow: Bool { consumption == "inProgress" && !isArchived }
    public var author: String { extra["author"]?.string ?? "" }
    public var summary: String { extra["summary"]?.string ?? "" }
    public var tags: [String] { extra["tags"]?.array?.compactMap(\.string) ?? [] }
    public var collection: String { extra["collection"]?.string ?? "" }
  }

  public struct Conflict: Sendable, Identifiable {
    public let operation: String
    public let item: String
    public let expected: String?
    public let found: String
    public let by: String
    public var id: String { operation }
  }

  public private(set) var items: [String: Item] = [:]
  public private(set) var conflicts: [Conflict] = []
  /// Operations readable but not applied, with the reason.
  public private(set) var held: [(operation: String, by: String, reason: String)] = []
  public let rejected: Int
  public let unreadable: Int

  /// Folds capture, state and metadata changes in the agreed order. Kinds this module doesn't
  /// know are skipped, never treated as errors.
  public init(_ view: ReplicaView) {
    rejected = view.rejected.count
    unreadable = view.unreadable
    for (sequence, entry) in view.operations.enumerated() {
      if case .held(let reason) = entry.status {
        held.append((entry.id, entry.authorLabel, reason)); continue
      }
      apply(entry.operation, by: entry.authorLabel, sequence: sequence)
    }
  }

  mutating func apply(_ operation: ColophonOperation, by author: String, sequence: Int) {
    guard let item = operation.payload["item"]?.string else { return }
    switch operation.kind {
    case SavedLinks.Kind.capture:
      guard items[item] == nil, let url = operation.payload["url"]?.string else { return }
      var extra = operation.payload
      for known in ["item", "url", "title"] { extra[known] = nil }
      let added = extra["added"]?.double.flatMap { $0.isFinite ? Date(timeIntervalSince1970: $0) : nil } ?? operation.created
      items[item] = Item(id: item, url: url, title: operation.payload["title"]?.string ?? url, added: added,
        sequence: sequence, consumption: extra["consumption"]?.string, retention: extra["retention"]?.string ?? "saved",
        revision: operation.id, changedBy: author, extra: extra)
    case SavedLinks.Kind.setState, SavedLinks.Kind.editMetadata:
      guard var current = items[item] else { return }
      let expected = operation.payload["expect"]?.string
      if let expected, expected != current.revision {
        conflicts.append(Conflict(operation: operation.id, item: item, expected: expected, found: current.revision, by: author))
        return
      }
      if operation.kind == SavedLinks.Kind.setState {
        if let consumption = operation.payload["consumption"]?.string { current.consumption = consumption }
        if let retention = operation.payload["retention"]?.string { current.retention = retention }
        if let digest = operation.payload["archiveImportCompleted"]?.string { current.extra["archiveImportCompleted"] = .string(digest) }
      } else {
        if let title = operation.payload["title"]?.string { current.title = title }
        for key in ["author", "summary", "collection"] {
          if let value = operation.payload[key]?.string { current.extra[key] = .string(value) }
        }
        if let values = operation.payload["tags"]?.array, values.allSatisfy({ $0.string != nil }) {
          current.extra["tags"] = .array(SavedLinks.normalizedTags(values.compactMap(\.string)).map(JSONValue.string))
        }
      }
      current.revision = operation.id
      current.changedBy = author
      items[item] = current
    default:
      break // A newer kind this client doesn't know; other clients may.
    }
  }

  /// Newest first.
  public var sorted: [Item] { items.values.sorted { $0.sequence > $1.sequence } }
}
