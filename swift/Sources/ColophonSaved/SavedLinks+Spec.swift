import ColophonCore
import ColophonReplica
import Foundation

public extension SavedLinks {
  static let consumptionValues = ["notStarted", "inProgress", "doneEnough", "completed", "abandoned"]
  static let retentionValues = ["captured", "saved", "chosen", "resurface", "released"]

  static var operations: [OperationSpec] {
    [
      OperationSpec(Kind.capture, "Save a link to read later.", [
        FieldSpec("item", .string, required: true, "A new unique ID for the saved item."),
        FieldSpec("url", .string, required: true, "The http(s) address."),
        FieldSpec("title", .string, required: true, "The title to show."),
      ]),
      OperationSpec(Kind.setState, "Change whether a saved item is read, and whether it's kept.", [
        FieldSpec("item", .string, required: true, "The saved item."),
        FieldSpec("consumption", .string, "Reading progress.", values: consumptionValues),
        FieldSpec("retention", .string, "Whether it's kept; `released` archives it.", values: retentionValues),
        FieldSpec("expect", .string, "The item's revision you last saw; a stale one records a conflict."),
      ]),
      OperationSpec(Kind.editMetadata, "Edit a saved item's title, description, tags or collection.", [
        FieldSpec("item", .string, required: true, "The saved item."),
        FieldSpec("title", .string, "The title to show."),
        FieldSpec("author", .string, "The author."),
        FieldSpec("summary", .string, "A description or personal summary."),
        FieldSpec("tags", .strings, "All tag memberships; an empty list clears them."),
        FieldSpec("collection", .string, "A collection name; an empty name clears it."),
        FieldSpec("expect", .string, "The item's revision you last saw; a stale one records a conflict."),
      ]),
    ]
  }

  static func describe(_ state: SavedShelf) -> JSONValue {
    .object(["items": .array(state.sorted.map { item in
      var object: [String: JSONValue] = ["item": .string(item.id), "url": .string(item.url), "title": .string(item.title),
        "consumption": JSONValue(item.consumption), "retention": JSONValue(item.retention),
        "revision": .string(item.revision)]
      if !item.author.isEmpty { object["author"] = .string(item.author) }
      if !item.summary.isEmpty { object["summary"] = .string(item.summary) }
      if !item.tags.isEmpty { object["tags"] = .array(item.tags.map(JSONValue.string)) }
      if !item.collection.isEmpty { object["collection"] = .string(item.collection) }
      return .object(object)
    }), "conflicts": .number(Double(state.conflicts.count))])
  }
}
