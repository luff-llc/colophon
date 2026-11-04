import ColophonCore
import ColophonReplica
import Foundation

/// `reading.books` v1: books a person reads, their reading plans, progress and book notes.
///
/// Plan statuses use Marginalia's `BookReadingStatus`: `unplanned`, `wantToRead`, `reading`,
/// `paused`, `finished`, `doneEnough`, `abandoned`. Dates are `YYYY-MM-DD` declarations, not
/// instants, so they don't move between time zones.
public enum Books: DomainModule {
  public static let namespace = "reading.books"
  public static let version = 1
  public static let kinds = [Kind.add, Kind.edit, Kind.remove, Kind.setPlan, Kind.progress, Kind.note, Kind.editNote,
    Kind.resolveNote, Kind.deleteNote]

  public enum Kind {
    public static let add = "book.add"
    public static let edit = "book.edit"
    public static let remove = "book.remove"
    public static let resolveNote = "note.resolve"
    public static let setPlan = "book.setPlan"
    public static let progress = "book.progress"
    public static let note = "note.add"
    public static let editNote = "note.edit"
    public static let deleteNote = "note.delete"
  }

  public static func add(book: String = UUID().uuidString.lowercased(), title: String, author: String,
    isbn: String? = nil, extra: [String: JSONValue] = [:]) -> Command
  {
    var payload = extra
    payload["book"] = .string(book)
    payload["title"] = .string(title)
    payload["author"] = .string(author)
    if let isbn { payload["isbn"] = .string(isbn) }
    return command(Kind.add, payload)
  }

  /// Corrects a book's details. Absent fields keep their value; extra fields are merged.
  public static func edit(book: String, title: String? = nil, author: String? = nil, pages: Int? = nil,
    extra: [String: JSONValue] = [:]) -> Command
  {
    var payload = extra
    payload["book"] = .string(book)
    if let title { payload["title"] = .string(title) }
    if let author { payload["author"] = .string(author) }
    if let pages { payload["pages"] = .number(Double(pages)) }
    return command(Kind.edit, payload)
  }

  /// Removes a book and its notes from the shelf.
  public static func remove(book: String) -> Command { command(Kind.remove, ["book": .string(book)]) }

  /// Settles a note's concurrent versions: `text` becomes the note and the alternatives are cleared.
  public static func resolveNote(_ note: String, text: String, expect: String?) -> Command {
    command(Kind.resolveNote, ["note": .string(note), "text": .string(text), "expect": JSONValue(expect)])
  }

  /// `reread` starts a new reading of a finished book rather than rewriting the old one.
  public static func setPlan(book: String, status: String, started: String? = nil, finished: String? = nil,
    reread: Bool = false, expect: String?) -> Command
  {
    command(Kind.setPlan, ["book": .string(book), "status": .string(status), "started": JSONValue(started),
      "finished": JSONValue(finished), "reread": .bool(reread), "expect": JSONValue(expect)])
  }

  /// Where the reader is. The newest report in the agreed order wins; progress is not a decision.
  public static func progress(book: String, page: Int? = nil, fraction: Double) -> Command {
    command(Kind.progress, ["book": .string(book), "page": JSONValue(page), "fraction": .number(min(1, max(0, fraction)))])
  }

  /// A book note: the person's words, optionally with the passage and where it is.
  public static func note(_ note: String = UUID().uuidString.lowercased(), book: String, text: String, quote: String? = nil,
    location: String? = nil) -> Command
  {
    command(Kind.note, ["note": .string(note), "book": .string(book), "text": .string(text), "quote": JSONValue(quote),
      "location": JSONValue(location)])
  }

  /// Edits keep every concurrent version: a stale `expect` adds an alternative instead of
  /// replacing someone else's words.
  public static func editNote(_ note: String, text: String, expect: String?) -> Command {
    command(Kind.editNote, ["note": .string(note), "text": .string(text), "expect": JSONValue(expect)])
  }

  public static func deleteNote(_ note: String) -> Command { command(Kind.deleteNote, ["note": .string(note)]) }

  public static func fold(_ view: ReplicaView) -> Bookshelf { Bookshelf(view) }
}
