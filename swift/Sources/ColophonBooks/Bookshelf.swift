import ColophonCore
import ColophonReplica
import Foundation

/// The `reading.books` projection.
public struct Bookshelf: Sendable {
  public struct Reading: Sendable, Hashable {
    public var status: String
    public var started: String?
    public var finished: String?
  }

  public struct Book: Sendable, Identifiable, Hashable {
    public let id: String
    public var title: String
    public var author: String
    public var isbn: String?
    public var added: Date
    /// Position in the agreed operation order.
    public var sequence: Int
    /// Every reading, oldest first; the last is current.
    public var readings: [Reading] = [Reading(status: "unplanned")]
    public var page: Int?
    /// Page count, from the add or a later edit.
    public var pages: Int?
    public var fraction: Double = 0
    public var revision: String
    public var extra: [String: JSONValue]

    public var current: Reading { readings[readings.count - 1] }
    public var status: String { current.status }
  }

  public struct Note: Sendable, Identifiable, Hashable {
    public let id: String
    public let book: String
    public var text: String
    public var quote: String?
    public var location: String?
    public var created: Date
    public var sequence: Int
    public var author: String
    public var revision: String
    /// Concurrent edits that didn't replace this text, newest last.
    public var alternatives: [String] = []
  }

  public private(set) var books: [String: Book] = [:]
  public private(set) var notes: [String: Note] = [:]
  public private(set) var conflicts: [String] = []

  public init(_ view: ReplicaView) {
    for entry in view.admitted { apply(entry.operation, by: entry.authorLabel) }
  }

  private mutating func apply(_ operation: ColophonOperation, by author: String) {
    let payload = operation.payload
    switch operation.kind {
    case Books.Kind.add:
      guard let id = payload["book"]?.string, books[id] == nil, let title = payload["title"]?.string else { return }
      var extra = payload
      for known in ["book", "title", "author", "isbn"] { extra[known] = nil }
      books[id] = Book(id: id, title: title, author: payload["author"]?.string ?? "", isbn: payload["isbn"]?.string,
        added: operation.created, sequence: books.count, pages: payload["pages"]?.int, revision: operation.id, extra: extra)
    case Books.Kind.edit:
      guard let id = payload["book"]?.string, var book = books[id] else { return }
      if let title = payload["title"]?.string { book.title = title }
      if let author = payload["author"]?.string { book.author = author }
      if let pages = payload["pages"]?.int { book.pages = pages }
      for (key, value) in payload where !["book", "title", "author", "isbn", "pages"].contains(key) { book.extra[key] = value }
      books[id] = book
    case Books.Kind.remove:
      guard let id = payload["book"]?.string else { return }
      books[id] = nil
      notes = notes.filter { $0.value.book != id }
    case Books.Kind.resolveNote:
      guard let id = payload["note"]?.string, var note = notes[id], let text = payload["text"]?.string else { return }
      if let expect = payload["expect"]?.string, expect != note.revision { note.alternatives.append(text); notes[id] = note; return }
      note.text = text
      note.alternatives = []
      note.revision = operation.id
      notes[id] = note
    case Books.Kind.setPlan:
      guard let id = payload["book"]?.string, var book = books[id], let status = payload["status"]?.string else { return }
      if let expect = payload["expect"]?.string, expect != book.revision { conflicts.append(operation.id); return }
      let reading = Reading(status: status, started: payload["started"]?.string, finished: payload["finished"]?.string)
      if payload["reread"]?.bool == true { book.readings.append(reading) } else { book.readings[book.readings.count - 1] = reading }
      book.revision = operation.id
      books[id] = book
    case Books.Kind.progress:
      guard let id = payload["book"]?.string, var book = books[id] else { return }
      book.page = payload["page"]?.int
      book.fraction = payload["fraction"]?.double ?? book.fraction
      books[id] = book
    case Books.Kind.note:
      guard let id = payload["note"]?.string, notes[id] == nil, let book = payload["book"]?.string,
        let text = payload["text"]?.string
      else { return }
      notes[id] = Note(id: id, book: book, text: text, quote: payload["quote"]?.string, location: payload["location"]?.string,
        created: operation.created, sequence: notes.count, author: author, revision: operation.id)
    case Books.Kind.editNote:
      guard let id = payload["note"]?.string, var note = notes[id], let text = payload["text"]?.string else { return }
      if let expect = payload["expect"]?.string, expect != note.revision {
        note.alternatives.append(text)
      } else {
        note.text = text
        note.revision = operation.id
      }
      notes[id] = note
    case Books.Kind.deleteNote:
      if let id = payload["note"]?.string { notes[id] = nil }
    default:
      break
    }
  }

  public func notes(for book: String) -> [Note] {
    notes.values.filter { $0.book == book }.sorted { ($0.sequence, $0.id) < ($1.sequence, $1.id) }
  }
  public var sorted: [Book] { books.values.sorted { $0.sequence > $1.sequence } }
}
