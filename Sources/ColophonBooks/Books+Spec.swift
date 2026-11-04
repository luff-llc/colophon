import ColophonCore
import ColophonReplica
import Foundation

public extension Books {
  static let statusValues = ["unplanned", "wantToRead", "reading", "paused", "finished", "doneEnough", "abandoned"]

  static var operations: [OperationSpec] {
    [
      OperationSpec(Kind.add, "Add a book.", [
        FieldSpec("book", .string, required: true, "A new unique ID for the book."),
        FieldSpec("title", .string, required: true, "Title."),
        FieldSpec("author", .string, required: true, "Author, as it should be shown."),
        FieldSpec("isbn", .string, "ISBN-13, if known."),
      ]),
      OperationSpec(Kind.edit, "Correct a book's details.", [
        FieldSpec("book", .string, required: true, "The book."),
        FieldSpec("title", .string, "Title."),
        FieldSpec("author", .string, "Author."),
        FieldSpec("pages", .integer, "Page count."),
      ]),
      OperationSpec(Kind.remove, "Remove a book and its notes.", [FieldSpec("book", .string, required: true, "The book.")]),
      OperationSpec(Kind.resolveNote, "Settle a note's concurrent versions.", [
        FieldSpec("note", .string, required: true, "The note."),
        FieldSpec("text", .string, required: true, "The text to keep."),
        FieldSpec("expect", .string, "The note's revision you last saw."),
      ]),
      OperationSpec(Kind.setPlan, "Set a book's reading status and dates.", [
        FieldSpec("book", .string, required: true, "The book."),
        FieldSpec("status", .string, required: true, "Reading status.", values: statusValues),
        FieldSpec("started", .string, "Start date, YYYY-MM-DD."),
        FieldSpec("finished", .string, "Finish date, YYYY-MM-DD."),
        FieldSpec("reread", .boolean, "Start a new reading instead of changing the current one."),
        FieldSpec("expect", .string, "The book's revision you last saw."),
      ]),
      OperationSpec(Kind.progress, "Record where the reader is.", [
        FieldSpec("book", .string, required: true, "The book."),
        FieldSpec("page", .integer, "Page number."),
        FieldSpec("fraction", .number, required: true, "Fraction read, 0 to 1."),
      ]),
      OperationSpec(Kind.note, "Add a book note.", [
        FieldSpec("note", .string, required: true, "A new unique ID for the note."),
        FieldSpec("book", .string, required: true, "The book."),
        FieldSpec("text", .string, required: true, "The person's own words."),
        FieldSpec("quote", .string, "The passage, verbatim."),
        FieldSpec("location", .string, "Page or chapter."),
      ]),
      OperationSpec(Kind.editNote, "Edit a book note.", [
        FieldSpec("note", .string, required: true, "The note."),
        FieldSpec("text", .string, required: true, "New text."),
        FieldSpec("expect", .string, "The note's revision you last saw; a stale one keeps both versions."),
      ]),
      OperationSpec(Kind.deleteNote, "Delete a book note.", [FieldSpec("note", .string, required: true, "The note.")]),
    ]
  }

  static func describe(_ state: Bookshelf) -> JSONValue {
    .object(["books": .array(state.sorted.map { book in
      .object(["book": .string(book.id), "title": .string(book.title), "author": .string(book.author),
        "status": .string(book.status), "fraction": .number(book.fraction), "revision": .string(book.revision),
        "notes": .array(state.notes(for: book.id).map { note in
          .object(["note": .string(note.id), "text": .string(note.text), "quote": JSONValue(note.quote),
            "location": JSONValue(note.location), "revision": .string(note.revision)])
        })])
    })])
  }
}
