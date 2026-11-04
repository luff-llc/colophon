import ColophonCore
import ColophonListening
import ColophonReplica
import Foundation

/// Continues one authenticated Taupe clipping in Scribenda without changing its source.
/// IDs depend on the library and clipping creation, so retries and later edits reopen it.
public struct PodcastNoteContinuation: Sendable {
  public let notebookID: String
  public let entryID: String

  public static func open(_ link: PodcastNoteLink, in replica: Replica) throws -> Self {
    guard link.destination == .writing else { throw PodcastNoteSource.Failure.invalidMoment }
    let source = try PodcastNoteSource.resolve(link, in: replica)
    guard case .member(let namespaces, let write) = try replica.membership(), write, namespaces.contains(Notes.namespace) else {
      throw PodcastNoteSource.Failure.accessRequired
    }
    let identity: JSONValue = .array([.string(source.libraryID), .string(source.note.id), .string(source.note.creationRevision)])
    let key = Canonical.digest(try Canonical.encode(identity))
    let notebook = "scribenda-loose-notes"
    let entry = "taupe-note-" + key
    let attachment = "taupe-source-" + key
    let cell = "taupe-thought-" + key
    var state = try replica.state(of: Notes.self)
    if state.notebooks[notebook] == nil {
      try replica.perform(Notes.create(notebook: notebook, title: "Loose notes"))
      state = try replica.state(of: Notes.self)
    }
    if state.notebooks[notebook]?.archived == true {
      try replica.perform(Notes.archive(notebook: notebook, archived: false))
      state = try replica.state(of: Notes.self)
    }
    guard state.notebooks[notebook]?.archived == false else { throw PodcastNoteSource.Failure.sourceUnavailable }
    if state.entries[entry] == nil {
      try replica.perform(Notes.putEntry(entry, notebook: notebook))
      state = try replica.state(of: Notes.self)
    }
    guard state.entries[entry]?.notebook == notebook else { throw PodcastNoteSource.Failure.sourceUnavailable }
    // Preserve the first source revision even when Continue is used again after a Taupe edit.
    if state.attachments[attachment] == nil {
      let reference = NotesAttachment.SourceReference(libraryID: source.libraryID, namespace: Podcasts.namespace,
        artifactID: source.note.id, revision: source.note.revision, quote: source.note.anchor?.quote ?? source.note.quote)
      let command = Notes.attach(attachment, notebook: notebook, entry: entry, role: .reading,
        name: "Moment from Taupe", source: reference)
      try Notes.validate(command.kind, command.payload)
      try replica.perform(command)
      state = try replica.state(of: Notes.self)
    }
    guard let retained = state.attachments[attachment], retained.notebook == notebook, retained.entry == entry,
      retained.source?.libraryID == source.libraryID, retained.source?.namespace == Podcasts.namespace,
      retained.source?.artifactID == source.note.id,
      let pinnedRevision = retained.source?.revision,
      let pinnedLink = PodcastNoteLink(libraryID: source.libraryID, noteID: source.note.id, revision: pinnedRevision)
    else { throw PodcastNoteSource.Failure.sourceUnavailable }
    // If an interrupted continuation left only metadata or a reference, finish from the
    // pinned revision, never from a newer request. A person's existing cell is never replaced.
    let pinned = try PodcastNoteSource.resolve(pinnedLink, in: replica)
    if state.cells[cell] == nil {
      try replica.perform(Notes.putCell(cell, notebook: notebook, kind: .markdown, source: pinned.note.text, entry: entry))
      state = try replica.state(of: Notes.self)
    }
    guard state.cells(in: notebook, entry: entry).contains(where: { $0.id == cell }) else {
      throw PodcastNoteSource.Failure.sourceUnavailable
    }
    return Self(notebookID: notebook, entryID: entry)
  }
}
