import ColophonCore
import ColophonReplica
import Foundation

/// Resolves a signed note revision through the receiving app's existing library grant.
/// Recorded audio seconds remain approximate; resolving a note does not verify a transcript.
public struct PodcastNoteSource: Sendable {
  public enum Failure: Error, Equatable { case wrongLibrary, accessRequired, sourceUnavailable, invalidMoment }

  public let libraryID: String
  public let note: Listening.Note

  public static func resolve(_ link: PodcastNoteLink, in replica: Replica) throws -> Self {
    let authority = try replica.authority()
    guard authority.libraryID == link.libraryID else { throw Failure.wrongLibrary }
    guard let grant = authority.members[replica.identity.id]?.current,
      grant.namespaces.contains(Podcasts.namespace), grant.expires.map({ $0 > .now }) ?? true else {
      throw Failure.accessRequired
    }
    let view = try replica.read(Podcasts.namespace)
    let admitted = view.admitted
    // An operation ID is a source reference only when unambiguous in authenticated history.
    let matches = admitted.indices.filter { admitted[$0].operation.id == link.revision }
    guard matches.count == 1, let end = matches.first,
      view.operations.filter({ $0.operation.id == link.revision }).count == 1 else { throw Failure.sourceUnavailable }
    let history = ReplicaView(operations: Array(admitted[...end]), rejected: [], unreadable: 0, libraryID: view.libraryID)
    guard let note = Listening(history).notes[link.noteID], note.revision == link.revision,
      admitted.filter({ $0.operation.id == note.creationRevision }).count == 1 else { throw Failure.sourceUnavailable }
    if case .moment(let episode, let seconds) = link.destination {
      guard note.episode == episode, note.seconds == seconds else { throw Failure.invalidMoment }
    }
    return Self(libraryID: link.libraryID, note: note)
  }

  public var momentURL: URL? {
    guard let seconds = note.seconds else { return nil }
    return PodcastNoteLink(libraryID: libraryID, noteID: note.id, revision: note.revision,
      destination: .moment(episode: note.episode, seconds: seconds))?.url
  }
}
