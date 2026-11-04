import ColophonAuthority
import ColophonCore
import ColophonReplica
import Foundation

/// Verifies an optional transcript anchor before an app signs a person's note. Existing
/// timestamp-only notes remain valid and never acquire an inferred transcript anchor.
public struct TranscriptNoteService {
  public enum SourceStatus: Sendable, Equatable {
    case verified, pending, mismatch, legacy
  }

  public let replica: Replica
  public init(replica: Replica) { self.replica = replica }

  public func validate(_ anchor: TranscriptNoteAnchor) throws {
    let document = try SharedTranscriptService(replica: replica).resolve(anchor.reference)
    guard anchor.matches(document) else { throw SharedTranscriptError.wrongCitation }
  }

  public func status(of note: Listening.Note) -> SourceStatus {
    guard note.hasAnchorClaim else { return .legacy }
    guard let anchor = note.anchor, note.episode == anchor.reference.episode,
      note.show == anchor.reference.show else { return .mismatch }
    do {
      try validate(anchor)
      return .verified
    } catch SharedTranscriptError.missingTranscript {
      return .pending
    } catch SharedTranscriptError.noCurrentAccess {
      return .pending
    } catch {
      return .mismatch
    }
  }

  /// The signer, not the self-declared note origin, establishes attribution.
  public func signer(of note: Listening.Note) throws -> (label: String, role: MemberRole)? {
    guard let member = try replica.authority().members[note.authorID] else { return nil }
    return (member.label, member.role)
  }

  public func noteCommand(episode: String, show: String, text: String, anchor: TranscriptNoteAnchor,
    seconds: Double? = nil, noteID: String = UUID().uuidString.lowercased()) throws -> Command
  {
    guard anchor.reference.episode == episode, anchor.reference.show == show, !text.isEmpty else {
      throw SharedTranscriptError.invalidCommand
    }
    let authority = try replica.authority()
    guard let member = authority.members[replica.identity.id], member.current != nil,
      member.role == .app || member.role == .device
    else { throw SharedTranscriptError.wrongRole }
    try validate(anchor)
    return Podcasts.note(noteID, episode: episode, show: show, seconds: seconds, text: text,
      quote: anchor.quote, origin: "person", anchor: anchor)
  }
}
