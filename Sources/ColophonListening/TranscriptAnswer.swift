import ColophonAuthority
import Foundation

/// Every retained claim carries every exact supporting passage. Verification establishes the
/// quoted bytes and source signer; it does not establish entailment or factual correctness.
public struct TranscriptAnswerClaim: Codable, Hashable, Sendable {
  public let text: String
  public let citations: [TranscriptNoteAnchor]

  public init(text: String, citations: [TranscriptNoteAnchor]) {
    self.text = text
    self.citations = citations
  }
}

public struct TranscriptAnswerRecord: Sendable, Identifiable, Equatable {
  public enum Status: String, Sendable { case verified, pendingSource, invalidCitation, conflict }
  public enum Origin: String, Sendable { case onDevice, agent }
  public let id: String
  public let libraryID: String
  public let commandID: String
  public let question: String
  public let claims: [TranscriptAnswerClaim]
  public let authorID: String
  public let authorLabel: String
  public let authorRole: MemberRole
  public let origin: Origin
  public let status: Status
}

public struct TranscriptAnswerCollection: Sendable {
  public let records: [TranscriptAnswerRecord]
  public let heldCount: Int
}

public enum TranscriptAnswerError: Error, Equatable, Sendable {
  case invalidInput, noCurrentAccess, commandIDConflict, notAdmitted, duplicateOperationID(String)
}
