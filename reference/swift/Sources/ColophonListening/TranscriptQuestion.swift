import Foundation

public struct TranscriptQuestionRequest: Codable, Hashable, Sendable, Identifiable {
  public let id: String
  public let libraryID: String
  public let question: String
  /// The complete disclosure boundary of this request; these are exact historical passages.
  public let scope: [TranscriptNoteAnchor]
  public let scopeDigest: String
  public let targetAgentID: String
  public let expires: Date
  public let commandID: String
  public let authorID: String
  public let authorLabel: String
}

public struct TranscriptQuestionResponse: Sendable, Equatable, Identifiable {
  public let id: String
  public let requestRevision: String
  public let claims: [TranscriptAnswerClaim]
  public let agentID: String
  public let agentLabel: String
  public let commandID: String
  /// Broker-side technical validation, separate from the person choosing to keep an answer.
  public let admissionRevision: String?
}

public struct TranscriptQuestionState: Sendable, Equatable, Identifiable {
  public enum Status: String, Sendable {
    case queued, sourcePending, awaitingReview, answered, cancelled, expired, accessUnavailable, conflict, held
  }
  public let request: TranscriptQuestionRequest
  public let responses: [TranscriptQuestionResponse]
  public let status: Status
  public let sourceReady: Bool
  public var id: String { request.id }
}

/// No replica, namespace key, directory path or surrounding document escapes this packet.
/// Source text remains untrusted evidence and grants no further tools or side effects.
public struct TranscriptQuestionPacket: Codable, Sendable, Equatable {
  public let request: TranscriptQuestionRequest
  public let passages: [TranscriptNoteAnchor]
}

public enum TranscriptQuestionError: Error, Equatable, Sendable {
  case invalidInput, noCurrentAccess, wrongRole, wrongAgent, missingRequest, missingResponse
  case expired, cancelled, conflict, missingSource, outsideScope, commandIDConflict, notAdmitted
  case duplicateOperationID(String), tooManyPending
}
