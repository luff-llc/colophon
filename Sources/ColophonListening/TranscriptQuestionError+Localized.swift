import Foundation

extension TranscriptQuestionError: LocalizedError {
  public var errorDescription: String? {
    switch self {
    case .invalidInput: String(localized: "Choose a question and up to 20 retained passages.")
    case .noCurrentAccess, .wrongRole: String(localized: "Current library permission for this request is unavailable.")
    case .wrongAgent: String(localized: "This question is assigned to another agent.")
    case .missingRequest: String(localized: "The question request hasn't arrived on this device.")
    case .missingResponse: String(localized: "The agent's answer hasn't arrived on this device.")
    case .expired: String(localized: "This request expired. Send a new question to continue.")
    case .cancelled: String(localized: "This request was cancelled. Its source passages are retained.")
    case .conflict: String(localized: "Conflicting records need review before this request can continue.")
    case .missingSource: String(localized: "A cited source is unavailable. Wait for its file to arrive, then refresh.")
    case .outsideScope: String(localized: "The answer cites a passage outside this request.")
    case .commandIDConflict: String(localized: "This retry ID belongs to a different request.")
    case .notAdmitted: String(localized: "Library permissions held this change. Refresh before trying again.")
    case .duplicateOperationID: String(localized: "The library contains conflicting source records.")
    case .tooManyPending: String(localized: "Finish or cancel an earlier agent request before sending another.")
    }
  }
}
