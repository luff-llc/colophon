import Foundation

public enum AdditionalAccessError: Error, Equatable, LocalizedError {
  case invalidRequest, staleGrant, withdrawn, conflictingRequest, requestChanged, authorityChanged
  case invalidSelection, incompleteApproval, journalConflict, exceedsLimits
  public var errorDescription: String? {
    switch self {
    case .invalidRequest: "The additional-access request is invalid."
    case .staleGrant: "Library access changed. Make a new explicit request."
    case .withdrawn: "This request was withdrawn. A new request needs a new request ID."
    case .conflictingRequest: "This request ID already names a different decision."
    case .requestChanged: "The current request changed or was withdrawn. Review it again."
    case .authorityChanged: "Library authority changed before approval could be committed."
    case .invalidSelection: "Select only additional areas named in the request."
    case .incompleteApproval: "The additional grant or its key shares are incomplete."
    case .journalConflict: "The signed approval no longer matches the library's authority history."
    case .exceedsLimits: "The additional-access record exceeds its bounded format limits."
    }
  }
}
