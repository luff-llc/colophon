import Foundation

public enum FileEvidenceManifestError: Error, Equatable, LocalizedError {
  case unsupportedFormat
  case invalidStructure
  case exceedsLimits
  case invalidReference
  case pageMismatch

  public var errorDescription: String? {
    switch self {
    case .unsupportedFormat: "The file evidence manifest format is unsupported."
    case .invalidStructure: "The file evidence manifest has an invalid structure or ordering."
    case .exceedsLimits: "The file evidence manifest exceeds its version's limits."
    case .invalidReference: "A file evidence reference is invalid or inconsistent."
    case .pageMismatch: "The supplied file evidence page does not match its reference."
    }
  }
}
