import ColophonCore
import Foundation

/// A pointer to one signed, immutable transcript operation and its encrypted content.
/// It is not an enclosure URL, a recording-byte identity, or a copy of the transcript.
public struct SharedTranscriptReference: Codable, Hashable, Sendable {
  public let libraryID: String
  public let episode: String
  public let show: String
  public let revision: String
  public let blob: BlobRef

  public init(libraryID: String, episode: String, show: String, revision: String, blob: BlobRef) {
    self.libraryID = libraryID
    self.episode = episode
    self.show = show
    self.revision = revision
    self.blob = blob
  }
}

/// An exact text excerpt from a pinned transcript revision. Timing and recording-byte
/// binding require a later additive contract; this first slice does not infer them.
public struct SharedTranscriptCitation: Codable, Hashable, Sendable {
  public let quote: String
  public init(quote: String) { self.quote = quote }
}

public struct SharedTranscriptContribution: Codable, Sendable, Equatable {
  public let id: String
  public let proposalRevision: String
  public let text: String
  public let citation: SharedTranscriptCitation
  public let proposedBy: String
  public let proposedByLabel: String
  public var acceptanceRevision: String?
  public var acceptedBy: String?
  public var acceptedByLabel: String?
  /// Optional intentional note authored in the separately signed acceptance operation.
  public var intentionalNote: String?
}

public struct SharedTranscriptReceipt: Codable, Sendable, Equatable {
  public enum Outcome: String, Codable, Sendable { case applied, staleRevision, invalidProposal, invalidCitation }
  public let commandID: String
  public let author: String
  public let operationID: String
  public let outcome: Outcome
  public let revision: String?
  public let observedRevision: String?
}

public struct SharedTranscriptState: Codable, Sendable {
  public let contributions: [SharedTranscriptContribution]
  public let receipts: [SharedTranscriptReceipt]
  /// Latest applied proposal or acceptance revision for each contribution ID.
  public let currentRevisionByContributionID: [String: String]
  /// Signed context operations held for holder review; they do not enter the admitted fold.
  public let heldContextCount: Int
  /// Signer of the transcript operation, separate from its self-described source label.
  public let transcriptAuthor: String?
  public let transcriptAuthorLabel: String?
}

public enum SharedTranscriptError: LocalizedError, Equatable {
  case noCurrentAccess, missingTranscript, wrongLibrary, wrongCitation, wrongRole
  case invalidCommand, commandIDConflict, duplicateOperationID(String)

  public var errorDescription: String? {
    switch self {
    case .noCurrentAccess:
      String(localized: "Current access to shared podcast transcripts is unavailable or expired.")
    case .missingTranscript:
      String(localized: "The pinned transcript source is unavailable on this device. Sync and retry.")
    case .wrongLibrary:
      String(localized: "This transcript reference belongs to a different library.")
    case .wrongCitation:
      String(localized: "The quoted text does not occur in the pinned transcript revision.")
    case .wrongRole:
      String(localized: "This member does not have the required role or write grant.")
    case .invalidCommand:
      String(localized: "The shared transcript command is invalid or was not admitted.")
    case .commandIDConflict:
      String(localized: "This command ID was already used with a different signed request.")
    case .duplicateOperationID(let id):
      String(localized: "Conflicting signed operations share revision \(id); shared transcript state cannot be trusted.")
    }
  }
}
