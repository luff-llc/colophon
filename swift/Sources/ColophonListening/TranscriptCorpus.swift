import ColophonCore
import Foundation

/// Authenticated provenance of a selected, locally retained transcript. `timed` describes the
/// source, not verified alignment to the recording currently downloaded on this device.
public struct TranscriptCorpusSource: Codable, Hashable, Sendable {
  public let reference: SharedTranscriptReference
  public let source: String
  public let language: String?
  public let timed: Bool
  public let audio: String?
  public let authorID: String
  public let authorLabel: String
  public let showTitle: String
  public init(reference: SharedTranscriptReference, source: String, language: String?, timed: Bool,
    audio: String?, authorID: String, authorLabel: String, showTitle: String) {
    self.reference = reference; self.source = source; self.language = language; self.timed = timed
    self.audio = audio; self.authorID = authorID; self.authorLabel = authorLabel; self.showTitle = showTitle
  }
  public var episodeID: String { reference.episode }
  public var showID: String { reference.show }
  public var episodeTitle: String { reference.episode }
}

public struct TranscriptCorpusCoverage: Codable, Equatable, Sendable {
  public let selectedCount: Int
  public let indexedCount: Int
  public let missingBlobCount: Int
  public let invalidBlobCount: Int
  public let heldCount: Int
  /// Counts indexing JSON decodes in this actor's lifetime; bounded source-page validation is separate.
  public let decodedDocumentCount: Int
  public var isComplete: Bool { indexedCount == selectedCount && heldCount == 0 }
}

public struct TranscriptCorpusHit: Hashable, Sendable, Identifiable {
  public let source: TranscriptCorpusSource
  public let anchor: TranscriptNoteAnchor
  public let score: Int
  /// First matched term in original document coordinates, separate from excerpt context.
  public let matchStartUTF16: Int
  public init(source: TranscriptCorpusSource, anchor: TranscriptNoteAnchor, score: Int, matchStartUTF16: Int) {
    self.source = source; self.anchor = anchor; self.score = score; self.matchStartUTF16 = matchStartUTF16
  }
  public var id: String { "\(source.reference.revision):\(anchor.startUTF16)" }
  public var snippet: String { anchor.quote }
}

/// Opaque continuation bound to this exact query and corpus generation. Refreshing an unchanged
/// corpus preserves it; arrivals, changed selection and access changes invalidate it.
public struct TranscriptCorpusCursor: Codable, Hashable, Sendable {
  let generation: String
  let queryDigest: String
  let offset: Int
}

public struct TranscriptCorpusPage: Sendable {
  public let hits: [TranscriptCorpusHit]
  public let coverage: TranscriptCorpusCoverage
  public let nextCursor: TranscriptCorpusCursor?
}

public enum TranscriptCorpusMatchMode: String, Codable, Hashable, Sendable {
  /// Every whole term must be present in one passage.
  case allTerms
  /// Ignore common English question words and require at least 60% of meaningful terms.
  case question
}

public enum TranscriptCorpusError: Error, Equatable, Sendable {
  case staleCursor, invalidQuery
}
