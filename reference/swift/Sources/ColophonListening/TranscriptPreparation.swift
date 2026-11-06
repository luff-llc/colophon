import ColophonCore
import Foundation

/// Facts retained with the immutable source. Unknown language, timing and recording alignment
/// stay unknown; publisher origin alone says nothing about authorship or audio alignment.
public struct TranscriptSourceReceipt: Codable, Hashable, Sendable {
  public enum Completeness: String, Codable, Sendable { case complete, partial, unknown }
  public var sourceURL: String?
  public var finalURL: String?
  public var retrieved: Date
  public var raw: BlobRef?
  public var mediaType: String?
  public var etag: String?
  public var lastModified: String?
  public var parser: String?
  public var engine: String?
  public var runtime: String?
  public var language: String?
  public var recordingSource: TranscriptRecordingSource?
  public var recordingDigest: String?
  public var completeness: Completeness

  public init(sourceURL: String? = nil, finalURL: String? = nil, retrieved: Date = .now,
    raw: BlobRef? = nil, mediaType: String? = nil, etag: String? = nil, lastModified: String? = nil,
    parser: String? = nil, engine: String? = nil, runtime: String? = nil, language: String? = nil,
    recordingDigest: String? = nil, recordingSource: TranscriptRecordingSource? = nil, completeness: Completeness = .unknown)
  {
    self.sourceURL = sourceURL; self.finalURL = finalURL; self.retrieved = retrieved
    self.raw = raw; self.mediaType = mediaType; self.etag = etag; self.lastModified = lastModified
    self.parser = parser; self.engine = engine; self.runtime = runtime; self.language = language
    self.recordingSource = recordingSource
    self.recordingDigest = recordingDigest; self.completeness = completeness
  }

  /// Reject credential-bearing and non-web addresses in a shared receipt. A local import
  /// retains bytes, never the person's private filesystem path.
  public static func webURL(_ value: String?) -> String? {
    guard let value, let parts = URLComponents(string: value), let scheme = parts.scheme?.lowercased(),
      ["http", "https"].contains(scheme), parts.user == nil, parts.password == nil,
      let host = parts.host, !host.isEmpty else { return nil }
    var clean = parts
    clean.fragment = nil
    return clean.url?.absoluteString
  }

  public func validate() throws {
    try recordingSource?.validate()
    guard recordingDigest.map(PodcastRecordingIdentity.isDigest) ?? true,
      sourceURL == nil || Self.webURL(sourceURL) == sourceURL,
      finalURL == nil || Self.webURL(finalURL) == finalURL,
      [etag, lastModified, mediaType, parser, engine, runtime, language].allSatisfy({ value in
        value.map { $0.utf8.count <= 4096 && !$0.contains("\r") && !$0.contains("\n") } ?? true
      }) else { throw TranscriptPreparationError.invalidSource }
  }
}

public struct TranscriptPreparationRequest: Codable, Hashable, Sendable {
  public enum Policy: String, Codable, Sendable { case publisherThenSpeech, speech, manualImport, mac }
  public var id: String
  public var libraryID: String
  public var episode: String
  public var show: String
  public var audioURL: String?
  public var recordingSource: TranscriptRecordingSource?
  public var recordingDigest: String?
  public var language: String?
  public var feed: String?
  public var enclosure: String?
  public var title: String?
  public var workerID: String?
  public var policy: Policy
  /// A clipping depends on retaining the exact recording until a complete result applies.
  public var holdAudio: Bool
  public init(id: String, libraryID: String, episode: String, show: String,
    audioURL: String? = nil, recordingDigest: String? = nil, recordingSource: TranscriptRecordingSource? = nil, language: String? = nil,
    feed: String? = nil, enclosure: String? = nil, title: String? = nil,
    policy: Policy = .publisherThenSpeech, holdAudio: Bool = false, workerID: String? = nil)
  {
    self.id = id; self.libraryID = libraryID; self.episode = episode; self.show = show
    self.recordingSource = recordingSource
    self.audioURL = audioURL; self.recordingDigest = recordingDigest; self.language = language
    self.feed = feed; self.enclosure = enclosure; self.title = title; self.policy = policy; self.holdAudio = holdAudio; self.workerID = workerID
  }
}

public struct TranscriptPreparationResult: Codable, Hashable, Sendable {
  public var document: TranscriptDocument
  public var source: String
  public var receipt: TranscriptSourceReceipt
  /// Before commit this holds original input bytes. The signed receipt subsequently pins
  /// their encrypted BlobRef; the durable ready file survives a crash between both writes.
  public var raw: Data?
  public init(document: TranscriptDocument, source: String, receipt: TranscriptSourceReceipt, raw: Data? = nil) {
    self.document = document; self.source = source; self.receipt = receipt; self.raw = raw
  }
  public func validate() throws {
    try receipt.validate()
    guard !document.text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
      document.text.utf8.count <= 20_000_000, (raw?.count ?? 0) <= 5_000_000,
      ["publisher", "person", "onDevice", "agent"].contains(source)
    else { throw TranscriptPreparationError.invalidSource }
    var previous: Double = 0
    for word in document.words ?? [] {
      guard !word.text.isEmpty, word.start.isFinite, word.end.isFinite,
        word.start >= previous, word.end > word.start else { throw TranscriptPreparationError.invalidSource }
      previous = word.start
    }
    if source == "onDevice" {
      guard receipt.recordingDigest != nil, receipt.engine != nil else { throw TranscriptPreparationError.invalidSource }
    }
  }
}

public enum TranscriptPreparationError: LocalizedError, Equatable {
  case invalidSource, conflictingRequest, missingRequest, cancelled, wrongWorker, noAccess, recordingChanged, notReady
  public var errorDescription: String? {
    switch self {
    case .invalidSource: String(localized: "The transcript source or preparation result is invalid.")
    case .conflictingRequest: String(localized: "This preparation ID already belongs to a different request.")
    case .missingRequest: String(localized: "The preparation request is unavailable.")
    case .cancelled: String(localized: "Preparation was cancelled. The retained source is unchanged.")
    case .wrongWorker: String(localized: "This request is assigned to another worker.")
    case .noAccess: String(localized: "Current permission to prepare transcripts is unavailable.")
    case .recordingChanged: String(localized: "The recording changed. The retained result belongs to the earlier recording.")
    case .notReady: String(localized: "The complete transcript result is not ready to apply.")
    }
  }
}
