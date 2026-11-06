import ColophonCore
import ColophonReplica
import Foundation

/// Episode notes, reviewed ad segments and transcripts: the parts of listening worth keeping and
/// sharing with other devices and agents.
public extension Podcasts {
  enum ContentKind {
    public static let addNote = "note.add"
    public static let editNote = "note.edit"
    public static let resolveNote = "note.resolve"
    public static let deleteNote = "note.delete"
    public static let segments = "episode.segments"
    public static let transcript = "episode.transcript"
  }

  /// A note at a moment in an episode. `origin` is `person` or `ai` (an on-device or agent answer
  /// the person kept), so derived text is never mistaken for the person's own words.
  static func note(_ note: String = UUID().uuidString.lowercased(), episode: String, show: String, seconds: Double?,
    text: String, quote: String? = nil, origin: String = "person", anchor: TranscriptNoteAnchor? = nil) -> Command
  {
    var payload: [String: JSONValue] = ["note": .string(note), "episode": .string(episode), "show": .string(show),
      "seconds": JSONValue(seconds), "text": .string(text), "quote": JSONValue(quote), "origin": .string(origin)]
    if let anchor { payload["transcriptAnchor"] = anchor.json }
    return command(ContentKind.addNote, payload)
  }

  static func editNote(_ note: String, text: String, expect: String?) -> Command {
    command(ContentKind.editNote, ["note": .string(note), "text": .string(text), "expect": JSONValue(expect)])
  }

  static func resolveNote(_ note: String, text: String, expect: String?) -> Command {
    command(ContentKind.resolveNote, ["note": .string(note), "text": .string(text), "expect": JSONValue(expect)])
  }

  static func deleteNote(_ note: String) -> Command { command(ContentKind.deleteNote, ["note": .string(note)]) }

  /// Ad (or other) segments for one specific audio file. `source` is `detected` (by an engine,
  /// named in `detector`) or `person`; a person's review always wins over detection for that
  /// audio. `audio` identifies the file the times refer to (its enclosure URL or digest), because
  /// dynamic ad insertion changes timings between downloads.
  static func segments(episode: String, show: String, audio: String, segments: [(start: Double, end: Double, kind: String)],
    source: String, detector: String? = nil) -> Command
  {
    command(ContentKind.segments, ["episode": .string(episode), "show": .string(show), "audio": .string(audio),
      "source": .string(source), "detector": JSONValue(detector),
      "segments": .array(segments.map { .object(["start": .number($0.start), "end": .number($0.end), "kind": .string($0.kind)]) })])
  }

  /// A transcript, stored as a blob: JSON `{"text": …, "words"?: [{"text", "start", "end"}]}`.
  /// `source` is `publisher`, `onDevice` or `agent`. `audio` is the digest of the recording a
  /// transcript was made from, when it was made from one: its times hold for those bytes.
  static func transcript(episode: String, show: String, source: String, language: String?, blob: BlobRef,
    timed: Bool, audio: String? = nil) -> Command
  {
    command(ContentKind.transcript, ["episode": .string(episode), "show": .string(show), "source": .string(source),
      "language": JSONValue(language), "blob": blob.json, "timed": .bool(timed), "audio": JSONValue(audio)])
  }
}

extension Podcasts {
  /// Timed words grouped into sentences: a break after ., ? or !, or a pause over 1.2 s.
  static func segments(of words: [TranscriptDocument.Word]) -> [(start: Double, end: Double, text: String)] {
    var result: [(start: Double, end: Double, text: String)] = []
    var current: [TranscriptDocument.Word] = []
    func close() {
      guard let first = current.first, let last = current.last else { return }
      result.append((first.start, last.end, current.map(\.text).joined(separator: " ")))
      current = []
    }
    for word in words {
      if let last = current.last, word.start - last.end > 1.2 { close() }
      current.append(word)
      if let mark = word.text.last, ".?!".contains(mark) { close() }
    }
    close()
    return result
  }
}

/// What a transcript blob contains.
public struct TranscriptDocument: Codable, Sendable, Hashable {
  public struct Word: Codable, Sendable, Hashable {
    public let text: String
    public let start: Double
    public let end: Double
    /// Optional span provenance: "word" is existing word timing; "passage" is a
    /// whole-cue fallback. Absence is legacy/unspecified: retain a conservative legacy
    /// interpretation, especially when one span covers a whole paragraph.
    /// Preserve unknown future strings when decoding/encoding; readers must not use
    /// them to upgrade precision or discard otherwise readable text and cue times.
    public let timing: String?
    public init(text: String, start: Double, end: Double, timing: String? = nil) {
      self.text = text
      self.start = start
      self.end = end
      self.timing = timing
    }
  }

  public let text: String
  public let words: [Word]?

  public init(text: String, words: [Word]?) {
    self.text = text
    self.words = words
  }
}

public extension Replica {
  /// Stores a transcript as a blob and records it for the episode.
  @discardableResult
  func saveTranscript(_ document: TranscriptDocument, episode: String, show: String, source: String,
    language: String?, audio: String? = nil) throws -> ColophonOperation
  {
    let blob = try putBlob(Canonical.encode(document), in: Podcasts.namespace)
    return try perform(Podcasts.transcript(episode: episode, show: show, source: source, language: language, blob: blob,
      timed: document.words?.isEmpty == false, audio: audio))
  }

  /// The best transcript recorded for an episode, if its blob has synced here.
  func transcript(of episode: String, in listening: Listening) throws -> TranscriptDocument? {
    guard let record = listening.transcripts[episode], let data = try blob(record.blob, in: Podcasts.namespace) else {
      return nil
    }
    return try Canonical.decode(TranscriptDocument.self, from: data)
  }
}
