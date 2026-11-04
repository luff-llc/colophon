import ColophonCore
import ColophonReplica
import Foundation

/// Chapters made for an episode that has none from its publisher (from its transcript, by a
/// device or an agent, or by the person). Like ad segments, they are bound to one recording by
/// its digest, because their times only hold for those bytes.
public extension Podcasts {
  enum ChapterKind {
    public static let save = "episode.chapters"
  }

  /// `source` is `generated` (named in `origin`, such as "Apple Intelligence from the
  /// transcript") or `person`; a person's chapters beat generated ones for the same recording.
  static func chapters(episode: String, show: String, audio: String, entries: [(start: Double, title: String)],
    source: String, origin: String?) -> Command
  {
    command(ChapterKind.save, ["episode": .string(episode), "show": .string(show), "audio": .string(audio),
      "source": .string(source), "origin": JSONValue(origin),
      "entries": .array(entries.map { .object(["start": .number($0.start), "title": .string($0.title)]) })])
  }

  internal static var chapterSpecs: [OperationSpec] {
    [
      OperationSpec(ChapterKind.save, "Record chapters for one recording of an episode that has none from its publisher.", [
        FieldSpec("episode", .string, required: true, "The episode."),
        FieldSpec("show", .string, required: true, "The show."),
        FieldSpec("audio", .string, required: true, "Lowercase hex SHA-256 of the audio file the times refer to."),
        FieldSpec("source", .string, required: true, "Who made them. Agents write generated.",
          values: ["generated", "person"]),
        FieldSpec("origin", .string, "How they were made, for example the model and that it read the transcript."),
        FieldSpec("entries", .objects, required: true, "The chapters, each {\"start\": seconds, \"title\": text}."),
      ]),
    ]
  }
}

public extension Listening {
  struct ChapterSet: Sendable, Hashable {
    public struct Entry: Sendable, Hashable {
      public let start: Double
      public let title: String
    }
    public let audio: String
    public let entries: [Entry]
    public let source: String
    public let origin: String?
    public let by: String
  }

  /// The chapters in force for an episode's recording, if any were recorded.
  func chapterSet(for episode: String, recordingDigest: String?) -> ChapterSet? {
    guard let recordingDigest else { return nil }
    return chapters[episode]?[recordingDigest]
  }
}
