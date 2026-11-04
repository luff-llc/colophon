import ColophonCore
import Foundation

/// An immutable retained file or descriptive source pointer. A pointer never grants access.
public struct NotesAttachment: Sendable, Identifiable, Hashable {
  public enum Role: String, Sendable, CaseIterable { case reading, slides, handout, image, audio, file, link }

  /// `web` is a bookmark, not retained evidence. `library` pins an exact signed revision.
  /// Location fields are descriptive until the source's own resolver verifies them.
  public struct SourceReference: Sendable, Hashable {
    public let kind: String
    public let url: String?
    public let libraryID: String?
    public let namespace: String?
    public let artifactID: String?
    public let revision: String?
    public let quote: String?
    public let page: Int?
    public let seconds: Double?
    public let recordingDigest: String?

    public init(url: String) {
      kind = "web"; self.url = url
      libraryID = nil; namespace = nil; artifactID = nil; revision = nil
      quote = nil; page = nil; seconds = nil; recordingDigest = nil
    }

    public init(libraryID: String, namespace: String, artifactID: String, revision: String,
      quote: String? = nil, page: Int? = nil, seconds: Double? = nil, recordingDigest: String? = nil)
    {
      kind = "library"; url = nil; self.libraryID = libraryID; self.namespace = namespace
      self.artifactID = artifactID; self.revision = revision; self.quote = quote
      self.page = page; self.seconds = seconds; self.recordingDigest = recordingDigest
    }

    public var json: JSONValue {
      .object(["kind": .string(kind), "url": JSONValue(url), "library": JSONValue(libraryID),
        "namespace": JSONValue(namespace), "artifact": JSONValue(artifactID), "revision": JSONValue(revision),
        "quote": JSONValue(quote), "page": JSONValue(page), "seconds": JSONValue(seconds),
        "recording": JSONValue(recordingDigest)])
    }
  }

  public let id: String
  public let notebook: String
  public let entry: String?
  public let role: Role
  public let name: String
  public let mime: String?
  public let blob: BlobRef?
  public let source: SourceReference?
  public let revision: String
  public let author: String
  public let authorLabel: String
  public init(id: String, notebook: String, entry: String? = nil, role: Role, name: String,
    mime: String? = nil, blob: BlobRef? = nil, source: SourceReference? = nil, revision: String,
    author: String, authorLabel: String) {
    self.id = id; self.notebook = notebook; self.entry = entry; self.role = role; self.name = name
    self.mime = mime; self.blob = blob; self.source = source; self.revision = revision
    self.author = author; self.authorLabel = authorLabel
  }
}
