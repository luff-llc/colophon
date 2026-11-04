import Foundation

/// A session, journal entry or thought within a notebook. Original cells stay independent.
public struct NotesEntry: Sendable, Identifiable, Hashable {
  public struct Version: Sendable, Hashable {
    public let title: String?
    public let date: String?
    public let tags: [String]
    public let revision: String
    public let author: String
    public let authorLabel: String
    public init(title: String? = nil, date: String? = nil, tags: [String] = [], revision: String,
      author: String, authorLabel: String) {
      self.title = title; self.date = date; self.tags = tags; self.revision = revision
      self.author = author; self.authorLabel = authorLabel
    }
  }
  public let id: String
  public let notebook: String
  public var current: Version
  public var alternatives: [Version] = []
  /// Latest activity in the deterministic admitted-operation order, never author wall time.
  public var touched = 0
  public init(id: String, notebook: String, current: Version, alternatives: [Version] = [], touched: Int = 0) {
    self.id = id; self.notebook = notebook; self.current = current; self.alternatives = alternatives; self.touched = touched
  }
  public var title: String? { current.title }
  public var date: String? { current.date }
  public var tags: [String] { current.tags }
  public var revision: String { current.revision }
  public var author: String { current.author }
  public var authorLabel: String { current.authorLabel }
}
