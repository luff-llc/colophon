import Foundation

/// Attributed organisation, never an overwrite of the person's captured cells.
public struct NotesOrganisationProposal: Sendable, Identifiable, Hashable {
  public enum Status: String, Sendable { case pending, kept, dismissed }
  public let id: String
  public let notebook: String
  public let entry: String
  public let title: String?
  public let tags: [String]
  public let markdown: String
  public let inputs: [String: String]
  public let revision: String
  public let author: String
  public let authorLabel: String
  public var status: Status = .pending
  public var reviewedMarkdown: String?
  public var reviewRevision: String?
  public var reviewedBy: String?
  public init(id: String, notebook: String, entry: String, title: String? = nil, tags: [String] = [],
    markdown: String, inputs: [String: String], revision: String, author: String, authorLabel: String,
    status: Status = .pending, reviewedMarkdown: String? = nil, reviewRevision: String? = nil, reviewedBy: String? = nil) {
    self.id = id; self.notebook = notebook; self.entry = entry; self.title = title; self.tags = tags
    self.markdown = markdown; self.inputs = inputs; self.revision = revision; self.author = author
    self.authorLabel = authorLabel; self.status = status; self.reviewedMarkdown = reviewedMarkdown
    self.reviewRevision = reviewRevision; self.reviewedBy = reviewedBy
  }
}
