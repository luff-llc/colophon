import ColophonCore
import ColophonReplica
import Foundation

/// The `notes` projection.
public struct Notebooks: Sendable {
  public struct Output: Sendable, Hashable {
    public let mime: String
    public let data: String
  }

  public struct Run: Sendable, Hashable {
    public let sourceDigest: String
    public let runtime: String
    public let outputs: [Output]
    public let error: String?
  }

  public struct Cell: Sendable, Identifiable, Hashable {
    public let id: String
    public var kind: Notes.CellKind
    public var source: String
    public var language: String?
    public var entry: String? = nil
    public var revision: String
    public var editedBy: String
    /// Concurrent edits that didn't replace this source, kept so no one's words are lost.
    public var alternatives: [String] = []
    public var lastRun: Run?

    /// Whether the recorded output came from the current source.
    public var outputIsCurrent: Bool { lastRun?.sourceDigest == Notes.digest(source) }
  }

  public struct Notebook: Sendable, Identifiable, Hashable {
    public let id: String
    public var title: String
    public var kind: String
    public var topic: String?
    public var archived = false
    public var created: Date
    public var updated: Date
    /// Position of the latest change in the agreed operation order.
    public var touched = 0
    public var order: [String] = []
    public init(id: String, title: String, kind: String = "notebook", topic: String? = nil,
      created: Date = .now, updated: Date = .now, touched: Int = 0, order: [String] = []) {
      self.id = id; self.title = title; self.kind = kind; self.topic = topic
      self.created = created; self.updated = updated; self.touched = touched; self.order = order
    }
  }

  public private(set) var notebooks: [String: Notebook] = [:]
  public private(set) var cells: [String: Cell] = [:]
  public private(set) var entries: [String: NotesEntry] = [:]
  public private(set) var attachments: [String: NotesAttachment] = [:]
  public private(set) var proposals: [String: NotesOrganisationProposal] = [:]
  /// Admitted signed records that fail the Notes domain contract. They remain in the log.
  public private(set) var invalidOperations: [String] = []
  private var cellNotebooks: [String: String] = [:]
  private var entriesByNotebook: [String: [NotesEntry]] = [:]
  private var cellsByEntry: [String: [String: [Cell]]] = [:]
  private var attachmentsByEntry: [String: [String: [NotesAttachment]]] = [:]
  private var proposalsByEntry: [String: [String: [NotesOrganisationProposal]]] = [:]
  private var proposalCurrency: [String: Bool] = [:]
  private var immutablePayloads: [String: [String: JSONValue]] = [:]
  /// Edits that arrived after their cell was deleted, by cell ID, newest last. Deleted cells stay
  /// deleted; a client may offer to restore one as a new cell.
  public private(set) var editsToDeleted: [String: [String]] = [:]
  /// The same late edits with their context, so a client can restore one in place.
  public private(set) var lateEdits: [String: [LateEdit]] = [:]

  public struct LateEdit: Sendable, Hashable {
    public let notebook: String
    public let kind: Notes.CellKind
    public let language: String?
    public let source: String
    public let by: String
    public let operation: String
  }
  private var deleted: Set<String> = []

  public init(_ view: ReplicaView) {
    for entry in view.admitted { apply(entry) }
    // Build display projections once per fold, never once per row/render.
    for entry in entries.values { entriesByNotebook[entry.notebook, default: []].append(entry) }
    for notebook in notebooks.values {
      for cell in cells(in: notebook.id) { cellsByEntry[notebook.id, default: [:]][cell.entry ?? "", default: []].append(cell) }
    }
    for a in attachments.values { attachmentsByEntry[a.notebook, default: [:]][a.entry ?? "", default: []].append(a) }
    for p in proposals.values { proposalsByEntry[p.notebook, default: [:]][p.entry, default: []].append(p) }
    for key in entriesByNotebook.keys {
      entriesByNotebook[key]?.sort { ($0.touched, $0.id) > ($1.touched, $1.id) }
    }
    for notebook in attachmentsByEntry.keys {
      for entry in attachmentsByEntry[notebook, default: [:]].keys { attachmentsByEntry[notebook]?[entry]?.sort { $0.id < $1.id } }
    }
    for notebook in proposalsByEntry.keys {
      for entry in proposalsByEntry[notebook, default: [:]].keys { proposalsByEntry[notebook]?[entry]?.sort { $0.id < $1.id } }
    }
    for proposal in proposals.values { proposalCurrency[proposal.id] = proposalInputsAreCurrent(proposal) }
  }

  public func cells(in notebook: String) -> [Cell] { (notebooks[notebook]?.order ?? []).compactMap { cells[$0] } }

  public func entries(in notebook: String) -> [NotesEntry] {
    entriesByNotebook[notebook] ?? []
  }

  public func cells(in notebook: String, entry: String?) -> [Cell] {
    cellsByEntry[notebook]?[entry ?? ""] ?? []
  }

  public func attachments(in notebook: String, entry: String?) -> [NotesAttachment] {
    attachmentsByEntry[notebook]?[entry ?? ""] ?? []
  }

  public func proposals(in notebook: String, entry: String) -> [NotesOrganisationProposal] {
    proposalsByEntry[notebook]?[entry] ?? []
  }

  public func proposalInputsAreCurrent(_ proposal: NotesOrganisationProposal) -> Bool {
    if let saved = proposals[proposal.id], saved == proposal, let current = proposalCurrency[proposal.id] { return current }
    let inputs = cells(in: proposal.notebook).filter { $0.entry == proposal.entry }
    return inputs.allSatisfy { $0.alternatives.isEmpty }
      && proposal.inputs == Dictionary(uniqueKeysWithValues: inputs.map { ($0.id, $0.revision) })
  }

  public var active: [Notebook] { notebooks.values.filter { !$0.archived }.sorted { $0.touched > $1.touched } }
  private var applied = 0

  private mutating func apply(_ admitted: AdmittedOperation) {
    let operation = admitted.operation
    let author = admitted.authorLabel
    let payload = operation.payload
    guard operation.v == 1, NotesContentValidation.valid(operation.kind, payload) else {
      invalidOperations.append(operation.id); return
    }
    applied += 1
    guard let notebookID = payload["notebook"]?.string else { return }
    if operation.kind == Notes.Kind.create {
      guard notebooks[notebookID] == nil, let title = payload["title"]?.string else { return }
      notebooks[notebookID] = Notebook(id: notebookID, title: title, kind: payload["kind"]?.string ?? "notebook",
        topic: payload["topic"]?.string, created: operation.created, updated: operation.created, touched: applied)
      return
    }
    guard var notebook = notebooks[notebookID] else { return }
    if [Notes.Kind.putEntry, Notes.Kind.attach, Notes.Kind.propose, Notes.Kind.reviewProposal].contains(operation.kind) {
      guard applyContent(admitted, notebook: notebookID) else { invalidOperations.append(operation.id); return }
    }
    if operation.kind.hasPrefix("cell."), let cellID = payload["cell"]?.string, let owner = cellNotebooks[cellID], owner != notebookID {
      invalidOperations.append(operation.id); return
    }
    if operation.kind == Notes.Kind.putCell, let entryID = payload["entry"]?.string,
      entries[entryID]?.notebook != notebookID {
      invalidOperations.append(operation.id); return
    }
    let activeEntry = payload["entry"]?.string ?? payload["cell"]?.string.flatMap { cells[$0]?.entry }
      ?? payload["proposal"]?.string.flatMap { proposals[$0]?.entry }
    if let activeEntry, entries[activeEntry]?.notebook == notebookID { entries[activeEntry]?.touched = applied }
    notebook.updated = max(notebook.updated, operation.created)
    notebook.touched = applied
    defer { notebooks[notebookID] = notebook }
    switch operation.kind {
    case Notes.Kind.rename:
      if let title = payload["title"]?.string { notebook.title = title }
    case Notes.Kind.archive:
      notebook.archived = payload["archived"]?.bool ?? true
    case Notes.Kind.putCell:
      guard let id = payload["cell"]?.string, let source = payload["source"]?.string,
        let kind = payload["kind"]?.string.flatMap(Notes.CellKind.init(rawValue:))
      else { return }
      if deleted.contains(id) {
        editsToDeleted[id, default: []].append(source)
        lateEdits[id, default: []].append(LateEdit(notebook: notebookID, kind: kind, language: payload["language"]?.string,
          source: source, by: author, operation: operation.id))
        return
      }
      if var cell = cells[id] {
        if let expect = payload["expect"]?.string, expect != cell.revision {
          cell.alternatives.append(source)
        } else {
          cell.source = source
          cell.kind = kind
          cell.language = payload["language"]?.string ?? cell.language
          if let entry = payload["entry"]?.string { cell.entry = entry }
          cell.revision = operation.id
          cell.editedBy = author
        }
        cells[id] = cell
      } else {
        cells[id] = Cell(id: id, kind: kind, source: source, language: payload["language"]?.string, revision: operation.id,
          editedBy: author)
        cells[id]?.entry = payload["entry"]?.string
        cellNotebooks[id] = notebookID
        insert(id, after: payload["after"]?.string, in: &notebook)
      }
    case Notes.Kind.resolveCell:
      guard let id = payload["cell"]?.string, var cell = cells[id], let source = payload["source"]?.string else { return }
      if let expect = payload["expect"]?.string, expect != cell.revision {
        cell.alternatives.append(source)
      } else {
        cell.source = source
        cell.alternatives = []
        cell.revision = operation.id
        cell.editedBy = author
      }
      cells[id] = cell
    case Notes.Kind.moveCell:
      guard let id = payload["cell"]?.string, notebook.order.contains(id) else { return }
      notebook.order.removeAll { $0 == id }
      insert(id, after: payload["after"]?.string, in: &notebook)
    case Notes.Kind.deleteCell:
      guard let id = payload["cell"]?.string else { return }
      notebook.order.removeAll { $0 == id }
      cells[id] = nil
      deleted.insert(id)
      cellNotebooks[id] = notebookID
    case Notes.Kind.output:
      guard let id = payload["cell"]?.string, cells[id] != nil, let digest = payload["sourceDigest"]?.string else { return }
      let outputs = (payload["outputs"]?.array ?? []).compactMap { value -> Output? in
        guard let object = value.object, let mime = object["mime"]?.string, let data = object["data"]?.string else { return nil }
        return Output(mime: mime, data: data)
      }
      cells[id]?.lastRun = Run(sourceDigest: digest, runtime: payload["runtime"]?.string ?? "", outputs: outputs,
        error: payload["error"]?.string)
    default:
      break
    }
  }

  private mutating func applyContent(_ admitted: AdmittedOperation, notebook: String) -> Bool {
    let op = admitted.operation
    let p = op.payload
    switch op.kind {
    case Notes.Kind.putEntry:
      guard let id = p["entry"]?.string, let tags = NotesContentValidation.tags(p) else { return false }
      let version = NotesEntry.Version(title: p["title"]?.string, date: p["date"]?.string, tags: tags,
        revision: op.id, author: admitted.author, authorLabel: admitted.authorLabel)
      if var entry = entries[id] {
        guard entry.notebook == notebook else { return false }
        if p["expect"]?.string != entry.revision {
          entry.alternatives.append(version)
        } else {
          entry.current = version
          // Alternatives are retained: an ordinary metadata edit does not settle concurrent versions.
        }
        entries[id] = entry
      } else {
        guard p["expect"] == nil || p["expect"] == .null else { return false }
        entries[id] = NotesEntry(id: id, notebook: notebook, current: version)
      }
      return true
    case Notes.Kind.attach:
      guard let id = p["attachment"]?.string, let name = p["name"]?.string,
        let role = p["role"]?.string.flatMap(NotesAttachment.Role.init(rawValue:)) else { return false }
      if let entry = p["entry"]?.string, entries[entry]?.notebook != notebook { return false }
      let key = "attachment/" + id
      if let prior = immutablePayloads[key] { return prior == p && attachments[id]?.author == admitted.author }
      attachments[id] = NotesAttachment(id: id, notebook: notebook, entry: p["entry"]?.string, role: role,
        name: name, mime: p["mime"]?.string, blob: BlobRef(json: p["blob"]),
        source: NotesContentValidation.source(p["source"]), revision: op.id, author: admitted.author,
        authorLabel: admitted.authorLabel)
      immutablePayloads[key] = p
      return true
    case Notes.Kind.propose:
      guard let id = p["proposal"]?.string, let entry = p["entry"]?.string,
        entries[entry]?.notebook == notebook, let markdown = p["markdown"]?.string,
        let tags = NotesContentValidation.tags(p), let inputs = p["inputs"]?.object else { return false }
      let key = "proposal/" + id
      if let prior = immutablePayloads[key] { return prior == p && proposals[id]?.author == admitted.author }
      let proposal = NotesOrganisationProposal(id: id, notebook: notebook, entry: entry, title: p["title"]?.string,
        tags: tags, markdown: markdown, inputs: inputs.compactMapValues(\.string), revision: op.id,
        author: admitted.author, authorLabel: admitted.authorLabel)
      guard proposalInputsAreCurrent(proposal) else { return false }
      proposals[id] = proposal
      immutablePayloads[key] = p
      return true
    case Notes.Kind.reviewProposal:
      guard let id = p["proposal"]?.string, var proposal = proposals[id], proposal.notebook == notebook,
        let keep = p["keep"]?.bool, admitted.authorRole != .agent, admitted.authorRole != .service else { return false }
      let desired: NotesOrganisationProposal.Status = keep ? .kept : .dismissed
      if proposal.status != .pending {
        return proposal.status == desired && proposal.reviewedMarkdown == p["markdown"]?.string && proposal.reviewedBy == admitted.author
      }
      guard !keep || proposalInputsAreCurrent(proposal) else { return false }
      proposal.status = desired
      proposal.reviewRevision = op.id
      proposal.reviewedBy = admitted.author
      proposal.reviewedMarkdown = keep ? p["markdown"]?.string : nil
      proposals[id] = proposal
      return true
    default:
      return false
    }
  }

  /// Inserts after an existing cell, or at the top when `after` is nil or no longer present.
  private func insert(_ id: String, after: String?, in notebook: inout Notebook) {
    if let after, let index = notebook.order.firstIndex(of: after) {
      notebook.order.insert(id, at: index + 1)
    } else {
      notebook.order.insert(id, at: 0)
    }
  }
}
