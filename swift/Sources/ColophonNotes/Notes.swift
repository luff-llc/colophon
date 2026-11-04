import ColophonCore
import ColophonReplica
import Foundation

/// `notes` v1: notebooks of cells — Markdown, LaTeX, code and raw text — with recorded outputs.
///
/// Running code is a client capability, not part of the data: a client that ran a cell records
/// the output together with the digest of the source it ran, so another device can show the
/// output and tell whether it's stale.
public enum Notes: DomainModule {
  public static let namespace = "notes"
  public static let version = 1
  public static let kinds = [Kind.create, Kind.rename, Kind.archive, Kind.putCell, Kind.moveCell, Kind.deleteCell,
    Kind.output, Kind.resolveCell, Kind.putEntry, Kind.attach, Kind.propose, Kind.reviewProposal]

  public enum Kind {
    public static let create = "notebook.create"
    public static let rename = "notebook.rename"
    public static let archive = "notebook.archive"
    public static let putCell = "cell.put"
    public static let moveCell = "cell.move"
    public static let deleteCell = "cell.delete"
    public static let resolveCell = "cell.resolve"
    public static let output = "cell.output"
    public static let putEntry = "entry.put"
    public static let attach = "attachment.add"
    public static let propose = "entry.propose"
    public static let reviewProposal = "proposal.review"
  }

  public enum CellKind: String, Sendable, CaseIterable { case markdown, latex, code, raw }

  /// Notebook kinds follow Marginalia: `notebook`, `lecture`, `seminar`, `document`.
  public static func create(notebook: String = UUID().uuidString.lowercased(), title: String, kind: String = "notebook",
    topic: String? = nil) -> Command
  {
    command(Kind.create, ["notebook": .string(notebook), "title": .string(title), "kind": .string(kind),
      "topic": JSONValue(topic)])
  }

  public static func rename(notebook: String, title: String) -> Command {
    command(Kind.rename, ["notebook": .string(notebook), "title": .string(title)])
  }

  public static func archive(notebook: String, archived: Bool = true) -> Command {
    command(Kind.archive, ["notebook": .string(notebook), "archived": .bool(archived)])
  }

  /// Creates or edits a cell. A new cell goes after `after` (nil: at the top). For an edit,
  /// `expect` is the revision the writer edited; a stale one keeps both versions.
  public static func putCell(_ cell: String = UUID().uuidString.lowercased(), notebook: String, kind: CellKind,
    source: String, language: String? = nil, after: String? = nil, expect: String? = nil, entry: String? = nil) -> Command
  {
    var payload: [String: JSONValue] = ["cell": .string(cell), "notebook": .string(notebook), "kind": .string(kind.rawValue),
      "source": .string(source), "language": JSONValue(language), "after": JSONValue(after), "expect": JSONValue(expect)]
    if let entry { payload["entry"] = .string(entry) }
    return command(Kind.putCell, payload)
  }

  /// Settles a cell's concurrent versions: `source` becomes the cell and alternatives are cleared.
  /// To keep the current text, pass it as `source`.
  public static func resolveCell(_ cell: String, notebook: String, source: String, expect: String?) -> Command {
    command(Kind.resolveCell, ["cell": .string(cell), "notebook": .string(notebook), "source": .string(source),
      "expect": JSONValue(expect)])
  }

  public static func moveCell(_ cell: String, notebook: String, after: String?) -> Command {
    command(Kind.moveCell, ["cell": .string(cell), "notebook": .string(notebook), "after": JSONValue(after)])
  }

  public static func deleteCell(_ cell: String, notebook: String) -> Command {
    command(Kind.deleteCell, ["cell": .string(cell), "notebook": .string(notebook)])
  }

  /// Records what running a cell produced. `mime` is e.g. `text/plain`, `image/svg+xml`.
  public static func output(cell: String, notebook: String, source: String, runtime: String,
    outputs: [(mime: String, data: String)], error: String? = nil) -> Command
  {
    command(Kind.output, ["cell": .string(cell), "notebook": .string(notebook), "sourceDigest": .string(digest(source)),
      "runtime": .string(runtime), "error": JSONValue(error),
      "outputs": .array(outputs.map { .object(["mime": .string($0.mime), "data": .string($0.data)]) })])
  }

  public static func digest(_ source: String) -> String { Canonical.digest(Data(source.utf8)) }

  public static func fold(_ view: ReplicaView) -> Notebooks { Notebooks(view) }
}
