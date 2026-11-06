import ColophonCore
import ColophonReplica
import Foundation

public extension Notes {
  static func validate(_ kind: String, _ payload: [String: JSONValue]) throws {
    guard let spec = operations.first(where: { $0.kind == kind }) else {
      throw ColophonError.malformed("Unknown Notes operation")
    }
    try spec.validate(payload)
    guard NotesContentValidation.valid(kind, payload) else {
      throw ColophonError.malformed("Invalid Notes content")
    }
  }

  static func putEntry(_ id: String = UUID().uuidString.lowercased(), notebook: String,
    title: String? = nil, date: String? = nil, tags: [String] = [], expect: String? = nil) -> Command
  {
    command(Kind.putEntry, ["entry": .string(id), "notebook": .string(notebook), "title": JSONValue(title),
      "date": JSONValue(date), "tags": .array(tags.map(JSONValue.string)), "expect": JSONValue(expect)])
  }

  static func attach(_ id: String = UUID().uuidString.lowercased(), notebook: String, entry: String? = nil,
    role: NotesAttachment.Role, name: String, mime: String? = nil, blob: BlobRef? = nil,
    source: NotesAttachment.SourceReference? = nil) -> Command
  {
    command(Kind.attach, ["attachment": .string(id), "notebook": .string(notebook), "entry": JSONValue(entry),
      "role": .string(role.rawValue), "name": .string(name), "mime": JSONValue(mime),
      "blob": blob?.json ?? .null, "source": source?.json ?? .null])
  }

  static func propose(_ id: String = UUID().uuidString.lowercased(), notebook: String, entry: String,
    title: String? = nil, tags: [String] = [], markdown: String, inputs: [String: String]) -> Command
  {
    command(Kind.propose, ["proposal": .string(id), "notebook": .string(notebook), "entry": .string(entry),
      "title": JSONValue(title), "tags": .array(tags.map(JSONValue.string)), "markdown": .string(markdown),
      "inputs": .object(inputs.mapValues(JSONValue.string))])
  }

  static func reviewProposal(_ id: String, notebook: String, keep: Bool, markdown: String? = nil) -> Command {
    command(Kind.reviewProposal, ["proposal": .string(id), "notebook": .string(notebook), "keep": .bool(keep),
      "markdown": JSONValue(markdown)])
  }

  static var queries: [QuerySpec] {
    [QuerySpec("entry", "Read one entry with bounded cells, material descriptors and proposals; pointers do not grant source access.", [
      FieldSpec("notebook", .string, required: true, "Notebook ID."),
      FieldSpec("entry", .string, required: true, "Entry ID."),
      FieldSpec("offset", .integer, "Zero-based offset for each collection."),
      FieldSpec("limit", .integer, "Items per collection, 1 through 50; default 20."),
    ]) { replica, args in
      guard let notebook = args["notebook"]?.string, let entry = args["entry"]?.string,
        let offset = args["offset"] == nil ? 0 : args["offset"]?.int,
        let limit = args["limit"] == nil ? 20 : args["limit"]?.int,
        offset >= 0, (1...50).contains(limit)
      else { throw ColophonError.malformed("Invalid entry query") }
      let state = try replica.state(of: Notes.self)
      guard let item = state.entries[entry], item.notebook == notebook else {
        throw ColophonError.malformed("Entry unavailable")
      }
      let cells = state.cells(in: notebook, entry: entry)
      let attachments = state.attachments(in: notebook, entry: entry)
      let proposals = state.proposals(in: notebook, entry: entry)
      var header = entryJSON(item).object ?? [:]
      header["alternatives"] = .array((header["alternatives"]?.array ?? []).prefix(20).map { $0 })
      header["alternativeCount"] = .number(Double(item.alternatives.count))
      let result: JSONValue = .object(["entry": .object(header), "offset": .number(Double(offset)),
        "cells": .array(cells.dropFirst(offset).prefix(limit).map { cell in
          .object(["cell": .string(cell.id), "revision": .string(cell.revision), "kind": .string(cell.kind.rawValue),
            "source": .string(String(cell.source.prefix(16_384))), "truncated": .bool(cell.source.count > 16_384)])
        }),
        "attachments": .array(attachments.dropFirst(offset).prefix(limit).map(attachmentJSON)),
        "proposals": .array(proposals.dropFirst(offset).prefix(limit).map(proposalJSON)),
        "cellCount": .number(Double(cells.count)), "attachmentCount": .number(Double(attachments.count)),
        "proposalCount": .number(Double(proposals.count))])
      guard try Canonical.encode(result).count <= 1_048_576 else {
        throw ColophonError.malformed("Entry response exceeds 1 MiB; reduce limit or query a later offset")
      }
      return result
    }]
  }

  internal static var entryOperations: [OperationSpec] {
    let notebook = FieldSpec("notebook", .string, required: true, "Notebook ID.")
    return [
      OperationSpec(Kind.putEntry, "Create entry metadata or edit against its current revision; conflicts retain complete versions.", [
        notebook, FieldSpec("entry", .string, required: true, "Stable entry ID."),
        FieldSpec("title", .string, "Optional title."), FieldSpec("date", .string, "ISO calendar date YYYY-MM-DD."),
        FieldSpec("tags", .strings, "Labels."), FieldSpec("expect", .string, "Current metadata revision when editing.")]),
      OperationSpec(Kind.attach, "Attach an immutable sealed file or descriptive source pointer; exactly one is required.", [
        notebook, FieldSpec("attachment", .string, required: true, "Stable immutable ID."),
        FieldSpec("entry", .string, "Omit for notebook-wide materials."),
        FieldSpec("role", .string, required: true, "Material role.", values: NotesAttachment.Role.allCases.map(\.rawValue)),
        FieldSpec("name", .string, required: true, "Display name."), FieldSpec("mime", .string, "Content type."),
        FieldSpec("blob", .object, "Sealed BlobRef."), FieldSpec("source", .object, "Typed web or exact library reference.")]),
      OperationSpec(Kind.propose, "Append organisation against every current cell revision in this entry, preserving originals.", [
        notebook, FieldSpec("entry", .string, required: true, "Entry ID."),
        FieldSpec("proposal", .string, required: true, "Stable immutable proposal ID."),
        FieldSpec("title", .string, "Proposed title."), FieldSpec("tags", .strings, "Proposed labels."),
        FieldSpec("markdown", .string, required: true, "Organised contribution, at most 16 KiB."),
        FieldSpec("inputs", .object, required: true, "Map of every entry cell ID to its exact revision.")]),
      OperationSpec(Kind.reviewProposal, "Keep or dismiss a pending contribution; keeping requires unchanged input cells. Agent/service review is refused.", [
        notebook, FieldSpec("proposal", .string, required: true, "Proposal ID."),
        FieldSpec("keep", .boolean, required: true, "Keep rather than dismiss."),
        FieldSpec("markdown", .string, "Optional person-edited version; original proposal remains available.")]),
    ]
  }

  internal static func entryJSON(_ entry: NotesEntry) -> JSONValue {
    func version(_ v: NotesEntry.Version) -> JSONValue {
      .object(["title": JSONValue(v.title), "date": JSONValue(v.date), "tags": .array(v.tags.map(JSONValue.string)),
        "revision": .string(v.revision), "author": .string(v.author), "authorLabel": .string(v.authorLabel)])
    }
    return .object(["entry": .string(entry.id), "notebook": .string(entry.notebook), "current": version(entry.current),
      "alternatives": .array(entry.alternatives.map(version)), "touched": .number(Double(entry.touched))])
  }

  internal static func attachmentJSON(_ a: NotesAttachment) -> JSONValue {
    .object(["attachment": .string(a.id), "notebook": .string(a.notebook), "entry": JSONValue(a.entry),
      "role": .string(a.role.rawValue), "name": .string(a.name), "mime": JSONValue(a.mime),
      "blob": a.blob?.json ?? .null, "source": a.source?.json ?? .null, "revision": .string(a.revision),
      "author": .string(a.author), "authorLabel": .string(a.authorLabel)])
  }

  internal static func proposalJSON(_ p: NotesOrganisationProposal) -> JSONValue {
    .object(["proposal": .string(p.id), "notebook": .string(p.notebook), "entry": .string(p.entry),
      "title": JSONValue(p.title), "tags": .array(p.tags.map(JSONValue.string)), "markdown": .string(p.markdown),
      "inputs": .object(p.inputs.mapValues(JSONValue.string)), "revision": .string(p.revision),
      "author": .string(p.author), "authorLabel": .string(p.authorLabel), "status": .string(p.status.rawValue),
      "reviewedMarkdown": JSONValue(p.reviewedMarkdown), "reviewRevision": JSONValue(p.reviewRevision),
      "reviewedBy": JSONValue(p.reviewedBy)])
  }
}
