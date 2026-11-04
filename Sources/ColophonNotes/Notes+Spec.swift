import ColophonCore
import ColophonReplica
import Foundation

public extension Notes {
  static var operations: [OperationSpec] {
    let kinds = CellKind.allCases.map(\.rawValue)
    return [
      OperationSpec(Kind.create, "Create a notebook.", [
        FieldSpec("notebook", .string, required: true, "A new unique ID."),
        FieldSpec("title", .string, required: true, "Title."),
        FieldSpec("kind", .string, "What it is.", values: ["notebook", "lecture", "seminar", "document"]),
        FieldSpec("topic", .string, "Course or topic."),
      ]),
      OperationSpec(Kind.rename, "Rename a notebook.", [
        FieldSpec("notebook", .string, required: true, "The notebook."),
        FieldSpec("title", .string, required: true, "New title."),
      ]),
      OperationSpec(Kind.archive, "Archive or restore a notebook.", [
        FieldSpec("notebook", .string, required: true, "The notebook."),
        FieldSpec("archived", .boolean, "False to restore."),
      ]),
      OperationSpec(Kind.putCell, "Add a cell, or edit one.", [
        FieldSpec("cell", .string, required: true, "Cell ID; a new one adds a cell."),
        FieldSpec("notebook", .string, required: true, "The notebook."),
        FieldSpec("kind", .string, required: true, "Cell kind.", values: kinds),
        FieldSpec("source", .string, required: true, "Markdown, LaTeX, code or text."),
        FieldSpec("language", .string, "For code: javascript, python, swift, ..."),
        FieldSpec("after", .string, "For a new cell, the cell it follows; omit for the top."),
        FieldSpec("expect", .string, "For an edit, the revision you edited; a stale one keeps both."),
        FieldSpec("entry", .string, "Optional entry membership; omission on edit preserves it."),
      ]),
      OperationSpec(Kind.resolveCell, "Settle a cell's concurrent versions.", [
        FieldSpec("cell", .string, required: true, "The cell."),
        FieldSpec("notebook", .string, required: true, "The notebook."),
        FieldSpec("source", .string, required: true, "The text to keep."),
        FieldSpec("expect", .string, "The cell's revision you last saw."),
      ]),
      OperationSpec(Kind.moveCell, "Move a cell.", [
        FieldSpec("cell", .string, required: true, "The cell."),
        FieldSpec("notebook", .string, required: true, "The notebook."),
        FieldSpec("after", .string, "The cell it should follow; omit for the top."),
      ]),
      OperationSpec(Kind.deleteCell, "Delete a cell.", [
        FieldSpec("cell", .string, required: true, "The cell."),
        FieldSpec("notebook", .string, required: true, "The notebook."),
      ]),
    ] + entryOperations
  }

  static func describe(_ state: Notebooks) -> JSONValue {
    .object(["entries": .array(state.entries.values.sorted { $0.id < $1.id }.map(entryJSON)),
      "attachments": .array(state.attachments.values.sorted { $0.id < $1.id }.map(attachmentJSON)),
      "proposals": .array(state.proposals.values.sorted { $0.id < $1.id }.map(proposalJSON)),
      "invalidOperations": .array(state.invalidOperations.map(JSONValue.string)), "notebooks": .array(state.active.map { notebook in
      .object(["notebook": .string(notebook.id), "title": .string(notebook.title), "kind": .string(notebook.kind),
        "cells": .array(state.cells(in: notebook.id).map { cell in
          .object(["cell": .string(cell.id), "kind": .string(cell.kind.rawValue), "source": .string(cell.source),
            "revision": .string(cell.revision), "entry": JSONValue(cell.entry), "outputIsCurrent": .bool(cell.outputIsCurrent)])
        })])
    })])
  }
}
