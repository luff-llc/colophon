// Reuses the reference adapter evaluation, without changing its domain semantics.
import Foundation
import ColophonCore
import ColophonReplica
import ColophonBooks
import ColophonListening
import ColophonSaved
import ColophonNotes
import ColophonSession
import ColophonMigration

/// Evaluates actual reference prefixes. Unsupported service codecs stay unresolved; an
/// admitted signature alone is never permission to project an unknown historical effect.
struct SourceEvaluation {
    var outcome = "unresolved"
    var context: [String: Any] = [:]
    static func evaluate(namespace: String, entries: [SourceEntry], index: Int, library: String, progress: LegacyImportBindings) throws -> Self {
        let entry = entries[index].admitted, op = entry.operation, p = op.payload
        func view(_ end: Int) -> ReplicaView {
            ReplicaView(operations: entries.prefix(end).map(\.admitted), rejected: [], unreadable: 0, libraryID: library, namespace: namespace)
        }
        let before = view(index), after = view(index + 1)
        var result = Self()
        guard entry.status == .admitted else { return result }
        if namespace == "listening.podcasts", ["legacy.bridge.import", "legacy.podcastState.import", "podcast.source.publish", "playback.naturalEnd.batch"].contains(op.kind),
           entries.filter({ $0.admitted.id == op.id }).count > 1 { return result }
        switch namespace {
        case "reading.books": result.outcome = "applied" // The Rust books adapter evaluates the old fold itself.
        case "reading.saved":
            let old = SavedLinks.fold(before), new = SavedLinks.fold(after), id = p["item"]?.string ?? ""
            if new.conflicts.contains(where: { $0.operation == op.id }) { result.outcome = "conflict" }
            else if SavedLinks.kinds.contains(op.kind) {
                result.outcome = new.items[id]?.revision == op.id ? "applied" : "noEffect"
            }
            var heads: [String: Any] = [:]
            for component in ["state", "metadata", "activity"] {
                heads[id + "/" + component] = progress.heads[try tuple(namespace, id, component)] as Any? ?? NSNull()
            }
            result.context = ["heads": heads, "existingItems": Array(old.items.keys)]
        case "notes":
            let old = Notes.fold(before), new = Notes.fold(after)
            let notebook = p["notebook"]?.string ?? "", cell = p["cell"]?.string ?? "", entryID = p["entry"]?.string ?? ""
            if new.invalidOperations.contains(op.id) { result.outcome = "invalid" }
            else if new.lateEdits[cell]?.contains(where: { $0.operation == op.id }) == true { result.outcome = "lateEdit" }
            else {
                switch op.kind {
                case "notebook.create": result.outcome = old.notebooks[notebook] == nil && new.notebooks[notebook] != nil ? "applied" : "noEffect"
                case "notebook.rename", "notebook.archive": result.outcome = new.notebooks[notebook] != nil ? "applied" : "noEffect"
                case "cell.put", "cell.resolve":
                    result.outcome = new.cells[cell]?.revision == op.id ? "applied" : (new.cells[cell]?.alternatives != old.cells[cell]?.alternatives ? "conflict" : "noEffect")
                case "cell.move": result.outcome = old.notebooks[notebook]?.order != new.notebooks[notebook]?.order ? "applied" : "noEffect"
                case "cell.delete": result.outcome = new.notebooks[notebook] != nil ? "applied" : "noEffect"
                case "attachment.add": result.outcome = old.attachments[p["attachment"]?.string ?? ""] == nil && new.attachments[p["attachment"]?.string ?? ""] != nil ? "applied" : "noEffect"
                case "cell.output": result.outcome = old.cells[cell]?.lastRun != new.cells[cell]?.lastRun ? "applied" : "noEffect"
                case "entry.put": result.outcome = new.entries[entryID]?.revision == op.id ? "applied" : "conflict"
                default: break // Proposal custody and attachment/blob closure need the full service adapter.
                }
            }
            var identities: [String: String] = [:]
            for (category, ids) in [("notebook", Array(new.notebooks.keys)), ("cell", Array(new.cells.keys) + [cell]), ("entry", Array(new.entries.keys)), ("attachment", Array(new.attachments.keys))] {
                for id in ids where !id.isEmpty { identities[try tuple(library, category, id)] = id }
            }
            var heads: [String: Any] = [:]
            heads[try tuple("cell", cell)] = old.cells[cell]?.revision as Any? ?? NSNull()
            heads[try tuple("entry", entryID)] = old.entries[entryID]?.revision as Any? ?? NSNull()
            // Notebook and order are independent components, reconstructed from the old prefix.
            let prior = before.admitted
            heads[try tuple("notebook", notebook)] = prior.last(where: { $0.operation.payload["notebook"]?.string == notebook && ["notebook.create", "notebook.rename", "notebook.archive"].contains($0.operation.kind) })?.id as Any? ?? NSNull()
            // Imported order head is separate from cell text. Keep native destination edits
            // out of this map so catch-up remains conditional against the imported baseline.
            let importedOrder = progress.heads[try tuple(namespace, notebook, "order")]
            heads[try tuple("order", notebook)] = importedOrder as Any? ?? NSNull()
            var revisions: [String: String] = [:]
            for prior in before.admitted {
                for category in ["cell", "entry", "notebook", "order"] {
                    if let mapped = progress.revisions[try tuple(namespace, category, prior.id)] { revisions[try tuple(category, prior.id)] = mapped }
                }
            }
            if let importedOrder { revisions[try tuple("order", importedOrder)] = importedOrder }
            var effective = try JSONSerialization.jsonObject(with: JSONEncoder().encode(p)) as? [String: Any] ?? [:]
            if result.outcome == "conflict" || result.outcome == "lateEdit" {
                // The full losing candidate uses the attempted source, never the winning text.
                effective["kind"] = p["kind"]?.string ?? old.cells[cell]?.kind.rawValue
                effective["language"] = (p["language"]?.string ?? old.cells[cell]?.language) as Any? ?? NSNull()
                effective["entry"] = (p["entry"]?.string ?? old.cells[cell]?.entry) as Any? ?? NSNull()
            } else if let cell = new.cells[cell] {
                effective["kind"] = cell.kind.rawValue; effective["source"] = cell.source
                effective["language"] = cell.language as Any? ?? NSNull(); effective["entry"] = cell.entry as Any? ?? NSNull()
            }
            if result.outcome == "applied", let entry = new.entries[entryID] {
                effective["title"] = entry.title as Any? ?? NSNull(); effective["date"] = entry.date as Any? ?? NSNull(); effective["tags"] = entry.tags
            }
            result.context = ["identities": identities, "heads": heads, "revisions": revisions, "effective_payload": effective, "source_order": old.notebooks[notebook]?.order ?? []]
            if op.kind == "cell.resolve", old.cells[cell]?.alternatives.isEmpty == true { result.context["alternatives"] = [String](); result.context["projected_alternatives"] = [String]() }
        case "listening.podcasts":
            let old = Podcasts.fold(before), new = Podcasts.fold(after)
            var serviceRevisions: [String: String] = [:]
            let show = p["show"]?.string ?? "", episode = p["episode"]?.string ?? "", note = p["note"]?.string ?? ""
            var effective = try JSONSerialization.jsonObject(with: JSONEncoder().encode(p)) as? [String: Any] ?? [:]
            if new.conflicts.contains(op.id) { result.outcome = "conflict" }
            else {
                switch op.kind {
                case "show.follow", "show.unfollow", "show.settings":
                    result.outcome = old.shows[show] != new.shows[show] || old.showRevisions[show] != new.showRevisions[show] ? "applied" : "noEffect"
                    if let value = new.shows[show] { effective["feed"] = value.feed; effective["title"] = value.title }
                case "episode.position", "position.recover": result.outcome = new.episodes[episode]?.positionRevision == op.id ? "applied" : "noEffect"
                case "episode.setState": result.outcome = new.episodes[episode]?.stateRevision == op.id ? "applied" : "noEffect"
                case "queue.set": result.outcome = new.queueRevision == op.id ? "applied" : "noEffect"
                case "note.add", "note.edit", "note.resolve": result.outcome = new.notes[note]?.revision == op.id ? "applied" : "noEffect"
                case "note.delete": result.outcome = old.notes[note] != nil && new.notes[note] == nil ? "applied" : "noEffect"
                case "legacy.bridge.import":
                    if let receipt = new.legacyBridgeReceipts.values.first(where: { $0.operationID == op.id }), receipt.outcome == .applied {
                        effective = ["feeds": receipt.appliedShowIDs.compactMap { id -> [String: Any]? in
                            guard let show = new.shows[id] else { return nil }
                            return ["targetShowID": id, "feedURL": show.feed, "title": show.title]
                        }]; result.outcome = "applied"
                    } else { result.outcome = "noEffect" }
                case "podcast.source.publish":
                    if let body = PodcastSourcePublication.decode(op) {
                        var actions: [[String: Any]] = []
                        for action in body.actions {
                            guard old.podcastSourceActions[action.actionID] == nil,
                                  let receipt = new.podcastSourceActions[action.actionID], receipt.applied,
                                  let fact = new.podcastSourceFacts[action.factKey] else { continue }
                            let showID = Podcasts.showID(feed: action.feed)
                            let episodeID = action.guid.map { Podcasts.episodeID(feed: action.feed, guid: $0) }
                            let component = fact.kind == "position" ? "position" : (fact.kind == "consumption" ? "state" : "show")
                            let id = component == "show" ? showID : (episodeID ?? "")
                            var fields: [String: Any] = ["id": id, "expect": action.expectedRevision as Any? ?? NSNull()]
                            let kind: String
                            switch fact.kind {
                            case "follow": kind = "follow"; fields["url"] = action.feed; fields["title"] = new.shows[showID]?.title ?? action.feed
                            case "unfollow": kind = "unfollow"
                            case "position":
                                guard let seconds = fact.body["seconds"]?.double else { continue }
                                kind = "position"; fields["show"] = showID; fields["seconds"] = seconds; fields["seek"] = fact.body["deliberate"]?.bool ?? false
                            case "consumption": kind = "setState"; fields["show"] = showID; fields["consumption"] = fact.body["consumption"]?.string
                            default: continue
                            }
                            if let expected = action.expectedRevision, let imported = progress.heads[try tuple(namespace, id, component)] {
                                serviceRevisions[try tuple(component, expected)] = imported
                            }
                            actions.append(["kind": kind, "mode": action.mode.rawValue, "payload": fields])
                        }
                        effective = ["actions": actions]
                        result.outcome = new.podcastSourceConflicts.contains(op.id) ? "conflict" : (actions.isEmpty ? "retained" : "applied")
                    } else { result.outcome = "invalid" }
                case "legacy.podcastState.import":
                    if let body = LegacyPodcastStateImport.decode(op) {
                        var records: [[String: Any]] = []
                        for record in body.records {
                            var fields: [String: Any] = ["feed": record.feed, "guid": record.guid]
                            if new.episodes[record.episodeID]?.positionRevision == op.id,
                               old.episodes[record.episodeID]?.positionRevision != op.id,
                               let seconds = record.seconds { fields["seconds"] = seconds }
                            if new.episodes[record.episodeID]?.stateRevision == op.id,
                               old.episodes[record.episodeID]?.stateRevision != op.id,
                               let state = record.consumption { fields["consumption"] = state }
                            if fields.count > 2 { records.append(fields) }
                        }
                        effective = ["records": records]; result.outcome = records.isEmpty ? "noEffect" : "applied"
                    } else { result.outcome = "invalid" }
                case "transcript.prepare", "transcript.prepare.cancel", "transcript.prepare.result", "question.request", "question.cancel": result.outcome = "retained"
                default: break
                }
            }
            var revisions = serviceRevisions
            var heads: [String: Any] = [:]
            for prior in before.admitted {
                for component in ["show", "position", "state", "queue", "text", "playlist"] {
                    if let mapped = progress.revisions[try tuple(namespace, component, prior.id)] { revisions[try tuple(component, prior.id)] = mapped }
                }
            }
            for (component, id, oldHead) in [("show", show, old.showRevisions[show]), ("position", episode, old.episodes[episode]?.positionRevision), ("state", episode, old.episodes[episode]?.stateRevision), ("text", note, old.notes[note]?.revision), ("queue", "queue", old.queueRevision)] {
                if let oldHead, let imported = progress.heads[try tuple(namespace, id, component)] { revisions[try tuple(component, oldHead)] = imported }
            }
            for (component, id) in [("show", show), ("position", episode), ("state", episode), ("text", note), ("queue", "queue")] {
                heads[try tuple(component, id)] = progress.heads[try tuple(namespace, id, component)] as Any? ?? NSNull()
            }
            result.context = ["effectivePayload": effective, "revisions": revisions, "catchUp": true, "destinationHeads": heads,
                              "reason": result.outcome == "unresolved" ? "Service projection/codec not connected; source retained for reconciliation" : ""]
        default: break
        }
        return result
    }
}
