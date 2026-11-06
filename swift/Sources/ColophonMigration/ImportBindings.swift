import Foundation
import ColophonSession

enum ImportBindings {
    /// Component receipts are deliberately never refreshed from native 0.2 edits.
    static func bind(namespace: String, source: LegacyOperation, command: LegacyImportCommand, payload: [String: Any], operationID: String, progress: inout MigrationProgress) {
        let id = payload["id"] as? String ?? "", kind = command.kind
        var components: [String] = []
        switch namespace {
        case "reading.saved":
            components = kind == "capture" ? ["state", "metadata", "activity"] : (kind == "setState" ? ["state", "activity"] : ["metadata", "activity"])
        case "notes":
            switch kind {
            case "createNotebook": components = ["notebook", "order"]
            case "renameNotebook", "archiveNotebook": components = ["notebook"]
            case "putCell", "resolveCell", "deleteCell": components = ["cell"]
            case "moveCell": components = ["order"]
            case "putEntry": components = ["entry"]
            default: break
            }
        case "listening.podcasts":
            switch kind {
            case "follow", "unfollow", "editShow": components = ["show"]
            case "position", "recoverPosition": components = ["position"]
            case "setState": components = ["state"]
            case "queue": components = ["queue"]
            case "addNote", "editNote", "resolveNote", "deleteNote": components = ["text"]
            default: break
            }
        default: break
        }
        if namespace == "notes", let notebook = payload["notebook"] as? String,
           kind == "moveCell" || kind == "deleteCell" || (kind == "putCell" && payload["expect"] is NSNull) {
            progress.heads[tuple(namespace, notebook, "order")] = operationID
        }
        for component in components {
            progress.revisions[tuple(namespace, component, source.id)] = operationID
            progress.heads[tuple(namespace, component == "queue" ? "queue" : id, component)] = operationID
        }
    }
}
