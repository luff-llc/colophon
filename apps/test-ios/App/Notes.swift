import Foundation

/// The test apps' notes: `note.put` records in the `notes` namespace, the kind the core's own journeys write. The core's
/// notes fold does not know the kind (it keeps such operations admitted and folds nothing), so the apps fold them here
/// from the engine's admitted operations, in the engine's order (clock, author, operation): the last `note.put` for an
/// `id` wins, and one with `"deleted": true` removes the note. The payload is the same on iPhone and Android:
/// `{"id", "text", "deleted"?, "photo"?: {"digest", "mediaType", "size"}}`.
struct Note: Identifiable, Equatable, Sendable {
    struct Photo: Equatable, Sendable { var digest: String; var mediaType: String; var size: Int }
    let id: String
    var text: String
    var photo: Photo?
    /// The member key that wrote the latest version, and the label the account gives it.
    var author: String
    var authorLabel: String
    var created: String
}

enum NotesFold {
    static let namespace = "notes"
    static let kind = "note.put"

    enum Failure: LocalizedError {
        case notReadable(String)
        var errorDescription: String? { switch self { case .notReadable(let why): "The notes could not be read: \(why)" } }
    }

    /// Folds the engine's `view_json` outcome. A refusal (`{"ok":false,…}`) is an error, never an empty list.
    static func fold(viewJSON: Data, labels: [String: String]) throws -> (notes: [Note], held: Int, refused: Int) {
        guard let outcome = try JSONSerialization.jsonObject(with: viewJSON) as? [String: Any] else { throw Failure.notReadable("not JSON") }
        guard outcome["ok"] as? Bool == true, let value = outcome["value"] as? [String: Any] else {
            throw Failure.notReadable("\(outcome["reason"] ?? "unknown"): \(outcome["detail"] ?? "")")
        }
        let admitted = value["admitted"] as? [[String: Any]] ?? []
        var notes: [String: Note] = [:]
        var order: [String] = []
        for op in admitted where op["kind"] as? String == kind {
            guard let payload = op["payload"] as? [String: Any], let id = payload["id"] as? String else { continue }
            if payload["deleted"] as? Bool == true { notes[id] = nil; order.removeAll { $0 == id }; continue }
            let author = op["author"] as? String ?? ""
            var photo: Note.Photo?
            if let p = payload["photo"] as? [String: Any], let digest = p["digest"] as? String {
                photo = .init(digest: digest, mediaType: p["mediaType"] as? String ?? "image/jpeg", size: (p["size"] as? NSNumber)?.intValue ?? 0)
            }
            let label = labels[author] ?? (op["authorLabel"] as? String) ?? (op["author_label"] as? String) ?? String(author.prefix(8))
            if notes[id] == nil { order.append(id) }
            notes[id] = Note(id: id, text: payload["text"] as? String ?? "", photo: photo, author: author, authorLabel: label,
                             created: op["created"] as? String ?? "")
        }
        let held = (value["held"] as? [Any])?.count ?? 0
        let refused = (value["refused"] as? [Any])?.count ?? 0
        return (order.reversed().compactMap { notes[$0] }, held, refused)
    }

    static func payload(id: String, text: String, photo: Note.Photo?, deleted: Bool = false) throws -> Data {
        var object: [String: Any] = ["id": id, "text": text]
        if deleted { object = ["id": id, "deleted": true] }
        if let photo, !deleted { object["photo"] = ["digest": photo.digest, "mediaType": photo.mediaType, "size": photo.size] }
        return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }
}
