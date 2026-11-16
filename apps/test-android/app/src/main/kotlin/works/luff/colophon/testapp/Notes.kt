package works.luff.colophon.testapp

import org.json.JSONArray
import org.json.JSONObject

/**
 * `note.put` records in the `notes` namespace, folded here from the engine's admitted operations in the engine's order:
 * the last `note.put` for an `id` wins, `"deleted": true` removes it. Same payload as the iPhone app:
 * `{"id", "text", "deleted"?, "photo"?: {"digest", "mediaType", "size"}}`.
 */
data class Note(val id: String, val text: String, val photo: Photo?, val author: String, val authorLabel: String, val created: String) {
    data class Photo(val digest: String, val mediaType: String, val size: Long)
}

object NotesFold {
    const val NAMESPACE = "notes"
    const val KIND = "note.put"

    class Failure(message: String) : Exception(message)
    data class Folded(val notes: List<Note>, val held: Int, val refused: Int)

    /** Folds the engine's `view_json` outcome. A refusal (`{"ok":false,…}`) is an error, never an empty list. */
    fun fold(viewJson: String, labels: Map<String, String>): Folded {
        val outcome = JSONObject(viewJson)
        if (!outcome.optBoolean("ok")) throw Failure("The notes could not be read: ${outcome.optString("reason")}: ${outcome.optString("detail")}")
        val value = outcome.getJSONObject("value")
        val admitted = value.optJSONArray("admitted") ?: JSONArray()
        val notes = LinkedHashMap<String, Note>()
        for (i in 0 until admitted.length()) {
            val op = admitted.getJSONObject(i)
            if (op.optString("kind") != KIND) continue
            val payload = op.optJSONObject("payload") ?: continue
            val id = payload.optString("id").ifEmpty { null } ?: continue
            if (payload.optBoolean("deleted")) { notes.remove(id); continue }
            val author = op.optString("author")
            val photo = payload.optJSONObject("photo")?.let { p ->
                p.optString("digest").ifEmpty { null }?.let { Note.Photo(it, p.optString("mediaType", "image/jpeg"), p.optLong("size")) }
            }
            val label = labels[author] ?: op.optString("authorLabel").ifEmpty { null } ?: op.optString("author_label").ifEmpty { null } ?: author.take(8)
            notes.remove(id)
            notes[id] = Note(id, payload.optString("text"), photo, author, label, op.optString("created"))
        }
        return Folded(notes.values.reversed(), value.optJSONArray("held")?.length() ?: 0, value.optJSONArray("refused")?.length() ?: 0)
    }

    fun payload(id: String, text: String, photo: Note.Photo?, deleted: Boolean = false): String {
        if (deleted) return JSONObject().put("deleted", true).put("id", id).toString()
        val o = JSONObject().put("id", id).put("text", text)
        photo?.let { o.put("photo", JSONObject().put("digest", it.digest).put("mediaType", it.mediaType).put("size", it.size)) }
        return o.toString()
    }
}
