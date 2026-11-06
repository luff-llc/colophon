package org.luff.colophon

import java.io.File
import java.util.Base64

/** Private durable publication intent. No plaintext query state or private keys. */
internal data class SessionJournal(
    var libraryID: String? = null,
    var left: Boolean = false,
    var knownPaths: MutableSet<String> = mutableSetOf(),
    var pending: MutableMap<String, ByteArray> = mutableMapOf(),
) {
    fun save(file: File) {
        AtomicFile.write(encode().toByteArray(Charsets.UTF_8), file)
    }

    private fun encode(): String = buildString {
        append('{')
        append("\"libraryID\":")
        append(libraryID?.let { jsonString(it) } ?: "null")
        append(",\"left\":")
        append(left)
        append(",\"knownPaths\":[")
        knownPaths.sorted().forEachIndexed { index, path ->
            if (index > 0) append(',')
            append(jsonString(path))
        }
        append("],\"pending\":{")
        pending.keys.sorted().forEachIndexed { index, path ->
            if (index > 0) append(',')
            append(jsonString(path))
            append(':')
            append(jsonString(Base64.getEncoder().encodeToString(pending[path])))
        }
        append("}}")
    }

    companion object {
        fun load(file: File): SessionJournal {
            if (!file.exists()) return SessionJournal()
            val text = AtomicFile.read(file, AtomicFile.MAX_JOURNAL_BYTES).decodeToString()
            return try {
                decode(text)
            } catch (error: StorageException.Corrupt) {
                throw error
            } catch (error: StorageException) {
                throw StorageException.Corrupt(error.message ?: "Corrupt session journal")
            } catch (error: IllegalArgumentException) {
                throw StorageException.Corrupt(error.message ?: "Corrupt session journal")
            }
        }

        internal fun decode(text: String): SessionJournal {
            val parser = JsonParser(text)
            val root = parser.parseValue()
            parser.skipWhitespace()
            if (!parser.done()) throw StorageException.Unavailable("Trailing journal data")
            val obj = root as? Json.Obj ?: throw StorageException.Unavailable("Journal root must be an object")
            val journal = SessionJournal()
            journal.libraryID = obj.string("libraryID")
            journal.left = obj.bool("left") ?: false
            journal.knownPaths = obj.stringList("knownPaths").toMutableSet()
            journal.pending = obj.stringMap("pending").mapValues { Base64.getDecoder().decode(it.value) }.toMutableMap()
            return journal
        }
    }
}

internal sealed class Json {
    data class Text(val value: String) : Json()
    data class Bool(val value: Boolean) : Json()
    data class Number(val raw: String) : Json()
    data object Null : Json()
    data class Array(val items: List<Json>) : Json()
    data class Obj(val fields: Map<String, Json>) : Json() {
        fun string(key: String): String? = when (val value = fields[key]) {
            null, Null -> null
            is Text -> value.value
            else -> throw StorageException.Unavailable("Journal field $key is not a string")
        }
        fun bool(key: String): Boolean? = when (val value = fields[key]) {
            null, Null -> null
            is Bool -> value.value
            else -> throw StorageException.Unavailable("Journal field $key is not a boolean")
        }
        fun stringList(key: String): List<String> = when (val value = fields[key]) {
            null, Null -> emptyList()
            is Array -> value.items.map {
                (it as? Text)?.value ?: throw StorageException.Unavailable("Journal list $key must be strings")
            }
            else -> throw StorageException.Unavailable("Journal field $key is not an array")
        }
        fun stringMap(key: String): Map<String, String> = when (val value = fields[key]) {
            null, Null -> emptyMap()
            is Obj -> value.fields.mapValues { (_, nested) ->
                (nested as? Text)?.value ?: throw StorageException.Unavailable("Journal pending values must be strings")
            }
            else -> throw StorageException.Unavailable("Journal field $key is not an object")
        }
        fun array(key: String): List<Json> = when (val value = fields[key]) {
            null, Null -> emptyList()
            is Array -> value.items
            else -> throw StorageException.Unavailable("JSON field $key is not an array")
        }
    }
}

internal class JsonParser(private val text: String) {
    private var i = 0
    fun done(): Boolean = i >= text.length
    fun skipWhitespace() {
        while (i < text.length && text[i].isWhitespace()) i++
    }

    fun parseValue(): Json {
        skipWhitespace()
        return when (peek()) {
            '"' -> Json.Text(parseString())
            '{' -> parseObject()
            '[' -> parseArray()
            't', 'f' -> parseBool()
            'n' -> parseNull()
            '-', in '0'..'9' -> parseNumber()
            else -> throw StorageException.Unavailable("Malformed JSON value")
        }
    }

    private fun parseObject(): Json.Obj {
        expect('{')
        skipWhitespace()
        if (peek() == '}') {
            i++
            return Json.Obj(emptyMap())
        }
        val fields = linkedMapOf<String, Json>()
        while (true) {
            val key = parseString()
            skipWhitespace()
            expect(':')
            fields[key] = parseValue()
            skipWhitespace()
            when (peek()) {
                ',' -> i++
                '}' -> {
                    i++
                    return Json.Obj(fields)
                }
                else -> throw StorageException.Unavailable("Malformed JSON object")
            }
        }
    }

    private fun parseArray(): Json.Array {
        expect('[')
        skipWhitespace()
        if (peek() == ']') {
            i++
            return Json.Array(emptyList())
        }
        val items = mutableListOf<Json>()
        while (true) {
            items.add(parseValue())
            skipWhitespace()
            when (peek()) {
                ',' -> i++
                ']' -> {
                    i++
                    return Json.Array(items)
                }
                else -> throw StorageException.Unavailable("Malformed JSON array")
            }
        }
    }

    private fun parseNumber(): Json.Number {
        val start = i
        if (i < text.length && text[i] == '-') i++
        if (i >= text.length || !text[i].isDigit()) throw StorageException.Unavailable("Malformed JSON number")
        if (text[i] == '0') {
            i++
        } else {
            while (i < text.length && text[i].isDigit()) i++
        }
        if (i < text.length && text[i] == '.') {
            i++
            if (i >= text.length || !text[i].isDigit()) throw StorageException.Unavailable("Malformed JSON number")
            while (i < text.length && text[i].isDigit()) i++
        }
        if (i < text.length && (text[i] == 'e' || text[i] == 'E')) {
            i++
            if (i < text.length && (text[i] == '+' || text[i] == '-')) i++
            if (i >= text.length || !text[i].isDigit()) throw StorageException.Unavailable("Malformed JSON number")
            while (i < text.length && text[i].isDigit()) i++
        }
        return Json.Number(text.substring(start, i))
    }

    private fun parseBool(): Json.Bool = when {
        text.startsWith("true", i) -> {
            i += 4
            Json.Bool(true)
        }
        text.startsWith("false", i) -> {
            i += 5
            Json.Bool(false)
        }
        else -> throw StorageException.Unavailable("Malformed JSON boolean")
    }

    private fun parseNull(): Json.Null {
        if (!text.startsWith("null", i)) throw StorageException.Unavailable("Malformed JSON null")
        i += 4
        return Json.Null
    }

    private fun parseString(): String {
        skipWhitespace()
        expect('"')
        val out = StringBuilder()
        while (i < text.length) {
            when (val ch = text[i++]) {
                '"' -> return out.toString()
                '\\' -> {
                    if (i >= text.length) throw StorageException.Unavailable("Truncated JSON string")
                    out.append(
                        when (val next = text[i++]) {
                            '"', '\\', '/' -> next
                            'n' -> '\n'
                            'r' -> '\r'
                            't' -> '\t'
                            'u' -> {
                                if (i + 4 > text.length) throw StorageException.Unavailable("Truncated JSON string")
                                val hex = text.substring(i, i + 4)
                                i += 4
                                val code = hex.toIntOrNull(16) ?: throw StorageException.Unavailable("Bad JSON escape")
                                code.toChar()
                            }
                            else -> throw StorageException.Unavailable("Bad JSON escape")
                        },
                    )
                }
                else -> out.append(ch)
            }
        }
        throw StorageException.Unavailable("Unterminated JSON string")
    }

    private fun expect(ch: Char) {
        skipWhitespace()
        if (i >= text.length || text[i] != ch) throw StorageException.Unavailable("Expected $ch")
        i++
    }

    private fun peek(): Char {
        skipWhitespace()
        if (i >= text.length) throw StorageException.Unavailable("Truncated JSON")
        return text[i]
    }
}
