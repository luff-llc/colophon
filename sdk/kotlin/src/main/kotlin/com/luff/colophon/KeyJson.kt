package com.luff.colophon

// Host-side inspection of descriptors and core-authenticated keyrings; the core verifies protocol data.
internal sealed class KeyJson {
    data class Text(val value: String) : KeyJson()
    data class Bool(val value: Boolean) : KeyJson()
    data class Number(val raw: String) : KeyJson()
    data object Null : KeyJson()
    data class Array(val items: List<KeyJson>) : KeyJson()
    data class Obj(val fields: Map<String, KeyJson>) : KeyJson() {
        fun string(key: String): String? = when (val value = fields[key]) {
            null, Null -> null
            is Text -> value.value
            else -> throw BindingException.InvalidData("Journal field $key is not a string")
        }
        fun bool(key: String): Boolean? = when (val value = fields[key]) {
            null, Null -> null
            is Bool -> value.value
            else -> throw BindingException.InvalidData("Journal field $key is not a boolean")
        }
        fun stringList(key: String): List<String> = when (val value = fields[key]) {
            null, Null -> emptyList()
            is Array -> value.items.map {
                (it as? Text)?.value ?: throw BindingException.InvalidData("Journal list $key must be strings")
            }
            else -> throw BindingException.InvalidData("Journal field $key is not an array")
        }
        fun stringMap(key: String): Map<String, String> = when (val value = fields[key]) {
            null, Null -> emptyMap()
            is Obj -> value.fields.mapValues { (_, nested) ->
                (nested as? Text)?.value ?: throw BindingException.InvalidData("Journal pending values must be strings")
            }
            else -> throw BindingException.InvalidData("Journal field $key is not an object")
        }
        fun array(key: String): List<KeyJson> = when (val value = fields[key]) {
            null, Null -> emptyList()
            is Array -> value.items
            else -> throw BindingException.InvalidData("JSON field $key is not an array")
        }
    }
}

internal class KeyJsonParser(private val text: String) {
    private var i = 0
    fun done(): Boolean = i >= text.length
    fun skipWhitespace() {
        while (i < text.length && text[i] in " \t\r\n") i++
    }

    fun parseValue(): KeyJson {
        skipWhitespace()
        return when (peek()) {
            '"' -> KeyJson.Text(parseString())
            '{' -> parseObject()
            '[' -> parseArray()
            't', 'f' -> parseBool()
            'n' -> parseNull()
            '-', in '0'..'9' -> parseNumber()
            else -> throw BindingException.InvalidData("Malformed JSON value")
        }
    }

    private fun parseObject(): KeyJson.Obj {
        expect('{')
        skipWhitespace()
        if (peek() == '}') {
            i++
            return KeyJson.Obj(emptyMap())
        }
        val fields = linkedMapOf<String, KeyJson>()
        while (true) {
            val key = parseString()
            skipWhitespace()
            expect(':')
            if (fields.containsKey(key)) throw BindingException.InvalidData("Duplicate JSON member")
            fields[key] = parseValue()
            skipWhitespace()
            when (peek()) {
                ',' -> i++
                '}' -> {
                    i++
                    return KeyJson.Obj(fields)
                }
                else -> throw BindingException.InvalidData("Malformed JSON object")
            }
        }
    }

    private fun parseArray(): KeyJson.Array {
        expect('[')
        skipWhitespace()
        if (peek() == ']') {
            i++
            return KeyJson.Array(emptyList())
        }
        val items = mutableListOf<KeyJson>()
        while (true) {
            items.add(parseValue())
            skipWhitespace()
            when (peek()) {
                ',' -> i++
                ']' -> {
                    i++
                    return KeyJson.Array(items)
                }
                else -> throw BindingException.InvalidData("Malformed JSON array")
            }
        }
    }

    private fun parseNumber(): KeyJson.Number {
        val start = i
        if (i < text.length && text[i] == '-') i++
        if (i >= text.length || !text[i].isDigit()) throw BindingException.InvalidData("Malformed JSON number")
        if (text[i] == '0') {
            i++
        } else {
            while (i < text.length && text[i].isDigit()) i++
        }
        if (i < text.length && text[i] == '.') {
            i++
            if (i >= text.length || !text[i].isDigit()) throw BindingException.InvalidData("Malformed JSON number")
            while (i < text.length && text[i].isDigit()) i++
        }
        if (i < text.length && (text[i] == 'e' || text[i] == 'E')) {
            i++
            if (i < text.length && (text[i] == '+' || text[i] == '-')) i++
            if (i >= text.length || !text[i].isDigit()) throw BindingException.InvalidData("Malformed JSON number")
            while (i < text.length && text[i].isDigit()) i++
        }
        return KeyJson.Number(text.substring(start, i))
    }

    private fun parseBool(): KeyJson.Bool = when {
        text.startsWith("true", i) -> {
            i += 4
            KeyJson.Bool(true)
        }
        text.startsWith("false", i) -> {
            i += 5
            KeyJson.Bool(false)
        }
        else -> throw BindingException.InvalidData("Malformed JSON boolean")
    }

    private fun parseNull(): KeyJson.Null {
        if (!text.startsWith("null", i)) throw BindingException.InvalidData("Malformed JSON null")
        i += 4
        return KeyJson.Null
    }

    private fun parseString(): String {
        skipWhitespace()
        expect('"')
        val out = StringBuilder()
        while (i < text.length) {
            when (val ch = text[i++]) {
                '"' -> return out.toString()
                '\\' -> {
                    if (i >= text.length) throw BindingException.InvalidData("Truncated JSON string")
                    out.append(
                        when (val next = text[i++]) {
                            '"', '\\', '/' -> next
                            'b' -> '\b'
                            'f' -> '\u000c'
                            'n' -> '\n'
                            'r' -> '\r'
                            't' -> '\t'
                            'u' -> {
                                if (i + 4 > text.length) throw BindingException.InvalidData("Truncated JSON string")
                                val hex = text.substring(i, i + 4)
                                i += 4
                                val code = hex.toIntOrNull(16) ?: throw BindingException.InvalidData("Bad JSON escape")
                                code.toChar()
                            }
                            else -> throw BindingException.InvalidData("Bad JSON escape")
                        },
                    )
                }
                else -> {
                    if (ch < ' ') throw BindingException.InvalidData("JSON control character")
                    out.append(ch)
                }
            }
        }
        throw BindingException.InvalidData("Unterminated JSON string")
    }

    private fun expect(ch: Char) {
        skipWhitespace()
        if (i >= text.length || text[i] != ch) throw BindingException.InvalidData("Expected $ch")
        i++
    }

    private fun peek(): Char {
        skipWhitespace()
        if (i >= text.length) throw BindingException.InvalidData("Truncated JSON")
        return text[i]
    }
}

internal fun keyObject(bytes: ByteArray): KeyJson.Obj {
    val parser = KeyJsonParser(bytes.toString(Charsets.UTF_8))
    val result = parser.parseValue() as? KeyJson.Obj ?: throw BindingException.InvalidData("Expected JSON object")
    parser.skipWhitespace()
    if (!parser.done()) throw BindingException.InvalidData("Trailing JSON")
    return result
}

internal fun keyQuote(text: String): String = buildString {
    append('"')
    for (ch in text) when (ch) {
        '"' -> append("\\\"")
        '\\' -> append("\\\\")
        else -> if (ch < ' ') append("\\u%04x".format(ch.code)) else append(ch)
    }
    append('"')
}
