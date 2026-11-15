package com.luff.colophon.session

import java.math.BigDecimal
import java.math.BigInteger

/**
 * A small strict JSON reader and writer for the documents the session itself reads or builds: the engine's
 * `*_json` results, a request's terms, the default policy, the session journal. Values are `Map<String, Any?>`
 * (insertion order kept), `List<Any?>`, `String`, `Long` or `BigInteger` (integers), `Double` (anything with a
 * fraction or exponent), `Boolean` and `null`. Record payloads are never re-encoded through it: the session passes
 * an app's JSON text to the engine unchanged.
 */
object Json {
    class ParseException(message: String) : IllegalArgumentException(message)

    private const val MAX_DEPTH = 256

    fun parse(text: String): Any? {
        val p = Parser(text)
        p.ws()
        val v = p.value(0)
        p.ws()
        if (p.i != text.length) throw ParseException("trailing characters at ${p.i}")
        return v
    }

    /** `parse` as an object, or null when the text is not a JSON object. */
    fun obj(text: String): Map<String, Any?>? = try {
        @Suppress("UNCHECKED_CAST")
        parse(text) as? Map<String, Any?>
    } catch (_: ParseException) {
        null
    }

    /** Writes `value`; object keys sorted when `sorted` (the canonical order the Swift SDK writes). */
    fun write(value: Any?, sorted: Boolean = true): String = StringBuilder().also { write(it, value, sorted) }.toString()

    fun quote(text: String): String = StringBuilder().also { string(it, text) }.toString()

    private fun write(out: StringBuilder, value: Any?, sorted: Boolean) {
        when (value) {
            null -> out.append("null")
            is String -> string(out, value)
            is Boolean -> out.append(value)
            is Int, is Long, is Short, is Byte, is BigInteger -> out.append(value.toString())
            is UInt, is ULong -> out.append(value.toString())
            is Double -> {
                require(value.isFinite()) { "JSON has no NaN or infinity" }
                if (value == Math.floor(value) && kotlin.math.abs(value) < 1e15) out.append(value.toLong()) else out.append(value)
            }
            is Float -> write(out, value.toDouble(), sorted)
            is BigDecimal -> out.append(value.toPlainString())
            is RawJson -> out.append(value.text)
            is Map<*, *> -> {
                out.append('{')
                val keys = value.keys.map { it as String }.let { if (sorted) it.sorted() else it }
                keys.forEachIndexed { n, k ->
                    if (n > 0) out.append(',')
                    string(out, k); out.append(':'); write(out, value[k], sorted)
                }
                out.append('}')
            }
            is Iterable<*> -> {
                out.append('[')
                value.forEachIndexed { n, v -> if (n > 0) out.append(','); write(out, v, sorted) }
                out.append(']')
            }
            else -> throw IllegalArgumentException("not a JSON value: ${value::class.simpleName}")
        }
    }

    private fun string(out: StringBuilder, s: String) {
        out.append('"')
        for (c in s) {
            when (c) {
                '"' -> out.append("\\\"")
                '\\' -> out.append("\\\\")
                '\n' -> out.append("\\n")
                '\r' -> out.append("\\r")
                '\t' -> out.append("\\t")
                '\b' -> out.append("\\b")
                '\u000c' -> out.append("\\f")
                else -> if (c < ' ') out.append(String.format("\\u%04x", c.code)) else out.append(c)
            }
        }
        out.append('"')
    }

    private class Parser(val s: String) {
        var i = 0
        fun ws() { while (i < s.length && (s[i] == ' ' || s[i] == '\n' || s[i] == '\r' || s[i] == '\t')) i++ }
        fun fail(what: String): Nothing = throw ParseException("$what at $i")
        fun value(depth: Int): Any? {
            if (depth > MAX_DEPTH) fail("nested too deeply")
            if (i >= s.length) fail("unexpected end")
            return when (val c = s[i]) {
                '{' -> obj(depth)
                '[' -> arr(depth)
                '"' -> str()
                't' -> lit("true", true)
                'f' -> lit("false", false)
                'n' -> lit("null", null)
                else -> if (c == '-' || c in '0'..'9') num() else fail("unexpected '$c'")
            }
        }
        fun lit(word: String, v: Any?): Any? {
            if (!s.startsWith(word, i)) fail("bad literal")
            i += word.length
            return v
        }
        fun obj(depth: Int): Map<String, Any?> {
            i++
            val out = LinkedHashMap<String, Any?>()
            ws()
            if (i < s.length && s[i] == '}') { i++; return out }
            while (true) {
                ws()
                if (i >= s.length || s[i] != '"') fail("expected a key")
                val k = str()
                if (out.containsKey(k)) fail("duplicate key")
                ws()
                if (i >= s.length || s[i] != ':') fail("expected ':'")
                i++; ws()
                out[k] = value(depth + 1)
                ws()
                if (i >= s.length) fail("unexpected end")
                when (s[i]) {
                    ',' -> i++
                    '}' -> { i++; return out }
                    else -> fail("expected ',' or '}'")
                }
            }
        }
        fun arr(depth: Int): List<Any?> {
            i++
            val out = ArrayList<Any?>()
            ws()
            if (i < s.length && s[i] == ']') { i++; return out }
            while (true) {
                ws()
                out.add(value(depth + 1))
                ws()
                if (i >= s.length) fail("unexpected end")
                when (s[i]) {
                    ',' -> i++
                    ']' -> { i++; return out }
                    else -> fail("expected ',' or ']'")
                }
            }
        }
        fun str(): String {
            i++
            val out = StringBuilder()
            while (true) {
                if (i >= s.length) fail("unterminated string")
                val c = s[i++]
                when {
                    c == '"' -> return out.toString()
                    c == '\\' -> {
                        if (i >= s.length) fail("bad escape")
                        when (val e = s[i++]) {
                            '"' -> out.append('"'); '\\' -> out.append('\\'); '/' -> out.append('/')
                            'b' -> out.append('\b'); 'f' -> out.append('\u000c'); 'n' -> out.append('\n')
                            'r' -> out.append('\r'); 't' -> out.append('\t')
                            'u' -> {
                                val c1 = hex4()
                                // Spec §2.3: a surrogate escape is valid only as a high-low pair.
                                if (c1.isLowSurrogate()) fail("lone low surrogate")
                                if (c1.isHighSurrogate()) {
                                    if (!s.startsWith("\\u", i)) fail("lone high surrogate")
                                    i += 2
                                    val c2 = hex4()
                                    if (!c2.isLowSurrogate()) fail("lone high surrogate")
                                    out.append(c1).append(c2)
                                } else out.append(c1)
                            }
                            else -> fail("bad escape '$e'")
                        }
                    }
                    c < ' ' -> fail("control character in string")
                    else -> out.append(c)
                }
            }
        }
        fun hex4(): Char {
            if (i + 4 > s.length) fail("bad escape")
            val text = s.substring(i, i + 4)
            if (!text.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) fail("bad escape")
            i += 4
            return text.toInt(16).toChar()
        }
        fun num(): Any {
            val start = i
            if (s[i] == '-') i++
            if (i >= s.length) fail("bad number")
            if (s[i] == '0') i++ else if (s[i] in '1'..'9') { while (i < s.length && s[i].isDigit()) i++ } else fail("bad number")
            var integer = true
            if (i < s.length && s[i] == '.') {
                integer = false; i++
                if (i >= s.length || !s[i].isDigit()) fail("bad number")
                while (i < s.length && s[i].isDigit()) i++
            }
            if (i < s.length && (s[i] == 'e' || s[i] == 'E')) {
                integer = false; i++
                if (i < s.length && (s[i] == '+' || s[i] == '-')) i++
                if (i >= s.length || !s[i].isDigit()) fail("bad number")
                while (i < s.length && s[i].isDigit()) i++
            }
            val text = s.substring(start, i)
            if (!integer) return text.toDouble()
            return text.toLongOrNull() ?: BigInteger(text)
        }
    }
}

/** Already-encoded JSON, written unchanged (a signed blob manifest is embedded byte for byte). */
class RawJson(val text: String)

internal fun Map<String, Any?>.string(key: String): String? = this[key] as? String
@Suppress("UNCHECKED_CAST")
internal fun Map<String, Any?>.obj(key: String): Map<String, Any?>? = this[key] as? Map<String, Any?>
internal fun Map<String, Any?>.list(key: String): List<Any?>? = this[key] as? List<Any?>
internal fun Map<String, Any?>.long(key: String): Long? = (this[key] as? Number)?.toLong()
