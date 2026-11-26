package com.luff.colophon.hosts

import com.luff.colophon.session.Json
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction

/**
 * The session frame inside a home stream `session` message, taken out as text, never re-serialised.
 *
 * The home carries a sealed frame verbatim as the `frame` value of `{"type":"session",…,"frame":<frame>}` (stream
 * §5.2), and a receiver accepts only the frame's canonical bytes. Parsing the message and serialising `frame` again
 * would hand the codec bytes the sender never signed whenever the two encodings differ (an escape, a number form, a
 * duplicate name collapsed), and could turn a non-canonical frame into an acceptable one. So the host locates the
 * value's span in the message text and passes exactly those characters on; the codec then judges them.
 */
object Frames {
    /** Deeper than any stream message may nest (a frame's 64 levels and the message's one, stream §5.2). */
    private const val MAX_DEPTH = 66

    private class Fail : RuntimeException(null, null, false, false)

    /** A strict JSON scanner (RFC 8259) that reports where values are instead of building them. */
    private class Scan(val s: String) {
        var i = 0
        fun fail(): Nothing = throw Fail()
        fun ws() { while (i < s.length && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) i++ }
        fun expect(c: Char) { ws(); if (i >= s.length || s[i] != c) fail(); i++ }
        private fun hex(c: Char): Int = when (c) { in '0'..'9' -> c - '0'; in 'a'..'f' -> c - 'a' + 10; in 'A'..'F' -> c - 'A' + 10; else -> fail() }
        /** A string at `i` (at its quote), every escape checked; returns its decoded value. */
        fun string(): String {
            if (i >= s.length || s[i] != '"') fail()
            i++
            val out = StringBuilder()
            while (true) {
                if (i >= s.length) fail()
                val c = s[i]
                if (c == '"') { i++; return out.toString() }
                if (c < ' ') fail()
                if (c == '\\') {
                    if (i + 1 >= s.length) fail()
                    when (s[i + 1]) {
                        'u' -> {
                            if (i + 6 > s.length) fail()
                            var v = 0
                            for (k in 2 until 6) v = v * 16 + hex(s[i + k])
                            out.append(v.toChar()); i += 6
                        }
                        '"' -> { out.append('"'); i += 2 }
                        '\\' -> { out.append('\\'); i += 2 }
                        '/' -> { out.append('/'); i += 2 }
                        'b' -> { out.append('\b'); i += 2 }
                        'f' -> { out.append('\u000c'); i += 2 }
                        'n' -> { out.append('\n'); i += 2 }
                        'r' -> { out.append('\r'); i += 2 }
                        't' -> { out.append('\t'); i += 2 }
                        else -> fail()
                    }
                    continue
                }
                out.append(c); i++
            }
        }
        private fun digits(): Int { val start = i; while (i < s.length && s[i] in '0'..'9') i++; return i - start }
        private fun number() {
            if (i < s.length && s[i] == '-') i++
            if (i >= s.length) fail()
            if (s[i] == '0') i++ else if (s[i] in '1'..'9') digits() else fail()
            if (i < s.length && s[i] == '.') { i++; if (digits() == 0) fail() }
            if (i < s.length && (s[i] == 'e' || s[i] == 'E')) {
                i++
                if (i < s.length && (s[i] == '+' || s[i] == '-')) i++
                if (digits() == 0) fail()
            }
        }
        /** One value, validated; returns its [start, end) span. */
        fun value(depth: Int): IntRange {
            if (depth > MAX_DEPTH) fail()
            ws()
            val start = i
            if (i >= s.length) fail()
            when (val c = s[i]) {
                '"' -> string()
                '{', '[' -> {
                    val close = if (c == '{') '}' else ']'
                    i++; ws()
                    if (i < s.length && s[i] == close) { i++; return start until i }
                    while (true) {
                        if (c == '{') { ws(); string(); expect(':') }
                        value(depth + 1)
                        ws()
                        if (i >= s.length) fail()
                        val d = s[i]
                        if (d == ',') { i++; continue }
                        if (d == close) { i++; break }
                        fail()
                    }
                }
                't' -> literal("true")
                'f' -> literal("false")
                'n' -> literal("null")
                else -> number()
            }
            return start until i
        }
        private fun literal(word: String) { if (!s.startsWith(word, i)) fail(); i += word.length }
    }

    /**
     * The exact text of the top-level `frame` value of a stream `session` message, or null. The whole message must be
     * one strict JSON object (every string, escape, number, literal and nesting level checked, nothing after it); a
     * member named `frame` at another level, or inside a string, is not it. A message naming `frame` twice (in any
     * spelling that decodes to `frame`) is refused: which one a JSON parser keeps is not defined, so the host cannot
     * know which bytes the home meant.
     */
    fun sessionFrameText(message: String): String? {
        val scan = Scan(message)
        return try {
            scan.expect('{')
            scan.ws()
            var found: IntRange? = null
            if (scan.i < message.length && message[scan.i] == '}') scan.i++ else {
                while (true) {
                    scan.ws()
                    val name = scan.string()
                    scan.expect(':')
                    val span = scan.value(1)
                    if (name == "frame") {
                        if (found != null) return null
                        found = span
                    }
                    scan.ws()
                    if (scan.i >= message.length) scan.fail()
                    val d = message[scan.i]
                    if (d == ',') { scan.i++; continue }
                    if (d == '}') { scan.i++; break }
                    scan.fail()
                }
            }
            scan.ws()
            if (scan.i != message.length) return null
            found?.let { message.substring(it.first, it.last + 1) }
        } catch (_: Fail) {
            null
        }
    }

    /**
     * Where a frame is for: its outer `namespace` and `cell`, read to route it to a cell's host and nothing else. The
     * bytes handed to the endpoint are always the frame text itself.
     */
    fun frameCell(frameText: String): Pair<String, String>? {
        val v = Json.obj(frameText) ?: return null
        val namespace = v["namespace"] as? String ?: return null
        val cell = v["cell"] as? String ?: return null
        return namespace to cell
    }

    /** The frame text as the bytes the endpoint receives (UTF-8). */
    fun frameBytes(text: String): ByteArray = text.toByteArray(Charsets.UTF_8)

    /** A `Send` effect's bytes as the text `HomeStream.sessionFrame` carries; null when they are not UTF-8. */
    fun frameText(bytes: ByteArray): String? = try {
        Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes)).toString()
    } catch (_: CharacterCodingException) {
        null
    }
}
