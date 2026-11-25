package com.luff.colophon.hosts

import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/**
 * [Frames.sessionFrameText] on adversarial messages: the frame's original text when the message is one strict JSON
 * object with exactly one top-level `frame`, and nothing otherwise (the matrix of js/test06/frames.test.ts).
 */
class FramesTest {
    private val f = """{"a":"x\"}y","b":[1,-2.5e3,true,false,null,{}],"c":"é\n"}"""

    @Test fun keepsTheFramesText() {
        val kept = listOf(
            Triple("first", """{"frame":$f,"type":"session"}""", f),
            Triple("last", """{"type":"session","n":3,"frame":$f}""", f),
            Triple("whitespace everywhere", " \n{ \"type\" : \"session\" ,\t\"frame\"\r\n:  $f  }\n", f),
            Triple("a string frame", """{"type":"session","frame":"a\"b"}""", """"a\"b""""),
            Triple("an escaped quote before it", """{"x":"\"frame\":1","frame":$f}""", f),
            Triple("\"frame\" inside a nested object", """{"x":{"frame":1},"frame":$f}""", f),
            Triple("\"frame\" inside a string", """{"x":"{\"frame\":{}}","frame":$f}""", f),
            Triple("unicode escapes in other members", """{"x":"😀\u0000","frame":$f}""", f),
            Triple("spacing inside the frame kept", """{"frame":{ "k" : [ 1 , 2 ] }}""", """{ "k" : [ 1 , 2 ] }"""),
            Triple("raw non-ASCII kept", "{\"frame\":{\"k\":\"é😀\"}}", "{\"k\":\"é😀\"}"),
        )
        for ((name, message, frame) in kept) assertEquals(frame, Frames.sessionFrameText(message), name)
    }

    @Test fun refusesEverythingElse() {
        val refused = listOf(
            "an invalid bare token after it" to """{"frame":{},"x":wat}""",
            "an invalid token in it" to """{"frame":{"a":tru}}""",
            "a bad number" to """{"frame":{"a":01}}""",
            "a bad fraction" to """{"frame":{"a":1.}}""",
            "a bad exponent" to """{"frame":{"a":1e}}""",
            "a bad escape" to """{"frame":{"a":"\x"}}""",
            "a short unicode escape" to """{"frame":{"a":"\u12"}}""",
            "a raw control character" to "{\"frame\":{\"a\":\"\u0001\"}}",
            "two frames" to """{"frame":$f,"frame":$f}""",
            "two frames, one spelt with an escape" to """{"frame":$f,"frame":{}}""",
            "trailing data" to """{"frame":$f}x""",
            "two objects" to """{"frame":$f}{}""",
            "an unclosed object" to """{"frame":$f""",
            "a trailing comma" to """{"frame":$f,}""",
            "no frame" to """{"type":"session"}""",
            "frame only nested" to """{"x":{"frame":{}}}""",
            "an array" to "[$f]",
            "empty" to "",
            "a bare string" to "\"frame\"",
            "nesting past the bound" to """{"frame":${"[".repeat(80)}${"]".repeat(80)}}""",
        )
        for ((name, message) in refused) assertNull(Frames.sessionFrameText(message), name)
    }

    @Test fun nestingUpToTheBoundIsKept() {
        val deep = "[".repeat(65) + "]".repeat(65)
        assertEquals(deep, Frames.sessionFrameText("""{"frame":$deep}"""))
    }

    @Test fun routesByTheFramesOwnNamespaceAndCell() {
        assertEquals("listening.podcasts" to "now-playing", Frames.frameCell("""{"cell":"now-playing","namespace":"listening.podcasts","n":1}"""))
        assertNull(Frames.frameCell("""{"cell":1,"namespace":"x"}"""))
        assertNull(Frames.frameCell("not json"))
    }
}
