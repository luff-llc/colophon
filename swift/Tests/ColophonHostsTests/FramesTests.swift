import Testing
@testable import ColophonHosts

/// `SessionFrames.frameText(ofMessage:)` on adversarial messages: the frame's original bytes when the message is one
/// strict JSON object with exactly one top-level `frame`, and nothing otherwise (the matrix of js/test06/frames.test.ts).
@Suite struct FramesTests {
    static let frame = #"{"a":"x\"}y","b":[1,-2.5e3,true,false,null,{}],"c":"\u00e9\n"}"#

    static let kept: [(String, String, String)] = [
        ("first", #"{"frame":\#(frame),"type":"session"}"#, frame),
        ("last", #"{"type":"session","n":3,"frame":\#(frame)}"#, frame),
        ("whitespace everywhere", " \n{ \"type\" : \"session\" ,\t\"frame\"\r\n:  \(frame)  }\n", frame),
        ("a string frame", #"{"type":"session","frame":"a\"b"}"#, #""a\"b""#),
        ("an escaped quote before it", #"{"x":"\"frame\":1","frame":\#(frame)}"#, frame),
        ("\"frame\" inside a nested object", #"{"x":{"frame":1},"frame":\#(frame)}"#, frame),
        ("\"frame\" inside a string", #"{"x":"{\"frame\":{}}","frame":\#(frame)}"#, frame),
        ("unicode escapes in other members", #"{"x":"\ud83d\ude00\u0000","frame":\#(frame)}"#, frame),
        ("spacing inside the frame kept", #"{"frame":{ "k" : [ 1 , 2 ] }}"#, #"{ "k" : [ 1 , 2 ] }"#),
        ("non-ASCII bytes kept as they are", #"{"frame":{"t":"café ☕︎"}}"#, #"{"t":"café ☕︎"}"#),
    ]
    static let refused: [(String, String)] = [
        ("an invalid bare token after it", #"{"frame":{},"x":wat}"#),
        ("an invalid token in it", #"{"frame":{"a":tru}}"#),
        ("a bad number", #"{"frame":{"a":01}}"#),
        ("a bad escape", #"{"frame":{"a":"\x"}}"#),
        ("a short unicode escape", #"{"frame":{"a":"\u12"}}"#),
        ("a raw control character", "{\"frame\":{\"a\":\"\u{01}\"}}"),
        ("two frames", #"{"frame":\#(frame),"frame":\#(frame)}"#),
        ("two frames, one spelt with an escape", #"{"frame":\#(frame),"fr\u0061me":{}}"#),
        ("two frames, the first spelt with an escape", #"{"\u0066rame":1,"frame":\#(frame)}"#),
        ("two frames, one spelt entirely in escapes", #"{"frame":\#(frame),"\u0066\u0072\u0061\u006d\u0065":2}"#),
        ("trailing data", #"{"frame":\#(frame)}x"#),
        ("two objects", #"{"frame":\#(frame)}{}"#),
        ("an unclosed object", #"{"frame":\#(frame)"#),
        ("a trailing comma", #"{"frame":\#(frame),}"#),
        ("no frame", #"{"type":"session"}"#),
        ("frame only nested", #"{"x":{"frame":{}}}"#),
        ("an array", "[\(frame)]"),
        ("empty", ""),
        ("nesting past the bound", #"{"frame":"# + String(repeating: "[", count: 80) + String(repeating: "]", count: 80) + "}"),
    ]

    @Test(arguments: kept.indices) func keepsTheFramesBytes(_ k: Int) {
        let (name, message, frame) = Self.kept[k]
        let got = SessionFrames.frameText(ofMessage: message)
        #expect(got == frame, "\(name)")
    }
    @Test(arguments: refused.indices) func refuses(_ k: Int) {
        let (name, message) = Self.refused[k]
        let got = SessionFrames.frameText(ofMessage: message)
        #expect(got == nil, "\(name)")
    }
    @Test func nestingAtTheBoundIsKept() {
        let deep = String(repeating: "[", count: 65) + String(repeating: "]", count: 65)
        let got = SessionFrames.frameText(ofMessage: #"{"frame":"# + deep + "}")
        #expect(got == deep)
    }
}
