import Foundation

/// The session frame inside a home stream `session` message, taken out as text, never re-serialised.
///
/// The home carries a sealed frame verbatim as the `frame` value of `{"type":"session",…,"frame":<frame>}` (stream
/// §5.2), and a receiver accepts only the frame's canonical bytes. Parsing the message and serialising `frame` again
/// would hand the codec bytes the sender never signed whenever the two encodings differ (an escape, a number form, a
/// duplicate name collapsed), and could turn a non-canonical frame into an acceptable one. So the host locates the
/// value's span in the message's UTF-8 and passes exactly those bytes on; the codec then judges them.
public enum SessionFrames {
    /// Deeper than any stream message may nest (a frame's 64 levels and the message's one, stream §5.2).
    static let maxDepth = 66

    /// The exact text of the top-level `frame` value of a stream `session` message, or nil. The whole message must be
    /// one strict JSON object (RFC 8259: every string, escape, number, literal and nesting level checked, nothing after
    /// it); a member named `frame` at another level, or inside a string, is not it. A message naming `frame` twice (in
    /// any spelling that decodes to `frame`) is refused: which one a JSON parser keeps is not defined, so the host cannot
    /// know which bytes the home meant.
    public static func frameText(ofMessage message: String) -> String? {
        let bytes = Array(message.utf8)
        var scan = Scan(bytes: bytes)
        do {
            try scan.expect(UInt8(ascii: "{"))
            scan.skipSpace()
            var found: Range<Int>?
            if scan.peek == UInt8(ascii: "}") {
                scan.i += 1
            } else {
                while true {
                    scan.skipSpace()
                    let name = try scan.string()
                    try scan.expect(UInt8(ascii: ":"))
                    let span = try scan.value(depth: 1)
                    if name == "frame" {
                        if found != nil { return nil }
                        found = span
                    }
                    scan.skipSpace()
                    switch scan.peek {
                    case UInt8(ascii: ","): scan.i += 1; continue
                    case UInt8(ascii: "}"): scan.i += 1
                    default: throw Scan.Failure()
                    }
                    break
                }
            }
            scan.skipSpace()
            guard scan.i == bytes.count, let found else { return nil }
            return String(decoding: bytes[found], as: UTF8.self)
        } catch {
            return nil
        }
    }

    /// Where a frame is for: its outer `namespace` and `cell`, read to route it to a cell's host and nothing else. The
    /// bytes handed to the endpoint are always the frame text itself.
    public static func cell(ofFrame frame: String) -> (namespace: String, cell: String)? {
        guard let object = try? JSONSerialization.jsonObject(with: Data(frame.utf8)) as? [String: Any],
              let namespace = object["namespace"] as? String, let cell = object["cell"] as? String else { return nil }
        return (namespace, cell)
    }
}

/// A strict JSON scanner (RFC 8259) over UTF-8 that reports where values are instead of building them.
private struct Scan {
    struct Failure: Error {}
    let bytes: [UInt8]
    var i = 0
    init(bytes: [UInt8]) { self.bytes = bytes }

    var peek: UInt8? { i < bytes.count ? bytes[i] : nil }
    mutating func skipSpace() {
        while let c = peek, c == 0x20 || c == 0x09 || c == 0x0a || c == 0x0d { i += 1 }
    }
    mutating func expect(_ c: UInt8) throws {
        skipSpace()
        guard peek == c else { throw Failure() }
        i += 1
    }
    private func hex(_ at: Int) throws -> UInt32 {
        guard at + 4 <= bytes.count else { throw Failure() }
        var v: UInt32 = 0
        for b in bytes[at..<at + 4] {
            let d: UInt32
            switch b {
            case 0x30...0x39: d = UInt32(b - 0x30)
            case 0x41...0x46: d = UInt32(b - 0x41 + 10)
            case 0x61...0x66: d = UInt32(b - 0x61 + 10)
            default: throw Failure()
            }
            v = v << 4 | d
        }
        return v
    }
    /// A string at `i` (at its quote), every escape checked; returns its decoded value (lone surrogates become U+FFFD,
    /// which is never part of a name this scanner compares).
    mutating func string() throws -> String {
        guard peek == UInt8(ascii: "\"") else { throw Failure() }
        i += 1
        var raw: [UInt8] = []
        var scalars = String.UnicodeScalarView()
        func flush() { if !raw.isEmpty { scalars.append(contentsOf: String(decoding: raw, as: UTF8.self).unicodeScalars); raw.removeAll() } }
        var pendingHigh: UInt32?
        func emit(_ u: UInt32) {
            if let high = pendingHigh {
                pendingHigh = nil
                if (0xDC00...0xDFFF).contains(u) {
                    scalars.append(Unicode.Scalar(0x10000 + ((high - 0xD800) << 10) + (u - 0xDC00)) ?? "\u{FFFD}")
                    return
                }
                scalars.append("\u{FFFD}")
            }
            if (0xD800...0xDBFF).contains(u) { pendingHigh = u; return }
            scalars.append(Unicode.Scalar(u) ?? "\u{FFFD}")
        }
        while true {
            guard let c = peek else { throw Failure() }
            if c == UInt8(ascii: "\"") { i += 1; break }
            if c < 0x20 { throw Failure() }
            if c == UInt8(ascii: "\\") {
                guard i + 1 < bytes.count else { throw Failure() }
                flush()
                let e = bytes[i + 1]
                switch e {
                case UInt8(ascii: "u"): emit(try hex(i + 2)); i += 6; continue
                case UInt8(ascii: "\""): emit(0x22)
                case UInt8(ascii: "\\"): emit(0x5C)
                case UInt8(ascii: "/"): emit(0x2F)
                case UInt8(ascii: "b"): emit(0x08)
                case UInt8(ascii: "f"): emit(0x0C)
                case UInt8(ascii: "n"): emit(0x0A)
                case UInt8(ascii: "r"): emit(0x0D)
                case UInt8(ascii: "t"): emit(0x09)
                default: throw Failure()
                }
                i += 2
                continue
            }
            if pendingHigh != nil { pendingHigh = nil; scalars.append("\u{FFFD}") }
            raw.append(c)
            i += 1
        }
        flush()
        if pendingHigh != nil { scalars.append("\u{FFFD}") }
        return String(scalars)
    }
    /// One value, validated; returns its span.
    mutating func value(depth: Int) throws -> Range<Int> {
        guard depth <= SessionFrames.maxDepth else { throw Failure() }
        skipSpace()
        let start = i
        guard let c = peek else { throw Failure() }
        if c == UInt8(ascii: "\"") { _ = try string(); return start..<i }
        if c == UInt8(ascii: "{") || c == UInt8(ascii: "[") {
            let object = c == UInt8(ascii: "{")
            let close = object ? UInt8(ascii: "}") : UInt8(ascii: "]")
            i += 1
            skipSpace()
            if peek == close { i += 1; return start..<i }
            while true {
                if object { skipSpace(); _ = try string(); try expect(UInt8(ascii: ":")) }
                _ = try value(depth: depth + 1)
                skipSpace()
                guard let d = peek else { throw Failure() }
                if d == UInt8(ascii: ",") { i += 1; continue }
                if d == close { i += 1; return start..<i }
                throw Failure()
            }
        }
        for literal in ["true", "false", "null"] {
            let l = Array(literal.utf8)
            if i + l.count <= bytes.count, Array(bytes[i..<i + l.count]) == l { i += l.count; return start..<i }
        }
        try number()
        return start..<i
    }
    /// `-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?`
    private mutating func number() throws {
        func digit(_ b: UInt8?) -> Bool { b.map { (0x30...0x39).contains($0) } ?? false }
        if peek == UInt8(ascii: "-") { i += 1 }
        guard let first = peek, digit(first) else { throw Failure() }
        i += 1
        if first != UInt8(ascii: "0") { while digit(peek) { i += 1 } }
        if peek == UInt8(ascii: ".") {
            i += 1
            guard digit(peek) else { throw Failure() }
            while digit(peek) { i += 1 }
        }
        if peek == UInt8(ascii: "e") || peek == UInt8(ascii: "E") {
            i += 1
            if peek == UInt8(ascii: "+") || peek == UInt8(ascii: "-") { i += 1 }
            guard digit(peek) else { throw Failure() }
            while digit(peek) { i += 1 }
        }
    }
}
