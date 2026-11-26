import Foundation

/// The strict JSON reader and canonical writer behind the `now-playing` payloads (docs/now-playing.md §2). It reads the
/// whole RFC 8259 grammar so that every input gets one well-defined verdict, refuses what 0.5 §2.3 refuses (duplicate
/// member names at any depth, lone surrogates, nesting deeper than 64, anything after the value), and keeps each number
/// as its token so that integers are judged exactly rather than through a floating-point value.
enum NowPlayingJSON: Equatable {
    case object([(String, NowPlayingJSON)])
    case array([NowPlayingJSON])
    case string(String)
    /// The number token as written.
    case number(String)
    case bool(Bool)
    case null

    static func == (a: NowPlayingJSON, b: NowPlayingJSON) -> Bool {
        switch (a, b) {
        case (.object(let x), .object(let y)): x.count == y.count && zip(x, y).allSatisfy { $0.0 == $1.0 && $0.1 == $1.1 }
        case (.array(let x), .array(let y)): x == y
        case (.string(let x), .string(let y)): x == y
        case (.number(let x), .number(let y)): x == y
        case (.bool(let x), .bool(let y)): x == y
        case (.null, .null): true
        default: false
        }
    }

    enum Failure: Error, Equatable { case syntax, duplicate }

    /// Parses exactly one JSON value from `bytes` (UTF-8). Duplicate member names anywhere are `.duplicate`; anything
    /// else that is not one well-formed value is `.syntax`.
    static func parse(_ bytes: [UInt8]) throws(Failure) -> NowPlayingJSON {
        var reader = Reader(bytes: bytes)
        let value = try reader.value(depth: 0)
        reader.whitespace()
        guard reader.at == bytes.count else { throw .syntax }
        return value
    }

    private struct Reader {
        let bytes: [UInt8]
        var at = 0
        static let maximumDepth = 64

        mutating func whitespace() {
            while at < bytes.count, [0x20, 0x09, 0x0A, 0x0D].contains(bytes[at]) { at += 1 }
        }
        mutating func value(depth: Int) throws(Failure) -> NowPlayingJSON {
            whitespace()
            guard at < bytes.count else { throw .syntax }
            switch bytes[at] {
            case UInt8(ascii: "{"):
                guard depth < Self.maximumDepth else { throw .syntax }
                return try object(depth: depth + 1)
            case UInt8(ascii: "["):
                guard depth < Self.maximumDepth else { throw .syntax }
                return try array(depth: depth + 1)
            case UInt8(ascii: "\""): return .string(try string())
            case UInt8(ascii: "t"): try literal("true"); return .bool(true)
            case UInt8(ascii: "f"): try literal("false"); return .bool(false)
            case UInt8(ascii: "n"): try literal("null"); return .null
            default: return .number(try number())
            }
        }
        mutating func literal(_ word: String) throws(Failure) {
            let w = Array(word.utf8)
            guard at + w.count <= bytes.count, Array(bytes[at..<at + w.count]) == w else { throw .syntax }
            at += w.count
        }
        mutating func object(depth: Int) throws(Failure) -> NowPlayingJSON {
            at += 1
            var members: [(String, NowPlayingJSON)] = []
            var names = Set<String>()
            var duplicate = false
            whitespace()
            if at < bytes.count, bytes[at] == UInt8(ascii: "}") { at += 1; return .object([]) }
            while true {
                whitespace()
                guard at < bytes.count, bytes[at] == UInt8(ascii: "\"") else { throw .syntax }
                let name = try string()
                if !names.insert(name).inserted { duplicate = true }
                whitespace()
                guard at < bytes.count, bytes[at] == UInt8(ascii: ":") else { throw .syntax }
                at += 1
                let v: NowPlayingJSON
                do { v = try value(depth: depth) } catch .duplicate { duplicate = true; v = .null }
                members.append((name, v))
                whitespace()
                guard at < bytes.count else { throw .syntax }
                if bytes[at] == UInt8(ascii: ",") { at += 1; continue }
                guard bytes[at] == UInt8(ascii: "}") else { throw .syntax }
                at += 1
                break
            }
            // A syntax error anywhere wins over a duplicate: the whole input is read before a duplicate is reported.
            if duplicate { throw .duplicate }
            return .object(members)
        }
        mutating func array(depth: Int) throws(Failure) -> NowPlayingJSON {
            at += 1
            var items: [NowPlayingJSON] = []
            var duplicate = false
            whitespace()
            if at < bytes.count, bytes[at] == UInt8(ascii: "]") { at += 1; return .array([]) }
            while true {
                do { items.append(try value(depth: depth)) } catch .duplicate { duplicate = true }
                whitespace()
                guard at < bytes.count else { throw .syntax }
                if bytes[at] == UInt8(ascii: ",") { at += 1; continue }
                guard bytes[at] == UInt8(ascii: "]") else { throw .syntax }
                at += 1
                break
            }
            if duplicate { throw .duplicate }
            return .array(items)
        }
        mutating func number() throws(Failure) -> String {
            let start = at
            func digits() -> Int { let s = at; while at < bytes.count, (0x30...0x39).contains(bytes[at]) { at += 1 }; return at - s }
            if at < bytes.count, bytes[at] == UInt8(ascii: "-") { at += 1 }
            guard at < bytes.count, (0x30...0x39).contains(bytes[at]) else { throw .syntax }
            if bytes[at] == UInt8(ascii: "0") { at += 1 } else { _ = digits() }
            if at < bytes.count, bytes[at] == UInt8(ascii: ".") {
                at += 1
                guard digits() > 0 else { throw .syntax }
            }
            if at < bytes.count, bytes[at] == UInt8(ascii: "e") || bytes[at] == UInt8(ascii: "E") {
                at += 1
                if at < bytes.count, bytes[at] == UInt8(ascii: "+") || bytes[at] == UInt8(ascii: "-") { at += 1 }
                guard digits() > 0 else { throw .syntax }
            }
            return String(decoding: bytes[start..<at], as: UTF8.self)
        }
        mutating func hex4() throws(Failure) -> UInt32 {
            guard at + 4 <= bytes.count else { throw .syntax }
            var v: UInt32 = 0
            for b in bytes[at..<at + 4] {
                let d: UInt32
                switch b {
                case 0x30...0x39: d = UInt32(b - 0x30)
                case 0x41...0x46: d = UInt32(b - 0x41 + 10)
                case 0x61...0x66: d = UInt32(b - 0x61 + 10)
                default: throw .syntax
                }
                v = v * 16 + d
            }
            at += 4
            return v
        }
        /// A string token; its bytes must be valid UTF-8 and its escapes must not leave a lone surrogate.
        mutating func string() throws(Failure) -> String {
            at += 1
            var out: [UInt8] = []
            while true {
                guard at < bytes.count else { throw .syntax }
                let b = bytes[at]
                if b == UInt8(ascii: "\"") { at += 1; break }
                if b < 0x20 { throw .syntax }
                if b != UInt8(ascii: "\\") { out.append(b); at += 1; continue }
                at += 1
                guard at < bytes.count else { throw .syntax }
                let e = bytes[at]
                at += 1
                switch e {
                case UInt8(ascii: "\""): out.append(0x22)
                case UInt8(ascii: "\\"): out.append(0x5C)
                case UInt8(ascii: "/"): out.append(0x2F)
                case UInt8(ascii: "b"): out.append(0x08)
                case UInt8(ascii: "f"): out.append(0x0C)
                case UInt8(ascii: "n"): out.append(0x0A)
                case UInt8(ascii: "r"): out.append(0x0D)
                case UInt8(ascii: "t"): out.append(0x09)
                case UInt8(ascii: "u"):
                    var scalar = try hex4()
                    if (0xD800...0xDBFF).contains(scalar) {
                        guard at + 6 <= bytes.count, bytes[at] == UInt8(ascii: "\\"), bytes[at + 1] == UInt8(ascii: "u") else { throw .syntax }
                        at += 2
                        let low = try hex4()
                        guard (0xDC00...0xDFFF).contains(low) else { throw .syntax }
                        scalar = 0x10000 + ((scalar - 0xD800) << 10) + (low - 0xDC00)
                    } else if (0xDC00...0xDFFF).contains(scalar) {
                        throw .syntax
                    }
                    guard let u = Unicode.Scalar(scalar) else { throw .syntax }
                    out.append(contentsOf: Array(String(Character(u)).utf8))
                default: throw .syntax
                }
            }
            // Validate UTF-8 strictly: decoding with repair and comparing bytes catches every ill-formed sequence.
            let text = String(decoding: out, as: UTF8.self)
            guard Array(text.utf8) == out else { throw .syntax }
            return text
        }
    }

    // MARK: Canonical writing (0.5 §2.1)

    /// `s` as a canonical JSON string: the minimal escapes JSON requires, lowercase hex, non-ASCII as UTF-8.
    static func quoted(_ s: String) -> String {
        var out = "\""
        for u in s.unicodeScalars {
            switch u {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\u{08}": out += "\\b"
            case "\u{0C}": out += "\\f"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            default:
                if u.value < 0x20 {
                    let hex = String(u.value, radix: 16)
                    out += "\\u" + String(repeating: "0", count: 4 - hex.count) + hex
                } else {
                    out.unicodeScalars.append(u)
                }
            }
        }
        return out + "\""
    }

    /// The exact value of an integer token (`-?(0|[1-9][0-9]*)`) when it lies in 0 … 2^53 − 1; nil when the token
    /// has a fraction or an exponent (not an integer token) is reported separately by `isIntegerToken`.
    static func isIntegerToken(_ token: String) -> Bool { !token.contains(where: { $0 == "." || $0 == "e" || $0 == "E" }) }
    static func safeInteger(_ token: String) -> Int64? {
        guard isIntegerToken(token) else { return nil }
        let negative = token.hasPrefix("-")
        let digits = negative ? token.dropFirst() : Substring(token)
        // Longer than 16 digits is beyond 2^53 − 1 (9007199254740991, 16 digits).
        guard digits.count <= 16, let magnitude = Int64(digits) else { return nil }
        if negative { return magnitude == 0 ? 0 : nil }
        return magnitude <= NowPlayingAnchor.maximumInteger ? magnitude : nil
    }
}
