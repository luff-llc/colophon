import Foundation

/// Why bytes are not a `now-playing` anchor or presence value. The checks run in this order, and the first that fails
/// is the answer (docs/now-playing.md §2):
/// `tooLarge`, `syntax`, `duplicateField`, `notObject`, `unknownField`, `missingField`, `wrongType`, `outOfRange`,
/// `badText`, `notCanonical`. Within one check, fields are taken in canonical (sorted) order.
public enum NowPlayingCodingError: String, Error, Sendable, Equatable, CaseIterable {
    /// More than `maxPayload` (8,192) bytes, refused before parsing.
    case tooLarge
    /// Not one well-formed JSON value in UTF-8 (including a lone surrogate escape, nesting deeper than 64, or anything
    /// after the value).
    case syntax
    /// A member name appears twice in one object, at any depth.
    case duplicateField
    /// The value is not a JSON object.
    case notObject
    /// A field the format does not define.
    case unknownField
    /// A field the format requires is absent.
    case missingField
    /// A field of the wrong JSON type: a string, a boolean, or an integer token (no fraction, no exponent).
    case wrongType
    /// An integer outside 0 … 2^53 − 1.
    case outOfRange
    /// A string field that is empty, longer than 1,024 UTF-8 bytes, only white space, or holds a control character.
    case badText
    /// Valid, but not in canonical form (0.5 §2.1): keys sorted, no white space, minimal escapes.
    case notCanonical
}

/// The anchor of the `listening.podcasts/now-playing` cell (sessions §S12): where playback was on the publishing
/// device's clock. It is the cell's snapshot and the payload of each ordered message.
///
/// The encoding is the canonical JSON of
/// `{"at":…,"episode":…,"playing":…,"positionMs":…,"ratePermille":…,"show":…}` and nothing else: all six fields are
/// required, integers are 0 … 2^53 − 1, and `episode` and `show` are listening IDs (1 … 1,024 UTF-8 bytes, not only
/// white space, no control character). Reading is strict: anything else is a `NowPlayingCodingError`.
public struct NowPlayingAnchor: Sendable, Hashable {
    /// The largest integer any field or translation result holds: 2^53 − 1.
    public static let maximumInteger: Int64 = (1 << 53) - 1
    /// The largest encoded anchor (the cell's `maxPayload` by default).
    public static let maximumBytes = 8_192

    /// The episode's ID.
    public let episode: String
    /// The show's ID.
    public let show: String
    /// The position, in milliseconds, at `at`.
    public let positionMs: Int64
    /// The playback rate in thousandths (1,000 is normal speed, 1,250 is 1.25×).
    public let ratePermille: Int64
    /// Whether audio was playing at `at`; a paused anchor does not move.
    public let playing: Bool
    /// The publishing device's monotonic clock (sessions §S7), in milliseconds, when `positionMs` was true.
    public let at: Int64

    /// An anchor, or `outOfRange` / `badText` when a value breaks the format.
    public init(episode: String, show: String, positionMs: Int64, ratePermille: Int64, playing: Bool, at: Int64) throws(NowPlayingCodingError) {
        for v in [at, positionMs, ratePermille] where !(0...Self.maximumInteger).contains(v) { throw .outOfRange }
        for s in [episode, show] where !Self.validText(s) { throw .badText }
        self.episode = episode; self.show = show; self.positionMs = positionMs; self.ratePermille = ratePermille
        self.playing = playing; self.at = at
    }

    /// The canonical bytes.
    public var encoded: Data {
        let text = "{\"at\":\(at),\"episode\":\(NowPlayingJSON.quoted(episode)),\"playing\":\(playing),\"positionMs\":\(positionMs),"
            + "\"ratePermille\":\(ratePermille),\"show\":\(NowPlayingJSON.quoted(show))}"
        return Data(text.utf8)
    }

    /// Reads an anchor from exactly these bytes.
    public init(decoding data: Data) throws(NowPlayingCodingError) {
        let object = try Self.object(data, fields: ["at", "episode", "playing", "positionMs", "ratePermille", "show"])
        // Types, in canonical order; then ranges; then text; then the canonical bytes.
        let types: [(String, Kind)] = [("at", .integer), ("episode", .string), ("playing", .bool), ("positionMs", .integer),
                                       ("ratePermille", .integer), ("show", .string)]
        for (k, kind) in types where !kind.matches(object[k]) { throw .wrongType }
        let at = try Self.integer(object["at"]), positionMs = try Self.integer(object["positionMs"])
        let rate = try Self.integer(object["ratePermille"])
        guard case .string(let episode)? = object["episode"], case .string(let show)? = object["show"],
              case .bool(let playing)? = object["playing"] else { throw .wrongType }
        try self.init(episode: episode, show: show, positionMs: positionMs, ratePermille: rate, playing: playing, at: at)
        guard encoded == data else { throw .notCanonical }
    }

    enum Kind {
        case integer, string, bool
        func matches(_ v: NowPlayingJSON?) -> Bool {
            switch (self, v) {
            case (.integer, .number(let token)?): NowPlayingJSON.isIntegerToken(token)
            case (.string, .string(_)?): true
            case (.bool, .bool(_)?): true
            default: false
            }
        }
    }
    static func integer(_ v: NowPlayingJSON?) throws(NowPlayingCodingError) -> Int64 {
        guard case .number(let token)? = v, let value = NowPlayingJSON.safeInteger(token) else { throw .outOfRange }
        return value
    }

    // MARK: Shared reading rules

    /// The fields of one strict, flat object, after the size, syntax, duplicate, object and field-set checks.
    static func object(_ data: Data, fields: Set<String>) throws(NowPlayingCodingError) -> [String: NowPlayingJSON] {
        guard data.count <= maximumBytes else { throw .tooLarge }
        let value: NowPlayingJSON
        do { value = try NowPlayingJSON.parse(Array(data)) } catch .duplicate { throw .duplicateField } catch { throw .syntax }
        guard case .object(let members) = value else { throw .notObject }
        var object: [String: NowPlayingJSON] = [:]
        for (k, v) in members { object[k] = v }
        if object.keys.contains(where: { !fields.contains($0) }) { throw .unknownField }
        if fields.contains(where: { object[$0] == nil }) { throw .missingField }
        return object
    }

    /// The listening-ID rule (as the core's `colophon-id`): 1 … 1,024 UTF-8 bytes, not only white space, no control
    /// character. White space is the Unicode `White_Space` set and control characters are `Cc`, spelled out so that
    /// every language applies the same set.
    static func validText(_ s: String) -> Bool {
        let bytes = s.utf8.count
        guard bytes >= 1, bytes <= 1_024 else { return false }
        var allSpace = true
        for u in s.unicodeScalars {
            if u.value < 0x20 || (0x7F...0x9F).contains(u.value) { return false }
            if !whiteSpace.contains(u.value) { allSpace = false }
        }
        return !allSpace
    }
    /// Unicode `White_Space` (control characters among them are refused before this matters).
    static let whiteSpace: Set<UInt32> = [0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0x85, 0xA0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004,
                                          0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200A, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000]
}
