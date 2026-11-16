import Foundation

/// The two payloads the test apps pass between devices (as a QR code, a pasted text or a deep link), the same bytes on
/// iPhone and Android:
///
/// * an **invite** (`CTJ1.`), shown by a device of the account: the home's prefix and slot, the account ID, and the
///   account's `authority/` history. A 0.5 device with nothing cannot fetch the history from a home that keeps it for
///   members (docs/session.md), so the joining device takes it from the invite, writes it to its own store and verifies
///   it like any other copy;
/// * a **request** (`CTR1.`), shown by the joining device: its signed member request (`exportRequest()`), whose pairing
///   code both screens show.
///
/// Each is the canonical JSON (or the request's own bytes), raw-DEFLATE compressed, base64url without padding.
enum PairingPayload {
    struct Invite: Equatable, Sendable {
        var homePrefix: String
        var slot: String
        var account: String
        /// Store path to the exact bytes.
        var history: [String: Data]
    }

    enum Failure: LocalizedError {
        case notAPayload, badHistory(String)
        var errorDescription: String? {
            switch self {
            case .notAPayload: "This is not a Colophon test invite or request."
            case .badHistory(let path): "The invite carries a path that is not account history: \(path)"
            }
        }
    }

    static let invitePrefix = "CTJ1."
    static let requestPrefix = "CTR1."

    static func encode(_ invite: Invite) throws -> String {
        let object: [String: Any] = ["v": 1, "prefix": invite.homePrefix, "slot": invite.slot, "account": invite.account,
                                     "history": invite.history.mapValues { $0.base64EncodedString() }]
        return invitePrefix + b64url(try deflate(JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])))
    }
    static func encodeRequest(_ request: Data) throws -> String { requestPrefix + b64url(try deflate(request)) }

    static func decodeInvite(_ text: String) throws -> Invite {
        guard let data = try body(text, prefix: invitePrefix),
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any], object["v"] as? Int == 1,
              let prefix = object["prefix"] as? String, let slot = object["slot"] as? String, let account = object["account"] as? String,
              let history = object["history"] as? [String: String] else { throw Failure.notAPayload }
        var files: [String: Data] = [:]
        for (path, b64) in history {
            guard isHistoryPath(path), let bytes = Data(base64Encoded: b64) else { throw Failure.badHistory(path) }
            files[path] = bytes
        }
        guard account.count == 64, account.allSatisfy(\.isHexDigit), !files.isEmpty else { throw Failure.notAPayload }
        return Invite(homePrefix: prefix, slot: slot, account: account, history: files)
    }
    static func decodeRequest(_ text: String) throws -> Data {
        guard let data = try body(text, prefix: requestPrefix) else { throw Failure.notAPayload }
        return data
    }
    static func kind(_ text: String) -> String? {
        let t = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if t.hasPrefix(invitePrefix) { return "invite" }
        if t.hasPrefix(requestPrefix) { return "request" }
        return nil
    }

    /// `authority/` followed by 8 digits and `.json`: the only paths an invite may write.
    static func isHistoryPath(_ path: String) -> Bool {
        let parts = path.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2, parts[0] == "authority", parts[1].hasSuffix(".json") else { return false }
        let digits = parts[1].dropLast(5)
        return digits.count == 8 && digits.allSatisfy { $0 >= "0" && $0 <= "9" }
    }

    private static func body(_ text: String, prefix: String) throws -> Data? {
        let t = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard t.hasPrefix(prefix), let raw = unb64url(String(t.dropFirst(prefix.count))) else { return nil }
        return try inflate(raw)
    }
    private static func deflate(_ data: Data) throws -> Data { try (data as NSData).compressed(using: .zlib) as Data }
    private static func inflate(_ data: Data) throws -> Data { try (data as NSData).decompressed(using: .zlib) as Data }
    static func b64url(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
    static func unb64url(_ text: String) -> Data? {
        var s = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while s.count % 4 != 0 { s += "=" }
        return Data(base64Encoded: s)
    }
}
