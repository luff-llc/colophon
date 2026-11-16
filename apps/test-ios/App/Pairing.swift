import Compression
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

    enum Failure: LocalizedError, Equatable {
        case notAPayload, badHistory(String), tooLarge
        var errorDescription: String? {
            switch self {
            case .notAPayload: "This is not a Colophon test invite or request."
            case .badHistory(let path): "The invite carries a path that is not account history: \(path)"
            case .tooLarge: "This payload is larger than an invite or a request may be."
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
        guard text.utf8.count <= maximumText else { throw Failure.tooLarge }
        let t = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard t.hasPrefix(prefix), let raw = unb64url(String(t.dropFirst(prefix.count))) else { return nil }
        return try inflate(raw)
    }
    private static func deflate(_ data: Data) throws -> Data { try (data as NSData).compressed(using: .zlib) as Data }
    /// The most an inflated payload may be (as on Android), and the longest text taken at all.
    static let maximumInflated = 32 * 1024 * 1024
    static let maximumText = 8 * 1024 * 1024
    /// Raw DEFLATE, stopped as soon as the output passes `maximumInflated`: a small bomb in a link cannot exhaust the app.
    static func inflate(_ data: Data) throws -> Data {
        var stream = compression_stream(dst_ptr: UnsafeMutablePointer<UInt8>(bitPattern: 1)!, dst_size: 0,
                                        src_ptr: UnsafePointer<UInt8>(bitPattern: 1)!, src_size: 0, state: nil)
        guard compression_stream_init(&stream, COMPRESSION_STREAM_DECODE, COMPRESSION_ZLIB) == COMPRESSION_STATUS_OK else { throw Failure.notAPayload }
        defer { compression_stream_destroy(&stream) }
        var out = Data()
        let chunk = 64 * 1024
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: chunk)
        defer { buffer.deallocate() }
        return try data.withUnsafeBytes { (input: UnsafeRawBufferPointer) throws -> Data in
            guard let base = input.bindMemory(to: UInt8.self).baseAddress else { throw Failure.notAPayload }
            stream.src_ptr = base; stream.src_size = input.count
            while true {
                stream.dst_ptr = buffer; stream.dst_size = chunk
                let status = compression_stream_process(&stream, Int32(COMPRESSION_STREAM_FINALIZE.rawValue))
                out.append(buffer, count: chunk - stream.dst_size)
                if out.count > maximumInflated { throw Failure.tooLarge }
                switch status {
                case COMPRESSION_STATUS_END: return out
                case COMPRESSION_STATUS_OK: if stream.src_size == 0 && stream.dst_size == chunk { throw Failure.notAPayload }
                default: throw Failure.notAPayload
                }
            }
        }
    }
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
