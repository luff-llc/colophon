import CryptoKit
import Foundation

/// Record encoding (spec §2). JSON with sorted keys, unescaped slashes, ISO 8601 dates and
/// standard base64 for bytes. Signatures always cover the exact stored bytes, so a reader in any
/// language verifies what it read rather than re-encoding it.
public enum Canonical {
  public static func encode(_ value: some Encodable) throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    encoder.dateEncodingStrategy = .iso8601
    return try encoder.encode(value)
  }

  public static func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .iso8601
    return try decoder.decode(type, from: data)
  }

  public static func hex(_ bytes: some Sequence<UInt8>) -> String {
    bytes.map { ($0 < 16 ? "0" : "") + String($0, radix: 16) }.joined()
  }

  /// Lowercase hex SHA-256.
  public static func digest(_ data: Data) -> String { hex(SHA256.hash(data: data)) }

  /// Zero-padded decimal, for record names that must sort in order.
  public static func padded(_ number: Int, width: Int) -> String {
    let digits = String(number)
    return String(repeating: "0", count: max(0, width - digits.count)) + digits
  }
}
