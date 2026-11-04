import CryptoKit
import Foundation

/// A 256-bit secret the person keeps on paper or in a password manager (spec §3.3). It derives the
/// library's recovery identity, whose public half is named in genesis. No domain, account or
/// service is involved, so the library can be recovered with everything else gone.
public struct RecoveryKit: Sendable, Equatable {
  public let secret: Data

  /// Crockford-style base32 without I, L, O or U.
  static let alphabet = Array("ABCDEFGHJKMNPQRSTVWXYZ0123456789")
  static let salt = Data("colophon/recovery/1".utf8)

  public init() { secret = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) } }

  public init(secret: Data) throws {
    guard secret.count == 32 else { throw ColophonError.wrongRecoveryKit }
    self.secret = secret
  }

  /// Parses the printed form; spacing, dashes and case don't matter.
  public init(_ text: String) throws {
    var bits = 0, value = 0
    var bytes: [UInt8] = []
    for character in text.uppercased() where character != "-" && !character.isWhitespace {
      guard let index = Self.alphabet.firstIndex(of: character) else { throw ColophonError.wrongRecoveryKit }
      value = ((value << 5) | index) & 0xffff
      bits += 5
      if bits >= 8 {
        bits -= 8
        bytes.append(UInt8((value >> bits) & 0xff))
      }
    }
    guard bytes.count == 32 else { throw ColophonError.wrongRecoveryKit }
    secret = Data(bytes)
  }

  /// 52 characters in groups of four.
  public var text: String {
    var output: [Character] = []
    var bits = 0, value = 0
    for byte in secret {
      value = ((value << 8) | Int(byte)) & 0xffff
      bits += 8
      while bits >= 5 {
        bits -= 5
        output.append(Self.alphabet[(value >> bits) & 31])
      }
    }
    if bits > 0 { output.append(Self.alphabet[(value << (5 - bits)) & 31]) }
    return stride(from: 0, to: output.count, by: 4).map { String(output[$0 ..< min($0 + 4, output.count)]) }
      .joined(separator: "-")
  }

  /// The recovery identity. Each scalar is HKDF-SHA256(secret, salt "colophon/recovery/1",
  /// info "<purpose>/<counter>") for the first counter from 0 that yields a valid P-256 scalar.
  public func identity() throws -> SoftwareIdentity {
    try P256Derivation.identity(secret: secret, salt: Self.salt, failure: .wrongRecoveryKit)
  }
}
