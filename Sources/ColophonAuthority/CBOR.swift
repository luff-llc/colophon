import ColophonCore
import CryptoKit
import Foundation

/// The slice of CBOR a COSE P-256 key needs: a definite-length map of small integers and
/// definite byte strings. Every other shape is malformed.
enum CBOR {
  enum Value: Equatable {
    case unsigned(UInt64)
    case negative(Int64)
    case bytes(Data)
  }

  /// COSE_Key → X9.63 uncompressed `0x04 || x || y`. Requires kty 2, alg -7, crv 1, and 32-byte x and y.
  static func p256x963(fromCOSE data: Data) throws -> Data {
    var reader = Reader(data)
    let pairs = try reader.readMap()
    guard reader.finished else { throw ColophonError.malformed("COSE key") }
    var fields: [Int64: Value] = [:]
    for (key, value) in pairs {
      guard fields[key] == nil else { throw ColophonError.malformed("COSE key") }
      fields[key] = value
    }
    guard fields.count == 5 else { throw ColophonError.malformed("COSE key") }
    guard case .unsigned(2) = fields[1] else { throw ColophonError.malformed("COSE key") }
    guard case .negative(-7) = fields[3] else { throw ColophonError.malformed("COSE key") }
    guard case .unsigned(1) = fields[-1] else { throw ColophonError.malformed("COSE key") }
    guard case .bytes(let x) = fields[-2], x.count == 32 else { throw ColophonError.malformed("COSE key") }
    guard case .bytes(let y) = fields[-3], y.count == 32 else { throw ColophonError.malformed("COSE key") }
    let key = Data([0x04]) + x + y
    guard (try? P256.Signing.PublicKey(x963Representation: key)) != nil else { throw ColophonError.malformed("COSE key") }
    return key
  }

  private struct Reader {
    let data: Data
    var index = 0
    var finished: Bool { index == data.count }

    init(_ data: Data) { self.data = Data(data) }

    mutating func readMap() throws -> [(Int64, Value)] {
      guard index < data.count else { throw ColophonError.malformed("COSE key") }
      let byte = data[index]
      let major = byte >> 5
      let info = byte & 0x1f
      guard major == 5, info <= 23 else { throw ColophonError.malformed("COSE key") }
      index += 1
      var pairs: [(Int64, Value)] = []
      for _ in 0 ..< Int(info) {
        pairs.append((try readKey(), try readValue()))
      }
      return pairs
    }

    private mutating func readKey() throws -> Int64 {
      switch try readValue() {
      case .unsigned(let value):
        guard value <= UInt64(Int64.max) else { throw ColophonError.malformed("COSE key") }
        return Int64(value)
      case .negative(let value): return value
      case .bytes: throw ColophonError.malformed("COSE key")
      }
    }

    private mutating func readValue() throws -> Value {
      guard index < data.count else { throw ColophonError.malformed("COSE key") }
      let byte = data[index]
      index += 1
      let major = byte >> 5
      let info = byte & 0x1f
      let argument = try readArgument(info, major: major)
      switch major {
      case 0: return .unsigned(argument)
      case 1:
        guard argument <= UInt64(Int64.max) else { throw ColophonError.malformed("COSE key") }
        return .negative(-1 - Int64(argument))
      case 2:
        guard argument <= 64 else { throw ColophonError.malformed("COSE key") }
        let length = Int(argument)
        guard index + length <= data.count else { throw ColophonError.malformed("COSE key") }
        let bytes = data[index ..< index + length]
        index += length
        return .bytes(Data(bytes))
      default: throw ColophonError.malformed("COSE key")
      }
    }

    /// Small integers use the immediate form or one extra byte. Byte-string lengths may also use two.
    private mutating func readArgument(_ info: UInt8, major: UInt8) throws -> UInt64 {
      if info < 24 { return UInt64(info) }
      if info == 24 {
        guard index < data.count else { throw ColophonError.malformed("COSE key") }
        let value = UInt64(data[index])
        index += 1
        return value
      }
      if info == 25, major == 2 {
        guard index + 1 < data.count else { throw ColophonError.malformed("COSE key") }
        let value = (UInt64(data[index]) << 8) | UInt64(data[index + 1])
        index += 2
        return value
      }
      throw ColophonError.malformed("COSE key")
    }
  }
}
