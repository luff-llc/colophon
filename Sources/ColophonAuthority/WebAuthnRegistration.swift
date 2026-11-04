import ColophonCore
import CryptoKit
import Foundation

/// Reads a WebAuthn attestation object far enough to recover the new credential and its COSE key.
/// `fmt` and `attStmt` are accepted so a packed or Apple attestation still yields `authData`.
/// Extension bytes are skipped only when they are one definite CBOR value.
public enum WebAuthnRegistration {
  /// Credential id and the ES256 COSE key embedded in `authData`. The AT flag is required.
  public static func parse(attestationObject: Data) throws -> (credentialID: Data, coseKey: Data) {
    var reader = Reader(attestationObject)
    let fields = try reader.readMap()
    guard reader.finished else { throw ColophonError.malformed("attestation") }
    guard case .text(let fmt) = fields["fmt"], !fmt.isEmpty else { throw ColophonError.malformed("attestation") }
    guard fields["attStmt"] != nil else { throw ColophonError.malformed("attestation") }
    guard case .bytes(let authData) = fields["authData"] else { throw ColophonError.malformed("attestation") }
    return try credential(in: authData)
  }

  /// `fmt: "none"` attestation object. Tests and the synthetic authenticator share this encoding.
  public static func formatNone(authData: Data) -> Data {
    var data = Data([0xa3])
    data.append(text("fmt"))
    data.append(text("none"))
    data.append(text("attStmt"))
    data.append(0xa0)
    data.append(text("authData"))
    data.append(byteString(authData))
    return data
  }

  /// Authenticator data with attested credential data. The AT flag is set.
  public static func attestedAuthenticatorData(rpID: String, flags: UInt8, credentialID: Data, coseKey: Data,
    aaguid: Data = Data(count: 16)) -> Data
  {
    var data = Data(SHA256.hash(data: Data(rpID.utf8)))
    data.append(flags | 0x40)
    data.append(contentsOf: [0, 0, 0, 0])
    var identifier = Data(aaguid.prefix(16))
    if identifier.count < 16 { identifier.append(Data(count: 16 - identifier.count)) }
    data.append(identifier)
    data.append(UInt8((credentialID.count >> 8) & 0xff))
    data.append(UInt8(credentialID.count & 0xff))
    data.append(credentialID)
    data.append(coseKey)
    return data
  }

  /// ES256 COSE_Key for an uncompressed P-256 public key.
  public static func es256COSE(x963: Data) throws -> Data {
    let key = Data(x963)
    guard key.count == 65, key.first == 0x04 else { throw ColophonError.malformed("COSE key") }
    var data = Data([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20])
    data.append(key.subdata(in: 1 ..< 33))
    data.append(contentsOf: [0x22, 0x58, 0x20])
    data.append(key.subdata(in: 33 ..< 65))
    return data
  }

  private static func credential(in authData: Data) throws -> (credentialID: Data, coseKey: Data) {
    guard authData.count >= 37 else { throw ColophonError.malformed("attestation") }
    let flags = authData[authData.startIndex + 32]
    guard flags & 0x40 != 0 else { throw ColophonError.malformed("attestation") }
    var index = 37
    guard authData.count >= index + 18 else { throw ColophonError.malformed("attestation") }
    index += 16
    let length = (Int(authData[authData.startIndex + index]) << 8) | Int(authData[authData.startIndex + index + 1])
    index += 2
    guard length > 0, length <= 1024, authData.count >= index + length else { throw ColophonError.malformed("attestation") }
    let credentialID = authData.subdata(in: index ..< (index + length))
    index += length
    let rest = authData.subdata(in: index ..< authData.count)
    var reader = Reader(rest)
    let start = reader.index
    try reader.skip(depth: 0)
    guard reader.index > start else { throw ColophonError.malformed("attestation") }
    let coseKey = rest.subdata(in: start ..< reader.index)
    if flags & 0x80 != 0 { try reader.skip(depth: 0) }
    guard reader.finished else { throw ColophonError.malformed("attestation") }
    _ = try CBOR.p256x963(fromCOSE: coseKey)
    return (credentialID, coseKey)
  }

  private static func text(_ value: String) -> Data {
    let raw = Data(value.utf8)
    var data = header(major: 3, count: raw.count)
    data.append(raw)
    return data
  }

  private static func byteString(_ raw: Data) -> Data {
    var data = header(major: 2, count: raw.count)
    data.append(raw)
    return data
  }

  private static func header(major: UInt8, count: Int) -> Data {
    let prefix = major << 5
    if count < 24 { return Data([prefix | UInt8(count)]) }
    if count < 256 { return Data([prefix | 24, UInt8(count)]) }
    return Data([prefix | 25, UInt8((count >> 8) & 0xff), UInt8(count & 0xff)])
  }

  private enum Node {
    case text(String)
    case bytes(Data)
    case other
  }

  /// Definite-length CBOR. Indefinite lengths and anything past the size cap are rejected.
  private struct Reader {
    let data: Data
    var index = 0
    var finished: Bool { index == data.count }
    private let cap = 1_048_576

    init(_ data: Data) { self.data = Data(data) }

    mutating func readMap() throws -> [String: Node] {
      let header = try byte()
      guard header >> 5 == 5 else { throw ColophonError.malformed("attestation") }
      let count = try argumentCount(header & 0x1f)
      var fields: [String: Node] = [:]
      for _ in 0 ..< count {
        guard case .text(let key) = try readNode(depth: 0) else { throw ColophonError.malformed("attestation") }
        guard fields[key] == nil else { throw ColophonError.malformed("attestation") }
        fields[key] = try readNode(depth: 0)
      }
      return fields
    }

    mutating func skip(depth: Int) throws { _ = try readNode(depth: depth) }

    private mutating func readNode(depth: Int) throws -> Node {
      guard depth < 32 else { throw ColophonError.malformed("attestation") }
      let header = try byte()
      let major = header >> 5
      let info = header & 0x1f
      if info == 31 { throw ColophonError.malformed("attestation") }
      let argument = try argument(info)
      switch major {
      case 0, 1:
        return .other
      case 2, 3:
        guard argument <= UInt64(cap) else { throw ColophonError.malformed("attestation") }
        let length = Int(argument)
        guard index + length <= data.count else { throw ColophonError.malformed("attestation") }
        let slice = data.subdata(in: index ..< (index + length))
        index += length
        if major == 3 {
          guard let text = String(data: slice, encoding: .utf8) else { throw ColophonError.malformed("attestation") }
          return .text(text)
        }
        return .bytes(slice)
      case 4:
        let count = try count(argument)
        for _ in 0 ..< count { _ = try readNode(depth: depth + 1) }
        return .other
      case 5:
        let count = try count(argument)
        for _ in 0 ..< count {
          _ = try readNode(depth: depth + 1)
          _ = try readNode(depth: depth + 1)
        }
        return .other
      case 6:
        _ = try readNode(depth: depth + 1)
        return .other
      case 7:
        // `argument` already consumed the simple value or float.
        return .other
      default:
        throw ColophonError.malformed("attestation")
      }
    }

    private mutating func byte() throws -> UInt8 {
      guard index < data.count else { throw ColophonError.malformed("attestation") }
      let value = data[index]
      index += 1
      return value
    }

    private func count(_ argument: UInt64) throws -> Int {
      guard argument <= 100_000 else { throw ColophonError.malformed("attestation") }
      return Int(argument)
    }

    private mutating func argumentCount(_ info: UInt8) throws -> Int {
      if info == 31 { throw ColophonError.malformed("attestation") }
      return try count(argument(info))
    }

    private mutating func argument(_ info: UInt8) throws -> UInt64 {
      if info < 24 { return UInt64(info) }
      let width: Int
      switch info {
      case 24: width = 1
      case 25: width = 2
      case 26: width = 4
      case 27: width = 8
      default: throw ColophonError.malformed("attestation")
      }
      var value: UInt64 = 0
      for _ in 0 ..< width { value = (value << 8) | UInt64(try byte()) }
      return value
    }
  }
}
