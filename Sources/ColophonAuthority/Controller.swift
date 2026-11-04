import ColophonCore
import CryptoKit
import Foundation

/// One key that can act for the person (spec §6.6): an app owner key or a WebAuthn credential.
public struct Controller: Codable, Sendable, Hashable {
  public static let kinds = ["p256", "webauthn"]
  public static let roles = ["approve", "control", "recover"]

  public let kind: String
  /// P-256 signing public key, X9.63 uncompressed. For WebAuthn, converted from the COSE key.
  public let key: Data
  /// Relying party ID. Required for `webauthn`.
  public let rpID: String?
  /// WebAuthn credential ID, so a client can ask the authenticator. Not used in verification.
  public let credential: Data?
  public let label: String
  public let roles: [String]
  /// When true, every WebAuthn signature from this controller must carry the UV flag.
  public let verification: Bool?

  public init(kind: String, key: Data, rpID: String?, credential: Data?, label: String, roles: [String],
    verification: Bool?)
  {
    self.kind = kind
    self.key = key
    self.rpID = rpID
    self.credential = credential
    self.label = label
    self.roles = roles
    self.verification = verification
  }

  /// First 32 lowercase hex characters of SHA-256(`key`), the same scheme as `PublicIdentity.id`.
  public var id: String { String(Canonical.digest(key).prefix(32)) }

  /// Parses an ES256 P-256 COSE_Key into an uncompressed public key.
  public static func webauthn(coseKey: Data, rpID: String, credential: Data, label: String, roles: [String],
    verification: Bool?) throws -> Controller
  {
    guard !rpID.isEmpty else { throw ColophonError.malformed("webauthn controller") }
    let key = try CBOR.p256x963(fromCOSE: coseKey)
    return Controller(kind: "webauthn", key: key, rpID: rpID, credential: credential, label: label, roles: roles,
      verification: verification)
  }

  /// Checks one signature over `body`. `requireVerification` forces the UV flag for WebAuthn.
  public func verify(signature: Data, assertion: Assertion?, over body: Data, requireVerification: Bool) -> Bool {
    switch kind {
    case "p256": return verifyP256(signature, assertion: assertion, over: body)
    case "webauthn": return verifyWebAuthn(signature, assertion: assertion, over: body, requireVerification: requireVerification)
    default: return false
    }
  }

  private func verifyP256(_ signature: Data, assertion: Assertion?, over body: Data) -> Bool {
    guard assertion == nil, let key = try? P256.Signing.PublicKey(x963Representation: key),
      let parsed = try? P256.Signing.ECDSASignature(rawRepresentation: signature)
    else { return false }
    return key.isValidSignature(parsed, for: body)
  }

  private func verifyWebAuthn(_ signature: Data, assertion: Assertion?, over body: Data, requireVerification: Bool) -> Bool {
    guard let assertion, let rpID, !rpID.isEmpty else { return false }
    guard let client = try? JSONDecoder().decode(ClientData.self, from: assertion.clientData) else { return false }
    guard client.type == "webauthn.get", client.crossOrigin != true else { return false }
    guard client.challenge == Self.base64url(Data(SHA256.hash(data: body))) else { return false }
    guard Self.origin(client.origin, matches: rpID) else { return false }
    guard assertion.authenticatorData.count >= 37 else { return false }
    let rpHash = Data(SHA256.hash(data: Data(rpID.utf8)))
    guard assertion.authenticatorData.prefix(32) == rpHash else { return false }
    let flags = assertion.authenticatorData[assertion.authenticatorData.startIndex + 32]
    guard flags & 0x01 != 0 else { return false }
    if (requireVerification || verification == true) && flags & 0x04 == 0 { return false }
    guard let key = try? P256.Signing.PublicKey(x963Representation: key),
      let parsed = try? P256.Signing.ECDSASignature(derRepresentation: signature)
    else { return false }
    // CryptoKit hashes this message with SHA-256. WebAuthn already placed SHA-256(clientData) in it.
    let message = assertion.authenticatorData + Data(SHA256.hash(data: assertion.clientData))
    return key.isValidSignature(parsed, for: message)
  }

  /// `https://<rpID>` or `https://<labels>.<rpID>`, with no port, path or user info.
  static func origin(_ origin: String, matches rpID: String) -> Bool {
    let prefix = "https://"
    guard origin.hasPrefix(prefix) else { return false }
    let host = origin.dropFirst(prefix.count)
    guard !host.isEmpty, host.allSatisfy({ $0 != "/" && $0 != ":" && $0 != "?" && $0 != "#" && $0 != "@" && $0 != "\\" })
    else { return false }
    if host == rpID { return true }
    let suffix = "." + rpID
    guard host.hasSuffix(suffix), host.count > suffix.count else { return false }
    let labels = host.dropLast(suffix.count)
    return !labels.hasPrefix(".") && !labels.hasSuffix(".") && !labels.contains("..")
  }

  static func base64url(_ data: Data) -> String {
    data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }

  private struct ClientData: Decodable {
    let type: String
    let challenge: String
    let origin: String
    let crossOrigin: Bool?
  }
}
