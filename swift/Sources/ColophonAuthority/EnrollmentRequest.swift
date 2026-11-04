import ColophonCore
import CryptoKit
import Foundation

/// A principal asking to join (spec §7). The requester signs it, proving it holds the key it names.
public struct EnrollmentRequest: Codable, Sendable, Identifiable {
  public let member: PublicIdentity
  public let label: String
  public let role: MemberRole
  public let custody: KeyCustody
  public let namespaces: [String]
  /// For a custodial member, the service holding its key.
  public let keyOperator: String?
  /// Whether the requester wants to write. Nil is an older client that did not say.
  public let write: Bool?
  /// Bundle identifier of the app that asked. Informational; it never changes what is granted.
  public let app: String?
  /// Device model the request was made on. Informational.
  public let device: String?
  public let created: Date

  public init(member: PublicIdentity, label: String, role: MemberRole, custody: KeyCustody, namespaces: [String],
    keyOperator: String? = nil, write: Bool? = nil, app: String? = nil, device: String? = nil)
  {
    self.keyOperator = keyOperator
    self.member = member
    self.label = label
    self.role = role
    self.custody = custody
    self.namespaces = namespaces
    self.write = write
    self.app = app
    self.device = device
    created = .now
  }

  public var id: String { member.id }

  /// Six digits both sides show (spec §7.2): the first four bytes of
  /// SHA-256(libraryID UTF-8 || requester signing key), big-endian, modulo 1,000,000.
  /// Comparing them binds the request on screen to this library and this key.
  public static func pairingCode(libraryID: String, member: PublicIdentity) -> String {
    let digest = Array(SHA256.hash(data: Data(libraryID.utf8) + member.signing))
    let number = digest.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) } % 1_000_000
    return Canonical.padded(Int(number), width: 6)
  }
}
