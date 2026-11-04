import ColophonCore
import Foundation

/// One entry in a library's authority history (spec §6). Entries are numbered from 1, each names
/// the digest of the previous entry's body, and each is signed by the role in `by`.
public struct AuthorityEntry: Codable, Sendable {
  public enum Kind: String, Codable, Sendable {
    /// Entry 1. Names the root, the recovery identity and the library's label.
    case genesis
    /// Admits a member, or replaces its grant.
    case grant
    /// Ends a member's access from this entry on.
    case revoke
    /// Gives one principal the key for one namespace epoch.
    case shareKey
    /// Moves the root to a new identity. The only entry the recovery identity or a steward quorum
    /// may sign.
    case handover
    /// Replaces the stewards who can hand the root over together (organizational libraries).
    case stewards
    /// Replaces the recovery identity, so an old recovery kit no longer recovers the library.
    /// Signed by the root.
    case rotateRecovery
    /// Replaces the controller keyring. The first one, signed by the root, adopts it (spec §6.6).
    case keyring
  }

  public enum Signer: String, Codable, Sendable { case root, recovery, quorum, controller }

  public let seq: Int
  /// Lowercase hex SHA-256 of the previous entry's body bytes; absent for genesis.
  public let previous: String?
  public let issued: Date
  public let kind: Kind
  public let by: Signer

  // genesis
  public var label: String?
  public var root: PublicIdentity?
  // genesis, rotateRecovery
  public var recovery: PublicIdentity?
  /// Who the library belongs to, for example a legal entity for an organizational library.
  public var controller: [String: String]?
  // genesis, stewards
  public var stewards: [PublicIdentity]?
  public var threshold: Int?
  // grant
  public var member: PublicIdentity?
  public var role: MemberRole?
  public var custody: KeyCustody?
  public var namespaces: [String]?
  public var write: Bool?
  public var expires: Date?
  public var caveats: [Caveat]?
  /// For custodial members: who holds the key.
  public var keyOperator: String?
  /// Informational bundle identifier of the app that asked. Old clients ignore it.
  public var app: String?
  /// Informational device model ("iPhone", "Mac"). Old clients ignore it.
  public var device: String?
  // revoke, shareKey
  public var memberID: String?
  // revoke: the revoked member's operations the holder had seen; they stay admitted.
  public var kept: [String]?
  // shareKey
  public var namespace: String?
  public var epoch: Int?
  public var key: SealedKey?
  // keyring. `threshold` is the control threshold. `signer` is the primary controller when `by` is controller.
  public var controllers: [Controller]?
  public var slots: [VaultSlot]?
  public var vault: PublicIdentity?
  public var signer: String?
  /// How many distinct `recover` controllers a recovery change needs. Absent means 1.
  public var recoverThreshold: Int?

  init(seq: Int, previous: String?, kind: Kind, by: Signer = .root) {
    self.seq = seq
    self.previous = previous
    issued = .now
    self.kind = kind
    self.by = by
  }

  /// A draft carrying only content; `AuthorityHolder` numbers, chains and signs it.
  static func draft(_ kind: Kind, by: Signer = .root) -> AuthorityEntry { AuthorityEntry(seq: 0, previous: nil, kind: kind, by: by) }

  func numbered(_ seq: Int, after previous: Data) -> AuthorityEntry {
    var entry = AuthorityEntry(seq: seq, previous: Canonical.digest(previous), kind: kind, by: by)
    entry.label = label
    entry.root = root
    entry.recovery = recovery
    entry.controller = controller
    entry.stewards = stewards
    entry.threshold = threshold
    entry.caveats = caveats
    entry.keyOperator = keyOperator
    entry.app = app
    entry.device = device
    entry.member = member
    entry.role = role
    entry.custody = custody
    entry.namespaces = namespaces
    entry.write = write
    entry.expires = expires
    entry.memberID = memberID
    entry.kept = kept
    entry.namespace = namespace
    entry.epoch = epoch
    entry.key = key
    entry.controllers = controllers
    entry.slots = slots
    entry.vault = vault
    entry.signer = signer
    entry.recoverThreshold = recoverThreshold
    return entry
  }

  /// Decodes an entry's body. When it names a kind, signer, role or custody this version doesn't
  /// know, a newer app wrote it: that is `newerAuthority`, not a damaged library.
  static func decode(_ body: Data, at seq: Int) throws -> AuthorityEntry {
    let entry: AuthorityEntry
    do {
      entry = try Canonical.decode(AuthorityEntry.self, from: body)
    } catch let error as DecodingError {
      if let probe = try? Canonical.decode(Probe.self, from: body), probe.isNewer {
        throw ColophonError.newerAuthority(probe.seq ?? seq)
      }
      throw error
    }
    try KeyringRules.rejectUnknown(controllers: entry.controllers, slots: entry.slots, seq: entry.seq)
    return entry
  }

  /// The closed vocabulary of an entry, read as plain strings.
  private struct Probe: Decodable {
    let seq: Int?
    let kind: String?
    let by: String?
    let role: String?
    let custody: String?

    var isNewer: Bool {
      func unknown<T: RawRepresentable<String>>(_ value: String?, _: T.Type) -> Bool {
        value.map { T(rawValue: $0) == nil } ?? false
      }
      return unknown(kind, Kind.self) || unknown(by, Signer.self) || unknown(role, MemberRole.self)
        || unknown(custody, KeyCustody.self)
    }
  }
}

/// What kind of principal a member is, for people reading a member list.
public enum MemberRole: String, Codable, Sendable, CaseIterable {
  case device, app, web, agent, service
}
