import ColophonCore
import Foundation

/// An existing member's explicit request for additional scopes. This is not an enrollment record.
/// Mutable provider state is not monotonic cancellation or authority; owner approval is still required.
public struct AdditionalAccessRequest: Codable, Sendable, Equatable {
  public static let format = "org.colophon.additional-access-request"
  public static let kind = "access.additional"
  public static let maximumBodyBytes = 65_536
  public static let maximumRecordBytes = 131_072
  public enum Status: String, Codable, Sendable { case pending, withdrawn }
  public let format: String
  public let kind: String
  public let version: Int
  public let libraryID: String
  public let member: PublicIdentity
  public let expectedGrantSequence: Int
  public let requestID: UUID
  public let additionalNamespaces: [String]
  public let status: Status

  init(libraryID: String, member: PublicIdentity, expectedGrantSequence: Int, requestID: UUID,
    additionalNamespaces: [String], status: Status) {
    format = Self.format; kind = Self.kind; version = 1; self.libraryID = libraryID; self.member = member
    self.expectedGrantSequence = expectedGrantSequence; self.requestID = requestID
    self.additionalNamespaces = additionalNamespaces; self.status = status
  }
  public static func path(memberID: String) -> String { "requests/additional-" + memberID + ".json" }
  func validateShape() throws {
    guard format == Self.format, kind == Self.kind, version == 1, !libraryID.isEmpty, libraryID.utf8.count <= 1024,
      expectedGrantSequence > 0, member.signing.count <= 256, member.agreement.count <= 256,
      !additionalNamespaces.isEmpty, additionalNamespaces.count <= 64,
      additionalNamespaces == Array(Set(additionalNamespaces)).sorted(),
      additionalNamespaces.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 256 && !$0.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) }) else {
      throw AdditionalAccessError.invalidRequest
    }
    guard try Canonical.encode(self).count <= Self.maximumBodyBytes else { throw AdditionalAccessError.exceedsLimits }
  }
  func validate(in state: AuthorityState, now: Date, pending: Bool = true) throws -> AuthorityState.Member {
    try validateShape()
    guard libraryID == state.libraryID, let actual = state.members[member.id], actual.key == member,
      actual.revokedAt == nil, let grant = actual.current,
      grant.seq == expectedGrantSequence, grant.expires.map({ now < $0 }) ?? true else { throw AdditionalAccessError.staleGrant }
    guard additionalNamespaces.allSatisfy({ !grant.namespaces.contains($0) }) else { throw AdditionalAccessError.staleGrant }
    if pending, status != .pending { throw AdditionalAccessError.withdrawn }
    return actual
  }

  /// Bound to a verified signature and deterministic path; not a promise of provider finality.
  public struct Record: Sendable {
    public let request: AdditionalAccessRequest
    public let bodyDigest: String
    public let signed: SignedRecord
    public var path: String { AdditionalAccessRequest.path(memberID: request.member.id) }
    static func decode(_ data: Data, path: String) throws -> Self {
      // The store may already have allocated Data; these bounds apply before JSON decoding.
      guard data.count <= AdditionalAccessRequest.maximumRecordBytes else { throw AdditionalAccessError.exceedsLimits }
      let signed = try Canonical.decode(SignedRecord.self, from: data)
      guard signed.body.count <= AdditionalAccessRequest.maximumBodyBytes else { throw AdditionalAccessError.exceedsLimits }
      let request = try Canonical.decode(AdditionalAccessRequest.self, from: signed.body)
      try request.validateShape()
      guard path == AdditionalAccessRequest.path(memberID: request.member.id), request.member.verify(signed) else {
        throw AdditionalAccessError.invalidRequest
      }
      return .init(request: request, bodyDigest: Canonical.digest(signed.body), signed: signed)
    }
  }
}
