import ColophonAuthority
import ColophonCore
import Foundation

/// An operation a replica could read, with its admission result.
public struct AdmittedOperation: Sendable, Identifiable {
  public enum Status: Sendable, Equatable {
    case admitted
    /// Readable but not applied; a person or the holder decides.
    case held(String)
  }

  public let operation: ColophonOperation
  public let author: String
  public let authorLabel: String
  /// Authoritative member role from the signed authority log, never operation payload.
  public let authorRole: MemberRole
  public let status: Status
  public var id: String { operation.id }
}

/// An operation that failed verification or admission.
public struct RejectedOperation: Sendable {
  public let path: String
  public let reason: String
}
