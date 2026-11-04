import ColophonCore
import Foundation

/// Unsigned, immutable approval plan anchored to one verified authority head and signed request.
/// Passkey callers sign exactly signingBodies, then commit those records through the approval service.
public struct PreparedAdditionalAccessApproval: Sendable {
  public let request: AdditionalAccessRequest.Record
  public let selectedNamespaces: [String]
  public let desiredNamespaces: [String]
  public let baseSequence: Int
  public let baseDigest: String
  public let signingBodies: [Data]
  let drafts: [AuthorityEntry]
}
