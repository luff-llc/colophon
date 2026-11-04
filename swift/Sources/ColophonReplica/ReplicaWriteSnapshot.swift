import Foundation

/// An immutable complete view captured for a conditional local write. Its opaque token
/// belongs to the issuing Replica and namespace; it cannot be constructed by clients.
public struct ReplicaWriteSnapshot: Sendable {
  public let view: ReplicaView
  let owner: UUID
  let namespace: String
  let token: Int
}
