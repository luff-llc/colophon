import ColophonAuthority
import ColophonCore
import Foundation

/// Exact bytes checked against one opaque Replica snapshot. A portable copy of these values
/// is evidence/attribution, not a transferable authority grant or proof linking plaintext to
/// the original ciphertext without the source namespace key. No key is exposed here.
public struct ReplicaReadingOperationEvidence: Sendable {
  public let libraryID: String
  public let operation: ColophonOperation
  public let authorID: String
  public let authorLabel: String
  public let authorRole: MemberRole
  public let sourceSigningPublicKey: Data
  public let plaintext: Data
  public let signedRecord: Data
}
