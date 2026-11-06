import Foundation

/// A semantic change to one namespace (spec §8). Payload fields a client doesn't understand
/// travel through untouched.
public struct ColophonOperation: Codable, Sendable, Hashable, Identifiable {
  public let id: String
  public let kind: String
  /// Version of the namespace's module the author wrote against.
  public let v: Int
  /// The author's Lamport clock in this namespace.
  public let clock: Int
  /// The newest authority entry the author had seen. Admission uses the grants in force there.
  public let authority: Int
  /// Author-reported; never used to order or authorize.
  public let created: Date
  public let payload: [String: JSONValue]

  public init(id: String, kind: String, v: Int, clock: Int, authority: Int, created: Date, payload: [String: JSONValue]) {
    self.id = id
    self.kind = kind
    self.v = v
    self.clock = clock
    self.authority = authority
    self.created = created
    self.payload = payload
  }
}

/// The signed, visible part of a stored operation. The operation itself is sealed with the
/// namespace key for `epoch`: AES-256-GCM, `nonce || ciphertext || tag`.
public struct OperationHeader: Codable, Sendable {
  public let author: String
  public let namespace: String
  public let epoch: Int
  public let sealed: Data

  public init(author: String, namespace: String, epoch: Int, sealed: Data) {
    self.author = author
    self.namespace = namespace
    self.epoch = epoch
    self.sealed = sealed
  }
}
