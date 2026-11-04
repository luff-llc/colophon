import Foundation

/// A reference to an encrypted blob (spec §8.4): large content such as a transcript, kept out of
/// the operation itself. The blob is sealed with a namespace epoch key and stored under the
/// SHA-256 of its sealed bytes; the operation that references it is what's signed.
public struct BlobRef: Codable, Hashable, Sendable {
  /// Lowercase hex SHA-256 of the stored (sealed) bytes; also the file name.
  public let digest: String
  /// Lowercase hex SHA-256 of the plaintext, checked after opening.
  public let plain: String
  public let epoch: Int
  public let size: Int

  public init(digest: String, plain: String, epoch: Int, size: Int) {
    self.digest = digest
    self.plain = plain
    self.epoch = epoch
    self.size = size
  }

  public var json: JSONValue {
    .object(["digest": .string(digest), "plain": .string(plain), "epoch": .number(Double(epoch)),
      "size": .number(Double(size))])
  }

  public init?(json: JSONValue?) {
    guard let object = json?.object, let digest = object["digest"]?.string, let plain = object["plain"]?.string,
      let epoch = object["epoch"]?.int, let size = object["size"]?.int
    else { return nil }
    self.init(digest: digest, plain: plain, epoch: epoch, size: size)
  }
}
