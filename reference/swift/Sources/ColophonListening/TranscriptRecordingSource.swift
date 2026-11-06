import Foundation

/// A historical feed description of a recording. Matching metadata is approximate:
/// dynamically inserted audio can differ even at the same address and byte length.
public struct TranscriptRecordingSource: Codable, Hashable, Sendable {
  public let feed: String
  public let guid: String
  public let enclosure: String
  public let byteLength: Int64

  public init(feed: String, guid: String, enclosure: String, byteLength: Int64) {
    self.feed = feed
    self.guid = guid
    self.enclosure = enclosure
    self.byteLength = byteLength
  }

  public func validate() throws {
    guard TranscriptSourceReceipt.webURL(feed) == feed,
      TranscriptSourceReceipt.webURL(enclosure) == enclosure,
      !guid.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
      guid.utf8.count <= 4096, !guid.contains("\r"), !guid.contains("\n"), byteLength > 0
    else { throw TranscriptPreparationError.invalidSource }
  }

  /// This permits an approximate reading clock, never verified recording operations.
  public func matches(_ other: Self) -> Bool {
    guard (try? validate()) != nil, (try? other.validate()) != nil else { return false }
    return self == other
  }
}
