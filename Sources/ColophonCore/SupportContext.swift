import CryptoKit
import Foundation

/// Current diagnostic state. The fingerprint permits comparison between apps without exposing the library ID.
public struct SupportContext: Codable, Sendable, Equatable {
  public enum Membership: String, Codable, Sendable { case noLibrary, pending, member, revoked, failed }
  public enum Gauge: String, Codable, Sendable, CaseIterable {
    case sourceOperations, sourceItems, sourceFacts, sharedFacts, sharedShows, sharedEpisodes, pendingFacts, quarantined
  }
  public let observedAt: Date
  public let libraryFingerprint: String?
  public let membership: Membership
  public let gauges: [Gauge: Int]

  public init(libraryID: String?, membership: Membership, gauges: [Gauge: Int] = [:]) {
    observedAt = Date()
    libraryFingerprint = libraryID.map { Canonical.digest(Data($0.utf8)) }
    self.membership = membership
    self.gauges = gauges.mapValues { min(1_000_000_000, max(0, $0)) }
  }

  private enum CodingKeys: String, CodingKey { case observedAt, libraryFingerprint, membership, gauges }

  public init(from decoder: any Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    observedAt = try container.decode(Date.self, forKey: .observedAt)
    membership = try container.decode(Membership.self, forKey: .membership)
    let candidate = try container.decodeIfPresent(String.self, forKey: .libraryFingerprint)
    if let candidate, candidate.utf8.count == 64,
      candidate.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) {
      libraryFingerprint = candidate
    } else { libraryFingerprint = nil }
    let decoded = try container.decode([Gauge: Int].self, forKey: .gauges)
    gauges = decoded.mapValues { min(1_000_000_000, max(0, $0)) }
  }

  init(fingerprint: String?, membership: Membership, gauges: [Gauge: Int]) {
    observedAt = Date(); libraryFingerprint = fingerprint; self.membership = membership
    self.gauges = gauges
  }
}
