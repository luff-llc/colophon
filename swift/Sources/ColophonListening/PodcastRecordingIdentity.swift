import CryptoKit
import Foundation

/// Identity of the retained audio bytes, never the address that served them.
public enum PodcastRecordingIdentity {
  public static func isDigest(_ value: String) -> Bool {
    value.utf8.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
  }

  /// Bounded-memory hashing off the caller's actor. Streams remain unverified.
  @concurrent public static func digest(of file: URL) async throws -> String {
    guard file.isFileURL else { throw CocoaError(.fileReadUnsupportedScheme) }
    let handle = try FileHandle(forReadingFrom: file)
    defer { try? handle.close() }
    var hash = SHA256()
    while let bytes = try handle.read(upToCount: 1_048_576), !bytes.isEmpty {
      try Task.checkCancellation()
      hash.update(data: bytes)
    }
    try Task.checkCancellation()
    return hash.finalize().map { String(format: "%02x", $0) }.joined()
  }
}

public extension Listening {
  /// URL-keyed records remain available for review, but cannot authorize timed jumps.
  func segmentSet(for episode: String, recordingDigest: String?) -> SegmentSet? {
    guard let recordingDigest, PodcastRecordingIdentity.isDigest(recordingDigest) else { return nil }
    return segments[episode]?[recordingDigest]
  }
}
