import Foundation

/// Untrusted ordered chunk references. Construction/decoding alone establishes no validity,
/// availability, namespace authorization, AEAD authenticity or file-content verification.
public struct FileEvidenceChunkPage: Codable, Hashable, Sendable {
  public static let format = "org.colophon.file-evidence.chunk-page"
  public let format: String
  public let version: Int
  public let startIndex: Int
  public let chunks: [BlobRef]

  public init(format: String = FileEvidenceChunkPage.format, version: Int = FileEvidenceLimits.version,
    startIndex: Int, chunks: [BlobRef]) {
    self.format = format; self.version = version; self.startIndex = startIndex; self.chunks = chunks
  }
  private enum CodingKeys: String, CodingKey { case format, version, startIndex, chunks }
  public init(from decoder: any Decoder) throws {
    try FileEvidenceLimits.keys(decoder, equal: ["format", "version", "startIndex", "chunks"])
    let values = try decoder.container(keyedBy: CodingKeys.self)
    format = try values.decode(String.self, forKey: .format); version = try values.decode(Int.self, forKey: .version)
    startIndex = try values.decode(Int.self, forKey: .startIndex)
    chunks = try values.decode([FileEvidenceLimits.Reference].self, forKey: .chunks).map(\.value)
  }
  /// Enforces the input byte cap only. Call validateStructure separately; direct Codable decode
  /// is likewise untrusted and does not provide this pre-decode byte bound.
  public static func decodeUntrusted(_ data: Data) throws -> Self {
    guard data.count <= FileEvidenceLimits.pageBytes else { throw FileEvidenceManifestError.exceedsLimits }
    return try Canonical.decode(Self.self, from: data)
  }
  public func validateStructure() throws -> Structure {
    guard format == Self.format, version == FileEvidenceLimits.version else { throw FileEvidenceManifestError.unsupportedFormat }
    guard !chunks.isEmpty, chunks.count <= FileEvidenceLimits.chunksPerPage else { throw FileEvidenceManifestError.exceedsLimits }
    guard startIndex >= 0, startIndex <= FileEvidenceLimits.chunks - chunks.count else { throw FileEvidenceManifestError.invalidStructure }
    var ciphertext: [String: BlobRef] = [:], plaintext: [String: Int] = [:]
    for ref in chunks {
      try FileEvidenceLimits.validate(ref, maximumBytes: FileEvidenceLimits.chunkBytes)
      try FileEvidenceLimits.consistent(ref, ciphertext: &ciphertext, plaintext: &plaintext)
    }
    let encoded = try Canonical.encode(self)
    guard encoded.count <= FileEvidenceLimits.pageBytes else { throw FileEvidenceManifestError.exceedsLimits }
    return Structure(value: self, canonicalBytes: encoded)
  }
  /// A bounded schema value only. It does not establish any chunk's plaintext or authentication.
  public struct Structure: Sendable {
    public let value: FileEvidenceChunkPage
    public let canonicalBytes: Data
    fileprivate init(value: FileEvidenceChunkPage, canonicalBytes: Data) {
      self.value = value; self.canonicalBytes = canonicalBytes
    }
  }
}
