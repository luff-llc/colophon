import Foundation

/// Explicit version1 policy, not generic Replica/store/transport limits.
public enum FileEvidenceLimits {
  public static let version = 1
  public static let chunkBytes = 1_048_576
  public static let chunksPerPage = 128
  public static let pageBytes = 65_536
  public static let pages = 512
  public static let rootBytes = 262_144
  public static let chunks = 65_536
  public static let fileBytes: Int64 = 68_719_476_736
  public static let emptyFileDigest = Canonical.digest(Data())

  static func isDigest(_ value: String) -> Bool {
    value.utf8.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
  }
  static func validate(_ ref: BlobRef, maximumBytes: Int) throws {
    guard isDigest(ref.digest), isDigest(ref.plain), ref.epoch > 0,
      ref.size > 0, ref.size <= maximumBytes else { throw FileEvidenceManifestError.invalidReference }
  }
  static func keys(_ decoder: any Decoder, equal expected: Set<String>) throws {
    let values = try decoder.container(keyedBy: Key.self)
    guard Set(values.allKeys.map(\.stringValue)) == expected else { throw FileEvidenceManifestError.invalidStructure }
  }
  struct Key: CodingKey {
    let stringValue: String
    let intValue: Int? = nil
    init?(stringValue: String) { self.stringValue = stringValue }
    init?(intValue: Int) { return nil }
  }
  /// Decode the existing wire BlobRef without silently dropping unsupported reference fields.
  struct Reference: Decodable {
    let value: BlobRef
    private enum CodingKeys: String, CodingKey { case digest, plain, epoch, size }
    init(from decoder: any Decoder) throws {
      try FileEvidenceLimits.keys(decoder, equal: ["digest", "plain", "epoch", "size"])
      let fields = try decoder.container(keyedBy: CodingKeys.self)
      value = BlobRef(digest: try fields.decode(String.self, forKey: .digest),
        plain: try fields.decode(String.self, forKey: .plain), epoch: try fields.decode(Int.self, forKey: .epoch),
        size: try fields.decode(Int.self, forKey: .size))
    }
  }
  static func consistent(_ ref: BlobRef, ciphertext: inout [String: BlobRef], plaintext: inout [String: Int]) throws {
    if let previous = ciphertext[ref.digest], previous != ref { throw FileEvidenceManifestError.invalidReference }
    if let size = plaintext[ref.plain], size != ref.size { throw FileEvidenceManifestError.invalidReference }
    ciphertext[ref.digest] = ref; plaintext[ref.plain] = ref.size
  }
}
