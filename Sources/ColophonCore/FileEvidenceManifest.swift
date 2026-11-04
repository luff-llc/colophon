import Foundation

/// Untrusted fixed-depth file metadata. A signed operation can reference its ordinary BlobRef;
/// this value does not encode namespace, authorization, historical authorship or verified content.
public struct FileEvidenceManifest: Codable, Hashable, Sendable {
  public static let format = "org.colophon.file-evidence"
  public let format: String
  public let version: Int
  public let chunkSize: Int
  public let fileDigest: String
  public let totalBytes: Int64
  public let chunkCount: Int
  public let pages: [PageReference]

  public struct PageReference: Codable, Hashable, Sendable {
    public let startIndex: Int
    public let count: Int
    public let ref: BlobRef
    public init(startIndex: Int, count: Int, ref: BlobRef) {
      self.startIndex = startIndex; self.count = count; self.ref = ref
    }
    private enum CodingKeys: String, CodingKey { case startIndex, count, ref }
    public init(from decoder: any Decoder) throws {
      try FileEvidenceLimits.keys(decoder, equal: ["startIndex", "count", "ref"])
      let values = try decoder.container(keyedBy: CodingKeys.self)
      startIndex = try values.decode(Int.self, forKey: .startIndex); count = try values.decode(Int.self, forKey: .count)
      ref = try values.decode(FileEvidenceLimits.Reference.self, forKey: .ref).value
    }
  }
  public init(format: String = FileEvidenceManifest.format, version: Int = FileEvidenceLimits.version,
    chunkSize: Int = FileEvidenceLimits.chunkBytes, fileDigest: String, totalBytes: Int64,
    chunkCount: Int, pages: [PageReference]) {
    self.format = format; self.version = version; self.chunkSize = chunkSize; self.fileDigest = fileDigest
    self.totalBytes = totalBytes; self.chunkCount = chunkCount; self.pages = pages
  }
  private enum CodingKeys: String, CodingKey { case format, version, chunkSize, fileDigest, totalBytes, chunkCount, pages }
  public init(from decoder: any Decoder) throws {
    try FileEvidenceLimits.keys(decoder, equal: ["format", "version", "chunkSize", "fileDigest", "totalBytes", "chunkCount", "pages"])
    let values = try decoder.container(keyedBy: CodingKeys.self)
    format = try values.decode(String.self, forKey: .format); version = try values.decode(Int.self, forKey: .version)
    chunkSize = try values.decode(Int.self, forKey: .chunkSize); fileDigest = try values.decode(String.self, forKey: .fileDigest)
    totalBytes = try values.decode(Int64.self, forKey: .totalBytes); chunkCount = try values.decode(Int.self, forKey: .chunkCount)
    pages = try values.decode([PageReference].self, forKey: .pages)
  }
  /// Applies the input byte cap before parsing, but deliberately returns an untrusted value.
  /// Direct Codable decoding has no pre-decode byte cap and must not be used for unbounded input.
  public static func decodeUntrusted(_ data: Data) throws -> Self {
    guard data.count <= FileEvidenceLimits.rootBytes else { throw FileEvidenceManifestError.exceedsLimits }
    return try Canonical.decode(Self.self, from: data)
  }
  public func validateStructure() throws -> Structure {
    guard format == Self.format, version == FileEvidenceLimits.version else { throw FileEvidenceManifestError.unsupportedFormat }
    guard chunkSize == FileEvidenceLimits.chunkBytes, totalBytes >= 0, chunkCount >= 0 else { throw FileEvidenceManifestError.invalidStructure }
    guard totalBytes <= FileEvidenceLimits.fileBytes, chunkCount <= FileEvidenceLimits.chunks,
      pages.count <= FileEvidenceLimits.pages else { throw FileEvidenceManifestError.exceedsLimits }
    guard FileEvidenceLimits.isDigest(fileDigest) else { throw FileEvidenceManifestError.invalidReference }
    if totalBytes == 0 {
      guard chunkCount == 0, pages.isEmpty, fileDigest == FileEvidenceLimits.emptyFileDigest else { throw FileEvidenceManifestError.invalidStructure }
    } else {
      // Subtract first so ceiling division never adds to an untrusted Int64 maximum.
      let expectedCount = (totalBytes - 1) / Int64(chunkSize) + 1
      guard Int64(chunkCount) == expectedCount, !pages.isEmpty else { throw FileEvidenceManifestError.invalidStructure }
    }
    var nextIndex = 0
    var ciphertext: [String: BlobRef] = [:], plaintext: [String: Int] = [:]
    for page in pages {
      guard page.startIndex == nextIndex, page.count > 0, page.count <= FileEvidenceLimits.chunksPerPage,
        page.count <= chunkCount - nextIndex else { throw FileEvidenceManifestError.invalidStructure }
      try FileEvidenceLimits.validate(page.ref, maximumBytes: FileEvidenceLimits.pageBytes)
      try FileEvidenceLimits.consistent(page.ref, ciphertext: &ciphertext, plaintext: &plaintext)
      nextIndex += page.count
    }
    guard nextIndex == chunkCount else { throw FileEvidenceManifestError.invalidStructure }
    let encoded = try Canonical.encode(self)
    guard encoded.count <= FileEvidenceLimits.rootBytes else { throw FileEvidenceManifestError.exceedsLimits }
    return Structure(value: self, canonicalBytes: encoded)
  }

  /// Root schema/ordering only. Page contents, chunks and the whole-file digest are unverified.
  public struct Structure: Sendable {
    public let value: FileEvidenceManifest
    public let canonicalBytes: Data
    fileprivate init(value: FileEvidenceManifest, canonicalBytes: Data) {
      self.value = value; self.canonicalBytes = canonicalBytes
    }
    /// The loader supplies bounded plaintext page bytes, not ciphertext. Checks those bytes'
    /// advertised digest/size and graph shape. This performs no storage access of its own, AES
    /// decryption, current authorization, chunk-content hashing or whole-file verification.
    /// The caller must bound loader allocations before reading; rejecting an oversized returned
    /// Data cannot prevent arbitrary allocation inside that callback. This validation retains
    /// up to 65,536 ordered chunk references and bounded consistency indexes, not chunk contents.
    public func validateGraph(loadPage: (BlobRef) throws -> Data) throws -> GraphStructure {
      var chunks: [BlobRef] = []
      chunks.reserveCapacity(value.chunkCount)
      var ciphertext: [String: BlobRef] = [:], plaintext: [String: Int] = [:]
      for descriptor in value.pages {
        try FileEvidenceLimits.consistent(descriptor.ref, ciphertext: &ciphertext, plaintext: &plaintext)
        let bytes = try loadPage(descriptor.ref)
        guard bytes.count == descriptor.ref.size, bytes.count <= FileEvidenceLimits.pageBytes,
          Canonical.digest(bytes) == descriptor.ref.plain else { throw FileEvidenceManifestError.pageMismatch }
        let page = try FileEvidenceChunkPage.decodeUntrusted(bytes).validateStructure().value
        guard page.startIndex == descriptor.startIndex, page.chunks.count == descriptor.count else { throw FileEvidenceManifestError.invalidStructure }
        for ref in page.chunks {
          let index = chunks.count
          guard index < value.chunkCount else { throw FileEvidenceManifestError.invalidStructure }
          let expectedSize = index == value.chunkCount - 1
            ? Int(value.totalBytes - Int64(index) * Int64(value.chunkSize)) : value.chunkSize
          guard ref.size == expectedSize else { throw FileEvidenceManifestError.invalidStructure }
          try FileEvidenceLimits.consistent(ref, ciphertext: &ciphertext, plaintext: &plaintext)
          chunks.append(ref)
        }
      }
      guard chunks.count == value.chunkCount else { throw FileEvidenceManifestError.invalidStructure }
      return GraphStructure(root: value, chunks: chunks)
    }
  }
  /// Bounded ordered references only. Chunk bytes and the complete file still need independent
  /// size/digest/AEAD verification and current access checks by the consuming service.
  public struct GraphStructure: Sendable {
    public let root: FileEvidenceManifest
    public let chunks: [BlobRef]
    fileprivate init(root: FileEvidenceManifest, chunks: [BlobRef]) { self.root = root; self.chunks = chunks }
  }
}
