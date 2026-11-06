import ColophonCore
import Foundation

/// Where a library's records live (spec §5). Anything that can list, read and create files can
/// carry a library: a local folder, iCloud Drive, Dropbox, a relay, an S3 bucket. The store sees
/// only signed records and ciphertext.
///
/// Records are immutable once created, except enrollment requests, which a member may replace.
/// `create` must fail if the path exists; that is what keeps two writers from both claiming the
/// same authority sequence number.
public protocol RecordStore: Sendable {
  /// Names directly inside `directory`, sorted. Empty if the directory doesn't exist.
  func list(_ directory: String) throws -> [String]
  /// Contents of `path`, or nil when the file is absent. A store may throw `ColophonError.pending`
  /// when the bytes exist but are not local yet.
  func read(_ path: String) throws -> Data?
  /// Writes a new record; throws `ColophonError.alreadyExists` if the path exists.
  func create(_ path: String, _ data: Data) throws
  /// Writes or replaces a mutable record.
  func replace(_ path: String, _ data: Data) throws
  /// Metadata-only availability of known logical paths. Requests every pending record without
  /// coordinating or reading its bytes. Nil means this provider has no progress measurements.
  func downloadProgress(for paths: [String]) throws -> RecordDownloadProgress?
  /// Uses bytes already obtained and verified by the replica without reopening their metadata.
  func downloadProgress(for paths: [String], knownDownloaded: Set<String>) throws -> RecordDownloadProgress?
}

extension RecordStore {
  public func downloadProgress(for paths: [String]) throws -> RecordDownloadProgress? { nil }
  public func downloadProgress(for paths: [String], knownDownloaded: Set<String>) throws -> RecordDownloadProgress? {
    try downloadProgress(for: paths)
  }
}

/// The record layout every store shares.
public enum LibraryPath {
  public static let authority = "authority"
  public static let requests = "requests"
  public static let operations = "ops"
  public static let blobs = "blobs"

  public static func authority(_ seq: Int) -> String { "authority/" + Canonical.padded(seq, width: 8) + ".json" }
  public static func request(_ member: String) -> String { "requests/" + member + ".json" }
  public static func blob(_ digest: String) -> String { "blobs/" + digest }

  public static func operation(author: String, clock: Int, id: String) -> String {
    "ops/" + author + "/" + Canonical.padded(clock, width: 12) + "-" + id + ".json"
  }
}
