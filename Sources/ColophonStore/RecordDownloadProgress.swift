import Foundation

/// Availability of the records discovered so far. A count is not a claim that the remote
/// directory has finished arriving, or that the records have passed signature verification.
public struct RecordDownloadProgress: Sendable, Equatable {
  public let downloadedRecords: Int
  public let totalRecords: Int
  /// Transfer bytes are absent unless the provider supplies trustworthy measurements.
  public let downloadedBytes: Int64?
  public let totalBytes: Int64?
  public let estimatedTimeRemaining: Duration?

  public init(downloadedRecords: Int, totalRecords: Int, downloadedBytes: Int64? = nil, totalBytes: Int64? = nil,
    estimatedTimeRemaining: Duration? = nil) {
    self.totalRecords = max(0, totalRecords)
    self.downloadedRecords = min(max(0, downloadedRecords), self.totalRecords)
    self.downloadedBytes = downloadedBytes.map { max(0, $0) }
    self.totalBytes = totalBytes.map { max(0, $0) }
    self.estimatedTimeRemaining = estimatedTimeRemaining
  }

  public var pendingRecords: Int { totalRecords - downloadedRecords }
  public var fractionCompleted: Double? {
    guard totalRecords > 0 else { return nil }
    return Double(downloadedRecords) / Double(totalRecords)
  }
}
