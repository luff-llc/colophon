import Foundation

/// Transfer measurements from the provider's metadata, never allocated blocks on disk.
public struct UbiquityTransferProgress: Sendable, Equatable {
  public let downloadedBytes: Int64
  public let totalBytes: Int64

  public init(downloadedBytes: Int64, totalBytes: Int64) {
    self.totalBytes = max(0, totalBytes)
    self.downloadedBytes = min(max(0, downloadedBytes), self.totalBytes)
  }
}
