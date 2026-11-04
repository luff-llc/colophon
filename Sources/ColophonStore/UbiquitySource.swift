import Foundation

/// Metadata and download requests are injectable so cloud journeys do not require an iCloud
/// account, network access, or elapsed wall time in tests.
public protocol UbiquitySource: Sendable {
  func availability(of file: URL) throws -> UbiquitousItemAvailability
  func requestDownload(of file: URL) throws
  /// A cache-only query. Nil means the provider has no trustworthy transfer measurement yet.
  func transferProgress(of file: URL) -> UbiquityTransferProgress?
}

extension UbiquitySource {
  public func transferProgress(of file: URL) -> UbiquityTransferProgress? { nil }
}
