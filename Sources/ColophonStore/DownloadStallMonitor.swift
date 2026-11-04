import Foundation

/// Bounds time without progress, rather than total download time. Callers inject monotonic
/// instants in tests. Repeated discoveries and regressing/flapping counts cannot extend a wait.
public struct DownloadStallMonitor: Sendable {
  public let stallInterval: Duration
  private var lastAdvance: ContinuousClock.Instant
  private var downloadedRecords = 0
  private var downloadedBytes: Int64 = 0
  private var hasBaseline = false
  private var baseline: RecordDownloadProgress?
  private var latest: RecordDownloadProgress?
  private var estimateStart: ContinuousClock.Instant?
  private var positiveSamples = 0

  public init(stallInterval: Duration = .seconds(30), now: ContinuousClock.Instant = .now) {
    self.stallInterval = stallInterval
    self.lastAdvance = now
  }

  @discardableResult
  public mutating func observe(_ progress: RecordDownloadProgress, at now: ContinuousClock.Instant = .now) -> Bool {
    let advanced = hasBaseline && (progress.downloadedRecords > downloadedRecords || (progress.downloadedBytes ?? 0) > downloadedBytes)
    hasBaseline = true
    downloadedRecords = max(downloadedRecords, progress.downloadedRecords)
    downloadedBytes = max(downloadedBytes, progress.downloadedBytes ?? 0)
    if advanced { lastAdvance = now }
    if baseline == nil || latest?.totalRecords != progress.totalRecords || latest?.totalBytes != progress.totalBytes {
      baseline = progress
      estimateStart = now
      positiveSamples = 0
    } else if advanced { positiveSamples += 1 }
    latest = progress
    return advanced
  }

  public func isStalled(at now: ContinuousClock.Instant = .now) -> Bool {
    lastAdvance.duration(to: now) >= stallInterval
  }

  /// A rough recent pace estimate. Discovery changes restart the sample, and stalled or
  /// undersampled transfers have no estimate. Callers must label a count-based estimate as rough.
  public func estimatedTimeRemaining(at now: ContinuousClock.Instant = .now) -> Duration? {
    guard let baseline, let latest, let estimateStart, positiveSamples >= 2,
      lastAdvance.duration(to: now) < .seconds(5) else { return nil }
    let duration = estimateStart.duration(to: now)
    let components = duration.components
    let elapsed = Double(components.seconds) + Double(components.attoseconds) / 1e18
    if let before = baseline.downloadedBytes, let after = latest.downloadedBytes,
      let total = latest.totalBytes, after > before, total > after, elapsed >= 5 {
      return .seconds(Double(total - after) * elapsed / Double(after - before))
    }
    let completed = latest.downloadedRecords - baseline.downloadedRecords
    guard elapsed >= 10, completed >= 5, latest.pendingRecords > 0 else { return nil }
    return .seconds(Double(latest.pendingRecords) * elapsed / Double(completed))
  }
}
