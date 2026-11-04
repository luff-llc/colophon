import Foundation

/// An optional transfer measurement cache. Worker polls never touch NSMetadataQuery or its
/// results; the query and notification handling remain on the main actor. Every mutable cache
/// property, including its query owner, is protected by `lock`.
final class UbiquityDownloadMetadata: @unchecked Sendable {
  private let root: URL
  private let lock = NSLock()
  private var startRequested = false
  private var queryOwner: QueryOwner?
  private var measurements: [String: UbiquityTransferProgress] = [:]

  init(root: URL) { self.root = root.standardizedFileURL }

  /// Called only after the filesystem source recognizes an actual cloud-only item. Ordinary
  /// local libraries do not create queries, observers, tasks or scan metadata.
  func start() {
    let shouldStart = lock.withLock {
      guard !startRequested else { return false }
      startRequested = true
      return true
    }
    guard shouldStart else { return }
    Task { @MainActor [weak self] in
      guard let self else { return }
      let owner = QueryOwner(root: root) { [weak self] updated, removed in
        self?.update(updated: updated, removed: removed)
      }
      lock.withLock { queryOwner = owner }
      owner.start()
    }
  }

  func progress(of file: URL) -> UbiquityTransferProgress? {
    let path = file.standardizedFileURL.path(percentEncoded: false)
    return lock.withLock { measurements[path] }
  }

  private func update(updated: [String: UbiquityTransferProgress], removed: [String]) {
    lock.withLock {
      for path in removed { measurements.removeValue(forKey: path) }
      for (path, progress) in updated { measurements[path] = progress }
    }
  }

  deinit {
    guard let owner = lock.withLock({ queryOwner }) else { return }
    // NSMetadataQuery must stop on the same actor that started it. Retain only the owner
    // until cleanup runs; the task must not resurrect this cache or its filesystem source.
    Task { @MainActor in owner.stop() }
  }

  @MainActor private final class QueryOwner: NSObject {
    private let query = NSMetadataQuery()
    private let rootPath: String
    private let publish: @Sendable ([String: UbiquityTransferProgress], [String]) -> Void

    init(root: URL, publish: @escaping @Sendable ([String: UbiquityTransferProgress], [String]) -> Void) {
      self.rootPath = root.path(percentEncoded: false)
      self.publish = publish
      super.init()
      query.searchScopes = [root]
      query.predicate = NSPredicate(format: "%K == YES", NSMetadataItemIsUbiquitousKey)
      query.notificationBatchingInterval = 1
      query.operationQueue = .main
    }

    func start() {
      let center = NotificationCenter.default
      center.addObserver(self, selector: #selector(gathered(_:)), name: .NSMetadataQueryDidFinishGathering, object: query)
      center.addObserver(self, selector: #selector(changed(_:)), name: .NSMetadataQueryDidUpdate, object: query)
      if !query.start() { stop() }
    }

    func stop() {
      NotificationCenter.default.removeObserver(self, name: .NSMetadataQueryDidFinishGathering, object: query)
      NotificationCenter.default.removeObserver(self, name: .NSMetadataQueryDidUpdate, object: query)
      query.stop()
    }

    @objc private func gathered(_ notification: Notification) {
      query.disableUpdates()
      defer { query.enableUpdates() }
      var updated: [String: UbiquityTransferProgress] = [:]
      // Exactly one initial scan. Later notifications include only the changed result set.
      for index in 0..<query.resultCount {
        guard let item = query.result(at: index) as? NSMetadataItem,
          let path = path(of: item), let progress = measurement(of: item) else { continue }
        updated[path] = progress
      }
      publish(updated, [])
    }

    @objc private func changed(_ notification: Notification) {
      query.disableUpdates()
      defer { query.enableUpdates() }
      let added = notification.userInfo?[NSMetadataQueryUpdateAddedItemsKey] as? [NSMetadataItem] ?? []
      let changed = notification.userInfo?[NSMetadataQueryUpdateChangedItemsKey] as? [NSMetadataItem] ?? []
      let deleted = notification.userInfo?[NSMetadataQueryUpdateRemovedItemsKey] as? [NSMetadataItem] ?? []
      var updated: [String: UbiquityTransferProgress] = [:]
      var removed = deleted.compactMap { path(of: $0) }
      for item in added + changed {
        guard let path = path(of: item) else { continue }
        if let progress = measurement(of: item) { updated[path] = progress }
        else { removed.append(path) }
      }
      publish(updated, removed)
    }

    private func path(of item: NSMetadataItem) -> String? {
      guard let url = item.value(forAttribute: NSMetadataItemURLKey) as? URL else { return nil }
      let path = url.standardizedFileURL.path(percentEncoded: false)
      // Scope is also checked before caching, so this adapter cannot retain measurements
      // from another library if a provider returns a broader result set.
      return path.hasPrefix(rootPath + "/") ? path : nil
    }

    private func measurement(of item: NSMetadataItem) -> UbiquityTransferProgress? {
      guard let size = item.value(forAttribute: NSMetadataItemFSSizeKey) as? NSNumber,
        let percent = item.value(forAttribute: NSMetadataUbiquitousItemPercentDownloadedKey) as? NSNumber,
        size.doubleValue.isFinite, size.doubleValue >= 0, size.doubleValue < Double(Int64.max),
        percent.doubleValue.isFinite else { return nil }
      let total = size.int64Value
      let fraction = min(100, max(0, percent.doubleValue)) / 100
      // The provider's percentage is a transfer estimate, not allocated disk blocks or a
      // byte read. Unknown percentage/size stays unknown rather than becoming zero.
      let downloaded = Int64((Double(total) * fraction).rounded(.towardZero))
      return UbiquityTransferProgress(downloadedBytes: min(total, downloaded), totalBytes: total)
    }
  }
}
