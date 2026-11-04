import ColophonCore
import Darwin
import Foundation

/// A library in a folder the person chose. File access is coordinated, so iCloud Drive and other
/// file providers see consistent writes. A file that is still in iCloud is not downloaded on the
/// calling thread: the read asks for the download and throws `ColophonError.pending`. Nil means
/// the file is absent.
public struct FolderStore: BoundedRecordStore {
  public let url: URL
  private let ubiquitySource: any UbiquitySource
  private let downloadedSizes = DownloadedRecordSizes()
  /// How long a coordinated read waits for its claim. Tests inject a short deadline.
  public var coordinationDeadline: Duration
  /// How long a coordinated write waits for its claim. Longer than a read so a slow provider can finish.
  public var writeCoordinationDeadline: Duration
  /// Called on the calling thread immediately before a claim. Tests use this to prove a read did not coordinate.
  var willCoordinate: (@Sendable () -> Void)?
  /// Called inside a write accessor after the claim is granted, before the bytes are written.
  var willPerform: (@Sendable () -> Void)?

  public init(_ url: URL, coordinationDeadline: Duration = .seconds(1), writeCoordinationDeadline: Duration = .seconds(10),
    requestDownload: @escaping @Sendable (URL) throws -> Void = {
      try FileManager.default.startDownloadingUbiquitousItem(at: $0)
    }, ubiquitySource: (any UbiquitySource)? = nil) {
    self.url = url
    self.coordinationDeadline = coordinationDeadline
    self.writeCoordinationDeadline = writeCoordinationDeadline
    self.ubiquitySource = ubiquitySource ?? FileUbiquitySource(download: requestDownload, metadata: UbiquityDownloadMetadata(root: url))
  }

  public func list(_ directory: String) throws -> [String] {
    let folder = url.appending(path: directory, directoryHint: .isDirectory)
    let contents: [String]
    do { contents = try FileManager.default.contentsOfDirectory(atPath: folder.path) }
    catch let error as CocoaError where error.code == .fileReadNoSuchFile || error.code == .fileNoSuchFile { return [] }
    var names = Set<String>()
    for name in contents {
      // iCloud keeps a not-yet-downloaded file as ".<name>.icloud".
      if name.hasPrefix("."), name.hasSuffix(".icloud") {
        let real = String(name.dropFirst().dropLast(".icloud".count))
        try? ubiquitySource.requestDownload(of: folder.appending(path: real))
        names.insert(real)
      } else if !name.hasPrefix(".") {
        names.insert(name)
      }
    }
    return names.sorted()
  }

  public func downloadProgress(for paths: [String]) throws -> RecordDownloadProgress? {
    try downloadProgress(for: paths, knownDownloaded: [])
  }

  public func downloadProgress(for paths: [String], knownDownloaded: Set<String>) throws -> RecordDownloadProgress? {
    let paths = Set(paths)
    var downloaded = 0
    var downloadedBytes: Int64 = 0
    var totalBytes: Int64 = 0
    var bytesKnown = !paths.isEmpty
    for path in paths {
      let file = url.appending(path: path)
      let availability = knownDownloaded.contains(path) ? .downloaded : try ubiquitySource.availability(of: file)
      switch availability {
      case .downloaded: downloaded += 1
      case .pending, .absent:
        // A known record remains required even if its placeholder disappears. Requests can
        // transiently fail while the provider discovers it; absence never counts as a download.
        try? ubiquitySource.requestDownload(of: file)
      }
      let transfer: UbiquityTransferProgress?
      if let provider = ubiquitySource.transferProgress(of: file) {
        transfer = provider
      } else if availability == .downloaded, let size = downloadedSizes.size(of: file) {
        transfer = UbiquityTransferProgress(downloadedBytes: size, totalBytes: size)
      } else { transfer = nil }
      if let transfer {
        let downloadedAmount = availability == .downloaded ? transfer.totalBytes : transfer.downloadedBytes
        let (nextDownloaded, downloadedOverflow) = downloadedBytes.addingReportingOverflow(downloadedAmount)
        let (nextTotal, totalOverflow) = totalBytes.addingReportingOverflow(transfer.totalBytes)
        if downloadedOverflow || totalOverflow { bytesKnown = false }
        else { downloadedBytes = nextDownloaded; totalBytes = nextTotal }
      } else { bytesKnown = false }
    }
    return RecordDownloadProgress(downloadedRecords: downloaded, totalRecords: paths.count,
      downloadedBytes: bytesKnown ? downloadedBytes : nil, totalBytes: bytesKnown ? totalBytes : nil)
  }

  public func read(_ path: String) throws -> Data? {
    let file = url.appending(path: path)
    switch availability(of: file) {
    case .absent:
      return nil
    case .pending:
      try? ubiquitySource.requestDownload(of: file)
      throw ColophonError.pending(path)
    case .present:
      break
    }
    let box = CoordinationBox(NSFileAccessIntent.readingIntent(with: file, options: .withoutChanges))
    let claimed: Bool
    do {
      claimed = try claim(box, deadline: coordinationDeadline) { actual in
        do { box.setData(try Data(contentsOf: actual)) }
        catch let error as CocoaError where error.code == .fileReadNoSuchFile || error.code == .fileNoSuchFile {}
      }
    } catch {
      if Self.isMissing(error) { return try classifyMissingRead(file, path) }
      if Self.isCancelled(error) { throw Self.missedRead(file, path) }
      throw error
    }
    if !claimed { throw Self.missedRead(file, path) }
    if let data = box.data() {
      downloadedSizes.record(Int64(data.count), for: file)
      return data
    }
    return try classifyMissingRead(file, path)
  }

  /// Bounds file allocation inside the coordinated accessor. A provider may still block
  /// after a claim begins; the coordination deadline is not a hard read-time deadline.
  public func read(_ path: String, maximumBytes: Int) throws -> Data? {
    guard maximumBytes >= 0 else { throw BoundedRecordReadError.exceedsLimit }
    let file = url.appending(path: path)
    switch availability(of: file) {
    case .absent:
      return nil
    case .pending:
      try? ubiquitySource.requestDownload(of: file)
      throw ColophonError.pending(path)
    case .present:
      break
    }
    let box = CoordinationBox(NSFileAccessIntent.readingIntent(with: file, options: .withoutChanges))
    let claimed: Bool
    do {
      claimed = try claim(box, deadline: coordinationDeadline) { actual in
        do { if let bytes = try BoundedRecordFile.read(actual, maximumBytes: maximumBytes) { box.setData(bytes) } }
        catch let error as CocoaError where error.code == .fileReadNoSuchFile || error.code == .fileNoSuchFile {}
      }
    } catch {
      if Self.isMissing(error) { return try classifyMissingRead(file, path) }
      if Self.isCancelled(error) { throw Self.missedRead(file, path) }
      throw error
    }
    if !claimed { throw Self.missedRead(file, path) }
    if let data = box.data() {
      downloadedSizes.record(Int64(data.count), for: file)
      return data
    }
    return try classifyMissingRead(file, path)
  }

  public func create(_ path: String, _ data: Data) throws {
    try write(path, data, options: .withoutOverwriting)
  }

  public func replace(_ path: String, _ data: Data) throws {
    try write(path, data, options: .atomic)
  }

  private func write(_ path: String, _ data: Data, options: Data.WritingOptions) throws {
    let file = url.appending(path: path)
    try FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
    let box = CoordinationBox(NSFileAccessIntent.writingIntent(with: file, options: []))
    let claimed: Bool
    do {
      claimed = try claim(box, deadline: writeCoordinationDeadline) { actual in
        self.willPerform?()
        do { try data.write(to: actual, options: options) }
        catch CocoaError.fileWriteFileExists { throw ColophonError.alreadyExists(path) }
      }
    } catch {
      if Self.isCancelled(error) { throw ColophonError.unavailable(path) }
      throw error
    }
    if !claimed { throw ColophonError.unavailable(path) }
    downloadedSizes.record(Int64(data.count), for: file)
  }

  /// Keeps the current authority bytes and marks conflict versions resolved. Callers rebase their
  /// own pending intents before this, so a lost version is re-signed rather than merged.
  public func resolveAuthorityConflicts() throws {
    for name in try list(LibraryPath.authority) {
      let file = url.appending(path: LibraryPath.authority + "/" + name)
      let conflicts = NSFileVersion.unresolvedConflictVersionsOfItem(at: file) ?? []
      guard !conflicts.isEmpty else { continue }
      for version in conflicts { version.isResolved = true }
      try NSFileVersion.removeOtherVersionsOfItem(at: file)
    }
  }

  private enum Availability { case absent, pending, present }

  /// The file may disappear after the preflight but before a coordinated accessor runs.
  /// Only a second proven absence is nil; a new placeholder remains a pending read.
  private func classifyMissingRead(_ file: URL, _ path: String) throws -> Data? {
    switch availability(of: file) {
    case .absent: return nil
    case .pending:
      try? ubiquitySource.requestDownload(of: file)
      throw ColophonError.pending(path)
    case .present: throw ColophonError.unavailable(path)
    }
  }

  /// A proven absent file skips coordination. Permission and provider errors still reach the
  /// coordinator, where they can be reported rather than mistaken for an absent record.
  private func availability(of file: URL) -> Availability {
    switch try? ubiquitySource.availability(of: file) {
    case .absent: return .absent
    case .pending: return .pending
    case .downloaded, nil: return .present
    }
  }

  private static func missedRead(_ file: URL, _ path: String) -> ColophonError {
    if file.path(percentEncoded: false).contains("/Mobile Documents/") { return .pending(path) }
    return .unavailable(path)
  }

  /// Returns false when the claim is still waiting at the deadline. The accessor then skips
  /// `perform`. An accessor that has already started runs to completion and its result is returned.
  private func claim(_ box: CoordinationBox, deadline: Duration, perform: @escaping @Sendable (URL) throws -> Void) throws -> Bool {
    let semaphore = DispatchSemaphore(value: 0)
    willCoordinate?()
    let coordinator = box.coordinator
    coordinator.coordinate(with: [box.intent], queue: box.queue) { error in
      let target = box.targetURL()
      defer {
        box.finish()
        semaphore.signal()
      }
      if let error {
        box.setError(error)
        return
      }
      guard box.begin() else { return }
      do { try perform(target) }
      catch { box.setError(error) }
    }
    if semaphore.wait(timeout: .now() + Self.seconds(deadline)) == .timedOut {
      switch box.timedOutIfWaiting() {
      case .cancel:
        coordinator.cancel()
        return false
      case .wait:
        semaphore.wait()
      case .done:
        break
      }
    }
    if let error = box.error() { throw error }
    return true
  }

  private static func seconds(_ duration: Duration) -> TimeInterval {
    let components = duration.components
    return TimeInterval(components.seconds) + TimeInterval(components.attoseconds) / 1_000_000_000_000_000_000
  }

  private static func isMissing(_ error: any Error) -> Bool {
    let cocoa = error as NSError
    return cocoa.domain == NSCocoaErrorDomain
      && (cocoa.code == NSFileReadNoSuchFileError || cocoa.code == NSFileNoSuchFileError)
  }

  private static func isCancelled(_ error: any Error) -> Bool {
    let cocoa = error as NSError
    return cocoa.domain == NSCocoaErrorDomain && cocoa.code == NSUserCancelledError
  }
}

/// One lock covers the coordinator, the intent, the accessor result and the gate.
/// `coordinate` and `cancel` run on the caller. The accessor does not touch the coordinator.
private final class CoordinationBox: @unchecked Sendable {
  private let lock = NSLock()
  let coordinator = NSFileCoordinator()
  let queue: OperationQueue
  let intent: NSFileAccessIntent
  private var stored: Data?
  private var failure: (any Error)?
  private enum Gate { case waiting, running, timedOut, finished }
  private var gate: Gate = .waiting

  init(_ intent: NSFileAccessIntent) {
    self.intent = intent
    let queue = OperationQueue()
    queue.maxConcurrentOperationCount = 1
    self.queue = queue
  }

  func targetURL() -> URL { lock.withLock { intent.url } }
  func setData(_ data: Data) { lock.withLock { stored = data } }
  func data() -> Data? { lock.withLock { stored } }
  func setError(_ error: any Error) { lock.withLock { failure = error } }
  func error() -> (any Error)? { lock.withLock { failure } }

  enum Timeout { case cancel, wait, done }

  func begin() -> Bool {
    lock.withLock {
      guard gate == .waiting else { return false }
      gate = .running
      return true
    }
  }

  func timedOutIfWaiting() -> Timeout {
    lock.withLock {
      switch gate {
      case .waiting:
        gate = .timedOut
        return .cancel
      case .running:
        return .wait
      case .timedOut, .finished:
        return .done
      }
    }
  }

  func finish() { lock.withLock { gate = .finished } }
}
