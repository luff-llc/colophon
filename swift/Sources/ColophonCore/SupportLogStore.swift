import Foundation
import OSLog

/// App-local, bounded troubleshooting breadcrumbs. Does not read or export any library file.
/// Fixed schema provides a durable cross-launch trail without exporting arbitrary OSLog strings.
public actor SupportLogStore {
  public static let maximumBytes = 131_072
  public static let maximumEvents = 256
  private static let retention: TimeInterval = 7 * 24 * 60 * 60
  private static let logger = Logger(subsystem: Bundle.main.bundleIdentifier ?? "org.colophon", category: "sharedlibrary")
  private let directory: URL
  private var events: [SupportEvent] = []
  private var context: SupportContext?
  private struct Journal: Codable {
    let events: [SupportEvent]
    let context: SupportContext?
  }
  private var loaded = false
  private var storageAvailable = true
  private var pendingFlush: Task<Void, Never>?

  public init(directory: URL) { self.directory = directory }
  private var journal: URL { directory.appending(path: "recent-events.json") }

  public func record(stage: SupportEvent.Stage, outcome: SupportEvent.Outcome, error: (any Error)? = nil) {
    load()
    record(stage: stage, outcome: outcome, failure: error.map(SupportEvent.Failure.init))
  }

  public func record(stage: SupportEvent.Stage, outcome: SupportEvent.Outcome, failure: SupportEvent.Failure?) {
    load()
    let event = SupportEvent(stage: stage, outcome: outcome, failure: failure)
    // Refresh loops must not evict useful transitions or write the same failure every few seconds.
    let previous = events.last { candidate in
      candidate.stage == stage && (outcome == .started ? candidate.outcome == .started : candidate.outcome != .started)
    }
    if let previous, previous.outcome == outcome, previous.failure == event.failure,
      event.date.timeIntervalSince(previous.date) < 60 { return }
    let category = event.failure?.category.rawValue ?? "none"
    let code = event.failure?.code ?? 0
    if outcome == .failed {
      Self.logger.error("Stage \(stage.rawValue, privacy: .public) outcome \(outcome.rawValue, privacy: .public) category \(category, privacy: .public) code \(code)")
    } else {
      Self.logger.notice("Stage \(stage.rawValue, privacy: .public) outcome \(outcome.rawValue, privacy: .public)")
    }
    events.append(event)
    prune()
    scheduleFlush()
  }

  public func updateContext(libraryID: String?, membership: SupportContext.Membership,
    gauges: [SupportContext.Gauge: Int] = [:]) {
    load()
    let incoming = SupportContext(libraryID: libraryID, membership: membership, gauges: gauges)
    var merged = incoming.libraryFingerprint == context?.libraryFingerprint ? context?.gauges ?? [:] : [:]
    merged.merge(incoming.gauges) { _, new in new }
    if incoming.libraryFingerprint == context?.libraryFingerprint, incoming.membership == context?.membership,
      merged == context?.gauges { return }
    context = SupportContext(fingerprint: incoming.libraryFingerprint, membership: membership, gauges: merged)
    scheduleFlush()
  }

  /// A failed refresh can retain the last known library fingerprint without asserting a new identity.
  public func updateMembership(_ membership: SupportContext.Membership) {
    load()
    guard context?.membership != membership else { return }
    context = SupportContext(fingerprint: context?.libraryFingerprint, membership: membership, gauges: context?.gauges ?? [:])
    scheduleFlush()
  }

  public func report(application: SupportReport.Application = .init()) -> SupportReport {
    load(); flush(); prune()
    return SupportReport(application: application, events: events, logStorageAvailable: storageAvailable, context: context)
  }

  public func clear() throws {
    pendingFlush?.cancel(); pendingFlush = nil
    events = []; loaded = true
    do {
      if FileManager.default.fileExists(atPath: journal.path) { try FileManager.default.removeItem(at: journal) }
      storageAvailable = true
    } catch { storageAvailable = false; throw error }
  }

  private func load() {
    guard !loaded else { return }; loaded = true
    guard FileManager.default.fileExists(atPath: journal.path) else { return }
    do {
      let attributes = try FileManager.default.attributesOfItem(atPath: journal.path)
      guard let size = attributes[.size] as? NSNumber, size.intValue <= Self.maximumBytes else {
        storageAvailable = false; return
      }
      let data = try Data(contentsOf: journal, options: .mappedIfSafe)
      guard data.count <= Self.maximumBytes else { storageAvailable = false; return }
      let decoder = JSONDecoder()
      if let decoded = try? decoder.decode(Journal.self, from: data) {
        events = Array(decoded.events.suffix(Self.maximumEvents)); context = decoded.context
      } else {
        events = Array(try decoder.decode([SupportEvent].self, from: data).suffix(Self.maximumEvents))
      }
      prune()
    } catch { storageAvailable = false }
  }

  private func scheduleFlush() {
    guard pendingFlush == nil else { return }
    pendingFlush = Task { [weak self] in
      do { try await Task.sleep(for: .milliseconds(750)) } catch { return }
      await self?.flush()
    }
  }

  /// Flush at an app lifecycle checkpoint or before producing an export.
  public func flush() {
    guard pendingFlush != nil else { return }
    pendingFlush?.cancel(); pendingFlush = nil
    persist()
  }

  private func prune() {
    let earliest = Date().addingTimeInterval(-Self.retention)
    events = Array(events.filter { $0.date >= earliest }.suffix(Self.maximumEvents))
  }

  private func persist() {
    prune()
    do {
      let encoder = JSONEncoder()
      var data = try encoder.encode(Journal(events: events, context: context))
      while data.count > Self.maximumBytes, !events.isEmpty {
        events.removeFirst(); data = try encoder.encode(Journal(events: events, context: context))
      }
      try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700])
      try data.write(to: journal, options: .atomic)
      try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: journal.path)
      var excluded = directory
      var values = URLResourceValues(); values.isExcludedFromBackup = true
      try excluded.setResourceValues(values)
      storageAvailable = true
    } catch { storageAvailable = false }
  }
}
