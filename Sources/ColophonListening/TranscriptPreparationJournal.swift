import ColophonCore
import Foundation

public struct TranscriptPreparationRecord: Codable, Hashable, Sendable {
  public enum State: String, Codable, Sendable { case queued, running, interrupted, ready, applied, failed, cancelled }
  public var request: TranscriptPreparationRequest
  public var state: State
  public var attempts: Int
  public var updated: Date
  public var failure: String?
  public var resultDigest: String?
  public var appliedRevision: String?
  public var remoteRevision: String?
  public var audioReleased: Bool
}

/// One process owns a journal. All mutable state is protected by `lock`; each transition is
/// atomically written before becoming visible. This is restart recovery, not a distributed lease.
public final class TranscriptPreparationJournal: @unchecked Sendable {
  public let directory: URL
  private let lock = NSLock()
  private var records: [String: TranscriptPreparationRecord]

  public init(directory: URL) throws {
    self.directory = directory
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    var saved: [String: TranscriptPreparationRecord] = [:]
    for file in try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
      where file.lastPathComponent.hasSuffix(".job.json") {
      // Fail closed on damaged metadata: never silently forget a retention pin.
      let record = try Canonical.decode(TranscriptPreparationRecord.self, from: Data(contentsOf: file))
      guard saved[record.request.id] == nil else { throw TranscriptPreparationError.conflictingRequest }
      saved[record.request.id] = record
    }
    records = saved
  }

  public func all() -> [TranscriptPreparationRecord] {
    lock.withLock { records.values.sorted { ($0.updated, $0.request.id) < ($1.updated, $1.request.id) } }
  }
  public func record(_ id: String) -> TranscriptPreparationRecord? { lock.withLock { records[id] } }
  public func retainsAudio(episode: String) -> Bool {
    lock.withLock { records.values.contains { $0.request.episode == episode
      && ($0.request.holdAudio || $0.request.policy != .manualImport)
      && !$0.audioReleased && $0.state != .applied
      && ($0.request.holdAudio || $0.state != .cancelled) } }
  }
  public func audioFile(_ id: String) -> URL { directory.appending(path: key(id) + ".audio") }
  public func resultFile(_ id: String) -> URL { directory.appending(path: key(id) + ".result.json") }

  /// Private unfinished recognition. A checkpoint never becomes a ready/admitted source.
  public func checkpoint(_ id: String, result: TranscriptPreparationResult) throws {
    try result.validate()
    guard result.source == "onDevice", result.receipt.completeness == .partial,
      result.receipt.recordingDigest != nil else { throw TranscriptPreparationError.invalidSource }
    try lock.withLock {
      let record = try required(id)
      guard record.state == .running else { throw TranscriptPreparationError.notReady }
      if let expected = record.request.recordingDigest,
        expected != result.receipt.recordingDigest { throw TranscriptPreparationError.recordingChanged }
      if let prior = try readDraft(id) {
        guard prior.receipt.recordingDigest == result.receipt.recordingDigest else {
          throw TranscriptPreparationError.recordingChanged
        }
        let priorEnd = prior.document.words?.map(\.end).max() ?? 0
        let nextEnd = result.document.words?.map(\.end).max() ?? 0
        // A retry starts at zero; keep the earlier attempt until recognition catches up.
        guard nextEnd >= priorEnd else { return }
      }
      try write(Canonical.encode(result), to: draftFile(id))
    }
  }

  public func draft(_ id: String) throws -> TranscriptPreparationResult? {
    try lock.withLock {
      let record = try required(id)
      guard record.state != .applied, record.state != .cancelled else { return nil }
      return try readDraft(id)
    }
  }

  public func discardDraft(_ id: String) throws {
    try lock.withLock {
      _ = try required(id)
      let file = draftFile(id)
      if FileManager.default.fileExists(atPath: file.path) { try FileManager.default.removeItem(at: file) }
    }
  }

  private func draftFile(_ id: String) -> URL { directory.appending(path: key(id) + ".draft.json") }
  private func readDraft(_ id: String) throws -> TranscriptPreparationResult? {
    let file = draftFile(id)
    guard FileManager.default.fileExists(atPath: file.path) else { return nil }
    let result = try Canonical.decode(TranscriptPreparationResult.self, from: Data(contentsOf: file))
    try result.validate()
    guard result.source == "onDevice", result.receipt.completeness == .partial,
      result.receipt.recordingDigest != nil else { throw TranscriptPreparationError.invalidSource }
    return result
  }

  @discardableResult public func enqueue(_ request: TranscriptPreparationRequest) throws -> TranscriptPreparationRecord {
    try request.recordingSource?.validate()
    return try lock.withLock {
      guard !request.id.isEmpty, !request.episode.isEmpty, !request.show.isEmpty,
        request.recordingDigest.map(PodcastRecordingIdentity.isDigest) ?? true else {
        throw TranscriptPreparationError.invalidSource
      }
      if let prior = records[request.id] {
        guard prior.request == request else { throw TranscriptPreparationError.conflictingRequest }
        return prior
      }
      let next = TranscriptPreparationRecord(request: request, state: .queued, attempts: 0, updated: .now,
        failure: nil, resultDigest: nil, appliedRevision: nil, remoteRevision: nil, audioReleased: false)
      try persist(next); return next
    }
  }
  public func recoverInterrupted() throws {
    try lock.withLock {
      for var record in Array(records.values) where record.state == .running {
        // A result can have reached disk immediately before metadata. Recover it without ASR.
        if let result = try? readResult(record.request.id) {
          record.resultDigest = Canonical.digest(try Canonical.encode(result)); record.state = .ready
        } else { record.state = .interrupted }
        record.updated = .now; try persist(record)
      }
    }
  }
  @discardableResult public func begin(_ id: String) throws -> TranscriptPreparationRecord {
    try lock.withLock {
      var record = try required(id)
      guard [.queued, .interrupted, .failed].contains(record.state) else {
        throw record.state == .cancelled ? TranscriptPreparationError.cancelled : .notReady
      }
      record.state = .running; record.attempts += 1; record.failure = nil; record.updated = .now
      try persist(record); return record
    }
  }
  public func ready(_ id: String, result: TranscriptPreparationResult) throws {
    try result.validate()
    try lock.withLock {
      var record = try required(id)
      if let expected = record.request.recordingDigest, result.source == "onDevice",
        expected != result.receipt.recordingDigest { throw TranscriptPreparationError.recordingChanged }
      let data = try Canonical.encode(result)
      let digest = Canonical.digest(data)
      if let prior = record.resultDigest {
        guard prior == digest else { throw TranscriptPreparationError.conflictingRequest }
        return
      }
      // Keep even a cancelled late result for recovery/review, never turn it into active work.
      try write(data, to: resultFile(id))
      record.resultDigest = digest
      if record.state != .cancelled { record.state = .ready }
      record.updated = .now; try persist(record)
    }
  }
  public func result(_ id: String) throws -> TranscriptPreparationResult {
    try lock.withLock {
      let record = try required(id)
      let result = try readResult(id)
      guard record.resultDigest == Canonical.digest(try Canonical.encode(result)) else {
        throw TranscriptPreparationError.invalidSource
      }
      return result
    }
  }
  /// Reuse of an already admitted source needs no new result or source operation.
  public func reused(_ id: String, revision: String) throws {
    try update(id) { record in
      guard record.state != .cancelled, !revision.isEmpty else { throw TranscriptPreparationError.cancelled }
      record.state = .applied; record.appliedRevision = revision
    }
  }
  public func submitted(_ id: String, revision: String) throws {
    try update(id) { record in
      guard record.state != .cancelled else { throw TranscriptPreparationError.cancelled }
      record.remoteRevision = revision; record.state = .queued
    }
  }
  public func applied(_ id: String, revision: String) throws {
    try update(id) { record in
      guard record.state == .ready || (record.state == .applied && record.appliedRevision == revision) else {
        throw record.state == .cancelled ? TranscriptPreparationError.cancelled : .notReady
      }
      record.state = .applied; record.appliedRevision = revision; record.failure = nil
    }
  }
  public func fail(_ id: String, message: String, interrupted: Bool = false) throws {
    try update(id) { record in
      guard record.state != .cancelled && record.state != .applied && record.state != .ready else { return }
      record.state = interrupted ? .interrupted : .failed; record.failure = String(message.prefix(4096))
    }
  }
  /// Retain a ready result and its state while making a failed reconciliation reviewable.
  public func reportFailure(_ id: String, message: String) throws {
    try update(id) { record in
      guard record.state != .applied && record.state != .cancelled else { return }
      record.failure = String(message.prefix(4096))
    }
  }
  public func cancel(_ id: String) throws {
    try update(id) { record in if record.state != .applied { record.state = .cancelled } }
  }
  /// A deliberate discard may release audio even after failure/cancellation. Text and raw
  /// receipts are retained independently; cleanup never removes them along with audio.
  public func releaseAudio(_ id: String) throws { try update(id) { $0.audioReleased = true } }
  public func removeAppliedAudio(_ id: String) throws {
    try lock.withLock {
      let record = try required(id)
      guard record.state == .applied || record.audioReleased else { throw TranscriptPreparationError.notReady }
      let file = audioFile(id)
      if FileManager.default.fileExists(atPath: file.path) { try FileManager.default.removeItem(at: file) }
    }
  }
  private func update(_ id: String, _ action: (inout TranscriptPreparationRecord) throws -> Void) throws {
    try lock.withLock { var record = try required(id); try action(&record); record.updated = .now; try persist(record) }
  }
  private func required(_ id: String) throws -> TranscriptPreparationRecord {
    guard let value = records[id] else { throw TranscriptPreparationError.missingRequest }; return value
  }
  private func readResult(_ id: String) throws -> TranscriptPreparationResult {
    let value = try Canonical.decode(TranscriptPreparationResult.self, from: Data(contentsOf: resultFile(id)))
    try value.validate(); return value
  }
  private func persist(_ record: TranscriptPreparationRecord) throws {
    try write(Canonical.encode(record), to: directory.appending(path: key(record.request.id) + ".job.json"))
    records[record.request.id] = record
  }
  private func write(_ data: Data, to file: URL) throws {
    try PrivateAtomicFile.write(data, to: file)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
  }
  private func key(_ id: String) -> String { Canonical.digest(Data(id.utf8)) }
}
