import ColophonCore
import Foundation

/// Private caller-owned local journal. Confirmed records remain receipts and are never replayed.
/// Unlike requests, this is not a shared provider slot and contains only already-signed authority bytes.
public struct AdditionalAccessApprovalJournal: Sendable {
  struct Entry: Codable, Sendable {
    let format: String
    let version: Int
    let batch: AdditionalAccessApprovalBatch
    var confirmed: Bool
  }
  public let directory: URL
  private static let lock = NSLock()
  public init(directory: URL) { self.directory = directory }
  func save(_ batch: AdditionalAccessApprovalBatch) throws -> AdditionalAccessApprovalBatch {
    try Self.lock.withLock {
      _ = try batch.validatedRequest()
      if let old = try loadUnlocked(id: batch.id) {
        guard try Canonical.encode(old.batch) == Canonical.encode(batch) else { throw AdditionalAccessError.journalConflict }
        return old.batch
      }
      for old in try entriesUnlocked(libraryID: batch.libraryID) where old.batch.memberID == batch.memberID
        && old.batch.requestID == batch.requestID && old.batch.requestBodyDigest == batch.requestBodyDigest {
        guard old.batch.selectedNamespaces == batch.selectedNamespaces, old.batch.baseSequence == batch.baseSequence,
          old.batch.baseDigest == batch.baseDigest, old.batch.records.map(\.body) == batch.records.map(\.body) else {
          throw AdditionalAccessError.journalConflict
        }
        return old.batch // Keep the first exact signed tail even if a retry made new ECDSA signatures.
      }
      try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
      try write(.init(format: AdditionalAccessApprovalBatch.format, version: 1, batch: batch, confirmed: false))
      return batch
    }
  }
  func confirm(_ batch: AdditionalAccessApprovalBatch) throws {
    try Self.lock.withLock {
      guard var entry = try loadUnlocked(id: batch.id), try Canonical.encode(entry.batch) == Canonical.encode(batch) else { throw AdditionalAccessError.journalConflict }
      entry.confirmed = true; try write(entry)
    }
  }
  func load(id: String) throws -> Entry? { try Self.lock.withLock { try loadUnlocked(id: id) } }
  public func pending(libraryID: String) throws -> [AdditionalAccessApprovalBatch] {
    try entries(libraryID: libraryID).filter { !$0.confirmed }.map(\.batch)
  }
  func matching(_ record: AdditionalAccessRequest.Record, selected: [String]) throws -> Entry? {
    let values = try entries(libraryID: record.request.libraryID).filter {
      $0.batch.memberID == record.request.member.id && $0.batch.requestID == record.request.requestID
        && $0.batch.requestBodyDigest == record.bodyDigest
    }
    guard values.count <= 1 else { throw AdditionalAccessError.journalConflict }
    guard let found = values.first else { return nil }
    guard found.batch.selectedNamespaces == selected.sorted() else { throw AdditionalAccessError.journalConflict }
    return found
  }
  private func entries(libraryID: String) throws -> [Entry] {
    try Self.lock.withLock { try entriesUnlocked(libraryID: libraryID) }
  }
  private func entriesUnlocked(libraryID: String) throws -> [Entry] {
    guard FileManager.default.fileExists(atPath: directory.path) else { return [] }
    let names = try FileManager.default.contentsOfDirectory(atPath: directory.path)
    return try names.filter { $0.hasSuffix(".json") }.compactMap { name in
      let id = String(name.dropLast(5))
      guard Self.validID(id), let entry = try loadUnlocked(id: id), entry.batch.libraryID == libraryID else { return nil }
      return entry
    }
  }
  private static func validID(_ id: String) -> Bool {
    id.utf8.count == 64 && id.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
  }
  private func loadUnlocked(id: String) throws -> Entry? {
    guard Self.validID(id) else { throw AdditionalAccessError.journalConflict }
    let url = directory.appendingPathComponent(id + ".json")
    guard FileManager.default.fileExists(atPath: url.path) else { return nil }
    let input = try FileHandle(forReadingFrom: url); defer { try? input.close() }
    var bytes = Data()
    while bytes.count <= AdditionalAccessApprovalBatch.maximumBytes {
      let part = try input.read(upToCount: min(65_536, AdditionalAccessApprovalBatch.maximumBytes + 1 - bytes.count)) ?? Data()
      if part.isEmpty { break }; bytes.append(part)
    }
    guard bytes.count <= AdditionalAccessApprovalBatch.maximumBytes else { throw AdditionalAccessError.exceedsLimits }
    let value = try Canonical.decode(Entry.self, from: bytes)
    guard value.format == AdditionalAccessApprovalBatch.format, value.version == 1, value.batch.id == id else { throw AdditionalAccessError.journalConflict }
    _ = try value.batch.validatedRequest()
    return value
  }
  private func write(_ entry: Entry) throws {
    let bytes = try Canonical.encode(entry)
    guard bytes.count <= AdditionalAccessApprovalBatch.maximumBytes else { throw AdditionalAccessError.exceedsLimits }
    try PrivateAtomicFile.write(bytes, to: directory.appendingPathComponent(entry.batch.id + ".json"))
  }
}
