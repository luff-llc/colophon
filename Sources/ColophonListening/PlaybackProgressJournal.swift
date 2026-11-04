import ColophonCore
import ColophonReplica
import CryptoKit
import Foundation

public enum PlaybackProgressJournalError: Error, Equatable {
  case noCurrentAccess, wrongContext, invalidTicket, invalidCiphertext, invalidSnapshot
  case limitExceeded, staleRevision, unavailable
}

/// An authenticated, app-private outbox. One process and one live handle own its file.
/// All mutable state, including the in-memory data key, is protected by `lock`.
/// Mutations acknowledge an atomic file replacement before publishing their new revision.
/// This protects ordinary process-crash ordering, not hostile rollback or sudden power loss.
/// Invalidate the old handle before reopening. Startup compaction requires the existing
/// member key and rotates the ticket before discarding tombstones.
public final class PlaybackProgressJournal<Payload: Codable & Sendable>: @unchecked Sendable {
  public struct Context: Equatable, Sendable {
    public let libraryID: String
    public let member: PublicIdentity
  }

  public struct Revision: Codable, Hashable, Sendable {
    public let generation: String
    public let sequence: UInt64
  }

  public struct Record: Sendable {
    public let id: String
    /// Nil is a committed cancellation/acknowledgement barrier, not an absent record.
    public let payload: Payload?
    public let revision: Revision
  }

  public struct Receipt: Sendable {
    public let id: String
    public let revision: Revision
  }

  public struct Limits: Sendable {
    public var maximumRecords: Int
    public var maximumPlaintextBytes: Int
    public var maximumFileBytes: Int
    public init(maximumRecords: Int = 512, maximumPlaintextBytes: Int = 1_048_576,
      maximumFileBytes: Int = 2_097_152) {
      self.maximumRecords = maximumRecords
      self.maximumPlaintextBytes = maximumPlaintextBytes
      self.maximumFileBytes = maximumFileBytes
    }
  }

  private struct Entry: Codable {
    let sequence: UInt64
    let payload: Payload?
  }

  private struct Snapshot: Codable {
    var sequence: UInt64
    var entries: [String: Entry]
  }

  public let context: Context
  private let file: URL
  private let limits: Limits
  private let files: PlaybackProgressJournalFiles
  private let ticketBytes: Data
  private let generation: String
  private let lock = NSLock()
  private var key: SymmetricKey?
  private var snapshot: Snapshot

  /// Opening never chooses a library or identity from stored bytes. The supplied current
  /// replica must authorize the exact identity, namespace and library named by the ticket.
  /// A protected member key or an invalid existing file fails without replacing the file.
  public convenience init(directory: URL, replica: Replica, limits: Limits = .init()) throws {
    try self.init(directory: directory, replica: replica, limits: limits, files: .live)
  }

  init(directory: URL, replica: Replica, limits: Limits, files: PlaybackProgressJournalFiles) throws {
    guard (1...4_096).contains(limits.maximumRecords),
      (1...16_777_216).contains(limits.maximumPlaintextBytes),
      (1...33_554_432).contains(limits.maximumFileBytes) else {
      throw PlaybackProgressJournalError.limitExceeded
    }
    let context = try Self.currentContext(replica)
    let file = directory.appending(path: "playback-progress.journal")
    var ticketBytes: Data
    var generation: String
    var key: SymmetricKey
    var snapshot: Snapshot
    var needsWrite = false
    if let bytes = try files.read(file, limits.maximumFileBytes) {
      guard bytes.count <= limits.maximumFileBytes,
        let envelope = try? Canonical.decode(PlaybackProgressJournalEnvelope.self, from: bytes),
        envelope.ticket.count <= PlaybackProgressJournalFormat.maximumTicketBytes,
        let signed = try? Canonical.decode(SignedRecord.self, from: envelope.ticket),
        signed.signature.count == 64, signed.cosignatures?.isEmpty != false,
        context.member.verify(signed),
        let ticket = try? Canonical.decode(PlaybackProgressJournalTicket.self, from: signed.body)
      else { throw PlaybackProgressJournalError.invalidTicket }
      guard ticket.purpose == PlaybackProgressJournalFormat.purpose,
        ticket.version == PlaybackProgressJournalFormat.version,
        ticket.namespace == Podcasts.namespace,
        ticket.libraryID == context.libraryID, ticket.member == context.member else {
        throw PlaybackProgressJournalError.wrongContext
      }
      guard let parsed = UUID(uuidString: ticket.generation),
        parsed.uuidString.lowercased() == ticket.generation else {
        throw PlaybackProgressJournalError.invalidTicket
      }
      ticketBytes = envelope.ticket
      generation = ticket.generation
      // Keep key-access errors intact so protected access remains a retryable failure.
      key = try replica.identity.open(ticket.key)
      guard key.bitCount == 256 else { throw PlaybackProgressJournalError.invalidTicket }
      let plaintext: Data
      do {
        plaintext = try AES.GCM.open(AES.GCM.SealedBox(combined: envelope.ciphertext),
          using: key, authenticating: ticketBytes)
      } catch { throw PlaybackProgressJournalError.invalidCiphertext }
      guard plaintext.count <= limits.maximumPlaintextBytes else {
        throw PlaybackProgressJournalError.limitExceeded
      }
      guard let restored = try? Canonical.decode(Snapshot.self, from: plaintext) else {
        throw PlaybackProgressJournalError.invalidSnapshot
      }
      snapshot = restored
      try Self.validate(snapshot, limits: limits)
      if snapshot.entries.values.contains(where: { $0.payload == nil }) {
        // No old-process callbacks survive this boundary. A new generation rejects every
        // old receipt; live pending payloads survive and no tombstone is silently evicted.
        let fresh = try Self.makeTicket(context: context, identity: replica.identity)
        ticketBytes = fresh.bytes; generation = fresh.generation; key = fresh.key
        var entries: [String: Entry] = [:]
        var sequence: UInt64 = 0
        let ordered = snapshot.entries.sorted { lhs, rhs in
          lhs.value.sequence == rhs.value.sequence
            ? lhs.key < rhs.key : lhs.value.sequence < rhs.value.sequence
        }
        for (id, entry) in ordered {
          guard let payload = entry.payload else { continue }
          sequence += 1
          entries[id] = Entry(sequence: sequence, payload: payload)
        }
        snapshot = Snapshot(sequence: sequence, entries: entries)
        needsWrite = true
      }
    } else {
      let fresh = try Self.makeTicket(context: context, identity: replica.identity)
      ticketBytes = fresh.bytes; generation = fresh.generation; key = fresh.key
      snapshot = Snapshot(sequence: 0, entries: [:])
      needsWrite = true
    }
    if needsWrite {
      let bytes = try Self.encode(snapshot, ticketBytes: ticketBytes, key: key, limits: limits)
      try files.write(file, bytes)
    }
    self.context = context
    self.file = file
    self.limits = limits
    self.files = files
    self.ticketBytes = ticketBytes
    self.generation = generation
    self.key = key
    self.snapshot = snapshot
  }

  public func records() throws -> [String: Record] {
    try lock.withLock {
      guard key != nil else { throw PlaybackProgressJournalError.unavailable }
      return snapshot.entries.mapValuesWithKey { id, entry in
        Record(id: id, payload: entry.payload,
          revision: Revision(generation: generation, sequence: entry.sequence))
      }
    }
  }

  /// Nil expectation requires an absent record. It never means blind overwrite.
  @discardableResult public func replace(id: String, payload: Payload, expecting revision: Revision?) throws -> Receipt {
    try mutate(id: id, payload: payload, expecting: revision)
  }

  /// Even cancellation of an absent ID is written as a barrier against an older capture.
  @discardableResult public func tombstone(id: String, expecting revision: Revision?) throws -> Receipt {
    try mutate(id: id, payload: nil, expecting: revision)
  }

  /// Drops this handle's data key without changing the retained encrypted file.
  public func invalidate() { lock.withLock { key = nil } }

  private func mutate(id: String, payload: Payload?, expecting revision: Revision?) throws -> Receipt {
    try lock.withLock {
      guard let key else { throw PlaybackProgressJournalError.unavailable }
      guard !id.isEmpty, id.utf8.count <= 256 else { throw PlaybackProgressJournalError.limitExceeded }
      let current = snapshot.entries[id].map { Revision(generation: generation, sequence: $0.sequence) }
      guard current == revision else { throw PlaybackProgressJournalError.staleRevision }
      if payload == nil, let entry = snapshot.entries[id], entry.payload == nil {
        return Receipt(id: id, revision: Revision(generation: generation, sequence: entry.sequence))
      }
      guard snapshot.sequence < UInt64.max else { throw PlaybackProgressJournalError.limitExceeded }
      var next = snapshot
      next.sequence += 1
      next.entries[id] = Entry(sequence: next.sequence, payload: payload)
      let bytes = try Self.encode(next, ticketBytes: ticketBytes, key: key, limits: limits)
      do { try files.write(file, bytes) }
      catch {
        // The writer may have committed before reporting an error. Reopen to inspect the
        // actual file; an uncertain handle must never overwrite it from its older memory.
        self.key = nil
        throw error
      }
      snapshot = next
      return Receipt(id: id, revision: Revision(generation: generation, sequence: next.sequence))
    }
  }

  private static func currentContext(_ replica: Replica) throws -> Context {
    let identity = try replica.identity.availablePublicIdentity()
    let authority = try replica.authority()
    guard let member = authority.members[identity.id], member.key == identity,
      member.revokedAt == nil, let grant = member.current, grant.write,
      grant.namespaces.contains(Podcasts.namespace), grant.expires.map({ $0 > .now }) ?? true else {
      throw PlaybackProgressJournalError.noCurrentAccess
    }
    return Context(libraryID: authority.libraryID, member: identity)
  }

  private static func makeTicket(context: Context, identity: any Identity)
    throws -> (bytes: Data, generation: String, key: SymmetricKey) {
    let key = SymmetricKey(size: .bits256)
    let generation = UUID().uuidString.lowercased()
    let ticket = PlaybackProgressJournalTicket(purpose: PlaybackProgressJournalFormat.purpose,
      version: PlaybackProgressJournalFormat.version, namespace: Podcasts.namespace,
      libraryID: context.libraryID, member: context.member, generation: generation,
      key: try SealedKey(key, to: context.member))
    let signed = try SignedRecord(signing: Canonical.encode(ticket), with: identity)
    guard context.member.verify(signed) else { throw PlaybackProgressJournalError.invalidTicket }
    return (try Canonical.encode(signed), generation, key)
  }

  private static func validate(_ snapshot: Snapshot, limits: Limits) throws {
    guard snapshot.entries.count <= limits.maximumRecords else { throw PlaybackProgressJournalError.limitExceeded }
    var sequences: Set<UInt64> = []
    for (id, entry) in snapshot.entries {
      guard !id.isEmpty, id.utf8.count <= 256, entry.sequence > 0,
        entry.sequence <= snapshot.sequence, sequences.insert(entry.sequence).inserted else {
        throw PlaybackProgressJournalError.invalidSnapshot
      }
    }
  }

  private static func encode(_ snapshot: Snapshot, ticketBytes: Data, key: SymmetricKey, limits: Limits) throws -> Data {
    try validate(snapshot, limits: limits)
    let plaintext = try Canonical.encode(snapshot)
    guard plaintext.count <= limits.maximumPlaintextBytes else { throw PlaybackProgressJournalError.limitExceeded }
    guard let ciphertext = try AES.GCM.seal(plaintext, using: key, authenticating: ticketBytes).combined else {
      throw PlaybackProgressJournalError.invalidCiphertext
    }
    let bytes = try Canonical.encode(PlaybackProgressJournalEnvelope(ticket: ticketBytes, ciphertext: ciphertext))
    guard bytes.count <= limits.maximumFileBytes else { throw PlaybackProgressJournalError.limitExceeded }
    return bytes
  }
}

enum PlaybackProgressJournalFormat {
  static let purpose = "org.luff.taupe.playback-progress"
  static let version = 1
  static let maximumTicketBytes = 16_384
}

struct PlaybackProgressJournalTicket: Codable {
  let purpose: String
  let version: Int
  let namespace: String
  let libraryID: String
  let member: PublicIdentity
  let generation: String
  let key: SealedKey
}

struct PlaybackProgressJournalEnvelope: Codable {
  let ticket: Data
  let ciphertext: Data
}

struct PlaybackProgressJournalFiles: Sendable {
  let read: @Sendable (URL, Int) throws -> Data?
  let write: @Sendable (URL, Data) throws -> Void

  static let live = Self(read: { file, maximumBytes in
    do {
      let values = try file.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey])
      guard values.isRegularFile == true, values.isSymbolicLink != true else {
        throw PlaybackProgressJournalError.invalidSnapshot
      }
      guard let size = values.fileSize, size <= maximumBytes else {
        throw PlaybackProgressJournalError.limitExceeded
      }
      let data = try Data(contentsOf: file)
      guard data.count <= maximumBytes else { throw PlaybackProgressJournalError.limitExceeded }
      return data
    } catch let error as CocoaError where error.code == .fileReadNoSuchFile || error.code == .fileNoSuchFile {
      return nil
    }
  }, write: { file, data in
    let directory = file.deletingLastPathComponent()
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700])
    let values = try directory.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
    guard values.isDirectory == true, values.isSymbolicLink != true else {
      throw PlaybackProgressJournalError.invalidSnapshot
    }
    try data.write(to: file, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
  })
}

private extension Dictionary {
  func mapValuesWithKey<T>(_ transform: (Key, Value) throws -> T) rethrows -> [Key: T] {
    try Dictionary<Key, T>(uniqueKeysWithValues: map { (key, value) in (key, try transform(key, value)) })
  }
}
