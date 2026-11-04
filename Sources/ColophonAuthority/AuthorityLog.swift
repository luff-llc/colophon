import ColophonCore
import ColophonStore
import Foundation

/// Reads a store's authority history. Entries are immutable, so verified ones are kept and only
/// new entries are read and checked on each refresh.
public final class AuthorityLog: @unchecked Sendable {
  public let store: any RecordStore
  private let lock = NSLock()
  // Protected by `lock`.
  private var records: [SignedRecord] = []
  private var cached: AuthorityState?

  public init(store: any RecordStore) { self.store = store }

  /// True when genesis exists, including when its bytes are still downloading.
  public var exists: Bool {
    do { return try store.read(LibraryPath.authority(1)) != nil }
    catch let error as ColophonError {
      switch error {
      case .pending, .unavailable: return true
      default: return false
      }
    } catch { return false }
  }

  /// Readable entries, stopping at a file that is still downloading. Does not publish a head.
  public func verifiedPrefix() throws -> AuthorityState? {
    let cached = lock.withLock { records }
    var candidate = cached
    var seq = candidate.count + 1
    while true {
      let data: Data?
      do { data = try store.read(LibraryPath.authority(seq)) }
      catch let error as ColophonError {
        if case .pending = error { break }
        throw error
      }
      guard let data else { break }
      candidate.append(try Canonical.decode(SignedRecord.self, from: data))
      seq += 1
    }
    if candidate.isEmpty { return nil }
    return try AuthorityState(records: candidate)
  }

  /// Drops the cached prefix so the next read sees bytes another writer replaced.
  public func invalidateCache() {
    lock.withLock {
      records = []
      cached = nil
    }
  }

  /// The current verified state.
  public func state() throws -> AuthorityState {
    try lock.withLock {
      var seq = records.count + 1
      var candidate = records
      while true {
        let data = try store.read(LibraryPath.authority(seq))
        guard let data else { break }
        candidate.append(try Canonical.decode(SignedRecord.self, from: data))
        seq += 1
      }
      if candidate.count != records.count || cached == nil {
        let state = try AuthorityState(records: candidate)
        // A later provider read, decode or verification failure must not advance the prefix
        // while leaving its cached state behind. Publish both only after the whole pass succeeds.
        records = candidate
        cached = state
      }
      guard let cached else { throw ColophonError.notALibrary }
      return cached
    }
  }

  /// Writes entries after `state.latest`. The intent, when this batch is an approval, is saved
  /// before the first create. A signature failure writes nothing.
  func append(_ drafts: [AuthorityEntry], signer: (AuthorityEntry) -> any Identity, after state: AuthorityState,
    intents: AuthorityIntentStore? = nil) throws
  {
    var previous = state.lastBody
    var seq = state.latest
    var prepared: [(Int, SignedRecord)] = []
    var numbered: [AuthorityEntry] = []
    for draft in drafts {
      seq += 1
      let entry = draft.numbered(seq, after: previous)
      let body = try Canonical.encode(entry)
      let record = try SignedRecord(signing: body, with: signer(entry))
      prepared.append((seq, record))
      numbered.append(entry)
      previous = body
    }
    if let intents, var intent = AuthorityWriteIntent.capture(libraryID: state.libraryID, drafts: numbered, state: state) {
      intent.sequences = prepared.map(\.0)
      intent.digests = prepared.map { Canonical.digest($0.1.body) }
      try intents.save(intent)
    }
    for (sequence, record) in prepared {
      try store.create(LibraryPath.authority(sequence), try Canonical.encode(record))
    }
  }
}
