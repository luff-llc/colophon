import ColophonAuthority
import ColophonCore
import ColophonStore
import CryptoKit
import Foundation
import Security

/// One member's view of a library (spec §8). Every client, including the root's own app, reads
/// and writes content through a replica, using only the keys it was given.
///
/// Records are immutable, so each one is verified and decrypted once and then cached; a refresh
/// reads only new files.
public final class Replica: @unchecked Sendable {
  public enum Membership: Sendable, Equatable {
    case pending
    case member(namespaces: [String], write: Bool)
    case revoked
  }

  public let store: any RecordStore
  public let identity: any Identity
  public let log: AuthorityLog

  private struct Decoded {
    let header: OperationHeader
    let operation: ColophonOperation
  }

  private struct PendingRead {
    let token: Int
    var notified: Bool
  }

  /// How many pending reads this fold cleared. Touched only while `lock` is held.
  private final class AvailabilityClears {
    var count = 0
  }

  private struct OperationFile: Equatable {
    let author: String
    let path: String
  }

  private struct ProjectionKey: Equatable {
    let namespace: String
    let libraryID: String
    let authorityHead: Int
    let files: [OperationFile]
    let availabilityGeneration: Int
  }

  private struct Projection {
    let key: ProjectionKey
    let view: ReplicaView
    let admission: Admission
    /// Present only while this exact projection is held in `projections`.
    let token: Int?
  }

  private let snapshotOwner = UUID()
  // Recursive only so an unexpected synchronous storage/identity callback can fail
  // explicitly rather than deadlock or append inside an unfinished write.
  private let writeLock = NSRecursiveLock()
  private var writeInProgress = false // Protected by writeLock.
  private let lock = NSLock()
  // Protected by `lock`: cached records, availability of operation paths that could not be read,
  // projection counters, and `authorityReads`.
  private var decoded: [String: Decoded] = [:]
  private var headers: [String: (header: OperationHeader, signed: Bool)] = [:]
  private var pendingReads: [String: PendingRead] = [:]
  private var knownOperationPaths: Set<String> = []
  private var pendingProbeOrder: [String] = []
  private var pendingProbeIndexes: [String: Int] = [:]
  private var nextProbeIndex = 0
  private var nextPendingToken = 0
  private var availabilityGeneration = 0
  private var projections: [String: Projection] = [:]
  private var nextProjectionToken = 0
  private var projectionBuilds = 0
  /// Calls to `authority()`. Protected by `lock`. Package tests use it; production does not.
  private var authorityReads = 0
  private static let availabilityProbeLimit = 32

  /// Deterministic work counter for package tests; never used to choose production behavior.
  var projectionBuildCount: Int { lock.withLock { projectionBuilds } }
  /// How many times `authority()` has read the folder. Protected by `lock`.
  var authorityReadCount: Int { lock.withLock { authorityReads } }

  public init(store: any RecordStore, identity: any Identity) {
    self.store = store
    self.identity = identity
    log = AuthorityLog(store: store)
  }

  public func authority() throws -> AuthorityState {
    lock.withLock { authorityReads += 1 }
    return try log.state()
  }

  public func membership() throws -> Membership {
    let identityID = try identity.availablePublicIdentity().id
    guard let member = try authority().members[identityID] else { return .pending }
    guard member.revokedAt == nil, let grant = member.current else { return .revoked }
    return .member(namespaces: grant.namespaces, write: grant.write)
  }

  // MARK: Joining

  /// Asks to join. The holder sees the request; both sides show the pairing code.
  @discardableResult
  public func requestEnrollment(label: String, role: MemberRole, namespaces: [String], keyOperator: String? = nil,
    write: Bool = true, app: String? = nil, device: String? = nil) throws -> EnrollmentRequest
  {
    let request = EnrollmentRequest(member: identity.publicIdentity, label: label, role: role, custody: identity.custody,
      namespaces: namespaces, keyOperator: keyOperator, write: write, app: app, device: device)
    let body = try Canonical.encode(request)
    try store.replace(LibraryPath.request(identity.id), Canonical.encode(SignedRecord(signing: body, with: identity)))
    return request
  }

  public func pairingCode() throws -> String {
    EnrollmentRequest.pairingCode(libraryID: try authority().libraryID, member: identity.publicIdentity)
  }

  // MARK: Reading

  /// Checks only operation paths previously listed but not yet readable. The generation changes
  /// once when their bytes become available, including when another reader observes them first.
  /// Each pass checks at most 32 pending paths in round-robin order; a larger cloud backlog can
  /// take several refreshes to detect. Decoding and admission remain in `read(_:)`.
  public func refreshOperationAvailability() -> Int {
    let pending = lock.withLock {
      var selected: [(path: String, token: Int)] = []
      selected.reserveCapacity(min(Self.availabilityProbeLimit, pendingProbeOrder.count))
      for _ in 0..<min(Self.availabilityProbeLimit, pendingProbeOrder.count) {
        if nextProbeIndex >= pendingProbeOrder.count { nextProbeIndex = 0 }
        let path = pendingProbeOrder[nextProbeIndex]
        nextProbeIndex += 1
        if let read = pendingReads[path], !read.notified {
          selected.append((path, read.token))
        }
      }
      return selected
    }
    for (path, token) in pending {
      let available: Bool
      do { available = try store.read(path) != nil }
      catch { available = false }
      guard available else { continue }
      lock.withLock {
        guard var read = pendingReads[path], read.token == token, !read.notified else { return }
        read.notified = true
        pendingReads[path] = read
        removePendingProbeLocked(path)
        availabilityGeneration += 1
      }
    }
    return lock.withLock { availabilityGeneration }
  }

  /// Maintains the round-robin set without scanning previous or already hydrated records.
  /// Call only while holding `lock`.
  private func removePendingProbeLocked(_ path: String) {
    guard let index = pendingProbeIndexes.removeValue(forKey: path) else { return }
    let lastIndex = pendingProbeOrder.count - 1
    if index != lastIndex {
      let moved = pendingProbeOrder[lastIndex]
      pendingProbeOrder[index] = moved
      pendingProbeIndexes[moved] = index
    }
    pendingProbeOrder.removeLast()
    nextProbeIndex = min(nextProbeIndex, pendingProbeOrder.count)
  }

  /// Folds a module's namespace into its state.
  public func state<M: DomainModule>(of module: M.Type) throws -> M.State { M.fold(try read(M.namespace)) }

  /// True when `read` can return without opening operation bytes. A cold or still-downloading
  /// namespace is false; callers on the main actor warm it elsewhere first.
  public func hasWarmProjection(for namespace: String) -> Bool {
    (try? lookup(namespace).cached) != nil
  }

  /// True while a listed operation has not returned bytes. `readComplete` stays nil until it does.
  public var hasPendingOperationReads: Bool { lock.withLock { !pendingReads.isEmpty } }

  /// Availability for the records discovered by the last projection read. No directory scan
  /// or coordinated byte read is needed. Every pending path is requested, not just the bounded
  /// passive availability probe. Counts describe known records, not verified domain history.
  public func operationDownloadProgress() throws -> RecordDownloadProgress {
    let (paths, pending) = lock.withLock { (knownOperationPaths, Set(pendingReads.keys)) }
    if let available = try store.downloadProgress(for: Array(paths), knownDownloaded: paths.subtracting(pending)) {
      return available
    }
    return RecordDownloadProgress(downloadedRecords: max(0, paths.count - pending.count), totalRecords: paths.count)
  }

  public func read(_ namespace: String) throws -> ReplicaView { try projection(namespace).view }

  /// Returns nil while a known operation is unavailable or the projection changed during
  /// the read. Callers that infer absence from history must not act on a partial view.
  public func readComplete(_ namespace: String) throws -> ReplicaView? {
    let first = try projection(namespace)
    if let view = installed(first) { return view }
    let moved = lock.withLock { availabilityGeneration != first.key.availabilityGeneration }
    guard moved else { return nil }
    return installed(try projection(namespace))
  }

  /// Capture a complete view for domain validation outside the write lock. Nil means
  /// known records are unavailable or the installed projection moved during capture.
  public func writeSnapshot(_ namespace: String) throws -> ReplicaWriteSnapshot? {
    let result = try projection(namespace)
    guard let view = installed(result), let token = result.token else { return nil }
    return ReplicaWriteSnapshot(view: view, owner: snapshotOwner, namespace: namespace, token: token)
  }

  /// Delivers exact selected reading.saved records from this Replica's complete snapshot.
  /// Each callback receives one record, so callers can stage evidence without accumulating
  /// all plaintext. Selection does not itself establish item scope; the reading domain must
  /// validate that closure before exporting. This extraction requires BoundedRecordStore;
  /// initial snapshot/authority acquisition still uses the existing generic read APIs.
  /// No authority records, namespace keys or source.native data are returned.
  public func readingOperationEvidence(for operationIDs: Set<String>, from snapshot: ReplicaWriteSnapshot,
    requiringFreshness: @Sendable () throws -> Void,
    consume: (ReplicaReadingOperationEvidence) throws -> Void) throws {
    let namespace = "reading.saved"
    guard snapshot.owner == snapshotOwner, snapshot.namespace == namespace,
      snapshot.view.namespace == namespace, let libraryID = snapshot.view.libraryID,
      snapshot.view.unreadable == 0 else { throw ReplicaReadingEvidenceError.wrongSnapshot }
    guard let bounded = store as? any BoundedRecordStore else { throw BoundedRecordReadError.unsupportedStore }
    func access() throws -> AuthorityState {
      try readingEvidenceAuthority(snapshot, requiringFreshness: requiringFreshness)
    }
    func checkSnapshot() throws {
      _ = try access()
      let found = try lookup(namespace)
      guard let cached = found.cached, cached.token == snapshot.token, installed(cached) != nil else {
        throw ReplicaWriteError.staleSnapshot
      }
      _ = try access()
    }
    try checkSnapshot()
    var counts: [String: Int] = [:]
    var selected: [AdmittedOperation] = []
    for entry in snapshot.view.operations where operationIDs.contains(entry.id) {
      try Task.checkCancellation()
      counts[entry.id, default: 0] += 1
      if entry.status == .admitted { selected.append(entry) }
    }
    for id in operationIDs {
      guard counts[id] == 1 else { throw ReplicaReadingEvidenceError.ambiguousOperation(id) }
    }
    guard selected.count == operationIDs.count else { throw ReplicaReadingEvidenceError.wrongSnapshot }
    for entry in selected {
      let state = try access()
      let path = LibraryPath.operation(author: entry.author, clock: entry.operation.clock, id: entry.id)
      guard let bytes = try bounded.read(path, maximumBytes: 64_000_000) else {
        throw ReplicaReadingEvidenceError.missingRecord(entry.id)
      }
      _ = try access()
      guard bytes.count <= 64_000_000 else {
        throw ReplicaReadingEvidenceError.exceedsLimits
      }
      let record = try Canonical.decode(SignedRecord.self, from: bytes)
      let header = try Canonical.decode(OperationHeader.self, from: record.body)
      guard header.author == entry.author, header.namespace == namespace,
        let author = state.members[entry.author], author.key.verify(record),
        let sealed = state.keys[namespace]?[header.epoch]?[identity.id] else {
        throw ReplicaReadingEvidenceError.invalidRecord(entry.id)
      }
      let plaintext = try AES.GCM.open(AES.GCM.SealedBox(combined: header.sealed), using: identity.open(sealed))
      guard plaintext.count <= 64_000_000,
        try Canonical.decode(ColophonOperation.self, from: plaintext) == entry.operation else {
        throw ReplicaReadingEvidenceError.invalidRecord(entry.id)
      }
      _ = try access()
      try consume(ReplicaReadingOperationEvidence(libraryID: libraryID, operation: entry.operation,
        authorID: entry.author, authorLabel: entry.authorLabel, authorRole: entry.authorRole,
        sourceSigningPublicKey: author.key.signing, plaintext: plaintext, signedRecord: bytes))
      _ = try access()
    }
    try checkSnapshot()
  }

  /// Opens one referenced reading blob with a pre-allocation transport cap. This is one
  /// bounded AES-GCM blob in memory, not streaming decryption or native-original custody.
  public func readingBlob(_ reference: BlobRef, maximumBytes: Int, from snapshot: ReplicaWriteSnapshot,
    requiringFreshness: @Sendable () throws -> Void) throws -> Data {
    guard maximumBytes >= 0, maximumBytes <= 128_000_000,
      reference.size >= 0, reference.size <= maximumBytes, reference.epoch >= 1,
      reference.digest.utf8.count == 64, reference.plain.utf8.count == 64,
      reference.digest.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
      reference.plain.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
      throw BoundedRecordReadError.exceedsLimit
    }
    guard let bounded = store as? any BoundedRecordStore else { throw BoundedRecordReadError.unsupportedStore }
    // Batch callers perform provider-list snapshot validation at their boundaries; each
    // blob checks the local token and fresh authority without rescanning the full journal.
    let state = try readingEvidenceAuthority(snapshot, requiringFreshness: requiringFreshness)
    guard let sealed = state.keys["reading.saved"]?[reference.epoch]?[identity.id] else { throw ColophonError.noAccess("reading.saved") }
    guard let cipher = try bounded.read(LibraryPath.blob(reference.digest), maximumBytes: reference.size + 28),
      cipher.count == reference.size + 28, Canonical.digest(cipher) == reference.digest else {
      throw ColophonError.malformed("Reading recovery blob")
    }
    _ = try readingEvidenceAuthority(snapshot, requiringFreshness: requiringFreshness)
    let data = try AES.GCM.open(AES.GCM.SealedBox(combined: cipher), using: identity.open(sealed))
    guard data.count == reference.size, Canonical.digest(data) == reference.plain else {
      throw ColophonError.malformed("Reading recovery blob")
    }
    _ = try readingEvidenceAuthority(snapshot, requiringFreshness: requiringFreshness)
    return data
  }

  private func readingEvidenceAuthority(_ snapshot: ReplicaWriteSnapshot,
    requiringFreshness: @Sendable () throws -> Void) throws -> AuthorityState {
    let namespace = "reading.saved"
    guard snapshot.owner == snapshotOwner, snapshot.namespace == namespace,
      snapshot.view.namespace == namespace, let libraryID = snapshot.view.libraryID,
      snapshot.view.unreadable == 0 else { throw ReplicaReadingEvidenceError.wrongSnapshot }
    try Task.checkCancellation(); try requiringFreshness()
    guard lock.withLock({ pendingReads.isEmpty && projections[namespace]?.token == snapshot.token }) else {
      throw ReplicaWriteError.staleSnapshot
    }
    let state = try authority(), memberID = try identity.availablePublicIdentity().id
    guard state.libraryID == libraryID else { throw ReplicaReadingEvidenceError.wrongSnapshot }
    guard let member = state.members[memberID], member.revokedAt == nil, let grant = member.current,
      grant.namespaces.contains(namespace) else { throw ColophonError.noAccess(namespace) }
    if let expiry = grant.expires, Date.now >= expiry { throw ColophonError.expired }
    try requiringFreshness(); try Task.checkCancellation()
    return state
  }

  private func installed(_ result: Projection) -> ReplicaView? {
    lock.withLock {
      guard let token = result.token, pendingReads.isEmpty,
        availabilityGeneration == result.key.availabilityGeneration,
        projections[result.key.namespace]?.token == token else { return nil }
      return result.view
    }
  }

  /// List every logical path before using a cached projection. This preserves discovery of
  /// external and earlier-clock operations even when this replica's own journal is warm.
  private func operationFiles() throws -> [OperationFile] {
    var files: [OperationFile] = []
    for author in try store.list(LibraryPath.operations) {
      for name in try store.list(LibraryPath.operations + "/" + author) {
        files.append(OperationFile(author: author, path: LibraryPath.operations + "/" + author + "/" + name))
      }
    }
    lock.withLock { knownOperationPaths.formUnion(files.map(\.path)) }
    return files
  }

  private struct ProjectionLookup {
    let identityID: String
    let state: AuthorityState
    let files: [OperationFile]
    let generation: Int
    let cached: Projection?
  }

  /// The installed projection when its key still matches the folder. Nil means the next read
  /// has to open operation bytes. Listing and authority reads do not open those bytes.
  private func lookup(_ namespace: String) throws -> ProjectionLookup {
    let identityID = try identity.availablePublicIdentity().id
    let state = try authority()
    let files = try operationFiles()
    let (generation, pending, cached) = lock.withLock {
      (availabilityGeneration, !pendingReads.isEmpty, projections[namespace])
    }
    let key = ProjectionKey(namespace: namespace, libraryID: state.libraryID, authorityHead: state.latest,
      files: files, availabilityGeneration: generation)
    // An unavailable record may hydrate without changing the logical path list. A direct read
    // keeps checking it immediately; the session's passive poll remains bounded separately.
    let hit: Projection?
    if !pending, let cached, cached.key == key,
      lock.withLock({ availabilityGeneration == generation && pendingReads.isEmpty &&
        projections[namespace]?.token == cached.token })
    {
      hit = cached
    } else { hit = nil }
    return ProjectionLookup(identityID: identityID, state: state, files: files, generation: generation, cached: hit)
  }

  private func projection(_ namespace: String) throws -> Projection {
    let found = try lookup(namespace)
    if let cached = found.cached { return cached }
    let identityID = found.identityID
    let state = found.state
    let files = found.files
    let generation = found.generation

    let keys = try (state.keys[namespace] ?? [:]).compactMapValues { sealed -> SymmetricKey? in
      guard let addressed = sealed[identityID] else { return nil }
      do { return try identity.open(addressed) }
      catch {
        let failure = error as NSError
        if failure.domain == NSOSStatusErrorDomain, failure.code == Int(errSecInteractionNotAllowed) {
          throw error
        }
        return nil
      }
    }
    var readable: [(path: String, decoded: Decoded)] = []
    var rejected: [RejectedOperation] = []
    var unreadable = 0
    let clears = AvailabilityClears()
    for file in files {
      switch load(file.path, folder: file.author, namespace: namespace, state: state, keys: keys, clears: clears) {
      case .decoded(let value): readable.append((file.path, value))
      case .otherNamespace, .notYet: continue
      case .unreadable: unreadable += 1
      case .rejected(let reason): rejected.append(RejectedOperation(path: file.path, reason: reason))
      }
    }
    readable.sort { order($0.decoded, $1.decoded) }
    var admission = Admission(state: state, namespace: namespace)
    var operations: [AdmittedOperation] = []
    for (path, value) in readable {
      guard let author = state.members[value.header.author] else { continue }
      switch admission.judge(value.operation, header: value.header, author: author) {
      case .success(let status):
        operations.append(AdmittedOperation(operation: value.operation, author: author.id, authorLabel: author.label,
          authorRole: author.role, status: status))
      case .failure(let refusal):
        rejected.append(RejectedOperation(path: path, reason: refusal.message))
      }
    }
    let view = ReplicaView(operations: operations, rejected: rejected, unreadable: unreadable,
      libraryID: state.libraryID, namespace: namespace)
    let key = ProjectionKey(namespace: namespace, libraryID: state.libraryID, authorityHead: state.latest,
      files: files, availabilityGeneration: generation)
    return lock.withLock {
      projectionBuilds += 1
      let now = availabilityGeneration
      // This fold may be what advanced the generation, by clearing the reads it was waiting on.
      // That complete result is cacheable. A generation move from somewhere else is not.
      let ownAdvance = now == generation + clears.count
      let complete = pendingReads.isEmpty && unreadable == 0 && (now == generation || ownAdvance)
      guard complete else {
        return Projection(key: key, view: view, admission: admission, token: nil)
      }
      let installedKey = ProjectionKey(namespace: namespace, libraryID: state.libraryID, authorityHead: state.latest,
        files: files, availabilityGeneration: now)
      nextProjectionToken += 1
      let result = Projection(key: installedKey, view: view, admission: admission, token: nextProjectionToken)
      projections[namespace] = result
      return result
    }
  }

  private enum Loaded {
    case decoded(Decoded)
    case otherNamespace, notYet, unreadable
    case rejected(String)
  }

  private func load(_ path: String, folder: String, namespace: String, state: AuthorityState,
    keys: [Int: SymmetricKey], clears: AvailabilityClears) -> Loaded
  {
    if let hit = lock.withLock({ decoded[path] }) {
      return hit.header.namespace == namespace ? .decoded(hit) : .otherNamespace
    }
    let cachedHeader = lock.withLock { headers[path] }
    let header: OperationHeader
    if let cachedHeader {
      guard cachedHeader.header.namespace == namespace else { return .otherNamespace }
      guard cachedHeader.signed else { return .rejected("Signature doesn't verify") }
      header = cachedHeader.header
    } else {
      let data: Data?
      do { data = try store.read(path) }
      catch { data = nil }
      guard let data else {
        let cachedDuringRead = lock.withLock {
          if decoded[path] != nil || headers[path] != nil { return true }
          nextPendingToken += 1
          pendingReads[path] = PendingRead(token: nextPendingToken, notified: false)
          if pendingProbeIndexes[path] == nil {
            pendingProbeIndexes[path] = pendingProbeOrder.count
            pendingProbeOrder.append(path)
          }
          return false
        }
        return cachedDuringRead ? load(path, folder: folder, namespace: namespace, state: state, keys: keys, clears: clears) : .notYet
      }
      defer {
        lock.withLock {
          if let pending = pendingReads.removeValue(forKey: path), !pending.notified {
            removePendingProbeLocked(path)
            availabilityGeneration += 1
            clears.count += 1
          }
        }
      }
      guard let record = try? Canonical.decode(SignedRecord.self, from: data),
        let parsed = try? Canonical.decode(OperationHeader.self, from: record.body)
      else { return .rejected("Not a record") }
      guard parsed.author == folder, let author = state.members[parsed.author] else {
        return parsed.namespace == namespace ? .rejected("Not written by a member") : .otherNamespace
      }
      let signed = author.key.verify(record)
      lock.withLock { headers[path] = (parsed, signed) }
      guard parsed.namespace == namespace else { return .otherNamespace }
      guard signed else { return .rejected("Signature doesn't verify") }
      header = parsed
    }
    guard let key = keys[header.epoch] else { return .unreadable }
    guard let plaintext = try? AES.GCM.open(AES.GCM.SealedBox(combined: header.sealed), using: key),
      let operation = try? Canonical.decode(ColophonOperation.self, from: plaintext)
    else { return .rejected("Can't be decrypted") }
    let value = Decoded(header: header, operation: operation)
    lock.withLock { decoded[path] = value }
    return .decoded(value)
  }

  /// The order every replica agrees on: clock, then author ID, then operation ID.
  private func order(_ a: Decoded, _ b: Decoded) -> Bool {
    (a.operation.clock, a.header.author, a.operation.id) < (b.operation.clock, b.header.author, b.operation.id)
  }

  /// Advance a warm projection after our own highest-clock write. The manifest comparison on
  /// the next read still discovers any external write made before or during this one.
  private func advanceProjection(_ prior: Projection, path: String, header: OperationHeader,
    operation: ColophonOperation, member: AuthorityState.Member, state: AuthorityState)
  {
    // A rejected readable operation may sort after this write even though its clock was
    // omitted from the admitted clock choice. A refund can then change that earlier refusal.
    guard let token = prior.token, prior.view.rejected.isEmpty, prior.key.libraryID == state.libraryID,
      prior.key.authorityHead == state.latest else { return }
    var admission = prior.admission
    guard case .success(let status) = admission.judge(operation, header: header, author: member) else {
      // Rejection order and budget effects are recomputed from the complete journal on demand.
      return
    }
    var operations = prior.view.operations
    operations.append(AdmittedOperation(operation: operation, author: member.id, authorLabel: member.label,
      authorRole: member.role, status: status))
    var files = prior.key.files
    var lower = 0
    var upper = files.count
    while lower < upper {
      let middle = lower + (upper - lower) / 2
      if files[middle].path < path { lower = middle + 1 } else { upper = middle }
    }
    files.insert(OperationFile(author: member.id, path: path), at: lower)
    let key = ProjectionKey(namespace: prior.key.namespace, libraryID: prior.key.libraryID,
      authorityHead: prior.key.authorityHead, files: files,
      availabilityGeneration: prior.key.availabilityGeneration)
    let view = ReplicaView(operations: operations, rejected: prior.view.rejected,
      unreadable: prior.view.unreadable, libraryID: prior.view.libraryID, namespace: prior.key.namespace)
    lock.withLock {
      guard availabilityGeneration == prior.key.availabilityGeneration, pendingReads.isEmpty,
        projections[prior.key.namespace]?.token == token else { return }
      nextProjectionToken += 1
      projections[prior.key.namespace] = Projection(key: key, view: view, admission: admission,
        token: nextProjectionToken)
    }
  }

  // MARK: Blobs

  /// Seals and stores large content for a namespace this member may write; reference it from an
  /// operation with the returned ref. Storing the same content twice is harmless.
  public func putBlob(_ data: Data, in namespace: String) throws -> BlobRef {
    let state = try authority()
    guard !state.needsRevocationRotation(in: namespace), !state.needsVaultRotationCompletion(in: namespace) else {
      throw ColophonError.keysCantDoThis(String(localized:
        "Your library's keys are still being updated. Open the device that started the change and try again."))
    }
    guard let member = state.members[identity.id], member.revokedAt == nil, let grant = member.current,
      grant.write, grant.namespaces.contains(namespace), let epoch = state.epoch(of: namespace),
      let sealed = state.keys[namespace]?[epoch]?[identity.id]
    else { throw ColophonError.noAccess(namespace) }
    guard let stored = try AES.GCM.seal(data, using: identity.open(sealed)).combined else {
      throw ColophonError.malformed("blob")
    }
    let digest = Canonical.digest(stored)
    do { try store.create(LibraryPath.blob(digest), stored) } catch ColophonError.alreadyExists {}
    return BlobRef(digest: digest, plain: Canonical.digest(data), epoch: epoch, size: data.count)
  }

  /// Opens a blob this member can read. Nil while it hasn't synced here yet.
  public func blob(_ ref: BlobRef, in namespace: String) throws -> Data? {
    guard let stored = try store.read(LibraryPath.blob(ref.digest)) else { return nil }
    guard Canonical.digest(stored) == ref.digest else { throw ColophonError.malformed("blob") }
    let state = try authority()
    guard let sealed = state.keys[namespace]?[ref.epoch]?[identity.id] else { throw ColophonError.noAccess(namespace) }
    let data = try AES.GCM.open(AES.GCM.SealedBox(combined: stored), using: identity.open(sealed))
    guard Canonical.digest(data) == ref.plain else { throw ColophonError.malformed("blob") }
    return data
  }

  // MARK: Writing

  /// Seals, signs and writes an operation to this member's own folder.
  @discardableResult
  public func perform(_ command: Command) throws -> ColophonOperation {
    try withWriteLock { try performLocked(command, snapshot: nil) }
  }

  /// Check the known complete view before signing, then append while local writes through
  /// this instance are serialized. External arrivals and independent Replica instances
  /// are not atomic with this check; this is not a distributed compare-and-append.
  @discardableResult
  public func perform(_ command: Command, ifUnchanged snapshot: ReplicaWriteSnapshot) throws -> ColophonOperation {
    try withWriteLock { try performLocked(command, snapshot: snapshot) }
  }

  private func withWriteLock<T>(_ work: () throws -> T) throws -> T {
    try writeLock.withLock {
      guard !writeInProgress else { throw ReplicaWriteError.reentrantWrite }
      writeInProgress = true
      defer { writeInProgress = false }
      return try work()
    }
  }

  private func performLocked(_ command: Command, snapshot: ReplicaWriteSnapshot?) throws -> ColophonOperation {
    let state: AuthorityState
    var guardedProjection: Projection?
    if let snapshot {
      guard snapshot.owner == snapshotOwner, snapshot.namespace == command.namespace else {
        throw ReplicaWriteError.staleSnapshot
      }
      // Listing and fresh authority discovery detect local changes since the caller's
      // observation. Never rebuild a domain projection under the write lock.
      let found = try lookup(command.namespace)
      guard let cached = found.cached, cached.token == snapshot.token, installed(cached) != nil else {
        throw ReplicaWriteError.staleSnapshot
      }
      state = found.state
      guardedProjection = cached
    } else {
      state = try authority()
      guardedProjection = nil
    }
    guard !state.needsRevocationRotation(in: command.namespace), !state.needsVaultRotationCompletion(in: command.namespace) else {
      throw ColophonError.keysCantDoThis(String(localized:
        "Your library's keys are still being updated. Open the device that started the change and try again."))
    }
    guard let member = state.members[identity.id] else { throw ColophonError.notAMember }
    guard member.revokedAt == nil, let grant = member.current else { throw ColophonError.revoked }
    if let expires = grant.expires, expires < .now { throw ColophonError.expired }
    guard grant.write, grant.namespaces.contains(command.namespace), let epoch = state.epoch(of: command.namespace),
      let sealed = state.keys[command.namespace]?[epoch]?[identity.id]
    else { throw ColophonError.noAccess(command.namespace) }
    let prior = try guardedProjection ?? projection(command.namespace)
    let clock = (prior.view.operations.last?.operation.clock ?? 0) + 1
    let operation = ColophonOperation(id: UUID().uuidString.lowercased(), kind: command.kind, v: command.v, clock: clock,
      authority: state.latest, created: .now, payload: command.payload)
    let plaintext = try Canonical.encode(operation)
    // Canonical encoding stores dates at second precision. Cache the value a fresh replica
    // will decode from these exact bytes, not the pre-encoding in-memory operation.
    let storedOperation = try Canonical.decode(ColophonOperation.self, from: plaintext)
    guard let ciphertext = try AES.GCM.seal(plaintext, using: identity.open(sealed)).combined else {
      throw ColophonError.malformed("operation")
    }
    let header = OperationHeader(author: identity.id, namespace: command.namespace, epoch: epoch, sealed: ciphertext)
    let record = try SignedRecord(signing: Canonical.encode(header), with: identity)
    let path = LibraryPath.operation(author: identity.id, clock: clock, id: operation.id)
    // A same-instance reader may have installed a newer view while signing. This is a
    // best-effort last check, not a lock on external writes or readers after this point.
    if snapshot != nil, installed(prior) == nil { throw ReplicaWriteError.staleSnapshot }
    try store.create(path, Canonical.encode(record))
    lock.withLock {
      headers[path] = (header, true)
      decoded[path] = Decoded(header: header, operation: storedOperation)
    }
    advanceProjection(prior, path: path, header: header, operation: storedOperation, member: member, state: state)
    return operation
  }
}
