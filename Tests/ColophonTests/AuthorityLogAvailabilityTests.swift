import ColophonAuthority
import ColophonCore
import ColophonStore
import Foundation
import Testing

struct AuthorityLogAvailabilityTests {
  @Test func pendingAuthorityFileIsNotTheHead() throws {
    let root = FileManager.default.temporaryDirectory.appending(path: "colophon-pending-head-" + UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let folder = FolderStore(root)
    let rootKey = SoftwareIdentity()
    let member = SoftwareIdentity()
    let (holder, _) = try AuthorityHolder.create(in: folder, label: "Pending", root: rootKey,
      firstMember: member.publicIdentity, memberLabel: "Member", custody: .software, namespaces: ["notes"])
    let log = AuthorityLog(store: folder)
    let before = try log.state()
    try holder.revoke(member.id)
    let revoked = try AuthorityLog(store: folder).state()
    let relative = LibraryPath.authority(revoked.latest)
    let file = root.appending(path: relative)
    let saved = try Data(contentsOf: file)
    try FileManager.default.removeItem(at: file)
    let placeholder = file.deletingLastPathComponent().appending(path: "." + file.lastPathComponent + ".icloud")
    try Data("cloud".utf8).write(to: placeholder)
    log.invalidateCache()

    var pending: ColophonError?
    do { _ = try log.state() }
    catch let error as ColophonError { pending = error }
    #expect(pending == .pending(relative))
    let prefix = try log.verifiedPrefix()
    let prefixLatest = prefix?.latest ?? -1
    #expect(prefixLatest >= before.latest)
    #expect(prefixLatest < revoked.latest)
    #expect(prefix?.members[member.id]?.revokedAt != nil)

    try saved.write(to: file)
    try FileManager.default.removeItem(at: placeholder)
    let restored = try log.state()
    #expect(restored.latest == revoked.latest)
    #expect(restored.members[member.id]?.revokedAt != nil)
  }

  @Test func placeholderGenesisStillCountsAsPresent() throws {
    let root = FileManager.default.temporaryDirectory.appending(path: "colophon-pending-genesis-" + UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    try FileManager.default.createDirectory(at: root.appending(path: "authority"), withIntermediateDirectories: true)
    try Data("cloud".utf8).write(to: root.appending(path: "authority/.00000001.json.icloud"))
    let present = AuthorityLog(store: FolderStore(root)).exists
    #expect(present)
  }

  enum Failure: CaseIterable { case read, decode, signature }
  enum Change: CaseIterable { case handover, revocation }

  @Test(arguments: Failure.allCases, Change.allCases)
  func repairedAuthorityRetriesFromLastVerifiedPrefix(failure: Failure, change: Change) throws {
    let memory = MemoryStore()
    let root = SoftwareIdentity()
    let nextRoot = SoftwareIdentity()
    let member = SoftwareIdentity()
    let (holder, _) = try AuthorityHolder.create(in: memory, label: "Synthetic", root: root,
      firstMember: member.publicIdentity, memberLabel: "Synthetic member", custody: .software,
      namespaces: ["notes"])
    let store = AuthorityReadFaultStore(base: memory)
    let observer = AuthorityLog(store: store)
    let before = try observer.state()
    switch change {
    case .handover: try holder.handOver(to: nextRoot.publicIdentity)
    case .revocation: try holder.revoke(member.id)
    }
    let expected = try AuthorityLog(store: memory).state()
    let path = LibraryPath.authority(expected.latest)
    let storedBytes = try memory.read(path)
    let originalBytes = try #require(storedBytes)
    switch failure {
    case .read:
      // All new records can be decoded before the provider denies the next path. A failed
      // pass must not consume those records while retaining an older cached state.
      store.failReading(LibraryPath.authority(expected.latest + 1))
    case .decode:
      memory.tamper(path, Data("incomplete provider bytes".utf8))
    case .signature:
      let record = try Canonical.decode(SignedRecord.self, from: originalBytes)
      let invalid = SignedRecord(body: record.body, signature: Data(repeating: 0, count: 64))
      memory.tamper(path, try Canonical.encode(invalid))
    }
    store.resetCounts()
    var refused = false
    do { _ = try observer.state() } catch { refused = true }
    #expect(refused, "Read, decode and verification failures must remain visible")
    store.failReading(nil)
    memory.tamper(path, originalBytes)
    let repaired = try observer.state()
    #expect(repaired.latest == expected.latest)
    #expect(repaired.root == expected.root)
    #expect(repaired.members[member.id]?.revokedAt == expected.members[member.id]?.revokedAt)
    switch change {
    case .handover:
      #expect(repaired.root == nextRoot.publicIdentity)
      _ = try AuthorityHolder(log: observer, root: nextRoot)
    case .revocation:
      #expect(repaired.members[member.id]?.revokedAt != nil)
    }
    // Error recovery may reread the new suffix; it must keep the verified prefix cached.
    let prefixReads = (1...before.latest).reduce(0) { $0 + store.readCount(LibraryPath.authority($1)) }
    #expect(prefixReads == 0)
    let settled = try observer.state()
    #expect(settled.latest == repaired.latest)
  }
}

private final class AuthorityReadFaultStore: RecordStore, @unchecked Sendable {
  let base: MemoryStore
  private let lock = NSLock()
  private var failedPath: String?
  private var counts: [String: Int] = [:]
  init(base: MemoryStore) { self.base = base }
  func failReading(_ path: String?) { lock.withLock { failedPath = path } }
  func resetCounts() { lock.withLock { counts.removeAll() } }
  func readCount(_ path: String) -> Int { lock.withLock { counts[path, default: 0] } }
  func list(_ directory: String) throws -> [String] { try base.list(directory) }
  func read(_ path: String) throws -> Data? {
    let fails = lock.withLock {
      counts[path, default: 0] += 1
      return failedPath == path
    }
    if fails { throw CocoaError(.fileReadNoPermission) }
    return try base.read(path)
  }
  func create(_ path: String, _ data: Data) throws { try base.create(path, data) }
  func replace(_ path: String, _ data: Data) throws { try base.replace(path, data) }
}
