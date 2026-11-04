import ColophonAuthority
import ColophonCore
import ColophonReplica
import Foundation
import Testing

@testable import ColophonStore

private final class CoordinationCounter: @unchecked Sendable {
  private let lock = NSLock()
  private var value = 0
  func increment() { lock.withLock { value += 1 } }
  var count: Int { lock.withLock { value } }
}

private final class DownloadRequests: @unchecked Sendable {
  private let lock = NSLock()
  private var urls: [URL] = []
  func append(_ url: URL) { lock.withLock { urls.append(url) } }
  var requested: [URL] { lock.withLock { urls } }
}

private final class ClaimGate: @unchecked Sendable {
  let started = DispatchSemaphore(value: 0)
  let release = DispatchSemaphore(value: 0)
  let finished = DispatchSemaphore(value: 0)
}

private final class WriteOutcome: @unchecked Sendable {
  let done = DispatchSemaphore(value: 0)
  private let lock = NSLock()
  private var value: Result<Void, Error>?

  func finish(_ work: () throws -> Void) {
    let result = Result { try work() }
    lock.withLock { value = result }
    done.signal()
  }

  func take() -> Result<Void, Error>? { lock.withLock { value } }
}

/// Holds a write claim until `release` so a reader can observe the deadline.
private func holdWriteClaim(_ file: URL, gate: ClaimGate) {
  var error: NSError?
  NSFileCoordinator().coordinate(writingItemAt: file, options: [], error: &error) { _ in
    gate.started.signal()
    gate.release.wait()
  }
  gate.finished.signal()
}

private func blockingRead(_ store: FolderStore, _ path: String) throws -> (Data?, Duration) {
  let start = ContinuousClock.now
  let data = try store.read(path)
  return (data, start.duration(to: .now))
}

private final class ReadOutcome: @unchecked Sendable {
  let done = DispatchSemaphore(value: 0)
  private let lock = NSLock()
  private var value: Result<(Data?, Duration), Error>?

  func finish(_ work: () throws -> (Data?, Duration)) {
    let result = Result { try work() }
    lock.withLock { value = result }
    done.signal()
  }

  func take() -> Result<(Data?, Duration), Error>? { lock.withLock { value } }
}

struct CloudCoordinationTests {
  @Test func absentReadReturnsNilWithoutCoordinating() throws {
    let root = FileManager.default.temporaryDirectory.appending(path: "colophon-absent-" + UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    var store = FolderStore(root)
    let counter = CoordinationCounter()
    store.willCoordinate = { counter.increment() }
    let missing = try store.read("note.json")
    let claims = counter.count
    #expect(missing == nil)
    #expect(claims == 0)
  }

  @Test func placeholderReadThrowsPendingWithoutCoordinating() throws {
    let root = FileManager.default.temporaryDirectory.appending(path: "colophon-placeholder-" + UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    try Data("placeholder".utf8).write(to: root.appending(path: ".note.json.icloud"))
    var store = FolderStore(root)
    let counter = CoordinationCounter()
    store.willCoordinate = { counter.increment() }

    var caught: ColophonError?
    do { _ = try store.read("note.json") }
    catch let error as ColophonError { caught = error }
    let beforePresent = counter.count
    #expect(caught == .pending("note.json"))
    #expect(beforePresent == 0)
    let described = ColophonError.pending("note.json").localizedDescription
    #expect(described == "note.json is still downloading from iCloud.")
    let failure = SupportEvent.Failure(ColophonError.pending("note.json"))
    #expect(failure.code == 16)

    try Data("hello".utf8).write(to: root.appending(path: "note.json"))
    let present = try store.read("note.json")
    let afterPresent = counter.count
    #expect(present == Data("hello".utf8))
    #expect(afterPresent == 1)
  }

  @Test func placeholderArrivingAfterPreflightStillReportsPending() throws {
    let root = FileManager.default.temporaryDirectory.appending(path: "colophon-evicted-" + UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    let file = root.appending(path: "note.json")
    let placeholder = root.appending(path: ".note.json.icloud")
    try Data("initial".utf8).write(to: file)
    let requests = DownloadRequests()
    var store = FolderStore(root, requestDownload: { requests.append($0) })
    store.willCoordinate = {
      try? FileManager.default.removeItem(at: file)
      try? Data("placeholder".utf8).write(to: placeholder)
    }

    var caught: ColophonError?
    do { _ = try store.read("note.json") }
    catch let error as ColophonError { caught = error }
    let expected = ColophonError.pending("note.json")
    let requested = requests.requested
    let expectedRequests: [URL] = [file]
    let placeholderExists = FileManager.default.fileExists(atPath: placeholder.path)
    #expect(caught == expected)
    #expect(requested == expectedRequests)
    #expect(placeholderExists)
  }

  @Test func readThrowsUnavailableWithinTheDeadlineWhileAWriteClaimIsHeld() throws {
    let root = FileManager.default.temporaryDirectory.appending(path: "colophon-claim-" + UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    let file = root.appending(path: "note.json")
    let bytes = Data("held".utf8)
    try bytes.write(to: file)
    let gate = ClaimGate()
    defer { gate.release.signal() }
    let holder = Thread { holdWriteClaim(file, gate: gate) }
    holder.start()
    let claimed = gate.started.wait(timeout: .now() + .seconds(5))
    #expect(claimed == .success)
    guard claimed == .success else { return }

    let outcome = ReadOutcome()
    let store = FolderStore(root, coordinationDeadline: .milliseconds(200))
    let reader = Thread { outcome.finish { try blockingRead(store, "note.json") } }
    reader.start()
    // A missing deadline must fail this test, not stall the suite. Releasing the claim lets a
    // blocked read finish so the expectation can run.
    let inTime = outcome.done.wait(timeout: .now() + .seconds(2))
    if inTime == .timedOut {
      gate.release.signal()
      let finished = outcome.done.wait(timeout: .now() + .seconds(5))
      #expect(finished == .success)
    }
    let blocked = try #require(outcome.take())
    #expect(inTime == .success)
    switch blocked {
    case .success:
      Issue.record("A local claim that misses its deadline must throw unavailable")
    case .failure(let error):
      let colophon = error as? ColophonError
      #expect(colophon == .unavailable("note.json"))
    }

    gate.release.signal()
    let releasedClaim = gate.finished.wait(timeout: .now() + .seconds(5))
    #expect(releasedClaim == .success)
    let fresh = FolderStore(root)
    let released = try fresh.read("note.json")
    #expect(released == bytes)
  }

  @Test func pendingOperationsStayPartialUntilTheirBytesArrive() throws {
    let namespace = "cloud.pending"
    let store = MemoryStore()
    let member = SoftwareIdentity()
    _ = try AuthorityHolder.create(in: store, label: "Pending", root: SoftwareIdentity(),
      firstMember: member.publicIdentity, memberLabel: "Member", role: .app, custody: .software,
      namespaces: [namespace])
    let writer = Replica(store: store, identity: member)
    let command = { (value: Int) in
      Command(namespace: namespace, kind: "cloud.add", payload: ["amount": .number(Double(value))])
    }
    let first = try writer.perform(command(1))
    _ = try writer.perform(command(2))
    let paths = store.snapshot.keys.filter { $0.hasPrefix("ops/") }.sorted()
    let gatedPath = try #require(paths.last)
    let gate = PendingOperationStore(base: store, gatedPath: gatedPath)
    let replica = Replica(store: gate, identity: member)

    let partial = try replica.read(namespace)
    let partialClocks = partial.operations.map(\.operation.clock)
    let incomplete = try replica.readComplete(namespace)
    #expect(partialClocks == [first.clock])
    #expect(incomplete == nil)

    gate.reveal()
    let completed = try #require(try replica.readComplete(namespace))
    let completedClocks = completed.operations.map(\.operation.clock)
    #expect(completedClocks == [1, 2])
  }

  @Test func ubiquitousClaimTimeoutThrowsPending() throws {
    let root = FileManager.default.temporaryDirectory
      .appending(path: "Mobile Documents", directoryHint: .isDirectory)
      .appending(path: "colophon-ubiquitous-claim-" + UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    let file = root.appending(path: "note.json")
    try Data("held".utf8).write(to: file)
    let gate = ClaimGate()
    defer { gate.release.signal() }
    let holder = Thread { holdWriteClaim(file, gate: gate) }
    holder.start()
    let claimed = gate.started.wait(timeout: .now() + .seconds(5))
    #expect(claimed == .success)
    guard claimed == .success else { return }

    let outcome = ReadOutcome()
    let store = FolderStore(root, coordinationDeadline: .milliseconds(200))
    let reader = Thread { outcome.finish { try blockingRead(store, "note.json") } }
    reader.start()
    let inTime = outcome.done.wait(timeout: .now() + .seconds(2))
    if inTime == .timedOut {
      gate.release.signal()
      let finished = outcome.done.wait(timeout: .now() + .seconds(5))
      #expect(finished == .success)
    }
    let blocked = try #require(outcome.take())
    #expect(inTime == .success)
    switch blocked {
    case .success:
      Issue.record("An iCloud claim that misses its deadline must throw pending")
    case .failure(let error):
      let colophon = error as? ColophonError
      #expect(colophon == .pending("note.json"))
    }
  }

  @Test func timedOutWaitingWriteDoesNotLandLater() throws {
    let root = FileManager.default.temporaryDirectory.appending(path: "colophon-late-write-" + UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    let file = root.appending(path: "note.json")
    let original = Data("original".utf8)
    try original.write(to: file)
    let gate = ClaimGate()
    defer { gate.release.signal() }
    let holder = Thread { holdWriteClaim(file, gate: gate) }
    holder.start()
    let claimed = gate.started.wait(timeout: .now() + .seconds(5))
    #expect(claimed == .success)
    guard claimed == .success else { return }

    let store = FolderStore(root, coordinationDeadline: .seconds(1), writeCoordinationDeadline: .milliseconds(200))
    let outcome = WriteOutcome()
    let writer = Thread { outcome.finish { try store.replace("note.json", Data("late".utf8)) } }
    writer.start()
    let inTime = outcome.done.wait(timeout: .now() + .seconds(2))
    if inTime == .timedOut {
      gate.release.signal()
      let finished = outcome.done.wait(timeout: .now() + .seconds(5))
      #expect(finished == .success)
    }
    #expect(inTime == .success)
    let result = try #require(outcome.take())
    switch result {
    case .success:
      Issue.record("A write still waiting for its claim must fail at the deadline")
    case .failure(let error):
      let colophon = error as? ColophonError
      #expect(colophon == .unavailable("note.json"))
    }
    gate.release.signal()
    let released = gate.finished.wait(timeout: .now() + .seconds(5))
    #expect(released == .success)
    let after = try FolderStore(root).read("note.json")
    #expect(after == original)
  }

  @Test func writeAlreadyInsidePerformWaitsForItsResult() throws {
    let root = FileManager.default.temporaryDirectory.appending(path: "colophon-running-write-" + UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    let file = root.appending(path: "note.json")
    try Data("original".utf8).write(to: file)
    let gate = ClaimGate()
    defer { gate.release.signal() }
    var configured = FolderStore(root, coordinationDeadline: .milliseconds(200), writeCoordinationDeadline: .milliseconds(200))
    configured.willPerform = {
      gate.started.signal()
      gate.release.wait()
    }
    let store = configured
    let outcome = WriteOutcome()
    let writer = Thread { outcome.finish { try store.replace("note.json", Data("landed".utf8)) } }
    writer.start()
    let entered = gate.started.wait(timeout: .now() + .seconds(5))
    #expect(entered == .success)
    guard entered == .success else { return }
    let early = outcome.done.wait(timeout: .now() + .milliseconds(800))
    #expect(early == .timedOut)
    gate.release.signal()
    let finished = outcome.done.wait(timeout: .now() + .seconds(5))
    #expect(finished == .success)
    let result = try #require(outcome.take())
    switch result {
    case .failure:
      Issue.record("A write already inside its accessor must return that accessor's result")
    case .success:
      break
    }
    let landed = try Data(contentsOf: file)
    #expect(landed == Data("landed".utf8))
  }
}

private final class PendingOperationStore: RecordStore, @unchecked Sendable {
  let base: MemoryStore
  let gatedPath: String
  private let lock = NSLock()
  private var revealed = false

  init(base: MemoryStore, gatedPath: String) {
    self.base = base
    self.gatedPath = gatedPath
  }

  func list(_ directory: String) throws -> [String] { try base.list(directory) }
  func read(_ path: String) throws -> Data? {
    if path == gatedPath, !lock.withLock({ revealed }) { return nil }
    return try base.read(path)
  }
  func create(_ path: String, _ data: Data) throws { try base.create(path, data) }
  func replace(_ path: String, _ data: Data) throws { try base.replace(path, data) }
  func reveal() { lock.withLock { revealed = true } }
}
