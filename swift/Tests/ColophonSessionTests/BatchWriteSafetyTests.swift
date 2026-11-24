import Foundation
import Testing
import ColophonKeys
import ColophonSavedKit
@testable import ColophonSession

/// A member key that runs a hook on each signature, so a test can act at an exact point inside a batch.
private final class HookedKeys: AsyncKeyProvider, @unchecked Sendable {
    let base = SoftwareKeys()
    private let lock = NSLock()
    private var hook: (@Sendable (Int) async -> Void)?
    private var signed = 0
    /// Runs `hook` with the count of signatures made since it was set, before each later one is made.
    func onSign(_ hook: (@Sendable (Int) async -> Void)?) { lock.withLock { self.hook = hook; signed = 0 } }
    var form: KeyForm { base.form }
    var supportsPRF: Bool { base.supportsPRF }
    func assert(challenge: String, prfSalt: Data?) async throws -> KeyAssertion? { try await base.assert(challenge: challenge, prfSalt: prfSalt) }
    func prf(salt: Data) async throws -> SecretBytes? { try await base.prf(salt: salt) }
    func publicKeys() async throws -> PublicKeys { try await base.publicKeys() }
    func sign(body: Data) async throws -> Data {
        let (hook, count) = lock.withLock { () -> ((@Sendable (Int) async -> Void)?, Int) in signed += 1; return (hook, signed - 1) }
        await hook?(count)
        return try await base.sign(body: body)
    }
    func sharedSecret(peer: Data) async throws -> SecretBytes { try await base.sharedSecret(peer: peer) }
    func keyDescriptor() async throws -> KeyDescriptorView { try await base.keyDescriptor() }
}

/// A store that, once armed, fails to list `requests/` after its next write: the snapshot after a durable write fails.
private final class SnapshotFailingMedium: RecordMedium, @unchecked Sendable {
    let base = MemoryMedium()
    private let lock = NSLock()
    private var armed = false, failing = false
    func arm() { lock.withLock { armed = true } }
    func listing() throws -> [MediumEntry] { try base.listing() }
    func listing(prefix: String) throws -> [MediumEntry] {
        if prefix == "requests/", lock.withLock({ let fail = failing; failing = false; return fail }) {
            throw StorageError.unavailable("the requests listing failed")
        }
        return try base.listing(prefix: prefix)
    }
    func read(_ path: String) throws -> Data { try base.read(path) }
    func readBlob(_ path: String) throws -> Data { try base.readBlob(path) }
    func write(_ writes: [MediumWrite]) throws {
        try base.write(writes)
        lock.withLock { if armed { armed = false; failing = true } }
    }
    func changes() -> AsyncStream<Void> { base.changes() }
}

@MainActor struct BatchWriteSafetyTests {
    private func link(_ id: String) throws -> DomainCommand {
        try .saveLink(id: id, url: URL(string: "https://example.org/\(id)")!, title: id.uppercased())
    }
    private func ids(_ session: ColophonSession) async throws -> Set<String> {
        Set(try await SavedStore(session: session).load(ItemsQuery(limit: 100)).get().rows.map { $0.id })
    }
    private func interruption(_ body: () async throws -> Void) async -> BatchInterruption? {
        do { try await body(); Issue.record("the batch was not interrupted"); return nil }
        catch let error as BatchInterruption { return error }
        catch { Issue.record("not an interruption: \(error)"); return nil }
    }

    /// A write moves `revision` by exactly one, a batch too, and a refusal leaves it where the refresh put it.
    @Test func aWriteAndABatchEachMoveTheRevisionByOne() async throws {
        let device = Device()
        await device.session.create()
        let start = device.session.revision
        try await device.session.perform(try link("a"), observed: device.session.observedRevision)
        #expect(device.session.revision == start &+ 1)
        try await device.session.perform([try link("b"), try link("c"), try link("d")], observed: device.session.observedRevision)
        #expect(device.session.revision == start &+ 2)
        let stale = ObservedRevision(context: device.session.observedRevision.context, revision: start)
        await #expect(throws: SessionError.staleRevision) { _ = try await device.session.perform([try link("e")], observed: stale) }
        #expect(device.session.revision == start &+ 2)
    }

    /// Another device's write is found by the batch's reconcile: the revision the caller observed is stale and nothing is
    /// written. After a refresh the same batch goes through.
    @Test func anExternalChangeFoundByTheReconcileMakesTheBatchStale() async throws {
        let first = Device()
        await first.session.create()
        let observed = first.session.observedRevision
        let other = Device(medium: first.medium, member: first.member, owner: first.owner)
        await other.session.restore()
        try #require(other.session.phase == .ready, "\(other.session.phase)")
        try await other.session.perform(try link("elsewhere"), observed: other.session.observedRevision)
        await #expect(throws: SessionError.staleRevision) { _ = try await first.session.perform([try link("a")], observed: observed) }
        let elsewhere: Set<String> = ["elsewhere"]
        #expect(try await ids(first.session) == elsewhere)
        _ = try await first.session.perform([try link("a")], observed: first.session.observedRevision)
        let both: Set<String> = ["elsewhere", "a"]
        #expect(try await ids(first.session) == both)
    }

    /// A write budget spent mid-batch refuses the command that would exceed it; the commands before it are kept.
    @Test func aWriteBudgetSpentMidBatchStopsIt() async throws {
        let first = Device()
        await first.session.create()
        let second = Device(medium: first.medium)
        await second.session.restore()
        try await approveByScan(joining: second.session, approving: first.session,
                                grant: GrantOptions(namespaces: nil, access: nil, expires: nil, writeBudget: 2))
        await second.session.refresh()
        try #require(second.session.phase == .ready, "\(second.session.phase) \(second.session.lastError ?? "")")
        let stopped = await interruption {
            _ = try await second.session.perform([try link("a"), try link("b"), try link("c"), try link("d")], observed: second.session.observedRevision)
        }
        let stop = try #require(stopped)
        #expect(stop.index == 2, "\(stop.error)")
        #expect(stop.receipts.count == 2)
        guard case ColophonError.refused(_, let reason, _) = stop.error else { Issue.record("expected a refusal, got \(stop.error)"); return }
        #expect(reason == "budgetSpent")
        // A refusal other than a denial fails the session's phase, as for a single write; a relaunch reads what is kept.
        let relaunched = second.relaunch()
        await relaunched.restore()
        let kept: Set<String> = ["a", "b"]
        #expect(try await ids(relaunched) == kept)
    }

    /// The clock moves before each command of a batch: a grant that expires while the batch signs refuses the rest.
    @Test func aGrantThatExpiresMidBatchRefusesTheRest() async throws {
        let clock = Clock()
        let first = Device(clock: { clock.now })
        await first.session.create()
        let keys = HookedKeys()
        let second = Device(medium: first.medium, keys: keys, clock: { clock.now })
        await second.session.restore()
        let expires = ISO8601DateFormatter().string(from: clock.now.addingTimeInterval(3600))
        try await approveByScan(joining: second.session, approving: first.session,
                                grant: GrantOptions(namespaces: nil, access: nil, expires: expires, writeBudget: nil))
        await second.session.refresh()
        try #require(second.session.phase == .ready, "\(second.session.phase) \(second.session.lastError ?? "")")
        keys.onSign { count in if count == 0 { clock.advance(by: 7200) } }
        let stopped = await interruption {
            _ = try await second.session.perform([try link("a"), try link("b"), try link("c")], observed: second.session.observedRevision)
        }
        keys.onSign(nil)
        let stop = try #require(stopped)
        #expect(stop.index == 1, "\(stop.error)")
        #expect(stop.receipts.count == 1)
    }

    /// A query made while a batch signs waits for it to persist, so it never shows a command the store then refuses.
    @Test func aReadDuringABatchNeverShowsWhatTheStoreRefuses() async throws {
        let keys = HookedKeys()
        let device = Device(keys: keys)
        await device.session.create()
        let session = device.session, worker = device.session.worker, medium = device.medium
        final class Box: @unchecked Sendable {
            let lock = NSLock(); var task: Task<Set<String>?, Never>?; var done = false
        }
        let box = Box()
        keys.onSign { count in
            guard count == 1 else { return }
            // The first command is admitted; the store will refuse the batch.
            medium.setFault(.failWrite(after: 0))
            let task = Task { @MainActor in
                let seen = try? await Set(SavedStore(session: session).load(ItemsQuery(limit: 10)).get().rows.map { $0.id })
                box.lock.withLock { box.done = true }
                return seen
            }
            box.lock.withLock { box.task = task }
            // Until the read either waits for the batch or (without the wait) has already read.
            while await worker.waitingReads == 0, !box.lock.withLock({ box.done }) { await Task.yield() }
        }
        await #expect(throws: StorageError.self) {
            _ = try await session.perform([try link("a"), try link("b")], observed: session.observedRevision)
        }
        keys.onSign(nil)
        medium.setFault(.none)
        let read = try #require(box.lock.withLock { box.task })
        let seen = await read.value
        #expect(seen?.contains("a") != true, "the read showed an operation the store refused: \(seen ?? [])")
    }

    /// A snapshot that fails after the batch is durable does not hide it: the receipts come back, the error is reported,
    /// and a refresh publishes the written items.
    @Test func aSnapshotFailureAfterADurableBatchKeepsItsReceipts() async throws {
        let medium = SnapshotFailingMedium()
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: home) }
        let session = ColophonSession(configuration: .init(memberLabel: "Test device", namespaces: ["reading.saved"], location: .medium(medium),
            privateContainer: home, keys: SoftwareKeys(), ownerController: SoftwareKeys(), createWithoutHome: true, deviceSecrets: MemoryDeviceSecrets()))
        await session.create()
        try #require(session.phase == .ready)
        medium.arm()
        let receipts = try await session.perform([try link("a"), try link("b")], observed: session.observedRevision)
        #expect(receipts.count == 2)
        #expect(session.lastError?.contains("requests listing failed") == true, "\(session.lastError ?? "")")
        await session.refusalRefresh?.value
        #expect(session.phase == .ready, "\(session.phase)")
        let written: Set<String> = ["a", "b"]
        #expect(try await ids(session) == written)
    }
}
