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
        return try base.sign(body: body)
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

/// A store whose next write fails without writing anything: read back, its paths are missing, so the outcome is unknown.
private final class UnverifiableMedium: RecordMedium, @unchecked Sendable {
    let base = MemoryMedium()
    private let lock = NSLock()
    private var armed = false
    func arm() { lock.withLock { armed = true } }
    func listing() throws -> [MediumEntry] { try base.listing() }
    func read(_ path: String) throws -> Data { try base.read(path) }
    func readBlob(_ path: String) throws -> Data { try base.readBlob(path) }
    func write(_ writes: [MediumWrite]) throws {
        if lock.withLock({ let fire = armed; armed = false; return fire }) { throw StorageError.unavailable("the disk went away") }
        try base.write(writes)
    }
    func changes() -> AsyncStream<Void> { base.changes() }
}

/// A store that, once armed, refuses the write `failing` calls later (0 is the next one) and writes nothing for it.
private final class CountingMedium: RecordMedium, @unchecked Sendable {
    let base = MemoryMedium()
    private let lock = NSLock()
    private var countdown: Int?
    func fail(after writes: Int) { lock.withLock { countdown = writes } }
    func listing() throws -> [MediumEntry] { try base.listing() }
    func read(_ path: String) throws -> Data { try base.read(path) }
    func readBlob(_ path: String) throws -> Data { try base.readBlob(path) }
    func write(_ writes: [MediumWrite]) throws {
        let refuse = lock.withLock { () -> Bool in
            guard let left = countdown else { return false }
            if left == 0 { countdown = nil; return true }
            countdown = left - 1; return false
        }
        if refuse { throw StorageError.unavailable("the disk refused the write") }
        try base.write(writes)
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
        // The phase to judge is the one the refresh and the store's change notices settle on.
        await session.refusalRefresh?.value
        await session.flushExternalChanges()
        #expect(session.phase == .ready, "\(session.phase)")
        let written: Set<String> = ["a", "b"]
        #expect(try await ids(session) == written)
    }


    /// A store failure whose outcome cannot be read back is reported as possibly recorded, not as nothing written.
    @Test func aWriteWhoseOutcomeCannotBeReadBackSaysSo() async throws {
        let medium = UnverifiableMedium()
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: home) }
        let session = ColophonSession(configuration: .init(memberLabel: "Test device", namespaces: ["reading.saved"], location: .medium(medium),
            privateContainer: home, keys: SoftwareKeys(), ownerController: SoftwareKeys(), createWithoutHome: true, deviceSecrets: MemoryDeviceSecrets()))
        await session.create()
        try #require(session.phase == .ready)
        medium.arm()
        do {
            try await session.perform(try link("a"), observed: session.observedRevision)
            Issue.record("the write was reported as saved")
        } catch StorageError.unavailable(let reason) {
            #expect(reason.contains("may have been recorded"), "\(reason)")
        }
        // The next refresh settles it: here the write never reached the store.
        await session.refresh()
        #expect(session.phase == .ready, "\(session.phase)")
        #expect(try await ids(session).isEmpty)
    }

    /// A drained envelope whose write is durable is saved and acknowledged even when the session's journal cannot be
    /// saved, so it is not written again.
    @Test func aDurableIngressWriteIsAcknowledgedWhenTheJournalCannotBeSaved() async throws {
        let device = Device()
        await device.session.create()
        let library = try #require(device.session.libraryID), member = try #require(device.session.memberID)
        let group = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: group) }
        let inbox = IngressInbox(appGroupContainer: group)
        try await inbox.enqueue(IngressEnvelope(libraryID: library, memberID: member, command: try link("shared")))
        // A directory where the journal goes: every save of it fails.
        let journal = device.home.appendingPathComponent("session.json")
        try? FileManager.default.removeItem(at: journal)
        try FileManager.default.createDirectory(at: journal.appendingPathComponent("blocked"), withIntermediateDirectories: true)
        let results = try await device.session.drain(inbox)
        #expect(results.values.allSatisfy { if case .saved = $0 { true } else { false } }, "\(results)")
        #expect(try await inbox.pending().isEmpty, "the envelope was acknowledged")
        _ = try await device.session.drain(inbox)
        let once: Set<String> = ["shared"]
        #expect(try await ids(device.session) == once)
        #expect(try await SavedStore(session: device.session).load(ItemsQuery(limit: 10)).get().total == 1)
    }

    /// A store that refuses command 2 of 4 stops the batch there: commands 0 and 1 are durable after a reopen, and
    /// nothing from 2 on is written.
    @Test func aStoreFailureMidBatchKeepsThePrefix() async throws {
        let medium = CountingMedium()
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: home) }
        let member = SoftwareKeys(), owner = SoftwareKeys(), secrets = MemoryDeviceSecrets()
        func session() -> ColophonSession {
            ColophonSession(configuration: .init(memberLabel: "Test device", namespaces: ["reading.saved"], location: .medium(medium),
                privateContainer: home, keys: member, ownerController: owner, createWithoutHome: true, deviceSecrets: secrets))
        }
        let first = session()
        await first.create()
        try #require(first.phase == .ready)
        medium.fail(after: 2)
        let stopped = await interruption {
            _ = try await first.perform([try link("a"), try link("b"), try link("c"), try link("d")], observed: first.observedRevision)
        }
        let stop = try #require(stopped)
        #expect(stop.index == 2)
        #expect(stop.receipts.count == 2)
        #expect(stop.error is StorageError, "\(stop.error)")
        let reopened = session()
        await reopened.restore()
        #expect(reopened.phase == .ready, "\(reopened.phase) \(reopened.lastError ?? "")")
        let prefix: Set<String> = ["a", "b"]
        #expect(try await ids(reopened) == prefix)
    }
}
