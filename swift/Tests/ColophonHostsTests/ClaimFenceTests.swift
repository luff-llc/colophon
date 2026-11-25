import Foundation
import os
import SQLite3
import Testing
@testable import ColophonHosts
import ColophonSession

/// The fence across independent store clients: two clients of one storage racing to open in every interleaving of their
/// transactions, a rebuild racing an open, a superseded holder stopping within one beat, fences outside the range
/// refused, and the SQLite store's compare-and-set across two connections to one database file
/// (js/test06/claim-fence.test.ts, with the durable store this host ships).
@MainActor @Suite(.serialized) struct ClaimFenceTests {
    static let beat: Int64 = 400
    static func policy() throws -> String {
        var p = try #require(try JSONSerialization.jsonObject(with: Data(try sessionDefaultPolicy().utf8)) as? [String: Any])
        p["beatMs"] = beat; p["holderTimeoutMs"] = 1_500; p["askTimeoutMs"] = 300; p["presenceTimeoutMs"] = 1_500
        return json(p)
    }
    /// A carrier that carries nothing (these tests are about the store).
    struct Nowhere: CellCarrier {
        func attach(_ cell: any StreamCell) async throws { cell.linkUp() }
        func detach(_ cell: any StreamCell) async {}
        func sendSession(_ frame: String) async -> Bool { true }
        func onPass(_ listener: @escaping @Sendable () -> Void) async -> ListenerToken? { nil }
    }
    func open(_ store: any ClaimStore, _ clock: ManualClock, log: Log<CellHostEvent>? = nil) async throws -> SessionCellHost {
        let (first, _) = try await LocalAccount.pair()
        var options = CellHostOptions(account: try first.account(), carrier: Nowhere(), namespace: listening, cell: nowPlaying, store: store)
        options.clock = clock; options.policy = try Self.policy()
        return try await SessionCellHost.open(options) { log?.append($0) }
    }
    /// The hosts still acting once every fence check has had a beat to look.
    func survivors(_ clock: ManualClock, _ hosts: [SessionCellHost]) async -> [SessionCellHost] {
        for _ in 0..<200 {
            var busy = false
            for h in hosts { let s = await h.state; if s == .opening || s == .rebuilding { busy = true } }
            if !busy { break }
            try? await Task.sleep(for: .milliseconds(5))
        }
        await clock.advance(Self.beat + 1)
        await settle()
        var left: [SessionCellHost] = []
        for h in hosts where await h.state == .open { left.append(h) }
        return left
    }
    /// Every order of `a` copies of A and `b` copies of B.
    nonisolated static func interleavings(_ a: Int, _ b: Int) -> [[String]] {
        if a == 0 { return [Array(repeating: "B", count: b)] }
        if b == 0 { return [Array(repeating: "A", count: a)] }
        return interleavings(a - 1, b).map { ["A"] + $0 } + interleavings(a, b - 1).map { ["B"] + $0 }
    }

    @Test(arguments: interleavings(2, 2)) func twoClientsOpenAtOnceInEveryInterleavingExactlyOneHoldsTheCell(_ order: [String]) async throws {
        let storage = SteppedStorage()
        let clock = ManualClock()
        let a = Task { try? await open(storage.client("A"), clock) }
        let b = Task { try? await open(storage.client("B"), clock) }
        // Each open's first two transactions (its load and its reservation) run in this order; then everything runs.
        for tag in order { try await storage.release(tag) }
        storage.free()
        let hosts = [await a.value, await b.value].compactMap { $0 }
        let left = await survivors(clock, hosts)
        #expect(left.count == 1, "\(order)")
        for h in hosts { h.close() }
    }

    @Test(arguments: interleavings(1, 2)) func aRebuildRacesAnOpenInEveryInterleavingExactlyOneHoldsTheCell(_ order: [String]) async throws {
        let storage = SteppedStorage()
        storage.set(gated: false)
        let clock = ManualClock()
        let a = try await open(storage.client("A"), clock)
        storage.set(gated: true)
        // A rebuilds (its clock went back), reserving a new generation, while B opens.
        clock.jump(to: clock.mono - 1_000)
        a.linkDown()
        let b = Task { try? await open(storage.client("B"), clock) }
        for tag in order { try await storage.release(tag) }
        storage.free()
        let hosts = [a] + [await b.value].compactMap { $0 }
        // The manual clock went back 1 s: timers set before that are due 1 s later on it.
        await clock.advance(1_000)
        let left = await survivors(clock, hosts)
        #expect(left.count == 1, "\(order)")
        for h in hosts { h.close() }
    }

    @Test func aSupersededHolderStopsWithinOneBeatAndSendsNothingAfter() async throws {
        let store = MemoryClaimStore()
        let clock = ManualClock()
        let log = Log<CellHostEvent>()
        let a = try await open(store, clock, log: log)
        try await a.command("take", json: json(["command": "take", "state": NSNull()]))
        await settle()
        let replaced = clock.mono
        let b = try await open(store, clock)
        await clock.advance(Self.beat)
        await eventually { log.all.contains { if case .failed(.superseded, _) = $0 { true } else { false } } }
        let failed = try #require(log.all.firstIndex { if case .failed(.superseded, _) = $0 { true } else { false } })
        #expect(clock.mono - replaced <= Self.beat)
        for _ in 0..<10 { await clock.advance(Self.beat) }
        #expect(!log.all.dropFirst(failed).contains { shape($0).hasPrefix("sent:") })
        #expect(await a.state == .failed)
        #expect(await b.state == .open)
        a.close(); b.close()
    }

    @Test func fencesThatAreNotNonNegativeIntegersBelow2To53AreRefused() throws {
        for v: Int64 in [-1, 1 << 53, .max, .min] {
            #expect(throws: ClaimStoreError.badFence) { _ = try Fence(generation: v, seq: 0) }
            #expect(throws: ClaimStoreError.badFence) { _ = try Fence(generation: 1, seq: v) }
        }
        #expect(try Fence(generation: Fence.maximum, seq: Fence.maximum).generation == Fence.maximum)
        let f1 = try Fence(generation: 1, seq: 0), f2 = try Fence(generation: 1, seq: 1)
        #expect(compareAndSet(held: nil, record: StoredClaim(claim: nil, fence: f1), expected: nil) != nil)
        #expect(compareAndSet(held: StoredClaim(claim: nil, fence: f1), record: StoredClaim(claim: nil, fence: f1), expected: f1) == nil, "not greater")
        #expect(compareAndSet(held: StoredClaim(claim: nil, fence: f1), record: StoredClaim(claim: nil, fence: f2), expected: nil) == nil, "not the expected fence")
        #expect(compareAndSet(held: StoredClaim(claim: nil, fence: f2), record: StoredClaim(claim: nil, fence: f1), expected: f2) == nil, "never back")
    }

    // MARK: The SQLite store

    static func database() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("colophon-claims-\(UUID().uuidString)").appendingPathExtension("sqlite")
    }
    static func remove(_ url: URL) {
        for suffix in ["", "-wal", "-shm"] { try? FileManager.default.removeItem(atPath: url.path + suffix) }
    }

    @Test func theSQLiteStoreComparesAndSetsAndKeepsWhatItStoredAcrossConnections() async throws {
        let path = Self.database()
        defer { Self.remove(path) }
        let one = try await SQLiteClaimStore(path: path, name: "cell")
        #expect(try await one.load() == nil)
        let f1 = try Fence(generation: 1, seq: 0), f2 = try Fence(generation: 1, seq: 1), f3 = try Fence(generation: 2, seq: 0)
        #expect(try await one.save(StoredClaim(claim: nil, fence: f1), expected: nil) == .stored)
        #expect(try await one.save(StoredClaim(claim: "x", fence: f2), expected: nil) == .stale, "not the held fence")
        #expect(try await one.save(StoredClaim(claim: "x", fence: f1), expected: f1) == .stale, "not greater")
        #expect(try await one.save(StoredClaim(claim: "{\"claim\":1}", fence: f2), expected: f1) == .stored)
        // A second connection (another client) sees exactly what the first committed.
        let two = try await SQLiteClaimStore(path: path, name: "cell")
        #expect(try await two.load() == StoredClaim(claim: "{\"claim\":1}", fence: f2))
        #expect(try await two.fence() == f2)
        #expect(try await two.save(StoredClaim(claim: "y", fence: f3), expected: f1) == .stale, "a stale client writes nothing")
        #expect(try await one.load()?.claim == "{\"claim\":1}")
        // Another name in the same file is another cell.
        let other = try await SQLiteClaimStore(path: path, name: "other")
        #expect(try await other.load() == nil)
        #expect(try await other.save(StoredClaim(claim: nil, fence: f1), expected: nil) == .stored)
        #expect(try await one.fence() == f2)
        // The durability settings in force on a connection to the file.
        #expect(try Self.pragma(path, "journal_mode") == "wal")
    }

    @Test func manyClientsOfOneDatabaseRacingFromOneFenceStoreExactlyOnce() async throws {
        let path = Self.database()
        defer { Self.remove(path) }
        var clients: [SQLiteClaimStore] = []
        for _ in 0..<8 { clients.append(try await SQLiteClaimStore(path: path, name: "cell")) }
        for round in 0..<2 {
            let held = try await clients[0].fence()
            let base = held?.generation ?? 0
            let outcomes = try await withThrowingTaskGroup(of: SaveOutcome.self) { group in
                for (k, client) in clients.enumerated() {
                    let record = StoredClaim(claim: "round \(round) client \(k)", fence: try Fence(generation: base + 1, seq: Int64(k)))
                    group.addTask { try await client.save(record, expected: held) }
                }
                var all: [SaveOutcome] = []
                for try await outcome in group { all.append(outcome) }
                return all
            }
            #expect(outcomes.filter { $0 == .stored }.count == 1, "round \(round): \(outcomes)")
            let after = try await clients[3].fence()
            #expect(after?.generation == base + 1)
        }
    }

    @Test func twoHostsOnTwoConnectionsToOneDatabaseOpeningAtOnceLeaveExactlyOneHolder() async throws {
        for attempt in 0..<4 {
            let path = Self.database()
            defer { Self.remove(path) }
            let clock = ManualClock()
            let one = try await SQLiteClaimStore(path: path, name: "cell"), two = try await SQLiteClaimStore(path: path, name: "cell")
            let a = Task { try? await open(one, clock) }
            let b = Task { try? await open(two, clock) }
            let hosts = [await a.value, await b.value].compactMap { $0 }
            let left = await survivors(clock, hosts)
            #expect(left.count == 1, "attempt \(attempt): \(hosts.count) opened")
            for h in hosts { h.close() }
        }
    }

    @Test func aHostOnTheSQLiteStoreRestartsFromWhatItStored() async throws {
        let path = Self.database()
        defer { Self.remove(path) }
        let clock = ManualClock()
        let first = try await open(try await SQLiteClaimStore(path: path, name: "cell"), clock)
        try await first.command("take", json: json(["command": "take", "state": b64("anchor")]))
        await eventually { first.storedClaim?.contains("\"holder\"") == true }
        let stored = first.storedClaim
        first.close()
        await settle()
        // Another connection (a new process would open one) holds the same claim, under a fence the next host reserves above.
        let reopened = try await SQLiteClaimStore(path: path, name: "cell")
        #expect(try await reopened.load()?.claim == stored)
        let second = try await open(reopened, clock)
        #expect(try second.current?.isHolder() == true)
        #expect(try second.current?.gated() == true, "a restarted holder is gated (§S6)")
        second.close()
    }

    @Test func theSQLiteStoreFailsClosedOnADatabaseItDidNotMake() async throws {
        // A table of another definition.
        let foreign = Self.database()
        defer { Self.remove(foreign) }
        try Self.exec(foreign, "CREATE TABLE colophon_claims (name TEXT PRIMARY KEY, generation INTEGER, seq INTEGER, claim TEXT)")
        await #expect(throws: ClaimStoreError.self) { _ = try await SQLiteClaimStore(path: foreign, name: "cell") }
        // A file that is not a database.
        let garbage = Self.database()
        defer { Self.remove(garbage) }
        try Data(repeating: 0x5A, count: 4096).write(to: garbage)
        await #expect(throws: ClaimStoreError.self) { _ = try await SQLiteClaimStore(path: garbage, name: "cell") }
        // Values outside the fence's range or of another type cannot be stored behind the store's back either.
        let made = Self.database()
        defer { Self.remove(made) }
        _ = try await SQLiteClaimStore(path: made, name: "cell")
        #expect(throws: (any Error).self) { try Self.exec(made, "INSERT INTO colophon_claims VALUES ('cell', 9007199254740992, 0, NULL)") }
        #expect(throws: (any Error).self) { try Self.exec(made, "INSERT INTO colophon_claims VALUES ('cell', -1, 0, NULL)") }
        #expect(throws: (any Error).self) { try Self.exec(made, "INSERT INTO colophon_claims VALUES ('cell', 'one', 0, NULL)") }
        #expect(throws: (any Error).self) { try Self.exec(made, "INSERT INTO colophon_claims VALUES ('cell', 1, 0, x'00ff')") }
    }

    struct SQLFailure: Error { let message: String }
    static func exec(_ url: URL, _ sql: String) throws {
        var db: OpaquePointer?
        guard sqlite3_open(url.path, &db) == SQLITE_OK, let db else { throw SQLFailure(message: "open") }
        defer { sqlite3_close(db) }
        guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else { throw SQLFailure(message: String(cString: sqlite3_errmsg(db))) }
    }
    static func pragma(_ url: URL, _ name: String) throws -> String? {
        var db: OpaquePointer?
        guard sqlite3_open(url.path, &db) == SQLITE_OK, let db else { throw SQLFailure(message: "open") }
        defer { sqlite3_close(db) }
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(db, "PRAGMA \(name)", -1, &statement, nil) == SQLITE_OK, let statement else { throw SQLFailure(message: "prepare") }
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW else { return nil }
        return sqlite3_column_text(statement, 0).map { String(cString: $0) }
    }
}

/// One underlying storage and any number of client handles on it. Each read and each compare-and-set is one transaction,
/// applied atomically when the test lets it run; transactions of different handles interleave in the order the test picks.
final class SteppedStorage: Sendable {
    private struct State {
        var record: StoredClaim?
        var gated = true
        var pending: [(tag: String, run: @Sendable () -> Void)] = []
    }
    private let state = OSAllocatedUnfairLock(initialState: State())
    func set(gated: Bool) { state.withLock { $0.gated = gated } }
    func client(_ tag: String) -> any ClaimStore { Client(storage: self, tag: tag) }
    /// Runs one pending transaction of `tag`, waiting for it to be issued.
    func release(_ tag: String) async throws {
        for _ in 0..<2_000 {
            let run = state.withLock { s -> (@Sendable () -> Void)? in
                guard let k = s.pending.firstIndex(where: { $0.tag == tag }) else { return nil }
                return s.pending.remove(at: k).run
            }
            if let run { run(); await settle(1); return }
            try await Task.sleep(for: .milliseconds(2))
        }
        Issue.record("\(tag) issued no transaction")
    }
    /// Ungates and runs everything pending.
    func free() {
        let all = state.withLock { s -> [@Sendable () -> Void] in s.gated = false; let p = s.pending.map(\.run); s.pending = []; return p }
        for run in all { run() }
    }
    fileprivate func step<T: Sendable>(_ tag: String, _ body: @escaping @Sendable (inout StoredClaim?) -> T) async -> T {
        await withCheckedContinuation { continuation in
            let run: @Sendable () -> Void = { [state] in continuation.resume(returning: state.withLock { body(&$0.record) }) }
            let now = state.withLock { s -> Bool in if s.gated { s.pending.append((tag, run)); return false }; return true }
            if now { run() }
        }
    }
    private struct Client: ClaimStore {
        let storage: SteppedStorage
        let tag: String
        func load() async throws -> StoredClaim? { await storage.step(tag) { $0 } }
        func fence() async throws -> Fence? { await storage.step(tag) { $0?.fence } }
        func save(_ record: StoredClaim, expected: Fence?) async throws -> SaveOutcome {
            await storage.step(tag) { held in
                guard let next = compareAndSet(held: held, record: record, expected: expected) else { return .stale }
                held = next
                return .stored
            }
        }
    }
}
