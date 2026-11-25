import Dispatch
import Foundation
import SQLite3

/// A durable claim store in one row of a SQLite database, through the system's SQLite (`libsqlite3`, part of the OS).
///
/// **The compare-and-set.** `save` runs `BEGIN IMMEDIATE`, reads the held row, compares, writes and commits in that one
/// transaction. `BEGIN IMMEDIATE` takes the database's write lock before the read, so of any number of clients of the
/// same file (other instances, processes, app extensions sharing a container) exactly one is between its read and its
/// commit at a time, and each compares against the fence the previous commit left: the save is linearizable across
/// every client. A client that cannot take the lock within `busyTimeout` fails the save (an error, never `.stale`).
///
/// **Durability.** The database runs in WAL mode with `synchronous = FULL` and `fullfsync = ON`: a commit returns only
/// after its WAL frames are synced with `F_FULLFSYNC` (which on Apple platforms also flushes the drive's cache), so
/// `.stored` means the claim survives a crash or power loss. In WAL mode a commit becomes visible to other connections
/// only when it updates the WAL index, after that sync, so no reader sees a fence that could still be withdrawn.
/// (`synchronous = NORMAL` would make a commit visible before it is synced, and could lose the last commits on power
/// loss; it is not used.) Checkpoints use `F_FULLFSYNC` too (`checkpoint_fullfsync`).
///
/// **Failing closed.** The database is the store's alone: it may hold exactly the claim table and its key's index, and
/// any other schema object (a trigger, a view, another table or index), found when it opens or inside any read or write
/// transaction, is an error. Every write is read back inside its transaction and must be exactly what was written, or
/// it rolls back. The table is `STRICT` with range checks, and every read checks each column's type and range: a row it
/// cannot validate is an error from `load`, `fence` and `save`, never skipped. Every setting above is read back on both
/// connections when they open (SQLite ignores an unknown pragma silently); a connection that does not report it cannot
/// be opened.
///
/// Each instance is one client with two connections: one writes (every `save`), one reads (`load` and the per-beat
/// `fence`), so a slow write does not delay a fence check. Several cells may share one database file under different
/// `name`s.
public final class SQLiteClaimStore: ClaimStore {
    /// The table every claim store uses. The database holds nothing else: see `expectedSchema`.
    public static let schema = """
        CREATE TABLE colophon_claims (name TEXT PRIMARY KEY NOT NULL, \
        generation INTEGER NOT NULL CHECK (generation BETWEEN 0 AND 9007199254740991), \
        seq INTEGER NOT NULL CHECK (seq BETWEEN 0 AND 9007199254740991), \
        claim TEXT) STRICT
        """
    public let name: String
    private let writer: SQLiteConnection
    private let reader: SQLiteConnection

    /// Opens (creating it if needed) the store for `name` in the database at `path`, a file used for claims only.
    /// `busyTimeout` bounds how long a save waits for another client's write.
    ///
    /// On iOS, iPadOS, visionOS, tvOS and watchOS the database and its `-wal` and `-shm` files get
    /// `completeUntilFirstUserAuthentication` protection, set and read back as each one appears
    /// (`ClaimFileProtection`).
    public init(path: URL, name: String, busyTimeout: Duration = .seconds(5)) async throws {
        self.name = name
        let ms = Int32(clamping: busyTimeout.components.seconds * 1000 + busyTimeout.components.attoseconds / 1_000_000_000_000_000)
        writer = try SQLiteConnection(path: path.path, busyTimeoutMs: ms, label: "org.luff.colophon.claims.write")
        try await writer.prepareSchema()
        reader = try SQLiteConnection(path: path.path, busyTimeoutMs: ms, label: "org.luff.colophon.claims.read")
        try await reader.checkSchema()
    }

    public func load() async throws -> StoredClaim? { try await reader.read(name) }
    public func fence() async throws -> Fence? { try await reader.read(name)?.fence }
    public func save(_ record: StoredClaim, expected: Fence?) async throws -> SaveOutcome {
        try await writer.compareAndSet(name, record: record, expected: expected)
    }

    /// What each connection reports for the settings the store requires (tests).
    func settings() async throws -> [[String: String]] { [try await writer.settings(), try await reader.settings()] }
    /// Faults injected for tests: the reader's reads fail, or the writer fails after its write and before its commit.
    func inject(readsFail: Bool = false, failBeforeCommit: Bool = false) async {
        await reader.inject(readsFail: readsFail, failBeforeCommit: false)
        await writer.inject(readsFail: false, failBeforeCommit: failBeforeCommit)
    }
}

/// One SQLite connection, used only on its own serial queue (the actor's executor): SQLite's calls block, on a
/// sync or on another client's lock, and never run on the cooperative pool.
actor SQLiteConnection {
    private let queue: DispatchSerialQueue
    nonisolated var unownedExecutor: UnownedSerialExecutor { queue.asUnownedSerialExecutor() }
    /// Closes the connection when the actor goes.
    private final class Connection {
        let db: OpaquePointer
        init(_ db: OpaquePointer) { self.db = db }
        deinit { sqlite3_close_v2(db) }
    }
    private let connection: Connection
    private var readsFail = false
    private var failBeforeCommit = false
    private let path: String
    /// Whether the database, `-wal` and `-shm` files all have the protection class (checked until they do).
    private var protected = false

    /// Every object the database may hold, as `sqlite_schema` lists them (`type`, `name`, `tbl_name`, `sql`), sorted:
    /// the table and the index SQLite makes for its primary key. Besides these only SQLite's own tables (named
    /// `sqlite_`, which no statement can create: `sqlite_stat1` after `ANALYZE`, `sqlite_sequence`) may appear; they
    /// carry no behaviour. Anything else (a trigger, a view, another table or index) could change what a write does or
    /// what a read sees, and the store refuses the database.
    static let expectedSchema: [[String?]] = [
        ["index", "sqlite_autoindex_colophon_claims_1", "colophon_claims", nil],
        ["table", "colophon_claims", "colophon_claims", SQLiteClaimStore.schema],
    ]

    init(path: String, busyTimeoutMs: Int32, label: String) throws {
        queue = DispatchSerialQueue(label: label, qos: .userInitiated)
        self.path = path
        var handle: OpaquePointer?
        var flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX | SQLITE_OPEN_EXRESCODE
        #if !os(macOS)
        flags |= SQLITE_OPEN_FILEPROTECTION_COMPLETEUNTILFIRSTUSERAUTHENTICATION
        #endif
        let rc = sqlite3_open_v2(path, &handle, flags, nil)
        guard rc == SQLITE_OK, let handle else {
            let message = handle.map { String(cString: sqlite3_errmsg($0)) } ?? "code \(rc)"
            if let handle { sqlite3_close_v2(handle) }
            throw ClaimStoreError.storage("the claim database could not be opened: \(message)")
        }
        do { try Self.configure(handle, busyTimeoutMs: busyTimeoutMs) } catch {
            sqlite3_close_v2(handle)
            throw error
        }
        connection = Connection(handle)
    }

    /// Sets and verifies the protection class on the files that exist, until all three have it.
    private func protect() throws {
        guard !protected else { return }
        protected = try ClaimFileProtection.ensure([path, path + "-wal", path + "-shm"]).count == 3
    }

    /// Sets every setting the store's guarantees rest on, and reads each one back: SQLite accepts an unknown or
    /// ignored pragma silently, so a setting is in force only when the connection reports it.
    private static func configure(_ db: OpaquePointer, busyTimeoutMs: Int32) throws {
        guard sqlite3_busy_timeout(db, busyTimeoutMs) == SQLITE_OK else { throw failure(db, "the claim database refused a busy timeout") }
        let mode = try text(db, "PRAGMA journal_mode = WAL")
        guard mode?.lowercased() == "wal" else { throw ClaimStoreError.storage("the claim database refused WAL mode (\(mode ?? "none"))") }
        for setting in ["synchronous = FULL", "fullfsync = ON", "checkpoint_fullfsync = ON", "trusted_schema = OFF"] {
            try exec(db, "PRAGMA " + setting)
        }
        let required: [(String, String)] = [("journal_mode", "wal"), ("synchronous", "2"), ("fullfsync", "1"), ("checkpoint_fullfsync", "1"),
                                             ("trusted_schema", "0"), ("busy_timeout", String(busyTimeoutMs))]
        for (pragma, value) in required {
            let got = try text(db, "PRAGMA " + pragma)?.lowercased()
            guard got == value else { throw ClaimStoreError.storage("the claim database reports \(pragma) = \(got ?? "nothing"), not \(value)") }
        }
    }

    private func handle() throws -> OpaquePointer { connection.db }
    func settings() throws -> [String: String] {
        let db = try handle()
        var out: [String: String] = [:]
        for pragma in ["journal_mode", "synchronous", "fullfsync", "checkpoint_fullfsync", "trusted_schema", "busy_timeout"] {
            out[pragma] = try Self.text(db, "PRAGMA " + pragma)
        }
        return out
    }
    func inject(readsFail: Bool, failBeforeCommit: Bool) { self.readsFail = readsFail; self.failBeforeCommit = failBeforeCommit }

    /// Creates the table in an empty database, then checks that the database holds exactly what the store creates.
    func prepareSchema() throws {
        let db = try handle()
        try Self.exec(db, "BEGIN IMMEDIATE")
        do {
            if try Self.objects(db).isEmpty { try Self.exec(db, SQLiteClaimStore.schema) }
            try Self.checkSchema(db)
            try Self.exec(db, "COMMIT")
        } catch {
            Self.rollback(db)
            throw error
        }
        try protect()
    }
    /// Fails unless the database holds exactly the store's table and its key's index.
    func checkSchema() throws { try Self.checkSchema(try handle()) }

    /// The held row, read in one transaction that first checks the schema.
    func read(_ name: String) throws -> StoredClaim? {
        if readsFail { throw ClaimStoreError.storage("the claim database could not be read (injected)") }
        let db = try handle()
        try Self.exec(db, "BEGIN")
        do {
            try Self.checkSchema(db)
            let held = try Self.held(db, name)
            try Self.exec(db, "COMMIT")
            return held
        } catch {
            Self.rollback(db)
            throw error
        }
    }

    /// The compare-and-set: under the write lock (`BEGIN IMMEDIATE`), check the schema, read, compare, write, read the
    /// row back and require it to be exactly what was written, then commit. Anything unexpected rolls back and throws.
    func compareAndSet(_ name: String, record: StoredClaim, expected: Fence?) throws -> SaveOutcome {
        let db = try handle()
        try Self.exec(db, "BEGIN IMMEDIATE")
        do {
            try Self.checkSchema(db)
            let held = try Self.held(db, name)
            guard let next = ColophonHosts.compareAndSet(held: held, record: record, expected: expected) else {
                try Self.exec(db, "ROLLBACK")
                return .stale
            }
            let sql = """
                INSERT INTO colophon_claims (name, generation, seq, claim) VALUES (?1, ?2, ?3, ?4)
                ON CONFLICT (name) DO UPDATE SET generation = excluded.generation, seq = excluded.seq, claim = excluded.claim
                """
            try Self.withStatement(db, sql) { statement in
                try Self.bind(db, statement, 1, name)
                sqlite3_bind_int64(statement, 2, next.fence.generation)
                sqlite3_bind_int64(statement, 3, next.fence.seq)
                if let claim = next.claim { try Self.bind(db, statement, 4, claim) } else { sqlite3_bind_null(statement, 4) }
                let rc = sqlite3_step(statement)
                guard rc == SQLITE_DONE else { throw Self.failure(db, "the claim could not be written") }
                guard sqlite3_changes(db) == 1 else { throw ClaimStoreError.storage("the claim write changed \(sqlite3_changes(db)) rows") }
            }
            guard try Self.held(db, name) == next else { throw ClaimStoreError.storage("the claim read back is not the claim written") }
            if failBeforeCommit { throw ClaimStoreError.storage("the claim write failed before its commit (injected)") }
            // The commit point: it returns only after the WAL is synced (synchronous = FULL, fullfsync).
            try Self.exec(db, "COMMIT")
        } catch {
            Self.rollback(db)
            throw error
        }
        // The first write creates the -wal and -shm files: they get the protection class before success is reported.
        try protect()
        return .stored
    }

    // MARK: Statements

    private static let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

    private static func failure(_ db: OpaquePointer, _ what: String) -> ClaimStoreError {
        .storage("\(what): \(String(cString: sqlite3_errmsg(db))) (\(sqlite3_extended_errcode(db)))")
    }
    private static func exec(_ db: OpaquePointer, _ sql: String) throws {
        guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else { throw failure(db, "the claim database refused a statement") }
    }
    private static func rollback(_ db: OpaquePointer) {
        if sqlite3_get_autocommit(db) == 0 { sqlite3_exec(db, "ROLLBACK", nil, nil, nil) }
    }
    private static func withStatement<T>(_ db: OpaquePointer, _ sql: String, _ body: (OpaquePointer) throws -> T) throws -> T {
        var statement: OpaquePointer?
        guard sqlite3_prepare_v3(db, sql, -1, 0, &statement, nil) == SQLITE_OK, let statement else { throw failure(db, "a claim statement could not be prepared") }
        defer { sqlite3_finalize(statement) }
        return try body(statement)
    }
    private static func bind(_ db: OpaquePointer, _ statement: OpaquePointer, _ index: Int32, _ text: String) throws {
        guard sqlite3_bind_text(statement, index, text, -1, transient) == SQLITE_OK else { throw failure(db, "a claim value could not be bound") }
    }
    /// The first column of the first row of `sql`, as text.
    private static func text(_ db: OpaquePointer, _ sql: String) throws -> String? {
        try withStatement(db, sql) { statement in
            let rc = sqlite3_step(statement)
            guard rc == SQLITE_ROW else {
                if rc == SQLITE_DONE { return nil }
                throw failure(db, "the claim database refused a statement")
            }
            return sqlite3_column_text(statement, 0).map { String(cString: $0) }
        }
    }
    /// Every object in the database's schema, sorted.
    private static func objects(_ db: OpaquePointer) throws -> [[String?]] {
        try withStatement(db, "SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type, name") { statement in
            var rows: [[String?]] = []
            while true {
                let rc = sqlite3_step(statement)
                if rc == SQLITE_DONE { return rows }
                guard rc == SQLITE_ROW else { throw failure(db, "the claim database's schema could not be read") }
                rows.append((0..<4).map { c in sqlite3_column_text(statement, Int32(c)).map { String(cString: $0) } })
            }
        }
    }
    private static func checkSchema(_ db: OpaquePointer) throws {
        let own = try objects(db).filter { !($0[0] == "table" && ($0[1] ?? "").hasPrefix("sqlite_") && $0[1] == $0[2]) }
        guard own == expectedSchema else {
            throw ClaimStoreError.unreadable("the claim database holds something other than the claim table")
        }
    }
    /// The row held for `name`, validated column by column.
    private static func held(_ db: OpaquePointer, _ name: String) throws -> StoredClaim? {
        let sql = "SELECT typeof(generation), typeof(seq), typeof(claim), generation, seq, claim FROM colophon_claims WHERE name = ?1"
        return try withStatement(db, sql) { statement in
            try bind(db, statement, 1, name)
            let rc = sqlite3_step(statement)
            if rc == SQLITE_DONE { return nil }
            guard rc == SQLITE_ROW else { throw failure(db, "the claim could not be read") }
            func type(_ column: Int32) -> String { sqlite3_column_text(statement, column).map { String(cString: $0) } ?? "" }
            guard type(0) == "integer", type(1) == "integer", ["text", "null"].contains(type(2)) else {
                throw ClaimStoreError.unreadable("the stored claim has a column of the wrong type")
            }
            let fence: Fence
            do { fence = try Fence(generation: sqlite3_column_int64(statement, 3), seq: sqlite3_column_int64(statement, 4)) } catch {
                throw ClaimStoreError.unreadable("the stored claim's fence is out of range")
            }
            var claim: String?
            if type(2) == "text" {
                guard let bytes = sqlite3_column_blob(statement, 5) else { throw ClaimStoreError.unreadable("the stored claim could not be read") }
                let data = Data(bytes: bytes, count: Int(sqlite3_column_bytes(statement, 5)))
                guard let text = String(data: data, encoding: .utf8) else { throw ClaimStoreError.unreadable("the stored claim is not UTF-8") }
                claim = text
            }
            guard sqlite3_step(statement) == SQLITE_DONE else { throw ClaimStoreError.unreadable("more than one claim is stored under one name") }
            return StoredClaim(claim: claim, fence: fence)
        }
    }
}
