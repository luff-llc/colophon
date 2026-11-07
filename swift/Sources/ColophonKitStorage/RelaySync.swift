import Foundation
import CryptoKit

public enum RelaySyncState: Equatable, Sendable {
    /// No relay is configured.
    case disabled
    case idle
    case syncing
    /// The relay is unreachable. Local reads and writes continue; nothing is assumed missing.
    case offline(reason: String)
    /// The relay refused the storage token. Replace it; sync stops retrying quickly.
    case unauthorized
    case error(reason: String)
}

/// Synchronizes a local record store with one relay slot (spec §8.4). The local store stays the
/// source of truth: the relay only ever adds records to it, and absence on the relay is never
/// deletion. Records are immutable, so listing both sides is enough to reconcile them.
///
/// Work is proportional to the change: the change feed is read from a persisted cursor, the
/// relay's known paths live in an append-only private log, local records are enumerated by path
/// and only records that must be pushed or compared are read. Blob chunks (`blobs/<sha256>`) are
/// pushed before records so a manifest never reaches a peer ahead of its ciphertext, and are
/// pulled lazily with `fetchBlob(_:)`.
public actor RelaySync {
    public struct Report: Equatable, Sendable {
        public var pulled: Int = 0
        public var pushed: Int = 0
        /// Paths whose relay bytes differ from the local record. Local bytes are kept.
        public var conflicts: [String] = []
        /// Encrypted blob chunks uploaded in this pass.
        public var pushedBlobs: Int = 0
        /// Local record bodies read in this pass (pushes, conflict checks, the genesis check).
        public var localRecordReads: Int = 0
        /// Change-feed entries listed in this pass.
        public var listed: Int = 0
        public init() {}
    }
    private struct State: Codable {
        var relay: String
        var cursor: String?
        var conflicts: [String]?
        /// Legacy format (before the append-only log); migrated on load.
        var remote: [String: String]?
    }

    public nonisolated let endpoint: RelayEndpoint
    private let local: any RecordStore
    private let client: RelayClient
    private let stateFile: URL?
    private var cursor: String?
    private var remote: [String: String] = [:]
    private var conflicts = Set<String>()
    private var loaded = false
    private var listedOnce = false
    private var genesisChecked = false
    private var unsavedRemote: [(String, String?)] = []
    private var stateDirty = false
    private var occupied = false
    private var waiters: [CheckedContinuation<Void, Never>] = []
    private let parallelism = 8

    /// `stateFile` (private container, never the shared library) remembers the cursor; the
    /// relay's known paths are kept beside it in `<name>-remote.log`. Without it every launch
    /// relists the slot.
    private let namespaces: [String]
    private let validateAuthority: (@Sendable ([String: Data]) async throws -> Void)?
    private let verifyLive: (@Sendable (String, Data) async throws -> UInt64)?
    public init(local: any RecordStore, endpoint: RelayEndpoint, transport: any RelayTransport = URLSessionRelayTransport(), stateFile: URL? = nil, namespaces: [String] = [], verifyLive: (@Sendable (String, Data) async throws -> UInt64)? = nil, validateAuthority: (@Sendable ([String: Data]) async throws -> Void)? = nil) {
        self.local = local; self.endpoint = endpoint; self.stateFile = stateFile; self.namespaces = namespaces
        self.verifyLive = verifyLive
        self.validateAuthority = validateAuthority
        client = RelayClient(endpoint: endpoint, transport: transport)
    }

    /// True once a listing of the relay has completed in this process.
    public var hasListed: Bool { listedOnce }

    /// True when the relay's listing, as last seen, holds `path` (a record or blob chunk).
    public func relayHolds(_ path: String) throws -> Bool {
        try loadState(); return remote[path] != nil
    }

    /// One complete pass: list, pull what the local store lacks, push what the relay lacks.
    /// Throws `RelayError` without changing local records it could not verify.
    @discardableResult public func sync() async throws -> Report {
        await enter(); defer { exit() }
        try loadState()
        var report = Report()
        let listed = try await list()
        report.listed = listed.count
        let localPaths = try await local.syncPaths(namespaces: namespaces)
        let genesis = "authority/00000001.json"
        if localPaths.contains(genesis), let theirs = remote[genesis], !genesisChecked || listed[genesis] != nil {
            let mine = try await local.read(paths: [genesis])
            report.localRecordReads += mine.count
            if let bytes = mine[genesis], Self.sha256(bytes) != theirs { throw RelayError.differentLibrary }
            genesisChecked = true
        }
        // Pull: every listed record the local store lacks, verified against the listing.
        var missing = remote.keys.filter { path in
            !localPaths.contains(path) && !RecordPath.isReplaceable(path) && (try? RecordPath.validate(path)) != nil
        }.sorted(by: Self.pullOrder)
        var pulledPaths = Set<String>()
        if let validateAuthority {
            let authorityMissing = missing.filter { $0.hasPrefix("authority/") }
            let fetched = try await fetch(authorityMissing)
            if !fetched.isEmpty { try await local.append(fetched); pulledPaths.formUnion(fetched.keys); report.pulled += fetched.count }
            let paths = localPaths.filter { $0.hasPrefix("authority/") }.union(authorityMissing)
            let authority = try await local.read(paths: Array(paths))
            report.localRecordReads += authority.count
            if !authority.isEmpty { try await validateAuthority(authority) }
            missing.removeAll { $0.hasPrefix("authority/") }
        }
        for batch in stride(from: 0, to: missing.count, by: 256).map({ Array(missing[$0..<min(missing.count, $0 + 256)]) }) {
            let fetched = try await fetch(batch)
            if !fetched.isEmpty {
                try await local.append(fetched)
                pulledPaths.formUnion(fetched.keys)
                report.pulled += fetched.count
            }
        }
        // Conflicts: only immutable paths whose listing changed in this pass and that this store already held.
        let compare = listed.keys.filter { localPaths.contains($0) && !pulledPaths.contains($0) && (try? RecordPath.validate($0)) != nil && !RecordPath.isReplaceable($0) }
        if !compare.isEmpty {
            let bytes = try await local.read(paths: compare)
            report.localRecordReads += bytes.count
            for (path, data) in bytes {
                if Self.sha256(data) != remote[path] { conflicts.insert(path) } else { conflicts.remove(path) }
            }
        }
        // Blob chunks first: a peer that sees a manifest must be able to fetch its ciphertext.
        if let blobs = local as? any BlobStore {
            let unpushed = try await blobs.blobPaths().keys.filter { remote[$0] == nil }.sorted()
            for start in stride(from: 0, to: unpushed.count, by: parallelism) {
                let batch = unpushed[start..<min(unpushed.count, start + parallelism)]
                var chunks: [(String, String, Data)] = []
                for path in batch {
                    let bytes = try await blobs.readBlob(path)
                    let sha = Self.sha256(bytes)
                    // A local chunk that fails its content address is never uploaded.
                    if "blobs/" + sha == path { chunks.append((path, sha, bytes)) }
                }
                try await withThrowingTaskGroup(of: (String, String, RelayClient.PutResult).self) { group in
                    for (path, sha, bytes) in chunks {
                        group.addTask { [client] in (path, sha, try await client.putIfAbsent(path, bytes: bytes)) }
                    }
                    for try await (path, sha, result) in group {
                        switch result {
                        case .created: report.pushedBlobs += 1; remember(path, sha)
                        case .present: remember(path, sha)
                        case .conflict: conflicts.insert(path)
                        }
                    }
                }
            }
        }
        // Push: every local record the relay lacks. 200 and 201 both mean it now holds it.
        let unpushed = localPaths.filter { remote[$0] == nil && !RecordPath.isReplaceable($0) }.sorted(by: Self.pullOrder)
        for batchStart in stride(from: 0, to: unpushed.count, by: 64) {
            let batch = Array(unpushed[batchStart..<min(unpushed.count, batchStart + 64)])
            let records = try await local.read(paths: batch)
            report.localRecordReads += records.count
            for start in stride(from: 0, to: batch.count, by: parallelism) {
                let slice = batch[start..<min(batch.count, start + parallelism)]
                try await withThrowingTaskGroup(of: (String, String, RelayClient.PutResult).self) { group in
                    for path in slice {
                        guard let bytes = records[path] else { continue }
                        let sha = Self.sha256(bytes)
                        group.addTask { [client] in (path, sha, try await client.putIfAbsent(path, bytes: bytes)) }
                    }
                    for try await (path, sha, result) in group {
                        switch result {
                        case .created: report.pushed += 1; remember(path, sha)
                        case .present: remember(path, sha)
                        case .conflict: conflicts.insert(path)
                        }
                    }
                }
            }
        }
        // History/intent has been persisted on both sides before a live slot is promoted.
        // Validate the signed/decrypted generation, then CAS the exact version read before
        // the network wait. A racing local playback write wins and is retried next pass.
        if let verifyLive {
            let slots = Set(localPaths.filter(RecordPath.isReplaceable)).union(remote.keys.filter(RecordPath.isReplaceable))
            for path in slots.sorted() {
                let mine = try await local.read(paths: [path])[path]
                report.localRecordReads += mine == nil ? 0 : 1
                if let mine, Self.sha256(mine) == remote[path] { continue }
                let theirs = try await client.get(path)
                if let theirs, Self.sha256(theirs) != remote[path] { continue } // feed raced: relist
                let mineGeneration = if let mine { try? await verifyLive(path, mine) } else { nil as UInt64? }
                let theirGeneration = if let theirs { try? await verifyLive(path, theirs) } else { nil as UInt64? }
                if let theirs, let theirGeneration, mineGeneration == nil || theirGeneration > mineGeneration! {
                    if try await local.replaceLive(path, expected: mine, bytes: theirs) { report.pulled += 1 }
                } else if let mine, let mineGeneration, theirGeneration == nil || mineGeneration > theirGeneration! {
                    let result = try await client.putIfAbsent(path, bytes: mine, replacing: theirs.map(Self.sha256))
                    if result != .conflict { remember(path, Self.sha256(mine)); report.pushed += 1 }
                } else if mineGeneration != nil, mine != theirs { conflicts.insert(path) }
            }
        }
        try saveState()
        report.conflicts = conflicts.sorted()
        return report
    }

    /// Lazily fetches one encrypted chunk the local store lacks, verifies that its bytes hash to
    /// its name, and appends it to the local blob store. Returns nil when the relay lacks it too.
    /// Resumable by construction: each verified chunk is durable before the next is requested.
    public func fetchBlob(_ path: String) async throws -> Data? {
        try BlobPath.validate(path)
        guard let blobs = local as? any BlobStore else { throw StorageError.unavailable("The local store keeps no blobs") }
        guard let bytes = try await client.get(path, maximumBytes: 65536 + 16) else { return nil }
        guard "blobs/" + Self.sha256(bytes) == path else {
            throw RelayError.protocolViolation("Blob chunk does not match its content address: \(path)")
        }
        try await blobs.appendBlob(path, bytes: bytes)
        try loadState()
        if remote[path] == nil { remember(path, String(path.dropFirst(6))); try saveState() }
        return bytes
    }

    /// Long-polls the relay's change feed after the saved cursor, outside the pass gate.
    /// Returns true when the relay reports entries this device has not listed yet.
    public func waitForRemoteChanges(seconds: Int) async throws -> Bool {
        try loadState()
        let page = try await client.changes(after: cursor, limit: 1, wait: max(0, min(30, seconds)), namespaces: namespaces)
        return !page.entries.isEmpty
    }

    /// Authority first, then requests, then operations, so a partial pull is most useful.
    private static func pullOrder(_ a: String, _ b: String) -> Bool {
        func rank(_ p: String) -> Int { p.hasPrefix("authority/") ? 0 : p.hasPrefix("requests/") ? 1 : 2 }
        return (rank(a), a) < (rank(b), b)
    }

    /// Lists from the saved cursor and returns the entries that changed in this pass.
    private func list() async throws -> [String: String] {
        var restarted = false
        var listed: [String: String] = [:]
        while true {
            let page: RelayClient.ChangePage
            do { page = try await client.changes(after: cursor, limit: 1000, namespaces: namespaces) }
            catch RelayError.cursorReset where !restarted {
                // The relay lost or rebuilt its log. Forget what it held and relist from the start.
                restarted = true; cursor = nil; remote = [:]; listed = [:]; genesisChecked = false
                unsavedRemote = []; try resetRemoteLog(); continue
            }
            for entry in page.entries {
                guard (try? RecordPath.validate(entry.path)) != nil || (try? BlobPath.validate(entry.path)) != nil else {
                    throw RelayError.protocolViolation("Invalid path in change feed: \(entry.path)")
                }
                if entry.deleted == true { remove(entry.path); listed[entry.path] = nil; continue }
                guard let sha = entry.sha256, sha.count == 64 else { throw RelayError.protocolViolation("Entry without digest: \(entry.path)") }
                // Entries this device already knew (its own pushes, relistings) are not changes.
                if remote[entry.path] != sha { remember(entry.path, sha); listed[entry.path] = sha }
            }
            guard page.cursor != cursor || page.entries.isEmpty else { throw RelayError.protocolViolation("Cursor did not advance") }
            if page.cursor != cursor { cursor = page.cursor; stateDirty = true }
            if !page.more { break }
        }
        listedOnce = true
        return listed
    }

    private func fetch(_ paths: [String]) async throws -> [String: Data] {
        var result: [String: Data] = [:]
        for start in stride(from: 0, to: paths.count, by: parallelism) {
            let slice = paths[start..<min(paths.count, start + parallelism)]
            try await withThrowingTaskGroup(of: (String, Data?).self) { group in
                for path in slice { group.addTask { [client] in (path, try await client.get(path)) } }
                for try await (path, bytes) in group {
                    // Listed but gone (a withdrawn request, or a racing relay rebuild): skip it.
                    guard let bytes else { continue }
                    guard Self.sha256(bytes) == remote[path] else {
                        throw RelayError.protocolViolation("Record bytes do not match the listed digest: \(path)")
                    }
                    result[path] = bytes
                }
            }
        }
        return result
    }

    static func sha256(_ bytes: Data) -> String { SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined() }

    private func remember(_ path: String, _ sha: String) {
        remote[path] = sha; unsavedRemote.append((path, sha))
    }
    private func remove(_ path: String) {
        guard remote[path] != nil else { return }
        remote[path] = nil; unsavedRemote.append((path, nil))
    }
    private var stateScope: String { endpoint.url.absoluteString + "|colophon/relay/3|" + namespaces.sorted().joined(separator: ",") }
    private var remoteLog: URL? {
        stateFile.map { $0.deletingLastPathComponent().appendingPathComponent($0.deletingPathExtension().lastPathComponent + "-remote.log") }
    }

    private func loadState() throws {
        guard !loaded else { return }
        loaded = true
        guard let stateFile, FileManager.default.fileExists(atPath: stateFile.path) else { return }
        let bytes = try AtomicFile.read(stateFile, maximumBytes: 64 * 1024 * 1024)
        // A corrupt or foreign state file only costs a full relisting.
        guard let stored = try? JSONDecoder().decode(State.self, from: bytes), stored.relay == stateScope else { return }
        cursor = stored.cursor
        conflicts = Set(stored.conflicts ?? [])
        if let legacy = stored.remote {
            // Migrate the whole-map format once into the append-only log.
            remote = legacy
            try resetRemoteLog()
            unsavedRemote = legacy.map { ($0.key, Optional($0.value)) }
            try saveState()
            return
        }
        guard let log = remoteLog, FileManager.default.fileExists(atPath: log.path) else {
            // A cursor without its known paths would skip records: relist instead.
            cursor = nil; return
        }
        let logBytes = try AtomicFile.read(log, maximumBytes: 256 * 1024 * 1024)
        let lastNewline = logBytes.lastIndex(of: UInt8(ascii: "\n")) ?? logBytes.startIndex
        remote.reserveCapacity(logBytes.count / 100)
        // "<sha256> <path>" adds, "- <path>" removes; a torn last line (no newline) is ignored.
        for line in logBytes[logBytes.startIndex..<lastNewline].split(separator: UInt8(ascii: "\n")) {
            if line.first == UInt8(ascii: "-"), line.count > 2 {
                remote[String(decoding: line.dropFirst(2), as: UTF8.self)] = nil
            } else if line.count > 65, line[line.startIndex + 64] == UInt8(ascii: " ") {
                remote[String(decoding: line.dropFirst(65), as: UTF8.self)] = String(decoding: line.prefix(64), as: UTF8.self)
            }
        }
    }
    private func resetRemoteLog() throws {
        guard let log = remoteLog else { return }
        try AtomicFile.write(Data(), to: log)
        stateDirty = true
    }
    private func saveState() throws {
        guard let stateFile else { unsavedRemote = []; return }
        if !unsavedRemote.isEmpty, let log = remoteLog {
            var text = ""
            for (path, sha) in unsavedRemote { text += (sha ?? "-") + " " + path + "\n" }
            try AtomicFile.append(Data(text.utf8), to: log)
            unsavedRemote = []
        }
        let state = State(relay: stateScope, cursor: cursor, conflicts: conflicts.sorted(), remote: nil)
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let encoded = try encoder.encode(state)
        if stateDirty || (try? AtomicFile.read(stateFile, maximumBytes: 1024 * 1024)) != encoded {
            try AtomicFile.write(encoded, to: stateFile)
        }
        stateDirty = false
    }
    private func enter() async {
        if occupied { await withCheckedContinuation { waiters.append($0) } } else { occupied = true }
    }
    private func exit() {
        if waiters.isEmpty { occupied = false } else { waiters.removeFirst().resume() }
    }
}
