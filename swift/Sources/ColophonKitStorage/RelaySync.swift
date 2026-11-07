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
public actor RelaySync {
    public struct Report: Equatable, Sendable {
        public var pulled: Int = 0
        public var pushed: Int = 0
        /// Paths whose relay bytes differ from the local record. Local bytes are kept.
        public var conflicts: [String] = []
    }
    private struct State: Codable {
        var relay: String
        var cursor: String?
        var remote: [String: String]
    }

    public nonisolated let endpoint: RelayEndpoint
    private let local: any RecordStore
    private let client: RelayClient
    private let stateFile: URL?
    private var state: State
    private var loaded = false
    private var listedOnce = false
    private var localDigests: [String: String] = [:]
    private var occupied = false
    private var waiters: [CheckedContinuation<Void, Never>] = []
    private let parallelism = 8

    /// `stateFile` (private container, never the shared library) remembers the cursor and the
    /// relay's known paths across launches. Without it every launch relists the slot.
    public init(local: any RecordStore, endpoint: RelayEndpoint, transport: any RelayTransport = URLSessionRelayTransport(), stateFile: URL? = nil) {
        self.local = local; self.endpoint = endpoint; self.stateFile = stateFile
        client = RelayClient(endpoint: endpoint, transport: transport)
        state = State(relay: endpoint.url.absoluteString, cursor: nil, remote: [:])
    }

    /// True once a listing of the relay has completed in this process.
    public var hasListed: Bool { listedOnce }

    /// One complete pass: list, pull what the local store lacks, push what the relay lacks.
    /// Throws `RelayError` without changing local records it could not verify.
    @discardableResult public func sync() async throws -> Report {
        await enter(); defer { exit() }
        try loadState()
        try await list()
        var localRecords = try await local.read()
        var report = Report()
        let genesis = "authority/00000001.json"
        if let mine = localRecords[genesis], let theirs = state.remote[genesis], digest(genesis, mine) != theirs {
            throw RelayError.differentLibrary
        }
        // Pull: every listed record the local store lacks, verified against the listing.
        let missing = state.remote.keys.filter { path in
            localRecords[path] == nil && (try? RecordPath.validate(path)) != nil
        }.sorted(by: Self.pullOrder)
        for batch in stride(from: 0, to: missing.count, by: 256).map({ Array(missing[$0..<min(missing.count, $0 + 256)]) }) {
            let fetched = try await fetch(batch)
            if !fetched.isEmpty {
                try await local.append(fetched)
                for (path, bytes) in fetched { localRecords[path] = bytes }
                report.pulled += fetched.count
            }
        }
        for (path, bytes) in localRecords {
            if let theirs = state.remote[path], digest(path, bytes) != theirs { report.conflicts.append(path) }
        }
        // Push: every local record the relay lacks. 200 and 201 both mean it now holds it.
        let unpushed = localRecords.keys.filter { state.remote[$0] == nil }.sorted(by: Self.pullOrder)
        for batch in stride(from: 0, to: unpushed.count, by: parallelism).map({ Array(unpushed[$0..<min(unpushed.count, $0 + parallelism)]) }) {
            try await withThrowingTaskGroup(of: (String, RelayClient.PutResult).self) { group in
                for path in batch {
                    guard let bytes = localRecords[path] else { continue }
                    group.addTask { [client] in (path, try await client.putIfAbsent(path, bytes: bytes)) }
                }
                for try await (path, result) in group {
                    switch result {
                    case .created: report.pushed += 1; state.remote[path] = digest(path, localRecords[path] ?? Data())
                    case .present: state.remote[path] = digest(path, localRecords[path] ?? Data())
                    case .conflict: report.conflicts.append(path)
                    }
                }
            }
        }
        try saveState()
        report.conflicts.sort()
        return report
    }

    /// Long-polls the relay's change feed after the saved cursor, outside the pass gate.
    /// Returns true when the relay reports entries this device has not listed yet.
    public func waitForRemoteChanges(seconds: Int) async throws -> Bool {
        try loadState()
        let cursor = state.cursor
        let page = try await client.changes(after: cursor, limit: 1, wait: max(0, min(30, seconds)))
        return !page.entries.isEmpty
    }

    /// Authority first, then requests, then operations, so a partial pull is most useful.
    private static func pullOrder(_ a: String, _ b: String) -> Bool {
        func rank(_ p: String) -> Int { p.hasPrefix("authority/") ? 0 : p.hasPrefix("requests/") ? 1 : 2 }
        return (rank(a), a) < (rank(b), b)
    }

    private func list() async throws {
        var restarted = false
        while true {
            let page: RelayClient.ChangePage
            do { page = try await client.changes(after: state.cursor, limit: 1000) }
            catch RelayError.cursorReset where !restarted {
                // The relay lost or rebuilt its log. Forget what it held and relist from the start.
                restarted = true; state.cursor = nil; state.remote = [:]; continue
            }
            for entry in page.entries {
                guard (try? RecordPath.validate(entry.path)) != nil || (try? BlobPath.validate(entry.path)) != nil else {
                    throw RelayError.protocolViolation("Invalid path in change feed: \(entry.path)")
                }
                if entry.deleted == true { state.remote[entry.path] = nil; continue }
                guard let sha = entry.sha256, sha.count == 64 else { throw RelayError.protocolViolation("Entry without digest: \(entry.path)") }
                state.remote[entry.path] = sha
            }
            guard page.cursor != state.cursor || page.entries.isEmpty else { throw RelayError.protocolViolation("Cursor did not advance") }
            state.cursor = page.cursor
            if !page.more { break }
        }
        listedOnce = true
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
                    guard Self.sha256(bytes) == state.remote[path] else {
                        throw RelayError.protocolViolation("Record bytes do not match the listed digest: \(path)")
                    }
                    result[path] = bytes
                }
            }
        }
        return result
    }

    private func digest(_ path: String, _ bytes: Data) -> String {
        if let known = localDigests[path] { return known }
        let value = Self.sha256(bytes); localDigests[path] = value; return value
    }
    static func sha256(_ bytes: Data) -> String { SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined() }

    private func loadState() throws {
        guard !loaded else { return }
        loaded = true
        guard let stateFile, FileManager.default.fileExists(atPath: stateFile.path) else { return }
        let bytes = try AtomicFile.read(stateFile, maximumBytes: 64 * 1024 * 1024)
        // A corrupt or foreign state file only costs a full relisting.
        if let stored = try? JSONDecoder().decode(State.self, from: bytes), stored.relay == state.relay { state = stored }
    }
    private func saveState() throws {
        guard let stateFile else { return }
        try AtomicFile.write(try JSONEncoder().encode(state), to: stateFile)
    }
    private func enter() async {
        if occupied { await withCheckedContinuation { waiters.append($0) } } else { occupied = true }
    }
    private func exit() {
        if waiters.isEmpty { occupied = false } else { waiters.removeFirst().resume() }
    }
}
