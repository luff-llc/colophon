import CryptoKit
import Darwin
import Foundation

/// The file-backed record medium: a folder in the app's private container, an App Group or iCloud.
///
/// **All or none, for every process.** One `write` is a batch, published through a journal in the library
/// folder (`.colophon.nosync/`, which iCloud does not sync):
///
/// 1. under an exclusive lock (`flock` on `.colophon.nosync/lock`, inside `NSFileCoordinator` when coordinated),
///    any batch an earlier process left behind is completed or discarded, and every conflict is checked;
/// 2. every file of the batch is written (0600) and synchronised in a staging directory `.colophon.nosync/<id>/`;
/// 3. a batch record naming each path, its staged file, digest and size is written, synchronised and renamed to
///    `<id>.record`, and the journal directory is synchronised: this is the commit point;
/// 4. each file moves into place (`linkat` for an immutable record, `renameat` of a fresh link for a live slot,
///    so the staged copy stays until the end), each parent directory synchronised;
/// 5. the record is removed, then the staging directory.
///
/// On every later open (the first listing, read or write of any process), a record whose staged files are all
/// present and match their digests is completed; a record that does not is discarded with its staged files;
/// staging directories without a record (a batch that failed or died before its commit point) are removed.
/// A failure before the commit point removes the staged files and throws; if that removal fails too, the error
/// says so and the next open removes them. A failure after the commit point throws `unavailable` and leaves the
/// record: the next open of any process completes the batch. An immutable file that appears with other bytes while
/// a recorded batch moves into place (only a writer outside this protocol can do that) is a `conflict`: the
/// entries this batch linked are unlinked again and the batch is discarded.
///
/// **Readers never see half a batch.** Listings and reads take the same lock, shared: they wait while a batch
/// moves into place, and a reader that finds a batch record completes it (exclusively) before it reads.
///
/// **Links are never followed.** Every path is resolved one component at a time from a directory handle with
/// `openat(…, O_NOFOLLOW)`; a symbolic link anywhere below the folder is `invalidPath`, and because the check is
/// the open there is no gap in which one can be swapped in. iCloud placeholders and dataless ubiquitous items
/// start a download and answer `unavailable` (never absence); an `NSFilePresenter` gives wake-up hints.
public final class FolderMedium: RecordMedium, @unchecked Sendable {
    public let folder: URL
    private let coordinated: Bool
    private let lock = NSLock()
    private var presenters: [UUID: FolderPresenter] = [:]
    private var hook: (@Sendable (FolderBatchStep) throws -> Void)?
    static let journalName = ".colophon.nosync"

    public init(folder: URL) {
        self.folder = Self.canonical(folder); coordinated = true
    }
    /// Test seam for restricted hosts without `filecoordinationd`. Never a production fallback: the journal and its
    /// lock still make every batch all or none for every process; only the iCloud coordination is skipped.
    package init(folder: URL, coordinated: Bool) {
        self.folder = Self.canonical(folder); self.coordinated = coordinated
    }

    /// Called at each step of a batch (tests: a crash helper kills the process there; a fault test throws).
    package var batchHook: (@Sendable (FolderBatchStep) throws -> Void)? {
        get { lock.withLock { hook } }
        set { lock.withLock { hook = newValue } }
    }
    private func step(_ step: FolderBatchStep) throws { try batchHook?(step) }

    /// The real path of `url`, resolving every symbolic link of the part that exists (`resolvingSymlinksInPath` turns
    /// `/private/var` into `/var`, which is not what the file system reports back). A folder that does not exist
    /// yet keeps its remaining components.
    static func canonical(_ url: URL) -> URL {
        var tail: [String] = []
        var base = url.standardizedFileURL
        while true {
            if let resolved = realpath(base.path, nil) {
                defer { free(resolved) }
                return tail.reversed().reduce(URL(fileURLWithPath: String(cString: resolved))) { $0.appendingPathComponent($1) }
            }
            guard base.path != "/" else { return url }
            tail.append(base.lastPathComponent)
            base = base.deletingLastPathComponent()
        }
    }

    deinit {
        for presenter in presenters.values {
            NSFileCoordinator.removeFilePresenter(presenter)
            presenter.continuation.finish()
        }
    }

    // MARK: Reading

    public func listing() throws -> [MediumEntry] {
        try listing(prefix: "")
    }

    /// A directory prefix opens that subtree directly. Other prefixes match the start of each record path.
    public func listing(prefix: String) throws -> [MediumEntry] {
        let directoryPrefix = prefix.hasSuffix("/") ? String(prefix.dropLast()) : prefix
        let validDirectory = (try? RecordPaths.validate(directoryPrefix)) != nil
        let entries = try reading { root -> [MediumEntry] in
            var result: [MediumEntry] = []
            if validDirectory {
                // Walk only the requested directory. Each component is checked without following links.
                let (parent, leaf) = try resolveParent(root, directoryPrefix, create: false, allowNonDirectory: true)
                if let parent, let child = try childDirectory(parent, leaf, path: directoryPrefix, create: false, allowNonDirectory: true) {
                    // APFS may open a differently cased name. Report paths with their stored spelling.
                    let componentCount = directoryPrefix.split(separator: "/").count
                    let actual = child.openPath()?.split(separator: "/").suffix(componentCount).joined(separator: "/")
                    if actual == nil || actual == directoryPrefix {
                        try list(child, prefix: (actual ?? directoryPrefix) + "/", into: &result)
                        return result.sorted { $0.path < $1.path }
                    }
                }
                if prefix.hasSuffix("/") { return [] }
            }
            try list(root, prefix: "", into: &result)
            if !prefix.isEmpty { result = result.filter { $0.path.hasPrefix(prefix) } }
            return result.sorted { $0.path < $1.path }
        }
        return entries ?? []
    }

    private func list(_ directory: DirectoryHandle, prefix: String, into result: inout [MediumEntry]) throws {
        for entry in try directory.entries() {
            let name = entry.name
            if name.hasPrefix(".") {
                if name.hasSuffix(".icloud") {
                    let path = prefix + String(name.dropFirst().dropLast(7))
                    throw DownloadPending(url: folder.appendingPathComponent(path), name: name)
                }
                continue // the journal, Finder's files, a 0.4 stage file: never records
            }
            let path = prefix + name
            if entry.isSymlink { throw StorageError.invalidPath(path) }
            guard entry.isDirectory || entry.isRegular else { continue }
            // Bound recursion using the same path limit imposed on stored records.
            try RecordPaths.validate(path)
            let info = entry.info
            try checkDataless(info, path)
            if entry.isDirectory {
                guard let child = try directory.directory(name, create: false) else { continue }
                try list(child, prefix: path + "/", into: &result)
                continue
            }
            let modified = Double(info.st_mtimespec.tv_sec) + Double(info.st_mtimespec.tv_nsec) / 1e9
            result.append(MediumEntry(path: path, version: "\(info.st_ino):\(info.st_size):\(modified)"))
        }
    }

    public func read(_ path: String) throws -> Data {
        try RecordPaths.validate(path)
        let found = try reading { root -> Data? in try readFile(root, path, maximumBytes: RecordPaths.maximumBytes) }
        guard let bytes = found ?? nil else { throw StorageError.unavailable("Missing record: " + path) }
        return bytes
    }

    public func readBlob(_ path: String) throws -> Data {
        guard RecordPaths.isBlob(path) else { throw StorageError.invalidPath(path) }
        try RecordPaths.validate(path)
        let found = try reading { root -> Data? in try readFile(root, path, maximumBytes: 1 << 20) }
        return (found ?? nil) ?? Data()
    }

    private func readFile(_ root: DirectoryHandle, _ path: String, maximumBytes: Int) throws -> Data? {
        let (parent, leaf) = try resolveParent(root, path, create: false)
        guard let parent else { return nil }
        try checkPlaceholder(parent, leaf, path)
        return try readRecord(parent, leaf, path, maximumBytes: maximumBytes)
    }

    private func readRecord(_ parent: DirectoryHandle, _ leaf: String, _ path: String, maximumBytes: Int) throws -> Data? {
        if let info = try parent.info(leaf) {
            if info.st_mode & S_IFMT == S_IFLNK { throw StorageError.invalidPath(path) }
            try checkDataless(info, path)
        }
        return try parent.read(leaf, maximumBytes: maximumBytes)
    }

    /// Runs `body` with the folder's handle under the shared lock, after completing any batch left behind. Nil when
    /// the folder does not exist yet (an empty store).
    private func reading<T>(_ body: (DirectoryHandle) throws -> T) throws -> T? {
        // The folder can be created or evicted after initialization. Read fresh resource values before taking flock.
        try downloadAfterUnlock {
            try checkAvailability(URL(fileURLWithPath: folder.path))
            return try lockedRead(body)
        }
    }

    private func lockedRead<T>(_ body: (DirectoryHandle) throws -> T) throws -> T? {
        guard let root = try DirectoryHandle.open(folder.path) else { return nil }
        let journal = try openJournal(root)
        do {
            let shared = try FolderFiles.Lock(journal, exclusive: false)
            let clean = try !hasLeftovers(journal)
            if clean { return try withExtendedLifetime(shared) { try body(root) } }
        }
        // A batch was left behind: complete or discard it under the exclusive lock, then read under that lock.
        return try coordinate { () -> T in
            let exclusive = try FolderFiles.Lock(journal, exclusive: true)
            return try withExtendedLifetime(exclusive) {
                try recover(root, journal)
                return try body(root)
            }
        }
    }

    // MARK: Writing

    public func write(_ writes: [MediumWrite]) throws {
        for item in writes {
            guard item.bytes.count <= RecordPaths.maximumBytes else { throw StorageError.limitExceeded }
            try RecordPaths.validate(item.path)
        }
        guard !writes.isEmpty else { return }
        try downloadAfterUnlock {
            try coordinate {
                try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
                guard let root = try DirectoryHandle.open(folder.path) else { throw StorageError.unavailable("Cannot open the library folder") }
                let journal = try openJournal(root)
                let exclusive = try FolderFiles.Lock(journal, exclusive: true)
                try withExtendedLifetime(exclusive) {
                    try recover(root, journal)
                    try publish(writes, root: root, journal: journal)
                }
            }
        }
        signal()
    }

    private func publish(_ writes: [MediumWrite], root: DirectoryHandle, journal: DirectoryHandle) throws {
        // Nothing is staged until no write conflicts.
        var plan: [(path: String, bytes: Data, replace: Bool)] = []
        var pending: [String: Data] = [:]
        for item in writes {
            var previous = pending[item.path]
            if previous == nil { previous = try readFile(root, item.path, maximumBytes: RecordPaths.maximumBytes) }
            if previous == item.bytes { continue }
            if previous != nil, !RecordPaths.isReplaceable(item.path) { throw StorageError.conflict(item.path) }
            if let index = plan.firstIndex(where: { $0.path == item.path }) { plan.remove(at: index) }
            plan.append((item.path, item.bytes, RecordPaths.isReplaceable(item.path))); pending[item.path] = item.bytes
        }
        guard !plan.isEmpty else { return }
        let id = UUID().uuidString.lowercased()
        var record = BatchRecord(entries: [])
        do {
            guard let staging = try journal.directory(id, create: true) else { throw StorageError.unavailable("Cannot create the batch staging directory") }
            var entries: [BatchRecord.Entry] = []
            for (index, item) in plan.enumerated() {
                let name = String(index)
                try staging.create(name, bytes: item.bytes)
                entries.append(BatchRecord.Entry(path: item.path, staged: name, digest: Self.digest(item.bytes), size: item.bytes.count, replace: item.replace))
                try step(.staged(index))
            }
            try staging.sync()
            record = BatchRecord(entries: entries)
            let encoded = try JSONEncoder().encode(record)
            try journal.remove(id + ".record.tmp")
            try journal.create(id + ".record.tmp", bytes: encoded)
            guard renameat(journal.fd, id + ".record.tmp", journal.fd, id + ".record") == 0 else { throw FolderFiles.failure(errno, "batch record") }
            try journal.sync()
        } catch {
            // Before the commit point: nothing is published. Remove what was staged.
            do {
                try step(.rollback)
                try journal.remove(id + ".record.tmp")
                try journal.remove(id + ".record")
                try journal.removeDirectory(id)
            } catch let cleanup {
                throw StorageError.unavailable("The batch was not published (\(Self.describe(error))), and its staged files could not be removed (\(Self.describe(cleanup))); the next open removes them")
            }
            throw error
        }
        try step(.recorded)
        do { try complete(id, record, root: root, journal: journal) }
        catch StorageError.conflict(let path) { throw StorageError.conflict(path) }
        catch let pending as DownloadPending { throw pending }
        catch { throw StorageError.unavailable("The batch is recorded and will be completed on the next open: \(Self.describe(error))") }
    }

    /// Moves every entry of a recorded batch into place, then removes the record and the staging directory.
    /// Idempotent: an entry already in place with its bytes is left as it is. A conflicting immutable file undoes the
    /// links this call made, discards the batch and throws `conflict`.
    private func complete(_ id: String, _ record: BatchRecord, root: DirectoryHandle, journal: DirectoryHandle) throws {
        guard let staging = try journal.directory(id, create: false) else { throw StorageError.unavailable("The staging directory of batch \(id) is missing") }
        var linked: [(DirectoryHandle, String)] = []
        for (index, entry) in record.entries.enumerated() {
            let (parentHandle, leaf) = try resolveParent(root, entry.path, create: true)
            guard let parent = parentHandle else { throw StorageError.unavailable("Cannot create the directory of \(entry.path)") }
            if entry.replace {
                let moving = entry.staged + ".move"
                try staging.remove(moving)
                guard linkat(staging.fd, entry.staged, staging.fd, moving, 0) == 0 else { throw FolderFiles.failure(errno, entry.path) }
                guard renameat(staging.fd, moving, parent.fd, leaf) == 0 else { throw FolderFiles.failure(errno, entry.path) }
            } else if linkat(staging.fd, entry.staged, parent.fd, leaf, 0) == 0 {
                linked.append((parent, leaf))
            } else {
                guard errno == EEXIST else { throw FolderFiles.failure(errno, entry.path) }
                let present: Data?
                do {
                    present = try readRecord(parent, leaf, entry.path, maximumBytes: RecordPaths.maximumBytes)
                } catch let pending as DownloadPending {
                    throw pending
                } catch {
                    present = nil
                }
                guard let bytes = present, bytes.count == entry.size, Self.digest(bytes) == entry.digest else {
                    for (directory, name) in linked.reversed() { try directory.remove(name); try directory.sync() }
                    try journal.remove(id + ".record")
                    try journal.sync()
                    try? journal.removeDirectory(id)
                    throw StorageError.conflict(entry.path)
                }
            }
            try parent.sync()
            try step(.applied(index))
        }
        try journal.remove(id + ".record")
        try journal.sync()
        try step(.recordRemoved)
        // The batch is complete; leftover staged files are garbage the next open removes.
        try? journal.removeDirectory(id)
    }

    /// Completes or discards every batch an earlier process left, and removes staging that never reached a record.
    private func recover(_ root: DirectoryHandle, _ journal: DirectoryHandle) throws {
        let entries = try journal.entries()
        for entry in entries where entry.name.hasSuffix(".record") && entry.isRegular {
            let id = String(entry.name.dropLast(7))
            let bytes = try journal.read(entry.name, maximumBytes: 16 * 1024 * 1024)
            if let bytes, let record = try? JSONDecoder().decode(BatchRecord.self, from: bytes), record.version == 1,
               try stagedFilesAreValid(record, id: id, journal: journal) {
                do { try complete(id, record, root: root, journal: journal) }
                catch StorageError.conflict { continue } // discarded by `complete`: another writer's bytes are there
            } else {
                try journal.removeDirectory(id)
                try journal.remove(entry.name)
                try journal.sync()
            }
        }
        for entry in try journal.entries() {
            if entry.isDirectory, !(try journalHasRecord(journal, entry.name)) { try journal.removeDirectory(entry.name) }
            else if entry.name.hasSuffix(".record.tmp") { try journal.remove(entry.name) }
        }
    }

    private func journalHasRecord(_ journal: DirectoryHandle, _ id: String) throws -> Bool {
        var info = stat()
        return fstatat(journal.fd, id + ".record", &info, AT_SYMLINK_NOFOLLOW) == 0
    }

    private func stagedFilesAreValid(_ record: BatchRecord, id: String, journal: DirectoryHandle) throws -> Bool {
        guard let staging = try journal.directory(id, create: false) else { return false }
        for entry in record.entries {
            guard (try? RecordPaths.validate(entry.path)) != nil, !entry.staged.contains("/"), !entry.staged.hasPrefix("."),
                  let bytes = try? staging.read(entry.staged, maximumBytes: RecordPaths.maximumBytes),
                  bytes.count == entry.size, Self.digest(bytes) == entry.digest else { return false }
        }
        return true
    }

    /// Anything in the journal besides its lock: a record, a staging directory, a temporary record.
    private func hasLeftovers(_ journal: DirectoryHandle) throws -> Bool {
        try journal.entries().contains { $0.name != "lock" }
    }

    private func openJournal(_ root: DirectoryHandle) throws -> DirectoryHandle {
        guard let journal = try root.directory(Self.journalName, create: true) else { throw StorageError.unavailable("Cannot open the batch journal") }
        #if os(iOS) || os(visionOS)
        try? FileManager.default.setAttributes([.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
                                               ofItemAtPath: folder.appendingPathComponent(Self.journalName).path)
        #endif
        return journal
    }

    /// The directory that holds `path` and the last component, walked from `root` without following any link.
    private func resolveParent(
        _ root: DirectoryHandle, _ path: String, create: Bool, allowNonDirectory: Bool = false
    ) throws -> (DirectoryHandle?, String) {
        let components = path.split(separator: "/").map(String.init)
        guard let leaf = components.last else { throw StorageError.invalidPath(path) }
        var current = root
        var prefix = ""
        for component in components.dropLast() {
            let componentPath = prefix + component
            guard let next = try childDirectory(current, component, path: componentPath, create: create, allowNonDirectory: allowNonDirectory) else {
                return (nil, leaf)
            }
            current = next
            prefix = componentPath + "/"
        }
        return (current, leaf)
    }

    private func childDirectory(
        _ parent: DirectoryHandle, _ name: String, path: String, create: Bool, allowNonDirectory: Bool
    ) throws -> DirectoryHandle? {
        try checkPlaceholder(parent, name, path)
        if let info = try parent.info(name) {
            let kind = info.st_mode & S_IFMT
            if kind == S_IFLNK { throw StorageError.invalidPath(path) }
            try checkDataless(info, path)
            if allowNonDirectory && kind != S_IFDIR { return nil }
        }
        return try parent.directory(name, create: create)
    }

    private func checkPlaceholder(_ directory: DirectoryHandle, _ name: String, _ path: String) throws {
        let placeholder = "." + name + ".icloud"
        var info = stat()
        if fstatat(directory.fd, placeholder, &info, AT_SYMLINK_NOFOLLOW) == 0 {
            throw DownloadPending(url: folder.appendingPathComponent(path), name: placeholder)
        }
    }

    private func checkDataless(_ info: stat, _ path: String) throws {
        if info.st_flags & UInt32(SF_DATALESS) != 0 {
            let url = path.isEmpty ? folder : folder.appendingPathComponent(path)
            throw DownloadPending(url: url, name: url.lastPathComponent)
        }
    }

    private struct DownloadPending: Error {
        let url: URL
        let name: String
    }

    /// The lock and any file coordination have unwound before a download request reaches FileProvider.
    private func downloadAfterUnlock<T>(_ body: () throws -> T) throws -> T {
        do { return try body() }
        catch let pending as DownloadPending {
            try? FileManager.default.startDownloadingUbiquitousItem(at: pending.url)
            throw StorageError.unavailable("iCloud download pending: \(pending.name)")
        }
    }

    private func coordinate<T>(_ body: () throws -> T) throws -> T {
        guard coordinated else { return try body() }
        var coordinationError: NSError?
        var result: Result<T, any Error>?
        NSFileCoordinator().coordinate(writingItemAt: folder, options: [], error: &coordinationError) { _ in
            result = Result { try body() }
        }
        if let coordinationError { throw StorageError.unavailable("File coordination is unavailable: " + coordinationError.localizedDescription) }
        guard let result else { throw StorageError.unavailable("File coordination did not run the write") }
        return try result.get()
    }

    static func digest(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
    private static func describe(_ error: any Error) -> String { (error as? LocalizedError)?.errorDescription ?? String(describing: error) }

    // MARK: Change hints

    public func changes() -> AsyncStream<Void> {
        let id = UUID()
        let (stream, continuation) = AsyncStream<Void>.makeStream(bufferingPolicy: .bufferingNewest(1))
        let presenter = FolderPresenter(folder: folder, continuation: continuation)
        lock.withLock { presenters[id] = presenter }
        NSFileCoordinator.addFilePresenter(presenter)
        continuation.onTermination = { [weak self] _ in
            guard let self else { return }
            if let presenter = self.lock.withLock({ self.presenters.removeValue(forKey: id) }) { NSFileCoordinator.removeFilePresenter(presenter) }
        }
        return stream
    }
    private func signal() { for presenter in lock.withLock({ Array(presenters.values) }) { presenter.signal() } }

    private func checkAvailability(_ url: URL) throws {
        let name = url.lastPathComponent
        let placeholder = url.deletingLastPathComponent().appendingPathComponent("." + name + ".icloud")
        if name.hasSuffix(".icloud") || FileManager.default.fileExists(atPath: placeholder.path) {
            throw DownloadPending(url: url, name: name)
        }
        var info = stat()
        guard lstat(url.path, &info) == 0 else {
            if errno == ENOENT { return }
            throw FolderFiles.failure(errno, url.path)
        }
        if info.st_mode & S_IFMT == S_IFLNK { throw StorageError.invalidPath(url.path) }
        try checkDataless(info, "")
        do {
            let values = try url.resourceValues(forKeys: [.isUbiquitousItemKey, .ubiquitousItemDownloadingStatusKey])
            if values.isUbiquitousItem == true && values.ubiquitousItemDownloadingStatus != .current {
                throw DownloadPending(url: url, name: name)
            }
        } catch let error as CocoaError where error.code == .fileReadNoSuchFile || error.code == .fileNoSuchFile {
            return
        }
    }
}

/// Immutable callback bridge. Foundation owns scheduling; no mutable state is shared.
private final class FolderPresenter: NSObject, NSFilePresenter, Sendable {
    let presentedItemURL: URL?
    let presentedItemOperationQueue: OperationQueue
    let continuation: AsyncStream<Void>.Continuation
    init(folder: URL, continuation: AsyncStream<Void>.Continuation) {
        presentedItemURL = folder
        self.continuation = continuation
        let queue = OperationQueue()
        queue.maxConcurrentOperationCount = 1
        presentedItemOperationQueue = queue
    }
    func signal() { continuation.yield(()) }
    func presentedItemDidChange() { signal() }
    func presentedSubitemDidAppear(at url: URL) { signal() }
    func presentedSubitemDidChange(at url: URL) { signal() }
    func accommodatePresentedSubitemDeletion(at url: URL, completionHandler: @escaping (Error?) -> Void) {
        signal(); completionHandler(nil)
    }
}
