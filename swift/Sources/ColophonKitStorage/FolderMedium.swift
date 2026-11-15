import Foundation
import Darwin

/// The file-backed record medium: a folder in the app's private container, an App Group or iCloud.
///
/// What it keeps from the 0.4 folder store: writes go through `NSFileCoordinator`; files are staged
/// with mode 0600, synchronised, and linked (immutable) or renamed (replaceable) into place; the
/// directory is synchronised before success; symbolic links anywhere under the folder are refused;
/// iCloud placeholders and non-current ubiquitous items start a download and answer `unavailable`
/// (never absence); an `NSFilePresenter` gives wake-up hints.
///
/// What is new: the paths are the core's (any depth, `authority/`, `predecessor/`, `vetoes/`,
/// `transitions/`, `heads/`, `ops/`, `state/`, `blobs/`, and the host's own `requests/`), a listing
/// carries a version token per path in one pass, and one `write` is all-or-none: every conflict is
/// checked before the first file is published, and an I/O failure after that removes what the call
/// created and restores what it replaced. (A crash in the middle of a batch cannot be undone; the
/// engine reopens over what was published and the stores of a finished action are idempotent.)
public final class FolderMedium: RecordMedium, @unchecked Sendable {
    public let folder: URL
    private let coordinated: Bool
    private let lock = NSLock()
    private var presenters: [UUID: FolderPresenter] = [:]

    public init(folder: URL) { self.folder = folder.resolvingSymlinksInPath(); coordinated = true }
    /// Test seam for restricted hosts without `filecoordinationd`. Never a production fallback.
    init(folder: URL, coordinated: Bool) { self.folder = folder.resolvingSymlinksInPath(); self.coordinated = coordinated }

    deinit {
        for presenter in presenters.values {
            NSFileCoordinator.removeFilePresenter(presenter)
            presenter.continuation.finish()
        }
    }

    public func listing() throws -> [MediumEntry] {
        do {
            try checkAvailability(folder)
            guard FileManager.default.fileExists(atPath: folder.path) else { return [] }
            var scanError: (any Error)?
            guard let enumerator = FileManager.default.enumerator(at: folder, includingPropertiesForKeys: nil, options: [],
                                                                   errorHandler: { _, error in scanError = error; return false }) else {
                throw StorageError.unavailable("Cannot enumerate the library folder")
            }
            let prefix = folder.path + "/"
            var result: [MediumEntry] = []
            for case let file as URL in enumerator {
                let name = file.lastPathComponent
                if name.hasPrefix(".") {
                    if name.hasSuffix(".icloud") {
                        try? FileManager.default.startDownloadingUbiquitousItem(at: file.deletingLastPathComponent().appendingPathComponent(String(name.dropFirst().dropLast(7))))
                        throw StorageError.unavailable("iCloud download pending: \(name)")
                    }
                    if file.hasDirectoryPath || (try? file.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true { enumerator.skipDescendants() }
                    continue
                }
                var info = stat()
                guard lstat(file.path, &info) == 0 else { throw StorageError.unavailable("Cannot stat \(file.path)") }
                if (info.st_mode & S_IFMT) == S_IFLNK { throw StorageError.invalidPath(file.path) }
                guard (info.st_mode & S_IFMT) == S_IFREG else { continue }
                try checkAvailability(file)
                guard file.path.hasPrefix(prefix) else { throw StorageError.invalidPath(file.path) }
                let path = String(file.path.dropFirst(prefix.count))
                try RecordPaths.validate(path)
                let modified = Double(info.st_mtimespec.tv_sec) + Double(info.st_mtimespec.tv_nsec) / 1e9
                result.append(MediumEntry(path: path, version: "\(info.st_ino):\(info.st_size):\(modified)"))
            }
            if let scanError { throw scanError }
            return result.sorted { $0.path < $1.path }
        } catch let error as StorageError { throw error }
        catch { throw StorageError.unavailable(error.localizedDescription) }
    }

    public func read(_ path: String) throws -> Data {
        try RecordPaths.validate(path); try rejectSymlinks(path)
        let url = folder.appendingPathComponent(path)
        try checkAvailability(url)
        do { return try AtomicFile.read(url, maximumBytes: RecordPaths.maximumBytes) }
        catch let error as StorageError { throw error }
        catch let error as CocoaError where error.code == .fileReadNoSuchFile || error.code == .fileNoSuchFile {
            throw StorageError.unavailable("Missing record: " + path)
        } catch { throw StorageError.unavailable(error.localizedDescription) }
    }

    public func readBlob(_ path: String) throws -> Data {
        guard RecordPaths.isBlob(path) else { throw StorageError.invalidPath(path) }
        try RecordPaths.validate(path); try rejectSymlinks(path)
        let url = folder.appendingPathComponent(path)
        try checkAvailability(url)
        guard FileManager.default.fileExists(atPath: url.path) else { return Data() }
        do { return try AtomicFile.read(url, maximumBytes: 1 << 20) }
        catch let error as StorageError { throw error }
        catch { throw StorageError.unavailable(error.localizedDescription) }
    }

    public func write(_ writes: [MediumWrite]) throws {
        for item in writes {
            guard item.bytes.count <= RecordPaths.maximumBytes else { throw StorageError.limitExceeded }
            try RecordPaths.validate(item.path); try rejectSymlinks(item.path)
        }
        do { try coordinate { root in try self.apply(writes, in: root) } }
        catch let error as StorageError { throw error }
        catch { throw StorageError.unavailable(error.localizedDescription) }
        signal()
    }

    private func apply(_ writes: [MediumWrite], in root: URL) throws {
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        // Pass one: nothing is published until no write conflicts.
        var plan: [(url: URL, bytes: Data, previous: Data?)] = []
        var pending: [String: Data] = [:]
        for item in writes {
            let url = root.appendingPathComponent(item.path)
            var target = root
            for component in item.path.split(separator: "/") { target.appendPathComponent(String(component)); try checkAvailability(target) }
            var previous: Data? = pending[item.path]
            if previous == nil, FileManager.default.fileExists(atPath: url.path) {
                previous = try AtomicFile.read(url, maximumBytes: RecordPaths.maximumBytes)
            }
            if previous == item.bytes { continue }
            if previous != nil, !RecordPaths.isReplaceable(item.path) { throw StorageError.conflict(item.path) }
            plan.append((url, item.bytes, previous)); pending[item.path] = item.bytes
        }
        // Pass two: publish in order; on failure undo what this call did.
        var published: [(url: URL, previous: Data?)] = []
        do {
            for step in plan {
                try AtomicFile.write(step.bytes, to: step.url, immutable: step.previous == nil)
                published.append((step.url, step.previous))
            }
        } catch {
            for done in published.reversed() {
                if let previous = done.previous { try? AtomicFile.write(previous, to: done.url) }
                else { try? FileManager.default.removeItem(at: done.url) }
            }
            throw error
        }
    }

    private func coordinate(_ body: @escaping (URL) throws -> Void) throws {
        guard coordinated else { try body(folder); return }
        var coordinationError: NSError?
        var writeError: (any Error)?
        NSFileCoordinator().coordinate(writingItemAt: folder, options: [], error: &coordinationError) { actual in
            do { try body(actual) } catch { writeError = error }
        }
        if let coordinationError { throw StorageError.unavailable(coordinationError.localizedDescription) }
        if let writeError { throw writeError }
    }

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

    private func rejectSymlinks(_ path: String) throws {
        guard folder.resolvingSymlinksInPath().path == folder.path else { throw StorageError.invalidPath(folder.path) }
        var url = folder
        for component in path.split(separator: "/") {
            url.appendPathComponent(String(component))
            if (try? url.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink) == true { throw StorageError.invalidPath(path) }
        }
    }
    private func checkAvailability(_ url: URL) throws {
        let name = url.lastPathComponent
        let placeholder = url.deletingLastPathComponent().appendingPathComponent("." + name + ".icloud")
        if name.hasSuffix(".icloud") || FileManager.default.fileExists(atPath: placeholder.path) {
            try? FileManager.default.startDownloadingUbiquitousItem(at: url)
            throw StorageError.unavailable("iCloud download pending: \(name)")
        }
        do {
            let values = try url.resourceValues(forKeys: [.isUbiquitousItemKey, .ubiquitousItemDownloadingStatusKey, .isSymbolicLinkKey])
            guard values.isSymbolicLink != true else { throw StorageError.invalidPath(url.path) }
            if values.isUbiquitousItem == true && values.ubiquitousItemDownloadingStatus != .current {
                try? FileManager.default.startDownloadingUbiquitousItem(at: url)
                throw StorageError.unavailable("iCloud download pending: \(name)")
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
