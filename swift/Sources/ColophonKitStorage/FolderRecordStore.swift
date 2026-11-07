import Foundation

public actor FolderRecordStore: RecordStore {
    public nonisolated let folder: URL
    private let coordinated: Bool
    private var presenters: [UUID: FolderPresenter] = [:]
    private var knownPaths = Set<String>()

    public init(folder: URL) { self.folder = folder.resolvingSymlinksInPath(); coordinated = true }
    // Explicit test seam for restricted hosts without filecoordinationd. Never a production fallback.
    init(folder: URL, coordinated: Bool) { self.folder = folder.resolvingSymlinksInPath(); self.coordinated = coordinated }

    deinit {
        for presenter in presenters.values {
            NSFileCoordinator.removeFilePresenter(presenter)
            presenter.continuation.finish()
        }
    }

    public func read() throws -> [String: Data] {
        var result: [String: Data] = [:]
        for (path, file) in try enumerate() { result[path] = try AtomicFile.read(file, maximumBytes: 16 * 1024 * 1024) }
        return result
    }
    /// Enumerates directories only; no record bytes are read.
    public func paths() async throws -> Set<String> { Set(try enumerate().keys) }
    public func read(paths: [String]) async throws -> [String: Data] {
        do {
            try checkAvailability(folder)
            var result: [String: Data] = [:]
            for path in paths {
                try RecordPath.validate(path); try rejectSymlinks(path)
                let url = folder.appendingPathComponent(path)
                try checkAvailability(url)
                guard FileManager.default.fileExists(atPath: url.path) else { continue }
                result[path] = try AtomicFile.read(url, maximumBytes: 16 * 1024 * 1024)
            }
            return result
        } catch let error as StorageError { throw error }
        catch { throw StorageError.unavailable(error.localizedDescription) }
    }
    public func paths(namespaces: [String]) async throws -> Set<String> { Set(try enumerate(namespaces: namespaces).keys) }
    public func syncPaths(namespaces: [String]) async throws -> Set<String> { Set(try enumerate(namespaces: namespaces, includeHistory: true).keys) }
    public func versions(paths: Set<String>) async throws -> [String: String] {
        var result: [String: String] = [:]
        for path in paths {
            try RecordPath.validate(path); try rejectSymlinks(path)
            let url = folder.appendingPathComponent(path)
            try checkAvailability(url)
            let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
            result[path] = "\(attributes[.systemFileNumber] ?? ""):\(attributes[.size] ?? ""):\((attributes[.modificationDate] as? Date)?.timeIntervalSince1970 ?? 0)"
        }
        return result
    }
    private func enumerate(namespaces: [String]? = nil, includeHistory: Bool = false) throws -> [String: URL] {
        do {
            try checkAvailability(folder)
            let manager = FileManager.default
            var result: [String: URL] = [:]
            for directory in ["authority", "requests", "ops", "state", "history"] {
                if namespaces != nil && !includeHistory && directory == "history" { continue }
                let root = folder.appendingPathComponent(directory)
                if !manager.fileExists(atPath: root.path) {
                    try checkAvailability(root)
                    continue
                }
                var scanError: (any Error)?
                guard let enumerator = manager.enumerator(at: root, includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey], errorHandler: { _, error in
                    scanError = error; return false
                }) else { throw StorageError.unavailable("Cannot enumerate \(directory)") }
                for case let file as URL in enumerator {
                    if let namespaces, !namespaces.isEmpty {
                        let relative = String(file.path.dropFirst(folder.path.count + 1)).split(separator: "/")
                        if relative.count >= 3 && ["ops", "state", "history"].contains(String(relative[0])) && !relative[2].hasSuffix(".json") && !namespaces.contains(String(relative[2])) {
                            enumerator.skipDescendants(); continue
                        }
                    }
                    try checkAvailability(file)
                    let values = try file.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
                    guard values.isSymbolicLink != true else { throw StorageError.invalidPath(file.path) }
                    guard values.isRegularFile == true, !file.lastPathComponent.hasPrefix(".") else { continue }
                    let canonical = file.resolvingSymlinksInPath().path
                    let prefix = folder.resolvingSymlinksInPath().path + "/"
                    guard canonical.hasPrefix(prefix) else { throw StorageError.invalidPath(file.path) }
                    let path = String(canonical.dropFirst(prefix.count))
                    try RecordPath.validate(path)
                    result[path] = file
                }
                if let scanError { throw scanError }
            }
            guard knownPaths.filter({ RecordPath.missingBlocks($0) && (namespaces == nil || RecordPath.listingIncludes($0, namespaces: namespaces ?? [])) }).isSubset(of: Set(result.keys)) else {
                throw StorageError.unavailable("Previously observed records are missing")
            }
            knownPaths.formUnion(result.keys)
            return result
        } catch let error as StorageError { throw error }
        catch { throw StorageError.unavailable(error.localizedDescription) }
    }

    public func append(_ records: [String: Data]) throws {
        do { try appendCoordinated(records) }
        catch let error as StorageError { throw error }
        catch { throw StorageError.unavailable(error.localizedDescription) }
    }
    private func appendCoordinated(_ records: [String: Data]) throws {
        try checkAvailability(folder)
        for (path, bytes) in records {
            guard bytes.count <= 16 * 1024 * 1024 else { throw StorageError.limitExceeded }
            try RecordPath.validate(path); try rejectSymlinks(path)
        }
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        let write: (URL) throws -> Void = { root in
            for path in records.keys.sorted() {
                guard let bytes = records[path] else { continue }
                var target = root
                for component in path.split(separator: "/") {
                    target.appendPathComponent(String(component))
                    try self.checkAvailability(target)
                }
                try AtomicFile.write(bytes, to: root.appendingPathComponent(path), immutable: !RecordPath.isReplaceable(path))
            }
        }
        if coordinated {
            var coordinationError: NSError?
            var writeError: (any Error)?
            NSFileCoordinator().coordinate(writingItemAt: folder, options: [], error: &coordinationError) { actual in
                do { try write(actual) } catch { writeError = error }
            }
            if let coordinationError { throw StorageError.unavailable(coordinationError.localizedDescription) }
            if let writeError { throw writeError }
        } else { try write(folder) }
        for presenter in presenters.values { presenter.signal() }
    }

    public func replaceLive(_ path: String, expected: Data?, bytes: Data) async throws -> Bool {
        try RecordPath.validate(path); try rejectSymlinks(path)
        guard RecordPath.isReplaceable(path) else { throw StorageError.invalidPath(path) }
        var replaced = false
        let write: (URL) throws -> Bool = { root in
            let url = root.appendingPathComponent(path)
            try self.checkAvailability(url)
            let old = FileManager.default.fileExists(atPath: url.path) ? try AtomicFile.read(url, maximumBytes: 16 * 1024 * 1024) : nil
            if old == bytes { return true }
            guard old == expected else { return false }
            try AtomicFile.write(bytes, to: url); return true
        }
        if coordinated {
            var coordinationError: NSError?, writeError: (any Error)?
            NSFileCoordinator().coordinate(writingItemAt: folder, options: [], error: &coordinationError) { root in
                do { replaced = try write(root) } catch { writeError = error }
            }
            if let coordinationError { throw StorageError.unavailable(coordinationError.localizedDescription) }
            if let writeError { throw writeError }
        } else { replaced = try write(folder) }
        if replaced { for presenter in presenters.values { presenter.signal() } }
        return replaced
    }
    public func changes() -> AsyncStream<Void> {
        let id = UUID()
        let (stream, continuation) = AsyncStream<Void>.makeStream(bufferingPolicy: .bufferingNewest(1))
        let presenter = FolderPresenter(folder: folder, continuation: continuation)
        presenters[id] = presenter
        NSFileCoordinator.addFilePresenter(presenter)
        continuation.onTermination = { [weak self] _ in Task { await self?.removePresenter(id) } }
        return stream
    }
    private func removePresenter(_ id: UUID) {
        if let presenter = presenters.removeValue(forKey: id) { NSFileCoordinator.removeFilePresenter(presenter) }
    }
    private func rejectSymlinks(_ path: String) throws {
        var url = folder
        guard folder.resolvingSymlinksInPath().path == folder.path else { throw StorageError.invalidPath(folder.path) }
        for component in path.split(separator: "/") {
            url.appendPathComponent(String(component))
            if (try? url.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink) == true { throw StorageError.invalidPath(path) }
        }
    }
    nonisolated private func checkAvailability(_ url: URL) throws {
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

extension FolderRecordStore: BlobStore {
    public func readBlob(_ path: String) throws -> Data {
        try BlobPath.validate(path); try rejectSymlinks(path)
        let url = folder.appendingPathComponent(path)
        try checkAvailability(url)
        return try AtomicFile.read(url, maximumBytes: 65536 + 16)
    }
    public func hasBlob(_ path: String) throws -> Bool {
        try BlobPath.validate(path); try rejectSymlinks(path)
        let url = folder.appendingPathComponent(path)
        try checkAvailability(url)
        return FileManager.default.fileExists(atPath: url.path)
    }
    public func removeBlob(_ path: String) throws {
        try BlobPath.validate(path); try rejectSymlinks(path)
        let url = folder.appendingPathComponent(path)
        do { try FileManager.default.removeItem(at: url) }
        catch let error as CocoaError where error.code == .fileNoSuchFile { }
        catch { throw StorageError.unavailable(error.localizedDescription) }
    }
    public func blobPaths() throws -> [String: Date] {
        let root = folder.appendingPathComponent("blobs")
        guard FileManager.default.fileExists(atPath: root.path) else { try checkAvailability(root); return [:] }
        let names: [String]
        do { names = try FileManager.default.contentsOfDirectory(atPath: root.path) }
        catch { throw StorageError.unavailable(error.localizedDescription) }
        var result: [String: Date] = [:]
        for name in names where !name.hasPrefix(".") {
            let path = "blobs/" + name
            guard (try? BlobPath.validate(path)) != nil else { continue }
            let values = try? root.appendingPathComponent(name).resourceValues(forKeys: [.contentModificationDateKey])
            result[path] = values?.contentModificationDate ?? .distantPast
        }
        return result
    }
    public func appendBlob(_ path: String, bytes: Data) throws {
        try BlobPath.validate(path); try rejectSymlinks(path)
        guard bytes.count <= 65536 + 16 else { throw StorageError.limitExceeded }
        try checkAvailability(folder)
        let write: (URL) throws -> Void = { root in
            try AtomicFile.write(bytes, to: root.appendingPathComponent(path), immutable: true)
        }
        if coordinated {
            var coordinationError: NSError?, writeError: (any Error)?
            NSFileCoordinator().coordinate(writingItemAt: folder, options: [], error: &coordinationError) { root in
                do { try write(root) } catch { writeError = error }
            }
            if let coordinationError { throw StorageError.unavailable(coordinationError.localizedDescription) }
            if let writeError { throw writeError }
        } else { try write(folder) }
    }
}
