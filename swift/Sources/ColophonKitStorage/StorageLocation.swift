import Foundation

public enum StorageLocation: Sendable {
    case privateContainer(URL)
    case appGroup(identifier: String, libraryName: String)
    case iCloud(container: String, libraryName: String)
    case folder(URL)
    case memory(MemoryRecordStore)

    /// Establishes this process's container access before using a persisted location.
    public func resolve() throws -> any RecordStore {
        switch self {
        case .memory(let store): return store
        case .privateContainer(let home): return FolderRecordStore(folder: home.appendingPathComponent("Library"))
        case .folder(let url): return FolderRecordStore(folder: url)
        case .appGroup(let identifier, let name):
            try validateName(name)
            guard let root = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: identifier) else {
                throw StorageError.unavailable("App Group container is inaccessible")
            }
            return FolderRecordStore(folder: root.appendingPathComponent(name))
        case .iCloud(let container, let name):
            try validateName(name)
            guard let root = FileManager.default.url(forUbiquityContainerIdentifier: container) else {
                throw StorageError.unavailable("iCloud container is inaccessible")
            }
            return FolderRecordStore(folder: root.appendingPathComponent("Documents").appendingPathComponent(name))
        }
    }
    private func validateName(_ name: String) throws {
        guard !name.isEmpty, name != ".", name != "..", !name.contains("/"), !name.contains("\\") else { throw StorageError.invalidPath(name) }
    }
}

/// Opaque engine-owned cache bytes. Only the engine may validate/use their verified prefix.
/// This folder must be in the app's private container, never the library or App Group.
public actor CheckpointCache {
    private let folder: URL
    public init(privateContainer: URL) { folder = privateContainer.appendingPathComponent("Checkpoints") }
    public func load(libraryID: String) throws -> Data? {
        let url = try location(libraryID)
        do { return try AtomicFile.read(url, maximumBytes: 64 * 1024 * 1024) }
        catch let error as CocoaError where error.code == .fileReadNoSuchFile || error.code == .fileNoSuchFile { return nil }
    }
    public func save(_ bytes: Data, libraryID: String) throws {
        guard bytes.count <= 64 * 1024 * 1024 else { throw StorageError.limitExceeded }
        let url = try location(libraryID)
        try AtomicFile.write(bytes, to: url)
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        var mutable = url
        try mutable.setResourceValues(values)
    }
    public func remove(libraryID: String) throws {
        let url = try location(libraryID)
        if FileManager.default.fileExists(atPath: url.path) { try FileManager.default.removeItem(at: url) }
    }
    private func location(_ id: String) throws -> URL {
        guard id.count == 32, id.allSatisfy({ $0.isHexDigit && !$0.isUppercase }) else { throw StorageError.invalidPath(id) }
        return folder.appendingPathComponent(id + ".checkpoint")
    }
}
