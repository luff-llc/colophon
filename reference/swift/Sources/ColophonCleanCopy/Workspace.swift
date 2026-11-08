import CryptoKit
import Darwin
import Foundation

/// Failures that prevent a clean copy from being certified.
public enum CleanCopyError: Error, Equatable, Sendable {
    /// A source or snapshot file changed since its manifest was recorded.
    case changedSource(String)
    /// A path overlaps the source, or contains an unsupported filesystem entry.
    case unsafePath(String)
    /// The working directory belongs to another source or destination.
    case workspaceMismatch
    /// Another process owns this working directory.
    case busy
    /// The dedicated reader has not received all requested read grants and shares.
    case approvalRequired
    /// Verification is blocked by an unanswered specification question.
    case verificationUnavailable
    /// An existing destination was not created by this workspace.
    case destinationExists
}

/// A private, durable snapshot and its source digest manifest. No method writes the source.
public struct CleanCopyWorkspace: Sendable {
    /// The host-owned private working directory.
    public let directory: URL
    /// Open an existing workspace; metadata is validated when an operation starts.
    public init(directory: URL) { self.directory = canonicalLocation(directory) }

    /// Copy exact file bytes using FileManager. Repeating this before import refreshes approval
    /// records; repeating it after import only accepts the original unchanged source.
    @discardableResult
    public static func snapshot(source: URL, work: URL) throws -> Self {
        let source = canonicalLocation(source)
        let workspace = Self(directory: work)
        guard !overlaps(source, workspace.directory) else { throw CleanCopyError.unsafePath(work.path) }
        try privateDirectory(workspace.directory)
        let lease = try WorkspaceLease(directory: workspace.directory)
        defer { lease.close() }
        let metadataURL = workspace.directory.appendingPathComponent("workspace.json")
        if FileManager.default.fileExists(atPath: metadataURL.path) {
            let existing = try workspace.metadata()
            guard existing.source == source.path else { throw CleanCopyError.workspaceMismatch }
            if FileManager.default.fileExists(atPath: workspace.directory.appendingPathComponent("destination.json").path) {
                try workspace.assertSourceUnchanged()
                try workspace.assertSnapshotUnchanged()
                return workspace
            }
        } else {
            // Do not adopt an unrelated directory or overwrite its private files.
            let names = try FileManager.default.contentsOfDirectory(atPath: workspace.directory.path)
            guard Set(names).isSubset(of: ["workspace.lock"]) else { throw CleanCopyError.workspaceMismatch }
        }
        let before = try fileManifest(source)
        let staged = workspace.directory.appendingPathComponent("snapshot-" + UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: staged) }
        try FileManager.default.copyItem(at: source, to: staged)
        try privatize(staged)
        guard try fileManifest(staged) == before else { throw CleanCopyError.changedSource("snapshot") }
        guard try fileManifest(source) == before else { throw CleanCopyError.changedSource(source.path) }
        let requestURL = workspace.directory.appendingPathComponent("reader-request.json")
        if FileManager.default.fileExists(atPath: requestURL.path) {
            let request = try JSONDecoder().decode(ReaderRequest.self, from: Data(contentsOf: requestURL))
            try writePrivate(request.bytes, to: staged.appendingPathComponent(request.path))
        }
        let snapshot = workspace.snapshotDirectory
        if FileManager.default.fileExists(atPath: snapshot.path) { try FileManager.default.removeItem(at: snapshot) }
        try FileManager.default.moveItem(at: staged, to: snapshot)
        try writePrivate(try encode(before), to: workspace.directory.appendingPathComponent("source-manifest.json"))
        try writePrivate(try encode(WorkspaceMetadata(source: source.path)), to: metadataURL)
        return workspace
    }

    /// Rehash the original source only for this integrity check; all protocol reads use the snapshot.
    public func assertSourceUnchanged() throws {
        let source = URL(fileURLWithPath: try metadata().source, isDirectory: true)
        let expected = try manifest()
        let current = try fileManifest(source)
        guard current == expected else {
            let changed = Set(current.keys).union(expected.keys).filter { current[$0] != expected[$0] }.sorted()
            throw CleanCopyError.changedSource(changed.joined(separator: ", "))
        }
    }

    /// Refuse a destination within the original source, or overlapping private workspace data.
    public func validateDestination(_ destination: URL) throws {
        let destination = canonicalLocation(destination)
        let source = URL(fileURLWithPath: try metadata().source, isDirectory: true)
        guard !overlaps(destination, source), !overlaps(destination, directory) else {
            throw CleanCopyError.unsafePath(destination.path)
        }
    }

    var snapshotDirectory: URL { directory.appendingPathComponent("source", isDirectory: true) }
    func metadata() throws -> WorkspaceMetadata {
        try JSONDecoder().decode(WorkspaceMetadata.self, from: Data(contentsOf: directory.appendingPathComponent("workspace.json")))
    }
    func manifest() throws -> [String: String] {
        try JSONDecoder().decode([String: String].self, from: Data(contentsOf: directory.appendingPathComponent("source-manifest.json")))
    }
    func assertSnapshotUnchanged() throws {
        var current = try fileManifest(snapshotDirectory)
        var expected = try manifest()
        let requestURL = directory.appendingPathComponent("reader-request.json")
        if FileManager.default.fileExists(atPath: requestURL.path) {
            let request = try JSONDecoder().decode(ReaderRequest.self, from: Data(contentsOf: requestURL))
            // The sole intentional snapshot mutation is our own exported request.
            guard current[request.path] == digest(request.bytes) else { throw CleanCopyError.changedSource(request.path) }
            current[request.path] = nil; expected[request.path] = nil
        }
        guard current == expected else { throw CleanCopyError.changedSource("private snapshot") }
    }
    func snapshotRecords() throws -> [String: Data] {
        try assertSnapshotUnchanged()
        var records: [String: Data] = [:]
        for path in try fileManifest(snapshotDirectory).keys {
            records[path] = try Data(contentsOf: snapshotDirectory.appendingPathComponent(path))
        }
        return records
    }
}

struct WorkspaceMetadata: Codable { let source: String }

func canonicalLocation(_ url: URL) -> URL {
    var ancestor = url.standardizedFileURL
    var suffix: [String] = []
    while !FileManager.default.fileExists(atPath: ancestor.path), ancestor.path != "/" {
        suffix.append(ancestor.lastPathComponent); ancestor.deleteLastPathComponent()
    }
    var result = ancestor.resolvingSymlinksInPath()
    for component in suffix.reversed() { result.appendPathComponent(component) }
    return result.standardizedFileURL
}

func overlaps(_ first: URL, _ second: URL) -> Bool {
    first.path == second.path || first.path.hasPrefix(second.path + "/") || second.path.hasPrefix(first.path + "/")
}
func digest(_ bytes: Data) -> String { SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined() }
func encode<T: Encodable>(_ value: T) throws -> Data {
    let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .prettyPrinted, .withoutEscapingSlashes]
    return try encoder.encode(value)
}
func privateDirectory(_ directory: URL) throws {
    let manager = FileManager.default
    if manager.fileExists(atPath: directory.path) {
        let attrs = try manager.attributesOfItem(atPath: directory.path)
        guard attrs[.type] as? FileAttributeType == .typeDirectory else { throw CleanCopyError.unsafePath(directory.path) }
    } else { try manager.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700]) }
    try manager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
}
func writePrivate(_ bytes: Data, to url: URL) throws {
    try privateDirectory(url.deletingLastPathComponent())
    if FileManager.default.fileExists(atPath: url.path) {
        guard try FileManager.default.attributesOfItem(atPath: url.path)[.type] as? FileAttributeType == .typeRegular else {
            throw CleanCopyError.unsafePath(url.path)
        }
    }
    try bytes.write(to: url, options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
}
func fileManifest(_ root: URL) throws -> [String: String] {
    let root = root.standardizedFileURL.resolvingSymlinksInPath()
    let manager = FileManager.default
    guard try manager.attributesOfItem(atPath: root.path)[.type] as? FileAttributeType == .typeDirectory else {
        throw CleanCopyError.unsafePath(root.path)
    }
    var scanError: (any Error)?
    guard let enumerator = manager.enumerator(at: root, includingPropertiesForKeys: [.isRegularFileKey, .isDirectoryKey, .isSymbolicLinkKey],
        errorHandler: { _, error in scanError = error; return false }) else { throw CleanCopyError.unsafePath(root.path) }
    var result: [String: String] = [:]
    for case let url as URL in enumerator {
        let values = try url.resourceValues(forKeys: [.isRegularFileKey, .isDirectoryKey, .isSymbolicLinkKey])
        guard values.isSymbolicLink != true, values.isDirectory == true || values.isRegularFile == true else {
            throw CleanCopyError.unsafePath(url.path)
        }
        if values.isRegularFile == true {
            let canonical = url.standardizedFileURL.resolvingSymlinksInPath()
            guard canonical.path.hasPrefix(root.path + "/") else { throw CleanCopyError.unsafePath(url.path) }
            let path = String(canonical.path.dropFirst(root.path.count + 1))
            result[path] = digest(try Data(contentsOf: url))
        }
    }
    if let scanError { throw scanError }
    return result
}
func privatize(_ root: URL) throws {
    try privateDirectory(root)
    let manifest = try fileManifest(root)
    for path in manifest.keys {
        let url = root.appendingPathComponent(path)
        var parent = url.deletingLastPathComponent()
        while parent.path.hasPrefix(root.path + "/") {
            try privateDirectory(parent); parent.deleteLastPathComponent()
        }
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}

final class WorkspaceLease {
    private var descriptor: Int32
    init(directory: URL) throws {
        descriptor = open(directory.appendingPathComponent("workspace.lock").path, O_CREAT | O_RDWR | O_NOFOLLOW, 0o600)
        guard descriptor >= 0 else { throw CleanCopyError.busy }
        guard flock(descriptor, LOCK_EX | LOCK_NB) == 0 else { Darwin.close(descriptor); descriptor = -1; throw CleanCopyError.busy }
        do { try rejectSymlinkEntries(directory) }
        catch { close(); throw error }
    }
    func close() {
        if descriptor >= 0 { flock(descriptor, LOCK_UN); Darwin.close(descriptor); descriptor = -1 }
    }
    deinit { close() }
}

// SDK journals and encrypted staging files also live here. Reject links before handing any
// of these paths to the SDK, so an existing link cannot redirect a private write to the source.
private func rejectSymlinkEntries(_ directory: URL) throws {
    var scanError: (any Error)?
    guard let enumerator = FileManager.default.enumerator(at: directory,
        includingPropertiesForKeys: [.isSymbolicLinkKey, .isDirectoryKey, .isRegularFileKey],
        errorHandler: { _, error in scanError = error; return false }) else { throw CleanCopyError.unsafePath(directory.path) }
    for case let url as URL in enumerator {
        let values = try url.resourceValues(forKeys: [.isSymbolicLinkKey, .isDirectoryKey, .isRegularFileKey])
        guard values.isSymbolicLink != true, values.isDirectory == true || values.isRegularFile == true else {
            throw CleanCopyError.unsafePath(url.path)
        }
    }
    if let scanError { throw scanError }
}

extension CleanCopyError: LocalizedError {
    /// Actionable diagnostics for the command-line host.
    public var errorDescription: String? {
        switch self {
        case .changedSource(let path): "Source integrity check failed: \(path). Preserve the workspace and inspect report.json."
        case .unsafePath(let path): "Unsafe or overlapping path: \(path)."
        case .workspaceMismatch: "This workspace belongs to a different source, destination or owner, or required private state is missing."
        case .busy: "Another clean-copy process owns this workspace."
        case .approvalRequired: "Approve the exported reader request on a controller device, then rerun snapshot SRC WORK."
        case .verificationUnavailable: "Copy is not certified. Inspect report.md for unresolved records, failures and accounting/view comparisons."
        case .destinationExists: "Destination already exists and was not created by this workspace. Choose a new path."
        }
    }
}
