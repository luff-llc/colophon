import Foundation
import Darwin
import ColophonKitStorage

public struct IngressEnvelope: Codable, Equatable, Sendable, Identifiable {
    public let id: UUID
    public let libraryID: String
    public let memberID: String
    public let expires: Date
    public let command: DomainCommand
    public init(id: UUID = UUID(), libraryID: String, memberID: String, expires: Date = .now.addingTimeInterval(86400), command: DomainCommand) {
        self.id = id; self.libraryID = libraryID; self.memberID = memberID; self.expires = expires; self.command = command
    }
    func validate(now: Date = .now) throws {
        guard libraryID.count == 32, memberID.count == 32, expires > now,
              expires.timeIntervalSince(now) <= 7 * 86400, command.payload.count <= 32 * 1024,
              !command.namespace.isEmpty, !command.kind.isEmpty else { throw SessionError.invalidCommand }
    }
}

/// Extension-owned queue, never an authority or signing identity. The app validates grants.
/// This directory belongs in the App Group, separate from the immutable library records.
public actor IngressInbox {
    public let folder: URL
    public let maximumCount: Int
    public let maximumBytes: Int
    public init(appGroupContainer: URL, maximumCount: Int = 128, maximumBytes: Int = 64 * 1024) {
        folder = appGroupContainer.appendingPathComponent("ColophonIngress")
        self.maximumCount = max(1, min(maximumCount, 1024)); self.maximumBytes = max(1024, min(maximumBytes, 256 * 1024))
    }
    @discardableResult public func enqueue(_ envelope: IngressEnvelope) throws -> WriteReceipt {
        try envelope.validate()
        let bytes = try JSONEncoder().encode(envelope)
        guard bytes.count <= maximumBytes else { throw StorageError.limitExceeded }
        try withLock {
            let url = location(envelope.id)
            if FileManager.default.fileExists(atPath: url.path) {
                guard try AtomicFile.read(url, maximumBytes: maximumBytes) == bytes else { throw StorageError.conflict(envelope.id.uuidString) }
                return
            }
            guard try files().count < maximumCount else { throw StorageError.limitExceeded }
            try AtomicFile.write(bytes, to: url, immutable: true)
        }
        return .queued
    }
    public func pending() throws -> [IngressEnvelope] {
        try withLock {
            let urls = try files()
            guard urls.count <= maximumCount else { throw StorageError.limitExceeded }
            return try urls.map { url in
                let envelope = try JSONDecoder().decode(IngressEnvelope.self, from: AtomicFile.read(url, maximumBytes: maximumBytes))
                guard url.lastPathComponent == envelope.id.uuidString + ".json" else { throw SessionError.invalidCommand }
                return envelope
            }
        }
    }
    /// Only call after a saved receipt. Equality fences a replacement between read and ack.
    func acknowledge(_ envelope: IngressEnvelope) throws {
        try withLock {
            let url = location(envelope.id)
            let current = try JSONDecoder().decode(IngressEnvelope.self, from: AtomicFile.read(url, maximumBytes: maximumBytes))
            guard current == envelope else { throw SessionError.destinationChanged }
            try FileManager.default.removeItem(at: url)
        }
    }
    private func location(_ id: UUID) -> URL { folder.appendingPathComponent(id.uuidString + ".json") }
    private func files() throws -> [URL] {
        var failure: (any Error)?
        guard let enumerator = FileManager.default.enumerator(at: folder, includingPropertiesForKeys: nil,
            options: [.skipsSubdirectoryDescendants, .skipsHiddenFiles], errorHandler: { _, error in failure = error; return false })
        else { throw StorageError.unavailable("Cannot enumerate inbox") }
        var result: [URL] = []
        for case let url as URL in enumerator where url.pathExtension == "json" {
            guard result.count < maximumCount else { throw StorageError.limitExceeded }
            result.append(url)
        }
        if let failure { throw failure }
        return result.sorted { $0.lastPathComponent < $1.lastPathComponent }
    }
    private func withLock<T>(_ action: () throws -> T) throws -> T {
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let fd = open(folder.appendingPathComponent(".lock").path, O_CREAT | O_RDWR | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw StorageError.unavailable("Inbox is inaccessible") }
        defer { close(fd) }
        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else { throw StorageError.unavailable("Inbox is busy; retry") }
        defer { flock(fd, LOCK_UN) }
        return try action()
    }
}
