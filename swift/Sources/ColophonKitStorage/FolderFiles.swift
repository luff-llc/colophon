import Darwin
import Foundation

/// An open directory: every path below it is resolved one component at a time with `openat(…, O_NOFOLLOW)`, so a
/// symbolic link swapped in after a check is never followed (there is no check-then-use gap: the check is the open).
final class DirectoryHandle: @unchecked Sendable {
    let fd: Int32
    init(fd: Int32) { self.fd = fd }
    deinit { close(fd) }

    static func open(_ path: String) throws -> DirectoryHandle? {
        let fd = Darwin.open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        if fd < 0 {
            if errno == ENOENT { return nil }
            throw FolderFiles.failure(errno, path)
        }
        return DirectoryHandle(fd: fd)
    }

    /// The child directory `name`, created (0700) when `create` is set; nil when it is absent and `create` is not.
    func directory(_ name: String, create: Bool) throws -> DirectoryHandle? {
        var fd = openat(self.fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        if fd < 0, errno == ENOENT, create {
            if mkdirat(self.fd, name, 0o700) != 0, errno != EEXIST { throw FolderFiles.failure(errno, name) }
            fd = openat(self.fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        }
        if fd < 0 {
            if errno == ENOENT { return nil }
            throw FolderFiles.failure(errno, name)
        }
        return DirectoryHandle(fd: fd)
    }

    /// The bytes of the regular file `name`; nil when it is absent. A symbolic link or a non-regular file is refused.
    func read(_ name: String, maximumBytes: Int) throws -> Data? {
        let fd = openat(self.fd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        if fd < 0 {
            if errno == ENOENT { return nil }
            throw FolderFiles.failure(errno, name)
        }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0 else { throw FolderFiles.failure(errno, name) }
        guard (info.st_mode & S_IFMT) == S_IFREG else { throw StorageError.invalidPath(name) }
        guard Int(info.st_size) <= maximumBytes else { throw StorageError.limitExceeded }
        var data = Data(count: Int(info.st_size))
        var offset = 0
        try data.withUnsafeMutableBytes { buffer in
            guard let base = buffer.baseAddress else { return }
            while offset < buffer.count {
                let got = Darwin.read(fd, base + offset, buffer.count - offset)
                if got < 0 { if errno == EINTR { continue }; throw FolderFiles.failure(errno, name) }
                if got == 0 { break }
                offset += got
            }
        }
        guard offset == data.count else { throw StorageError.unavailable("Short read: \(name)") }
        // A file that grew after fstat is not ours to judge here; one byte more means it changed under us.
        var probe: UInt8 = 0
        guard Darwin.read(fd, &probe, 1) == 0 else { throw StorageError.unavailable("Changed while read: \(name)") }
        return data
    }

    /// Creates `name` exclusively (0600), writes `bytes`, synchronises it. Never follows a link, never replaces.
    func create(_ name: String, bytes: Data) throws {
        let fd = openat(self.fd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw FolderFiles.failure(errno, name) }
        defer { close(fd) }
        try bytes.withUnsafeBytes { buffer in
            guard let base = buffer.baseAddress else { return }
            var offset = 0
            while offset < buffer.count {
                let put = Darwin.write(fd, base + offset, buffer.count - offset)
                if put < 0 { if errno == EINTR { continue }; throw FolderFiles.failure(errno, name) }
                offset += put
            }
        }
        guard fsync(fd) == 0 else { throw FolderFiles.failure(errno, name) }
    }

    func sync() throws { guard fsync(fd) == 0 else { throw FolderFiles.failure(errno, "directory") } }

    /// Removes `name` (a file); an absent file is not an error.
    func remove(_ name: String) throws {
        if unlinkat(fd, name, 0) != 0, errno != ENOENT { throw FolderFiles.failure(errno, name) }
    }
    /// Removes the directory `name` and the files directly in it.
    func removeDirectory(_ name: String) throws {
        if let child = try directory(name, create: false) {
            for entry in try child.entries() where !entry.isDirectory { try child.remove(entry.name) }
        }
        if unlinkat(fd, name, AT_REMOVEDIR) != 0, errno != ENOENT { throw FolderFiles.failure(errno, name) }
    }

    struct Entry { let name: String; let isDirectory: Bool; let isSymlink: Bool; let isRegular: Bool; let info: stat }

    /// The entries of this directory (not `.` or `..`), with `lstat` information taken relative to the handle.
    func entries() throws -> [Entry] {
        let copy = dup(fd)
        guard copy >= 0 else { throw FolderFiles.failure(errno, "directory") }
        guard let stream = fdopendir(copy) else { close(copy); throw FolderFiles.failure(errno, "directory") }
        defer { closedir(stream) }
        rewinddir(stream)
        var out: [Entry] = []
        while true {
            errno = 0
            guard let item = readdir(stream) else {
                if errno != 0 { throw FolderFiles.failure(errno, "directory") }
                break
            }
            let name = withUnsafePointer(to: &item.pointee.d_name) {
                $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) { String(cString: $0) }
            }
            if name == "." || name == ".." { continue }
            var info = stat()
            guard fstatat(fd, name, &info, AT_SYMLINK_NOFOLLOW) == 0 else {
                if errno == ENOENT { continue }
                throw FolderFiles.failure(errno, name)
            }
            let kind = info.st_mode & S_IFMT
            out.append(Entry(name: name, isDirectory: kind == S_IFDIR, isSymlink: kind == S_IFLNK, isRegular: kind == S_IFREG, info: info))
        }
        return out
    }
}

enum FolderFiles {
    static func failure(_ code: Int32, _ what: String) -> StorageError {
        if code == ELOOP || code == ENOTDIR { return .invalidPath(what) }
        if code == EFBIG { return .limitExceeded }
        return .unavailable("\(what): \(String(cString: strerror(code)))")
    }

    /// An exclusive or shared `flock` on the journal's lock file, through its own open file description (so threads
    /// of one process exclude each other too). Released when the returned handle goes.
    final class Lock {
        private let fd: Int32
        init(_ journal: DirectoryHandle, exclusive: Bool) throws {
            let fd = openat(journal.fd, "lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
            guard fd >= 0 else { throw FolderFiles.failure(errno, "lock") }
            while flock(fd, exclusive ? LOCK_EX : LOCK_SH) != 0 {
                if errno == EINTR { continue }
                let code = errno
                close(fd)
                throw FolderFiles.failure(code, "lock")
            }
            self.fd = fd
        }
        deinit { flock(fd, LOCK_UN); close(fd) }
    }
}

/// What one batch publishes, written and synchronised before anything moves into place (the commit point).
struct BatchRecord: Codable, Equatable {
    struct Entry: Codable, Equatable {
        /// The record path, relative to the library folder.
        let path: String
        /// The staged file's name in the batch's staging directory.
        let staged: String
        /// Lowercase hex SHA-256 and size of the staged bytes.
        let digest: String
        let size: Int
        /// Replaced by rename (a live slot), or published by link (immutable).
        let replace: Bool
    }
    var version = 1
    let entries: [Entry]
}

/// A step of a batch, for the tests' crash and fault hooks.
package enum FolderBatchStep: Equatable, Sendable {
    /// The staged file of entry `n` is written and synchronised.
    case staged(Int)
    /// The batch record is durable: the batch now completes on any later open.
    case recorded
    /// Entry `n` is in place.
    case applied(Int)
    /// The batch record is removed: the batch is complete.
    case recordRemoved
    /// Removing a failed batch's staged files (before the commit point).
    case rollback
}
