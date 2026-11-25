import Foundation

/// The data-protection class of the claim database's files on the device platforms.
///
/// `completeUntilFirstUserAuthentication`: readable while the device is locked after its first unlock, so that a
/// device playing in the background with its screen locked can still check its fence every beat (under `complete` the
/// reads would fail while locked and the cell would fail closed). SQLite creates the database when it opens it, the
/// `-wal` and `-shm` files later; each is set to this class, and read back, as soon as it exists, and a file that
/// already has another class (a stricter one from an earlier version, or none) is moved to it.
///
/// On macOS a file's protection attribute is not a data-protection class an app relies on, so nothing is set there and
/// the files are what the containing folder gives them.
enum ClaimFileProtection {
    #if os(macOS)
    static let applies = false
    #else
    static let applies = true
    #endif

    /// Sets the class on each of `paths` that exists and reads it back; returns the paths that now have it. Throws when
    /// a file's class cannot be set or does not read back as set.
    static func ensure(_ paths: [String]) throws -> Set<String> {
        guard applies else { return Set(paths) }
        #if os(macOS)
        return Set(paths)
        #else
        let wanted = FileProtectionType.completeUntilFirstUserAuthentication
        var done: Set<String> = []
        for path in paths where FileManager.default.fileExists(atPath: path) {
            if (try? FileManager.default.attributesOfItem(atPath: path)[.protectionKey] as? FileProtectionType) != wanted {
                do { try FileManager.default.setAttributes([.protectionKey: wanted], ofItemAtPath: path) } catch {
                    throw ClaimStoreError.storage("the claim file's protection class could not be set: \(error.localizedDescription)")
                }
            }
            let now = try? FileManager.default.attributesOfItem(atPath: path)[.protectionKey] as? FileProtectionType
            guard now == wanted else { throw ClaimStoreError.storage("the claim file's protection class reads back as \(now.map { $0.rawValue } ?? "none")") }
            done.insert(path)
        }
        return done
        #endif
    }
}
