import Foundation
import Testing
import ColophonKitStorage

/// Whether `filecoordinationd` answers here. A sandbox that denies it (an automated checker's) makes every coordinated
/// write fail with `unavailable("File coordination is unavailable: …")`, which is the right production behaviour; the
/// tests of the coordinated path are then skipped with this reason, and the uncoordinated tests cover the journal.
enum FileCoordinationProbe {
    static let available: Bool = {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("coordination-probe-" + UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        do { try FolderMedium(folder: root).write([MediumWrite(path: "probe/x.json", bytes: Data([1]))]); return true }
        catch { return false }
    }()
    static let reason: Comment = "filecoordinationd is unreachable in this environment (a sandbox): the coordinated path cannot run"
}
