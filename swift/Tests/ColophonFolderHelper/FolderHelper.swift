import Darwin
import Foundation
import ColophonKitStorage

/// A second process for the folder medium's tests (never shipped):
///
///   crash <folder> <step>          writes `FolderHelper.batch` and is killed (SIGKILL) at `step`
///                                  (`staged:N`, `recorded`, `applied:N`, `recordRemoved`)
///   watch <folder> <stop-file> <batch-size>
///                                  lists until `stop-file` exists; prints `listings L violations V` where a violation
///                                  is a listing that holds some but not all files of one batch
///   write <folder> <batches> <batch-size>
///                                  writes that many batches, one after another
@main enum FolderHelper {
    /// The batch the crash mode writes: four immutable records and two replaceable slots.
    static let batch: [MediumWrite] = [
        MediumWrite(path: "authority/00000002.json", bytes: Data("{\"seq\":2}".utf8)),
        MediumWrite(path: "ops/a/notes/000000000002-b.json", bytes: Data("{\"op\":2}".utf8)),
        MediumWrite(path: "transitions/aa.json", bytes: Data("{\"t\":2}".utf8)),
        MediumWrite(path: "receipts/aa/home.json", bytes: Data("{\"r\":2}".utf8)),
        MediumWrite(path: "state/a/notes/slot.json", bytes: Data("{\"slot\":2}".utf8)),
        MediumWrite(path: "heads/home.json", bytes: Data("{\"head\":2}".utf8)),
    ]

    static func main() {
        let arguments = CommandLine.arguments
        guard arguments.count >= 3 else { fail("usage") }
        let medium = FolderMedium(folder: URL(fileURLWithPath: arguments[2]), coordinated: false)
        switch arguments[1] {
        case "crash":
            guard arguments.count == 4 else { fail("usage") }
            let target = arguments[3]
            medium.batchHook = { step in
                let name: String = switch step {
                case .staged(let n): "staged:\(n)"
                case .recorded: "recorded"
                case .applied(let n): "applied:\(n)"
                case .recordRemoved: "recordRemoved"
                case .rollback: "rollback"
                }
                if name == target { kill(getpid(), SIGKILL) }
            }
            do { try medium.write(batch) } catch { fail("write: \(error)") }
            print("finished without reaching \(target)")
        case "watch":
            guard arguments.count == 5, let size = Int(arguments[4]) else { fail("usage") }
            let stop = URL(fileURLWithPath: arguments[3])
            var listings = 0, violations = 0
            print("ready"); fflush(stdout)
            while !FileManager.default.fileExists(atPath: stop.path) {
                guard let entries = try? medium.listing() else { violations += 1; continue }
                listings += 1
                var counts: [String: Int] = [:]
                for entry in entries where entry.path.hasPrefix("ops/w/") {
                    let group = entry.path.split(separator: "/")[2]
                    counts[String(group), default: 0] += 1
                }
                if counts.values.contains(where: { $0 != size }) { violations += 1 }
            }
            print("listings \(listings) violations \(violations)")
        case "write":
            guard arguments.count == 5, let count = Int(arguments[3]), let size = Int(arguments[4]) else { fail("usage") }
            for index in 0..<count {
                do { try medium.write(group(index, size: size)) } catch { fail("write: \(error)") }
            }
        default: fail("usage")
        }
    }

    static func group(_ index: Int, size: Int) -> [MediumWrite] {
        (0..<size).map { MediumWrite(path: "ops/w/b\(index)/f\($0).json", bytes: Data("{\"b\":\(index),\"f\":\($0)}".utf8)) }
            + [MediumWrite(path: "state/w/slot.json", bytes: Data("{\"b\":\(index)}".utf8))]
    }

    static func fail(_ message: String) -> Never {
        FileHandle.standardError.write(Data((message + "\n").utf8))
        exit(2)
    }
}
