import Darwin
import Foundation
import Testing
@testable import ColophonKitStorage

/// The folder medium's batches: all or none across a process kill at every step, across a second process listing
/// while batches publish, and across failures (including a rollback that fails).
@Suite(.serialized) struct FolderBatchTests {
    private func folder() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("batch-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    /// The helper executable, built with the tests (`ColophonFolderHelper`).
    static var helper: URL {
        var candidates: [URL] = []
        if let bundle = Bundle.allBundles.first(where: { $0.bundlePath.hasSuffix(".xctest") }) {
            candidates.append(bundle.bundleURL.deletingLastPathComponent().appendingPathComponent("ColophonFolderHelper"))
        }
        let repository = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        candidates.append(repository.appendingPathComponent(".build/debug/ColophonFolderHelper"))
        return candidates.first { FileManager.default.isExecutableFile(atPath: $0.path) } ?? candidates[candidates.count - 1]
    }

    private func run(_ arguments: [String]) throws -> (status: Int32, reason: Process.TerminationReason, output: String) {
        let process = Process()
        process.executableURL = Self.helper
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        try process.run()
        let output = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (process.terminationStatus, process.terminationReason, String(decoding: output, as: UTF8.self))
    }

    /// The state before the batch: one record and the two live slots the batch replaces.
    private let before: [MediumWrite] = [
        MediumWrite(path: "authority/00000001.json", bytes: Data("{\"seq\":1}".utf8)),
        MediumWrite(path: "state/a/notes/slot.json", bytes: Data("{\"slot\":1}".utf8)),
        MediumWrite(path: "heads/home.json", bytes: Data("{\"head\":1}".utf8)),
    ]
    private let batch: [(String, String)] = [
        ("authority/00000002.json", "{\"seq\":2}"), ("ops/a/notes/000000000002-b.json", "{\"op\":2}"), ("transitions/aa.json", "{\"t\":2}"),
        ("receipts/aa/home.json", "{\"r\":2}"), ("state/a/notes/slot.json", "{\"slot\":2}"), ("heads/home.json", "{\"head\":2}"),
    ]

    private func journalLeftovers(_ root: URL) throws -> [String] {
        try FileManager.default.contentsOfDirectory(atPath: root.appendingPathComponent(".colophon.nosync").path).filter { $0 != "lock" }.sorted()
    }

    /// Killed at every step of a batch, the folder reopens (in this process) to the batch entirely absent before the
    /// commit point and entirely present from it on, with nothing left in the journal.
    @Test func aProcessKilledAtEveryStepLeavesTheBatchAllOrNone() throws {
        let steps = (0..<6).map { "staged:\($0)" } + ["recorded"] + (0..<6).map { "applied:\($0)" } + ["recordRemoved"]
        for step in steps {
            let root = try folder(); defer { try? FileManager.default.removeItem(at: root) }
            try FolderMedium(folder: root, coordinated: false).write(before)
            let result = try run(["crash", root.path, step])
            #expect(result.reason == .uncaughtSignal && result.status == SIGKILL, "the helper was killed at \(step): \(result.output)")
            // A batch was left on disk as it was at the kill.
            let reopened = FolderMedium(folder: root, coordinated: false)
            let paths = Set(try reopened.listing().map(\.path))
            let committed = !step.hasPrefix("staged")
            for (path, text) in batch {
                if committed {
                    #expect(try reopened.read(path) == Data(text.utf8), "\(step): \(path) carries the batch's bytes")
                } else if path.hasPrefix("state/") || path.hasPrefix("heads/") {
                    #expect(try reopened.read(path) != Data(text.utf8), "\(step): \(path) keeps its earlier bytes")
                } else {
                    #expect(!paths.contains(path), "\(step): \(path) was not published")
                }
            }
            #expect(try reopened.read("authority/00000001.json") == Data("{\"seq\":1}".utf8))
            #expect(try journalLeftovers(root).isEmpty, "\(step): the journal is clean after the reopen")
        }
    }

    /// A second process lists continuously while this one publishes 40 batches of 8 files: no listing ever holds part
    /// of a batch.
    @Test func aSecondProcessNeverListsHalfABatch() throws {
        let root = try folder(); defer { try? FileManager.default.removeItem(at: root) }
        let stop = root.appendingPathComponent("stop")
        let library = root.appendingPathComponent("library")
        let medium = FolderMedium(folder: library, coordinated: false)
        try medium.write([MediumWrite(path: "authority/00000001.json", bytes: Data("{}".utf8))])
        let process = Process()
        process.executableURL = Self.helper
        process.arguments = ["watch", library.path, stop.path, "8"]
        let pipe = Pipe()
        process.standardOutput = pipe
        try process.run()
        // Wait for the watcher to start listing.
        var ready = Data()
        while !String(decoding: ready, as: UTF8.self).contains("ready") { ready += pipe.fileHandleForReading.availableData }
        for index in 0..<40 {
            try medium.write((0..<8).map { MediumWrite(path: "ops/w/b\(index)/f\($0).json", bytes: Data("{\"b\":\(index),\"f\":\($0)}".utf8)) }
                             + [MediumWrite(path: "state/w/slot.json", bytes: Data("{\"b\":\(index)}".utf8))])
        }
        FileManager.default.createFile(atPath: stop.path, contents: Data())
        let rest = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        let report = String(decoding: ready + rest, as: UTF8.self)
        let numbers = report.split(whereSeparator: { !$0.isNumber }).compactMap { Int($0) }
        #expect(process.terminationStatus == 0, "\(report)")
        #expect(numbers.count >= 2 && numbers[numbers.count - 1] == 0, "listings with part of a batch: \(report)")
        #expect((numbers.first ?? 0) > 0, "the watcher listed: \(report)")
        #expect(try medium.listing().filter { $0.path.hasPrefix("ops/w/") }.count == 320)
    }

    /// An I/O failure while staging publishes nothing; when removing the staged files fails too, the error says so and
    /// the next open removes them.
    @Test func aRollbackThatFailsIsReportedAndRepairedOnTheNextOpen() throws {
        let root = try folder(); defer { try? FileManager.default.removeItem(at: root) }
        let medium = FolderMedium(folder: root, coordinated: false)
        try medium.write(before)
        struct Injected: Error {}
        medium.batchHook = { step in if step == .staged(2) || step == .rollback { throw Injected() } }
        let writes = batch.map { MediumWrite(path: $0.0, bytes: Data($0.1.utf8)) }
        do { try medium.write(writes); Issue.record("the injected failure was not reported") }
        catch StorageError.unavailable(let reason) {
            #expect(reason.contains("not published") && reason.contains("could not be removed"), "\(reason)")
        }
        #expect(try !journalLeftovers(root).isEmpty, "the staged files are still there")
        medium.batchHook = nil
        let paths = Set(try medium.listing().map(\.path))
        #expect(!paths.contains("authority/00000002.json") && !paths.contains("transitions/aa.json"))
        #expect(try medium.read("state/a/notes/slot.json") == Data("{\"slot\":1}".utf8))
        #expect(try journalLeftovers(root).isEmpty, "the open removed them")
        // A plain staging failure rolls back without leaving anything.
        medium.batchHook = { step in if step == .staged(1) { throw Injected() } }
        #expect(throws: Injected.self) { try medium.write(writes) }
        #expect(try journalLeftovers(root).isEmpty)
    }

    /// A failure after the commit point is reported as such; the next open (here a new instance, as another process
    /// would be) completes the batch.
    @Test func aFailureAfterTheCommitPointIsCompletedOnTheNextOpen() throws {
        let root = try folder(); defer { try? FileManager.default.removeItem(at: root) }
        let medium = FolderMedium(folder: root, coordinated: false)
        try medium.write(before)
        struct Injected: Error {}
        medium.batchHook = { step in if step == .applied(1) { throw Injected() } }
        do { try medium.write(batch.map { MediumWrite(path: $0.0, bytes: Data($0.1.utf8)) }); Issue.record("not reported") }
        catch StorageError.unavailable(let reason) { #expect(reason.contains("completed on the next open"), "\(reason)") }
        let other = FolderMedium(folder: root, coordinated: false)
        for (path, text) in batch { #expect(try other.read(path) == Data(text.utf8), "\(path)") }
        #expect(try journalLeftovers(root).isEmpty)
    }

    /// A parent directory that is a symbolic link is refused for writes and reads, and nothing lands where it points.
    @Test func aSymlinkedParentIsNeverWrittenThrough() throws {
        let root = try folder(), outside = try folder()
        defer { try? FileManager.default.removeItem(at: root); try? FileManager.default.removeItem(at: outside) }
        let medium = FolderMedium(folder: root, coordinated: false)
        try FileManager.default.createSymbolicLink(at: root.appendingPathComponent("ops"), withDestinationURL: outside)
        #expect(throws: StorageError.self) { try medium.write([MediumWrite(path: "ops/a/x.json", bytes: Data([1]))]) }
        #expect(try FileManager.default.contentsOfDirectory(atPath: outside.path).isEmpty, "nothing was written through the link")
        try Data([2]).write(to: outside.appendingPathComponent("y.json"))
        #expect(throws: StorageError.self) { _ = try medium.read("ops/y.json") }
        #expect(throws: StorageError.self) { _ = try medium.listing() }
    }
}
