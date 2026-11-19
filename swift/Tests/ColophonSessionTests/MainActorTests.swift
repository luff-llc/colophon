import CryptoKit
import Darwin
import Foundation
import Testing
@testable import ColophonKitStorage
@testable import ColophonSession

/// A medium that records every call made on the main thread. Record and blob I/O belongs to the session's worker
/// and the blob executor, never to the main actor.
final class MainThreadWatchingMedium: RecordMedium, @unchecked Sendable {
    let base: any RecordMedium
    private let lock = NSLock()
    private var calls: [String] = []
    init(_ base: any RecordMedium) { self.base = base }
    var mainThreadCalls: [String] { lock.withLock { calls } }
    private func note(_ call: String) { if Thread.isMainThread { lock.withLock { calls.append(call) } } }
    func listing() throws -> [MediumEntry] { note("listing"); return try base.listing() }
    func read(_ path: String) throws -> Data { note("read " + path); return try base.read(path) }
    func readBlob(_ path: String) throws -> Data { note("readBlob " + path); return try base.readBlob(path) }
    func write(_ writes: [MediumWrite]) throws { note("write \(writes.count)"); try base.write(writes) }
    func changes() -> AsyncStream<Void> { base.changes() }
}

/// The process's physical footprint (what the system charges the process for), in bytes.
func physicalFootprint() -> UInt64 {
    var info = task_vm_info_data_t()
    var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<natural_t>.size)
    let result = withUnsafeMutablePointer(to: &info) {
        $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count) }
    }
    return result == KERN_SUCCESS ? info.phys_footprint : 0
}

/// Measures how late a main-actor timer fires while work runs elsewhere, and the footprint's peak.
@MainActor final class MainActorProbe {
    private(set) var worstLateness: Duration = .zero
    private(set) var ticks = 0
    private(set) var peakFootprint: UInt64 = 0
    private var task: Task<Void, Never>?
    func start() {
        task = Task { @MainActor [weak self] in
            let period = Duration.milliseconds(5)
            while !Task.isCancelled {
                let before = ContinuousClock.now
                try? await Task.sleep(for: period)
                guard let self else { return }
                let late = ContinuousClock.now - before - period
                if late > worstLateness { worstLateness = late }
                ticks += 1
                peakFootprint = max(peakFootprint, physicalFootprint())
            }
        }
    }
    func stop() { task?.cancel(); task = nil }
}

@MainActor @Suite(.serialized) struct MainActorTests {
    /// A 200 MB blob goes in from a file and comes back out to a file while the main actor keeps answering a 5 ms
    /// timer within 250 ms, no medium call runs on the main thread, and the footprint grows by far less than the blob
    /// (the chunks are streamed, never held whole). The blob executor itself refuses to run on the main thread
    /// (`dispatchPrecondition`), so a regression that moves the file work onto the main actor stops this test.
    @Test(.timeLimit(.minutes(5))) func aLargeBlobIsWrittenAndReadWithoutHoldingTheMainActor() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("main-actor-" + UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let watching = MainThreadWatchingMedium(FolderMedium(folder: root.appendingPathComponent("library"), coordinated: false))
        let session = ColophonSession(configuration: .init(memberLabel: "Mac", namespaces: ["reading.saved"], location: .medium(watching),
            privateContainer: root.appendingPathComponent("private"), keys: SoftwareKeys(), ownerController: SoftwareKeys(),
            createWithoutHome: true, deviceSecrets: MemoryDeviceSecrets()))
        await session.create()
        try #require(session.phase == .ready)
        session.stopSync()

        // 200 MB of non-repeating content, written off the main actor.
        let size = 200 * 1024 * 1024
        let source = root.appendingPathComponent("source.bin")
        let expected = try await Task.detached { () throws -> String in
            FileManager.default.createFile(atPath: source.path, contents: nil)
            let handle = try FileHandle(forWritingTo: source)
            defer { try? handle.close() }
            var hasher = SHA256()
            var block = [UInt8](repeating: 0, count: 1 << 20)
            for index in 0..<(size >> 20) {
                for offset in stride(from: 0, to: block.count, by: 8) {
                    withUnsafeBytes(of: UInt64(index << 20 + offset).littleEndian) { block.replaceSubrange(offset..<offset + 8, with: $0) }
                }
                hasher.update(data: block); try handle.write(contentsOf: block)
            }
            return hasher.finalize().map { String(format: "%02x", $0) }.joined()
        }.value

        let probe = MainActorProbe()
        let baseline = physicalFootprint()
        probe.start()
        let progressSeen = ProgressCounter()
        let blob = try await session.putBlob(contentsOf: source, namespace: "reading.saved", mediaType: "application/octet-stream",
                                             reference: "large", progress: { progressSeen.record($0) })
        #expect(blob.digest == expected && blob.size == size)
        let file = try await session.blobFile(namespace: "reading.saved", digest: blob.digest)
        defer { try? FileManager.default.removeItem(at: file) }
        probe.stop()
        print("main actor: worst lateness \(probe.worstLateness) over \(probe.ticks) ticks; footprint peak +\((probe.peakFootprint > baseline ? probe.peakFootprint - baseline : 0) >> 20) MiB")

        let written = try FileManager.default.attributesOfItem(atPath: file.path)[.size] as? Int
        #expect(written == size)
        #expect(probe.ticks > 10, "the timer ran while the blob moved")
        #expect(probe.worstLateness < .milliseconds(250), "the main actor was held for \(probe.worstLateness)")
        #expect(watching.mainThreadCalls.isEmpty, "medium calls on the main thread: \(watching.mainThreadCalls.prefix(5))")
        let growth = probe.peakFootprint > baseline ? probe.peakFootprint - baseline : 0
        #expect(growth < 96 * 1024 * 1024, "footprint grew by \(growth >> 20) MiB for a 200 MiB blob")
        #expect(progressSeen.stages == [.addressing, .storing] && progressSeen.last == Int64(size))
    }

    @Test func aRequestFileIsReadOffTheMainActorAndBounded() async throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("request-" + UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: url) }
        try Data(repeating: 1, count: 2048).write(to: url)
        #expect(try await BlobIO.readRequest(url).count == 2048)
        await #expect(throws: StorageError.limitExceeded) { _ = try await BlobIO.readRequest(url, maximumBytes: 1024) }
    }
}

final class ProgressCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var seen: [BlobProgress.Stage] = []
    private var lastStoring: Int64 = 0
    func record(_ progress: BlobProgress) {
        lock.withLock {
            if seen.last != progress.stage { seen.append(progress.stage) }
            if progress.stage == .storing { lastStoring = progress.completed }
        }
    }
    var stages: [BlobProgress.Stage] { lock.withLock { seen } }
    var last: Int64 { lock.withLock { lastStoring } }
}
