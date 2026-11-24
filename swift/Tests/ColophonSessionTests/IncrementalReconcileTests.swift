import Foundation
import Testing
import ColophonKeys
import ColophonKit
import ColophonKitStorage
import ColophonSavedKit
@testable import ColophonSession

/// The reconcile before each write lists the whole medium but hands the engine only what changed since the listing it
/// last took. Writes with nothing changed outside take no full refresh; outside changes are still seen.
@MainActor struct IncrementalReconcileTests {
    @Test(.enabled(if: FileCoordinationProbe.available, FileCoordinationProbe.reason))
    func writesTakeOnlyWhatChangedAndStillSeeOutsideChanges() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let library = root.appendingPathComponent("library")
        let configuration = SessionConfiguration(memberLabel: "Mac", namespaces: ["reading.saved"], location: .folder(library),
            privateContainer: root.appendingPathComponent("first"), keys: SoftwareKeys(), ownerController: SoftwareKeys(),
            createWithoutHome: true, deviceSecrets: MemoryDeviceSecrets())
        var first: ColophonSession? = ColophonSession(configuration: configuration)
        await first?.create()
        #expect(first?.phase == .ready)
        // Another device over the same folder, through its own `FolderMedium`.
        let second = ColophonSession(configuration: .init(memberLabel: "Phone", namespaces: ["reading.saved"], location: .folder(library),
            privateContainer: root.appendingPathComponent("second"), keys: SoftwareKeys(), ownerController: SoftwareKeys(),
            createWithoutHome: true, deviceSecrets: MemoryDeviceSecrets()))
        await second.restore()
        try await approveByScan(joining: second, approving: try #require(first))
        await second.refresh()
        #expect(second.phase == .ready)
        first = nil

        // The first device relaunched as a bare worker: no folder watcher, so every reconcile below is a write's own.
        let worker = SessionWorker(configuration: configuration)
        var revision = try await worker.restore().revision
        for index in 0..<5 {
            revision = try await worker.write(try link("mine-\(index)"), observed: revision).1.revision
        }
        let quietFull = await worker.fullRefreshes
        let quietIncremental = await worker.incrementalRefreshes
        #expect(quietFull == 0, "writes with nothing changed outside take no full refresh")
        #expect(quietIncremental == 5)

        // A new operation file from the other device is read by the next write's reconcile: the write sees the
        // library moved on and is refused as stale.
        let before = try operationFiles(library)
        await second.refresh()
        try await second.perform(try link("outside"), observed: second.observedRevision)
        let outside = try operationFiles(library).subtracting(before)
        #expect(!outside.isEmpty)
        do {
            _ = try await worker.write(try link("after-outside"), observed: revision)
            Issue.record("the outside operation was not seen")
        } catch let refusal as SessionRefusal {
            #expect(refusal.error == .staleRevision)
            revision = refusal.snapshot.revision
        }
        revision = try await worker.write(try link("after-outside"), observed: revision).1.revision
        let items = String(decoding: try await worker.query(namespace: "reading.saved", name: "items", arguments: Data("{}".utf8)), as: UTF8.self)
        #expect(items.contains(#""id":"outside""#), "the other device's item is in this device's view")
        let seenFull = await worker.fullRefreshes
        #expect(seenFull == 0, "an added file is read without a full refresh")

        // A removed file makes the next reconcile refresh in full.
        let removed = try #require(outside.sorted().first)
        try FileManager.default.removeItem(at: library.appendingPathComponent(removed))
        _ = try? await worker.write(try link("after-removal"), observed: revision)
        let removalFull = await worker.fullRefreshes
        #expect(removalFull == 1, "a removed file is judged by a full refresh")
        revision = try await worker.refresh().revision

        // Other bytes at a verified operation's path are found by the next write, through the incremental path.
        let replaced = try #require(before.sorted().first)
        try Data("{\"replaced\":true}".utf8).write(to: library.appendingPathComponent(replaced), options: .atomic)
        do {
            _ = try await worker.write(try link("after-replacement"), observed: revision)
            Issue.record("the replaced operation was not seen")
        } catch let error as ColophonError {
            guard case .integrity = error else { Issue.record("expected an integrity failure, got \(error)"); return }
        }
        let replacementFull = await worker.fullRefreshes
        #expect(replacementFull == 1)
    }

    @Test func theDeltaIsWhatWasAddedOrChangedAndNilForEverythingElse() {
        func entries(_ pairs: [(String, String?)]) -> [MediumEntry] { pairs.map { MediumEntry(path: $0.0, version: $0.1) } }
        let old = entries([("a", "1"), ("b", "1"), ("c", "1")])
        let same = ListingBaseline.delta(from: old, to: old)
        #expect(same == [])
        let grown = ListingBaseline.delta(from: old, to: entries([("a", "1"), ("aa", "1"), ("b", "2"), ("c", "1"), ("d", "1")]))
        #expect(grown == entries([("aa", "1"), ("b", "2"), ("d", "1")]))
        let fromEmpty = ListingBaseline.delta(from: [], to: old)
        #expect(fromEmpty == old)
        #expect(ListingBaseline.delta(from: old, to: entries([("a", "1"), ("c", "1")])) == nil, "a removed path")
        #expect(ListingBaseline.delta(from: old, to: entries([("a", "1"), ("b", "1")])) == nil, "a removed last path")
        #expect(ListingBaseline.delta(from: old, to: entries([("b", "1"), ("c", "1")])) == nil, "a removed first path")
        #expect(ListingBaseline.delta(from: old, to: entries([("a", "1"), ("b", nil), ("c", "1")])) == nil, "a path without a version")
        #expect(ListingBaseline.delta(from: old, to: entries([("a", "1"), ("b", ""), ("c", "1")])) == nil, "an empty version")
        #expect(ListingBaseline.delta(from: old, to: entries([("a", "1"), ("c", "1"), ("b", "1")])) == nil, "out of path order")
        #expect(ListingBaseline.delta(from: old, to: entries([("a", "1"), ("a", "1"), ("b", "1"), ("c", "1")])) == nil, "a repeated path")
        #expect(ListingBaseline.isOrdered(old))
        #expect(!ListingBaseline.isOrdered(entries([("b", "1"), ("a", "1")])))
    }

    private func link(_ name: String) throws -> DomainCommand {
        try .saveLink(id: name, url: try #require(URL(string: "https://example.org/" + name)), title: name)
    }

    /// Every operation file under the folder, by its record path.
    private func operationFiles(_ library: URL) throws -> Set<String> {
        let ops = library.appendingPathComponent("ops")
        guard let walker = FileManager.default.enumerator(at: ops, includingPropertiesForKeys: [.isRegularFileKey]) else { return [] }
        var paths: Set<String> = []
        for case let url as URL in walker where try url.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile == true {
            let components = url.resolvingSymlinksInPath().pathComponents
            guard let index = components.lastIndex(of: "ops") else { continue }
            paths.insert(components[index...].joined(separator: "/"))
        }
        return paths
    }
}
