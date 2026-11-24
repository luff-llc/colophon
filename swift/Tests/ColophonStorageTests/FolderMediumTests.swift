import Foundation
import Testing
@testable import ColophonKitStorage

struct FolderMediumTests {
    private func folder() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    @Test func writesListsAndReadsAtThePathsTheCoreGives() throws {
        let root = try folder(); defer { try? FileManager.default.removeItem(at: root) }
        let medium = FolderMedium(folder: root, coordinated: false)
        #expect(try medium.listing().isEmpty, "a folder that does not exist yet is an empty store")
        try medium.write([MediumWrite(path: "authority/00000001.json", bytes: Data([1])), MediumWrite(path: "predecessor/authority/00000001.json", bytes: Data([2])),
                          MediumWrite(path: "ops/a/notes/000000000001-b.json", bytes: Data([3])), MediumWrite(path: "blobs/" + String(repeating: "c", count: 64), bytes: Data([4]))])
        let listing = try medium.listing()
        #expect(listing.map(\.path) == ["authority/00000001.json", "blobs/" + String(repeating: "c", count: 64), "ops/a/notes/000000000001-b.json", "predecessor/authority/00000001.json"])
        #expect(listing.allSatisfy { $0.version?.isEmpty == false }, "every path carries a version in the one listing")
        #expect(try medium.read("authority/00000001.json") == Data([1]))
        #expect(try medium.readBlob("blobs/" + String(repeating: "c", count: 64)) == Data([4]))
        #expect(try medium.readBlob("blobs/" + String(repeating: "d", count: 64)).isEmpty, "a chunk that is not held reads empty, not as an error")
        #expect(throws: StorageError.self) { _ = try medium.read("authority/00000009.json") }
        // A changed file gets a new version token.
        let before = try #require(listing.first { $0.path == "state/x" || $0.path == "authority/00000001.json" }?.version)
        try medium.write([MediumWrite(path: "state/a/notes/slot.json", bytes: Data([5]))])
        try medium.write([MediumWrite(path: "state/a/notes/slot.json", bytes: Data([6, 6]))])
        #expect(try medium.read("state/a/notes/slot.json") == Data([6, 6]), "a live slot is replaceable")
        #expect(try medium.listing().first { $0.path == "authority/00000001.json" }?.version == before)
    }

    @Test func aBatchThatConflictsPublishesNothing() throws {
        let root = try folder(); defer { try? FileManager.default.removeItem(at: root) }
        let medium = FolderMedium(folder: root, coordinated: false)
        try medium.write([MediumWrite(path: "authority/00000001.json", bytes: Data([1]))])
        #expect(throws: StorageError.conflict("authority/00000001.json")) {
            try medium.write([MediumWrite(path: "ops/a/notes/000000000001-b.json", bytes: Data([9])), MediumWrite(path: "authority/00000001.json", bytes: Data([2]))])
        }
        #expect(try medium.listing().map(\.path) == ["authority/00000001.json"], "the first write of the failed batch was not published")
        #expect(try medium.read("authority/00000001.json") == Data([1]), "immutable bytes are never overwritten")
        try medium.write([MediumWrite(path: "authority/00000001.json", bytes: Data([1]))])
    }

    @Test func aDirectoryPrefixOnlyListsThatSubtree() throws {
        let root = try folder(); defer { try? FileManager.default.removeItem(at: root) }
        let medium: any RecordMedium = FolderMedium(folder: root, coordinated: false)
        try medium.write([MediumWrite(path: "authority/one.json", bytes: Data([1]))])
        let unrelated = root.appendingPathComponent("authority/.two.json.icloud")
        try Data().write(to: unrelated)
        #expect(try medium.listing(prefix: "requests/").isEmpty)
        try medium.write([
            MediumWrite(path: "requests/z.json", bytes: Data([2])),
            MediumWrite(path: "requests/nested/b.json", bytes: Data([3])),
            MediumWrite(path: "requests/a.json", bytes: Data([4]))
        ])
        let scoped = try medium.listing(prefix: "requests/")
        #expect(scoped.map(\.path) == ["requests/a.json", "requests/nested/b.json", "requests/z.json"])
        #expect(try medium.listing(prefix: "requests") == scoped)
        #expect(try medium.listing(prefix: "requests/nested/").map(\.path) == ["requests/nested/b.json"])
        #expect(throws: StorageError.unavailable("iCloud download pending: .two.json.icloud")) { try medium.listing() }

        try FileManager.default.removeItem(at: unrelated)
        #expect(try medium.listing(prefix: "") == medium.listing())
        #expect(try medium.listing(prefix: "requests/a") == Array(scoped.prefix(1)))
        #expect(try medium.listing(prefix: "requests/a.json/").isEmpty)
    }

    @Test func aMaximumLengthNameDoesNotRequireARepresentablePlaceholderName() throws {
        let root = try folder(); defer { try? FileManager.default.removeItem(at: root) }
        let medium = FolderMedium(folder: root, coordinated: false)
        let path = "requests/" + String(repeating: "a", count: 255)
        let bytes = Data([1])
        try medium.write([MediumWrite(path: path, bytes: bytes)])
        #expect(try medium.read(path) == bytes)
        #expect(try medium.listing(prefix: path).map(\.path) == [path])
    }

    @Test func aDirectoryPrefixRespectsTheStoredCase() throws {
        let root = try folder(); defer { try? FileManager.default.removeItem(at: root) }
        let medium = FolderMedium(folder: root, coordinated: false)
        try medium.write([MediumWrite(path: "Requests/a.json", bytes: Data([1]))])
        #expect(try medium.listing(prefix: "requests/").isEmpty)
        #expect(try medium.listing(prefix: "Requests/").map(\.path) == ["Requests/a.json"])
    }

    @Test func aScopedListingRefusesSymlinksAndChecksPlaceholdersOnTheRequestedPath() throws {
        let root = try folder(); defer { try? FileManager.default.removeItem(at: root) }
        let medium = FolderMedium(folder: root, coordinated: false)
        let requests = root.appendingPathComponent("requests")
        try FileManager.default.createSymbolicLink(at: requests, withDestinationURL: root)
        #expect(throws: StorageError.invalidPath("requests")) { try medium.listing(prefix: "requests/nested/") }
        try FileManager.default.removeItem(at: requests)
        try Data().write(to: root.appendingPathComponent(".requests.icloud"))
        #expect(throws: StorageError.unavailable("iCloud download pending: .requests.icloud")) {
            try medium.listing(prefix: "requests/nested/")
        }
    }

    @Test func aScopedListingRefusesAnOverlongEmptyDirectory() throws {
        let root = try folder(); defer { try? FileManager.default.removeItem(at: root) }
        let medium = FolderMedium(folder: root, coordinated: false)
        let component = String(repeating: "a", count: 255)
        let path = "requests/\(component)/\(component)"
        try FileManager.default.createDirectory(at: root.appendingPathComponent(path), withIntermediateDirectories: true)
        #expect(throws: StorageError.invalidPath(path)) { try medium.listing(prefix: "requests/") }
        #expect(throws: StorageError.invalidPath(path)) { try medium.listing() }
    }

    @Test func pathsThatEscapeOrHideAreRefusedAndSymlinksAreNeverFollowed() throws {
        let root = try folder(); defer { try? FileManager.default.removeItem(at: root) }
        let medium = FolderMedium(folder: root, coordinated: false)
        for bad in ["../x.json", "/abs.json", "a//b.json", ".hidden/x.json", "a/.x.json", "a\\b.json", ""] {
            #expect(throws: StorageError.self, "\(bad)") { try medium.write([MediumWrite(path: bad, bytes: Data([1]))]) }
        }
        let outside = try folder(); defer { try? FileManager.default.removeItem(at: outside) }
        try Data([7]).write(to: outside.appendingPathComponent("target.json"))
        try FileManager.default.createDirectory(at: root.appendingPathComponent("authority"), withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(at: root.appendingPathComponent("authority/00000001.json"), withDestinationURL: outside.appendingPathComponent("target.json"))
        #expect(throws: StorageError.self) { _ = try medium.read("authority/00000001.json") }
        #expect(throws: StorageError.self) { _ = try medium.listing() }
    }

    @Test func anICloudPlaceholderIsUnavailableNeverAbsent() throws {
        let root = try folder(); defer { try? FileManager.default.removeItem(at: root) }
        let library = root.appendingPathComponent("library")
        let medium = FolderMedium(folder: library, coordinated: false)
        #expect(try medium.listing().isEmpty)
        try FileManager.default.createDirectory(at: library.appendingPathComponent("authority"), withIntermediateDirectories: true)
        try Data().write(to: library.appendingPathComponent("authority/.00000002.json.icloud"))
        #expect(throws: StorageError.unavailable("iCloud download pending: .00000002.json.icloud")) { _ = try medium.listing() }
        #expect(throws: StorageError.unavailable("iCloud download pending: .00000002.json.icloud")) { _ = try medium.read("authority/00000002.json") }
        #expect(throws: StorageError.unavailable("iCloud download pending: .00000002.json.icloud")) {
            try medium.write([MediumWrite(path: "authority/00000002.json", bytes: Data([2]))])
        }
    }

    @Test(.enabled(if: FileCoordinationProbe.available, FileCoordinationProbe.reason))
    func theCoordinatedPathWorksAndAWriteWakesTheObserver() async throws {
        let root = try folder(); defer { try? FileManager.default.removeItem(at: root) }
        let medium = FolderMedium(folder: root)
        var iterator = medium.changes().makeAsyncIterator()
        try medium.write([MediumWrite(path: "authority/00000001.json", bytes: Data([1]))])
        #expect(await iterator.next() != nil, "a hint arrives after a write")
        #expect(try medium.read("authority/00000001.json") == Data([1]))
    }

    /// A coordinator that is not told about this medium's own presenter waits on it: about half a second per write.
    /// 0.5.3 and earlier paid that on every write while a session watched its folder.
    @Test(.enabled(if: FileCoordinationProbe.available, FileCoordinationProbe.reason))
    func aWriteDoesNotWaitOnThisMediumsOwnPresenter() async throws {
        let root = try folder(); defer { try? FileManager.default.removeItem(at: root) }
        let medium = FolderMedium(folder: root)
        let watching = medium.changes()
        var durations: [Duration] = []
        for index in 0..<5 {
            let started = ContinuousClock.now
            try medium.write([MediumWrite(path: "ops/a/listening/\(index)-x.json", bytes: Data([UInt8(index)]))])
            durations.append(ContinuousClock.now - started)
        }
        let median = durations.sorted()[2]
        #expect(median < .milliseconds(200), "a coordinated write waited \(median) with an observer open")
        withExtendedLifetime(watching) {}
    }

    @Test(.enabled(if: FileCoordinationProbe.available, FileCoordinationProbe.reason))
    func everyObserverHearsAWriteAndOneEndingLeavesTheOthers() async throws {
        let root = try folder(); defer { try? FileManager.default.removeItem(at: root) }
        let medium = FolderMedium(folder: root)
        var first = medium.changes().makeAsyncIterator()
        var second = medium.changes().makeAsyncIterator()
        let thirdStream = medium.changes()
        let third = Task { for await _ in thirdStream {} }
        try medium.write([MediumWrite(path: "authority/00000001.json", bytes: Data([1]))])
        #expect(await first.next() != nil)
        #expect(await second.next() != nil)
        third.cancel()
        _ = await third.value
        let registered = NSFileCoordinator.filePresenters.contains { $0.presentedItemURL == medium.folder }
        #expect(registered, "the presenter stays registered while other streams are open")
        try medium.write([MediumWrite(path: "authority/00000002.json", bytes: Data([2]))])
        #expect(await first.next() != nil, "the remaining observers still hear writes")
        #expect(await second.next() != nil)
    }

    /// Another writer's change reaches this medium through its presenter, not through `signal()`.
    @Test(.enabled(if: FileCoordinationProbe.available, FileCoordinationProbe.reason), .timeLimit(.minutes(1)))
    func anotherWritersChangeReachesTheObserverThroughThePresenter() async throws {
        let root = try folder(); defer { try? FileManager.default.removeItem(at: root) }
        let watched = FolderMedium(folder: root)
        try watched.write([MediumWrite(path: "authority/00000001.json", bytes: Data([1]))])
        var hints = watched.changes().makeAsyncIterator()
        try FolderMedium(folder: root).write([MediumWrite(path: "authority/00000002.json", bytes: Data([2]))])
        #expect(await hints.next() != nil, "a write by another medium wakes this medium's observer")
    }
}
