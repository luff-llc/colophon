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
        let medium = FolderMedium(folder: root, coordinated: false)
        try FileManager.default.createDirectory(at: root.appendingPathComponent("authority"), withIntermediateDirectories: true)
        try Data().write(to: root.appendingPathComponent("authority/.00000002.json.icloud"))
        #expect(throws: StorageError.unavailable("iCloud download pending: .00000002.json.icloud")) { _ = try medium.listing() }
        #expect(throws: StorageError.self) { _ = try medium.read("authority/00000002.json") }
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
}
