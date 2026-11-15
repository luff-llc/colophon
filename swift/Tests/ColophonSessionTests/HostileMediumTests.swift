import Foundation
import Testing
import ColophonSavedKit
import ColophonSession

@MainActor struct HostileMediumTests {
    @Test func aListingThatFailsIsRetryNeverEmptyAndRecovers() async throws {
        let device = Device()
        await device.session.create()
        device.medium.setFault(.throwOnListing("the disk is gone"))
        await device.session.refresh()
        #expect(device.session.phase == .retry, "\(device.session.phase)")
        #expect(device.session.lastError?.contains("disk is gone") == true)
        device.medium.setFault(.none)
        await device.session.refresh()
        #expect(device.session.phase == .ready)
    }

    @Test func aSourceThatReturnsGarbageOrThrowsNeverOpensALibrary() async throws {
        let device = Device()
        await device.session.create()
        for fault in [MemoryMedium.Fault.garbage(Data(repeating: 0xff, count: 17)), .throwOnRead("boom")] {
            device.medium.setFault(fault)
            let reader = Device(medium: device.medium, member: device.member, owner: device.owner)
            await reader.session.restore()
            #expect(reader.session.phase != .ready && !reader.session.hasUsableContent, "\(fault) gave \(reader.session.phase)")
            await #expect(throws: SessionError.notReady) { _ = try await reader.session.query(namespace: "reading.saved", name: "items", arguments: Data("{}".utf8)) }
        }
        device.medium.setFault(.none)
        let reader = Device(medium: device.medium, member: device.member, owner: device.owner)
        await reader.session.restore()
        #expect(reader.session.phase == .ready, "an honest source opens it again")
    }

    @Test func aWriteThatTheDiskRefusesLeavesNothingAndTheSessionRecovers() async throws {
        let device = Device()
        await device.session.create()
        let store = SavedStore(session: device.session)
        try await device.session.perform(try .saveLink(id: "a", url: URL(string: "https://example.org/a")!, title: "A"), observed: device.session.observedRevision)
        let before = device.medium.snapshot()
        device.medium.setFault(.failWrite(after: 0))
        await #expect(throws: StorageError.self) {
            try await device.session.perform(try .saveLink(id: "b", url: URL(string: "https://example.org/b")!, title: "B"), observed: device.session.observedRevision)
        }
        #expect(device.medium.snapshot() == before, "the failed finish left no file")
        device.medium.setFault(.none)
        await device.session.refresh()
        #expect(device.session.phase == .ready, "\(device.session.phase)")
        #expect(try await store.load(ItemsQuery(limit: 10)).get().total == 1, "the failed write is not in the history")
        try await device.session.perform(try .saveLink(id: "c", url: URL(string: "https://example.org/c")!, title: "C"), observed: device.session.observedRevision)
        #expect(try await store.load(ItemsQuery(limit: 10)).get().total == 2)
    }

    @Test func aMediumWriteIsAllOrNone() throws {
        let medium = MemoryMedium(files: ["authority/00000001.json": Data([1])])
        // The second write conflicts with immutable bytes: the first of the batch must not remain.
        #expect(throws: StorageError.conflict("authority/00000001.json")) {
            try medium.write([MediumWrite(path: "ops/a/b/000000000001-x.json", bytes: Data([9])), MediumWrite(path: "authority/00000001.json", bytes: Data([2]))])
        }
        #expect(medium.snapshot() == ["authority/00000001.json": Data([1])])
    }
}
