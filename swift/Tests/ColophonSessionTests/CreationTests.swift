import Foundation
import Testing
import ColophonSession

@MainActor struct CreationTests {
    @Test func createdAccountIsReadyAndShowsTheNoHomeWarning() async throws {
        let device = Device()
        await device.session.restore()
        #expect(device.session.phase == .noLibrary)
        await device.session.create()
        print("PHASE", device.session.phase, device.session.lastError ?? "-")
        for (path, bytes) in device.medium.snapshot().sorted(by: { $0.key < $1.key }) { print("FILE", path, bytes.count) }
        #expect(device.session.phase == .ready)
        #expect(device.session.notices.noHome)
        #expect(device.session.libraryID?.count == 64)
    }
}
