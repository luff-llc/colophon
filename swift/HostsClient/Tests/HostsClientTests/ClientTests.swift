import Foundation
import Testing
import ColophonHosts
import ColophonSession
import HostsClient

@MainActor @Suite struct ClientTests {
    @Test func anAppOpensACellHostFromItsSessionWithThePublicAPIOnly() async throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("colophon-hosts-client-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: home) }
        let session = ColophonSession(configuration: SessionConfiguration(memberLabel: "App", namespaces: ["listening.podcasts"], location: .memory(MemoryMedium()),
            privateContainer: home, keys: SoftwareKeys(), ownerController: SoftwareKeys(), createWithoutHome: true, deviceSecrets: MemoryDeviceSecrets()))
        await session.create()
        try #require(session.phase == .ready)
        let cell = try await openCell(session: session, store: MemoryClaimStore())
        #expect(cell.state.joined)
        #expect(cell.host.snapshot?.joined == true)
        try await cell.take(Data("anchor".utf8))
        #expect(cell.host.snapshot?.isHolder == true)
        cell.close()
    }
}
