import Foundation
import Testing
import ColophonKeys
import ColophonSavedKit
import ColophonSession

/// One device of a test account: a session over a shared medium, with software keys.
@MainActor final class Device {
    let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let medium: MemoryMedium
    let member: SoftwareKeys
    let owner: SoftwareKeys
    let session: ColophonSession
    init(medium: MemoryMedium = MemoryMedium(), member: SoftwareKeys = SoftwareKeys(), owner: SoftwareKeys = SoftwareKeys(),
         homes: [HomeConfiguration] = [], createWithoutHome: Bool = true, recovery: SoftwareKeys? = nil, additional: [AdditionalController] = [], namespaces: [String] = ["reading.saved"],
         clock: @escaping @Sendable () -> Date = { Date() }) {
        self.medium = medium; self.member = member; self.owner = owner
        session = ColophonSession(configuration: .init(memberLabel: "Test device", namespaces: namespaces, location: .memory(medium),
            privateContainer: home, keys: member, ownerController: owner, recoveryKeys: recovery, homes: homes, createWithoutHome: createWithoutHome, additionalControllers: additional,
            deviceSecrets: MemoryDeviceSecrets(), now: clock))
    }
    isolated deinit { try? FileManager.default.removeItem(at: home) }
}

/// Two devices of one account, each with its own folder, joined through one in-process home. The second is
/// approved and has pulled the first's history.
@MainActor func twoDevicesOnAHome() async throws -> (home: SimHome, first: Device, second: Device) {
    let home = SimHome()
    let make: @Sendable (String) async throws -> Data = { account in
        home.setAccount(account)
        return try home.memberRequest(account: account, createdMs: Int64(Date().timeIntervalSince1970 * 1000) - 5000)
    }
    let endpoint = URL(string: home.base + "/")!
    let first = Device(homes: [HomeConfiguration(endpoint: endpoint, request: make, transport: home)], createWithoutHome: false)
    await first.session.create()
    first.session.stopSync()
    let second = Device(medium: MemoryMedium(files: first.medium.snapshot().filter { $0.key.hasPrefix("authority/") }),
                        homes: [HomeConfiguration(endpoint: endpoint, transport: home)], createWithoutHome: false)
    await second.session.restore()
    second.session.stopSync()
    try await first.session.importRequest(try await second.session.exportRequest())
    try await first.session.approve(try #require(first.session.requests.first))
    _ = await first.session.syncNow()
    _ = await second.session.syncNow()
    await second.session.refresh()
    try #require(second.session.phase == .ready)
    return (home, first, second)
}
