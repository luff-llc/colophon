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
         homes: [HomeConfiguration] = [], createWithoutHome: Bool = true, namespaces: [String] = ["reading.saved"],
         clock: @escaping @Sendable () -> Date = { Date() }) {
        self.medium = medium; self.member = member; self.owner = owner
        session = ColophonSession(configuration: .init(memberLabel: "Test device", namespaces: namespaces, location: .memory(medium),
            privateContainer: home, keys: member, ownerController: owner, homes: homes, createWithoutHome: createWithoutHome,
            deviceSecrets: MemoryDeviceSecrets(), now: clock))
    }
    isolated deinit { try? FileManager.default.removeItem(at: home) }
}
