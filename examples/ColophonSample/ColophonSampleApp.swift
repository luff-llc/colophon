import SwiftUI
import ColophonSession

@main struct ColophonSampleApp: App {
    // One process session, shared by every window. No core or storage calls in product views.
    @State private var session: ColophonSession
    init() {
        // Launch with --demo-key-failure to exercise the visible error and Retry without
        // Keychain entitlements or touching an existing sample library.
        let demonstration = ProcessInfo.processInfo.arguments.contains("--demo-key-failure")
        let home = demonstration ? FileManager.default.temporaryDirectory.appendingPathComponent("ColophonKeyFailure-" + UUID().uuidString)
            : URL.applicationSupportDirectory.appending(path: "ColophonSample")
        let keys: any AsyncKeyProvider = demonstration ? DemoKeyFailure() : KeychainKeys(service: "org.luff.ColophonSample", backend: .software)
        let recovery: any AsyncKeyProvider = demonstration ? SoftwareKeys() : KeychainKeys(service: "org.luff.ColophonSample", account: "recovery", backend: .software)
        _session = State(initialValue: ColophonSession(configuration: .init(
            memberLabel: "Colophon Sample", namespaces: ["reading.saved"],
            location: .privateContainer(home), privateContainer: home,
            keys: keys, recoveryKeys: recovery)))
    }
    var body: some Scene {
        WindowGroup { SampleView(session: session).task { await session.restore() } }
    }
}

/// Fails the first key access; Retry then uses the same in-memory identity.
private actor DemoKeyFailure: AsyncKeyProvider {
    let keys = SoftwareKeys()
    var locked = true
    struct Locked: LocalizedError {
        var errorDescription: String? { "Demo: key access was locked. Retry to continue with this identity." }
    }
    func publicKeys() async throws -> PublicKeys {
        if locked { locked = false; throw Locked() }
        return try await keys.publicKeys()
    }
    func sign(body: Data) async throws -> Data { try keys.sign(body: body) }
    func agree(peer: Data) async throws -> Data { try keys.agree(peer: peer) }
}
