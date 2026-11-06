import SwiftUI
import ColophonSession

@main struct ColophonSampleApp: App {
    // One process session, shared by every window. No core or storage calls in product views.
    @State private var session: ColophonSession
    init() {
        let home = URL.applicationSupportDirectory.appending(path: "ColophonSample")
        _session = State(initialValue: ColophonSession(configuration: .init(
            memberLabel: "Colophon Sample", namespaces: ["reading.saved"],
            location: .privateContainer(home), privateContainer: home,
            keys: KeychainKeys(service: "org.luff.ColophonSample", backend: .software),
            recoveryKeys: KeychainKeys(service: "org.luff.ColophonSample", account: "recovery", backend: .software))))
    }
    var body: some Scene {
        WindowGroup { SampleView(session: session).task { await session.restore() } }
    }
}
