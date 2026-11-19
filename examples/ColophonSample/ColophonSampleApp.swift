import CoreImage
import SwiftUI
import ColophonSession
import ColophonSessionUI

@main struct ColophonSampleApp: App {
    // One process session, shared by every window. No core or storage calls in product views.
    private let keys: any AsyncKeyProvider
    @State private var session: ColophonSession
    init() {
        // Launch with --demo-key-failure to exercise the visible error and Retry without
        // Keychain entitlements or touching an existing sample library.
        let demonstration = ProcessInfo.processInfo.arguments.contains("--demo-key-failure")
        let home = demonstration ? FileManager.default.temporaryDirectory.appendingPathComponent("ColophonKeyFailure-" + UUID().uuidString)
            : URL.applicationSupportDirectory.appending(path: "ColophonSample")
        let keys: any AsyncKeyProvider = demonstration ? DemoKeyFailure() : KeychainKeys(service: "org.luff.ColophonSample", backend: .software)
        self.keys = keys
        let recovery: any AsyncKeyProvider = demonstration ? SoftwareKeys() : KeychainKeys(service: "org.luff.ColophonSample", account: "recovery", backend: .software)
        _session = State(initialValue: ColophonSession(configuration: .init(
            memberLabel: "Colophon Sample", namespaces: ["reading.saved"],
            location: .privateContainer(home), privateContainer: home,
            keys: keys, recoveryKeys: recovery)))
    }
    var body: some Scene {
        WindowGroup { SampleView(session: session, host: .init(rejoinKeys: { keys }, scanRequest: { try await PasteboardQR.request() })) }
    }
}

/// The sample's "scan": the QR code in an image on the pasteboard (a photo or screenshot of the joining device's screen,
/// where it shows its request). The payload is the request's canonical envelope (spec §9.1); the session checks it. An app
/// with a camera reads the code live instead.
private enum PasteboardQR {
    struct NoCode: LocalizedError {
        var errorDescription: String? { "Copy a picture of the other device's request code first, then scan again." }
    }
    @MainActor static func request() throws -> Data {
        #if canImport(AppKit)
        guard let data = NSPasteboard.general.data(forType: .png) ?? NSPasteboard.general.data(forType: .tiff),
              let image = CIImage(data: data) else { throw NoCode() }
        #else
        guard let picture = UIPasteboard.general.image, let image = CIImage(image: picture) else { throw NoCode() }
        #endif
        let detector = CIDetector(ofType: CIDetectorTypeQRCode, context: nil, options: [CIDetectorAccuracy: CIDetectorAccuracyHigh])
        guard let text = detector?.features(in: image).compactMap({ ($0 as? CIQRCodeFeature)?.messageString }).first else { throw NoCode() }
        return Data(text.utf8)
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
