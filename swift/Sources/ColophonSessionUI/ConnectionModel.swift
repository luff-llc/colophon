import ColophonSession
import Foundation
import Observation

@Observable @MainActor public final class ConnectionModel {
    public private(set) var completed = false
    public private(set) var nextStep = ""
    public let action = LibraryActionModel()
    public init() {}
    public func connect(_ location: StorageLocation, purpose: LibraryConnectionPurpose, host: LibraryHostActions) async {
        await action.run {
            completed = false
            guard let connect = host.connect else { throw LibraryUIError.unavailable("Choosing a location is not available in this app.") }
            let url: URL? = if case .folder(let url) = location { url } else { nil }
            let scoped = url?.startAccessingSecurityScopedResource() == true
            defer { if scoped { url?.stopAccessingSecurityScopedResource() } }
            try await connect(purpose, location)
            switch (purpose, location) {
            case (.join, _):
                nextStep = "Continue with the selected library. If it needs approval, compare this device’s pairing code on a device that already has access."
            case (.connectAnotherDevice, .appGroup):
                nextStep = "Open the other app on this device and choose the shared library. Approve its request only after comparing the pairing code."
            default:
                nextStep = "On the other device, choose this library. Compare its pairing code here before approving access."
            }
            completed = true
        }
    }
}
