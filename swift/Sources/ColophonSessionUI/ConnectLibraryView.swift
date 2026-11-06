import ColophonSession
import SwiftUI
import UniformTypeIdentifiers

public struct ConnectLibraryView: View {
    let host: LibraryHostActions
    let purpose: LibraryConnectionPurpose
    @State private var model = ConnectionModel()
    @State private var choosingFolder = false
    public init(host: LibraryHostActions, purpose: LibraryConnectionPurpose = .connectAnotherDevice) {
        self.host = host; self.purpose = purpose
    }
    public var body: some View {
        Form {
            if model.completed {
                Section {
                    Label("Library Location Prepared", systemImage: "checkmark.circle")
                    Text(model.nextStep)
                }.accessibilityIdentifier("addDevice.next")
            } else {
                Section {
                    Label(purpose == .join ? "Find Your Library" : "Use Your Library Elsewhere", systemImage: "externaldrive.badge.person.crop")
                        .font(.title2.bold())
                    Text("iCloud Drive or a shared folder carries your library between devices. Every new identity still needs approval.")
                    Text("An App Group shares a library between apps on this device. It does not sync to another device.")
                        .foregroundStyle(.secondary)
                }
                Section("Library Location") {
                    ForEach(host.containers) { choice in
                        Button(choice.title, systemImage: choice.kind == .iCloud ? "icloud" : "apps.iphone") {
                            connect(choice.location)
                        }.accessibilityIdentifier("addDevice.\(choice.kind == .iCloud ? "iCloud" : "appGroup").\(choice.id)")
                    }
                    Button("Choose Folder…", systemImage: "folder") { choosingFolder = true }
                        .accessibilityIdentifier("addDevice.folder")
                }.disabled(host.connect == nil || model.action.isWorking)
                if host.connect == nil {
                    Text("Choosing a library location is not available in this app yet.")
                        .foregroundStyle(.secondary).accessibilityIdentifier("addDevice.unavailable")
                }
            }
            if model.action.isWorking { ProgressView("Preparing library location") }
            LibraryErrorView(message: model.action.error)
        }
        .formStyle(.grouped)
        .navigationTitle(purpose == .join ? "Use Your Library" : "Connect Another Device")
        .interactiveDismissDisabled(model.action.isWorking)
        .fileImporter(isPresented: $choosingFolder, allowedContentTypes: [.folder]) { result in
            switch result {
            case .success(let url): connect(.folder(url))
            case .failure(let error): model.action.report(error)
            }
        }
    }
    private func connect(_ location: StorageLocation) {
        Task { await model.connect(location, purpose: purpose, host: host) }
    }
}
