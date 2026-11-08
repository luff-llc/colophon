import SwiftUI

public struct RecoveryKitView: View {
    let host: LibraryHostActions
    @State private var model = RecoveryKitModel()
    @State private var confirmsRecovery = false
    public init(host: LibraryHostActions) { self.host = host }
    public var body: some View {
        @Bindable var model = model
        Form {
            Section {
                Label("A Way Back to Your Library", systemImage: "key.horizontal")
                    .font(.title2.bold())
                Text("Keep your recovery kit somewhere private and safe. The kit can add a device controller according to your library’s keyring rules.")
            }
            Section("Keep Your Kit") {
                if let kit = model.exported {
                    Text(kit).font(.body.monospaced()).textSelection(.enabled)
                        .privacySensitive()
                        .accessibilityLabel("Recovery kit").accessibilityValue(kit)
                        .accessibilityIdentifier("library.recoveryKit")
                    ShareLink(item: kit) { Label("Save Recovery Kit", systemImage: "square.and.arrow.up") }
                        .accessibilityIdentifier("library.kitShare")
                    Toggle("I’ve kept it somewhere safe", isOn: $model.kept)
                        .accessibilityIdentifier("library.keptKit")
                    Button("Done") { model.clear() }
                        .disabled(!model.kept).accessibilityIdentifier("library.kitDone")
                } else {
                    Button("Prepare Recovery Kit") { Task { await model.prepare(host: host) } }
                        .disabled(host.exportRecoveryKit == nil)
                        .accessibilityIdentifier("library.kitExport")
                    if host.exportRecoveryKit == nil { Text("Recovery kit export is not available in this app yet.").foregroundStyle(.secondary) }
                }
            }
            Section {
                SecureField("Recovery kit", text: $model.input)
                    .autocorrectionDisabled().privacySensitive()
                    .accessibilityIdentifier("library.recoveryKitField")
                Button("Restore Device") { confirmsRecovery = true }
                    .disabled(host.importRecoveryKit == nil || model.input.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    .accessibilityIdentifier("library.kitImport")
                if host.importRecoveryKit == nil { Text("Recovery kit import is not available in this app yet.").foregroundStyle(.secondary) }
                if model.imported { Label("Device Restored", systemImage: "checkmark.circle").accessibilityIdentifier("library.kitImported") }
            } header: { Text("Restore on This Device") }
              footer: { Text("The kit adds this device’s controller and grants its member access. Use the kit for the library you selected.") }
            if model.action.isWorking { ProgressView("Accessing recovery kit") }
            LibraryErrorView(message: model.action.error)
        }
        .formStyle(.grouped)
        .disabled(model.action.isWorking)
        .navigationTitle("Recovery Kit")
        .confirmationDialog("Restore this device?", isPresented: $confirmsRecovery, titleVisibility: .visible) {
            Button("Restore Device") { Task { await model.restoreDevice(host: host) } }
                .accessibilityIdentifier("library.kitImport.confirm")
            Button("Cancel", role: .cancel) {}.accessibilityIdentifier("library.kitImport.cancel")
        } message: { Text("The recovery kit adds a controller to the keyring. Existing controllers and contributions stay in place.") }
        .onDisappear { model.clear() }
        .interactiveDismissDisabled(model.action.isWorking || model.exported != nil)
    }
}
