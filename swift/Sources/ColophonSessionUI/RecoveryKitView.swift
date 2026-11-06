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
                Text("Keep your recovery kit somewhere private and safe. Anyone with the kit may be able to take control of your library.")
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
                Button("Recover Library") { confirmsRecovery = true }
                    .disabled(host.importRecoveryKit == nil || model.input.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    .accessibilityIdentifier("library.kitImport")
                if host.importRecoveryKit == nil { Text("Recovery kit import is not available in this app yet.").foregroundStyle(.secondary) }
                if model.imported { Label("Recovery Completed", systemImage: "checkmark.circle").accessibilityIdentifier("library.kitImported") }
            } header: { Text("Recover a Library") }
              footer: { Text("Recovery can change who controls the library. Use the kit for the library you selected.") }
            if model.action.isWorking { ProgressView("Accessing recovery kit") }
            LibraryErrorView(message: model.action.error)
        }
        .formStyle(.grouped)
        .disabled(model.action.isWorking)
        .navigationTitle("Recovery Kit")
        .confirmationDialog("Recover this library?", isPresented: $confirmsRecovery, titleVisibility: .visible) {
            Button("Recover Library") { Task { await model.recover(host: host) } }
                .accessibilityIdentifier("library.kitImport.confirm")
            Button("Cancel", role: .cancel) {}.accessibilityIdentifier("library.kitImport.cancel")
        } message: { Text("The recovery kit may replace the library’s controlling identity. Existing contributions remain attributed to their authors.") }
        .onDisappear { model.clear() }
        .interactiveDismissDisabled(model.action.isWorking || model.exported != nil)
    }
}
