import ColophonSession
import SwiftUI

public struct ApproveRequestView: View {
    let session: any LibrarySessionSource
    @State private var model: ApprovalModel
    @Environment(\.dismiss) private var dismiss
    /// A request scanned from the joining device's screen (its pairing is confirmed by the scan).
    public init(scanned: ScannedRequest, session: any LibrarySessionSource) {
        self.session = session
        _model = State(initialValue: ApprovalModel(scanned: scanned, session: session))
    }
    /// A request the devices paired for by the six-digit code: `code` is this device's digits, which the person
    /// compares with the joining device's before approving.
    public init(request: AccessRequest, pairing: AccountPairing, code: String, session: any LibrarySessionSource) {
        self.session = session
        _model = State(initialValue: ApprovalModel(request: request, pairing: pairing, code: code, session: session))
    }
    public var body: some View {
        @Bindable var model = model
        Form {
            Section {
                Text(model.request.label).font(.title2.bold())
                Text("\(LibraryWords.kind(model.request.kind)) · \(LibraryWords.access(model.request.access))")
                    .foregroundStyle(.secondary)
                if let code = model.code {
                    PairingCodeView(code: code)
                    Toggle("The other device shows the same code", isOn: $model.codeMatches)
                        .accessibilityIdentifier("library.approve.codeMatches")
                    Button("The Codes Are Different", role: .destructive) {
                        Task { if await model.codesDiffer(session: session) { dismiss() } }
                    }
                    .accessibilityIdentifier("library.approve.codesDiffer")
                } else {
                    Label("Scanned from the device asking to join", systemImage: "qrcode.viewfinder")
                        .accessibilityIdentifier("library.approve.scanned")
                }
            } footer: { Text(model.code == nil
                ? "This request was read from the other device's screen, so it is the one that device made."
                : "A name alone does not identify a device. Approve only if the other device shows exactly these six digits.") }
            Section("Can Use") {
                ForEach(model.request.namespaces, id: \.self) { namespace in
                    Toggle(LibraryWords.namespace(namespace), isOn: Binding(
                        get: { model.namespaces.contains(namespace) },
                        set: { if $0 { model.namespaces.insert(namespace) } else { model.namespaces.remove(namespace) } }))
                        .accessibilityIdentifier("library.approve.namespace.\(namespace)")
                }
                Toggle("Read only", isOn: $model.readOnly)
                    .disabled(!model.request.access.contains(.write) || !model.request.access.contains(.read))
                    .accessibilityIdentifier("library.approve.readOnly")
            }
            Section("Limits") {
                Toggle("Set an expiry", isOn: $model.limitsExpiry).accessibilityIdentifier("library.approve.limitExpiry")
                if model.limitsExpiry {
                    DatePicker("Access ends", selection: $model.expires, displayedComponents: [.date, .hourAndMinute])
                        .accessibilityIdentifier("library.approve.expiry")
                }
                if !model.readOnly {
                    Toggle("Limit the number of changes", isOn: $model.limitsBudget)
                        .accessibilityIdentifier("library.approve.limitBudget")
                    if model.limitsBudget {
                        TextField("Maximum changes", text: $model.budget)
                            .accessibilityIdentifier("library.approve.budget")
                    }
                }
            }
            Section {
                LibraryErrorView(message: model.action.error)
                if model.action.isWorking { ProgressView("Approving access") }
                Button("Approve Access") {
                    Task { if await model.approve(session: session) { dismiss() } }
                }
                .buttonStyle(.borderedProminent)
                .disabled((try? model.grant()) == nil)
                .accessibilityIdentifier("library.approve")
            } footer: { Text("A controller with approval authority must approve access. You can end this member’s access later.") }
        }
        .formStyle(.grouped)
        .disabled(model.action.isWorking)
        .interactiveDismissDisabled(model.action.isWorking)
        .navigationTitle("Review Access")
    }
}
