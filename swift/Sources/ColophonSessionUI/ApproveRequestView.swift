import ColophonSession
import SwiftUI

public struct ApproveRequestView: View {
    let session: any LibrarySessionSource
    @State private var model: ApprovalModel
    @Environment(\.dismiss) private var dismiss
    public init(request: AccessRequest, session: any LibrarySessionSource) {
        self.session = session
        _model = State(initialValue: ApprovalModel(request: request, session: session))
    }
    public var body: some View {
        @Bindable var model = model
        Form {
            Section {
                Text(model.request.label).font(.title2.bold())
                Text("\(LibraryWords.kind(model.request.kind)) · \(LibraryWords.access(model.request.access))")
                    .foregroundStyle(.secondary)
                PairingCodeView(code: model.request.pairingCode)
                Toggle("I compared both codes and they match", isOn: $model.codeMatches)
                    .accessibilityIdentifier("library.approve.codeMatches")
            } footer: { Text("A name alone does not identify a device. Compare the code with the person or device asking to join.") }
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
