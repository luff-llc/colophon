import ColophonSession
import SwiftUI

public struct MemberDetailView: View {
    let session: any LibrarySessionSource
    let member: Member
    @State private var model: MemberAccessModel
    @State private var confirmsRevocation = false
    @Environment(\.dismiss) private var dismiss
    public init(member: Member, session: any LibrarySessionSource) {
        self.member = member; self.session = session
        _model = State(initialValue: MemberAccessModel(member: member, session: session))
    }
    public var body: some View {
        Form {
            Section {
                Label(member.label, systemImage: "person.crop.circle").font(.title2.bold())
                Text(LibraryWords.kind(member.kind)).foregroundStyle(.secondary)
                Text(LibraryWords.grant(member)).accessibilityIdentifier("library.member.grant")
            }
            if let grant = member.grant {
                Section("Can Use") {
                    ForEach(grant.namespaces, id: \.self) { namespace in
                        VStack(alignment: .leading) {
                            Text(LibraryWords.namespace(namespace))
                            Text(LibraryWords.access(grant.access)).foregroundStyle(.secondary)
                        }.accessibilityElement(children: .combine)
                    }
                }
            }
            Section {
                Text(LibraryWords.revocation)
                if member.grant != nil && member.revokedAt == nil {
                    Button("End Access", role: .destructive) { confirmsRevocation = true }
                        .disabled(model.action.isWorking).accessibilityIdentifier("library.access.end")
                }
                LibraryErrorView(message: model.action.error)
                if model.action.isWorking { ProgressView("Ending access") }
            }
        }.formStyle(.grouped).navigationTitle(member.label)
        .confirmationDialog("End access for \(member.label)?", isPresented: $confirmsRevocation, titleVisibility: .visible) {
            Button("End Access", role: .destructive) {
                Task {
                    if await model.revoke(session: session) { dismiss() }
                }
            }.accessibilityIdentifier("library.access.end.confirm")
            Button("Cancel", role: .cancel) {}.accessibilityIdentifier("library.access.end.cancel")
        } message: { Text(LibraryWords.revocation) }
    }
}
