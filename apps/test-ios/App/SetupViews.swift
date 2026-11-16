import ColophonSession
import SwiftUI

/// First run: the home, then create an account or join one.
struct SetupView: View {
    @Environment(AppModel.self) private var model
    @State private var prefix = ""
    @State private var reach = ""
    @State private var provisioner = ""
    @State private var token = ""
    @State private var invite = ""
    @State private var scanning = false

    private var softwareOwnerAvailable: Bool {
        #if DEBUG || targetEnvironment(simulator)
        true
        #else
        false
        #endif
    }

    var body: some View {
        Form {
            Section {
                LabeledContent("Home URL prefix") {
                    TextField("https://…/", text: $prefix).accessibilityIdentifier("homePrefix")
                }
                LabeledContent("Reach over") {
                    TextField("empty: as named", text: $reach).accessibilityIdentifier("reachPrefix")
                }
                LabeledContent("Home service") {
                    TextField("provisions a new account's home", text: $provisioner).accessibilityIdentifier("provisioner")
                }
                LabeledContent("Home service token") {
                    SecureField("printed by the home service at start-up", text: $token).accessibilityIdentifier("provisionerToken")
                }
                HStack {
                    Button("Use staging") {
                        prefix = BuildDefaults.current.stagingPrefix; reach = ""; provisioner = BuildDefaults.current.stagingProvisioner
                    }.buttonStyle(.borderless).accessibilityIdentifier("useStaging")
                    Spacer()
                    Button("Use this Mac") {
                        let d = Settings(); prefix = d.homePrefix; reach = d.reachPrefix; provisioner = d.provisioner
                    }.buttonStyle(.borderless)
                }
                Text("A new account gets the slot \u{201C}t…\u{201D} under the prefix. \u{201C}Reach over\u{201D} sends the home's requests to this URL instead (a relay on this Mac); leave it empty for a real https home.")
                    .font(.footnote).foregroundStyle(.secondary)
            } header: { Text("Home") }
            Section {
                Button("Create with a passkey") { save(); Task { await model.create(owner: .passkey) } }
                    .accessibilityIdentifier("createPasskey")
                if softwareOwnerAvailable {
                    Button("Create with a software owner key (test only)") { save(); Task { await model.create(owner: .software) } }
                        .accessibilityIdentifier("createSoftware")
                }
                Text("Passkey: relying party \(BuildDefaults.current.relyingParty). It works only where that domain lists this app (see the README).")
                    .font(.footnote).foregroundStyle(.secondary)
            } header: { Text("New account") }
            Section {
                TextField("Paste an invite (CTJ1.…)", text: $invite, axis: .vertical).lineLimit(3...6)
                    .font(.system(.footnote, design: .monospaced)).accessibilityIdentifier("invite")
                HStack {
                    Button("Join") { Task { await model.prepareJoin(invite) } }.disabled(invite.isEmpty).accessibilityIdentifier("join")
                    Spacer()
                    if ScannerView.isAvailable { Button("Scan") { scanning = true } }
                }
            } header: { Text("Join an account") } footer: {
                Text("On a device of the account: Devices, Add a device. Scan its code, or paste its invite.")
            }
            Section { NavigationLink("Log") { LogView() } }
        }
        .navigationTitle("Colophon test")
        .disabled(model.busy != nil)
        .onAppear { prefix = model.settings.homePrefix; reach = model.settings.reachPrefix; provisioner = model.settings.provisioner; token = model.settings.provisionerToken }
        // Settings can change under the form (a reset, a test hand-off): show what is stored.
        .onChange(of: model.settings) { _, s in prefix = s.homePrefix; reach = s.reachPrefix; provisioner = s.provisioner; token = s.provisionerToken }
        .sheet(isPresented: $scanning) {
            ScannerView { text in scanning = false; invite = text; Task { await model.prepareJoin(text) } }
        }
    }

    private func save() { model.updateHome(prefix: prefix, reach: reach, provisioner: provisioner, token: token) }
}

/// A joining device that is not approved yet: its request and code, for the owner device.
struct WaitingView: View {
    @Environment(AppModel.self) private var model
    let code: String
    @State private var payload: String?

    var body: some View {
        List {
            Section("Waiting for approval") {
                Text(code).font(.system(.largeTitle, design: .monospaced)).accessibilityIdentifier("pairingCode")
                Text("On the owner device: Devices, Add a device, then scan this code or paste this request. Approve only if it shows the same code.")
                    .font(.footnote)
                Text(TrustWords.waiting).font(.footnote).foregroundStyle(.secondary)
            }
            if let payload {
                Section("This device's request") {
                    QRCodeView(text: payload)
                    PayloadText(text: payload)
                }
            }
            Section {
                Button("Check for approval") { Task { await model.sync() } }.accessibilityIdentifier("checkApproval")
                if let sync = model.lastSync { SyncOutcomeView(outcome: sync) }
                NavigationLink("Status") { StatusView() }
            }
        }
        .navigationTitle("Join")
        .task { payload = try? await model.requestPayload() }
        .refreshable { await model.sync() }
    }
}

/// A payload as selectable text with a Copy button.
struct PayloadText: View {
    let text: String
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(text).font(.system(.caption2, design: .monospaced)).lineLimit(4).textSelection(.enabled)
                .accessibilityIdentifier("payload").accessibilityValue(text)
            Button("Copy") { UIPasteboard.general.string = text }.accessibilityIdentifier("copyPayload")
        }
    }
}

/// What the pairing does and does not prove, the same words on iPhone and Android. Until a signed invite and the §7.3
/// ceremony land in the SDKs, an invite is not authenticated.
enum TrustWords {
    static let invite = "Join only with an invite you got in person or over a channel you trust. The invite is not signed: it does not prove who made it, or that the home and the account are theirs."
    static let waiting = "The code lets the owner device check that the request it received is this device's, unchanged. It does not prove that the invite came from the person you think."
    static let approve = "Compare this code with the one on the joining device. A matching code shows the request came from that device unchanged; it does not prove who holds the device. Confirm only after checking; reject if the codes differ."
}

/// A link, a scan or a paste only fills this screen: nothing is stored and nothing is sent until the person confirms.
struct JoinConfirmView: View {
    @Environment(AppModel.self) private var model
    let pending: AppModel.PendingInvite

    var body: some View {
        NavigationStack {
            List {
                Section("Ask to join this account?") {
                    LabeledContent("Home", value: pending.host).accessibilityIdentifier("confirmHost")
                    LabeledContent("Account", value: pending.accountShort).accessibilityIdentifier("confirmAccount")
                    Text("This device will store the account's history, then ask the account's owner device to approve it.").font(.footnote)
                }
                Section { Text(TrustWords.invite).font(.footnote).foregroundStyle(.orange) }
                if let error = model.actionError { Section { Text(error).font(.footnote).foregroundStyle(.red).accessibilityIdentifier("confirmError") } }
                Section {
                    Button("Ask to join") { Task { await model.confirmJoin() } }.accessibilityIdentifier("confirmJoin")
                    Button("Cancel", role: .cancel) { model.cancelJoin() }.accessibilityIdentifier("cancelJoin")
                }
            }
            .navigationTitle("Join")
            .disabled(model.busy != nil)
        }
        .interactiveDismissDisabled()
    }
}
