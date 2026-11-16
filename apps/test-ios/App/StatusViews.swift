import ColophonSession
import CoreImage.CIFilterBuiltins
import SwiftUI
import VisionKit

/// Adding devices (owner) and the member list.
struct DevicesView: View {
    @Environment(AppModel.self) private var model
    @State private var invite: String?
    @State private var scanning = false

    var body: some View {
        List {
            if model.isOwner {
                Section {
                    if let invite {
                        QRCodeView(text: invite)
                        PayloadText(text: invite)
                    } else {
                        Button("Add a device: show the invite") { Task { invite = try? await model.invitePayload() } }
                            .accessibilityIdentifier("showInvite")
                    }
                } header: { Text("1. The new device scans or pastes this") }
                Section {
                    if ScannerView.isAvailable {
                        Button("Scan its request") { scanning = true }.accessibilityIdentifier("scanRequest")
                    } else {
                        Text("This device has no camera: approve from a device that can scan the request.").font(.footnote)
                    }
                    Text("Point the camera at the new device's screen. Only a request read from that screen can be approved.").font(.footnote)
                } header: { Text("2. Then scan its request") }
                if let scanned = model.scanned {
                    Section {
                        Text(TrustWords.approve).font(.footnote).foregroundStyle(.secondary)
                        VStack(alignment: .leading, spacing: 6) {
                            Text(scanned.request.label).font(.headline).accessibilityIdentifier("scannedRequest")
                            Text("\(scanned.request.kind) · \(scanned.request.id)").font(.caption)
                            HStack {
                                Button("Approve") { Task { await model.approveScanned() } }.accessibilityIdentifier("approve")
                                Spacer()
                                Button("Reject", role: .destructive) { model.rejectScanned() }.accessibilityIdentifier("reject")
                            }.buttonStyle(.borderless)
                        }
                    } header: { Text("3. Approve the device you scanned") }
                }
            } else {
                Section { Text("This device joined the account with a member key only: it cannot add, approve or revoke devices.").font(.footnote) }
            }
            if let session = model.session {
                Section("Members") {
                    ForEach(session.members, id: \.id) { member in
                        VStack(alignment: .leading) {
                            Text("\(member.label)\(member.id == session.memberID ? " (this device)" : "")")
                            Text("\(member.kind) · \(member.id)").font(.caption)
                            if member.revokedAt != nil { Text("revoked").font(.caption).foregroundStyle(.red) }
                            if model.isOwner, member.revokedAt == nil, member.id != session.memberID, !member.home {
                                Button("Revoke", role: .destructive) { Task { await model.revoke(member) } }
                            }
                        }
                    }
                }
            }
        }
        .navigationTitle("Devices")
        .sheet(isPresented: $scanning) {
            ScannerView { text in scanning = false; Task { await model.scanRequest(text) } }
        }
    }
}

/// The truth: every field the session publishes that a tester needs, the log, and the destructive buttons.
struct StatusView: View {
    @Environment(AppModel.self) private var model
    @State private var confirmReset = false
    @State private var confirmSignOut = false

    var body: some View {
        TimelineView(.periodic(from: .now, by: 2)) { _ in
            List {
                if let session = model.session { sessionSections(session) }
                Section("Home") {
                    row("URL", model.settings.homeBase ?? "-")
                    row("Reached over", model.settings.reachPrefix.isEmpty ? "as named" : model.settings.reachPrefix)
                    let sighting = model.observer.snapshot()
                    if let head = sighting.head {
                        row("Last head", "seq \(head.seq), issued \(head.issued), fetched \(head.at.formatted(date: .omitted, time: .standard))")
                            .accessibilityIdentifier("lastHead")
                    } else { row("Last head", "none fetched yet") }
                    if let last = sighting.last { row("Last answer", "\(last.status): \(last.method) \(last.path)") }
                    if let refusal = sighting.lastRefusal {
                        row("Last refusal", "\(refusal.status) at \(refusal.at.formatted(date: .omitted, time: .standard)): \(refusal.method) \(refusal.path) \(refusal.detail)")
                    }
                    if let error = sighting.transportError { row("Transport error", error) }
                    row("Requests sent", "\(sighting.requests)")
                }
                Section("Last sync") {
                    if let sync = model.lastSync { SyncOutcomeView(outcome: sync) } else { Text("Not run from this screen yet") }
                    Button("Sync now") { Task { await model.sync() } }.accessibilityIdentifier("syncNow")
                }
                Section("This device") {
                    Button("Lock") { Task { await model.lock() } }.accessibilityIdentifier("lock")
                    Button("Unlock") { Task { await model.unlock() } }
                    Button("Sign out (wipe local state)", role: .destructive) { confirmSignOut = true }.accessibilityIdentifier("signOut")
                    Button("Reset this device", role: .destructive) { confirmReset = true }.accessibilityIdentifier("reset")
                }
                Section { NavigationLink("Log (last 200 events)") { LogView() } }
            }
        }
        .navigationTitle("Status")
        .confirmationDialog("Wipe this device's account state? The account and other devices are unchanged.", isPresented: $confirmSignOut, titleVisibility: .visible) {
            Button("Sign out", role: .destructive) { Task { await model.signOut() } }.accessibilityIdentifier("confirmSignOut")
        }
        .confirmationDialog("Reset this device to the build's defaults?", isPresented: $confirmReset, titleVisibility: .visible) {
            Button("Reset", role: .destructive) { Task { await model.resetDevice() } }
        }
    }

    @ViewBuilder private func sessionSections(_ session: ColophonSession) -> some View {
        Section("Session") {
            row("Phase", String(describing: session.phase)).accessibilityIdentifier("phase")
            row("Account", session.libraryID ?? "-")
            row("This device's key", session.memberID ?? "-")
            row("Owner", model.settings.owner?.rawValue ?? "-")
            row("Sync state", String(describing: session.syncState))
            row("Last synced", session.lastSynced?.formatted(date: .abbreviated, time: .standard) ?? "never")
            row("Session error", session.lastError ?? "none")
            row("Home faults", session.homeFaults.map(AppModel.describe).joined(separator: "\n").ifEmpty("none"))
            row("Home issues", session.homeIssues.map { "\($0.home.prefix(8)): \(AppModel.describe($0.problem))" }.joined(separator: "\n").ifEmpty("none"))
            row("Held / refused notes", "\(model.heldAndRefused.held) / \(model.heldAndRefused.refused)")
            if session.notices.noHome { Text("This account has no home.").foregroundStyle(.red) }
            if session.duties.soleDevice { Text("This account has one control key: a stolen device could not be vetoed.").font(.caption) }
        }
        Section("Pending changes") {
            if session.notices.pending.isEmpty { Text("None") }
            ForEach(session.notices.pending, id: \.digest) { pending in
                VStack(alignment: .leading) {
                    Text("\(pending.components.joined(separator: ", ")) by \(pending.signers.map(\.label).joined(separator: ", "))")
                    Text("veto deadline: \(pending.vetoDeadlineMs.map { Date(timeIntervalSince1970: Double($0) / 1000).formatted() } ?? "-") · due: \(pending.dueMs.map { Date(timeIntervalSince1970: Double($0) / 1000).formatted() } ?? "-")")
                        .font(.caption)
                    Text(pending.digest).font(.caption2)
                    if pending.vetoable { Button("Veto", role: .destructive) { Task { await model.veto(pending) } } }
                }
            }
        }
        Section("Homes the account names") {
            ForEach(session.homes, id: \.id) { home in
                row(home.label, "\(home.status) · \(home.endpoints.joined(separator: " ")) · \(home.id)")
            }
        }
    }

    private func row(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label).font(.caption).foregroundStyle(.secondary)
            Text(value).font(.footnote).textSelection(.enabled).accessibilityValue(value)
        }
    }
}

struct LogView: View {
    @Environment(AppModel.self) private var model
    var body: some View {
        List(model.log.reversed()) { entry in
            VStack(alignment: .leading) {
                Text(entry.at.formatted(date: .omitted, time: .standard)).font(.caption2).foregroundStyle(.secondary)
                Text(entry.text).font(.footnote).textSelection(.enabled)
            }
        }
        .navigationTitle("Log")
    }
}

/// A QR code of `text` (CoreImage). A payload over one code's capacity says so: use Copy.
struct QRCodeView: View {
    let text: String
    var body: some View {
        if let image = Self.image(text) {
            Image(uiImage: image).interpolation(.none).resizable().scaledToFit().frame(maxWidth: 320).accessibilityIdentifier("qr")
        } else {
            Text("Too large for one QR code (\(text.utf8.count) characters): copy and paste it instead.").font(.footnote).foregroundStyle(.orange)
        }
    }
    static func image(_ text: String) -> UIImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "L"
        guard let output = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 8, y: 8)),
              let cg = CIContext().createCGImage(output, from: output.extent) else { return nil }
        return UIImage(cgImage: cg)
    }
}

/// The camera (VisionKit). Not available in the Simulator: paste instead.
struct ScannerView: UIViewControllerRepresentable {
    let found: (String) -> Void
    static var isAvailable: Bool { DataScannerViewController.isSupported && DataScannerViewController.isAvailable }

    func makeUIViewController(context: Context) -> DataScannerViewController {
        let controller = DataScannerViewController(recognizedDataTypes: [.barcode(symbologies: [.qr])], qualityLevel: .balanced,
                                                   isHighlightingEnabled: true)
        controller.delegate = context.coordinator
        try? controller.startScanning()
        return controller
    }
    func updateUIViewController(_ controller: DataScannerViewController, context: Context) {}
    func makeCoordinator() -> Coordinator { Coordinator(found: found) }

    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        let found: (String) -> Void
        private var done = false
        init(found: @escaping (String) -> Void) { self.found = found }
        func dataScanner(_ scanner: DataScannerViewController, didAdd items: [RecognizedItem], allItems: [RecognizedItem]) {
            for item in items {
                if case .barcode(let code) = item, let text = code.payloadStringValue, PairingPayload.kind(text) != nil, !done {
                    done = true; scanner.stopScanning(); found(text)
                }
            }
        }
    }
}
