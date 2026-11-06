import SwiftUI

public struct SupportReportView: View {
    let session: any LibrarySessionSource
    @State private var report = ""
    public init(session: any LibrarySessionSource) { self.session = session }
    public var body: some View {
        Form {
            Section {
                Label("A Report You Can Review", systemImage: "ladybug").font(.title2.bold())
                Text("Includes your system version, connection state and counts of members, requests and ledger entries. Library content, names, identifiers, paths, pairing codes, keys and error details are excluded.")
                Text("Nothing is sent until you choose where to share it.").foregroundStyle(.secondary)
            }
            Section("Report Preview") {
                Text(report).font(.body.monospaced()).textSelection(.enabled)
                    .accessibilityIdentifier("support.report.preview")
                ShareLink(item: report) { Label("Share Support Report", systemImage: "square.and.arrow.up") }
                    .disabled(report.isEmpty).accessibilityIdentifier("support.report.share")
                Button("Refresh Report", systemImage: "arrow.clockwise", action: prepare)
                    .accessibilityIdentifier("support.report.refresh")
            }
        }.formStyle(.grouped).navigationTitle("Support Report").task { prepare() }
    }
    private func prepare() { report = (try? SupportReport(session: session).text()) ?? "Report unavailable" }
}
