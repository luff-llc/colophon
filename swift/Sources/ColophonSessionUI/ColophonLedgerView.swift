import SwiftUI

public struct ColophonLedgerView: View {
    let session: any LibrarySessionSource
    public init(session: any LibrarySessionSource) { self.session = session }
    public var body: some View {
        List {
            Section {
                Text("The colophon records who contributed and how access changed. Past contributions keep their attribution after access ends.")
                    .foregroundStyle(.secondary)
            }
            if session.ledger.isEmpty {
                ContentUnavailableView("No Entries Yet", systemImage: "text.book.closed")
            }
            ForEach(session.ledger, id: \.sequence) { entry in
                VStack(alignment: .leading, spacing: 8) {
                    Text(entry.text)
                    Text(entry.actorLabel).font(.headline)
                    Text(LibraryWords.date(entry.at)).font(.subheadline).foregroundStyle(.secondary)
                }.accessibilityElement(children: .combine)
                    .accessibilityIdentifier("library.ledger.entry.\(entry.sequence)")
            }
        }.navigationTitle("Colophon").accessibilityIdentifier("library.ledger")
    }
}
