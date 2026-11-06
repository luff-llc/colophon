import SwiftUI

struct LibrarySheet<Content: View>: View {
    let title: String
    @ViewBuilder let content: () -> Content
    @Environment(\.dismiss) private var dismiss
    var body: some View {
        NavigationStack {
            content().navigationTitle(title)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Close") { dismiss() }.accessibilityIdentifier("library.sheet.close")
                    }
                }
        }
        #if os(macOS)
        .frame(minWidth: 420, idealWidth: 560, minHeight: 480, idealHeight: 640)
        #endif
    }
}
