import SwiftUI

public struct PairingCodeView: View {
    public let code: String
    public init(code: String) { self.code = code }
    public var body: some View {
        Text(code)
            .font(.largeTitle.monospaced().bold())
            .multilineTextAlignment(.center)
            .fixedSize(horizontal: false, vertical: true)
            .textSelection(.enabled)
            .accessibilityLabel("Pairing code")
            .accessibilityValue(code.map(String.init).joined(separator: " "))
            .accessibilityIdentifier("library.pairingCode")
    }
}

#Preview { PairingCodeView(code: "123456") }
