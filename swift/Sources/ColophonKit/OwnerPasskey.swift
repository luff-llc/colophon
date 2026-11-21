import Foundation

/// A current WebAuthn controller's descriptor read from a history a joining device accepted. Only
/// `AdmittedHistory.ownerDescriptor(keyID:)` (ColophonSession) makes one; `KeyDescriptor(passkey:)` (ColophonKeys) turns
/// it into what a passkey provider takes.
public struct OwnerPasskey: Sendable, Equatable {
    /// The descriptor as the history names it (`rp`, credential, origins).
    public let view: KeyDescriptorView
    /// Within this package only: for a view the core returned as a current WebAuthn controller.
    package init?(view: KeyDescriptorView) {
        guard view.form == .webauthn, view.rp != nil, view.credential != nil, view.signing.count == 65 else { return nil }
        self.view = view
    }
}
