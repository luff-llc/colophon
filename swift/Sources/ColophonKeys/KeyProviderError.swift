import AuthenticationServices
import Foundation
import LocalAuthentication
import Security

/// Portable F2 outcomes for Apple key operations. Protocol validation errors remain core errors.
public enum KeyProviderError: String, Error, Sendable, Equatable {
    /// The person or originating action cancelled the operation.
    case cancelled
    /// Authentication did not establish the person's presence.
    case presenceFailed
    /// This platform or credential cannot perform the requested operation.
    case unsupportedHere
    /// The selected credential or device-bound key is missing.
    case credentialMissing
    /// The required key hardware is unavailable.
    case hardwareUnavailable

    /// Maps Apple authentication and key-store failures without inspecting localized prose.
    public static func map(_ error: any Error) -> Self {
        if let error = error as? Self { return error }
        if error is WebAuthnSecurityKeyUnavailableError || error is WebAuthnAssociationError { return .unsupportedHere }
        if error is CancellationError { return .cancelled }
        var current = error as NSError
        var fallback = Self.hardwareUnavailable
        for _ in 0..<6 {
            let domain = current.domain.lowercased()
            let debug = ((current.userInfo["NSDebugDescription"] as? String) ?? "").lowercased()
            // Preserve the source adapter's association diagnostic: Apple has no public association code.
            if domain.contains("webcredential") || debug.contains("associat") || debug.contains("webcredential") {
                return .unsupportedHere
            }
            if current.domain == LAError.errorDomain {
                switch LAError.Code(rawValue: current.code) {
                case .userCancel, .appCancel, .systemCancel: return .cancelled
                case .biometryNotAvailable, .biometryNotEnrolled, .passcodeNotSet: return .hardwareUnavailable
                default: return .presenceFailed
                }
            }
            if current.domain == ASAuthorizationError.errorDomain {
                switch ASAuthorizationError.Code(rawValue: current.code) {
                case .canceled: return .cancelled
                case .notHandled, .notInteractive: return .unsupportedHere
                default: fallback = .presenceFailed
                }
            }
            if current.domain == NSOSStatusErrorDomain {
                switch OSStatus(current.code) {
                case errSecUserCanceled: return .cancelled
                case errSecItemNotFound: return .credentialMissing
                case errSecNotAvailable: return .hardwareUnavailable
                case errSecUnimplemented: return .unsupportedHere
                case errSecAuthFailed, errSecInteractionNotAllowed: return .presenceFailed
                default: break
                }
            }
            guard let next = current.userInfo[NSUnderlyingErrorKey] as? NSError, next !== current else { break }
            current = next
        }
        return fallback
    }
}

/// Hardware-key ceremonies are unavailable on this platform.
public struct WebAuthnSecurityKeyUnavailableError: Error, LocalizedError, Sendable {
    /// Creates the unavailable-security-key diagnostic.
    public init() {}
    /// Human-readable platform diagnostic.
    public var errorDescription: String? { "Security keys are not available on this device." }
}

/// The app does not have a relying-party association for this credential.
public struct WebAuthnAssociationError: Error, LocalizedError, Sendable {
    /// Creates the missing-association diagnostic.
    public init() {}
    /// Human-readable relying-party association diagnostic.
    public var errorDescription: String? { "The app is not associated with this credential's relying party." }
}
