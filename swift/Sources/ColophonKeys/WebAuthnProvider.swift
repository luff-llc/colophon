import ColophonKit
import CryptoKit
import Foundation
import Security

struct WebAuthnProvider: Sendable {
    let kind: CredentialKind
    let descriptor: KeyDescriptor
    let ceremonies: any WebAuthnCeremonies

    static func register(kind: CredentialKind, relyingParty: String, userID: Data, userName: String,
                         challenge: Data, ceremonies: any WebAuthnCeremonies) async throws -> KeyDescriptor {
        try checkPlatform(kind: kind, ceremonies: ceremonies)
        let registration: Registration
        do {
            try Task.checkCancellation()
            registration = try await ceremonies.register(kind: kind, rpID: relyingParty, userID: userID,
                                                          userName: userName, challenge: challenge)
            try Task.checkCancellation()
        } catch { throw KeyProviderError.map(error) }
        let descriptor = try KeyDescriptor(attestationObject: registration.attestationObject, relyingParty: relyingParty)
        guard descriptor.credential == registration.credentialID else { throw KeyProviderError.credentialMissing }
        return descriptor
    }

    func assert(challenge: String, prfSalt: Data?) async throws -> WebauthnResult {
        try Self.checkPlatform(kind: kind, ceremonies: ceremonies)
        if let prfSalt {
            guard prfSalt.count == 32, ceremonies.supportsPRF(kind: kind) else { throw KeyProviderError.unsupportedHere }
        }
        // W5 challenges are unpadded base64url; pass decoded challenge bytes to AS without hashing again.
        let encoded = challenge.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        guard let bytes = Data(base64Encoded: encoded + String(repeating: "=", count: (4 - encoded.count % 4) % 4)) else {
            throw KeyProviderError.unsupportedHere
        }
        let result: AssertionResult
        do {
            try Task.checkCancellation()
            result = try await ceremonies.assert(kind: kind, rpID: descriptor.relyingParty,
                credential: descriptor.credential, challenge: bytes, prfSalt: prfSalt, requireVerification: true)
            try Task.checkCancellation()
        } catch { throw KeyProviderError.map(error) }
        guard result.credentialID == descriptor.credential else { throw KeyProviderError.credentialMissing }
        if prfSalt != nil {
            guard result.prfOutput?.count == 32 else { throw KeyProviderError.unsupportedHere }
        }
        return WebauthnResult(signature: result.signature, authenticatorData: result.authenticatorData,
                              clientData: result.clientData, prf: prfSalt == nil ? nil : result.prfOutput)
    }

    func prf(salt: Data) async throws -> Data? {
        // Existing-slot opening has no body to sign. New slots MUST instead use assert with the core challenge.
        let challenge = try randomBytes().base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        return try await assert(challenge: challenge, prfSalt: salt).prf
    }

    private static func checkPlatform(kind: CredentialKind, ceremonies: any WebAuthnCeremonies) throws {
        if kind == .securityKey, !ceremonies.supportsSecurityKeys { throw KeyProviderError.unsupportedHere }
    }
}

func randomBytes() throws -> Data {
    var bytes = Data(count: 32)
    let status = bytes.withUnsafeMutableBytes { buffer in
        guard let address = buffer.baseAddress else { return errSecParam }
        return SecRandomCopyBytes(kSecRandomDefault, buffer.count, address)
    }
    guard status == errSecSuccess else { throw KeyProviderError.hardwareUnavailable }
    return bytes
}
