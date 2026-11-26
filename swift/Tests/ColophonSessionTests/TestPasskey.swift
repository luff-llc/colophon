import CryptoKit
import Foundation
import ColophonKeys
import ColophonSession

/// A software WebAuthn authenticator: the same assertions a platform passkey makes (authenticator data with UP
/// and UV, client data over the core's challenge, DER signature) and a deterministic PRF. It exists so the
/// whole creation and unlock paths run without a person; it is a test double, not a key store.
final class TestPasskey: AsyncKeyProvider, @unchecked Sendable {
    let key = P256.Signing.PrivateKey()
    let rp: String
    let credential: Data
    private let lock = NSLock()
    private var assertions = 0
    var assertCount: Int { lock.withLock { assertions } }
    private(set) var prfRequests = 0
    init(rp: String = "id.luff.works", credential: Data = Data([1, 2, 3])) { self.rp = rp; self.credential = credential }
    var form: KeyForm { .webauthn }
    var supportsPRF: Bool { true }
    static func prfOutput(_ salt: Data) -> SecretBytes { SecretBytes(copying: SHA256.hash(data: Data("test-prf".utf8) + salt)) }
    func assert(challenge: String, prfSalt: Data?) async throws -> KeyAssertion? {
        try assert(from: "https://\(rp)", challenge: challenge, prfSalt: prfSalt)
    }
    func assert(from origin: String, challenge: String, prfSalt: Data?) throws -> KeyAssertion {
        lock.withLock { assertions += 1; if prfSalt != nil { prfRequests += 1 } }
        let clientData = Data("{\"challenge\":\"\(challenge)\",\"origin\":\"\(origin)\",\"type\":\"webauthn.get\"}".utf8)
        var authData = Data(SHA256.hash(data: Data(rp.utf8)))
        authData.append(contentsOf: [0x05, 0, 0, 0, 0])
        let signature = try key.signature(for: authData + Data(SHA256.hash(data: clientData))).derRepresentation
        return KeyAssertion(signature: signature, authenticatorData: authData, clientData: clientData, prf: prfSalt.map(Self.prfOutput))
    }
    func prf(salt: Data) async throws -> SecretBytes? { lock.withLock { prfRequests += 1 }; return Self.prfOutput(salt) }
    func publicKeys() async throws -> PublicKeys { PublicKeys(signing: key.publicKey.x963Representation, agreement: Data()) }
    func sign(body: Data) async throws -> Data { throw KeyProviderError.unsupportedHere }
    func sharedSecret(peer: Data) async throws -> SecretBytes { throw KeyProviderError.unsupportedHere }
    func keyDescriptor() async throws -> KeyDescriptorView {
        KeyDescriptorView(form: .webauthn, signing: key.publicKey.x963Representation, agreement: nil, rp: rp, credential: credential,
                          origins: [], authorityOrigins: [])
    }
}

/// A `TestPasskey` as a device that does not know its public key sees it (a discoverable get): every get answers with
/// the passkey's credential, made from `origin`, for the relying party the authenticator claims (`claimedRP`).
struct TestPasskeyAuthenticator: PasskeyAuthenticator {
    let passkey: TestPasskey
    var origin: String? = nil
    var claimedRP: String? = nil
    var rp: String { claimedRP ?? passkey.rp }
    func get(challenge: String, credential: Data?) async throws -> PasskeyGet {
        if let credential, credential != passkey.credential { throw KeyProviderError.credentialMissing }
        let a = try passkey.assert(from: origin ?? "https://\(passkey.rp)", challenge: challenge, prfSalt: nil)
        return PasskeyGet(credential: passkey.credential, signature: a.signature, authenticatorData: a.authenticatorData, clientData: a.clientData)
    }
}
