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
    private(set) var assertions = 0
    private(set) var prfRequests = 0
    init(rp: String = "id.luff.works", credential: Data = Data([1, 2, 3])) { self.rp = rp; self.credential = credential }
    var form: KeyForm { .webauthn }
    static func prfOutput(_ salt: Data) -> Data { Data(SHA256.hash(data: Data("test-prf".utf8) + salt)) }
    func assert(challenge: String, prfSalt: Data?) async throws -> WebauthnResult? {
        lock.withLock { assertions += 1; if prfSalt != nil { prfRequests += 1 } }
        let clientData = Data("{\"challenge\":\"\(challenge)\",\"origin\":\"https://\(rp)\",\"type\":\"webauthn.get\"}".utf8)
        var authData = Data(SHA256.hash(data: Data(rp.utf8)))
        authData.append(contentsOf: [0x05, 0, 0, 0, 0])
        let signature = try key.signature(for: authData + Data(SHA256.hash(data: clientData))).derRepresentation
        return WebauthnResult(signature: signature, authenticatorData: authData, clientData: clientData, prf: prfSalt.map(Self.prfOutput))
    }
    func prf(salt: Data) async throws -> Data? { lock.withLock { prfRequests += 1 }; return Self.prfOutput(salt) }
    func publicKeys() async throws -> PublicKeys { PublicKeys(signing: key.publicKey.x963Representation, agreement: Data()) }
    func sign(body: Data) async throws -> Data { throw KeyProviderError.unsupportedHere }
    func agree(peer: Data) async throws -> Data { throw KeyProviderError.unsupportedHere }
    func keyDescriptor() async throws -> KeyDescriptorView {
        KeyDescriptorView(form: .webauthn, signing: key.publicKey.x963Representation, agreement: nil, rp: rp, credential: credential,
                          origins: [], authorityOrigins: [])
    }
}
