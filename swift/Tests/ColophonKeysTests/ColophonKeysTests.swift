import AuthenticationServices
import ColophonKit
import CryptoKit
import Foundation
import LocalAuthentication
import Security
import Testing
@testable import ColophonKeys

struct ColophonKeysTests {
    @Test(arguments: [CredentialKind.passkey, .securityKey])
    func registrationReturnsCoreDescriptor(kind: CredentialKind) async throws {
        let ceremony = FakeCeremonies()
        let descriptor = try await register(kind, ceremony)
        #expect(descriptor.relyingParty == "keys.example")
        #expect(descriptor.credential == Data([1]))
        #expect(descriptor.signing == ceremony.signing.publicKey.x963Representation)
        #expect(descriptor.json == (try parseRegistration(attestationObject: await ceremony.attestation(rp: "keys.example"), rp: "keys.example")))
        #expect(await ceremony.registrations == 1)
        #expect(await ceremony.assertions == 0)
    }

    @Test(arguments: [CredentialKind.passkey, .securityKey])
    func assertionBuildsAndOpensPRFSlot(kind: CredentialKind) async throws {
        let ceremonies = FakeCeremonies()
        let descriptor = try await register(kind, ceremonies)
        let provider = provider(kind, descriptor, ceremonies)
        #expect(provider.form == .webauthn)
        let owner = SoftwareKeys(), member = SoftwareKeys()
        let library = try await Library.create(owner: member, label: "Keys", ownerLabel: "Owner",
                                                namespaces: ["notes"], controller: owner)
        let slot = try await library.buildPasskeySlot(descriptor: descriptor.json, provider: provider, label: "PRF")
        #expect(await ceremonies.assertions == 1)
        let last = try #require(await ceremonies.requests.last)
        #expect(last.credential == descriptor.credential)
        #expect(last.salt?.count == 32)
        #expect(last.challenge.count == 32)
        #expect(last.requireVerification)
        let controller = try controllerJSON(descriptor)
        let ownerID = SHA256.hash(data: try owner.signingPublicKey()).prefix(16).map { String(format: "%02x", $0) }.joined()
        try await library.addPasskey(controller: controller, slot: slot, signers: [ownerID])
        let reopened = try await Library.open(records: library.records, me: member)
        try await reopened.unlockVault(using: [provider])
        #expect(await ceremonies.assertions == 2)
        #expect(await ceremonies.requests.last?.salt == last.salt)
        // The original assertion bytes are forwarded, never rewritten by the provider.
        let response = try #require(try await provider.assert(challenge: base64url(last.challenge), prfSalt: last.salt))
        let expectedAuth = await ceremonies.authenticatorData(rp: "keys.example")
        #expect(response.authenticatorData == expectedAuth)
        #expect(response.prf?.count == 32)
    }

    @Test func coreRejectsAnInvalidAssertionBeforeBuildingSlot() async throws {
        let ceremonies = FakeCeremonies(corruptSignature: true)
        let descriptor = try await register(.passkey, ceremonies)
        let library = try await Library.create(owner: SoftwareKeys(), label: "Keys", ownerLabel: "Owner",
                                                namespaces: ["notes"], controller: SoftwareKeys())
        await #expect(throws: (any Error).self) {
            try await library.buildPasskeySlot(descriptor: descriptor.json,
                provider: PasskeyProvider(descriptor: descriptor, ceremonies: ceremonies), label: "Bad")
        }
    }

    @Test(arguments: [CredentialKind.passkey, .securityKey])
    func unsupportedPRFFailsBeforeUI(kind: CredentialKind) async throws {
        let ceremonies = FakeCeremonies(prfAvailable: false)
        let descriptor = try await register(kind, ceremonies)
        let provider = provider(kind, descriptor, ceremonies)
        await #expect(throws: KeyProviderError.unsupportedHere) {
            try await provider.assert(challenge: base64url(Data(repeating: 1, count: 32)), prfSalt: Data(repeating: 2, count: 32))
        }
        #expect(await ceremonies.assertions == 0)
        // A credential without PRF remains usable for authority signatures.
        let result = try await provider.assert(challenge: base64url(Data(repeating: 1, count: 32)), prfSalt: nil)
        #expect(result?.prf == nil)
        #expect(await ceremonies.assertions == 1)
    }

    @Test func visionOSStyleSecurityKeyGate() async throws {
        let ceremonies = FakeCeremonies(securityKeysAvailable: false)
        await #expect(throws: KeyProviderError.unsupportedHere) { try await register(.securityKey, ceremonies) }
        #expect(await ceremonies.registrations == 0)
        let descriptor = try await register(.passkey, ceremonies)
        let provider = SecurityKeyProvider(descriptor: descriptor, ceremonies: ceremonies)
        await #expect(throws: KeyProviderError.unsupportedHere) {
            try await provider.assert(challenge: "AQ", prfSalt: nil)
        }
        #expect(await ceremonies.assertions == 0)
    }

    @Test(arguments: [false, true])
    func missingOrWrongSizedPRFHasNoFallback(wrongSize: Bool) async throws {
        let ceremonies = FakeCeremonies(missingPRF: !wrongSize, wrongPRFSize: wrongSize)
        let descriptor = try await register(.passkey, ceremonies)
        let provider = PasskeyProvider(descriptor: descriptor, ceremonies: ceremonies)
        await #expect(throws: KeyProviderError.unsupportedHere) { try await provider.prf(salt: Data(repeating: 1, count: 32)) }
    }

    @Test func credentialMismatchFailsExplicitly() async throws {
        let ceremonies = FakeCeremonies(wrongCredential: true)
        let descriptor = try await register(.passkey, ceremonies)
        let provider = PasskeyProvider(descriptor: descriptor, ceremonies: ceremonies)
        await #expect(throws: KeyProviderError.credentialMissing) { try await provider.assert(challenge: "AQ", prfSalt: nil) }
    }

    @Test func onePresenceCheckPerAction() async throws {
        let backend = FakeOwnerBackend()
        let owner = SecureEnclaveOwnerKey(backend: backend, requiresPresence: true)
        let session = try await owner.presence(scope: "Create library")
        let keys = try await session.publicKeys()
        #expect(keys.signing != keys.agreement)
        for body in [Data("genesis".utf8), Data("rekey".utf8), Data("grant".utf8)] {
            let signature = try P256.Signing.ECDSASignature(rawRepresentation: await session.sign(body: body))
            #expect(try P256.Signing.PublicKey(x963Representation: keys.signing).isValidSignature(signature, for: body))
        }
        #expect(await backend.scopes == ["Create library"])
        #expect(await backend.signatures == 3)
        _ = try await owner.presence(scope: "Add passkey")
        #expect(await backend.scopes == ["Create library", "Add passkey"])
    }

    @Test func ownerSessionCreatesLibraryUnderOnePresenceCheck() async throws {
        let backend = FakeOwnerBackend()
        let owner = SecureEnclaveOwnerKey(backend: backend, requiresPresence: true)
        let session = try await owner.presence(scope: "Create library")
        let library = try await Library.create(owner: SoftwareKeys(), label: "Keys", ownerLabel: "Owner",
                                                namespaces: ["notes"], controller: session)
        #expect(try await library.records.isEmpty == false)
        #expect(await backend.scopes == ["Create library"])
        #expect(await backend.signatures > 1)
    }

    @Test func ownerPersistenceIsDeviceOnlyAndExcludedFromBackups() {
        let attributes = SecureEnclaveOwnerKey.storageAttributes(tag: "test", data: Data([1]))
        #expect(attributes[kSecAttrAccessible] as? String == kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)
        #expect(attributes[kSecAttrSynchronizable] as? Bool == false)
        #expect(attributes[kSecUseDataProtectionKeychain] as? Bool == true)
    }

    @MainActor @Test func presentationRequiresItsOwnMountedHost() async throws {
        let context = WebAuthnPresentationContext()
        await #expect(throws: CancellationError.self) { try await context.perform { 1 } }
        context.appear()
        await #expect(throws: KeyProviderError.unsupportedHere) { try await context.perform { 1 } }
        context.disappear()
        await #expect(throws: CancellationError.self) { try await context.perform { 1 } }
    }

    @Test func malformedRegistrationRemainsACoreError() async throws {
        #expect(throws: (any Error).self) { try KeyDescriptor(attestationObject: Data([0]), relyingParty: "keys.example") }
        let ceremonies = FakeCeremonies()
        let attestation = await ceremonies.attestation(rp: "keys.example")
        #expect(throws: (any Error).self) { try KeyDescriptor(attestationObject: attestation, relyingParty: "foreign.example") }
    }

    @Test func portableErrorMapping() async throws {
        let cases: [(any Error, KeyProviderError)] = [
            (CancellationError(), .cancelled),
            (ASAuthorizationError(.canceled), .cancelled),
            (ASAuthorizationError(.notHandled), .unsupportedHere),
            (ASAuthorizationError(.failed), .presenceFailed),
            (LAError(.authenticationFailed), .presenceFailed),
            (LAError(.userCancel), .cancelled),
            (LAError(.biometryNotAvailable), .hardwareUnavailable),
            (NSError(domain: NSOSStatusErrorDomain, code: Int(errSecItemNotFound)), .credentialMissing),
            (NSError(domain: NSOSStatusErrorDomain, code: Int(errSecNotAvailable)), .hardwareUnavailable),
            (WebAuthnSecurityKeyUnavailableError(), .unsupportedHere),
            (WebAuthnAssociationError(), .unsupportedHere),
        ]
        for (error, expected) in cases { #expect(KeyProviderError.map(error) == expected) }
        let underlying = NSError(domain: NSOSStatusErrorDomain, code: Int(errSecItemNotFound))
        let wrapped = NSError(domain: ASAuthorizationError.errorDomain, code: ASAuthorizationError.failed.rawValue,
                              userInfo: [NSUnderlyingErrorKey: underlying])
        #expect(KeyProviderError.map(wrapped) == .credentialMissing)
        let association = NSError(domain: "com.apple.WebCredentials", code: 1)
        let wrappedAssociation = NSError(domain: ASAuthorizationError.errorDomain, code: ASAuthorizationError.failed.rawValue,
                                         userInfo: [NSUnderlyingErrorKey: association])
        #expect(KeyProviderError.map(wrappedAssociation) == .unsupportedHere)
        let ceremonies = FakeCeremonies(failure: .cancelled)
        await #expect(throws: KeyProviderError.cancelled) { try await register(.passkey, ceremonies) }
    }

    @Test func systemAvailabilityMatchesSDKGates() {
        let system = SystemWebAuthnCeremonies()
        #if os(visionOS)
        #expect(system.supportsSecurityKeys == false)
        #expect(system.supportsPRF(kind: .securityKey) == false)
        #else
        #expect(system.supportsSecurityKeys)
        if #available(iOS 26.4, macOS 26.4, *) { #expect(system.supportsPRF(kind: .securityKey)) }
        else { #expect(system.supportsPRF(kind: .securityKey) == false) }
        #endif
        if #available(iOS 18, macOS 15, visionOS 2, *) { #expect(system.supportsPRF(kind: .passkey)) }
        else { #expect(system.supportsPRF(kind: .passkey) == false) }
    }
}

private func base64url(_ data: Data) -> String {
    data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}
private func register(_ kind: CredentialKind, _ ceremonies: FakeCeremonies) async throws -> KeyDescriptor {
    switch kind {
    case .passkey: try await PasskeyProvider.register(relyingParty: "keys.example", userID: Data([2]), userName: "Person",
                                                     challenge: Data(repeating: 3, count: 32), ceremonies: ceremonies)
    case .securityKey: try await SecurityKeyProvider.register(relyingParty: "keys.example", userID: Data([2]), userName: "Person",
                                                             challenge: Data(repeating: 3, count: 32), ceremonies: ceremonies)
    }
}
private func provider(_ kind: CredentialKind, _ descriptor: KeyDescriptor, _ ceremonies: FakeCeremonies) -> any AsyncKeyProvider {
    switch kind {
    case .passkey: PasskeyProvider(descriptor: descriptor, ceremonies: ceremonies)
    case .securityKey: SecurityKeyProvider(descriptor: descriptor, ceremonies: ceremonies)
    }
}
private func controllerJSON(_ descriptor: KeyDescriptor) throws -> Data {
    try JSONSerialization.data(withJSONObject: ["key": JSONSerialization.jsonObject(with: descriptor.json),
        "label": "Passkey", "roles": ["control"], "verification": true], options: [.sortedKeys])
}

private actor FakeCeremonies: WebAuthnCeremonies {
    nonisolated let signing = P256.Signing.PrivateKey()
    nonisolated let supportsSecurityKeys: Bool
    nonisolated let prfAvailable: Bool
    let missingPRF: Bool
    let wrongPRFSize: Bool
    let wrongCredential: Bool
    let corruptSignature: Bool
    let failure: KeyProviderError?
    var registrations = 0
    var assertions = 0
    struct Request: Sendable {
        let credential: Data; let challenge: Data; let salt: Data?; let requireVerification: Bool
    }
    var requests: [Request] = []
    init(prfAvailable: Bool = true, securityKeysAvailable: Bool = true, missingPRF: Bool = false,
         wrongPRFSize: Bool = false, wrongCredential: Bool = false, corruptSignature: Bool = false,
         failure: KeyProviderError? = nil) {
        self.prfAvailable = prfAvailable; supportsSecurityKeys = securityKeysAvailable
        self.missingPRF = missingPRF; self.wrongPRFSize = wrongPRFSize; self.wrongCredential = wrongCredential
        self.corruptSignature = corruptSignature; self.failure = failure
    }
    nonisolated func supportsPRF(kind: CredentialKind) -> Bool { prfAvailable }
    func register(kind: CredentialKind, rpID: String, userID: Data, userName: String, challenge: Data) throws -> Registration {
        if let failure { throw failure }
        registrations += 1
        return Registration(credentialID: Data([1]), attestationObject: attestation(rp: rpID))
    }
    func authenticatorData(rp: String) -> Data { Data(SHA256.hash(data: Data(rp.utf8))) + Data([5, 0, 0, 0, 0]) }
    func assert(kind: CredentialKind, rpID: String, credential: Data, challenge: Data, prfSalt: Data?,
                requireVerification: Bool) throws -> AssertionResult {
        if let failure { throw failure }
        assertions += 1
        requests.append(Request(credential: credential, challenge: challenge, salt: prfSalt, requireVerification: requireVerification))
        let client = try JSONSerialization.data(withJSONObject: ["type": "webauthn.get", "challenge": base64url(challenge),
                                                                  "origin": "https://" + rpID], options: [.sortedKeys, .withoutEscapingSlashes])
        let auth = authenticatorData(rp: rpID)
        let signature = try signing.signature(for: auth + Data(SHA256.hash(data: client))).derRepresentation
        let output = prfSalt.map { salt in
            Data(HMAC<SHA256>.authenticationCode(for: salt, using: SymmetricKey(data: Data(repeating: 99, count: 32))))
        }
        return AssertionResult(credentialID: wrongCredential ? Data([9]) : credential,
            signature: corruptSignature ? Data([0]) : signature, authenticatorData: auth, clientData: client,
            prfOutput: missingPRF ? nil : wrongPRFSize ? Data([1]) : output)
    }
    func attestation(rp: String) -> Data {
        let point = signing.publicKey.x963Representation
        let cose = Data([0xa5, 1, 2, 3, 0x26, 0x20, 1, 0x21, 0x58, 32]) + point[1..<33]
            + Data([0x22, 0x58, 32]) + point[33..<65]
        let auth = Data(SHA256.hash(data: Data(rp.utf8))) + Data([0x41]) + Data(repeating: 0, count: 20) + Data([0, 1, 1]) + cose
        var attestation = Data([0xa3, 0x68])
        attestation += Data("authData".utf8)
        attestation += Data([0x58, UInt8(auth.count)])
        attestation += auth
        attestation += Data([0x63]) + Data("fmt".utf8) + Data([0x64]) + Data("none".utf8)
        attestation += Data([0x67]) + Data("attStmt".utf8) + Data([0xa0])
        return attestation
    }
}

private actor FakeOwnerBackend: OwnerKeyBackend {
    let keys = SoftwareKeys()
    var scopes: [String] = []
    var signatures = 0
    func presence(scope: String) -> any AsyncKeyProvider { scopes.append(scope); return self }
    func publicKeys() throws -> PublicKeys { PublicKeys(signing: try keys.signingPublicKey(), agreement: try keys.agreementPublicKey()) }
    func sign(body: Data) throws -> Data { signatures += 1; return try keys.sign(body: body) }
    func agree(peer: Data) throws -> Data { try keys.agree(peer: peer) }
}
